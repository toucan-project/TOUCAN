from django.urls import reverse

from django_rq import enqueue

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.parsers import FileUploadParser
from rest_framework.permissions import IsAuthenticated

from manage_api.models import DefaultSetting

from canary_files.serializers import UploadedFileSerializer

from canary_utils.lib.asynctasks import AsynchronousDelete


class GenerateCanaryItem(APIView):

    """
    Authenticated view responsible for creation of canary files.

    put: Take an incoming canary file and return a redirect to the
         file to be downloaded. The model is responsible for uploading
         the canary files to the right location.
    """

    permission_classes = (IsAuthenticated,)
    parser_classes = (FileUploadParser,)

    def put(self, request):
        user = request.user

        # consolidate dicts for validation
        data = {**request.data, **self._get_query_params(request)}

        serializer = UploadedFileSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        doc = serializer.validated_data['file']
        trigger = serializer.validated_data['trigger']
        location = serializer.validated_data['location']
        dns = serializer.validated_data['dns']
        domain = serializer.validated_data['domain']
        protocol = serializer.validated_data['protocol']

        canary = user.create_canary_as_user(doc, trigger, location,
                                            dns, protocol, domain)
        url = reverse('download-canary',
                      kwargs={
                               'identifier': canary.identifier
                            })

        return Response(data={'url': url})

    def _get_query_params(self, request):

        trigger = request.query_params.get('trigger')
        location = request.query_params.get('location')
        protocol = request.query_params.get('protocol', '')
        dns = request.query_params.get('dns', None)
        domain = request.query_params.get('domain', '')

        return dict({'trigger': trigger, 'location': location,
                     'dns': dns, 'domain': domain, 'protocol': protocol})


class DownloadCanaryItem(APIView):

    """
    Authenticated download of CanaryItems

    get: Download generated CanaryItem, will be deleted within the amount
         of seconds as specified by the default `removel_time` after
         accessing the resource.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, identifier):

        user = request.user
        canary = user.retrieve_user_canary(identifier)

        if not canary.canary_doc:
            raise NotFound(detail=f"{canary} already downloaded")

        response = Response()
        response.status_code = status.HTTP_200_OK
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = (f"attachment; "
                                           f"filename={canary.filename}")
        response['X-Accel-Redirect'] = f"/docs/{canary.filename}"

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        job = AsynchronousDelete(canary, defset.removal_time)
        enqueue(job.run)

        return response
