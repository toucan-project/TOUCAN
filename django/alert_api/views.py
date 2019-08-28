from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import FileUploadParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError, NotAuthenticated

from alert_api.models import MimiAlertItem, SampleItem, CanaryAlertItem

from alert_api.serializers import UploadedFileSerializer
from alert_api.serializers import CanaryAlertItemSerializer
from alert_api.serializers import JSONSerializer, GetCanaryAlertItemSerializer


class SysmonIncoming(APIView):

    """
    An unauthenticated API for incoming Sysmon events related to Mimikatz

    put: Create a MimiAlert and return 201 if a sample has not been uploaded,
         200 if a sample exists.
    """

    def put(self, request):

        serializer = JSONSerializer(data=request.data)

        if not serializer.is_valid():
            raise ValidationError('Invalid JSON')

        logmon = serializer.validated_data
        rip = request.META.get('REMOTE_ADDR')

        alert = MimiAlertItem.create_object(rip, dict(logmon))

        if SampleItem.sample_exists(alert.md5):
            status_code = status.HTTP_200_OK

        else:
            status_code = status.HTTP_201_CREATED

        return Response(status=status_code)


class FileItem(APIView):

    """
    An unauthenticated API endpoint for incoming samples.

    put: Create a SampleItem from the incoming binary file.
    """

    # hmmm, an unauthenticated file upload?
    parser_classes = (FileUploadParser,)

    def post(self, request, filename):

        data = self._get_request_data(request.data)

        serializer = UploadedFileSerializer(data=data)

        if not serializer.is_valid():
            raise ValidationError()

        sample = serializer.validated_data.get('file')
        SampleItem.save_sample(filename, sample)

        return Response(status=status.HTTP_200_OK)

    def _get_request_data(self, data):

        return {
                'file': data['file'],
                'content_type': data['file'].content_type
                }


class CanaryAlertItems(APIView):

    """
    Authenticated view for querying triggered alerts.

    get: Get triggered CanaryAlertItem(s)

    delete: Delete a triggered CanaryAlertItem by id, only possible
            with elevated privileges.

    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, id=None):

        if id:
            serializer = GetCanaryAlertItemSerializer(data={'id': id})
            serializer.is_valid()

            id = serializer.validated_data.get('id')
            items = CanaryAlertItem.objects.get(pk=id)

            serialized = CanaryAlertItemSerializer(items)

        else:

            items = CanaryAlertItem.objects.all()
            serialized = CanaryAlertItemSerializer(items, many=True)

        return Response(serialized.data, status=status.HTTP_200_OK)

    def delete(self, request, id):

        if not request.user.is_superuser:
            raise NotAuthenticated("Not allowed to delete this entry")

        serialized = GetCanaryAlertItemSerializer(data={'id': id})
        serialized.is_valid()

        id = serialized.validated_data.get('id')

        item = CanaryAlertItem.objects.get(pk=id)
        item.delete()

        return Response(status=status.HTTP_200_OK)
