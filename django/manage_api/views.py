from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from alert_api.models import MimiAlertItem, SampleItem

from manage_api.models import ExternalAPISetting

from manage_api.serializers import AddUserSerializer
from manage_api.serializers import DeleteUserSerializer
from manage_api.serializers import UserObjectSerializer
from manage_api.serializers import TriggerItemSerializer
from manage_api.serializers import AddTriggerItemSerializer
from manage_api.serializers import DownloadSampleSerializer
from manage_api.serializers import SysmonAlertItemSerializer
from manage_api.serializers import UpdateTriggerItemSerializer
from manage_api.serializers import ExternalAPISettingSerializer
from manage_api.serializers import AddExternalAPISettingSerializer
from manage_api.serializers import SysmonAlertDetailedItemSerializer


class SysmonAlertItems(APIView):

    """
    Authenticated class responsible for obtaining SysmonAlertItems

    get: Retrieve one or multiple MimiAlertItem details.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, id=None):

        if id:
            alerts = MimiAlertItem.get_detailed_alert(id)
            serialized = SysmonAlertDetailedItemSerializer(alerts, many=True)

        else:
            alerts = MimiAlertItem.get_all_alerts()
            serialized = SysmonAlertItemSerializer(alerts, many=True)

        return Response(serialized.data, status=status.HTTP_200_OK)


class TriggerItem(APIView):

    """
    Authenticated class responsible for retrieving, deletion and creation of
    trigger items.

    get: Obtain a trigger item by id.

    put: Create a trigger item.

    delete: Remove a trigger item by id.

    patch: Update a trigger's details.

    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, id=None):

        user = request.user

        if id:
            items = user.get_trigger_for_user(id)
            serialized = TriggerItemSerializer(items)

        else:

            items = user.get_all_triggers_for_user()
            serialized = TriggerItemSerializer(items, many=True)

        return Response(serialized.data, status=status.HTTP_200_OK)

    def put(self, request, id=None):

        user = request.user

        serializer = AddTriggerItemSerializer(data=request.data)
        serializer.is_valid()

        identifier = serializer.validated_data.get('identifier')
        sms = serializer.validated_data.get('sms', False)
        email = serializer.validated_data.get('email', False)

        user.create_trigger_for_user(sms, email, identifier)

        return Response(status=status.HTTP_200_OK)

    def patch(self, request, id):

        user = request.user

        serializer = UpdateTriggerItemSerializer(data=request.data)
        serializer.is_valid()

        identifier = serializer.validated_data.get('identifier')
        sms = serializer.validated_data.get('sms', False)
        email = serializer.validated_data.get('email', False)

        user.update_user_trigger_object(sms, email, identifier)

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, id):
        user = request.user

        user.delete_trigger_for_user(id)

        return Response("Trigger deleted", status=status.HTTP_200_OK)


class UserItem(APIView):

    """
    Authenticated class responsible for displaying current user details.

    get: Get details from current logged-in user.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request):

        content = {
            'user': request.user.username,
            'email': request.user.email,
            'phonenumber': request.user.phonenumber,
            'token': request.auth.key
        }

        return Response(content)


class UserItems(APIView):

    """
    Authenticated class responsible for creation / viewing of the application's
    users. Requires superuser privileges.

    get: Obtain all the application's users.

    put: Create a new user.

    delete: Delete a user.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request):

        user = request.user

        users = user.get_all_user_objects()
        serialized = UserObjectSerializer(users, many=True)

        return Response(serialized.data)

    def put(self, request):

        user = request.user

        serializer = AddUserSerializer(data=request.data)
        serializer.is_valid()

        email = serializer.validated_data.get('email')
        username = serializer.validated_data.get('username')
        phonenumber = serializer.validated_data.get('phonenumber')
        password = serializer.validated_data.get('password')

        new_user = user.create_new_user(username, email, phonenumber, password)

        content = {'token': new_user.auth_token.key}

        return Response(content, status=status.HTTP_200_OK)

    def delete(self, request):

        user = request.user

        serializer = DeleteUserSerializer(data=request.data)
        serializer.is_valid()

        username = serializer.validated_data.get('username')
        user.delete_user_with_username(username)

        return Response("User deleted!", status=status.HTTP_200_OK)


class DownloadItem(APIView):

    """
    Authenticated class responsible for downloading sample items.

    get: Obtain the sample item via md5.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request, md5):

        # add md5, so serializer can validate
        request.data['md5'] = md5
        serializer = DownloadSampleSerializer(data=request.data)
        serializer.is_valid()

        md5 = serializer.validated_data.get('md5')
        sample = SampleItem.retrieve_sample(md5)

        response = Response()
        response.status_code = status.HTTP_200_OK
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = (f"attachment; "
                                           f"filename={sample.filename}")
        response['X-Accel-Redirect'] = f"/samples/{sample.filename}"

        return response


class AddExternalAPISetting(APIView):

    """
    Authenticated class for managing ExternalAPI settings. These can be used
    to programatically add new API features.

    get: Get all ExternalAPISettings

    put: Create a new ExternalAPISetting.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        items = ExternalAPISetting.objects.all()
        serialized = ExternalAPISettingSerializer(items, many=True)

        return Response(serialized.data, status=status.HTTP_200_OK)

    def put(self, request):

        serializer = AddExternalAPISettingSerializer(data=request.data)
        serializer.is_valid()

        ExternalAPISetting.create_object(serializer.validated_data)

        return Response(status=status.HTTP_200_OK)
