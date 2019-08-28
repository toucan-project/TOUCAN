from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from canary_log_api.models import CanaryLogItem
from canary_log_api.serializers import LogItemsSerializer


class ViewLog(APIView):

    """
    Authenticated view for retrieving log related items

    get: Retrieve all log items that were created.
    """

    permission_classes = (IsAuthenticated,)

    def get(self, request):

        logs = CanaryLogItem.get_log_messages()
        many = True if len(logs) > 1 else False

        if many is False:
            logs = logs[0]

        serialized = LogItemsSerializer(logs, many=many)

        return Response(serialized.data, status=status.HTTP_200_OK)
