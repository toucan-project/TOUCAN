from rest_framework import serializers


class UploadedFileSerializer(serializers.Serializer):

    # 5 megabytes is the current max_length
    file = serializers.FileField(max_length=50000000, required=True,
                                 allow_empty_file=False)
    trigger = serializers.CharField(max_length=4)
    protocol = serializers.CharField(allow_blank=True, max_length=5,
                                     required=False)
    domain = serializers.CharField(allow_blank=True, max_length=50,
                                   required=False)
    location = serializers.CharField(max_length=50)
    dns = serializers.NullBooleanField(required=False)
