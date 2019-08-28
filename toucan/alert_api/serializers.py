from rest_framework import serializers

from alert_api.models import CanaryAlertItem
from alert_api.validators import hash_valid_validator, is_existing_canary_pk
from alert_api.validators import content_type_validator, uploaded_file_validator


class HashSerializer(serializers.Serializer):
    md5 = serializers.CharField(max_length=32,
                                validators=[hash_valid_validator])
    sha1 = serializers.CharField(max_length=40,
                                 validators=[hash_valid_validator])


class JSONSerializer(serializers.Serializer):

    machinename = serializers.CharField(max_length=50)
    sid = serializers.CharField(max_length=20)
    pid = serializers.IntegerField()
    date = serializers.DateTimeField()
    source = serializers.CharField(max_length=255)
    hashes = HashSerializer(source='*')
    target = serializers.CharField(max_length=255)
    accessMask = serializers.CharField(max_length=4)
    stack = serializers.CharField(max_length=999)


class UploadedFileSerializer(serializers.Serializer):

    # 5 megabytes is the current max_length
    file = serializers.FileField(max_length=5000000, required=True,
                                 allow_empty_file=False, validators=[
                                                uploaded_file_validator
                                               ])
    content_type = serializers.CharField(max_length=255, validators=[
                                               content_type_validator
                                              ])


class CanaryAlertItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = CanaryAlertItem
        fields = '__all__'


class GetCanaryAlertItemSerializer(serializers.Serializer):

    id = serializers.IntegerField(validators=[is_existing_canary_pk])
