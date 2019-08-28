from rest_framework import serializers

from alert_api.models import MimiAlertItem

from manage_api.models import User, Trigger
from manage_api.models import ExternalAPISetting

from alert_api.validators import hash_valid_validator

from manage_api.validators import username_taken_validator
from manage_api.validators import username_delete_validator
from manage_api.validators import identifier_exists_validator
from manage_api.validators import api_cred_validator, identifier_known_validator


class UpdateTriggerItemSerializer(serializers.Serializer):

    identifier = serializers.CharField(max_length=50, validators=[
                                        identifier_exists_validator
                                        ])
    email = serializers.BooleanField(default=False)
    sms = serializers.BooleanField(default=False)


class AddTriggerItemSerializer(serializers.Serializer):

    identifier = serializers.CharField(max_length=50, validators=[
                                        identifier_known_validator
                                        ])
    email = serializers.BooleanField(default=False)
    sms = serializers.BooleanField(default=False)


class DeleteUserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=15,
                                     validators=[username_delete_validator])


class AddUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=15,
                                     validators=[username_taken_validator])
    phonenumber = serializers.CharField(max_length=13)
    password = serializers.CharField()


class ExternalAPICredentialSerializer(serializers.Serializer):
    api_user = serializers.CharField(max_length=50, required=False)
    api_password = serializers.CharField(max_length=100, required=False)
    api_key = serializers.CharField(max_length=64, required=False)


class AddExternalAPISettingSerializer(serializers.Serializer):
    api_name = serializers.CharField(max_length=32)
    api_cred = ExternalAPICredentialSerializer(validators=[api_cred_validator])


class ExternalAPISettingSerializer(serializers.ModelSerializer):

    class Meta:
        model = ExternalAPISetting
        fields = (
           'id',
           'api_name',
           'api_user',
           'api_password',
           'api_key',
        )


class SysmonAlertItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = MimiAlertItem
        fields = (
            'id',
            'date',
            'source',
            'target',
        )


class SysmonAlertDetailedItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = MimiAlertItem
        fields = '__all__'


class TriggerItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = Trigger
        fields = (
            'id',
            'canary',
            'mimialert',
            'sms',
            'email')


class UserObjectSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            'username',
            'email',
            'phonenumber',
            'is_superuser',
            'auth_token')


class DownloadSampleSerializer(serializers.Serializer):
    md5 = serializers.CharField(max_length=32,
                                validators=[hash_valid_validator])
