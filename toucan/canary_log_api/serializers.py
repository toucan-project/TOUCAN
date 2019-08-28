from rest_framework import serializers

from canary_log_api.models import CanaryLogItem


class LogItemsSerializer(serializers.ModelSerializer):

    class Meta:
        model = CanaryLogItem
        fields = '__all__'

    def to_representation(self, instance):

        values = super(LogItemsSerializer, self).to_representation(instance)
        values['user'] = instance.user.username
        values['canary'] = instance.canary.identifier

        return values
