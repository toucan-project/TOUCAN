from django.db import models
from django.apps import apps
from django.utils import timezone
from django.db.transaction import atomic

from manage_api.models import User

from canary_utils.lib.util import return_stack_trace


class CanaryLogItem(models.Model):

    date = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL,  null=True)
    canary = models.ForeignKey('canary_files.CanaryItem', null=True,
                               on_delete=models.SET_NULL)
    msg = models.CharField(max_length=4096)
    stacktrace = models.TextField(null=True)

    @classmethod
    def log_message(cls, user, canary, msg):

        stacktrace = return_stack_trace(msg)

        with atomic():
            return cls.objects.create(user=user, canary=canary, msg=msg,
                                      stacktrace=stacktrace)

    @classmethod
    def log_message_id(cls, user, identifier, msg):

        CanaryItem = apps.get_model('canary_files.CanaryItem')
        canary = CanaryItem.objects.filter(identifier=identifier)

        if not canary.exists():
            canary = None

        else:
            canary = canary[0]

        cls.log_message(user, canary, msg)

    @classmethod
    def get_log_messages(cls):
        return cls.objects.all()

    def save(self, *args, **kwargs):
        self.date = timezone.now()
        super(CanaryLogItem, self).save(*args, **kwargs)
