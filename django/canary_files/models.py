from sys import argv
from os.path import basename
from tempfile import NamedTemporaryFile

from django.apps import apps
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.dispatch import receiver
from django.db.transaction import atomic
from django.db.models.signals import pre_delete, post_delete, post_save

from django_rq import enqueue

from rest_framework.exceptions import NotFound, ValidationError

from canary_api.settings import MEDIA_ROOT

from canary_utils.lib.asynctasks import AsynchronousDeploy
from canary_utils.lib.asynctasks import AsynchronousDeleteCanary

from alert_api.models import CanaryAlertItem
from canary_log_api.models import CanaryLogItem

from canary_utils.canary import generate_canary, make_canary
from canary_utils.canary import populate_canary, return_file

from canary_utils.lib.util import write_canary_file
from canary_utils.lib.util import write_named_string, remove_deployment_item

from manage_api.models import User, Trigger, DefaultSetting


class CanaryItem(models.Model):

    EMAIL_TRIGGER = 'email'
    SMS_TRIGGER = 'sms'
    BOTH_TRIGGER = 'all'

    TRIGGER_TYPE_CHOICES = ((EMAIL_TRIGGER, 'email'), (SMS_TRIGGER, 'sms'),
                            (BOTH_TRIGGER, 'all'))

    identifier = models.CharField(max_length=50, unique=True)
    trigger_type = models.CharField(max_length=4, choices=TRIGGER_TYPE_CHOICES)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    canary_doc = models.FileField(upload_to='docs')
    protocol = models.CharField(max_length=5)
    location = models.CharField(max_length=50)
    domain = models.CharField(max_length=50)
    dns = models.NullBooleanField()
    canary_filename = models.CharField(max_length=255)
    directory = models.CharField(max_length=255)

    @classmethod
    def create_canary(cls, user, file, trigger, location, dns,
                      protocol, domain):

        if not user.phonenumber:
            raise ValidationError("Please setup a phonenumber in your account")

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        if not protocol:
            protocol = defset.protocol

        if isinstance(dns, None.__class__):
            domain = defset.domain_name

        if isinstance(dns, None.__class__):
            dns = defset.dns

        identifier = generate_canary()

        gen_canary, canary_filename, c_string = cls._return_canary_file(
                                                cls, file, identifier, protocol,
                                                domain, dns, location, defset
                                                )

        with atomic():
            canary = cls.objects.create(canary_doc=gen_canary, dns=dns,
                                        identifier=identifier, added_by=user,
                                        trigger_type=trigger, domain=domain,
                                        canary_filename=canary_filename,
                                        protocol=protocol, location=location)

            Deployment = apps.get_model('canary_files.Deployment')
            Deployment.create_deployment(canary, c_string)

        if canary:
            cls._add_trigger_item_for_canary(cls, user, identifier, trigger)

        if dns:
            if not write_named_string(identifier, defset.deploy_root, canary,
                                      defset.resolver_ip):
                raise ValidationError("Cannot write named config")

        CanaryLogItem.log_message(user, canary, 'canary deployment started')

        return canary

    def redeploy_remote_files(self):

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        task = AsynchronousDeploy(defset, self, defset.source)
        enqueue(task.run)

    def remove_remote_files(self, deployment):

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        task = AsynchronousDeleteCanary(deployment, defset, self)
        enqueue(task.run)

    def deploy_remote_files(self):

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        task = AsynchronousDeploy(defset, self, defset.source)
        enqueue(task.run)

    @property
    def filename(self):
        return basename(self.canary_doc.file.name)

    @classmethod
    def canary_exists(cls, identifier):
        return cls.objects.filter(identifier=identifier).exists()

    @classmethod
    def retrieve_canary(cls, identifier, user):

        if cls.canary_exists(identifier):
            canary = cls.objects.get(added_by=user, identifier=identifier)
            CanaryLogItem.log_message(user, canary, 'canary downloaded')

            return canary

        else:
            raise NotFound('Canary not found')

    @classmethod
    def get_related_alert_items(self, obj):

        items = CanaryAlertItem.objects.filter(identifier=obj.identifier)

        if not items.exists():
            return 'N/A'

        url = reverse('admin:alert_api_canaryalertitem_changelist')
        url_item = '<a href="{}?identifier={}">{}</a>'

        return url_item.format(url, obj.identifier, obj.identifier)

    def _return_canary_file(self, file, identifier, protocol,
                            domain, dns, location, defset):

        extension, filename, ctype = return_file(file.name, protocol)
        outfile = f"{MEDIA_ROOT}/docs/{identifier}.{extension}"
        canary = populate_canary(identifier, protocol, domain, dns, filename,
                                 False, defset)

        # Add exception handling
        canary_doc = make_canary(file, outfile, extension, False, canary, False,
                                 False)

        self.cache = NamedTemporaryFile(prefix=defset.deploy_cache,
                                        delete=False).name

        ret = write_canary_file(identifier, filename, location,
                                defset.deploy_root, ctype,
                                extension, defset.canary_path,
                                False, self.cache)

        if not ret:
            raise ValidationError('Could not write canary file.')

        return canary_doc, filename, ret

    def _add_trigger_item_for_canary(self, user, identifier, trigger):

        if trigger == 'all':
            sms = True
            email = True

        elif trigger == 'sms':
            sms = True
            email = False

        elif trigger == 'email':
            sms = False
            email = True

        with atomic():
            return Trigger.create_object(user, sms, email, identifier)

    def __str__(self):
        return self.identifier


class Deployment(models.Model):

    FAIL_STATE = 'failed'
    DONE_STATE = 'completed'
    PENDING_STATE = 'pending'

    STATE_TYPES = ((FAIL_STATE, 'failed'), (DONE_STATE, 'completed'),
                   (PENDING_STATE, 'pending'))

    date = models.DateTimeField()
    canary = models.ForeignKey(CanaryItem, on_delete=models.CASCADE)
    canary_string = models.CharField(max_length=512)
    dest = models.CharField(max_length=255)
    state = models.CharField(max_length=9, choices=STATE_TYPES)
    reason = models.CharField(max_length=4096)

    @classmethod
    def create_deployment(cls, canary, canary_string):

        with atomic():
            cls.objects.create(canary=canary, canary_string=canary_string)

    @classmethod
    def full_deployment_fail(cls, reason, canary):

        deployments = cls.objects.filter(canary=canary)

        for item in deployments:
            item.reason = reason
            item.state = 'failed'
            item.save()

    def finished_deployment(self, dest):

        with atomic():
            self.reason = ''
            self.state = 'completed'
            self.dest = dest
            self.save()

        remove_deployment_item(self.canary_string)

    def failed_deployment(self, reason):

        with atomic():
            self.reason = reason
            self.state = 'failed'
            self.save()

    def pending_deployment(self):

        with atomic():
            self.state = 'pending'
            self.save()

    def save(self, *args, **kwargs):
        self.date = timezone.now()
        super(Deployment, self).save(*args, **kwargs)

    def __str__(self):
        return self.canary.identifier


@receiver(pre_delete, sender=CanaryItem)
def remote_file_delete(sender, instance, **kwargs):

    # before deletion, we need to get the datas
    deployment = Deployment.objects.filter(canary=instance)
    instance.remove_remote_files(deployment)


@receiver(post_delete, sender=CanaryItem)
def canary_delete(sender, instance, **kwargs):

    if instance.canary_doc:

        if instance.canary_doc.file.readable():
            instance.canary_doc.delete()


@receiver(post_save, sender=CanaryItem)
def canary_deploy(sender, instance, **kwargs):

    if 'test' not in argv:  # pragma: no cover, is tested separately

        # if there is no document, it means we are here due to the post_delete
        if instance.canary_doc:
            enqueue(instance.deploy_remote_files)
