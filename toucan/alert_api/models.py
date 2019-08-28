from hashlib import sha256
from os.path import basename
from datetime import datetime

from django.db import models
from django.urls import reverse
from django.dispatch import receiver
from django.db.transaction import atomic
from django.db.models.signals import post_delete

from rest_framework.exceptions import ValidationError

from ssdeep import hash

from canary_utils.lib.sms import SMS
from canary_utils.lib.smtp import SMTP


class CanaryAlertItem(models.Model):

    date = models.DateTimeField()
    identifier = models.CharField(max_length=50)
    canary_type = models.CharField(max_length=4)
    location = models.CharField(max_length=50)
    ip = models.CharField(max_length=15)
    node = models.CharField(max_length=10, blank=True)
    user_agent = models.CharField(max_length=250, blank=True)
    smb_loc = models.CharField(max_length=50, blank=True)
    filename = models.CharField(max_length=255, blank=True)

    @classmethod
    def create_object(cls, **kwargs):

        with atomic():
            obj = cls.objects.create(**kwargs)

        cls._trigger_alert(cls, obj, **kwargs)

        return obj

    def _trigger_alert(cls, obj, **kwargs):

        if obj.canary_type == 'unc':
            subject = 'UNC trigger'

        elif obj.canary_type == 'dns':
            subject = 'DNS trigger'

        elif 'http' in obj.canary_type:
            subject = 'HTTP trigger'

        filename = False if not obj.filename else obj.filename
        user_agent = False if not obj.user_agent else obj.user_agent
        node = False if not obj.node else obj.node

        smtp = SMTP()
        smtp.send_mail(obj.date, obj.identifier,
                       subject, obj.location,
                       obj.ip, node, ua=user_agent,
                       filename=filename)

        sms = SMS()
        sms.send_sms(obj.identifier, obj.date,
                     obj.location,
                     subject, obj.ip)


class MimiAlertItem(models.Model):

    machinename = models.CharField(max_length=50)
    sid = models.CharField(max_length=20)
    pid = models.IntegerField()
    date = models.DateTimeField()
    source = models.CharField(max_length=255)
    md5 = models.CharField(max_length=32)
    sha1 = models.CharField(max_length=40)
    target = models.CharField(max_length=255)
    accessMask = models.CharField(max_length=4)
    stack = models.CharField(max_length=999)

    @classmethod
    def create_object(cls, rip, logmon):

        with atomic():
            alert = cls.objects.create(**logmon)

        cls._trigger_alert(cls, logmon['machinename'], rip, logmon['source'])

        return alert

    @classmethod
    def get_all_alerts(cls):
        return cls.objects.all()

    @classmethod
    def get_detailed_alert(cls, id):
        return cls.objects.filter(id=id)

    def _trigger_alert(self, machinename, rip, source):

        # check if machinename is set, and a trigger has been added
        # if no machine trigger has been enabled, sms / email all users
        s = SMS()
        s.send_sms(machinename, datetime.today(), 'LSASS',
                   source, rip)

        smtp = SMTP()
        smtp.send_mail(datetime.today(), machinename, 'LSASS',
                       machinename, rip, 'RF')

    def __str__(self):
        return self.machinename


class SampleItem(models.Model):

    md5 = models.CharField(max_length=32, unique=True)
    sha1 = models.CharField(max_length=40, unique=True)
    sha256 = models.CharField(max_length=64, unique=True)
    ssdeep = models.CharField(max_length=148)
    sample = models.FileField(upload_to='samples')

    @classmethod
    def save_sample(cls, md5, sample):

        if not cls.sample_exists(md5):
            sha256, ssdeep = cls._retrieve_file_hashes(cls, sample)

            with atomic():
                sample = cls.objects.create(md5=md5, sample=sample, sha256=sha256,
                                            ssdeep=ssdeep)

            return sample

    @classmethod
    def retrieve_sample(cls, md5):

        if cls.sample_exists(md5):
            return cls.objects.get(md5=md5)

        else:
            raise ValidationError('Identifier not known')

    @classmethod
    def sample_exists(cls, md5):
        return cls.objects.filter(md5=md5).exists()

    @property
    def filename(self):
        return basename(self.sample.file.name)

    @classmethod
    def get_related_alert_items_as_url(cls, md5):

        items = MimiAlertItem.objects.filter(md5=md5)

        if not items.exists():
            return 'N/A'

        machinenames = cls._get_unique_machinenames(cls, items)
        url_items = cls._generate_item_url(cls, machinenames)

        if items.count() > 1:
            urls = ', '.join(url_items)

        else:
            urls = ''.join(url_items)

        return urls

    def _generate_item_url(self, items):

        url_items = []
        url_item = '<a href="{}?machinename={}">{}</a>'
        url = reverse('admin:alert_api_mimialertitem_changelist')

        for item in items:
            url_items.append(url_item.format(url, item, item))

        return url_items

    def _get_unique_machinenames(self, items):
        machinenames = set()

        for item in items:
            machinenames.add(item.machinename)

        return machinenames

    def _retrieve_file_hashes(self, sample):

        _sha256 = sha256()

        buf = sample.read(65535)

        while len(buf) > 0:
            _sha256.update(buf)
            buf = sample.read(65535)

        _ssdeep = hash(sample.read())

        return _ssdeep, _sha256.hexdigest()


@receiver(post_delete, sender=SampleItem)
def sample_delete(sender, instance, **kwargs):

    if instance.sample.file.readable():
        instance.sample.delete()
