from django.db import models
from django.apps import apps
from django.utils import timezone
from django.db.transaction import atomic
from django.contrib.auth.models import AbstractUser

from rest_framework.authtoken.models import Token

from rest_framework.exceptions import PermissionDenied
from rest_framework.exceptions import ValidationError, NotFound


class User(AbstractUser):

    username = models.CharField(max_length=50, unique=True,
                                null=False, blank=False)
    email = models.EmailField(unique=True, null=False, blank=False)
    phonenumber = models.CharField(max_length=13, null=False, blank=False)

    @classmethod
    def create_user(cls, username, password, email, phonenumber):

        with atomic():
            user = cls.objects.create_user(username, password=password,
                                           email=email, phonenumber=phonenumber)
            Token.objects.create(user=user)

        return user

    @classmethod
    def is_username_taken(cls, username):
        return cls.objects.filter(username=username).exists()

    @property
    def api_token(self):
        token = Token.objects.filter(user=self)

        if token.exists():
            return token[0].key

        else:
            return 'N/A'

    def create_canary_as_user(self, file, trigger, location, dns, protocol,
                              domain):
        CanaryItem = apps.get_model('canary_files.CanaryItem')

        return CanaryItem.create_canary(self, file, trigger, location, dns,
                                        protocol, domain)

    def retrieve_user_canary(self, identifier):
        CanaryItem = apps.get_model('canary_files.CanaryItem')

        return CanaryItem.retrieve_canary(identifier, self)

    def get_trigger_for_user(self, id):
        return Trigger.get_trigger_for_user(self, id)

    def get_all_triggers_for_user(self):
        return Trigger.get_all_triggers_for_user(self)

    def create_trigger_for_user(self, sms, email, identifier):
        return Trigger.create_object(self, sms, email, identifier)

    def update_user_trigger_object(self, sms, email, identifier):
        return Trigger.update_object(self, sms, email, identifier)

    def delete_trigger_for_user(self, id):
        return Trigger.delete_trigger_for_user(self, id)

    def get_all_user_objects(self):

        self._is_superuser()

        return User.objects.all()

    def create_new_user(self, username, email, phonenumber, password):

        self._is_superuser()

        return User.create_user(username, email, phonenumber, password)

    def delete_user_with_username(self, username):

        self._is_superuser()

        user = User.objects.get(username=username)
        user.delete()

    def _is_superuser(self):

        if not self.is_superuser:
            raise PermissionDenied


class SMTPSetting(models.Model):
    smtp_server = models.CharField(max_length=255)
    smtp_port = models.IntegerField()
    ssl = models.BooleanField()
    subject = models.CharField(max_length=255)
    sender = models.CharField(max_length=255)
    default_recv = models.CharField(max_length=255)


class SMSSetting(models.Model):
    sms_server = models.CharField(max_length=255)
    sms_endpoint = models.CharField(max_length=255)
    sms_client = models.CharField(max_length=255)
    sms_secret = models.CharField(max_length=255)


class DefaultSetting(models.Model):
    setting_name = models.CharField(max_length=50, default='Defaults',
                                    unique=True)
    domain_name = models.CharField(max_length=255,
                                   default='domain.subdomain.example')
    protocol = models.CharField(max_length=5, default='http')
    dns = models.BooleanField(default=True)
    smb_root = models.CharField(max_length=255)
    web_root = models.CharField(max_length=255)
    deploy_root = models.CharField(max_length=255)
    deploy_cache = models.CharField(max_length=255)
    canary_path = models.CharField(max_length=255)
    smb_canary_path = models.CharField(max_length=255)
    nginx_domain = models.CharField(max_length=63)
    secret_key = models.CharField(max_length=2048)
    removal_time = models.IntegerField()
    resolver_ip = models.CharField(max_length=15)
    source = models.CharField(max_length=255)


class ExternalAPISetting(models.Model):
    api_name = models.CharField(max_length=32, null=False)
    api_user = models.CharField(max_length=50, null=True)
    api_password = models.CharField(max_length=100, null=True)
    api_key = models.CharField(max_length=64, null=True)

    @classmethod
    def create_object(cls, args):

        # create one non-nested dict
        api_cred = args.pop('api_cred')
        args = {**args, **api_cred}

        with atomic():
            return cls.objects.create(**args)

    @classmethod
    def get_api_item_by_name(cls, api_name):

        if not cls._api_item_exists(cls, api_name):
            raise ValidationError('Item does not exist')

        return cls.objects.get(api_name=api_name)

    def _api_item_exists(self, api_name):
        return self.objects.filter(api_name=api_name).exists()


class TriggerContactDetails(object):
    sms = set()
    email = set()


class Trigger(models.Model):

    date = models.DateTimeField()
    user = models.ManyToManyField(User)
    canary = models.ForeignKey('canary_files.CanaryItem',
                               on_delete=models.CASCADE, blank=True, null=True)
    mimialert = models.ForeignKey('alert_api.MimiAlertItem',
                                  on_delete=models.CASCADE, blank=True,
                                  null=True)
    trigger_identifier = models.CharField(max_length=255, unique=True)
    sms = models.BooleanField()
    email = models.BooleanField()

    @classmethod
    def create_object(cls, user, sms, email, identifier):

        canary, mimialert = cls._get_alert_values(identifier)

        with atomic():
            trigger = Trigger.objects.create(canary=canary,
                                             mimialert=mimialert,
                                             sms=sms, email=email,
                                             trigger_identifier=identifier)
            trigger.user.set([user, ])
            trigger.save()

        return trigger

    @classmethod
    def update_object(cls, user, sms, email, identifier):

        trigger = Trigger.objects.filter(user=user,
                                         trigger_identifier=identifier)

        if trigger.exists():

            trigger = Trigger.objects.get(user=user,
                                          trigger_identifier=identifier)

            with atomic():
                trigger.sms = sms
                trigger.email = email
                trigger.save()

    @classmethod
    def get_trigger_items_for_identifier(cls, identifier):
        items = cls._get_identifier_trigger_item(cls, identifier)

        if items.count() > 0:
            items = cls._get_trigger_contact_items(cls, items)

        else:
            return False

        return items

    @classmethod
    def get_all_triggers_for_user(cls, user):

        if user.is_superuser:
            return Trigger.objects.all()

        else:
            return Trigger.objects.filter(user=user)

    @classmethod
    def get_trigger_for_user(cls, user, id):
        if not cls._trigger_exists(cls, user, id):
            raise NotFound("Trigger does not exist!")

        return Trigger.objects.get(user=user, id=id)

    @classmethod
    def delete_trigger_for_user(cls, user, id):
        if not cls._trigger_exists(cls, user, id):
            raise ValidationError("Trigger does not exist!")

        Trigger.objects.filter(user=user, id=id).delete()
        # delete it remotely too

    def save(self, *args, **kwargs):

        if self.canary:
            self.trigger_identifier = self.canary.identifier

        elif self.mimialert:
            self.trigger_identifier = self.mimialert.machinename

        self.date = timezone.now()
        super(Trigger, self).save(*args, **kwargs)

    def _get_alert_values(identifier):

        MimiAlertItem = apps.get_model('alert_api.MimiAlertItem')
        CanaryItem = apps.get_model('canary_files.CanaryItem')

        mimialert = MimiAlertItem.objects.filter(
                                            machinename=identifier
                                        ).exists()
        canary = CanaryItem.objects.filter(identifier=identifier).exists()

        if not mimialert and not canary:
            raise ValidationError('Identifier unknown')

        if canary:
            canary = CanaryItem.objects.get(identifier=identifier)

        else:
            canary = None

        if mimialert:
            mimialert = MimiAlertItem.objects.get(machinename=identifier)

        else:
            mimialert = None

        return canary, mimialert

    def _trigger_exists(self, user, id):
        return Trigger.objects.filter(user=user, id=id).exists()

    def _get_identifier_trigger_item(self, identifier):
        return Trigger.objects.filter(trigger_identifier=identifier)

    def _get_mail_address_user_set(self, user_set):

        mail_addresses = set()

        for user in user_set.all():

            if user.email:
                mail_addresses.add(user.email)

        if not mail_addresses:
            return False

        return mail_addresses

    def _get_phonenumber_user_set(self, user_set):

        phonenumbers = set()

        for user in user_set.all():

            if user.phonenumber:
                phonenumbers.add(user.phonenumber)

        if not phonenumbers:
            return False

        return phonenumbers

    def _get_trigger_contact_items(self, items):

        trigger = TriggerContactDetails()

        for item in items:

            if item.sms:
                phonenumbers = self._get_phonenumber_user_set(self, item.user)

                if phonenumbers:
                    trigger.sms = phonenumbers

            if item.email:

                mail_addresses = self._get_mail_address_user_set(self,
                                                                 item.user)

                if mail_addresses:
                    trigger.email = mail_addresses

        return trigger
