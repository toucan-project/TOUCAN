#!/usr/bin/env python3
from cryptography.fernet import Fernet as Crypto

from django.core.management.base import BaseCommand

from canary_api.settings import SECRET_KEY
from manage_api.models import DefaultSetting


class Encrypt():

    def __init__(self, vault_key):

        c = Crypto(SECRET_KEY)

        key = c.encrypt(vault_key.encode('utf-8'))
        defset = DefaultSetting.objects.get(setting_name='Defaults')

        defset.secret_key = key.decode('utf-8')
        defset.save()


class Command(BaseCommand):

    help = "Encrypt vault key with new SECRET"

    def add_arguments(self, parser):
        parser.add_argument('vault_key', type=str)

    def handle(self, **options):

        vault_key = options.get('vault_key')
        Encrypt(vault_key)
