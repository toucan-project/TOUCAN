#!/usr/bin/env python3
from binascii import Error
from secrets import token_urlsafe, base64

from django.core.management.base import BaseCommand


class GenerateSecret():

    def __init__(self):

        secret = token_urlsafe(32)

        i = 0
        while not self._verify_padding(secret):
            secret += '='
            i += 1

            if i == 2:
                secret = token_urlsafe(32)
                i = 0

        print(secret)

    def _verify_padding(self, secret):

        try:
            base64.b64decode(secret)

        except Error:
            return False

        return secret


class Command(BaseCommand):

    help = "Generate a new secret"

    def handle(self, **options):
        GenerateSecret()
