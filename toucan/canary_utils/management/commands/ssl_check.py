#!/usr/bin/env python3
from os import access, R_OK

from django.core.management.base import BaseCommand

from canary_log_api.models import CanaryLogItem
from canary_utils.lib.util import SSLVerify, print_error


class Command(BaseCommand):

    help = "Check certificate validity."

    def add_arguments(self, parser):
        parser.add_argument('-l', '--local-certificate', type=str,
                            help='Path to a local certificate.')
        parser.add_argument('--ip', type=str,
                            help='Remote ip for certificate check.')
        parser.add_argument('--port', type=int,
                            help='Remote port where SSL server is running on.')

    def handle(self, **options):
        ip = options.get('ip')
        port = options.get('port')
        local = options.get('local_certificate')

        if not ip and not port and not local:
            print_error('--- Please specify an argument')
            return False

        if ip and port and local:
            print_error('--- Cannot specify ip / port combination and '
                        'local certificate!')
            return False

        if ip and port:
            self._verify_remote_certificates(ip, port)

        if local and access(local, R_OK):
            self._verify_local_certificate(local)

    def _verify_local_certificate(self, local):

        expired, expiring = SSLVerify.is_local_certificate_valid(local)

        if expired:
            msg = f"[SSL WARNING] Certificate {local} is expired!"
            CanaryLogItem.log_message(None, None, msg)

        elif expiring:
            msg = f"[SSL WARNING] Certificate {local} is expiring soon!"
            CanaryLogItem.log_message(None, None, msg)

    def _verify_remote_certificates(self, ip, port):

        expired, expiring = SSLVerify.is_remote_certificate_valid(ip, port)

        if expired:
            msg = f"[SSL WARNING] Certificate at {ip}:{port} is expired!"
            CanaryLogItem.log_message(None, None, msg)

        elif expiring:
            msg = f"[SSL WARNING] Certificate at {ip}:{port} is expiring soon!"
            CanaryLogItem.log_message(None, None, msg)
