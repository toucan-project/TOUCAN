#!/usr/bin/env python3
from os import access, R_OK, W_OK

from django.core.management.base import BaseCommand

from canary_utils.lib.util import print_error


class Command(BaseCommand):

    help = "Deactivate BIND zone db entries."

    def add_arguments(self, parser):
        parser.add_argument('--identifier', type=str,
                            help='Canary identifier.')
        parser.add_argument('--path', type=str,
                            help='Path to zone db.')

    def handle(self, **options):
        identifier = options.get('identifier')
        path = options.get('path')

        if not identifier and not path:
            print_error('--- please specify identifier and path')

            return False

        zones = self._read_zone_file(path)

        if not zones:
            return False

        zones = self._remove_dns_lines_from_file_path(zones, identifier)

        self._write_new_dns_file(zones, path)

    def _write_new_dns_file(self, zones, path):

        if not access(path, W_OK):
            print_error(f"--- cannot open {path} for writing")

            return False

        with open(path, 'w+') as fd:
            fd.writelines(zones)

    def _remove_dns_lines_from_file_path(self, zones, identifier):

        for i, zone in enumerate(zones):

            if identifier in zone:
                break

        start = i - 1
        index = i
        end = i + 1

        indices = [start, index, end]

        new_zones = []

        for i, zone in enumerate(zones):

            if i not in indices:
                new_zones.append(zone)

        return new_zones

    def _read_zone_file(self, path):

        if not access(path, R_OK):
            print_error(f"--- cannot access {path}")
            return False

        with open(path, 'r') as fd:
            zones = fd.readlines()

        return zones
