#!/usr/bin/env python3
from canary_utils.lib.daemon import cmdServer
from django.core.management.base import BaseCommand


class Daemon():

    def __init__(self):
        cmdServer()


class Command(BaseCommand):

    help = "Start the canary daemon"

    def handle(self, **options):
        Daemon()
