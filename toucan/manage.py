#!/usr/bin/env python
import os
import sys
from tempfile import gettempdir
from os.path import exists

from django.conf import settings


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'canary_api.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    if 'createsuperuser' in sys.argv:
        # Redirect user to the custom command
        index = sys.argv.index('createsuperuser')
        sys.argv[index] = 'createcanaryadmin'

    elif 'test' in sys.argv:
        dirs = ['docs', 'samples']

        tmpdirs = ['.deploy_cache', '.deploy_cache/dns', '.deploy_cache/smb',
                   '.deploy_cache/http']

        if not exists(settings.MEDIA_ROOT):
            os.mkdir(settings.MEDIA_ROOT)

        for suffix in dirs:

            directory = f"{settings.MEDIA_ROOT}/{suffix}"

            if not exists(directory):
                os.mkdir(directory)

        for suffix in tmpdirs:

            directory = f"{gettempdir()}/{suffix}"

            if not exists(directory):
                os.mkdir(directory)

    execute_from_command_line(sys.argv)
