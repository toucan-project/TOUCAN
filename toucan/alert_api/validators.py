from string import hexdigits
from magic import from_buffer

from rest_framework.exceptions import ValidationError, NotFound

from alert_api.models import CanaryAlertItem


def hash_valid_validator(hash):

    if not all(b in hexdigits for b in hash):
        raise ValidationError("Not a valid hash")


def is_existing_canary_pk(id):

    if not CanaryAlertItem.objects.filter(pk=id).exists():
        raise NotFound("Unknown id")


def content_type_validator(content_type):

    if content_type != 'application/octet-stream':
        raise ValidationError()


def uploaded_file_validator(file):

    mime_type = from_buffer(file.read(), mime=True)
    file.seek(0)

    if mime_type != 'application/x-dosexec':
        raise ValidationError('Format not supported')
