from django.apps import apps
from rest_framework.exceptions import ValidationError

from manage_api.models import Trigger


def api_cred_validator(api_cred):

    if 'api_key' in api_cred.keys():

        if 'api_user' in api_cred.keys() or 'api_password' in api_cred.keys():
            raise ValidationError("Supply a key or user/password "
                                  "combination")

    elif ('api_user' in api_cred.keys() and 'api_password'
            not in api_cred.keys()):
        raise ValidationError("Please supply a password")

    elif ('api_password' in api_cred.keys() and 'api_user'
            not in api_cred.keys()):
        raise ValidationError("Please supply a username")

    elif ('api_key' not in api_cred.keys() and 'api_password'
            not in api_cred.keys() and 'api_user' not in api_cred.keys()):
        raise ValidationError("Invalid request")


def username_taken_validator(username):

    User = apps.get_model('manage_api', 'User')

    if User.objects.filter(username=username).exists():
        raise ValidationError("The username is taken")


def username_delete_validator(username):

    User = apps.get_model('manage_api', 'User')

    if not User.objects.filter(username=username).exists():
        raise ValidationError("User does not exists")


def identifier_known_validator(identifier):

    if Trigger.objects.filter(trigger_identifier=identifier).exists():
        return ValidationError("Identifier already known.")


def identifier_exists_validator(identifier):

    if not Trigger.objects.filter(trigger_identifier=identifier).exists():
        return ValidationError("Identifier not found")
