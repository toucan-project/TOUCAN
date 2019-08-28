from re import fullmatch
from django.contrib.auth.management.commands import createsuperuser

from rest_framework.authtoken.models import Token


class Command(createsuperuser.Command):
    """Overwrite of the createsuperuser command, to force entry of
       a valid phonenumber."""

    def __init__(self, *args, **kwargs):
        """Make username a class variable."""
        self.username = ''
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        """Run createsuperuser.handle(**) and add the phonenumber
           to the newly created superuser."""

        self.UserModel.REQUIRED_FIELDS.append('phonenumber')
        options['phonenumber'] = None

        super(Command, self).handle(*args, **options)

        user = self.UserModel.objects.get(username=self.username)

        Token.objects.create(user=user)

    def get_input_data(self, field, message, default=None):
        """Run get_input_data and when the username is added, assign it to
           the username class variable."""
        val = super(Command, self).get_input_data(field, message, default)

        if field == self.username_field:
            self.username = val

        elif field == self.UserModel._meta.get_field('phonenumber'):
            # this should be validated in the model
            while not fullmatch('^\\+[0-9]{10,12}$', val):
                self.stderr.write('Enter a valid Dutch phonenumber...')
                val = input(message)  # nosec: safe in Python3

        return val
