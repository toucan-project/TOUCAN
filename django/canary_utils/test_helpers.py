from uuid import uuid4
from shutil import rmtree
from random import shuffle
from zipfile import ZipFile
from string import hexdigits
from requests import Session
from datetime import datetime
from hashlib import md5, sha1
from OpenSSL.crypto import X509
from re import findall, compile
from os import access, R_OK, listdir, remove

from unittest.mock import MagicMock

from django.utils import timezone
from django.core.files.uploadedfile import InMemoryUploadedFile

from manage_api.models import User

from canary_files.models import CanaryItem

from alert_api.models import CanaryAlertItem
from alert_api.models import SampleItem, MimiAlertItem


class UserHelpers():
    """Helpers to generate users and other useful tools for unit testing."""

    @classmethod
    def create_authenticated_user(cls, username=None, email=None,
                                  phonenumber='+31612312312',
                                  password='test123',
                                  superuser=False):
        """Create a user and manage user account."""

        if not username:
            username = cls._generate_random_string(cls)

        if not email:
            email = f"{cls._generate_random_string(cls)}@test.tst"

        user = User.create_user(username, password, email,
                                phonenumber)

        if superuser:
            user.is_superuser = True
            user.save()

        return user

    @classmethod
    def create_authentication_header(cls, token):
        """Create the token authorization header."""
        return {'HTTP_AUTHORIZATION': f"Token {token}"}

    def _generate_random_string(self):
        digits = list(hexdigits)
        shuffle(digits)

        return ''.join(digits[0:10])


class CanaryAlertHelpers():
    """Helpers for creating CanaryAlertItems."""

    def __init__(self):

        self.date = timezone.now()
        self.identifier = str(uuid4())
        self.location = 'test_unit'
        self.ip = '126.0.3.1'
        self.node = 'test_node'
        self.user_agent = 'i-like-turtles'
        self.smb_loc = 'turtle-ville'
        self.filename = ':thinking:'

        self.kwargs = {'date': self.date,
                       'identifier': self.identifier,
                       'canary_type': '',
                       'location': self.location,
                       'ip': self.ip,
                       'node': self.node,
                       'user_agent': self.user_agent,
                       'smb_loc': self.smb_loc,
                       'filename': self.filename}

    def create_alert_items(self):
        """Create one of each alert item."""

        types = ['dns', 'unc', 'http']
        alerts = []

        for type in types:

            self.kwargs['canary_type'] = type
            alerts.append(CanaryAlertItem.create_object(**self.kwargs))

        return alerts


class CanaryFileHelpers():

    """Helpers for creating test Canary files."""

    @classmethod
    def create_canary_file(cls, user, type='all'):

        if not user:
            user = UserHelpers.create_authenticated_user()

        fd = open('canary_utils/tests/excel.xlsx', 'rb')
        size = len(fd.read())
        fd.seek(0)

        canary = InMemoryUploadedFile(
                                 fd, 'uploaded', 'excel.xlsx',
                                 content_type='application/octet-stream',
                                 size=size, charset='binary'
                                 )

        canary_item = CanaryItem.create_canary(user, canary,
                                               type, 'test_unit',
                                               True, 'http',
                                               'test.legit.subdomain.example')
        fd.close()

        return canary_item


class X509Helpers():

    """Helpers for creating X509 objects."""

    @classmethod
    def return_x509_object(cls, expiry, expired):

        x509 = MagicMock(X509)

        date = datetime.fromtimestamp(expiry)

        x509.has_expired.return_value = expired

        # x509 object returns bytes for get_notAfter
        x509.get_notAfter.return_value = bytes(
                            date.strftime('%Y%m%d%H%M%SZ'), 'utf-8'
                            )

        return x509


class MimiAlertHelpers():
    """Helpers to create MimiAlertItems"""

    @classmethod
    def create_alert_item(cls, md5='60b725f10c9c85c70d97880dfe8191b3'):
        """Helper to create a MimiAlertItem."""
        machinename = str(uuid4())
        sid = str(uuid4())
        pid = 1
        date = timezone.now()
        source = 'malware.exe'
        target = 'lsass.exe'
        sha1 = '3f786850e387550fdab836ed7e6dc881de23001b'
        accessMask = '0000'
        stack = 'not a heap'

        item = MimiAlertItem.objects.create(
                machinename=machinename,
                sid=sid,
                pid=pid,
                date=date,
                source=source,
                target=target,
                md5=md5,
                sha1=sha1,
                accessMask=accessMask,
                stack=stack
                )

        return item


class LoggerHelper():

    @classmethod
    def return_mock_logger(cls):
        return MockLogger()


class MockLogger():

    def log_exception(self, msg):
        return 0

    def log_info(self, msg):
        return 0


class FilterHelper():

    @classmethod
    def return_exists_bool(cls, bool):
        return MockFilter(bool)


class MockFilter():

    def __init__(self, bool):
        self.bool = bool

    def exists(self):
        return self.bool


class ThreadHelper():

    @classmethod
    def return_mock_thread(cls):
        return MockThread(alive=True)

    @classmethod
    def return_mock_thread_dead(cls):
        return MockThread(alive=False)


class MockThread():

    def __init__(self, alive):
        self.alive = alive

    def start(self):
        return True

    def is_alive(self):
        return self.alive

    def setDaemon(self, bool):
        return True

    def join(self, i):
        self.alive = False
        return True


class SampleFileHelpers():

    """Helpers for creating test sample files."""

    @classmethod
    def create_sample_mimikatz(cls):
        """Import mimikatz Sample in the items."""
        md5, sha1 = cls.download_latest_mimikatz()

        with open('/tmp/Win32/mimikatz.exe', 'rb') as fd:
            size = len(fd.read())
            fd.seek(0)

            # fake an uploaded file
            sample = InMemoryUploadedFile(
                             fd, 'uploaded', 'mimikatz.exe',
                             content_type='application/octet-stream',
                             size=size, charset='binary'
                             )

            return SampleItem.save_sample(md5, sample)

    @classmethod
    def download_latest_mimikatz(cls):
        """Download the latest Mimikatz version from GitHub."""

        filename = '/tmp/mimikatz.zip'

        if not access(filename, R_OK):
            session = Session()

            r = session.get(
                         'https://github.com/gentilkiwi/mimikatz/releases'
                           ).text
            rgx = (r'(?=<a href=")*'
                   r'(/gentilkiwi/mimikatz/releases/download/.*\.zip)')

            matches = findall(compile(rgx), r)

            if len(matches) > 0:
                download = f"https://www.github.com{matches[0]}"

            with open(filename, 'wb+') as fd:
                with session.get(download, stream=True) as f:
                    fd.write(f.content)

        z = ZipFile(filename)
        z.extract('x64/mimikatz.exe', path='/tmp')
        z.extract('Win32/mimikatz.exe', path='/tmp')

        return cls._hash_files(cls)

    def _hash_files(self):
        """Generate md5 and sha1 hashes for the EXE file."""

        _sha1 = sha1()
        _md5 = md5()

        with open(f"/tmp/x64/mimikatz.exe", 'rb') as fd:
            buf = fd.read(65535)

            while len(buf) > 0:
                _sha1.update(buf)
                _md5.update(buf)
                buf = fd.read(65535)

        return (_md5.hexdigest(), _sha1.hexdigest())


class MockResponse():
    """A mock Response object for the requests module."""

    def __init__(self, status_code, text=None):
        self.status_code = status_code

        if text:
            self.text = text


class MockSession:
    """Mock functions that return a MockResponse for mimicking
       requests.Session."""

    @classmethod
    def return_status_code(cls, status_code):
        return MockResponse(status_code, text='Failed because test')

    @classmethod
    def return_token_text(cls):
        return MockResponse(200,
                            ('{"access_token":'
                             '"eDdX8Kr6gmS1Axvp1iPDWuSsPOofOe", "token_type":'
                             '"Bearer", "expires_in": 3600, "scope":'
                             '"read write"}'))
