from uuid import uuid4
from random import randint
from requests import Session
from hashlib import md5, sha1
from secrets import token_bytes
from smtplib import SMTP as smtp
from os import access, R_OK, F_OK

from unittest.mock import Mock, patch

from django.urls import reverse
from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.exceptions import ValidationError

from alert_api.models import CanaryAlertItem, MimiAlertItem, SampleItem

from canary_files.models import CanaryItem

from canary_utils.test_helpers import UserHelpers, MockSession
from canary_utils.test_helpers import CanaryAlertHelpers, FilterHelper
from canary_utils.test_helpers import SampleFileHelpers, MimiAlertHelpers


class IncomingMimiAlertTestcase(TestCase):

    fixtures = ['manage_api/fixtures/sms_test_settings.json',
                'manage_api/fixtures/smtp_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

        self.md5, self.sha1 = self._generate_hashes()

        smtp.connect = Mock(return_value=((220, False)))
        smtp.close = Mock(return_value=0)
        smtp.ehlo = Mock(return_value=0)
        smtp.sendmail = Mock(return_value=0)

        self.json = {'machinename': str(uuid4()),
                     'sid': randint(65535, 102391),
                     'pid': randint(10, 65535),
                     'date': timezone.now(),
                     'source': 'C:\\Windows\\TEMP\\mimiii.exe',
                     'hashes': {'md5': self.md5,
                                'sha1': self.sha1},
                     'target': 'lsass.exe',
                     'accessMask': '4882',
                     'stack': 'not a heap'}

    def test_send_mimialert_item(self):
        """Test send a valid MimiAlert, should return 201."""

        # return a faked Requests response object, do not send SMS
        Session.post = Mock(return_value=MockSession.return_token_text())

        # patch smtp functions so no actual mail is send
        url = reverse('incoming-mimialert')
        response = self.client.put(url, data=self.json,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(len(MimiAlertItem.get_all_alerts()), 1)

    def test_delete_sample_removes_file(self):
        """Test deleting a SampleItem removes the file."""

        sample = SampleFileHelpers.create_sample_mimikatz()
        path = sample.sample.path

        sample.delete()

        self.assertFalse(access(path, F_OK))

    def test_send_mimialert_item_known_sample(self):
        """Test send a MimiAlert with known sample, should return 200."""

        # creating the sample
        SampleItem.objects.create(md5=self.md5, sample='a sample')

        Session.post = Mock(return_value=MockSession.return_token_text())

        url = reverse('incoming-mimialert')
        response = self.client.put(url, data=self.json,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_send_invalid_syslog_item(self):
        """Test send an invalid SyslogItem, should return 400."""

        self.json.pop('hashes')

        url = reverse('incoming-mimialert')
        response = self.client.put(url, data=self.json,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(len(MimiAlertItem.get_all_alerts()), 0)

    def test_send_invalid_syslog_hash_item(self):
        """Test send invalid hashes with SyslogItem, should return 400."""

        self.json['hashes']['md5'] = 'blaaat'
        self.json['hashes']['sha1'] = 'shhhhaaaaaaaa'

        url = reverse('incoming-mimialert')

        response = self.client.put(url, data=self.json,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(len(MimiAlertItem.get_all_alerts()), 0)

    def _generate_hashes(self):

        _md5 = md5()
        _md5.update(token_bytes(25))

        _sha1 = sha1()
        _sha1.update(token_bytes(25))

        return (_md5.hexdigest(), _sha1.hexdigest())


class IncomingFileTestcase(TestCase):

    def setUp(self):

        smtp.connect = Mock(return_value=((220, False)))
        smtp.close = Mock(return_value=0)
        smtp.ehlo = Mock(return_value=0)
        smtp.sendmail = Mock(return_value=0)

    def test_post_sample_file(self):
        """Test POST mimikatz sample file, should return True."""

        md5, sha1 = SampleFileHelpers.download_latest_mimikatz()

        url = reverse('incoming-sample', args={md5})

        with open('/tmp/x64/mimikatz.exe', 'rb') as fd:
            response = self.client.post(url, fd.read(),
                                        content_type='application/octet-stream')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(SampleItem.objects.filter(md5=md5).exists())

        item = SampleItem.objects.get()
        item.delete()

    def test_delete_sample_removes_file(self):
        """Test delete SampleFile removes object from disk. Should return
           False."""
        md5, sha1 = SampleFileHelpers.download_latest_mimikatz()

        url = reverse('incoming-sample', args={md5})

        with open('/tmp/x64/mimikatz.exe', 'rb') as fd:
            self.client.post(url, fd.read(),
                             content_type='application/octet-stream')

        self.assertTrue(SampleItem.objects.filter(md5=md5).exists())

        item = SampleItem.objects.get()
        path = item.sample.path

        self.assertTrue(access(path, R_OK))
        item.delete()

        self.assertFalse(access(path, R_OK))

    def test_retrieve_invalid_sample(self):
        """Test can retrieve added sample, should return True."""

        SampleFileHelpers.create_sample_mimikatz()

        _md5 = md5()
        _md5.update(b'not a valid hash')
        digest = _md5.hexdigest()

        with self.assertRaises(ValidationError) as exception:
            SampleItem.retrieve_sample(digest)

        self.assertEqual(str(exception.exception.detail[0]),
                         'Identifier not known')

    def test_post_empty_sample_file_json(self):
        """Test POST empty sample file with JSON content-type,
           should return 400."""

        url = reverse('incoming-sample', args={'filename'})
        response = self.client.post(url, content_type='application/json')

        self.assertEqual(response.status_code,
                         status.HTTP_400_BAD_REQUEST)

    def test_post_empty_sample_file(self):
        """Test POST empty sample file with correct content-type,
           should return 400."""

        url = reverse('incoming-sample', args={'filename'})
        response = self.client.post(url,
                                    content_type='application/octet-stream')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_related_url_item(self):
        """Test if related URL items are obtained properly, must return True."""

        sample = SampleFileHelpers.create_sample_mimikatz()
        alert = MimiAlertHelpers.create_alert_item(sample.md5)

        item = SampleItem.get_related_alert_items_as_url(sample.md5)

        # __str__ of MimiAlertItem will retrieve machinename
        # this has to be tested anyway
        mn = str(alert)

        url = reverse('admin:alert_api_mimialertitem_changelist')
        ref = '<a href="{}?machinename={}">{}</a>'.format(url, mn, mn)

        self.assertEqual(item, ref)

    def test_related_url_items(self):
        """Test if related URL items are obtained properly, must return True."""

        sample = SampleFileHelpers.create_sample_mimikatz()

        # __str__ of MimiAlertItem will retrieve machinename
        # this has to be tested anyway
        alerts = [str(MimiAlertHelpers.create_alert_item(sample.md5)),
                  str(MimiAlertHelpers.create_alert_item(sample.md5))]

        # items is converted to a string, split it back to a list
        items = SampleItem.get_related_alert_items_as_url(
                                         sample.md5
                                              ).split(', ')

        # make sure the order is the same
        sorted_items = []

        if alerts[0] in items[0]:
            sorted_items.append((alerts[0], items[0]))
            sorted_items.append((alerts[1], items[1]))

        else:
            sorted_items.append((alerts[0], items[1]))
            sorted_items.append((alerts[1], items[0]))

        for alert, item in sorted_items:

            url = reverse('admin:alert_api_mimialertitem_changelist')
            ref = '<a href="{}?machinename={}">{}</a>'.format(url, alert, alert)

            self.assertEqual(item, ref)

    def test_no_related_url_items(self):
        """Test if related URL returns N/A on empty list."""

        sample = SampleFileHelpers.create_sample_mimikatz()
        item = SampleItem.get_related_alert_items_as_url(sample.md5)

        self.assertEqual(item, 'N/A')

    def test_post_delete_sample_file(self):
        """Test if sample is deleted after object removal, should return
           False."""

        sample = SampleFileHelpers.create_sample_mimikatz()
        path = sample.sample.path

        sample.delete()

        self.assertFalse(access(path, R_OK))


class TriggeredAlertTestcase(TestCase):

    fixtures = ['manage_api/fixtures/sms_test_settings.json',
                'manage_api/fixtures/smtp_test_settings.json']

    def setUp(self):

        smtp.connect = Mock(return_value=((220, False)))
        smtp.close = Mock(return_value=0)
        smtp.ehlo = Mock(return_value=0)
        smtp.sendmail = Mock(return_value=0)

        self.c = CanaryAlertHelpers()
        self.alerts = self.c.create_alert_items()

        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

    def test_get_triggered_alert(self):
        """Test can retrieve triggered alert, return True."""

        url = reverse('triggered-alerts', args={1})
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        items = dict(response.data)
        items.pop('id')

        for key in items.keys():
            self.assertTrue(key in self.c.kwargs.keys())

    def test_get_triggered_alerts(self):
        """Test can retrieve multiple triggered alerts, should return 2."""

        # generate a new uuid and create an extra object
        self.c.kwargs['identifier'] = str(uuid4())
        CanaryAlertItem.create_object(**self.c.kwargs)

        url = '/api/alert/log/'
        response = self.client.get(url, **self.headers)

        number_of_items = 4

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_items)

    def test_get_alert_unauthenticated(self):
        """Test unauthenticated users cannot retrieve triggered items,
           return 401."""

        url = reverse('triggered-alerts', args={1})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_non_existent_alert(self):
        """Test attempt to retrieve non-existent item, should return 404."""

        url = reverse('triggered-alerts', args={1337})
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_triggered_alert(self):
        """Test can delete trigger object as superuser, return 200."""

        self.mu.is_superuser = True
        self.mu.save()

        url = reverse('triggered-alerts', args={1})
        response = self.client.delete(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(CanaryAlertItem.objects.filter(id=1).exists())

    def test_delete_triggered_alert_non_superuser(self):
        """Test attempt to delete trigger object as non-superuser,
           return 401."""

        url = reverse('triggered-alerts', args={1})
        response = self.client.delete(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_alert_unauthenticated(self):
        """Test attempt to delete trigger object without authentication,
           return 401."""

        url = reverse('triggered-alerts', args={1})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_related_canary_alert_items(self):
        """Test attempt to get related alert items, return True."""

        alert = self.alerts[0]
        item = CanaryItem.get_related_alert_items(alert)

        url = reverse('admin:alert_api_canaryalertitem_changelist')
        ref = '<a href="{}?identifier={}">{}</a>'.format(url, alert.identifier,
                                                         alert.identifier)

        self.assertEqual(item, ref)

    def test_related_canary_alert_item_na(self):
        """Test attempt to get related alert items, return True."""

        alert = self.alerts[0]
        with patch.object(CanaryAlertItem.objects, 'filter',
                          return_value=FilterHelper.return_exists_bool(False)):

            item = CanaryItem.get_related_alert_items(alert)

        self.assertEqual(item, 'N/A')
