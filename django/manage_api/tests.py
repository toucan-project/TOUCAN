from unittest.mock import patch, Mock

from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.exceptions import ValidationError

from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet as Crypto

from canary_files.models import AsynchronousDeploy, Deployment

from canary_utils.test_helpers import MimiAlertHelpers
from canary_utils.test_helpers import CanaryFileHelpers
from canary_utils.test_helpers import UserHelpers, SampleFileHelpers

from manage_api.models import Trigger, ExternalAPISetting
from manage_api.models import TriggerContactDetails, DefaultSetting


class RetrievingMimiAlertItems(TestCase):

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

    def test_get_single_item(self):
        """Retrieve single MimiAlertItem, returns 1"""

        MimiAlertHelpers.create_alert_item()
        url = reverse('sysmon_alert_item', kwargs={'id': 1})

        response = self.client.get(url, **self.headers)
        self.assertTrue(response.status_code, status.HTTP_200_OK)

        self.assertEqual(len(response.data), 1)

    def test_get_many_items(self):
        """Retrieve multiple MimiAlertItems, returns 5"""

        number_of_items = 5
        create_multiple_items(number_of_items)

        url = reverse('sysmon_alert_items')

        response = self.client.get(url, **self.headers)
        self.assertTrue(response.status_code, status.HTTP_200_OK)

        self.assertEqual(len(response.data), number_of_items)

    def test_get_unauthenticated_item(self):
        """Attempt to get retrieve items without token, return 401"""

        MimiAlertHelpers.create_alert_item()

        url = reverse('sysmon_alert_item', kwargs={'id': 1})

        response = self.client.get(url)

        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_unauthenticated_items(self):
        """Attempt to get retrieve items without token, return 401"""

        number_of_items = 5
        create_multiple_items(number_of_items)

        url = reverse('sysmon_alert_items')

        response = self.client.get(url)

        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ManageTriggerItems(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

    def test_retrieve_trigger_item(self):
        """Test retrieve trigger item, should return 4 keys"""

        create_trigger_item(self.mu)
        url = reverse('trigger_item', kwargs={'id': 1})
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 5)

    def test_retrieve_trigger_items_as_superuser(self):
        """Test retrieving trigger items as super user,
           should return 5 items."""

        number_of_items = 5

        create_multiple_trigger_items(number_of_items, self.mu)

        su = UserHelpers.create_authenticated_user(superuser=True)
        headers = UserHelpers.create_authentication_header(su.api_token)

        url = reverse('trigger_item')
        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_items)

    def test_retrieve_trigger_items(self):
        """Test retrieve trigger item, should return 5 items"""

        number_of_items = 5

        create_multiple_trigger_items(number_of_items, self.mu)

        url = reverse('trigger_item')
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_items)

    def test_retrieve_trigger_item_invalid(self):
        """Test retrieve non-existent trigger item, should return 404."""

        create_trigger_item(self.mu)
        url = reverse('trigger_item', kwargs={'id': 1337})
        response = self.client.get(url, **self.headers)

        self.assertTrue(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_trigger_item_invalid(self):
        """Test delete non-existent trigger item, should return 404."""

        create_trigger_item(self.mu)
        url = reverse('trigger_item', kwargs={'id': 1337})
        response = self.client.delete(url, **self.headers)

        self.assertTrue(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_retrieve_trigger_item_unauth(self):
        """Test retrieve trigger item without authentication,
           should return 401"""

        create_trigger_item(self.mu)
        url = reverse('trigger_item', kwargs={'id': 1})
        response = self.client.get(url)

        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_trigger_items_unauth(self):
        """Test retrieve trigger item without authentication,
           should return 401"""

        number_of_items = 5

        create_multiple_trigger_items(number_of_items, self.mu)
        url = reverse('trigger_item')
        response = self.client.get(url)

        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_put_trigger_item_mimi(self):
        """Test PUT trigger item for MimiAlertItem return 200."""

        item = MimiAlertHelpers.create_alert_item()

        json = {'sms': True, 'email': False,
                'identifier': item.machinename}

        url = reverse('trigger_item')

        response = self.client.put(url, json, **self.headers,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_trigger_item_canary(self):
        """Test PUT trigger item for CanaryFile should return True."""

        canary = CanaryFileHelpers.create_canary_file(self.mu)

        # remove automaticalyl created trigger for call to succeed
        canary.trigger_set.first().delete()

        json = {'sms': False, 'email': True,
                'identifier': canary.identifier}

        url = reverse('trigger_item')

        response = self.client.put(url, json, **self.headers,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        created = canary.trigger_set.first()

        self.assertEqual(created.sms, json['sms'])
        self.assertEqual(created.email, json['email'])
        self.assertEqual(created.trigger_identifier, json['identifier'])

    def test_update_trigger_item(self):
        """Test PATCH trigger item with new values, should return True."""
        canary = CanaryFileHelpers.create_canary_file(self.mu)

        json = {'sms': True, 'email': True,
                'identifier': canary.identifier}

        id = canary.pk

        url = reverse('trigger_item', kwargs={'id': id})

        response = self.client.patch(url, json, **self.headers,
                                     content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        canary.refresh_from_db()
        created = canary.trigger_set.first()

        self.assertEqual(created.sms, json['sms'])
        self.assertEqual(created.email, json['email'])
        self.assertEqual(created.trigger_identifier, json['identifier'])

    def test_put_trigger_item_unauth(self):
        """Test PUT trigger item without authentication, should return 403."""

        item = MimiAlertHelpers.create_alert_item()

        json = {'sms': True, 'email': False,
                'identifier': item.machinename}

        url = reverse('trigger_item')

        response = self.client.put(url, json,
                                   content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_put_trigger_item_invalid(self):
        """Test PUT trigger item with invalid values, should return 400."""

        json = {'sms': True, 'email': False,
                'identifier': 'blaaaaaat'}

        url = reverse('trigger_item')

        response = self.client.put(url, json, **self.headers,
                                   content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_trigger_item(self):
        """Test attempt to delete trigger item, should return 200."""
        canary = CanaryFileHelpers.create_canary_file(self.mu)

        id = canary.pk
        identifier = canary.identifier

        url = reverse('trigger_item', kwargs={'id': id})

        response = self.client.delete(url, **self.headers,
                                      content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertFalse(Trigger.objects.filter(
                               trigger_identifier=identifier
                            ).exists())

    def test_get_trigger_contact_details(self):
        """Test attempt to obtain trigger contact details, should return
           True."""

        canary = CanaryFileHelpers.create_canary_file(self.mu, type='email')
        contacts = Trigger.get_trigger_items_for_identifier(canary.identifier)

        self.assertIsInstance(contacts, TriggerContactDetails)
        self.assertEqual(len(contacts.email), 1)

    def test_get_trigger_contact_details_no_email(self):
        """Test attempt to obtain trigger contact details, no email set,
           should return 0"""

        self.mu.email = ''
        self.mu.save()

        canary = CanaryFileHelpers.create_canary_file(self.mu)
        contacts = Trigger.get_trigger_items_for_identifier(canary.identifier)

        self.assertIsInstance(contacts, TriggerContactDetails)
        self.assertEqual(len(contacts.email), 0)

    def test_get_trigger_contact_details_no_phonenumber(self):
        """Test attempt to obtain trigger contact details, no email set,
           should return 0"""

        canary = CanaryFileHelpers.create_canary_file(self.mu, type='sms')

        self.mu.phonenumber = ''
        self.mu.save()

        contacts = Trigger.get_trigger_items_for_identifier(canary.identifier)

        self.assertIsInstance(contacts, TriggerContactDetails)
        self.assertEqual(len(contacts.email), 0)


class RetrievingSampleItems(TestCase):

    def setUp(self):

        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

        self.sample = SampleFileHelpers.create_sample_mimikatz()

    def test_can_retrieve_sample_item(self):
        """Test can user retrieve sample item, should return 200. Cannot
           actually download the sample, as we use Nginx for that."""

        url = reverse('download-sample', args={self.sample.md5})
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ManageExternalItems(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

    def test_get_external_item(self):
        """Test GET an external ap setting, return 200."""

        ExternalAPISetting.objects.create(api_name='test',
                                          api_key='blaaaaaaat')

        url = reverse('external-setting')
        response = self.client.get(url, **self.headers)

        number_of_items = 1

        self.assertEqual(len(response.data), number_of_items)

    def test_put_external_item(self):
        """Test PUT an external API settings item, return 200."""

        api = {'api_name': 'test_api',
               'api_cred': {
                            'api_user': 'root',
                            'api_password': 'toor'
                            }
               }

        url = reverse('external-setting')

        response = self.client.put(url, api, **self.headers,
                                   content_type='application/json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_external_api_item_by_name(self):
        """Attempt to get an external API item by name, should return True"""

        ExternalAPISetting.objects.create(api_name='test',
                                          api_key='blaaaaaaat')

        item = ExternalAPISetting.get_api_item_by_name('test')
        self.assertIsInstance(item, ExternalAPISetting)

    def test_get_no_external_item_by_name(self):
        """Attempt to get a non-existent API item by name, should raise
           exception."""

        with self.assertRaises(ValidationError):
            ExternalAPISetting.get_api_item_by_name('test')


class RetrieveAccountInformation(TestCase):

    def test_retrieve_user_information(self):
        """Test can retrieve user information, should return 4 keys"""

        mu = UserHelpers.create_authenticated_user()
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        url = reverse('user_item')
        number_of_keys = 4

        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_keys)

    def test_retrieve_all_users_information(self):
        """Test can retrieve all user information, should return 6 users"""

        self._create_multiple_users()

        su = UserHelpers.create_authenticated_user(superuser=True)
        token = su.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        url = reverse('user_items')
        number_of_users = 6

        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_users)

    def test_retrieve_user_information_unauth(self):
        """Test can retrieve user information, should return 4 keys"""

        mu = UserHelpers.create_authenticated_user()
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        url = reverse('user_item')
        number_of_keys = 4

        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_keys)

    def test_retrieve_all_users_information_unauth(self):
        """Test can retrieve all user information without token,
           should return 401"""

        self._create_multiple_users()

        url = reverse('user_items')

        response = self.client.get(url)

        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_all_users_information_non_superuser(self):
        """Test can retrieve all user information as normal user,
           should return 403"""

        self._create_multiple_users()

        su = UserHelpers.create_authenticated_user(superuser=False)
        token = su.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        url = reverse('user_items')

        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def _create_multiple_users(self):

        names = ['peter', 'frank', 'paul', 'john', 'derp']

        for username in names:
            UserHelpers.create_authenticated_user(username=username)


class UserManagement(TestCase):

    def setUp(self):
        self.email = 'test@admin.ninja'
        self.username = 'lolwut'
        self.phonenumber = '+31612312312'
        self.password = 'hahahahahahahaha'
        self.superuser = False

    def test_create_manage_user(self):
        """As super user creates a new user and return a valid token"""

        mu = UserHelpers.create_authenticated_user(superuser=True)
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        data = {'email': self.email,
                'username': self.username,
                'phonenumber': self.phonenumber,
                'password': self.phonenumber,
                'superuser': False}

        url = reverse('user_items')

        headers['content_type'] = 'application/json'

        response = self.client.put(url, data, **headers)
        token = response.data.get('token')
        self.assertTrue(mu.is_username_taken(self.username))
        self.assertTrue(mu.is_superuser)

    def test_create_manage_user_normal_user(self):
        """As a normal user attempts to create a new user, should return 403"""

        mu = UserHelpers.create_authenticated_user()
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        data = {'email': self.email,
                'username': self.username,
                'phonenumber': self.phonenumber,
                'password': self.phonenumber,
                'superuser': False}

        url = reverse('user_items')

        headers['content_type'] = 'application/json'

        response = self.client.put(url, data, **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(mu.is_username_taken(self.username))

    def test_create_manage_user_unauth(self):
        """Without authentication attempts to create a new user,
           should return 401"""

        data = {'email': self.email,
                'username': self.username,
                'phonenumber': self.phonenumber,
                'password': self.phonenumber,
                'superuser': False}

        url = reverse('user_items')

        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_manage_user(self):
        """Attempts to delete a user, should return False"""

        mu = UserHelpers.create_authenticated_user(superuser=True)
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        self._create_user()

        data = {'username': self.username}

        url = reverse('user_items')

        headers['content_type'] = 'application/json'

        response = self.client.delete(url, data, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(mu.is_username_taken(self.username))

    def test_delete_manage_user_normal_user(self):
        """Attempts to delete a user as a normal user, should return True"""

        mu = UserHelpers.create_authenticated_user()
        token = mu.auth_token.key
        headers = UserHelpers.create_authentication_header(token)

        self._create_user()

        data = {'username': self.username}

        url = reverse('user_items')

        headers['content_type'] = 'application/json'

        response = self.client.delete(url, data, **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(mu.is_username_taken(self.username))

    def test_delete_manage_user_unauth(self):
        """Attempts to delete a user without authentication, should return
           True"""
        self._create_user()

        data = {'username': self.username}

        url = reverse('user_items')

        response = self.client.delete(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_property_api_token(self):
        """Test if the api_token property returns the token, should
           return True."""

        user = self._create_user()
        self.assertEqual(user.api_token, user.auth_token.key)

    def test_property_no_api_token(self):
        """Test removal of the token then call the property, should
           return N/A."""

        user = self._create_user()
        user.auth_token.delete()

        self.assertEqual(user.api_token, 'N/A')

    def _create_user(self):
        return UserHelpers.create_authenticated_user(
                    username=self.username,
                    password=self.password,
                    email=self.email,
                    phonenumber=self.phonenumber
                    )


class DeploymentTest(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.canary = CanaryFileHelpers.create_canary_file(None)

    def test_failed_deployment_logs_object(self):
        """Test failed deployment should log object."""

        defset = DefaultSetting.objects.get()

        NotCrypto = Mock(return_value=1, side_effect=InvalidToken())

        with patch.dict(
                AsynchronousDeploy._return_secret_key.__globals__,
                {'Crypto': NotCrypto}):

            task = AsynchronousDeploy(
                                    defset,
                                    self.canary,
                                    '/etc/ansible/hosts'
                                    )
            task.run()
        number_of_fails = 2

        self.assertEqual(Deployment.objects.filter(
                            state='failed'
                        ).count(), number_of_fails)

    def test_fail_item_from_deployment(self):
        """Test failing an individual item."""

        items = Deployment.objects.all()
        items[0].failed_deployment('test')

        self.assertTrue(Deployment.objects.filter(
                         state='failed'
                    ).exists())

    def test_finished_deployment_item(self):
        """Test finishing an individual item."""

        items = Deployment.objects.all()
        items[0].finished_deployment('/etc/passwd')

        # also test __str__
        self.assertEqual(items[1].canary.identifier, str(items[1]))

        self.assertTrue(Deployment.objects.filter(
                         state='completed'
                    ).exists())


def create_multiple_items(n):

    for i in range(0, n):
        MimiAlertHelpers.create_alert_item()


def create_trigger_item(mu):

    item = MimiAlertHelpers.create_alert_item()
    user = mu
    email = True
    sms = False

    Trigger.create_object(user, sms, email, item.machinename)


def create_multiple_trigger_items(n, mu):

    for i in range(0, n):
        create_trigger_item(mu)
