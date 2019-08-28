from uuid import uuid4

from django.urls import reverse
from django.test import TestCase

from rest_framework import status

from canary_files.models import CanaryItem
from canary_log_api.models import CanaryLogItem
from canary_utils.test_helpers import UserHelpers


class RetrieveLogItems(TestCase):

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key
        self.headers = UserHelpers.create_authentication_header(self.token)

    def test_get_single_item(self):
        """Retrieve single log item, returns 5 keys"""

        number_of_keys = 6

        self._create_mock_log_item()
        url = reverse('logs')

        response = self.client.get(url, **self.headers)
        self.assertTrue(response.status_code, status.HTTP_200_OK)

        self.assertEqual(len(response.data), number_of_keys)

    def test_get_multiple_items(self):
        """Retrieve multiple log items, return 5 items"""

        number_of_items = 5

        for i in range(0, number_of_items):
            self._create_mock_log_item()

        url = reverse('logs')

        response = self.client.get(url, **self.headers)

        self.assertTrue(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), number_of_items)

    def _create_mock_log_item(self):

        canary = CanaryItem.objects.create(identifier=uuid4(),
                                           added_by=self.mu)
        CanaryLogItem.log_message(self.mu, canary, 'mocked item')
