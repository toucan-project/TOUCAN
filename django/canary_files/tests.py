from os import access, R_OK

from rq import SimpleWorker
from django_rq.workers import get_worker

from unittest.mock import Mock, patch

from django.urls import reverse
from django.test import TestCase

from rest_framework import status

from canary_files.models import CanaryItem, Deployment, canary_delete

from canary_utils.test_helpers import UserHelpers, CanaryFileHelpers


class APICanaryGenerationTestcase(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key

    def test_generate_excel_file(self):
        """PUT an excel file, retrieve backdoored file"""

        headers = UserHelpers.create_authentication_header(self.token)

        headers['HTTP_CONTENT_DISPOSITION'] = 'attachment;filename="excel.xlsx"'

        params = "?trigger=all&location=test"
        ctype = ('application/vnd.openxmlformats-officedocument.'
                 'spreadsheetml.sheet')

        with open('canary_utils/tests/excel.xlsx', 'rb') as fd:
            request = self.client.put(f"{reverse('canary')}{params}",
                                      fd.read(), content_type=ctype,
                                      **headers)

        self.assertEqual(request.status_code, status.HTTP_200_OK)

        item = CanaryItem.objects.get()

        # also test __str__ method of CanaryItem
        self.assertEqual(item.identifier, str(item))

        self.assertEqual(item.filename.split('.')[1], 'xlsx')

    def test_generate_excel_file_unicode(self):
        """PUT an excel file, with non-western unicode filename, retrieve backdoored
           file"""

        headers = {'HTTP_AUTHORIZATION': f"Token {self.token}",
                   'HTTP_CONTENT_DISPOSITION': ('attachment;'
                                                'filename="帶有數據的excel文件.xlsx"')}

        params = "?trigger=all&location=test"
        ctype = ('application/vnd.openxmlformats-officedocument.'
                 'spreadsheetml.sheet')

        with open('canary_utils/tests/excel.xlsx', 'rb') as fd:
            request = self.client.put(f"{reverse('canary')}{params}",
                                      fd.read(), content_type=ctype,
                                      **headers)

        self.assertEqual(request.status_code, status.HTTP_200_OK)

        item = CanaryItem.objects.get()

        self.assertTrue(item.filename.split('.')[1] == 'xlsx')

    def test_generate_file_no_phonenumber(self):
        """PUT a canary file while not having a phonenumber setup, should
           return True."""

        self.mu.phonenumber = ''
        self.mu.save()

        headers = {'HTTP_AUTHORIZATION': f"Token {self.token}",
                   'HTTP_CONTENT_DISPOSITION': ('attachment;'
                                                'filename="excel.xlsx')}

        params = "?trigger=all&location=test"
        ctype = ('application/vnd.openxmlformats-officedocument.'
                 'spreadsheetml.sheet')

        with open('canary_utils/tests/excel.xlsx', 'rb') as fd:
            response = self.client.put(f"{reverse('canary')}{params}",
                                       fd.read(), content_type=ctype,
                                       **headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_pdf_file_no_write(self):
        """PUT PDF file, return 400 cannot write file."""

        headers = UserHelpers.create_authentication_header(self.token)

        headers['HTTP_CONTENT_DISPOSITION'] = 'attachment;filename="pdf.pdf"'

        params = "?trigger=all&location=test"
        ctype = 'application/pdf'

        # patch the return value of the return_file function that is used
        # within the _return_canary_file function of the CanaryItem model
        with patch.dict(CanaryItem._return_canary_file.__globals__,
                        {'return_file': Mock
                            (return_value=('pdf', '/.../../../../../root/a.not',
                                           'http'))}):

            with open('canary_utils/tests/test-pdf.pdf', 'rb') as fd:
                response = self.client.put(f"{reverse('canary')}{params}",
                                           fd.read(), content_type=ctype,
                                           **headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_pdf_cannot_write_named(self):
        """Attempt to write pdf but path is not writable, return 400."""

        headers = UserHelpers.create_authentication_header(self.token)

        headers['HTTP_CONTENT_DISPOSITION'] = 'attachment;filename="pdf.pdf"'

        params = "?trigger=sms&location=test?dns=true"
        ctype = 'application/pdf'

        with patch.dict(CanaryItem._return_canary_file.__globals__,
                        {'write_named_string': Mock(return_value=False)}):

            with open('canary_utils/tests/test-pdf.pdf', 'rb') as fd:
                response = self.client.put(f"{reverse('canary')}{params}",
                                           fd.read(), content_type=ctype,
                                           **headers)

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_canary_remove_file(self):
        """Attempt to remove the canary file using the canary_delete,
           should return 404"""

        headers = UserHelpers.create_authentication_header(self.token)
        canary = CanaryFileHelpers.create_canary_file(self.mu)

        path = canary.canary_doc.path
        canary_delete(CanaryItem, canary)

        self.assertFalse(access(path, R_OK))

        url = reverse('download-canary', kwargs={'identifier':
                                                 canary.identifier})
        response = self.client.get(url, **headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class CanaryItemTestcase(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key

    def test_redeploy_of_canary(self):
        """Test redeploy functionalities actually work."""

        file = CanaryFileHelpers.create_canary_file(self.mu)
        Deployment.full_deployment_fail('test', file)

        eq = Mock(return_value=0)

        with patch.dict(file.redeploy_remote_files.__globals__,
                        {'enqueue': eq}):
            file.redeploy_remote_files()
            eq.assert_called()

    def test_can_delete_remote_files(self):
        """Test canary can delete remote files."""

        file = CanaryFileHelpers.create_canary_file(self.mu)

        eq = Mock(return_value=0)

        with patch.dict(file.remove_remote_files.__globals__,
                        {'enqueue': eq}):
            file.delete()
            eq.assert_called()

    def test_can_deploy_remote_files(self):
        """Test canary can deploy remote files."""

        file = CanaryFileHelpers.create_canary_file(self.mu)

        eq = Mock(return_value=0)

        with patch.dict(file.deploy_remote_files.__globals__,
                        {'enqueue': eq}):
            file.deploy_remote_files()
            eq.assert_called()

    def test_can_item_set_pending(self):
        """Test Deployment canary can set state to pending."""

        file = CanaryFileHelpers.create_canary_file(self.mu)

        for item in Deployment.objects.filter(canary=file):
            item.pending_deployment()

        for item in Deployment.objects.filter(canary=file):
            self.assertEqual(item.state, 'pending')


class DownloadItemTestcase(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.mu = UserHelpers.create_authenticated_user()
        self.token = self.mu.auth_token.key

        self.headers = UserHelpers.create_authentication_header(self.token)
        self.canary = CanaryFileHelpers.create_canary_file(self.mu)

    def test_download_sample_item(self):
        """Test download sample, should return 200. Cannot actually
           download the sample because this an Nginx redirect to 'internal'."""

        url = reverse('download-canary', args={self.canary.identifier})

        response = self.client.get(url, **self.headers)
        get_worker(worker_class=SimpleWorker).work(burst=True)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_download_sample_item_nonexistent(self):
        """Test attempt to download a non-existent sample, should return 404."""

        url = reverse('download-canary', args={
                                        'aaaa87337454e5'
                                        })
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_download_sample_item_no_auth(self):
        """Test attempt to download sample file without authentication,
           return 401."""

        url = reverse('download-canary', args={self.canary.identifier})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
