import socket
import tempfile
from glob import glob
from ssl import SSLError
from requests import Session
from datetime import datetime
from zipfile import BadZipFile
from os import access, remove, F_OK
from smtplib import SMTP, SMTPRecipientsRefused
from unittest.mock import Mock, patch, MagicMock, mock_open

from django.test import TestCase
from django.conf import settings

from rq import SimpleWorker
from django_rq import enqueue
from django_rq.workers import get_worker

from alert_api.models import CanaryAlertItem

from canary_utils import tasks
from canary_utils import canary
from canary_utils.lib import deploy
from canary_utils.lib import daemon, logger, log, sms

from canary_utils.lib.daemon import serverState

from canary_utils.lib.asynctasks import AsynchronousDelete

from canary_utils.lib.util import write_canary_file, SSLVerify
from canary_utils.lib.util import open_zip, parse_deploy_cached

from canary_utils.test_helpers import CanaryFileHelpers
from canary_utils.test_helpers import MockSession, UserHelpers
from canary_utils.test_helpers import LoggerHelper, X509Helpers
from canary_utils.test_helpers import ThreadHelper, CanaryAlertHelpers

from manage_api.models import DefaultSetting

from canary_log_api.models import CanaryLogItem


class GenerateCanaryTest(TestCase):

    def test_generate_excel_canary(self):
        """ Generate an Excel canary file, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.xlsx', prefix='test_1').name
        ret = canary.make_excel_canary(
                'canary_utils/tests/excel.xlsx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, False
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        remove(file)

    def test_generate_word_canary(self):
        """ Generate a Word canary file, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.docx', prefix='test_2').name
        ret = canary.make_word_canary(
                'canary_utils/tests/excel.xlsx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, False
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        remove(file)

    def test_generate_pptx_canary(self):
        """ Generate a PowerPoint canary file, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.pptx', prefix='test_3').name
        ret = canary.make_ppt_canary(
                'canary_utils/tests/powerpoint.pptx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, False
                )
        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        remove(file)

    def test_generate_word_macro_canary(self):
        """ Generate a Word canary file with macro, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.docx', prefix='test_4').name
        ret = canary.make_macro_canary(
                'canary_utils/tests/word.docx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, False
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        remove(file)

    def test_generate_pdf_canary(self):
        """ Generate a PDF canary file, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.pdf', prefix='test_5').name
        ret = canary.make_pdf_canary(
                'canary_utils/tests/test-pdf.pdf', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png'
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        remove(file)

    def test_generate_word_canary_no_metadata(self):
        """ Generate a Word canary file replace metadata, should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.docx', prefix='test_6').name
        ret = canary.make_word_canary(
                'canary_utils/tests/excel.xlsx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, True
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        self._test_metadata_patched(file)
        remove(file)

    def test_generate_pptx_canary_no_metadata(self):
        """ Generate a PowerPoint canary file replace metadata, should
        return True"""

        file = tempfile.NamedTemporaryFile(suffix='.pptx', prefix='test_7').name
        ret = canary.make_ppt_canary(
                'canary_utils/tests/powerpoint.pptx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, True
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        self._test_metadata_patched(file)
        remove(file)

    def test_generate_word_macro_canary_no_metadata(self):
        """ Generate a Word canary file with macro replace metadata,
        should return True"""

        file = tempfile.NamedTemporaryFile(suffix='.docx', prefix='test_8').name
        ret = canary.make_macro_canary(
                'canary_utils/tests/word.docx', file,
                'http://schemas.blaaat/images/'
                '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                '.png', False, True
                )

        self.assertTrue(ret)
        self.assertTrue(access(file, F_OK))
        self._test_metadata_patched(file)
        remove(file)

    def test_generate_from_invalid_file(self):
        """Attempt to read invalid office file, should raise an exception"""
        file = tempfile.NamedTemporaryFile(suffix='.docx', prefix='test_9').name

        with self.assertRaisesRegex(BadZipFile, 'File is not a zip file'):
            canary.make_macro_canary(
                    'canary_utils/tests/test-pdf.pdf', file,
                    'http://schemas.blaaat/images/'
                    '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                    '.png', False, False
                    )

    def test_generate_non_existent_file(self):
        """Attempt to open a non-existent file, should return False"""
        file = tempfile.NamedTemporaryFile(suffix='.docx',
                                           prefix='test_10').name
        template = tempfile.NamedTemporaryFile(suffix='.docx',
                                               prefix='template_test_10').name

        with self.assertRaises(FileNotFoundError) as cm:
            canary.make_word_canary(template, file,
                                    'http://schemas.blaaat/images/'
                                    '1c83dd8e-2e8d-493d-8345-5868fef0c905'
                                    '.png', False, False)

        self.assertEqual(cm.exception.errno, 2)

    def test_generate_pdf_no_last_object(self):
        """Test generate PDF cannot find last object."""
        pass

    def test_generate_pdf_carriage_return(self):
        """Test generate PDF with carriage return"""
        pass

    def _test_metadata_patched(self, file):

        with open_zip(file) as z:
            custom = z.read('docProps/custom.xml')

        self.assertTrue(b'13:37' in custom)


class CanaryLogTestcase(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.mu = UserHelpers.create_authenticated_user()
        self.nginx = 'canary_utils/tests/nginx.log'
        self.dns = 'canary_utils/tests/querylog.log'
        self.smb = 'canary_utils/tests/smb.log'

    def test_can_parse_nginx_log(self):
        """Parse a Nginx log, and assert the _find_canary_nginx
           function is called."""

        with patch.object(log.Nginx, '_find_canary_nginx',
                          return_value=0) as find_canary_nginx:
            self._parse_nginx_lines()
            find_canary_nginx.assert_called()

    def test_can_detect_canary_nginx(self):
        """Parse an Nginx log, and assert that the create_object is
           called on CanaryAlertItem."""

        canary = CanaryFileHelpers.create_canary_file(self.mu)

        # matches the canary from one of the logs
        canary.canary_filename = '945e2d7b-ce9d-48a7-9dc4-82704a914a85.png'
        canary.save()

        with patch.object(CanaryAlertItem, 'create_object',
                          return_value=0) as create_object:
            self._parse_nginx_lines()
            create_object.assert_called()

    def test_can_parse_dns_log(self):
        """Parse a querylog, and assert the _find_canary_dns
           function is called."""

        with patch.object(log.DNS, '_find_canary_dns',
                          return_value=0) as find_canary_dns:
            self._parse_dns_lines()
            find_canary_dns.assert_called()

    def test_can_detect_canary_dns(self):
        """Parse a querylog, and assert that the create_object function is
           called on CanaryAlertItem."""

        canary = CanaryFileHelpers.create_canary_file(self.mu)

        canary.identifier = 'af3d31907327c803afcf'
        canary.save()

        with patch.object(CanaryAlertItem, 'create_object',
                          return_value=0) as create_object:
            self._parse_dns_lines()
            create_object.assert_called()

    def test_can_parse_smb_log(self):
        """Parse an SMB log, and assert that the _find_canary_smb is called."""

        with patch.object(log.SMB, '_find_canary_smb',
                          return_value=0) as find_canary_smb:
            self._parse_smb_lines()
            find_canary_smb.assert_called()

    def test_can_detect_canary_smb(self):
        """Parse an SMB log, and assert that the create_object function is called
           from CanaryAlertItem."""

        canary = CanaryFileHelpers.create_canary_file(self.mu)

        canary.canary_filename = 'ebb3945c-12a3-40de-b973-5a3408709346.xslt'
        canary.save()

        with patch.object(CanaryAlertItem, 'create_object',
                          return_value=0) as create_object:
            self._parse_smb_lines()
            create_object.assert_called()

    def test_can_start_parser_invalid_path(self):
        """Start log parser without a valid log."""

        monitor = log.Log()

        state = Mock()
        state.is_active = True

        parse_line = Mock(return_value=0)

        with self.assertRaises(FileNotFoundError):
            monitor.monitor_log(parse_line, '/var/log/not-real', state)

    def test_can_start_parser(self):
        """Start log parser with a valid log"""

        s = serverState()
        nginx = log.Nginx()
        monitor = log.Log()

        mopen = mock_open(read_data="Just testing the open function")

        with self.assertRaises(OSError):
            with patch.dict(monitor.monitor_log.__globals__[
                                                      '__builtins__'
                                                      ], {'open': mopen}):
                with patch.dict(monitor.monitor_log.__globals__,
                                {'sleep': Mock(side_effect=OSError())}
                                ) as sleep:
                    monitor.monitor_log(nginx.parse, self.nginx, s)
                    sleep.assert_called()

    def _parse_nginx_lines(self):
        nginx = log.Nginx()

        with open(self.nginx, 'r') as fd:
            lines = fd.readlines()

        for line in lines:
            nginx.parse(line)

    def _parse_dns_lines(self):
        dns = log.DNS()

        with open(self.dns, 'r') as fd:
            lines = fd.readlines()

        for line in lines:
            dns.parse(line)

    def _parse_smb_lines(self):
        smb = log.SMB()

        with open(self.smb, 'r') as fd:
            lines = fd.readlines()

        for line in lines:
            smb.parse(line)


class DaemonTestcase(TestCase):

    def setUp(self):

        logger.Logger = Mock(return_value=LoggerHelper.return_mock_logger())
        daemon.mkfifo = Mock(return_value=0)
        daemon.sleep = Mock(side_effect=OSError)

        daemon.settings.parsers = [['smb'], ['nginx'], ['dns']]

    def test_can_start_daemon(self):
        """Test attempt to start daemon."""

        with patch.dict(
                daemon.cmdServer.start_parsers.__globals__, {
                    'Thread': Mock(
                        return_value=ThreadHelper.return_mock_thread()
                        )
                    }):
                with patch.object(daemon.cmdServer, 'start_parsers',
                                  return_value=0):
                    self.d = daemon.cmdServer()

    def test_can_start_daemon_state_false(self):
        """Test attempt start daemon set serverstate to False."""

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread())}):

            with patch.object(daemon.serverState, 'is_active',
                              return_value=False):
                self.d = daemon.cmdServer()
                self.assertFalse(self.d.state.is_active())

            self.d.stop_parsers()

    def test_can_start_thread_handle_filenotfound(self):
        """Test serverstate to inactive when FileNotFoundError exception."""

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread(),
                         side_effect=FileNotFoundError('woopsie'))}):

            self.d = daemon.cmdServer()

            self.d.stop_parsers()

        self.assertFalse(self.d.state.is_active())

    def test_join_thread_when_parser_stop(self):
        """Test server should join threads on stop."""

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread())
                         }):

            with patch.object(daemon.serverState, 'is_active',
                              return_value=False):
                self.d = daemon.cmdServer()

            self.d.stop_parsers()

    def test_server_loop(self):
        """Test if server loops works."""

        self.d = daemon

        with patch.dict(self.d.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread()
                            )}):

            self.d.cmdServer()

    def test_restart_threads(self):
        """Test if thread not alive can restart."""

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread_dead())
                         }):

            self.d = daemon.cmdServer()
            self.d.check_alive()

    def test_server_watch_threads(self):
        """Test if server watch threads functions."""

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread())}):

            self.d = daemon.cmdServer()

            with self.assertRaises(OSError):
                self.d.watch_threads()

    def test_server_start_logs(self):

        with patch.dict(daemon.cmdServer.start_parsers.__globals__,
                        {'Thread': Mock(
                            return_value=ThreadHelper.return_mock_thread())}):

            daemon.Log.monitor_log = Mock(side_effect=OSError('test'))
            d = daemon.cmdServer()

            for item in ['smb', 'nginx', 'dns']:
                d.start_log(item)


class WriteDeploySettingsTest(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.c_id = canary.generate_canary
        self.location = 'testcase_share'
        self.action = 'sms'
        self.filename = 'd62c91ca-93c2-40b3-a962-9920139913e9.png'
        self.canary_url = f"http://schemas.testcase/images/{self.filename}"

        self.defset = DefaultSetting.objects.get(setting_name='Defaults')

        self.ctypes = {'http': self.c_id(), 'unc': self.c_id()}

        self.dir_types = {'http': self.defset.web_root,
                          'unc': self.defset.smb_root}

        for ctype in self.ctypes.keys():
            canary.write_settings(self.canary_url, self.ctypes[ctype],
                                  self.location, self.action,
                                  self.filename, ctype, False)

        def tearDown(self):

            deploy = parse_deploy_cached()

            for item in deploy:
                _, path = item
                remove(path)

            remove(canary.settings.cache)

        def test_write_cache_file(self):
            """Generates cache file and check if files exist, return True"""

            deploy = parse_deploy_cached()

            for item in deploy:
                _, path = item
                self.assertTrue(access(path, F_OK))


class CanaryPopulationTest(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.canary_id = canary.generate_canary()
        self.filename = '6c570eb4-1de4-4d63-b3d2-fabbad23d144.png'
        self.dns = False
        self.rdir = False
        self.defset = DefaultSetting.objects.get(setting_name='Defaults')
        self.domain = self.defset.domain_name

    def test_generate_web_canary(self):
        """Populate HTTP canary, should return True"""

        val_can = f"http://schemas.{self.domain}/images/{self.filename}"

        pop_can = canary.populate_canary(self.canary_id, 'http', self.domain,
                                         self.dns, self.filename, self.rdir,
                                         self.defset)

        self.assertEqual(pop_can, val_can)

    def test_generate_unc_canary(self):
        """Populate UNC canary, should return True"""
        val_can = f"\\\\schemas.{self.domain}\\templates\\{self.filename}"

        pop_can = canary.populate_canary(self.canary_id, 'unc', self.domain,
                                         self.dns, self.filename, self.rdir,
                                         self.defset)

        self.assertEqual(pop_can, val_can)


class WriteCanaryTest(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        defset = DefaultSetting.objects.get(setting_name='Defaults')
        self.filename = '12f3fe12-c626-4334-90d2-4426a67fb322.png'
        self.location = 'testcase_share'
        self.deploy_root = '/tmp/.deploy_cache'
        self.canary_path = defset.canary_path
        self.rdir = False

    def test_write_canary_file_http_docx(self):
        """Write the canary image HTTP docx, return True"""

        canary = CanaryFileHelpers.create_canary_file(None)

        ctype = 'http'
        extension = 'docx'
        self.assertTrue(write_canary_file(canary, self.filename, self.location,
                                          self.deploy_root, ctype,
                                          extension, self.canary_path,
                                          self.rdir, '.deploy_cache'))

        canary_out = f"{self.deploy_root}/http/{self.filename}"

        self.assertTrue(access(canary_out, F_OK))

        deploy = parse_deploy_cached(canary)

        for i, item in enumerate(deploy):
            suffix, path = item

            if i == 0:
                self.assertEqual(suffix, 'http')

            elif i == 1:
                self.assertEqual(suffix, 'dns')


class libSMSSTestcases(TestCase):

    fixtures = ['manage_api/fixtures/sms_test_settings.json',
                'manage_api/fixtures/smtp_test_settings.json',
                'manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        self.mu = UserHelpers.create_authenticated_user()
        SMTP.connect = Mock(return_value=((220, False)))
        SMTP.close = Mock(return_value=0)
        SMTP.ehlo = Mock(return_value=0)
        SMTP.sendmail = Mock(return_value=0)

        c = CanaryAlertHelpers()
        self.alert = c.create_alert_items()[0]
        self.canary = CanaryFileHelpers.create_canary_file(self.mu)

        self.alert.identifier = self.canary.identifier
        self.alert.save()

    def test_send_sms_return_true(self):
        """Test send SMS message on alert."""

        Session.post = Mock(return_value=MockSession.return_token_text())

        s = sms.SMS()
        s.send_sms(self.alert.identifier, self.alert.date, self.alert.location,
                   self.alert.canary_type, self.alert.ip)

    def test_send_sms_cannot_obtain_token(self):
        """Attempt to send SMS should result in TypeError."""

        with patch.object(Session, 'post',
                          return_value=MockSession.return_status_code(400)):

            s = sms.SMS()
            s.send_sms(self.alert.identifier, self.alert.date,
                       self.alert.location,
                       self.alert.canary_type,
                       self.alert.ip)


class libSMTPTestcase(TestCase):

    fixtures = ['manage_api/fixtures/sms_test_settings.json',
                'manage_api/fixtures/smtp_test_settings.json',
                'manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()

    def test_send_email_invalid_connect(self):
        """Test send an email, which fails with a connect error, should generate
           a log entry."""

        SMTP.close = Mock(return_value=0)
        SMTP.ehlo = Mock(return_value=0)
        SMTP.sendmail = Mock(return_value=0)

        c = CanaryAlertHelpers()

        with patch.object(SMTP, 'connect', return_value=((501, False))):
            self.alert = c.create_alert_items()[0]

        fails = CanaryLogItem.objects.filter(msg='(501, False)')

        self.assertTrue(fails.exists())
        self.assertIn('SMTPConnectError(code, msg)', fails[0].stacktrace)

    def test_send_email_invalid_recipient(self):
        """Test send an email which fails due to an invalid recipient, should generate
           a log entry."""

        SMTP.sock = MagicMock(socket)
        SMTP.sendmail = Mock(return_value=0, side_effect=SMTPRecipientsRefused(
                                                    'test recipient refused'
                                                )
                             )

        c = CanaryAlertHelpers()
        self.alert = c.create_alert_items()[0]

        fails = CanaryLogItem.objects.filter(msg='test recipient refused')

        self.assertTrue(fails.exists())
        self.assertIn('send_mail', fails[0].stacktrace)


class SSLVerifyTestcases(TestCase):

    def test_30_days_expiration(self):
        """Test if invalid certificate is detected."""

        time = datetime.now()

        # the x509 object will expire witin 28 days
        expiry = float(time.timestamp() + 2591952)

        x = X509Helpers.return_x509_object(expiry, False)

        self.assertFalse(SSLVerify.is_certificate_expired(x))
        self.assertTrue(SSLVerify.is_certificate_expiring(x))

    def test_certificate_expired(self):
        """Test if an expired certificate is being handled."""

        time = datetime.now()

        # the x509 object expired 32 days ago
        expiry = float(time.timestamp() - 2591952)

        x = X509Helpers.return_x509_object(expiry, True)

        self.assertTrue(SSLVerify.is_certificate_expired(x))

    def test_certificate_valid(self):
        """Test if a valid certificate leads to True."""

        time = datetime.now()

        expiry = float(time.timestamp() + 2593952)

        x = X509Helpers.return_x509_object(expiry, False)

        self.assertFalse(SSLVerify.is_certificate_expired(x))
        self.assertFalse(SSLVerify.is_certificate_expiring(x))

    def test_local_certificate_valid(self):
        """Test if local certificate validity check goes well."""

        time = datetime.now()
        expiry = float(time.timestamp() + 2593952)

        x = X509Helpers.return_x509_object(expiry, False)

        mopen = mock_open(read_data="Just testing the open function")

        with patch.dict(SSLVerify.is_local_certificate_valid.__globals__,
                        {'load_certificate': Mock(return_value=x)}):
            # for some reason with patch('__main__.open', mopen): .. didn't work
            with patch.dict(SSLVerify.is_local_certificate_valid.__globals__[
                                                          '__builtins__'
                                                            ], {'open': mopen}):

                self.assertTrue(
                        SSLVerify.is_local_certificate_valid('doesnotmatter')
                        )

    def test_get_remote_certificate(self):
        """Test if remote certificate validity is checked properly,
           should return True"""

        time = datetime.now()
        expiry = float(time.timestamp() + 2593952)

        x = X509Helpers.return_x509_object(expiry, True)

        with patch.dict(SSLVerify._get_remote_certificate_x509.__globals__,
                        {'get_server_certificate': Mock(return_value=0),
                         'load_certificate': Mock(return_value=x)}):
            SSLVerify.is_remote_certificate_valid('ip', 'port')

    def test_cannot_contact_host(self):
        """Test handling of an SSLError."""

        time = datetime.now()
        expiry = float(time.timestamp() + 2593952)

        x = X509Helpers.return_x509_object(expiry, True)

        with patch.dict(SSLVerify._get_remote_certificate_x509.__globals__,
                        {'get_server_certificate': Mock(return_value=0),
                         'load_certificate': Mock(return_value=x,
                                                  side_effect=SSLError())}):
            SSLVerify.is_remote_certificate_valid('ip', 'port')


class DeploymentTestcases(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):

        # overwrite function return values
        self.d = deploy.Deploy
        self.d._initialize_ssh_agent = Mock(return_value=0)
        self._create_mock_inventory()

        self.targets = ['http:/tmp/http', 'unc:/tmp/unc',
                        'dns:/tmp/dns']

    def tearDown(self):

        if access('/tmp/inventory', F_OK):
            remove('/tmp/inventory')

    def test_deploy_targets(self):
        """Test deployment all the way to `_run_task`. Should return False"""

        self.d._run_task = Mock(return_value=0)
        self._create_target_files()

        self.d.deploy_targets(self.targets, '0000', '.deploy',
                              'AAFFBB', 'peter', '/tmp/inventory')

    def test_deploy_targets_fail(self):
        """Test deployment failing after `_run_task`, should create failed deployment
           file. Should return True"""

        self.d._run_task = Mock(return_value=True)
        self._create_target_files()

        for target in self.targets:
            suff, path = target.split(':')

            self.d.deploy_targets([target], '0000', f"/tmp/deploy_{suff}",
                                  'AAFFBB', 'peter', '/tmp/inventory')

    def test_deploy_targets_invalid_inventory(self):
        """Attempting to deploy targets with an invalid inventory file.
           Should return False"""

        self.d._run_task = Mock(return_value=0)
        self._create_target_files()

        for target in self.targets:
            suff, path = target.split(':')

            with self.assertRaises(ValueError):
                self.d.deploy_targets([target], '0000',
                                      f"/tmp/deploy_{suff}",
                                      'AAFFBB', 'peter',
                                      '/etc/passwd')
            self.assertTrue(access(path, F_OK))

    def test_deploy_targets_no_inventory(self):
        """Attempting to deploy targets without an existing inventory file.
           Should return False."""
        self.d._run_task = Mock(return_value=0)
        self._create_target_files()

        for target in self.targets:
            suff, path = target.split(':')

            with self.assertRaises(ValueError):
                self.d.deploy_targets([target],
                                      '0000', f"/tmp/deploy_{suff}",
                                      'AAFFBB', 'peter', '/etc/ansible/hr0sts')
                self.assertTrue(access(path, F_OK))

    def _create_target_files(self):

        for file in ['/tmp/http', '/tmp/unc', '/tmp/dns',
                     '/tmp/deploy_http', '/tmp/deploy_unc',
                     '/tmp/deploy_dns']:

            with open(file, 'w+') as fd:
                fd.write('asdasdasdasdas\n')

    def _create_mock_inventory(self):

        inventory = ('[test]\n'
                     '0.1.2.3\n')

        with open('/tmp/inventory', 'w+') as fd:
            fd.write(inventory)


class AsynchronousTasksTestcase(TestCase):

    fixtures = ['manage_api/fixtures/default_test_settings.json']

    def setUp(self):
        self.mu = UserHelpers.create_authenticated_user()

    def test_canary_deletion(self):
        """Test deletion of canary file."""

        xlsx = CanaryFileHelpers.create_canary_file(self.mu)
        path = xlsx.canary_doc.path

        self.assertTrue(access(path, F_OK))

        job = AsynchronousDelete(xlsx, 0.1)

        enqueue(job.run)
        get_worker(worker_class=SimpleWorker).work(burst=True)

        self.assertFalse(access(path, F_OK))


class RQScheduledJobs(TestCase):

    def test_remove_job_media_docs(self):
        """Test if job for scheduling, properly removes the media/docs"""

        enqueue(tasks.delete_uploaded_files)
        get_worker(worker_class=SimpleWorker).work(burst=True)

        self.assertFalse(glob(f"{settings.MEDIA_ROOT}/docs/*"))
