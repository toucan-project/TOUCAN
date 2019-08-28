from time import sleep

from django.apps import apps

from canary_utils.lib.deploy import Deploy
from canary_utils.canary import deploy_canaries

from canary_api.settings import SECRET_KEY

from cryptography.fernet import Fernet as Crypto
from cryptography.fernet import InvalidToken


class AsynchronousDeployTask():

    def _return_secret_key(self):

        CanaryLogItem = apps.get_model('canary_log_api.CanaryLogItem')
        Deployment = apps.get_model('canary_files', 'Deployment')

        try:

            crypto = Crypto(SECRET_KEY)
            key = crypto.decrypt(self.defset.secret_key.encode('utf-8'))

            return key

        except InvalidToken:

            # the fernet exception InvalidToken, has no message object
            # and __str__ reduces it to an emtry string therefore we catch that
            # one separately
            msg = 'Invalid key used for decrypting the deployment variables.'

            Deployment.full_deployment_fail(msg, self.obj)
            CanaryLogItem.log_message(self.added_by, self.obj, msg)

            return False

        except Exception as e:

            # if string is empty
            if not e:
                msg = ('Decryption of deployment variables went wrong and '
                       'cannot get an error message. Deployment failed.')

            else:
                msg = e

            Deployment.full_deployment_fail(msg, self.obj)
            CanaryLogItem.log_message(self.added_by, self.obj, msg)

            return False


class AsynchronousDelete():
    """Class responsible for asynchronously deleting the uploaded
       documents."""

    def __init__(self, obj, rmt,  **kwargs):
        """Get variables and initialize object."""

        self.obj = obj
        self.rmt = rmt
        super(AsynchronousDelete, self).__init__(**kwargs)

    def run(self):
        """Execute the thread and delete the canary document."""

        CanaryLogItem = apps.get_model('canary_log_api', 'CanaryLogItem')
        CanaryLogItem.log_message(self.obj.added_by, self.obj,
                                  'plain document deleted')
        sleep(self.rmt)
        self.obj.canary_doc.delete()


class AsynchronousDeleteCanary(AsynchronousDeployTask):
    """Asynchronous task for deleting remote canary files."""

    def __init__(self, deployment, defset, obj, **kwargs):
        """Initialize the variables and the object."""

        self.added_by = obj.added_by
        self.defset = defset
        self.obj = obj
        self.deployment = deployment
        self.source = defset.source

        super(AsynchronousDeleteCanary, self).__init__(**kwargs)

    def run(self):
        """Execute the thread and remove the remote files from the server."""

        key = self._return_secret_key()

        if not key:
            return

        for item in self.deployment:

            if item.canary_string.startswith('dns:'):
                self._remove_lines_from_dns(key)

            else:
                self._remove_remote_files(key, item)

    def _remove_remote_files(self, key, item):
        Deploy.remove_targets(item.dest, key, self.obj, self.added_by,
                              self.source)

    def _remove_lines_from_dns(self, key):
        Deploy.remove_lines_from_dns(self.obj, key, self.added_by,
                                     self.source)


class AsynchronousDeploy(AsynchronousDeployTask):
    """Asynchronous task for deploying the correct files to the
       right places."""

    def __init__(self, defset, obj, source, **kwargs):
        """Initialize the variables and the object."""

        self.defset = defset
        self.identifier = obj.identifier
        self.added_by = obj.added_by
        self.obj = obj
        self.source = source

        super(AsynchronousDeploy, self).__init__(**kwargs)

    def run(self):
        """Decrypt the secret and execute the deployment task."""

        # wait for last database write
        sleep(2)

        key = self._return_secret_key()

        if not key:
            return

        deploy_canaries(key, self.identifier, self.added_by, self.obj)
