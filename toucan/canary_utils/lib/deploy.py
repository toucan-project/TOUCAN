import shutil
from collections import namedtuple
from subprocess import Popen, PIPE  # nosec: no injection issues

from django.apps import apps

import ansible.constants as C
from ansible.playbook.play import Play
from ansible.parsing.vault import VaultSecret
from ansible.vars.manager import VariableManager
from ansible.plugins.callback import CallbackBase
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.executor.task_queue_manager import TaskQueueManager

from canary_utils.lib.plays import Playbooks
from canary_utils.lib.util import get_files_from_task

from canary_log_api.models import CanaryLogItem

from manage_api.models import DefaultSetting


class ResultCallback(CallbackBase):
    """Callback to parse and print Ansible deployment results"""

    def __init__(self, canary, added_by, play_source, spath, **kwargs):

        self.identifier = canary.identifier
        self.canary = canary
        self.added_by = added_by
        self.playbook = play_source
        self.spath = spath

    def print_details(self, host, result):

        if ('msg' in result.keys()
                and 'invocation' in result.keys()):
            msg = result['msg']
            inv = None

            if 'dest' in result['invocation']['module_args'].keys():
                inv = result['invocation']['module_args']['dest']
                msg = f"[{host}] {msg}: {inv}"

            elif 'path' in result['invocation']['module_args'].keys():
                inv = result['invocation']['module_args']['path']
                msg = f"[{host}] {msg}: {inv}"

            else:
                msg = f"[{host}] task success: {msg}"

            self._write_details(msg, inv)

        elif 'dest' in result.keys() and 'src' in result.keys():

            dst = result['dest']
            src = result['src']
            msg = f"[{host}] {src} -> {dst}"

            self._write_details(msg, dst)

        elif 'diff' in result.keys():

            diff = result['diff']['after']

            dst = diff['path']

            if diff['state'] == 'absent':
                msg = f"[{host}] {dst} removed"

                # cannot canary in pre_delete
                self.canary = None

            else:
                return

            self._write_details(msg, dst)

        elif 'state' in result.keys():

            if result['state'] == 'absent':
                msg = f"[{host}] {result['path']} removed"

                # cannot log canary in pre_delete
                self.canary = None

            elif result['name'] == 'bind9':
                msg = f"[{host}] restarted DNS server"

            CanaryLogItem.log_message(user=self.added_by, msg=msg,
                                      canary=self.canary)

        elif 'cmd' in result.keys():

            cmd = result['cmd']

            if cmd[2] == 'manage_dns':
                identifier = cmd[4]

            msg = f"[{host}] removed {identifier} from {cmd[-1]}"

            # cannot log canary in pre_delete
            self.canary = None

            CanaryLogItem.log_message(user=self.added_by, msg=msg,
                                      canary=self.canary)

    def v2_runner_item_on_failed(self, result, **kwargs):
            self.v2_runner_on_failed(result)

    def v2_runner_on_failed(self, result, **kwargs):

        host = result._host
        msg = f"{host.name}: {result._result}"

        self._write_details(msg, host.name, failed=True)

    def v2_runner_on_ok(self, result, **kwargs):

        host = result._host
        result = result._result

        self.print_details(host, result)

    def v2_runner_on_unreachable(self, result):

        host = result._host.get_name()
        host = result._host

        msg = f"{host.name}: {result._result}"

        self._write_details(msg, host.name, failed=True)

    def _write_details(self, msg, dest, failed=False):

        CanaryLogItem.log_message(user=self.added_by, msg=msg,
                                  canary=self.canary)

        Deployment = apps.get_model('canary_files.Deployment')

        if not self.spath:
            canary_strings = get_files_from_task(self.playbook)

        else:
            canary_strings = self.spath

        for item in Deployment.objects.filter(canary=self.canary):
            if item.canary_string in canary_strings:

                if failed:
                    item.failed_deployment(msg)

                else:
                    item.finished_deployment(dest)


class Deploy():
    """Functions that are required for Ansible deployments."""

    @classmethod
    def check_deploy(cls, canary):
        """Checks if a deployment is available."""

        lines = []

        Deployment = apps.get_model('canary_files.Deployment')
        items = Deployment.objects.filter(canary=canary)

        for item in items:

            if item.canary_string:
                lines.append(item.canary_string)
                item.pending_deployment()

        if len(lines) > 0:
            print(f"[*] there are {len(lines)} undeployed files")

        return lines

    @classmethod
    def remove_targets(cls, dest, vault_key, canary, added_by, source):
        """Remotely deletes canary targets from servers."""

        cls._initialize_ssh_agent(cls, vault_key)

        node = Playbooks.return_template('node')

        node['tasks'].append(Playbooks.remove_file(dest))
        cls._initialize_play(node, vault_key, canary, added_by, source)

    @classmethod
    def remove_lines_from_dns(cls, canary, vault_key, added_by, source):
        """Remove lines from DNS zone db."""

        cls._initialize_ssh_agent(cls, vault_key)

        master = Playbooks.return_template('master')
        master['tasks'].append(Playbooks.remove_dns_lines(canary.identifier,
                                                          canary.domain))
        master['tasks'].append(Playbooks.restart_service('bind9'))

        cls._initialize_play(master, vault_key, canary, added_by, source)

    @classmethod
    def deploy_targets(cls, lines, vault_key, identifier, added_by, canary,
                       source):
        """Deploys targets using Playbooks and the Ansible inventory."""

        cls._initialize_ssh_agent(cls, vault_key)

        master = Playbooks.return_template('master')
        nodes = Playbooks.return_template('node')

        defset = DefaultSetting.objects.get(setting_name='Defaults')

        smb_root = defset.smb_root
        web_root = defset.web_root

        paths = []

        for i, line in enumerate(lines):
            proto, lpath = line.split(':')

            if proto == 'dns':
                rpath = '/etc/bind/zones/db.{{ auth_domain | mandatory }}'
                block_in, spath = Playbooks.file_append(lpath, rpath, ';')
                master['tasks'].append(block_in)
                paths.append(f"dns:{spath}")

            elif 'http' in proto:
                rpath = f"{web_root}/."
                nodes['tasks'].append(Playbooks.copy_files(lpath, rpath))

            elif proto == 'unc':
                rpath = f"{smb_root}/."
                nodes['tasks'].append(Playbooks.copy_files(lpath, rpath))

        if len(master['tasks']) >= 1:
            master['tasks'].append(Playbooks.restart_service('bind9'))

            cls._initialize_play(master, vault_key,
                                 canary, added_by, source, spath=paths)

        cls._initialize_play(nodes, vault_key,
                             canary, added_by, source)

    @classmethod
    def _run_task(cls, play, inventory, variable_manager, loader, options,
                  canary, added_by, play_source, spath):
        """Runs the Playbook tasks with the required variables and managers."""

        tqm = TaskQueueManager(
                inventory=inventory,
                variable_manager=variable_manager,
                loader=loader,
                options=options,
                passwords=dict(),
                stdout_callback=ResultCallback(canary, added_by, play_source,
                                               spath),
            )

        result = tqm.run(play)

        if tqm is not None:
            tqm.cleanup()
            shutil.rmtree(C.DEFAULT_LOCAL_TMP, True)

            return result

    @classmethod
    def _initialize_play(cls, play_source, vault_key, canary,
                         added_by, source, spath=None):
        """Initializes Ansible playbook with the default and required
           options."""

        Options = namedtuple('Options', ['connection', 'module_path', 'forks',
                                         'become', 'become_method',
                                         'become_user', 'check', 'diff'
                                         ])

        options = Options(connection='ssh', module_path=False, forks=10,
                          become=False, become_method='sudo',
                          become_user='root',
                          check=False,
                          diff=False)

        loader = DataLoader()

        vault_secrets = cls._initialize_vault_secrets(cls, vault_key)
        loader.set_vault_secrets(vault_secrets)

        inventory = InventoryManager(loader=loader,
                                     sources=source)

        if not inventory.parse_source(source, loader):
            raise ValueError('Invalid inventory source specified.')

        variable_manager = VariableManager(loader=loader, inventory=inventory)

        play = Play().load(play_source, variable_manager=variable_manager,
                           loader=loader)

        return cls._run_task(play, inventory, variable_manager, loader,
                             options, canary, added_by, play_source, spath)

    def _initialize_ssh_agent(self, password):
        """Initializes the SSH agent and loads the required private keys.
           This to prevent private key material being stored on disk."""

        dl = DataLoader()
        dl.set_vault_secrets(self._initialize_vault_secrets(self, password))

        # databaaaaaaase
        # maybe make distinction between multiple secrets depending on deploy
        ds = dl.load_from_file('/etc/ansible/key.ssh')
        key = self._return_valid_key(self, bytes(ds, encoding='utf-8'))

        ssh_add_cmd = "ssh-add -"

        ret = Popen((ssh_add_cmd.split()), stdin=PIPE)
        ret.communicate(key)

        if ret.returncode:
            raise OSError('--- something went wrong while loading the key')

    def _initialize_vault_secrets(self, password):
        """Create new VaultSecret data object with the password."""
        vault_secret = VaultSecret(_bytes=password)
        return [((C.DEFAULT_VAULT_IDENTITY, vault_secret))]

    def _return_valid_key(self, ds):
        """Rebuild the SSH key to be accepted by the agent."""

        material = ds.split(b' ')

        begin = material[:4]
        end = material[len(material)-4:]

        key = b' '.join(begin)
        key += b'\n'
        key += b'\n'.join(material[4:len(material)-4])
        key += b'\n'
        key += b' '.join(end)
        key += b'\n'

        return key
