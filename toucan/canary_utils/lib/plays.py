from datetime import datetime


class Playbooks():
    """Class containing methods for generating Playbooks."""

    @classmethod
    def return_template(cls, server, become='yes', name='Deploy files'):
        """Return master or node Playbook template."""

        if server == 'master':

            return dict(
                        name=name,
                        hosts='canary_main',
                        gather_facts='no',
                        become=become,
                        tasks=[]
                        )

        elif server == 'node':

            return dict(
                        name=name,
                        hosts='canary_nodes',
                        gather_facts='no',
                        become=become,
                        tasks=[]
                        )

    @classmethod
    def remove_dns_lines(cls, identifier, domain):
        """Task for removing identifier lines from DNS zone db."""

        env = '/opt/env/bin/python3'
        manage = '/opt/django/manage.py'
        app = 'manage_dns'
        args1 = "--identifier"
        args2 = "--path"
        value2 = f"/etc/bind/zones/db.{domain}"

        command = [env, manage, app, args1, identifier, args2, value2]

        return dict(
                    dict(action=dict(module='command',
                                     argv=command))
                    )

    @classmethod
    def restart_service(cls, service):
        """Task for restarting a systemd service."""

        return dict(
                    dict(action=dict(module='systemd',
                                     name=service,
                                     state='restarted'))
                    )

    @classmethod
    def copy_files(cls, lpath, rpath):
        """Task for copying files."""

        return dict(
                    dict(action=dict(module='copy',
                                     src=lpath,
                                     dest=rpath))
                    )

    @classmethod
    def remove_file(cls, dest):
        """Task for removing files."""

        return dict(
                    dict(action=dict(module='file',
                                     path=dest,
                                     state='absent'))
                    )

    @classmethod
    def file_append(cls, settings_path, rpath, comment):
        """Task for appending text to files."""

        with open(settings_path, 'r') as fd:
            block = fd.read()

        marker_begin = f"BEGIN ({cls._return_utc()})"
        marker_end = f"END"

        marker = f"{comment} {{mark}} AUTODEPLOYED BLOCK"

        return (dict(
                    dict(action=dict(module='blockinfile',
                                     path=rpath, block=block,
                                     marker_begin=marker_begin,
                                     marker_end=marker_end,
                                     marker=marker))
                    ), settings_path)

    @classmethod
    def _return_utc(self):
        """Return time as UTC."""

        return datetime.utcnow().isoformat()
