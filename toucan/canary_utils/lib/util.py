from os import path
from sys import stderr
from zipfile import ZipFile
from datetime import datetime
from os.path import abspath, join
from traceback import extract_tb, format_list
from ssl import get_server_certificate, SSLError
from os import access, makedirs, remove, R_OK, W_OK, F_OK

from django.apps import apps

import defusedxml.ElementTree as xml
from defusedxml.minidom import parseString
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from canary_api import settings


def print_relationships(items, hi):
    """Print XML relationships."""

    for item in items:
        for key, value in item.items():
            print(f'{key}: {value}')
        print()

    print(f'{hi} is the highest relationship')


def create_child(document, element_name, attributes):
    """Create new XML child attribute."""

    newChild = document.createElement(element_name)
    x = document.lastChild

    for attr in attributes.keys():
        newChild.setAttribute(attr, attributes[attr])

    x.appendChild(newChild)

    return x.toxml()


def find_active_tab(z):
    """Find active tab in an Excel document."""

    workbook_xml = z.read('xl/workbook.xml')

    s = parseString(workbook_xml)
    wb = s.lastChild

    active_tab = 0

    for item in wb.childNodes:
        if item.tagName == 'bookViews':
            break

    for item in item.childNodes:
        if item.tagName == 'workbookView':
            break

    if 'activeTab' in item.attributes.keys():
        active_tab = item.attributes['activeTab'].value

    return int(active_tab)


def fix_metadata():
    """Fix the metadata to remove any real author information."""

    with open('canary_utils/canary_templates/xml/custom.xml', 'r') as metadata:
        xml = metadata.read()

    return xml


def open_zip(filename):
    """Open a zip file."""

    return ZipFile(filename, 'r')


def get_next_rid(rel_xml):
    """Get the next relationship id in the XML document."""

    maxRid = 0
    e = xml.fromstring(rel_xml)

    for rel in e:
        if 'Id' in rel.keys():
            thisRid = int(rel.get('Id')[3:])

            if maxRid < thisRid:
                maxRid = thisRid

    return 'rId' + str(maxRid + 1)


def check_deploy_path(root, path, deploy_root):
    """Check to see if the deploy path is writeable."""

    up_root = abspath(join(root, '..'))

    if not has_access(root, 'F_OK'):

        if has_access(up_root, 'W_OK'):
            makedirs(root)

        else:
            return False

    elif has_access(path, 'F_OK') and not has_access(path, 'W_OK'):
        return False

    return True


def write_named_string(identifier, deploy_root, canary, ip):
    """Write the named string to a file for the playbook to append."""

    dns_root = f"{deploy_root}/dns"
    dns_path = f"{dns_root}/{identifier}.db.append"

    if not check_deploy_path(dns_root, dns_path, deploy_root):
        return False

    line = (f"{identifier.ljust(35-len(identifier))} "
            f"IN      A{' ' * (21 -len(ip))}{ip}")
    line += "\n"

    with open(dns_path, 'a+') as fd:
        fd.write(line)

    Deployment = apps.get_model('canary_files.Deployment')
    Deployment.create_deployment(canary, f"dns:{dns_path}")

    return True


def has_access(filename, mode=R_OK):
    """Returns true if file is accessible with the given mode."""

    modes = {'F_OK': F_OK, 'W_OK': W_OK}

    if mode != R_OK:
        mode = modes[mode]

    if access(filename, mode):
        return True

    return False


def parse_deploy_cached(canary):
    """Parse the deploy cache file and return a list."""

    deploy = []

    Deployment = apps.get_model('canary_files.Deployment')
    items = Deployment.objects.filter(canary=canary)

    for item in items:

        suffix, path = item.canary_string.split(':')
        deploy.append((suffix, path.rstrip()))

    return deploy


def get_files_from_task(playbook, spath=False):
    """Get files used in a task from a Playbook."""

    failed_tasks = []
    tasks = playbook.pop('tasks')

    for task in tasks:
        if 'action' in task.keys():
            task = task.pop('action')

        else:
            return

        if task['module'] == 'copy':
            src = task.get('src')

        elif task['module'] == 'blockinfile':
            src = spath

        if 'http' in src:
            failed_tasks.append(f"http:{src}")

        elif 'smb' in src:
            failed_tasks.append(f"unc:{src}")

        elif 'dns' in src:
            failed_tasks.append(f"dns:{src}")

    return failed_tasks


def remove_deployment_item(item):

    suffix, file = item.split(':')
    remove(file)


def write_canary_file(identifier, filename, location, deploy_root, ctype,
                      extension, canary_path, rdir, cache):
    """Write the canary files, used in templates."""

    if 'http' in ctype:
        canary_root = f"{deploy_root}/http"

    elif ctype == 'unc':
        canary_root = f"{deploy_root}/smb"

    if rdir:
        canary_root = f"{canary_root}/{rdir}"

    canary_out = f"{canary_root}/{filename}"

    if not check_deploy_path(canary_root, canary_out, deploy_root):
        print_error(f"--- could not write image to {deploy_root}")
        return False

    directory = path.split(canary_out)[0]

    if not has_access(directory, 'W_OK'):
        return False

    with open(canary_out, 'wb+') as fd:
        f = open(canary_path, 'rb')
        fd.write(f.read())
        f.close()

    if rdir:
        canary_out = '/'.join(canary_out.split('/')[:-1])

    entry = f"{ctype}:{canary_out}"

    return entry


def find_highest_xml(z, typex):
    """Find the highest XML file in the given document."""

    hi = 0
    xmls = []

    if typex == 'sheet':
        sheet = 'xl/worksheets/sheet'

    elif typex == 'drawing':
        sheet = 'xl/drawings/drawing'

    elif typex == 'drawing_rel':
        sheet = 'xl/drawings/_rels/drawing'

    elif typex == 'slide_rel':
        sheet = 'ppt/slides/_rels'

    elif typex == 'slides':
        sheet = 'ppt/slides'

    for i in z.namelist():
        if sheet in i:
            xmls.append(i)

    for x in xmls:

        if '.xml' in x:
            n = int(x.split('/')[-1].split('.xml')[0][-1])

            if n > hi:
                hi = n

    return hi


def return_stack_trace(exception):

    if not isinstance(exception, Exception):
        return 'N/A'

    tb = exception.__traceback__
    tb_list = extract_tb(tb)

    return ''.join(format_list(tb_list))


def print_error(message):

    print(message, file=stderr)


class SSLVerify:

    @classmethod
    def is_certificate_expired(cls, cert):

        if cert.has_expired():
            return True

        return False

    @classmethod
    def is_certificate_expiring(cls, cert):
        if cls._expires_within_30_days(cls, cert):
            return True

        return False

    @classmethod
    def is_local_certificate_valid(cls, path):

        with open(path, 'r') as fd:
            cert = fd.read()

        x509 = load_certificate(FILETYPE_PEM, cert)

        return cls._check_certificate_validity(cls, x509)

    @classmethod
    def is_remote_certificate_valid(cls, ip, port):

        cert = cls._get_remote_certificate_x509(cls, ip, port)

        if not cert:
            return False

        return cls._check_certificate_validity(cls, cert)

    def _check_certificate_validity(self, cert):

        expired = self.is_certificate_expired(cert)
        expiring = self.is_certificate_expiring(cert)

        return expired, expiring

    def _get_remote_certificate_x509(self, ip, port):

        try:
            cert = get_server_certificate((ip, port))
            x509 = load_certificate(FILETYPE_PEM, cert)

        except SSLError:
            return False

        return x509

    def _expires_within_30_days(self, cert):

        time = cert.get_notAfter()
        timetuple = self._get_timetuple_from_string(self, time)

        return datetime.timestamp(datetime.now()) > (timetuple.timestamp()
                                                     - 2592000)

    def _get_timetuple_from_string(self, string):
        return datetime.strptime(string.decode('utf-8'), '%Y%m%d%H%M%SZ')
