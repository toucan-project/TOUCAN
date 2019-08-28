#!/usr/bin/env python3
from uuid import uuid4
from random import randrange

from rest_framework.exceptions import ValidationError

from canary_api import settings

from canary_utils.lib.deploy import Deploy
from canary_utils.lib.util import has_access
from canary_utils.lib.pdf import make_pdf_canary
from canary_utils.lib.pptx import make_ppt_canary
from canary_utils.lib.docx import make_word_canary
from canary_utils.lib.xlsx import make_excel_canary
from canary_utils.lib.docm import make_macro_canary


def deploy_canaries(vault_key, identifier, added_by, canary, source):
    """Check the deployment cache and deploy targets if available."""

    targets = Deploy.check_deploy(canary)

    if targets:
        Deploy.deploy_targets(targets, vault_key, identifier, added_by, canary,
                              source)

    else:
        print('--- nothing to deploy!')


def make_canary(template, outfile, ext, macro, canary, force, metadata):
    """Generate corresponding canaries, based on the extension."""

    if not force:
        if has_access(outfile, 'F_OK'):
            raise ValidationError(f'{outfile} already exists')

    if ext == 'xlsx' or ext == 'xlsm':
        ret = make_excel_canary(template, outfile, canary, force, metadata)

    elif ext == 'pptx' or ext == 'ppt':
        ret = make_ppt_canary(template, outfile, canary, force, metadata)

    elif ext == 'docx' and not macro:
        ret = make_word_canary(template, outfile, canary, force, metadata)

    elif ext == 'docx' and macro:
        ret = make_macro_canary(template, outfile, canary, force, metadata)

    elif ext == 'pdf':
        ret = make_pdf_canary(template, outfile, canary)

    else:
        raise ValidationError(f"--- invalid filetype {ext}")

    return ret


def get_extension(template):
    """Return the extensions of the file."""

    temp = template.split('.')

    return temp[len(temp)-1]


def generate_canary():
    """Generate hex value as canary identifier."""

    return f"{randrange(16**20):x}"  # nosec: no cryptographic function


def get_canary_path_for_protocol(ctype):
    """Get remote path for canary files to be uploaded."""

    if ctype == 'unc':
        canary_path = settings.smb_canary_path

    else:
        canary_path = settings.canary_path

    return canary_path


def return_file(temp, protocol):
    """Remote filename for canary file, PNG, PDF or DOTX, depending on the
       file type."""
    extension = get_extension(temp)

    if extension == 'pdf':
        filename = f"{uuid4()}.pdf"
        ctype = 'unc'

    elif extension == 'docx':
        filename = f"{uuid4()}.dotx"
        ctype = protocol

    elif extension == 'xlsx' and protocol == 'unc':
        filename = f"{uuid4()}.xslt"
        ctype = protocol

    else:
        filename = f"{uuid4()}.png"
        ctype = protocol

    return extension, filename, ctype


def populate_canary(canary_id, protocol, domain, dns, filename, rdir,
                    settings):
    """Create actual canary URI / URL."""

    if protocol not in ['unc', 'http', 'https']:
        raise ValidationError('Unknown protocol specified')

    if dns:
        domain = f"{canary_id}.{domain}"

    else:
        domain = f"{settings.nginx_domain}.{domain}"

    if protocol == 'unc':

        if not rdir:
            canary = f"\\\\{domain}\\templates\\{filename}"

        else:
            canary = f"\\\\{domain}\\templates\\{rdir}\\{filename}"

    else:
        if not rdir:
            canary = f"{protocol}://{domain}/images/{filename}"

        else:
            canary = f"{protocol}://{domain}/images/{rdir}/{filename}"

    return canary
