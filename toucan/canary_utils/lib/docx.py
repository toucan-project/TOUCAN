#!/usr/bin/env python3
from zipfile import ZipFile
from defusedxml.minidom import parseString

from canary_api.settings import TEMPLATE_DIR
from canary_utils.lib.util import open_zip, create_child
from canary_utils.lib.util import fix_metadata, has_access


def inject_settings(settings_xml):
    """Inject settings into document."""

    s = parseString(settings_xml)
    return create_child(s, 'w:attachedTemplate', {'r:id': 'rId1'})


def make_word_canary(infile, outfile, target, force, metadata):
    """Inject attributes and create new Word canary document."""

    z = open_zip(infile)
    zout = ZipFile(outfile, 'w', compression=8)

    overwrite = ['word/_rels/settings.xml.rels', 'word/settings.xml',
                 'docProps/custom.xml']

    items = z.infolist()

    if overwrite[1] in z.namelist():
        buffer = inject_settings(z.read(overwrite[1]))
        zout.writestr(overwrite[1], buffer)

    for item in items:
        if item.filename not in overwrite:
            buffer = z.read(item.filename)
            zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[2]:

            if metadata:
                buffer = fix_metadata()

            else:
                buffer = z.read(item.filename)

            zout.writestr(item.filename, buffer)

    if overwrite[0] not in items:
        with open(f"{TEMPLATE_DIR}/xml/settings.xml.rels", 'r') as fd:
            r = fd.read().replace("{PLACE_HOLDER}", target)
            zout.writestr(overwrite[0], r)

    else:
        raise VaildationError('--- settings.xml.rels exists manually labor required...')

    return outfile
