#!/usr/bin/env python3
from zipfile import ZipFile
import defusedxml.ElementTree as xml
from defusedxml.minidom import parseString

from canary_api.settings import TEMPLATE_DIR
from canary_utils.lib.util import has_access
from canary_utils.lib.util import open_zip, create_child
from canary_utils.lib.util import get_next_rid, fix_metadata


def get_next_pid(custom_xml):
    """Get highest pid from XML file."""

    maxPid = 0
    e = xml.fromstring(custom_xml)

    for prop in e:

        if 'pid' in prop.keys():
            thisPid = int(prop.get('pid'))

            if maxPid < thisPid:
                maxPid = thisPid

    return str(maxPid + 1)


def get_fmt_id(custom_xml):
    """Return format id from  XML file."""

    e = xml.fromstring(custom_xml)

    for prop in e:
        if 'fmtid' in prop.keys():
            return prop.get('fmtid')


def inject_custom_property(custom_xml, name, value):
    """Inject custom macro properties into document."""

    s = parseString(custom_xml)
    a = s.firstChild

    prop = s.createElement('property')
    prop.setAttribute('fmtid', get_fmt_id(custom_xml))
    prop.setAttribute('pid', get_next_pid(custom_xml))
    prop.setAttribute('name', name)

    prop_lpwstr = s.createElement('vt:lpwstr')
    prop_val = s.createTextNode(value)

    prop_lpwstr.appendChild(prop_val)
    prop.appendChild(prop_lpwstr)
    a.appendChild(prop)

    return s.toxml()


def inject_doc_rels(docrel_xml):
    """Inject document relationships into document."""

    rId = get_next_rid(docrel_xml)
    s = parseString(docrel_xml)

    attr = {'Id': rId,
            'Type': 'http://schemas.microsoft.com/office'
                    '/2006/relationships/vbaProject',
            'Target': 'vbaProject.bin'}

    return create_child(s, 'Relationship', attr)


def inject_content_types(content_xml):
    """Add new content-types to the document."""

    s = parseString(content_xml)
    a = s.firstChild

    for tag in a.childNodes:
        if tag.hasAttribute('PartName'):
            if tag.getAttribute('PartName') == '/word/document.xml':
                tag.setAttribute('ContentType', 'application/vnd.ms-word'
                                                '.document.macroEnabled.'
                                                'main+xml')

    attr = {'Extension': 'bin',
            'ContentType': 'application/vnd.ms-office.vbaProject'}

    create_child(s, 'Default', attr)

    attr = {'PartName': '/word/vbaData.xml',
            'ContentType':  'application/vnd.ms-word.vbaData+xml'}

    return create_child(s, 'Override', attr)


def make_macro_canary(infile, outfile, canary, force, metadata):
    """Create and inject macros into new document."""

    z = open_zip(infile)
    zout = ZipFile(outfile, 'w', compression=8)

    overwrite = ['docProps/custom.xml', 'word/_rels/document.xml.rels',
                 '[Content_Types].xml', 'word/vbaProject.bin',
                 'word/vbaData.xml', 'word/_rels/vbaProject.bin.rels']

    items = z.infolist()

    for item in items:
        if item.filename == overwrite[0]:

                buffer = inject_custom_property(z.read(item.filename),
                                                'CustomFontUrl',
                                                canary
                                                + '\\C%20Font.ttf')
                if metadata:
                    buffer = fix_metadata()

                zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[1]:
            buffer = inject_doc_rels(z.read(item.filename))
            zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[2]:
            buffer = inject_content_types(z.read(item.filename))
            zout.writestr(item.filename, buffer)

        elif item.filename not in overwrite:
            buffer = z.read(item.filename)
            zout.writestr(item.filename, buffer)

    with open(f"{TEMPLATE_DIR}/xml/macro/vbaProject.bin", 'rb') as fd:
        zout.writestr(overwrite[3], fd.read())

    with open(f"{TEMPLATE_DIR}/xml/macro/vbaData.xml", 'r') as fd:
        zout.writestr(overwrite[4], fd.read())

    with open(f"{TEMPLATE_DIR}/xml/macro/vbaProject.bin.rels", 'r') as fd:
        zout.writestr(overwrite[5], fd.read())

    return outfile
