#!/usr/bin/env python3
from zipfile import ZipFile
from defusedxml.minidom import parseString

from canary_api.settings import TEMPLATE_DIR
from canary_utils.lib.util import has_access
from canary_utils.lib.util import get_next_rid, find_highest_xml
from canary_utils.lib.util import open_zip, create_child, fix_metadata


def inject_pic_slide(slide_xml, pic, rid):
    """Inject picture into slide."""

    s = parseString(slide_xml)

    for child in pic.childNodes:
        if child.tagName == 'p:blipFill':
            node = child

    for child in node.childNodes:
        if child.tagName == 'a:blip':
            node = child

    node.attributes['r:embed'].value = rid

    child = s.lastChild.firstChild.firstChild

    if not child.tagName == 'p:spTree':
        raise ValidationError('Could not find PPTX tag p:spTree')

    child.appendChild(pic)

    return s.toxml()


def inject_pic_rels(slide_xml_rels, rid, target):
    """Inject picture relationships."""

    s = parseString(slide_xml_rels)

    attr = {'Id': rid,
            'Target': target,
            'TargetMode': 'External',
            'Type': 'http://schemas.openxmlformats.org/officeDocument/'
                    '2006/relationships/image'}

    return create_child(s, 'Relationship', attr)


def read_xml_pic(xml_pic):
    """Read XML picture."""

    s = parseString(xml_pic)

    return s.lastChild.lastChild


def make_ppt_canary(infile, outfile, canary, force, metadata):
    """Create powerpoint canary from input file."""

    z = open_zip(infile)
    zout = ZipFile(outfile, 'w', compression=8)

    overwrite = ['ppt/slides/', 'ppt/slides/_rels/',
                 'docProps/custom.xml']
    targets = []

    hi_slide = f"slide{find_highest_xml(z, 'slides')}.xml"
    rid = get_next_rid(z.read(f"{overwrite[1]}{hi_slide}.rels"))

    for name in z.namelist():
        if 'ppt/slideMasters/_rels/' in name:
            targets.append(name)

    if len(targets) == 0:
        raise ValidationError('Could not find PPTX image to backload')

        return False

    items = z.infolist()

    for item in items:
        if item.filename == f"{overwrite[0]}{hi_slide}":
            with open(f"{TEMPLATE_DIR}/xml/slidePic.xml", 'r') as fd:
                pic = read_xml_pic(fd.read())

            buffer = inject_pic_slide(z.read(item.filename), pic, rid)
            zout.writestr(item.filename, buffer)

        elif item.filename == f"{overwrite[1]}{hi_slide}.rels":
            buffer = inject_pic_rels(z.read(item.filename), rid, canary)
            zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[2]:

            if metadata:
                buffer = fix_metadata()

            else:
                buffer = z.read(item.filename)

            zout.writestr(item.filename, buffer)

        elif item.filename not in overwrite:
            buffer = z.read(item.filename)
            zout.writestr(item.filename, buffer)

    return outfile
