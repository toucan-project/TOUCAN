#!/usr/bin/env python3
from os import path
from zipfile import ZipFile
import defusedxml.ElementTree as xml
from defusedxml.minidom import parseString

from canary_api.settings import TEMPLATE_DIR
from canary_utils.lib.util import has_access, find_active_tab
from canary_utils.lib.util import find_highest_xml, get_next_rid
from canary_utils.lib.util import create_child, open_zip, fix_metadata


def inject_content_types(fd, drawing_name):
    """Inject content-types in the XML file."""

    x = xml.parse(fd).getroot()
    png = False

    for elem in list(x):
        if elem.attrib['ContentType'] == 'image/png':
            png = True

    fd.seek(0)
    content_types_xml = fd.read()
    s = parseString(content_types_xml)

    if not png:
        index = 0
        x = s.lastChild
        for child in x.childNodes:
            if child.nodeName == 'Default':
                index += 1

        refChild = x.childNodes[index]
        newChild = s.createElement('Default')
        newChild.setAttribute('Extension', 'png')
        newChild.setAttribute('ContentType', 'image/png')

        x.insertBefore(newChild, refChild)

    attr = {'ContentType': 'application/vnd.openxmlformats-'
                           'officedocument.drawing+xml',
            'PartName': f"/xl/drawings/{drawing_name}.xml"}

    return create_child(s, 'Override', attr)


def inject_relationship(sheet_xml_rels, rid, drawing):
    """Inject a new drawing relationship in a sheet."""

    s = parseString(sheet_xml_rels)

    attr = {'Id': rid,
            'Target': f'../drawings/{drawing}.xml',
            'Type': 'http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/drawing'}

    return create_child(s, 'Relationship', attr)


def inject_drawing_xml_rels(drawing_xml_rels, target):
    """Inject the drawing XML relationships."""

    s = parseString(drawing_xml_rels)
    attr = {'Id': 'rId1',
            'Type': 'http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/image',
            'Target': target,
            'TargetMode': 'External'}

    return create_child(s, 'Relationship', attr)


def inject_drawing_sheet(fd, rid):
    """Inject drawing in a sheet."""

    sheet_xml = fd.read()
    s = parseString(sheet_xml)
    e = s.lastChild
    newChild = s.createElement('drawing')

    newChild.setAttribute('r:id', rid)

    e.appendChild(newChild)

    return s.toxml()


def make_excel_canary(infile, outfile, canary, force, metadata):
    """Create a canary Excel file from given input."""

    z = open_zip(infile)

    if not z:
        return False

    zout = ZipFile(outfile, 'w', compression=8)

    overwrite = ['xl/drawings/', 'xl/drawings/_rels/',
                 'xl/worksheets/', 'xl/worksheets/_rels/',
                 '[Content_Types].xml', 'docProps/custom.xml']

    items = z.infolist()

    cu_sheet = f"sheet{find_active_tab(z)+1}.xml"
    xml_rels = f"{overwrite[3]}{cu_sheet}.rels"

    rid = get_next_rid(z.read(xml_rels))

    rid = f"rId{int(rid[3:])+1}"
    drawing = f"drawing{int(find_highest_xml(z, 'drawing'))+1}"

    for item in items:
        if item.filename == f"{overwrite[2]}{cu_sheet}":
            buffer = inject_drawing_sheet(z.open(item.filename), rid)
            zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[4]:
            buffer = inject_content_types(z.open(item.filename), drawing)
            zout.writestr(item.filename, buffer)

        elif item.filename == xml_rels:
            buffer = inject_relationship(z.read(item.filename), rid, drawing)
            zout.writestr(item.filename, buffer)

        elif item.filename == overwrite[5]:

            if metadata:
                buffer = fix_metadata()

            else:
                buffer = z.read(item.filename)

            zout.writestr(item.filename, buffer)

        elif item.filename not in overwrite:
            buffer = z.read(item.filename)
            zout.writestr(item.filename, buffer)

    with open(f"{TEMPLATE_DIR}/xml/drawings/drawingX.xml", 'r') as fd:
        zout.writestr(f"{overwrite[0]}{drawing}.xml", fd.read())

    with open(f"{TEMPLATE_DIR}/xml/drawings/_rels/drawingX.xml.rels",
              'r') as fd:

        buffer = inject_drawing_xml_rels(fd.read(), canary)
        zout.writestr(f"{overwrite[1]}{drawing}.xml.rels", buffer)

    return outfile
