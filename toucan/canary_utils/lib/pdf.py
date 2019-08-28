#!/usr/bin/env python3
from subprocess import check_call, DEVNULL  # nosec: line 183 no injection

from rest_framework.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile

from canary_utils.lib.util import has_access


def get_highest_obj(pdf, lf):
    """Get highest object in the PDF."""

    highest_obj = False
    i = 0

    pdf.seek(0)

    lines_parsed = []

    for lines in pdf.readlines():

        if lines.find(lf.encode('utf-8')) != -1:
            for line in lines.split(b'\r'):
                lines_parsed.append(line)

        else:
            lines_parsed.append(lines)

    for line in lines_parsed:

        index = line.find('0 obj'.encode('utf-8'))

        if index != -1:

            i = int(line.decode('utf-8').split()[0])

            if not highest_obj:
                highest_obj = i

            elif i > highest_obj:
                highest_obj = i

    return(highest_obj, i)


def read_pdf_file(input_file):
    """Read a PDF file."""

    if isinstance(input_file, InMemoryUploadedFile):
        return input_file

    if not has_access(input_file):
        raise ValidationError(f"cannot access {input_file}")

    return open(input_file, 'rb')


def get_object_offsets(pdf, last, lf):
    """Get offsets of the object."""

    obj_start = f"{lf}{last} 0 obj{lf}".encode('utf-8')
    obj_end = f"endobj{lf}".encode('utf-8')

    obj_start_index = pdf.find(obj_start)
    obj_end_index = pdf.find(obj_end, obj_start_index)

    return obj_start_index, obj_end_index, obj_end


def get_last_object(last, pdf, lf):
    """Find last object."""

    pdf.seek(0)
    pdf = pdf.read()

    obj_start_index, obj_end_index, obj_end = get_object_offsets(pdf, last, lf)

    if obj_start_index == -1 or obj_end_index == -1:
        lf = '\r'
        obj_start_index, obj_end_index, obj_end = get_object_offsets(
                                                                     pdf,
                                                                     last,
                                                                     lf)

        if obj_start_index == -1 or obj_end_index == -1:
            return False

    return pdf[obj_start_index:obj_end_index + len(obj_end)], lf, obj_end_index


def get_trailer_object(last_obj):
    """Get the document's trailer object."""

    # if trailer is found, try to do a proper injection
    trailer = '\ntrailer\n'
    trailer += f"<</Size {last_obj}/Root<</AcroForm<</XFA {last_obj} "
    trailer += "0 R>>/Pages<<>>>>>>"

    return trailer.encode('utf-8')


def inject_new_object(obj, pdf, new_object, lf, last_obj):
    """Inject new object in PDF document."""

    pdf.seek(0)
    npdf = pdf.read().split(lf.encode('utf-8'))
    pdf.close()

    obj = obj.lstrip()
    obj = obj.rstrip()
    obj = obj.split(f"{lf}".encode('utf-8'))

    begin_index = npdf.index(obj[0])
    insert = new_object

    npdf.insert(begin_index - 1, insert)

    sep = lf.encode('utf-8')

    return sep.join(npdf), begin_index


def inject_trailer(begin_index, last_obj, pdf, lf):
    """Inject trailer into document."""

    trailer = get_trailer_object(last_obj)
    part = pdf[begin_index::].split(lf.encode('utf-8'))

    index = False

    for item in range(0, len(part)):

        if part[item] == b'startxref':
            index = item

    if not index:
        return False

    inject = part[index:]

    new_pdf = pdf.split(lf.encode('utf-8').join(inject))

    inject.insert(0, trailer)

    new_pdf.insert(1, lf.encode('utf-8').join(inject))

    return lf.encode('utf-8').join(new_pdf)


def create_new_object(hi, lf, target):
    """Create new PDF object."""

    obj = f"<?xml version=\"1.0\" ?>{lf}"
    obj += f"<?xml-stylesheet href=\"\\\\{target}\\whatever.xslt\""
    obj += f" type=\"text/xsl\" ?>{lf}"
    new_object = (f"{hi + 1} 0 obj{lf}"
                  f"<</Length {len(obj)}>>{lf}"
                  f"stream{lf}"
                  f"{obj}"
                  f"endstream{lf}"
                  f"endobj{lf}"
                  f"xref{lf}").encode('utf-8')

    return new_object, hi + 1


def is_dos_line_feed(pdf):
    """Check if the PDF contains DOS line feeds."""

    i = 0

    for line in pdf.readlines():

        if b'\r\n' in line:
            i += 1

    if i > 25:
        return True

    return False


def fix_pdf_mutool(output_file, output_patched):
    """Use the mutool command to fix and clean the PDF file."""

    output_path = output_patched.split('/')

    filename = f"patched_{output_path.pop(-1)}"
    output_path.append(filename)

    output_patched = '//'.join(output_path)

    cmd = ['mutool', 'clean', output_file, output_patched]
    ret = check_call(cmd, stdout=DEVNULL, stderr=DEVNULL)  # nosec: no injection

    return ret


def is_trailer_present(pdf, obj_end_index):
    """Checks if trailer is present in PDF file."""

    pdf.seek(0)
    pdf = pdf.read()

    if b'trailer' in pdf[obj_end_index::]:
        return True

    return False


def make_pdf_canary(input_file, output_file, target):
    """Create new canary PDF from input file."""

    pdf = read_pdf_file(input_file)

    lf = '\n'

    if is_dos_line_feed(pdf):
        lf = '\r\n'

    hi, last = get_highest_obj(pdf, lf)
    obj, lf, obj_end_index = get_last_object(last, pdf, lf)

    if not obj:
        raise ValidationError('Could not find PDF object offsets')

    new_object, last_obj = create_new_object(hi, lf, target)

    pdf, begin_index = inject_new_object(obj, pdf, new_object, lf,
                                         last_obj)
    pdf = inject_trailer(begin_index, last_obj, pdf, lf)

    with open(output_file, 'wb+') as fd:
        fd.write(pdf)

    fix_pdf_mutool(output_file, output_file)

    return output_file
