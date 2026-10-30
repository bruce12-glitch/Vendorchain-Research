"""Structural file gate; run inside sandbox.py for untrusted documents."""
import io
import struct
import warnings
import zlib
import zipfile
from xml.parsers import expat
from PIL import Image
from pypdf import PdfReader, filters
from pypdf.generic import DictionaryObject, ArrayObject, IndirectObject, StreamObject

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 16_000_000
MAX_SIDE = 6000
MAX_PAGES = 20
MAX_EXPANDED = 16 * 1024 * 1024
POLICY = {"version": "vendorchain.ingress.v1", "types": ["PDF", "PNG", "JPEG"],
          "maxBytes": MAX_BYTES, "maxPixels": MAX_PIXELS, "maxSide": MAX_SIDE,
          "maxPages": MAX_PAGES, "maxExpandedBytes": MAX_EXPANDED,
          "activeContent": "deny", "trailingImageBytes": "deny", "secondaryZipContainer": "deny"}

class Rejected(ValueError):
    pass

def dimensions(w, h):
    if w <= 0 or h <= 0 or w > MAX_SIDE or h > MAX_SIDE or w * h > MAX_PIXELS:
        raise Rejected("image_dimension_limit")

def png_structure(data):
    pos = 8
    chunks = 0
    while pos + 12 <= len(data):
        n = int.from_bytes(data[pos:pos+4], "big")
        typ = data[pos+4:pos+8]
        end = pos + 12 + n
        if end > len(data) or n > MAX_BYTES:
            raise Rejected("png_chunk_bounds")
        if zlib.crc32(data[pos+4:pos+8+n]) & 0xffffffff != int.from_bytes(data[pos+8+n:end], "big"):
            raise Rejected("png_crc")
        chunks += 1
        if chunks > 4096:
            raise Rejected("png_chunk_limit")
        if chunks == 1 and (typ != b'IHDR' or n != 13):
            raise Rejected("png_ihdr")
        if typ == b'IHDR':
            dimensions(*struct.unpack('>II', data[pos+8:pos+16]))
        if typ == b'IEND':
            if n != 0 or end != len(data):
                raise Rejected("png_trailing_data")
            return
        pos = end
    raise Rejected("png_incomplete")

def jpeg_structure(data):
    # Walk segment lengths and entropy-coded scans, including progressive scans.
    pos = 2
    scan = False
    while pos < len(data):
        if scan:
            marker = data.find(b'\xff', pos)
            if marker < 0:
                break
            pos = marker
        if data[pos] != 255:
            raise Rejected("jpeg_marker")
        while pos < len(data) and data[pos] == 255:
            pos += 1
        if pos >= len(data):
            break
        code = data[pos]
        pos += 1
        if scan and (code == 0 or 0xd0 <= code <= 0xd7):
            continue
        scan = False
        if code == 0xd9:
            if pos != len(data):
                raise Rejected("jpeg_trailing_data")
            return
        if code == 0xd8 or code == 0 or 0xd0 <= code <= 0xd7:
            raise Rejected("jpeg_unexpected_marker")
        if code == 1:
            continue
        if pos + 2 > len(data):
            break
        length = int.from_bytes(data[pos:pos+2], 'big')
        if length < 2 or pos + length > len(data):
            raise Rejected("jpeg_segment_bounds")
        pos += length
        scan = code == 0xda
    raise Rejected("jpeg_incomplete")

def image_gate(data, kind):
    (png_structure if kind == "PNG" else jpeg_structure)(data)
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as img:
            if img.format != kind:
                raise Rejected("image_parser_mismatch")
            dimensions(*img.size)
            if getattr(img, 'n_frames', 1) != 1:
                raise Rejected("animated_image")
            img.verify()
        with Image.open(io.BytesIO(data)) as img:
            img.load()  # Complete decode, not only the signature/header.
            return {"format": kind, "width": img.width, "height": img.height, "pages": 1}

def pdf_gate(data):
    if not data.rstrip().endswith(b'%%EOF'):
        raise Rejected("pdf_trailing_or_incomplete")
    # pypdf's bounded Flate decoder is essential before touching stream data.
    filters.ZLIB_MAX_OUTPUT_LENGTH = MAX_EXPANDED
    reader = PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted:
        raise Rejected("encrypted_pdf")
    if not 1 <= len(reader.pages) <= MAX_PAGES:
        raise Rejected("pdf_page_limit")
    seen = set()
    count = expanded = 0
    denied = {'/JS', '/JavaScript', '/Launch', '/EmbeddedFiles', '/EmbeddedFile',
              '/RichMedia', '/XFA', '/AA', '/OpenAction', '/SubmitForm', '/ImportData'}
    def walk(obj, depth=0):
        nonlocal count, expanded
        if depth > 48:
            raise Rejected("pdf_depth_limit")
        if isinstance(obj, IndirectObject):
            identity = (obj.idnum, obj.generation)
            if identity in seen:
                return
            seen.add(identity)
            obj = obj.get_object()
        count += 1
        if count > 20000:
            raise Rejected("pdf_object_limit")
        if isinstance(obj, DictionaryObject):
            if denied.intersection(str(k) for k in obj.keys()):
                raise Rejected("pdf_active_content")
            if str(obj.get('/S', '')) in denied or str(obj.get('/Type', '')) in denied:
                raise Rejected("pdf_active_content")
            if str(obj.get('/Subtype', '')) == '/Image':
                dimensions(int(obj.get('/Width', 0)), int(obj.get('/Height', 0)))
            if isinstance(obj, StreamObject):
                decoded = obj.get_data()
                expanded += len(decoded)
                if expanded > MAX_EXPANDED:
                    raise Rejected("pdf_expansion_limit")
                if str(obj.get('/Subtype', '')) == '/XML' or str(obj.get('/Type', '')) == '/Metadata':
                    # Parse the declared XML encoding rather than searching UTF-8
                    # bytes: UTF-16 DTDs otherwise evade a raw marker check.
                    parser = expat.ParserCreate()
                    def forbid_entity(*_):
                        raise Rejected('xml_dtd_forbidden')
                    parser.StartDoctypeDeclHandler = forbid_entity
                    parser.EntityDeclHandler = forbid_entity
                    parser.ExternalEntityRefHandler = forbid_entity
                    parser.Parse(decoded, True)
            for value in obj.values():
                walk(value, depth+1)
        elif isinstance(obj, ArrayObject):
            for value in obj:
                walk(value, depth+1)
    # Traverse reachable objects AND every xref object, including orphan payloads.
    walk(reader.trailer)
    for generation, offsets in reader.xref.items():
        if generation == 65535:
            continue
        for num in offsets:
            if num:
                walk(IndirectObject(num, generation, reader))
    for num in reader.xref_objStm:
        walk(IndirectObject(num, 0, reader))
    for page in reader.pages:
        width, height = float(page.mediabox.width), float(page.mediabox.height)
        if not 0 < width <= 14400 or not 0 < height <= 14400:
            raise Rejected("pdf_page_dimensions")
    return {"format": "PDF", "pages": len(reader.pages), "expandedBytes": expanded}

def validate(data):
    if not 0 < len(data) <= MAX_BYTES:
        raise Rejected("file_size_limit")
    if data.startswith((b'MZ', b'\x7fELF')):
        raise Rejected("EXECUTABLE_SPOOF")
    try:
        # A complete ZIP directory can be hidden inside legal image metadata or
        # between a PDF's last xref and a forged final EOF marker. No extraction.
        if zipfile.is_zipfile(io.BytesIO(data)):
            raise Rejected('secondary_zip_container')
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            return image_gate(data, "PNG")
        if data.startswith(b'\xff\xd8\xff'):
            return image_gate(data, "JPEG")
        if data.startswith(b'%PDF-'):
            return pdf_gate(data)
        raise Rejected("unsupported_signature")
    except Rejected:
        raise
    except Exception as exc:
        raise Rejected("parser_rejected_" + type(exc).__name__) from exc
