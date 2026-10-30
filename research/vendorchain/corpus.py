"""Generate inert regression fixtures and evaluate a hash-pinned external corpus."""
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib
from PIL import Image, PngImagePlugin, ImageDraw
from pypdf import PdfWriter, PdfReader
from pypdf.generic import NameObject, TextStringObject, DictionaryObject, DecodedStreamObject
from .ingress import MAX_BYTES, Rejected
from .sandbox import isolated

def png(index=0, mode='RGB'):
    image = Image.new(mode, (160+index%31,80+index%13), 1 if mode in ('1','P','L') else (255,255,255))
    ImageDraw.Draw(image).text((8,30),'VENDORCHAIN '+str(index),fill=0)
    meta = PngImagePlugin.PngInfo()
    meta.add_text('Description','Historical export /JavaScript is plain text, not executable. '+str(index))
    stream=io.BytesIO(); image.save(stream,format='PNG',pnginfo=meta,optimize=index%2==0)
    return stream.getvalue()

def jpeg(index=0):
    stream=io.BytesIO()
    image=Image.new('RGB',(160+index%29,90+index%11),'white')
    ImageDraw.Draw(image).text((8,30),'INVOICE '+str(index),fill='black')
    image.save(stream,format='JPEG',progressive=bool(index%2),quality=60+index%35,
               comment=('Corporate legacy scanner '+str(index)).encode())
    return stream.getvalue()

def pdf(index=0, action=None, xxe=False, expansion=False):
    writer=PdfWriter(); writer.add_blank_page(612+index%20,792)
    writer.add_metadata({'/Title':'Invoice '+str(index),'/Subject':'The literal /JS is harmless metadata'})
    if action=='JavaScript':
        # Name escapes exercise parser decoding; this is inert test text.
        writer._root_object[NameObject('/OpenAction')]=writer._add_object(DictionaryObject({
            NameObject('/S'):NameObject('/JavaScript'),NameObject('/JS'):TextStringObject('/* inert regression */')}))
    elif action=='Launch':
        writer._root_object[NameObject('/OpenAction')]=DictionaryObject({NameObject('/S'):NameObject('/Launch'),NameObject('/F'):TextStringObject('NONEXISTENT_TEST_ONLY')})
    elif action=='EmbeddedFile':
        writer.add_attachment('inert.txt',b'INERT regression archive marker')
    if xxe:
        stream=DecodedStreamObject(); stream.set_data(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///NONEXISTENT_VENDORCHAIN_TEST_ONLY">]><x>&e;</x>')
        stream[NameObject('/Type')]=NameObject('/Metadata');stream[NameObject('/Subtype')]=NameObject('/XML')
        writer._root_object[NameObject('/Metadata')]=writer._add_object(stream.flate_encode())
    if expansion:
        stream=DecodedStreamObject(); stream.set_data(b' '*(16*1024*1024+1))
        writer.pages[0][NameObject('/Contents')]=writer._add_object(stream.flate_encode())
    if index%2:
        writer.compress_identical_objects(remove_identicals=True,remove_orphans=False)
    out=io.BytesIO();writer.write(out);return out.getvalue()

def polyglot(image):
    out=io.BytesIO(image)
    # ZIP readers legally locate their directory after an arbitrary prefix.
    with zipfile.ZipFile(out,'a',compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('INERT.txt',b'No executable content')
    data=out.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None and archive.read('INERT.txt')
    if image.startswith(b'%PDF-'):
        assert len(PdfReader(io.BytesIO(data)).pages)==1
    else:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
    return data

def fixtures(benign=300):
    for i in range(benign):
        if i%3==0:
            yield 'benign','png-legacy-'+str(i),png(i, ['RGB','L','P','1'][i%4])
        elif i%3==1:
            yield 'benign','jpeg-progressive-'+str(i),jpeg(i)
        else:
            yield 'benign','pdf-metadata-'+str(i),pdf(i)
    for i in range(6):
        yield 'adversarial','png-zip-polyglot-'+str(i),polyglot(png(i))
        yield 'adversarial','jpeg-zip-polyglot-'+str(i),polyglot(jpeg(i))
        yield 'adversarial','pdf-zip-polyglot-'+str(i),polyglot(pdf(i))
    for i in range(8):
        for action in ['JavaScript','Launch','EmbeddedFile']:
            yield 'adversarial','pdf-'+action+'-'+str(i),pdf(i,action=action)
    for i in range(4):
        yield 'adversarial','pdf-xxe-'+str(i),pdf(i,xxe=True)
        yield 'adversarial','pdf-expansion-'+str(i),pdf(i,expansion=True)
    for i in range(15):
        yield 'adversarial','exe-extension-spoof-'+str(i),b'MZ'+b'INERT extension spoof '+str(i).encode()
    # Tiny, bounded header specimen; no large bitmap is ever constructed.
    ihdr=struct.pack('>IIBBBBB',65000,65000,8,2,0,0,0)
    chunk=b'IHDR'+ihdr
    yield 'adversarial','png-pixel-bomb',b'\x89PNG\r\n\x1a\n'+struct.pack('>I',13)+chunk+struct.pack('>I',zlib.crc32(chunk)&0xffffffff)
    yield 'adversarial','xml-xxe-wrapper',b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///NONEXISTENT_TEST_ONLY">]><x>&e;</x>'
    yield 'adversarial','truncated-pdf',b'%PDF-1.7\n%%EOF'

def generate(root, benign=300):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    entries=[]
    for label,name,data in fixtures(benign):
        filename=name+'.bin'
        (root/filename).write_bytes(data)
        entries.append({'path':filename,'label':label,'family':name.rsplit('-',1)[0],
                        'sha256':hashlib.sha256(data).hexdigest(),'source':'generated-inert-regression'})
    manifest={'version':1,'kind':'synthetic-regression','entries':entries}
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2))
    return root/'manifest.json'

def rate(errors,total):
    from scipy.stats import beta
    if not total:
        return {'errors':errors,'n':total,'rate':None,'ci95':None}
    lo=0.0 if errors==0 else float(beta.ppf(.025,errors,total-errors+1))
    hi=1.0 if errors==total else float(beta.ppf(.975,errors+1,total-errors))
    return {'errors':errors,'n':total,'rate':errors/total,'ci95':[lo,hi]}

def evaluate(manifest_path):
    path=Path(manifest_path).resolve()
    manifest=json.loads(path.read_text())
    results=[];seen=set()
    for entry in manifest['entries']:
        if entry['label'] not in ('benign','adversarial'):
            raise ValueError('invalid corpus label')
        file=(path.parent/entry['path']).resolve()
        if not file.is_relative_to(path.parent):
            raise ValueError('corpus path escapes root')
        if file.stat().st_size>MAX_BYTES:
            data=None
            # Hash in bounded chunks, so oversized external files cannot OOM the runner.
            h=hashlib.sha256()
            with file.open('rb') as source:
                for chunk in iter(lambda:source.read(65536),b''):h.update(chunk)
            actual=h.hexdigest()
        else:
            data=file.read_bytes();actual=hashlib.sha256(data).hexdigest()
        if actual!=entry['sha256']:
            raise ValueError('corpus content changed: '+entry['path'])
        if actual in seen:
            raise ValueError('duplicate corpus specimen: '+entry['path'])
        seen.add(actual)
        try:
            if data is None:raise Rejected('file_size_limit')
            isolated(data);accepted=True;reason='accepted'
        except Rejected as exc:
            accepted=False;reason=str(exc)
        results.append({**entry,'accepted':accepted,'reason':reason})
    benign=[r for r in results if r['label']=='benign']
    attacks=[r for r in results if r['label']=='adversarial']
    return {'kind':manifest['kind'],'manifestHash':hashlib.sha256(path.read_bytes()).hexdigest(),
            'falseRejections':rate(sum(not r['accepted'] for r in benign),len(benign)),
            'bypasses':rate(sum(r['accepted'] for r in attacks),len(attacks)),
            'results':results,'historicalCorporateCorpusValidated':manifest['kind']=='external-corporate-reviewed'}
