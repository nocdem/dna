#!/usr/bin/env python3
"""Explicit maintenance after reviewing independent reference output.

Adds newly generated fixtures. Refuses changes to existing fixture bytes so a
refresh cannot silently bless changed expected answers. Never called by CMake.
"""
import gzip
import hashlib
import json
import pathlib
import struct

folder=pathlib.Path(__file__).resolve().parent/'fixtures'
path=folder/'manifest.json';previous=json.loads(path.read_text()) if path.exists() else {}
manifest={}
for f in sorted(folder.glob('*.bin.gz')):
    compressed=f.read_bytes();raw=gzip.decompress(compressed)
    if raw[:8]!=b'PQPORT01':raise ValueError('Invalid fixture magic: '+f.name)
    count=struct.unpack_from('<I',raw,8)[0];off=12;stats={}
    if not 0<count<=10000:raise ValueError('Invalid fixture count: '+f.name)
    for _ in range(count):
        scheme,param,tid,flags=struct.unpack_from('<4I',raw,off);off+=16;fields=[]
        for i in range(8):
            n=struct.unpack_from('<I',raw,off)[0];off+=4
            if n>1048576 or off+n>len(raw):raise ValueError('Invalid blob: '+f.name)
            fields.append(raw[off:off+n]);off+=n
        d=stats.setdefault(f'{scheme}:{param}',{'records':0,'keypairs':0,'signatures':0,'rejections':0})
        d['records']+=1;d['keypairs']+=bool(flags&1);d['signatures']+=bool(flags&2)
        if flags&32:
            if len(fields[7])!=96 or any(x not in (0,1) for x in fields[7]):raise ValueError('Invalid differential answers')
            d['differential_cases']=d.get('differential_cases',0)+96;d['rejections']+=fields[7].count(0)
        else:d['rejections']+=not bool(flags&(1|4))
    if off!=len(raw):raise ValueError('Trailing fixture data: '+f.name)
    entry={'compressed_sha256':hashlib.sha256(compressed).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'records':count,'parameters':stats}
    if f.name in previous:
        for field in ['compressed_sha256','sha256','bytes','records']:
            if entry[field]!=previous[f.name][field]:raise ValueError('Existing fixture changed; investigate before editing its pin: '+f.name)
    manifest[f.name]=entry
if set(previous)-set(manifest):raise ValueError('An existing fixture was removed')
path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
print('Pinned fixtures:',len(manifest),'records:',sum(v['records'] for v in manifest.values()))
