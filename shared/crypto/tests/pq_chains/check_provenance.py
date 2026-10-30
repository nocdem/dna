#!/usr/bin/env python3
"""Offline integrity gate for vendored and reused crypto sources.

This verifies recorded hashes and manifest completeness; it does not establish
that a source is cryptographically correct or authenticate GitHub ownership.
"""
import hashlib
import pathlib
import re

ROOT=pathlib.Path(__file__).resolve().parents[4]
SIGN=ROOT/'shared/crypto/sign'
checked=set()
def check(path,expected):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        raise ValueError('Pinned source changed: '+str(path.relative_to(ROOT)))
    checked.add(path.resolve())

for name,manifest,base in [
    ('algorand_falcon','PROVENANCE.sha256',SIGN/'algorand_falcon'),
    ('slhdsa','SHA256SUMS',ROOT),('ckb_sphincs','SHA256SUMS',ROOT),
    ('mldsa','PROVENANCE.sha256',ROOT)]:
    count=0
    for line in (SIGN/name/manifest).read_text().splitlines():
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([0-9a-f]{64})\s+(.+)',line)
        if not match:raise ValueError('Malformed manifest line: '+line)
        check(base/match[2],match[1]);count+=1
    if not count:raise ValueError('Empty source manifest: '+name)

count=0
for line in (SIGN/'tidecoin_falcon/MANIFEST.md').read_text().splitlines():
    row=[x.strip() for x in line.strip('|').split('|')]
    if len(row)==4 and re.fullmatch(r'[0-9a-f]{64}',row[3]):
        check(SIGN/'tidecoin_falcon'/row[1],row[3]);count+=1
if not count:raise ValueError('Empty Tidecoin source manifest')
for name in ['algorand_falcon','tidecoin_falcon','slhdsa','ckb_sphincs']:
    for path in (SIGN/name/'upstream').rglob('*'):
        if path.is_file() and path.resolve() not in checked:
            raise ValueError('Unmanifested vendored source: '+str(path.relative_to(ROOT)))
print('PASS pinned source files:',len(checked))
