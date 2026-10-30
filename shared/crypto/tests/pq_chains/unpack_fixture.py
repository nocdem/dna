#!/usr/bin/env python3
"""Expand committed corpus after checking pinned hashes, count and gzip CRC."""
import gzip
import hashlib
import json
import pathlib
import struct
import sys

src, dst = map(pathlib.Path, sys.argv[1:])
metadata=json.loads((src.parent/'manifest.json').read_text())[src.name]
compressed=src.read_bytes()
if hashlib.sha256(compressed).hexdigest()!=metadata['compressed_sha256']:
    raise ValueError('Compressed fixture hash mismatch: '+src.name)
raw = gzip.decompress(compressed)
if hashlib.sha256(raw).hexdigest()!=metadata['sha256'] or len(raw)!=metadata['bytes']:
    raise ValueError('Fixture contents mismatch: '+src.name)
if raw[:8]!=b"PQPORT01" or struct.unpack_from("<I",raw,8)[0]!=metadata['records'] or metadata['records']<=0:
    raise ValueError('Fixture framing/count mismatch: '+src.name)
dst.write_bytes(raw)
