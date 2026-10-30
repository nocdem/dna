#!/usr/bin/env python3
"""Pinned-reference differential cases for the parent's red-team pass.
Consumes existing hashed fixtures; builds no production library.
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import struct
import subprocess
from prepare_vectors import HERE, NAMES, write_records

def read_records(name):
    path=HERE/'fixtures'/(name+'.bin.gz');compressed=path.read_bytes()
    meta=json.loads((path.parent/'manifest.json').read_text())[path.name]
    assert hashlib.sha256(compressed).hexdigest()==meta['compressed_sha256']
    raw=gzip.decompress(compressed);assert hashlib.sha256(raw).hexdigest()==meta['sha256']
    count=struct.unpack_from('<I',raw,8)[0];off=12;out=[]
    for _ in range(count):
        head=struct.unpack_from('<4I',raw,off);off+=16;fields=[]
        for i in range(8):
            n=struct.unpack_from('<I',raw,off)[0];off+=4;fields.append(raw[off:off+n]);off+=n
        out.append((*head,fields))
    assert off==len(raw)
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--upstream-root',type=pathlib.Path,required=True);a=ap.parse_args();root=a.upstream_root.resolve()
    work=root/'vector-build';outputs=[]
    pins={'algorand-falcon':'19f185792c39326bebc173b2a100c2c247423be3','tidecoin':'7d653be5d24e73b49d101578afb33d8d7a889c1d','ckb/deps/sphincsplus':'129b72c80e122a22a61f71b5d2b042770890ccee','dilithium':'444cdcc84eb36b66fe27b3a2529ee48f6d8150c2'}
    for name,pin in pins.items():
        assert subprocess.check_output(['git','-C',root/name,'rev-parse','HEAD'],text=True).strip()==pin
        assert not subprocess.check_output(['git','-C',root/name,'diff','HEAD','--','*.c','*.h'])
    for family in ['algorand','tidecoin','slhdsa','mldsa']:
        source={'slhdsa':'slhdsa-nist','mldsa':'mldsa-nist'}.get(family,family)
        selected={}
        for record in read_records(source):
            scheme,param,tid,flags,f=record
            if not flags&4 or not f[1] or not f[5]:continue
            if param not in selected:selected[param]=record
        if family=='algorand':
            r=selected[1024];f=list(r[4]);f[5]=f[7];f[7]=b''
            selected[1024]=(r[0],r[1],r[2],r[3]&~8,r[4])
            selected[1025]=(r[0],r[1],r[2],r[3]|8,f)
        chunks=[]
        for key,r in selected.items():
            param=r[1];inp=work/f'mutation-{family}-{key}.in';out=work/f'mutation-{family}-{key}.bin';exe=work/f'oracle-mutations-{family}-{key}'
            write_records(inp,[r]);flags=[]
            if family=='algorand':
                up=root/'algorand-falcon';names='codec common falcon fft fpr keygen rng shake sign vrfy deterministic1024'.split()
            elif family=='tidecoin':
                up=root/'tidecoin/src';names=[]
                sources=[up/'pq/falcon512.c',up/'pq/fips202.c']+[up/'pq/falcon-512'/(s+'.c') for s in 'codec common fft fpr keygen pqclean rng sign vrfy'.split()]
            elif family=='slhdsa':
                up=root/'ckb/deps/sphincsplus/ref';h='sha2' if param<6 else 'shake';p=NAMES[param].replace('SLH-DSA-','sphincs-').lower();flags=[f'-DPARAMS={p}']
                names='address merkle wots wotsx1 utils utilsx1 fors sign'.split()+['sha2' if param<6 else 'fips202',f'hash_{h}',f'thash_{h}_simple']
            else:
                up=root/'dilithium/ref';flags=[f'-DDILITHIUM_MODE={2 if param==44 else 3}'];names='ntt packing poly polyvec reduce rounding sign symmetric-shake fips202'.split()
            if names:sources=[up/(s+'.c') for s in names]
            subprocess.run(['cc','-O2','-std=c11','-D_DEFAULT_SOURCE',f'-DORACLE_{family.upper()}',*flags,'-I',str(up),str(HERE/'oracle_mutations.c'),*[str(s) for s in sources],'-lm','-o',str(exe)],check=True)
            subprocess.run([exe,inp,out],check=True);chunks.append(out.read_bytes()[12:])
        out=work/f'redteam-{family}.bin';out.write_bytes(b'PQPORT01'+struct.pack('<I',len(chunks))+b''.join(chunks));outputs.append(out)
    for out in outputs:
        raw=out.read_bytes();(HERE/'fixtures'/(out.name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
        print(out.name,len(raw),hashlib.sha256(raw).hexdigest(),flush=True)
    records=[]
    for i,n in enumerate([0,1,127,128,129,255,256,257,511,512,513,1024,4096,1048576]):
        msg=bytes((j*13+7)%256 for j in range(n))
        digest=hashlib.blake2b(msg,digest_size=32,person=b'ckb-sphincs+-msg').digest()
        records.append((7,0,i,4,[b'',msg,b'',b'',b'',b'',b'',digest]))
    out=work/'ckb-hash.bin';write_records(out,records)
    (HERE/'fixtures'/(out.name+'.gz')).write_bytes(gzip.compress(out.read_bytes(),mtime=0))
    print(out.name,len(out.read_bytes()),hashlib.sha256(out.read_bytes()).hexdigest(),flush=True)

if __name__=='__main__':main()
