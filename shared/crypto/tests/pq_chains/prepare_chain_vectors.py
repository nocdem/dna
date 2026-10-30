#!/usr/bin/env python3
"""Explicit maintenance: chain-specific independent reference fixture generation.

Requires already acquired pinned checkouts and a pinned noble install. Go fetches
the exact CIRCL versions through its checksum-verified module mechanism. Never
uses production adapter code to compute expected bytes.
"""
import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import subprocess
from prepare_vectors import HERE, write_records

def run(args, **kw):
    subprocess.run([str(a) for a in args], check=True, **kw)

def checked_repo(root, name, pin):
    p=root/name
    assert subprocess.check_output(['git','-C',p,'rev-parse','HEAD'],text=True).strip()==pin
    assert not subprocess.check_output(['git','-C',p,'diff','HEAD','--','*.c','*.h'])
    return p

def from_json(path, output):
    records=[]
    for t in json.loads(path.read_text()):
        records.append((t['scheme'],t['param'],t['id'],t['flags'],[bytes.fromhex(x) for x in t['fields']]))
    assert records
    write_records(output,records)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--upstream-root',type=pathlib.Path,required=True)
    ap.add_argument('--only',choices=['mldsa','qtc-slhdsa','circl','noble'],required=True)
    ap.add_argument('--go',default='/usr/local/go/bin/go');a=ap.parse_args()
    root=a.upstream_root.resolve();work=root/'vector-build';work.mkdir(exist_ok=True);outputs=[]
    if a.only=='mldsa':
        for name,pin,sub in [
            ('soqucoin','28222c3810701c05eb27e8feb09f032bb75fc097','src/crypto/dilithium'),
            ('qtc','5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24','src/libbitcoinpqc/dilithium/ref')]:
            up=checked_repo(root,name,pin)/sub
            srcs='ntt packing poly polyvec reduce rounding sign symmetric-shake fips202'.split()
            exe=work/f'oracle-{name}-mldsa';out=work/f'{name}-mldsa.bin'
            run(['cc','-O2','-std=c11','-DDILITHIUM_MODE=2','-I',up,HERE/'oracle_chain_mldsa.c',*[up/(s+'.c') for s in srcs],'-o',exe])
            run([exe,out]);outputs.append(out)
    if a.only=='qtc-slhdsa':
        qtc=checked_repo(root,'qtc','5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24')
        up=qtc/'src/libbitcoinpqc/sphincsplus/ref'
        srcs='address fors hash_shake merkle sign thash_shake_simple utils utilsx1 wots wotsx1 fips202'.split()
        exe=work/'oracle-qtc-slhdsa';out=work/'qtc-slhdsa.bin'
        run(['cc','-O2','-std=c11','-DPARAMS=sphincs-shake-128s','-I',up,HERE/'oracle_qtc_slhdsa.c',*[up/(s+'.c') for s in srcs],'-o',exe])
        run([exe,out]);outputs.append(out)
        header=(qtc/'src/test/data/fips205_slhdsa_kat.h').read_text()
        def extract(name):
            match=re.search(r'KAT_'+name+r'_HEX\s*=\s*((?:"[0-9a-fA-F]*"\s*)+);',header)
            assert match,name
            return bytes.fromhex(''.join(re.findall(r'"([0-9a-fA-F]*)"',match.group(1))))
        pk,msg,sig=extract('PK'),extract('MSG'),extract('SIG')
        out=work/'qtc-nist.bin';write_records(out,[(3,7,530,20,[b'',b'\0\0'+msg,b'',pk,b'',sig,b'',msg])]);outputs.append(out)
    if a.only=='circl':
        for ver in ['1.6.3','1.6.5']:
            folder=work/('circl-'+ver);folder.mkdir(exist_ok=True)
            for kind in ['mod','sum']:
                (folder/('go.'+kind)).write_bytes((HERE/'references'/('circl-'+ver+'.go.'+kind)).read_bytes())
            env={**os.environ,'GOTOOLCHAIN':'go1.26.10'}
            for kind in (['mldsa'] if ver=='1.6.3' else ['mldsa','slhdsa']):
                j=folder/(kind+'.json');out=work/('circl-'+ver+'-'+kind+'.bin')
                with j.open('w') as f:
                    run([a.go,'run','-mod=readonly',HERE/('oracle_circl_'+kind+'.go')],cwd=folder,env=env,stdout=f)
                from_json(j,out);outputs.append(out)
    if a.only=='noble':
        folder=root/'noble-oracle';lock=json.loads((folder/'package-lock.json').read_text())['packages']
        assert lock['node_modules/@noble/post-quantum']['version']=='0.2.1'
        assert lock['node_modules/@noble/post-quantum']['integrity']=='sha512-ImgfMp9notXSEocz464o1AefYfFWEkkszKMGO+ZiTn73yIBFeNyEHKQUMS+SheJwSNymldSts6YyVcQDjcnVVg=='
        assert lock['node_modules/@noble/hashes']['version']=='1.6.0'
        j=work/'noble.json';out=work/'asentum-noble.bin'
        with j.open('w') as f:run(['node',HERE/'oracle_noble.mjs',folder],stdout=f)
        from_json(j,out);outputs.append(out)
    for out in outputs:
        raw=out.read_bytes();(HERE/'fixtures'/(out.name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
        print(out.name,'bytes',len(raw),'sha256',hashlib.sha256(raw).hexdigest(),flush=True)

if __name__=='__main__':main()
