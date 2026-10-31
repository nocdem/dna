#!/usr/bin/env python3
"""Maintenance only: build pristine upstream helpers, never the port.

Usage: build_oracles.py UPSTREAM_ROOT OUTPUT_DIR. Public fixture inputs only.
No upstream mutation. Builds sequentially. Runtime tests never call this file.
"""
import os, pathlib, shutil, subprocess, sys

u, r = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:])
s = pathlib.Path(__file__).resolve().parent
r.mkdir(exist_ok=True, parents=True)
pins = {'algorand-falcon':'19f185792c39326bebc173b2a100c2c247423be3',
        'tidecoin':'7d653be5d24e73b49d101578afb33d8d7a889c1d',
        'soqucoin':'28222c3810701c05eb27e8feb09f032bb75fc097',
        'qtc':'5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24',
        'ckb':'082c0a19ce4e0b2c0b00f7b46f423f59a30afc71',
        'ckb/deps/sphincsplus':'129b72c80e122a22a61f71b5d2b042770890ccee'}
for repo,pin in pins.items():
    assert subprocess.check_output(['git','-C',u/repo,'rev-parse','HEAD'],text=True).strip()==pin
    assert not subprocess.check_output(['git','-C',u/repo,'diff','HEAD','--','*.c','*.cpp','*.h'])
def run(cmd):
    subprocess.run(list(map(str,cmd)),check=True)
def build(name,up,names,flags):
    print(name,flush=True)
    run(['cc','-O2','-std=c11','-D_DEFAULT_SOURCE',*flags,'-I',up,s/'keygen.c',
         *[up/(n+'.c') for n in names.split()],'-lm','-o',r/('oracle-'+name)])
build('tide-keygen',u/'tidecoin/src','pq/falcon512 pq/fips202 '+' '.join('pq/falcon-512/'+n for n in 'codec common fft fpr keygen pqclean rng sign vrfy'.split()),['-DTIDE'])
for name,path in [('soqu','soqucoin/src/crypto/dilithium'),('qtc','qtc/src/libbitcoinpqc/dilithium/ref')]:
    build(name+'-keygen',u/path,'ntt packing poly polyvec reduce rounding sign symmetric-shake fips202',['-DMLDSA','-DDILITHIUM_MODE=2'])
build('ckb-keygen',u/'ckb/deps/sphincsplus/ref','address merkle wots wotsx1 utils utilsx1 fors sign sha2 hash_sha2 thash_sha2_simple',['-DPARAMS=sphincs-sha2-256s'])
build('qtc-slh-keygen',u/'qtc/src/libbitcoinpqc/sphincsplus/ref','address merkle wots wotsx1 utils utilsx1 fors sign fips202 hash_shake thash_shake_simple',['-DPARAMS=sphincs-shake-128s'])
(r/'bitcoin-build-config.h').write_text('/* Standalone portable SHA; optional CPU features disabled. */\n')
for name,path,srcs,main in [('soqu-format','soqucoin/src','utiladdress bech32 crypto/sha256','soqu-format.cpp'),('tide-kdf','tidecoin/src','pq/pqhd_kdf crypto/hmac_sha512 crypto/sha512 support/cleanse','tide-kdf.cpp'),('qtc-format','qtc/src','pq/pq_keyderivation script/pqm hash crypto/hkdf_sha256_32 crypto/hmac_sha256 crypto/sha256 support/cleanse','qtc-format.cpp')]:
    up=u/path
    print(name,flush=True)
    extra = ['-DHAVE_ENDIAN_H=1', '-DHAVE_BYTESWAP_H=1', '-DHAVE_DECL_HTOBE16=1', '-DHAVE_DECL_HTOLE16=1', '-DHAVE_DECL_BE16TOH=1', '-DHAVE_DECL_LE16TOH=1', '-DHAVE_DECL_HTOBE32=1', '-DHAVE_DECL_HTOLE32=1', '-DHAVE_DECL_BE32TOH=1', '-DHAVE_DECL_LE32TOH=1', '-DHAVE_DECL_HTOBE64=1', '-DHAVE_DECL_HTOLE64=1', '-DHAVE_DECL_BE64TOH=1', '-DHAVE_DECL_LE64TOH=1', '-DHAVE_DECL_BSWAP_16=1', '-DHAVE_DECL_BSWAP_32=1', '-DHAVE_DECL_BSWAP_64=1'] if name == 'soqu-format' else []
    run(['g++',*extra,'-std=c++20','-O2','-ffunction-sections','-fdata-sections','-DDISABLE_OPTIMIZED_SHA256','-I',up,'-I',r,s/main,*[up/(n+'.cpp') for n in srcs.split()],'-Wl,--gc-sections','-o',r/('oracle-'+name)])

# Go and SDK dependency graphs are pinned by the checked-in sum/lock files.
go_dir=r/'oracle-go';go_dir.mkdir(exist_ok=True)
for name in ['go.mod','go.sum','oracle.go']:shutil.copyfile(s/name,go_dir/name)
subprocess.run([os.environ.get('GO_BIN','go'),'mod','edit','-replace=github.com/algorand/falcon='+str(u/'algorand-falcon')],cwd=go_dir,check=True)
subprocess.run([os.environ.get('GO_BIN','go'),'build','-buildvcs=false','-mod=readonly','-o',str(r/'oracle-go-bin'),'.'],cwd=go_dir,check=True)
node_dir=r/'asentum-oracle';node_dir.mkdir(exist_ok=True)
for name in ['package.json','package-lock.json']:shutil.copyfile(s/'asentum'/name,node_dir/name)
subprocess.run(['npm','ci','--ignore-scripts','--no-audit','--no-fund'],cwd=node_dir,check=True)
