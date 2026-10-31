#!/usr/bin/env python3
"""Explicit public-test fixture maintenance, independent of wallet implementation.

Needs build_oracles.py outputs, oracle.go compiled with the pinned modules, and
the previous port's pinned Asentum SDK 0.2.0 / Noble 0.2.1 install. No production
module imported, no real wallet data, no transaction or network operation.
"""
import hashlib, importlib.util, json, pathlib, shutil, subprocess, sys

up, work = map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
here=pathlib.Path(__file__).resolve().parent
fixtures=here.parent/'fixtures'
def run(name,data,*args):
    return subprocess.check_output([work/('oracle-'+name),*args],input=data)
def go(mode,data):
    return subprocess.check_output([work/'oracle-go-bin',mode,data.hex()],text=True)
def h(data):return hashlib.sha256(data).digest()
def h160(data):return hashlib.new('ripemd160',h(data)).digest()
def base58check(payload):
    raw=payload+h(h(payload))[:4];num=int.from_bytes(raw,'big');out=''
    while num:
        num,rem=divmod(num,58);out='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[rem]+out
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+out

# Execute the pinned chain's BIP-173/350 Python reference, not the JS codec.
spec=importlib.util.spec_from_file_location('bip350',up/'qtc/test/functional/test_framework/segwit_addr.py')
bip=importlib.util.module_from_spec(spec);spec.loader.exec_module(bip)
def bech(hrp,payload,m=False,witness=None):
    words=bip.convertbits(payload,8,5)
    if witness is not None:words=[witness]+words
    return bip.bech32_encode(bip.Encoding.BECH32M if m else bip.Encoding.BECH32,hrp,words)
assert bech('ckb',bytes.fromhex('009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce801b39bbc0b3673c7d36450bc14cfcdad2d559c6c64'),True)=='ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqxwquc4'

noble=work/'asentum-oracle';sdk=noble/'node_modules/@asentum/sdk/dist/index.js'
assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='e9cca1750b06eb62a93918b8fe43f6cf169acb54d1a6290dee3aff91e8fca834'
shutil.copyfile(sdk,noble/'asentum-sdk-0.2.0.mjs')
(noble/'receive-oracle.mjs').write_text("import { AsentumWallet } from './asentum-sdk-0.2.0.mjs';\nconst w=AsentumWallet.fromSeed(null,Uint8Array.from(Buffer.from(process.argv[2],'hex')));console.log(JSON.stringify({pk:Buffer.from(w.keypair.publicKey).toString('hex'),address:w.address}));w.keypair.secretKey.fill(0);\n")
roots={'algorand':('algorand-falcon1024-v1',32),'tidecoin':('tidecoin-falcon512-v1',32),
       'ckb':('ckb-slh-dsa-sha2-256s-v1',96),'soqucoin':('soqucoin-mldsa44-v1',32),
       'qtc':('qtc-pq-v1',32),'xion':('xion-mldsa65-v1',32),
       'splendor':('splendor-mldsa65-v1',32),'asentum':('asentum-mldsa65-v1',32)}
rows=[]
for v in json.loads((fixtures/'nodus-addresses.json').read_text())['vectors'][:3]:
    phrase=v['phrase'];master=hashlib.pbkdf2_hmac('sha512',phrase.encode(),b'mnemonic',2048,64)
    row={'phrase':phrase,'roots':{},'keys':{},'addresses':{}}
    for chain,(label,length) in roots.items():
        root=hashlib.shake_256(master+label.encode()).digest(length);row['roots'][chain]=root.hex()
        if chain=='algorand':
            seed=hashlib.new('sha512_256',b'PQKf1'+root).digest();a=json.loads(go('algorand',seed));pk=bytes.fromhex(a['pk'])
            row['keys'][chain]={'seed':seed.hex(),'pk':pk.hex(),'salt':a['salt']};row['addresses'][chain]={n:a['address'] for n in ['mainnet','testnet']}
        elif chain=='tidecoin':
            seed=run('tide-kdf',root)[:48];pk=run('tide-keygen',seed)
            row['keys'][chain]={'seed':seed.hex(),'pk':pk.hex()};row['addresses'][chain]={'mainnet':base58check(b'\x21'+h160(b'\x07'+pk))}
        elif chain=='ckb':
            pk=run('ckb-keygen',root);config=b'\x80\1\1\1\x6a'+pk
            args=hashlib.blake2b(config,digest_size=32,person=b'ckb-sphincs+-sct').digest()
            row['keys'][chain]={'seed':root.hex(),'pk':pk.hex(),'args':args.hex()};row['addresses'][chain]={}
            for network,hrp,code,kind in [('mainnet','ckb','302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf',1),('testnet','ckt','147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf',2)]:
                row['addresses'][chain][network]=bech(hrp,b'\0'+bytes.fromhex(code)+bytes([kind])+args,True)
        elif chain=='soqucoin':
            pk=run('soqu-keygen',root);assert pk[0]!=255,'native invalid marker, choose a different public phrase fixture'
            row['keys'][chain]={'seed':root.hex(),'pk':pk.hex()};row['addresses'][chain]={'mainnet':run('soqu-format',pk).decode()}
        elif chain=='qtc':
            row['keys'][chain]={};row['addresses'][chain]={}
            for network,hrp in [('mainnet','qtc'),('testnet','tqtc')]:
                entropy=run('qtc-format',root,network);assert len(entropy)==256
                primary=entropy[:32];backup=entropy[128:176]
                pk=run('qtc-keygen',primary);slh=run('qtc-slh-keygen',backup)
                tree=run('qtc-format',pk+slh,'root')
                row['keys'][chain][network]={'seed':primary.hex(),'backupSeed':backup.hex(),'pk':pk.hex(),'backupPk':slh.hex(),'root':tree.hex()}
                row['addresses'][chain][network]=bech(hrp,tree,True,2)
        else:
            pk=bytes.fromhex(go('mldsa65',root));row['keys'][chain]={'seed':root.hex(),'pk':pk.hex()}
            if chain=='asentum':
                sdkrow=json.loads(subprocess.check_output(['node',noble/'receive-oracle.mjs',root.hex()],text=True))
                assert sdkrow['pk']==pk.hex(),'SDK vs CIRCL key mismatch'
                row['addresses'][chain]={'testnet':sdkrow['address']}
            else:
                address=bech('xion',h(pk)[:20]) if chain=='xion' else 'SQ:'+hashlib.sha3_256(pk).hexdigest()
                row['addresses'][chain]={n:address for n in ['mainnet','testnet']}
    rows.append(row)

curve=[]
inputs=[hashlib.sha256(b'curve-test'+i.to_bytes(4,'little')).digest() for i in range(96)]
for y in [0,1,2,2**255-20,2**255-19,2**255-18,2**255-1]:
    for sign in [0,1]:inputs.append((y|(sign<<255)).to_bytes(32,'little'))
for value in inputs:curve.append({'bytes':value.hex(),'decodable':go('curve',value)=='true'})
bad=None
for i in range(4096):
    seed=i.to_bytes(32,'little');pk=run('soqu-keygen',seed)
    if pk[0]==255:bad={'seed':seed.hex(),'pk':pk.hex()};break
assert bad is not None
output={'provenance':{'goModules':(work/'oracle-go/go.sum').read_text(),'asentumDistSha256':hashlib.sha256(sdk.read_bytes()).hexdigest(),
 'bech32ReferenceSha256':hashlib.sha256((up/'qtc/test/functional/test_framework/segwit_addr.py').read_bytes()).hexdigest(),
 'recovery':'Nodus labels v1; Python hashlib PBKDF2-HMAC-SHA512/SHAKE256; no src/pq import',
 'oracles':'Pinned pristine native keygen; Tidecoin PQHD; Soqucoin native witness-v1 encoder/decoder; QTC HKDF/HashWriter/P2MR; Algorand Falcon; CIRCL; Asentum SDK'},
 'vectors':rows,'curve':curve,'soquInvalidMarker':bad}
dest=fixtures/'pq-receive.json';dest.write_text(json.dumps(output,indent=2)+'\n')
print('fixture',dest,'vectors',len(rows),'addresses',sum(len(a) for r in rows for a in r['addresses'].values()),'curve',len(curve),'sha256',hashlib.sha256(dest.read_bytes()).hexdigest())

# Native 32-byte Falcon seeds anchor this helper's address logic to committed
# Go known answers. Salt is canonical lowest non-decodable candidate.
algorand_rows=[json.loads(go('algorand',bytes([first])+bytes(31))) for first in [0,1,2,3,255]]
anchors={1:'GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4',2:'II4DO6IIP3EAEQMWJEOLOUU3VBRVCH3WF4MX6UCRUD36DOQJ3YSHA2DV5A',3:'KJGJA2DTCQH6LT2I2OH2YO5GIIBFC6JHX5O6UPA5ZZ5ZURFT3LHKMTRCEM'}
for index,address in anchors.items():assert algorand_rows[index]['address']==address
algo={'falcon':'19f185792c39326bebc173b2a100c2c247423be3','address_source':'66fdf4ad60479aa41e66cc39b65e7ed118834616:data/basics/pq_address_test.go','rows':algorand_rows}
(fixtures/'pq-receive-algorand.json').write_text(json.dumps(algo,indent=2)+'\n')
