#!/usr/bin/env python3
"""Explicit public-test fixture maintenance, independent of wallet implementation.

Usage: prepare_fixtures.py UPSTREAM_ROOT WORK_DIR (WORK_DIR = build_oracles.py output).

Proves: test/fixtures/pq-receive.json is produced by pinned native code and by
Python re-statements of the native rules, never by src/pq. Native rules (plan
/opt/dna/docs/plans/approved/2026-11-03-pq-native.md sections 1.1-1.4, 6):
 - Soqucoin: SoquShield cb3e842a key_service.dart HKDF-SHA256 + retry rule, ML-DSA-44
   keygen and Bech32m encoder of the pinned node oracle. Anchors (hard asserts):
   mainnet index 0 and 1 equal test/fixtures/soqu-derivation-kat.json.
 - Tidecoin: the Tidecoin Wallet extension 0.3.1 default restore (PBKDF2-HMAC-SHA512,
   10 iterations, "Tidecoin seed" tree, path m/84'/0'/0'/0, HASH160(0x07||pk), Bech32
   v0, HRP tbc), PQClean Falcon-512 keygen of the pinned oracle. Anchors (hard
   asserts, run FIRST = gate 1 of plan section 8 step 0): vectors[0] equals
   tbc1q6mcneezrufd6dpv5qey8tvnq9ztwwyczurx9d5, vectors[1] equals
   tbc1qq9tucj6wucylxsl9v29qndvsvh37mhg6r94qrg (answers of the real extension).
 - XION: Cosmos SDK 64fd208a hd.MlDsa65 derivation through native2/ oracle (circl v1.6.3).
 - Splendor: sqc-wallet 38ac3ded rule through the go-bip39 v1.1.0 + circl v1.6.5 oracle.
 - XION zero-parent case (Kurultay 52 condition 1) through the native2/ secp-zero mode.
Needs: build_oracles.py outputs (the Tidecoin and Soqucoin anchors need only the C
oracles; everything after them needs oracle-go-bin, oracle-xion-bin and the Asentum
npm install), the pinned chain checkouts, ripemd160 in hashlib. No production module
imported, no real wallet data, no transaction or network operation.
Leaves: test/fixtures/pq-receive.json and pq-receive-algorand.json rewritten;
WORK_DIR/asentum-oracle gains asentum-sdk-0.2.0.mjs and receive-oracle.mjs.
Can falsely pass: the Tidecoin rule is read from the shipped wasm by disassembly
(plan 1.4), checked only by the two extension answers - every other path or word
count is unchecked; the Soqucoin retry case is a Python mirror of key_service.dart
with the pinned node keygen (no native answer exists for a 0xFF path); XION and
Splendor expectations rest on the native-module oracles, the candidate addresses
asserted for vector 0 were computed with Nodus code before and are not native
answers; the pre-pass asserts and the fixture would pass together if the oracle
binaries were built from a wrong checkout (build_oracles.py asserts the commits).
A failed anchor is reported, never repaired by changing the expected address.
"""
import hashlib, hmac, importlib.util, json, pathlib, shutil, struct, subprocess, sys

up, work = map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
here=pathlib.Path(__file__).resolve().parent
fixtures=here.parent/'fixtures'
def run(name,data,*args):
    return subprocess.check_output([work/('oracle-'+name),*args],input=data)
def go(mode,data,binary='oracle-go-bin'):
    return subprocess.check_output([work/binary,mode,data.hex()],text=True)
def xion_oracle(mode,data):return go(mode,data,'oracle-xion-bin')
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

HARD=0x80000000
def bip39_seed(phrase):return hashlib.pbkdf2_hmac('sha512',phrase.encode(),b'mnemonic',2048,64)

# Tidecoin Wallet extension 0.3.1, default restore (plan section 1.4 steps 1-7; the rule is
# read from the shipped wasm, core.dcmp lines cited in the plan). Every PBKDF2 has 10 iterations.
def pbkdf2_10(password,salt,length):return hashlib.pbkdf2_hmac('sha512',password,salt,10,length)
def tide_keygen(seed48):
    out=run('tide-keygen',seed48,'with-secret-key');assert len(out)==897+1281,len(out)
    return out[:897],out[897:]
def tidecoin_native(phrase):
    seed64=pbkdf2_10(' '.join(phrase.split()).encode(),b'mnemonic',64)   # step 3: salt "mnemonic"+passphrase("")
    master=pbkdf2_10(b'Tidecoin seed',seed64,96)                            # step 4: password "Tidecoin seed", salt seed64
    keygen_seed,chain=master[:48],master[48:]
    pk,sk=tide_keygen(keygen_seed)
    for index in [84|HARD,0|HARD,0|HARD,0]:                                 # path m/84'/0'/0'/0
        data=(b'\x00'+sk if index&HARD else b'\x07'+pk)+struct.pack('>I',index)   # step 5
        child=pbkdf2_10(data,chain,96);keygen_seed,chain=child[:48],child[48:]
        pk,sk=tide_keygen(keygen_seed)
    address=bech('tbc',h160(b'\x07'+pk),False,0)                            # step 7: account 1 = the path node
    return {'master':master,'seed':keygen_seed,'pk':pk,'address':address}

# Soqucoin, SoquShield cb3e842a lib/services/key_service.dart (plan section 1.1 steps 2-6).
def soqu_okm(master,index,retry):
    info=b'soqucoin-pqwallet-v1'+struct.pack('>5I',44|HARD,21329|HARD,0|HARD,0,index)+(bytes([retry]) if retry>0 else b'')
    prk=hmac.new(h(master),master,hashlib.sha256).digest()                  # salt = SHA-256(seed64)
    return hmac.new(prk,info+b'\x01',hashlib.sha256).digest()
def soqu_select(master,index):
    for retry in range(9):                                                  # r = 0..8, first key not starting 0xFF
        okm=soqu_okm(master,index,retry);pk=run('soqu-keygen',okm)
        if pk[0]!=255:return retry,okm,pk
    raise AssertionError('all nine Soqucoin keys start with 0xFF')
def soqu_address(pk):return run('soqu-format',pk).decode()

# Anchors first (gate 1, plan section 8 step 0): they need only the C oracles. A failure
# stops here, before any Go oracle or any other chain runs. Never change an expected value.
nodus=json.loads((fixtures/'nodus-addresses.json').read_text())['vectors']
assert nodus[0]['phrase']=='abandon '*23+'art'
TIDE_ANCHORS=['tbc1q6mcneezrufd6dpv5qey8tvnq9ztwwyczurx9d5','tbc1qq9tucj6wucylxsl9v29qndvsvh37mhg6r94qrg']
for i,expected in enumerate(TIDE_ANCHORS):
    got=tidecoin_native(nodus[i]['phrase'])['address']
    assert got==expected,'GATE 1 FAILED: Tidecoin vector %d gives %s, the extension gave %s'%(i,got,expected)
print('GATE 1 PASSED: Tidecoin vectors 0 and 1 equal the extension answers')
kat=json.loads((fixtures/'soqu-derivation-kat.json').read_text())
assert nodus[0]['phrase']==kat['mnemonic']
katmain={v['accountIndex']:v['address'] for v in kat['vectors'] if v['network']=='mainnet'}
for index in [0,1]:
    got=soqu_address(soqu_select(bip39_seed(kat['mnemonic']),index)[2])
    assert got==katmain[index],'Soqucoin KAT index %d gives %s, SoquShield publishes %s'%(index,got,katmain[index])
print('Soqucoin mainnet index 0 and 1 equal soqu-derivation-kat.json')

noble=work/'asentum-oracle';sdk=noble/'node_modules/@asentum/sdk/dist/index.js'
assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='e9cca1750b06eb62a93918b8fe43f6cf169acb54d1a6290dee3aff91e8fca834'
shutil.copyfile(sdk,noble/'asentum-sdk-0.2.0.mjs')
(noble/'receive-oracle.mjs').write_text("import { AsentumWallet } from './asentum-sdk-0.2.0.mjs';\nconst w=AsentumWallet.fromSeed(null,Uint8Array.from(Buffer.from(process.argv[2],'hex')));console.log(JSON.stringify({pk:Buffer.from(w.keypair.publicKey).toString('hex'),address:w.address}));w.keypair.secretKey.fill(0);\n")
# Chains whose seed is still a Nodus label root (SHAKE256(master||label)); Soqucoin, Tidecoin, XION
# and Splendor follow their native rules (plan section 1).
roots={'algorand':('algorand-falcon1024-v1',32),'ckb':('ckb-slh-dsa-sha2-256s-v1',96),
       'qtc':('qtc-pq-v1',32),'asentum':('asentum-mldsa65-v1',32)}
# Candidates of plan sections 1.2 / 1.3, computed with Nodus code - not native answers. The native
# oracles must reproduce them; a mismatch stops and is reported (plan section 8 step 0).
XION_CANDIDATE=('8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7','xion1guj972pnfd80md69adnqltu3tpk3vctakrxgqz')
SPLENDOR_CANDIDATE='SQ:b0681bf95c4068feb39a3099dbcc299108cc779dbeed196debdea877074a37aa'
rows=[];legacy=[]
for v in nodus[:3]:
    phrase=v['phrase'];master=bip39_seed(phrase)
    row={'phrase':phrase,'roots':{},'keys':{},'addresses':{}}
    for chain in ['algorand','tidecoin','ckb','soqucoin','qtc','xion','splendor','asentum']:
        if chain in roots:
            label,length=roots[chain];root=hashlib.shake_256(master+label.encode()).digest(length);row['roots'][chain]=root.hex()
        if chain=='algorand':
            seed=hashlib.new('sha512_256',b'PQKf1'+root).digest();a=json.loads(go('algorand',seed));pk=bytes.fromhex(a['pk'])
            row['keys'][chain]={'seed':seed.hex(),'pk':pk.hex(),'salt':a['salt']};row['addresses'][chain]={n:a['address'] for n in ['mainnet','testnet']}
        elif chain=='tidecoin':
            t=tidecoin_native(phrase);row['tidecoinMaster']=t['master'].hex()
            row['keys'][chain]={'seed':t['seed'].hex(),'pk':t['pk'].hex()};row['addresses'][chain]={'mainnet':t['address']}
            # Today's Tidecoin rule, frozen for the unregistered send stack's tests (plan section 3.4).
            lroot=hashlib.shake_256(master+b'tidecoin-falcon512-v1').digest(32);lseed=run('tide-kdf',lroot)[:48];lpk=run('tide-keygen',lseed)
            legacy.append({'phrase':phrase,'roots':{'tidecoin':lroot.hex()},'keys':{'tidecoin':{'seed':lseed.hex(),'pk':lpk.hex()}},
                           'addresses':{'tidecoin':{'mainnet':base58check(b'\x21'+h160(b'\x07'+lpk))}}})
        elif chain=='ckb':
            pk=run('ckb-keygen',root);config=b'\x80\1\1\1\x6a'+pk
            args=hashlib.blake2b(config,digest_size=32,person=b'ckb-sphincs+-sct').digest()
            row['keys'][chain]={'seed':root.hex(),'pk':pk.hex(),'args':args.hex()};row['addresses'][chain]={}
            for network,hrp,code,kind in [('mainnet','ckb','302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf',1),('testnet','ckt','147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf',2)]:
                row['addresses'][chain][network]=bech(hrp,b'\0'+bytes.fromhex(code)+bytes([kind])+args,True)
        elif chain=='soqucoin':
            retry,okm,pk=soqu_select(master,0)
            row['soqucoinSeed']=okm.hex()
            row['keys'][chain]={'seed':okm.hex(),'pk':pk.hex(),'retry':retry};row['addresses'][chain]={'mainnet':soqu_address(pk)}
        elif chain=='qtc':
            row['keys'][chain]={};row['addresses'][chain]={}
            for network,hrp in [('mainnet','qtc'),('testnet','tqtc')]:
                entropy=run('qtc-format',root,network);assert len(entropy)==256
                primary=entropy[:32];backup=entropy[128:176]
                pk=run('qtc-keygen',primary);slh=run('qtc-slh-keygen',backup)
                tree=run('qtc-format',pk+slh,'root')
                row['keys'][chain][network]={'seed':primary.hex(),'backupSeed':backup.hex(),'pk':pk.hex(),'backupPk':slh.hex(),'root':tree.hex()}
                row['addresses'][chain][network]=bech(hrp,tree,True,2)
        elif chain=='xion':
            x=json.loads(xion_oracle('xion',phrase.encode()));seed=bytes.fromhex(x['seed']);pk=bytes.fromhex(x['pk']);addr=bytes.fromhex(x['address'])
            assert addr==h(pk)[:20],'SDK address bytes differ from SHA256(pk)[0:20]'
            address=bech('xion',addr);row['roots'][chain]=seed.hex()
            row['keys'][chain]={'seed':seed.hex(),'pk':pk.hex()};row['addresses'][chain]={n:address for n in ['mainnet','testnet']}
            if phrase==nodus[0]['phrase']:assert (seed.hex(),address)==XION_CANDIDATE,'XION oracle %s %s differs from the plan 1.2 candidate - report, do not change'%(seed.hex(),address)
        elif chain=='splendor':
            s=json.loads(go('splendor',phrase.encode()));seed=bytes.fromhex(s['seed']);pk=bytes.fromhex(s['pk'])
            assert s['address']=='SQ:'+hashlib.sha3_256(pk).hexdigest(),'oracle address differs from SHA3-256(pk)'
            row['roots'][chain]=seed.hex();row['keys'][chain]={'seed':seed.hex(),'pk':pk.hex()}
            row['addresses'][chain]={n:s['address'] for n in ['mainnet','testnet']}
            if phrase==nodus[0]['phrase']:assert s['address']==SPLENDOR_CANDIDATE,'Splendor oracle %s differs from the plan 1.3 candidate - report, do not change'%s['address']
        else:
            pk=bytes.fromhex(go('mldsa65',root));row['keys'][chain]={'seed':root.hex(),'pk':pk.hex()}
            sdkrow=json.loads(subprocess.check_output(['node',noble/'receive-oracle.mjs',root.hex()],text=True))
            assert sdkrow['pk']==pk.hex(),'SDK vs CIRCL key mismatch'
            row['addresses'][chain]={'testnet':sdkrow['address']}
    rows.append(row)

# Soqucoin retry case: public entropies until retry 0 gives a key starting with 0xFF, then record the
# retry-selected seed and address (plan section 6). A mirror of key_service.dart, not a native answer.
soqu_retry=None
for i in range(20000):
    entropy=hashlib.sha256(b'soqu-retry-case'+i.to_bytes(4,'little')).digest()
    phrase=go('mnemonic',entropy);master=bip39_seed(phrase)
    if run('soqu-keygen',soqu_okm(master,0,0))[0]!=255:continue
    retry,okm,pk=soqu_select(master,0);assert retry>=1
    soqu_retry={'entropy':entropy.hex(),'phrase':phrase,'retry0Seed':soqu_okm(master,0,0).hex(),'retry':retry,'seed':okm.hex(),'pk':pk.hex(),'address':soqu_address(pk)};break
assert soqu_retry is not None,'no 0xFF retry-0 key among 20000 public entropies'

# XION zero-parent case (Kurultay 52 condition 1): native compressed key, child key, chain code.
zero_parent=[]
for i in range(2):
    chain=hashlib.sha256(b'xion-zero-parent'+i.to_bytes(4,'little')).digest()
    z=json.loads(xion_oracle('secp-zero',chain));zero_parent.append({'chain':chain.hex(),**z})

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
output={'provenance':{'goModules':(work/'oracle-go/go.sum').read_text(),
 'xionGoModSha256':hashlib.sha256((here/'native2/go.mod').read_bytes()).hexdigest(),'xionGoSumSha256':hashlib.sha256((here/'native2/go.sum').read_bytes()).hexdigest(),
 'asentumDistSha256':hashlib.sha256(sdk.read_bytes()).hexdigest(),
 'bech32ReferenceSha256':hashlib.sha256((up/'qtc/test/functional/test_framework/segwit_addr.py').read_bytes()).hexdigest(),
 'recovery':'Nodus labels v1 for Algorand/CKB/QTC/Asentum (Python hashlib PBKDF2-HMAC-SHA512/SHAKE256); native rules for Soqucoin (SoquShield cb3e842a HKDF), XION (Cosmos SDK 64fd208a hd), Splendor (sqc-wallet 38ac3ded) and Tidecoin (extension 0.3.1 PBKDF2 tree); no src/pq import',
 'oracles':'Pinned pristine native keygen; Tidecoin PQClean Falcon-512 with secret key; Soqucoin native witness-v1 encoder/decoder; QTC HKDF/HashWriter/P2MR; Algorand Falcon; CIRCL v1.6.5 + go-bip39 v1.1.0 (Splendor); Cosmos SDK hd + circl v1.6.3 + decred secp256k1 v4.4.1 (XION, secp-zero); Asentum SDK'},
 'vectors':rows,'curve':curve,'soquInvalidMarker':bad,'legacyTidecoin':legacy,'soqucoinRetry':soqu_retry,'xionZeroParent':zero_parent}
dest=fixtures/'pq-receive.json';dest.write_text(json.dumps(output,indent=2)+'\n')
print('fixture',dest,'vectors',len(rows),'addresses',sum(len(a) for r in rows for a in r['addresses'].values()),'curve',len(curve),'sha256',hashlib.sha256(dest.read_bytes()).hexdigest())

# Native 32-byte Falcon seeds anchor this helper's address logic to committed
# Go known answers. Salt is canonical lowest non-decodable candidate.
algorand_rows=[json.loads(go('algorand',bytes([first])+bytes(31))) for first in [0,1,2,3,255]]
anchors={1:'GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4',2:'II4DO6IIP3EAEQMWJEOLOUU3VBRVCH3WF4MX6UCRUD36DOQJ3YSHA2DV5A',3:'KJGJA2DTCQH6LT2I2OH2YO5GIIBFC6JHX5O6UPA5ZZ5ZURFT3LHKMTRCEM'}
for index,address in anchors.items():assert algorand_rows[index]['address']==address
algo={'falcon':'19f185792c39326bebc173b2a100c2c247423be3','address_source':'66fdf4ad60479aa41e66cc39b65e7ed118834616:data/basics/pq_address_test.go','rows':algorand_rows}
(fixtures/'pq-receive-algorand.json').write_text(json.dumps(algo,indent=2)+'\n')
