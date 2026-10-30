#!/usr/bin/env python3
"""Rebuild test-only fixtures from EXACT pinned upstream checkouts.

Never link the port to generate its own expected answers. Acquired inputs are
recorded with SHA256; committed signatures and negative answers are preserved.
Run from any directory: python3 prepare_vectors.py --upstream-root PATH.
This is an explicit maintenance command, not a build-time network dependency.
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import struct
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
PINS = {
    "algorand-falcon": "19f185792c39326bebc173b2a100c2c247423be3",
    "tidecoin": "7d653be5d24e73b49d101578afb33d8d7a889c1d",
    "tidecoin-legacy": "cfcb4d8a21f5a944c29d5c215c38ef7b66323f7b",
    "ckb": "082c0a19ce4e0b2c0b00f7b46f423f59a30afc71",
    "ckb/deps/sphincsplus": "129b72c80e122a22a61f71b5d2b042770890ccee",
}
INPUT_HASHES = {
    "acvp/mldsa-keyGen.json": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "acvp/mldsa-sigGen.json": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "acvp/mldsa-sigVer.json": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    "ckb/tests/nist-test-vector-tests/test_vectors/internalProjection.json": "99322595b31ebf9a69d10d57b4a24d6760776bbe1435119632ca25dfb17c3e72",
}
NAMES = [f"SLH-DSA-{family}-{level}{speed}" for family in ["SHA2", "SHAKE"]
         for level in [128, 192, 256] for speed in ["f", "s"]]

def run(args):
    subprocess.run([str(a) for a in args], check=True)

def write_records(path, records):
    with path.open("wb") as f:
        f.write(b"PQPORT01" + struct.pack("<I", len(records)))
        for scheme, param, tcid, flags, fields in records:
            assert len(fields) == 8
            f.write(struct.pack("<IIII", scheme, param, tcid, flags))
            for b in fields:
                f.write(struct.pack("<I", len(b)) + b)

def hexbytes(t, key):
    return bytes.fromhex(t.get(key) or "")

def final_message(t):
    """Mirror pinned CKB's NIST test adapter, not production code under test."""
    alg = t.get("hashAlg", "none")
    msg = hexbytes(t, "message")
    ctx = t.get("context")
    prefix = (bytes([int(alg != "none"), len(hexbytes(t, "context"))]) + hexbytes(t, "context")) if ctx is not None else b""
    if alg == "none":
        return prefix + msg
    names = {"SHA2-224": ("sha224", 4), "SHA2-256": ("sha256", 1),
             "SHA2-384": ("sha384", 2), "SHA2-512": ("sha512", 3),
             "SHA2-512/224": ("sha512_224", 5), "SHA2-512/256": ("sha512_256", 6),
             "SHA3-224": ("sha3_224", 7), "SHA3-256": ("sha3_256", 8),
             "SHA3-384": ("sha3_384", 9), "SHA3-512": ("sha3_512", 10),
             "SHAKE-128": ("shake_128", 11), "SHAKE-256": ("shake_256", 12)}
    name, oid = names[alg]
    h = hashlib.new(name, msg)
    digest = h.digest(32 if oid == 11 else 64) if oid >= 11 else h.digest()
    return prefix + bytes.fromhex("06096086480165030402") + bytes([oid]) + digest

def main():
    ap = argparse.ArgumentParser();ap.add_argument("--upstream-root", type=pathlib.Path, required=True)
    ap.add_argument("--only", choices=["algorand", "tidecoin", "slhdsa", "ckb", "mldsa"])
    a = ap.parse_args(); root = a.upstream_root.resolve()
    work = root / "vector-build"; work.mkdir(exist_ok=True)
    fixtures = HERE / "fixtures"; fixtures.mkdir(exist_ok=True)
    for name, pin in PINS.items():
        actual = subprocess.check_output(["git", "-C", str(root/name), "rev-parse", "HEAD"], text=True).strip()
        assert actual == pin, (name, actual, pin)
        assert not subprocess.check_output(["git", "-C", str(root/name), "diff", "HEAD", "--", "*.c", "*.cpp", "*.h", "*.json"]), name
    for path, expected in INPUT_HASHES.items():
        if a.only in (None,"mldsa") or path.startswith("ckb/"):
            assert hashlib.sha256((root/path).read_bytes()).hexdigest()==expected,path
    outputs = []
    if a.only in (None, "algorand"):
        up = root/"algorand-falcon"
        sources = [up/(s+".c") for s in "codec common falcon fft fpr keygen rng shake sign vrfy deterministic1024".split()]
        run(["cc", "-O2", "-std=c11", "-D_DEFAULT_SOURCE", "-I", up, HERE/"oracle_algorand.c", *sources, "-o", work/"oracle_algorand"])
        path=work/"algorand.bin";run([work/"oracle_algorand",path]);outputs.append(path)
    if a.only in (None, "tidecoin"):
        old=root/"tidecoin-legacy/src"
        names="codec common fft fpr keygen pqclean rng sign vrfy fips202".split()
        run(["cc","-O2","-x","c","-DLEGACY_REFERENCE","-I",old,HERE/"oracle_tidecoin.c",*[old/(s+".cpp") for s in names],"-lm","-o",work/"oracle_tidecoin_old"])
        historical=work/"tidecoin-historical.bin";run([work/"oracle_tidecoin_old",historical]);outputs.append(historical)
        up=root/"tidecoin/src";sources=[up/"pq/falcon-512"/(s+".c") for s in names if s!="fips202"]
        run(["cc","-O2","-I",up,HERE/"oracle_tidecoin.c",up/"pq/falcon512.c",up/"pq/fips202.c",*sources,"-lm","-o",work/"oracle_tidecoin"])
        path=work/"tidecoin.bin";run([work/"oracle_tidecoin",path,historical]);outputs.append(path)
    source=root/"ckb/tests/nist-test-vector-tests/test_vectors/internalProjection.json"
    suite=json.loads(source.read_text());selected={};records=[]
    for group in suite["testGroups"]:
        param=NAMES.index(group["parameterSet"])
        for t in group["tests"]:
            flags=4 if t["testPassed"] else 0
            if group["signatureInterface"]=="internal" and t["testPassed"] and param not in selected:
                selected[param]=t;flags|=3
            if group["signatureInterface"]=="external" and group["preHash"]=="pure":flags|=16
            sk=hexbytes(t,"sk");n=len(hexbytes(t,"pk"))//2
            fields=[sk[:3*n],final_message(t),hexbytes(t,"context"),hexbytes(t,"pk"),sk,
                    hexbytes(t,"signature"),hexbytes(t,"additionalRandomness"),hexbytes(t,"message")]
            records.append((3,param,t["tcId"],flags,fields))
    assert len(records)==504 and len(selected)==12
    if a.only in (None,"slhdsa"):
        path=work/"slhdsa-nist.bin";write_records(path,records);outputs.append(path)
    if a.only in (None,"ckb"):
        up=root/"ckb/deps/sphincsplus/ref";all_bytes=[]
        for param in range(12):
            t=selected[param];preimage=bytes(range(256))*2+bytes([param])
            digest=hashlib.blake2b(preimage,digest_size=32,person=b"ckb-sphincs+-msg").digest()
            record=(4,param+48,t["tcId"],6,[b"",preimage,b"",hexbytes(t,"pk"),hexbytes(t,"sk"),b"",hexbytes(t,"additionalRandomness"),digest])
            inp=work/f"ckb-{param}.in";out=work/f"ckb-{param}.bin";write_records(inp,[record])
            p=NAMES[param].replace("SLH-DSA-","sphincs-").lower();family="sha2" if param<6 else "shake"
            srcs="address merkle wots wotsx1 utils utilsx1 fors sign".split()+["sha2" if param<6 else "fips202",f"hash_{family}",f"thash_{family}_simple"]
            exe=work/f"oracle_ckb_{param}"
            run(["cc","-O2","-std=c11",f"-DPARAMS={p}","-I",up,HERE/"oracle_ckb.c",*[up/(s+".c") for s in srcs],"-o",exe])
            run([exe,inp,out]);all_bytes.append(out.read_bytes()[12:])
            print("CKB oracle",param+48,p,flush=True)
        path=work/"ckb.bin";path.write_bytes(b"PQPORT01"+struct.pack("<I",12)+b"".join(all_bytes));outputs.append(path)
    if a.only in (None,"mldsa"):
        records=[];existing=[]
        for mode in ["keyGen","sigGen","sigVer"]:
            d=json.loads((root/"acvp"/f"mldsa-{mode}.json").read_text())
            for g in d["testGroups"]:
                param=int(g["parameterSet"].split("-")[-1])
                if param not in [44,65,87] or g.get("externalMu"):continue
                for t in (g["tests"][:1] if param==87 else g["tests"]):
                    flags=1 if mode=="keyGen" else (6 if mode=="sigGen" else 4 if t["testPassed"] else 0)
                    if g.get("signatureInterface")=="external" and g["preHash"]=="pure":flags|=16
                    rnd=bytes(32) if g.get("deterministic",True) else hexbytes(t,"rnd")
                    fields=[hexbytes(t,"seed"),final_message(t),hexbytes(t,"context"),hexbytes(t,"pk"),hexbytes(t,"sk"),hexbytes(t,"signature"),rnd,hexbytes(t,"message")]
                    if param==87:existing.append((6,param,t["tcId"],flags,fields))
                    else:records.append((5,param,t["tcId"],flags,fields))
        path=work/"mldsa-nist.bin";write_records(path,records);outputs.append(path)
        path=work/"existing-dsa87.bin";write_records(path,existing);outputs.append(path)
    for path in outputs:
        target=fixtures/(path.name+".gz");target.write_bytes(gzip.compress(path.read_bytes(),mtime=0))
        print(target.name,"bytes",path.stat().st_size,"sha256",hashlib.sha256(path.read_bytes()).hexdigest(),flush=True)

if __name__=="__main__":main()
