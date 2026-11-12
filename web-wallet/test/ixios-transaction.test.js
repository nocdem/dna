import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {decodeRlp,encodeRlp} from 'ethers';import {ixiosSigningHash,signIxiosTransfer,parseIxiosSignedTransfer} from '../src/pq/ixios/transaction.js';
const vectors=JSON.parse(readFileSync(new URL('./ixios-reference/vectors.json',import.meta.url))),wasmBytes=readFileSync(new URL('../src/pq/mldsa87-sign.wasm',import.meta.url));
for(const v of vectors)test(`Ixios v1.1.1 native signer oracle: ${v.compact?'32-byte compact':'48-byte'} destination`,async()=>{const transfer={to:'0x'+v.to,amount:BigInt(v.value),nonce:BigInt(v.nonce),gasPrice:BigInt(v.gasPrice),gasLimit:BigInt(v.gas)},r=await signIxiosTransfer(transfer,{seed:Uint8Array.from(Buffer.from(v.seed,'hex')),rnd:new Uint8Array(32),wasmBytes});assert.equal(ixiosSigningHash(transfer),'0x'+v.signingHash);assert.equal(Buffer.from(r.publicKey).toString('hex'),v.publicKey);assert.equal(Buffer.from(r.signature).toString('hex'),v.signature);assert.equal(r.raw,'0x'+v.raw);assert.equal(r.hash,v.txHash);assert.equal(r.from,v.sender);const parsed=parseIxiosSignedTransfer(r.raw);assert.equal(parsed.to.toLowerCase(),transfer.to.toLowerCase());assert.equal(parsed.from,r.from);assert.equal(parsed.amount,transfer.amount);assert.equal((decodeRlp(r.raw)[3].length-2)/2,v.compact?32:48);});
test('Ixios strict parser rejects noncanonical and unsupported wire fields',()=>{const raw='0x'+vectors[0].raw;for(const [idx,val]of [[0,'0x0007'],[3,'0x'+'01'.repeat(20)],[5,'0x01'],[6,'0x26'],[7,'0x01'],[9,'0x02']]){let a=decodeRlp(raw);a[idx]=val;assert.throws(()=>parseIxiosSignedTransfer(encodeRlp(a)));}assert.throws(()=>parseIxiosSignedTransfer(raw.toUpperCase()));});
test('Ixios verify-only WASM accepts native vectors and rejects signature or transaction mutation',async()=>{const {verifyIxiosSignedTransfer}=await import('../src/pq/ixios/verify.js'),wasmBytes=readFileSync(new URL('../src/pq/ixios/mldsa87-verify.wasm',import.meta.url));for(const v of vectors){const raw='0x'+v.raw;assert.equal((await verifyIxiosSignedTransfer(raw,{wasmBytes})).hash,v.txHash);for(const idx of [0,1,3,4,11]){const a=decodeRlp(raw);const pos=idx===11?100:a[idx].length-2,b=Buffer.from(a[idx].slice(2),'hex');b[pos% b.length]^=1;a[idx]='0x'+b.toString('hex');await assert.rejects(verifyIxiosSignedTransfer(encodeRlp(a),{wasmBytes}));}}});
test('browser WASM hedged source-floor admission fixture is reproducible',async()=>{const v=vectors[0],r=await signIxiosTransfer({to:'0x'+v.to,amount:BigInt(v.value),nonce:7n,gasPrice:93000000000000000n,gasLimit:1000n},{seed:Uint8Array.from(Buffer.from(v.seed,'hex')),rnd:new Uint8Array(32).fill(7),wasmBytes});assert.equal(r.raw,readFileSync(new URL('./ixios-reference/hedged-admission.hex',import.meta.url),'utf8').trim());assert.equal(r.hash,'0x6664369378ad5093de9ccb3adb024343e64e4293e1f7745e5368f001c1012d20');});

// ---- Ixios test network (chain id 3): added with the test-network entry ----
// What this proves: with {networkId:'testnet'} the signing hash, the v byte (0x29), the signature, the raw bytes,
// the hash and the sender equal the pinned reference's for chain id 3 (vectors-chain3.json, written only by
// `go run oracle.go 3` against ixiosSpark v1.1.1, never by hand); the parser and the verify-only WASM bind the
// signed bytes to the entry (0x29 under testnet only, 0x25 under mainnet only); the chain-1 vectors above are untouched.
// Compile flags / environment: none. Leaves nothing behind.
// Falsely passes if: vectors-chain3.json were produced by this code (it must come from the reference oracle); the file is
// read inside each test on purpose, so a missing file fails these tests and no existing test.
const chain3 = () => JSON.parse(readFileSync(new URL('./ixios-reference/vectors-chain3.json', import.meta.url)));
const verifyWasm = () => readFileSync(new URL('../src/pq/ixios/mldsa87-verify.wasm', import.meta.url));
const transferOf = v => ({ to: '0x' + v.to, amount: BigInt(v.value), nonce: BigInt(v.nonce), gasPrice: BigInt(v.gasPrice), gasLimit: BigInt(v.gas) });
for (const index of [0, 1]) test(`Ixios test network (chain id 3) signer equals the reference oracle: vector ${index}, ${index === 1 ? '32-byte compact' : '48-byte'} destination`, async () => {
  const v = chain3()[index], transfer = transferOf(v), seed = Uint8Array.from(Buffer.from(v.seed, 'hex'));
  assert.equal(v.compact, index === 1);
  const r = await signIxiosTransfer(transfer, { seed, rnd: new Uint8Array(32), wasmBytes, networkId: 'testnet' });
  assert.equal(ixiosSigningHash(transfer, { networkId: 'testnet' }), '0x' + v.signingHash);
  assert.equal(r.signingHash, '0x' + v.signingHash);
  assert.notEqual(ixiosSigningHash(transfer), '0x' + v.signingHash, 'the chain-1 hash must differ from the chain-3 hash');
  assert.equal(Buffer.from(r.publicKey).toString('hex'), v.publicKey);
  assert.equal(Buffer.from(r.signature).toString('hex'), v.signature);
  assert.equal(r.raw, '0x' + v.raw);
  assert.equal(r.hash, v.txHash);
  assert.equal(r.from, v.sender);
  assert.equal(decodeRlp(r.raw)[6], '0x29');
  const parsed = parseIxiosSignedTransfer(r.raw, { networkId: 'testnet' });
  assert.equal(parsed.to.toLowerCase(), transfer.to.toLowerCase());
  assert.equal(parsed.from, r.from); assert.equal(parsed.amount, transfer.amount); assert.equal(parsed.hash, v.txHash);
  assert.equal(parsed.signingHash, '0x' + v.signingHash);
});
test('Ixios parser binds v to the entry: 0x29 only under testnet, 0x25 only under mainnet', () => {
  const chain1Raw = '0x' + vectors[0].raw, chain3Raw = '0x' + chain3()[0].raw;
  assert.equal(decodeRlp(chain1Raw)[6], '0x25'); assert.equal(decodeRlp(chain3Raw)[6], '0x29');
  assert.doesNotThrow(() => parseIxiosSignedTransfer(chain3Raw, { networkId: 'testnet' }));
  assert.throws(() => parseIxiosSignedTransfer(chain3Raw, { networkId: 'mainnet' }), /Unsupported Ixios signed transaction/);
  assert.throws(() => parseIxiosSignedTransfer(chain3Raw), /Unsupported Ixios signed transaction/, 'the default is mainnet');
  assert.throws(() => parseIxiosSignedTransfer(chain1Raw, { networkId: 'testnet' }), /Unsupported Ixios signed transaction/);
  assert.doesNotThrow(() => parseIxiosSignedTransfer(chain1Raw, { networkId: 'mainnet' }));
  assert.doesNotThrow(() => parseIxiosSignedTransfer(chain1Raw));
  // Any other v is refused under both entries (the existing 0x26 case, now on the test entry too).
  for (const v of ['0x26', '0x27', '0x01', '0x']) for (const networkId of ['mainnet', 'testnet']) {
    for (const raw of [chain1Raw, chain3Raw]) { const a = decodeRlp(raw); a[6] = v; assert.throws(() => parseIxiosSignedTransfer(encodeRlp(a), { networkId }), /Unsupported Ixios signed transaction/, `${networkId} ${v}`); }
  }
});
test('Ixios an unknown network id fails closed in the signer, hash and parser', async () => {
  const v = vectors[0], transfer = transferOf(v), seed = Uint8Array.from(Buffer.from(v.seed, 'hex'));
  await assert.rejects(signIxiosTransfer(transfer, { seed, rnd: new Uint8Array(32), wasmBytes, networkId: 'regtest' }), /^Error: Unknown Ixios network\.$/);
  assert.throws(() => ixiosSigningHash(transfer, { networkId: 'regtest' }), /^Error: Unknown Ixios network\.$/);
  assert.throws(() => parseIxiosSignedTransfer('0x' + v.raw, { networkId: 'regtest' }), /^Error: Unknown Ixios network\.$/);
});
test('Ixios verify-only WASM accepts the chain-3 vectors under testnet only, and rebinds the signing hash to the entry', async () => {
  const { verifyIxiosSignedTransfer } = await import('../src/pq/ixios/verify.js'), wasmBytes = verifyWasm();
  for (const v of chain3()) {
    const raw = '0x' + v.raw;
    assert.equal((await verifyIxiosSignedTransfer(raw, { wasmBytes, networkId: 'testnet' })).hash, v.txHash);
    await assert.rejects(verifyIxiosSignedTransfer(raw, { wasmBytes, networkId: 'mainnet' }), /Unsupported Ixios signed transaction/);
    await assert.rejects(verifyIxiosSignedTransfer(raw, { wasmBytes }), /Unsupported Ixios signed transaction/);
    for (const idx of [0, 1, 3, 4, 11]) {
      const a = decodeRlp(raw), pos = idx === 11 ? 100 : a[idx].length - 2, b = Buffer.from(a[idx].slice(2), 'hex');
      b[pos % b.length] ^= 1; a[idx] = '0x' + b.toString('hex');
      await assert.rejects(verifyIxiosSignedTransfer(encodeRlp(a), { wasmBytes, networkId: 'testnet' }), `mutated field ${idx}`);
    }
  }
  // A chain-1 signature carrying v = 0x29 passes the parser's shape check under testnet, but the signing hash is
  // recomputed for chain id 3, so the signature no longer verifies: the parser really rebinds the hash.
  for (const v of vectors) {
    const a = decodeRlp('0x' + v.raw); a[6] = '0x29';
    await assert.rejects(verifyIxiosSignedTransfer(encodeRlp(a), { wasmBytes, networkId: 'testnet' }), /Invalid Ixios ML-DSA-87 signature/);
  }
  // The chain-1 vectors still verify as before, under the default and under mainnet explicitly.
  for (const v of vectors) {
    assert.equal((await verifyIxiosSignedTransfer('0x' + v.raw, { wasmBytes })).hash, v.txHash);
    assert.equal((await verifyIxiosSignedTransfer('0x' + v.raw, { wasmBytes, networkId: 'mainnet' })).hash, v.txHash);
    await assert.rejects(verifyIxiosSignedTransfer('0x' + v.raw, { wasmBytes, networkId: 'testnet' }), /Unsupported Ixios signed transaction/);
  }
});
