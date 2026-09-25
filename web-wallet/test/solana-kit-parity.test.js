// Byte parity between the @solana/kit send path (0.1.23) and the @solana/web3.js
// 1.99.0 path it replaced. test/fixtures/solana-kit-parity.json was produced ONCE
// from the 0.1.22 code by scripts/make-solana-parity-fixture.mjs with the same
// fixed RPC responses replayed here. Ed25519 is deterministic, so identical
// message bytes under the same key must give identical signatures.
// How it can lie: if the fixture is regenerated from the kit code, this compares
// the kit code with itself (see the generator's header).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { encodeBase58 } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { getAddressEncoder } from '@solana/kit';
import { prepare } from '../src/adapters/solana.js';
import { deriveWallet } from '../src/keys.js';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/solana-kit-parity.json', import.meta.url)));
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const bytes = base64 => new Uint8Array(Buffer.from(base64, 'base64'));
function splitWire(wire) {
  assert.ok(wire[0] < 0x80);
  return { signatures: Array.from({ length: wire[0] }, (_, i) => wire.slice(1 + 64 * i, 65 + 64 * i)), message: wire.slice(1 + 64 * wire[0]) };
}
test('the fixture itself is self-consistent: fee message = broadcast message, signature verifies under the wallet key', () => {
  assert.match(fixture.source, /@solana\/web3\.js 1\.99\.0/);
  assert.equal(fixture.cases.length, 3);
  for (const c of fixture.cases) {
    const { signatures, message } = splitWire(bytes(c.wireBase64));
    assert.equal(signatures.length, 1, c.name);
    assert.equal(Buffer.from(message).toString('base64'), c.messageBase64, c.name);
    assert.equal(c.requests.find(r => r.method === 'getFeeForMessage').params[0], c.messageBase64, c.name);
    assert.equal(Buffer.from(signatures[0]).toString('hex'), c.signatureHex, c.name);
    assert.ok(ed25519.verify(signatures[0], message, getAddressEncoder().encode(fixture.owner)), c.name);
  }
});
test('kit send path reproduces the web3.js wire bytes, message, signature and JSON-RPC requests exactly', async t => {
  const oldFetch = globalThis.fetch; t.after(() => { globalThis.fetch = oldFetch; });
  for (const c of fixture.cases) {
    const wallet = deriveWallet(phrase);
    assert.equal(wallet.addresses.solana, fixture.owner);
    const requests = [];
    globalThis.fetch = async (url, options) => {
      const body = JSON.parse(options.body);
      requests.push({ url, method: body.method, params: body.params });
      if (body.method === 'sendTransaction') return Response.json({ jsonrpc: '2.0', id: body.id, result: encodeBase58(splitWire(bytes(body.params[0])).signatures[0]) });
      assert.ok(Object.hasOwn(c.responses, body.method), `${c.name}: unexpected ${body.method}`);
      return Response.json({ jsonrpc: '2.0', id: body.id, result: c.responses[body.method] });
    };
    const transfer = await prepare({ wallet, to: fixture.recipient, asset: c.asset, units: BigInt(c.units), endpoint: fixture.endpoint });
    assert.equal(transfer.fee, c.fee, c.name);
    let broadcast;
    const returned = await transfer.send(details => { broadcast = details; });
    // Same methods, same order, same params (object key order is not significant on the wire).
    assert.deepEqual(requests, c.requests, c.name);
    const sent = requests.find(r => r.method === 'sendTransaction').params[0];
    assert.equal(sent, c.wireBase64, `${c.name}: wire bytes`);
    const { signatures, message } = splitWire(bytes(sent));
    assert.equal(Buffer.from(message).toString('base64'), c.messageBase64, `${c.name}: message bytes`);
    assert.equal(Buffer.from(signatures[0]).toString('hex'), c.signatureHex, `${c.name}: signature`);
    assert.equal(returned, c.signatureBase58, c.name);
    assert.deepEqual(broadcast, c.broadcast, c.name);
    assert.equal(typeof broadcast.lastValidBlockHeight, 'number', c.name);
  }
});
