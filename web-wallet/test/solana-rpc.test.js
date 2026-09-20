import { readFileSync } from 'node:fs';
import { createAssociatedTokenAccountIdempotentInstruction, createTransferCheckedInstruction } from '../src/adapters/solana-token.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { Transaction, Keypair, SystemInstruction, PublicKey } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '../src/adapters/solana-token.js';
import { encodeBase58 } from 'ethers';
import { prepare } from '../src/adapters/solana.js';
import { deriveWallet, disposeWallet } from '../src/keys.js';
import { CHAINS } from '../src/config.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
test('updated Solana SDK transport and token codecs preserve native/SPL signed transactions with one broadcast', async t => {
  const wallet = deriveWallet(phrase), to = Keypair.fromSeed(new Uint8Array(32).fill(2)).publicKey;
  const accounts = [Keypair.fromSeed(new Uint8Array(32).fill(3)).publicKey, Keypair.fromSeed(new Uint8Array(32).fill(4)).publicKey];
  const oldFetch = globalThis.fetch; t.after(() => { globalThis.fetch = oldFetch; });
  let currentAsset, broadcasts = [], noted;
  globalThis.fetch = async (_, options) => {
    const body = JSON.parse(options.body); assert.ok(!options.body.includes(phrase));
    const result = {
      getGenesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
      getLatestBlockhash: { context: { slot: 1 }, value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100 } },
      getFeeForMessage: { context: { slot: 1 }, value: 5000 }, getBalance: { context: { slot: 1 }, value: 1000000000 }, getBlockHeight: 50,
      getAccountInfo: { context: { slot: 1 }, value: null }, getMinimumBalanceForRentExemption: 2039280,
      getTokenAccountsByOwner: { context: { slot: 1 }, value: accounts.map((key, i) => ({ pubkey: key.toBase58(), account: { executable: false, owner: TOKEN_PROGRAM_ID.toBase58(), lamports: 2039280, rentEpoch: 0, data: { program: 'spl-token', space: 165, parsed: { type: 'account', info: { state: 'initialized', mint: currentAsset?.address, owner: wallet.addresses.solana, tokenAmount: { amount: i ? '700000' : '400000', decimals: 6, uiAmount: 0.4, uiAmountString: '0.4' } } } } } })) },
    }[body.method];
    if (body.method === 'sendTransaction') {
      assert.deepEqual(body.params[1], { encoding: 'base64', maxRetries: 0, preflightCommitment: 'confirmed' });
      assert.notEqual(body.params[1].skipPreflight, true);
      const tx = Transaction.from(Buffer.from(body.params[0], 'base64')); assert.ok(tx.verifySignatures()); broadcasts.push(tx);
      return Response.json({ jsonrpc: '2.0', id: body.id, result: encodeBase58(tx.signature) });
    }
    assert.notEqual(result, undefined, body.method);
    return Response.json({ jsonrpc: '2.0', id: body.id, result });
  };
  currentAsset = { symbol: 'SOL', decimals: 9 };
  const native = await prepare({ wallet, to: to.toBase58(), asset: currentAsset, units: 12345n, endpoint: CHAINS.solana.endpoint });
  assert.equal(broadcasts.length, 0); const hash = await native.send(details => { noted = details; });
  assert.equal(hash, noted.hash); assert.equal(noted.lastValidBlockHeight, 100);
  const nativeData = SystemInstruction.decodeTransfer(broadcasts[0].instructions[0]); assert.equal(nativeData.lamports, 12345n); assert.equal(nativeData.toPubkey.toBase58(), to.toBase58());
  currentAsset = CHAINS.solana.tokens[1];
  const spl = await prepare({ wallet, to: to.toBase58(), asset: currentAsset, units: 1000000n, endpoint: CHAINS.solana.endpoint });
  assert.match(spl.fee, /account rent/); await spl.send();
  const tx = broadcasts[1]; assert.equal(tx.instructions.length, 3); assert.equal(tx.instructions[0].data[0], 1);
  const transfers = tx.instructions.slice(1);
  assert.deepEqual(transfers.map(ix => ix.data.readBigUInt64LE(1)), [400000n, 600000n]);
  for (const ix of transfers) {
    assert.equal(ix.data[0], 12); assert.equal(ix.data[9], 6);
    assert.equal(ix.keys[3].pubkey.toBase58(), wallet.addresses.solana); assert.equal(ix.keys[3].isSigner, true);
    assert.equal(ix.keys[2].pubkey.toBase58(), (await getAssociatedTokenAddress(ix.keys[1].pubkey, to)).toBase58());
  }
  assert.equal(broadcasts.length, 2);
  const cancelled = await prepare({ wallet, to: to.toBase58(), asset: currentAsset, units: 1n, endpoint: CHAINS.solana.endpoint });
  await assert.rejects(cancelled.send(async () => { await Promise.resolve(); disposeWallet(wallet); }), /locked/);
  assert.equal(broadcasts.length, 2);
});

test('maintained generated token instructions match prior SPL reference bytes and account roles', async () => {
  const vector = JSON.parse(readFileSync(new URL('./fixtures/spl-reference.json', import.meta.url)));
  const pub = key => new PublicKey(vector[key]);
  const ata = await getAssociatedTokenAddress(pub('mint'), pub('recipient'));
  assert.equal(ata.toBase58(), vector.associatedAccount);
  const instructions = [createAssociatedTokenAccountIdempotentInstruction(pub('owner'), ata, pub('recipient'), pub('mint')), createTransferCheckedInstruction(pub('sourceAccount'), pub('mint'), ata, pub('owner'), 400000n, 6)];
  const serialize = x => ({ programId: x.programId.toBase58(), keys: x.keys.map(k => ({ ...k, pubkey: k.pubkey.toBase58() })), data: Buffer.from(x.data).toString('hex') });
  assert.deepEqual(instructions.map(serialize), vector.instructions);
});
