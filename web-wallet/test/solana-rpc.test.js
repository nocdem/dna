import { readFileSync } from 'node:fs';
import { createAssociatedTokenAccountIdempotentInstruction, createTransferCheckedInstruction } from '../src/adapters/solana-token.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { getAddressDecoder, getAddressEncoder, getTransactionDecoder, getCompiledTransactionMessageDecoder, decompileTransactionMessage } from '@solana/kit';
import { parseTransferSolInstruction } from '@solana-program/system';
import { TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '../src/adapters/solana-token.js';
import { encodeBase58 } from 'ethers';
import { prepare } from '../src/adapters/solana.js';
import { deriveWallet, disposeWallet } from '../src/keys.js';
import { CHAINS } from '../src/config.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const addressFromSeed = fill => getAddressDecoder().decode(ed25519.getPublicKey(new Uint8Array(32).fill(fill)));
// Decode a broadcast wire transaction, check every signature against its signer
// address, and return the decompiled instructions ({programAddress, accounts:[{address, role}], data}).
function decodeVerified(base64) {
  const tx = getTransactionDecoder().decode(Buffer.from(base64, 'base64'));
  for (const [signer, signature] of Object.entries(tx.signatures)) assert.ok(signature && ed25519.verify(signature, tx.messageBytes, getAddressEncoder().encode(signer)));
  return { signature: Object.values(tx.signatures)[0], instructions: decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(tx.messageBytes)).instructions };
}
test('updated Solana SDK transport and token codecs preserve native/SPL signed transactions with one broadcast', async t => {
  const wallet = deriveWallet(phrase), to = addressFromSeed(2);
  const associated = await getAssociatedTokenAddress(CHAINS.solana.tokens[1].address, wallet.solana.publicKey);
  const accounts = [addressFromSeed(3), addressFromSeed(4), associated];
  const oldFetch = globalThis.fetch; t.after(() => { globalThis.fetch = oldFetch; });
  let currentAsset, broadcasts = [], noted, omitAssociated = false, wrongOwner = false, primaryBalance = '2000000';
  globalThis.fetch = async (_, options) => {
    const body = JSON.parse(options.body); assert.ok(!options.body.includes(phrase));
    const result = {
      getGenesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
      getLatestBlockhash: { context: { slot: 1 }, value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100 } },
      getFeeForMessage: { context: { slot: 1 }, value: 5000 }, getBalance: { context: { slot: 1 }, value: 1000000000 }, getBlockHeight: 50,
      getAccountInfo: { context: { slot: 1 }, value: null }, getMinimumBalanceForRentExemption: 2039280,
      getTokenAccountsByOwner: { context: { slot: 1 }, value: accounts.filter(key => !omitAssociated || key !== associated).map((key, i) => ({ pubkey: key, account: { executable: false, owner: TOKEN_PROGRAM_ID, lamports: 2039280, rentEpoch: 0, data: { program: 'spl-token', space: 165, parsed: { type: 'account', info: { state: 'initialized', mint: currentAsset?.address, owner: wrongOwner ? to : wallet.addresses.solana, tokenAmount: { amount: key === associated ? primaryBalance : i ? '700000' : '400000', decimals: 6, uiAmount: 0.4, uiAmountString: '0.4' } } } } } })) },
    }[body.method];
    if (body.method === 'sendTransaction') {
      assert.deepEqual(body.params[1], { encoding: 'base64', maxRetries: 0, preflightCommitment: 'confirmed' });
      assert.notEqual(body.params[1].skipPreflight, true);
      const tx = decodeVerified(body.params[0]); broadcasts.push(tx);
      return Response.json({ jsonrpc: '2.0', id: body.id, result: encodeBase58(tx.signature) });
    }
    assert.notEqual(result, undefined, body.method);
    return Response.json({ jsonrpc: '2.0', id: body.id, result });
  };
  currentAsset = { symbol: 'SOL', decimals: 9 };
  const native = await prepare({ wallet, to, asset: currentAsset, units: 12345n, endpoint: CHAINS.solana.endpoint });
  assert.equal(broadcasts.length, 0); const hash = await native.send(details => { noted = details; });
  assert.equal(hash, noted.hash); assert.equal(noted.lastValidBlockHeight, 100);
  const nativeData = parseTransferSolInstruction(broadcasts[0].instructions[0]); assert.equal(nativeData.data.amount, 12345n); assert.equal(nativeData.accounts.destination.address, to);
  currentAsset = CHAINS.solana.tokens[1];
  const spl = await prepare({ wallet, to, asset: currentAsset, units: 1000000n, endpoint: CHAINS.solana.endpoint });
  assert.match(spl.fee, /account rent/); await spl.send();
  const tx = broadcasts[1]; assert.equal(tx.instructions.length, 2); assert.equal(tx.instructions[0].data[0], 1);
  const transfers = tx.instructions.slice(1);
  assert.deepEqual(transfers.map(ix => Buffer.from(ix.data).readBigUInt64LE(1)), [1000000n]);
  for (const ix of transfers) {
    assert.equal(ix.data[0], 12); assert.equal(ix.data[9], 6);
    assert.equal(ix.accounts[0].address, associated);
    assert.equal(ix.accounts[3].address, wallet.addresses.solana); assert.equal(!!(ix.accounts[3].role & 2), true);
    assert.equal(ix.accounts[2].address, await getAssociatedTokenAddress(ix.accounts[1].address, to));
  }
  assert.equal(broadcasts.length, 2);
  const tokenArgs = { wallet, to, asset: currentAsset, units: 1000000n, endpoint: 'https://rpc.example' };
  omitAssociated = true;
  await assert.rejects(prepare(tokenArgs), /Primary token account unavailable/);
  omitAssociated = false; primaryBalance = '400000';
  await assert.rejects(prepare(tokenArgs), /Insufficient balance in the primary/);
  primaryBalance = '2000000'; wrongOwner = true;
  await assert.rejects(prepare(tokenArgs), /Invalid primary/);
  wrongOwner = false;
  assert.equal(broadcasts.length, 2);
  const cancelled = await prepare({ wallet, to, asset: currentAsset, units: 1n, endpoint: CHAINS.solana.endpoint });
  await assert.rejects(cancelled.send(async () => { await Promise.resolve(); disposeWallet(wallet); }), /locked/);
  assert.equal(broadcasts.length, 2);
});

test('malformed recipient-account replies and program-address recipients stop before any broadcast, in the wallet’s own words', async t => {
  const wallet = deriveWallet(phrase), to = addressFromSeed(2), token = CHAINS.solana.tokens[1];
  const associated = await getAssociatedTokenAddress(token.address, wallet.solana.publicKey);
  const oldFetch = globalThis.fetch; t.after(() => { globalThis.fetch = oldFetch; disposeWallet(wallet); });
  let accountInfo; const methods = [];
  globalThis.fetch = async (_, options) => {
    const body = JSON.parse(options.body); methods.push(body.method);
    const result = {
      getGenesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
      getLatestBlockhash: { context: { slot: 1 }, value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100 } },
      getFeeForMessage: { context: { slot: 1 }, value: 5000 }, getBalance: { context: { slot: 1 }, value: 1000000000 }, getMinimumBalanceForRentExemption: 2039280,
      getTokenAccountsByOwner: { context: { slot: 1 }, value: [{ pubkey: associated, account: { executable: false, owner: TOKEN_PROGRAM_ID, lamports: 2039280, rentEpoch: 0, data: { program: 'spl-token', space: 165, parsed: { type: 'account', info: { state: 'initialized', mint: token.address, owner: wallet.addresses.solana, tokenAmount: { amount: '2000000', decimals: 6, uiAmount: 2, uiAmountString: '2' } } } } } }] },
      getAccountInfo: accountInfo
    }[body.method];
    assert.notEqual(result, undefined, body.method);
    return Response.json({ jsonrpc: '2.0', id: body.id, result });
  };
  // A reply without a well-formed `value` must not be read as "account absent" (web3.js rejected it).
  for (const malformed of [{ context: { slot: 1 } }, { context: { slot: 1 }, value: { data: 'garbage' } }, { context: { slot: 1 }, value: { data: ['', 'base64'], executable: false, lamports: -1, owner: TOKEN_PROGRAM_ID } }, { context: { slot: 1 }, value: 0 }]) {
    accountInfo = malformed; methods.length = 0;
    await assert.rejects(prepare({ wallet, to, asset: token, units: 1000000n, endpoint: 'https://rpc.example' }), /RPC returned an invalid recipient token account\./);
    assert.ok(!methods.includes('getMinimumBalanceForRentExemption') && !methods.includes('sendTransaction'), JSON.stringify(malformed));
  }
  // A well-formed existing account is present: no rent, prepare succeeds.
  accountInfo = { context: { slot: 1 }, value: { data: ['', 'base64'], executable: false, lamports: 2039280, owner: TOKEN_PROGRAM_ID, rentEpoch: 0, space: 165 } };
  assert.doesNotMatch((await prepare({ wallet, to, asset: token, units: 1000000n, endpoint: 'https://rpc.example' })).fee, /account rent/);
  // SOL to the System Program address: kit refuses to compile (an invoked program cannot be writable).
  methods.length = 0;
  const rejected = await prepare({ wallet, to: '11111111111111111111111111111111', asset: { symbol: 'SOL', decimals: 9 }, units: 1n, endpoint: 'https://rpc.example' }).then(() => null, error => error);
  assert.ok(rejected instanceof Error);
  assert.match(rejected.message, /^Invalid Solana transaction: the recipient is a program address/);
  assert.doesNotMatch(rejected.message, /Solana error #|npx/);
  assert.ok(!methods.includes('sendTransaction'));
});

test('maintained generated token instructions match prior SPL reference bytes and account roles', async () => {
  const vector = JSON.parse(readFileSync(new URL('./fixtures/spl-reference.json', import.meta.url)));
  const pub = key => vector[key];
  const ata = await getAssociatedTokenAddress(pub('mint'), pub('recipient'));
  assert.equal(ata, vector.associatedAccount);
  const instructions = [createAssociatedTokenAccountIdempotentInstruction(pub('owner'), ata, pub('recipient'), pub('mint')), createTransferCheckedInstruction(pub('sourceAccount'), pub('mint'), ata, pub('owner'), 400000n, 6)];
  // Account roles are kit's AccountRole bits: 2 = signer, 1 = writable.
  const serialize = x => ({ programId: x.programAddress, keys: x.accounts.map(k => ({ pubkey: k.address, isSigner: !!(k.role & 2), isWritable: !!(k.role & 1) })), data: Buffer.from(x.data).toString('hex') });
  assert.deepEqual(instructions.map(serialize), vector.instructions);
});
