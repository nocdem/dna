import test from 'node:test';
import assert from 'node:assert/strict';
import { HDNodeWallet, Transaction as EthTransaction } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { AccountRole, getAddressDecoder, getAddressEncoder, pipe, createTransactionMessage, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash, appendTransactionMessageInstruction, compileTransaction, getTransactionEncoder, getTransactionDecoder, getCompiledTransactionMessageDecoder, decompileTransactionMessage } from '@solana/kit';
import { getTransferSolInstruction, parseTransferSolInstruction } from '@solana-program/system';
import { TronWeb } from 'tronweb';
import { deriveWallet, disposeWallet, newPhrase } from '../src/keys.js';
import { amountUnits, rawInteger, endpointUrl, request } from '../src/core.js';
import { readCpunk, parseCpunkBalance } from '../src/adapters/cpunk.js';
import { prepareTransfer } from '../src/wallet.js';
import { validateTransaction } from '../src/adapters/tron.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const address = 'Rj7J7MiX2bWy8sNybZfJFiwvEcU44PH89JnTmBXGREmPgVHvx8j5XvXFDNmV5RYdB3MzvgCTAY3RimZ7DWkV2zwBDTSjJNCvroNW2Tps';
test('24-word Nodus root produces fixed first-account external addresses', () => {
  const wallet = deriveWallet(phrase);
  assert.deepEqual(wallet.addresses, { ethereum: '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', bsc: '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb', solana: '3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx', tron: 'TEfhiqsW1SdN44DeHrAWVmbyr8ZbvChrtS' });
  disposeWallet(wallet); assert.equal(wallet.locked, true); assert.equal(wallet.evm, null); assert.equal(wallet.solana, null); assert.equal(wallet.tronPrivateKey, null);
  assert.throws(() => deriveWallet('abandon '.repeat(12)), /24-word/);
  const generated = newPhrase(); assert.equal(generated.split(' ').length, 24); assert.ok(deriveWallet(generated).addresses.ethereum);
});
test('exact units reject floats, negative, excessive precision, overflow and malformed RPC balances', () => {
  assert.equal(amountUnits('9007199254740993.000000000000000001', 18), 9007199254740993000000000000000001n);
  for (const amount of ['0', '-1', '1e3', '.1', '1.0000001', 'NaN', ' 1', '01']) assert.throws(() => amountUnits(amount, 6));
  assert.throws(() => amountUnits((2n ** 256n).toString(), 0));
  assert.equal(rawInteger('0xffffffffffffffff'), 18446744073709551615n);
  assert.throws(() => rawInteger(Number.MAX_SAFE_INTEGER + 1));
  assert.throws(() => rawInteger(undefined));
  assert.throws(() => endpointUrl('http://rpc.cellframe.net/connect'));
  assert.throws(() => endpointUrl('https://user:password@example.com'));
});
test('CPUNK uses public-address query only and distinguishes errors from exact zero', async () => {
  let sent;
  const result = await readCpunk({ address, endpoint: 'https://rpc.example/connect', fetcher: async (url, options) => { sent = JSON.parse(options.body); return Response.json({ result: [[{ balance: '1234.000000000000000001' }]] }); } });
  assert.equal(result.balance, '1234.000000000000000001');
  assert.deepEqual(sent, { method: 'wallet', subcommand: 'info', arguments: { net: 'Backbone', addr: address, token: 'CPUNK' }, id: 1 });
  assert.equal(parseCpunkBalance({ result: [[{ balance: '0' }]] }), '0');
  for (const bad of [{}, { result: [] }, { result: [[{ balance: 0 }]] }, { result: [[{ balance: '0', token: 'CELL' }]] }, { error: {}, result: [[{ balance: '1' }]] }]) assert.throws(() => parseCpunkBalance(bad));
  await assert.rejects(readCpunk({ address: phrase, endpoint: 'https://rpc.example' }), /public address/);
  await assert.rejects(request('https://rpc.example', {}, { fetcher: async () => { throw new Error('network'); } }), /unavailable/);
});
test('review only sends on confirmation, once, and rejects expired/cancelled/ambiguous retries', async () => {
  let sends = 0;
  const args = { wallet: deriveWallet(phrase), chain: 'ethereum', symbol: 'ETH', to: '0x0000000000000000000000000000000000000001', amount: '1' };
  const mock = (expiresAt, nonce = 7) => ({ ethereum: { prepare: async () => ({ expiresAt, fee: '0.001 ETH', nonce, send: async onBroadcast => { sends++; await onBroadcast?.({ hash: 'hash', nonce }); return 'hash'; } }) } });
  const review = await prepareTransfer(args, mock(Date.now() + 10000)); assert.equal(sends, 0); assert.equal(review.nonce, 7);
  let broadcastDetails;
  assert.equal(await review.confirm(details => { broadcastDetails = details; }), 'hash'); assert.equal(sends, 1); assert.equal(broadcastDetails.nonce, 7); await assert.rejects(review.confirm(), /closed/);
  const cancelled = await prepareTransfer(args, mock(Date.now() + 10000)); cancelled.cancel(); await assert.rejects(cancelled.confirm(), /closed/);
  const expired = await prepareTransfer(args, mock(Date.now() - 1)); await assert.rejects(expired.confirm(), /expired/);
  const failure = await prepareTransfer(args, { ethereum: { prepare: async () => ({ expiresAt: Date.now() + 10000, send: async () => { throw new Error('ambiguous'); } }) } });
  await assert.rejects(failure.confirm(), /ambiguous/); await assert.rejects(failure.confirm(), /closed/);
  await assert.rejects(prepareTransfer({ ...args, symbol: 'CPUNK' }), /Unsupported asset/);
  // Cellframe/CPUNK has no send adapter (src/wallet.js's real adapter map is
  // unchanged: ethereum, bsc, solana, tron only), so a send attempt on it is
  // rejected by the same generic guard as an unopened wallet, before ever
  // reaching assetFor() or a chain implementation.
  await assert.rejects(prepareTransfer({ ...args, chain: 'cellframe', symbol: 'CPUNK' }), /Open a wallet first/);
  assert.equal(sends, 1);
});
test('offline ETH and SOL signatures serialize and recover the intended sender and amount', async () => {
  const wallet = deriveWallet(phrase), to = '0x0000000000000000000000000000000000000001';
  const signed = await wallet.evm.signTransaction({ to, value: 123456789012345678n, chainId: 1, nonce: 0, gasLimit: 21000n, gasPrice: 1000000000n, type: 0 });
  const decoded = EthTransaction.from(signed);
  assert.equal(decoded.from, wallet.addresses.ethereum); assert.equal(decoded.to, to); assert.equal(decoded.value, 123456789012345678n); assert.equal(decoded.chainId, 1n);
  // The wallet's Solana buffer is seed || public key; signing uses its first 32 bytes (adapters/solana.js).
  const target = getAddressDecoder().decode(ed25519.getPublicKey(new Uint8Array(32).fill(2))), owner = wallet.solana.publicKey;
  const unsigned = compileTransaction(pipe(createTransactionMessage({ version: 'legacy' }), m => setTransactionMessageFeePayer(owner, m), m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 0n }, m), m => appendTransactionMessageInstruction(getTransferSolInstruction({ source: { address: owner, role: AccountRole.WRITABLE_SIGNER }, destination: target, amount: 12345n }), m)));
  const signature = ed25519.sign(unsigned.messageBytes, wallet.solana.secretKey.subarray(0, 32));
  const parsed = getTransactionDecoder().decode(getTransactionEncoder().encode({ ...unsigned, signatures: { [owner]: signature } }));
  assert.deepEqual(Object.keys(parsed.signatures), [wallet.addresses.solana]); assert.equal(ed25519.verify(parsed.signatures[owner], parsed.messageBytes, getAddressEncoder().encode(owner)), true);
  const transfer = parseTransferSolInstruction(decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(parsed.messageBytes)).instructions[0]);
  assert.equal(transfer.accounts.destination.address, target); assert.equal(transfer.data.amount, 12345n);
});
test('TRON rejects altered recipients, amounts, permissions and unexpected calls before signing', async () => {
  const wallet = deriveWallet(phrase);
  const tron = new TronWeb({ fullHost: 'https://api.trongrid.io' });
  const to = TronWeb.address.fromPrivateKey(HDNodeWallet.fromPhrase(phrase, undefined, "m/44'/195'/0'/0/1").privateKey.slice(2));
  const tx = await tron.transactionBuilder.sendTrx(to, 1000000, wallet.addresses.tron, { blockHeader: { ref_block_bytes: 'abcd', ref_block_hash: '0123456789abcdef', expiration: Date.now() + 60000, timestamp: Date.now() } });
  const intent = { from: wallet.addresses.tron, to, asset: { symbol: 'TRX' }, units: 1000000n };
  validateTransaction(tx, intent);
  const signed = await tron.trx.sign(tx, wallet.tronPrivateKey); assert.equal(signed.signature.length, 1);
  for (const mutate of [x => x.raw_data.contract[0].parameter.value.amount++, x => x.raw_data.contract[0].parameter.value.to_address = TronWeb.address.toHex(wallet.addresses.tron), x => x.raw_data.contract.push(x.raw_data.contract[0]), x => x.raw_data.contract[0].Permission_id = 2]) {
    const changed = structuredClone(tx); mutate(changed); assert.throws(() => validateTransaction(changed, intent));
  }
});
test('TRON rejects an expiration outside the accepted broadcast window', async () => {
  const wallet = deriveWallet(phrase);
  const tron = new TronWeb({ fullHost: 'https://api.trongrid.io' });
  const to = TronWeb.address.fromPrivateKey(HDNodeWallet.fromPhrase(phrase, undefined, "m/44'/195'/0'/0/1").privateKey.slice(2));
  const tx = await tron.transactionBuilder.sendTrx(to, 1000000, wallet.addresses.tron, { blockHeader: { ref_block_bytes: 'abcd', ref_block_hash: '0123456789abcdef', expiration: Date.now() + 60000, timestamp: Date.now() } });
  const intent = { from: wallet.addresses.tron, to, asset: { symbol: 'TRX' }, units: 1000000n };
  validateTransaction(tx, intent);
  // The expiration check runs before txCheck's encoding-consistency check, so
  // mutating only the expiration proves this specific check fires, not txCheck.
  const tooFar = structuredClone(tx); tooFar.raw_data.expiration = Date.now() + 11 * 60 * 1000;
  assert.throws(() => validateTransaction(tooFar, intent), /expiration is out of range/);
  const notNumber = structuredClone(tx); notNumber.raw_data.expiration = String(tx.raw_data.expiration);
  assert.throws(() => validateTransaction(notNumber, intent), /expiration is out of range/);
});
