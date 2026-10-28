import { ed25519 } from '@noble/curves/ed25519';
import { AccountRole, isAddress, isSolanaError, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT, SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE,
  getAddressEncoder, getBase64Decoder, pipe, createSolanaRpcFromTransport, createTransactionMessage,
  setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash, appendTransactionMessageInstructions,
  compileTransaction, assertIsTransactionWithinSizeLimit, getBase64EncodedWireTransaction, getSignatureFromTransaction } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { getTransferSolInstruction } from '@solana-program/system';
import { TronWeb } from 'tronweb';
import * as solana from '../../../src/adapters/solana.js';
import * as tron from '../../../src/adapters/tron.js';
import { assertWalletActive } from '../../../src/keys.js';
import { rpc, request, rawInteger, formatUnits } from '../../../src/core.js';
import { rpcFetch } from '../../../src/rpc-transport.js';

// The web adapters cannot accept another expected genesis: solana.js:10-12
// compares CHAINS.solana.genesisHash; tron.js:15-19 also pins the endpoint.
// Extension-only adaptation: check the selected network identity before every
// testnet use. Mainnet continues through the original adapters unchanged.
// Full genesis equality matches those adapters. Expected testnet values:
// /opt/dna/tasks/orchestration.md:5921, "[nodus-1] 2026-10-29 — Verifier p8",
// live reads on 2026-10-28 23:12–23:13 UTC; that entry retracts the earlier
// prefix / last-four-byte derivation. Keyring-api scopes are labels only.
export async function checkNetwork(chain, network, options) {
  if (network.id === 'mainnet') return (chain === 'solana' ? solana : tron).checkNetwork(network.endpoint, options);
  if (chain === 'solana') {
    const genesis = await rpc(network.endpoint, 'getGenesisHash', [], options);
    if (genesis !== network.genesisHash) throw new Error('RPC genesis does not match the selected Solana network.');
  } else {
    const genesis = (await request(`${network.endpoint}/wallet/getblockbynum`, { num: 0 }, options))?.blockID;
    if (genesis !== network.genesisHash) throw new Error('RPC genesis does not match the selected TRON network.');
  }
}

// Native Solana prepare and its transport/error/signing helpers are copied
// from web-wallet/src/adapters/solana.js:25-88,100-158 at 9b1188174.
// Only checkNetwork takes the selected network. Native-only testnets: the
// token lists in web-wallet/src/config.js:29-30 (Solana), :33-35 (TRON) are
// mainnet addresses; no testnet token deployments were supplied.
function createRpc(endpoint) {
  return createSolanaRpcFromTransport(async ({ payload, signal }) => {
    const response = await rpcFetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: stringifyJsonWithBigInts(payload), signal });
    if (!response.ok) throw new Error(`RPC request failed (HTTP ${response.status}).`);
    const data = parseJsonWithBigInts(await response.text());
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('RPC rejected the request.');
    return data;
  });
}
async function call(request) {
  try { return await request.send(); } catch (error) {
    if (!isSolanaError(error)) throw error;
    if (isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)) throw new Error('RPC rejected the transaction in preflight simulation.');
    throw new Error(`RPC rejected the request (Solana error ${error.context.__code}).`);
  }
}
function transactionError(error) {
  if (!isSolanaError(error)) return error;
  if (isSolanaError(error, SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE)) return new Error('Invalid Solana transaction: the recipient is a program address and cannot receive this transfer.');
  return new Error(`Invalid Solana transaction (Solana error ${error.context.__code}).`);
}
function build(step) {
  try {
    const result = step();
    return result instanceof Promise ? result.catch(error => { throw transactionError(error); }) : result;
  } catch (error) { throw transactionError(error); }
}
const unsignedBigInt = value => typeof value === 'bigint' && value >= 0n;
const validLifetime = latest => typeof latest?.blockhash === 'string' && isAddress(latest.blockhash) && unsignedBigInt(latest.lastValidBlockHeight) && latest.lastValidBlockHeight <= BigInt(Number.MAX_SAFE_INTEGER);
function signWithWalletKey(transaction, signer) {
  const signers = Object.keys(transaction.signatures);
  if (signers.length !== 1 || signers[0] !== signer.publicKey) throw new Error('Unexpected Solana transaction signers.');
  const signature = ed25519.sign(transaction.messageBytes, signer.secretKey.subarray(0, 32));
  if (!ed25519.verify(signature, transaction.messageBytes, getAddressEncoder().encode(signer.publicKey))) throw new Error('Signature verification failed.');
  const signed = Object.freeze({ ...transaction, signatures: Object.freeze({ [signer.publicKey]: signature }) });
  try { assertIsTransactionWithinSizeLimit(signed); } catch (error) {
    if (isSolanaError(error, SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT)) throw new Error('Transaction too large.');
    throw error;
  }
  return signed;
}
async function prepareSolana({ wallet, to, asset, units }, network) {
  if (!isAddress(to)) throw new Error('Invalid Solana address.');
  if (asset.address) throw new Error('Testnet token deployments are not configured.');
  await checkNetwork('solana', network);
  if (units > 2n ** 64n - 1n) throw new Error('Amount exceeds Solana token limits.');
  const connection = createRpc(network.endpoint), owner = wallet.solana.publicKey;
  const instructions = [build(() => getTransferSolInstruction({ source: { address: owner, role: AccountRole.WRITABLE_SIGNER }, destination: to, amount: units }))];
  const latest = (await call(connection.getLatestBlockhash()))?.value;
  if (!validLifetime(latest)) throw new Error('RPC returned an invalid blockhash.');
  const tx = build(() => compileTransaction(pipe(createTransactionMessage({ version: 'legacy' }),
    m => setTransactionMessageFeePayer(owner, m),
    m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: latest.blockhash, lastValidBlockHeight: latest.lastValidBlockHeight }, m),
    m => appendTransactionMessageInstructions(instructions, m))));
  const fee = (await call(connection.getFeeForMessage(build(() => getBase64Decoder().decode(tx.messageBytes)))))?.value;
  if (!unsignedBigInt(fee)) throw new Error('Could not estimate Solana network fee.');
  const balance = (await call(connection.getBalance(owner)))?.value;
  if (!unsignedBigInt(balance)) throw new Error('RPC returned an invalid balance.');
  if (balance < fee + units) throw new Error('Insufficient SOL for amount, fee and account rent.');
  return { fee: `${formatUnits(fee, 9)} SOL fee`, expiresAt: Date.now() + 45000,
    async send(onBroadcast) {
      assertWalletActive(wallet); await checkNetwork('solana', network);
      const height = await call(connection.getBlockHeight());
      if (!unsignedBigInt(height)) throw new Error('RPC returned an invalid block height.');
      if (height > latest.lastValidBlockHeight) throw new Error('Transaction expired. Review a fresh transaction.');
      assertWalletActive(wallet);
      const signed = build(() => signWithWalletKey(tx, wallet.solana));
      const hash = build(() => getSignatureFromTransaction(signed));
      await onBroadcast?.({ hash, lastValidBlockHeight: Number(latest.lastValidBlockHeight) });
      assertWalletActive(wallet);
      const returned = await call(connection.sendTransaction(build(() => getBase64EncodedWireTransaction(signed)), { encoding: 'base64', maxRetries: 0n }));
      if (returned !== hash) throw new Error('RPC returned a different transaction identifier.');
      return hash;
    } };
}
// Native branch of adapters/tron.js:60-89; exported client and transaction
// validation are reused. Only the identity check is adapted for testnets.
async function prepareTron({ wallet, to, asset, units }, network) {
  if (!TronWeb.isAddress(to)) throw new Error('Invalid TRON recipient.');
  if (asset.address) throw new Error('Testnet token deployments are not configured.');
  await checkNetwork('tron', network);
  const client = tron.createTronClient(network.endpoint), from = wallet.addresses.tron;
  if (units > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('TRX amount exceeds the safe SDK limit.');
  const tx = await client.transactionBuilder.sendTrx(to, Number(units), from);
  tron.validateTransaction(tx, { from, to, asset, units });
  return { fee: 'TRON bandwidth and recipient activation fees may apply; final charge is set by the network.', expiresAt: Math.min(Date.now() + 45000, tx.raw_data.expiration),
    async send(onBroadcast) {
      assertWalletActive(wallet); await checkNetwork('tron', network); assertWalletActive(wallet);
      tron.validateTransaction(tx, { from, to, asset, units });
      const signed = await client.trx.sign(tx, wallet.tronPrivateKey);
      assertWalletActive(wallet);
      await onBroadcast?.({ hash: signed.txID, expiration: tx.raw_data.expiration });
      assertWalletActive(wallet);
      const result = await client.trx.sendRawTransaction(signed);
      if (!result.result) throw new Error('TRON rejected the broadcast. Check the explorer before retrying.');
      return signed.txID;
    } };
}
export function testnetAdapter(chain, network) {
  return { ...(chain === 'solana' ? solana : tron),
    prepare: fields => (chain === 'solana' ? prepareSolana : prepareTron)(fields, network),
    async balances(_chain, address, _endpoint, options = {}) {
      if (chain === 'solana' ? !isAddress(address) : !TronWeb.isAddress(address)) throw new Error('Invalid address.');
      await checkNetwork(chain, network, options);
      if (chain === 'solana') {
        const native = await rpc(network.endpoint, 'getBalance', [address, { commitment: 'confirmed' }], options);
        return [{ symbol: 'SOL', balance: formatUnits(rawInteger(native.value), 9) }];
      }
      const result = await request(`${network.endpoint}/v1/accounts/${address}`, undefined, options);
      if (!Array.isArray(result.data)) throw new Error('Invalid TRON account response.');
      return [{ symbol: 'TRX', balance: formatUnits(rawInteger(result.data[0]?.balance ?? 0), 6) }];
    },
  };
}

// Status branches copied from src/activity.js:116-143, after the selected
// identity check. Never send or infer failure from absence.
export async function checkTestnetActivity(row, network, options) {
  await checkNetwork(row.chain, network, options);
  if (row.chain === 'solana') {
    const result = await rpc(network.endpoint, 'getSignatureStatuses', [[row.hash], { searchTransactionHistory: true }], options);
    if (!Array.isArray(result?.value) || result.value.length !== 1) throw new Error('Invalid signature status.');
    const status = result.value[0];
    if (status) {
      if (!Object.hasOwn(status, 'err') || !['processed', 'confirmed', 'finalized'].includes(status.confirmationStatus)) throw new Error('Unrecognized signature status.');
      if (status.confirmationStatus === 'finalized') return { status: status.err === null ? 'confirmed' : 'failed', note: status.err === null ? 'Finalized on Solana.' : 'Execution failed on Solana (finalized).' };
      return { status: 'included', note: status.err === null ? 'Observed; awaiting finality.' : 'Execution error observed; awaiting finality.' };
    }
    if (Number.isSafeInteger(row.lastValidBlockHeight)) {
      const height = await rpc(network.endpoint, 'getBlockHeight', [{ commitment: 'finalized' }], options);
      if (!Number.isSafeInteger(height)) throw new Error('Invalid block height.');
      if (height > row.lastValidBlockHeight) return { status: 'unknown', note: 'Blockhash validity ended, but absence from this lookup does not prove failure. Tracking continues; check the explorer before resending.' };
    }
    return { status: 'pending', note: 'No finalized signature found yet.' };
  }
  const tx = await request(`${network.endpoint}/walletsolidity/gettransactionbyid`, { value: row.hash }, options);
  if (tx.txID) {
    if (tx.txID.toLowerCase() !== row.hash.toLowerCase() || !Array.isArray(tx.ret) || tx.ret.length !== 1 || typeof tx.ret[0].contractRet !== 'string') throw new Error('Invalid solidified transaction.');
    return { status: tx.ret[0].contractRet === 'SUCCESS' ? 'confirmed' : 'failed', note: 'Execution result from a solidified TRON transaction.' };
  }
  if (Object.keys(tx).length) throw new Error('Unrecognized TRON transaction response.');
  return { status: 'pending', note: 'Not solidified. Check explorer before resending; no absence-based failure is assumed.' };
}
