import { ed25519 } from '@noble/curves/ed25519';
import { AccountRole, isAddress, isSolanaError, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE, SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT, SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE, getAddressEncoder, getBase64Decoder, pipe, createSolanaRpcFromTransport, createTransactionMessage, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash, appendTransactionMessageInstructions, compileTransaction, assertIsTransactionWithinSizeLimit, getBase64EncodedWireTransaction, getSignatureFromTransaction } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { getTransferSolInstruction } from '@solana-program/system';
import { assertWalletActive } from '../keys.js';
import { TOKEN_PROGRAM_ID, getAssociatedTokenAddress, createAssociatedTokenAccountIdempotentInstruction, createTransferCheckedInstruction } from './solana-token.js';
import { CHAINS } from '../config.js';
import { rpc, rawInteger, formatUnits } from '../core.js';
import { rpcFetch } from '../rpc-transport.js';
export async function checkNetwork(endpoint, options) {
  if (await rpc(endpoint, 'getGenesisHash', [], options) !== CHAINS.solana.genesisHash) throw new Error('RPC is not Solana mainnet.');
}
function solanaAddress(text) {
  if (!isAddress(text)) throw new Error('Invalid Solana address.');
  return text;
}
// kit's default HTTP transport calls the global fetch and takes no custom one, so it
// would bypass the response-size, JSON-shape and pacing limits in rpc-transport.js.
// Every kit RPC call of this adapter goes through rpcFetch instead. Integers travel
// as bigint both ways, as in kit's own Solana transport.
function createRpc(endpoint) {
  return createSolanaRpcFromTransport(async ({ payload, signal }) => {
    const response = await rpcFetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: stringifyJsonWithBigInts(payload), signal });
    if (!response.ok) throw new Error(`RPC request failed (HTTP ${response.status}).`);
    const data = parseJsonWithBigInts(await response.text());
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('RPC rejected the request.');
    return data;
  });
}
// kit's production errors read "Solana error #<code>; Decode this error by running
// npx …"; show the wallet's own short text instead (the code stays for support).
async function call(request) {
  try { return await request.send(); } catch (error) {
    if (!isSolanaError(error)) throw error;
    if (isSolanaError(error, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)) throw new Error('RPC rejected the transaction in preflight simulation.');
    throw new Error(`RPC rejected the request (Solana error ${error.context.__code}).`);
  }
}
// The same for kit errors raised while building, compiling, signing or encoding a
// transaction. Synchronous steps stay synchronous (no await between the lock check
// and signing in send()); a promise-returning step is mapped when it rejects.
function transactionError(error) {
  if (!isSolanaError(error)) return error;
  // The only writable accounts are the sender, the SOL recipient and the two derived
  // token accounts, so a writable invoked program here is the recipient.
  if (isSolanaError(error, SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE)) return new Error('Invalid Solana transaction: the recipient is a program address and cannot receive this transfer.');
  return new Error(`Invalid Solana transaction (Solana error ${error.context.__code}).`);
}
function build(step) {
  try {
    const result = step();
    return result instanceof Promise ? result.catch(error => { throw transactionError(error); }) : result;
  } catch (error) { throw transactionError(error); }
}
// getAccountInfo with base64 encoding: `value` is null (no account) or an account
// object. Anything else is a malformed reply, never "absent" (web3.js rejected it too).
function accountInfoState(reply) {
  if (!reply || typeof reply !== 'object' || !Object.hasOwn(reply, 'value')) return 'invalid';
  const v = reply.value;
  if (v === null) return 'absent';
  const wellFormed = v && typeof v === 'object' && Array.isArray(v.data) && v.data.length === 2 && typeof v.data[0] === 'string' && v.data[1] === 'base64'
    && typeof v.executable === 'boolean' && unsignedBigInt(v.lamports) && typeof v.owner === 'string' && isAddress(v.owner);
  return wellFormed ? 'present' : 'invalid';
}
// kit returns RPC integers as bigint (decimals/uiAmount excepted).
const unsignedBigInt = value => typeof value === 'bigint' && value >= 0n;
// A blockhash has an address's shape: 32 bytes in base58.
const validLifetime = latest => typeof latest?.blockhash === 'string' && isAddress(latest.blockhash) && unsignedBigInt(latest.lastValidBlockHeight) && latest.lastValidBlockHeight <= BigInt(Number.MAX_SAFE_INTEGER);
// WARNING: kit's own key-pair signers keep the Ed25519 key in a WebCrypto object
// that lock cannot overwrite. Sign with noble over the wallet's own buffer instead
// (keys.js), exactly as @solana/web3.js 1.99.0 did: ed25519.sign(message, secretKey[0..32]).
function signWithWalletKey(transaction, signer) {
  const signers = Object.keys(transaction.signatures);
  if (signers.length !== 1 || signers[0] !== signer.publicKey) throw new Error('Unexpected Solana transaction signers.');
  const signature = ed25519.sign(transaction.messageBytes, signer.secretKey.subarray(0, 32));
  // web3.js serialize() verified every signature against the message's signer key; keep that.
  if (!ed25519.verify(signature, transaction.messageBytes, getAddressEncoder().encode(signer.publicKey))) throw new Error('Signature verification failed.');
  const signed = Object.freeze({ ...transaction, signatures: Object.freeze({ [signer.publicKey]: signature }) });
  // web3.js serialize() also refused a transaction over the 1232-byte packet limit.
  try { assertIsTransactionWithinSizeLimit(signed); } catch (error) {
    if (isSolanaError(error, SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT)) throw new Error('Transaction too large.');
    throw error;
  }
  return signed;
}
export async function balances(chain, address, endpoint, options = {}) {
  solanaAddress(address); await checkNetwork(endpoint, options);
  const native = await rpc(endpoint, 'getBalance', [address, { commitment: 'confirmed' }], options);
  const tokens = await Promise.allSettled(CHAINS.solana.tokens.map(async t => {
    const data = await rpc(endpoint, 'getTokenAccountsByOwner', [address, { mint: t.address }, { encoding: 'jsonParsed', commitment: 'confirmed' }], options);
    if (!Array.isArray(data?.value)) throw new Error('Invalid token accounts.');
    const amount = data.value.reduce((sum, a) => sum + rawInteger(a.account.data.parsed.info.tokenAmount.amount), 0n);
    return { ...t, balance: formatUnits(amount, t.decimals) };
  }));
  return [{ symbol: 'SOL', balance: formatUnits(rawInteger(native.value), 9) }, ...tokens.map((r, i) => r.status === 'fulfilled' ? r.value : { symbol: CHAINS.solana.tokens[i].symbol, error: 'Balance unavailable' })];
}
export async function prepare({ wallet, to, asset, units, endpoint }) {
  const recipient = solanaAddress(to); await checkNetwork(endpoint);
  if (units > 2n ** 64n - 1n) throw new Error('Amount exceeds Solana token limits.');
  // Commitment 'confirmed' is kit's default for every call below (preflightCommitment for sendTransaction).
  const connection = createRpc(endpoint);
  const owner = wallet.solana.publicKey;
  const instructions = [];
  let rent = 0n;
  if (!asset.address) instructions.push(build(() => getTransferSolInstruction({ source: { address: owner, role: AccountRole.WRITABLE_SIGNER }, destination: recipient, amount: units })));
  else {
    const mint = solanaAddress(asset.address);
    const dest = await build(() => getAssociatedTokenAddress(mint, recipient));
    const source = await build(() => getAssociatedTokenAddress(mint, owner));
    const accounts = await call(connection.getTokenAccountsByOwner(owner, { mint }, { encoding: 'jsonParsed' }));
    if (!Array.isArray(accounts?.value)) throw new Error('Invalid token accounts.');
    // WARNING: an RPC-selected source could spend an unrelated delegated account.
    // Only the wallet's locally derived associated account may be signed here.
    const matches = accounts.value.filter(account => account?.pubkey === source);
    if (matches.length !== 1) throw new Error('Primary token account unavailable. Transfers require the wallet’s associated token account.');
    const account = matches[0].account, info = account?.data?.parsed?.info;
    if (account?.owner !== TOKEN_PROGRAM_ID || account.data.parsed?.type !== 'account' || info?.owner !== owner || info?.mint !== mint || info?.state !== 'initialized' || info?.tokenAmount?.decimals !== asset.decimals) throw new Error('Invalid primary token account.');
    if (rawInteger(info.tokenAmount.amount) < units) throw new Error('Insufficient balance in the primary token account. Other token accounts are not used for transfers.');
    instructions.push(build(() => createAssociatedTokenAccountIdempotentInstruction(owner, dest, recipient, mint)));
    const destState = accountInfoState(await call(connection.getAccountInfo(dest, { encoding: 'base64' })));
    if (destState === 'invalid') throw new Error('RPC returned an invalid recipient token account.');
    if (destState === 'absent') {
      rent = await call(connection.getMinimumBalanceForRentExemption(165n));
      if (!unsignedBigInt(rent)) throw new Error('Could not read Solana account rent.');
    }
    instructions.push(build(() => createTransferCheckedInstruction(source, mint, dest, owner, units, asset.decimals)));
  }
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
  if (balance < fee + rent + (asset.address ? 0n : units)) throw new Error('Insufficient SOL for amount, fee and account rent.');
  return { fee: `${formatUnits(fee, 9)} SOL fee${rent ? ` + ${formatUnits(rent, 9)} SOL account rent` : ''}`, expiresAt: Date.now() + 45000,
    async send(onBroadcast) {
        assertWalletActive(wallet);
      await checkNetwork(endpoint);
      const height = await call(connection.getBlockHeight());
      if (!unsignedBigInt(height)) throw new Error('RPC returned an invalid block height.');
      if (height > latest.lastValidBlockHeight) throw new Error('Transaction expired. Review a fresh transaction.');
      assertWalletActive(wallet);
      const signed = build(() => signWithWalletKey(tx, wallet.solana));
      const hash = build(() => getSignatureFromTransaction(signed));
      await onBroadcast?.({ hash, lastValidBlockHeight: Number(latest.lastValidBlockHeight) });
      assertWalletActive(wallet);
      // Preflight stays on: skipPreflight is omitted, as web3.js omitted it when false.
      const returned = await call(connection.sendTransaction(build(() => getBase64EncodedWireTransaction(signed)), { encoding: 'base64', maxRetries: 0n }));
      if (returned !== hash) throw new Error('RPC returned a different transaction identifier.');
      return hash;
    } };
}
