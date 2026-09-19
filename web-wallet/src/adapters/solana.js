import { assertWalletActive } from '../keys.js';
import { Connection, PublicKey, Transaction, SystemProgram } from '@solana/web3.js';
import { getAssociatedTokenAddressSync, createAssociatedTokenAccountIdempotentInstruction, createTransferCheckedInstruction } from '@solana/spl-token';
import { CHAINS } from '../config.js';
import { rpc, rawInteger, formatUnits } from '../core.js';
const GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
export async function checkNetwork(endpoint) {
  if (await rpc(endpoint, 'getGenesisHash', []) !== GENESIS) throw new Error('RPC is not Solana mainnet.');
}
export async function balances(chain, address, endpoint) {
  new PublicKey(address); await checkNetwork(endpoint);
  const native = await rpc(endpoint, 'getBalance', [address, { commitment: 'confirmed' }]);
  const tokens = await Promise.allSettled(CHAINS.solana.tokens.map(async t => {
    const data = await rpc(endpoint, 'getTokenAccountsByOwner', [address, { mint: t.address }, { encoding: 'jsonParsed', commitment: 'confirmed' }]);
    if (!Array.isArray(data?.value)) throw new Error('Invalid token accounts.');
    const amount = data.value.reduce((sum, a) => sum + rawInteger(a.account.data.parsed.info.tokenAmount.amount), 0n);
    return { ...t, balance: formatUnits(amount, t.decimals) };
  }));
  return [{ symbol: 'SOL', balance: formatUnits(rawInteger(native.value), 9) }, ...tokens.map((r, i) => r.status === 'fulfilled' ? r.value : { symbol: CHAINS.solana.tokens[i].symbol, error: 'Balance unavailable' })];
}
export async function prepare({ wallet, to, asset, units, endpoint }) {
  const recipient = new PublicKey(to); await checkNetwork(endpoint);
  if (units > 2n ** 64n - 1n) throw new Error('Amount exceeds Solana token limits.');
  const connection = new Connection(endpoint, { commitment: 'confirmed', disableRetryOnRateLimit: true,
    fetch: (url, options) => fetch(url, { ...options, signal: options?.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000) }) });
  const owner = wallet.solana.publicKey;
  const tx = new Transaction();
  let rent = 0;
  if (!asset.address) tx.add(SystemProgram.transfer({ fromPubkey: owner, toPubkey: recipient, lamports: units }));
  else {
    const mint = new PublicKey(asset.address);
    const dest = getAssociatedTokenAddressSync(mint, recipient);
    const accounts = await connection.getParsedTokenAccountsByOwner(owner, { mint });
    let remaining = units;
    tx.add(createAssociatedTokenAccountIdempotentInstruction(owner, dest, recipient, mint));
    if (!await connection.getAccountInfo(dest)) rent = await connection.getMinimumBalanceForRentExemption(165);
    for (const account of accounts.value) {
      const info = account.account.data.parsed.info;
      if (info.state !== 'initialized') continue;
      const available = rawInteger(info.tokenAmount.amount);
      const part = available < remaining ? available : remaining;
      if (part > 0n) tx.add(createTransferCheckedInstruction(account.pubkey, mint, dest, owner, part, asset.decimals));
      remaining -= part;
      if (!remaining) break;
    }
    if (remaining) throw new Error('Insufficient spendable token balance.');
  }
  const latest = await connection.getLatestBlockhash();
  tx.recentBlockhash = latest.blockhash; tx.feePayer = owner;
  const fee = (await connection.getFeeForMessage(tx.compileMessage())).value;
  if (fee === null) throw new Error('Could not estimate Solana network fee.');
  const balance = await connection.getBalance(owner);
  if (rawInteger(balance) < BigInt(fee + rent) + (asset.address ? 0n : units)) throw new Error('Insufficient SOL for amount, fee and account rent.');
  return { fee: `${formatUnits(BigInt(fee), 9)} SOL fee${rent ? ` + ${formatUnits(BigInt(rent), 9)} SOL account rent` : ''}`, expiresAt: Date.now() + 45000,
    async send() {
        assertWalletActive(wallet);
      await checkNetwork(endpoint);
      if (await connection.getBlockHeight() > latest.lastValidBlockHeight) throw new Error('Transaction expired. Review a fresh transaction.');
      assertWalletActive(wallet);
      tx.sign(wallet.solana);
      return connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, maxRetries: 0 });
    } };
}
