import { encodeBase58 } from 'ethers';
import { assertWalletActive } from '../keys.js';
import { Connection, PublicKey, Transaction, SystemProgram } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID, getAssociatedTokenAddress, createAssociatedTokenAccountIdempotentInstruction, createTransferCheckedInstruction } from './solana-token.js';
import { CHAINS } from '../config.js';
import { rpc, rawInteger, formatUnits } from '../core.js';
import { rpcFetch } from '../rpc-transport.js';
export async function checkNetwork(endpoint) {
  if (await rpc(endpoint, 'getGenesisHash', []) !== CHAINS.solana.genesisHash) throw new Error('RPC is not Solana mainnet.');
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
    fetch: rpcFetch });
  const owner = wallet.solana.publicKey;
  const tx = new Transaction();
  let rent = 0;
  if (!asset.address) tx.add(SystemProgram.transfer({ fromPubkey: owner, toPubkey: recipient, lamports: units }));
  else {
    const mint = new PublicKey(asset.address);
    const dest = await getAssociatedTokenAddress(mint, recipient);
    const source = await getAssociatedTokenAddress(mint, owner);
    const accounts = await connection.getParsedTokenAccountsByOwner(owner, { mint });
    // WARNING: an RPC-selected source could spend an unrelated delegated account.
    // Only the wallet's locally derived associated account may be signed here.
    const matches = accounts.value.filter(account => account.pubkey.equals(source));
    if (matches.length !== 1) throw new Error('Primary token account unavailable. Transfers require the wallet’s associated token account.');
    const account = matches[0].account, info = account.data.parsed?.info;
    if (!account.owner.equals(TOKEN_PROGRAM_ID) || account.data.parsed?.type !== 'account' || info?.owner !== owner.toBase58() || info?.mint !== mint.toBase58() || info?.state !== 'initialized' || info?.tokenAmount?.decimals !== asset.decimals) throw new Error('Invalid primary token account.');
    if (rawInteger(info.tokenAmount.amount) < units) throw new Error('Insufficient balance in the primary token account. Other token accounts are not used for transfers.');
    tx.add(createAssociatedTokenAccountIdempotentInstruction(owner, dest, recipient, mint));
    if (!await connection.getAccountInfo(dest)) rent = await connection.getMinimumBalanceForRentExemption(165);
    tx.add(createTransferCheckedInstruction(source, mint, dest, owner, units, asset.decimals));
  }
  const latest = await connection.getLatestBlockhash();
  tx.recentBlockhash = latest.blockhash; tx.feePayer = owner;
  const fee = (await connection.getFeeForMessage(tx.compileMessage())).value;
  if (fee === null) throw new Error('Could not estimate Solana network fee.');
  const balance = await connection.getBalance(owner);
  if (rawInteger(balance) < BigInt(fee + rent) + (asset.address ? 0n : units)) throw new Error('Insufficient SOL for amount, fee and account rent.');
  return { fee: `${formatUnits(BigInt(fee), 9)} SOL fee${rent ? ` + ${formatUnits(BigInt(rent), 9)} SOL account rent` : ''}`, expiresAt: Date.now() + 45000,
    async send(onBroadcast) {
        assertWalletActive(wallet);
      await checkNetwork(endpoint);
      if (await connection.getBlockHeight() > latest.lastValidBlockHeight) throw new Error('Transaction expired. Review a fresh transaction.');
      assertWalletActive(wallet);
      tx.sign(wallet.solana);
      const hash = encodeBase58(tx.signature);
      await onBroadcast?.({ hash, lastValidBlockHeight: latest.lastValidBlockHeight });
      assertWalletActive(wallet);
      const returned = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, maxRetries: 0 });
      if (returned !== hash) throw new Error('RPC returned a different transaction identifier.');
      return hash;
    } };
}
