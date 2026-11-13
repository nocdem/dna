import { assertWalletActive } from '../keys.js';
import { JsonRpcProvider, FetchRequest, Interface, getAddress, keccak256, formatUnits } from 'ethers';
import { CHAINS } from '../config.js';
import { rawInteger, rpc } from '../core.js';
import { ethersGetUrl } from '../rpc-transport.js';
const erc20 = new Interface(['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)']);
export async function balances(chain, address, endpoint, options = {}) {
  getAddress(address);
  await checkNetwork(chain, endpoint, options);
  const c = CHAINS[chain];
  const native = rawInteger(await rpc(endpoint, 'eth_getBalance', [address, 'latest'], options));
  const tokens = await Promise.allSettled(c.tokens.map(async t => ({ ...t, balance: formatUnits(rawInteger(await rpc(endpoint, 'eth_call', [{ to: t.address, data: erc20.encodeFunctionData('balanceOf', [address]) }, 'latest'], options)), t.decimals) })));
  return [{ symbol: c.symbol, balance: formatUnits(native, 18) }, ...tokens.map((r, i) => r.status === 'fulfilled' ? r.value : { symbol: c.tokens[i].symbol, error: 'Balance unavailable' })];
}
// Whether `text` is an EVM address as typed (src/wallet.js: an address
// always wins over a chain name). A mixed-case text with a wrong checksum
// is an address that fails (prepare refuses it), not a name.
export function isRecipientAddress(text) { return typeof text === 'string' && /^0x[0-9a-fA-F]{40}$/.test(text); }
// Whether `text` is an ATTEMPT at an EVM address — anything starting with
// 0x / 0X. Such text is never looked up as a chain name (src/wallet.js).
export function looksLikeAddress(text) { return typeof text === 'string' && /^0[xX]/.test(text); }
export async function checkNetwork(chain, endpoint, options) {
  if (rawInteger(await rpc(endpoint, 'eth_chainId', [], options)) !== BigInt(CHAINS[chain].chainId)) throw new Error('RPC is connected to the wrong network.');
}
// Network fee rule (plan 2026-11-12-evm-fee): a network whose latest block reports a base fee above zero gets a type 2 transaction with
// maxPriorityFeePerGas = eth_maxPriorityFeePerGas and maxFeePerGas = 2 x base fee + that tip, so the tip survives a rising base fee;
// a network without one (BNB Smart Chain reports 0) keeps type 0 at eth_gasPrice. A quote that cannot be read stops the transaction.
const FEE_READ_FAILED = 'Network fee could not be read from the RPC endpoint.';
// The Block schema's required fields; only their presence is checked here, the base fee's own shape is checked on its own.
const BLOCK_FIELDS = ['hash', 'parentHash', 'sha3Uncles', 'miner', 'stateRoot', 'transactionsRoot', 'receiptsRoot', 'logsBloom', 'number',
  'gasLimit', 'gasUsed', 'timestamp', 'extraData', 'mixHash', 'nonce', 'size', 'transactions', 'uncles'];
// The RPC `uint` shape below 2^256: lower-case hex, no leading zero. rawInteger() would also take numbers and decimal strings.
function quantity(value) {
  if (typeof value !== 'string' || !/^0x(0|[1-9a-f][0-9a-f]{0,63})$/.test(value)) throw new Error('RPC returned a malformed fee quantity.');
  return BigInt(value);
}
async function latestBlock(endpoint, options) {
  const block = await rpc(endpoint, 'eth_getBlockByNumber', ['latest', false], options);
  if (!block || typeof block !== 'object' || Array.isArray(block) || !BLOCK_FIELDS.every(field => Object.hasOwn(block, field))) throw new Error('RPC returned an invalid block.');
  return block;
}
// Returns { fields, perGas }: the fee fields to sign and the price per gas the balance check and the review use (the most it can cost).
export async function networkFee(endpoint, options) {
  try {
    const block = await latestBlock(endpoint, options);
    if (Object.hasOwn(block, 'baseFeePerGas')) {
      const base = quantity(block.baseFeePerGas);
      if (base > 0n) {
        const maxPriorityFeePerGas = quantity(await rpc(endpoint, 'eth_maxPriorityFeePerGas', [], options)), maxFeePerGas = 2n * base + maxPriorityFeePerGas;
        if (maxFeePerGas >= 2n ** 256n) throw new Error('RPC returned a fee above the transaction limit.');
        return { fields: { type: 2, maxFeePerGas, maxPriorityFeePerGas }, perGas: maxFeePerGas };
      }
    }
    const gasPrice = quantity(await rpc(endpoint, 'eth_gasPrice', [], options));
    if (gasPrice === 0n) throw new Error('RPC returned a zero gas price.');
    return { fields: { type: 0, gasPrice }, perGas: gasPrice };
  } catch (cause) { throw new Error(FEE_READ_FAILED, { cause }); }
}
// At signing: a type 2 transaction whose approved cap the latest base fee has passed could not be included, so it is refused before anything
// is signed instead of being broadcast to wait. The approved fields are never raised.
export async function assertFeeCovered(endpoint, maxFeePerGas, options) {
  let base;
  try {
    const block = await latestBlock(endpoint, options);
    if (!Object.hasOwn(block, 'baseFeePerGas')) throw new Error('RPC returned a block without a base fee.');
    base = quantity(block.baseFeePerGas);
  } catch (cause) { throw new Error(FEE_READ_FAILED, { cause }); }
  if (base > maxFeePerGas) throw new Error('Network fee rose above the approved maximum. Prepare the transfer again.');
}
export async function prepare({ chain, wallet, to, asset, units, endpoint }) {
  to = getAddress(to);
  await checkNetwork(chain, endpoint);
  const transport = new FetchRequest(endpoint); transport.timeout = 15000;
  transport.getUrlFunc = ethersGetUrl;
  const provider = new JsonRpcProvider(transport, undefined, { batchMaxCount: 1 });
  try {
    const from = wallet.addresses[chain];
    const tx = { from, to: asset.address || to, value: asset.address ? 0n : units, data: asset.address ? erc20.encodeFunctionData('transfer', [to, units]) : '0x' };
    const [gas, fee, nonce, balance] = await Promise.all([provider.estimateGas(tx), networkFee(endpoint), provider.getTransactionCount(from, 'pending'), provider.getBalance(from)]);
    const gasLimit = gas * 120n / 100n;
    if (balance < gasLimit * fee.perGas + tx.value) throw new Error('Insufficient native balance for amount and network fee.');
    const unsigned = { ...tx, chainId: CHAINS[chain].chainId, nonce, gasLimit, ...fee.fields };
    delete unsigned.from;
    return { fee: `Up to ${formatUnits(gasLimit * fee.perGas, 18)} ${CHAINS[chain].symbol}`, expiresAt: Date.now() + 60000, nonce,
      async send(onBroadcast) {
        assertWalletActive(wallet);
        await checkNetwork(chain, endpoint);
        assertWalletActive(wallet);
        if (unsigned.type === 2) { await assertFeeCovered(endpoint, unsigned.maxFeePerGas); assertWalletActive(wallet); }
        const signed = await wallet.evm.signTransaction(unsigned);
        assertWalletActive(wallet);
        const hash = keccak256(signed); await onBroadcast?.({ hash, nonce });
        assertWalletActive(wallet);
        const returned = await rpc(endpoint, 'eth_sendRawTransaction', [signed]);
        if (returned?.toLowerCase() !== hash.toLowerCase()) throw new Error('RPC returned a different transaction identifier.');
        return hash;
      } };
  } finally { provider.destroy(); }
}
