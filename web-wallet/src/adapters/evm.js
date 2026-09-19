import { assertWalletActive } from '../keys.js';
import { JsonRpcProvider, FetchRequest, Interface, getAddress, keccak256, formatUnits } from 'ethers';
import { CHAINS } from '../config.js';
import { rawInteger, rpc } from '../core.js';
const erc20 = new Interface(['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)']);
export async function balances(chain, address, endpoint) {
  getAddress(address);
  await checkNetwork(chain, endpoint);
  const c = CHAINS[chain];
  const native = rawInteger(await rpc(endpoint, 'eth_getBalance', [address, 'latest']));
  const tokens = await Promise.allSettled(c.tokens.map(async t => ({ ...t, balance: formatUnits(rawInteger(await rpc(endpoint, 'eth_call', [{ to: t.address, data: erc20.encodeFunctionData('balanceOf', [address]) }, 'latest'])), t.decimals) })));
  return [{ symbol: c.symbol, balance: formatUnits(native, 18) }, ...tokens.map((r, i) => r.status === 'fulfilled' ? r.value : { symbol: c.tokens[i].symbol, error: 'Balance unavailable' })];
}
export async function checkNetwork(chain, endpoint) {
  if (rawInteger(await rpc(endpoint, 'eth_chainId', [])) !== BigInt(CHAINS[chain].chainId)) throw new Error('RPC is connected to the wrong network.');
}
export async function prepare({ chain, wallet, to, asset, units, endpoint }) {
  to = getAddress(to);
  await checkNetwork(chain, endpoint);
  const transport = new FetchRequest(endpoint); transport.timeout = 15000;
  const provider = new JsonRpcProvider(transport, undefined, { batchMaxCount: 1 });
  try {
    const from = wallet.addresses[chain];
    const tx = { from, to: asset.address || to, value: asset.address ? 0n : units, data: asset.address ? erc20.encodeFunctionData('transfer', [to, units]) : '0x' };
    const [gas, fees, nonce, balance] = await Promise.all([provider.estimateGas(tx), provider.getFeeData(), provider.getTransactionCount(from, 'pending'), provider.getBalance(from)]);
    const gasLimit = gas * 120n / 100n;
    const gasPrice = fees.gasPrice;
    if (!gasPrice || balance < gasLimit * gasPrice + tx.value) throw new Error('Insufficient native balance for amount and network fee.');
    const unsigned = { ...tx, chainId: CHAINS[chain].chainId, nonce, gasLimit, gasPrice, type: 0 };
    delete unsigned.from;
    return { fee: `Up to ${formatUnits(gasLimit * gasPrice, 18)} ${CHAINS[chain].symbol}`, expiresAt: Date.now() + 60000,
      async send(onBroadcast) {
        assertWalletActive(wallet);
        await checkNetwork(chain, endpoint);
        assertWalletActive(wallet);
        const signed = await wallet.evm.signTransaction(unsigned);
        assertWalletActive(wallet);
        const hash = keccak256(signed); onBroadcast?.({ hash });
        const returned = await rpc(endpoint, 'eth_sendRawTransaction', [signed]);
        if (returned?.toLowerCase() !== hash.toLowerCase()) throw new Error('RPC returned a different transaction identifier.');
        return hash;
      } };
  } finally { provider.destroy(); }
}
