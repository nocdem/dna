import { assertWalletActive } from '../keys.js';
import { TronWeb, utils } from 'tronweb';
import { CHAINS } from '../config.js';
import { request, rawInteger, formatUnits } from '../core.js';
const FEE_LIMIT = 100_000_000;
export async function balances(chain, address, endpoint) {
  if (!TronWeb.isAddress(address)) throw new Error('Invalid TRON address.');
  const result = await request(`${endpoint.replace(/\/$/, '')}/v1/accounts/${address}`);
  if (!Array.isArray(result.data)) throw new Error('Invalid TRON account response.');
  const account = result.data[0];
  return [{ symbol: 'TRX', balance: formatUnits(rawInteger(account?.balance ?? 0), 6) }, ...CHAINS.tron.tokens.map(t => {
    const entry = account?.trc20?.find(row => Object.hasOwn(row, t.address));
    return { ...t, balance: formatUnits(rawInteger(entry?.[t.address] ?? '0'), t.decimals) };
  })];
}
export function validateTransaction(tx, { from, to, asset, units }) {
  const hex = a => TronWeb.address.toHex(a).toLowerCase();
  const contracts = tx?.raw_data?.contract;
  if (!Array.isArray(contracts) || contracts.length !== 1 || tx.signature || tx.raw_data.data) throw new Error('Unexpected TRON transaction.');
  const contract = contracts[0], value = contract.parameter?.value;
  if (!value || hex(value.owner_address) !== hex(from) || contract.Permission_id) throw new Error('Unexpected TRON sender or permission.');
  if (!asset.address) {
    if (contract.type !== 'TransferContract' || hex(value.to_address) !== hex(to) || rawInteger(value.amount) !== units) throw new Error('TRON transfer does not match the reviewed request.');
  } else {
    const data = `a9059cbb${hex(to).slice(2).padStart(64, '0')}${units.toString(16).padStart(64, '0')}`;
    if (contract.type !== 'TriggerSmartContract' || hex(value.contract_address) !== hex(asset.address) || value.data?.toLowerCase() !== data || (value.call_value ?? 0) !== 0 || value.call_token_value || value.token_id || tx.raw_data.fee_limit !== FEE_LIMIT) throw new Error('TRON token transfer does not match the reviewed request.');
  }
  if (!utils.transaction.txCheck(tx)) throw new Error('TRON transaction encoding does not match its contents.');
}
export async function prepare({ wallet, to, asset, units, endpoint }) {
  if (!TronWeb.isAddress(to)) throw new Error('Invalid TRON recipient.');
  // Keep signing on the repository's mainnet provider. Never silently fall back to Shasta.
  if (endpoint.replace(/\/$/, '') !== CHAINS.tron.endpoint) throw new Error('TRON sending requires the configured mainnet provider.');
  const tron = new TronWeb({ fullHost: endpoint, timeout: 15000 });
  const from = wallet.addresses.tron;
  let tx;
  if (!asset.address) {
    if (units > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('TRX amount exceeds the safe SDK limit.');
    tx = await tron.transactionBuilder.sendTrx(to, Number(units), from);
  } else {
    const result = await tron.transactionBuilder.triggerSmartContract(asset.address, 'transfer(address,uint256)', { feeLimit: FEE_LIMIT, callValue: 0 }, [{ type: 'address', value: to }, { type: 'uint256', value: units.toString() }], from);
    if (!result.result?.result || !result.transaction) throw new Error('TRON could not build the token transfer.');
    tx = result.transaction;
  }
  validateTransaction(tx, { from, to, asset, units });
  return { fee: asset.address ? 'Energy fee limit: 100 TRX. Bandwidth fees may also apply.' : 'TRON bandwidth and recipient activation fees may apply; final charge is set by the network.', expiresAt: Math.min(Date.now() + 45000, tx.raw_data.expiration),
    async send() {
        assertWalletActive(wallet);
      validateTransaction(tx, { from, to, asset, units });
      const signed = await tron.trx.sign(tx, wallet.tronPrivateKey);
      assertWalletActive(wallet);
      const result = await tron.trx.sendRawTransaction(signed);
      if (!result.result) throw new Error('TRON rejected the broadcast. Check the explorer before retrying.');
      return signed.txID;
    } };
}
