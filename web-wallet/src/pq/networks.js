import { PQ_PRICE_IDS } from './prices.js';
const sendNote = 'Receive only. Sending and balances are not available in this release.';
function entry(name, symbol, decimals, ids, icon, readable = false, readNote) {
  const networks = ids.map(id => Object.freeze({ id, label: id === 'mainnet' ? 'Mainnet' : 'Testnet' }));
  return Object.freeze({ name, symbol, decimals, icon, networkGroup: 'pq', tokens: Object.freeze([]),
    receiveOnly: true, balanceUnavailable: !readable, sendNote: readNote || (readable ? 'Sending is not available in this release. Balances and native payment history are read only.' : sendNote),
    networks: Object.freeze(networks), defaultNetwork: ids[0] });
}
export const PQ_NETWORKS = Object.freeze({
  algorand: entry('Algorand', 'ALGO', 6, ['mainnet', 'testnet'], 'algorand.png', true),
  tidecoin: entry('Tidecoin', 'TDC', 8, ['mainnet'], 'tidecoin.svg'),
  ckb: entry('Nervos CKB', 'CKB', 8, ['mainnet', 'testnet'], 'ckb.png', true, 'Total live-cell capacity is not necessarily spendable. Sending is unavailable.'),
  soqucoin: entry('Soqucoin', 'SOQ', 8, ['mainnet'], 'soqucoin.png', true, 'Confirmed native total includes immature coinbase and is not necessarily spendable. Sending is unavailable.'),
  qtc: entry('QTC', 'QTC', 8, ['mainnet', 'testnet'], 'qtc.svg', true, 'Confirmed indexed total includes immature coinbase and is not necessarily spendable. Sending is unavailable.'),
  xion: entry('Verona / XION', 'XION', 6, ['mainnet', 'testnet'], 'verona.svg', true, 'Bank balance excludes staking and rewards and does not establish spendability. Sending is unavailable.'),
  splendor: entry('Splendor', 'SPLD', 18, ['mainnet', 'testnet'], 'splendor.svg', true, 'Committed native balance. Sending is unavailable.'),
  asentum: entry('Asentum', 'ASE', 18, ['testnet'], 'asentum.png', true, 'Testnet balances are read only. Sending is not available in this release.'),
});
export const PQ_ENTRIES = Object.freeze(Object.entries(PQ_NETWORKS).map(([chain, network]) =>
  Object.freeze({ network, asset: Object.freeze({ chain, symbol: network.symbol,
    decimals: network.decimals, key: `${chain}:${network.symbol}`,
    ...(PQ_PRICE_IDS[chain] ? { priceId: PQ_PRICE_IDS[chain] } : {}) }) })));
export function isPqChain(chain) {
  return typeof chain === 'string' && Object.hasOwn(PQ_NETWORKS, chain);
}
export function pqNetwork(chain, id = isPqChain(chain) ? PQ_NETWORKS[chain].defaultNetwork : undefined) {
  if (!isPqChain(chain)) throw new Error('Unknown PQ chain.');
  const choice = PQ_NETWORKS[chain].networks.find(network => network.id === id);
  if (!choice) throw new Error('Unknown PQ network.');
  return choice;
}
