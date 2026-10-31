const sendNote = 'Receive only. Sending and balances are not available in this release.';
function entry(name, symbol, decimals, ids, icon) {
  const networks = ids.map(id => Object.freeze({ id, label: id === 'mainnet' ? 'Mainnet' : 'Testnet' }));
  return Object.freeze({ name, symbol, decimals, icon, networkGroup: 'pq', tokens: Object.freeze([]),
    receiveOnly: true, balanceUnavailable: true, sendNote,
    networks: Object.freeze(networks), defaultNetwork: ids[0] });
}
export const PQ_NETWORKS = Object.freeze({
  algorand: entry('Algorand', 'ALGO', 6, ['mainnet', 'testnet'], 'algorand.png'),
  tidecoin: entry('Tidecoin', 'TDC', 8, ['mainnet'], 'tidecoin.svg'),
  ckb: entry('Nervos CKB', 'CKB', 8, ['mainnet', 'testnet'], 'ckb.png'),
  soqucoin: entry('Soqucoin', 'SOQ', 8, ['mainnet'], 'soqucoin.png'),
  qtc: entry('QTC', 'QTC', 8, ['mainnet', 'testnet'], 'qtc.svg'),
  xion: entry('Verona / XION', 'XION', 6, ['mainnet', 'testnet'], 'verona.svg'),
  splendor: entry('Splendor', 'SPLD', 18, ['mainnet', 'testnet'], 'splendor.svg'),
  asentum: entry('Asentum', 'ASE', 18, ['testnet'], 'asentum.png'),
});
export const PQ_ENTRIES = Object.freeze(Object.entries(PQ_NETWORKS).map(([chain, network]) =>
  Object.freeze({ network, asset: Object.freeze({ chain, symbol: network.symbol,
    decimals: network.decimals, key: `${chain}:${network.symbol}` }) })));
export function isPqChain(chain) {
  return typeof chain === 'string' && Object.hasOwn(PQ_NETWORKS, chain);
}
export function pqNetwork(chain, id = isPqChain(chain) ? PQ_NETWORKS[chain].defaultNetwork : undefined) {
  if (!isPqChain(chain)) throw new Error('Unknown PQ chain.');
  const choice = PQ_NETWORKS[chain].networks.find(network => network.id === id);
  if (!choice) throw new Error('Unknown PQ network.');
  return choice;
}
