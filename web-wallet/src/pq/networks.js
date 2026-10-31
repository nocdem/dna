const sendNote = 'Receive only. Sending and balances are not available in this release.';
function entry(name, symbol, decimals, ids) {
  const networks = ids.map(id => Object.freeze({ id, label: id === 'mainnet' ? 'Mainnet' : 'Testnet' }));
  return Object.freeze({ name, symbol, decimals, tokens: Object.freeze([]),
    receiveOnly: true, balanceUnavailable: true, sendNote,
    networks: Object.freeze(networks), defaultNetwork: ids[0] });
}
export const PQ_NETWORKS = Object.freeze({
  algorand: entry('Algorand', 'ALGO', 6, ['mainnet', 'testnet']),
  tidecoin: entry('Tidecoin', 'TDC', 8, ['mainnet']),
  ckb: entry('Nervos CKB', 'CKB', 8, ['mainnet', 'testnet']),
  soqucoin: entry('Soqucoin', 'SOQ', 8, ['mainnet']),
  qtc: entry('QTC', 'QTC', 8, ['mainnet', 'testnet']),
  xion: entry('Verona / XION', 'XION', 6, ['mainnet', 'testnet']),
  splendor: entry('Splendor', 'SPLD', 18, ['mainnet', 'testnet']),
  asentum: entry('Asentum', 'ASE', 18, ['testnet']),
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
