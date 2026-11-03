// Implemented wallet features, independent of endpoint readiness or failures.
// Shared by Wallet, Connect and the extension’s separate screen router.
const receiveOnly = { receive: true, balance: false, history: false, send: false };
const transfer = { receive: true, balance: true, history: true, send: true };
const definitions = {
  nodus: { ...transfer, earn: true, contracts: true, sharedVaults: true },
  ethereum: transfer, bsc: { ...transfer, history: false }, solana: transfer, tron: transfer,
  cellframe: { ...receiveOnly, balance: true, history: true },
  ixios: { ...receiveOnly, balance: true },
  algorand: { ...receiveOnly, balance: true, history: true },
  ckb: { ...receiveOnly, balance: true }, tidecoin: receiveOnly, soqucoin: { ...receiveOnly, balance: true, history: true },
  qtc: { ...receiveOnly, balance: true, history: true }, xion: { ...receiveOnly, balance: true, history: true }, splendor: { ...receiveOnly, balance: true, history: true }, asentum: { ...receiveOnly, balance: true }
};
const empty = Object.freeze({ receive: false, balance: false, history: false, send: false, earn: false, contracts: false, sharedVaults: false });
export const NETWORK_CAPABILITIES = Object.freeze(Object.fromEntries(Object.entries(definitions).map(([chain, flags]) => [chain, Object.freeze({ ...empty, ...flags })])));
export function capabilitiesFor(chain) { return typeof chain === 'string' && Object.hasOwn(NETWORK_CAPABILITIES, chain) ? NETWORK_CAPABILITIES[chain] : empty; }
export function pageSupported(chain, page) {
  const feature = { send: 'send', receive: 'receive', earn: 'earn', vaults: 'sharedVaults', contracts: 'contracts', 'wallet-activity': 'history' }[page];
  return !feature || capabilitiesFor(chain)[feature];
}
