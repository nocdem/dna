// Web Wallet integration only. The extension has its own custody/router and
// has its own independently gated integration.
import { capabilitiesFor, pageSupported } from '../capabilities.js';
export function walletCapabilities(chain, networkId) {
  const base = capabilitiesFor(chain);
  if (chain === 'asentum') return { ...base, send: networkId === 'testnet', history: networkId === 'testnet' }; // local submissions only
  if (chain === 'soqucoin') return { ...base, send: networkId === 'mainnet', history: true };
  if (chain === 'algorand') return { ...base, send: networkId === 'mainnet' };
  if (chain === 'qtc') return { ...base, history: true };
  return base;
}
export function walletPageSupported(chain, page, networkId) {
  if (page === 'send') return walletCapabilities(chain, networkId).send;
  if (page === 'wallet-activity') return walletCapabilities(chain, networkId).history;
  return pageSupported(chain, page);
}
export function walletPqNetwork(chain, config, networkId) {
  return { ...config, testnet: networkId === 'testnet',
        ...(chain === 'asentum' && networkId === 'testnet' ? { receiveOnly: false, sendNote: 'Native ASE testnet only. Set an explicit maximum fee per gas; Activity shows local submissions only.' } : {}),
        ...(chain === 'soqucoin' && networkId === 'mainnet' ? { receiveOnly: false, sendNote: 'Native transparent SOQ payments; mature node-verified inputs only.' } : {}),
    ...(chain === 'algorand' && networkId === 'mainnet' ? { receiveOnly: false, sendNote: 'Native ALGO payments; verified mainnet protocol and direct Falcon account required.' } : {}) };
}
