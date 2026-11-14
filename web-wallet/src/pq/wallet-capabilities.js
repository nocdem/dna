// Web Wallet and Connect gates. The send / history flags come from the table the
// trusted extension reads too (src/pq/send-gates.js; operator 2026-11-03: the
// surfaces must match). Differences are the explicit override list below and the
// notes, which stay platform text.
import { capabilitiesFor, pageSupported } from '../capabilities.js';
import { pqSendGate } from './send-gates.js';
import { CKB_FULL_RECIPIENT_SEND_ENABLED } from './ckb-recipient-policy.js';
// Web override list (operator decision 2026-11-03, docs/plans/approved/2026-11-03-pq-send-parity.md
// section 0: sending on these networks stays in the extension): the extension sends on these mainnets, the web wallet and Connect
// do not and say so. Printed by test/pq-send-gate-parity.test.js.
export const WEB_SEND_OFF = Object.freeze([['xion', 'mainnet'], ['splendor', 'mainnet'], ['qtc', 'mainnet']].map(entry => Object.freeze(entry)));
const SEND_FROM_EXTENSION = Object.freeze({ xion: 'XION', splendor: 'SPLD', qtc: 'QTC' });
export function walletCapabilities(chain, networkId) {
  const base = capabilitiesFor(chain), gate = pqSendGate(chain, networkId);
  const flags = gate ? { ...base, ...gate } : base;
  return WEB_SEND_OFF.some(([c, id]) => c === chain && id === networkId) ? { ...flags, send: false } : flags;
}
export function walletPageSupported(chain, page, networkId) {
  if (page === 'send') return walletCapabilities(chain, networkId).send;
  if (page === 'wallet-activity') return walletCapabilities(chain, networkId).history;
  return pageSupported(chain, page);
}
export function walletPqNetwork(chain, config, networkId) {
  return { ...config, testnet: networkId === 'testnet', receiveOnly: !walletCapabilities(chain, networkId).send,
        ...(chain === 'asentum' && networkId === 'testnet' ? { sendNote: 'Native ASE testnet only. Set an explicit maximum fee per gas; Activity shows local submissions only.' } : {}),
        ...(chain === 'soqucoin' && networkId === 'mainnet' ? { sendNote: 'Native transparent SOQ payments; mature node-verified inputs only.' } : {}),
    ...(chain === 'algorand' && networkId === 'mainnet' ? { sendNote: 'Native ALGO payments; verified mainnet protocol and direct Falcon account required.' } : {}),
    // Same wording as the extension (extension/src/constants/capabilities.js, extensionNetworkConfig).
    ...(chain === 'ckb' && networkId === 'mainnet' ? {
      sendNote: CKB_FULL_RECIPIENT_SEND_ENABLED ? 'Native CKB to full-format Bech32m recipients; quantum inputs only. Address validity does not prove recipient control. Signed simulation is disclosed to the configured node.' : 'Native CKB only; quantum-lock recipients and empty-data, non-cellbase inputs. Signed simulation is disclosed to the configured node.' } : {}),
    ...(Object.hasOwn(SEND_FROM_EXTENSION, chain) && networkId === 'mainnet' ? { sendNote: `Send ${SEND_FROM_EXTENSION[chain]} from the extension.` } : {}) };
}
// The Ixios network config the wallet shows for a network id of IXIOS_NETWORKS: send follows the shared gate, the notes are the
// extension's wording (extension/src/constants/capabilities.js, extensionNetworkConfig; test/pq-send-gate-parity.test.js compares them).
// An id outside the table gets no send and the extension's refusal note.
const IXIOS_SEND_NOTE = 'Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.';
export function walletIxiosNetwork(config, networkId) {
  return { ...config, receiveOnly: !walletCapabilities('ixios', networkId).send,
    sendNote: networkId === 'mainnet' ? IXIOS_SEND_NOTE : networkId === 'testnet' ? `Ixios test network: test IXIOS only. ${IXIOS_SEND_NOTE}` : 'IXIOS sends are available only on the mainnet code candidate.' };
}
