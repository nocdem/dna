import { CKB_FULL_RECIPIENT_SEND_ENABLED } from '../../../src/pq/ckb-recipient-policy.js';
import { capabilitiesFor, pageSupported } from '../../../src/capabilities.js';
import { pqSendGate, PQ_PAGE_HISTORY_CHAINS } from '../../../src/pq/send-gates.js';

// Trusted extension wallet UI only. This does not enable site-provider signing,
// assets, rekeyed accounts or testnet sends. The send / history flags of the
// post-quantum networks, Ixios included, come from src/pq/send-gates.js, the table
// the web wallet and Connect read too (operator 2026-11-03: the surfaces must match;
// the web wallet keeps its own override list for XION, Splendor and QTC).
// The background still independently enforces mainnet + v42 + direct-account
// identity and balance/fee checks before preparing and before signing.
// Ethereum's and BNB Smart Chain's test networks (evm-networks.js) have balances, receive and native sends; the
// account history reader reads mainnet only, so history is off there.
const onEvmTestNetwork = (chain, networkId) => (chain === 'ethereum' || chain === 'bsc') && networkId !== undefined && networkId !== 'mainnet';
export function extensionCapabilitiesFor(chain, networkId) {
  const shared = capabilitiesFor(chain);
  if (onEvmTestNetwork(chain, networkId)) return { ...shared, history: false };
  // Ixios: send and history are on for every listed network (mainnet and the test network) and off for an unlisted id; that row
  // now lives in the shared table (src/pq/send-gates.js), read by the web wallet and Connect too. Live RPC availability remains qualified.
  const gate = pqSendGate(chain, networkId);
  return gate ? { ...shared, ...gate } : shared;
}
export function extensionPageSupported(chain, page, networkId) {
  if (page === 'wallet-activity' && onEvmTestNetwork(chain, networkId)) return false;
  return page === 'send' ? extensionCapabilitiesFor(chain, networkId).send : page === 'wallet-activity' && [...PQ_PAGE_HISTORY_CHAINS, 'ixios'].includes(chain) ? extensionCapabilitiesFor(chain, networkId).history : pageSupported(chain, page);
}
export function extensionNetworkConfig(chain, config, networkId) {
  if (chain === 'ixios') return { ...config, receiveOnly: !extensionCapabilitiesFor(chain, networkId).send, sendNote: networkId === 'mainnet' ? 'Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.' : networkId === 'testnet' ? 'Ixios test network: test IXIOS only. Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.' : 'IXIOS sends are available only on the mainnet code candidate.' };
  if (chain === 'qtc') return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet' ? 'Native QTC mainnet only, up to 8 inputs. Final gateway submission, not public simulation; provider-reported spendability and local submission history.' : 'QTC testnet sending and recovery are not enabled.' };
  if (chain === 'ckb') return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet' ? (CKB_FULL_RECIPIENT_SEND_ENABLED ? 'Native CKB to full-format Bech32m recipients; quantum inputs only. Address validity does not prove recipient control. Signed simulation is disclosed to the configured node.' : 'Native CKB only; quantum-lock recipients and empty-data, non-cellbase inputs. Signed simulation is disclosed to the configured node.') : 'CKB sending and recovery are available on mainnet only.' };
  if (chain === 'xion') return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet' ? 'Native XION only. Choose fee and gas; these are not a network quote. The configured node reports state and the signed transaction expires at the reviewed height.' : 'XION testnet sending and recovery are not enabled.' };
  if (chain === 'splendor') return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet'
    ? 'Native SPLD mainnet transfers. Review the current node minimum fee and nonce; uncertain sends support explicit same-transaction recovery.'
    : 'Splendor testnet remains receive only in this extension candidate.' };
  if (chain === 'asentum') return { ...config, receiveOnly: networkId !== 'testnet', sendNote: networkId === 'testnet' ? 'Native ASE on testnet only. Choose an explicit maximum fee per gas; local submissions only.' : 'Asentum sends are available only on verified testnet.' };
  if (chain === 'soqucoin') return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet'
    ? 'Native SOQ only. Node-verified mature inputs, up to 15 inputs; explicit same-transaction recovery is available for uncertain submissions.'
    : 'Soqucoin sending is available only on verified mainnet.' };
  if (chain !== 'algorand') return config;
  return { ...config, receiveOnly: networkId !== 'mainnet', sendNote: networkId === 'mainnet'
    ? 'Native ALGO payments only. Mainnet v42, direct Falcon account; assets and rekeyed accounts are not supported.'
    : 'Algorand testnet is receive only. Sending is available only on verified mainnet.' };
}
