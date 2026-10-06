// @nodus/evm-sdk — the Nodus EVM for Node.js scripts. In-repo only, not
// published (decision docs/plans/decisions/2026-10-06-evm-dev-tooling.md
// item 3). See ../README.md.
export { NodusEvm, decodeLog, DEFAULT_WASM_DIR } from './sdk.js';
export { reviewAndSend } from './review.js';
export { deriveIdentity } from './identity.js';
export { DEFAULT_NETWORK, DEFAULT_EVM_NETWORK, parseEndpoint, resolveNetwork, resolveEvmNetwork } from './network.js';
// the wallet's own codecs and units, re-exported unchanged
export {
  Interface, decodeRevert, selectorOf, topicOf,
  parseAddress, isAddress, toChecksumAddress, evmAddressFromFingerprint, evmAddressFromPublicKey, EVM_WITHDRAW_ADDRESS,
  WEI_PER_RAW, EVM_DECIMALS, NODUS_DECIMALS, rawToWei, weiToRaw, formatUnits, parseUnits, formatWei, parseWei, formatRaw, parseRaw,
  EMPTY_CODE_HASH, EVM_LOGS_MAX, EVM_LOGS_SPAN, EVM_MAX_FEE_RAW, EVM_TX_GAS_CAP, NODUS_REVIEW_MS, revertText
} from './wallet.js';
