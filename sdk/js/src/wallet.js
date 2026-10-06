// The ONE place the SDK reaches into the web wallet's source. Everything the
// SDK does with keys, addresses, the ABI, the §18 reads and the EVM envelope
// is the wallet's own code, imported — never copied (decision
// docs/plans/decisions/2026-10-06-evm-dev-tooling.md item 3: the SDK is
// derived from the wallet's EVM modules — ABI, address, signing via
// send.wasm).
//
// These files import `ethers` and `@noble/hashes` by bare name; Node resolves
// them from web-wallet/node_modules (the importing file's own package), so
// `npm ci` must have run in web-wallet/ (README "Requirements").

// identity: the 24-word phrase -> the ML-DSA-87 signing seed and the Nodus
// address (src/nodus/derive.js, the same derivation as
// shared/crypto/key/bip39/seed_derivation.c)
export { nodusSigningSeed, deriveNodusAddress } from '../../../web-wallet/src/nodus/derive.js';
export { validateNodusPhrase } from '../../../web-wallet/src/recovery.js';

// the send module (C -> WASM) and its client (one queue, lock order)
export {
  createNodusSendModule, validateNodusSendNetwork, validateNodusEvmNetwork,
  NODUS_SEND_NETWORK, NODUS_EVM_NETWORK
} from '../../../web-wallet/src/nodus/send-module.js';
export { createNodusClient } from '../../../web-wallet/src/nodus/client.js';

// smart contracts: addresses, ABI, units, the §18 reply checks, the account
// (review / one-pending queue) and the contract wrapper
export {
  parseAddress, isAddress, toChecksumAddress, evmAddressFromFingerprint, evmAddressFromPublicKey,
  EVM_WITHDRAW_ADDRESS, bytesToHex, hexToBytes
} from '../../../web-wallet/src/evm/address.js';
export {
  Interface, decodeRevert, selectorOf, topicOf, parseParam, encodeSequence, decodeSequence, typeString
} from '../../../web-wallet/src/evm/abi.js';
export {
  WEI_PER_RAW, EVM_DECIMALS, NODUS_DECIMALS, rawToWei, weiToRaw, formatUnits, parseUnits,
  formatWei, parseWei, formatRaw, parseRaw
} from '../../../web-wallet/src/evm/units.js';
export { EMPTY_CODE_HASH, EVM_LOGS_MAX, EVM_LOGS_SPAN } from '../../../web-wallet/src/evm/rpc.js';
export {
  EvmAccount, Contract, revertText, createdCheck, EVM_MAX_FEE_RAW, EVM_TX_GAS_CAP
} from '../../../web-wallet/src/evm/contract.js';
export { parseBalance, parseRulesetInfo, NODUS_REVIEW_MS } from '../../../web-wallet/src/adapters/nodus.js';
