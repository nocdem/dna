// MetaMask v13.54.0 app/scripts/constants/stream.ts:2-11; operator names, 2026-10-28.
export const CONTENT_SCRIPT = 'nodus-contentscript';
export const INPAGE = 'nodus-inpage';
export const EIP_1193_PROVIDER = 'nodus-provider';
export const CAIP_MULTICHAIN_PROVIDER = 'nodus-multichain-provider';

// Q-9 prefix substitution: providers 22.1.1 dist/StreamProvider.mjs:35-57, 74-77;
// app/scripts/streams/provider-stream.ts:297, 414, 437; shared/constants/messages.ts:5.
export const PROVIDER_METHODS = Object.freeze({
  accountsChanged: 'nodus_accountsChanged',
  chainChanged: 'nodus_chainChanged',
  getProviderState: 'nodus_getProviderState',
  logWeb3ShimUsage: 'nodus_logWeb3ShimUsage',
  connectCanRetry: 'NODUS_EXTENSION_CONNECT_CAN_RETRY',
  streamFailure: 'NODUS_STREAM_FAILURE',
});
export const EXTENSION_READY = 'NODUS_EXTENSION_READY';
