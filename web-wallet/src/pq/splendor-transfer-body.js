// Offline canonical unsigned native transfer body only. NOT a complete signer.
// Reference: Splendor core/types/transaction.go TransactionBody and NewTransfer;
// core/crypto/mldsa.go, pinned 38ac3ded57d6fa931dba3036d490c5d66b0fbcbc.
// Go json.Marshal uses bare big.Int integers, arrays for addresses and struct order.
// The signer must SHA3-256 these bytes and use ML-DSA-65 with FIPS-204 context
// SPLENDOR-QC-TX-v1. Never substitute a message prefix for the FIPS context.
const chains = Object.freeze({ mainnet:'splendor-quantum-1', testnet:'splendor-quantum-testnet-1' });
const uint = (s, name, max) => {
  if (typeof s !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(s) || BigInt(s) > max) throw new Error(`Invalid ${name}.`);
  return s;
};
function address(a) {
  if (typeof a !== 'string' || !/^SQ:[0-9a-f]{64}$/.test(a) || /^SQ:0{64}$/.test(a)) throw new Error('Invalid Splendor address.');
  return Array.from({length:32}, (_, i) => parseInt(a.slice(3+i*2, 5+i*2), 16));
}
export const SPLENDOR_TRANSFER_CONTEXT = 'SPLENDOR-QC-TX-v1';
export function splendorTransferBody({networkId, from, to, amount, fee, nonce, timestamp} = {}) {
  if (!Object.hasOwn(chains, networkId)) throw new Error('Unsupported Splendor network.');
  const source = address(from), target = address(to);
  uint(amount, 'amount', (1n << 256n)-1n); uint(fee, 'fee', (1n << 256n)-1n);
  uint(nonce, 'nonce', (1n << 64n)-1n); uint(timestamp, 'timestamp', (1n << 63n)-1n);
  // Explicit construction avoids JS numeric rounding for big integers.
  return `{"version":1,"chain_id":${JSON.stringify(chains[networkId])},"type":1,"alg_id":"ML-DSA-65","from":${JSON.stringify(source)},"to":${JSON.stringify(target)},"amount":${amount},"fee":${fee},"nonce":${nonce},"timestamp":${timestamp}}`;
}
