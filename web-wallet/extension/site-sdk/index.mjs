import createNodusSiteVerifyWasm from './nodus-site-verify.mjs';

const encoder = new TextEncoder();
function messageBytes(message) {
  if (typeof message === 'string') return encoder.encode(message);
  if (message instanceof Uint8Array) return message;
  throw new TypeError('Message must be text or a Uint8Array.');
}
function hex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function fixedBytes(value, length) {
  if (value instanceof Uint8Array) return value.length === length ? value : null;
  if (typeof value !== 'string') return null;
  const text = value.startsWith('0x') ? value.slice(2) : value;
  if (text.length !== length * 2 || !/^[0-9a-f]+$/i.test(text)) return null;
  return Uint8Array.from(text.match(/../g), pair => parseInt(pair, 16));
}

// EIP-6963 identity: extension/src/inpage.js startInpage(). Listen before
// requesting reannouncement, so synchronous announcements cannot be lost.
export function createNodusConnector({ window = globalThis.window } = {}) {
  let discovery, account;
  function provider() {
    if (discovery) return discovery;
    if (!window?.addEventListener || !window?.dispatchEvent) throw new Error('Nodus provider discovery requires a browser window.');
    discovery = new Promise(resolve => {
      const announce = event => {
        const detail = event.detail;
        if (detail?.info?.rdns !== 'io.nodusnetwork.wallet' || detail.info.name !== 'Nodus Wallet' ||
            typeof detail.provider?.request !== 'function') return;
        window.removeEventListener('eip6963:announceProvider', announce);
        resolve(detail.provider);
      };
      window.addEventListener('eip6963:announceProvider', announce);
      window.dispatchEvent(new window.Event('eip6963:requestProvider'));
    });
    return discovery;
  }
  async function connect() {
    const accounts = await (await provider()).request({ method: 'nodus_requestAccounts' });
    if (!Array.isArray(accounts) || !accounts[0]?.address || !accounts[0]?.publicKey) throw new Error('Nodus returned no account.');
    account = accounts[0]; return account;
  }
  async function signMessage(message) {
    const bytes = messageBytes(message);
    // SignatureController 39.2.10 dist/utils/validation.cjs:17-24 refuses
    // empty data before normalization. "0x" would instead sign UTF-8 text.
    if (!bytes.length) throw new TypeError('Invalid message "data": message must be non-empty.');
    const data = `0x${hex(bytes)}`;
    const current = account || await connect();
    return (await provider()).request({ method: 'nodus_signMessage', params: [data, current.address] });
  }
  function createConnectButton({ document = window?.document, onConnect, onError } = {}) {
    if (!document?.createElement) throw new Error('A document is required to create the connect button.');
    const button = document.createElement('button');
    button.type = 'button'; button.textContent = 'Connect with Nodus';
    button.onclick = async () => {
      try { const value = await connect(); await onConnect?.(value); return value; }
      catch (error) { if (onError) return onError(error); throw error; }
    };
    return button;
  }
  return { connect, signMessage, createConnectButton };
}

const connector = createNodusConnector();
export const connect = connector.connect;
export const signMessage = connector.signMessage;
export const createConnectButton = connector.createConnectButton;

let verifier;
async function withVerifier(run) {
  verifier ||= createNodusSiteVerifyWasm().catch(error => { verifier = undefined; throw error; });
  const M = await verifier, allocations = [];
  const copy = value => {
    const ptr = M._malloc(Math.max(value.length, 1));
    if (!ptr) throw new Error('Could not allocate verification input.');
    allocations.push([ptr, value.length]); M.HEAPU8.set(value, ptr); return ptr;
  };
  try {
    return run(M, copy);
  } finally {
    for (const [ptr, length] of allocations) { M.HEAPU8.fill(0, ptr, ptr + length); M._free(ptr); }
  }
}

// The address rule in src/nodus/derive.js: SHA3-512(publicKey), lowercase
// hex. Hash only through the project's qgp_sha3_512 in the C bridge.
export async function addressOf(publicKey) {
  const pk = fixedBytes(publicKey, 2592);
  if (!pk) throw new TypeError('Public key must contain 2592 bytes.');
  return withVerifier((M, copy) => {
    const pkAt = copy(pk), addressAt = copy(new Uint8Array(64));
    if (M._nsv_address_of(pkAt, addressAt) !== 0) throw new Error('Nodus address derivation failed.');
    return hex(M.HEAPU8.subarray(addressAt, addressAt + 64));
  });
}

// No JS hash or signature implementation: encode inputs, then call the
// project's nodus_verify_site_message through the verify-only C bridge.
export async function verify({ origin, message, publicKey, signature } = {}) {
  if (typeof origin !== 'string' || !origin) return false;
  let bytes;
  try { bytes = messageBytes(message); } catch { return false; }
  const site = encoder.encode(origin), pk = fixedBytes(publicKey, 2592), sig = fixedBytes(signature, 4627);
  if (!pk || !sig || site.length > 0xffffffff || bytes.length > 0xffffffff) return false;
  return withVerifier((M, copy) => {
    const originAt = copy(site), messageAt = copy(bytes), sigAt = copy(sig), pkAt = copy(pk);
    return M._nsv_verify(originAt, site.length, messageAt, bytes.length, sigAt, pkAt) === 1;
  });
}
