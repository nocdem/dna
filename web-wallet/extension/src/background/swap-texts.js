import { rpcErrors } from '@metamask/rpc-errors';

// The user-signed request texts of the swap and the liquidity add, as the plan fixes them (plan
// 2026-11-08-swap-bot-plan.nodus1.md section 6.4, agreed by the operator 2026-11-10, givens item 71): the byte rules
// of 6.4.2, the typed data of 6.4.3 and 6.4.6, the plain texts of 6.4.4 and 6.4.6. The extension builds the typed
// data itself and checks every site-supplied plain text against the transfer it holds, so what the user signs is
// what is paid (the bot refuses a text whose fields differ from its own rebuild, 6.2, so the extension does not
// loosen that; it only refuses a text that is not canonical or that names another transfer than the one it holds).

const U64_MAX = 2n ** 64n - 1n;
const DECIMAL = /^(0|[1-9]\d{0,19})$/;
export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX128 = /^[0-9a-f]{128}$/;
export const ETHEREUM_ADDRESS = /^0x[0-9a-f]{40}$/;
// Amounts in the plain texts: `<integer>.<8 digits> NODUS`, `<integer>.<6 digits> USDT` (6.4.2).
const NODUS_AMOUNT = /^(0|[1-9]\d*)\.(\d{8}) NODUS$/;
const USDT_AMOUNT = /^(0|[1-9]\d*)\.(\d{6}) USDT$/;
const PRINTABLE = /^[\x20-\x7e\n]+$/;

export const SWAP_APP_NAME = 'Nodus Swap';
const NODUS_TO_USDT_TITLE = 'Nodus Swap: NODUS to USDT request';
const LIQUIDITY_ADD_TITLE = 'Nodus Swap: liquidity add request';
const NODUS_TO_USDT_KEYS = ['Sender', 'Destination', 'Amount', 'Minimum To Receive', 'Transfer ID', 'Chain ID', 'Request Number'];
const LIQUIDITY_ADD_KEYS = ['Ethereum Address', 'Nodus Address', 'USDT Amount', 'NODUS Amount', 'Transfer ID', 'Chain ID', 'Request Number'];

const refuse = message => rpcErrors.invalidParams(message);

// A raw unsigned integer given as a decimal string: no sign, no leading zero, at most 2^64 - 1 (6.4.2).
export function rawAmount(value, label, { positive = false } = {}) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) throw refuse(`${label} must be a decimal string.`);
  const raw = BigInt(value);
  if (raw > U64_MAX) throw refuse(`${label} is out of range.`);
  if (positive && raw === 0n) throw refuse(`${label} must be above zero.`);
  return raw;
}
export function lowerHex(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) throw refuse(`${label} is not in the agreed form (lowercase hex).`);
  return value;
}
export function amountText(raw, decimals, unit) {
  const scale = 10n ** BigInt(decimals);
  return `${raw / scale}.${(raw % scale).toString().padStart(decimals, '0')} ${unit}`;
}
function amountRaw(text, pattern, decimals) {
  const match = pattern.exec(text);
  if (!match) return null;
  const raw = BigInt(match[1]) * 10n ** BigInt(decimals) + BigInt(match[2]);
  return raw > U64_MAX ? null : raw;
}

// 6.4.3: the typed data of a USDT -> NODUS request. `chainId` is the network the USDT is paid on.
export function usdtToNodusTyped({ chainId, sender, destination, amount, minimumToReceive, requestNumber }) {
  return {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }],
      UsdtToNodusRequest: [
        { name: 'sender', type: 'address' }, { name: 'destination', type: 'string' }, { name: 'amount', type: 'uint256' },
        { name: 'minimumToReceive', type: 'uint256' }, { name: 'requestNumber', type: 'uint256' },
      ],
    },
    primaryType: 'UsdtToNodusRequest',
    domain: { name: SWAP_APP_NAME, chainId },
    message: { sender, destination, amount, minimumToReceive, requestNumber },
  };
}
// 6.4.6: the Ethereum half of a liquidity add.
export function liquidityAddTyped({ chainId, ethereumAddress, nodusAddress, usdtAmount, nodusAmount, requestNumber }) {
  return {
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }],
      LiquidityAddRequest: [
        { name: 'ethereumAddress', type: 'address' }, { name: 'nodusAddress', type: 'string' }, { name: 'usdtAmount', type: 'uint256' },
        { name: 'nodusAmount', type: 'uint256' }, { name: 'requestNumber', type: 'uint256' },
      ],
    },
    primaryType: 'LiquidityAddRequest',
    domain: { name: SWAP_APP_NAME, chainId },
    message: { ethereumAddress, nodusAddress, usdtAmount, nodusAmount, requestNumber },
  };
}

// 6.4.4 and 6.4.6 plain texts, built the way the bot rebuilds them. A site uses its own copy of this layout; the
// extension uses these builders in its tests and compares texts it is given with the parsers below.
export function nodusToUsdtText({ sender, destination, amount, minimumToReceive, transferId, chainId, requestNumber }) {
  return [NODUS_TO_USDT_TITLE, `Sender: ${sender}`, `Destination: ${destination}`, `Amount: ${amountText(amount, 8, 'NODUS')}`,
    `Minimum To Receive: ${amountText(minimumToReceive, 6, 'USDT')}`, `Transfer ID: ${transferId}`, `Chain ID: ${chainId}`,
    `Request Number: ${requestNumber}`].join('\n');
}
export function liquidityAddText({ ethereumAddress, nodusAddress, usdtAmount, nodusAmount, transferId, chainId, requestNumber }) {
  return [LIQUIDITY_ADD_TITLE, `Ethereum Address: ${ethereumAddress}`, `Nodus Address: ${nodusAddress}`, `USDT Amount: ${amountText(usdtAmount, 6, 'USDT')}`,
    `NODUS Amount: ${amountText(nodusAmount, 8, 'NODUS')}`, `Transfer ID: ${transferId}`, `Chain ID: ${chainId}`, `Request Number: ${requestNumber}`].join('\n');
}

// The "Key: value" lines of one kind, in the fixed order, each once, one LF between lines, no LF at the end (6.4.2).
function keyedValues(text, title, keys) {
  if (typeof text !== 'string' || !PRINTABLE.test(text) || text.length > 1024) throw refuse('The request text is not in the agreed form.');
  const lines = text.split('\n');
  if (lines.length !== keys.length + 1 || lines[0] !== title) throw refuse('The request text is not in the agreed form.');
  return keys.map((key, index) => {
    const prefix = `${key}: `;
    if (!lines[index + 1].startsWith(prefix)) throw refuse('The request text is not in the agreed form.');
    return lines[index + 1].slice(prefix.length);
  });
}
const matching = (value, pattern) => { if (!pattern.test(value)) throw refuse('The request text is not in the agreed form.'); return value; };
const raw = (value, pattern, decimals) => { const result = amountRaw(value, pattern, decimals); if (result === null) throw refuse('The request text is not in the agreed form.'); return result; };

// Strict parse of the NODUS -> USDT text. Returns its fields; anything not canonical is refused.
export function parseNodusToUsdtText(text) {
  const [sender, destination, amount, minimum, transferId, chainId, number] = keyedValues(text, NODUS_TO_USDT_TITLE, NODUS_TO_USDT_KEYS);
  const fields = { sender: matching(sender, HEX128), destination: matching(destination, ETHEREUM_ADDRESS), amount: raw(amount, NODUS_AMOUNT, 8),
    minimumToReceive: raw(minimum, USDT_AMOUNT, 6), transferId: matching(transferId, HEX128), chainId: matching(chainId, HEX64),
    requestNumber: rawAmount(number, 'The request number') };
  if (nodusToUsdtText({ ...fields, requestNumber: fields.requestNumber.toString() }) !== text) throw refuse('The request text is not in the agreed form.');
  return fields;
}
export function parseLiquidityAddText(text) {
  const [ethereumAddress, nodusAddress, usdt, nodus, transferId, chainId, number] = keyedValues(text, LIQUIDITY_ADD_TITLE, LIQUIDITY_ADD_KEYS);
  const fields = { ethereumAddress: matching(ethereumAddress, ETHEREUM_ADDRESS), nodusAddress: matching(nodusAddress, HEX128),
    usdtAmount: raw(usdt, USDT_AMOUNT, 6), nodusAmount: raw(nodus, NODUS_AMOUNT, 8), transferId: matching(transferId, HEX128),
    chainId: matching(chainId, HEX64), requestNumber: rawAmount(number, 'The request number') };
  if (liquidityAddText({ ...fields, requestNumber: fields.requestNumber.toString() }) !== text) throw refuse('The request text is not in the agreed form.');
  return fields;
}

// The bot is reached at an https origin the site names (givens item 97: "Adresi site her istekte söylesin."). Only
// scheme://host[:port] is accepted, so the extension, not the site, chooses the path (plan 6.4.7); no credentials,
// path, query or fragment. https only: the manifest's host permission covers https (manifest.json host_permissions).
export function botOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw refuse('The bot address is not a valid web address.'); }
  if (typeof value !== 'string' || url.protocol !== 'https:' || ![url.origin, `${url.origin}/`].includes(value)) {
    throw refuse('The bot address must be an https address without a path.');
  }
  return url.origin;
}
