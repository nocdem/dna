// Smart contracts (the Nodus EVM domain) — the Solidity ABI codec.
//
// The contract ABI specification of Solidity 0.8.30 (docs/abi-spec.rst:
// "Formal Specification of the Encoding", "Function Selector", "Events",
// "Errors"), with ONE Nodus difference, the one the Nodus solc makes
// (nodus/tools/evm/solc/README.md, "Semantic rules" 1, 2, 10): `address` is a
// full 32-byte word — encoded as the word itself, decoded with no mask and no
// rejection (every 256-bit word is a valid address). Selectors and event
// topics are computed from the same signatures as upstream (`f(address)`).
//
// Values (JS side):
//   address        "0x" + 64 hex (input: any form parseAddress accepts;
//                  output: checksummed, src/evm/address.js)
//   uint<M>/int<M> bigint (input also: a decimal string or a safe integer)
//   bool           boolean
//   bytes<M>/bytes "0x" + hex (input also: Uint8Array)
//   string         string (UTF-8)
//   T[k] / T[]     array
//   tuple          array in component order (input also: an object keyed by
//                  the component names)
// Decoding is strict: a word outside the type's range (dirty high bits of
// uint<M>, a bad sign extension of int<M>, a bool other than 0/1, non-zero
// padding of bytes<M>) and any offset or length outside the data REJECT.
//
// Decoding is BOUNDED (red-team 1 F10): what is decoded comes from a node
// (call output, revert data, receipt logs) or from a pasted ABI, and ABI
// offsets may alias — many heads can point at the same tail, so a small
// input can describe an enormous value. Each decode call has a budget of
// decoded values (ABI_MAX_ELEMENTS) and of bytes / string payload copied
// out (ABI_MAX_DECODED_BYTES), checked BEFORE anything is allocated; a type
// may nest at most ABI_MAX_DEPTH arrays / tuples, its static head size is
// computed once at parse time with checked arithmetic (ABI_MAX_HEAD), and a
// fixed-length array's heads must fit in the data before its elements are
// decoded. Over a bound = REJECT, never a partial value.
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, parseAddress, toChecksumAddress } from './address.js';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
const WORD = 32;

export const ABI_MAX_DEPTH = 32;                     // nested arrays / tuples in one type
export const ABI_MAX_TYPE_TEXT = 1024;               // characters of one type string
export const ABI_MAX_HEAD = 1 << 24;                 // static head bytes of one type
export const ABI_MAX_ELEMENTS = 100000;              // values decoded by one call
export const ABI_MAX_DECODED_BYTES = 4 * 1024 * 1024; // bytes / string payload decoded by one call

// ── types ──────────────────────────────────────────────────────────────

function fail(what) { throw new Error(`ABI: ${what}.`); }

// A parameter of an ABI JSON entry ({ type, components?, name? }) -> node.
// Every node carries `dynamic` and `head` (its head size in bytes),
// computed here once. (One argument only: it is used with Array#map.)
export function parseParam(param) { return parseNode(param, 0); }

function parseNode(param, depth) {
  if (!param || typeof param.type !== 'string') fail('a parameter has no type');
  if (param.type.length > ABI_MAX_TYPE_TEXT) fail('a type is too long');
  const m = /^([^[\]]*)((\[\d*\])*)$/.exec(param.type);
  if (!m) fail(`bad type ${param.type}`);
  const base = m[1];
  const dims = [...m[2].matchAll(/\[(\d*)\]/g)].map(d => (d[1] === '' ? null : Number(d[1])));
  if (depth + dims.length + (base === 'tuple' ? 1 : 0) > ABI_MAX_DEPTH) fail('a type is nested too deeply');
  let node;
  if (base === 'tuple') {
    if (!Array.isArray(param.components)) fail('a tuple has no components');
    const components = param.components.map(c => parseNode(c, depth + dims.length + 1));
    const dynamic = components.some(c => c.dynamic);
    let head = WORD;
    if (!dynamic) {
      head = 0;
      for (const c of components) { head += c.head; if (head > ABI_MAX_HEAD) fail('a type is too large'); }
    }
    node = { kind: 'tuple', components, names: param.components.map(c => c.name || ''), dynamic, head };
  } else {
    node = parseBase(base);
  }
  for (const n of dims) {
    if (n !== null && (!Number.isSafeInteger(n) || n < 1)) fail(`bad array length in ${param.type}`);
    const dynamic = n === null || node.dynamic;
    // checked: n × the element's head, never computed past ABI_MAX_HEAD
    if (!dynamic && node.head > 0 && n > Math.floor(ABI_MAX_HEAD / node.head)) fail('a type is too large');
    node = { kind: 'array', length: n, child: node, dynamic, head: dynamic ? WORD : n * node.head };
  }
  return node;
}

function parseBase(base) {
  const word = (kind, extra = {}) => ({ kind, ...extra, dynamic: false, head: WORD });
  if (base === 'address') return word('address');
  if (base === 'bool') return word('bool');
  if (base === 'string') return { kind: 'string', dynamic: true, head: WORD };
  if (base === 'bytes') return { kind: 'bytes', dynamic: true, head: WORD };
  let m;
  if ((m = /^(u?)int(\d*)$/.exec(base))) {
    const bits = m[2] === '' ? 256 : Number(m[2]);
    if (bits < 8 || bits > 256 || bits % 8) fail(`bad integer type ${base}`);
    return word(m[1] ? 'uint' : 'int', { bits });
  }
  if ((m = /^bytes(\d+)$/.exec(base))) {
    const size = Number(m[1]);
    if (size < 1 || size > 32) fail(`bad type ${base}`);
    return word('fixedbytes', { size });
  }
  if (base === 'function') fail('function-typed values are not supported on Nodus (32-byte addresses)');
  return fail(`unsupported type ${base}`);
}

// The canonical type text used in signatures.
export function typeString(node) {
  switch (node.kind) {
    case 'uint': case 'int': return `${node.kind}${node.bits}`;
    case 'fixedbytes': return `bytes${node.size}`;
    case 'array': return `${typeString(node.child)}[${node.length ?? ''}]`;
    case 'tuple': return `(${node.components.map(typeString).join(',')})`;
    default: return node.kind;
  }
}

// Both computed once by parseParam (bounded there).
const isDynamic = node => node.dynamic;
const headSize = node => node.head;

// ── encoding ───────────────────────────────────────────────────────────

function concat(parts) {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function wordOf(n) {
  const out = new Uint8Array(WORD);
  let v = n;
  for (let i = WORD - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function toBig(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === 'string' && /^-?(0|[1-9]\d*)$/.test(value.trim())) return BigInt(value.trim());
  if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value.trim())) return BigInt(value.trim());
  return fail(`not an integer: ${String(value)}`);
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(value)) return hexToBytes(value.slice(2));
  return fail('bytes must be 0x-prefixed hex');
}

function padRight(bytes) {
  const n = Math.ceil(bytes.length / WORD) * WORD;
  const out = new Uint8Array(n);
  out.set(bytes);
  return out;
}

function encodeOne(node, value) {
  switch (node.kind) {
    case 'address': {
      if (typeof value !== 'string') fail('an address must be text');
      return hexToBytes(parseAddress(value));
    }
    case 'bool':
      if (typeof value !== 'boolean') fail('a bool must be true or false');
      return wordOf(value ? 1n : 0n);
    case 'uint': {
      const v = toBig(value);
      if (v < 0n || v >= 2n ** BigInt(node.bits)) fail(`value out of range for uint${node.bits}`);
      return wordOf(v);
    }
    case 'int': {
      const v = toBig(value), half = 2n ** BigInt(node.bits - 1);
      if (v < -half || v >= half) fail(`value out of range for int${node.bits}`);
      return wordOf(v < 0n ? 2n ** 256n + v : v);
    }
    case 'fixedbytes': {
      const b = toBytes(value);
      if (b.length !== node.size) fail(`bytes${node.size} needs exactly ${node.size} bytes`);
      return padRight(b);
    }
    case 'bytes': {
      const b = toBytes(value);
      return concat([wordOf(BigInt(b.length)), padRight(b)]);
    }
    case 'string': {
      if (typeof value !== 'string') fail('a string must be text');
      const b = enc.encode(value);
      return concat([wordOf(BigInt(b.length)), padRight(b)]);
    }
    case 'array': {
      if (!Array.isArray(value)) fail('an array value must be an array');
      if (node.length !== null && value.length !== node.length) fail(`expected ${node.length} items`);
      const body = encodeSequence(value.map(() => node.child), value);
      return node.length === null ? concat([wordOf(BigInt(value.length)), body]) : body;
    }
    case 'tuple': {
      let values = value;
      if (!Array.isArray(values)) {
        if (!values || typeof values !== 'object') fail('a tuple value must be an array or an object');
        values = node.names.map(name => { if (!name || !(name in value)) fail('a tuple object needs every component name'); return value[name]; });
      }
      if (values.length !== node.components.length) fail(`expected ${node.components.length} tuple components`);
      return encodeSequence(node.components, values);
    }
    default: return fail('unsupported type');
  }
}

// The head/tail encoding of a sequence (the spec's enc((X1, ..., Xk))).
export function encodeSequence(nodes, values) {
  if (!Array.isArray(values) || values.length !== nodes.length) fail(`expected ${nodes.length} values`);
  const heads = [], tails = [];
  let tailOffset = nodes.reduce((s, n) => s + headSize(n), 0);
  nodes.forEach((node, i) => {
    const encoded = encodeOne(node, values[i]);
    if (isDynamic(node)) {
      heads.push(wordOf(BigInt(tailOffset)));
      tails.push(encoded);
      tailOffset += encoded.length;
    } else {
      heads.push(encoded);
    }
  });
  return concat([...heads, ...tails]);
}

// ── decoding ───────────────────────────────────────────────────────────

function readWord(data, at) {
  if (!Number.isSafeInteger(at) || at < 0 || at + WORD > data.length) fail('data too short');
  let v = 0n;
  for (let i = 0; i < WORD; i++) v = (v << 8n) | BigInt(data[at + i]);
  return v;
}

function readOffset(data, at) {
  const v = readWord(data, at);
  if (v > BigInt(data.length)) fail('offset outside the data');
  return Number(v);
}

// The budget of ONE decode call (see the header): values and bytes / string
// payload left. Charged before anything is allocated.
function newBudget() { return { elements: ABI_MAX_ELEMENTS, bytes: ABI_MAX_DECODED_BYTES }; }
function charge(budget, elements, bytes) {
  if (elements > budget.elements) fail('the data decodes to more values than allowed');
  if (bytes > budget.bytes) fail('the data decodes to more bytes than allowed');
  budget.elements -= elements;
  budget.bytes -= bytes;
}

function decodeOne(node, data, at, budget, depth) {
  if (depth > ABI_MAX_DEPTH) fail('the data is nested too deeply');
  charge(budget, 1, 0);
  switch (node.kind) {
    case 'address':
      readWord(data, at);                       // bounds; the whole word is the address
      return toChecksumAddress(bytesToHex(data.subarray(at, at + WORD)));
    case 'bool': {
      const v = readWord(data, at);
      if (v > 1n) fail('a bool word is not 0 or 1');
      return v === 1n;
    }
    case 'uint': {
      const v = readWord(data, at);
      if (v >= 2n ** BigInt(node.bits)) fail(`a uint${node.bits} word has high bits set`);
      return v;
    }
    case 'int': {
      const w = readWord(data, at), half = 2n ** BigInt(node.bits - 1);
      const v = w >= 2n ** 255n ? w - 2n ** 256n : w;
      if (v < -half || v >= half) fail(`an int${node.bits} word is not sign-extended`);
      return v;
    }
    case 'fixedbytes': {
      readWord(data, at);
      for (let i = node.size; i < WORD; i++) if (data[at + i] !== 0) fail(`bytes${node.size} padding is not zero`);
      return `0x${bytesToHex(data.subarray(at, at + node.size))}`;
    }
    case 'bytes': case 'string': {
      const len = readWord(data, at);
      if (len > BigInt(data.length - at - WORD)) fail('length outside the data');
      const n = Number(len);
      // aliased offsets can point many heads at one large tail: the payload
      // copied out counts against the call's byte budget
      charge(budget, 0, n);
      const raw = data.subarray(at + WORD, at + WORD + n);
      if (node.kind === 'bytes') return `0x${bytesToHex(raw)}`;
      try { return dec.decode(raw); } catch { return fail('a string is not valid UTF-8'); }
    }
    case 'array': {
      let count = node.length, base = at;
      if (count === null) {
        const len = readWord(data, at);
        base = at + WORD;
        if (len > BigInt(ABI_MAX_ELEMENTS)) fail('array length outside the data');
        count = Number(len);
      }
      // the heads of every element must fit in the data, and the count in
      // the budget, BEFORE anything is allocated for them
      const unit = isDynamic(node.child) ? WORD : headSize(node.child);
      if (base > data.length || (unit > 0 && count > Math.floor((data.length - base) / unit))) fail('array length outside the data');
      if (count > budget.elements) fail('the data decodes to more values than allowed');
      return decodeRepeated(node.child, count, data, base, budget, depth + 1);
    }
    case 'tuple':
      return decodeNodes(node.components, data, at, budget, depth + 1);
    default: return fail('unsupported type');
  }
}

// One element of a head/tail sequence at `head` (offsets relative to `base`).
function decodeAt(node, data, base, head, budget, depth) {
  if (isDynamic(node)) {
    const off = readOffset(data, head);
    if (base + off > data.length) fail('offset outside the data');
    return decodeOne(node, data, base + off, budget, depth);
  }
  return decodeOne(node, data, head, budget, depth);
}

function decodeNodes(nodes, data, base, budget, depth) {
  const out = [];
  let head = base;
  for (const node of nodes) {
    out.push(decodeAt(node, data, base, head, budget, depth));
    head += isDynamic(node) ? WORD : headSize(node);
  }
  return out;
}

// `count` elements of one type (an array's body).
function decodeRepeated(node, count, data, base, budget, depth) {
  const out = [];
  const step = isDynamic(node) ? WORD : headSize(node);
  for (let i = 0, head = base; i < count; i++, head += step) out.push(decodeAt(node, data, base, head, budget, depth));
  return out;
}

// Decode a head/tail sequence starting at `base` (offsets are relative to
// it), within ONE fresh budget.
export function decodeSequence(nodes, data, base = 0) {
  return decodeNodes(nodes, data, base, newBudget(), 0);
}

// ── selectors, entries ─────────────────────────────────────────────────

export const keccak = bytes => keccak_256(bytes);
export function selectorOf(signature) { return `0x${bytesToHex(keccak_256(enc.encode(signature)).subarray(0, 4))}`; }
export function topicOf(signature) { return `0x${bytesToHex(keccak_256(enc.encode(signature)))}`; }

function entrySignature(entry) {
  return `${entry.name}(${(entry.inputs || []).map(p => typeString(parseParam(p))).join(',')})`;
}

const PANIC_REASONS = {
  0x00n: 'generic compiler panic', 0x01n: 'assertion failed', 0x11n: 'arithmetic overflow or underflow',
  0x12n: 'division or modulo by zero', 0x21n: 'invalid enum value', 0x22n: 'invalid storage byte array',
  0x31n: 'pop on an empty array', 0x32n: 'array index out of bounds', 0x41n: 'out of memory',
  0x51n: 'call to an uninitialized internal function'
};

// A contract interface from its ABI JSON (array, or JSON text).
export class Interface {
  constructor(abi) {
    const list = typeof abi === 'string' ? JSON.parse(abi) : abi;
    if (!Array.isArray(list)) fail('the ABI must be a JSON array');
    this.functions = []; this.events = []; this.errors = []; this.constructorEntry = null;
    for (const entry of list) {
      if (!entry || typeof entry !== 'object') fail('an ABI entry is not an object');
      const type = entry.type || 'function';
      if (type === 'function') {
        const inputs = (entry.inputs || []).map(parseParam), outputs = (entry.outputs || []).map(parseParam);
        const signature = entrySignature(entry);
        const mutability = entry.stateMutability || (entry.constant ? 'view' : 'nonpayable');
        this.functions.push({ name: entry.name, signature, selector: selectorOf(signature), inputs, outputs, inputNames: (entry.inputs || []).map(p => p.name || ''), outputNames: (entry.outputs || []).map(p => p.name || ''), mutability, readOnly: mutability === 'view' || mutability === 'pure', payable: mutability === 'payable' });
      } else if (type === 'event') {
        const signature = entrySignature(entry);
        this.events.push({ name: entry.name, signature, topic: topicOf(signature), anonymous: !!entry.anonymous, inputs: (entry.inputs || []).map(p => ({ node: parseParam(p), name: p.name || '', indexed: !!p.indexed })) });
      } else if (type === 'error') {
        const signature = entrySignature(entry);
        this.errors.push({ name: entry.name, signature, selector: selectorOf(signature), inputs: (entry.inputs || []).map(parseParam), inputNames: (entry.inputs || []).map(p => p.name || '') });
      } else if (type === 'constructor') {
        const mutability = entry.stateMutability || 'nonpayable';
        this.constructorEntry = { inputs: (entry.inputs || []).map(parseParam), inputNames: (entry.inputs || []).map(p => p.name || ''), payable: mutability === 'payable' };
      }
    }
  }

  // By name (must be unique), by full signature "name(type,...)", or one of
  // this interface's own function entries.
  getFunction(key) {
    if (key && typeof key === 'object' && this.functions.includes(key)) return key;
    if (typeof key !== 'string') fail('a function is named by its name or signature');
    const found = key.includes('(') ? this.functions.filter(f => f.signature === key) : this.functions.filter(f => f.name === key);
    if (found.length === 0) fail(`no function ${key}`);
    if (found.length > 1) fail(`${key} is overloaded; use its full signature`);
    return found[0];
  }

  encodeFunctionData(key, args = []) {
    const fn = this.getFunction(key);
    return concat([hexToBytes(fn.selector.slice(2)), encodeSequence(fn.inputs, args)]);
  }

  decodeFunctionData(key, data) {
    const fn = this.getFunction(key);
    const bytes = toBytes(data);
    if (bytes.length < 4 || `0x${bytesToHex(bytes.subarray(0, 4))}` !== fn.selector) fail('the data is not a call of this function');
    return decodeSequence(fn.inputs, bytes.subarray(4));
  }

  decodeFunctionResult(key, data) {
    const fn = this.getFunction(key);
    return decodeSequence(fn.outputs, toBytes(data));
  }

  // initcode = bytecode ‖ abi.encode(constructor arguments)
  encodeDeploy(bytecode, args = []) {
    const code = toBytes(bytecode);
    if (code.length === 0) fail('the bytecode is empty');
    const inputs = this.constructorEntry ? this.constructorEntry.inputs : [];
    return concat([code, encodeSequence(inputs, args)]);
  }

  // Topics for a log filter: [topic0, ...indexed values]; `null` = any.
  // Indexed string / bytes are matched by their keccak256 (spec "Events");
  // indexed arrays and tuples are not supported here.
  encodeEventTopics(key, values = []) {
    const ev = key.includes('(') ? this.events.find(e => e.signature === key) : this.events.find(e => e.name === key);
    if (!ev) fail(`no event ${key}`);
    const indexed = ev.inputs.filter(p => p.indexed);
    if (values.length > indexed.length) fail('too many indexed values');
    const topics = ev.anonymous ? [] : [ev.topic];
    values.forEach((value, i) => {
      if (value === null || value === undefined) { topics.push(null); return; }
      const node = indexed[i].node;
      if (node.kind === 'string') topics.push(`0x${bytesToHex(keccak_256(enc.encode(value)))}`);
      else if (node.kind === 'bytes') topics.push(`0x${bytesToHex(keccak_256(toBytes(value)))}`);
      else if (isDynamic(node) || node.kind === 'array' || node.kind === 'tuple') fail('indexed arrays and tuples cannot be filtered here');
      else topics.push(`0x${bytesToHex(encodeOne(node, value))}`);
    });
    return topics;
  }

  // A log { topics: ["0x"+64 hex], data } -> { name, signature, args:
  // [{ name, value }] } or null when no event of this ABI matches. An
  // indexed dynamic value is returned as { hash } (only its keccak256 is in
  // the log).
  parseLog(log) {
    const topics = (log.topics || []).map(t => String(t).toLowerCase());
    const data = toBytes(log.data || '0x');
    for (const ev of this.events) {
      if (ev.anonymous || topics[0] !== ev.topic) continue;
      const indexed = ev.inputs.filter(p => p.indexed);
      if (topics.length !== 1 + indexed.length) continue;
      const plain = ev.inputs.filter(p => !p.indexed);
      let values;
      try { values = decodeSequence(plain.map(p => p.node), data); } catch { continue; }
      let ti = 1, vi = 0;
      const args = ev.inputs.map(p => {
        if (!p.indexed) return { name: p.name, value: values[vi++] };
        const t = topics[ti++];
        if (isDynamic(p.node) || p.node.kind === 'array' || p.node.kind === 'tuple') return { name: p.name, value: { hash: t } };
        return { name: p.name, value: decodeOne(p.node, hexToBytes(t.slice(2)), 0, newBudget(), 0) };
      });
      return { name: ev.name, signature: ev.signature, args };
    }
    return null;
  }

  // Revert data -> { kind: 'error', message } (Error(string)), { kind:
  // 'panic', code, message } (Panic(uint256)), { kind: 'custom', name,
  // args } (an error of this ABI), { kind: 'empty' } or { kind: 'unknown',
  // data }.
  decodeRevert(data) { return decodeRevert(data, this); }
}

const STRING_NODE = parseParam({ type: 'string' }), UINT256_NODE = parseParam({ type: 'uint256' });
export function decodeRevert(data, iface = null) {
  const bytes = toBytes(data);
  if (bytes.length === 0) return { kind: 'empty' };
  const sel = bytes.length >= 4 ? `0x${bytesToHex(bytes.subarray(0, 4))}` : '';
  try {
    if (sel === '0x08c379a0') return { kind: 'error', message: decodeSequence([STRING_NODE], bytes.subarray(4))[0] };
    if (sel === '0x4e487b71') {
      const code = decodeSequence([UINT256_NODE], bytes.subarray(4))[0];
      return { kind: 'panic', code, message: PANIC_REASONS[code] || 'panic' };
    }
    const custom = iface?.errors.find(e => e.selector === sel);
    if (custom) {
      const values = decodeSequence(custom.inputs, bytes.subarray(4));
      return { kind: 'custom', name: custom.name, args: custom.inputNames.map((name, i) => ({ name, value: values[i] })) };
    }
  } catch { /* malformed: reported as unknown below */ }
  return { kind: 'unknown', data: `0x${bytesToHex(bytes)}` };
}
