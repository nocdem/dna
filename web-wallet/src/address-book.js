// Address book — saved recipients for sending, one entry per (network,
// address): { id, label, network, address }. Pure: no DOM, no storage, no
// network; test/address-book.test.js pins it under node --test.
//
// Where it comes from: the DNA Connect app's wallet address book
// (messenger/src/api/engine/dna_engine_addressbook.c: address, label,
// network, notes; filtered by network; screens/wallet/address_dialog.dart:
// the network is fixed when the entry is made from a send). Operator
// 2026-10-03: for EVERY network the wallet sends on (EVM, Solana, TRON, …,
// NODUS); the send form of a network offers only that network's entries and
// checks the address with that network's own address check.
//
// The address checks are handed in (`validators`: network id -> function
// that returns the address in its saved form or throws a plain-words error)
// by src/app.js, which owns the adapters — this file imports none of them
// (the TRON adapter alone pulls in TronWeb).
//
// Storage: src/activity-storage.js serializeAddressBook / parseAddressBook,
// only with a saved wallet (decision 2026-10-02-device-cache-only-when-
// saved); an unsaved wallet keeps the list in memory for the session.
import { inspectUntrusted } from './connect/ui/text.js';

export const ADDRESS_BOOK_MAX = 200;      // entries
export const ADDRESS_LABEL_MAX = 48;      // characters, as a vault name (src/vaults/core.js VAULT_LABEL_MAX)
export const ADDRESS_MAX = 128;           // characters: the longest address the wallet sends to (NODUS, 128 hex)
const ID = /^a[1-9]\d{0,8}$/;
const NETWORK = /^[a-z0-9]{1,24}$/;
// An address of a network this build has no check for (a build without a
// network an entry was saved under): printable ASCII without spaces only.
const PLAIN_ADDRESS = /^[\x21-\x7e]{1,128}$/;

// The name a person typed for a saved address — the vault-name rule
// (src/vaults/core.js vaultLabel): trimmed, no control characters or line
// separators, at most ADDRESS_LABEL_MAX characters, and no invisible or
// direction-changing characters and no mixed alphabets (connect/ui/text.js
// inspectUntrusted, the rule Messages applies to names). Required.
export function addressLabel(value) {
  if (typeof value !== 'string') throw new Error('Enter a name for this address.');
  const label = value.trim();
  const control = c => { const p = c.codePointAt(0); return p < 0x20 || (p >= 0x7f && p <= 0x9f) || p === 0x2028 || p === 0x2029; };
  if (!label) throw new Error('Enter a name for this address.');
  if ([...label].length > ADDRESS_LABEL_MAX || [...value].some(control)) throw new Error(`A name can have at most ${ADDRESS_LABEL_MAX} characters, without line breaks.`);
  if (inspectUntrusted(value, { name: true }).unusual) throw new Error('A name cannot contain invisible or direction-changing characters, or mix alphabets.');
  return label;
}

// The address in its saved form, by that network's own check.
export function checkAddress(network, value, validators) {
  const check = validators?.[network];
  if (typeof check !== 'function') throw new Error('Addresses of this network cannot be saved here.');
  const typed = typeof value === 'string' ? value.trim() : '';
  if (!typed) throw new Error('Enter the address.');
  const address = check(typed);
  if (typeof address !== 'string' || !address || address.length > ADDRESS_MAX) throw new Error('This address cannot be saved.');
  return address;
}

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
// Shown by name (letter case ignored), then network, then address; the
// same list always gives the same order.
export function sortAddressBook(list) {
  return [...list].sort((a, b) => compare(a.label.toLowerCase(), b.label.toLowerCase()) || compare(a.label, b.label) || compare(a.network, b.network) || compare(a.address, b.address));
}

function nextId(list) {
  let max = 0;
  for (const e of list) max = Math.max(max, Number(e.id.slice(1)));
  return `a${max + 1}`;
}

export function findAddress(list, network, address) {
  return list.find(e => e.network === network && e.address === address);
}

// A new entry; the same address on the same network is saved once.
// @return the new list (the old one is not changed).
export function addAddress(list, { label, network, address }, validators) {
  if (list.length >= ADDRESS_BOOK_MAX) throw new Error(`The address book is full (${ADDRESS_BOOK_MAX} addresses). Delete one first.`);
  const entry = { id: nextId(list), label: addressLabel(label), network, address: checkAddress(network, address, validators) };
  const same = findAddress(list, entry.network, entry.address);
  if (same) throw new Error(`This address is already saved as “${same.label}”.`);
  return sortAddressBook([...list, entry]);
}

// A changed entry (name, network or address). @return the new list.
export function updateAddress(list, id, { label, network, address }, validators) {
  const index = list.findIndex(e => e.id === id);
  if (index < 0) throw new Error('This address is no longer in the address book.');
  const entry = { id, label: addressLabel(label), network, address: checkAddress(network, address, validators) };
  const same = list.find(e => e.id !== id && e.network === entry.network && e.address === entry.address);
  if (same) throw new Error(`This address is already saved as “${same.label}”.`);
  const next = [...list];
  next[index] = entry;
  return sortAddressBook(next);
}

export function removeAddress(list, id) { return list.filter(e => e.id !== id); }

// The entries of one network, in the shown order.
export function addressesFor(list, network) { return sortAddressBook(list.filter(e => e.network === network)); }

// A list read back from storage: every entry checked again (the address by
// its network's check where this build has one; otherwise kept as saved, but
// only if it is plain printable text — such an entry is never offered in a
// send form of this build, see src/app.js). Ids and (network, address) pairs
// unique. Anything else throws.
export function checkAddressBook(value, validators) {
  const invalid = () => new Error('Invalid saved address book.');
  if (!Array.isArray(value) || value.length > ADDRESS_BOOK_MAX) throw invalid();
  const ids = new Set(), pairs = new Set(), out = [];
  for (const e of value) {
    if (!e || typeof e !== 'object' || Object.keys(e).sort().join() !== 'address,id,label,network' ||
        typeof e.id !== 'string' || !ID.test(e.id) || typeof e.network !== 'string' || !NETWORK.test(e.network) ||
        typeof e.address !== 'string') throw invalid();
    let label, address;
    try {
      label = addressLabel(e.label);
      address = typeof validators?.[e.network] === 'function' ? checkAddress(e.network, e.address, validators) : e.address;
    } catch { throw invalid(); }
    if (label !== e.label || address !== e.address || !PLAIN_ADDRESS.test(address)) throw invalid();
    const pair = `${e.network}\n${address}`;
    if (ids.has(e.id) || pairs.has(pair)) throw invalid();
    ids.add(e.id); pairs.add(pair);
    out.push({ id: e.id, label, network: e.network, address });
  }
  return sortAddressBook(out);
}
