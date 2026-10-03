// Nodus Connect — the chain names (HF-4) kept on this device, pure rules.
// No DOM, no network, no storage: test/connect-ui.test.js pins them.
//
// Governing records:
//   docs/plans/decisions/2026-10-02-onchain-names.md — item 4: a name is
//     permanent (no expiry, no renewal); a name is shown only when the
//     reverse lookup (dnac_name_of) confirmed it for that ID.
//   docs/plans/decisions/2026-10-02-device-cache-only-when-saved.md — kept on
//     the device only for a saved wallet, inside its encrypted Messages
//     history (src/connect/store.js state.chainNames); an unsaved wallet
//     keeps the same state in memory only.
//
// What is kept: state.chainNames[fp] = { name, at } — a name the lookup
// found for that ID at `at` (unix seconds). Because a name is permanent, a
// kept name does not expire: a contact's kept name is shown at once and not
// asked again; this wallet's OWN kept name is shown at once and asked again
// once per session (a confirmed "no name" or another name replaces it). A
// contact without a known name is asked again when its conversation is
// opened; a failed lookup is tried again on a later round; no ID is asked
// twice within CHAIN_LOOKUP_SPACING_MS.
import { chainNameOk } from '../../nodus/names.js';

// The kept name of an entry, or '' (anything malformed counts as none).
export function keptChainName(entry) {
  return entry && typeof entry === 'object' && chainNameOk(entry.name) ? entry.name : '';
}

// The least time between two lookups of the same ID (milliseconds), whatever
// asks (the sync round or opening a conversation) and whatever the outcome:
// a node that fails is not asked again for that ID before it has passed.
// Held in memory only (messages.js chainTried) — never in a kept state.
export const CHAIN_LOOKUP_SPACING_MS = 60000;

// Whether the spacing since the last lookup of an ID has passed.
//   lastTry  the page clock (ms) when that ID was last looked up, or
//            undefined (not looked up this session)
//   now      the page clock (ms) now
// A clock that went back (now < lastTry) does not block the ID for good.
export function chainLookupSpaced(lastTry, now) {
  if (typeof lastTry !== 'number' || !Number.isFinite(lastTry)) return true;
  if (typeof now !== 'number' || !Number.isFinite(now)) return false;
  return now < lastTry || now - lastTry >= CHAIN_LOOKUP_SPACING_MS;
}

// Whether `fp` is looked up now. asked: answered this session (a confirmed
// name or a confirmed "no name"; a failed lookup does not count); known: a
// name is known (kept or found this session); recheck: this wallet's own ID
// (asked once per session even when a name is kept); opened: the user just
// opened the conversation with this contact — an ID without a known name is
// asked again then even if it was answered "no name" earlier this session
// (the contact may have registered a name since). lastTry / now: the
// spacing (chainLookupSpaced); both left out = no spacing applies.
export function chainLookupNeeded({ asked, known, recheck, opened, lastTry, now }) {
  if (!chainLookupSpaced(lastTry, now)) return false;
  if (opened === true) return !known;
  return !asked && (recheck === true || !known);
}

// A confirmed lookup answer (src/nodus/names.js parseNameOf: { found, name })
// against the kept entry `before` (or undefined).
//   keep  the ID's name may be kept (this wallet or a contact)
//   now   unix seconds as a decimal string
// @return { name, entry, changed }: name = what is shown ('' = no name);
// entry = the entry to keep (null = none); changed = the kept state moved
// (the caller saves once).
export function chainNameAfterLookup(before, found, { keep, now }) {
  const kept = keptChainName(before) ? before : null;
  // Not an answer (src/nodus/names.js parseNameOf throws first): nothing moves.
  if (!found || (found.found !== true && found.found !== false) || (found.found === true && !chainNameOk(found.name))) return { name: kept ? kept.name : '', entry: kept, changed: false };
  if (found.found === true) {
    if (!keep) return { name: found.name, entry: kept, changed: false };
    if (kept && kept.name === found.name) return { name: found.name, entry: kept, changed: false };
    return { name: found.name, entry: { name: found.name, at: now }, changed: true };
  }
  return { name: '', entry: null, changed: before !== undefined };
}

// The own name the Nodus Connect page shows (Home header, identity lines,
// More): the wallet's own confirmed lookup answer when it has one
// (walletAnswer = { name }, '' = confirmed none), else the name Messages
// knows (kept on this device, or found this session), else ''.
export function shownOwnName(walletAnswer, messagesName) {
  if (walletAnswer && typeof walletAnswer.name === 'string') return chainNameOk(walletAnswer.name) ? walletAnswer.name : '';
  return chainNameOk(messagesName) ? messagesName : '';
}

// The More menu's entry for "Your ID & profile".
export const PROFILE_ENTRY_TEXT = 'Your ID & profile';
export function profileEntryText(name) {
  return chainNameOk(name) ? `${name} — ID & profile` : PROFILE_ENTRY_TEXT;
}
