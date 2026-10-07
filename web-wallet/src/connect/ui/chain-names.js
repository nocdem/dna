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
// Since web 0.1.74 a CONTACT's answered "no name" is kept too, in
// state.chainNoName[fp] = at (the same state record, the same
// saved-wallet-only rule; src/connect/store.js says why it is not a ''
// name in chainNames), so the sync round does not ask that contact again
// in every session: not before CHAIN_NO_NAME_RECHECK_SECONDS have passed
// (chainNoNameFresh).
// Only an ANSWER is kept — never a failed lookup — and never for this
// wallet's own ID (asked once per session as before). Opening the
// conversation still asks at once (chainLookupNeeded `opened`).
//
// One exception to "no network": resolveContactName (end of this file), the
// add-contact-by-name lookup, which calls the client it is handed.
import { chainNameOk } from '../../nodus/names.js';
import { resolveChainName, NAME_CHECK_ROW } from '../../adapters/nodus.js';

const U64 = /^(0|[1-9]\d{0,19})$/;

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

// How long a contact's answered "no name" stands before the sync round asks
// again (seconds): one day. A contact who registers a name later shows it
// within a day without anything being done; the user sees it at once by
// opening the conversation (recheckChainNameOnOpen asks then, whatever is
// kept). Before web 0.1.74 every session asked every contact without a
// name (one lookup of 1-2 s each, one after another, before the message
// check: 17.9 s for 17 contacts on the operator's phone, 2026-10-07).
export const CHAIN_NO_NAME_RECHECK_SECONDS = 86400;

// Whether a kept "no name" answer (state.chainNoName[fp]: unix seconds of
// the answer, decimal string, or undefined) is younger than
// CHAIN_NO_NAME_RECHECK_SECONDS at `now` (unix seconds, decimal string).
// Anything malformed is not kept. A clock that went back (now < at) does
// not keep the answer: it is asked again, as chainLookupSpaced does not
// block an ID for good.
export function chainNoNameFresh(at, now) {
  if (!U64.test(String(at)) || !U64.test(String(now))) return false;
  const a = BigInt(String(at)), t = BigInt(String(now));
  return t >= a && t - a < BigInt(CHAIN_NO_NAME_RECHECK_SECONDS);
}

// What a confirmed lookup answer does to a contact's kept "no name"
// (state.chainNoName[fp], `before` = its value or undefined):
//   keep  the answer may be kept: a CONTACT (never the own ID, never a
//         stranger — the found-name rule, chainNameAfterLookup, keeps a
//         name of either; a "no name" is kept for contacts only)
//   now   unix seconds as a decimal string
// @return { at, changed }: at = the value to keep (null = none); changed =
// the kept state moved (the caller saves once). Not an answer: nothing
// moves. A found name: the "no name" goes. An answered "no name": kept
// with this answer's time (keep), else removed. A failed lookup never
// reaches here (src/nodus/names.js parseNameOf throws first).
export function chainNoNameAfterLookup(before, found, { keep, now }) {
  const kept = U64.test(String(before)) ? String(before) : null;
  if (!found || (found.found !== true && found.found !== false) || (found.found === true && !chainNameOk(found.name))) return { at: kept, changed: false };
  if (found.found === false && keep && U64.test(String(now))) return { at: String(now), changed: kept !== String(now) };
  return { at: null, changed: before !== undefined };
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

// ── Adding a contact by chain name ──────────────────────────────────────
// The one function here that reaches the network — only through the client
// it is handed. `name` (already a valid name, text.js parseContactInput) ->
// its owner's Nodus ID, resolved by the wallet's own NODUS-send lookup
// (src/adapters/nodus.js resolveChainName: the module's nameLookup, ONE
// node's committed state — decision 2026-10-02-onchain-names.md item 9,
// accepted risk). The owner ID is the contact ID (the reverse lookup,
// nameOf, reads names by the same ID). Every failure is a plain-words error
// and never falls back to anything else:
//   - no ready client with names: the network is not ready;
//   - the lookup answered "nobody holds it": not registered;
//   - anything else (rejected call, malformed answer): the lookup failed.
export const NAME_NOT_READY_TEXT = 'Adding a contact by chain name needs the network connection, which is not ready yet. Try again once Messages is connected, or use their ID.';
export const NAME_UNREGISTERED_TEXT = 'No one has registered that name.';
export const NAME_LOOKUP_FAILED_TEXT = 'The name could not be looked up right now. Try again in a minute, or use their ID.';
// The wallet's caution (src/adapters/nodus.js NAME_CHECK_ROW), shown under
// a resolved name before the request may be sent.
export const NAME_CHECK_TEXT = NAME_CHECK_ROW[1];
export async function resolveContactName(client, name) {
  if (!client || client.state !== 'ready' || !client.nameable) throw new Error(NAME_NOT_READY_TEXT);
  let found;
  try { found = await resolveChainName(client, name); }
  catch (error) {
    // resolveChainName's own words for "nobody holds it" (the NODUS send's
    // error, test/hf4-client.test.js); test/connect-ui.test.js pins the
    // mapping against the real function.
    if (/^No one has registered the chain name /.test(error?.message || '')) throw new Error(NAME_UNREGISTERED_TEXT);
    throw new Error(NAME_LOOKUP_FAILED_TEXT);
  }
  return { name, owner: found.owner, committedHeight: found.committedHeight };
}
