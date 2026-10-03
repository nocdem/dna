// Nodus Connect — the per-contact "Details" line of a conversation: what the
// last message check of that contact returned, step by step, so a check
// that shows nothing can be read on a phone without a developer console.
//
// MEMORY ONLY. A diagnostics record lives in the page's session state
// (messages.js `diags`, cleared by wipe()) and is never written to the
// encrypted history store (src/connect/store.js, decision
// docs/plans/decisions/2026-09-30-connect-history-at-rest.md).
//
// NO SECRETS. A record holds counts, day numbers and the core's fixed status
// words — never a salt (only whether it changed), a key, a blob hash, a
// ciphertext or message text. An error message is bounded and every long
// hex run in it is cut out (errorText) before it is kept.

const U64 = /^(0|[1-9]\d{0,19})$/;
const WORD = /^[a-z_]{1,32}$/;            // nc_read.c nc_outcome_str / nc_why_str, core status words
const ERROR_MAX = 120;                    // characters of an error message kept

const word = value => (typeof value === 'string' && WORD.test(value) ? value : 'unknown');
const count = value => (U64.test(String(value)) ? Number(String(value)) : 0);

// A new record for a check started at `atMs` (Date.now()).
export function newDiag(atMs) {
  // noSalt: this device holds no salt for the contact after the salt step,
  // so no message could be read.
  return { at: Number(atMs) || 0, profile: null, salt: null, noSalt: false, days: [], error: '' };
}

// The salt step: `result` of core.saltReconcile, `changed` true when it gave
// a salt different from the one this device held. `earlier`: the salt was
// already reconciled this session (no read this check).
export function diagSalt({ result, changed = false, earlier = false } = {}) {
  if (earlier) return { status: 'earlier' };
  return { status: word(result?.status), outcome: word(result?.outcome), why: word(result?.why), changed: changed === true };
}

// One day bucket: `result` of core.outboxFetchDay.
export function diagDay(day, result) {
  return {
    day: U64.test(String(day)) ? String(day) : '?',
    outcome: word(result?.outcome),
    why: word(result?.why),
    count: Array.isArray(result?.messages) ? result.messages.length : 0,
    dropped: count(result?.dropped),
    other: count(result?.other),
    unchanged: result?.unchanged === true
  };
}

// The message of an exception, safe to show: control characters removed,
// any run of 16 or more hex characters cut out (a salt, key or ciphertext
// can never pass), at most ERROR_MAX characters. A SyntaxError (an answer
// that could not be parsed) can quote its input, so only its kind is kept.
export function errorText(error) {
  if (error instanceof SyntaxError) return 'the answer could not be read';
  const raw = error instanceof Error ? error.message : String(error ?? '');
  const text = raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/[0-9a-fA-F]{16,}/g, '…').replace(/\s+/g, ' ').trim();
  if (!text) return 'unknown error';
  return text.length > ERROR_MAX ? `${text.slice(0, ERROR_MAX - 1)}…` : text;
}

function saltText(salt) {
  if (!salt) return '';
  if (salt.status === 'earlier') return 'salt ok';
  if (salt.status === 'nothing_to_write' || salt.status === 'published') return `salt ok${salt.changed ? ' (changed)' : ''}`;
  const why = salt.why && salt.why !== 'none' ? `, ${salt.why}` : '';
  return `salt ${salt.status} (${salt.outcome}${why})${salt.changed ? ' (changed)' : ''}`;
}

function dayText(d) {
  const why = d.why && d.why !== 'none' ? ` (${d.why})` : '';
  if (d.unchanged) return `day ${d.day}: ${d.outcome}${why}, unchanged`;
  return `day ${d.day}: ${d.outcome}${why}, ${d.count} read, ${d.dropped} not checked, ${d.other} other`;
}

// The Details text of one record, '' when there is none. `clock` turns the
// record's time into the shown label (the caller's locale). Days that were
// empty with nothing to report are folded into one count, so an 8-day
// check stays short.
export function diagText(diag, clock = ms => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) {
  if (!diag) return '';
  const parts = [`Last check ${clock(diag.at)}`];
  if (diag.profile) parts.push(diag.profile === 'ok' ? 'profile ok' : 'profile could not be read');
  const salt = saltText(diag.salt);
  if (salt) parts.push(salt);
  if (diag.noSalt) parts.push('no salt yet, messages not read');
  let quiet = 0;
  for (const d of diag.days) {
    if (d.outcome === 'empty' && d.why === 'none' && !d.count && !d.dropped && !d.other) { quiet++; continue; }
    parts.push(dayText(d));
  }
  if (quiet) parts.push(`${quiet} empty day${quiet === 1 ? '' : 's'}`);
  const line = parts.join(' · ');
  return diag.error ? `${line}\nLast check failed: ${diag.error}` : line;
}
