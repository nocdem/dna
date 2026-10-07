// SESSION LOG (operator 2026-10-07: "sometimes Connect stays in
// 'connecting'" — and then: "not only for this — logs in general"). One
// page-wide, in-memory list of what this session did and what it showed:
// the connection steps of the NODUS client with their durations and the
// retries (src/nodus/client.js `steps`, src/app.js RECONNECT), the status
// texts the wallet showed (src/app.js message), Messages' failures
// (src/connect/ui/messages.js explain / closeMessages), the vault and
// smart-contract panels' status lines, and uncaught page errors.
//
// MEMORY ONLY: a ring of the last SESSION_LOG_MAX lines, cleared when the
// wallet locks (src/app.js lock — which `pagehide` also runs) and gone with
// the page. Never written to storage, never sent anywhere: the user copies
// or downloads it (Device & settings → Logs) and sends it themselves.
//
// NO SECRETS. Callers never pass seeds, keys, recovery words, passwords or
// message texts; and every line is scrubbed here as well (scrubLogText):
// control characters out, any run of 16+ hex characters (an ID, a key, a
// hash, an EVM address) and any run of 25+ letters/digits (a base58
// address) cut to "…", anything in double quotes (a chain name, a contact
// label) cut to "…", amounts (a decimal number, or a number before an
// upper-case symbol such as "1 NODUS") replaced by "#", at most
// LOG_TEXT_MAX characters. A short ID prefix (≤ 15 hex) passes.
//
// The log never decides anything: it only records. A failing log call is
// swallowed and never changes what its caller does.

export const SESSION_LOG_MAX = 500;
export const LOG_TEXT_MAX = 300;
// The fixed categories (anything else is logged as 'wallet').
export const LOG_CATEGORIES = Object.freeze(['net', 'messages', 'wallet', 'send', 'stake', 'names', 'evm', 'vault', 'ui-error']);
// The Logs view's filters -> which lines they show.
const WALLET_CATEGORIES = new Set(['wallet', 'send', 'stake', 'names', 'evm', 'vault']);
export const LOG_FILTERS = Object.freeze({
  all: () => true,
  network: line => line.category === 'net',
  messages: line => line.category === 'messages',
  wallet: line => WALLET_CATEGORIES.has(line.category),
  errors: line => line.error || line.category === 'ui-error'
});

export function scrubLogText(value) {
  const raw = value instanceof Error ? value.message : typeof value === 'string' ? value : String(value ?? '');
  const text = raw
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/"[^"]{0,200}"|“[^”]{0,200}”/g, '"…"')
    .replace(/(?:0x)?[0-9a-fA-F]{16,}/g, '…')
    .replace(/[A-Za-z0-9]{25,}/g, '…')
    .replace(/\d[\d,]*(?:\.\d+)?(\s*)(?=[A-Z][A-Z0-9]{1,9}\b)/g, '#$1')
    .replace(/\d+\.\d+/g, '#')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length > LOG_TEXT_MAX ? `${text.slice(0, LOG_TEXT_MAX - 1)}…` : text;
}

const pad = (n, width = 2) => String(n).padStart(width, '0');
// Local time of day, "18:02:11".
export function clockText(ms) { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
// Local date and time, "2026-10-07 18:02:11".
export function dateTimeText(ms) { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${clockText(ms)}`; }
// "5012" -> "5 012" (no locale: the same text on every device).
export const groupedMs = ms => String(Math.max(0, Math.round(ms))).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
// The download's file name: nodus-<page>-log-YYYYMMDD-HHMM.txt (local time).
export function logFileName(page, ms) {
  const d = new Date(ms);
  return `nodus-${page === 'connect' ? 'connect' : 'wallet'}-log-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}.txt`;
}

export function createSessionLog({ now = () => Date.now(), max = SESSION_LOG_MAX } = {}) {
  let lines = [], startedAt = now(), steps = new Set();
  const listeners = new Set();
  const changed = () => { for (const fn of listeners) { try { fn(); } catch { /* a view never breaks the log */ } } };
  function log(category, text, { error = false } = {}) {
    try {
      const shown = scrubLogText(text);
      if (!shown) return;
      lines.push({ at: now(), category: LOG_CATEGORIES.includes(category) ? category : 'wallet', error: error === true, text: shown });
      if (lines.length > max) lines.splice(0, lines.length - max);
      changed();
    } catch { /* the log never changes what its caller does */ }
  }
  // A step that takes time (a connection step): begin() now, end() once —
  // a second end() (a late result of an abandoned step) is ignored. While
  // it runs, the view shows it (runningLines), "stuck" past `boundMs`.
  // `label`: the line's prefix, e.g. "attempt 2".
  function begin(category, name, { label = '', boundMs = 0 } = {}) {
    const step = { category, name: scrubLogText(name), label: scrubLogText(label), boundMs, startedAt: now() };
    steps.add(step);
    changed();
    return {
      end(outcome, error) {
        if (!steps.delete(step)) return;
        const ms = groupedMs(now() - step.startedAt);
        const why = error ? ` (${scrubLogText(error) || 'unknown error'})` : '';
        const ok = outcome === 'ok';
        const what = outcome === 'timed out' ? `timed out after ${ms} ms` : `${ms} ms ${ok ? 'ok' : 'failed'}`;
        log(category, `${step.label ? `${step.label} · ` : ''}${step.name} ${what}${ok ? '' : why}`, { error: !ok });
      }
    };
  }
  // The steps still running, one line each; a step past its bound is
  // "stuck" (and counts as an error for the Errors filter).
  function runningLines(filter = 'all', clock = clockText) {
    const keep = LOG_FILTERS[filter] || LOG_FILTERS.all, at = now();
    const out = [];
    for (const step of steps) {
      const stuck = step.boundMs > 0 && at - step.startedAt > step.boundMs;
      if (!keep({ category: step.category, error: stuck })) continue;
      out.push(`${clock(step.startedAt)} [${step.category}] ${step.label ? `${step.label} · ` : ''}${step.name} running ${Math.floor((at - step.startedAt) / 1000)} s${stuck ? ' — stuck' : ''}`);
    }
    return out;
  }
  function entries(filter = 'all') {
    const keep = LOG_FILTERS[filter] || LOG_FILTERS.all;
    return lines.filter(keep).map(line => ({ ...line }));
  }
  // The shown text: one line per entry ("18:02:11 [net] …", "!" marks a
  // failure), then the steps still running.
  function text(filter = 'all', clock = clockText) {
    return [...entries(filter).map(line => `${clock(line.at)} [${line.category}]${line.error ? ' !' : ''} ${line.text}`), ...runningLines(filter, clock)].join('\n');
  }
  // The copied / downloaded text: a header (app version, page, browser,
  // session start), then every line (all categories).
  function exportText({ version = 'unknown', page = 'wallet', userAgent = '' } = {}) {
    const agent = String(userAgent).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, 300);
    const header = [
      `${page === 'connect' ? 'Nodus Connect' : 'Nodus Wallet'} session log`,
      `Version: ${String(version).slice(0, 40)}`,
      `Page: ${page === 'connect' ? 'connect' : 'wallet'}`,
      `Browser: ${agent || 'unknown'}`,
      `Session start: ${dateTimeText(startedAt)} (local time)`,
      `Exported: ${dateTimeText(now())} (local time)`,
      'Only this session. Nothing is sent automatically.',
      ''
    ];
    const body = text('all', dateTimeText);
    return `${header.join('\n')}${body || '(no entries)'}\n`;
  }
  function clear() { lines = []; steps = new Set(); startedAt = now(); changed(); }
  function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
  return { log, begin, entries, text, runningLines, exportText, clear, subscribe, get startedAt() { return startedAt; }, get size() { return lines.length; } };
}

// The page's one log.
export const sessionLog = createSessionLog();

// The adapter src/nodus/client.js takes as `steps`: each step is logged in
// `category` with the label "attempt N" (attempt() read when the step
// starts) and marked stuck past `boundMs`.
export function stepLog(log, category, attempt, boundMs = 0) {
  return { begin: name => log.begin(category, name, { label: `attempt ${attempt()}`, boundMs }) };
}

// Uncaught page errors and unhandled rejections: their message only (never
// a stack, never the rejected value itself). Registered once per page.
export function logPageErrors(target, log = sessionLog) {
  if (!target?.addEventListener) return;
  target.addEventListener('error', event => log.log('ui-error', `Page error: ${event?.message || 'unknown error'}`, { error: true }));
  target.addEventListener('unhandledrejection', event => {
    const reason = event?.reason;
    log.log('ui-error', `Unhandled failure: ${reason instanceof Error ? reason.message : typeof reason === 'string' ? reason : 'unknown error'}`, { error: true });
  });
}

// The Logs view (Device & settings → Logs, in index.html and
// connect-site/index.html): the filter, the text, Copy and Download. Shown
// text is refreshed while the section is open (every second, for the
// running-step lines) and whenever the log changes.
export function mountSessionLogView({ panel, filter, output, copy, download, status }, { log = sessionLog, version = 'unknown', page = 'wallet' } = {}) {
  if (!panel || !filter || !output || !copy || !download || !status) return;
  let ticker;
  const render = () => {
    if (!panel.open) return;
    const text = log.text(filter.value) || 'Nothing logged in this session yet.';
    if (output.value !== text) { output.value = text; output.scrollTop = output.scrollHeight; }
  };
  const exported = () => log.exportText({ version, page, userAgent: globalThis.navigator?.userAgent || '' });
  log.subscribe(render);
  filter.addEventListener('change', render);
  panel.addEventListener('toggle', () => {
    clearInterval(ticker); ticker = undefined;
    status.textContent = '';
    if (panel.open) { render(); ticker = setInterval(render, 1000); }
  });
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(exported()); status.textContent = 'Logs copied.'; }
    catch { status.textContent = 'Copy is unavailable here. Use Download logs instead.'; }
  });
  download.addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([exported()], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url; link.download = logFileName(page, Date.now());
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    status.textContent = 'Logs downloaded.';
  });
}
