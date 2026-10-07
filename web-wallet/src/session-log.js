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
  // running(): the same steps as data — { at, category, error (stuck),
  // text } — for the Logs view (mountSessionLogView); runningLines() is
  // their text form, so the two never differ.
  function running(filter = 'all') {
    const keep = LOG_FILTERS[filter] || LOG_FILTERS.all, at = now();
    const out = [];
    for (const step of steps) {
      const stuck = step.boundMs > 0 && at - step.startedAt > step.boundMs;
      if (!keep({ category: step.category, error: stuck })) continue;
      out.push({ at: step.startedAt, category: step.category, error: stuck, text: `${step.label ? `${step.label} · ` : ''}${step.name} running ${Math.floor((at - step.startedAt) / 1000)} s${stuck ? ' — stuck' : ''}` });
    }
    return out;
  }
  function runningLines(filter = 'all', clock = clockText) {
    return running(filter).map(step => `${clock(step.at)} [${step.category}] ${step.text}`);
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
  return { log, begin, entries, text, running, runningLines, exportText, clear, subscribe, get startedAt() { return startedAt; }, get size() { return lines.length; } };
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

// One line of the Logs view: its time, a category chip, an error marker
// (text, not colour alone) and its text — every part set as textContent,
// never as markup. Spaces between the parts keep a copied selection
// readable. `running`: a step still running (log.running).
function logLineNode({ at, category, error, text }, running = false) {
  const part = (tag, className, value) => { const node = document.createElement(tag); node.className = className; node.textContent = value; return node; };
  const row = document.createElement('div');
  row.className = `log-line${error ? ' is-error' : ''}${running ? ' is-running' : ''}`;
  row.dataset.category = category;
  const time = part('time', 'log-time', clockText(at));
  time.dateTime = new Date(at).toISOString();
  row.append(time, ' ', part('span', 'log-chip', category), ' ');
  if (error) row.append(part('span', 'log-flag', running ? '! stuck' : '! error'), ' ');
  row.append(part('span', 'log-msg', text));
  return row;
}
const lineKey = line => `${line.at}|${line.category}|${line.error ? 1 : 0}|${line.text}`;
// How many lines from the front of `shown` are gone (the ring dropped them,
// or the log was cleared) so that the rest is still the start of `keys`.
function evictedFront(shown, keys) {
  for (let drop = 0; drop <= shown.length; drop++) {
    const rest = shown.length - drop;
    if (rest > keys.length) continue;
    let same = true;
    for (let i = 0; i < rest && same; i++) same = shown[drop + i] === keys[i];
    if (same) return drop;
  }
  return shown.length;
}

// The Logs view (the Logs page, in index.html and connect-site/index.html):
// the filter, the lines, Copy and Download. `output` is the line viewer
// (#session-log-text, role="log"): finished lines are appended as they come
// (only new lines are added, so a screen reader hears only those), the
// running-step lines below them are updated in place every second, and the
// view follows the newest line only when it was already scrolled to the
// bottom. The shown lines are refreshed while the section is open (every
// second, for the running steps) and whenever the log changes. Copy and
// Download take log.exportText — the plain text, unchanged by this view.
export function mountSessionLogView({ panel, filter, output, copy, download, status }, { log = sessionLog, version = 'unknown', page = 'wallet' } = {}) {
  if (!panel || !filter || !output || !copy || !download || !status) return;
  let ticker;
  const finished = document.createElement('div'), running = document.createElement('div'), empty = document.createElement('p');
  finished.className = 'log-entries'; running.className = 'log-running'; empty.className = 'log-empty';
  empty.textContent = 'Nothing logged in this session yet.';
  output.replaceChildren(finished, running, empty);
  let shownFilter = null, shownKeys = [], runningKeys = [];
  const render = ({ toBottom = false } = {}) => {
    if (!panel.open) return;
    const chosen = filter.value, lines = log.entries(chosen), steps = log.running(chosen);
    const atBottom = toBottom || output.scrollHeight - output.scrollTop - output.clientHeight <= 4;
    const keys = lines.map(lineKey);
    if (chosen !== shownFilter) {
      // a new filter: the whole list once, not read out line by line (busy
      // until the next task, so the change is not announced as additions)
      output.setAttribute('aria-busy', 'true');
      finished.replaceChildren(...lines.map(line => logLineNode(line)));
      shownFilter = chosen; shownKeys = keys;
      setTimeout(() => output.removeAttribute('aria-busy'), 0);
    } else {
      const drop = evictedFront(shownKeys, keys), kept = shownKeys.length - drop;
      for (let i = 0; i < drop; i++) finished.firstChild?.remove();
      if (keys.length > kept) finished.append(...lines.slice(kept).map(line => logLineNode(line)));
      shownKeys = keys;
    }
    // Running steps: a line is replaced only when its step (or its stuck
    // mark) changes; the seconds count is updated in place.
    const stepKeys = steps.map(step => `${step.at}|${step.category}|${step.error ? 1 : 0}`);
    if (stepKeys.join('\n') !== runningKeys.join('\n')) { running.replaceChildren(...steps.map(step => logLineNode(step, true))); runningKeys = stepKeys; }
    else steps.forEach((step, i) => { const msg = running.children[i]?.querySelector('.log-msg'); if (msg && msg.textContent !== step.text) msg.textContent = step.text; });
    empty.hidden = lines.length > 0 || steps.length > 0;
    if (atBottom) output.scrollTop = output.scrollHeight;
  };
  const exported = () => log.exportText({ version, page, userAgent: globalThis.navigator?.userAgent || '' });
  log.subscribe(() => render());
  filter.addEventListener('change', () => render({ toBottom: true }));
  panel.addEventListener('toggle', () => {
    clearInterval(ticker); ticker = undefined;
    status.textContent = '';
    if (panel.open) { render({ toBottom: true }); ticker = setInterval(() => render(), 1000); }
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
