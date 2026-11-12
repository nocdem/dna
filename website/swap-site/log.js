// The page's diagnostic log (operator 2026-11-12: "tum heryere debug icin full log ekle"). One line per event:
//   [swap-site] <ISO time> <area> <event> key=value ...
// written with console.info, or console.warn for a failure. Only the NAMED fields a caller passes are written, and only
// as short plain values: an object, a function or a stack is never printed, a long string is cut, and a field whose name
// says signature, key, secret or words is replaced. A logger never throws into its caller, whatever the sink does.
// The page holds no secrets (addresses and amounts may be logged); the guards are for an answer that one day carries one.

export const LOG_PREFIX = '[swap-site]';
const MAX_TEXT = 200;
const HIDDEN = /signature|publickey|secret|seed|mnemonic|words|privatekey/i;

function plain(name, value) {
  if (HIDDEN.test(name)) return '"[omitted]"';
  switch (typeof value) {
    case 'string': return JSON.stringify(value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value);
    case 'number': case 'boolean': return String(value);
    case 'bigint': return value.toString();
    case 'undefined': return null;               // an absent field is not written
    default: return value === null ? 'null' : '"[not-plain]"';
  }
}

// -> "k=v k=v" for the fields that are present, in the caller's order.
export function formatFields(fields) {
  const out = [];
  for (const [name, value] of Object.entries(fields ?? {})) {
    const text = plain(name, value);
    if (text !== null) out.push(`${name}=${text}`);
  }
  return out.join(' ');
}

// The named fields of an adapter / extension error (never the error object, its stack or its `cause`). Each property is
// read on its own, so a getter that throws (or a value that is not an object) gives "[unreadable]" for that field and
// never reaches the caller: the callers evaluate this as an argument, outside the logger's guard.
const ERROR_FIELDS = ['code', 'extensionCode', 'delivered', 'paid', 'nodusSent', 'reason', 'openRequestNumber', 'answered', 'message'];
export function errorFields(err) {
  const out = {};
  for (const name of ERROR_FIELDS) {
    try { out[name] = err?.[name]; } catch { out[name] = '[unreadable]'; }
  }
  return out;
}

// A logger that does nothing: the default of every module, so a caller that gives no logger is unchanged.
export const nullLog = Object.freeze({ info() {}, warn() {}, timer: () => () => 0 });

// Wraps any logger-shaped object so that nothing it does reaches the caller. Applied to every logger a module receives.
export function guardLog(log) {
  if (!log) return nullLog;
  const safe = name => (...args) => { try { log[name](...args); } catch { /* a diagnostic never changes the flow */ } };
  return {
    info: safe('info'), warn: safe('warn'),
    timer() {
      let t;
      try { t = log.timer(); } catch { return () => 0; }
      return () => { try { const v = t(); return Number.isFinite(v) ? v : 0; } catch { return 0; } };
    },
  };
}

// sink: { info, warn } (the console); now: () => Date; clock: () => milliseconds, monotonic.
export function createLogger({ sink = globalThis.console, now = () => new Date(), clock = () => globalThis.performance.now() } = {}) {
  const write = (level, area, event, fields) => {
    const line = `${LOG_PREFIX} ${now().toISOString()} ${area} ${event}`;
    const tail = formatFields(fields);
    sink[level](tail ? `${line} ${tail}` : line);
  };
  return guardLog({
    info: (area, event, fields) => write('info', area, event, fields),
    warn: (area, event, fields) => write('warn', area, event, fields),
    timer() { const t0 = clock(); return () => Math.round(clock() - t0); },
  });
}
