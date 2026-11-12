// DEBUG LOG (operator 2026-11-12: "tum heryere debug icin full log ekle."): one line per event, written at debug level
// under one prefix so the lines can be found with a single search. It is our own logger: the shared `loglevel` logger
// that libraries write to is never used here, and library output stays as silent as before.
//
// Line: `nodus-debug <ISO time> <area> <event> key=value ...`.
//
// NO SECRETS, by construction rather than by care of the callers: a field is written only when its value is a string,
// number, boolean or bigint. An object, an error, a byte array or a function is replaced by its type name, so a
// whole request, a whole error (a library error message can echo parameters) or a buffer cannot reach a line. A field
// whose NAME says it carries a secret is dropped. Callers still pass only identifiers, counts, durations, host names,
// method names, error codes and our own fixed words: never seed words, passwords, keys, signatures, signed bytes,
// signed text, typed fields, transaction fields or provider URLs (use hostOf). Where a failure is reported, use
// errorFields (code and name only).
//
// A failing sink never reaches the caller.
export const DEBUG_LOG_PREFIX = 'nodus-debug';
const FIELD_MAX = 160;
// Field names that are dropped whatever they hold.
const SECRET_NAME = /seed|word|phrase|pass|secret|private|mnemonic|signature|signed|envelope|payload|text|typed|params|body|key/i;
let sink = line => { console.debug(line); };

// Replaces the sink; returns a function that puts the previous one back (tests capture lines with it).
export function setDebugLogSink(next) {
  const previous = sink; sink = next;
  return () => { sink = previous; };
}

function render(value) {
  if (typeof value === 'string') {
    const clean = value.replace(/[\u0000-\u001f\u007f]/g, ' ');
    const cut = clean.length > FIELD_MAX ? `${clean.slice(0, FIELD_MAX)}…` : clean;
    return /^[A-Za-z0-9_.:\/@+\-]*$/.test(cut) && cut !== '' ? cut : JSON.stringify(cut);
  }
  if (typeof value === 'number') return Number.isFinite(value) ? String(Math.round(value * 100) / 100) : 'nan';
  if (typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  return `[${Array.isArray(value) ? 'array' : typeof value}]`;
}

export function debugLog(area, event, fields = {}) {
  try {
    let line = `${DEBUG_LOG_PREFIX} ${new Date().toISOString()} ${area} ${event}`;
    for (const [name, value] of Object.entries(fields ?? {})) {
      if (value === undefined || value === null || SECRET_NAME.test(name)) continue;
      line += ` ${name}=${render(value)}`;
    }
    sink(line);
  } catch { /* the log never changes what its caller does */ }
}

// The only way a failure enters a line: its numeric or word code and its class name, never its message.
// Each property is read inside its own guard (an accessor on a foreign error can throw): the log never changes the
// error that goes on.
export function errorFields(error) {
  let code, name;
  try { const value = error?.code; if (typeof value === 'number' || (typeof value === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(value))) code = value; } catch { /* left out of the line */ }
  try { const value = error?.name; if (typeof value === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(value)) name = value; } catch { /* left out of the line */ }
  return { outcome: 'error', code, name };
}

// The host of a URL; anything else gives 'invalid'. Never the path, the query or credentials.
export function hostOf(url) {
  try { return new URL(String(url)).host || 'invalid'; } catch { return 'invalid'; }
}

const clock = () => (globalThis.performance?.now ? globalThis.performance.now() : Date.now());
// Starts a timer; the returned function gives the elapsed whole milliseconds.
export function stopwatch() {
  const started = clock();
  return () => Math.round(clock() - started);
}

// Runs `work`, then writes one line with its duration and outcome (ok, or the error's code and name); the result or
// the error goes on unchanged.
export async function timed(area, event, fields, work) {
  const elapsed = stopwatch();
  try {
    const value = await work();
    debugLog(area, event, { ...fields, ms: elapsed(), outcome: 'ok' });
    return value;
  } catch (error) {
    debugLog(area, event, { ...fields, ms: elapsed(), ...errorFields(error) });
    throw error;
  }
}

// A thin WebSocket subclass that writes the open, each frame's size and the close of every connection, never a
// frame's content. The Nodus send module opens its sockets through the global constructor (its generated glue reads
// `WebSocket` directly and takes only a url and a subprotocol), so this is the one place where its requests and
// answers can be seen. Installed once; only for the hosts named in `hosts` (the configured Nodus endpoints), so no
// other page or library socket is touched.
let installedFor;
export function logWebSocketsFor(hosts) {
  const Native = globalThis.WebSocket;
  if (typeof Native !== 'function') return;
  if (installedFor) { for (const host of hosts) installedFor.add(host); return; }
  installedFor = new Set(hosts);
  // The size of a frame, read inside its own guard: 0 when it cannot be read; the frame itself is never touched otherwise.
  const size = data => { try { return typeof data === 'string' ? new TextEncoder().encode(data).length : data?.byteLength ?? data?.size ?? 0; } catch { return 0; } };
  class LoggedWebSocket extends Native {
    constructor(url, protocols) {
      super(url, protocols);
      const host = hostOf(url);
      if (!installedFor.has(host)) return;
      const elapsed = stopwatch(); let lastSend;
      this.addEventListener('open', () => debugLog('nodus-ws', 'open', { host, ms: elapsed() }));
      this.addEventListener('message', event => { try { debugLog('nodus-ws', 'received', { host, bytes: size(event.data), ms_since_send: lastSend ? lastSend() : undefined }); } catch { /* the log only records */ } });
      this.addEventListener('error', () => debugLog('nodus-ws', 'error', { host, ms: elapsed() }));
      this.addEventListener('close', event => { try { debugLog('nodus-ws', 'close', { host, code: event.code, ms: elapsed() }); } catch { /* the log only records */ } });
      const send = this.send.bind(this);
      this.send = data => { try { lastSend = stopwatch(); debugLog('nodus-ws', 'sent', { host, bytes: size(data) }); } catch { /* the log only records */ } return send(data); };
    }
  }
  globalThis.WebSocket = LoggedWebSocket;
}
