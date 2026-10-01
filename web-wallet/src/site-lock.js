// Cross-site "not both open" rule (decision
// docs/plans/decisions/2026-10-01-connect-own-origin.md, operator: "ikisi aynı
// açık olmasın"): wallet.nodusnetwork.io and connect.nodusnetwork.io must not
// both have an unlocked wallet in one browser.
//
// Web Locks and storage are per origin, so the single-tab lock
// (`nodus.wallet.session`, src/app.js) cannot see the other site. A cookie
// can: with Domain=nodusnetwork.io both subdomains read and write the same
// one. While a wallet is unlocked its page refreshes
//   nodus_open=<site>.<ms>; Path=/; Max-Age=15; Secure; SameSite=Strict
// every 5 s (site 'wallet' or 'connect', ms = Date.now()). The other site
// refuses to unlock while that mark is fresh (< 15 s old) and, if it is
// itself unlocked, locks when it sees the other site's fresh mark. The cookie
// holds no identity data: only which site and when.
//
// Limits (stated, not hidden): per browser profile only (two devices, or two
// browsers, can both be open — then only the node's same-node session
// eviction applies, nodus_auth.c:95-116); a background tab whose timers the
// browser throttles below one tick per 15 s lets its mark expire, and the
// other site may then open — the throttled tab locks itself at its next tick
// when it sees the other site's mark. A browser that refuses the cookie
// (e.g. a Secure cookie on plain http) is not blocked: the rule fails open.
export const COOKIE_NAME = 'nodus_open';
export const REFRESH_MS = 5000;
export const FRESH_MS = 15000;
const SITES = Object.freeze({ wallet: 'wallet.nodusnetwork.io', connect: 'connect.nodusnetwork.io' });
const MARK = /^(wallet|connect)\.(0|[1-9]\d{0,15})$/;

function checkSite(site) { if (!Object.hasOwn(SITES, site)) throw new Error('Unknown site.'); return site; }

// Domain=nodusnetwork.io only on the real subdomains; on localhost and in
// tests the cookie stays host-only.
export function cookieDomain(hostname) {
  return typeof hostname === 'string' && hostname.endsWith('.nodusnetwork.io') ? 'nodusnetwork.io' : null;
}

function attributes(maxAge, hostname) {
  const domain = cookieDomain(hostname);
  return `; Path=/; Max-Age=${maxAge}; Secure; SameSite=Strict${domain ? `; Domain=${domain}` : ''}`;
}

// The document.cookie assignment that sets this site's mark.
export function markCookie(site, now, hostname) {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid time.');
  return `${COOKIE_NAME}=${checkSite(site)}.${now}${attributes(FRESH_MS / 1000, hostname)}`;
}

// The document.cookie assignment that removes the mark (same Path / Domain).
export function clearCookie(hostname) { return `${COOKIE_NAME}=${attributes(0, hostname)}`; }

// Every well-formed mark in a document.cookie string ("a=1; nodus_open=…").
// Anything malformed is ignored.
export function parseMarks(cookieString) {
  if (typeof cookieString !== 'string') return [];
  const marks = [];
  for (const part of cookieString.split(';')) {
    const at = part.indexOf('=');
    if (at < 0 || part.slice(0, at).trim() !== COOKIE_NAME) continue;
    const match = MARK.exec(part.slice(at + 1).trim());
    if (match) marks.push({ site: match[1], ms: Number(match[2]) });
  }
  return marks;
}

// Fresh: written less than FRESH_MS ago (a mark from the future by more than
// that is not trusted as fresh).
export function isFresh(mark, now) { return !!mark && now - mark.ms < FRESH_MS && mark.ms - now < FRESH_MS; }

// The other site with a fresh mark, or null.
export function otherSiteOpen(cookieString, site, now) {
  checkSite(site);
  const other = parseMarks(cookieString).find(mark => mark.site !== site && isFresh(mark, now));
  return other ? other.site : null;
}

// Whether the mark in the cookie (any one of them) is this site's.
export function markIsOurs(cookieString, site) {
  checkSite(site);
  return parseMarks(cookieString).some(mark => mark.site === site);
}

// Plain words, shown before unlocking (refusal) and after a forced lock.
export function refusalText(other) {
  return checkSite(other) === 'wallet'
    ? `Your wallet is open on ${SITES.wallet}. Lock it there first.`
    : `Nodus Connect is open on ${SITES.connect}. Lock it there first.`;
}
export function lockedText(other) {
  return checkSite(other) === 'wallet'
    ? `Your wallet was opened on ${SITES.wallet}, so it was locked here. Lock it there to use it here.`
    : `Nodus Connect was opened on ${SITES.connect}, so the wallet was locked here. Lock it there to use it here.`;
}

// The page side. `doc` needs only a `cookie` property; the clock and the
// interval are injectable for tests. onOther(text) is called once when, while
// running, the other site's fresh mark is seen (the caller locks).
export function createSiteLock({ site, doc = globalThis.document, hostname = globalThis.location?.hostname, now = () => Date.now(), every = globalThis.setInterval, stopEvery = globalThis.clearInterval, onOther } = {}) {
  checkSite(site);
  let timer;
  const read = () => { try { return String(doc.cookie ?? ''); } catch { return ''; } };
  const write = value => { try { doc.cookie = value; } catch { /* fail open */ } };
  // Refusal text when the other site is open now, else null.
  function otherOpen() {
    const other = otherSiteOpen(read(), site, now());
    return other ? refusalText(other) : null;
  }
  function tick() {
    const other = otherSiteOpen(read(), site, now());
    if (other) { stop(); onOther?.(lockedText(other)); return; }
    write(markCookie(site, now(), hostname));
  }
  function start() {
    if (timer !== undefined) return;
    timer = every(tick, REFRESH_MS);
    tick();
  }
  function stop() {
    if (timer !== undefined) { stopEvery(timer); timer = undefined; }
    if (markIsOurs(read(), site)) write(clearCookie(hostname));
  }
  return { otherOpen, start, stop, get running() { return timer !== undefined; } };
}
