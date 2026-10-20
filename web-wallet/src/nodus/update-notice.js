// UPDATE NOTICE (web 0.1.129; design docs/plans/2026-10-20-update-required-
// warning-design.md §1 B; operator 2026-10-20: an app that needs an update
// must say so from inside the app). The wallet site and Nodus Connect both
// run src/app.js, which asks the module after every successful connection
// (client.rulesetCompat — a new client after each reconnect asks again) and
// shows the result here as a banner at the top of the page.
//
// The decision is the module's (nodus_ruleset_compat in the C client
// library, the same rule the CLI and nodus-light use); this file only turns
// its outcome into words:
//   2  the network already runs rules this page does not carry — "out of
//      date" + a Reload button. Not dismissible: nothing can be built
//      until the page is reloaded.
//   1  a switch to such rules is committed at block nextHeight — the
//      upgrade notice, no Reload button (the new page may not be published
//      yet). Dismissible; a dismissed switch (same generation and height)
//      is not shown again in this page's life.
//   0  nothing is shown (and a shown notice is removed).
// The page is updated server-side, so the remedy is always "reload".
// English only, like every other text of this app.
//
// The notice never changes what is built or signed: builds stay gated by
// the module's tuple match (design §3 G1). A dishonest node can show a
// false notice or hide a true one (§3); a hidden one costs only what a
// build refused after the switch costs today (G2).

// compat: parseRulesetCompat's result (src/adapters/nodus.js). Returns null
// (nothing to show) or { level: 'required' | 'upcoming', text, details,
// dismissible, key }.
export function updateNoticeOf(compat) {
  if (!compat || compat.outcome === 0) return null;
  const max = compat.maxGeneration;
  if (compat.outcome === 2) {
    return {
      level: 'required',
      text: `This page is out of date: the Nodus network now uses newer rules (generation ${compat.generation}). Reload the page to get the current version.`,
      details: `Network rules: generation ${compat.generation} at block ${compat.tip}. This page supports up to generation ${max}.`,
      dismissible: false,
      key: `required:${compat.generation}`
    };
  }
  if (compat.outcome === 1) {
    const left = compat.nextHeight - compat.tip;
    return {
      level: 'upcoming',
      text: `A Nodus network upgrade happens at block ${compat.nextHeight} (in about ${left} ${left === 1n ? 'block' : 'blocks'}). This page will need to be reloaded after the update is published.`,
      details: `Network rules: generation ${compat.generation} now, generation ${compat.nextGeneration} from block ${compat.nextHeight}; current block ${compat.tip}. This page supports up to generation ${max}.`,
      dismissible: true,
      key: `upcoming:${compat.nextGeneration}:${compat.nextHeight}`
    };
  }
  return null;
}

// The banner. `doc` the page's document, `reload` what the Reload button
// does (location.reload in the page). show(notice) replaces what is shown
// (null removes it); a notice dismissed once (its key) is not shown again.
export function createUpdateNotice({ doc = globalThis.document, reload = () => globalThis.location.reload() } = {}) {
  const dismissed = new Set();
  let banner = null;
  function clear() { banner?.remove(); banner = null; }
  function show(notice) {
    clear();
    if (!notice || dismissed.has(notice.key)) return;
    const box = doc.createElement('div');
    box.id = 'nodus-update-notice';
    box.className = 'update-notice';
    box.dataset.level = notice.level;
    box.setAttribute('role', notice.level === 'required' ? 'alert' : 'status');
    const text = doc.createElement('p');
    text.className = 'update-notice-text';
    text.textContent = notice.text;
    const details = doc.createElement('p');
    details.className = 'update-notice-details';
    details.textContent = notice.details;
    const actions = doc.createElement('div');
    actions.className = 'update-notice-actions';
    // Reload only where it helps now: the current version is already
    // published when the network runs rules this page lacks (outcome 2);
    // before a switch the new page may not be published yet.
    if (notice.level === 'required') {
      const again = doc.createElement('button');
      again.type = 'button';
      again.className = 'update-notice-reload';
      again.textContent = 'Reload';
      again.addEventListener('click', () => reload());
      actions.append(again);
    }
    if (notice.dismissible) {
      const close = doc.createElement('button');
      close.type = 'button';
      close.className = 'secondary update-notice-dismiss';
      close.textContent = 'Dismiss';
      close.addEventListener('click', () => { dismissed.add(notice.key); clear(); });
      actions.append(close);
    }
    box.append(text, details, actions);
    doc.body.prepend(box);
    banner = box;
  }
  return { show, clear };
}
