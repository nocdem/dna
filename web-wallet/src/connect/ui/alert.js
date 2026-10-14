// New-message alert (web 0.1.122; operator 2026-10-14: "yeni msg falan
// geldiğinde uyarı gelmiyor" — chose a count in the tab title and a sound,
// not system notifications). Nodus Connect only: the wallet site has no
// Messages (vite.connect.config.js).
//
//   - Tab title: while the unread total is above 0 the title is
//     "(N) <the page's own title>"; at 0 the page's own title again. The
//     total is the one Messages hands its host (messages.js render ->
//     host.onUnread: unread messages of contacts and groups; contact requests
//     are a separate count, onRequests, and are not added).
//   - Sound: a short, quiet chime when the unread total GROWS compared with
//     the last value seen — only once Messages says its first message check
//     of this session has finished (`caughtUp`, messages.js), so the messages
//     that arrived while away show in the title without a chime. At most one
//     chime per CHIME_GAP_MS (a check delivering ten messages = one chime).
//     Made with the Web Audio API (an oscillator and a gain envelope): no
//     audio file, no request. A browser allows sound only after the user has
//     used the page: a sound context that is not running is skipped silently.
//   - The on/off choice ("Sound for new messages", Device & settings; default
//     on) is a per-browser preference in this browser's localStorage, like the
//     automatic lock (src/auto-lock.js) and zero balances
//     (src/zero-balances.js). It holds no user data and is not tied to a
//     wallet; the rule that only a saved wallet keeps data on the device
//     (decision 2026-10-02-device-cache-only-when-saved) is about caches of
//     wallet data and does not cover it. A missing, unreadable or unknown
//     value, or a browser that refuses storage, gives the default (on).
export const SOUND_KEY = 'nodus.connect.sound.v1';
export const CHIME_GAP_MS = 2000;

export function readSound(storage) {
  try { return storage?.getItem(SOUND_KEY) !== '0'; }
  catch { return true; }
}

// True when the choice was kept (a browser that refuses storage keeps it for
// this page only).
export function writeSound(storage, on) {
  try { storage.setItem(SOUND_KEY, on === true ? '1' : '0'); return true; }
  catch { return false; }
}

export function soundNote(on) {
  return on
    ? 'A short sound plays when a new message arrives while this page is open.'
    : 'No sound plays for new messages. The number of unread messages still shows in the page title.';
}

// The title for an unread total. Pure.
export function titleWithCount(base, count) {
  return Number.isSafeInteger(count) && count > 0 ? `(${count}) ${base}` : base;
}

// doc: holds `title` (the page's own title is read once, here); sound: the
// starting choice; now: the clock for the chime gap; audio: the sound
// context constructor, or undefined when the browser has none.
export function createMessageAlert({
  doc = globalThis.document,
  sound = true,
  now = () => Date.now(),
  audio = () => globalThis.AudioContext || globalThis.webkitAudioContext
} = {}) {
  const base = doc.title;
  let soundOn = sound === true;
  let last = 0, primed = false, lastChimeAt = -Infinity, context;

  function showTitle(count) {
    const next = titleWithCount(base, count);
    if (doc.title !== next) doc.title = next;
  }

  function play() {
    const t = context.currentTime;
    const tone = context.createOscillator(), envelope = context.createGain();
    tone.type = 'sine';
    tone.frequency.setValueAtTime(880, t);
    tone.frequency.exponentialRampToValueAtTime(660, t + 0.18);
    envelope.gain.setValueAtTime(0.0001, t);
    envelope.gain.exponentialRampToValueAtTime(0.05, t + 0.02);
    envelope.gain.exponentialRampToValueAtTime(0.0001, t + 0.2);
    tone.connect(envelope);
    envelope.connect(context.destination);
    tone.onended = () => { try { tone.disconnect(); envelope.disconnect(); } catch { /* already gone */ } };
    tone.start(t);
    tone.stop(t + 0.22);
  }

  async function chime() {
    if (!soundOn) return;
    const at = now();
    if (at - lastChimeAt < CHIME_GAP_MS) return;
    lastChimeAt = at;
    try {
      if (!context) {
        const Context = audio();
        if (typeof Context !== 'function') return;
        context = new Context();
      }
      if (context.state !== 'running') await context.resume();
      // Still not allowed, or allowed only much later: no sound for this one.
      if (context.state !== 'running' || now() - at > 1000 || !soundOn) return;
      play();
    } catch { /* no sound; never an error per message */ }
  }

  return {
    // count: the unread total; caughtUp: Messages' first check of this
    // session has finished (messages.js host.onUnread second argument).
    unread(count, caughtUp = false) {
      const n = Number.isSafeInteger(count) && count > 0 ? count : 0;
      showTitle(n);
      const grew = caughtUp === true && primed && n > last;
      last = n;
      primed = caughtUp === true;
      if (grew) void chime();
    },
    // Messages closed or the wallet locked: the page's own title, and the
    // next open starts again without a chime for its first check.
    reset() { last = 0; primed = false; showTitle(0); },
    setSound(on) { soundOn = on === true; },
    get sound() { return soundOn; }
  };
}

// The "Sound for new messages" switch (connect-site/index.html, Device &
// settings): box = the checkbox, note = its hint line, storage = this
// browser's localStorage or undefined.
export function wireSoundSwitch({ box, note, alert, storage }) {
  const apply = on => { box.checked = on; alert.setSound(on); return soundNote(on); };
  note.textContent = apply(readSound(storage));
  box.addEventListener('change', () => {
    const kept = writeSound(storage, box.checked);
    note.textContent = apply(box.checked) + (kept ? '' : ' This browser did not allow saving the choice: it applies until this page is closed.');
  });
}
