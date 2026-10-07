// Entry of the Nodus Connect site (connect.nodusnetwork.io; decision
// docs/plans/decisions/2026-10-01-connect-own-origin.md): the wallet page
// (src/app.js, which only raises src/wallet-extensions.js events) plus Messages (src/connect/ui/messages.js) on the
// wallet's ONE unlock, ONE NODUS client and ONE lock, presented in the shape
// of the DNA Connect app (messenger/dna_messenger_flutter
// screens/home_screen.dart): Home, Chats, Wallet, More.
//
// As src/main.js: freeze ethers' pluggable RNG/KDF backends before any other
// code runs. Then, BEFORE src/app.js loads: name the site (the cross-site
// cookie, src/site-lock.js), register Messages as the wallet's extension
// (src/wallet-extensions.js), so app.js raises its events to it from the
// first unlock on, and wire the app shell below.
//
// The shell only shows and hides parts of connect-site/index.html. It reads
// what src/app.js shows (whether #wallet-open is visible, the portfolio
// total, the NODUS row) and never writes into the wallet's state: every
// wallet action stays the wallet's own control (#quick-send, #quick-receive,
// #lock, …), clicked or shown here.
import { Buffer } from 'buffer';
import { randomBytes, pbkdf2 } from 'ethers';
import './connect/ui/messenger.css';
globalThis.Buffer = Buffer;
randomBytes.lock(); pbkdf2.lock();
// The release shown on the page (package.json version, vite.connect.config.js define).
for (const node of document.querySelectorAll('.app-version')) node.textContent = `Version ${__APP_VERSION__}`;

const $ = id => document.getElementById(id);
const TABS = ['home', 'chats', 'wallet', 'more'];

// ── app shell ──────────────────────────────────────────────────────────
// tab: the screen shown; origin 'more' while Chats shows a screen opened
// from the More menu (Contacts, Contact requests, Your ID & profile): Back
// returns there, and the rail keeps More highlighted. messagesClosed: no own
// ID because Messages closed with a reason while the wallet is open
// (messages.js onIdentity, 4th argument); the lock clears it.
let tab = 'home', origin = null, ownId = null, ownName = '', ownAvatar = '', messagesScreen = 'list', messagesClosed = false;
const scrollByTab = {};

function setTab(next, { highlight = next } = {}) {
  if (next !== tab) { scrollByTab[tab] = scrollY; }
  const changed = next !== tab;
  tab = next;
  for (const name of TABS) $(`tab-${name}`).hidden = name !== next;
  for (const item of document.querySelectorAll('.app-nav-item')) {
    if (item.dataset.tab === highlight) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  if (changed) scrollTo(0, scrollByTab[next] || 0);
}

function badge(id, count) {
  const node = $(id);
  node.textContent = count ? (count > 99 ? '99+' : String(count)) : '';
  node.hidden = !count;
}

// The own chain name shown on Home (#home-name, the identity line) and in
// More (#more-name, the identity line), from two sources
// (src/connect/ui/chain-names.js shownOwnName):
//   - the wallet's own reverse lookup on open (src/app.js refreshName
//     raises ownName; decision 2026-10-02-onchain-names — a name is shown
//     only when the lookup for this ID confirms it): once it ANSWERED
//     (confirmed), its answer is shown, '' = no name;
//   - until then, the name Messages knows (onIdentity): kept on this device
//     inside the saved wallet's encrypted history (state.chainNames,
//     decision 2026-10-02-device-cache-only-when-saved), or found by its
//     own lookup this session.
// Neither, or the wallet locked: "Your ID".
const YOUR_ID_TEXT = 'Your ID';
let walletNameAnswer = null;             // { name } once the wallet's lookup answered, else null

function wireShell({ messagesNavigate, ownIdText, nodusSymbol, initials, fillAvatar, shownOwnName, profileEntryText }) {
  const navigate = target => messagesNavigate(target);

  function openFromMore(target) {
    origin = 'more';
    setTab('chats', { highlight: 'more' });
    navigate(target);
    // Messages not open: it shows Chats with its status; nothing to go back to.
    if (messagesScreen === 'list') { origin = null; setTab('chats'); }
  }

  for (const item of document.querySelectorAll('.app-nav-item')) {
    item.onclick = () => {
      // A screen opened from More gives way to Chats itself.
      if (item.dataset.tab === 'chats' && origin) navigate('chats');
      origin = null;
      setTab(item.dataset.tab);
    };
  }

  // Unlock / lock: src/app.js shows or hides #wallet-open.
  function syncOpen() {
    const open = !$('wallet-open').hidden;
    $('start-screen').hidden = open;
    // Deleting the saved wallet stays reachable in both states (it sits
    // outside the open wallet in the wallet page).
    const place = open ? $('device-panel') : $('vault-delete-home');
    if ($('vault-delete-details').parentElement !== place) place.append($('vault-delete-details'));
    origin = null;
    for (const name of TABS) scrollByTab[name] = 0;
    setTab('home');
    scrollTo(0, 0);
    if (open) $('home-title').focus({ preventScroll: true });
    syncNameRegistration();
  }
  new MutationObserver(syncOpen).observe($('wallet-open'), { attributes: true, attributeFilter: ['hidden'] });

  // In-page links (the wallet's section links, "How storage and protection
  // work", Privacy & safety): show the screen holding the target first, in
  // the capture phase, so the link's own scroll and src/app.js's handlers
  // (Earn, Send / Receive) run on a visible screen.
  document.addEventListener('click', event => {
    const link = event.target.closest?.('a[href^="#"]');
    if (!link) return;
    const target = document.getElementById(decodeURIComponent(link.hash.slice(1)));
    if (!target) return;
    if ($('about-screen').contains(target)) { event.preventDefault(); openAbout(target); return; }
    const screen = target.closest('.app-screen');
    if (screen && !$('wallet-open').hidden) {
      const name = screen.id.slice('tab-'.length);
      if (name !== tab) { origin = null; setTab(name); }
    }
  }, true);

  // Privacy & safety: one screen over the start screen or the app.
  let aboutReturn = 0;
  function openAbout(target) {
    if (document.body.dataset.overlay !== 'about') { aboutReturn = scrollY; document.body.dataset.overlay = 'about'; }
    if (target.id === 'privacy') scrollTo(0, 0); else target.scrollIntoView({ block: 'start' });
    $('about-title').focus({ preventScroll: true });
  }
  $('about-back').onclick = () => {
    delete document.body.dataset.overlay;
    scrollTo(0, aboutReturn);
    ($('wallet-open').hidden ? $('start-title') : $(`${tab}-title`))?.focus({ preventScroll: true });
  };

  // Home.
  function syncNameRegistration() {
    const knownName = shownOwnName(walletNameAnswer, ownId ? ownName : '');
    const open = !$('wallet-open').hidden;
    const ready = open && !knownName && !$('quick-name').hidden && !$('quick-name').disabled;
    $('home-name-registration').hidden = !open || !!knownName;
    $('home-register-name').disabled = !ready;
    $('home-name-status').textContent = ready
      ? 'Open the name form to check availability and review the price and network fee.'
      : ($('own-name').textContent.trim() || 'Name registration is unavailable until the wallet checks your name on the network.');
  }
  const nameObserver = new MutationObserver(syncNameRegistration);
  nameObserver.observe($('quick-name'), { attributes: true, attributeFilter: ['hidden', 'disabled'] });
  nameObserver.observe($('own-name'), { childList: true, characterData: true, subtree: true });
  $('home-register-name').onclick = () => {
    syncNameRegistration();
    if ($('home-register-name').disabled) return;
    origin = null; setTab('wallet'); $('quick-name').click();
  };
  $('home-new-chat').onclick = () => { origin = null; setTab('chats'); navigate('add'); };
  $('home-send').onclick = () => { setTab('wallet'); $('quick-send').click(); };
  $('home-receive').onclick = () => { setTab('wallet'); $('quick-receive').click(); };
  $('home-open-wallet').onclick = () => { setTab('wallet'); $('wallet-title').focus({ preventScroll: true }); };
  $('home-copy-id').onclick = async () => {
    if (!ownId) return;
    try { await navigator.clipboard.writeText(ownId); $('home-id-status').textContent = 'Your ID was copied.'; }
    catch { $('home-id-status').textContent = 'Copy is unavailable. Open Your ID & profile in More and copy it there.'; }
  };
  // The wallet's own numbers, shown again on Home (read only).
  const mirror = () => {
    $('home-total').textContent = $('portfolio-total').textContent;
    const row = [...$('balances').querySelectorAll('.asset-group')].find(node => node.dataset.symbol === nodusSymbol);
    $('home-nodus').textContent = row?.querySelector('.asset-value strong')?.textContent || '—';
  };
  const mirrorObserver = new MutationObserver(mirror);
  for (const id of ['portfolio-total', 'balances']) mirrorObserver.observe($(id), { childList: true, characterData: true, subtree: true });

  // More.
  $('more-profile').onclick = () => openFromMore('profile');
  $('more-contacts').onclick = () => openFromMore('contacts');
  $('more-requests').onclick = () => openFromMore('requests');
  // The address book is part of the wallet (src/app.js, #address-book-panel).
  $('more-address-book').onclick = () => {
    setTab('wallet');
    $('address-book-panel').scrollIntoView({ block: 'start' });
    $('address-book-title').focus({ preventScroll: true });
  };
  $('more-device').onclick = () => {
    setTab('wallet');
    $('device-panel').scrollIntoView({ block: 'start' });
    $('device-title').focus({ preventScroll: true });
  };
  // Logs: this session's log (src/session-log.js), a section of Device &
  // settings, opened (src/app.js mountSessionLogView fills it).
  $('more-logs').onclick = () => {
    setTab('wallet');
    $('session-logs').open = true;
    $('session-logs').scrollIntoView({ block: 'start' });
    $('session-logs-title').focus({ preventScroll: true });
  };

  // Status line: shown again whenever src/app.js writes a new message, and
  // hidden again after a few seconds like an app snackbar — it sits over
  // the chat composer otherwise.
  const toast = document.querySelector('.app-toast');
  let toastTimer;
  new MutationObserver(() => {
    delete toast.dataset.dismissed;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.dataset.dismissed = 'true'; }, 6000);
  }).observe($('wallet-status'), { childList: true, characterData: true, subtree: true });
  $('toast-dismiss').onclick = () => { clearTimeout(toastTimer); toast.dataset.dismissed = 'true'; };

  function showIdentity() {
    const name = shownOwnName(walletNameAnswer, ownId ? ownName : '');
    $('home-name').textContent = name || YOUR_ID_TEXT;
    $('more-name').textContent = profileEntryText(name);
    for (const [markId, textId] of [['home-avatar', 'home-id'], ['more-avatar', 'more-id']]) {
      const mark = $(markId);
      // The own profile picture (messages.js onIdentity), else the initials.
      fillAvatar(mark, ownId ? initials(ownId, name) : '··', ownId ? ownAvatar : '');
      mark.className = `contact-avatar avatar-large ${ownId ? `avatar-${parseInt(ownId[0], 16) % 6}` : 'home-avatar-empty'}`;
      // The chain name (HF-4) first, then the short ID; with no ID, why
      // (locked or opening, or Messages could not open — messages.js ownIdText).
      $(textId).textContent = ownIdText({ id: ownId, name, closed: messagesClosed });
    }
    $('home-copy-id').disabled = !ownId;
    $('home-id-status').textContent = '';
    syncNameRegistration();
  }

  // A wallet extension (src/wallet-extensions.js): the wallet's own name
  // lookup, and the lock that clears it.
  const nameExtension = {
    ownName({ name, confirmed } = {}) { walletNameAnswer = confirmed === true ? { name: typeof name === 'string' ? name : '' } : null; showIdentity(); },
    locked() { walletNameAnswer = null; ownId = null; ownName = ''; ownAvatar = ''; messagesClosed = false; showIdentity(); }
  };

  // Messages' host callbacks (src/connect/ui/messages.js mountMessages).
  const host = {
    onUnread(count) { badge('nav-chats-count', count); },
    onRequests(count) { for (const id of ['nav-more-count', 'more-contacts-count', 'more-requests-count']) badge(id, count); },
    onIdentity(fp, name = '', avatarBase64 = '', closed = false) { ownId = fp; ownName = fp ? name : ''; ownAvatar = fp ? avatarBase64 : ''; messagesClosed = !fp && closed === true; showIdentity(); },
    onScreen(screen) {
      messagesScreen = screen;
      // A conversation, Contacts or Your ID & profile covers the bottom bar
      // on a narrow screen (a pushed screen in the app).
      $('wallet-open').dataset.pushed = String(screen !== 'list');
      if (screen === 'list' && origin) { origin = null; if (tab === 'chats') setTab('chats'); }
    },
    onBack() {
      if (origin !== 'more') return false;
      origin = null;
      setTab('more');
      $('more-title').focus({ preventScroll: true });
      return true;
    }
  };
  return { host, nameExtension };
}

try {
  const [{ configureSite, registerExtension }, { mountMessages, messagesNavigate, walletExtension, initials, vaultHost, ownIdText }, { NODUS_ASSET }, { fillAvatar }, { mountVaults, vaultExtension }, { shownOwnName, profileEntryText }, { mountSmartContracts, smartContractExtension }] = await Promise.all([
    import('./wallet-extensions.js'), import('./connect/ui/messages.js'), import('./nodus/network.js'), import('./connect/ui/dom.js'), import('./vaults/ui.js'), import('./connect/ui/chain-names.js'), import('./evm/ui.js')
  ]);
  configureSite('connect');
  const { host, nameExtension } = wireShell({ messagesNavigate, ownIdText, nodusSymbol: NODUS_ASSET.symbol, initials, fillAvatar, shownOwnName, profileEntryText });
  mountMessages($('nc-root'), host);
  registerExtension(walletExtension);
  registerExtension(nameExtension);
  // Shared vaults (src/vaults/ui.js) in the Wallet tab's NODUS area; they
  // tell members and keep vaults through Messages (vaultHost).
  mountVaults({ panelNode: $('vault-panel'), rootNode: $('vaults-root'), messagesHost: vaultHost });
  registerExtension(vaultExtension);
  // Smart contracts (src/evm/ui.js) in the Wallet tab's NODUS area, as on
  // the wallet page (src/main.js): hidden unless the connected node reports
  // the EVM generation (client.evmBuildable / evmReadable) and NODUS is the
  // selected network.
  mountSmartContracts({ panelNode: $('evm-panel'), rootNode: $('evm-root') });
  registerExtension(smartContractExtension);
  await import('./app.js');
  for (const id of ['create', 'restore', 'unlock-wallet']) $(id).disabled = false;
  $('wallet-boot-status').hidden = true;
} catch {
  $('wallet-boot-status').textContent = 'Nodus Connect could not load. Reload this page to try again.';
}
