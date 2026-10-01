// Entry of the Nodus Connect site (connect.nodusnetwork.io; decision
// docs/plans/decisions/2026-10-01-connect-own-origin.md): the wallet page
// (src/app.js, unchanged) plus Messages (src/connect/ui/messages.js) on the
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

const $ = id => document.getElementById(id);
const TABS = ['home', 'chats', 'wallet', 'more'];
const NO_ID_TEXT = 'Appears when Messages is connected';

// ── app shell ──────────────────────────────────────────────────────────
// tab: the screen shown; origin 'more' while Chats shows a screen opened
// from the More menu (Contacts, Contact requests, Your ID & profile): Back
// returns there, and the rail keeps More highlighted.
let tab = 'home', origin = null, ownId = null, ownName = '', messagesScreen = 'list';
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

function wireShell({ messagesNavigate, shortId, nodusSymbol }) {
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
  $('more-device').onclick = () => {
    setTab('wallet');
    $('device-panel').scrollIntoView({ block: 'start' });
    $('device-title').focus({ preventScroll: true });
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
    for (const [markId, textId] of [['home-avatar', 'home-id'], ['more-avatar', 'more-id']]) {
      const mark = $(markId);
      mark.textContent = ownId ? (ownName ? [...ownName].slice(0, 2).join('') : ownId.slice(0, 2)).toUpperCase() : '··';
      mark.className = `contact-avatar avatar-large ${ownId ? `avatar-${parseInt(ownId[0], 16) % 6}` : 'home-avatar-empty'}`;
      // A verified registered name (nc_name_verify) first, then the short ID.
      $(textId).textContent = ownId ? (ownName ? `${ownName} · ${shortId(ownId)}` : shortId(ownId)) : NO_ID_TEXT;
    }
    $('home-copy-id').disabled = !ownId;
    $('home-id-status').textContent = '';
  }

  // Messages' host callbacks (src/connect/ui/messages.js mountMessages).
  return {
    onUnread(count) { badge('nav-chats-count', count); },
    onRequests(count) { for (const id of ['nav-more-count', 'more-contacts-count', 'more-requests-count']) badge(id, count); },
    onIdentity(fp, name = '') { ownId = fp; ownName = fp ? name : ''; showIdentity(); },
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
}

try {
  const [{ configureSite, registerExtension }, { mountMessages, messagesNavigate, walletExtension }, { shortId }, { NODUS_ASSET }] = await Promise.all([
    import('./wallet-extensions.js'), import('./connect/ui/messages.js'), import('./connect/ui/text.js'), import('./nodus/network.js')
  ]);
  configureSite('connect');
  const host = wireShell({ messagesNavigate, shortId, nodusSymbol: NODUS_ASSET.symbol });
  mountMessages($('nc-root'), host);
  registerExtension(walletExtension);
  await import('./app.js');
  for (const id of ['create', 'restore', 'unlock-wallet']) $(id).disabled = false;
  $('wallet-boot-status').hidden = true;
} catch {
  $('wallet-boot-status').textContent = 'Nodus Connect could not load. Reload this page to try again.';
}
