// Entry of the Nodus Connect site (connect.nodusnetwork.io; decision
// docs/plans/decisions/2026-10-01-connect-own-origin.md): the wallet page
// (src/app.js, unchanged) plus Messages (src/connect/ui/messages.js) on the
// wallet's ONE unlock, ONE NODUS client and ONE lock.
//
// As src/main.js: freeze ethers' pluggable RNG/KDF backends before any other
// code runs. Then, BEFORE src/app.js loads: name the site (the cross-site
// cookie, src/site-lock.js) and register Messages as the wallet's extension
// (src/wallet-extensions.js), so app.js raises its events to it from the
// first unlock on.
import { Buffer } from 'buffer';
import { randomBytes, pbkdf2 } from 'ethers';
import './connect/ui/messenger.css';
globalThis.Buffer = Buffer;
randomBytes.lock(); pbkdf2.lock();
try {
  const [{ configureSite, registerExtension }, { mountMessages, walletExtension }] = await Promise.all([
    import('./wallet-extensions.js'), import('./connect/ui/messages.js')
  ]);
  configureSite('connect');
  const badge = document.getElementById('nav-messages-count');
  mountMessages(document.getElementById('nc-root'), {
    onUnread(count) { badge.textContent = count ? String(count) : ''; badge.hidden = !count; }
  });
  registerExtension(walletExtension);
  await import('./app.js');
  // The panel's Lock is the wallet's Lock (one lock).
  document.getElementById('messages-lock').onclick = () => document.getElementById('lock').click();
  for (const id of ['create', 'restore', 'unlock-wallet']) document.getElementById(id).disabled = false;
  document.getElementById('wallet-boot-status').hidden = true;
} catch {
  document.getElementById('wallet-boot-status').textContent = 'Nodus Connect could not load. Reload this page to try again.';
}
