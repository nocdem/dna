import { Buffer } from 'buffer';
globalThis.Buffer = Buffer;
try {
  await import('./app.js');
  for (const id of ['create', 'restore', 'unlock-wallet']) document.getElementById(id).disabled = false;
  document.getElementById('wallet-boot-status').hidden = true;
} catch {
  document.getElementById('wallet-boot-status').textContent = 'The wallet could not load. Reload this page to try again.';
}
