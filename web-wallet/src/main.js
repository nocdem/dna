import { Buffer } from 'buffer';
import { randomBytes, pbkdf2 } from 'ethers';
globalThis.Buffer = Buffer;
// Freeze ethers' pluggable RNG/KDF backends before the rest of the app runs, so
// no later code (this app's own or a compromised dependency) can register a
// replacement implementation. The vault's own PBKDF2 uses WebCrypto directly
// (src/vault.js), not this ethers helper, so locking it changes nothing here.
randomBytes.lock(); pbkdf2.lock();
try {
  await import('./app.js');
  for (const id of ['create', 'restore', 'unlock-wallet']) document.getElementById(id).disabled = false;
  document.getElementById('wallet-boot-status').hidden = true;
} catch {
  document.getElementById('wallet-boot-status').textContent = 'The wallet could not load. Reload this page to try again.';
}
