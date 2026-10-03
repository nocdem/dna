import { Buffer } from 'buffer';
import { randomBytes, pbkdf2 } from 'ethers';
globalThis.Buffer = Buffer;
// Freeze ethers' pluggable RNG/KDF backends before the rest of the app runs, so
// no later code (this app's own or a compromised dependency) can register a
// replacement implementation. The vault's own PBKDF2 uses WebCrypto directly
// (src/vault.js), not this ethers helper, so locking it changes nothing here.
randomBytes.lock(); pbkdf2.lock();
// The release shown on the page (package.json version, vite.config.js define).
for (const node of document.querySelectorAll('.app-version')) node.textContent = `Version ${__APP_VERSION__}`;
try {
  // Shared vaults (src/vaults/ui.js): the wallet page's one extension —
  // registered before src/app.js loads, so it hears the first unlock. No
  // Messages here: vaults live for the session and members are told from
  // Nodus Connect.
  const [{ registerExtension }, { mountVaults, vaultExtension }] = await Promise.all([import('./wallet-extensions.js'), import('./vaults/ui.js')]);
  mountVaults({ panelNode: document.getElementById('vault-panel'), rootNode: document.getElementById('vaults-root') });
  registerExtension(vaultExtension);
  await import('./app.js');
  for (const id of ['create', 'restore', 'unlock-wallet']) document.getElementById(id).disabled = false;
  document.getElementById('wallet-boot-status').hidden = true;
} catch {
  document.getElementById('wallet-boot-status').textContent = 'The wallet could not load. Reload this page to try again.';
}
