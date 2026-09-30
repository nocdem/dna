// Entry of the Messages preview page (/preview/, package NC-4c). As the
// wallet's src/main.js does: freeze ethers' pluggable RNG/KDF backends before
// any other code runs, then load the page code.
import { randomBytes, pbkdf2 } from 'ethers';
import './style.css';
randomBytes.lock(); pbkdf2.lock();
try {
  const { startMessages } = await import('./messages.js');
  startMessages();
  document.getElementById('nc-boot').hidden = true;
} catch {
  document.getElementById('nc-boot').textContent = 'Messages could not load. Reload this page to try again.';
}
