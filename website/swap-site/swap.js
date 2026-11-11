// Connects swap.nodusnetwork.io to the Nodus Connect extension (operator 2026-11-10, givens item 62:
// "sadece extansion ile olucak simdilik"). Discovery follows the extension's own site connector
// (web-wallet/extension/site-sdk/index.mjs:20-42): EIP-6963, rdns io.nodusnetwork.wallet, name "Nodus Wallet".
// Only account requests are sent here; nothing is signed or sent.
(() => {
  const button = document.getElementById('connect-btn');
  const status = document.getElementById('connect-status');
  const nodusAddr = document.getElementById('nodus-addr');
  const EXT_PAGE = 'https://nodusnetwork.io/extension.html';
  const short = value => value.length > 14 ? `${value.slice(0, 6)}…${value.slice(-4)}` : value;
  const say = text => { status.textContent = text; status.hidden = !text; };
  let found = null;
  window.addEventListener('eip6963:announceProvider', event => {
    const detail = event.detail;
    if (detail?.info?.rdns === 'io.nodusnetwork.wallet' && detail.info.name === 'Nodus Wallet' &&
        typeof detail.provider?.request === 'function') found = detail.provider;
  });
  window.dispatchEvent(new Event('eip6963:requestProvider'));
  const waitForProvider = () => new Promise(resolve => {
    if (found) return resolve(found);
    window.dispatchEvent(new Event('eip6963:requestProvider'));
    setTimeout(() => resolve(found), 800);
  });
  button.addEventListener('click', async () => {
    say('');
    const provider = await waitForProvider();
    if (!provider) {
      say('The Nodus Connect extension was not found in this browser.');
      button.textContent = 'Get the extension'; button.onclick = () => { location.href = EXT_PAGE; };
      return;
    }
    button.disabled = true; button.textContent = 'Connecting…';
    try {
      const nodus = await provider.request({ method: 'nodus_requestAccounts' });
      const eth = await provider.request({ method: 'eth_requestAccounts' });
      const n = Array.isArray(nodus) && nodus[0]?.address, e = Array.isArray(eth) && eth[0];
      if (!n || !e) throw new Error('no account');
      button.textContent = `${short(n)} · ${short(e)}`; button.title = `Nodus ${n}\nEthereum ${e}`;
      nodusAddr.textContent = short(n); nodusAddr.title = n;
      say('Connected to Nodus Connect. Swaps open when the swap service starts.');
    } catch (error) {
      button.disabled = false; button.textContent = 'Connect extension';
      if (error?.code === 4001) say('The connection was rejected in the extension.');
      else if (error?.code === 4100) say('Open the extension and accept its data notice first, then connect again.');
      else say('The extension did not connect. Unlock it and try again.');
    }
  });
})();
