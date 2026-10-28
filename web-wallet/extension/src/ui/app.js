import { connectTrusted } from './trusted-port.js';
import { bindActivity } from './activity.js';
import { createWalletUi } from './wallet-ui.js';
import { actionButton, renderHome, renderReceive, renderConnect, renderSites, renderSettings } from './views.js';
import { renderEvmApproval, renderEvmSend } from './evm-screens.js';
import { renderNodusSend, renderNodusHistory, renderNodusContracts } from './nodus-screens.js';
import { renderNodusConnect, renderNodusSiteApproval } from './nodus-site-screens.js';
import { NODUS_PERMISSION } from '../background/permissions.js';
import { createPhraseFields } from '../../../src/phrase-fields.js';

// Approved plan §3.2/§3.6/§7: all three trusted pages use the same web-wallet UI modules.
export async function mountWalletPage({ document = globalThis.document, window = globalThis.window, client = connectTrusted() } = {}) {
  const ui = createWalletUi(client), root = document.getElementById('screen');
  const navigation = document.getElementById('wallet-navigation'), status = document.getElementById('wallet-status');
  let page = 'home', receiveNetwork, fields, revealed, busy = false, disposed = false, revision = 0;
  let sendChain, sendReview, contractResult, stopNodusReview;
  let idleTimer, entryDeadline = 0, walletDeadline = 0, refreshPending = false, publicState;
  const subscriptions = ['ApprovalController:stateChange', 'PermissionController:stateChange', 'EvmController:stateChange'];
  function element(tag, text, className = '') {
    const node = document.createElement(tag); node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function showError(error) { status.textContent = error.message; status.className = 'field-error'; }
  function clearSensitive() {
    stopNodusReview?.(); stopNodusReview = undefined;
    revision++; fields?.clear(); fields = undefined; ui.clearPhrase();
    revealed?.replaceChildren(); revealed = undefined;
    for (const input of root.querySelectorAll('input')) input.value = '';
    entryDeadline = 0;
    if (sendReview) void (sendChain === 'nodus' ? ui.cancelNodusSend(sendReview.id) : ui.cancelEvmSend(sendReview.id)).catch(() => {});
    sendReview = undefined;
    contractResult = undefined;
  }
  function hasEntry() { return ui.phraseStep || revealed || [...root.querySelectorAll('input[type="password"]')].some(input => input.value); }
  // Web wallet app.js:885-903: a fixed ten minutes for recovery words/passwords, independently of auto-lock.
  // The wallet alarm belongs to the background. This timeout only clears sensitive DOM and reads its current lock state.
  function scheduleIdle(activity = false) {
    clearTimeout(idleTimer);
    if (disposed) return;
    const now = Date.now(), minutes = ui.state?.preferences.autoLockTimeLimit ?? 0;
    if (hasEntry() && (activity || !entryDeadline)) entryDeadline = now + 10 * 60_000;
    if (!hasEntry()) entryDeadline = 0;
    if (ui.state?.isUnlocked && minutes && (activity || !walletDeadline)) walletDeadline = now + minutes * 60_000;
    if (!ui.state?.isUnlocked || !minutes) walletDeadline = 0;
    const deadlines = [entryDeadline, walletDeadline].filter(Boolean);
    if (deadlines.length) idleTimer = setTimeout(() => {
      if (entryDeadline && Date.now() >= entryDeadline) { clearSensitive(); page = 'home'; render(); }
      walletDeadline = 0;
      void refresh().catch(showError);
    }, Math.max(0, Math.min(...deadlines) - now));
  }
  async function refresh() {
    const state = await ui.refresh();
    if (disposed) return;
    const changed = publicState !== JSON.stringify(state);
    if (publicState && !state.isUnlocked && page !== 'phrase') { clearSensitive(); page = 'home'; }
    publicState = JSON.stringify(state);
    if (busy) { refreshPending ||= changed; return; }
    if (changed) render();
    scheduleIdle();
    if (state.isUnlocked && (state.evm || state.nodus) && page === 'home') void loadBalances().catch(showError);
  }
  async function loadBalances(force = false) {
    await Promise.all([ui.state?.evm && ui.loadEvmBalances({ force }), ui.state?.nodus && ui.loadNodusBalances({ force })]);
    if (disposed || page !== 'home' || !ui.state?.isUnlocked) return;
    if (busy) { refreshPending = true; return; }
    publicState = JSON.stringify(ui.state); render();
  }
  async function run(action, { renderAfter = true } = {}) {
    if (busy || disposed) return;
    busy = true; root.inert = navigation.inert = true; status.textContent = '';
    try { await action(); }
    catch (error) { showError(error); }
    finally {
      try { await ui.refresh(); } catch (error) { showError(error); }
      busy = false; root.inert = navigation.inert = false;
      if (!disposed) {
        publicState = JSON.stringify(ui.state); if (renderAfter || !ui.state?.isUnlocked || refreshPending) render(); scheduleIdle();
        if (ui.state?.isUnlocked && (ui.state.evm || ui.state.nodus) && page === 'home') void loadBalances().catch(showError);
      }
      if (refreshPending) { refreshPending = false; void refresh().catch(showError); }
    }
  }
  function navigate(next, network) {
    if (busy) return;
    clearSensitive(); page = next; receiveNetwork = network; status.textContent = ''; render(); scheduleIdle();
    if (page === 'home' && (ui.state?.evm || ui.state?.nodus)) void loadBalances().catch(showError);
    if (page === 'nodus-history') return run(() => ui.loadNodusHistory());
  }
  function passwordInput(form, id, label, autocomplete, minimum) {
    const caption = element('label', label), input = element('input');
    caption.htmlFor = input.id = id; input.type = 'password'; input.autocomplete = autocomplete;
    input.required = true; input.minLength = minimum; input.maxLength = 1024;
    form.append(caption, input); return input;
  }
  function confirmNodus(id) {
    return run(async () => {
      const contractReview = page === 'contracts', review = sendReview;
      sendReview = undefined;
      try {
        const hash = await ui.confirmNodusSend(id); page = 'home';
        status.className = 'hint'; status.textContent = `Transaction submitted; confirmation is pending. Transfer ID ${hash}.`;
        await ui.loadNodusBalances({ force: true });
      } catch (error) {
        if (contractReview) {
          // src/evm/ui.js:154-161: show the error in the review with Close.
          sendReview = { ...review, error: error.message || 'Sending failed.' }; return;
        }
        // src/app.js:2389-2412: close the review, keep the send page and show
        // the original error; only a recorded send gets the Activity note.
        const note = error.data?.activityTracked ? ' The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.' : '';
        throw new Error(`${error.message}${note}`);
      }
    });
  }
  function renderPhrase() {
    root.append(element('h1', ui.phraseStep === 'backup' ? 'Back up your recovery phrase' : ui.phraseStep === 'verify' ? 'Verify your backup' : 'Import your recovery phrase'));
    root.append(element('p', 'Keep a private offline backup of all 24 words. This screen clears after 10 minutes without use.', 'phrase-caution'));
    const form = element('form'), error = element('p', '', 'field-error'), grid = element('div', undefined, 'phrase-grid');
    form.append(grid, error); fields = createPhraseFields(grid, error);
    const isBackup = ui.phraseStep === 'backup';
    // beginCreate's generated phrase was set on this renderer's fields by the create action below.
    fields.set('', isBackup, { allowPaste: ui.phraseStep !== 'verify' });
    let password, confirmation;
    if (!isBackup) {
      root.append(element('p', ui.phraseStep === 'verify' ? 'Type each word from your written backup; pasting is disabled here.' : 'Enter or paste your 24-word recovery phrase.', 'hint'));
      password = passwordInput(form, 'new-password', 'Local password', 'new-password', 16);
      confirmation = passwordInput(form, 'confirm-password', 'Confirm password', 'new-password', 16);
      form.append(element('p', 'Use a unique password of 16–1024 characters. Your recovery phrase is saved encrypted in this browser.', 'hint'));
    }
    const submit = element('button', isBackup ? 'I saved the words — verify backup' : 'Save and unlock'); submit.type = 'submit';
    form.append(submit, actionButton(document, 'Cancel', () => navigate('home'))); root.append(form);
    form.onsubmit = event => {
      event.preventDefault();
      if (isBackup) { ui.confirmBackup(); fields.clear(); fields = undefined; render(); scheduleIdle(true); return; }
      return run(async () => {
        let phrase = fields.read(), entered = password.value, repeated = confirmation.value;
        password.value = confirmation.value = '';
        try { await ui.savePhrase(phrase, entered, repeated); fields?.clear(); page = 'home'; }
        finally { phrase = entered = repeated = null; }
      });
    };
  }
  function render() {
    if (disposed || !ui.state) return;
    // A public-state notification never replaces a recovery form that the user is filling.
    if (page === 'phrase' && fields && ui.phraseStep && root.querySelector('.phrase-grid')) return;
    stopNodusReview?.(); stopNodusReview = undefined;
    fields?.clear(); fields = undefined; revealed?.replaceChildren(); revealed = undefined;
    root.replaceChildren(); navigation.replaceChildren();
    const state = ui.state;
    if (state.isUnlocked) {
      for (const [label, next] of [['Home', 'home'], ['Connected sites', 'sites'], ['Settings', 'settings']]) navigation.append(actionButton(document, label, () => navigate(next)));
      navigation.append(actionButton(document, 'Lock', () => run(async () => { clearSensitive(); page = 'home'; await ui.lock(); })));
    }
    if (page === 'phrase' && ui.phraseStep) { renderPhrase(); return; }
    if (!state.isInitialized) {
      root.append(element('h1', 'Your Nodus wallet'), element('p', 'Create a new 24-word recovery phrase or import your existing phrase.'));
      const actions = element('div', undefined, 'actions');
      actions.append(actionButton(document, 'Create wallet', () => {
        clearSensitive(); const phrase = ui.beginCreate(); page = 'phrase'; render(); fields.set(phrase, true); scheduleIdle(true);
      }, false), actionButton(document, 'Import phrase', () => { clearSensitive(); ui.beginImport(); page = 'phrase'; render(); fields.focus(); scheduleIdle(true); }));
      root.append(actions); return;
    }
    if (!state.isUnlocked) {
      root.append(element('h1', 'Unlock your wallet'));
      const form = element('form'), password = passwordInput(form, 'unlock-password', 'Password', 'current-password', 12);
      const submit = element('button', 'Unlock'); submit.type = 'submit'; form.append(submit); root.append(form);
      form.onsubmit = event => { event.preventDefault(); return run(async () => { const entered = password.value; password.value = ''; await ui.unlock(entered); page = 'home'; }); };
      return;
    }
    const pending = Object.values(state.pendingApprovals || {})[0];
    if (pending) {
      if (pending.type === 'nodus_signMessage') {
        renderNodusSiteApproval(document, root, pending, {
          approve: request => run(() => ui.approveNodusMessage(request)), reject: request => run(() => ui.rejectNodusMessage(request)),
        });
      } else if (pending.requestData?.permissions?.[NODUS_PERMISSION] && Object.keys(pending.requestData.permissions).length === 1) {
        renderNodusConnect(document, root, state, pending, {
          approve: request => run(() => ui.approveNodusConnect(request)), reject: request => run(() => ui.rejectConnect(request)),
        });
      } else if (['personal_sign', 'eth_signTypedData', 'transaction', 'wallet_switchEthereumChain'].includes(pending.type)) {
        renderEvmApproval(document, root, pending, {
          approve: request => run(() => ui.approveEvm(request)), reject: request => run(() => ui.rejectEvm(request)),
        });
      } else renderConnect(document, root, state, pending, {
          approve: (...args) => run(() => ui.approveConnect(...args)), reject: request => run(() => ui.rejectConnect(request)),
        });
      return;
    }
    if (page === 'contracts') stopNodusReview = renderNodusContracts(document, root, { account: state.addresses.nodus, readable: state.nodus.evmReadable,
      buildable: state.nodus.evmBuildable, result: contractResult, review: sendReview }, {
      read: fields => run(async () => { contractResult = await ui.readNodusContract(fields); }),
      prepare: fields => run(async () => { sendReview = await ui.prepareNodusContract(fields); }),
      confirm: confirmNodus, cancel: () => navigate('contracts'),
    });
    else if (page === 'send' && sendChain === 'nodus') stopNodusReview = renderNodusSend(document, root, { account: state.addresses.nodus, tokens: state.nodus.tokens, review: sendReview }, {
      prepare: request => run(async () => { sendReview = await ui.prepareNodusSend(request); }),
      confirm: confirmNodus,
      cancel: () => navigate('home'),
    });
    else if (page === 'nodus-history') renderNodusHistory(document, root, state.nodusHistory, {
      refresh: () => run(() => ui.loadNodusHistory()),
      resubmit: hash => run(async () => {
        const result = await ui.resubmitNodusSend(hash); await ui.loadNodusHistory();
        status.className = 'hint'; status.textContent = result.message || (result.outcome === 'sent' ? 'Broadcast submitted; awaiting confirmation.' : result.outcome);
      }),
    });
    else if (page === 'send') renderEvmSend(document, root, { chain: sendChain, account: state.addresses[sendChain], review: sendReview }, {
      prepare: request => run(async () => { sendReview = await ui.prepareEvmSend(request); }),
      confirm: id => run(async () => {
        const hash = await ui.confirmEvmSend(id); sendReview = undefined; page = 'home';
        status.className = 'hint'; status.textContent = `Transaction sent: ${hash}`; await ui.loadEvmBalances({ force: true });
      }),
      cancel: () => navigate('home'),
    });
    else if (page === 'receive') renderReceive(document, root, receiveNetwork, state.addresses, address => run(async () => { await window.navigator.clipboard.writeText(address); status.className = 'hint'; status.textContent = 'Address copied.'; }));
    else if (page === 'sites') renderSites(document, root, state, origin => run(() => ui.revoke(origin)));
    else if (page === 'settings') renderSettings(document, root, state, {
      discardActivity: () => run(async () => {
        const message = await ui.discardNodusActivity();
        status.className = 'hint'; status.textContent = message ?? '';
      }),
      setAutoLock: minutes => run(async () => { await ui.setAutoLock(minutes); walletDeadline = 0; }),
      selectEvmNetwork: chain => run(() => ui.selectEvmNetwork(chain)),
      setEvmEndpoint: (chain, endpoint) => run(() => ui.setEvmEndpoint(chain, endpoint)),
      reveal: (password, container) => {
        const started = revision;
        return run(async () => {
          let phrase;
          try {
            phrase = await ui.revealPhrase(password); password = null;
            if (disposed || started !== revision) return;
            container.hidden = false;
            const grid = element('div', undefined, 'phrase-grid'), error = element('p', '', 'field-error');
            container.replaceChildren(grid, error); createPhraseFields(grid, error).set(phrase, true); revealed = container; scheduleIdle(true);
          } finally { phrase = password = null; }
        }, { renderAfter: false });
      },
    });
    else renderHome(document, root, state, network => navigate('receive', network), chain => {
      sendChain = chain; navigate('send');
    }, () => run(() => loadBalances(true)), () => navigate('nodus-history'), () => { sendChain = 'nodus'; navigate('contracts'); });
  }
  const unbindActivity = bindActivity(document, client, () => {
    scheduleIdle(true);
    // Re-read the background while using an open wallet (including another window's manual lock).
    // Locked password and recovery forms retain their entered values until their explicit action or timeout.
    if (ui.state?.isUnlocked) void refresh().catch(showError);
  }, showError);
  const removeNotification = client.onNotification(message => { if (message.method === 'messengerSubscription') void refresh().catch(showError); });
  const removeDisconnect = client.onDisconnect(() => { dispose(); root.replaceChildren(); navigation.replaceChildren(); showError(new Error('Wallet background disconnected. Reopen this wallet page.')); });
  const onFocus = () => { void refresh().catch(showError); };
  const onVisible = () => { if (!document.hidden) onFocus(); };
  function dispose() {
    if (disposed) return;
    disposed = true; clearSensitive(); clearTimeout(idleTimer); unbindActivity(); removeNotification(); removeDisconnect();
    window.removeEventListener('focus', onFocus); document.removeEventListener('visibilitychange', onVisible); window.removeEventListener('pagehide', dispose);
    for (const event of subscriptions) void client.request('messengerUnsubscribe', [event]).catch(() => {});
    client.close();
  }
  window.addEventListener('focus', onFocus); document.addEventListener('visibilitychange', onVisible); window.addEventListener('pagehide', dispose);
  try { for (const event of subscriptions) await client.request('messengerSubscribe', [event]); await refresh(); }
  catch (error) { showError(error); }
  return { refresh, dispose };
}

if (globalThis.document && globalThis.chrome?.runtime) void mountWalletPage();
