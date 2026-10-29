import { connectTrusted } from './trusted-port.js';
import { bindActivity } from './activity.js';
import { createWalletUi } from './wallet-ui.js';
import { actionButton, renderHome, renderReceive, renderConnect, renderSites, renderSettings } from './views.js';
import { renderEvmApproval, renderEvmSend } from './evm-screens.js';
import { renderNodusSend, renderNodusHistory, renderNodusContracts } from './nodus-screens.js';
import { renderNodusConnect, renderNodusSiteApproval } from './nodus-site-screens.js';
import { renderSolanaTronSend, renderSolanaTronHistory } from './solana-tron-screens.js';
import { NODUS_PERMISSION } from '../background/permissions.js';
import { createPhraseFields } from '../../../src/phrase-fields.js';
import { walletHeading } from './presentation.js';
import { autoLockBarText } from '../../../src/auto-lock.js';
import { WALLET_MARKUP } from './wallet-markup.js';
import { sessionLog, logPageErrors } from '../../../src/session-log.js';

// Approved plan §3.2/§3.6/§7: all three trusted pages use the same web-wallet UI modules.
export async function mountWalletPage({ document = globalThis.document, window = globalThis.window, client = connectTrusted(), renderOpenWallet, renderEntry } = {}) {
  const ui = createWalletUi(client), root = document.getElementById('screen');
  const navigation = document.getElementById('wallet-navigation'), status = document.getElementById('wallet-status');
  logPageErrors(window);
  if (renderEntry) { const boot = document.createElement('p'); boot.id = 'wallet-boot-status'; boot.className = 'hint'; boot.setAttribute('role', 'status'); boot.textContent = 'Loading wallet…'; root.replaceChildren(boot); }
  let page = 'home', receiveNetwork, fields, revealed, busy = false, disposed = false, revision = 0;
  let sendChain, sendReview, contractResult, stopSendReview;
  let portfolioText, openScreen;
  function updatePortfolio() {
    if (openScreen) { openScreen.update(); return; }
    if (!portfolioText) return;
    const summary = ui.portfolio();
    for (const key of ['label', 'total', 'status']) portfolioText[key].textContent = summary[key];
  }
  const isSolanaTron = chain => chain === 'solana' || chain === 'tron';
  const hasBalances = state => state && (state.evm || state.nodus || state.addresses?.solana || state.addresses?.tron);
  const cancelReview = () => sendChain === 'nodus' ? ui.cancelNodusSend(sendReview.id)
    : isSolanaTron(sendChain) ? ui.cancelSolanaTronSend(sendChain, sendReview.id) : ui.cancelEvmSend(sendReview.id);
  let idleTimer, entryDeadline = 0, walletDeadline = 0, refreshPending = false, publicState;
  const subscriptions = ['ApprovalController:stateChange', 'PermissionController:stateChange', 'EvmController:stateChange', 'NetworksController:stateChange'];
  function element(tag, text, className = '') {
    const node = document.createElement(tag); node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function showError(error) { status.textContent = error.message; status.className = 'field-error'; sessionLog.log('wallet', error, { error: true }); }
  function clearSensitive() {
    openScreen?.dispose(); openScreen = undefined;
    stopSendReview?.(); stopSendReview = undefined;
    revision++; fields?.clear(); fields = undefined; ui.clearPhrase();
    revealed?.replaceChildren(); revealed = undefined;
    for (const input of root.querySelectorAll('input')) input.value = '';
    entryDeadline = 0;
    if (sendReview) void cancelReview().catch(() => {});
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
    const previousNetworks = ui.state?.networks;
    let state = await ui.refresh();
    if (disposed) return;
    if (state.isUnlocked && page === 'chain-history' && previousNetworks &&
      previousNetworks[receiveNetwork] !== state.networks?.[receiveNetwork]) {
      await ui.loadSolanaTronHistory(receiveNetwork); state = ui.state;
      if (disposed) return;
    }
    const changed = publicState !== JSON.stringify(state);
    if (publicState && !state.isUnlocked && page !== 'phrase') { clearSensitive(); sessionLog.clear(); page = 'home'; }
    publicState = JSON.stringify(state);
    if (busy) { refreshPending ||= changed; updatePortfolio(); return; }
    if (changed) render();
    updatePortfolio();
    scheduleIdle();
    if (state.isUnlocked && hasBalances(state) && page === 'home') void loadBalances().catch(showError);
  }
  async function loadBalances(force = false) {
    if (openScreen?.loadBalances) { await openScreen.loadBalances(force); updatePortfolio(); return; }
    const reads = Promise.all([ui.state?.evm && ui.loadEvmBalances({ force }), ui.state?.nodus && ui.loadNodusBalances({ force }), ui.loadSolanaTronBalances({ force }), ui.loadPrices({ force })]);
    updatePortfolio();
    await reads;
    updatePortfolio();
    if (disposed || page !== 'home' || !ui.state?.isUnlocked) return;
    const nextState = JSON.stringify(ui.state);
    if (nextState === publicState) return;
    if (busy) { refreshPending = true; return; }
    publicState = nextState; render(); updatePortfolio();
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
        publicState = JSON.stringify(ui.state); if (renderAfter || !ui.state?.isUnlocked || refreshPending) render(); updatePortfolio(); scheduleIdle();
        if (ui.state?.isUnlocked && hasBalances(ui.state) && page === 'home') void loadBalances().catch(showError);
      }
      if (refreshPending) { refreshPending = false; void refresh().catch(showError); }
    }
  }
  function navigate(next, network) {
    if (busy) return;
    clearSensitive(); page = next; receiveNetwork = network; status.textContent = ''; render(); scheduleIdle();
    if (page === 'home' && hasBalances(ui.state)) void loadBalances().catch(showError);
    if (page === 'nodus-history') return run(() => ui.loadNodusHistory());
    if (page === 'chain-history') return run(() => ui.loadSolanaTronHistory(receiveNetwork));
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
    if (renderOpenWallet) { renderReferencePhrase(); return; }
    root.append(walletHeading(document, ui.phraseStep === 'backup' ? 'Back up your recovery phrase' : ui.phraseStep === 'verify' ? 'Verify your backup' : 'Import your recovery phrase'));
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
  function renderReferencePhrase() {
    const template = document.createElement('template'); template.innerHTML = WALLET_MARKUP;
    root.className = ''; root.replaceChildren(template.content.cloneNode(true));
    const $ = id => root.querySelector('#' + id);
    $('wallet-status').replaceWith(status);
    for (const id of ['wallet-boot-status', 'welcome', 'unlock-form', 'wallet-open']) $(id).hidden = true;
    const form = $('phrase-form'), isBackup = ui.phraseStep === 'backup'; form.hidden = false;
    fields = createPhraseFields($('phrase-grid'), $('phrase-error'));
    fields.set('', isBackup, { allowPaste: ui.phraseStep !== 'verify' });
    $('phrase-label').textContent = isBackup ? 'Write down your 24-word recovery phrase privately' : ui.phraseStep === 'verify' ? 'Re-enter your saved recovery phrase' : 'Enter your 24-word Nodus recovery phrase';
    $('phrase-help').textContent = 'Keep an offline backup. Your recovery phrase is saved encrypted in this browser. This screen clears after 10 minutes of inactivity.';
    $('skip-verify-row').hidden = !isBackup;
    if (ui.phraseStep === 'verify') $('phrase-entry-help').textContent = 'Type each word from your written backup; pasting is disabled here.';
    const password = passwordInput(form, 'new-password', 'Local password', 'new-password', 16);
    const confirmation = passwordInput(form, 'confirm-password', 'Confirm password', 'new-password', 16);
    // A normal backup proceeds to verification; the explicit skip also needs
    // the extension's mandatory saved-vault password before it can continue.
    const passwordVisibility = () => {
      password.required = confirmation.required = !isBackup || $('skip-verify').checked;
      password.hidden = confirmation.hidden = !password.required;
      for (const input of [password, confirmation]) form.querySelector(`label[for="${input.id}"]`).hidden = input.hidden;
      $('phrase-submit').textContent = isBackup ? $('skip-verify').checked ? 'I saved it — open wallet' : 'I saved the words — verify backup' : 'Save and unlock';
    };
    $('skip-verify').onchange = passwordVisibility; passwordVisibility();
    const warning = document.createElement('template');
    warning.innerHTML = '<dialog id="skip-verify-dialog" aria-labelledby="skip-verify-title" aria-describedby="skip-verify-text"><h2 id="skip-verify-title">Skip checking your recovery words?</h2><div id="skip-verify-text"><p class="notice">You have not checked your saved copy of the 24 words.</p><p>If that copy has a mistake or a missing word, or if you lose it, this wallet and its funds cannot be restored. Nobody, including Nodus, can recover them for you.</p></div><div class="actions"><button id="skip-verify-back" type="button" class="secondary" autofocus>Go back</button><button id="skip-verify-yes" type="button">Yes, skip checking</button></div></dialog>';
    root.append(warning.content.cloneNode(true));
    $('skip-verify-back').onclick = () => $('skip-verify-dialog').close();
    const save = skip => run(async () => {
      let entered = password.value, repeated = confirmation.value, phrase;
      password.value = confirmation.value = '';
      try {
        if (skip) await ui.skipVerification(entered, repeated);
        else { phrase = fields.read(); await ui.savePhrase(phrase, entered, repeated); }
        fields?.clear(); page = 'home';
      } finally { entered = repeated = phrase = null; }
    });
    $('skip-verify-yes').onclick = () => {
      $('skip-verify-dialog').close();
      if (ui.phraseStep === 'backup' && $('skip-verify').checked) return save(true);
    };
    $('phrase-cancel').onclick = () => navigate('home');
    form.onsubmit = event => {
      event.preventDefault();
      if (isBackup) {
        if ($('skip-verify').checked) { $('skip-verify-dialog').showModal(); return; }
        ui.confirmBackup(); fields.clear(); fields = undefined; render(); scheduleIdle(true); return;
      }
      return save(false);
    };
    if (ui.phraseStep === 'verify') fields.focus();
    else { $('recovery-warning-title').focus({ preventScroll: true }); $('recovery-warning').scrollIntoView({ block: 'start' }); }
  }
  function render() {
    if (disposed || !ui.state) return;
    const state = ui.state;
    const pending = Object.values(state.pendingApprovals || {})[0];
    if (renderOpenWallet && state.isUnlocked && !pending && !(page === 'phrase' && ui.phraseStep)) {
      if (openScreen) { openScreen.update(); return; }
      fields?.clear(); fields = undefined; revealed?.replaceChildren(); revealed = undefined;
      root.replaceChildren(); navigation.replaceChildren();
      openScreen = renderOpenWallet({ document, window, root, status, ui, run, loadBalances,
        lock: () => run(async () => { clearSensitive(); sessionLog.clear(); page = 'home'; await ui.lock(); }),
        setAutoLock: minutes => run(async () => { await ui.setAutoLock(minutes); walletDeadline = 0; }),
        clearReveal: () => { revealed?.replaceChildren(); revealed = undefined; entryDeadline = 0; },
        reveal: (password, container) => {
          const started = revision;
          return run(async () => {
            let phrase;
            try {
              phrase = await ui.revealPhrase(password); password = null;
              if (disposed || started !== revision) return;
              container.hidden = false;
              const grid = element('div', undefined, 'phrase-grid'), error = element('p', '', 'field-error');
              container.replaceChildren(grid, error);
              const display = createPhraseFields(grid, error); display.set(phrase, true); revealed = container; scheduleIdle(true);
            } finally { phrase = password = null; }
          }, { renderAfter: false });
        },
      });
      return;
    }
    openScreen?.dispose(); openScreen = undefined;
    root.className = renderOpenWallet ? 'card wallet-card' : '';
    // A public-state notification never replaces a recovery form that the user is filling.
    if (page === 'phrase' && fields && ui.phraseStep && root.querySelector('.phrase-grid')) return;
    stopSendReview?.(); stopSendReview = undefined;
    fields?.clear(); fields = undefined; revealed?.replaceChildren(); revealed = undefined;
    root.replaceChildren(); navigation.replaceChildren();
    portfolioText = undefined;
    if (sendReview?.network && sendReview.network !== state.networks?.[sendChain]) {
      void cancelReview().catch(() => {}); sendReview = undefined;
    }
    if (state.isUnlocked) {
      const home = page === 'home' && !pending;
      navigation.className = home ? 'extension-home-header' : 'extension-navigation';
      const session = element('div', undefined, home ? 'wallet-session' : 'extension-page-actions');
      if (home) {
        navigation.append(walletHeading(document, 'Your wallet'));
        const open = element('div');
        open.append(element('span', undefined, 'session-indicator'), element('span', 'Wallet open in this browser'));
        open.append(element('span', autoLockBarText(state.preferences.autoLockTimeLimit), 'session-timeout'));
        session.append(open);
      } else {
        const back = actionButton(document, 'Home', () => navigate('home')); back.className += ' page-back'; session.append(back);
      }
      session.append(actionButton(document, 'Lock', () => run(async () => { clearSensitive(); sessionLog.clear(); page = 'home'; await ui.lock(); })));
      navigation.append(session);
    }
    if (page === 'phrase' && ui.phraseStep) { renderPhrase(); return; }
    if (renderEntry && !state.isUnlocked) {
      renderEntry({ document, root, status, state, ui, run,
        create: () => { clearSensitive(); const phrase = ui.beginCreate(); page = 'phrase'; render(); fields.set(phrase, true); scheduleIdle(true); },
        restore: () => { clearSensitive(); ui.beginImport(); page = 'phrase'; render(); if (!renderOpenWallet) fields.focus(); scheduleIdle(true); },
        unlock: password => run(async () => { await ui.unlock(password); page = 'home'; }),
      });
      return;
    }
    if (!state.isInitialized) {
      root.append(walletHeading(document, 'Your Nodus wallet'), element('p', 'Create a new 24-word recovery phrase or import your existing phrase.'));
      const actions = element('div', undefined, 'actions');
      actions.append(actionButton(document, 'Create wallet', () => {
        clearSensitive(); const phrase = ui.beginCreate(); page = 'phrase'; render(); fields.set(phrase, true); scheduleIdle(true);
      }, false), actionButton(document, 'Import phrase', () => { clearSensitive(); ui.beginImport(); page = 'phrase'; render(); fields.focus(); scheduleIdle(true); }));
      root.append(actions);
      const networks = element('div', undefined, 'wallet-network-list'); networks.setAttribute('aria-label', 'Wallet networks');
      for (const [index, symbol] of ['NODUS', 'ETH', 'BNB', 'SOL', 'TRX'].entries()) networks.append(element('span', symbol, index === 0 ? 'native-network' : ''));
      root.append(networks); return;
    }
    if (!state.isUnlocked) {
      root.append(walletHeading(document, 'Unlock your wallet'));
      const form = element('form'), password = passwordInput(form, 'unlock-password', 'Password', 'current-password', 12);
      const submit = element('button', 'Unlock'); submit.type = 'submit'; form.append(submit); root.append(form);
      form.onsubmit = event => { event.preventDefault(); return run(async () => { const entered = password.value; password.value = ''; await ui.unlock(entered); page = 'home'; }); };
      return;
    }
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
    if (page === 'contracts') stopSendReview = renderNodusContracts(document, root, { account: state.addresses.nodus, readable: state.nodus.evmReadable,
      buildable: state.nodus.evmBuildable, result: contractResult, review: sendReview }, {
      read: fields => run(async () => { contractResult = await ui.readNodusContract(fields); }),
      prepare: fields => run(async () => { sendReview = await ui.prepareNodusContract(fields); }),
      confirm: confirmNodus, cancel: () => navigate('contracts'),
    });
    else if (page === 'send' && sendChain === 'nodus') stopSendReview = renderNodusSend(document, root, { account: state.addresses.nodus, tokens: state.nodus.tokens, review: sendReview }, {
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
    else if (page === 'chain-history') renderSolanaTronHistory(document, root, { chain: receiveNetwork, history: state.solanaTronHistory[receiveNetwork] }, {
      refresh: () => run(() => ui.loadSolanaTronHistory(receiveNetwork, { manual: true })),
    });
    else if (page === 'send' && isSolanaTron(sendChain)) stopSendReview = renderSolanaTronSend(document, root, { chain: sendChain, account: state.addresses[sendChain], review: sendReview, network: state.networks?.[sendChain] }, {
      prepare: request => run(async () => { sendReview = await ui.prepareSolanaTronSend(request); }),
      confirm: id => run(async () => {
        // src/app.js:2346-2413: close the consumed review on every outcome,
        // track ambiguity only when a signed local record actually exists.
        sendReview = undefined;
        try {
          const hash = await ui.confirmSolanaTronSend(sendChain, id); page = 'home';
          status.className = 'hint'; status.textContent = `Broadcast submitted; confirmation is pending. Transaction ID ${hash}.`;
          await ui.loadSolanaTronBalances({ force: true });
        } catch (error) {
          const note = error.data?.activityTracked ? ' A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.' : '';
          throw new Error(`${error.message}${note}`);
        }
      }),
      cancel: () => navigate('home'),
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
      setChainNetwork: (chain, network) => run(() => ui.setChainNetwork(chain, network)),
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
    else portfolioText = renderHome(document, root, { ...state, portfolio: ui.portfolio() }, network => navigate('receive', network), chain => {
      sendChain = chain; navigate('send');
    }, () => run(() => loadBalances(true)), () => navigate('nodus-history'), () => { sendChain = 'nodus'; navigate('contracts'); }, chain => navigate('chain-history', chain), [
      { label: 'Connected sites', icon: 'sites', run: () => navigate('sites') },
      { label: 'Settings', icon: 'settings', run: () => navigate('settings') },
    ]);
  }
  const unbindActivity = bindActivity(document, client, () => {
    scheduleIdle(true);
    // Re-read the background while using an open wallet (including another window's manual lock).
    // Locked password and recovery forms retain their entered values until their explicit action or timeout.
    if (ui.state?.isUnlocked) void refresh().catch(showError);
  }, showError);
  const removeNotification = client.onNotification(message => { if (['messengerSubscription', 'walletStateChanged'].includes(message.method)) void refresh().catch(showError); });
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
  catch (error) { const boot = root.querySelector('#wallet-boot-status'); if (boot) { boot.hidden = false; boot.textContent = 'The wallet could not load. Reload this page to try again.'; } showError(error); }
  return { refresh, dispose };
}
