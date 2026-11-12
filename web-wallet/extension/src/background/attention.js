import { CHIME_GAP_MS } from '../../../src/connect/ui/alert.js';
import { debugLog, errorFields } from '../../../src/debug-log.js';

// What the extension shows when something needs the user: the toolbar badge, one system notification for waiting
// approvals and one for new messages, and what a click on either does. Approval and message state is read, never
// changed, except that a click asks the approval module to show its window.
const APPROVAL_ID = 'nodus-approval', MESSAGE_ID = 'nodus-messages';
const BADGE_APPROVAL = { text: '!', color: '#e8706a' }, BADGE_COUNT_COLOR = '#0376C9', BADGE_TEXT_COLOR = '#FFFFFF';
const BADGE_MAX_COUNT = 99, ICON = 'icons/nodus-128.png', CONNECT_PAGE = 'home.html?view=connect';

export function createAttention({ action, notifications, runtime, windows, tabs, messenger, approvals, getUnread, getUiState, showConnectIn, now = () => Date.now() }) {
  let destroyed = false, queued = false;
  // The approval notification is made once per spell: the time during which at least one approval waits.
  let inSpell = false;
  // The message rule: a notification only for growth of the unread total after the first check of an open session.
  let last = 0, primed = false, lastMessageAt = -Infinity, messageMayBeShown = true;
  let shownText, shownColor;

  const note = (event, error, fields = {}) => debugLog('attention', event, { ...errorFields(error), ...fields });
  // Every notification call is guarded: a refusal or a missing API is written as one debug line and never reaches the caller.
  function notify(call, ...args) {
    try {
      const result = notifications?.[call]?.(...args);
      if (typeof result?.catch === 'function') result.catch(error => note('notification-failed', error, { call }));
    } catch (error) { note('notification-failed', error, { call }); }
  }

  // The label: "!" for any waiting approval, else the unread messages, else empty.
  function updateBadge() {
    if (!action) return;
    const waiting = approvals.pendingCount() > 0;
    const count = waiting ? 0 : Math.max(0, Number(getUnread().count) || 0);
    const text = waiting ? BADGE_APPROVAL.text : count > 0 ? (count > BADGE_MAX_COUNT ? `${BADGE_MAX_COUNT}+` : String(count)) : '';
    const color = waiting ? BADGE_APPROVAL.color : BADGE_COUNT_COLOR;
    const textChanged = text !== shownText, colorChanged = text !== '' && color !== shownColor;
    if (!textChanged && !colorChanged) return;
    shownText = text; if (text !== '') shownColor = color;
    try {
      if (textChanged) action.setBadgeText({ text });
      if (colorChanged) {
        action.setBadgeBackgroundColor({ color });
        if (typeof action.setBadgeTextColor === 'function') action.setBadgeTextColor({ color: BADGE_TEXT_COLOR });
      }
    } catch (error) { note('badge-failed', error); }
  }

  function onApprovalChange() {
    if (destroyed) return;
    const pending = approvals.pendingCount();
    if (pending > 0 && !inSpell) {
      inSpell = true;
      // Tested once, at the start of the spell: with a toolbar popup open the popup shows the approval.
      if (getUiState().popupCount === 0) {
        notify('create', APPROVAL_ID, { type: 'basic', iconUrl: runtime.getURL(ICON), title: 'Approval requests are waiting',
          message: 'Open Nodus Connect to review them.', requireInteraction: true });
      }
    } else if (pending === 0 && inSpell) {
      inSpell = false; notify('clear', APPROVAL_ID);
    }
    updateBadge();
  }

  function checkMessages() {
    const { count, caughtUp } = getUnread();
    const n = Number.isSafeInteger(count) && count > 0 ? count : 0, caught = caughtUp === true;
    const grew = caught && primed && n > last;
    last = n; primed = caught;
    if (grew && getUiState().popupCount === 0 && now() - lastMessageAt >= CHIME_GAP_MS) {
      lastMessageAt = now(); messageMayBeShown = true;
      notify('create', MESSAGE_ID, { type: 'basic', iconUrl: runtime.getURL(ICON), title: 'Nodus Connect — new message',
        message: 'Open Nodus Connect to read it.', requireInteraction: true });
    }
    // An open session whose first check finished with nothing unread has nothing to announce. A closed session
    // (lock, restart) leaves the notification: its message is still in the saved history.
    if (caught && n === 0 && messageMayBeShown) { messageMayBeShown = false; notify('clear', MESSAGE_ID); }
  }

  // Connect changes arrive on every render of the worker's session; a synchronous burst is one recompute of the final state.
  function messagesChanged() {
    if (destroyed || queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      if (destroyed) return;
      try { updateBadge(); checkMessages(); } catch (error) { note('recompute-failed', error); }
    });
  }

  async function openConnect() {
    const [tabId] = getUiState().tabIds;
    if (tabId !== undefined) {
      try {
        showConnectIn(tabId);
        const tab = await tabs.update(tabId, { active: true });
        if (typeof tab?.windowId === 'number') await windows.update(tab.windowId, { focused: true });
        return;
      } catch (error) { note('focus-tab-failed', error); }
    }
    const url = runtime.getURL(CONNECT_PAGE);
    try { await tabs.create({ url }); }
    catch (error) { note('open-tab-failed', error); await windows.create({ url, focused: true }); }
  }

  async function onClicked(id) {
    if (id !== APPROVAL_ID && id !== MESSAGE_ID) return;
    try {
      if (id === APPROVAL_ID) await approvals.showWindow();
      else await openConnect();
    } catch (error) { note('click-failed', error, { id }); }
    if (id === MESSAGE_ID) messageMayBeShown = false;
    notify('clear', id);
  }

  messenger.subscribe('ApprovalController:stateChange', onApprovalChange);
  // A click can be the event that wakes a stopped worker: the worker's lazy listener buffers it until this call.
  const lazyListener = globalThis.chrome?.notifications === notifications && notifications?.onClicked && globalThis.stateHooks?.lazyListener;
  try {
    if (lazyListener) lazyListener.addListener('notifications', 'onClicked', onClicked);
    else notifications?.onClicked?.addListener(onClicked);
  } catch (error) { note('notification-failed', error, { call: 'onClicked.addListener' }); }
  // No approval survives a restart, so a notification left by an earlier worker is cleared; the message one is not.
  notify('clear', APPROVAL_ID);
  onApprovalChange();
  updateBadge();

  return {
    messagesChanged,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      messenger.unsubscribe('ApprovalController:stateChange', onApprovalChange);
      try { notifications?.onClicked?.removeListener(onClicked); }
      catch (error) { note('notification-failed', error, { call: 'onClicked.removeListener' }); }
      try { action?.setBadgeText({ text: '' }); } catch { /* the badge is only a hint */ }
    },
  };
}
