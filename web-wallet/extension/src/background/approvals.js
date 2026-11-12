import { ApprovalController } from '@metamask/approval-controller';
import { providerErrors } from '@metamask/rpc-errors';
import { ApprovalType } from '@metamask/controller-utils';
import { SWAP_METHOD_NAMES, SWAP_PAYMENT_APPROVAL } from '../constants/swap.js';

// Port: MetaMask v13.54.0 app/scripts/lib/createOriginThrottlingMiddleware.ts:14-43.
// The swap methods join the list (plan section 18 change 1 leaves the throttled-method list to this build): a site
// that is refused three times in 30 s is blocked for 60 s on them, as on the signing methods above.
const BLOCKABLE_METHODS = new Set([
  'wallet_addEthereumChain', 'eth_sendTransaction', 'eth_signTypedData', 'eth_signTypedData_v1',
  'eth_signTypedData_v3', 'eth_signTypedData_v4', 'personal_sign', 'wallet_switchEthereumChain',
  'wallet_sendCalls', 'wallet_watchAsset', 'nodus_signMessage', ...SWAP_METHOD_NAMES,
]);
const TEST_ORIGINS = ['http://127.0.0.1:8080', 'http://127.0.0.1:8081', 'http://127.0.0.1:8082',
  'http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'];

const BADGE_COLOR_APPROVAL = '#0376C9';
const BADGE_MAX_COUNT = 9;
export const badgeLabel = (count, maxCount = BADGE_MAX_COUNT) => (count > maxCount ? `${maxCount}+` : String(count));

export function createApprovals({ messenger, runtime, windows, tabs, action, platform, getUiState = () => ({ popupCount: 0, tabIds: new Set() }) }) {
  // Port: app/scripts/platforms/extension.ts:52-59, 198-199; named platform boundary retained.
  platform ??= {
    openWindow: options => windows.create({ ...options, url: runtime.getURL(options.url) }),
    focusWindow: id => windows.update(id, { focused: true }),
    updateWindowPosition: (id, left, top) => windows.update(id, { left, top }),
    getAllWindows: () => windows.getAll(),
    getLastFocusedWindow: () => windows.getLastFocused(),
  };
  let popupId, uiOpening = null;
  const throttledOrigins = new Map();

  // Port: app/scripts/lib/notification-manager.ts:70-125, 146-163.
  async function showPopup() {
    const popup = (await platform.getAllWindows()).find(win => win.type === 'popup' && win.id === popupId);
    if (popup && typeof popup.id === 'number') return platform.focusWindow(popup.id);
    let left = 0, top = 0;
    try {
      const lastFocused = await platform.getLastFocusedWindow();
      top = lastFocused.top ?? 0;
      left = Math.max((lastFocused.left ?? 0) + ((lastFocused.width ?? 0) - 400), 0);
    } catch {
      // Port: notification-manager.ts:96-102, retaining its screen-coordinate fallback.
      const { screenX, screenY, outerWidth } = window;
      top = Math.max(screenY, 0);
      left = Math.max(screenX + (outerWidth - 400), 0);
    }
    const size = { url: 'notification.html', type: 'popup', width: 400, height: 620 };
    let popupWindow, placedByBrowser = false;
    try { popupWindow = await platform.openWindow({ ...size, left, top }); }
    catch {
      // The browser refuses a position that is not within the visible screen space; without left and top it places
      // the window itself, so the approval still gets a window. A second failure reaches the caller as before.
      popupWindow = await platform.openWindow(size); placedByBrowser = true;
    }
    // Port: notification-manager.ts:114-121; extension.ts:62-68 provides the platform operation.
    // A window the browser placed keeps its place: asking for the refused position again would fail again.
    if (!placedByBrowser && typeof popupWindow.id === 'number' && popupWindow.left !== left && popupWindow.state !== 'fullscreen') {
      await platform.updateWindowPosition(popupWindow.id, left, top);
    }
    popupId = popupWindow.id;
  }

  // Port: app/scripts/background.ts:1050-1101; plan §3.2:204-212 removes side-panel/Vivaldi.
  function triggerUi() {
    if (uiOpening) return uiOpening;
    uiOpening = (async () => {
      const { popupCount, tabIds } = getUiState();
      if (popupCount > 0) return;
      if (tabIds.size && tabs) {
        const activeTabs = await tabs.query({ active: true });
        if (activeTabs.some(tab => tabIds.has(tab.id))) return;
      }
      await showPopup();
    })().finally(() => { uiOpening = null; });
    return uiOpening;
  }

  // Port: approval-controller 10.0.0 dist/ApprovalController.js:82-115.
  const controller = new ApprovalController({
    messenger: messenger.buildChild({ namespace: 'ApprovalController' }),
    // Port: wallet-init/instance-options/approval-controller.ts:27-36.
    // Plan §3.4:318-319 removes snaps, including the reference's additional snap-dialog exclusion.
    typesExcludedFromRateLimiting: [ApprovalType.PersonalSign, ApprovalType.EthSignTypedData, ApprovalType.Transaction, 'nodus_signMessage', SWAP_PAYMENT_APPROVAL],
    showApprovalRequest: () => {
      // The pinned controller invokes this callback without awaiting its promise (:117).
      // background.ts:1088-1100 resets only the opening flag on failure, leaving pending approvals intact.
      // Observe the unawaited rejection; plan §11:964-966 excludes raw window/request errors from logs.
      void triggerUi().catch(() => {});
    },
  });
  // The toolbar icon shows how many approvals wait; with none the badge is cleared. A failed badge call never
  // affects an approval.
  function updateBadge() {
    const count = Object.keys(controller.state.pendingApprovals ?? {}).length;
    try {
      action?.setBadgeText({ text: count > 0 ? badgeLabel(count) : '' });
      action?.setBadgeBackgroundColor({ color: BADGE_COLOR_APPROVAL });
    } catch { /* the badge is only a hint */ }
  }
  messenger.subscribe('ApprovalController:stateChange', updateBadge);
  updateBadge();
  const pendingCount = () => Object.keys(controller.state.pendingApprovals ?? {}).length;
  // Set by the approval window page just before it closes itself and consumed by the next removal of that window, so
  // the removal can be told from the user closing it.
  let automaticClose = false;
  // Opens the window again for approvals still waiting. An opening in flight may have just focused the window that is
  // closing, so it is waited for first; the new run then sees the cleared window id and opens a new window.
  async function reopenForPending() {
    if (uiOpening) { try { await uiOpening; } catch { /* its failure was already observed by the caller that started it */ } }
    if (pendingCount() > 0) await triggerUi();
  }
  const onRemoved = id => {
    if (id !== popupId) return;
    popupId = undefined;
    const automatic = automaticClose; automaticClose = false;
    // A window the user closed answers every approval waiting in it; a window that closed itself leaves any approval
    // that arrived meanwhile to a new window.
    if (!automatic) { rejectAll(); return; }
    if (pendingCount() > 0) void reopenForPending().catch(() => {});
  };
  windows.onRemoved.addListener(onRemoved);

  function reject(id) { controller.rejectRequest(id, providerErrors.userRejectedRequest()); }
  // The cause keeps these rejections out of the per-origin spam count: the site did not ask for them.
  function rejectAll() {
    for (const approval of Object.values(controller.state.pendingApprovals ?? {})) {
      controller.rejectRequest(approval.id, providerErrors.userRejectedRequest({ data: { cause: 'rejectAllApprovals' } }));
    }
  }
  function rejectOrigin(origin) {
    for (const approval of Object.values(controller.state.pendingApprovals)) {
      if (approval.origin === origin) reject(approval.id);
    }
  }

  // Port: app/scripts/metamask-controller.js:5268-5279 and lib/createOriginThrottlingMiddleware.ts:66-168.
  function createOriginThrottlingMiddleware() {
    return (req, res, next, end) => {
      const { method, origin } = req;
      if (!BLOCKABLE_METHODS.has(method) || TEST_ORIGINS.includes(origin)) return next();
      const current = throttledOrigins.get(origin);
      if (current && current.rejections >= 3 && Date.now() - current.lastRejection <= 60_000) {
        return end(providerErrors.unauthorized('Request blocked due to spam filter.'));
      }
      return next(done => {
        if (res.error?.code === 4001) {
          if (res.error.data?.cause !== 'rejectAllApprovals') {
            const previous = throttledOrigins.get(origin) ?? { rejections: 0, lastRejection: 0 };
            const now = Date.now();
            throttledOrigins.set(origin, { rejections: now - previous.lastRejection < 30_000 ? previous.rejections + 1 : 1, lastRejection: now });
          }
        } else if (throttledOrigins.has(origin)) throttledOrigins.set(origin, { rejections: 0, lastRejection: 0 });
        done();
      });
    };
  }

  return { controller, triggerUi, reject, rejectOrigin, createOriginThrottlingMiddleware,
    whenUiSettled: () => uiOpening ?? Promise.resolve(),
    markAutomaticClose: () => { automaticClose = true; },
    destroy() { windows.onRemoved.removeListener(onRemoved); controller.clearRequests(providerErrors.userRejectedRequest()); messenger.unsubscribe('ApprovalController:stateChange', updateBadge); controller.destroy(); } };
}
