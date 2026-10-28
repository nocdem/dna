import { ApprovalController } from '@metamask/approval-controller';
import { providerErrors } from '@metamask/rpc-errors';
import { ApprovalType } from '@metamask/controller-utils';

// Port: MetaMask v13.54.0 app/scripts/lib/createOriginThrottlingMiddleware.ts:14-43.
const BLOCKABLE_METHODS = new Set([
  'wallet_addEthereumChain', 'eth_sendTransaction', 'eth_signTypedData', 'eth_signTypedData_v1',
  'eth_signTypedData_v3', 'eth_signTypedData_v4', 'personal_sign', 'wallet_switchEthereumChain',
  'wallet_sendCalls', 'wallet_watchAsset',
]);
const TEST_ORIGINS = ['http://127.0.0.1:8080', 'http://127.0.0.1:8081', 'http://127.0.0.1:8082',
  'http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082'];

export function createApprovals({ messenger, runtime, windows, tabs, platform, getUiState = () => ({ popupCount: 0, tabIds: new Set() }) }) {
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
    const popupWindow = await platform.openWindow({ url: 'notification.html', type: 'popup', width: 400, height: 620, left, top });
    // Port: notification-manager.ts:114-121; extension.ts:62-68 provides the platform operation.
    if (typeof popupWindow.id === 'number' && popupWindow.left !== left && popupWindow.state !== 'fullscreen') {
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
    typesExcludedFromRateLimiting: [ApprovalType.PersonalSign, ApprovalType.EthSignTypedData, ApprovalType.Transaction,
      ApprovalType.WatchAsset, ApprovalType.EthGetEncryptionPublicKey, ApprovalType.EthDecrypt],
    showApprovalRequest: () => {
      // The pinned controller invokes this callback without awaiting its promise (:117).
      // background.ts:1088-1100 resets only the opening flag on failure, leaving pending approvals intact.
      // Observe the unawaited rejection; plan §11:964-966 excludes raw window/request errors from logs.
      void triggerUi().catch(() => {});
    },
  });
  const onRemoved = id => { if (id === popupId) popupId = undefined; };
  windows.onRemoved.addListener(onRemoved);

  function reject(id) { controller.rejectRequest(id, providerErrors.userRejectedRequest()); }
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
    destroy() { windows.onRemoved.removeListener(onRemoved); controller.clearRequests(providerErrors.userRejectedRequest()); controller.destroy(); } };
}
