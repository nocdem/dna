// Closes the approval window once nothing is left to answer. Only a window whose type is 'popup' is closed: a
// browser tab or the full wallet page is left alone. When the window type cannot be read, closing is still tried,
// since it may be the approval popup. window.close() is tried first (it closes only this window, not other tabs of
// a browser window); if the page is still there, the current tab is removed.
// Only the approval window page (notification.html) is given the closer; the toolbar popup and the full page get none.
export const approvalWindowOptions = (pathname, close = closeApprovalWindow) =>
  pathname?.split('/').pop() === 'notification.html' ? { closeWhenNothingPending: () => close() } : {};

export async function closeApprovalWindow({ browser = globalThis.chrome, window = globalThis.window } = {}) {
  try {
    const current = await browser.windows.getCurrent();
    if (current?.type && current.type !== 'popup') return false;
  } catch { /* the type cannot be ruled out as a popup; continue */ }
  window.close();
  try {
    const tab = await browser.tabs.getCurrent();
    if (typeof tab?.id === 'number') await browser.tabs.remove(tab.id);
  } catch { /* the page may already be gone */ }
  return true;
}
