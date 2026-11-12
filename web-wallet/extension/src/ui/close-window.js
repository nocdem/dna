// Closes the approval window once nothing is left to answer. Only a window whose type is 'popup' is closed: a
// browser tab or the full wallet page is left alone. When the window type cannot be read, closing is still tried,
// since it may be the approval popup. The background is told first that this close is automatic (otherwise the
// removal of the window counts as the user closing it and rejects every pending approval). window.close() is tried
// first (it closes only this window, not other tabs of a browser window); if the page is still there, the current
// tab is removed; if the page is still there after that, the mark is withdrawn so a later close by the user counts
// as the user's.
// Only the approval window page (notification.html) is given the closer; the toolbar popup and the full page get none.
export const approvalWindowOptions = (pathname, close = closeApprovalWindow) =>
  pathname?.split('/').pop() === 'notification.html' ? { closeWhenNothingPending: client => close({ client }) } : {};

export async function closeApprovalWindow({ client, browser = globalThis.chrome, window = globalThis.window } = {}) {
  try {
    const current = await browser.windows.getCurrent();
    if (current?.type && current.type !== 'popup') return false;
  } catch { /* the type cannot be ruled out as a popup; continue */ }
  await client.request('markNotificationPopupAsAutomaticallyClosed');
  window.close();
  try {
    const tab = await browser.tabs.getCurrent();
    if (typeof tab?.id === 'number') await browser.tabs.remove(tab.id);
  } catch { /* the page may already be gone */ }
  // Still running: neither close worked.
  try { await client.request('clearNotificationPopupAutomaticClose'); } catch { /* the background may be gone too */ }
  return true;
}
