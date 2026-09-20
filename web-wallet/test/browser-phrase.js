// Public test fixtures only. Exercise the same paste event as the browser UI.
export async function pastePhrase(page, phrase, position = 1) {
  await page.locator(`#phrase-${position}`).evaluate((input, text) => {
    const clipboardData = new DataTransfer(); clipboardData.setData('text/plain', text);
    input.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
  }, phrase);
}
export async function readPhrase(page) {
  return page.locator('#phrase-grid input').evaluateAll(inputs => inputs.map(input => input.value).join(' ').trim());
}
