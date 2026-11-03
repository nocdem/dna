// The data notice the user agrees to before the extension handles any user
// data (operator 2026-11-03 "veri izin ekranı orada da olsun",
// docs/plans/decisions/2026-11-03-chrome-web-store.md:11; Chrome Web Store user
// data FAQ question 10: the disclosure and an explicit agreement must occur
// within the product's own interface). The stored value is the text version of
// the notice the user agreed to; a new version asks again.
export const CONSENT_KEY = 'nodus.privacyConsent.v1';
export const CONSENT_VERSION = '1';

export function createPrivacyConsent({ storage }) {
  // Only a positive answer is remembered: the version is a build constant and
  // the key is never removed by "Delete saved wallet".
  let given = false;
  async function isGiven() {
    if (given) return true;
    const saved = await storage.get(CONSENT_KEY);
    if (saved[CONSENT_KEY] === CONSENT_VERSION) given = true;
    return given;
  }
  async function accept() {
    await storage.set({ [CONSENT_KEY]: CONSENT_VERSION });
    given = true;
  }
  return { isGiven, accept };
}
