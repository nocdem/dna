// Port: MetaMask v13.54.0 shared/lib/provider-injection.ts:6-128; unchanged signature and reference block lists (plan §3.3:219-222).
export default function shouldInjectProvider() {
  return checkFrameOriginForProviderInjection() && checkURLForProviderInjection(new URL(window.location.href)) && checkDocumentForProviderInjection();
}

// A frame with an opaque origin (a sandboxed frame without allow-same-origin) reports "null" as its origin while its
// URL still names a site: every page message the streams address to that site's origin is refused by the browser
// ("The target origin provided ... does not match the recipient window's origin ('null')"), and no site permission can
// name such a frame. Nothing is injected there.
export function checkFrameOriginForProviderInjection() {
  return window.origin !== 'null';
}

export function checkURLForProviderInjection(url) {
  return suffixCheck(url) && !blockedDomainCheck(url);
}

function suffixCheck({ pathname }) {
  const prohibitedTypes = [/\.xml$/u, /\.pdf$/u];
  for (const prohibitedType of prohibitedTypes) {
    if (prohibitedType.test(pathname)) return false;
  }
  return true;
}

function blockedDomainCheck(url) {
  const blockedDomains = [
    'execution.consensys.io', 'execution.metamask.io', 'uscourts.gov', 'dropbox.com',
    'webbyawards.com', 'adyen.com', 'gravityforms.com', 'harbourair.com',
    'ani.gamer.com.tw', 'blueskybooking.com', 'sharefile.com', 'battle.net',
    'accounts.google.com', 'accounts.youtube.com', 'appleid.apple.com',
  ];
  const blockedUrlPaths = ['cdn.shopify.com/s/javascripts/tricorder/xtld-read-only-frame.html'];
  const { hostname: currentHostname, pathname: currentPathname } = url;
  const trimTrailingSlash = str => str.endsWith('/') ? str.slice(0, -1) : str;
  return blockedDomains.some(blockedDomain => blockedDomain === currentHostname || currentHostname.endsWith(`.${blockedDomain}`)) ||
    blockedUrlPaths.some(blockedUrlPath => trimTrailingSlash(blockedUrlPath) === trimTrailingSlash(currentHostname + currentPathname));
}

export function checkDocumentForProviderInjection() {
  return doctypeCheck() && documentElementCheck();
}

function doctypeCheck() {
  const { doctype } = window.document;
  if (doctype) return doctype.name === 'html';
  return true;
}

function documentElementCheck() {
  const documentElement = document.documentElement.nodeName;
  if (documentElement) return documentElement.toLowerCase() === 'html';
  return true;
}
