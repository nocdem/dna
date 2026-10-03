// Extension points of src/app.js (decision 2026-10-01-connect-own-origin.md).
//
// The wallet page (src/main.js, wallet.nodusnetwork.io) registers only the
// shared vaults (src/vaults/ui.js); the site name is 'wallet'. The Nodus
// Connect page (src/connect-main.js, connect.nodusnetwork.io) calls
// configureSite() BEFORE it imports src/app.js and registers Messages and
// the shared vaults, so both run on the wallet's one unlock, one NODUS
// client (one send.wasm module, one tier-2 session) and one lock.
//
// Events app.js raises (an extension implements any subset):
//   attach({ lock })            once, when app.js has loaded; lock(reason?)
//                               is the wallet's own lock (the ONE lock).
//   nodusReady({ client, phrase, vaultId, fresh })
//                               the wallet's NODUS client finished unlock
//                               for the open wallet. phrase: the normalised
//                               recovery phrase; vaultId: the saved wallet's
//                               id when the wallet was opened by unlocking
//                               the saved copy, else null; fresh: true only
//                               for words generated in this tab and verified
//                               (decision 2026-09-30-nodus-connect-thin-core
//                               Q1).
//   nodusClosing({ reason })    the NODUS client is about to be locked, or
//                               has left 'ready'. Raised BEFORE client.lock()
//                               on every path app.js controls (lock order:
//                               Messages core, then the client — design
//                               rev 5 §1.8). reason: plain words, or
//                               undefined for a wallet lock.
//   nodusUnavailable()          the Nodus address or client could not be
//                               set up for the open wallet (app.js tries
//                               again by itself and raises nodusReady
//                               once a connection is made).
//   ownName({ name, confirmed }) the open wallet's own chain name, as the
//                               reverse lookup (dnac_name_of for this
//                               wallet's address, src/adapters/nodus.js
//                               ownChainName) answered it; '' when there is
//                               none, the lookup failed, or names are not
//                               available / the wallet closed. confirmed:
//                               true only when the lookup answered (name
//                               found, or '' = confirmed no name); absent
//                               for a failed lookup, names unavailable or
//                               the wallet closing.
//   vaultDeleting()             the saved wallet is about to be deleted
//                               from this device (its Messages history goes
//                               with it, src/app.js vault-delete).
//   locked()                    the wallet was locked.
// Questions app.js asks (gather: every extension's answer, arrays joined):
//   recipients({ network })     recipients the send form may offer for that
//                               network id besides the address book:
//                               [{ label, address }]. Messages answers its
//                               contacts for 'nodus' (src/connect/ui/
//                               messages.js); the address is checked by the
//                               wallet again before it is offered.
// An extension that throws never breaks the wallet path that raised the event.
const extensions = [];
let site = 'wallet';

export function configureSite(name) {
  if (name !== 'wallet' && name !== 'connect') throw new Error('Unknown site.');
  site = name;
}
export function siteName() { return site; }
export function registerExtension(extension) { extensions.push(extension); }
export function raise(event, detail) {
  for (const extension of extensions) {
    try { extension[event]?.(detail); } catch { /* the wallet path continues */ }
  }
}
export function gather(question, detail) {
  const out = [];
  for (const extension of extensions) {
    try {
      const answer = extension[question]?.(detail);
      if (Array.isArray(answer)) out.push(...answer);
    } catch { /* the other answers still count */ }
  }
  return out;
}
