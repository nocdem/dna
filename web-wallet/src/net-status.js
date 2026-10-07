// NETWORK STATUS in the open-wallet bar (operator 2026-10-07): a coloured
// dot and one short line, next to "Wallet open in this browser", saying
// whether the wallet is connected to the Nodus network. Pure: no DOM, so the
// mapping is tested on its own (test/net-status.test.js); src/app.js writes it.
//
// Levels:
//   'connecting'  amber  a connection is being made, or a lost / failed one
//                        is tried again by itself (src/app.js RECONNECT)
//   'connected'   green  the NODUS client is 'ready'
//   'offline'     red    not connected and not tried again by itself; the
//                        user's way back is the existing one: lock and reopen
//   'off'         none   this build has no NODUS module: the wallet never
//                        connects to the Nodus network, so nothing is shown
//
// The text is the same for every attempt of a level (no countdown): it sits
// in a polite live region, and a changing number would be read out again on
// every retry.

export const NET_STATUS_TEXT = Object.freeze({
  connecting: 'Connecting to the Nodus network…',
  connected: 'Connected to the Nodus network',
  offline: 'Not connected to the Nodus network. Lock and reopen your wallet to retry.'
});

// A state of the NODUS client (src/nodus/client.js, STATES) -> level.
// 'error' and 'locked' map to 'offline'; src/app.js decides right after them
// whether the connection is tried again (then it shows 'connecting') or not.
// Anything unknown is 'offline': never show "connected" for a state this
// mapping does not know.
export function netLevelFor(clientState) {
  switch (clientState) {
    case 'ready': return 'connected';
    case 'identifying':
    case 'identified':
    case 'connecting': return 'connecting';
    default: return 'offline';
  }
}

// Level -> what the bar shows: { level, text }, or null for 'off' (hidden).
// An unknown level is shown as 'offline'.
export function netStatusView(level) {
  if (level === 'off') return null;
  const known = Object.hasOwn(NET_STATUS_TEXT, level) ? level : 'offline';
  return { level: known, text: NET_STATUS_TEXT[known] };
}
