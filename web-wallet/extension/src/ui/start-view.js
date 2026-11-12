// The view a wallet page opens on, from its address query (`home.html?view=connect`). A query, not a hash: the wallet
// screen routes on the hash. Anything else, or no search string, gives null (the wallet as before).
export function startView(search) {
  if (typeof search !== 'string') return null;
  return new URLSearchParams(search).get('view') === 'connect' ? 'connect' : null;
}
