// Explorer confirmed index; includes immature coinbase and excludes mempool.
import { witnessAddress } from './soqucoin.js';
import { integerJson, atoms, decimalAtoms } from './integer-json.js';
const NETWORKS = Object.freeze({
  mainnet: { prefix: 'qtc', url: 'https://qtc.events', chain: 'main', genesis: 'd5f04a8a320b4e7bb454c7c564ca9cf191f70d7521d2486b62274df776f4eb24' },
  testnet: { prefix: 'tqtc', url: 'https://testnet.qtc.events', chain: 'test', genesis: 'efcba50d2de7cb16fd92423df899eba29e750b2271ef0ea64efe8cfeb4382ddf' }
});
export async function readQtcBalances(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported QTC network.');
  const network = NETWORKS[networkId], root = witnessAddress(account, network.prefix, 2), options = { signal, fetcher };
  const chain = await integerJson(`${network.url}/api/v1/chain`, options);
  if (chain?.chain !== network.chain) throw new Error('QTC provider is connected to the wrong network.');
  const genesis = await integerJson(`${network.url}/api/v1/block/0`, options);
  if (genesis?.block?.hash !== network.genesis || atoms(genesis.block.height) !== 0n) throw new Error('QTC provider has the wrong genesis.');
  const data = await integerJson(`${network.url}/api/v1/address/${encodeURIComponent(account)}`, options);
  const a = data?.address;
  if (!a || typeof a !== 'object' || Array.isArray(a) || a.address !== account) throw new Error('Invalid QTC account response.');
  const received = atoms(a.received), sent = atoms(a.sent), count = atoms(a.tx_count), utxos = atoms(a.utxo_count), balance = atoms(data.balance);
  if (sent > received || received - sent !== balance) throw new Error('Inconsistent QTC account balance.');
  if (a.first_height === '-1') {
    if (a.script !== '' || a.type !== '' || received !== 0n || sent !== 0n || count !== 0n || utxos !== 0n || balance !== 0n) throw new Error('Invalid QTC empty account.');
  } else {
    atoms(a.first_height);
    const script = '5220' + Array.from(root, b => b.toString(16).padStart(2, '0')).join('');
    if (a.script !== script || typeof a.type !== 'string' || !a.type) throw new Error('Invalid QTC account script.');
  }
  return [{ symbol: 'QTC', balance: decimalAtoms(balance) }];
}


// Explorer-indexed confirmed net flows, including transaction fees in outgoing
// amounts. Neither this index nor the reported inputs are an inclusion proof.
// Endpoint schema: qtcchain/qtc-explorer at 73a6076, internal/web/server.go
// and internal/store/store.go. Shielded transactions are omitted.
export async function readQtcHistory(account, { networkId = 'mainnet', signal, fetcher } = {}) {
  if (!Object.hasOwn(NETWORKS, networkId)) throw new Error('Unsupported QTC network.');
  const network = NETWORKS[networkId], root = witnessAddress(account, network.prefix, 2), options = { signal, fetcher };
  const chain = await integerJson(`${network.url}/api/v1/chain`, options);
  if (chain?.chain !== network.chain) throw new Error('QTC provider is connected to the wrong network.');
  const genesis = await integerJson(`${network.url}/api/v1/block/0`, options);
  if (genesis?.block?.hash !== network.genesis || atoms(genesis.block.height) !== 0n) throw new Error('QTC provider has the wrong genesis.');
  const data = await integerJson(`${network.url}/api/v1/address/${encodeURIComponent(account)}/txs?limit=50`, options);
  if (!Array.isArray(data.txs) || data.txs.length > 50) throw new Error('Invalid QTC history response.');
  if (atoms(data.total) < BigInt(data.txs.length)) throw new Error('Invalid QTC history count.');
  // An index page should have at most one entry for each transaction. Refuse
  // duplicates even if one is malformed or shielded; never pick a winner.
  const ids = new Set();
  for (const tx of data.txs) {
    if (typeof tx?.txid === 'string' && /^[0-9a-f]{64}$/.test(tx.txid)) {
      if (ids.has(tx.txid)) throw new Error('Duplicate QTC transaction.');
      ids.add(tx.txid);
    }
  }
  const script = '5220' + Array.from(root, b => b.toString(16).padStart(2, '0')).join('');
  const rows = [];
  const own = item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid QTC entry.');
    if (item.address !== undefined && typeof item.address !== 'string') throw new Error('Invalid QTC address.');
    if (item.script !== undefined && (typeof item.script !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(item.script))) throw new Error('Invalid QTC script.');
    const byAddress = item.address === account, byScript = item.script === script;
    if (byAddress !== byScript) throw new Error('Ambiguous QTC ownership.');
    return byAddress;
  };
  for (const tx of data.txs) {
    try {
      if (!tx || typeof tx.txid !== 'string' || !/^[0-9a-f]{64}$/.test(tx.txid) || tx.shielded !== false || typeof tx.coinbase !== 'boolean' || !Array.isArray(tx.vin) || !Array.isArray(tx.vout) || tx.vin.length === 0 || tx.vout.length === 0 || tx.vin.length > 10000 || tx.vout.length > 10000) continue;
      const height = atoms(tx.height), seconds = atoms(tx.blocktime);
      if (height === 0n || seconds === 0n || seconds > 9999999999n) continue;
      let incoming = 0n, outgoing = 0n;
      for (const input of tx.vin) {
        const value = atoms(input?.value);
        if (tx.coinbase) {
          // Indexer stores coinbase text, value 0, and no resolved previous output.
          if (tx.vin.length !== 1 || typeof input.coinbase !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(input.coinbase) || value !== 0n || input.txid || input.address || input.script) throw new Error('Invalid QTC coinbase.');
        } else {
          if (input.coinbase || typeof input.txid !== 'string' || !/^[0-9a-f]{64}$/.test(input.txid)) throw new Error('Invalid QTC input.');
          if (own(input)) outgoing += value;
        }
      }
      for (const output of tx.vout) {
        const value = atoms(output.value);
        if (own(output)) incoming += value;
      }
      if (incoming === outgoing) continue;
      const out = outgoing > incoming;
      rows.push({ chain: 'qtc', hash: tx.txid, time: Number(seconds) * 1000, dir: out ? 'out' : 'in', symbol: 'QTC', amount: decimalAtoms(out ? outgoing - incoming : incoming - outgoing), peer: '', status: 'confirmed' });
    } catch { /* omit malformed provider entries */ }
  }
  return rows.sort((a, b) => b.time - a.time || a.hash.localeCompare(b.hash));
}
