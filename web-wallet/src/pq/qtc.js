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
