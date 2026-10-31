// Browser-only isolated fixture. Real shipped WASM identity/history/state codec
// and IndexedDB; network exports below are explicit in-memory answers. No live
// node, real account, signature/transport assertion, or production test hook.
import { createNodusSendModule, NODUS_SEND_NETWORK } from '../src/nodus/send-module.js';
import { nodusSigningSeed } from '../src/nodus/derive.js';
import { createNodusConnectCore, CONTACT_ACCEPTED_MSG } from '../src/connect/core.js';
import { createMessagesSession } from '../src/connect/ui/messages.js';
import { openHistoryStore, databaseNameForVault, STORE_MESSAGES } from '../src/connect/store.js';

export async function recoveryFixture(root, remoteMode = false) {
  const vectors = (await (await fetch('/test/fixtures/pq-receive.json')).json()).vectors;
  const OLD = '5a'.repeat(32), OFFER = '6b'.repeat(32), OTHER = '7c'.repeat(64), REMOVED = '8d'.repeat(64);
  const net = { inbox: {}, lists: {}, reads: [], writes: [], outcomes: {}, failAck: false, failSeal: 0, failAfterAck: false, heldAck: null };
  const actors = {};
  const time = () => String(Math.floor(Date.now() / 1000));
  const record = (sender, acceptance = false, salt = OFFER, timestamp = time()) => ({
    sender, acceptance, salt, timestamp, expiry: String(BigInt(timestamp) + 604800n),
    message: acceptance ? CONTACT_ACCEPTED_MSG : 'Synthetic reconnect request',
  });
  const put = (to, r) => { net.inbox[to] = [...(net.inbox[to] || []).filter(x => x.sender !== r.sender), structuredClone(r)]; };
  for (const [i, label] of ['a', 'b'].entries()) {
    const phrase = vectors[i].phrase;
    let mod = await createNodusSendModule(NODUS_SEND_NETWORK, {});
    const { fingerprint: fp } = await mod.identify({ seed: nodusSigningSeed(phrase) });
    const vaultId = btoa(String.fromCharCode(...new Uint8Array(16).fill(i + 101)));
    let queue = Promise.resolve();
    const profile = who => ({ outcome: 'found', why: 'none', record: '{}',
      profile: { fingerprint: who, name: '', claimed_name: '', has_mlkem: true } });
    const wrap = api => {
      let fake;
      return {
        ...api,
        num(name, types, args) {
          fake = undefined;
          if (name === 'nc_hist_encrypt' && net.failSeal > 0) { net.failSeal--; throw new Error('Synthetic storage failure'); }
          return api.num(name, types, args);
        },
        str: name => name === 'nc_result' && fake !== undefined ? JSON.stringify(fake) : api.str(name),
        async call(name, types, args = []) {
          fake = undefined;
          switch (name) {
            case 'nc_profile_get': case 'nc_profile_load':
              if (net.heldProfile && args[0] === net.holdProfileFp) { net.profileHeld = true; await net.heldProfile; }
              fake = args[0] === net.unavailableProfile ? { outcome: 'unreadable', why: 'timeout' } : profile(args[0]); break;
            case 'nc_contacts_get': {
              net.reads.push({ owner: fp, name });
              const outcome = net.outcomes[fp] || 'found';
              if (outcome === 'throw') throw new Error('Synthetic contact list unavailable');
              fake = { outcome, why: outcome === 'unreadable' ? 'timeout' : 'none', contacts: outcome === 'found' ? structuredClone(net.lists[fp] || []) : [] };
              break;
            }
            case 'nc_requests_get': fake = { outcome: 'found', requests: structuredClone(net.inbox[fp] || []) }; break;
            case 'nc_request_new':
              net.writes.push({ owner: fp, name, args }); put(args[0], record(fp)); fake = { salt: OFFER }; break;
            case 'nc_request_approve':
              net.writes.push({ owner: fp, name, args });
              if (net.heldAck) await net.heldAck;
              if (net.failAck) throw new Error('Synthetic acknowledgement unavailable');
              put(args[0], record(fp, true, args[1])); fake = {};
              if (net.failAfterAck) { net.failAfterAck = false; net.failSeal = 1; }
              break;
            case 'nc_request_withdraw':
              net.writes.push({ owner: fp, name, args });
              net.inbox[args[0]] = (net.inbox[args[0]] || []).filter(x => x.sender !== fp); fake = {}; break;
            case 'nc_contacts_add': {
              net.writes.push({ owner: fp, name, args });
              const contacts = net.lists[fp] ||= [];
              for (const c of JSON.parse(args[0])) if (!contacts.some(x => x.fp === c.fp)) contacts.push(c);
              fake = { status: 'published', outcome: 'found' }; break;
            }
            case 'nc_salt_reconcile':
              net.reads.push({ owner: fp, name, args });
              fake = { status: 'nothing_to_write', outcome: 'found', choice: 'keep_local', salt: args[1] || OLD }; break;
            case 'nc_contact_reads':
              fake = { contacts: JSON.parse(args[0]).map(c => ({ ack: { outcome: 'empty' }, days: c.days.map(d => ({ outcome: 'empty', day: d.day, messages: [] })) })) }; break;
            case 'nc_ack_send': fake = {}; break;
            // A regression must never accidentally exercise a message send.
            case 'nc_outbox_send': throw new Error('This fixture forbids message sending');
            case 'nc_unlock': return api.call(name, types, args);
            default: throw new Error(`Unexpected synthetic network export: ${name}`);
          }
          return 0;
        },
      };
    };
    const serial = run => { const p = queue.then(() => mod.connect(api => run(wrap(api)))); queue = p.catch(() => {}); return p; };
    const client = { state: 'ready', fingerprint: fp, localConnectable: true, nameable: false,
      connect: serial, connectLocal: serial, connectSync: run => mod.connectSync(api => run(wrap(api))) };
    actors[label] = { phrase, fp, mod, client, vaultId, session: null,
      async restart() {
        // nc_lock is terminal for a module instance, just like the production
        // wallet lifecycle. Reopen with a new module and the SAME public fixture.
        await queue; mod.lock(); mod = await createNodusSendModule(NODUS_SEND_NETWORK, {});
        const identified = await mod.identify({ seed: nodusSigningSeed(phrase) });
        if (identified.fingerprint !== fp) throw new Error('Synthetic identity changed');
        actors[label].mod = mod;
      },
    };
    net.lists[fp] = [];
  }
  const a = actors.a, b = actors.b;
  net.lists[b.fp] = [{ fp: a.fp, salt: OLD }];
  async function withStore(label, run) {
    const x = actors[label]; await x.restart();
    const core = createNodusConnectCore({ nodus: x.client });
    await core.unlock({ words: new TextEncoder().encode(x.phrase), fresh: false });
    const store = await openHistoryStore({ core, vaultId: x.vaultId });
    try { return await run(store); } finally { store.close(); core.lock(); }
  }
  await withStore('b', async store => {
    store.state.contacts.push({ fp: a.fp, salt: OLD, listed: true });
    store.state.removed.push(REMOVED);
    store.state.nextSeq = '2';
    await store.save(store.state, [{ seq: '1', fp: a.fp, dir: 'in', text: 'KEPT SYNTHETIC HISTORY', remoteSeq: '12', at: Date.now(), senderTs: time() }]);
  });
  let view;
  async function open(label) {
    const x = actors[label]; x.session?.close();
    if (label === 'b') { view?.close(); root.replaceChildren(); }
    await x.restart();
    const session = createMessagesSession({ onChange: () => {
      if (label === 'b' && remoteMode) queueMicrotask(() => view?.applySnapshot(session.snapshot()));
    } });
    x.session = session;
    if (label === 'b') {
      view = remoteMode ? createMessagesSession({ remote: async (name, fields) => {
        try { return await session.action(name, fields); } finally { view.applySnapshot(session.snapshot()); }
      } }) : session;
      view.mountMessages(root);
    }
    await session.open({ client: x.client, phrase: x.phrase, vaultId: x.vaultId, fresh: false });
    return session.snapshot();
  }
  async function messageBytes(label) {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open(databaseNameForVault(actors[label].vaultId)); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    try {
      const values = await new Promise((resolve, reject) => { const r = db.transaction(STORE_MESSAGES).objectStore(STORE_MESSAGES).getAll(); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      return values.map(r => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, ArrayBuffer.isView(v) ? [...v] : v instanceof ArrayBuffer ? [...new Uint8Array(v)] : v])));
    } finally { db.close(); }
  }
  return { actors, net, OLD, OFFER, OTHER, REMOVED, record, put, open, messageBytes,
    state: label => actors[label].session.snapshot(),
    action: (label, name, input) => actors[label].session.action(name, input),
    requests: () => view.messagesNavigate('requests'),
    async stored(label) { actors[label].session.close(); return withStore(label, s => structuredClone(s.state)); },
    close() { view?.close(); for (const x of Object.values(actors)) { x.session?.close(); x.mod.lock(); } },
  };
}
