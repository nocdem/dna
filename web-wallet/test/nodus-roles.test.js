// Nodus Connect "Nodus" page (src/nodus-roles.js, HF-6 screens; design
// docs/plans/2026-10-12-connect-hf6-screens-design.md rev 1): the pure
// helpers the page decides with, and the adapter checks under them
// (src/adapters/nodus.js parseValidators / parseStorageByOwner /
// checkConsent / prepareHf6) against an in-memory client.
//
// What it proves: the suggested --expiry is tip + window − 10 (none for an
// unknown tip); a percent commission becomes basis points and the chain's
// maximum is a ceiling; sending opens only at the HF-6 generation and never
// when the node did not say; "your witnesses" are the generation-4 rows
// owned by this wallet only; a consent that expires before the transaction's
// validity fails its check line and prepareHf6 refuses it, and the node-key
// line is "free" only against the complete witness list (BUGS W-21); the
// role bonds are the node's (hf6Bonds): what prepareHf6 builds, a failed
// read builds nothing (BUGS W-20); leaving storage only for a listed,
// storing node (W-21); the node is given one request code
// (nodus-consent-v1:<role>:<owner>:<expiry>:<chain>) in one fixed command
// `sudo nodus-cli consent <code>`, and a code with a bad kind, owner, expiry
// or chain is never made (W-22); the earliest heights
// of the timing facts (witness join, storage exit); the validator list keeps the generation-4 ids and
// refuses all-zero ones; the storage list's shape rules; prepareHf6 refuses
// below the HF-6 generation and refuses a signed transaction whose node key
// is not the consent's. "Stop being a witness" (prepareHf6 kind 'unstake',
// the generation-4 UNSTAKE): offered only for this wallet's own active /
// eligible witnesses (canStopWitness; the adapter refuses another owner's,
// a leaving one, an unknown or all-zero id, a module without the witness
// list), built with no consent and no bond, its review names the witness
// and has no node key line, and a signed witness id or node key that is not
// the request's is refused; the lock block counts are epochs × E. No key
// rotation (Kurultay #18 item 1): no 'rotate' kind, no rotate heights, a
// rotate consent check or build is refused before the client is asked.
// Requires: nothing beyond `npm ci` (node --test). Leaves nothing behind.
// How it can lie: the client is a fake — the module's own consent checks,
// signature verification and envelope bytes are NOT exercised here (that is
// test/hf6-connect-wasm.test.js and the parity build); the numbers below are
// fixtures, not chain values.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  suggestExpiry, EXPIRY_MARGIN, percentToBps, gateOpen, ownWitnesses, consentMarginLine, keyCheckLine, consentRequestCode, consentRequestCommand,
  epochStartAtOrAfter, witnessJoinFrom, storageExitHeights, canStopWitness, lockBlocks
} from '../src/nodus-roles.js';
import * as roles from '../src/nodus-roles.js';
import {
  parseValidators, parseStorageByOwner, checkConsent, prepareHf6, parseHf6Rules, parseHf6Bonds, hf6Bonds, HF6_NOT_YET_TEXT, HF6_KINDS,
  consentEndsBefore, CONSENT_ENDS_EARLY_TEXT
} from '../src/adapters/nodus.js';

const OWN = '1a'.repeat(64), OTHER = '2b'.repeat(64), NODE = '3c'.repeat(64), NODE2 = '4d'.repeat(64);
const VID = '5e'.repeat(64), VID2 = '6f'.repeat(64);

test('roles: the suggested expiry is tip + window - 10, none for an unknown tip', () => {
  assert.equal(EXPIRY_MARGIN, 10n);
  assert.equal(suggestExpiry(1000n, 720n), 1710n);
  assert.equal(suggestExpiry(0n, 720n), null);
  assert.equal(suggestExpiry(1000n, 10n), null);
  assert.equal(suggestExpiry(1000, 720n), null, 'numbers are BigInt only');
});

test('roles: commission percent -> basis points, the maximum is a ceiling', () => {
  assert.equal(percentToBps('10', 5000n), 1000n);
  assert.equal(percentToBps('12.5', 5000n), 1250n);
  assert.equal(percentToBps('0.25', 5000n), 25n);
  assert.equal(percentToBps('0', 5000n), 0n);
  assert.equal(percentToBps(' 50 ', 5000n), 5000n);
  assert.throws(() => percentToBps('50.01', 5000n), /at most 50%/);
  assert.throws(() => percentToBps('', 5000n), /Enter a commission/);
  assert.throws(() => percentToBps('1.234', 5000n), /two decimals/);
  assert.throws(() => percentToBps('-1', 5000n));
  assert.equal(percentToBps('75', null), 7500n, 'no maximum known: the module refuses above it');
});

test('roles: sending opens only at the HF-6 generation', () => {
  assert.equal(gateOpen(3n, 4), false);
  assert.equal(gateOpen(4n, 4), true);
  assert.equal(gateOpen(5n, 4), true);
  assert.equal(gateOpen('4', 4), true);
  assert.equal(gateOpen('3', 4), false);
  assert.equal(gateOpen(undefined, 4), false, 'the node did not say');
  assert.equal(gateOpen(null, 4), false);
  assert.equal(gateOpen('0', 4), false);
  assert.equal(gateOpen(4n, 0), false, 'no HF-6 generation known');
});

test('roles: your witnesses are the generation-4 rows owned by this wallet', () => {
  const rows = [
    { fingerprint: NODE, hasV2: true, validatorId: VID, ownerFp: OWN },
    { fingerprint: NODE2, hasV2: true, validatorId: VID2, ownerFp: OTHER },
    { fingerprint: OTHER, hasV2: false, validatorId: '', ownerFp: '' },
    { fingerprint: OWN, hasV2: false, validatorId: '', ownerFp: '' }
  ];
  assert.deepEqual(ownWitnesses(rows, OWN).map(v => v.validatorId), [VID]);
  assert.deepEqual(ownWitnesses(rows, ''), []);
  assert.deepEqual(ownWitnesses(undefined, OWN), []);
});

// BUGS W-21: a consent ending before the transaction's last valid block is a
// FAILED check line (no Review), not a warning; an unknown height fails too.
test('roles: the consent margin line fails exactly when the consent expires first, or the height is unknown', () => {
  assert.equal(consentEndsBefore(1050n, 1090n), true);
  assert.equal(consentEndsBefore(1090n, 1090n), false);
  assert.equal(consentEndsBefore(1700n, 1090n), false);
  assert.equal(consentEndsBefore(null, 1090n), false, 'storage exit: no consent');
  assert.deepEqual(consentMarginLine(1050n, 1090n), { id: 'margin', ok: false, detail: CONSENT_ENDS_EARLY_TEXT });
  assert.equal(CONSENT_ENDS_EARLY_TEXT, 'This consent expires before this transaction could be included; make a new consent on the node.');
  assert.equal(consentMarginLine(1090n, 1090n).ok, true);
  assert.equal(consentMarginLine(1700n, 1090n).ok, true);
  const unknown = consentMarginLine(1700n, null);
  assert.equal(unknown.ok, false);
  assert.match(unknown.detail, /could not be checked/);
});

// BUGS W-21: the "node key already used" check is taken / free / unknown;
// unknown (list pending, failed, or partial) fails — Review stays off.
test('roles: the node-key line is free only against the complete witness list', () => {
  const rows = [{ fingerprint: NODE }, { fingerprint: NODE2 }];
  assert.deepEqual(keyCheckLine({ rows, truncated: false, error: '' }, NODE).state, 'taken');
  assert.equal(keyCheckLine({ rows, truncated: false, error: '' }, NODE).ok, false);
  const free = keyCheckLine({ rows, truncated: false, error: '' }, OTHER);
  assert.equal(free.state, 'free'); assert.equal(free.ok, true);
  for (const [witnesses, why] of [[null, /still being read/], [{ rows: [], truncated: true, error: 'timeout' }, /could not be read \(timeout\)/], [{ rows, truncated: true, error: '' }, /only part of the witnesses/]]) {
    const line = keyCheckLine(witnesses, OTHER);
    assert.equal(line.state, 'unknown'); assert.equal(line.ok, false); assert.match(line.detail, /could not be checked/); assert.match(line.detail, why);
  }
  assert.equal(keyCheckLine({ rows, truncated: true, error: '' }, NODE).state, 'taken', 'a key found in a partial list is taken');
});

// BUGS W-22, decision 2026-10-14-consent-request-code.md: the page gives one
// request code and one fixed command; the node finds its own key.
test('roles: the consent request code and the one node command', () => {
  const CHAIN = '77'.repeat(32);
  assert.equal(consentRequestCode({ kind: 'stake', owner: OWN, expiry: '1710', chainId: CHAIN }), `nodus-consent-v1:witness:${OWN}:1710:${CHAIN}`);
  assert.equal(consentRequestCode({ kind: 'storageRegister', owner: OWN, expiry: '1710', chainId: CHAIN }), `nodus-consent-v1:storage:${OWN}:1710:${CHAIN}`);
  assert.equal(consentRequestCode({ kind: 'stake', owner: OWN, expiry: 1710n, chainId: CHAIN }), `nodus-consent-v1:witness:${OWN}:1710:${CHAIN}`, 'a BigInt expiry');
  const code = consentRequestCode({ kind: 'storageRegister', owner: OWN, expiry: 1710n, chainId: CHAIN });
  assert.ok(/^[0-9a-z:-]+$/.test(code), 'no space, no shell character');
  assert.equal(consentRequestCommand(code), `sudo nodus-cli consent nodus-consent-v1:storage:${OWN}:1710:${CHAIN}`);
  const ok = { kind: 'stake', owner: OWN, expiry: '1710', chainId: CHAIN };
  for (const kind of ['storageExit', 'unstake', 'rotate', '', undefined, 'toString']) {
    assert.throws(() => consentRequestCode({ ...ok, kind }), /Unknown consent action/, String(kind));
  }
  for (const owner of [OWN.toUpperCase(), OWN.slice(2), `${OWN}00`, '', undefined]) {
    assert.throws(() => consentRequestCode({ ...ok, owner }), /Invalid owner/, String(owner));
  }
  for (const expiry of ['0', '01', '-1', '1.5', ' 1710', '', 0n, -5n, 1710, null]) {
    assert.throws(() => consentRequestCode({ ...ok, expiry }), /Invalid expiry/, String(expiry));
  }
  for (const chainId of [CHAIN.toUpperCase(), CHAIN.slice(2), `${CHAIN}00`, '', undefined]) {
    assert.throws(() => consentRequestCode({ ...ok, chainId }), /Invalid chain/, String(chainId));
  }
});

// Kurultay #18 item 1 (decision 2026-10-13-kurultay-18-summary.md): no key
// rotation in HF-6 — no rotate kind, no rotate heights, the consent check
// and the build refuse it before reaching the module.
test('roles: there is no key rotation (ROTATE removed from HF-6)', async () => {
  assert.deepEqual([...HF6_KINDS], ['stake', 'storageRegister', 'storageExit', 'unstake']);
  assert.equal(roles.rotationHeights, undefined);
  const client = fakeClient();
  assert.throws(() => checkConsent({ client, from: OWN, kind: 'rotate', text: 'x', tip: 1000n }), /Unknown consent action/);
  await assert.rejects(prepareHf6({ client, from: OWN, kind: 'rotate', consent: 'x', validatorId: VID }), /Unknown witness or storage action/);
  assert.equal(client.builds.length, 0, 'nothing was built');
});

test('roles: the earliest heights of the timing facts', () => {
  assert.equal(epochStartAtOrAfter(720n, 720n), 720n);
  assert.equal(epochStartAtOrAfter(721n, 720n), 1440n);
  assert.equal(witnessJoinFrom(1000n, 1440n), 2441n);
  assert.equal(witnessJoinFrom(1000n, null), null);
  // exit included at 1001: B_rel 1440, locked 12 epochs, again from 2161
  assert.deepEqual(storageExitHeights(1000n, 720n, 12n), { release: 1440n, lockedUntil: 10080n, registerAgainFrom: 2161n });
  // design rev 6 §11.4: an exit at 720 may register again at 1441 at the earliest
  assert.equal(storageExitHeights(719n, 720n, 12n).registerAgainFrom, 1441n);
});

test('roles: the validator list keeps the generation-4 ids and refuses zero ones', () => {
  const base = { selfStake: '1', delegated: '0', commissionBps: 0, status: 0, delegators: 0 };
  const { validators } = parseValidators({ truncated: false, validators: [
    { ...base, fingerprint: NODE, hasV2: true, validatorId: VID, ownerFp: OWN },
    { ...base, fingerprint: NODE2 }
  ] });
  assert.equal(validators[0].validatorId, VID);
  assert.equal(validators[0].ownerFp, OWN);
  assert.equal(validators[1].hasV2, false);
  assert.equal(validators[1].ownerFp, '');
  assert.throws(() => parseValidators({ truncated: false, validators: [{ ...base, fingerprint: NODE, hasV2: true, validatorId: '0'.repeat(128), ownerFp: OWN }] }), /invalid witness list/);
  assert.throws(() => parseValidators({ truncated: false, validators: [
    { ...base, fingerprint: NODE, hasV2: true, validatorId: VID, ownerFp: OWN },
    { ...base, fingerprint: NODE2, hasV2: true, validatorId: VID, ownerFp: OWN }
  ] }), /invalid witness list/, 'a repeated validator_id');
});

test('roles: the storage list shape', () => {
  const node = (fp, status) => ({ fp, status, bond: '100', failStreak: 0, graceUntil: '0', registered: '5', exit: '0', member: false, segments: '0' });
  const ok = parseStorageByOwner({ tip: '900', total: '2', nodes: [node(NODE, 1), node(NODE2, 3)] });
  assert.deepEqual(ok.nodes.map(n => n.status), ['active', 'released']);
  assert.equal(ok.hidden, 0n);
  assert.throws(() => parseStorageByOwner({ tip: '900', total: '3', nodes: [node(NODE, 1), node(NODE2, 3)] }), /invalid storage/, 'fewer nodes than min(total, 256)');
  assert.throws(() => parseStorageByOwner({ tip: '900', total: '2', nodes: [node(NODE2, 1), node(NODE, 3)] }), /invalid storage/, 'not ascending');
  assert.throws(() => parseStorageByOwner({ tip: '900', total: '1', nodes: [node(NODE, 4)] }), /invalid storage/, 'unknown status');
});

// An in-memory client in the shape src/nodus/client.js gives the page.
// witnesses: the validator list (send-module.js validators() rows) — given,
// the client is stakeable; unstake builds read back signedVid (default: the
// requested id) and signedUnstakeNodeFp (default '': the call has no key).
// bonds: what hf6Bonds() answers (the node-reported role bonds, raw
// decimal; an Error = the read fails); storage: this wallet's storage nodes
// (storageByOwner rows).
const BONDS = { stakeMin: '200000000000000', storageBond: '100000000000000' };
function fakeClient({ generation = '4', nodeFp = NODE, signedNodeFp = nodeFp, expiry = '1700', witnesses, signedVid, signedUnstakeNodeFp = '', bonds = BONDS, storage = [] } = {}) {
  const coin = { nullifier: 'aa'.repeat(64), amount: '250000000000000' };
  const checks = ['format', 'op', 'chain', 'owner', 'subject', 'expiry', 'signature'].map(id => ({ id, ok: true, detail: `${id} ok` }));
  const builds = [];
  return {
    state: 'ready', identified: true, hf6able: true, stakeable: !!witnesses, fingerprint: OWN, chainId: '77'.repeat(32),
    hf6Rules: { consentWindow: '720', generation: 4, minTenureBlocks: '1440', storageExitLockEpochs: '12', validatorUnbondEpochs: '84' },
    builds,
    hf6Bonds: async () => { if (bonds instanceof Error) throw bonds; return { ...bonds }; },
    storageByOwner: async () => ({ tip: '1000', total: String(storage.length), epochStart: '720', set: '0', setCount: '0', nodes: storage.map(n => ({ ...n })) }),
    consentCheck: () => ({ ok: true, checks: checks.map(c => ({ ...c })), nodeFp, expiry }),
    balance: async () => ({ total: coin.amount, spendable: coin.amount }),
    list: async () => ({ tip: '1000', coins: [coin], truncated: false }),
    rulesetInfo: async () => ({ tip: '1000', generation, gen2Height: '0' }),
    ...(witnesses ? { validators: async () => ({ truncated: false, validators: witnesses }) } : {}),
    hf6Build: async args => {
      builds.push(args);
      const unstake = args.op === 'unstake', exit = args.op === 'storageExit';
      return {
        envelope: new Uint8Array([1]), intentId: 'cd'.repeat(64), wireId: 'ef'.repeat(64),
        decoded: { op: args.op, owner: OWN, nodeFp: unstake ? signedUnstakeNodeFp : exit ? args.nodeFp : signedNodeFp, validatorId: unstake ? signedVid ?? args.validatorId : '', bond: args.amount, commissionBps: args.commissionBps, consentExpiry: unstake || exit ? '' : expiry, fee: '1000000', change: String(BigInt(coin.amount) - BigInt(args.amount) - 1000000n), expiryHeight: args.expiryHeight, chainId: '77'.repeat(32), inputs: [coin.nullifier] }
      };
    },
    submit: async () => ({ accepted: true })
  };
}

test('roles: checkConsent passes the module lines through, checked for shape', () => {
  const r = checkConsent({ client: fakeClient(), from: OWN, kind: 'stake', text: 'x', tip: 1000n });
  assert.equal(r.ok, true);
  assert.equal(r.nodeFp, NODE);
  assert.equal(r.expiry, 1700n);
  const bad = fakeClient();
  bad.consentCheck = () => ({ ok: true, checks: [], nodeFp: NODE, expiry: '1' });
  assert.throws(() => checkConsent({ client: bad, from: OWN, kind: 'stake', text: 'x', tip: 1000n }), /invalid consent check/);
  assert.throws(() => checkConsent({ client: fakeClient(), from: OTHER, kind: 'stake', text: 'x', tip: 1000n }), /does not match/);
});

test('roles: prepareHf6 refuses below the HF-6 generation and builds at it', async () => {
  await assert.rejects(prepareHf6({ client: fakeClient({ generation: '3' }), from: OWN, kind: 'storageRegister', consent: 'x' }), { message: HF6_NOT_YET_TEXT });
  const t = await prepareHf6({ client: fakeClient(), from: OWN, kind: 'storageRegister', consent: 'x' });
  assert.equal(t.decoded.bond, BigInt(BONDS.storageBond));
  assert.equal(t.decoded.nodeFp, NODE);
  assert.equal(t.decoded.expiryHeight, 1090n, 'tip + 90');
  assert.equal(t.balanceAfter, 250000000000000n - 100000000000000n - 1000000n);
  assert.equal(consentEndsBefore(t.decoded.consentExpiry, t.decoded.expiryHeight), false);
});

// BUGS W-21: a consent that ends before the transaction's validity is
// refused before anything is built (it was a Review warning).
test('roles: prepareHf6 refuses a consent that expires before the transaction could be included', async () => {
  for (const kind of ['storageRegister', 'stake']) {
    const client = fakeClient({ expiry: '1089' });
    await assert.rejects(prepareHf6({ client, from: OWN, kind, consent: 'x', bond: '2000000', commissionBps: '0' }), { message: CONSENT_ENDS_EARLY_TEXT });
    assert.equal(client.builds.length, 0, 'nothing was built');
  }
  const edge = await prepareHf6({ client: fakeClient({ expiry: '1090' }), from: OWN, kind: 'storageRegister', consent: 'x' });
  assert.equal(edge.decoded.consentExpiry, 1090n, 'lasting to the last valid block passes');
});

// BUGS W-20: the bonds are the node's (chain params 19 / 21), read by
// prepareHf6 — what is built, not a compiled value.
test('roles: the node-reported bonds are what prepareHf6 builds; a failed read builds nothing', async () => {
  const bonds = { stakeMin: '15000050000000', storageBond: '50000000000000' };   // 150,000.5 and 500,000 NODUS
  const client = fakeClient({ bonds });
  const s = await prepareHf6({ client, from: OWN, kind: 'storageRegister', consent: 'x' });
  assert.equal(client.builds[0].amount, bonds.storageBond, 'the storage bond asked for is the node\'s');
  assert.equal(s.decoded.bond, 50000000000000n);
  assert.equal(new Map(s.review).get('Bond'), '500000.0 NODUS');
  await assert.rejects(prepareHf6({ client, from: OWN, kind: 'stake', consent: 'x', bond: '150000', commissionBps: '0' }), /at least 150000\.5 NODUS/);
  const w = await prepareHf6({ client, from: OWN, kind: 'stake', consent: 'x', bond: '150000.5', commissionBps: '0' });
  assert.equal(w.decoded.bond, 15000050000000n, 'the node\'s floor, below the compiled 2,000,000');
  const failing = fakeClient({ bonds: new Error('The network\'s bond amounts could not be read (rc=-1).') });
  for (const kind of ['storageRegister', 'stake']) {
    await assert.rejects(prepareHf6({ client: failing, from: OWN, kind, consent: 'x', bond: '2000000', commissionBps: '0' }), /bond amounts could not be read/);
  }
  assert.equal(failing.builds.length, 0, 'nothing was built');
  // the answer is checked for shape (the module resolved 0 and the range)
  assert.deepEqual(parseHf6Bonds(BONDS), { stakeMin: 200000000000000n, storageBond: 100000000000000n });
  for (const bad of [null, { stakeMin: '0', storageBond: '1' }, { stakeMin: '1', storageBond: '' }, { stakeMin: '01', storageBond: '1' }, { stakeMin: 5, storageBond: '1' }]) {
    assert.throws(() => parseHf6Bonds(bad), /invalid/, JSON.stringify(bad));
  }
  assert.deepEqual(await hf6Bonds({ client: fakeClient({ bonds }), from: OWN }), { stakeMin: 15000050000000n, storageBond: 50000000000000n });
  await assert.rejects(hf6Bonds({ client: fakeClient(), from: OTHER }), /does not match/);
});

// BUGS W-21: leaving storage re-reads this wallet's storage nodes and
// refuses (before any build) a node not listed or not storing.
test('roles: prepareHf6 storageExit builds only for a listed, storing node', async () => {
  const node = (fp, status) => ({ fp, status, bond: '100000000000000', failStreak: 0, graceUntil: '0', registered: '5', exit: '0', member: false, segments: '0' });
  const storage = [node(NODE, 1), node(NODE2, 2)];
  const ok = fakeClient({ storage });
  const t = await prepareHf6({ client: ok, from: OWN, kind: 'storageExit', nodeFp: NODE });
  assert.deepEqual(ok.builds.map(b => [b.op, b.nodeFp, b.amount]), [['storageExit', NODE, '0']]);
  assert.equal(t.decoded.bond, 0n);
  for (const [fp, pattern] of [[NODE2, /cannot leave now \(Leaving\)/], ['ee'.repeat(64), /not in this wallet's list of storage nodes/]]) {
    const client = fakeClient({ storage });
    await assert.rejects(prepareHf6({ client, from: OWN, kind: 'storageExit', nodeFp: fp }), pattern);
    assert.equal(client.builds.length, 0, 'nothing was built');
  }
});

test('roles: prepareHf6 refuses a signed node key that is not the consent\'s (G2/G3)', async () => {
  await assert.rejects(prepareHf6({ client: fakeClient({ signedNodeFp: NODE2 }), from: OWN, kind: 'storageRegister', consent: 'x' }), /does not match your request/);
});

test('roles: the witness bond is a floor', async () => {
  await assert.rejects(prepareHf6({ client: fakeClient(), from: OWN, kind: 'stake', consent: 'x', bond: '1999999', commissionBps: '1000' }), /at least/);
  const t = await prepareHf6({ client: fakeClient(), from: OWN, kind: 'stake', consent: 'x', bond: '2100000', commissionBps: '1000' });
  assert.equal(t.decoded.bond, 210000000000000n);
  assert.equal(t.decoded.commissionBps, 1000n);
});

// ── "Stop being a witness" (generation-4 UNSTAKE) ───────────────────────
// send-module.js validators() rows: status 0 active, 1 retiring, 4 eligible.
const VID3 = '7a'.repeat(64), VID4 = '8b'.repeat(64);
const wrow = (fp, vid, owner, status) => ({ fingerprint: fp, selfStake: '200000000000000', delegated: '0', commissionBps: 500, status, delegators: 0, hasV2: true, validatorId: vid, ownerFp: owner });
const WITNESSES = [
  wrow(NODE, VID, OWN, 0),          // this wallet's, active
  wrow(NODE2, VID2, OWN, 4),        // this wallet's, waiting for a seat
  wrow('9c'.repeat(64), VID3, OWN, 1),   // this wallet's, already leaving
  wrow('ad'.repeat(64), VID4, OTHER, 0)  // another wallet's
];

test('roles: "Stop being a witness" is offered for an active or eligible witness only; locks are epochs × E', () => {
  const { validators } = parseValidators({ truncated: false, validators: WITNESSES });
  assert.deepEqual(ownWitnesses(validators, OWN).filter(canStopWitness).map(v => v.validatorId), [VID, VID2]);
  assert.equal(canStopWitness(undefined), false);
  assert.equal(lockBlocks(84n, 720n), 60480n);
  assert.equal(lockBlocks(12n, 720n), 8640n);
  assert.equal(lockBlocks(null, 720n), null, 'the module does not carry the constant');
  assert.equal(lockBlocks(84n, null), null, 'no epoch length known');
  assert.equal(parseHf6Rules(fakeClient().hf6Rules).validatorUnbondEpochs, 84n);
  const { validatorUnbondEpochs, ...older } = fakeClient().hf6Rules;
  assert.equal(validatorUnbondEpochs, '84');
  assert.equal(parseHf6Rules(older).validatorUnbondEpochs, null, 'a module without it: no block count');
});

test('roles: prepareHf6 unstake builds for this wallet\'s active / eligible witness, no consent, no bond', async () => {
  for (const vid of [VID, VID2]) {
    const client = fakeClient({ witnesses: WITNESSES });
    const t = await prepareHf6({ client, from: OWN, kind: 'unstake', validatorId: vid });
    assert.deepEqual(client.builds.map(b => [b.op, b.consent, b.validatorId, b.nodeFp, b.amount, b.commissionBps]), [['unstake', '', vid, '', '0', '0']]);
    assert.equal(t.decoded.bond, 0n);
    assert.equal(t.decoded.validatorId, vid);
    assert.equal(t.decoded.nodeFp, '');
    assert.equal(t.decoded.consentExpiry, null);
    assert.equal(t.balanceAfter, 250000000000000n - 1000000n, 'fee only');
    const rows = new Map(t.review);
    assert.equal(rows.get('Action'), 'Stop being a witness');
    assert.equal(rows.get('Witness'), vid);
    assert.ok(rows.has('Network fee') && rows.has('Balance after'));
    assert.ok(!rows.has('Node key fingerprint') && !rows.has('Bond') && !rows.has('Consent valid until block'), 'no node key, no bond, no consent');
  }
});

test('roles: prepareHf6 unstake refuses before building what the chain would refuse', async () => {
  const refuse = async (args, pattern, client = fakeClient({ witnesses: WITNESSES })) => {
    await assert.rejects(prepareHf6({ client, from: OWN, kind: 'unstake', ...args }), pattern);
    assert.equal(client.builds.length, 0, 'nothing was built');
  };
  await refuse({ validatorId: VID3 }, /cannot stop now \(Leaving\)/);
  await refuse({ validatorId: VID4 }, /not one of this wallet's witnesses/);
  await refuse({ validatorId: 'be'.repeat(64) }, /not one of this wallet's witnesses/);
  await refuse({ validatorId: '0'.repeat(128) }, /Choose one of your witnesses/);
  await refuse({ validatorId: '' }, /Choose one of your witnesses/);
  await refuse({ validatorId: VID }, /witness list is not available/, fakeClient());
  await refuse({ validatorId: VID }, { message: HF6_NOT_YET_TEXT }, fakeClient({ witnesses: WITNESSES, generation: '3' }));
});

test('roles: prepareHf6 unstake refuses a signed witness id or node key that is not the request\'s', async () => {
  await assert.rejects(prepareHf6({ client: fakeClient({ witnesses: WITNESSES, signedVid: VID2 }), from: OWN, kind: 'unstake', validatorId: VID }), /does not match your request/);
  await assert.rejects(prepareHf6({ client: fakeClient({ witnesses: WITNESSES, signedUnstakeNodeFp: NODE }), from: OWN, kind: 'unstake', validatorId: VID }), /invalid transaction/);
});
