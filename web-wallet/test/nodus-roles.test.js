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
// owned by this wallet only; the Review warning fires exactly when the
// consent expires before the transaction's validity; the earliest heights
// of the timing facts; the validator list keeps the generation-4 ids and
// refuses all-zero ones; the storage list's shape rules; prepareHf6 refuses
// below the HF-6 generation and refuses a signed transaction whose node key
// is not the consent's. "Stop being a witness" (prepareHf6 kind 'unstake',
// the generation-4 UNSTAKE): offered only for this wallet's own active /
// eligible witnesses (canStopWitness; the adapter refuses another owner's,
// a leaving one, an unknown or all-zero id, a module without the witness
// list), built with no consent and no bond, its review names the witness
// and has no node key line, and a signed witness id or node key that is not
// the request's is refused; the lock block counts are epochs × E.
// Requires: nothing beyond `npm ci` (node --test). Leaves nothing behind.
// How it can lie: the client is a fake — the module's own consent checks,
// signature verification and envelope bytes are NOT exercised here (that is
// test/hf6-connect-wasm.test.js and the parity build); the numbers below are
// fixtures, not chain values.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  suggestExpiry, EXPIRY_MARGIN, percentToBps, gateOpen, ownWitnesses, consentExpiresEarly, consentCommand,
  epochStartAtOrAfter, witnessJoinFrom, rotationHeights, storageExitHeights, canStopWitness, lockBlocks
} from '../src/nodus-roles.js';
import { parseValidators, parseStorageByOwner, checkConsent, prepareHf6, parseHf6Rules, HF6_NOT_YET_TEXT } from '../src/adapters/nodus.js';

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

test('roles: the consent warning fires exactly when the consent expires first', () => {
  assert.equal(consentExpiresEarly(1050n, 1090n), true);
  assert.equal(consentExpiresEarly(1090n, 1090n), false);
  assert.equal(consentExpiresEarly(1700n, 1090n), false);
  assert.equal(consentExpiresEarly(null, 1090n), false, 'storage exit: no consent');
});

test('roles: the node commands are the forms nodus-cli accepts', () => {
  assert.equal(consentCommand({ kind: 'stake', owner: OWN, expiry: '1710' }), `nodus-cli -i ~/.nodus -s 127.0.0.1 validator consent --op stake --owner ${OWN} --expiry 1710`);
  assert.equal(consentCommand({ kind: 'storageRegister', owner: OWN, expiry: '1710' }), `nodus-cli -i ~/.nodus -s 127.0.0.1 storage consent --owner ${OWN} --expiry 1710`);
  assert.equal(consentCommand({ kind: 'rotate', owner: OWN, expiry: '1710', validatorId: VID }), `nodus-cli -i ~/.nodus -s 127.0.0.1 validator consent --op rotate --owner ${OWN} --subject ${VID} --expiry 1710`);
});

test('roles: the earliest heights of the timing facts', () => {
  assert.equal(epochStartAtOrAfter(720n, 720n), 720n);
  assert.equal(epochStartAtOrAfter(721n, 720n), 1440n);
  assert.equal(witnessJoinFrom(1000n, 1440n), 2441n);
  assert.equal(witnessJoinFrom(1000n, null), null);
  // tip 1000 -> F = 1440, U = 2160
  assert.deepEqual(rotationHeights(1000n, 720n), { boundary: 1440n, switchAt: 2160n, keepThrough: 2161n, keepThroughStorage: 2520n, releasedAt: 2880n });
  assert.equal(rotationHeights(1000n, null), null);
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
function fakeClient({ generation = '4', nodeFp = NODE, signedNodeFp = nodeFp, expiry = '1700', witnesses, signedVid, signedUnstakeNodeFp = '' } = {}) {
  const coin = { nullifier: 'aa'.repeat(64), amount: '250000000000000' };
  const checks = ['format', 'op', 'chain', 'owner', 'subject', 'expiry', 'signature'].map(id => ({ id, ok: true, detail: `${id} ok` }));
  const builds = [];
  return {
    state: 'ready', identified: true, hf6able: true, stakeable: !!witnesses, fingerprint: OWN, chainId: '77'.repeat(32),
    hf6Rules: { stakeMin: '200000000000000', storageBond: '100000000000000', consentWindow: '720', generation: 4, minTenureBlocks: '1440', storageExitLockEpochs: '12', validatorUnbondEpochs: '84' },
    builds,
    consentCheck: () => ({ ok: true, checks: checks.map(c => ({ ...c })), nodeFp, expiry }),
    balance: async () => ({ total: coin.amount, spendable: coin.amount }),
    list: async () => ({ tip: '1000', coins: [coin], truncated: false }),
    rulesetInfo: async () => ({ tip: '1000', generation, gen2Height: '0' }),
    ...(witnesses ? { validators: async () => ({ truncated: false, validators: witnesses }) } : {}),
    hf6Build: async args => {
      builds.push(args);
      const unstake = args.op === 'unstake';
      return {
        envelope: new Uint8Array([1]), intentId: 'cd'.repeat(64), wireId: 'ef'.repeat(64),
        decoded: { op: args.op, owner: OWN, nodeFp: unstake ? signedUnstakeNodeFp : signedNodeFp, validatorId: unstake ? signedVid ?? args.validatorId : '', bond: args.amount, commissionBps: args.commissionBps, consentExpiry: unstake ? '' : expiry, fee: '1000000', change: String(BigInt(coin.amount) - BigInt(args.amount) - 1000000n), expiryHeight: args.expiryHeight, chainId: '77'.repeat(32), inputs: [coin.nullifier] }
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
  assert.equal(t.decoded.bond, parseHf6Rules(fakeClient().hf6Rules).storageBond);
  assert.equal(t.decoded.nodeFp, NODE);
  assert.equal(t.decoded.expiryHeight, 1090n, 'tip + 90');
  assert.equal(t.balanceAfter, 250000000000000n - 100000000000000n - 1000000n);
  assert.equal(consentExpiresEarly(t.decoded.consentExpiry, t.decoded.expiryHeight), false);
  const early = await prepareHf6({ client: fakeClient({ expiry: '1050' }), from: OWN, kind: 'storageRegister', consent: 'x' });
  assert.equal(consentExpiresEarly(early.decoded.consentExpiry, early.decoded.expiryHeight), true);
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
