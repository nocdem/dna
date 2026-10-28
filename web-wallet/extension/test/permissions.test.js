import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { JsonRpcEngine } from '@metamask/json-rpc-engine';
import { Caip25EndowmentPermissionName, Caip25CaveatType, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { createLockCoordinator } from '../src/background/lock.js';
import { createPermissions, SEND_METADATA } from '../src/background/permissions.js';
import { createApprovals } from '../src/background/approvals.js';

// Node >=22.14; no flags/network/disk output. Public unlocked account state is a fixture; controllers are real.
const account = '0xf278cf59f82edcf871d630f28ecc8056f25c1cdb';
async function fixture(t) {
  const messenger = new Messenger({ namespace: 'Background' }), lockCoordinator = createLockCoordinator();
  const windows = { onRemoved: { addListener() {}, removeListener() {} }, async getAll() { return []; }, async getLastFocused() { return {}; },
    async create(options) { return { ...options, id: 1 }; }, async update() {} };
  const approvals = createApprovals({ messenger, windows, runtime: { id: 'fixture', getURL: path => path } });
  const permissions = createPermissions({ messenger, approvals, lockCoordinator,
    runtime: { id: 'fixture' }, getNetworkState: () => ({ chainId: '0x1', networkVersion: '1', isConnected: true }) });
  permissions.setAccounts([account]); await lockCoordinator.unlock(async () => {});
  const engine = new JsonRpcEngine();
  engine.push((req, _res, next) => { req.origin = 'https://site.example'; next(); });
  engine.push(permissions.createEthAccountsMethodMiddleware()); engine.push(permissions.createPermissionMiddleware('https://site.example'));
  engine.push(permissions.createEip1193MethodMiddleware());
  let id = 0;
  const request = (method, params) => engine.handle({ id: ++id, jsonrpc: '2.0', method, params });
  t.after(() => { engine.destroy(); approvals.destroy(); });
  return { permissions, approvals, request, lockCoordinator };
}
async function pendingApproval(approvals) {
  for (let turn = 0; turn < 40; turn++) {
    const pending = Object.values(approvals.controller.state.pendingApprovals)[0];
    if (pending) return pending;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail('No approval was created');
}
function approvedRequest(pending) {
  const request = structuredClone(pending.requestData);
  const caveat = request.permissions[Caip25EndowmentPermissionName].caveats.find(item => item.type === Caip25CaveatType);
  caveat.value = setEthAccounts(caveat.value, [account]);
  return request;
}

// Proves CAIP-25 is granted only through real approval and legacy APIs translate/revoke it; a pre-granted fixture could bypass the approval boundary.
test('accounts require approval and legacy permission methods expose the CAIP-25 grant', async t => {
  const { permissions, approvals, request } = await fixture(t);
  assert.deepEqual((await request('eth_accounts')).result, []);
  const connecting = request('eth_requestAccounts'), pending = await pendingApproval(approvals);
  assert.equal(pending.origin, 'https://site.example'); assert.equal(pending.type, 'wallet_requestPermissions');
  assert.deepEqual((await request('eth_accounts')).result, []);
  await permissions.acceptPermissionsRequest(approvedRequest(pending));
  assert.deepEqual((await connecting).result, [account]);
  const listed = (await request('wallet_getPermissions')).result;
  assert.equal(listed[0].parentCapability, 'eth_accounts'); assert.deepEqual(listed[0].caveats[0].value, [account]);
  assert.equal((await request('wallet_revokePermissions', [{ eth_accounts: {} }])).result, null);
  assert.deepEqual((await request('eth_accounts')).result, []);
  const denied = request('wallet_requestPermissions', [{ eth_accounts: {} }]);
  approvals.reject((await pendingApproval(approvals)).id); assert.equal((await denied).error.code, 4001);
});

// Proves permission reads/approval follow getPermittedAccounts without a lock check; an ungranted origin alone would hide the withdrawn lock-hiding behaviour.
test('lock preserves permitted accounts and provider discovery retains the runtime id', async t => {
  const { permissions, approvals, request, lockCoordinator } = await fixture(t);
  const connecting = request('eth_requestAccounts'), pending = await pendingApproval(approvals);
  await lockCoordinator.lock();
  assert.deepEqual((await request('eth_accounts')).result, []);
  await permissions.acceptPermissionsRequest(approvedRequest(pending));
  assert.deepEqual((await connecting).result, [account]);
  assert.deepEqual((await request('eth_accounts')).result, [account]);
  assert.deepEqual((await request('eth_requestAccounts')).result, [account]);
  const denied = request('wallet_requestPermissions', [{ eth_accounts: {} }]);
  approvals.reject((await pendingApproval(approvals)).id); assert.equal((await denied).error.code, 4001);
  const discovery = (await request('nodus_getProviderState')).result;
  assert.equal(discovery.extensionId, 'fixture'); assert.deepEqual(discovery.accounts, [account]);
  assert.equal(SEND_METADATA, 'nodus_sendDomainMetadata');
  assert.equal((await request(SEND_METADATA, { name: 'fixture' })).result, true);
  assert.equal((await request('nodus_logWeb3ShimUsage')).result, true);
  assert.equal((await request('resolvePendingApproval', ['anything'])).error.code, -32601);
});
