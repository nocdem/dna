import test from 'node:test';
import assert from 'node:assert/strict';
import { Transaction, verifyTypedData } from 'ethers';
import { Caip25EndowmentPermissionName, setEthAccounts } from '@metamask/chain-agnostic-permission';
import { setup, account, payTo } from './swap-fixture.js';
import { SEPOLIA } from '../src/constants/evm-networks.js';
import { connectDetails, createWalletUi } from '../src/ui/wallet-ui.js';
import { NODUS_PERMISSION } from '../src/background/permissions.js';

// Extension tests of plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 6 and section 19 line 666 (operator
// 2026-11-10, givens item 81: "Her site eklentiyi Sepolia'ya geçirebilsin."): a website's wallet_switchEthereumChain to
// 0xaa36a7 asks for the chain permission and the user's approval along today's path and is no longer answered 4902.
// Environment: Node >=22.14, pinned packages, injected Ethereum RPC stub that answers chain id 0xaa36a7 for a URL
// containing "sepolia" (swap-fixture.js); no flags, no network, no output files. Leftovers: none.
// How they could falsely pass: the RPC stub chooses the chain id by URL text, so a test proves the extension asked the
// Sepolia endpoint and refused a wrong chain id, not that publicnode serves Sepolia (the pinned chain list names it:
// eip155-11155111.json:13). Typed data is verified with ethers' own recovery.
const typedFor = chainId => ({ domain: { name: 'Public fixture', chainId }, primaryType: 'Message',
  types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }], Message: [{ name: 'text', type: 'string' }] }, message: { text: 'public typed message' } });
const switchTo = (remote, chainId) => remote.request('wallet_switchEthereumChain', [{ chainId }]);

// Walks the permission approval and then the switch approval, as the existing BSC test does.
async function approveSwitch(f, switching) {
  const permission = await f.nextApproval(switching); assert.equal(permission.type, 'wallet_requestPermissions');
  const approved = structuredClone(permission.requestData), caveat = approved.permissions[Caip25EndowmentPermissionName].caveats[0];
  caveat.value = setEthAccounts(caveat.value, [account.toLowerCase()]);
  await f.background.permissions.acceptPermissionsRequest(approved);
  const pending = await f.nextApproval(switching); assert.equal(pending.type, 'wallet_switchEthereumChain');
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  return { permission, pending };
}

// Proves the switch asks the chain permission and the user's approval, is not answered 4902, and then every site
// read answers Sepolia from the Sepolia endpoint. A test of eth_chainId alone would miss a permission skipped.
test('a site switch to 0xaa36a7 asks permission and approval, then the provider is Sepolia', async t => {
  const f = await setup(t), remote = f.site(); await f.connectEthereum(remote, ['0x1']);
  assert.equal((await remote.request('eth_chainId')).result, '0x1');
  const switching = switchTo(remote, '0xaa36a7');
  const { permission, pending } = await approveSwitch(f, switching);
  assert.equal((await switching).result, null);
  assert.equal(pending.requestData.targetChain, 'sepolia'); assert.equal(pending.requestData.chain, 'ethereum');
  assert.deepEqual(Object.keys(permission.requestData.permissions), [Caip25EndowmentPermissionName]);
  assert.deepEqual(new Set(f.background.permissions.getChainIds(remote.origin)), new Set(['0x1', '0xaa36a7']));
  assert.equal((await remote.request('eth_chainId')).result, '0xaa36a7'); assert.equal((await remote.request('net_version')).result, '11155111');
  assert.equal((await remote.request('eth_blockNumber')).result, '0x10');
  assert.ok(f.calls.some(call => call.method === 'eth_blockNumber' && call.url === `${SEPOLIA.endpoint}/`));
  assert.equal(f.background.evm.getState().selectedChain, 'sepolia');
  assert.equal((await f.background.engine.getNetworkState()).chainId, '0xaa36a7');
});

// Proves a refused switch leaves the selected network unchanged, at both prompts: the chain permission and the switch.
test('a refused switch to Sepolia leaves the selected network unchanged', async t => {
  const f = await setup(t), remote = f.site(); await f.connectEthereum(remote, ['0x1']);
  let switching = switchTo(remote, '0xaa36a7'), permission = await f.nextApproval(switching);
  f.background.approvals.reject(permission.id); assert.equal((await switching).error.code, 4001);
  assert.equal(f.background.evm.getState().selectedChain, 'ethereum'); assert.equal((await remote.request('eth_chainId')).result, '0x1');
  assert.equal(f.background.permissions.getChainIds(remote.origin).includes('0xaa36a7'), false);
  switching = switchTo(remote, '0xaa36a7'); permission = await f.nextApproval(switching);
  const approved = structuredClone(permission.requestData), caveat = approved.permissions[Caip25EndowmentPermissionName].caveats[0];
  caveat.value = setEthAccounts(caveat.value, [account.toLowerCase()]); await f.background.permissions.acceptPermissionsRequest(approved);
  const pending = await f.nextApproval(switching); f.background.approvals.reject(pending.id);
  assert.equal((await switching).error.code, 4001);
  assert.equal(f.background.evm.getState().selectedChain, 'ethereum'); assert.equal((await remote.request('eth_chainId')).result, '0x1');
});

// Proves that after an approved switch typed data with domain chain id 11155111 is signed and one with chain id 1 is
// refused, before any prompt; the recovered signer is the wallet's account.
test('after the switch, typed data for chain id 11155111 is signed and chain id 1 is refused', async t => {
  const f = await setup(t), remote = f.site(); await f.connectEthereum(remote, ['0x1']);
  const switching = switchTo(remote, '0xaa36a7'); await approveSwitch(f, switching); await switching;
  const wrong = await remote.request('eth_signTypedData_v4', [account, JSON.stringify(typedFor(1))]);
  assert.equal(wrong.error.code, -32602); assert.match(wrong.error.message, /different network/); assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  const signing = remote.request('eth_signTypedData_v4', [account, JSON.stringify(typedFor(11155111))]), pending = await f.nextApproval(signing);
  assert.equal(pending.type, 'eth_signTypedData'); assert.equal(pending.requestData.chain, 'sepolia');
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  const typed = typedFor(11155111), { EIP712Domain: _domain, ...types } = typed.types;
  assert.equal(verifyTypedData(typed.domain, types, typed.message, (await signing).result), account);
});

// Proves a site transaction is prepared for 11155111 (and one for chain id 1 is refused), is sent through the Sepolia
// endpoint, and leaves no mainnet Activity row (my choice, documented in evm.js).
test('after the switch, a site transaction is prepared and sent for chain id 11155111', async t => {
  const f = await setup(t), remote = f.site(); await f.connectEthereum(remote, ['0x1']);
  const switching = switchTo(remote, '0xaa36a7'); await approveSwitch(f, switching); await switching;
  const wrong = await remote.request('eth_sendTransaction', [{ from: account, to: payTo, value: '0x7b', chainId: '0x1' }]);
  assert.equal(wrong.error.code, -32602); assert.match(wrong.error.message, /different network/);
  const sending = remote.request('eth_sendTransaction', [{ from: account, to: payTo, value: '0x7b', chainId: '0xaa36a7' }]), pending = await f.nextApproval(sending);
  assert.equal(pending.type, 'transaction'); assert.equal(pending.requestData.chain, 'sepolia');
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  const answer = await sending; assert.equal(answer.error, undefined);
  assert.equal(f.raw.length, 1); const transaction = Transaction.from(f.raw[0]);
  assert.equal(transaction.chainId, 11155111n); assert.equal(transaction.to.toLowerCase(), payTo); assert.equal(transaction.value, 123n);
  const sent = f.calls.find(call => call.method === 'eth_sendRawTransaction'); assert.equal(sent.url, `${SEPOLIA.endpoint}/`);
  assert.equal(answer.result, transaction.hash);
  assert.equal(f.background.nodus.chainActivity('ethereum').rows().length, 0, 'no mainnet Activity row for a Sepolia transaction');
});

// Proves switches to 1 and 56 behave as before (permission and approval, then the chain id), 4902 stays for an unknown
// chain, and a switch from Sepolia back to Ethereum works.
test('switches to 0x1 and 0x38 behave as before and unknown chains still answer 4902', async t => {
  const f = await setup(t), remote = f.site(); await f.connectEthereum(remote, ['0x1', '0x38', '0xaa36a7']);
  for (const [chainId, expected, key] of [['0x38', '0x38', 'bsc'], ['0xaa36a7', '0xaa36a7', 'sepolia'], ['0x1', '0x1', 'ethereum']]) {
    const switching = switchTo(remote, chainId), pending = await f.nextApproval(switching);
    assert.equal(pending.type, 'wallet_switchEthereumChain'); assert.equal(pending.requestData.targetChain, key);
    await f.background.approvals.controller.acceptRequest(pending.id, true); assert.equal((await switching).result, null);
    assert.equal((await remote.request('eth_chainId')).result, expected);
  }
  assert.equal((await switchTo(remote, '0x1')).result, null, 'switching to the selected chain needs no prompt');
  for (const chainId of ['0x2', '0xaa36a8']) assert.equal((await switchTo(remote, chainId)).error.code, 4902);
  assert.equal((await switchTo(remote, 'invalid')).error.code, -32602);
});

// Proves a Sepolia choice is not restored after a restart (the operator's "yeniden acista mainnet", the networks.js
// reset), the saved endpoint state holds one endpoint per network (the test networks included), and the wallet's own
// screens answer for Sepolia (approved plan section 5.6: it is a listed network of the Ethereum selector).
test('a restart returns to Ethereum; saved endpoints cover every network; wallet screens answer for Sepolia', async t => {
  const f = await setup(t);
  await f.background.evm.selectNetwork('sepolia'); await f.background.store.flush();
  assert.equal(f.background.networks.get('ethereum').id, 'sepolia', 'the site switch and the selector are one choice');
  assert.deepEqual(Object.keys(f.background.store.backup().EvmController.endpoints).sort(), ['bsc', 'bsctestnet', 'ethereum', 'sepolia']);
  const restarted = await (async () => {
    const module = await import('../src/background/index.js');
    return module.createBackground({ ...f.fixture, runtime: { ...f.fixture.runtime, onConnect: { addListener() {}, removeListener() {} } } });
  })();
  try { assert.equal(restarted.evm.getState().selectedChain, 'ethereum'); assert.equal((await restarted.engine.getNetworkState()).chainId, '0x1'); }
  finally { await restarted.destroy(); }
  assert.deepEqual(await f.background.evm.getBalances('sepolia'), [{ symbol: 'ETH', balance: '10.0' }]);
  await f.background.evm.setEndpoint('sepolia', SEPOLIA.endpoint);
  await assert.rejects(f.background.evm.getBalances('unknown'), /Unsupported EVM network/);
});

// Proves the permission screen understands the chain permission a Sepolia switch asks for and offers Sepolia only then:
// a first connection still lists Ethereum and BNB Smart Chain only.
test('the connection screen lists Sepolia only when the request names it', async t => {
  const f = await setup(t), remote = f.site(), connecting = remote.request('eth_requestAccounts'), first = await f.nextApproval(connecting);
  assert.deepEqual(connectDetails(first).networks.map(network => network.key), ['ethereum', 'bsc']);
  f.background.approvals.reject(first.id); assert.equal((await connecting).error.code, 4001);
  const known = f.site('https://known.example'); await f.connectEthereum(known, ['0x1']);
  const switching = switchTo(known, '0xaa36a7'), permission = await f.nextApproval(switching);
  const offered = connectDetails(permission).networks;
  assert.deepEqual(offered.find(network => network.key === 'sepolia'), { key: 'sepolia', name: 'Ethereum Sepolia', chainId: '0xaa36a7' });
  assert.equal(offered.some(network => network.key === 'bsc'), false);
  f.background.approvals.reject(permission.id); assert.equal((await switching).error.code, 4001);
});

// Proves a site that already holds the Nodus permission and the Ethereum connection (the swap site, givens items 68 and
// 81) can switch to 0xaa36a7: the permission request of the switch carries the site's existing Nodus permission next
// to the new chain scope, the connection screen accepts it and lists the account and Sepolia, approving it through the
// screen's own approveConnect grants Sepolia, the switch completes, and the Nodus permission and its account caveat
// are as they were. How it could falsely pass: the fake client below only forwards approvePermissionsRequest to the
// background, so a screen that renders wrongly is not seen here (ui-flows.test.js covers rendering); the account caveat
// is compared with a snapshot taken before the switch, so a background that re-pinned the same value would also pass,
// which is the intended behaviour.
test('a site holding the Nodus permission can switch to Sepolia through the connection screen', async t => {
  const f = await setup(t), remote = f.site(); await f.connectNodus(remote); await f.connectEthereum(remote, ['0x1']);
  const nodusBefore = structuredClone(f.background.permissions.controller.getPermissions(remote.origin)[NODUS_PERMISSION]);
  assert.equal(nodusBefore.caveats.length, 1);
  const switching = switchTo(remote, '0xaa36a7'), permission = await f.nextApproval(switching);
  assert.equal(permission.type, 'wallet_requestPermissions');
  assert.deepEqual(Object.keys(permission.requestData.permissions).sort(), [Caip25EndowmentPermissionName, NODUS_PERMISSION].sort());
  const details = connectDetails(permission);
  assert.ok(details.networks.some(network => network.key === 'sepolia'));
  const requests = [], ui = createWalletUi({ request: async (method, args) => {
    requests.push(method);
    return method === 'getState' ? { isUnlocked: false } : f.background.permissions.acceptPermissionsRequest(args[0]);
  } });
  await ui.approveConnect(permission, [account.toLowerCase()], details.networks.map(network => network.chainId));
  assert.deepEqual(requests, ['approvePermissionsRequest', 'getState']);
  const pending = await f.nextApproval(switching); assert.equal(pending.type, 'wallet_switchEthereumChain');
  await f.background.approvals.controller.acceptRequest(pending.id, true);
  assert.equal((await switching).result, null);
  assert.ok(f.background.permissions.getChainIds(remote.origin).includes('0xaa36a7'));
  assert.equal((await remote.request('eth_chainId')).result, '0xaa36a7');
  assert.deepEqual(f.background.permissions.controller.getPermissions(remote.origin)[NODUS_PERMISSION].caveats, nodusBefore.caveats);
  assert.deepEqual(f.background.permissions.getNodusAccounts(remote.origin).map(item => item.address), [f.nodusMock.state.fingerprint]);
});

// Proves the screen still refuses an incremental request whose extra permissions are not exactly the site's existing
// ones, unchanged: a changed Nodus caveat, a permission the site does not hold, a permission listed as changed by the
// diff, and the same Nodus permission without any diff (a non-incremental request keeps the old rule). Each case is a
// copy of the real request of the Sepolia switch with one edit, and approveConnect must refuse it as well. How it
// could falsely pass: a refusal for another reason would also match the message, so the unedited copy is checked to
// pass first.
test('the connection screen refuses an incremental request that changes or adds a non-Ethereum permission', async t => {
  const f = await setup(t), remote = f.site(); await f.connectNodus(remote); await f.connectEthereum(remote, ['0x1']);
  const switching = switchTo(remote, '0xaa36a7'), permission = await f.nextApproval(switching);
  assert.doesNotThrow(() => connectDetails(permission));
  const edited = change => { const copy = structuredClone(permission); change(copy.requestData); return copy; };
  const cases = {
    'changed Nodus caveat': edited(data => {
      // The request shares the unchanged permission object with diff.currentPermissions, so replace it by a new object.
      const held = data.permissions[NODUS_PERMISSION], [caveat] = held.caveats;
      data.permissions[NODUS_PERMISSION] = { ...held, caveats: [{ ...caveat, value: { ...caveat.value, address: 'ef'.repeat(64) } }] };
    }),
    'extra permission the site does not hold': edited(data => { data.permissions.unexpected = {}; }),
    'extra permission listed as changed': edited(data => { data.diff.permissionDiffMap[NODUS_PERMISSION] = {}; }),
    'Nodus permission without a diff': edited(data => { delete data.diff; }),
  };
  const ui = createWalletUi({ request: async () => assert.fail('a refused request must not reach the background') });
  for (const [name, request] of Object.entries(cases)) {
    assert.throws(() => connectDetails(request), /Unsupported connection permissions/, name);
    await assert.rejects(ui.approveConnect(request, [account.toLowerCase()], ['0xaa36a7']), /Unsupported connection permissions/, name);
  }
  f.background.approvals.reject(permission.id); assert.equal((await switching).error.code, 4001);
});
