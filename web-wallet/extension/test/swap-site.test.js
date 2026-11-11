import test from 'node:test';
import assert from 'node:assert/strict';
import { Interface, Transaction, getAddress, verifyTypedData } from 'ethers';
import { setup, account, token, payTo, BOT, foundationNodus, wireId, nodusPublicKey, nodusSignature } from './swap-fixture.js';
import { liquidityAddText, liquidityAddTyped, nodusToUsdtText, usdtToNodusTyped } from '../src/background/swap-texts.js';
import { SWAP_METHODS } from '../src/constants/swap.js';

// Extension tests of plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 1 and section 19 line 666 (givens items
// 84, 88, 97): the extension that pays signs the user's request, posts it to the bot at the address the site gives, and
// pays ONLY if that request reached the bot. Environment: Node >=22.14, pinned packages, committed WASM, injected
// stubs for Ethereum RPC, the bot and the Nodus module (swap-fixture.js); no flags, no network, no output files.
// Leftovers: none (every background is destroyed by the fixture). How these tests could falsely pass: the stub bot
// and the fake Nodus signature prove ordering and routing only, not TLS, CORS or the real bot; a payment that is
// "not sent" is shown by the stub RPC / module seeing no call, so a payment sent through a path that bypasses
// both stubs would go unseen (the fixture's fetch mock throws on any unexpected RPC method and on any other URL).
const erc20 = new Interface(['function transfer(address,uint256) returns (bool)']);
const destinationNodus = 'ef'.repeat(64);

// What a user-visible request looks like for each direction.
function usdtRequest(overrides = {}) {
  return { from: account, botUrl: BOT, token, payTo, destination: destinationNodus, amount: '25000000', minimumToReceive: '240000000000', requestNumber: '123456789', ...overrides };
}
async function connectBoth(f, remote) { await f.connectEthereum(remote); return f.connectNodus(remote); }
async function hold(f, remote, nodusAccount, amount = '200000000') {
  const holding = remote.request(SWAP_METHODS.holdTransfer, [{ account: nodusAccount.address, to: foundationNodus, amount }]);
  const [pending] = await f.walk(holding, ['nodus_swapPayment']);
  const answer = await holding; assert.equal(answer.error, undefined);
  return { answer: answer.result, pending };
}
function nodusText(f, nodusAccount, held, overrides = {}) {
  return nodusToUsdtText({ sender: nodusAccount.address, destination: account.toLowerCase(), amount: 200000000n, minimumToReceive: 4950000n,
    transferId: held.transferId, chainId: held.chainId, requestNumber: '123456789', ...overrides });
}

// ---- USDT -> NODUS ----

// Proves the typed request is signed by the user's key with the plan's domain and fields, posted to the bot at the
// site's address with the flat body of plan 6.4.7, and the USDT `transfer(payTo, amount)` of the named token is
// broadcast only AFTER that post. A test of the payment alone would miss the order; one of the post alone, the tie.
test('USDT -> NODUS: the typed request is signed and posted, then the USDT transfer is paid', async t => {
  const f = await setup(t), remote = f.site(); await connectBoth(f, remote);
  const request = usdtRequest(), swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [request]);
  const [signature, payment] = await f.walk(swapping, ['eth_signTypedData', 'nodus_swapPayment']);
  const answer = await swapping; assert.equal(answer.error, undefined);
  // The signature approval shows the exact typed request.
  for (const text of ['"name": "Nodus Swap"', '"chainId": 1', '"amount": "25000000"', `"destination": "${destinationNodus}"`, '"requestNumber": "123456789"']) assert.ok(signature.requestData.text.includes(text), text);
  // Exactly one post, to the fixed path of the bot at the origin the site gave.
  assert.equal(f.botCalls.length, 1); assert.equal(f.botCalls[0].url, `${BOT}/amm/swap`); assert.equal(f.botCalls[0].method, 'POST');
  const body = f.botCalls[0].body;
  assert.deepEqual(Object.keys(body).sort(), ['amount', 'destination', 'kind', 'minimumToReceive', 'requestNumber', 'sender', 'signature']);
  assert.equal(body.kind, 'usdt_to_nodus'); assert.equal(body.sender, account.toLowerCase()); assert.equal(body.destination, destinationNodus);
  assert.match(body.signature, /^0x[0-9a-f]{130}$/);
  // The signature is the user's: ethers recovers the account from the plan's typed data with domain chain id 1.
  const typed = usdtToNodusTyped({ chainId: 1, sender: body.sender, destination: body.destination, amount: body.amount, minimumToReceive: body.minimumToReceive, requestNumber: body.requestNumber });
  const { EIP712Domain: _domain, ...types } = typed.types;
  assert.equal(verifyTypedData(typed.domain, types, typed.message, body.signature), account);
  // The payment: one raw transaction after the post, a USDT transfer of the named token to the named address.
  assert.deepEqual(f.events, ['bot', 'eth_sendRawTransaction']);
  const transaction = Transaction.from(f.raw[0]);
  assert.equal(transaction.to.toLowerCase(), token); assert.equal(transaction.chainId, 1n); assert.equal(transaction.value, 0n);
  const decoded = erc20.decodeFunctionData('transfer', transaction.data);
  assert.equal(decoded[0].toLowerCase(), payTo); assert.equal(decoded[1], 25000000n);
  // The payment approval shows the exact amount and destinations.
  const rows = Object.fromEntries(payment.requestData.rows);
  assert.equal(rows['Pay to'], getAddress(payTo)); assert.equal(rows['Token contract'], getAddress(token)); assert.ok(rows.Amount.startsWith('25.0 USDT')); assert.equal(rows['Bot that received the request'], BOT);
  assert.equal(answer.result.delivered, true); assert.equal(answer.result.paid, true); assert.equal(answer.result.hash, Transaction.from(f.raw[0]).hash);
});

// Proves nothing is paid, and no payment approval is even shown, when the request did not reach the bot: a refused
// connection, an HTTP error, a forwarder's 502, the bot refusing with received:false, and a 200 that is not the bot's
// answer. Testing only one failure mode would miss a path that treats "an HTTP answer" as delivery.
for (const [mode, answered] of [['refuse', false], ['error', true], ['gateway', true], ['reject', true], ['plain', true]]) {
  test(`USDT -> NODUS: nothing is paid when the bot ${mode === 'refuse' ? 'refuses the connection' : `answers (${mode})`}`, async t => {
    const f = await setup(t), remote = f.site(); await connectBoth(f, remote); f.state.bot = mode;
    const swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest()]);
    await f.walk(swapping, ['eth_signTypedData']);
    const answer = await swapping;
    assert.equal(answer.error.code, -32603); assert.match(answer.error.message, /Nothing was paid/);
    // The pinned @metamask/rpc-errors 7.0.3 serializes object data with a `cause` field (null when absent): dist/classes.cjs:56.
    assert.deepEqual(answer.error.data, { delivered: false, paid: false, answered, reason: answer.error.data.reason, cause: null });
    if (mode === 'reject') assert.equal(answer.error.data.reason, 'bad_signature');
    assert.equal(f.botCalls.length, 1); assert.equal(f.raw.length, 0); assert.deepEqual(f.events, ['bot']);
    assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  });
}

// Proves a refused signature stops everything before the bot is contacted, and a refused payment after delivery
// reports that the bot has the request but nothing was paid.
test('USDT -> NODUS: a rejected signature posts nothing; a rejected payment is reported as delivered and unpaid', async t => {
  const f = await setup(t), remote = f.site(); await connectBoth(f, remote);
  let swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest()]);
  await f.walk(swapping, ['eth_signTypedData'], { rejectAt: 0 });
  assert.equal((await swapping).error.code, 4001); assert.equal(f.botCalls.length, 0); assert.equal(f.raw.length, 0);
  swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest()]);
  await f.walk(swapping, ['eth_signTypedData', 'nodus_swapPayment'], { rejectAt: 1 });
  const answer = await swapping;
  assert.equal(answer.error.code, 4001); assert.deepEqual(answer.error.data, { delivered: true, paid: false, cause: null });
  assert.equal(f.botCalls.length, 1); assert.equal(f.raw.length, 0);
});

// Proves the extension, not the site, fixes what is posted and where: the site cannot choose the path, a non-https or
// path-carrying bot address is refused before any approval, and unknown or missing fields are refused.
test('swap requests refuse a bad bot address, extra fields and a wrong sender before anything is shown', async t => {
  const f = await setup(t), remote = f.site(); await connectBoth(f, remote);
  for (const overrides of [{ botUrl: 'http://swap.nodusnetwork.io' }, { botUrl: `${BOT}/amm/swap` }, { botUrl: `${BOT}/?x=1` }, { botUrl: 'https://user:pw@swap.nodusnetwork.io' },
    { botUrl: 'not a url' }, { extra: '1' }, { from: '0x0000000000000000000000000000000000000001' }, { amount: '0' }, { amount: '01' }, { amount: '18446744073709551616' },
    { destination: 'EF'.repeat(64) }, { token: '0x1234' }]) {
    const answer = await remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest(overrides)]);
    assert.ok(answer.error, JSON.stringify(overrides)); assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  }
  assert.equal(f.botCalls.length, 0); assert.equal(f.raw.length, 0);
});

// Proves a swap payment is made on Ethereum or Sepolia only, not on the BNB Smart Chain the extension can also select.
test('USDT -> NODUS: a swap is refused while BNB Smart Chain is the selected network', async t => {
  const f = await setup(t), remote = f.site(); await connectBoth(f, remote); await f.background.evm.selectNetwork('bsc');
  const answer = await remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest()]);
  assert.equal(answer.error.code, -32602); assert.equal(f.botCalls.length, 0);
});

// Proves the bot's open-approval refusal (givens item 57; plan section 18 change 2) hands the open request number to the
// site: a canonical decimal 1..4294967295 is passed in error.data.openRequestNumber, any other form is dropped, and
// nothing is paid either way. Environment: stub bot of swap-fixture.js, mode 'open'. Leftovers: none. False pass: the
// stub's JSON is written from amm_http.c:355-372, so a changed bot field name would not be seen here.
for (const [number, kept] of [['123456', true], ['4294967295', true], ['0', false], ['4294967296', false], ['012', false], ['-5', false], ['1.5', false], ['abc', false], [7, false]]) {
  test(`USDT -> NODUS: an open_approval refusal passes openRequestNumber ${JSON.stringify(number)} ${kept ? 'on' : 'is dropped'}`, async t => {
    const f = await setup(t), remote = f.site(); await connectBoth(f, remote); f.state.bot = 'open'; f.state.openRequestNumber = number;
    const swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [usdtRequest()]);
    await f.walk(swapping, ['eth_signTypedData']);
    const answer = await swapping;
    assert.equal(answer.error.data.reason, 'open_approval'); assert.equal(answer.error.data.paid, false);
    if (kept) assert.equal(answer.error.data.openRequestNumber, number); else assert.equal(Object.hasOwn(answer.error.data, 'openRequestNumber'), false);
    assert.equal(f.raw.length, 0); assert.deepEqual(f.events, ['bot']);
  });
}

// ---- NODUS -> USDT ----

// Proves the NODUS transfer is built and signed but NOT sent when it is held, the site receives its wire id and the
// builder's chain id, the request text naming that transfer is signed and posted, and the held transfer is submitted
// only after the post. A test that only checked the post would miss an early send; one that only checked the submit
// would miss the unsent hold.
test('NODUS -> USDT: the transfer is held unsent, the text is signed and posted, then the held transfer is sent', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote);
  const { answer: held, pending } = await hold(f, remote, nodusAccount);
  assert.equal(held.transferId, wireId); assert.equal(held.chainId, f.nodusMock.state.chainId); assert.match(held.holdId, /^\d+$/);
  assert.equal(f.nodusMock.state.submissions.length, 0, 'held, not sent'); assert.equal(f.botCalls.length, 0);
  const rows = Object.fromEntries(pending.requestData.rows);
  assert.equal(rows.To, foundationNodus); assert.equal(rows.Amount, '2.0 NODUS'); assert.equal(rows['Transfer ID'], wireId); assert.equal(rows['Chain ID'], held.chainId);
  const text = nodusText(f, nodusAccount, held), sending = remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
  const [signature] = await f.walk(sending, ['nodus_signMessage']);
  const answer = await sending; assert.equal(answer.error, undefined);
  assert.equal(signature.requestData.text, text);
  assert.deepEqual(f.signCalls, [{ origin: 'https://site.example', text }]);
  assert.equal(f.botCalls.length, 1); assert.equal(f.botCalls[0].url, `${BOT}/amm/swap`);
  assert.deepEqual(f.botCalls[0].body, { kind: 'nodus_to_usdt', text: `0x${Buffer.from(text).toString('hex')}`, publicKey: `0x${nodusPublicKey}`, signature: `0x${nodusSignature}` });
  assert.deepEqual(f.events, ['bot', 'nodus_submit']); assert.equal(f.nodusMock.state.submissions.length, 1);
  assert.equal(answer.result.delivered, true); assert.equal(answer.result.paid, true); assert.equal(answer.result.transferId, wireId);
});

// Proves nothing is submitted, and the hold is dropped, when the request did not reach the bot.
for (const mode of ['refuse', 'error', 'gateway', 'reject']) {
  test(`NODUS -> USDT: the held transfer is never sent when the bot ${mode === 'refuse' ? 'refuses the connection' : `answers (${mode})`}`, async t => {
    const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote); f.state.bot = mode;
    const { answer: held } = await hold(f, remote, nodusAccount), text = nodusText(f, nodusAccount, held);
    const sending = remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
    await f.walk(sending, ['nodus_signMessage']);
    const answer = await sending;
    assert.equal(answer.error.code, -32603); assert.equal(answer.error.data.delivered, false); assert.equal(answer.error.data.paid, false);
    assert.equal(f.nodusMock.state.submissions.length, 0); assert.deepEqual(f.events, ['bot']);
    // The hold is gone: the same request cannot be retried against a transfer the user believes was dropped.
    const again = await remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
    assert.equal(again.error.code, -32602); assert.equal(f.botCalls.length, 1);
  });
}

// Proves the held transfer is refused to a locked wallet, to a site without the granted Nodus account, and to an
// account that is not the permitted one (the nodus_signMessage check), and that a lock drops the hold.
test('NODUS -> USDT: refused when the wallet is locked or the account is not the site\'s permitted account', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote);
  const unconnected = f.site('https://other.example');
  assert.equal((await unconnected.request(SWAP_METHODS.holdTransfer, [{ account: nodusAccount.address, to: foundationNodus, amount: '200000000' }])).error.code, 4100);
  assert.equal((await remote.request(SWAP_METHODS.holdTransfer, [{ account: 'ef'.repeat(64), to: foundationNodus, amount: '200000000' }])).error.code, 4100);
  for (const bad of [{ amount: '0' }, { amount: '1.5' }, { to: 'abc' }, { extra: 1 }]) {
    assert.equal((await remote.request(SWAP_METHODS.holdTransfer, [{ account: nodusAccount.address, to: foundationNodus, amount: '200000000', ...bad }])).error.code, -32602);
  }
  assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  const { answer: held } = await hold(f, remote, nodusAccount), text = nodusText(f, nodusAccount, held);
  await f.background.lock();
  const locked = await remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
  assert.ok(locked.error); assert.equal(f.botCalls.length, 0); assert.equal(f.nodusMock.state.submissions.length, 0);
  assert.ok((await remote.request(SWAP_METHODS.holdTransfer, [{ account: nodusAccount.address, to: foundationNodus, amount: '200000000' }])).error);
});

// Proves a held transfer past its expiry is never sent, in both places it can expire: before the request is posted
// (refused before any signature or post) and between the post and the send (posted, but not sent).
test('NODUS -> USDT: a held transfer past its expiry is never sent', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote);
  let { answer: held } = await hold(f, remote, nodusAccount), text = nodusText(f, nodusAccount, held);
  // The builder's own expiry (90 blocks ahead, adapters/nodus.js NODUS_EXPIRY_AHEAD) is within the plan's 100-block ceiling.
  const ahead = BigInt(held.expiryHeight) - BigInt(f.nodusMock.state.tip);
  assert.ok(ahead > 0n && ahead <= 100n, `expiry ${ahead} blocks ahead`);
  f.nodusMock.state.tip = held.expiryHeight;
  let answer = await remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
  assert.match(answer.error.message, /expired/); assert.equal(f.botCalls.length, 0); assert.equal(f.signCalls.length, 0); assert.equal(f.nodusMock.state.submissions.length, 0);
  // The tip one block below the expiry is still usable; it passes the expiry between the post and the send.
  f.nodusMock.state.tip = '1000';
  ({ answer: held } = await hold(f, remote, nodusAccount)); text = nodusText(f, nodusAccount, held);
  f.state.onBot = () => { f.nodusMock.state.tip = held.expiryHeight; };
  const sending = remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
  await f.walk(sending, ['nodus_signMessage']); answer = await sending;
  assert.match(answer.error.message, /expired/); assert.deepEqual(answer.error.data, { delivered: true, paid: false, cause: null });
  assert.equal(f.botCalls.length, 1); assert.equal(f.nodusMock.state.submissions.length, 0);
});

// Proves the signed text must name the held transfer: another transfer id, chain id, amount or sender is refused
// before any signature, so what the user signs is what is paid; and a text that is not canonical is refused.
test('NODUS -> USDT: a text that does not match the held transfer, or is not canonical, is refused unsigned', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote);
  const { answer: held } = await hold(f, remote, nodusAccount);
  const good = nodusText(f, nodusAccount, held);
  for (const text of [nodusText(f, nodusAccount, held, { transferId: 'ee'.repeat(64) }), nodusText(f, nodusAccount, held, { chainId: 'dd'.repeat(32) }),
    nodusText(f, nodusAccount, held, { amount: 300000000n }), nodusText(f, nodusAccount, held, { sender: 'ee'.repeat(64) }),
    `${good}\n`, good.replace('Request Number: ', 'Request Number:  '), good.replace('\n', '\r\n'), good.toUpperCase(), good.replace('Amount: 2.00000000', 'Amount: 2.0')]) {
    assert.notEqual(text, good, 'a tested text must differ from the good one, or it would open a signature approval and wait');
    const answer = await remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
    assert.equal(answer.error.code, -32602, text);
  }
  assert.equal(f.signCalls.length, 0); assert.equal(f.botCalls.length, 0); assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  // The hold survives a refused text: the honest text still goes through.
  const sending = remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text: good }]);
  await f.walk(sending, ['nodus_signMessage']); assert.equal((await sending).error, undefined);
});

// Proves a hold belongs to the site that made it, and a new hold of the same site drops the earlier one.
test('NODUS -> USDT: a hold cannot be used by another site; a new hold replaces the old one', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote), other = f.site('https://other.example'); await connectBoth(f, other);
  const { answer: first } = await hold(f, remote, nodusAccount);
  const stolen = await other.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: first.holdId, botUrl: BOT, text: nodusText(f, nodusAccount, first) }]);
  assert.equal(stolen.error.code, -32602);
  const { answer: second } = await hold(f, remote, nodusAccount);
  assert.notEqual(second.holdId, first.holdId);
  assert.equal((await remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: first.holdId, botUrl: BOT, text: nodusText(f, nodusAccount, first) }])).error.code, -32602);
  assert.equal(f.botCalls.length, 0);
});

// ---- liquidity add ----

function addRequest(f, nodusAccount, held, overrides = {}) {
  const fields = { ethereumAddress: account.toLowerCase(), nodusAddress: nodusAccount.address, usdtAmount: 1000000000n, nodusAmount: 200000000n, transferId: held.transferId, chainId: held.chainId, requestNumber: '42' };
  return { holdId: held.holdId, botUrl: BOT, ethereumAddress: account, token, payTo, usdtAmount: '1000000000', nodusAmount: '200000000', requestNumber: '42', text: liquidityAddText(fields), ...overrides };
}

// Proves both halves are signed and posted in the flat body of amm_http.h:44-51, and both payments are made only after
// the post: the NODUS transfer then the USDT transfer, each after the user approved its screen.
test('liquidity add: both halves are signed and posted flat, then both payments are sent', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote), { answer: held } = await hold(f, remote, nodusAccount);
  const request = addRequest(f, nodusAccount, held), adding = remote.request(SWAP_METHODS.sendLiquidityAdd, [request]);
  const [typedApproval, , payment] = await f.walk(adding, ['eth_signTypedData', 'nodus_signMessage', 'nodus_swapPayment']);
  const answer = await adding; assert.equal(answer.error, undefined);
  assert.ok(typedApproval.requestData.text.includes('"usdtAmount": "1000000000"'));
  assert.equal(f.botCalls.length, 1); assert.equal(f.botCalls[0].url, `${BOT}/amm/liquidity/add`);
  const body = f.botCalls[0].body;
  assert.deepEqual(Object.keys(body).sort(), ['ethSignature', 'ethereumAddress', 'nodusAddress', 'nodusAmount', 'nodusSignature', 'publicKey', 'requestNumber', 'text', 'usdtAmount']);
  assert.ok(Object.values(body).every(value => typeof value === 'string'));
  assert.equal(body.text, `0x${Buffer.from(request.text).toString('hex')}`); assert.equal(body.publicKey, `0x${nodusPublicKey}`); assert.equal(body.nodusSignature, `0x${nodusSignature}`);
  const typed = liquidityAddTyped({ chainId: 1, ethereumAddress: body.ethereumAddress, nodusAddress: body.nodusAddress, usdtAmount: body.usdtAmount, nodusAmount: body.nodusAmount, requestNumber: body.requestNumber });
  const { EIP712Domain: _domain, ...types } = typed.types;
  assert.equal(verifyTypedData(typed.domain, types, typed.message, body.ethSignature), account);
  assert.deepEqual(f.events, ['bot', 'nodus_submit', 'eth_sendRawTransaction']);
  assert.equal(Object.fromEntries(payment.requestData.rows)['Pay to'], getAddress(payTo));
  assert.equal(erc20.decodeFunctionData('transfer', Transaction.from(f.raw[0]).data)[1], 1000000000n);
  assert.equal(answer.result.nodusPaid, true); assert.equal(answer.result.usdtPaid, true);
});

// Proves neither payment is sent, no payment screen is shown and the hold is dropped when the post did not reach the bot.
for (const mode of ['refuse', 'error', 'reject']) {
  test(`liquidity add: neither payment is sent when the bot ${mode === 'refuse' ? 'refuses the connection' : `answers (${mode})`}`, async t => {
    const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote), { answer: held } = await hold(f, remote, nodusAccount); f.state.bot = mode;
    const adding = remote.request(SWAP_METHODS.sendLiquidityAdd, [addRequest(f, nodusAccount, held)]);
    await f.walk(adding, ['eth_signTypedData', 'nodus_signMessage']);
    const answer = await adding;
    assert.equal(answer.error.data.delivered, false); assert.equal(answer.error.data.paid, false);
    assert.equal(f.raw.length, 0); assert.equal(f.nodusMock.state.submissions.length, 0); assert.deepEqual(f.events, ['bot']);
    assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {});
  });
}

// Proves a refused USDT payment after delivery leaves the NODUS transfer unsent too (the user decides the USDT payment
// before the time-limited NODUS transfer goes out), and the tie of the two halves is enforced before any signature.
test('liquidity add: a refused USDT payment sends nothing; mismatched halves are refused unsigned', async t => {
  const f = await setup(t), remote = f.site(), nodusAccount = await connectBoth(f, remote), { answer: held } = await hold(f, remote, nodusAccount);
  const adding = remote.request(SWAP_METHODS.sendLiquidityAdd, [addRequest(f, nodusAccount, held)]);
  await f.walk(adding, ['eth_signTypedData', 'nodus_signMessage', 'nodus_swapPayment'], { rejectAt: 2 });
  const answer = await adding;
  assert.equal(answer.error.code, 4001); assert.equal(answer.error.data.delivered, true); assert.equal(answer.error.data.paid, false); assert.equal(answer.error.data.nodusSent, false);
  assert.equal(f.raw.length, 0); assert.equal(f.nodusMock.state.submissions.length, 0);
  const second = await hold(f, remote, nodusAccount); f.botCalls.length = 0;
  for (const overrides of [{ usdtAmount: '1000000001' }, { nodusAmount: '300000000' }, { requestNumber: '43' }, { ethereumAddress: '0x0000000000000000000000000000000000000001' }]) {
    const refused = await remote.request(SWAP_METHODS.sendLiquidityAdd, [addRequest(f, nodusAccount, second.answer, overrides)]);
    assert.equal(refused.error.code, -32602, JSON.stringify(overrides));
  }
  assert.equal(f.botCalls.length, 0); assert.equal(f.raw.length, 0);
});

// ---- wiring ----

// Proves the swap methods are refused to a page opened from disk (origin "null"), as the Nodus signing methods are.
test('swap methods are refused for a disk page before any approval', async t => {
  const f = await setup(t), { engine } = f.background.engine.setupProviderEngineEip1193({ origin: 'null', isFile: true });
  for (const method of Object.values(SWAP_METHODS)) {
    const answer = await engine.handle({ id: 9000, jsonrpc: '2.0', method, params: [{}] });
    assert.equal(answer.error.code, 4100, method);
  }
  assert.deepEqual(f.background.approvals.controller.state.pendingApprovals, {}); engine.destroy();
});
