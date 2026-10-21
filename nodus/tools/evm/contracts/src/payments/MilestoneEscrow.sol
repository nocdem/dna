// SPDX-License-Identifier: Apache-2.0
//
// MilestoneEscrow — one payer, one payee, one arbiter, value paid out milestone by milestone.
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// One escrow per deployment. The constructor fixes the three parties (distinct, non-zero, never
// the escrow itself), the
// milestone amounts (1..32 of them, each > 0 and a multiple of 10^10 wei = 1 raw NODUS unit,
// so all of it can leave the EVM) and a deadline in block time (> now).
//
// - fund(): the payer, exactly once, with exactly the sum, strictly before the deadline.
// - Each milestone moves exactly once, Pending -> Released or Refunded, and only after funding:
//     release(i)          payer   -> credit the payee
//     resolve(i, toPayee) arbiter -> credit the payee (true) or the payer (false)
//     refund(i)           payer, only from the deadline on -> credit the payer
//   The deadline gives the payer refund ELIGIBILITY, not priority: after it, a release or a
//   resolve that lands first still settles the milestone. No dispute window is reserved: the
//   arbiter must act before the deadline.
// - withdraw(): pays the caller's credit with a CALL forwarding all gas; the credit is cleared
//   first and restored by the revert if the payment fails.
// Accounting uses stored sums only, never address(this).balance. There is no receive(): value
// that arrives anyway (a SELFDESTRUCT beneficiary) is never credited and stays locked.
// Invariant: unsettled + credited + withdrawn == funded.
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "../security/ReentrancyGuard.sol";

contract MilestoneEscrow is ReentrancyGuard {
    uint256 public constant MAX_MILESTONES = 32;
    /// 1 raw NODUS unit in wei: the smallest amount that can leave the EVM.
    uint256 public constant Q = 10_000_000_000;

    enum MilestoneState {
        Pending,
        Released,
        Refunded
    }

    address private _payer;
    address private _payee;
    address private _arbiter;
    uint256 private _deadline;
    uint256 private _total;
    bool private _funded;
    uint256[] private _amounts;
    MilestoneState[] private _states;
    mapping(address => uint256) private _credit;
    uint256 private _unsettled;
    uint256 private _credited;
    uint256 private _withdrawn;

    error EscrowInvalidParty(address account);
    error EscrowInvalidMilestones(uint256 count);
    error EscrowInvalidAmount(uint256 index, uint256 amount);
    error EscrowInvalidDeadline(uint256 deadline);
    error EscrowUnauthorized(address account);
    error EscrowAlreadyFunded();
    error EscrowNotFunded();
    error EscrowWrongAmount(uint256 sent, uint256 expected);
    error EscrowDeadlinePassed(uint256 deadline);
    error EscrowBeforeDeadline(uint256 deadline);
    error EscrowInvalidIndex(uint256 index);
    error EscrowAlreadySettled(uint256 index, MilestoneState state);
    error EscrowNothingToWithdraw(address account);
    error EscrowPaymentFailed(address account, uint256 amount);

    event Funded(address indexed payer, uint256 amount);
    event Settled(uint256 indexed index, MilestoneState state, address indexed creditedTo, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    constructor(address payer, address payee, address arbiter, uint256[] memory amounts, uint256 deadline_) {
        if (payer == address(0) || payer == address(this)) revert EscrowInvalidParty(payer);
        if (payee == address(0) || payee == address(this) || payee == payer) revert EscrowInvalidParty(payee);
        if (arbiter == address(0) || arbiter == address(this) || arbiter == payer || arbiter == payee) {
            revert EscrowInvalidParty(arbiter);
        }
        if (amounts.length == 0 || amounts.length > MAX_MILESTONES) revert EscrowInvalidMilestones(amounts.length);
        if (deadline_ <= block.timestamp) revert EscrowInvalidDeadline(deadline_);
        uint256 sum = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            uint256 a = amounts[i];
            if (a == 0 || a % Q != 0) revert EscrowInvalidAmount(i, a);
            sum += a; // checked: an overflowing sum reverts with Panic(0x11)
            _amounts.push(a);
            _states.push(MilestoneState.Pending);
        }
        _payer = payer;
        _payee = payee;
        _arbiter = arbiter;
        _deadline = deadline_;
        _total = sum;
    }

    // ── views ───────────────────────────────────────────────────────────

    function parties() external view returns (address payer, address payee, address arbiter) {
        return (_payer, _payee, _arbiter);
    }

    function deadline() external view returns (uint256) {
        return _deadline;
    }

    function total() external view returns (uint256) {
        return _total;
    }

    function funded() external view returns (bool) {
        return _funded;
    }

    function milestoneCount() external view returns (uint256) {
        return _amounts.length;
    }

    function milestone(uint256 i) external view returns (uint256 amount, MilestoneState state) {
        if (i >= _amounts.length) revert EscrowInvalidIndex(i);
        return (_amounts[i], _states[i]);
    }

    function creditOf(address account) external view returns (uint256) {
        return _credit[account];
    }

    /// The accounting invariant's three terms; their sum equals total() once funded.
    function accounting() external view returns (uint256 unsettled, uint256 credited, uint256 withdrawn) {
        return (_unsettled, _credited, _withdrawn);
    }

    // ── actions ─────────────────────────────────────────────────────────

    function fund() external payable {
        if (msg.sender != _payer) revert EscrowUnauthorized(msg.sender);
        if (_funded) revert EscrowAlreadyFunded();
        if (block.timestamp >= _deadline) revert EscrowDeadlinePassed(_deadline);
        if (msg.value != _total) revert EscrowWrongAmount(msg.value, _total);
        _funded = true;
        _unsettled = _total;
        emit Funded(msg.sender, msg.value);
    }

    function release(uint256 i) external {
        if (msg.sender != _payer) revert EscrowUnauthorized(msg.sender);
        _settle(i, MilestoneState.Released, _payee);
    }

    function resolve(uint256 i, bool toPayee) external {
        if (msg.sender != _arbiter) revert EscrowUnauthorized(msg.sender);
        if (toPayee) _settle(i, MilestoneState.Released, _payee);
        else _settle(i, MilestoneState.Refunded, _payer);
    }

    function refund(uint256 i) external {
        if (msg.sender != _payer) revert EscrowUnauthorized(msg.sender);
        if (block.timestamp < _deadline) revert EscrowBeforeDeadline(_deadline);
        _settle(i, MilestoneState.Refunded, _payer);
    }

    function withdraw() external nonReentrant {
        uint256 amount = _credit[msg.sender];
        if (amount == 0) revert EscrowNothingToWithdraw(msg.sender);
        _credit[msg.sender] = 0;
        _credited -= amount;
        _withdrawn += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert EscrowPaymentFailed(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function _settle(uint256 i, MilestoneState to, address creditTo) private {
        if (!_funded) revert EscrowNotFunded();
        if (i >= _amounts.length) revert EscrowInvalidIndex(i);
        MilestoneState s = _states[i];
        if (s != MilestoneState.Pending) revert EscrowAlreadySettled(i, s);
        _states[i] = to;
        uint256 a = _amounts[i];
        _unsettled -= a;
        _credited += a;
        _credit[creditTo] += a;
        emit Settled(i, to, creditTo, a);
    }
}
