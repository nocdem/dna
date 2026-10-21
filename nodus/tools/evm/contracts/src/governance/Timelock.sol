// SPDX-License-Identifier: Apache-2.0
//
// Timelock — calls that can run only after a delay, for the Nodus EVM (32-byte addresses).
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// Roles: PROPOSER schedules, EXECUTOR executes, CANCELLER cancels. The timelock itself is the
// ONLY holder of DEFAULT_ADMIN_ROLE, from construction on: there is no external admin, and
// every later role change (grantRole / revokeRole) or delay change (updateDelay) is a call the
// timelock makes to itself through schedule + execute, i.e. it waits the delay too.
// Role rules on top of AccessControl:
//   - renounceRole always reverts (TimelockRenounceDisabled): a role leaves only by a delayed
//     revokeRole, so no holder can drop a role without the delay;
//   - PROPOSER and EXECUTOR never go to zero holders: a revoke of the last one reverts
//     (TimelockLastHolder) — with no proposer nothing could ever be scheduled again, with no
//     executor nothing could execute, including the change that would fix it;
//   - no role other than DEFAULT_ADMIN_ROLE is granted to address(0) or to the timelock itself
//     (TimelockInvalidAccount);
//   - DEFAULT_ADMIN_ROLE is never granted to another account nor revoked (TimelockAdminFixed).
// Delays (minDelay and every schedule delay) are at most MAX_DELAY = 365 days
// (TimelockDelayTooLong).
//
// Operation id = keccak256(abi.encode(target, value, data, salt)). States:
//   Unset -> Pending (schedule) -> Done (execute) | Cancelled (cancel).
// An id is scheduled at most once, in any state: a cancelled or executed operation needs a new
// salt to be scheduled again. There are no predecessors and no batches (v0.1).
//
// execute marks the operation Done BEFORE the call and pays `value` from the timelock's own
// balance (execute is not payable; send value to the timelock first — receive() accepts it).
// A failed call reverts the whole execute with TimelockCallFailed(id, reason), `reason` being
// the target's revert data as returned (empty when the target gave none), so the operation
// stays Pending and can be retried. The data is carried as an argument, not re-thrown raw:
// re-throwing needs inline assembly, which the library's source rules forbid.
// CALL success is EXECUTION success: a target that returns `false` without reverting still
// completes the operation (README "CALL success").
pragma solidity ^0.8.30;

import {AccessControl} from "../access/AccessControl.sol";
import {ReentrancyGuard} from "../security/ReentrancyGuard.sol";

contract Timelock is AccessControl, ReentrancyGuard {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    /// The largest minDelay and the largest schedule delay.
    uint256 public constant MAX_DELAY = 365 days;

    enum OperationState {
        Unset,
        Pending,
        Done,
        Cancelled
    }

    struct Operation {
        uint256 readyAt;
        OperationState state;
    }

    mapping(bytes32 => Operation) private _operations;
    uint256 private _minDelay;
    /// Number of accounts holding each role (kept for every role, enforced for PROPOSER and
    /// EXECUTOR).
    mapping(bytes32 => uint256) private _holders;

    error TimelockInvalidAccount(address account);
    error TimelockNoProposer();
    error TimelockNoExecutor();
    error TimelockAdminFixed();
    error TimelockRenounceDisabled();
    error TimelockLastHolder(bytes32 role);
    error TimelockUnauthorizedCaller(address caller);
    error TimelockInsufficientDelay(uint256 delay, uint256 minDelay);
    error TimelockDelayTooLong(uint256 delay, uint256 maxDelay);
    error TimelockUnexpectedOperationState(bytes32 id, OperationState state);
    error TimelockNotReady(bytes32 id, uint256 readyAt);
    error TimelockCallFailed(bytes32 id, bytes reason);

    event CallScheduled(
        bytes32 indexed id, address indexed target, uint256 value, bytes data, bytes32 salt, uint256 readyAt
    );
    event CallExecuted(bytes32 indexed id, address indexed target, uint256 value, bytes data);
    event Cancelled(bytes32 indexed id);
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    /// @param minDelay   smallest delay schedule accepts, in seconds of block time; at most
    ///                   MAX_DELAY
    /// @param proposers  at least one; every account non-zero and not the timelock
    /// @param executors  at least one; same rule
    /// @param cancellers may be empty; same rule
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address[] memory cancellers
    ) {
        if (proposers.length == 0) revert TimelockNoProposer();
        if (executors.length == 0) revert TimelockNoExecutor();
        if (minDelay > MAX_DELAY) revert TimelockDelayTooLong(minDelay, MAX_DELAY);
        _grantRole(DEFAULT_ADMIN_ROLE, address(this));
        _grantAll(PROPOSER_ROLE, proposers);
        _grantAll(EXECUTOR_ROLE, executors);
        _grantAll(CANCELLER_ROLE, cancellers);
        _minDelay = minDelay;
        emit MinDelayChange(0, minDelay);
    }

    receive() external payable {}

    function getMinDelay() external view returns (uint256) {
        return _minDelay;
    }

    function getOperationState(bytes32 id) external view returns (OperationState) {
        return _operations[id].state;
    }

    /// The block time from which the operation may execute (0 when never scheduled).
    function getReadyTime(bytes32 id) external view returns (uint256) {
        return _operations[id].readyAt;
    }

    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 salt)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, salt));
    }

    function schedule(address target, uint256 value, bytes calldata data, bytes32 salt, uint256 delay)
        external
        onlyRole(PROPOSER_ROLE)
        returns (bytes32 id)
    {
        id = hashOperation(target, value, data, salt);
        Operation storage op = _operations[id];
        if (op.state != OperationState.Unset) revert TimelockUnexpectedOperationState(id, op.state);
        if (delay < _minDelay) revert TimelockInsufficientDelay(delay, _minDelay);
        if (delay > MAX_DELAY) revert TimelockDelayTooLong(delay, MAX_DELAY);
        uint256 readyAt = block.timestamp + delay;
        op.readyAt = readyAt;
        op.state = OperationState.Pending;
        emit CallScheduled(id, target, value, data, salt, readyAt);
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        nonReentrant
        onlyRole(EXECUTOR_ROLE)
    {
        bytes32 id = hashOperation(target, value, data, salt);
        Operation storage op = _operations[id];
        if (op.state != OperationState.Pending) revert TimelockUnexpectedOperationState(id, op.state);
        if (block.timestamp < op.readyAt) revert TimelockNotReady(id, op.readyAt);
        op.state = OperationState.Done;
        (bool ok, bytes memory reason) = target.call{value: value}(data);
        if (!ok) revert TimelockCallFailed(id, reason);
        emit CallExecuted(id, target, value, data);
    }

    function cancel(bytes32 id) external onlyRole(CANCELLER_ROLE) {
        Operation storage op = _operations[id];
        if (op.state != OperationState.Pending) revert TimelockUnexpectedOperationState(id, op.state);
        op.state = OperationState.Cancelled;
        emit Cancelled(id);
    }

    /// Only through a delayed operation (the timelock calling itself).
    function updateDelay(uint256 newDelay) external {
        if (msg.sender != address(this)) revert TimelockUnauthorizedCaller(msg.sender);
        if (newDelay > MAX_DELAY) revert TimelockDelayTooLong(newDelay, MAX_DELAY);
        emit MinDelayChange(_minDelay, newDelay);
        _minDelay = newDelay;
    }

    /// Always reverts: every role change goes through a delayed revokeRole.
    function renounceRole(bytes32, address) public pure override {
        revert TimelockRenounceDisabled();
    }

    /// DEFAULT_ADMIN_ROLE stays with the timelock alone: it is never granted to another
    /// account, and the timelock's own is never revoked (that would freeze every role for
    /// good). Every other role is never granted to address(0) or to the timelock itself.
    function _grantRole(bytes32 role, address account) internal override returns (bool) {
        if (role == DEFAULT_ADMIN_ROLE) {
            if (account != address(this)) revert TimelockAdminFixed();
        } else if (account == address(0) || account == address(this)) {
            revert TimelockInvalidAccount(account);
        }
        bool granted = super._grantRole(role, account);
        if (granted) _holders[role] += 1;
        return granted;
    }

    /// Refuses DEFAULT_ADMIN_ROLE, and the revoke of the last PROPOSER or the last EXECUTOR.
    function _revokeRole(bytes32 role, address account) internal override returns (bool) {
        if (role == DEFAULT_ADMIN_ROLE) revert TimelockAdminFixed();
        if ((role == PROPOSER_ROLE || role == EXECUTOR_ROLE) && hasRole(role, account) && _holders[role] == 1) {
            revert TimelockLastHolder(role);
        }
        bool revoked = super._revokeRole(role, account);
        if (revoked) _holders[role] -= 1;
        return revoked;
    }

    /// The zero / self account check is in _grantRole.
    function _grantAll(bytes32 role, address[] memory accounts) private {
        for (uint256 i = 0; i < accounts.length; ++i) {
            _grantRole(role, accounts[i]);
        }
    }
}
