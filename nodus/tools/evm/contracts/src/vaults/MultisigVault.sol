// SPDX-License-Identifier: Apache-2.0
//
// MultisigVault — M-of-N owners approve a call on-chain before it runs, for the Nodus EVM.
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// Invariant, checked in the constructor and after EVERY owner / threshold change:
//   1 <= threshold <= ownerCount <= 32; owners distinct, non-zero, never the vault itself.
//
// - submit(to, value, data): an owner proposes; ids are sequential from 0; a proposal never
//   changes; it is tagged with the current configVersion and carries the submitter's approval.
// - approve / revokeApproval: an owner, on a pending proposal of the CURRENT configVersion.
// - execute(id): any owner, once approvals >= threshold. Marked Executed BEFORE the call; the
//   value comes from the vault's balance; a failed call reverts the whole execute with
//   VaultCallFailed(id, reason), `reason` = the target's revert data as returned (empty when
//   it gave none; carried as an argument because re-throwing it raw needs inline assembly,
//   which the source rules forbid); the proposal stays pending and can be retried.
//   CALL success is EXECUTION success (README).
// - addOwner / removeOwner / changeThreshold run only as a passed proposal (the vault calling
//   itself). Each bumps configVersion, which voids EVERY pending proposal of an older version:
//   approvals never survive an owner-set change (no stale or revived approvals).
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "../security/ReentrancyGuard.sol";

contract MultisigVault is ReentrancyGuard {
    uint256 public constant MAX_OWNERS = 32;

    struct Proposal {
        address to;
        uint256 value;
        bytes data;
        uint256 configVersion;
        uint256 approvals;
        bool executed;
    }

    address[] private _owners;
    mapping(address => bool) private _isOwner;
    uint256 private _threshold;
    uint256 private _configVersion;
    uint256 private _proposalCount;
    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(address => bool)) private _approved;

    error VaultNotOwner(address account);
    error VaultNotSelf(address caller);
    error VaultInvalidOwner(address account);
    error VaultInvalidConfig(uint256 ownerCount, uint256 threshold);
    error VaultUnknownProposal(uint256 id);
    error VaultAlreadyExecuted(uint256 id);
    error VaultStaleProposal(uint256 id, uint256 proposalVersion, uint256 currentVersion);
    error VaultAlreadyApproved(uint256 id, address owner);
    error VaultNotApproved(uint256 id, address owner);
    error VaultBelowThreshold(uint256 id, uint256 approvals, uint256 threshold);
    error VaultCallFailed(uint256 id, bytes reason);

    event Submitted(uint256 indexed id, address indexed proposer, address indexed to, uint256 value, bytes data);
    event Approved(uint256 indexed id, address indexed owner);
    event ApprovalRevoked(uint256 indexed id, address indexed owner);
    event Executed(uint256 indexed id);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 threshold);
    event Deposit(address indexed sender, uint256 value);

    modifier onlyOwner() {
        if (!_isOwner[msg.sender]) revert VaultNotOwner(msg.sender);
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert VaultNotSelf(msg.sender);
        _;
    }

    constructor(address[] memory owners, uint256 threshold_) {
        if (owners.length > MAX_OWNERS) revert VaultInvalidConfig(owners.length, threshold_);
        for (uint256 i = 0; i < owners.length; ++i) {
            _addOwner(owners[i]);
        }
        _threshold = threshold_;
        _checkConfig();
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    // ── views ───────────────────────────────────────────────────────────

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    function isOwner(address account) external view returns (bool) {
        return _isOwner[account];
    }

    function threshold() external view returns (uint256) {
        return _threshold;
    }

    function configVersion() external view returns (uint256) {
        return _configVersion;
    }

    function proposalCount() external view returns (uint256) {
        return _proposalCount;
    }

    function getProposal(uint256 id)
        external
        view
        returns (address to, uint256 value, bytes memory data, uint256 version, uint256 approvals, bool executed)
    {
        if (id >= _proposalCount) revert VaultUnknownProposal(id);
        Proposal storage p = _proposals[id];
        return (p.to, p.value, p.data, p.configVersion, p.approvals, p.executed);
    }

    function isApproved(uint256 id, address owner) external view returns (bool) {
        return _approved[id][owner];
    }

    // ── proposals ───────────────────────────────────────────────────────

    function submit(address to, uint256 value, bytes calldata data) external onlyOwner returns (uint256 id) {
        id = _proposalCount;
        _proposalCount = id + 1;
        Proposal storage p = _proposals[id];
        p.to = to;
        p.value = value;
        p.data = data;
        p.configVersion = _configVersion;
        p.approvals = 1;
        _approved[id][msg.sender] = true;
        emit Submitted(id, msg.sender, to, value, data);
        emit Approved(id, msg.sender);
    }

    function approve(uint256 id) external onlyOwner {
        Proposal storage p = _livePending(id);
        if (_approved[id][msg.sender]) revert VaultAlreadyApproved(id, msg.sender);
        _approved[id][msg.sender] = true;
        p.approvals += 1;
        emit Approved(id, msg.sender);
    }

    function revokeApproval(uint256 id) external onlyOwner {
        Proposal storage p = _livePending(id);
        if (!_approved[id][msg.sender]) revert VaultNotApproved(id, msg.sender);
        _approved[id][msg.sender] = false;
        p.approvals -= 1;
        emit ApprovalRevoked(id, msg.sender);
    }

    function execute(uint256 id) external nonReentrant onlyOwner {
        Proposal storage p = _livePending(id);
        if (p.approvals < _threshold) revert VaultBelowThreshold(id, p.approvals, _threshold);
        p.executed = true;
        (bool ok, bytes memory reason) = p.to.call{value: p.value}(p.data);
        if (!ok) revert VaultCallFailed(id, reason);
        emit Executed(id);
    }

    // ── configuration (only as a passed proposal) ───────────────────────

    function addOwner(address owner) external onlySelf {
        if (_owners.length >= MAX_OWNERS) revert VaultInvalidConfig(_owners.length + 1, _threshold);
        _addOwner(owner);
        _bumpConfig();
    }

    function removeOwner(address owner) external onlySelf {
        if (!_isOwner[owner]) revert VaultNotOwner(owner);
        uint256 n = _owners.length;
        for (uint256 i = 0; i < n; ++i) {
            if (_owners[i] == owner) {
                _owners[i] = _owners[n - 1];
                _owners.pop();
                break;
            }
        }
        _isOwner[owner] = false;
        emit OwnerRemoved(owner);
        _bumpConfig();
    }

    function changeThreshold(uint256 newThreshold) external onlySelf {
        _threshold = newThreshold;
        emit ThresholdChanged(newThreshold);
        _bumpConfig();
    }

    // ── internals ───────────────────────────────────────────────────────

    /// The proposal exists, is not executed and belongs to the current configuration.
    function _livePending(uint256 id) private view returns (Proposal storage p) {
        if (id >= _proposalCount) revert VaultUnknownProposal(id);
        p = _proposals[id];
        if (p.executed) revert VaultAlreadyExecuted(id);
        if (p.configVersion != _configVersion) revert VaultStaleProposal(id, p.configVersion, _configVersion);
    }

    function _addOwner(address owner) private {
        if (owner == address(0) || owner == address(this) || _isOwner[owner]) revert VaultInvalidOwner(owner);
        _isOwner[owner] = true;
        _owners.push(owner);
        emit OwnerAdded(owner);
    }

    function _bumpConfig() private {
        _configVersion += 1;
        _checkConfig();
    }

    function _checkConfig() private view {
        uint256 n = _owners.length;
        if (_threshold == 0 || _threshold > n || n > MAX_OWNERS) revert VaultInvalidConfig(n, _threshold);
    }
}
