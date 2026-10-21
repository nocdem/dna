// SPDX-License-Identifier: Apache-2.0
//
// AccessControl — bytes32 roles with per-role admin roles, for the Nodus EVM (32-byte addresses).
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// - DEFAULT_ADMIN_ROLE = 0x00; every role's admin role is DEFAULT_ADMIN_ROLE until
//   _setRoleAdmin changes it.
// - grantRole / revokeRole: only a holder of the role's admin role.
// - renounceRole(role, account): only for yourself (account == msg.sender); virtual, so an
//   inheritor may refuse it altogether.
// - The constructor grants nothing: the inheritor grants the first roles with _grantRole.
// - _grantRole / _revokeRole are no-ops without an event when nothing changes.
pragma solidity ^0.8.30;

abstract contract AccessControl {
    struct RoleData {
        mapping(address => bool) hasRole;
        bytes32 adminRole;
    }

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    mapping(bytes32 => RoleData) private _roles;

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    error AccessControlBadConfirmation();

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    modifier onlyRole(bytes32 role) {
        _checkRole(role, msg.sender);
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].hasRole[account];
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /// Gives up a role the caller holds; `callerConfirmation` must be the caller itself.
    /// Virtual: an inheritor may refuse renouncing altogether (Timelock does).
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != msg.sender) revert AccessControlBadConfirmation();
        _revokeRole(role, callerConfirmation);
    }

    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) revert AccessControlUnauthorizedAccount(account, role);
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /// @return true when the role was granted now, false when the account already held it.
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        if (hasRole(role, account)) return false;
        _roles[role].hasRole[account] = true;
        emit RoleGranted(role, account, msg.sender);
        return true;
    }

    /// @return true when the role was revoked now, false when the account did not hold it.
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        if (!hasRole(role, account)) return false;
        _roles[role].hasRole[account] = false;
        emit RoleRevoked(role, account, msg.sender);
        return true;
    }
}
