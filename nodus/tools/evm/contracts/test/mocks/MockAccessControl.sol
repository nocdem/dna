// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. A concrete AccessControl for shared/evm/tests/test_contract_lib.c.
// The constructor grants DEFAULT_ADMIN_ROLE to `admin` and makes ADMIN_B the admin role of
// ROLE_B (role-admin isolation: a DEFAULT_ADMIN_ROLE holder cannot grant ROLE_B).
// Storage (solc --storage-layout): slot 0 the roles mapping, slot 1 counter.
pragma solidity ^0.8.30;

import {AccessControl} from "../../src/access/AccessControl.sol";

contract MockAccessControl is AccessControl {
    bytes32 public constant ROLE_A = keccak256("ROLE_A");
    bytes32 public constant ROLE_B = keccak256("ROLE_B");
    bytes32 public constant ADMIN_B = keccak256("ADMIN_B");

    uint256 public counter;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _setRoleAdmin(ROLE_B, ADMIN_B);
    }

    function useA() external onlyRole(ROLE_A) {
        counter += 1;
    }
}
