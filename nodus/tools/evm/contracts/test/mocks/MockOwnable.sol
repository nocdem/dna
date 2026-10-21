// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. A concrete Ownable for shared/evm/tests/test_contract_lib.c.
// Storage (solc --storage-layout): slot 0 owner, slot 1 pendingOwner, slot 2 value.
pragma solidity ^0.8.30;

import {Ownable} from "../../src/access/Ownable.sol";

contract MockOwnable is Ownable {
    uint256 public value;

    constructor(address initialOwner) Ownable(initialOwner) {}

    function setValue(uint256 v) external onlyOwner {
        value = v;
    }
}
