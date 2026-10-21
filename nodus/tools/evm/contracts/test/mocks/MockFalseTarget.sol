// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. check() returns encoded `false` WITHOUT reverting, and counts
// its calls: a vault / timelock execute that targets it must still complete (CALL success is
// execution success, README "CALL success").
pragma solidity ^0.8.30;

contract MockFalseTarget {
    uint256 public calls;

    function check() external returns (bool) {
        calls += 1;
        return false;
    }
}
