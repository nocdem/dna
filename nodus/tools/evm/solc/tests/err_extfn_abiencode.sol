// SPDX-License-Identifier: GPL-3.0
// EXPECT: an external function value (32-byte address + 4-byte selector)
pragma solidity ^0.8.30;
contract C {
    function h() external {}
    function g() external view returns (bytes memory) { return abi.encode(this.h); }
}
