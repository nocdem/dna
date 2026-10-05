// SPDX-License-Identifier: GPL-3.0
// EXPECT: Nodus EVM addresses are 32 bytes (256 bits)
pragma solidity ^0.8.30;
contract C {
    function f(address a) external pure returns (bytes20) { return bytes20(a); }
}
