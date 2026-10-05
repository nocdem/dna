// SPDX-License-Identifier: GPL-3.0
// EXPECT: Nodus EVM addresses are 32 bytes (256 bits)
// address(uint160(...)) would silently truncate a 32-byte address.
pragma solidity ^0.8.30;
contract C {
    function f(uint256 x) external pure returns (address) { return address(uint160(x)); }
}
