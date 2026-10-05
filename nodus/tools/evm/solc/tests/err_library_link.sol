// SPDX-License-Identifier: GPL-3.0
// EXPECT: linking library
// Calling an external library function needs a linked (20-byte slot) library address: refused.
pragma solidity ^0.8.30;
library L {
    function ext(uint256 x) external pure returns (uint256) { return x + 1; }
}
contract C {
    function f(uint256 x) external pure returns (uint256) { return L.ext(x); }
}
