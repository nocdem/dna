// SPDX-License-Identifier: GPL-3.0
// EXPECT: an external function value (32-byte address + 4-byte selector)
// A function type name is not a valid expression, so `abi.decode(d, (function() external))`
// is a parser error upstream as well; the only way to name such a decode target is through a
// struct. Both the struct member (error 6259) and the abi.decode target (error 7215) report it.
pragma solidity ^0.8.30;
contract C {
    struct S { function() external f; }
    function g(bytes calldata d) external pure {
        abi.decode(d, (S));
    }
}
