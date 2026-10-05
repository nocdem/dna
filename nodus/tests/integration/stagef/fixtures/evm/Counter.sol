// SPDX-License-Identifier: MIT
// Stage F fixture for tests/test_cmt_evm.sh (Nodus EVM). Compiled once with the
// Nodus 32-byte-address solc (see README.md in this directory); the
// scenario deploys Counter.hex and never runs a compiler.
//
// What each function exercises on the chain:
//   increment()    SSTORE + one LOG2 (topic1 = the 32-byte caller address)
//   get()          SLOAD through the evm_call RPC (read-only)
//   boom()         a REVERT with Error(string) "boom" after an SSTORE —
//                  the failed execution is APPLIED (nonce + 1, fee paid)
//                  and the SSTORE is rolled back (design §4)
//   gasLimitNow()  the block environment's GASLIMIT (design §10)
pragma solidity 0.8.30;

contract Counter {
    uint256 public count;

    event Incremented(address indexed by, uint256 value);

    function increment() external {
        count += 1;
        emit Incremented(msg.sender, count);
    }

    function get() external view returns (uint256) {
        return count;
    }

    function boom() external {
        count += 100;
        revert("boom");
    }

    function gasLimitNow() external view returns (uint256) {
        return block.gaslimit;
    }
}
