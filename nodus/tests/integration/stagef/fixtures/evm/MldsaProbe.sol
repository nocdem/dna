// SPDX-License-Identifier: MIT
// Stage F fixture for tests/test_cmt_mldsa.sh (the ML-DSA-87 verification
// precompile, chain-config param 23). Compiled once with the Nodus
// 32-byte-address solc (see README.md in this directory); the scenario
// deploys MldsaProbe.hex and never runs a compiler.
//
// Both functions STATICCALL the address `pc` with `input` (pk ‖ sig ‖ msg)
// and report (call succeeded, output length, first output word). The
// precompile address is passed in (the scenario derives it,
// SHA3-512("NDS.EVMMLDSA87.v1")[0..32]) so the bytecode carries no chain
// constant.
//   probe()   a view — read through `evm call` (the node's simulation)
//   record()  a transaction — stores the same three values plus a call
//             counter, so what the EXECUTION saw is in committed state
// Below the activation height the address is an ordinary account without
// code: (true, 0, 0). From the activation height a valid signature gives
// (true, 32, the signer's address); an invalid one (true, 0, 0).
pragma solidity 0.8.30;

contract MldsaProbe {
    uint256 public calls;
    bool public lastOk;
    uint256 public lastLen;
    bytes32 public lastWord;

    function _probe(address pc, bytes calldata input)
        internal
        view
        returns (bool ok, uint256 len, bytes32 word)
    {
        bytes memory out;
        (ok, out) = pc.staticcall(input);
        len = out.length;
        if (len >= 32) {
            assembly {
                word := mload(add(out, 32))
            }
        }
    }

    function probe(address pc, bytes calldata input)
        external
        view
        returns (bool ok, uint256 len, bytes32 word)
    {
        return _probe(pc, input);
    }

    function record(address pc, bytes calldata input) external {
        (bool ok, uint256 len, bytes32 word) = _probe(pc, input);
        calls += 1;
        lastOk = ok;
        lastLen = len;
        lastWord = word;
    }
}
