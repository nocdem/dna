// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. Forces value into a contract that has no receive() (the escrow):
// force(target) creates a child whose init code is
//     0x7f <target, 32 bytes>   PUSH32 target
//     0xff                      SELFDESTRUCT
// with msg.value, so the child pays its whole balance to `target` and is deleted in the same
// transaction (EIP-6780). The SELFDESTRUCT opcode is carried as data, not written in Solidity:
// the Solidity `selfdestruct` (and its Yul builtin) draw a deprecation warning, and build.sh
// refuses every compiler diagnostic. abi.encodePacked(address) is 32 bytes on the Nodus
// compiler (nodus/tools/evm/solc/README.md, semantic rule 1), so the init code is 34 bytes.
pragma solidity ^0.8.30;

contract MockForcer {
    error ForceFailed();

    function force(address target) external payable {
        bytes memory init = abi.encodePacked(bytes1(0x7f), target, bytes1(0xff));
        address child;
        assembly {
            child := create(callvalue(), add(init, 0x20), mload(init))
        }
        if (child == address(0)) revert ForceFailed();
    }
}
