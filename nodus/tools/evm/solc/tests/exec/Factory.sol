// SPDX-License-Identifier: GPL-3.0
// Nodus EVM solc execution evidence (32-byte addresses): CREATE and CREATE2 from a contract.
// Engine rule (docs/plans/2026-10-04-nodus-evm-engine-design.md §2): CREATE =
// keccak256(rlp([sender32, nonce])), CREATE2 = keccak256(0xff ‖ sender32 ‖ salt ‖ keccak256(init)),
// all 32 bytes. Executed by shared/evm/tests/test_solc_exec.c, which computes the expected values.
pragma solidity ^0.8.30;

contract Child {
    address public creator;

    constructor() payable { creator = msg.sender; }

    function me() external view returns (address) { return address(this); }
}

contract Factory {
    function make() external returns (address a, address creatorSeen, address selfSeen) {
        Child c = new Child();
        a = address(c);
        creatorSeen = c.creator();
        selfSeen = c.me();
    }

    function make2(bytes32 salt) external returns (address a, address predicted, address creatorSeen) {
        Child c = new Child{salt: salt}();
        a = address(c);
        predicted = address(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, keccak256(type(Child).creationCode)))));
        creatorSeen = c.creator();
    }
}
