// SPDX-License-Identifier: GPL-3.0
// Nodus EVM solc execution evidence (32-byte addresses): ABI coding, conversions, comparison,
// environment opcodes and events.
// Executed by shared/evm/tests/test_solc_exec.c with addresses whose HIGH 12 bytes are non-zero.
pragma solidity ^0.8.30;

contract AbiConv {
    struct P { uint8 tag; address who; }

    event Seen(address indexed who, address plain, uint256 n);

    function enc(address x) external pure returns (bytes memory) { return abi.encode(x); }
    function encPacked(address x) external pure returns (bytes memory) { return abi.encodePacked(x); }
    function packedLen(address x) external pure returns (uint256) { return abi.encodePacked(x).length; }
    function dec(bytes calldata b) external pure returns (address) { return abi.decode(b, (address)); }
    function decMem(bytes memory b) external pure returns (address) { return abi.decode(b, (address)); }
    function roundTrip(address x) external pure returns (address) {
        return abi.decode(abi.encode(x), (address));
    }

    // calldata struct and dynamic array parameters, echoed through the ABI encoder
    function echoP(P calldata p) external pure returns (P memory) { return p; }
    function echoArr(address[] calldata xs) external pure returns (address[] memory) { return xs; }

    function toU(address x) external pure returns (uint256) { return uint256(x); }
    function fromU(uint256 x) external pure returns (address) { return address(x); }
    function toB(address x) external pure returns (bytes32) { return bytes32(x); }
    function fromB(bytes32 x) external pure returns (address) { return address(x); }
    function convIdentity(address x) external pure returns (bool) {
        return address(uint256(x)) == x && address(bytes32(x)) == x &&
               uint256(bytes32(x)) == uint256(x) && payable(x) == x;
    }

    function eq(address x, address y) external pure returns (bool) { return x == y; }
    function ne(address x, address y) external pure returns (bool) { return x != y; }
    function lt(address x, address y) external pure returns (bool) { return x < y; }

    function env() external view returns (address, address, address, address) {
        return (msg.sender, tx.origin, address(this), block.coinbase);
    }

    function emitSeen(address x, address y) external {
        emit Seen(x, y, 42);
    }
}
