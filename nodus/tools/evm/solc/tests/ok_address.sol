// SPDX-License-Identifier: GPL-3.0
// Nodus EVM solc (32-byte addresses): address handling that MUST compile.
// check.sh asserts on the compiler OUTPUT for this file (no execution):
//   - no 20-byte address mask in the deployed bytecode (legacy and --via-ir, with and without optimizer)
//   - storage layout: every address takes a whole slot (32 bytes, never packed)
//   - ABI JSON still says "address"
pragma solidity ^0.8.30;

interface IReceiver {
    function take(address who) external returns (address);
}

contract AddressOps {
    uint8 public small;     // slot 0
    address public owner;   // slot 1, offset 0, 32 bytes (upstream would pack it into slot 0)
    uint8 public small2;    // slot 2 (upstream would pack it next to owner)
    IReceiver public peer;  // slot 3, contract type = 32-byte address
    mapping(address => uint256) public balances;

    // 64 hex digits, EIP-55 checksum rule applied to all 64 digits.
    address constant FIXED = 0x8076F99ED6A2095ddE395300cF2E056F44e3F5CFA66b300c7b84E3972f379E50;
    // The same 64 digits all lowercase stay an ordinary number literal.
    bytes32 constant LOWER = 0x8076f99ed6a2095dde395300cf2e056f44e3f5cfa66b300c7b84e3972f379e50;

    event Seen(address indexed who, address other);

    constructor() {
        owner = msg.sender;
    }

    function me() external view returns (address) { return address(this); }
    function sender() external view returns (address) { return msg.sender; }
    function origin() external view returns (address) { return tx.origin; }
    function miner() external view returns (address) { return block.coinbase; }
    function fixedAddr() external pure returns (address) { return FIXED; }
    function lowerIsNumber() external pure returns (bool) { return address(LOWER) == FIXED; }

    function toWord(address a) external pure returns (uint256, bytes32) {
        return (uint256(a), bytes32(a));
    }

    function fromWord(uint256 x, bytes32 y) external pure returns (address, address) {
        return (address(x), address(y));
    }

    function same(address a, address b) external pure returns (bool) { return a == b; }

    function packed(address a) external pure returns (bytes memory) {
        return abi.encodePacked(a); // 32 bytes
    }

    function store(address a) external {
        owner = a;
        balances[a] += 1;
        emit Seen(a, msg.sender);
    }

    function setPeer(IReceiver r) external { peer = r; }

    function forward(IReceiver r, address who) external returns (address) {
        return r.take(who);
    }

    // CREATE2 on Nodus EVM: keccak256(0xff ++ sender32 ++ salt ++ keccak256(initcode)), all 32 bytes.
    function create2Address(bytes32 salt, bytes32 codeHash) external view returns (address) {
        return address(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash))));
    }

    // ecrecover stays typed `address`; its value is a 20-byte Ethereum address left-padded with zeros.
    function recover(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }

    // External function values on the stack only (local variable) are allowed.
    function callMe() external view returns (address) {
        function() external view returns (address) f = this.me;
        return f();
    }

    function isMeSelf() external view returns (bool) {
        function() external view returns (address) f = this.me;
        function() external view returns (address) g = this.me;
        return f == g && f.address == address(this);
    }
}

// A library with an external function compiles on its own: its runtime code starts with the
// deploy-time self address slot, which is now PUSH32 00..00 (0x7f + 32 zero bytes).
library SelfAddressLib {
    function ext(uint256 x) external pure returns (uint256) { return x + 1; }
    function internalOnly(address a) internal pure returns (uint256) { return uint256(a); }
}

contract UsesInternalLib {
    function f(address a) external pure returns (uint256) { return SelfAddressLib.internalOnly(a); }
}
