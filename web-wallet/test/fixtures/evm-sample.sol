// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract Sample {
    struct Pair { address who; uint64 amount; }
    struct Deep { Pair[] pairs; string note; bytes32 tag; }

    event Moved(address indexed from, address indexed to, uint256 value);
    event Noted(string indexed topic, bytes data, int16 delta);
    error NotAllowed(address caller, uint256 code);

    mapping(address => uint256) public balances;

    constructor(address owner, uint256 start) payable { balances[owner] = start; }

    function transfer(address to, uint256 value) external returns (bool) { emit Moved(msg.sender, to, value); return true; }
    function mixed(uint8 a, int16 b, bool c, bytes4 d, bytes calldata e, string calldata f) external pure returns (uint8, int16, bool, bytes4, bytes memory, string memory) { return (a, b, c, d, e, f); }
    function arrays(uint256[2] calldata fixedArr, address[] calldata dyn) external pure returns (uint256) { return fixedArr[0] + dyn.length; }
    function nested(Deep calldata d, Pair[2] calldata p) external pure returns (Deep memory) { p; return d; }
    function deposit() external payable {}
    function fail(uint256 code) external view { revert NotAllowed(msg.sender, code); }
    function note(string calldata topic, bytes calldata data, int16 delta) external { emit Noted(topic, data, delta); }
}
