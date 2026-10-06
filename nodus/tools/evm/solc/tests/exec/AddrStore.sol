// SPDX-License-Identifier: GPL-3.0
// Nodus EVM solc execution evidence (32-byte addresses): storage paths.
// Executed by shared/evm/tests/test_solc_exec.c with addresses whose HIGH 12 bytes are non-zero.
// Covers: state variable, constructor argument (CODECOPY decoder), immutable, mapping key and
// value, struct member (storage and memory), dynamic storage array, memory array.
pragma solidity ^0.8.30;

contract AddrStore {
    uint8 public small;                         // slot 0
    address public a;                           // slot 1 (a whole slot; never packed with small)
    address public initArg;                     // slot 2: the constructor argument
    mapping(address => address) public m;       // slot 3
    struct S { uint8 tag; address who; uint8 tag2; }
    S public s;                                 // slots 4..6
    address[] public arr;                       // slot 7
    address public immutable deployer;

    constructor(address init) {
        small = 0x5a;
        initArg = init;
        deployer = msg.sender;
    }

    function setA(address x) external { a = x; }
    function getA() external view returns (address) { return a; }

    function setM(address k, address v) external { m[k] = v; }
    function getM(address k) external view returns (address) { return m[k]; }

    function setS(address x) external { s = S(7, x, 9); }
    function getS() external view returns (uint8, address, uint8) { return (s.tag, s.who, s.tag2); }

    function push(address x) external { arr.push(x); }
    function at(uint256 i) external view returns (address) { return arr[i]; }
    function len() external view returns (uint256) { return arr.length; }

    // memory struct + memory array round trip (no storage)
    function memRound(address x, address y) external pure returns (address, address, address) {
        address[] memory t = new address[](3);
        t[1] = x;
        t[2] = y;
        S memory q = S(1, y, 2);
        return (t[1], q.who, t[2]);
    }
}
