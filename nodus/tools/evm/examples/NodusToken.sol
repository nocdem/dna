// SPDX-License-Identifier: Apache-2.0
//
// NodusToken — a minimal ERC-20-style token for the Nodus EVM (32-byte addresses).
//
// Compile with the Nodus solc (nodus/tools/evm/solc, version string carries
// "nodus.addr256"); a stock solc truncates every address to 20 bytes.
// Self-contained on purpose: no imports, no linked libraries, no uint160 /
// bytes20 conversions, no stored external function types (README "Semantic
// rules" 3, 6, 7 of nodus/tools/evm/solc/README.md).
//
// The whole supply is minted to the deployer by the constructor (no
// constructor arguments, so `nodus-cli evm deploy --solc` needs no --args).
pragma solidity ^0.8.30;

contract NodusToken {
    string public constant name = "Nodus Example Token";
    string public constant symbol = "NXT";
    uint8 public constant decimals = 18;

    /// 1,000,000 tokens with 18 decimals.
    uint256 public constant INITIAL_SUPPLY = 1_000_000 * 10 ** 18;

    uint256 public totalSupply;                                       // slot 0
    mapping(address => uint256) public balanceOf;                     // slot 1
    mapping(address => mapping(address => uint256)) public allowance; // slot 2

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        totalSupply = INITIAL_SUPPLY;
        balanceOf[msg.sender] = INITIAL_SUPPLY;
        emit Transfer(address(0), msg.sender, INITIAL_SUPPLY);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "NodusToken: allowance too low");
        unchecked {
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "NodusToken: transfer to the zero address");
        uint256 balance = balanceOf[from];
        require(balance >= value, "NodusToken: balance too low");
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
