// SPDX-License-Identifier: GPL-3.0
// Nodus EVM solc execution evidence (32-byte addresses): external calls, msg.sender seen by a
// callee, address.balance, value transfer (transfer / send / call), code introspection.
// Executed by shared/evm/tests/test_solc_exec.c; every contract address and EOA used has non-zero
// HIGH 12 bytes.
pragma solidity ^0.8.30;

contract Callee {
    address public lastSender;
    uint256 public lastValue;

    function hit() external payable returns (address) {
        lastSender = msg.sender;
        lastValue = msg.value;
        return msg.sender;
    }

    function who() external view returns (address, address) { return (msg.sender, tx.origin); }
}

contract Caller {
    // high-level call: extcodesize check + ABI-decoded return, then a second call reading storage
    function callHit(Callee c) external payable returns (address ret, address stored) {
        ret = c.hit{value: msg.value}();
        stored = c.lastSender();
    }

    function callWho(Callee c) external view returns (address, address) { return c.who(); }

    // low-level call to an address held as `address` (an account without code returns no data)
    function callLow(address c) external returns (bool ok, address ret) {
        bytes memory out;
        (ok, out) = c.call(abi.encodeWithSignature("hit()"));
        if (ok && out.length == 32) ret = abi.decode(out, (address));
    }

    function balanceOf(address x) external view returns (uint256) { return x.balance; }
    function selfBalance() external view returns (uint256) { return address(this).balance; }

    function payTransfer(address payable to, uint256 v) external { to.transfer(v); }
    function paySend(address payable to, uint256 v) external returns (bool) { return to.send(v); }
    function payCall(address to, uint256 v) external returns (bool ok) {
        (ok, ) = to.call{value: v}("");
    }

    function codeSize(address x) external view returns (uint256) { return x.code.length; }
    function codeHash(address x) external view returns (bytes32) { return x.codehash; }

    // DELEGATECALL into a library deployed at a 32-byte address (no linking: the address is data)
    function viaDelegate(address lib, uint256 x) external returns (bool ok, uint256 r) {
        bytes memory out;
        (ok, out) = lib.delegatecall(abi.encodeWithSignature("bump(uint256)", x));
        if (ok) r = abi.decode(out, (uint256));
    }

    receive() external payable {}
}

// Rule 7 (README): a library's deploy-time self address is a 32-byte PUSH32 slot. A non-view
// external library function called DIRECTLY must revert (ADDRESS == the stored self address);
// through DELEGATECALL it runs. A truncated self address would let the direct call succeed.
library SelfLib {
    event Bumped(uint256 x);

    function bump(uint256 x) external returns (uint256) {
        emit Bumped(x);
        return x + 1;
    }

    function pureOne(uint256 x) external pure returns (uint256) { return x + 1; }
}
