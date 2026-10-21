// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. A contract account for shared/evm/tests/test_contract_lib.c that
// plays three parts, chosen by setMode:
//   MODE_ACCEPT  (0) receive() / hook() accept and count the value
//   MODE_REVERT  (1) receive() / hook() revert MockRejected()  — the reverting payee
//   MODE_REENTER (2) receive() / hook() call reTarget with reData once and RECORD the outcome
//                    (reOk, reErr) instead of reverting — the re-entering attacker; the outer
//                    call therefore completes and the test reads whether the re-entry was refused
// act(target, value, data) makes this contract the caller of anything (e.g. escrow.withdraw())
// and records the outcome (lastOk, lastErr) without reverting.
pragma solidity ^0.8.30;

contract MockActor {
    uint8 public constant MODE_ACCEPT = 0;
    uint8 public constant MODE_REVERT = 1;
    uint8 public constant MODE_REENTER = 2;

    uint8 public mode;
    address public reTarget;
    bytes public reData;

    uint256 public hooks;
    uint256 public received;
    uint256 public reAttempts;
    bool public reOk;
    bytes4 public reErr;
    bool public lastOk;
    bytes4 public lastErr;

    error MockRejected();

    function setMode(uint8 m, address target, bytes calldata data) external {
        mode = m;
        reTarget = target;
        reData = data;
    }

    function act(address target, uint256 value, bytes calldata data) external payable {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        lastOk = ok;
        lastErr = _selector(ret);
    }

    function hook() external payable {
        _hook();
    }

    receive() external payable {
        _hook();
    }

    function _hook() private {
        if (mode == MODE_REVERT) revert MockRejected();
        hooks += 1;
        received += msg.value;
        if (mode == MODE_REENTER) {
            reAttempts += 1;
            (bool ok, bytes memory ret) = reTarget.call(reData);
            reOk = ok;
            reErr = _selector(ret);
        }
    }

    function _selector(bytes memory ret) private pure returns (bytes4 s) {
        if (ret.length >= 4) s = bytes4(ret);
    }
}
