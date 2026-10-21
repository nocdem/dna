// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. A concrete ReentrancyGuard + Pausable for
// shared/evm/tests/test_contract_lib.c. pause / unpause are open to anyone here (who may pause
// is the inheritor's choice). guardedCall calls out, so a MockActor in re-enter mode can try to
// come back into guardedCall (same function) or guardedOther (cross-function).
// unguardedPing is NOT marked whenNotPaused: it must keep working while paused.
// pausedPing is marked whenPaused: it works only while paused (ExpectedPause() otherwise).
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "../../src/security/ReentrancyGuard.sol";
import {Pausable} from "../../src/security/Pausable.sol";

contract MockGuarded is ReentrancyGuard, Pausable {
    uint256 public counter;
    uint256 public pings;
    uint256 public pausedPings;

    error GuardedCallFailed();

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function guardedCall(address target, bytes calldata data) external nonReentrant whenNotPaused {
        counter += 1;
        (bool ok,) = target.call(data);
        if (!ok) revert GuardedCallFailed();
    }

    function guardedOther() external nonReentrant {
        counter += 100;
    }

    function unguardedPing() external {
        pings += 1;
    }

    /// Runs only while paused (exercises whenPaused directly).
    function pausedPing() external whenPaused {
        pausedPings += 1;
    }
}
