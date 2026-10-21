// SPDX-License-Identifier: Apache-2.0
//
// Pausable — an on/off switch for functions marked whenNotPaused / whenPaused.
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// Starts unpaused. _pause() reverts when already paused, _unpause() when not paused. Who may
// pause is the inheritor's choice (wrap _pause / _unpause in its own access check). Only the
// functions the inheritor marks whenNotPaused stop; everything else keeps working.
pragma solidity ^0.8.30;

abstract contract Pausable {
    bool private _paused;

    error EnforcedPause();
    error ExpectedPause();

    event Paused(address account);
    event Unpaused(address account);

    modifier whenNotPaused() {
        if (_paused) revert EnforcedPause();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert ExpectedPause();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal whenNotPaused {
        _paused = true;
        emit Paused(msg.sender);
    }

    function _unpause() internal whenPaused {
        _paused = false;
        emit Unpaused(msg.sender);
    }
}
