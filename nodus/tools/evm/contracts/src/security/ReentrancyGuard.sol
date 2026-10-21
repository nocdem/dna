// SPDX-License-Identifier: Apache-2.0
//
// ReentrancyGuard — one status word that refuses re-entry into nonReentrant functions.
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
//
// The constructor writes NOT_ENTERED (1); nonReentrant reverts ReentrantCall() when the status
// is ENTERED (2), sets ENTERED before the body and restores NOT_ENTERED after it. A revert
// anywhere in the body also undoes the status write, so the guard is usable again.
// All nonReentrant functions of one contract share the status word: re-entry from one guarded
// function into ANOTHER guarded function is refused too.
pragma solidity ^0.8.30;

abstract contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    error ReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    modifier nonReentrant() {
        if (_status == ENTERED) revert ReentrantCall();
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
}
