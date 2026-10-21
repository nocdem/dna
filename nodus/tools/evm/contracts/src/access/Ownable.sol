// SPDX-License-Identifier: Apache-2.0
//
// Ownable — single owner with a two-step transfer, for the Nodus EVM (32-byte addresses).
//
// Part of the Nodus security contract library v0.1 (nodus/tools/evm/contracts, README.md).
// Compile with the Nodus solc (nodus/tools/evm/solc, version string carries "nodus.addr256");
// a stock solc truncates every address to 20 bytes.
//
// - The constructor takes the first owner (non-zero).
// - transferOwnership(new) only NOMINATES: it sets pendingOwner (overwriting an earlier
//   nomination). Ownership moves only when the nominee calls acceptOwnership(), so it never
//   lands on an account that did not accept it.
// - There is no renounceOwnership: a value-holding contract without an owner cannot be
//   recovered (deliberately cut in v0.1).
pragma solidity ^0.8.30;

abstract contract Ownable {
    address private _owner;        // slot 0 of an inheritor that lists Ownable first
    address private _pendingOwner; // slot 1

    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert OwnableUnauthorizedAccount(msg.sender);
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    /// Nominates `newOwner`; nothing changes until the nominee calls acceptOwnership().
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(_owner, newOwner);
    }

    /// Completes a transfer; only the current nominee may call it.
    function acceptOwnership() public {
        if (msg.sender != _pendingOwner) revert OwnableUnauthorizedAccount(msg.sender);
        address previous = _owner;
        _owner = msg.sender;
        delete _pendingOwner;
        emit OwnershipTransferred(previous, msg.sender);
    }
}
