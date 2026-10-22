// SPDX-License-Identifier: Apache-2.0
//
// MLDSA87Attested — one-time use of signed attestations (ML-DSA-87) for a consuming contract.
//
// Part of the Nodus contract library v0.2 (nodus/tools/evm/contracts, README.md).
// Design: docs/plans/2026-10-22-mldsa87-companion-library-design.md rev 2 §1.3, §1.5 (local).
//
// The signed message is  abi.encode(TAG_ATTEST_V1, block.chainid, address(this), actionType,
// nonce, expiry, signer, p1 .. pn)  — ONE abi.encode over all values, so its first 224 bytes are
// the header below no matter which parameters follow. The consuming contract builds `message`
// from the ACTUAL execution parameters, then calls _consumeAttestation BEFORE any effect.
//
// What this contract checks, in order: not expired; nonce unused for that signer; the message
// header equals (tag, chain id, this contract, actionType, nonce, expiry, signer); the signature.
// What the consumer still owns: building the full message, deciding who may sign, counting a
// signer once per decision, and never letting the effect read a value that is not signed
// (README "Consumer rules").
pragma solidity ^0.8.30;

import {MLDSA87} from "./MLDSA87.sol";

abstract contract MLDSA87Attested {
    /// signer => nonce => used. One slot of every inheriting contract (README storage note).
    mapping(address => mapping(uint256 => bool)) private _nonceUsed;

    error AttestationExpired(uint64 expiry);
    error AttestationNonceUsed(address signer, uint256 nonce);
    error AttestationHeaderMismatch();

    event AttestationConsumed(address indexed signer, uint256 indexed nonce, bytes32 indexed actionType);
    event AttestationNonceCancelled(address indexed signer, uint256 indexed nonce);

    function isAttestationNonceUsed(address signer, uint256 nonce) public view returns (bool) {
        return _nonceUsed[signer][nonce];
    }

    /// The signer voids a nonce it has not used yet, from its own account (the signer's EVM
    /// address is SHA3-512(pk)[0..32]). Best-effort: a relayer holding the attestation can land
    /// it first; only `expiry` is a hard bound. Reverts if the nonce is already used.
    function cancelAttestationNonce(uint256 nonce) external {
        if (_nonceUsed[msg.sender][nonce]) revert AttestationNonceUsed(msg.sender, nonce);
        _nonceUsed[msg.sender][nonce] = true;
        emit AttestationNonceCancelled(msg.sender, nonce);
    }

    /// Checks and consumes one attestation. Call it BEFORE any effect; a revert anywhere in
    /// the same call undoes the nonce mark.
    function _consumeAttestation(
        bytes32 actionType,
        uint256 nonce,
        uint64 expiry,
        address signer,
        bytes memory pk,
        bytes memory sig,
        bytes memory message
    ) internal {
        if (block.timestamp > expiry) revert AttestationExpired(expiry);
        if (_nonceUsed[signer][nonce]) revert AttestationNonceUsed(signer, nonce);
        _checkHeader(message, actionType, nonce, expiry, signer);
        MLDSA87.requireSigner(signer, pk, sig, message);
        _nonceUsed[signer][nonce] = true;
        emit AttestationConsumed(signer, nonce, actionType);
    }

    /// The first 224 bytes of `message` must be exactly the expected header. The length is
    /// checked first (abi.decode of a shorter message would revert with empty data); `expiry`
    /// is decoded as uint256 (an abi.decode into uint64 reverts with empty data on a dirty high
    /// half). Trailing bytes after the header are the action's parameters and are accepted.
    function _checkHeader(
        bytes memory message,
        bytes32 actionType,
        uint256 nonce,
        uint64 expiry,
        address signer
    ) private view {
        if (message.length < MLDSA87.HEADER_LEN) revert AttestationHeaderMismatch();
        bytes memory want = abi.encode(
            MLDSA87.TAG_ATTEST_V1, block.chainid, address(this), actionType, nonce, uint256(expiry), signer
        );
        if (!_headerEquals(message, want)) revert AttestationHeaderMismatch();
    }

    function _headerEquals(bytes memory message, bytes memory want) private pure returns (bool) {
        (bytes32 a, uint256 b, address c, bytes32 d, uint256 e, uint256 f, address g) =
            abi.decode(message, (bytes32, uint256, address, bytes32, uint256, uint256, address));
        return keccak256(abi.encode(a, b, c, d, e, f, g)) == keccak256(want);
    }
}
