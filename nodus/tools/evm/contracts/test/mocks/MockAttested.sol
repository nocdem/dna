// SPDX-License-Identifier: Apache-2.0
//
// TEST FIXTURE — never shipped. Concrete consumers of MLDSA87Attested for
// shared/evm/tests/test_contract_lib.c. It deliberately breaks the library's source rules the
// way the other mocks do: some actions are WRONG on purpose (a misordered header, a header-only
// message whose effect reads unsigned values, a notify that lets the target re-enter) so the
// tests can show that the library refuses or exposes them. Do not copy these actions.
//
// Views return the library constants (TAG_ATTEST_V1, PRECOMPILE) and the two action types so the
// C test can compare them with the decision bytes, with evm_mldsa87_addr and with the fixture
// test/fixtures/attest_v1.txt (the compiler's compile-time keccak256 against the tree's).
//
// Message builders are pure and are THE SAME internal functions the actions use, with
// (block.chainid, address(this), …) there and explicit values here, so the test can build the
// bytes a signer must sign for any chain id / contract.
//
// Actions (each: build the message from the execution parameters, consume the attestation,
// then run the effect):
//   approve(...)            Approve(uint256,address)         single signer; allowance[to] += amount
//   submit(...)             Submit(address,uint256,bytes)    2-of-3 over fixed signers; each signer
//                                                            counted once per proposal even under
//                                                            two nonces
//   approveMisordered(...)  Approve(uint256,address)         header words in the wrong order
//   approveHeaderOnly(...)  HeaderOnly(uint256,address)      signs only the header; the effect
//                                                            reads UNSIGNED amount and to (the
//                                                            README rule's negative example)
//   notify(...)             Notify(address)                  effect calls target.hook() (a re-entry
//                                                            door), after the nonce is consumed
//   guarded(...)            Guarded(uint256,bool)            reverts on the signed flag after the
//                                                            nonce was consumed (rollback)
// Raw wrappers: consumeRaw (any message, for the decode pins), verifyRaw, requireSignerRaw,
// requireSignerWithGas (requireSignerRaw in a gas-capped frame, for the starved-precompile case).
pragma solidity ^0.8.30;

import {MLDSA87} from "../../src/crypto/MLDSA87.sol";
import {MLDSA87Attested} from "../../src/crypto/MLDSA87Attested.sol";

contract MockAttested is MLDSA87Attested {
    bytes32 public constant APPROVE = keccak256("Approve(uint256,address)");
    bytes32 public constant SUBMIT = keccak256("Submit(address,uint256,bytes)");
    bytes32 public constant HEADER_ONLY = keccak256("HeaderOnly(uint256,address)");
    bytes32 public constant NOTIFY = keccak256("Notify(address)");
    bytes32 public constant GUARDED = keccak256("Guarded(uint256,bool)");

    uint256 public constant THRESHOLD = 2;

    mapping(address => uint256) public allowance;
    mapping(address => bool) public isSigner;
    mapping(bytes32 => mapping(address => bool)) public counted;
    mapping(bytes32 => uint256) public approvals;
    mapping(bytes32 => bool) public executed;
    uint256 public notified;
    uint256 public guardedRuns;

    error MockNotSigner(address who);
    error MockEffectFailed();

    event Approved(address indexed signer, address indexed to, uint256 amount);
    event Counted(bytes32 indexed proposal, address indexed signer, uint256 approvals);
    event Executed(bytes32 indexed proposal);

    constructor(address s0, address s1, address s2) {
        isSigner[s0] = true;
        isSigner[s1] = true;
        isSigner[s2] = true;
    }

    // ── constants as views (compared with the decision bytes / the engine in C) ──

    function tagAttestV1() external pure returns (bytes32) {
        return MLDSA87.TAG_ATTEST_V1;
    }

    function precompileAddress() external pure returns (address) {
        return MLDSA87.PRECOMPILE;
    }

    // ── pure message builders ──

    function approveMessage(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to
    ) external pure returns (bytes memory) {
        return _approveMsg(chainId, verifying, nonce, expiry, signer, amount, to);
    }

    function submitMessage(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target,
        uint256 value,
        bytes memory data
    ) external pure returns (bytes memory) {
        return _submitMsg(chainId, verifying, nonce, expiry, signer, target, value, data);
    }

    function misorderedMessage(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to
    ) external pure returns (bytes memory) {
        return _misorderedMsg(chainId, verifying, nonce, expiry, signer, amount, to);
    }

    function headerOnlyMessage(uint256 chainId, address verifying, uint256 nonce, uint64 expiry, address signer)
        external
        pure
        returns (bytes memory)
    {
        return _headerOnlyMsg(chainId, verifying, nonce, expiry, signer);
    }

    function notifyMessage(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target
    ) external pure returns (bytes memory) {
        return _notifyMsg(chainId, verifying, nonce, expiry, signer, target);
    }

    function guardedMessage(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        bool fail
    ) external pure returns (bytes memory) {
        return _guardedMsg(chainId, verifying, nonce, expiry, signer, amount, fail);
    }

    function proposalId(address target, uint256 value, bytes memory data) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data));
    }

    // ── actions ──

    function approve(
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _approveMsg(block.chainid, address(this), nonce, expiry, signer, amount, to);
        _consumeAttestation(APPROVE, nonce, expiry, signer, pk, sig, message);
        allowance[to] += amount;
        emit Approved(signer, to, amount);
    }

    function submit(
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target,
        uint256 value,
        bytes memory data,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _submitMsg(block.chainid, address(this), nonce, expiry, signer, target, value, data);
        _consumeAttestation(SUBMIT, nonce, expiry, signer, pk, sig, message);
        if (!isSigner[signer]) revert MockNotSigner(signer);
        bytes32 id = proposalId(target, value, data);
        // decision 7(a): the nonce is not the identity of the decision; a signer counts once
        // per proposal, whatever number of attestations it gives.
        if (counted[id][signer]) return;
        counted[id][signer] = true;
        uint256 n = approvals[id] + 1;
        approvals[id] = n;
        emit Counted(id, signer, n);
        if (n == THRESHOLD) {
            executed[id] = true;
            emit Executed(id);
        }
    }

    function approveMisordered(
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _misorderedMsg(block.chainid, address(this), nonce, expiry, signer, amount, to);
        _consumeAttestation(APPROVE, nonce, expiry, signer, pk, sig, message);
        allowance[to] += amount;
    }

    /// WRONG ON PURPOSE: only the header is signed, yet the effect uses `amount` and `to`, which
    /// the caller supplies unsigned. Anyone holding the attestation can choose them.
    function approveHeaderOnly(
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _headerOnlyMsg(block.chainid, address(this), nonce, expiry, signer);
        _consumeAttestation(HEADER_ONLY, nonce, expiry, signer, pk, sig, message);
        allowance[to] += amount;
    }

    /// The effect calls target.hook() AFTER the nonce was consumed; a re-entering target that
    /// replays the same attestation is refused with AttestationNonceUsed.
    function notify(
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _notifyMsg(block.chainid, address(this), nonce, expiry, signer, target);
        _consumeAttestation(NOTIFY, nonce, expiry, signer, pk, sig, message);
        notified += 1;
        (bool ok,) = target.call(abi.encodeWithSignature("hook()"));
        ok;
    }

    /// Consumes, then reverts when the SIGNED flag says so: the nonce mark must roll back.
    function guarded(
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        bool fail,
        bytes memory pk,
        bytes memory sig
    ) external {
        bytes memory message = _guardedMsg(block.chainid, address(this), nonce, expiry, signer, amount, fail);
        _consumeAttestation(GUARDED, nonce, expiry, signer, pk, sig, message);
        guardedRuns += 1;
        if (fail) revert MockEffectFailed();
        allowance[signer] += amount;
    }

    // ── raw wrappers ──

    /// Any message: the decode pins (223 bytes, a dirty expiry word, trailing bytes).
    function consumeRaw(
        bytes32 actionType,
        uint256 nonce,
        uint64 expiry,
        address signer,
        bytes memory pk,
        bytes memory sig,
        bytes memory message
    ) external {
        _consumeAttestation(actionType, nonce, expiry, signer, pk, sig, message);
    }

    function verifyRaw(bytes memory pk, bytes memory sig, bytes memory message)
        external
        view
        returns (bool ok, address signer)
    {
        return MLDSA87.verify(pk, sig, message);
    }

    function requireSignerRaw(address expected, bytes memory pk, bytes memory sig, bytes memory message)
        external
        view
    {
        MLDSA87.requireSigner(expected, pk, sig, message);
    }

    /// requireSignerRaw run in a frame that gets at most `gasCap` gas (a STATICCALL to self).
    /// For a cap in a window, the frame reaches the precompile call with too little gas for the
    /// precompile, the call fails and the library reverts MLDSA87InvalidSignature(expected);
    /// the test scans `gasCap` at run time to find that window (a top-level gas limit cannot,
    /// the calldata floor of the transaction is above it). Returns the nested call's success
    /// flag and its revert data.
    function requireSignerWithGas(
        uint256 gasCap,
        address expected,
        bytes memory pk,
        bytes memory sig,
        bytes memory message
    ) external view returns (bool ok, bytes memory ret) {
        (ok, ret) = address(this).staticcall{gas: gasCap}(
            abi.encodeWithSignature("requireSignerRaw(address,bytes,bytes,bytes)", expected, pk, sig, message)
        );
    }

    // ── internal builders (one abi.encode over header and parameters) ──

    function _approveMsg(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to
    ) internal pure returns (bytes memory) {
        return abi.encode(MLDSA87.TAG_ATTEST_V1, chainId, verifying, APPROVE, nonce, expiry, signer, amount, to);
    }

    function _submitMsg(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory) {
        return abi.encode(
            MLDSA87.TAG_ATTEST_V1, chainId, verifying, SUBMIT, nonce, expiry, signer, target, value, data
        );
    }

    /// actionType and the contract swapped: the header no longer matches.
    function _misorderedMsg(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        address to
    ) internal pure returns (bytes memory) {
        return abi.encode(MLDSA87.TAG_ATTEST_V1, chainId, APPROVE, verifying, nonce, expiry, signer, amount, to);
    }

    function _headerOnlyMsg(uint256 chainId, address verifying, uint256 nonce, uint64 expiry, address signer)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(MLDSA87.TAG_ATTEST_V1, chainId, verifying, HEADER_ONLY, nonce, expiry, signer);
    }

    function _notifyMsg(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        address target
    ) internal pure returns (bytes memory) {
        return abi.encode(MLDSA87.TAG_ATTEST_V1, chainId, verifying, NOTIFY, nonce, expiry, signer, target);
    }

    function _guardedMsg(
        uint256 chainId,
        address verifying,
        uint256 nonce,
        uint64 expiry,
        address signer,
        uint256 amount,
        bool fail
    ) internal pure returns (bytes memory) {
        return abi.encode(MLDSA87.TAG_ATTEST_V1, chainId, verifying, GUARDED, nonce, expiry, signer, amount, fail);
    }
}
