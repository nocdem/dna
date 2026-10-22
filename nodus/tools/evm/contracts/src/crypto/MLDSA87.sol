// SPDX-License-Identifier: Apache-2.0
//
// MLDSA87 — calls the Nodus ML-DSA-87 verification precompile.
//
// Part of the Nodus contract library v0.2 (nodus/tools/evm/contracts, README.md).
// Design: docs/plans/2026-10-22-mldsa87-companion-library-design.md rev 2 §1.2-1.4 (local).
//
// The precompile (decision docs/plans/decisions/2026-10-21-mldsa87-evm-precompile.md) takes
//     input = public key (2592 B) ‖ signature (4627 B) ‖ message (0 .. 65 536 B)
// and verifies under the fixed FIPS 204 context "nodus.evm.attest.v1". A valid signature
// returns the signer's 32-byte Nodus address SHA3-512(pk)[0..32]; a malformed input or an
// invalid signature is a SUCCESSFUL call with EMPTY output; too little gas fails the call.
//
// All functions are internal (inlined; no linked library, solc rule 7). The call is a
// zero-value STATICCALL (decision item 8). Nothing here authorises an action by itself and
// it never replaces chain authorization (2026-10-04-nodus-evm-domain.md decision 4).
pragma solidity ^0.8.30;

library MLDSA87 {
    /// The precompile address, SHA3-512("NDS.EVMMLDSA87.v1")[0..32] (decision item 5). Written
    /// as an all-lowercase number literal with an explicit conversion (solc rule 3).
    address internal constant PRECOMPILE =
        address(0x66e24906024f903b345880bf43c39224c772b9acf62cd78299ced278cb3c9cce);

    /// The message-format identifier of the signed attestation message (decision "TAG_ATTEST_V1").
    bytes32 internal constant TAG_ATTEST_V1 = keccak256("nodus.evm.attest.message.v1");

    uint256 internal constant PK_LEN = 2592;
    uint256 internal constant SIG_LEN = 4627;
    uint256 internal constant MSG_MAX = 65536;
    /// The signed header: seven 32-byte words (design §1.3).
    uint256 internal constant HEADER_LEN = 224;

    error MLDSA87BadLength();
    error MLDSA87MessageTooLong(uint256 length);
    error MLDSA87ZeroSigner();
    error MLDSA87InvalidSignature(address expected);

    /// Verifies `sig` over `message` for the key `pk`.
    /// Reverts on a wrong `pk` / `sig` length or a message over MSG_MAX (before the call).
    /// `ok` is true only when the call succeeded and returned exactly 32 bytes; then `signer`
    /// is the verified signer's address. A failed call (including a starved precompile) or an
    /// empty output gives ok == false and signer == address(0); the caller decides.
    function verify(bytes memory pk, bytes memory sig, bytes memory message)
        internal
        view
        returns (bool ok, address signer)
    {
        if (pk.length != PK_LEN || sig.length != SIG_LEN) revert MLDSA87BadLength();
        if (message.length > MSG_MAX) revert MLDSA87MessageTooLong(message.length);
        (bool success, bytes memory ret) = PRECOMPILE.staticcall(bytes.concat(pk, sig, message));
        ok = success && ret.length == 32;
        if (ok) signer = abi.decode(ret, (address));
    }

    /// Reverts unless `sig` is a valid signature over `message` by exactly `expected`.
    function requireSigner(address expected, bytes memory pk, bytes memory sig, bytes memory message)
        internal
        view
    {
        if (expected == address(0)) revert MLDSA87ZeroSigner();
        (bool ok, address signer) = verify(pk, sig, message);
        if (!ok || signer != expected) revert MLDSA87InvalidSignature(expected);
    }
}
