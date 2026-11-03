# Offline Tidecoin native script oracle

`synthetic.json` is a public, synthetic one-input Falcon-512 P2PKH transaction
created by `generate.mjs` from the existing test corpus seed. No real address,
credential, UTXO, network listener or broadcast is involved. The checked-in
fixture SHA-256 is `644c3b86697421e7a89a74d068412316ec7be88969ab0c1bf6db33c2bc72491c`;
regenerating it intentionally produces a different randomized Falcon signature. `verify.cpp`
links the actual Tidecoin consensus implementation, deserializes the bytes,
runs `CheckTransaction` and `IsStandardTx` using the upstream default dust
relay rate (3,000 atoms/kB); its `GetDustThreshold` reports 21,906 atoms
for the fixture P2PKH output. It checks the script with `VerifyScript` using the
pre-activation flags `P2SH|WITNESS` and legacy verification, and again with
`PQ_STRICT`. It also checks both legacy and strict with the upstream
`STANDARD_SCRIPT_VERIFY_FLAGS`; all four accepted this vector. In legacy mode,
changing the signed output, signature, or previous script was rejected. A valid strict verification here is a property of this
particular signature, not a guarantee for every legacy signature.

Upstream source: https://github.com/tidecoin/tidecoin at commit
`7d653be5d24e73b49d101578afb33d8d7a889c1d` (`src/script/interpreter.cpp`,
`src/consensus/tx_check.cpp`, and `src/validation.cpp` flags). Build-time Boost
1.88.0 came from the official release asset pinned by Tidecoin's
`depends/packages/boost.mk`, SHA-256
`dcea50f40ba1ecfc448fdf886c0165cf3e525fef2c9e3e080b9804e8117b9694`.
With this source and its header-only Boost dependency installed in an isolated
workspace, run the supplied offline build script, then the test:

```
TIDECOIN_SRC=/path/to/pinned/source BOOST_ROOT=/path/to/boost/install BUILD_ROOT=/path/to/isolated/build bash test/tidecoin-reference/build-oracle.sh
TIDECOIN_SCRIPT_ORACLE=/path/to/isolated/build/tidecoin-script-oracle node --test test/tidecoin-reference.test.js
```

This checks context-independent transaction shape and script verification
against a supplied previous output. It does **not** prove UTXO existence,
chain activation, the fee rate, node-specific policy configuration, mempool admission or live inclusion.
