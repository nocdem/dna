# QTC native ML-DSA signature oracle

The `.c` and `.h` files other than `verify.c` are unmodified files from
[`qtcchain/qtc` commit `5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24`, `src/libbitcoinpqc/dilithium/ref`](https://github.com/qtcchain/qtc/tree/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24/src/libbitcoinpqc/dilithium/ref).
They are covered by the upstream LICENSE; SHA-256 digests are in SHA256SUMS.
`verify.c` and `run.mjs` are the local host adapter. Run from web-wallet:

```sh
node test/qtc-reference/run.mjs
```

This compiles the native QTC verifier and verifies a synthetic wallet-produced
ML-DSA signature with a public test seed, and rejects a modified message.
It does not execute QTC script interpretation or validate a complete transaction
against a node, and it does not prove UTXO spendability or fee policy.

## QTC release node regtest oracle

Obtain the official QTC v0.2.5 x86_64 Linux archive from its GitHub release;
verify its published SHA-256
`cc2755c0b4f82d9c4f1d1dbf426249d38f4e1b1fba97ff7e53d072e0c3f805ca`.
With the extracted binaries, run:

```sh
QTC_BIN=/path/to/qtc-0.2.5/bin node test/qtc-reference/run-regtest.mjs
```

The runner verifies both executable hashes, starts a fresh local regtest node
with P2P networking, discovery, DNS seeding and wallet disabled, generates 101
synthetic blocks, then asks `testmempoolaccept` to validate (without submitting)
a transaction signed by a public test key. On 2026-11-02 the valid transaction
was accepted (3873 virtual bytes); both a modified signature and modified output
were rejected as an invalid ML-DSA signature. The public release v0.2.5 tag is
`0fcae58a017b10d5c0a5793cef39373bca0898c1`; the separate current source
port pin `5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24` is later. This tests that
release's regtest implementation, not mainnet UTXOs, deployment, or finality.

The runner also independently signs two adversarial structured-prevout claims:
one false input value and one different owned script/tree for the actual coin.
The release node rejected them respectively as `Invalid ML-DSA signature` and
`Witness program hash mismatch`. This demonstrates actual-prevout commitment,
not explorer unspentness or public gateway availability. No transaction was
submitted; all checks use the isolated synthetic regtest acceptance oracle.
