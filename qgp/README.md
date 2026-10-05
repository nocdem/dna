# qgp — post-quantum package signing (phase 1)

`qgp` signs the validator packages (`.deb`) and the trust state that decides
which release key may sign them. ML-DSA-87 (FIPS 204, pure mode, empty
context) via `shared/crypto` and SHA3-512. Linux only (Debian 12/13,
Ubuntu 24.04). Encryption is a later phase.

Written fresh on `shared/crypto`; nothing is taken from the historical QGP
repository.

## Build

```
cmake -S qgp -B qgp/build && cmake --build qgp/build -j$(nproc)
```

Builds `qgp` and `test_qgp_deb` (needs `libjson-c-dev` for the test).

## Commands

| Command | Does |
|---|---|
| `qgp keygen <out>` | new key: `<out>` (secret, 4896 B, mode 0600, created with O_EXCL) and `<out>.pub` (public, 2592 B); prints the key id and the trust-body `key` line |
| `qgp sign <file> <sk> [--out <sig>]` | detached signature, default `<file>.qgpsig` (see "Not yet approved") |
| `qgp verify <file> <sig> <pk>` | checks a detached signature |
| `qgp deb-sign <deb> <sk>` | appends the `_qgp.sig` member; `<sk>.pub` must sit next to `<sk>`; the file is replaced atomically |
| `qgp deb-verify <deb> --trust <dir> [--allow-downgrade]` | strict 4-member parse, prefix, signature by a pinned unrevoked key, then `dpkg-deb -f` on the same bytes, trust floor, highest accepted version |
| `qgp trust-make <body> <sk> --serial <n> --out <file> [--prev <trust-file>]` | signs a trust body; without `--prev` it is a bootstrap file |
| `qgp trust-accept <file>... --trust <dir> [--bootstrap]` | accepts trust files in serial order; `--bootstrap` only when `<dir>` holds no state yet |

Exit status: 0 accepted / done, 1 refused, 2 usage. Results on stdout,
diagnostics on stderr.

## Formats

The approved byte layouts are `docs/plans/2026-10-05-apt-qgp-signing-bytes.md`
items 1-3 as amended by its REV 2. The independent oracle and its vectors are
`scripts/qgp-sign/qgp_deb_oracle.py` and `qgp_deb_kat.json`.

- `.deb`: debian-binary, control.tar[.gz|.xz|.zst], data.tar[.gz|.xz|.zst|.bz2|.lzma],
  `_qgp.sig` — exactly these four, nothing after.
  `M_pkg = "NDS.QGPDEB.v1"‖0x000000 ‖ key_id(64) ‖ prefix_len(8, BE) ‖ SHA3-512(prefix)`.
- Trust file: `0x01 ‖ serial(8) ‖ signer key_id(64) ‖ body_len(4) ‖ body ‖ 4627(2) ‖ sig`;
  `M_trust = "NDS.QGPTRUST.v1"‖0x00 ‖ serial ‖ prev_digest ‖ signer ‖ SHA3-512(body)`,
  `prev_digest` = SHA3-512 of the previously accepted file (zeros at bootstrap).
- Key files: raw bytes, exact length (secret 4896, public 2592). **Not encrypted at rest yet.**

Trust directory: `qgp-trust` (last accepted file), `accepted-versions`
(highest accepted version per package), `.lock`.

## Not yet approved

`qgp sign` / `qgp verify` use
`M_file = "NDS.QGPFILE.v1"‖0x0000 ‖ file_len(8, BE) ‖ SHA3-512(file)` and a raw
4627-byte signature file. This layout is NOT part of the approved bytes; the
functions carry `_UNAPPROVED` in their names until the operator approves it.
