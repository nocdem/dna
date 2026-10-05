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
| `qgp sign <file> <sk> [--out <sig>]` | detached signature, default `<file>.qgpsig` (format under "Formats") |
| `qgp verify <file> <sig> <pk>` | checks a detached signature |
| `qgp deb-sign <deb> <sk>` | appends the `_qgp.sig` member; `<sk>.pub` must sit next to `<sk>`; the file is replaced atomically |
| `qgp deb-verify <deb> --trust <dir> [--allow-downgrade]` | strict 4-member parse, prefix, signature by a pinned unrevoked key, then `dpkg-deb -f` on the same bytes, trust floor, highest accepted version |
| `qgp trust-make <body> <sk> --serial <n> --out <file> [--prev <trust-file>]` | signs a trust body; without `--prev` it is a bootstrap file |
| `qgp trust-accept <file>... --trust <dir> [--bootstrap]` | accepts trust files in the order given, each chained to the one before; `--bootstrap` only when `<dir>` holds no state yet, and then takes the WHOLE chain (see "Bootstrap") |

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
- File signature (`qgp sign` / `qgp verify`, approved by the operator 2026-10-05,
  `docs/plans/decisions/2026-10-03-apt-repo-qgp.md`):
  `M_file = "NDS.QGPFILE.v1"‖0x0000 ‖ file_len(8, BE) ‖ SHA3-512(file)` — the 14-byte tag
  zero-padded to 16, so 16 + 8 + 64 = 88 bytes; pure ML-DSA-87, empty context. The
  signature file is the raw 4627-byte signature, nothing else.
- Key files: raw bytes, exact length (secret 4896, public 2592). The secret key is a
  mode-0600 file and is **not encrypted at rest**: the operator chose 0600 for now
  (2026-10-05, same decision file); encrypting it (password KDF + AEAD) is a later,
  separately discussed design. Accepted risk: root on the signing machine, a leaked
  backup or disk image, or a stolen machine yields the key.

Trust directory: `qgp-trust` (last accepted file), `accepted-versions`
(highest accepted version per package), `.lock`.

## Bootstrap

The bootstrap bundle is the WHOLE trust chain, every trust file from serial 1 to
the latest (decision `docs/plans/decisions/2026-10-03-apt-repo-qgp.md`, operator
2026-10-05; replaces bytes REV 2 R2-4 "ships the LATEST accepted trust file"):

```
qgp trust-accept --bootstrap f1 f2 ... fN --trust <dir>
```

- `<dir>` must hold no trust state yet.
- `f1` must be serial 1, signed with a zero `prev_digest` by a key listed in its
  own body (`trust-make` without `--prev`). Any other first file is refused:
  serial ≠ 1 → `bootstrap_must_start_at_serial_1`; a file signed over a non-zero
  `prev_digest` → `signature_invalid`.
- `f2 … fN` follow in order; each is checked against the one accepted before it,
  exactly as a normal `trust-accept`.
- The chain must have been checked by hand before it is pinned; nothing is
  stored past the first refused file.
