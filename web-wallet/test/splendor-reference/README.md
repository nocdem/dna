# Official Go verification oracle (synthetic fixture)

This optional, offline-after-dependency-install oracle reads `synthetic.json`,
which is a public deterministic test seed-derived transfer, not a real wallet.
The JS signer output is checked by the actual official Splendor Go module's
`types.Transaction.Validate`, `crypto.DeriveAddress`, `VerifySignature`, and
`FullHash`; expected hash is
`74d058c39415a477a7533641509992f7617a7deae047e9bbc8f9b75b22473198`.

Module v1.2.2 resolved to commit
`5ba2819316a85ba357aca02f68a922c409f659ba` (Go proxy module origin), and module
checksums are pinned in `go.sum`. The oracle was run with official Go 1.27.3
linux-amd64 binary (go.dev published SHA256
`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`).
With dependencies installed, run `go run . < synthetic.json` in this directory.
This verifies serialization/signature/key binding, not deployed mempool
acceptance, fee freshness, CORS, wallet safety or broadcast.
