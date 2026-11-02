# Optional XION protobuf fixture oracle

`generate-fixtures.mjs` independently encodes the fields in Cosmos SDK
`64fd208a11fb54f7ffdca1a1290c2cfbbc254e49` `proto/cosmos/tx/v1beta1/tx.proto`,
`proto/cosmos/bank/v1beta1/tx.proto` and `proto/cosmos/crypto/mldsa65/keys.proto`
using google-protobuf 3.21.4 BinaryWriter. It prints SHA-256 digests of the
body, auth-info and sign-doc bytes for synthetic mainnet/max-uint64 and
testnet/zero fixtures asserted by `test/xion-sign-doc.test.js`. It is a
serialization oracle, not evidence that XION will accept or include a tx.

To reproduce, install `google-protobuf@3.21.4` in an isolated temporary npm
project and make that package plus this wallet's pinned `@scure/base` and
`@noble/hashes` available to the script; never add oracle dependencies to the
production bundle. No network or private key is required for the generated
fixture itself.

## Synthetic in-memory XION app / CheckTx oracle

`native-ante-oracle_test.go.txt`, `native-ante-synthetic.json`, and
`native-ante-result.txt` preserve the 2026-11-02 oracle. The fixture is built
from the public PQ receive test phrase; it MUST NEVER be funded or broadcast.
Its SignDoc chain ID is `synthetic-xion`, not either public chain. Regenerate
and compare it offline with:

```
node test/xion-reference/generate-native-ante-fixture.mjs /tmp/xion-ante.json
cmp test/xion-reference/native-ante-synthetic.json /tmp/xion-ante.json
```

The oracle instantiated an in-memory XION app at testnet-source commit
`ac20074b40ecdf0d79320396fe1882d4c8f3d457`, with a local-only synthetic funded
BaseAccount and 0.025 uxion/gas *test setting*. It tested this wallet's TxRaw:
valid code 0; wrong signature, chain and account number code 4; wrong sequence
code 32; insufficient fee code 13. The same local app's simulation accepted
bad signature and insufficient fee. A separate direct cached-context ante
check accepted timeout height 2 at height 2, rejected it at height 3, and
rejected changing the timeout to 3 without a fresh signature. No node listener or public call was used.
Running the same harness with `XION_HIGH_ACCOUNT=1` initializes a synthetic
BaseAccount numbered 9223372036854775808; its matching JS-signed TxRaw passes
CheckTx (code 0) and a TxRaw signed for account zero fails (code 4). Output is
preserved in `native-ante-high-account-result.txt`. This checks uint64 account
numbers independently from the signed timeout's int64 height bound.
This is not proof of deployed fee policy, public network inclusion, or the
live inclusion or the deployed fee policy. The chain-specific v32 release
explicitly announces ML-DSA-65 native account keys despite the generic SDK
proto's validator-only warning.

To reproduce, check out that exact XION commit, copy the `.go.txt` harness to
its `app/local_xion_wallet_oracle_test.go`, and set `XION_FIXTURE` to the
absolute synthetic JSON path. Build using its pinned go.mod (SDK v0.55.0,
CometBFT v0.40.0); the result shown used Go 1.27.3 linux/amd64 (the deployed
node reported Go 1.26.10), `go test -p 2 ./app -run
'^TestLocalSyntheticXionWalletAnte$' -count=1 -v`. `GOPATH`, `GOCACHE`,
`GOTMPDIR`, and `TMPDIR` were isolated in the workspace overlay.

The Go proxy module for `github.com/burnt-labs/barretenberg-go v0.6.1` carries
a Git LFS pointer rather than the required Linux archive. For this local test
only, an official v0.6.1 checkout at commit
`d63a17507082e232025edcf98233ad293bafcfd1` supplied its LFS archive; its
size 96,628,910 and SHA-256
`815b86618f5df0c080dca532648560143978dbd8b255d875711b77f8237e1ade`
matched the original module pointer. The XION worktree used a local go.mod
replace to that checkout, and its Linux-only CGo link flags added `-lc++abi`
after `-lc++` (no application or cryptographic source changes). Debian 13
LLVM 19 shared runtime packages were extracted, not system-installed; package
SHA-256s were `02caf4050500bee68288172433d639986ae9ec609a30fc1cf53e0e25eea0dcdf`
(libc++), `586dfba17aa2d5722d1b60b4beafa987b02441905cbb1bc1a3548651062854e8`
(libc++abi), and `8473b38395b7e2d754146750a9ad71a699bb09e1f958f06a7e6804eda37f45c6`
(libunwind). `CGO_LDFLAGS` and `LD_LIBRARY_PATH` pointed at those extracted
libraries. The Go binary SHA-256 was
`5f5eb6d0b2fb6aa0bb5d5f8c5f1c944e0de955c925f0111af92a9d8f79680b5b`;
the signing WASM SHA-256 was
`71595ca97b1ec6cae445900f190feaa5fadec665449a36bffd7befa4b87c28a2`.
The large toolchain and LFS archives are deliberately not checked in.
