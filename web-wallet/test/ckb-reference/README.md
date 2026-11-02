# CKB TX_MESSAGE_ALL source oracle

`ckb_tx_message_all.h` is **unmodified** from Cryptape's MIT-licensed
[`nervosnetwork/quantum-resistant-lock-script` commit `082c0a19ce4e0b2c0b00f7b46f423f59a30afc71`](https://github.com/nervosnetwork/quantum-resistant-lock-script/blob/082c0a19ce4e0b2c0b00f7b46f423f59a30afc71/contracts/c-sphincs-all-in-one-lock/utils/ckb_tx_message_all.h), Git blob `92e1b761f933727d732e4d9e336a0576b7251a79`, SHA-256 `b30daad5fac9497bf7d6d40e97ec646c46ad238ca4506cefcb081678c9ead36a`. LICENSE is upstream MIT.

`oracle.c` is our host-only fake-syscall adapter, and the two local stub headers
satisfy includes for this isolated check. Run `node test/ckb-reference/run.mjs`
from web-wallet with a local C compiler; it compiles the exact upstream C
message algorithm, feeds synthetic CKB data and compares its byte stream to
our JS preimage and a pinned JS digest fixture. This checks one single-input,
empty-data/empty-type-witness case. It **does not execute the contract in
CKB-VM**, verify a full transaction's consensus, test real cells, or authorize
sending. The C compiler and source oracle are not required by browser runtime.

## Actual deployed CKB-VM lock oracle

`mainnet-quantum-lock.bin` is the public deployed cell data at mainnet outpoint
`0x4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a:0`,
as documented in the pinned upstream project's README. It was retrieved via
`get_live_cell` from the configured public mainnet RPC. Its SHA-256 is
`59a4c25e6185f906ba379db530fc08c1e1f8aa23db2bcb265a6ab321a0d5b527`;
CKB personalized data hash is
`0x49417a0ed39196e8d90d0088ca98bf6b881966ba1c2ea12160ca42141787565e`.
The cell's type script hashes to the official code hash
`0x302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf`.

Retrieve the official CKB standalone debugger v1.1.1 x86_64 Linux release
archive from its GitHub release and verify the published archive SHA-256
`0dee02804af46386527c8bb94c2ee63592594ca1ec952ea42ffa9df07a9f005e`.
The extracted binary's SHA-256 is
`24641357274ca464ecd86fd63b715ad96b5490d27b5ca029df37511e435d96f0`.
Then run:

```sh
CKB_DEBUGGER=/path/to/ckb-debugger node test/ckb-reference/run-vm.mjs
```

The runner verifies the binary and lock hashes, creates a deterministic mock
transaction from a public NIST test key (not a funded cell), executes the
actual deployed lock with CKB-VM, and checks tamper controls. The multi-input
fixture uses two distinct outpoints/capacities in the same quantum-lock group,
a distinct quantum recipient and sender change, and executes using both input
script indices. It rejects altered second-input capacity and witness signature.
Observed output:

```text
multi-valid: Run result: 0; All cycles: 25983557(24.8M)
multi-valid-second-group-index: Run result: 0; All cycles: 25983557(24.8M)
multi-altered-second-input-capacity: Run result: 107; All cycles: 25498136(24.3M)
multi-altered-witness: Run result: 107; All cycles: 25579225(24.4M)
valid: Run result: 0; All cycles: 26462819(25.2M)
altered-signature: Run result: 107; All cycles: 25492060(24.3M)
altered-output: Run result: 107; All cycles: 25492161(24.3M)
```

This executes the lock, not the full CKB node transaction-pool/consensus
pipeline. No transaction was broadcast, no real outpoint or secret was used,
and no assertion about live-cell spendability or finality follows.

## Full-format recipient support

The parser/transaction builder accepts only the full
`0x00 | code_hash | hash_type | args` Bech32m representation from
[RFC 0021](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md).
It limits hash types to the official [hash-type list](https://docs.nervos.org/docs/tech-explanation/hash-type) 0, 1, 2, and 4; deprecated
short/full Bech32 forms and other hash type values are not accepted. This
candidate additionally requires lowercase and at most 1023 characters as a local
resource policy; RFC 0021 itself removes the Bech32 length limit. Empty-data,
no-type recipient occupied capacity is `(8 + 32 + 1 + args.length) * 10^8`
shannons, per [Nervos occupied capacity rules](https://docs.nervos.org/docs/tech-explanation/capacity).
The sender, inputs, and change remain restricted to the existing quantum profile.

The documented Nervos public example address with the standard secp256k1
lock and 20-byte args has a 61 CKB minimum. The synthetic transaction uses
exactly that minimum and separate quantum-locked change. The deployed sender
lock VM oracle yielded:

```text
standard-recipient-exact-minimum: Run result: 0; All cycles: 26542903(25.3M)
standard-recipient-altered-capacity: Run result: 107; All cycles: 26461793(25.2M)
```

The VM enforces the sender lock, not recipient spendability or full-node
consensus. A valid full-format address is not proof the recipient controls or
can spend it. The reviewed trusted-wallet mainnet path supports this full-format subset;
network gates remain in force and site-provider signing is not exposed.
