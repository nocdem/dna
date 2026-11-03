# Public read-only observations, 2026-11-02 UTC

Captured with `curl` bounded to 8 seconds and 256 KiB, synthetic Origin
`https://wallet.invalid`; no credentials, generated user wallets or sends.
Raw JSON and HTTP headers are preserved as received; data is public and not
proof of current behavior. Headers include public gateway infrastructure data.

- `xion-empty-history`: 07:56:34 UTC, mainnet
  `GET https://api.xion-mainnet-1.burnt.com/cosmos/tx/v1beta1/txs`
  with `query=transfer.recipient='xion1qgpqyqszqgpqyqszqgpqyqszqgpqyqszp7aesp'`,
  `order_by=ORDER_BY_DESC`, `page=1`, `limit=1`. Address is synthetic.
- `splendor-mainnet-empty`: 07:56:36 UTC,
  `GET https://quantum-rpc.splendor.org/idx/v1/address/SQ:0000000000000000000000000000000000000000000000000000000000000000?limit=1`.
  All-zero address is a synthetic query.
- `splendor-testnet-address`: 07:57:18 UTC,
  `GET https://quantum-rpc-testnet.splendor.org/idx/v1/address/SQ:09f44c419a48c70579b1a532c60e5786ecacf4de76e606d1901dfaf21e9745a9?limit=2`.
  Address is the validator publicly documented in the official chain README.
- `splendor-testnet-receipt`: 07:57:36 UTC, node receipt for the first public
  transaction hash returned by the immediately preceding testnet query,
  `GET https://quantum-rpc-testnet.splendor.org/tx/90d1d47f1f969b82d8ee3a65ecd5bfe4ce0b91d5121a731da5776f3918f5e451/receipt`.

CORS header observations here apply only to the requested endpoint and origin;
the indexer returns `*`, while this node receipt did not return ACAO. Indexer
responses are operator-provided reports, not cryptographic inclusion proofs.
- `xion-testnet-public-contract`: 07:58:57 UTC, `GET
  https://api.xion-testnet-2.burnt.com/cosmos/tx/v1beta1/txs` with
  `query=transfer.sender='xion1epzznazp28up4asses7jdcyqnw3n8lu7f5g9xs'`,
  `order_by=ORDER_BY_DESC`, `page=1`, `limit=1`. The account is the public
  example admin in `burnt-labs/tradeos-cw-sc` README. The resulting on-chain
  record is a contract call, not a native send; it illustrates fee transfers
  in event search and must not be presented as native sent amount.
- `xion-testnet-public-send`: 07:59:17 UTC, `GET
  https://api.xion-testnet-2.burnt.com/cosmos/tx/v1beta1/txs` with
  `query=message.action='/cosmos.bank.v1beta1.MsgSend'`,
  `order_by=ORDER_BY_DESC`, `page=1`, `limit=1`. This is a public testnet
  on-chain transaction whose memo identifies an automation QA test. It is
  not a transaction initiated by this task.
- `xion-testnet-simulate`: 07:59:56 UTC, read-only `POST
  https://api.xion-testnet-2.burnt.com/cosmos/tx/v1beta1/simulate`; request
  fixture contains a synthetic arbitrary public-key byte pattern (not a wallet,
  no private key) and all-zero dummy signature. The endpoint returned HTTP 500,
  Cosmos error code 2, stating that the synthetic fee payer did not exist;
  no valid gas estimate or transaction acceptance follows from that error.
  The documented simulation endpoint is distinct from transaction broadcast.
- `asentum-empty-history`: 08:00:20 UTC, `GET
  https://explorer.asentum.com/api/indexer/address/0x0000000000000000000000000000000000000000/txs?page=1&size=1`.
  The all-zero address is synthetic. Response is HTTP 200, but has no
  Access-Control-Allow-Origin for the synthetic Origin. Node and separate
  explorer-indexer chain identity are not cryptographically bound.
- `splendor-testnet-status`: 08:00:42 UTC, read-only GET
  `https://quantum-rpc-testnet.splendor.org/status`; chain ID, genesis hash,
  decimals, smallest-unit fee and node-reported minimum are a point-in-time
  snapshot, not an executable fee guarantee.
- `xion-testnet-node-info`: 08:00:46 UTC, read-only GET
  `https://api.xion-testnet-2.burnt.com/cosmos/base/tendermint/v1beta1/node_info`.
  Reported chain ID is a provider assertion, not a cryptographic proof.
- `asentum-chain`: 08:18:57 UTC GET `https://testnet.asentum.com/chain`;
  finalized-header `baseFeePerGas` reported `1` wei. This is a cached,
  finalized snapshot, not a future-block fee guarantee.
- `asentum-genesis`: 08:19:03 UTC GET `https://testnet.asentum.com/genesis`;
  reports the known testnet genesis identity and public genesis data.
- `asentum-missing-receipt`: 08:20:38 UTC GET `/receipts/` with public example
  hash `0x3261a75d9804a1f92a08d88ca0878ad5edac0bf1e63c408d8f2181a6ffcd7ea1`
  from the official Asentum Node API Reference. HTTP 200 and `receipt not
  found` are an inconclusive status, not proof of failure/non-submission.
- `splendor-testnet-account`: 08:07:27 UTC GET
  `https://quantum-rpc-testnet.splendor.org/state/account/SQ:09f44c419a48c70579b1a532c60e5786ecacf4de76e606d1901dfaf21e9745a9`.
  The address is the publicly documented validator. Response includes the
  public on-chain ML-DSA key, not private material. Node did not return ACAO
  for the synthetic Origin; account state is a provider report, not a proof.

Asentum Web transport (2026-11-02 08:42–08:44 UTC): a synthetic
`Origin: https://example.com` OPTIONS preflight to the existing testnet `/tx`
endpoint returned HTTP 204, `Access-Control-Allow-Origin: *`, methods
`GET, POST, OPTIONS`, and `Content-Type, Authorization` allowed headers. A
GET of `/balance/ase1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5eqqfx` (the all-zero
synthetic 20-byte address, not a wallet-derived address) returned HTTP 200
with the same CORS headers and the captured JSON. The headers are normalized
to LF. This is read-only transport evidence, not transaction admission or a
cryptographic network proof; no transaction was submitted.
