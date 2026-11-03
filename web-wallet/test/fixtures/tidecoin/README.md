# Tidecoin legacy preimage fixture

`native-preimage-oracle.cpp` was compiled against the source checkout of
`tidecoin/tidecoin` at commit `7d653be5d24e73b49d101578afb33d8d7a889c1d`.
It uses that checkout's `CTxIn`, `CTxOut`, `CScript`, and `DataStream` to
serialize the exact synthetic SIGHASH_ALL preimage asserted in the JS test.
Reproduce, replacing `$TDC` with that checkout:

```
g++ -std=c++20 -ffunction-sections -fdata-sections -Wl,--gc-sections \
 -I"$TDC/src" native-preimage-oracle.cpp "$TDC/src/script/script.cpp" \
 "$TDC/src/support/cleanse.cpp" -o native-preimage-oracle
./native-preimage-oracle
```

This is an oracle for serialization, not a complete native node script or
mempool acceptance test; no funded addresses or broadcasts are involved.
