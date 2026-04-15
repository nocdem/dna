# Merkle Direction Convention (Server <-> Client)

**Source of truth:** `nodus/src/witness/nodus_witness_merkle.c`
- `nodus_witness_merkle_verify_proof` (~line 494)
- `nodus_witness_merkle_build_proof` (~line 413)
- `rfc6962_path` (~line 351), `reverse_proof` (~line 396)

## RFC 6962 Domain Tags
- `leaf_hash(d)     = SHA3-512(0x00 || d)`
- `inner_hash(L, R) = SHA3-512(0x01 || L || R)`

The caller passes a 64-byte composite digest (from
`nodus_witness_merkle_leaf_hash`); both `build_proof` and `verify_proof`
apply `leaf_hash` to that digest internally before walking.

## Server representation
- Flat sibling buffer: `uint8_t siblings[depth * 64]`
- Positions: `uint32_t positions` bitfield
- After `reverse_proof`, level indexing runs **leaf-to-root**: bit `i`
  and `siblings[i*64 .. i*64+64]` describe level `i` of the verifier
  walk, where `i=0` is the leaf level.

## Direction semantics (Q1, Q2, Q3)

**Q1 — `rfc6962_path` left subtree case:**
When `idx < k` the target is in the LEFT subtree, so the sibling is the
right subtree root. The code sets `sibling_is_left = 0` and leaves the
bit CLEARED. When `idx >= k` (target in RIGHT subtree), sibling is the
left subtree root, `sibling_is_left = 1`, bit is SET. "Left" means bit
value `1` in the final `positions` (sibling on LEFT).

**Q2 — `reverse_proof`:**
`rfc6962_path` collects siblings and position bits in **root-to-leaf**
order (outermost recursion first). `verify_proof` walks **leaf-to-root**.
`reverse_proof` flips both the sibling array and the bitfield across
`depth` bits so that after the flip, level `i` of the verifier walk
corresponds to bit `i` and slot `i` of the buffers.

**Q3 — `verify_proof` bit semantics:**
```c
if (positions & (1u << i))     // bit SET
    inner_hash(sib, cur, parent);   // sibling LEFT,  cur RIGHT
else                                  // bit CLEAR
    inner_hash(cur, sib, parent);   // sibling RIGHT, cur LEFT
```
- `positions & (1u << i) != 0` -> sibling LEFT at level `i`
- `positions & (1u << i) == 0` -> sibling RIGHT at level `i`

## Client conversion (dnac_merkle_proof_t)
- `proof->directions[i] = (uint8_t)((positions >> i) & 1u);`
- `memcpy(proof->siblings[i], server_siblings + i*64, 64);` for `i` in `[0, depth)`
- `proof->depth = depth`
- Client verifier rule (MUST match server):
  - `directions[i] == 1` -> `inner_hash(siblings[i], cur, parent)` (sibling LEFT)
  - `directions[i] == 0` -> `inner_hash(cur, siblings[i], parent)` (sibling RIGHT)
- Single-leaf tree: `depth == 0`, root equals leaf_hash(composite).
