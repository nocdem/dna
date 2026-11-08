#!/usr/bin/env python3
"""
hf9_xor_oracle.py - independent oracle for the HF-9 storage transition's XOR
baseline (plan docs/plans/approved/2026-11-04-hf9.md section 8.6, :306 and :309),
used by tests/test_cmt_hf9.sh (short-epoch run).

WHAT IT COMPUTES (and nothing else), from STORED inputs only
  E-s1   the union count of every member m of set(H) for H in {H2 - E, H2}:
         the number of published segments k (published_height <= H) with
             m in holders(k, set(H))
             OR (published_height(k) <= H - E and m in holders(k, set(H - E)))
         where holders() is the XOR rule. Source walk, read to its end:
         st_member_walk (nodus_witness_v2_storage.c:937-975) with the callback
         st_rel_union (:2418-2428), called from the edge's E-s1 loop
         (:2469-2492); a holder of set(H - E) that is not a member of set(H)
         is skipped (:957-967); an absent set(H - E) has count 0 (:2479).
  B1     held_union and n_new of every member m of set(B1) at the first
         generation-6 boundary B1 = H2 + E (plan :299-309, source: the
         per-segment loop of the boundary, nodus_witness_v2_storage.c:2175-2296,
         counts :2275-2296, held_union / n_new :2300-2325):
             old(k)     = published_height(k) + E <= B1                (:2189)
             prev(k)    = holders(k, set(H2))   (XOR, at B1 :2211-2222)
             new(k)     = the rendezvous (HRW) holders of k over eligible(set(H2)),
                          R copies = the E-s2 rows (derived here, not read)
             ended(m)   = #{ old k : m in prev(k) and m not in new(k) }
             n_new(m)   = #{ old k : m in new(k)  and m not in prev(k) }
             held_union = held(m) + ended(m),   held(m) = #current rows of m
         (the same numbers the E-s3 table gives when B1 has no event,
          :2304-2321: ended_x / new_x, built at :2540-2560.)

THE XOR RULE (shared/dnac/ledger_roots_v2.c, read to its end)
  a_key   = SHA3-512(TAG_STASGN || segment_root)     :811-818
  TAG_STASGN = "NDS.STASGN.v1" + 3 NUL = 16 bytes     :108
  holders = the R = 3 members with the SMALLEST (a_key XOR node_fp) as a 64-byte
            big-endian integer, members with fail_streak >= 3 skipped
            (DNA_V2_STORAGE_HOLDERS 3, DNA_V2_STORAGE_FAIL_LIMIT 3,
             ledger_roots_v2.h:856, :858), the order total (distinct fps)
                                                         :828-874
  Only hashlib.sha3_512 (SHA3-512, the hash the source calls) is used.

INPUT (text file, one record per line; fields separated by blanks)
  E <epoch_length>
  S <epoch_start> <node_fp_hex> <fail_streak>      member of a frozen set
  K <k> <segment_root_hex> <published_height>      published segment
  X <epoch_start> <node_fp_hex> <held_union> <n_new>   (ignored here; the shell compares)
  M <node_fp_hex>                                  member of set(B1)
  R <k> <node_fp_hex>                              (accepted, ignored: the rows are derived)
USAGE
  hf9_xor_oracle.py --h2 H2 --b1 B1 --copies R FILE
OUTPUT (sorted, one per line)
  ES1|<H>|<fp>|<union count>          for H in {H2-E, H2}, every member of set(H)
  RWS|<k>|<fp>                        the E-s2 rows (HRW, R copies) of every k published <= H2
  B1|<fp>|<held_union>|<n_new>        every M member
HRW (plan 8.3; shared/dnac/ledger_roots_v2.c:876-940): score = SHA3-512(TAG_STHRW
  || a_key || fp), TAG_STHRW = "NDS.STHRW.v1" + 4 NUL (:114); the R highest by
  (score, fp) among members with fail_streak < 3 (the same independent reading
  as nodus/tests/vectors/hf9_kat_oracle.py hrw_score / hrw_holders, whose KATs
  pin the construction; not imported - this file stands alone).
Exit 2 on any malformed input; the oracle never guesses.
"""
import argparse
import hashlib
import sys

TAG_STASGN = b"NDS.STASGN.v1\x00\x00\x00"      # ledger_roots_v2.c:108, 16 bytes
HOLDERS = 3                                     # ledger_roots_v2.h:856
FAIL_LIMIT = 3                                  # ledger_roots_v2.h:858
ROOT_LEN = 64


def die(msg):
    sys.stderr.write("hf9_xor_oracle: %s\n" % msg)
    sys.exit(2)


TAG_STHRW = b"NDS.STHRW.v1\x00\x00\x00\x00"    # ledger_roots_v2.c:114, 16 bytes


def assign_key(root):
    return hashlib.sha3_512(TAG_STASGN + root).digest()


def hrw_score(a_key, fp):
    """dna_v2_segment_score (ledger_roots_v2.c:876-886): SHA3-512(TAG_STHRW ||
    a_key || node_fp), 144 bytes preimage. Rank: higher score first, then the
    higher fingerprint (dna_v2_hrw_rank_cmp :888-895)."""
    return hashlib.sha3_512(TAG_STHRW + a_key + fp).digest()


def holders(a_key, members):
    """members: list of (fp bytes, fail_streak). The R smallest XOR distances,
    fail_streak >= 3 skipped (dna_v2_segment_holders)."""
    fps = [m[0] for m in members]
    if len(set(fps)) != len(fps):
        die("duplicate node fingerprints in a set")
    dist = []
    for fp, fs in members:
        if fs >= FAIL_LIMIT:
            continue
        d = bytes(a ^ b for a, b in zip(a_key, fp))
        dist.append((d, fp))
    dist.sort()
    return [fp for _, fp in dist[:HOLDERS]]


def parse(path):
    E = None
    sets, segs, mem_b1, rows = {}, [], [], []
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            t = line.split()
            if not t:
                continue
            if t[0] == "E" and len(t) == 2:
                E = int(t[1])
            elif t[0] == "S" and len(t) == 4:
                if len(t[2]) != 128:
                    die("line %d: node_fp is not 64 bytes" % ln)
                sets.setdefault(int(t[1]), []).append((bytes.fromhex(t[2]), int(t[3])))
            elif t[0] == "K" and len(t) == 4:
                if len(t[2]) != 128:
                    die("line %d: segment root is not 64 bytes" % ln)
                segs.append((int(t[1]), bytes.fromhex(t[2]), int(t[3])))
            elif t[0] == "X":
                pass
            elif t[0] == "M" and len(t) == 2:
                mem_b1.append(bytes.fromhex(t[1]))
            elif t[0] == "R" and len(t) == 3:
                rows.append((int(t[1]), bytes.fromhex(t[2])))
            else:
                die("line %d: unknown record '%s'" % (ln, line.strip()))
    if E is None or E <= 0:
        die("no epoch length")
    segs.sort()
    ks = [s[0] for s in segs]
    if ks != list(range(1, len(ks) + 1)):
        die("published segments are not exactly k = 1..n (st_segments_load, :712-760)")
    return E, sets, segs, mem_b1, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--h2", type=int, required=True)
    ap.add_argument("--b1", type=int, required=True)
    ap.add_argument("--copies", type=int, default=0,
                    help="R of the E-s2 rows (the asserted astate copies); needed with M records")
    ap.add_argument("file")
    a = ap.parse_args()
    E, sets, segs, mem_b1, rows = parse(a.file)
    out = []

    # E-s1: st_member_walk with st_rel_union (cur = set(H), prev = set(H - E))
    for H in (a.h2 - E, a.h2):
        if H < E:
            continue                              # :2473 H == 0 skipped
        cur = sets.get(H)
        if not cur:
            continue                              # :2475 no set(H): nothing
        prev = sets.get(H - E, [])                # :2479 absent -> count 0
        cur_fps = [m[0] for m in cur]
        cnt = {fp: 0 for fp in cur_fps}
        for k, root, pub in segs:
            if pub > H:
                continue                          # st_segments_load(w, H) :2483
            ak = assign_key(root)
            hc = holders(ak, cur)
            hp = holders(ak, prev) if (prev and pub <= H - E) else []
            involved = set()
            for fp in hc:
                if fp not in cnt:
                    die("a holder of set(%d) is not a member of it" % H)   # :957-967
                involved.add(fp)
            for fp in hp:
                if fp in cnt:
                    involved.add(fp)              # left the set: skipped :957-967
            for fp in involved:
                cnt[fp] += 1                      # st_rel_union
        for fp in cur_fps:
            out.append("ES1|%d|%s|%d" % (H, fp.hex(), cnt[fp]))

    # B1: prev(k) = XOR(set(H2)); new(k) = the rendezvous (HRW) holders of k over
    # eligible(set(H2)) with R copies - the E-s2 rows (nodus_witness_v2_storage.c
    # :2500-2535 with dna_v2_segment_holders_hrw, ledger_roots_v2.c:896-940), which
    # are the rows after B1 when B1 has no event (the shell asserts that). The
    # stored rows are NOT an input here: the oracle derives them and the shell
    # compares them (RWS lines), so the identity of the B1 gainer is derived too.
    if mem_b1:
        set_h2 = sets.get(a.h2)
        if not set_h2:
            die("set(H2) is absent: the XOR baseline cannot be derived")
        if a.copies < 1:
            die("--copies is required for the B1 derivation")
        set_h2 = sorted(set_h2)                   # strict ascent, node_fp ASC
        new = {}
        held = {}
        for k, root, pub in segs:
            if pub > a.h2:
                continue                          # E-s2 rows: published <= H2 :2518
            ak = assign_key(root)
            ranked = sorted(((hrw_score(ak, fp), fp) for fp, fs in set_h2
                             if fs < FAIL_LIMIT), reverse=True)
            for _, fp in ranked[:a.copies]:
                new.setdefault(k, set()).add(fp)
                held[fp] = held.get(fp, 0) + 1
                out.append("RWS|%d|%s" % (k, fp.hex()))
        ended = {fp: 0 for fp in mem_b1}
        nnew = {fp: 0 for fp in mem_b1}
        for k, root, pub in segs:
            if pub + E > a.b1:
                continue                          # not old(k): K9a cutoff :2189
            prevk = set(holders(assign_key(root), set_h2))
            newk = new.get(k, set())
            for fp in prevk:
                if fp not in newk and fp in ended:
                    ended[fp] += 1
            for fp in newk:
                if fp not in prevk:
                    if fp not in nnew:
                        die("a new holder is not a member of set(B1)")    # :2288
                    nnew[fp] += 1
        for fp in mem_b1:
            out.append("B1|%s|%d|%d" % (fp.hex(), held.get(fp, 0) + ended[fp], nnew[fp]))

    for line in sorted(out):
        print(line)


if __name__ == "__main__":
    main()
