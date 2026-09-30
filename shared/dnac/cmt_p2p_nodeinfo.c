/**
 * @file shared/dnac/cmt_p2p_nodeinfo.c
 * @brief cometbft @v0.38.26 `p2p/node_info.go` + the DefaultNodeInfo codec
 *        of proto/tendermint/p2p/types.pb.go, in C.
 *
 * Contract: cmt_p2p_nodeinfo.h. Functions in the reference's order; each
 * names its Go lines.
 *
 * NOTE cmt_pb_wire.h: included for the generated-code rules (backward
 * writer, r_tag, pb_skip, r_ld) exactly as cmt_p2p_mconn.c does for the
 * Packet codec; its scope comment names this file.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_wire.h"

#include <stdlib.h>
#include <string.h>

/* ══ storage ══════════════════════════════════════════════════════════ */

void cmt_p2p_node_info_init(cmt_p2p_node_info_t *ni)
{
    if (ni == NULL) {
        return;
    }
    memset(&ni->protocol_version, 0, sizeof(ni->protocol_version));
    memset(ni->f, 0, sizeof(ni->f));
    ni->used = 0;
}

int cmt_p2p_node_info_set(cmt_p2p_node_info_t *ni, cmt_p2p_ni_field_t f,
                          const void *bytes, size_t len)
{
    if (ni == NULL || (unsigned)f >= CMT_P2P_NI_NUM_FIELDS ||
        (bytes == NULL && len != 0)) {
        return CMT_FAULT;
    }
    if (len > sizeof(ni->arena) - ni->used) {
        return CMT_REJECT;
    }
    if (len != 0) {
        memcpy(ni->arena + ni->used, bytes, len);
    }
    ni->f[f].off = (uint32_t)ni->used;
    ni->f[f].len = (uint32_t)len;
    ni->used += len;
    return CMT_OK;
}

int cmt_p2p_node_info_set_str(cmt_p2p_node_info_t *ni, cmt_p2p_ni_field_t f,
                              const char *s)
{
    return cmt_p2p_node_info_set(ni, f, s != NULL ? s : "",
                                 s != NULL ? strlen(s) : 0);
}

const uint8_t *cmt_p2p_node_info_get(const cmt_p2p_node_info_t *ni,
                                     cmt_p2p_ni_field_t f, size_t *len)
{
    static const uint8_t empty[1] = { 0 };

    if (ni == NULL || (unsigned)f >= CMT_P2P_NI_NUM_FIELDS) {
        if (len != NULL) {
            *len = 0;
        }
        return empty;
    }
    if (len != NULL) {
        *len = ni->f[f].len;
    }
    return ni->arena + ni->f[f].off;
}

bool cmt_p2p_node_info_field_eq(const cmt_p2p_node_info_t *ni,
                                cmt_p2p_ni_field_t f,
                                const void *s, size_t len)
{
    size_t n;
    const uint8_t *p = cmt_p2p_node_info_get(ni, f, &n);

    if (n != len) {
        return false;
    }
    return len == 0 || (s != NULL && memcmp(p, s, len) == 0);
}

void cmt_p2p_network_from_chain_id(const uint8_t chain_id[32],
                                   char out[CMT_P2P_NETWORK_CAP])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    if (out == NULL) {
        return;
    }
    if (chain_id == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < 32; i++) {
        out[2 * i]     = hexd[chain_id[i] >> 4];
        out[2 * i + 1] = hexd[chain_id[i] & 0x0Fu];
    }
    out[64] = '\0';
}

/* ══ node.go:927-974 makeNodeInfo ═════════════════════════════════════ */

int cmt_p2p_node_info_make(cmt_p2p_node_info_t *ni,
                           const cmt_p2p_node_info_params_t *p)
{
    char network[CMT_P2P_NETWORK_CAP];
    int rc = CMT_OK;

    if (ni == NULL || p == NULL || p->node_id == NULL || p->chain_id == NULL ||
        (p->channels == NULL && p->n_channels != 0)) {
        return CMT_FAULT;
    }
    cmt_p2p_node_info_init(ni);
    ni->protocol_version.p2p = CMT_P2P_PROTOCOL_VERSION;   /* :939 */
    ni->protocol_version.block = p->block_version;         /* :940 */
    ni->protocol_version.app = p->app_version;             /* :941 */
    cmt_p2p_network_from_chain_id(p->chain_id, network);
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_ID, p->node_id);          /* :943 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_NETWORK, network);        /* :944 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_VERSION, p->version);     /* :945 */
    rc |= cmt_p2p_node_info_set(ni, CMT_P2P_NI_CHANNELS, p->channels,
                                p->n_channels);                             /* :946-951 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_MONIKER, p->moniker);     /* :952 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_TX_INDEX, p->tx_index);   /* :954 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_RPC_ADDRESS,
                                    p->rpc_address);                        /* :955 */
    rc |= cmt_p2p_node_info_set_str(ni, CMT_P2P_NI_LISTEN_ADDR,
                                    p->listen_addr);                        /* :963-970 */
    if (rc != CMT_OK) {
        return CMT_REJECT;
    }
    return cmt_p2p_node_info_validate(ni);                 /* :972 */
}

/* ══ node_info.go ═════════════════════════════════════════════════════ */

/* libs/strings/string.go:57-67 `IsASCIIText`. */
static bool is_ascii_text(const uint8_t *s, size_t len)
{
    size_t i;

    if (len == 0) {
        return false;
    }
    for (i = 0; i < len; i++) {
        if (s[i] < 32 || s[i] > 126) {
            return false;
        }
    }
    return true;
}

/* libs/strings/string.go:70-83 `ASCIITrim(s) == ""` — every byte is a
 * space. Only reached after is_ascii_text, so the panic branch (:78-79)
 * cannot occur. */
static bool ascii_trim_empty(const uint8_t *s, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (s[i] != 32) {
            return false;
        }
    }
    return true;
}

/* netaddress.go:399-405 — the text after the first "://" and before a
 * second one, as strings.Split(addr, "://")[1]. */
static void strip_protocol(const uint8_t *s, size_t len, const uint8_t **o,
                           size_t *olen)
{
    size_t i;

    for (i = 0; i + 3 <= len; i++) {
        if (s[i] == ':' && s[i + 1] == '/' && s[i + 2] == '/') {
            size_t start = i + 3, e;

            for (e = start; e + 3 <= len; e++) {
                if (s[e] == ':' && s[e + 1] == '/' && s[e + 2] == '/') {
                    break;
                }
            }
            if (e + 3 > len) {
                e = len;
            }
            *o = s + start;
            *olen = e - start;
            return;
        }
    }
    *o = s;
    *olen = len;
}

/* node_info.go:221-224 `NetAddress` → NewNetAddressString(
 * IDAddressString(ID, ListenAddr)). The concatenation is built over the
 * raw bytes, so an ID or address with any byte behaves as the Go string
 * does. */
int cmt_p2p_node_info_net_address(const cmt_p2p_node_info_t *ni,
                                  cmt_p2p_netaddr_t *out)
{
    const uint8_t *id, *la, *hp;
    size_t id_len, la_len, hp_len;
    char *buf;
    int rc;

    if (ni == NULL || out == NULL) {
        return CMT_FAULT;
    }
    id = cmt_p2p_node_info_get(ni, CMT_P2P_NI_ID, &id_len);
    la = cmt_p2p_node_info_get(ni, CMT_P2P_NI_LISTEN_ADDR, &la_len);
    strip_protocol(la, la_len, &hp, &hp_len);
    buf = (char *)malloc(id_len + 1 + hp_len + 1);
    if (buf == NULL) {
        return CMT_FAULT;
    }
    if (id_len != 0) {
        memcpy(buf, id, id_len);
    }
    buf[id_len] = '@';
    if (hp_len != 0) {
        memcpy(buf + id_len + 1, hp, hp_len);
    }
    buf[id_len + 1 + hp_len] = '\0';
    rc = cmt_p2p_netaddr_new_string(buf, id_len + 1 + hp_len, out);
    free(buf);
    return rc;
}

/* node_info.go:122-174 `Validate`. */
int cmt_p2p_node_info_validate(const cmt_p2p_node_info_t *ni)
{
    const uint8_t *v, *ch, *mo, *tx, *rpc;
    size_t v_len, ch_len, mo_len, tx_len, rpc_len, i, j;
    cmt_p2p_netaddr_t na;
    int rc;

    if (ni == NULL) {
        return CMT_FAULT;
    }
    /* :126-130 ListenAddr (and, through it, the ID) */
    rc = cmt_p2p_node_info_net_address(ni, &na);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_P2P_ERR_NONE) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    /* :134-139 Version */
    v = cmt_p2p_node_info_get(ni, CMT_P2P_NI_VERSION, &v_len);
    if (v_len > 0 && (!is_ascii_text(v, v_len) || ascii_trim_empty(v, v_len))) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    /* :141-152 Channels — at most 16, no duplicate */
    ch = cmt_p2p_node_info_get(ni, CMT_P2P_NI_CHANNELS, &ch_len);
    if (ch_len > CMT_P2P_MAX_NUM_CHANNELS) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    for (i = 0; i < ch_len; i++) {
        for (j = 0; j < i; j++) {
            if (ch[i] == ch[j]) {
                return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
            }
        }
    }
    /* :154-157 Moniker */
    mo = cmt_p2p_node_info_get(ni, CMT_P2P_NI_MONIKER, &mo_len);
    if (!is_ascii_text(mo, mo_len) || ascii_trim_empty(mo, mo_len)) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    /* :160-166 Other.TxIndex ∈ {"", "on", "off"} */
    tx = cmt_p2p_node_info_get(ni, CMT_P2P_NI_TX_INDEX, &tx_len);
    if (!(tx_len == 0 || (tx_len == 2 && memcmp(tx, "on", 2) == 0) ||
          (tx_len == 3 && memcmp(tx, "off", 3) == 0))) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    /* :168-171 Other.RPCAddress */
    rpc = cmt_p2p_node_info_get(ni, CMT_P2P_NI_RPC_ADDRESS, &rpc_len);
    if (rpc_len > 0 &&
        (!is_ascii_text(rpc, rpc_len) || ascii_trim_empty(rpc, rpc_len))) {
        return CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
    }
    return CMT_P2P_ERR_NONE;
}

/* node_info.go:179-215 `CompatibleWith`. */
int cmt_p2p_node_info_compatible_with(const cmt_p2p_node_info_t *ours,
                                      const cmt_p2p_node_info_t *other)
{
    const uint8_t *on, *nn, *oc, *pc;
    size_t on_len, nn_len, oc_len, pc_len, i, j;

    if (ours == NULL || other == NULL) {
        return CMT_FAULT;
    }
    if (ours->protocol_version.block != other->protocol_version.block) {
        return CMT_P2P_ERR_REJECTED_INCOMPATIBLE;          /* :185-188 */
    }
    on = cmt_p2p_node_info_get(ours, CMT_P2P_NI_NETWORK, &on_len);
    nn = cmt_p2p_node_info_get(other, CMT_P2P_NI_NETWORK, &nn_len);
    if (on_len != nn_len || (on_len != 0 && memcmp(on, nn, on_len) != 0)) {
        return CMT_P2P_ERR_REJECTED_INCOMPATIBLE;          /* :191-193 */
    }
    oc = cmt_p2p_node_info_get(ours, CMT_P2P_NI_CHANNELS, &oc_len);
    if (oc_len == 0) {
        return CMT_P2P_ERR_NONE;                           /* :196-198 */
    }
    pc = cmt_p2p_node_info_get(other, CMT_P2P_NI_CHANNELS, &pc_len);
    for (i = 0; i < oc_len; i++) {                         /* :201-210 */
        for (j = 0; j < pc_len; j++) {
            if (oc[i] == pc[j]) {
                return CMT_P2P_ERR_NONE;
            }
        }
    }
    return CMT_P2P_ERR_REJECTED_INCOMPATIBLE;              /* :211-213 */
}

/* node_info.go:226-228 `HasChannel`. */
bool cmt_p2p_node_info_has_channel(const cmt_p2p_node_info_t *ni,
                                   uint8_t ch_id)
{
    size_t n, i;
    const uint8_t *ch = cmt_p2p_node_info_get(ni, CMT_P2P_NI_CHANNELS, &n);

    for (i = 0; i < n; i++) {
        if (ch[i] == ch_id) {
            return true;
        }
    }
    return false;
}

/* ══ types.pb.go — the codec ══════════════════════════════════════════ */

static void wf_field(pb_w_t *w, uint32_t field, const cmt_p2p_node_info_t *ni,
                     cmt_p2p_ni_field_t f)
{
    size_t n;
    const uint8_t *p = cmt_p2p_node_info_get(ni, f, &n);

    wf_bytes(w, field, p, n);              /* omit-empty (`len(m.X) > 0`) */
}

/* types.pb.go:437-500 (DefaultNodeInfo), :399-420 (ProtocolVersion),
 * :522-546 (DefaultNodeInfoOther), written backward. */
int cmt_p2p_node_info_marshal(const cmt_p2p_node_info_t *ni, uint8_t *out,
                              size_t cap, size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (ni == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    /* :442-450 Other (field 8, always) */
    before = w.i;
    wf_field(&w, 2, ni, CMT_P2P_NI_RPC_ADDRESS);           /* :526-532 */
    wf_field(&w, 1, ni, CMT_P2P_NI_TX_INDEX);              /* :533-539 */
    wf_close_msg(&w, 8, before);
    wf_field(&w, 7, ni, CMT_P2P_NI_MONIKER);               /* :451-457 */
    wf_field(&w, 6, ni, CMT_P2P_NI_CHANNELS);              /* :458-464 */
    wf_field(&w, 5, ni, CMT_P2P_NI_VERSION);               /* :465-471 */
    wf_field(&w, 4, ni, CMT_P2P_NI_NETWORK);               /* :472-478 */
    wf_field(&w, 3, ni, CMT_P2P_NI_LISTEN_ADDR);           /* :479-485 */
    wf_field(&w, 2, ni, CMT_P2P_NI_ID);                    /* :486-492 */
    /* :493-500 ProtocolVersion (field 1, always) */
    before = w.i;
    wf_varint(&w, 3, ni->protocol_version.app);            /* :404-408 */
    wf_varint(&w, 2, ni->protocol_version.block);          /* :409-413 */
    wf_varint(&w, 1, ni->protocol_version.p2p);            /* :414-418 */
    wf_close_msg(&w, 1, before);
    return w_finish(&w, out_len);
}

/* types.pb.go:786-892 `ProtocolVersion.Unmarshal` — INTO the existing
 * value (a repeated field 1 merges). */
static int pv_unmarshal(const uint8_t *in, size_t len,
                        cmt_p2p_protocol_version_t *pv)
{
    size_t off = 0;

    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn >= 1 && fn <= 3) {
            uint64_t v;

            if (wt != 0) {
                return CMT_REJECT;                         /* wrong wireType */
            }
            if (cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fn == 1) {
                pv->p2p = v;
            } else if (fn == 2) {
                pv->block = v;
            } else {
                pv->app = v;
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* One string / bytes field: last one wins (:985 … :1147 assign). */
static int take_bytes(cmt_p2p_node_info_t *ni, cmt_p2p_ni_field_t f,
                      const uint8_t *p, size_t n)
{
    int rc = cmt_p2p_node_info_set(ni, f, p, n);

    return rc == CMT_OK ? CMT_OK : CMT_REJECT;
}

/* types.pb.go:1203-1316 `DefaultNodeInfoOther.Unmarshal` — into the
 * existing value. */
static int other_unmarshal(const uint8_t *in, size_t len,
                           cmt_p2p_node_info_t *ni)
{
    size_t off = 0;

    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 1 || fn == 2) {
            const uint8_t *p;
            size_t n;

            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (take_bytes(ni, fn == 1 ? CMT_P2P_NI_TX_INDEX
                                       : CMT_P2P_NI_RPC_ADDRESS, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* types.pb.go:893-1202 `DefaultNodeInfo.Unmarshal`. */
int cmt_p2p_node_info_unmarshal(const uint8_t *in, size_t len,
                                cmt_p2p_node_info_t *ni)
{
    static const cmt_p2p_ni_field_t by_num[8] = {
        CMT_P2P_NI_NUM_FIELDS,          /* 0 unused */
        CMT_P2P_NI_NUM_FIELDS,          /* 1 ProtocolVersion (message) */
        CMT_P2P_NI_ID,                  /* 2 */
        CMT_P2P_NI_LISTEN_ADDR,         /* 3 */
        CMT_P2P_NI_NETWORK,             /* 4 */
        CMT_P2P_NI_VERSION,             /* 5 */
        CMT_P2P_NI_CHANNELS,            /* 6 */
        CMT_P2P_NI_MONIKER              /* 7 */
    };
    size_t off = 0;

    if ((in == NULL && len != 0) || ni == NULL) {
        return CMT_FAULT;
    }
    cmt_p2p_node_info_init(ni);
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn >= 1 && fn <= 8) {
            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                         /* wrong wireType / EOF */
            }
            if (fn == 1) {
                if (pv_unmarshal(p, n, &ni->protocol_version) != CMT_OK) {
                    return CMT_REJECT;                     /* :951 */
                }
            } else if (fn == 8) {
                if (other_unmarshal(p, n, ni) != CMT_OK) {
                    return CMT_REJECT;                     /* :1178 */
                }
            } else if (take_bytes(ni, by_num[fn], p, n) != CMT_OK) {
                return CMT_REJECT;
            }
        } else {
            off = pre;                                     /* :1182-1195 */
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}
