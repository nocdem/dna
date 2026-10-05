/* exp_extract — DNAC Explorer: dnac_v3_block pages -> index rows. See
 * exp_extract.h. */

#include "exp_extract.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#include "dnac/dnac.h"                 /* dnac_name_bytes_ok (HF-4) */
#define LOG_TAG "EXP_EXTRACT"

/* "" or exactly 128 lowercase hex + NUL. */
static int fp_ok(const char s[129], int allow_empty) {
    if (s[0] == '\0') return allow_empty;
    for (int i = 0; i < 128; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return s[128] == '\0';
}

/* NUL-terminated within the node's op bound (the struct holds OP_MAX + 1). */
static int op_ok(const char *op) {
    return memchr(op, '\0', NODUS_DNAC_V3_OP_MAX + 1) != NULL;
}

static int header_matches(const exp_block_row_t *b, const nodus_dnac_v3_block_result_t *p) {
    return b->height == p->height &&
           memcmp(b->block_id, p->block_id, 64) == 0 &&
           memcmp(b->prev_id, p->prev_block_id, 64) == 0 &&
           b->time_ms == p->time_ms &&
           b->proposer_len == (uint32_t)p->proposer_len &&
           memcmp(b->proposer, p->proposer, p->proposer_len) == 0 &&
           memcmp(b->global_root, p->global_root, 64) == 0 &&
           b->applied_count == p->applied_count &&
           b->n_items == p->total_items;
}

/* HF-4 NAME_REGISTER ("nm"/"pr", nodus.h dnac_v3_block): "" with no price,
 * or a legal chain name (the ONE byte rule, dnac_name_bytes_ok) with a
 * price above zero on an applied item. */
static int name_ok(const nodus_dnac_v3_item_t *it) {
    const char *end = memchr(it->name, '\0', sizeof(it->name));
    if (!end) return 0;
    size_t len = (size_t)(end - it->name);
    if (len == 0) return it->name_price == 0;
    return it->has_effects && it->code == 0 && it->name_price > 0 &&
           dnac_name_bytes_ok((const uint8_t *)it->name, len);
}

_Static_assert(EXP_EVM_MAX_TICKETS == NODUS_DNAC_V3_EVM_MAX_TICKETS,
               "the index's ticket bound is the wire's");

/* Nodus EVM ("ev"/"ri"/"ro", nodus.h dnac_v3_block): applied items only; the
 * reserve move only beside "ev" (an EVMFUND leg is always paired with an
 * EVM leg, and the node sends "ev" for every applied EVM item), one
 * direction, within the index's INTEGER columns; the ticket list bounded. */
static int evm_ok(const nodus_dnac_v3_item_t *it) {
    if (!it->has_evm)
        return it->reserve_in == 0 && it->reserve_out == 0;
    if (!it->has_effects || it->code != 0) return 0;
    if (it->reserve_in != 0 && it->reserve_out != 0) return 0;
    if (it->reserve_in > (uint64_t)INT64_MAX || it->reserve_out > (uint64_t)INT64_MAX ||
        it->evm_gas_used > (uint64_t)INT64_MAX)
        return 0;
    if (it->evm_status > 1) return 0;
    if (it->evm_has_created && it->evm_status != 1) return 0;
    if (it->evm_n_tickets > NODUS_DNAC_V3_EVM_MAX_TICKETS) return 0;
    if (it->evm_tickets_more && it->evm_n_tickets != NODUS_DNAC_V3_EVM_MAX_TICKETS) return 0;
    return 1;
}

static int item_ok(const nodus_dnac_v3_item_t *it) {
    if (it->kind > NODUS_DNAC_V3_KIND_CLAIM) return 0;
    if (!op_ok(it->op)) return 0;
    if (!name_ok(it)) return 0;
    if (!evm_ok(it)) return 0;
    if (!it->has_effects) {
        return it->burned == 0 && it->rec_kind == NODUS_DNAC_V3_REC_NONE &&
               it->n_consumed == 0 && it->n_created == 0;
    }
    if (it->code != 0) return 0;
    if (it->n_consumed > NODUS_DNAC_V3_ITEM_MAX_IN) return 0;
    if (it->n_created > NODUS_DNAC_V3_ITEM_MAX_OUT) return 0;
    for (uint8_t c = 0; c < it->n_created; c++) {
        if (!fp_ok(it->created[c].owner, 0)) return 0;
    }
    if (it->rec_kind > NODUS_DNAC_V3_REC_CHAIN_CONFIG) return 0;
    if (!fp_ok(it->rec_validator_fp, 1) || !fp_ok(it->rec_delegator_fp, 1) ||
        !fp_ok(it->rec_dest_fp, 1)) {
        return 0;
    }
    return 1;
}

static int grow(void **arr, size_t *cap, size_t need, size_t elem) {
    if (need <= *cap) return 0;
    size_t nc = *cap ? *cap : 64;
    while (nc < need) nc *= 2;
    void *p = realloc(*arr, nc * elem);
    if (!p) return -1;
    *arr = p;
    *cap = nc;
    return 0;
}

int exp_extract_page(const nodus_dnac_v3_block_result_t *page, exp_block_batch_t *batch) {
    if (!page || !batch) return -1;
    if (page->count > 0 && !page->items) return -1;

    /* ── check the whole page first ── */
    if (batch->have_header) {
        if (!header_matches(&batch->block, page)) {
            QGP_LOG_ERROR(LOG_TAG, "page header of height %llu differs from the block's first page",
                          (unsigned long long)page->height);
            return -1;
        }
    } else {
        if (page->height == 0 || page->total_items > EXP_BLOCK_MAX_ITEMS ||
            page->proposer_len == 0 || page->proposer_len > 64) {
            QGP_LOG_ERROR(LOG_TAG, "height %llu: header out of bounds (n=%u, proposer %zu bytes)",
                          (unsigned long long)page->height, (unsigned)page->total_items,
                          page->proposer_len);
            return -1;
        }
    }

    size_t base = batch->n_items;
    if (base + page->count > (size_t)page->total_items) return -1;

    size_t new_ios = 0, new_evms = 0;
    for (size_t j = 0; j < page->count; j++) {
        const nodus_dnac_v3_item_t *it = &page->items[j];
        if ((size_t)it->index != base + j) {
            QGP_LOG_ERROR(LOG_TAG, "height %llu: item index %u where %zu was expected",
                          (unsigned long long)page->height, (unsigned)it->index, base + j);
            return -1;
        }
        if (!item_ok(it)) {
            QGP_LOG_ERROR(LOG_TAG, "height %llu item %u: out of bounds",
                          (unsigned long long)page->height, (unsigned)it->index);
            return -1;
        }
        new_ios += (size_t)it->n_consumed + (size_t)it->n_created;
        new_evms += it->has_evm ? 1u : 0u;
    }

    if (grow((void **)&batch->items, &batch->cap_items, base + page->count, sizeof(exp_item_row_t)) != 0 ||
        grow((void **)&batch->ios, &batch->cap_ios, batch->n_ios + new_ios, sizeof(exp_io_row_t)) != 0 ||
        (new_evms > 0 &&
         grow((void **)&batch->evms, &batch->cap_evms, batch->n_evms + new_evms,
              sizeof(exp_evm_row_t)) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "out of memory collecting height %llu", (unsigned long long)page->height);
        return -1;
    }

    /* ── append ── */
    if (!batch->have_header) {
        exp_block_row_t *b = &batch->block;
        memset(b, 0, sizeof(*b));
        b->height = page->height;
        memcpy(b->block_id, page->block_id, 64);
        memcpy(b->prev_id, page->prev_block_id, 64);
        b->time_ms = page->time_ms;
        memcpy(b->proposer, page->proposer, page->proposer_len);
        b->proposer_len = (uint32_t)page->proposer_len;
        memcpy(b->global_root, page->global_root, 64);
        b->applied_count = page->applied_count;
        b->n_items = page->total_items;
        batch->have_header = 1;
    }

    for (size_t j = 0; j < page->count; j++) {
        const nodus_dnac_v3_item_t *it = &page->items[j];
        exp_item_row_t *r = &batch->items[batch->n_items++];
        memset(r, 0, sizeof(*r));
        r->height = page->height;
        r->idx = it->index;
        r->kind = it->kind;
        r->code = it->code;
        r->has_wire_id = it->has_wire_id ? 1 : 0;
        memcpy(r->wire_id, it->wire_id, 64);
        r->has_intent_id = it->has_intent_id ? 1 : 0;
        memcpy(r->intent_id, it->intent_id, 64);
        r->has_fee = it->has_fee ? 1 : 0;
        r->fee = it->fee;
        strncpy(r->op, it->op, sizeof(r->op) - 1);
        r->op[sizeof(r->op) - 1] = '\0';
        r->has_effects = it->has_effects ? 1 : 0;
        r->burned = it->burned;
        /* HF-4: the registered name and its price (item_ok checked both) */
        memcpy(r->name, it->name, sizeof(r->name));
        r->name_price = it->name_price;
        if (it->has_effects && it->rec_kind != NODUS_DNAC_V3_REC_NONE) {
            r->rec.kind = it->rec_kind;
            memcpy(r->rec.validator, it->rec_validator_fp, 129);
            memcpy(r->rec.delegator, it->rec_delegator_fp, 129);
            memcpy(r->rec.dest, it->rec_dest_fp, 129);
            r->rec.amount = it->rec_amount;
            r->rec.commission_bps = it->rec_commission_bps;
            r->rec.param_id = it->cc_param_id;
            r->rec.new_value = it->cc_new_value;
            r->rec.effective = it->cc_effective;
        }

        if (!it->has_effects) continue;

        /* Nodus EVM: the node's EVM facts, copied as-is (evm_ok checked them) */
        if (it->has_evm) {
            static const char hexd[] = "0123456789abcdef";
            exp_evm_row_t *e = &batch->evms[batch->n_evms++];
            memset(e, 0, sizeof(*e));
            e->height = page->height;
            e->idx = it->index;
            e->status = it->evm_status;
            e->gas_used = it->evm_gas_used;
            memcpy(e->sender, it->evm_from, 32);
            e->has_target = it->evm_has_to ? 1 : 0;
            memcpy(e->target, it->evm_to, 32);
            e->has_created = it->evm_has_created ? 1 : 0;
            memcpy(e->created, it->evm_created, 32);
            e->has_value = it->evm_has_value ? 1 : 0;
            memcpy(e->value_wei, it->evm_value, 32);
            if (it->evm_has_dest) {
                for (int b = 0; b < 64; b++) {
                    e->dest[2 * b] = hexd[it->evm_dest[b] >> 4];
                    e->dest[2 * b + 1] = hexd[it->evm_dest[b] & 0x0F];
                }
                e->dest[128] = '\0';
            }
            e->n_logs = it->evm_n_logs;
            e->n_tickets = it->evm_n_tickets;
            e->tickets_more = it->evm_tickets_more ? 1 : 0;
            memcpy(e->tickets, it->evm_tickets, (size_t)it->evm_n_tickets * 64u);
            memcpy(e->wei_destroyed, it->evm_wei_destroyed, 32);
            memcpy(e->digest, it->evm_digest, 64);
            e->reserve_in = it->reserve_in;
            e->reserve_out = it->reserve_out;
        }

        for (uint8_t c = 0; c < it->n_consumed; c++) {
            exp_io_row_t *io = &batch->ios[batch->n_ios++];
            memset(io, 0, sizeof(*io));
            io->height = page->height;
            io->idx = it->index;
            io->dir = 0;
            io->pos = c;
            memcpy(io->coin_id, it->consumed[c], 64);
        }
        for (uint8_t c = 0; c < it->n_created; c++) {
            const nodus_dnac_v3_coin_t *coin = &it->created[c];
            exp_io_row_t *io = &batch->ios[batch->n_ios++];
            memset(io, 0, sizeof(*io));
            io->height = page->height;
            io->idx = it->index;
            io->dir = 1;
            io->pos = c;
            memcpy(io->coin_id, coin->id, 64);
            io->has_owner = 1;
            memcpy(io->address, coin->owner, 129);
            memcpy(io->token_id, coin->token_id, 64);
            io->amount = coin->amount;
            io->unlock_block = coin->unlock_block;
        }
    }
    return 0;
}
