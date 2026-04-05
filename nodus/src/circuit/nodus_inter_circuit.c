/**
 * Nodus — Inter-Node Circuit Table implementation
 */

#include "circuit/nodus_inter_circuit.h"
#include <string.h>

void nodus_inter_circuit_table_init(nodus_inter_circuit_table_t *t) {
    if (!t) return;
    memset(t, 0, sizeof(*t));
    t->next_our_cid_gen = 1;  /* Start at 1 — 0 reserved */
}

nodus_inter_circuit_t *nodus_inter_circuit_alloc(nodus_inter_circuit_table_t *t) {
    if (!t || t->count >= NODUS_INTER_CIRCUITS_MAX) return NULL;
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        if (!t->entries[i].in_use) {
            nodus_inter_circuit_t *c = &t->entries[i];
            memset(c, 0, sizeof(*c));
            c->in_use = true;
            c->our_cid = t->next_our_cid_gen++;
            t->count++;
            return c;
        }
    }
    return NULL;
}

nodus_inter_circuit_t *nodus_inter_circuit_lookup(nodus_inter_circuit_table_t *t,
                                                    uint64_t our_cid) {
    if (!t) return NULL;
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        if (t->entries[i].in_use && t->entries[i].our_cid == our_cid) {
            return &t->entries[i];
        }
    }
    return NULL;
}

void nodus_inter_circuit_free(nodus_inter_circuit_table_t *t, uint64_t our_cid) {
    if (!t) return;
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        if (t->entries[i].in_use && t->entries[i].our_cid == our_cid) {
            memset(&t->entries[i], 0, sizeof(nodus_inter_circuit_t));
            t->count--;
            return;
        }
    }
}

int nodus_inter_circuit_count(const nodus_inter_circuit_table_t *t) {
    return t ? t->count : 0;
}
