/**
 * Nodus — Circuit Table implementation
 */

#include "circuit/nodus_circuit.h"
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

void nodus_circuit_table_init(nodus_circuit_table_t *t) {
    if (!t) return;
    memset(t, 0, sizeof(*t));
    t->next_cid_gen = 1;  /* Start at 1 — 0 reserved */
}

nodus_circuit_t *nodus_circuit_alloc(nodus_circuit_table_t *t) {
    if (!t || t->count >= NODUS_MAX_CIRCUITS_PER_SESSION) return NULL;
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        if (!t->entries[i].in_use) {
            nodus_circuit_t *c = &t->entries[i];
            memset(c, 0, sizeof(*c));
            c->in_use = true;
            c->local_cid = t->next_cid_gen++;
            t->count++;
            return c;
        }
    }
    return NULL;
}

nodus_circuit_t *nodus_circuit_lookup(nodus_circuit_table_t *t, uint64_t local_cid) {
    if (!t) return NULL;
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        if (t->entries[i].in_use && t->entries[i].local_cid == local_cid) {
            return &t->entries[i];
        }
    }
    return NULL;
}

void nodus_circuit_free(nodus_circuit_table_t *t, uint64_t local_cid) {
    if (!t) return;
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        if (t->entries[i].in_use && t->entries[i].local_cid == local_cid) {
            memset(&t->entries[i], 0, sizeof(nodus_circuit_t));
            t->count--;
            return;
        }
    }
}

int nodus_circuit_count(const nodus_circuit_table_t *t) {
    return t ? t->count : 0;
}
