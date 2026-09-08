/* DNA — consensus engine registry (T1), design §4.1 / decision D-11.
 *
 * The chain's protocol identity selects the engine. There is exactly ONE entry
 * today (Tendermint), and the table is a static array walked linearly: at this
 * size a map would buy nothing and would introduce an iteration order that has
 * to be argued about (DG-1).
 *
 * Identity 0 is INVALID and always resolves to NULL — the tree's fail-closed
 * enum-zero rule. An unknown identity also resolves to NULL; what the node
 * DOES about that (D-11 says it halts) is the host's decision, not this
 * lookup's.
 *
 * ZERO CONSUMERS at T1: nothing in the tree calls this yet. The engine binding
 * is T4 (main plan §5, §7).
 */

#include <stdint.h>
#include <stddef.h>

#include "dna_consensus.h"
#include "tendermint/tm_core.h"

static const dna_consensus_ops_t *const table[] = { &tm_ops };

const dna_consensus_ops_t *dna_consensus_lookup(uint32_t protocol_id)
{
    size_t i;

    if (protocol_id == DNA_CONSENSUS_PROTOCOL_INVALID) return NULL;
    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i]->protocol_id == protocol_id) return table[i];
    }
    return NULL;
}
