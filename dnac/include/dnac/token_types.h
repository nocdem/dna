/**
 * @file token_types.h
 * @brief Code-level token type constants — NOT a consensus rule
 *
 * These constants document the convention for token ID type prefixes.
 * They are NOT committed to genesis (chain consensus) — see design doc
 * section 6.5 for rationale. Future token types can be added without a
 * hard fork by adding entries here.
 *
 * Native vs user-token discrimination is done by comparing against
 * trust->chain_def.native_token_id (committed in genesis), NOT by
 * inspecting prefix bytes.
 */

#ifndef DNAC_TOKEN_TYPES_H
#define DNAC_TOKEN_TYPES_H

#define DNAC_TOKEN_TYPE_NATIVE   0x00  /* chain native token (DNAC) */
#define DNAC_TOKEN_TYPE_USER     0x01  /* user-created via TX_TOKEN_CREATE */
/* Reserved for future use:
 * 0x02 = wrapped from another chain
 * 0x03 = NFT
 * 0x04..0xff = reserved
 */

#endif /* DNAC_TOKEN_TYPES_H */
