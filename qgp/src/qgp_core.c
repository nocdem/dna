/**
 * qgp_core.c - result-code names, hex.
 */
#include "qgp_core.h"

#include <string.h>

#include "crypto/utils/qgp_safe_string.h"

static const char *const g_rc_names[QGP_E__COUNT] = {
    [QGP_OK]                         = "ok",
    [QGP_E_ARG]                      = "bad_argument",
    [QGP_E_IO]                       = "io_error",
    [QGP_E_NOMEM]                    = "out_of_memory",
    [QGP_E_TOO_LARGE]                = "file_too_large",
    [QGP_E_CRYPTO]                   = "crypto_error",
    [QGP_E_SIGNATURE]                = "signature_invalid",
    [QGP_E_KEY_FILE]                 = "bad_key_file",
    [QGP_E_KEY_MISMATCH]             = "secret_key_does_not_match_public_key",
    [QGP_E_BAD_AR_MAGIC]             = "bad_ar_magic",
    [QGP_E_MEMBER_AFTER_QGP_SIG]     = "member_after_qgp_sig",
    [QGP_E_TRUNCATED_HEADER]         = "truncated_header",
    [QGP_E_BAD_FMAG]                 = "bad_fmag",
    [QGP_E_BAD_SIZE_FIELD]           = "bad_size_field",
    [QGP_E_UNEXPECTED_MEMBER_NAME]   = "unexpected_member_name",
    [QGP_E_QGP_SIG_HEADER_NOT_EXACT] = "qgp_sig_header_not_exact",
    [QGP_E_TRUNCATED_MEMBER]         = "truncated_member",
    [QGP_E_BAD_OR_MISSING_PADDING]   = "bad_or_missing_padding",
    [QGP_E_MISSING_MEMBER]           = "missing_member",
    [QGP_E_MEMBER_VERSION]           = "member_version",
    [QGP_E_SIG_LEN]                  = "sig_len",
    [QGP_E_PREFIX_LEN_MISMATCH]      = "prefix_len_mismatch",
    [QGP_E_REVOKED_KEY]              = "revoked_key",
    [QGP_E_UNKNOWN_KEY]              = "unknown_key",
    [QGP_E_EXTRA_MEMBER]             = "extra_member_already_signed",
    [QGP_E_BODY_TOO_LARGE]           = "body_too_large",
    [QGP_E_NON_PRINTABLE_ASCII_BYTE] = "non_printable_ascii_byte",
    [QGP_E_MISSING_FINAL_LF]         = "missing_final_lf",
    [QGP_E_BLANK_LINE]               = "blank_line",
    [QGP_E_TRAILING_SPACE]           = "trailing_space",
    [QGP_E_BAD_FIELD_SEPARATOR]      = "bad_field_separator",
    [QGP_E_BAD_FIELD_COUNT]          = "bad_field_count",
    [QGP_E_BAD_FINGERPRINT_HEX]      = "bad_fingerprint_hex",
    [QGP_E_BAD_PK_HEX_OR_LENGTH]     = "bad_pk_hex_or_length",
    [QGP_E_KEY_FP_MISMATCH]          = "key_fp_mismatch",
    [QGP_E_UNKNOWN_RECORD_TYPE]      = "unknown_record_type",
    [QGP_E_BAD_FLOOR_PACKAGE]        = "bad_floor_package",
    [QGP_E_BAD_FLOOR_VERSION]        = "bad_floor_version",
    [QGP_E_DUPLICATE_LINE]           = "duplicate_line",
    [QGP_E_UNSORTED]                 = "unsorted",
    [QGP_E_DUPLICATE_KEY_FP]         = "duplicate_key_fp",
    [QGP_E_DUPLICATE_FLOOR]          = "duplicate_floor",
    [QGP_E_KEY_AND_REVOKED]          = "key_and_revoked",
    [QGP_E_NO_KEY]                   = "no_key",
    [QGP_E_FILE_LENGTH]              = "file_length",
    [QGP_E_FILE_VERSION]             = "file_version",
    [QGP_E_SERIAL_NOT_INCREASING]    = "serial_not_increasing",
    [QGP_E_SIGNER_REVOKED]           = "signer_revoked",
    [QGP_E_SIGNER_NOT_TRUSTED]       = "signer_not_trusted",
    [QGP_E_REVOCATION_DROPPED]       = "revocation_dropped",
    [QGP_E_FLOOR_DROPPED]            = "floor_dropped",
    [QGP_E_FLOOR_LOWERED]            = "floor_lowered",
    [QGP_E_NO_TRUST_STATE]           = "no_trust_state",
    [QGP_E_STATE_EXISTS]             = "trust_state_already_exists",
    [QGP_E_STATE_CORRUPT]            = "trust_state_corrupt",
    [QGP_E_DPKG_DEB]                 = "dpkg_deb_failed",
    [QGP_E_BAD_CONTROL_FIELDS]       = "bad_control_fields",
    [QGP_E_BAD_PACKAGE_NAME]         = "bad_package_name",
    [QGP_E_BAD_VERSION]              = "bad_version",
    [QGP_E_BAD_ARCHITECTURE]         = "bad_architecture",
    [QGP_E_BELOW_FLOOR]              = "below_trust_floor",
    [QGP_E_DOWNGRADE]                = "below_highest_accepted_version",
    [QGP_E_BOOTSTRAP_SERIAL]         = "bootstrap_must_start_at_serial_1",
};

const char *qgp_rc_str(qgp_rc_t rc)
{
    if ((int)rc < 0 || rc >= QGP_E__COUNT || !g_rc_names[rc])
        return "unknown_error";
    return g_rc_names[rc];
}

void qgp_hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static int hex_nibble_lower(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int qgp_hex_decode_lower(const char *in, size_t in_len, uint8_t *out, size_t n)
{
    if (!in || !out || in_len != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble_lower(in[2 * i]);
        int lo = hex_nibble_lower(in[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
