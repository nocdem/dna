/// Scrubs secrets out of debug logs before they leave the device.
///
/// Conservative: prefers false positives over false negatives.
class LogSanitizer {
  /// BIP39 detection: 12+ consecutive lowercase words (3-8 letters each).
  static final RegExp _mnemonicRe =
      RegExp(r'(?:\b[a-z]{3,8}\b[ \t]+){11,}\b[a-z]{3,8}\b');

  /// Hex strings >= 64 chars.
  static final RegExp _hexRe = RegExp(r'\b[0-9a-fA-F]{64,}\b');

  /// Base64 strings >= 88 chars with at least one '=' padding.
  /// Matches: padded base64 like "AAAA...==".
  static final RegExp _base64PaddedRe =
      RegExp(r'[A-Za-z0-9+/]{88,}={1,2}');

  /// Base64 unpadded, >= 120 chars. Catches PQ keys whose byte length is
  /// divisible by 3 (no padding char) — e.g. Dilithium5 pubkey (2592B→3456ch),
  /// Kyber1024 secret key (3168B→4224ch), Kyber1024 ciphertext (1568B→2092ch).
  /// Threshold is high enough to avoid false positives on normal log lines.
  static final RegExp _base64UnpaddedRe =
      RegExp(r'\b[A-Za-z0-9+/]{120,}\b');

  /// password/token/secret/apikey followed by : = or whitespace then a value.
  /// Value may be quoted ("..." or '...') or unquoted (non-whitespace).
  static final RegExp _credRe = RegExp(
      r'''(password|passwd|token|secret|api[_-]?key)([:\s=]+)("[^"]*"|'[^']*'|[^\s"']+)''',
      caseSensitive: false);

  static String scrub(String input) {
    var out = input;
    out = out.replaceAll(_mnemonicRe, '[MNEMONIC REDACTED]');
    // Base64 (padded) must run BEFORE hex: 100 'A's match both, but if padded
    // with '=' it's explicitly base64.
    out = out.replaceAllMapped(_base64PaddedRe,
        (m) => '[B64-${m.group(0)!.length} REDACTED]');
    out = out.replaceAllMapped(_hexRe,
        (m) => '[KEY-${m.group(0)!.length ~/ 2}B REDACTED]');
    // Unpadded base64 must run AFTER hex (so hex hits first; hex strings would
    // otherwise match base64 alphabet too) but BEFORE credentials.
    out = out.replaceAllMapped(_base64UnpaddedRe,
        (m) => '[B64-${m.group(0)!.length} REDACTED]');
    // Credential scrubbing runs LAST so hex/base64 detection can catch values
    // first. Skip if value already starts with '[' (already redacted marker).
    out = out.replaceAllMapped(_credRe, (m) {
      final value = m.group(3)!;
      if (value.startsWith('[')) return m.group(0)!;
      return '${m.group(1)}=[REDACTED]';
    });
    return out;
  }
}
