/// Validator for DNA registered names.
///
/// Mirrors `dht_keyserver_is_valid_registered_name` in
/// `messenger/dht/keyserver/keyserver_lookup.c`. A legacy bug in the C
/// library's reverse_lookup caused it to return a fingerprint-format string
/// ("<16-hex>...") on lookup failure. Startup backfill in `main.dart`
/// cached that as the user's registered name, bypassing the registration
/// gate. This validator rejects that pattern so stale caches on already-
/// shipped builds can be cleaned up on the next launch.
bool isValidRegisteredName(String? name) {
  if (name == null) return false;
  final len = name.length;
  if (len == 0) return false;
  // DNA names are short; reject overlong input
  if (len >= 64) return false;
  // Reject trailing "..." (legacy fingerprint-format fallback)
  if (len >= 3 && name.endsWith('...')) return false;
  // Reject pure-hex strings of length >= 16 (looks like a fingerprint prefix)
  if (len >= 16) {
    final allHex = RegExp(r'^[0-9a-fA-F]+$').hasMatch(name);
    if (allHex) return false;
  }
  return true;
}
