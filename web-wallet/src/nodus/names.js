// Chain names (HF-4) — the JS mirror of the ONE name-byte rule,
// dnac/include/dnac/dnac.h dnac_name_bytes_ok (design
// docs/plans/2026-10-02-onchain-names-design.md rev 4 §2 "Name bytes";
// decision 2026-10-02-onchain-names.md items 5 and 11):
//   3..36 bytes, each a-z or 0-9; uppercase is REFUSED by the chain;
//   a name made only of 0-9a-f whose length is >= 8 is refused (it would
//   read as an ID prefix).
// What a person types is lower-cased with an ASCII-only table (A-Z -> a-z):
// String.prototype.toLocaleLowerCase in a Turkish locale maps 'I' to 'ı',
// which is not a name byte (design §2). Anything else is left as typed and
// then fails the rule. test/chain-name-vectors.js is the shared vector list
// (also checked against the module's nsw_name_ok, the C rule itself).
export const NAME_MIN_LEN = 3;          // DNAC_NAME_MIN_LEN
export const NAME_MAX_LEN = 36;         // DNAC_NAME_MAX_LEN
export const NAME_HEXLIKE_MIN_LEN = 8;  // DNAC_NAME_HEXLIKE_MIN_LEN

// The byte rule on text that is already lower-case.
export function chainNameOk(name) {
  if (typeof name !== 'string' || name.length < NAME_MIN_LEN || name.length > NAME_MAX_LEN) return false;
  let allHex = true;
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    const digit = c >= 0x30 && c <= 0x39, lower = c >= 0x61 && c <= 0x7a;
    if (!digit && !lower) return false;
    if (!digit && c > 0x66) allHex = false;
  }
  return !(allHex && name.length >= NAME_HEXLIKE_MIN_LEN);
}

// A-Z -> a-z, nothing else.
export function asciiLower(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 0x20) : text[i];
  }
  return out;
}

// What the person typed -> the chain name it denotes, or null.
export function chainName(typed) {
  if (typeof typed !== 'string') return null;
  const name = asciiLower(typed.trim());
  return chainNameOk(name) ? name : null;
}

// The send module's nameOf() answer (src/nodus/send-module.js), checked:
// { found: false } or { found: true, name } — ONE node's committed state
// (decision 2026-10-02-onchain-names.md item 9). Anything malformed throws.
export function parseNameOf(result) {
  const invalid = () => new Error('The Nodus module returned an invalid name.');
  if (!result || typeof result.found !== 'boolean' || typeof result.committedHeight !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(result.committedHeight)) throw invalid();
  if (!result.found) return { found: false };
  if (!chainNameOk(result.name)) throw invalid();
  return { found: true, name: result.name };
}
