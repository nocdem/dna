// Chain-name byte-rule vectors (HF-4) — ONE list for both sides of the rule:
// the JS mirror (src/nodus/names.js chainNameOk) and the C rule itself
// (dnac/include/dnac/dnac.h dnac_name_bytes_ok, reached through the send
// module's nsw_name_ok in the parity build). `ok` is the byte rule on the
// text EXACTLY as written (no lower-casing). Sources: design
// docs/plans/2026-10-02-onchain-names-design.md rev 4 §2 "Name bytes";
// decision 2026-10-02-onchain-names.md items 5 and 11 (3..36 of a-z0-9;
// all-hex of length >= 8 refused).
export const NAME_BYTE_VECTORS = Object.freeze([
  { text: 'abc', ok: true },                                  // shortest
  { text: 'ab', ok: false },                                  // too short
  { text: '', ok: false },
  { text: 'z'.repeat(36), ok: true },                         // longest
  { text: 'z'.repeat(37), ok: false },                        // too long
  { text: 'a'.repeat(36), ok: false },                        // all hex, >= 8 (item 11)
  { text: 'punk', ok: true },
  { text: 'nodus2026', ok: true },
  { text: '123', ok: true },                                  // digits only, short
  { text: '1234567', ok: true },                              // 7 hex-looking: allowed
  { text: '12345678', ok: false },                            // 8 hex-looking: an ID prefix
  { text: 'deadbee', ok: true },                              // 7 hex letters
  { text: 'deadbeef', ok: false },                            // 8 hex letters
  { text: 'cafe', ok: true },
  { text: 'deadbeefz', ok: true },                            // a non-hex letter
  { text: 'abcdefabcdefg', ok: true },
  { text: 'a'.repeat(8).replace(/a/g, 'f'), ok: false },      // 'ffffffff'
  { text: '0123456789abcdef', ok: false },                    // all-hex, 16
  { text: 'ABC', ok: false },                                 // uppercase refused
  { text: 'Punk', ok: false },
  { text: 'pu nk', ok: false },                               // space
  { text: 'pu-nk', ok: false },                               // dash
  { text: 'pu_nk', ok: false },                               // underscore
  { text: 'pu.nk', ok: false },                               // dot
  { text: 'punkı', ok: false },                          // dotless i (Turkish lower-casing of I)
  { text: 'аbc', ok: false }                             // Cyrillic a
]);

// What a person types -> the chain name it denotes (src/nodus/names.js
// chainName: trim, ASCII-only A-Z -> a-z, then the byte rule), or null.
export const NAME_INPUT_VECTORS = Object.freeze([
  { typed: 'punk', name: 'punk' },
  { typed: '  Punk ', name: 'punk' },
  { typed: 'NODUS', name: 'nodus' },
  { typed: 'PUNKI', name: 'punki' },                          // 'I' -> 'i', never 'ı'
  { typed: 'DEADBEEF', name: null },                          // lower-cases to an all-hex 8
  { typed: 'pünk', name: null },                         // non-ASCII letter
  { typed: 'a b c', name: null },
  { typed: 'ab', name: null },
  { typed: undefined, name: null }
]);
