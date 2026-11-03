// Format-only saved-recipient checks. No provider, signing or send capability.
// CKB/QTC checks cover mainnet recipient formats; send preflight checks
// the selected network again. Existing address-book storage bounds are intact.
import { bech32 } from '@scure/base';
import { parseCkbFullRecipient } from './ckb-full-recipient.js';
import { qtcScript } from './qtc-transaction.js';
function cosmosStyle(text, prefix, name) {
  try {
    if (typeof text !== 'string' || text !== text.toLowerCase()) throw new Error();
    const value=bech32.decode(text), bytes=bech32.fromWords(value.words);
    if (value.prefix!==prefix || bytes.length!==20 || bech32.encode(prefix,bech32.toWords(bytes))!==text) throw new Error();
    return text;
  } catch { throw new Error(`Invalid ${name} address.`); }
}
export const pqAddressBookChecks = Object.freeze({
  xion(text) { return cosmosStyle(text, 'xion', 'XION'); },
  ckb(text) { parseCkbFullRecipient(text, 'mainnet'); return text; },
  qtc(text) { qtcScript(text, 'mainnet'); return text; },
  splendor(text) {
    if (typeof text !== 'string' || !/^SQ:[0-9a-f]{64}$/.test(text) || /^SQ:0{64}$/.test(text)) throw new Error('Invalid Splendor address.');
    return text;
  },
  asentum(text) { return cosmosStyle(text, 'ase', 'Asentum'); },
});
