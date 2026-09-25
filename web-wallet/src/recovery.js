import { Mnemonic, wordlists } from 'ethers';
export const NODUS_WORD_COUNT = 24;
export function normalizePhrase(value) { return value.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' '); }
export function validateNodusPhrase(value) {
  if (typeof value !== 'string' || value.length > 1024) throw new Error('Enter your 24-word Nodus recovery phrase.');
  const phrase = normalizePhrase(value);
  if (phrase.split(' ').length !== NODUS_WORD_COUNT) throw new Error('Enter your 24-word Nodus recovery phrase.');
  if (!Mnemonic.isValidMnemonic(phrase)) throw new Error('Recovery phrase is invalid. Check the words and order.');
  return phrase;
}
const words = Array.from({ length: 2048 }, (_, index) => wordlists.en.getWord(index));
export function wordSuggestions(text, cursor, limit = 8) {
  if (!Number.isInteger(cursor) || cursor < 0 || cursor > text.length) return null;
  let start = cursor, end = cursor;
  while (start > 0 && !/\s/.test(text[start - 1])) start--;
  while (end < text.length && !/\s/.test(text[end])) end++;
  const prefix = text.slice(start, cursor).toLowerCase();
  const position = (text.slice(0, start).match(/\S+/g) || []).length + 1;
  if (!/^[a-z]+$/.test(prefix) || position > NODUS_WORD_COUNT) return null;
  return { start, end, position, words: words.filter(word => word.startsWith(prefix)).slice(0, limit) };
}
