import { NODUS_WORD_COUNT, normalizePhrase } from './recovery.js';
import { attachPhraseSuggestions } from './phrase-suggestions.js';

// Phrase values exist only in these inputs until local validation/derivation.
// No hidden aggregate input, storage, background clipboard access or network requests.
export function createPhraseFields(grid, error) {
  const inputs = [], clearSuggestions = [];
  const focus = index => inputs[Math.min(index, NODUS_WORD_COUNT - 1)].focus();
  function distribute(text, index) {
    const words = normalizePhrase(text).split(' ');
    const start = words.length === NODUS_WORD_COUNT ? 0 : index;
    if (text.length > 1024 || start + words.length > NODUS_WORD_COUNT) {
      error.textContent = 'Too many words. Paste exactly 24 words, or fewer words starting at the selected box.';
      return false;
    }
    error.textContent = '';
    clearSuggestions.forEach(clear => clear());
    words.forEach((word, offset) => { inputs[start + offset].value = word; });
    focus(start + words.length);
    return true;
  }
  for (let index = 0; index < NODUS_WORD_COUNT; index++) {
    const cell = document.createElement('div'), label = document.createElement('label');
    const input = document.createElement('input'), panel = document.createElement('div');
    cell.className = 'phrase-cell';
    label.htmlFor = input.id = `phrase-${index + 1}`;
    label.textContent = `${index + 1}.`;
    input.type = 'text'; input.maxLength = 1024;
    input.autocomplete = 'off'; input.autocapitalize = 'off'; input.spellcheck = false;
    input.setAttribute('autocorrect', 'off');
    input.setAttribute('aria-label', `Recovery word ${index + 1}`);
    input.setAttribute('role', 'combobox'); input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-controls', panel.id = `phrase-suggestions-${index + 1}`);
    input.setAttribute('aria-expanded', 'false');
    panel.className = 'phrase-suggestions'; panel.setAttribute('role', 'listbox'); panel.hidden = true;
    cell.append(label, input, panel); grid.append(cell); inputs.push(input);
    input.addEventListener('paste', event => {
      event.preventDefault();
      if (!input.readOnly) {
        if (distribute(event.clipboardData.getData('text/plain'), index)) {
          // A paste is activity even when input defaults have been prevented.
          input.dispatchEvent(new Event('input', { bubbles: true }));
        }
      }
    });
    input.addEventListener('input', () => {
      if (input.readOnly) return;
      const value = input.value;
      if (normalizePhrase(value).includes(' ')) {
        // Also handle mobile keyboards that insert several words as one input.
        if (!distribute(value, index)) input.value = '';
      } else {
        input.value = normalizePhrase(value);
        if (/\s$/.test(value) && input.value) focus(index + 1);
      }
    });
    clearSuggestions.push(attachPhraseSuggestions(input, panel, {
      position: index + 1, onChoose: () => focus(index + 1),
    }));
  }
  function clear() {
    clearSuggestions.forEach(clear => clear());
    inputs.forEach(input => { input.value = ''; });
    error.textContent = '';
  }
  return {
    clear,
    set(phrase = '', readOnly = false) {
      clear();
      const words = phrase ? phrase.split(' ') : [];
      inputs.forEach((input, index) => { input.readOnly = readOnly; input.value = words[index] || ''; });
    },
    read() {
      if (inputs.some(input => !input.value.trim())) throw new Error('Enter all 24 words of your 24-word Nodus recovery phrase.');
      return inputs.map(input => input.value.trim()).join(' ');
    },
    focus: () => focus(0),
  };
}
