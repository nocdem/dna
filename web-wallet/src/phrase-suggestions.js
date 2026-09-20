import { wordSuggestions } from './recovery.js';

// Local BIP39 dictionary only. No storage, telemetry or network calls.
export function attachPhraseSuggestions(input, panel, { position, onChoose }) {
  let choices = null, active = -1;
  function clear() {
    choices = null; active = -1; panel.replaceChildren(); panel.hidden = true;
    input.removeAttribute('aria-activedescendant'); input.setAttribute('aria-expanded', 'false');
  }
  function choose(index) {
    if (!choices || !choices.words[index] || input.readOnly || input.hidden) return;
    input.value = choices.words[index];
    input.focus(); clear(); input.dispatchEvent(new Event('input', { bubbles: true }));
    onChoose();
  }
  function highlight(index) {
    active = index;
    [...panel.querySelectorAll('[role="option"]')].forEach((button, i) => button.setAttribute('aria-selected', String(i === index)));
    input.setAttribute('aria-activedescendant', `${input.id}-option-${index}`);
  }
  function render() {
    clear();
    if (input.readOnly || document.activeElement !== input || input.selectionStart !== input.selectionEnd) return;
    choices = wordSuggestions(input.value, input.selectionStart);
    if (!choices?.words.length) return clear();
    panel.setAttribute('aria-label', `Suggestions for word ${position} of 24`);
    panel.replaceChildren(...choices.words.map((word, index) => {
      const button = document.createElement('button'); button.type = 'button'; button.textContent = word;
      button.id = `${input.id}-option-${index}`; button.className = 'secondary small'; button.tabIndex = -1;
      button.setAttribute('role', 'option'); button.setAttribute('aria-selected', 'false');
      button.addEventListener('pointerdown', event => event.preventDefault());
      button.addEventListener('click', () => choose(index));
      return button;
    }));
    panel.hidden = false; input.setAttribute('aria-expanded', 'true');
  }
  for (const event of ['input', 'click', 'keyup', 'focus']) input.addEventListener(event, event === 'keyup' ? event => { if (!['ArrowDown', 'ArrowUp', 'Enter', 'Tab', 'Escape'].includes(event.key)) render(); } : render);
  input.addEventListener('blur', clear);
  input.addEventListener('keydown', event => {
    if (event.key === 'Escape') return clear();
    if (!choices?.words.length) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const next = active < 0 ? (event.key === 'ArrowDown' ? 0 : choices.words.length - 1) : (active + (event.key === 'ArrowDown' ? 1 : choices.words.length - 1)) % choices.words.length;
      highlight(next);
    } else if (['Enter', 'Tab'].includes(event.key) && active >= 0) { event.preventDefault(); choose(active); }
  });
  return clear;
}
