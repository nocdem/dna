import { getAddress } from 'ethers';
import { nodusRecipient } from '../../../src/adapters/nodus.js';
import { isRecipientAddress as solanaAddress } from '../../../src/adapters/solana.js';
import { isRecipientAddress as tronAddress } from '../../../src/adapters/tron.js';
import { validateCellframeAddress } from '../../../src/cpunk-protocol.js';
import { addAddress, updateAddress, removeAddress, addressesFor, findAddress, checkAddress } from '../../../src/address-book.js';
import { setNetworkSelectOptions } from '../../../src/network-groups.js';

// src/app.js:675-692: format checks only; there is no client or key here.
const evmAddress = name => text => {
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) throw new Error(`Enter a ${name} address.`);
  try { return getAddress(text); } catch { throw new Error(`This ${name} address does not match its own check (capital and small letters). Copy it again from your source.`); }
};
export const ADDRESS_CHECKS = { nodus: nodusRecipient, ethereum: evmAddress('Ethereum'), bsc: evmAddress('BNB Smart Chain'),
  solana: text => { if (!solanaAddress(text)) throw new Error('Enter a Solana address.'); return text; },
  tron: text => { if (!tronAddress(text)) throw new Error('Enter a TRON address.'); return text; }, cellframe: validateCellframeAddress };

// src/app.js:700-857. Persistence crosses the trusted port; the Contacts
// group is deferred by the plan. The controls and strings are the web page's.
export function mountAddressBook({ root, document, ui, networks, selected, navigate, run }) {
  const $ = id => root.querySelector('#' + id);
  let entries = [], editing, armed, lastRecipient, choices = [], disposed = false;
  const short = text => text.length > 20 ? `${text.slice(0, 10)}…${text.slice(-6)}` : text;
  const el = (tag, text, className = '') => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const button = (text, click) => { const node = el('button', text, 'secondary small'); node.type = 'button'; node.onclick = click; return node; };
  const status = text => { $('address-book-status').textContent = text; };
  function reset() { editing = undefined; $('address-book-label').value = $('address-book-address').value = ''; $('address-book-form-title').textContent = 'Add an address'; $('address-book-save').textContent = 'Save address'; $('address-book-cancel').hidden = true; }
  function edit(entry) {
    if (!ADDRESS_CHECKS[entry.network]) { status('This address is of a network this version does not offer; it can only be deleted here.'); return; }
    editing = entry.id; $('address-book-label').value = entry.label; $('address-book-network').value = entry.network; $('address-book-address').value = entry.address;
    $('address-book-form-title').textContent = 'Change an address'; $('address-book-save').textContent = 'Save changes'; $('address-book-cancel').hidden = false;
    status(''); $('address-book-label').focus();
  }
  async function commit(next, done) {
    await ui.request('setAddressBook', [next]); if (disposed) return;
    entries = next; render(); status(done);
    if (lastRecipient && findAddress(entries, lastRecipient.chain, lastRecipient.address)) $('save-recipient-row').hidden = true;
  }
  function recipients() {
    const chain = selected();
    choices = ADDRESS_CHECKS[chain] ? addressesFor(entries, chain).filter(entry => entry.address !== ui.state.addresses?.[chain]) : [];
    $('recipient-saved').replaceChildren(...[{ label: 'Saved recipients…', address: '' }, ...choices].map((entry, index) => { const option = el('option', index ? `${entry.label} · ${short(entry.address)}` : entry.label); option.value = index ? String(index - 1) : ''; return option; }));
    const current = choices.findIndex(entry => entry.address === $('recipient').value.trim()); $('recipient-saved').value = current < 0 ? '' : String(current);
    $('recipient-book').hidden = !choices.length;
  }
  function render() {
    $('address-book-list').replaceChildren(...(entries.length ? entries.map(entry => {
      const row = el('div', undefined, 'address-book-row'), main = el('span', undefined, 'address-book-main'), actions = el('span', undefined, 'address-book-row-actions');
      main.append(el('strong', entry.label), el('small', networks[entry.network]?.name ?? entry.network), el('code', entry.address, 'address-book-address'));
      actions.append(button('Edit', () => edit(entry)), button(armed === entry.id ? 'Confirm delete' : 'Delete', () => {
        if (armed !== entry.id) { armed = entry.id; render(); return; }
        armed = undefined; if (editing === entry.id) reset(); return run(() => commit(removeAddress(entries, entry.id), 'Address deleted.'));
      }));
      if (armed === entry.id) actions.append(button('Keep', () => { armed = undefined; render(); }));
      row.append(main, actions); return row;
    }) : [el('p', 'No saved addresses yet. Add one below, or save a recipient after you send.', 'hint')]));
    recipients();
  }
  setNetworkSelectOptions($('address-book-network'), Object.keys(ADDRESS_CHECKS).map(chain => [chain, networks[chain]]));
  $('address-book-form').onsubmit = event => {
    event.preventDefault();
    return run(async () => {
      const fields = { label: $('address-book-label').value, network: $('address-book-network').value, address: $('address-book-address').value };
      const next = editing ? updateAddress(entries, editing, fields, ADDRESS_CHECKS) : addAddress(entries, fields, ADDRESS_CHECKS);
      const done = editing ? 'Address changed.' : 'Address saved.'; await commit(next, done); if (!disposed) reset();
    });
  };
  $('address-book-cancel').onclick = () => { reset(); status(''); };
  $('recipient-saved').onchange = () => { const entry = choices[Number($('recipient-saved').value)]; if ($('recipient-saved').value !== '' && entry) $('recipient').value = entry.address; };
  $('recipient').addEventListener('focus', recipients); $('recipient').addEventListener('input', recipients);
  $('save-recipient').onclick = () => {
    if (!lastRecipient) return; reset(); $('address-book-network').value = lastRecipient.chain; $('address-book-address').value = lastRecipient.address; $('address-book-label').value = lastRecipient.suggested;
    status('Give this address a name, then press Save address.'); navigate('address-book'); $('address-book-label').focus({ preventScroll: true });
  };
  void ui.request('getAddressBook').then(book => { if (!disposed) { entries = book.entries; $('address-book-storage').textContent = ['Saved encrypted with this wallet on this device.', book.note].filter(Boolean).join(' '); render(); } })
    .catch(error => { if (!disposed) status(error.message); });
  return { update: recipients, dispose() { disposed = true; entries = []; lastRecipient = undefined; },
    offer(chain, to, suggested = '') {
      $('save-recipient-row').hidden = true; lastRecipient = undefined;
      if (!ADDRESS_CHECKS[chain]) return;
      let address; try { address = checkAddress(chain, to, ADDRESS_CHECKS); } catch { return; }
      if (address === ui.state.addresses?.[chain] || findAddress(entries, chain, address)) return;
      lastRecipient = { chain, address, suggested }; $('save-recipient-text').textContent = `${short(address)} is not in your address book.`; $('save-recipient-row').hidden = false;
    } };
}
