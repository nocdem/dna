// Groups describe the wallet's supported key profile, not chain-wide security.
// Callers supply only their currently listed networks, including build flags.
const GROUPS = [
  { id: 'pq', label: 'Post-quantum (PQ)' },
  { id: 'legacy', label: 'Legacy' },
  { id: 'other', label: 'Other networks' },
];

export function groupNetworkEntries(entries) {
  const groups = GROUPS.map(group => ({ ...group, entries: [] }));
  for (const entry of entries) {
    const id = entry[1]?.networkGroup;
    groups[id === 'pq' ? 0 : id === 'legacy' ? 1 : 2].entries.push(entry);
  }
  return groups.filter(group => group.entries.length);
}

export function networkOptionGroups(document, entries) {
  return groupNetworkEntries(entries).map(group => {
    const optgroup = document.createElement('optgroup'); optgroup.label = group.label;
    optgroup.dataset.networkGroup = group.id;
    for (const [chain, network] of group.entries) {
      const option = document.createElement('option');
      option.value = chain; option.textContent = network?.name ?? chain;
      optgroup.append(option);
    }
    return optgroup;
  });
}

export function setNetworkSelectOptions(select, entries) {
  const selected = select.value;
  select.replaceChildren(...networkOptionGroups(select.ownerDocument, entries));
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
}
