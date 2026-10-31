// Explicit package boundaries only. Keep application and local WASM modules
// automatic; any cross-package grouping requires module-graph evidence.
export function vendorChunks(id, { getModuleInfo }) {
  // Avoid creating explicit chunks for modules eliminated by tree shaking.
  if (getModuleInfo(id)?.isIncluded !== true) return;
  const normalized = id.replaceAll('\\', '/');
  const marker = '/node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index < 0) return;
  const parts = normalized.slice(index + marker.length).split('/');
  const name = parts[0]?.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  if (!name || (name.startsWith('@') && !parts[1])) return;
  // Retain scope boundaries while producing filesystem-safe chunk names.
  return `vendor-${name.replaceAll('@', '').replaceAll('/', '__')}`;
}
