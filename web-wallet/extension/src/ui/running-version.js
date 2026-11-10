// The running version, small in the bottom corner of every extension page
// (operator 2026-11-10: "sayfanın en altına köşeye o anki çalışan versiyonu", "minnak olarak en alta sağ veya sol köşeye").
export function showRunningVersion(document, runtime) {
  const version = runtime?.getManifest?.()?.version;
  if (!version || document.querySelector('.extension-version')) return;
  const label = document.createElement('small');
  label.className = 'extension-version'; label.textContent = `v${version}`;
  document.body.append(label);
}
