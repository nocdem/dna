// Third-party license notices for the production bundle (0.1.22).
//
// Given the module ids Rollup rendered into the output, find the npm package
// that owns each one and collect that package's name, version, license field
// and license file text. vite.config.js calls this from a build plugin and
// writes the result to dist/THIRD-PARTY-LICENSES.txt. Pure Node (fs/path only),
// so test/licenses.test.js exercises it directly.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const { dirname, join } = posix, sep = '/';
// LICENSE, LICENCE, COPYING, LICENSE.md, LICENSE.txt, LICENSE-MIT, license, …
const LICENSE_FILE = /^(licen[cs]e|copying)([-._].*)?$/i;
const NODE_MODULES = '/node_modules/';

// A Rollup module id may be virtual (`\0` prefix) and may carry a query suffix
// (`?commonjs-exports`, `?url`, …); the file path is what is left, with `/`
// separators (Vite's ids already use them; Node's fs accepts them everywhere).
function modulePath(id) {
  const path = id.replace(/^\0+/, '').replace(/\?.*$/s, '').replaceAll('\\', '/');
  return path.includes(NODE_MODULES) ? path : undefined;
}

// The package that owns a file: the nearest package.json, walking up from the
// file but not above the innermost node_modules/<name> (or node_modules/@scope/
// <name>) directory, that has both `name` and `version`. Subdirectory
// package.json files that only set `type` (e.g. @noble/hashes/esm/) are skipped.
// Nested node_modules resolve to the innermost package, which is the copy that
// was actually bundled.
function owningPackage(path) {
  const at = path.lastIndexOf(NODE_MODULES) + NODE_MODULES.length;
  const parts = path.slice(at).split(sep);
  const rootDepth = parts[0].startsWith('@') ? 2 : 1;
  if (parts.length <= rootDepth) return undefined;
  const root = path.slice(0, at) + parts.slice(0, rootDepth).join(sep);
  for (let dir = dirname(path); dir.length >= root.length; dir = dirname(dir)) {
    const file = join(dir, 'package.json');
    if (existsSync(file)) {
      const json = JSON.parse(readFileSync(file, 'utf8'));
      if (json.name && json.version) return { dir, json };
    }
    if (dir === root) break;
  }
  return undefined;
}

// `license` as an SPDX string, a legacy `{ type }` object, or the legacy
// `licenses: [{ type }]` array.
function licenseField(json) {
  const value = json.license ?? json.licenses;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(entry => (typeof entry === 'string' ? entry : entry?.type)).filter(Boolean).join(' OR ') || undefined;
  if (value && typeof value === 'object' && typeof value.type === 'string') return value.type;
  return undefined;
}

function licenseTexts(dir) {
  return readdirSync(dir).filter(name => LICENSE_FILE.test(name) && statSync(join(dir, name)).isFile())
    .sort().map(name => ({ file: name, text: readFileSync(join(dir, name), 'utf8').replace(/\s+$/, '') }));
}

// Full license texts kept in licenses/ (byte-for-byte Debian copies; provenance
// in licenses/SOURCES.txt), appended once at the end of the notice file, in this
// order, when a bundled package's license needs them.
const APPENDIX = [['LGPL-3.0', 'LGPL-3.0.txt'], ['GPL-3.0', 'GPL-3.0.txt'], ['Apache-2.0', 'Apache-2.0.txt']];
// A package's own license file carries the Apache text only if it has the
// license's own terms heading.
const APACHE_TERMS = 'TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION';
// LGPL-3.0 incorporates GPL-3.0 by reference ("This version of the GNU Lesser
// General Public License incorporates the terms and conditions of version 3 of
// the GNU General Public License"), so both texts are appended.
function appendixFor(license, files) {
  const needed = [];
  if (/\bLGPL-3\.0/.test(license)) needed.push('LGPL-3.0', 'GPL-3.0');
  if (/\bApache-2\.0\b/.test(license) && !files.some(entry => entry.text.includes(APACHE_TERMS))) needed.push('Apache-2.0');
  return needed;
}

// The package whose LICENSE file supplies the MIT permission paragraphs, verbatim,
// for a bundled MIT package that ships no license file (Debian has no MIT text
// in /usr/share/common-licenses). @noble/hashes is a direct wallet dependency.
const MIT_PERMISSION_SOURCE = '@noble/hashes';
const MIT_PERMISSION_START = 'Permission is hereby granted';

// Every regular file under a package directory, relative, sorted; nested
// node_modules (other packages) excluded.
function packageFiles(dir) {
  return readdirSync(dir, { recursive: true }).map(String).map(file => file.replaceAll('\\', '/'))
    .filter(file => !file.split('/').includes('node_modules') && statSync(join(dir, file)).isFile()).sort();
}
// A line inside a JavaScript comment block: `//`, `/*`, ` *` or `*/`.
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*)/;
// For a package with a license field but no license file: the Copyright line(s)
// of the first comment block that contains one, searching the package's
// `module` and `main` entries first, then every other file in sorted order.
// Binary files are skipped. Returns [{ text, file, line }] (line is 1-based);
// empty when no file has one.
function copyrightLines(dir, json) {
  const files = packageFiles(dir);
  const entries = [json.module, json.main].filter(entry => typeof entry === 'string').map(entry => posix.normalize(entry).replace(/^\.\//, ''));
  for (const file of new Set([...entries.filter(entry => files.includes(entry)), ...files])) {
    const bytes = readFileSync(join(dir, file));
    if (bytes.includes(0)) continue;
    const lines = bytes.toString('utf8').split(/\r?\n/);
    let block = [];
    for (let index = 0; index <= lines.length; index++) {
      if (index < lines.length && COMMENT_LINE.test(lines[index])) { block.push(index); continue; }
      const hits = block.filter(number => /copyright/i.test(lines[number]));
      if (hits.length) return hits.map(number => ({ text: lines[number].trimEnd(), file, line: number + 1 }));
      block = [];
    }
  }
  return [];
}

// Returns the bundled packages, deduplicated by name@version and sorted by name
// (then version). Throws, naming the package, when a bundled package has
// neither a license field nor a license file. Each entry:
//   { name, version, license, files, appendix,
//     copyright?, copyrightMissing?, mitPermission? }  (the last three only for
//   a package with a license field but no license file).
// A field-only package with no copyright line found is not an error: `warn`
// (default: console.warn, printed in the build output) receives one message
// listing them.
export function collectThirdPartyLicenses(moduleIds, { warn = message => console.warn(message) } = {}) {
  const packages = new Map(), dirs = new Map();
  for (const id of moduleIds) {
    const path = modulePath(id);
    if (!path) continue;
    const owner = owningPackage(path);
    if (!owner) throw new Error(`Cannot find the package.json that owns bundled module ${path}`);
    const key = `${owner.json.name}@${owner.json.version}`;
    if (packages.has(key)) continue;
    const license = licenseField(owner.json), files = licenseTexts(owner.dir);
    if (!license && files.length === 0) throw new Error(`Bundled package ${key} (${owner.dir}) has no license field and no license file`);
    const entry = { name: owner.json.name, version: owner.json.version, license: license ?? '(no license field)', files, appendix: license ? appendixFor(license, files) : [] };
    if (files.length === 0) { entry.copyright = copyrightLines(owner.dir, owner.json); entry.copyrightMissing = entry.copyright.length === 0; }
    packages.set(key, entry); dirs.set(entry, owner.dir);
  }
  const list = [...packages.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
  const fieldOnlyMit = list.filter(pkg => pkg.files.length === 0 && /\bMIT\b/.test(pkg.license));
  if (fieldOnlyMit.length) {
    // The top-level copy (shortest path) of the source package, if bundled.
    const source = list.filter(pkg => pkg.name === MIT_PERMISSION_SOURCE && pkg.files.some(entry => entry.text.includes(MIT_PERMISSION_START)))
      .sort((a, b) => dirs.get(a).length - dirs.get(b).length)[0];
    if (!source) throw new Error(`MIT permission text source ${MIT_PERMISSION_SOURCE} is not in the bundle (needed for ${fieldOnlyMit.map(pkg => `${pkg.name}@${pkg.version}`).join(', ')})`);
    const file = source.files.find(entry => entry.text.includes(MIT_PERMISSION_START));
    const mitPermission = { source: `${source.name}@${source.version}`, file: file.file, text: file.text.slice(file.text.indexOf(MIT_PERMISSION_START)) };
    for (const pkg of fieldOnlyMit) pkg.mitPermission = mitPermission;
  }
  const missing = list.filter(pkg => pkg.copyrightMissing).map(pkg => `${pkg.name}@${pkg.version}`);
  if (missing.length) warn(`THIRD-PARTY-LICENSES: no copyright line found in package files of ${missing.join(', ')}`);
  return list;
}

// The text of THIRD-PARTY-LICENSES.txt for a list from collectThirdPartyLicenses().
// `licenseDir` holds the appendix texts (default: this project's licenses/).
export function formatThirdPartyLicenses(packages, { licenseDir = fileURLToPath(new URL('../licenses/', import.meta.url)) } = {}) {
  const rule = '='.repeat(78);
  const lines = [
    'Nodus Wallet: third-party software notices',
    '',
    'This web wallet bundles the open-source packages listed below. Each entry',
    'gives the package name and version, its declared license, and the license',
    'text shipped with the package. A package that ships no license file is',
    'listed with the copyright line found in its own files; full license texts a',
    'package only refers to are in the Appendix at the end.',
    '',
    'The Inter font files served under assets/fonts/ are licensed under the SIL',
    'Open Font License 1.1; see assets/fonts/OFL.txt.',
  ];
  for (const pkg of packages) {
    lines.push('', rule, `${pkg.name}@${pkg.version} — ${pkg.license}`, rule, '');
    if (pkg.files.length === 0) {
      lines.push('(no license file in package; license field only)', '');
      if (pkg.copyrightMissing) lines.push('(no copyright line found in package files)');
      for (const entry of pkg.copyright ?? []) lines.push(entry.text, `(copyright line from ${entry.file}:${entry.line})`);
      if (pkg.mitPermission) lines.push('', `MIT permission text, verbatim from the ${pkg.mitPermission.file} file of ${pkg.mitPermission.source} (that package's own copyright line omitted):`, '', pkg.mitPermission.text);
    }
    pkg.files.forEach((entry, index) => { if (index) lines.push(''); if (pkg.files.length > 1) lines.push(`--- ${entry.file} ---`); lines.push(entry.text); });
    if (pkg.appendix.length) lines.push('');
    for (const name of pkg.appendix) lines.push(`full text: see Appendix — ${name}`);
  }
  const needed = new Set(packages.flatMap(pkg => pkg.appendix));
  if (needed.size) {
    lines.push('', rule, 'Appendix: full license texts', rule, '',
      'Each text below is a byte-for-byte copy of the Debian original; source path,',
      'owning Debian package and SHA-256 are recorded in licenses/SOURCES.txt of',
      'the wallet source.');
    for (const [name, file] of APPENDIX) {
      if (!needed.has(name)) continue;
      lines.push('', `--- Appendix — ${name} ---`, '', readFileSync(join(licenseDir.replaceAll('\\', '/'), file), 'utf8').replace(/\n$/, ''));
    }
  }
  return lines.join('\n') + '\n';
}
