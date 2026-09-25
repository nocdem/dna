import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectThirdPartyLicenses, formatThirdPartyLicenses } from '../scripts/third-party-licenses.mjs';

// Resolver behind dist/THIRD-PARTY-LICENSES.txt (0.1.22). Real node_modules for
// the packages the wallet ships, plus synthetic packages for the failure rule.
const app = fileURLToPath(new URL('..', import.meta.url));
const modules = join(app, 'node_modules');
const version = name => JSON.parse(readFileSync(join(modules, name, 'package.json'), 'utf8')).version;

test('bundled module ids resolve to their owning packages with license text', () => {
  const ids = [
    // A file below @noble/hashes/esm/, which has its own name-less package.json.
    join(modules, '@noble/hashes/esm/sha3.js'),
    join(modules, '@noble/hashes/esm/utils.js'),
    join(modules, 'ethers/lib.esm/index.js'),
    // Rollup virtual/query forms of a real file.
    `\0${join(modules, 'qrcode-generator/dist/qrcode.mjs')}?commonjs-proxy`,
    // Application and virtual helper modules are not third-party packages.
    join(app, 'src/app.js'),
    '\0vite/preload-helper.js',
  ];
  const packages = collectThirdPartyLicenses(ids);
  assert.deepEqual(packages.map(p => `${p.name}@${p.version}`), [
    `@noble/hashes@${version('@noble/hashes')}`, `ethers@${version('ethers')}`, `qrcode-generator@${version('qrcode-generator')}`,
  ]);
  const byName = Object.fromEntries(packages.map(p => [p.name, p]));
  assert.equal(byName['@noble/hashes'].license, 'MIT');
  assert.match(byName['@noble/hashes'].files.map(f => f.text).join('\n'), /Permission is hereby granted/);
  assert.equal(byName.ethers.license, 'MIT');
  assert.match(byName.ethers.files.map(f => f.text).join('\n'), /Permission is hereby granted/);
  // qrcode-generator 2.0.4 ships no license file: the field alone is reported.
  assert.equal(byName['qrcode-generator'].license, 'MIT');
  assert.deepEqual(byName['qrcode-generator'].files, []);
  // …so its copyright line is taken from its own module entry, with file:line,
  // and the MIT permission paragraphs from the bundled top-level @noble/hashes.
  assert.deepEqual(byName['qrcode-generator'].copyright, [{ text: '// Copyright (c) 2009 Kazuhiko Arase', file: 'dist/qrcode.mjs', line: 5 }]);
  assert.equal(byName['qrcode-generator'].copyrightMissing, false);
  assert.equal(byName['qrcode-generator'].mitPermission.source, `@noble/hashes@${version('@noble/hashes')}`);
  assert.match(byName['qrcode-generator'].mitPermission.text, /^Permission is hereby granted/);
  assert.deepEqual(packages.map(p => p.appendix), [[], [], []]);
  const text = formatThirdPartyLicenses(packages);
  assert.match(text, /^Nodus Wallet: third-party software notices\n/);
  assert.match(text, /assets\/fonts\/OFL\.txt/);
  assert.ok(text.indexOf('@noble/hashes@') < text.indexOf('ethers@') && text.indexOf('ethers@') < text.indexOf('qrcode-generator@'), 'sorted by name');
  assert.match(text, /qrcode-generator@2\.0\.4 — MIT\n=+\n\n\(no license file in package; license field only\)/);
  assert.match(text, /\n\/\/ Copyright \(c\) 2009 Kazuhiko Arase\n\(copyright line from dist\/qrcode\.mjs:5\)\n/);
  assert.match(text, /MIT permission text, verbatim from the LICENSE file of @noble\/hashes@/);
  assert.doesNotMatch(text, /Appendix: full license texts/, 'no appendix without an LGPL or file-less Apache package');
});

// Writes a synthetic package under root/node_modules and returns a module id in it.
function fixturePackage(root, name, json, files = {}) {
  const dir = join(root, 'node_modules', name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', ...json }));
  for (const [file, content] of Object.entries({ 'index.js': '', ...files })) { mkdirSync(join(dir, file, '..'), { recursive: true }); writeFileSync(join(dir, file), content); }
  return join(dir, 'index.js');
}
const count = (text, needle) => text.split(needle).length - 1;

test('LGPL packages add the LGPL-3.0 and GPL-3.0 texts once, in one appendix', () => {
  const root = mkdtempSync(join(tmpdir(), 'nodus-licenses-'));
  try {
    const a = fixturePackage(root, 'lgpl-a', { license: 'LGPL-3.0-only' }, { LICENSE: 'Copyright (c) A\nSee https://www.gnu.org/licenses/lgpl-3.0.html' });
    const b = fixturePackage(root, 'lgpl-b', { license: 'LGPL-3.0-or-later' }, { LICENSE: 'Copyright (c) B' });
    const text = formatThirdPartyLicenses(collectThirdPartyLicenses([a, b]));
    assert.equal(count(text, 'Appendix: full license texts'), 1);
    assert.equal(count(text, '--- Appendix — LGPL-3.0 ---'), 1);
    assert.equal(count(text, '--- Appendix — GPL-3.0 ---'), 1);
    assert.equal(count(text, '--- Appendix — Apache-2.0 ---'), 0);
    assert.equal(count(text, 'full text: see Appendix — LGPL-3.0'), 2, 'each LGPL entry points to the appendix');
    // The package's own pointer text stays, followed by the reference.
    assert.match(text, /See https:\/\/www\.gnu\.org\/licenses\/lgpl-3\.0\.html\n\nfull text: see Appendix — LGPL-3\.0\nfull text: see Appendix — GPL-3\.0\n/);
    assert.ok(text.indexOf('Appendix: full license texts') > text.lastIndexOf('full text: see Appendix'), 'appendix is at the end');
    assert.match(text, /GNU LESSER GENERAL PUBLIC LICENSE\n\s+Version 3, 29 June 2007/);
    // Without an LGPL package there is no appendix.
    const plain = formatThirdPartyLicenses(collectThirdPartyLicenses([fixturePackage(root, 'mit-only', { license: 'MIT' }, { LICENSE: 'Copyright (c) M' })]));
    assert.equal(count(plain, 'Appendix: full license texts'), 0);
    assert.equal(count(plain, 'full text: see Appendix'), 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Apache-2.0 text is appended only when the package does not ship it', () => {
  const root = mkdtempSync(join(tmpdir(), 'nodus-licenses-'));
  try {
    const withText = fixturePackage(root, 'apache-own', { license: 'Apache-2.0' }, { 'LICENSE-APACHE': 'Apache License\nTERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n' });
    assert.equal(count(formatThirdPartyLicenses(collectThirdPartyLicenses([withText])), 'Appendix: full license texts'), 0);
    const fieldOnly = fixturePackage(root, 'apache-field', { license: 'Apache-2.0', main: './lib/main.js' }, { 'lib/main.js': "'use strict';\n/*!\n * apache-field\n * Copyright 2024 Example Authors\n */\n", 'z.js': '// Copyright later file\n' });
    const [pkg] = collectThirdPartyLicenses([fieldOnly]);
    // The main entry is searched first; the comment line is kept verbatim.
    assert.deepEqual(pkg.copyright, [{ text: ' * Copyright 2024 Example Authors', file: 'lib/main.js', line: 4 }]);
    const text = formatThirdPartyLicenses([pkg]);
    assert.match(text, /\n \* Copyright 2024 Example Authors\n\(copyright line from lib\/main\.js:4\)\n/);
    assert.match(text, /full text: see Appendix — Apache-2\.0\n/);
    assert.equal(count(text, '--- Appendix — Apache-2.0 ---'), 1);
    assert.match(text, /Apache License\s+Version 2\.0, January 2004/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a field-only package with no copyright line is listed as such and warned about, not failed', () => {
  const root = mkdtempSync(join(tmpdir(), 'nodus-licenses-'));
  try {
    const id = fixturePackage(root, 'no-copyright', { license: 'ISC' }, { 'README.md': '# no-copyright\n' });
    const warnings = [];
    const packages = collectThirdPartyLicenses([id], { warn: message => warnings.push(message) });
    assert.equal(packages[0].copyrightMissing, true);
    assert.deepEqual(warnings, ['THIRD-PARTY-LICENSES: no copyright line found in package files of no-copyright@1.0.0']);
    assert.match(formatThirdPartyLicenses(packages), /\(no copyright line found in package files\)/);
    // A field-only MIT package needs the MIT permission source in the bundle.
    const mit = fixturePackage(root, 'mit-field', { license: 'MIT' });
    assert.throws(() => collectThirdPartyLicenses([mit], { warn: () => {} }), /MIT permission text source @noble\/hashes is not in the bundle.*mit-field@1\.0\.0/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('licenses/ texts are byte-for-byte copies of the Debian originals', t => {
  for (const [original, copy] of [['LGPL-3', 'LGPL-3.0.txt'], ['GPL-3', 'GPL-3.0.txt'], ['Apache-2.0', 'Apache-2.0.txt']]) {
    const source = join('/usr/share/common-licenses', original);
    if (!existsSync(source)) { t.skip(`${source} is absent (not a Debian system); equality with licenses/${copy} NOT checked`); continue; }
    assert.ok(readFileSync(source).equals(readFileSync(join(app, 'licenses', copy))), `licenses/${copy} differs from ${source}`);
  }
});

test('a nested node_modules copy resolves to the nested package, not its parent', () => {
  const root = mkdtempSync(join(tmpdir(), 'nodus-licenses-'));
  try {
    const outer = join(root, 'node_modules/outer'), inner = join(outer, 'node_modules/@scope/inner');
    mkdirSync(join(inner, 'lib'), { recursive: true });
    writeFileSync(join(outer, 'package.json'), JSON.stringify({ name: 'outer', version: '1.0.0', license: 'MIT' }));
    writeFileSync(join(outer, 'LICENSE'), 'outer license');
    writeFileSync(join(inner, 'package.json'), JSON.stringify({ name: '@scope/inner', version: '2.0.0', license: 'ISC' }));
    writeFileSync(join(inner, 'LICENCE.md'), 'inner licence\n\n');
    writeFileSync(join(inner, 'lib/index.js'), '');
    const [pkg] = collectThirdPartyLicenses([join(inner, 'lib/index.js')]);
    assert.deepEqual(pkg, { name: '@scope/inner', version: '2.0.0', license: 'ISC', files: [{ file: 'LICENCE.md', text: 'inner licence' }], appendix: [] });
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a bundled package with neither a license field nor a license file fails, naming it', () => {
  const root = mkdtempSync(join(tmpdir(), 'nodus-licenses-'));
  try {
    const dir = join(root, 'node_modules/unlicensed-fixture');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'unlicensed-fixture', version: '0.0.1' }));
    writeFileSync(join(dir, 'index.js'), '');
    assert.throws(() => collectThirdPartyLicenses([join(dir, 'index.js')]), /unlicensed-fixture@0\.0\.1.*no license field and no license file/);
    // A license file alone is enough.
    writeFileSync(join(dir, 'COPYING'), 'fixture terms');
    assert.equal(collectThirdPartyLicenses([join(dir, 'index.js')])[0].license, '(no license field)');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
