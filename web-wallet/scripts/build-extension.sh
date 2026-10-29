#!/usr/bin/env bash
# Approved extension plan §9: package the orchestrator-built WASM with Vite.
# Does not build WASM or run a browser/test. Run from any working directory.
set -euo pipefail

wallet_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$wallet_root"

node node_modules/vite/bin/vite.js build --config vite.extension.config.js

version="$(node --input-type=module -e 'import { readFileSync } from "node:fs";
  const { version } = JSON.parse(readFileSync("dist-extension/unpacked/manifest.json", "utf8"));
  if (!/^\d+(\.\d+){0,3}$/.test(version)) throw new Error("Invalid extension manifest version");
  process.stdout.write(version);')"
output="$wallet_root/dist-extension"
staging="$(mktemp -d "$output/.extension-zip-XXXXXX")"
trap 'rm -rf -- "$staging"' EXIT

# Sort actual payload files, excluding directories and anything outside Vite's
# dedicated output. Feed that exact list to zip, then print each file's size.
cd -- "$output/unpacked"
node --input-type=module > "$staging/files.txt" <<'NODE'
import { readdir } from 'node:fs/promises';
async function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = `${prefix}${entry.name}`;
    if (entry.isDirectory()) files.push(...await filesBelow(path, `${path}/`));
    else if (entry.isFile()) files.push(path);
    else throw new Error(`Unexpected output entry: ${path}`);
  }
  return files.sort();
}
process.stdout.write((await filesBelow('.')).join('\n') + '\n');
NODE
/usr/bin/zip -X -q "$staging/package.zip" -@ < "$staging/files.txt"
mv -- "$staging/package.zip" "$output/nodus-wallet-$version.zip"
printf 'Archive: %s\n' "$output/nodus-wallet-$version.zip"
node --input-type=module - "$staging/files.txt" <<'NODE'
import { readFile, stat } from 'node:fs/promises';
const files = (await readFile(process.argv[2], 'utf8')).trimEnd().split('\n');
for (const file of files) process.stdout.write(`${file}\t${(await stat(file)).size} bytes\n`);
NODE
