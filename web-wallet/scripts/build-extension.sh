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

# Python's standard library creates a sorted archive with fixed timestamps and
# validates paths, regular files and CRCs. No system zip/unzip dependency.
python3 "$wallet_root/scripts/extension-archive.py" create "$output/unpacked" "$staging/package.zip"
mv -- "$staging/package.zip" "$output/nodus-wallet-$version.zip"
printf 'Archive: %s\n' "$output/nodus-wallet-$version.zip"
python3 "$wallet_root/scripts/extension-archive.py" list "$output/nodus-wallet-$version.zip" > "$staging/files.json"
node --input-type=module - "$staging/files.json" <<'NODE'
import { readFileSync } from 'node:fs';
for (const file of JSON.parse(readFileSync(process.argv[2], 'utf8'))) {
  process.stdout.write(`${file.path}\t${file.size} bytes\n`);
}
NODE
