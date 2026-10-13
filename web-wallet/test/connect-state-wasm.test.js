// P7 — the state schema v2 codec (connect/nc_state.h; design
// docs/plans/2026-10-13-connect-core-p7-state-design.md rev 2 + 2.1) against
// the shared hand-specified vectors of test/vectors/connect-state/ — the
// same files native ctest test_nc_state runs (connect/tests/test_nc_state.c).
//
// What it proves:
//   - always: the v1 gate of the C codec is store.js checkState — for every
//     "project" vector, the REAL checkState (src/connect/store.js) throws
//     exactly when the vector expects reason "checkState" (a vector whose
//     state is not JSON, reason "json", is not run through it: JSON.parse
//     itself refuses). So every "dropped" vector (rev 2.1: migrated, never
//     refused) and every "map" / "nextSeq" refusal is of a state the page's
//     checkState accepts, and every "ok" vector is one it accepts too;
//   - with NODUS_SEND_PARITY_OUT (`scripts/build-nodus-send-wasm.sh parity`;
//     otherwise SKIP — a skip is not a pass): the release-flags node build
//     (send-node.mjs) answers every vector byte for byte through the real
//     exports nc_state_project / nc_state_load, the input crossing through
//     the state input buffer (nc_state_in_alloc) in the form
//     src/connect/core.js sends ({"state":"<text>","map":"<text>"} for a
//     projection); a "project" vector with "v1" also loads back to that v1
//     and map, and that v1 projects to the same records again with
//     "dropped": [] (the round trip).
// Tokens (#A#, #c7#, …) and fills: see the "doc" entry of project.json.
// Requires: the vector files — none is a FAILURE, not a skip.
// Leaves behind: nothing.
// How it can lie: the vectors are hand-specified from the design and the
// JS; agreement proves C == the vectors, not that the vectors are the
// design. The checkState half compares only throw / no throw, not the
// defaults it writes into the object.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkState } from '../src/connect/store.js';

const DIR = fileURLToPath(new URL('./vectors/connect-state/', import.meta.url));
const TOKENS = {
  '1': '1'.repeat(128), A: 'a'.repeat(128), B: 'b'.repeat(128), C: 'c'.repeat(128), D: 'd'.repeat(128),
  E: 'e'.repeat(128), V: '9'.repeat(128), W: '8'.repeat(128),
  SA: 'a'.repeat(64), SB: 'b'.repeat(64), SC: 'c'.repeat(64), G: 'f'.repeat(64)
};
const tokens = text => text.replace(/#([^#]{1,21})#/g, (whole, body) => {
  if (Object.hasOwn(TOKENS, body)) return TOKENS[body];
  const id = /^([cpvg])(\d{1,20})$/.exec(body);
  return id ? id[1] + id[2].padStart(20, '0') : whole;
});
// "<token>" (with its quotes) -> a JSON array of the listed fps.
function fill(text, fills) {
  if (text === undefined || !fills) return text;
  let out = text;
  for (const [token, items] of Object.entries(fills)) {
    const list = [];
    for (const [fp, count] of items) for (let i = 0; i < count; i++) list.push(fp);
    out = out.split(JSON.stringify(token)).join(JSON.stringify(list));
  }
  return out;
}

function loadVectors() {
  assert.ok(existsSync(DIR), `${DIR} is missing`);
  const files = readdirSync(DIR).filter(f => f.endsWith('.json')).sort();
  assert.ok(files.length > 0, `no vector file in ${DIR}`);
  const all = [];
  for (const f of files) {
    const list = JSON.parse(tokens(readFileSync(join(DIR, f), 'utf8')));
    assert.ok(Array.isArray(list) && list.length > 0, `${f}: not a non-empty array`);
    list.forEach((v, i) => {
      if (v.kind === 'doc') return;
      assert.ok(v.kind === 'project' || v.kind === 'load', `${f}[${i}]: unknown kind`);
      all.push({ ...v, where: `${f}[${i}] ${v.name}` });
    });
  }
  assert.ok(all.some(v => v.kind === 'project') && all.some(v => v.kind === 'load'), 'both kinds present');
  return all;
}

// The bytes the codec must answer (connect/nc_state.h), assembled from the
// vector's texts with JSON.stringify's string form — as test_nc_state.c does.
const s = JSON.stringify;
// `dropped`: the paths the vector names ([] when it names none; the round
// trip, which drops nothing, passes []).
function projectResult(v, dropped = v.expect.dropped ?? []) {
  const e = v.expect;
  if (e.status !== 'ok') return `{"status":"invalid","reason":${s(e.reason)}}`;
  const records = e.records.map(r => `{"id":${s(r.id)},"fp":${s(r.fp)},"json":${s(fill(r.json, v.fills))}}`).join(',');
  return `{"status":"ok","nextSeq":${s(e.nextSeq)},"header":${s(fill(e.header, v.fills))},"records":[${records}],"dropped":${s(dropped)}}`;
}
function loadResult(e, fills) {
  if (e.status !== 'ok') return `{"status":"damaged","reason":${s(e.reason)}}`;
  return `{"status":"ok","state":${fill(e.state, fills)},"map":${s(e.map)}}`;
}

test('connect state: the v1 gate is store.js checkState (throws exactly on reason "checkState")', () => {
  const vectors = loadVectors().filter(v => v.kind === 'project' && v.expect.reason !== 'json');
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    let threw = false;
    try { checkState(JSON.parse(fill(v.state, v.fills))); } catch { threw = true; }
    assert.equal(threw, v.expect.status === 'invalid' && v.expect.reason === 'checkState', v.where);
  }
});

const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT;
const skip = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (build-nodus-send-wasm.sh parity)' : false;

test('connect state: the wasm module (nc_state_project / nc_state_load) answers every vector byte for byte', { skip }, async () => {
  const path = join(PARITY_OUT, 'send-node.mjs');
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  const M = await create();
  // The state input buffer (nc_state_in_alloc, P7 stage 2), as
  // src/connect/core.js putState fills it.
  const putIn = text => {
    const bytes = new TextEncoder().encode(text);
    const at = M.ccall('nc_state_in_alloc', 'number', ['number'], [bytes.length]);
    if (bytes.length) { assert.ok(at, 'nc_state_in_alloc'); M.HEAPU8.set(bytes, at); }
  };
  const call = name => {
    const rc = M.ccall(name, 'number', [], []);
    assert.equal(rc, 0, `${name}: ${M.ccall('nc_error', 'string', [], [])}`);
    return M.ccall('nc_result', 'string', [], []);
  };
  // core.js stateProject's input: both texts as JSON strings in one object.
  const project = (state, map) => { putIn(JSON.stringify({ state, map })); return call('nc_state_project'); };
  const load = (header, records) => { putIn(JSON.stringify({ header, records })); return call('nc_state_load'); };

  let ran = 0;
  for (const v of loadVectors()) {
    ran++;
    if (v.kind === 'project') {
      const want = projectResult(v);
      assert.equal(project(fill(v.state, v.fills), v.map), want, v.where);
      const e = v.expect;
      if (e.status === 'ok' && e.v1 !== undefined) {
        const v1 = fill(e.v1, v.fills);
        const map = Object.fromEntries(e.records.map(r => [r.fp, r.id]));
        const records = e.records.map(r => ({ id: r.id, json: fill(r.json, v.fills) }));
        assert.equal(load(fill(e.header, v.fills), records), loadResult({ status: 'ok', state: v1, map }), `${v.where} (round trip: load)`);
        assert.equal(project(v1, s(map)), projectResult(v, []), `${v.where} (round trip: project again)`);
      }
    } else {
      const records = v.records.map(r => ({ id: r.id, json: fill(r.json, v.fills) }));
      assert.equal(load(fill(v.header, v.fills), records), loadResult(v.expect, v.fills), v.where);
    }
  }
  assert.ok(ran > 0, 'no vector ran');
});
