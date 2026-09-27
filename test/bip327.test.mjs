#!/usr/bin/env node
// BIP327 vectors + adaptor round trip against the Node build (src/).
import { readFile } from 'node:fs/promises';
import { runVectors, runAdaptorRoundTrip } from '../src/bip327-selftest.js';
const load = (name) => readFile(new URL(`../docs/spec/bip327/${name}`, import.meta.url), 'utf8').then(JSON.parse);
const results = [...await runVectors(load), ...runAdaptorRoundTrip()];
let failed = 0;
for (const r of results) { if (!r.ok) failed++; console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name}${r.problem ? ': ' + r.problem : ''}`); }
console.log(failed === 0 ? `BIP327 SELFTEST PASSED (${results.length} checks)` : `BIP327 SELFTEST FAILED (${failed}/${results.length})`);
process.exit(failed === 0 ? 0 : 1);
