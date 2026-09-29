#!/usr/bin/env node
// Keeps the net in docs/protocol.md equal to docs/js/petri-net.js: the block
// between <!-- net:start --> and <!-- net:end --> is generated. `--check` fails
// when it differs; without it the block is rewritten.
import { readFileSync, writeFileSync } from 'node:fs';
import { toNotation, TRANSITIONS } from '../docs/js/petri-net.js';
const file = new URL('../docs/protocol.md', import.meta.url);
const doc = readFileSync(file, 'utf8');
const block = '<!-- net:start -->\n```\n' + toNotation() + '\n```\n\n' + TRANSITIONS.map((t) => `- \`${t.id}\`${t.actor ? ` (${t.actor})` : ''}: ${t.desc}`).join('\n') + '\n<!-- net:end -->';
const re = /<!-- net:start -->[\s\S]*?<!-- net:end -->/;
if (!re.test(doc)) throw new Error('docs/protocol.md has no net block markers');
const updated = doc.replace(re, block);
if (process.argv.includes('--check')) { if (updated !== doc) { console.error('docs/protocol.md net block is out of date: run node scripts/petri-doc.mjs'); process.exit(1); } console.log('protocol.md net block matches petri-net.js'); }
else { writeFileSync(file, updated); console.log('protocol.md net block written'); }
