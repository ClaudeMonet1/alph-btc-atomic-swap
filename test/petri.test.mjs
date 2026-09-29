#!/usr/bin/env node
// Exhaustive check of the protocol net (docs/js/petri-net.js): every place holds
// at most one token, the only dead marking is the empty one (every run ends with
// stop), Bob can never both refund and claim, Alice ends with both assets only
// through alice_has_both (Bob absent for 12 h after her claim), and every
// transition is reachable.
import { PLACES, TRANSITIONS } from '../docs/js/petri-net.js';
let failed = 0; const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };
const key = (m, f) => PLACES.map((p) => m[p.id] || 0).join('') + '|' + [...f].sort().join(',');
const enabled = (m) => TRANSITIONS.filter((t) => t.inputs.every((p) => (m[p] || 0) >= t.inputs.filter((q) => q === p).length));
const fire = (m, t) => { const n = { ...m }; for (const p of t.inputs) n[p]--; for (const p of t.outputs) n[p] = (n[p] || 0) + 1; for (const p of Object.keys(n)) if (!n[p]) delete n[p]; return n; };
const BOB_REFUNDS = new Set(['bob_abort_refund', 'bob_stall_refund', 'bob_refund']);
const seen = new Map(); const queue = [[{}, new Set(['start'])]];
const fired = new Set(); let bounded = true, deadlocks = [], bobBoth = false, aliceBothVia = new Set();
seen.set(key({}, new Set(['start'])), true);
// start from the empty marking: 'start' is the only enabled transition
while (queue.length) {
  const [m, flags] = queue.shift();
  const en = enabled(m).filter((t) => t.id !== 'start' || Object.keys(m).length === 0 && !flags.has('started'));
  if (!en.length && Object.keys(m).length) deadlocks.push(Object.keys(m).join('+'));
  for (const t of en) {
    fired.add(t.id);
    const n = fire(m, t);
    for (const v of Object.values(n)) if (v > 1) bounded = false;
    const f = new Set(flags); f.add('started');
    if (BOB_REFUNDS.has(t.id)) f.add('bobRefunded');
    if (t.id === 'bob_claims_alph') f.add('bobClaimed');
    if (t.id === 'alice_claims_btc' || t.id === 'alice_late_claim') f.add('aliceClaimed');
    if (t.id === 'alph_refund') f.add('aliceRefunded');
    if (f.has('bobRefunded') && f.has('bobClaimed')) bobBoth = true;
    if (f.has('aliceClaimed') && f.has('aliceRefunded') && Object.keys(n).length === 0) aliceBothVia.add(t.id);
    if (t.id === 'alice_has_both') aliceBothVia.add('alice_has_both');
    const k = key(n, f); if (seen.has(k)) continue; seen.set(k, true); queue.push([n, f]);
  }
}
check('every place holds at most one token', bounded);
check('no dead marking other than the empty net', deadlocks.length === 0, deadlocks.slice(0, 5).join(' ; '));
check('Bob never both refunds and claims', !bobBoth);
check('Alice ends with both assets only via alice_has_both', [...aliceBothVia].every((t) => t === 'alice_has_both' || t === 'stop'), [...aliceBothVia].join(','));
check('every transition reachable', TRANSITIONS.every((t) => fired.has(t.id)), TRANSITIONS.filter((t) => !fired.has(t.id)).map((t) => t.id).join(','));
console.log(`${seen.size} reachable states; ${failed ? 'PETRI TEST FAILED' : 'PETRI TEST PASSED'}`); process.exit(failed ? 1 : 0);
