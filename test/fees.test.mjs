#!/usr/bin/env node
// The pre-signed claim fee: what the page proposes must be what the peer accepts,
// at every amount a swap can have. A 2000 sat swap used to propose the relay
// minimum and then refuse it, which stopped a live swap after the peer had locked.
import { claimFeeFor, checkClaimFee, claimFeeCap, CLAIM_VBYTES, MIN_FEE_RATE, MIN_RELAY_CLAIM_FEE, MIN_SWAP_SAT, MAX_CLAIM_FEE_FRACTION, P2TR_DUST } from '../src/timelocks.js';
let failed = 0; const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };

check('relay minimum is the claim size at the floor rate', MIN_RELAY_CLAIM_FEE === MIN_FEE_RATE * CLAIM_VBYTES);
check('smallest swap leaves a spendable output', MIN_SWAP_SAT === MIN_RELAY_CLAIM_FEE + P2TR_DUST);

// What the proposer computes, the verifier accepts — at every amount and fee rate
const amounts = [MIN_SWAP_SAT, 500, 1000, 2000, 2219, 2220, 3000, 5000, 20_000, 100_000, 1_000_000];
const rates = [0, 1, 2, 5, 25, 300];
let worst = null;
for (const sat of amounts) for (const rate of rates) {
  const fee = claimFeeFor(rate, sat);
  try { checkClaimFee(fee, sat); } catch (e) { worst = `${sat} sat at ${rate} sat/vB -> ${fee} sat: ${e.message}`; }
}
check('every proposed fee passes the check', worst === null, worst || '');

check('a fee below the relay minimum is refused', (() => { try { checkClaimFee(MIN_RELAY_CLAIM_FEE - 1, 100000); return false; } catch { return true; } })());
check('a fee above the cap is refused', (() => { try { checkClaimFee(claimFeeCap(100000) + 1, 100000); return false; } catch { return true; } })());
check('the cap never sits below the relay minimum', amounts.every((s) => claimFeeCap(s) >= MIN_RELAY_CLAIM_FEE));
check('the share cap still bites on a large amount', claimFeeCap(1_000_000) === Math.floor(1_000_000 * MAX_CLAIM_FEE_FRACTION));
check('a dust-leaving claim is refused', (() => { try { checkClaimFee(MIN_RELAY_CLAIM_FEE, MIN_RELAY_CLAIM_FEE + P2TR_DUST - 1); return false; } catch { return true; } })());
check('a high rate is capped by the share on a large amount', claimFeeFor(300, 1_000_000) === Math.min(300 * 2 * CLAIM_VBYTES, claimFeeCap(1_000_000)));

console.log(failed ? `FEE TEST FAILED (${failed})` : 'FEE TEST PASSED'); process.exit(failed ? 1 : 0);
