// Timelock policy for the swap (docs/design.md, "Timelock Ordering").
//
// Alice's BTC claim reveals the adaptor secret t; Bob then claims ALPH with it.
// So Bob's leg (BTC) must become refundable FIRST and Alice's leg (ALPH) only
// later, with a margin: if Alice could refund ALPH while Bob's BTC is still
// locked, she would refund and then claim the BTC too. Both timeouts are
// absolute Unix timestamps: the Bitcoin refund leaf uses OP_CHECKLOCKTIMEVERIFY
// (evaluated against median time past, which lags wall clock by roughly one to
// two hours), the Ralph contract uses blockTimeStamp!() in milliseconds.
//
//   T_btc  = lock time + BTC_LOCK_SECONDS          (Bob's refund opens)
//   T_alph = T_btc + ALPH_MARGIN_SECONDS           (Alice's refund opens)
//   Bob refuses a contract with T_alph < T_btc + MIN_MARGIN_SECONDS.
//   Bob must refund promptly once T_btc has passed, or keep watching for
//   Alice's claim until T_alph: Alice can claim until his refund confirms.

export const BTC_LOCK_SECONDS = 24 * 3600;
export const ALPH_MARGIN_SECONDS = 12 * 3600;
export const MIN_MARGIN_SECONDS = 6 * 3600;
export const MAX_MARGIN_SECONDS = 7 * 24 * 3600;
export const MIN_BTC_LOCK_SECONDS = 1 * 3600;      // Alice refuses a BTC lock that expires sooner than this
export const MAX_BTC_LOCK_SECONDS = 48 * 3600;     // ... or later than this
export const LOCKTIME_THRESHOLD = 500_000_000;     // below this nLockTime means a block height

// Alice locks her ALPH only once Bob's funding transaction has this many
// confirmations: an unconfirmed lock is Bob's to replace. One is the floor that
// makes the check mean anything and is what the signet demo uses; a mainnet
// deployment should raise it with the amount.
export const MIN_LOCK_CONFIRMATIONS = 1;

// Confirmation depth scales with the amount at stake (audit S4, S10): a
// reorganisation that replaces Bob's lock after Alice has locked her ALPH, or
// Alice's claim after Bob has taken the ALPH, must cost more than it wins. Both
// parties derive the same depth from the agreed amount; the 24 h lock and the
// 12 h margin leave room for the deepest rung on both sides.
//   Bitcoin (10 min blocks):   < 0.001 BTC 1, < 0.01 BTC 2, < 0.1 BTC 3, else 6
//   Alephium (16 s per chain): < 0.001 BTC 2, < 0.01 BTC 4, < 0.1 BTC 8, else 16
// Devnet mines one block per transaction, so its depth stays at 1.
export const BTC_CONFIRMATION_LADDER = [[100_000, 1], [1_000_000, 2], [10_000_000, 3], [Infinity, 6]];
export const ALPH_CONFIRMATION_LADDER = [[100_000, 2], [1_000_000, 4], [10_000_000, 8], [Infinity, 16]];
function rung(ladder, btcSat) { for (const [below, depth] of ladder) if (btcSat < below) return depth; return ladder[ladder.length - 1][1]; }
// On signet and the Alephium testnet the coins have no value and blocks can be
// 10 to 20 minutes apart, so the demo waits for one block only; the ladder
// applies on mainnet (and on regtest, where the tests mine to it).
const TEST_NETWORKS = new Set(['signet', 'testnet']);
export function btcConfirmationsFor(btcSat, network = 'mainnet') { return TEST_NETWORKS.has(network) ? MIN_LOCK_CONFIRMATIONS : Math.max(MIN_LOCK_CONFIRMATIONS, rung(BTC_CONFIRMATION_LADDER, btcSat)); }
export function alphConfirmationsFor(btcSat, network = 'mainnet') { return network === 'devnet' || TEST_NETWORKS.has(network) ? 1 : rung(ALPH_CONFIRMATION_LADDER, btcSat); }
// Bob claims ALPH only once Alice's BTC claim has btcConfirmationsFor(amount)
// confirmations: the secret is readable from the mempool, but a claim that is
// later reorganised out while Bob has already taken the ALPH would leave Alice
// with nothing (S10). Kept as the floor of that depth.
export const CLAIM_CONFIRMATIONS = 1;
export const LOCK_CONFIRMATION_POLL_MS = 15_000;
export const LOCK_CONFIRMATION_TIMEOUT_MS = 6 * 3600 * 1000;

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// Bob's refund locktime for a lock made now.
export function btcLocktimeNow(now = nowSeconds()) {
  return now + BTC_LOCK_SECONDS;
}

// Alice's contract timeout (milliseconds) for a given BTC locktime.
export function alphTimeoutFor(btcLocktime) {
  return (btcLocktime + ALPH_MARGIN_SECONDS) * 1000;
}

// Alice checks Bob's chosen BTC locktime before she locks anything.
export function checkBtcLocktime(btcLocktime, { now = nowSeconds(), minLockSeconds = MIN_BTC_LOCK_SECONDS, maxLockSeconds = MAX_BTC_LOCK_SECONDS } = {}) {
  if (!Number.isInteger(btcLocktime) || btcLocktime < LOCKTIME_THRESHOLD) throw new Error(`BTC locktime ${btcLocktime} is not a Unix timestamp`);
  if (btcLocktime < now + minLockSeconds) throw new Error(`BTC lock expires too soon: ${btcLocktime} < now + ${minLockSeconds}s`);
  if (btcLocktime > now + maxLockSeconds) throw new Error(`BTC lock expires too late: ${btcLocktime} > now + ${maxLockSeconds}s`);
}

// Bob checks Alice's contract timeout against his BTC locktime before he pre-signs.
export function checkAlphTimeout(alphTimeoutMs, btcLocktime) {
  const t = BigInt(alphTimeoutMs);
  const min = BigInt(btcLocktime + MIN_MARGIN_SECONDS) * 1000n;
  const max = BigInt(btcLocktime + MAX_MARGIN_SECONDS) * 1000n;
  if (t < min) throw new Error(`ALPH timeout ${t} opens before the BTC refund plus margin (${min}): Alice could refund and then claim`);
  if (t > max) throw new Error(`ALPH timeout ${t} is unreasonably far (${max})`);
}

// Bounds Bob passes to verifyContractState for Alice's contract.
export function alphTimeoutBounds(btcLocktime) {
  return {
    minTimeout: (btcLocktime + MIN_MARGIN_SECONDS) * 1000,
    maxTimeout: (btcLocktime + MAX_MARGIN_SECONDS) * 1000,
  };
}

// ---- Fees ----
// The claim transaction is pre-signed, so its fee cannot be changed afterwards
// except by a child transaction: Alice proposes the fee when she deploys the
// contract (current estimate times a headroom), Bob accepts it within bounds,
// and both build the identical claim transaction from it. Once broadcast, the
// claim can be bumped by spending its output (child pays for parent); the same
// holds for Bob's refund, which he builds at refund time at the current rate.
export const CLAIM_VBYTES = 111;              // one P2TR input (key path), one P2TR output
export const REFUND_VBYTES = 150;             // one P2TR script-path input with the CLTV leaf, one output
export const FEE_HEADROOM = 2;                // pre-signed fee = headroom x current estimate
export const MIN_FEE_RATE = 1;                // sat/vB
export const MAX_CLAIM_FEE_FRACTION = 0.05;   // Bob refuses a claim fee above this share of the amount
export const P2TR_DUST = 330;

export function claimFeeFor(feeRate, btcSat) {
  const rate = Math.max(MIN_FEE_RATE, Math.ceil(feeRate * FEE_HEADROOM));
  const fee = rate * CLAIM_VBYTES;
  const cap = Math.floor(btcSat * MAX_CLAIM_FEE_FRACTION);
  return Math.max(MIN_FEE_RATE * CLAIM_VBYTES, Math.min(fee, cap));
}

export function checkClaimFee(feeSat, btcSat) {
  if (!Number.isInteger(feeSat) || feeSat < MIN_FEE_RATE * CLAIM_VBYTES) throw new Error(`claim fee ${feeSat} sat is below the relay minimum`);
  if (feeSat > Math.floor(btcSat * MAX_CLAIM_FEE_FRACTION)) throw new Error(`claim fee ${feeSat} sat exceeds ${MAX_CLAIM_FEE_FRACTION * 100}% of the amount`);
  if (btcSat - feeSat < P2TR_DUST) throw new Error(`claim output would be dust`);
}

