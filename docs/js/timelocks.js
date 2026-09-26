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
