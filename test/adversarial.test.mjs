#!/usr/bin/env node
// The protocol under attack. Every case below is something one party, or a
// stranger, would do to take both assets or to strand the other side; each one
// must fail. The chain-level attacks live in audit/ (they need regtest and the
// devnet); these run against the shared crypto and policy modules.
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  signerKey, xonlyKeyAgg, tapTweak, swapNonceGen, nonceAgg,
  adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract,
  adaptorSecretFromBytes, G, n, Fn, bytesToNum, numTo32b, pointToBytes, lift_x,
} from '../src/adaptor.js';
import { randomBytes } from '../src/curve.js';
import {
  checkBtcLocktime, checkAlphTimeout, alphTimeoutBounds, nowSeconds,
  claimFeeFor, checkClaimFee, claimFeeCap, P2TR_DUST, MIN_RELAY_CLAIM_FEE,
  MIN_BTC_LOCK_SECONDS, MAX_BTC_LOCK_SECONDS, MIN_MARGIN_SECONDS, MAX_MARGIN_SECONDS,
} from '../src/timelocks.js';

let failed = 0;
const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };
const refuses = (fn) => { try { fn(); return false; } catch { return true; } };
// a verifier may answer false or refuse outright; both mean the attack failed
const rejects = (fn) => { try { return fn() === false; } catch { return true; } };

// ---- one honest session, reused by the attacks below ----
function session({ msg = randomBytes(32), tSeed = randomBytes(32) } = {}) {
  const aliceSec = schnorr.utils.randomSecretKey(), bobSec = schnorr.utils.randomSecretKey();
  const alicePub = schnorr.getPublicKey(aliceSec), bobPub = schnorr.getPublicKey(bobSec);
  const { keyCtx, aggPubkey } = xonlyKeyAgg([alicePub, bobPub]);
  const { keyCtx: tweaked, Qbytes } = tapTweak(keyCtx, null);
  const { t, tBytes, T } = adaptorSecretFromBytes(tSeed);
  const aliceNonce = swapNonceGen(aliceSec, Qbytes, msg);
  const bobNonce = swapNonceGen(bobSec, Qbytes, msg);
  const aggNonce = nonceAgg([aliceNonce.pubNonce, bobNonce.pubNonce]);
  return { aliceSec, bobSec, alicePub, bobPub, keyCtx: tweaked, aggPubkey, Qbytes, t, tBytes, T, aliceNonce, bobNonce, aggNonce, msg };
}
const presign = (s, who) => adaptorSign(who === 'alice' ? s.aliceSec : s.bobSec, who === 'alice' ? s.aliceNonce.secNonce : s.bobNonce.secNonce, s.aggNonce, s.keyCtx, s.msg, s.T);

// ---- 1. The happy path, so the attacks below mean something ----
{
  const s = session();
  const pa = presign(s, 'alice'), pb = presign(s, 'bob');
  check('honest run: each pre-signature verifies', adaptorVerify(pa, s.aliceNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, s.msg, s.T)
    && adaptorVerify(pb, s.bobNonce.pubNonce, s.bobPub, s.aggNonce, s.keyCtx, s.msg, s.T));
  const agg = adaptorAggregate([pa, pb], s.aggNonce, s.keyCtx, s.msg, s.T);
  check('the pre-signature alone is not a valid signature', !schnorr.verify(new Uint8Array([...agg.R, ...agg.s]), s.msg, s.Qbytes));
  const sig = completeAdaptorSig(agg.R, agg.s, s.tBytes, agg.negR);
  check('completing it with the secret yields a valid signature', schnorr.verify(sig, s.msg, s.Qbytes));
  // This is what makes the swap atomic: the published signature hands the secret to the other side.
  const extracted = adaptorExtract(sig.slice(32), agg.s, agg.negR);
  check('the secret is recoverable from the published signature', bytesToHex(extracted) === bytesToHex(s.tBytes));
}

// ---- 2. Forging or tampering with a pre-signature ----
{
  const s = session();
  const pa = presign(s, 'alice');
  const flipped = Uint8Array.from(pa); flipped[31] ^= 1;
  check('a tampered pre-signature is refused', rejects(() => adaptorVerify(flipped, s.aliceNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, s.msg, s.T)));
  check('a pre-signature checked against the other party fails', rejects(() => adaptorVerify(pa, s.bobNonce.pubNonce, s.bobPub, s.aggNonce, s.keyCtx, s.msg, s.T)));
  check('an out-of-range scalar is refused', rejects(() => adaptorVerify(numTo32b(n - 1n), s.aliceNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, s.msg, s.T)));
  // A stranger cannot even produce a partial signature for a session they are not in
  const outsider = schnorr.utils.randomSecretKey();
  const oNonce = swapNonceGen(outsider, s.Qbytes, s.msg);
  check('a stranger cannot sign for this aggregate key at all', refuses(() => adaptorSign(outsider, oNonce.secNonce, s.aggNonce, s.keyCtx, s.msg, s.T)));
  check('a made-up scalar does not verify as a pre-signature', rejects(() => adaptorVerify(randomBytes(32), oNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, s.msg, s.T)));
}

// ---- 3. Binding: the pre-signature commits to this adaptor point, message and key ----
{
  const s = session();
  const pa = presign(s, 'alice');
  const { T: otherT } = adaptorSecretFromBytes(randomBytes(32));
  check('a different adaptor point breaks the pre-signature (W14)', rejects(() => adaptorVerify(pa, s.aliceNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, s.msg, otherT)));
  check('a different message breaks it', rejects(() => adaptorVerify(pa, s.aliceNonce.pubNonce, s.alicePub, s.aggNonce, s.keyCtx, randomBytes(32), s.T)));
  const other = session();
  check('a pre-signature from another session is worthless here (replay)', rejects(() => adaptorVerify(pa, s.aliceNonce.pubNonce, s.alicePub, other.aggNonce, other.keyCtx, other.msg, other.T)));
}

// ---- 4. Nonce reuse: the classic way to leak a secret key ----
{
  const s = session();
  presign(s, 'alice');
  check('the secret nonce is consumed: signing twice is refused', refuses(() => presign(s, 'alice')));
  const s2 = session();
  check('two sessions never draw the same nonce', bytesToHex(s.aliceNonce.pubNonce) !== bytesToHex(s2.aliceNonce.pubNonce));
}

// ---- 5. Completing with the wrong secret, or claiming to hold it ----
{
  const s = session();
  const agg = adaptorAggregate([presign(s, 'alice'), presign(s, 'bob')], s.aggNonce, s.keyCtx, s.msg, s.T);
  const wrong = adaptorSecretFromBytes(randomBytes(32)).tBytes;
  check('completing with the wrong secret gives an invalid signature', !schnorr.verify(completeAdaptorSig(agg.R, agg.s, wrong, agg.negR), s.msg, s.Qbytes));
  const negated = numTo32b(Fn.neg(bytesToNum(s.tBytes)));
  check('completing with the negated secret is also invalid', !schnorr.verify(completeAdaptorSig(agg.R, agg.s, negated, agg.negR), s.msg, s.Qbytes));
}

// ---- 6. Aggregating a foreign or tampered partial signature ----
{
  const s = session();
  const pa = presign(s, 'alice');
  const forged = randomBytes(32); // what an attacker can always produce: a scalar out of thin air
  const agg = adaptorAggregate([pa, forged], s.aggNonce, s.keyCtx, s.msg, s.T);
  check('a signature aggregated with a forged partial is invalid', !schnorr.verify(completeAdaptorSig(agg.R, agg.s, s.tBytes, agg.negR), s.msg, s.Qbytes));
  check('verification catches the forged partial before aggregation', rejects(() => adaptorVerify(forged, s.bobNonce.pubNonce, s.bobPub, s.aggNonce, s.keyCtx, s.msg, s.T)));
  // and the honest second partial still cannot be replaced by the first party's own
  check('one party cannot sign for both', rejects(() => adaptorVerify(pa, s.bobNonce.pubNonce, s.bobPub, s.aggNonce, s.keyCtx, s.msg, s.T)));
}

// ---- 7. Rogue key: can one side choose a key that lets it sign alone? ----
{
  const honest = schnorr.utils.randomSecretKey();
  const honestPub = schnorr.getPublicKey(honest);
  const target = schnorr.utils.randomSecretKey();            // the key the attacker wants to control
  const targetPub = schnorr.getPublicKey(target);
  // The textbook attack: present pk2 = target - pk1 so that a plain sum would be the target key.
  const P1 = lift_x(bytesToNum(honestPub));
  const Ptarget = lift_x(bytesToNum(targetPub));
  const rogue = pointToBytes(Ptarget.add(P1.negate()));
  const { aggPubkey } = xonlyKeyAgg([honestPub, rogue]);
  check('key aggregation defeats the rogue-key attack', bytesToHex(aggPubkey) !== bytesToHex(targetPub));
  const swapped = xonlyKeyAgg([rogue, honestPub]).aggPubkey;
  check('the aggregate depends on the order, so a party cannot silently reorder', bytesToHex(swapped) !== bytesToHex(aggPubkey));
}

// ---- 8. Timelocks: the 2026-09-27 finding, as policy ----
{
  const now = nowSeconds();
  const good = now + 24 * 3600;
  check('a sane BTC locktime is accepted', !refuses(() => checkBtcLocktime(good, { now })));
  check('a lock that expires too soon is refused', refuses(() => checkBtcLocktime(now + MIN_BTC_LOCK_SECONDS - 60, { now })));
  check('a lock far in the future is refused', refuses(() => checkBtcLocktime(now + MAX_BTC_LOCK_SECONDS + 60, { now })));
  check('a block height instead of a timestamp is refused', refuses(() => checkBtcLocktime(800000, { now })));
  const { minTimeout, maxTimeout } = alphTimeoutBounds(good);
  check('the honest ALPH timeout is accepted', !refuses(() => checkAlphTimeout(minTimeout, good)) && !refuses(() => checkAlphTimeout(maxTimeout, good)));
  // The attack: Alice's ALPH refund opens before Bob's BTC refund, so she refunds and still claims.
  check('an ALPH timeout before the BTC one is refused (S1-S3)', refuses(() => checkAlphTimeout((good - 3600) * 1000, good)));
  check('an ALPH timeout equal to the BTC one is refused', refuses(() => checkAlphTimeout(good * 1000, good)));
  check('an ALPH timeout inside the safety margin is refused', refuses(() => checkAlphTimeout((good + MIN_MARGIN_SECONDS - 60) * 1000, good)));
  check('an ALPH timeout years away is refused', refuses(() => checkAlphTimeout((good + MAX_MARGIN_SECONDS + 86400) * 1000, good)));
}

// ---- 9. Fees: a pre-signed fee the other side must live with ----
{
  const amount = 100_000;
  check('a fee that eats the amount is refused', refuses(() => checkClaimFee(amount - 100, amount)));
  check('a fee above the share cap is refused', refuses(() => checkClaimFee(claimFeeCap(amount) + 1, amount)));
  check('a fee below the relay minimum is refused', refuses(() => checkClaimFee(MIN_RELAY_CLAIM_FEE - 1, amount)));
  check('a fee leaving dust is refused', refuses(() => checkClaimFee(amount - P2TR_DUST + 1, amount)));
  check('a negative or fractional fee is refused', refuses(() => checkClaimFee(-1, amount)) && refuses(() => checkClaimFee(111.5, amount)));
  // A hostile fee estimate must not push the proposal past what the other side accepts
  check('an absurd fee estimate is capped to something acceptable', !refuses(() => checkClaimFee(claimFeeFor(1e6, amount), amount)));
}

console.log(failed ? `ADVERSARIAL TEST FAILED (${failed})` : 'ADVERSARIAL TEST PASSED'); process.exit(failed ? 1 : 0);
