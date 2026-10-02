// Swap layer over BIP327 MuSig2 (musig2.js): x-only party keys, the taproot
// tweak as a key-context tweak, and adaptor signatures.
//
// Adaptor signatures: with T = t*G the adaptor point, the effective nonce is
// R' = R + T and the challenge e = H(R' || Q || m). A partial adaptor signature
// is s' = k + e*a*d (the BIP327 partial signature computed with that e); the
// aggregate is completed with s = s'_agg + t, and t is extracted from the
// completed signature as t = s - s'_agg. R' is normalised to even Y for BIP340,
// which negates the nonces and t alike (negR).

import {
  G, n, Fn, taggedHash, pointFromBytes, cbytes, xbytes, hasEvenY, isInfinity, mul,
  bytesToNum, numTo32b, concatBytes, lift_x, Point, randomBytes,
} from './curve.js';
import {
  keyAgg, applyTweak, getXonlyPk, nonceGen, nonceAgg, readSecNonce, getSessionKeyAggCoeff, InvalidContributionError,
} from './musig2.js';

// ---- Keys ----

// BIP340 secret keys are used as MuSig2 secret keys for the plain key 02||x:
// negate the secret when its point has odd Y so that pk = 02||x is its key.
export function signerKey(secBytes) {
  const d = bytesToNum(secBytes);
  if (!(0n < d && d < n)) throw new Error('secret key out of range');
  const P = mul(G, d);
  const even = hasEvenY(P);
  return { sk: even ? secBytes : numTo32b(n - d), pk: cbytes(even ? P : P.negate()) };
}

export function plainFromXonly(xonly) {
  if (xonly.length !== 32) throw new Error('x-only public key must be 32 bytes');
  return concatBytes(new Uint8Array([2]), xonly);
}

// KeyAgg over the parties' x-only keys (lifted to 02||x). Returns the key
// context and the x-only aggregate key P_swap.
export function xonlyKeyAgg(xonlyPubkeys) {
  const keyCtx = keyAgg(xonlyPubkeys.map(plainFromXonly));
  return { keyCtx, aggPubkey: getXonlyPk(keyCtx) };
}

// Taproot output key Q = P + H_TapTweak(P || merkleRoot) * G as an x-only tweak
// of the key context: partial signatures made in the tweaked context aggregate
// (with the tacc term) to signatures valid for Q.
export function tapTweak(keyCtx, merkleRoot) {
  const P = getXonlyPk(keyCtx);
  const tweak = taggedHash('TapTweak', P, merkleRoot ?? new Uint8Array(0));
  const tweaked = applyTweak(keyCtx, tweak, true);
  return { keyCtx: tweaked, Qbytes: getXonlyPk(tweaked) };
}

// Fresh nonces for one signing session (aggpk: the x-only key the session signs for).
export function swapNonceGen(secBytes, aggpk, msg) {
  const { sk, pk } = signerKey(secBytes);
  return nonceGen({ sk, pk, aggpk, msg });
}

// ---- Adaptor session values ----

function adaptorSessionValues(aggNonce, keyCtx, msg, T) {
  const { Q, gacc, tacc } = keyCtx;
  if (aggNonce.length !== 66) throw new InvalidContributionError(null, 'aggnonce');
  const R1 = pointFromBytes(aggNonce.slice(0, 33));
  const R2 = pointFromBytes(aggNonce.slice(33, 66));
  const b = Fn.create(bytesToNum(taggedHash('MuSig/noncecoef', aggNonce, xbytes(Q), msg)));
  let Ragg = R1.add(mul(R2, b));
  if (isInfinity(Ragg)) Ragg = G;
  const Reff = Ragg.add(T);
  if (isInfinity(Reff)) throw new Error('effective nonce is the point at infinity');
  const negR = !hasEvenY(Reff);
  const Rfin = negR ? Reff.negate() : Reff;
  const e = Fn.create(bytesToNum(taggedHash('BIP0340/challenge', xbytes(Rfin), xbytes(Q), msg)));
  const g = hasEvenY(Q) ? 1n : n - 1n;
  return { Q, gacc, tacc, b, e, negR, Rfin, g };
}

// ---- adaptorSign: partial adaptor pre-signature (consumes the secret nonce) ----

export function adaptorSign(secBytes, secNonce, aggNonce, keyCtx, msg, T) {
  const { sk, pk } = signerKey(secBytes);
  const { k1: k1_, k2: k2_, pk: noncePk } = readSecNonce(secNonce);
  if (!noncePk.every((v, i) => v === pk[i])) throw new Error("The signer's pubkey does not match the one in secnonce.");
  const { gacc, b, e, negR, g } = adaptorSessionValues(aggNonce, keyCtx, msg, T);
  const k1 = negR ? n - k1_ : k1_;
  const k2 = negR ? n - k2_ : k2_;
  const d_ = bytesToNum(sk);
  const P = mul(G, d_);
  const a = getSessionKeyAggCoeff({ keyCtx }, P);
  const d = Fn.create(g * gacc * d_);
  const psig = numTo32b(Fn.create(k1 + b * k2 + e * a * d));
  const pubNonce = concatBytes(cbytes(mul(G, k1_)), cbytes(mul(G, k2_)));
  if (!adaptorVerify(psig, pubNonce, xbytes(P), aggNonce, keyCtx, msg, T)) throw new Error('adaptor pre-signature self-check failed');
  return psig;
}

// ---- adaptorVerify: check a party's partial adaptor pre-signature ----

export function adaptorVerify(psig, pubNonce, xonlyPk, aggNonce, keyCtx, msg, T) {
  const s = bytesToNum(psig);
  if (psig.length !== 32 || s >= n) return false;
  const { gacc, b, e, negR, g } = adaptorSessionValues(aggNonce, keyCtx, msg, T);
  const R1 = pointFromBytes(pubNonce.slice(0, 33));
  const R2 = pointFromBytes(pubNonce.slice(33, 66));
  let Re = R1.add(mul(R2, b));
  if (negR) Re = Re.negate();
  const P = pointFromBytes(plainFromXonly(xonlyPk));
  const a = getSessionKeyAggCoeff({ keyCtx }, P);
  return mul(G, s).equals(Re.add(mul(P, Fn.create(e * a * g * gacc))));
}

// ---- adaptorAggregate: aggregate pre-signature (R', s'_agg), not yet valid ----
// Includes the tweak contribution e*g*tacc, so completing it with t yields a
// BIP340 signature for the (tweaked) aggregate key.

export function adaptorAggregate(psigs, aggNonce, keyCtx, msg, T) {
  const { tacc, e, negR, Rfin, g } = adaptorSessionValues(aggNonce, keyCtx, msg, T);
  let s = 0n;
  for (let i = 0; i < psigs.length; i++) {
    const si = bytesToNum(psigs[i]);
    if (si >= n) throw new InvalidContributionError(i, 'psig');
    s = Fn.create(s + si);
  }
  s = Fn.create(s + e * g * tacc);
  return { R: xbytes(Rfin), s: numTo32b(s), negR };
}

// ---- completeAdaptorSig: s = s'_agg + t (or - t when R' was negated) ----

export function completeAdaptorSig(Rbytes, sAdaptorBytes, adaptorSecret, negR) {
  const t = bytesToNum(adaptorSecret);
  const sFinal = Fn.create(bytesToNum(sAdaptorBytes) + (negR ? n - t : t));
  return concatBytes(Rbytes, numTo32b(sFinal));
}

// ---- adaptorExtract: t = s - s'_agg (negated back when R' was negated) ----

export function adaptorExtract(completeSigSBytes, aggregatedAdaptorSBytes, negR) {
  const diff = Fn.create(bytesToNum(completeSigSBytes) - bytesToNum(aggregatedAdaptorSBytes));
  return numTo32b(negR ? Fn.neg(diff) : diff);
}

// Adaptor secret t with T = t*G normalised to even Y, so that T travels as 32 bytes.
export function adaptorSecretFromBytes(tBytes) {
  let t = Fn.create(bytesToNum(tBytes));
  if (t === 0n) throw new Error('adaptor secret is zero');
  let T = mul(G, t);
  if (!hasEvenY(T)) { t = n - t; T = T.negate(); }
  return { t, tBytes: numTo32b(t), T, Tbytes: xbytes(T) };
}

export { nonceAgg, G, n, Fn, lift_x, hasEvenY, bytesToNum, numTo32b, Point, taggedHash, cbytes, randomBytes };
export { xbytes as pointToBytes, xbytes as getPlainPubkey };
