// Adaptor Signatures built on MuSig2
//
// Normal Schnorr:  e = H(R || P || m),      s = r + e*x
// Adaptor:         e = H((R+T) || P || m),  s' = r + e*x   (pre-sig)
// Complete:        s = s' + t                               (valid sig for R+T)
// Extract:         t = s - s'                               (from on-chain s and known s')

import {
  Point, G, Fn, n,
  taggedHash, pointToBytes, lift_x,
  numTo32b, bytesToNum,
  hasEvenY, cbytes, getPlainPubkey,
} from './musig2.js';
import { concatBytes } from '@noble/curves/utils.js';

// ---- Adaptor session values ----
// Like getSessionValues but with adaptor point T added to effective R

function getAdaptorSessionValues(aggNonce, aggPubkey, msg, adaptorPoint) {
  const R1 = Point.fromBytes(aggNonce.slice(0, 33));
  const R2 = Point.fromBytes(aggNonce.slice(33, 66));
  const bHash = taggedHash('MuSig/noncecoef', aggNonce, aggPubkey, msg);
  const b = Fn.create(bytesToNum(bHash));
  const Ragg = R1.add(R2.multiply(b));

  // Adaptor: effective R = Ragg + T
  const Reff = Ragg.add(adaptorPoint);

  // We need the final R to have even Y for BIP-340 challenge
  const negR = !hasEvenY(Reff);
  const finalR = negR ? Reff.negate() : Reff;

  const e = Fn.create(bytesToNum(
    taggedHash('BIP0340/challenge', getPlainPubkey(finalR), aggPubkey, msg)
  ));
  return { Ragg, Reff, R: finalR, b, e, negR };
}

// ---- adaptorSign ----
// Create a partial adaptor pre-signature. The signer computes their partial sig
// using e = H((R_agg + T) || P || m) instead of e = H(R_agg || P || m).

export function adaptorSign(secretKey, secNonce, aggNonce, keyCoeffs, aggPubkey, msg, adaptorPoint, signerIndex, gacc) {
  const d_raw = bytesToNum(secretKey instanceof Uint8Array ? secretKey : numTo32b(secretKey));
  const k1 = bytesToNum(secNonce.slice(0, 32));
  const k2 = bytesToNum(secNonce.slice(32, 64));

  const { b, e, negR } = getAdaptorSessionValues(aggNonce, aggPubkey, msg, adaptorPoint);

  // Negate nonces if effective R had odd y
  const k1_ = negR ? Fn.neg(k1) : k1;
  const k2_ = negR ? Fn.neg(k2) : k2;

  const a = keyCoeffs[signerIndex];

  const P = G.multiply(d_raw);
  const d_eff = hasEvenY(P) ? d_raw : Fn.neg(d_raw);
  const d = Fn.create(gacc * d_eff);

  // s' = k1 + b*k2 + e*a*d (mod n) -- same formula, different e
  const s = Fn.create(k1_ + Fn.create(b * k2_) + Fn.create(Fn.create(e * a) * d));
  return numTo32b(s);
}

// ---- adaptorVerify ----
// Verify a partial adaptor pre-signature.

export function adaptorVerify(adaptorSig, pubNonce, pubkey, aggNonce, keyCoeffs, aggPubkey, msg, adaptorPoint, signerIndex, gacc) {
  const s = bytesToNum(adaptorSig);
  const { b, e, negR } = getAdaptorSessionValues(aggNonce, aggPubkey, msg, adaptorPoint);
  const a = keyCoeffs[signerIndex];

  const R1 = Point.fromBytes(pubNonce.slice(0, 33));
  const R2 = Point.fromBytes(pubNonce.slice(33, 66));
  let Re = R1.add(R2.multiply(b));
  if (negR) Re = Re.negate();

  const P = lift_x(bytesToNum(pubkey));
  const eag = Fn.create(Fn.create(e * a) * gacc);
  const lhs = G.multiply(s);
  const rhs = Re.add(P.multiply(eag));

  return lhs.equals(rhs);
}

// ---- adaptorAggregate ----
// Aggregate partial adaptor pre-signatures into a single adaptor pre-signature.
// The result is NOT a valid BIP-340 signature -- it needs completion with the secret t.

export function adaptorAggregate(partialAdaptorSigs, aggNonce, aggPubkey, msg, adaptorPoint) {
  const { R, negR } = getAdaptorSessionValues(aggNonce, aggPubkey, msg, adaptorPoint);

  let s = 0n;
  for (const psig of partialAdaptorSigs) {
    s = Fn.create(s + bytesToNum(psig));
  }

  // The aggregated pre-sig: (R_eff_x, s_agg)
  // Note: this is NOT a valid sig because s_agg = sum(ki) + e*sum(ai*di)
  // but the R in the sig is R_eff = R_agg + T, while the nonces sum to R_agg.
  // Completing with t will make it valid: s_final = s_agg + t (if R not negated)
  // or s_final = s_agg + (n - t) if R was negated.
  return { R: getPlainPubkey(R), s: numTo32b(s), negR };
}

// ---- completeAdaptorSig ----
// Complete the aggregated adaptor pre-sig to get a valid BIP-340 sig.
// s_final = s_adaptor + t (accounting for R parity)

export function completeAdaptorSig(Rbytes, sAdaptorBytes, adaptorSecret, negR) {
  const sAdaptor = bytesToNum(sAdaptorBytes);
  const t = bytesToNum(adaptorSecret);
  const t_ = negR ? Fn.neg(t) : t;
  const sFinal = Fn.create(sAdaptor + t_);
  return concatBytes(Rbytes, numTo32b(sFinal));
}

// ---- adaptorExtract ----
// Bob sees the completed signature on-chain. He extracts t from:
//   t = s_final - s_adaptor (accounting for R parity)

export function adaptorExtract(completeSigSBytes, aggregatedAdaptorSBytes, negR) {
  const sFinal = bytesToNum(completeSigSBytes);
  const sAdaptor = bytesToNum(aggregatedAdaptorSBytes);
  const tOrNegT = Fn.create(sFinal - sAdaptor);
  // If R was negated, we used -t to complete, so extracted value is -t; negate back
  const t = negR ? Fn.neg(tOrNegT) : tOrNegT;
  return numTo32b(t);
}

// Re-export for convenience
export { Point, G, Fn, n, numTo32b, bytesToNum, hasEvenY, lift_x, getPlainPubkey, cbytes, pointToBytes };
