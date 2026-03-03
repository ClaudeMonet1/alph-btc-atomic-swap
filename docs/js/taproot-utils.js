// Taproot utility functions for BIP-340 Schnorr + MuSig2 adaptor signatures

import {
  Point, G, Fn, n,
  taggedHash, lift_x, hasEvenY, getPlainPubkey, bytesToNum, numTo32b,
} from './musig2.js';

// Compute the taproot-tweaked aggregate key Q = P + H_TapTweak(P || merkle_root) * G
export function computeTweakedKey(aggPubkey, merkleRoot) {
  const tweakHash = taggedHash('TapTweak', aggPubkey, merkleRoot);
  const tweakScalar = bytesToNum(tweakHash);
  const P = lift_x(bytesToNum(aggPubkey));
  let Q = P.add(G.multiply(tweakScalar));
  const negated = !hasEvenY(Q);
  if (negated) Q = Q.negate();
  return { Q, Qbytes: getPlainPubkey(Q), tweakScalar, negated };
}

// Compute the adaptor challenge e for a given set of session parameters
export function computeAdaptorChallenge(aggNonce, aggPubkey, msg, adaptorPoint) {
  const R1 = Point.fromHex(aggNonce.slice(0, 33));
  const R2 = Point.fromHex(aggNonce.slice(33, 66));
  const bHash = taggedHash('MuSig/noncecoef', aggNonce, aggPubkey, msg);
  const b = Fn.create(bytesToNum(bHash));
  const Ragg = R1.add(R2.multiply(b));
  const Reff = Ragg.add(adaptorPoint);
  const negR = !hasEvenY(Reff);
  const Rfinal = negR ? Reff.negate() : Reff;
  const e = Fn.create(bytesToNum(
    taggedHash('BIP0340/challenge', getPlainPubkey(Rfinal), aggPubkey, msg)
  ));
  return e;
}

// Compute taproot-tweaked private key for key-path-only P2TR spend
export function computeTweakedPrivateKey(privateKeyBytes, pubkeyXOnly) {
  const d = bytesToNum(privateKeyBytes);
  const P = G.multiply(d);
  const dAdj = hasEvenY(P) ? d : Fn.create(n - d);
  const tweakHash = taggedHash('TapTweak', pubkeyXOnly);
  const tweak = bytesToNum(tweakHash);
  return numTo32b(Fn.create(dAdj + tweak));
}
