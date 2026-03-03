// BIP-327 MuSig2 implementation using @noble/curves/secp256k1
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
//
// Browser-compatible: uses secp256k1.ProjectivePoint (not schnorr.Point)

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bytesToNumberBE, concatBytes, numberToBytesBE } from '@noble/curves/utils';

const Point = secp256k1.ProjectivePoint;
const G = Point.BASE;
const n = secp256k1.CURVE.n;

// Scalar field modular arithmetic (replaces schnorr.Point.Fn)
const Fn = {
  ORDER: n,
  create: (v) => { const r = v % n; return r < 0n ? r + n : r; },
  neg: (v) => { const r = v % n; return r === 0n ? 0n : n - (r < 0n ? r + n : r); },
  toBytes: (v) => numberToBytesBE(v < 0n ? ((v % n) + n) % n : v % n, 32),
};

const taggedHash = schnorr.utils.taggedHash;
const lift_x = schnorr.utils.lift_x;

// 32-byte x-only serialization (like schnorr.utils.pointToBytes)
function pointToBytes(point) {
  const raw = point.toRawBytes(true); // 33-byte compressed
  return raw.slice(1); // drop prefix byte → 32-byte x-only
}

function numTo32b(num) { return Fn.toBytes(num); }
function bytesToNum(b) { return bytesToNumberBE(b); }

function cmpBytes(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

function hasEvenY(point) {
  return point.toAffine().y % 2n === 0n;
}

// 33-byte compressed serialization
function cbytes(point) {
  return point.toRawBytes(true);
}

function getPlainPubkey(point) {
  return pointToBytes(point); // 32-byte x-only
}

// Deserialize 33-byte compressed point
function pointFromBytes(bytes) {
  return Point.fromHex(bytes);
}

// ---- KeyAgg (BIP-327 §4.3) ----

function keyAggCoeff(pubkeys, pk, secondKeyIdx) {
  if (secondKeyIdx !== -1 && cmpBytes(pk, pubkeys[secondKeyIdx]) === 0) {
    return 1n;
  }
  const L = concatBytes(...pubkeys);
  const h = taggedHash('KeyAgg coefficient', L, pk);
  return Fn.create(bytesToNum(h));
}

export function keyAgg(pubkeys) {
  // pubkeys: array of 32-byte x-only Uint8Arrays
  let secondKeyIdx = -1;
  for (let i = 1; i < pubkeys.length; i++) {
    if (cmpBytes(pubkeys[i], pubkeys[0]) !== 0) {
      secondKeyIdx = i;
      break;
    }
  }

  const keyCoeffs = [];
  let Q = Point.ZERO;
  for (let i = 0; i < pubkeys.length; i++) {
    const Pi = lift_x(bytesToNum(pubkeys[i]));
    const ai = keyAggCoeff(pubkeys, pubkeys[i], secondKeyIdx);
    keyCoeffs.push(ai);
    Q = Q.add(Pi.multiply(ai));
  }

  // If Q has odd y, negate and track via gacc
  const gacc = hasEvenY(Q) ? 1n : Fn.create(n - 1n);
  if (!hasEvenY(Q)) Q = Q.negate();

  const aggPubkey = getPlainPubkey(Q);
  return { aggPoint: Q, aggPubkey, keyCoeffs, secondKeyIdx, gacc };
}

// ---- NonceGen (BIP-327 §4.5) ----

export function nonceGen(secretKey, aggPubkey, msg) {
  const sk = secretKey instanceof Uint8Array ? secretKey : numTo32b(secretKey);
  const rand = crypto.getRandomValues(new Uint8Array(32));

  const k1bytes = taggedHash('MuSig/nonce', rand, sk, aggPubkey, msg, new Uint8Array([0]));
  const k2bytes = taggedHash('MuSig/nonce', rand, sk, aggPubkey, msg, new Uint8Array([1]));

  let k1 = Fn.create(bytesToNum(k1bytes));
  let k2 = Fn.create(bytesToNum(k2bytes));
  if (k1 === 0n) k1 = 1n;
  if (k2 === 0n) k2 = 1n;

  const R1 = G.multiply(k1);
  const R2 = G.multiply(k2);

  const pubNonce = concatBytes(cbytes(R1), cbytes(R2)); // 66 bytes
  const secNonce = concatBytes(numTo32b(k1), numTo32b(k2)); // 64 bytes
  return { secNonce, pubNonce };
}

// ---- NonceAgg (BIP-327 §4.6) ----

export function nonceAgg(pubNonces) {
  const aggR = [];
  for (let j = 0; j < 2; j++) {
    let Rj = Point.ZERO;
    for (let i = 0; i < pubNonces.length; i++) {
      Rj = Rj.add(pointFromBytes(pubNonces[i].slice(j * 33, j * 33 + 33)));
    }
    aggR.push(Rj);
  }
  return concatBytes(cbytes(aggR[0]), cbytes(aggR[1]));
}

// ---- Session context helpers ----

function getNonceCoeff(aggNonce, aggPubkey, msg) {
  const R1 = pointFromBytes(aggNonce.slice(0, 33));
  const R2 = pointFromBytes(aggNonce.slice(33, 66));
  const bHash = taggedHash('MuSig/noncecoef', aggNonce, aggPubkey, msg);
  const b = Fn.create(bytesToNum(bHash));
  const R = R1.add(R2.multiply(b));
  return { R, b };
}

function getSessionValues(aggNonce, aggPubkey, msg) {
  const { R, b } = getNonceCoeff(aggNonce, aggPubkey, msg);
  const negR = !hasEvenY(R);
  const finalR = negR ? R.negate() : R;
  const e = Fn.create(bytesToNum(
    taggedHash('BIP0340/challenge', getPlainPubkey(finalR), aggPubkey, msg)
  ));
  return { R: finalR, b, e, negR };
}

// ---- PartialSign (BIP-327 §4.8) ----

export function partialSign(secretKey, secNonce, aggNonce, keyCoeffs, aggPubkey, msg, signerIndex, gacc) {
  // gacc: accumulated negation factor from keyAgg (1n or n-1n)
  const d_raw = bytesToNum(secretKey instanceof Uint8Array ? secretKey : numTo32b(secretKey));
  const k1 = bytesToNum(secNonce.slice(0, 32));
  const k2 = bytesToNum(secNonce.slice(32, 64));

  const { R, b, e, negR } = getSessionValues(aggNonce, aggPubkey, msg);

  // Negate nonces if aggregated R had odd y
  const k1_ = negR ? Fn.neg(k1) : k1;
  const k2_ = negR ? Fn.neg(k2) : k2;

  const a = keyCoeffs[signerIndex];

  const P = G.multiply(d_raw);
  const d_eff = hasEvenY(P) ? d_raw : Fn.neg(d_raw);
  const d = Fn.create(gacc * d_eff);

  // s = k1 + b*k2 + e*a*d (mod n)
  const s = Fn.create(k1_ + Fn.create(b * k2_) + Fn.create(Fn.create(e * a) * d));
  return numTo32b(s);
}

// ---- PartialSigVerify (BIP-327 §4.9) ----

export function partialSigVerify(partialSig, pubNonce, pubkey, aggNonce, keyCoeffs, aggPubkey, msg, signerIndex, gacc) {
  const s = bytesToNum(partialSig);
  const { R, b, e, negR } = getSessionValues(aggNonce, aggPubkey, msg);
  const a = keyCoeffs[signerIndex];

  const R1 = pointFromBytes(pubNonce.slice(0, 33));
  const R2 = pointFromBytes(pubNonce.slice(33, 66));

  let Re = R1.add(R2.multiply(b));
  if (negR) Re = Re.negate();

  const P = lift_x(bytesToNum(pubkey));

  // Verify: s*G == Re + e * a * gacc * P
  const lhs = G.multiply(s);
  const eag = Fn.create(Fn.create(e * a) * gacc);
  const rhs = Re.add(P.multiply(eag));

  return lhs.equals(rhs);
}

// ---- PartialSigAgg (BIP-327 §4.10) ----

export function partialSigAgg(partialSigs, aggNonce, aggPubkey, msg) {
  const { R } = getSessionValues(aggNonce, aggPubkey, msg);

  let s = 0n;
  for (const psig of partialSigs) {
    s = Fn.create(s + bytesToNum(psig));
  }

  const sig = concatBytes(getPlainPubkey(R), numTo32b(s));
  if (!schnorr.verify(sig, msg, aggPubkey)) {
    throw new Error('partialSigAgg: aggregated signature is invalid');
  }
  return sig;
}

export {
  Point, G, Fn, n,
  taggedHash, pointToBytes, lift_x,
  numTo32b, bytesToNum,
  hasEvenY, cbytes, getPlainPubkey,
  getNonceCoeff, getSessionValues,
};
