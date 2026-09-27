// Curve shim for the Node build (@noble/curves 2.x). docs/js/curve.js exposes
// the same interface over @noble/curves 1.x, so that musig2.js, adaptor.js and
// taproot-utils.js are byte-identical in both builds.
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE, concatBytes, hexToBytes, bytesToHex } from '@noble/curves/utils.js';

export const Point = schnorr.Point;
export const G = Point.BASE;
export const ZERO = Point.ZERO;
export const n = Point.Fn.ORDER;
export const Fn = {
  ORDER: n,
  create: (v) => Point.Fn.create(v),
  neg: (v) => Point.Fn.neg(Point.Fn.create(v)),
  toBytes: (v) => numberToBytesBE(Point.Fn.create(v), 32),
};
export const taggedHash = schnorr.utils.taggedHash;
export const lift_x = schnorr.utils.lift_x;
export const schnorrVerify = (sig, msg, pk) => schnorr.verify(sig, msg, pk);
export const schnorrGetPublicKey = (sk) => schnorr.getPublicKey(sk);
export const randomSecretKey = () => schnorr.utils.randomSecretKey();
export function pointFromBytes(b) { return Point.fromBytes(b); } // throws on invalid encodings
export function cbytes(P) { return P.toBytes(true); }
export function xbytes(P) { return P.toBytes(true).slice(1); }
export function hasEvenY(P) { return P.toAffine().y % 2n === 0n; }
export function isInfinity(P) { return P.equals(ZERO); }
export function mul(P, k) { k = Fn.create(k); return k === 0n ? ZERO : P.multiply(k); }
export function randomBytes(len) { return crypto.getRandomValues(new Uint8Array(len)); }
export function bytesToNum(b) { return bytesToNumberBE(b); }
export function numTo32b(v) { return Fn.toBytes(v); }
export { concatBytes, hexToBytes, bytesToHex };
