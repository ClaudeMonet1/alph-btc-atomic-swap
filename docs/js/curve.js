// Curve shim for the browser build (@noble/curves 1.x, vendored). src/curve.js
// exposes the same interface over @noble/curves 2.x, so that musig2.js,
// adaptor.js and taproot-utils.js are byte-identical in both builds.
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bytesToNumberBE, numberToBytesBE, concatBytes, hexToBytes, bytesToHex } from '@noble/curves/utils';

export const Point = secp256k1.ProjectivePoint;
export const G = Point.BASE;
export const ZERO = Point.ZERO;
export const n = secp256k1.CURVE.n;
const modn = (v) => { const r = v % n; return r < 0n ? r + n : r; };
export const Fn = {
  ORDER: n,
  create: modn,
  neg: (v) => { const r = modn(v); return r === 0n ? 0n : n - r; },
  toBytes: (v) => numberToBytesBE(modn(v), 32),
};
export const taggedHash = schnorr.utils.taggedHash;
export const lift_x = schnorr.utils.lift_x;
export const schnorrVerify = (sig, msg, pk) => schnorr.verify(sig, msg, pk);
export const schnorrGetPublicKey = (sk) => schnorr.getPublicKey(sk);
export const randomSecretKey = () => schnorr.utils.randomPrivateKey();
export function pointFromBytes(b) { return Point.fromHex(b); } // throws on invalid encodings
export function cbytes(P) { return P.toRawBytes(true); }
export function xbytes(P) { return P.toRawBytes(true).slice(1); }
export function hasEvenY(P) { return P.toAffine().y % 2n === 0n; }
export function isInfinity(P) { return P.equals(ZERO); }
export function mul(P, k) { k = modn(k); return k === 0n ? ZERO : P.multiply(k); }
export function randomBytes(len) { return crypto.getRandomValues(new Uint8Array(len)); }
export function bytesToNum(b) { return bytesToNumberBE(b); }
export function numTo32b(v) { return Fn.toBytes(v); }
export { concatBytes, hexToBytes, bytesToHex };
