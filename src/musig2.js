// MuSig2 as specified by BIP327, checked against the BIP's test vectors
// (docs/spec/bip327/*.json, run by bip327-selftest.js in Node and in the browser).
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
//
// Key aggregation works on 33-byte plain public keys; nonces carry the signer's
// public key; tweaks (plain or x-only) live in the key aggregation context and
// their contribution is added by PartialSigAgg. The swap-specific adaptor
// layer is in adaptor.js.

import {
  G, ZERO, n, Fn, taggedHash, pointFromBytes, cbytes, xbytes, hasEvenY, isInfinity, mul,
  randomBytes, bytesToNum, numTo32b, concatBytes,
} from './curve.js';

export class InvalidContributionError extends Error {
  constructor(signer, contrib) {
    super(`invalid ${contrib}${signer === null ? '' : ` from signer ${signer}`}`);
    this.name = 'InvalidContributionError';
    this.signer = signer;
    this.contrib = contrib;
  }
}

const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const allZero = (b) => b.every((v) => v === 0);
function u32be(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v); return b; }
function u64be(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v)); return b; }
function xor(a, b) { const out = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]; return out; }

// cpoint: a 33-byte compressed point; anything else is an invalid contribution.
function cpoint(b, signer, contrib) {
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new InvalidContributionError(signer, contrib);
  try { return pointFromBytes(b); } catch { throw new InvalidContributionError(signer, contrib); }
}
// cpoint_ext: as cpoint, with the all-zero encoding standing for the point at infinity.
function cpointExt(b, signer, contrib) {
  if (b.length === 33 && allZero(b)) return ZERO;
  return cpoint(b, signer, contrib);
}
function cbytesExt(P) { return isInfinity(P) ? new Uint8Array(33) : cbytes(P); }

// ---- Key aggregation (BIP327 KeyAgg, ApplyTweak) ----

function hashKeys(pubkeys) { return taggedHash('KeyAgg list', concatBytes(...pubkeys)); }

function getSecondKey(pubkeys) {
  for (let j = 1; j < pubkeys.length; j++) if (!eq(pubkeys[j], pubkeys[0])) return pubkeys[j];
  return new Uint8Array(33);
}

function keyAggCoeffInternal(pubkeys, pk, pk2) {
  if (eq(pk, pk2)) return 1n;
  return Fn.create(bytesToNum(taggedHash('KeyAgg coefficient', hashKeys(pubkeys), pk)));
}

export function keyAggCoeff(pubkeys, pk) { return keyAggCoeffInternal(pubkeys, pk, getSecondKey(pubkeys)); }

// pubkeys: array of 33-byte plain public keys. Returns the KeyAgg context.
export function keyAgg(pubkeys) {
  const pk2 = getSecondKey(pubkeys);
  let Q = ZERO;
  for (let i = 0; i < pubkeys.length; i++) {
    const P = cpoint(pubkeys[i], i, 'pubkey');
    Q = Q.add(mul(P, keyAggCoeffInternal(pubkeys, pubkeys[i], pk2)));
  }
  if (isInfinity(Q)) throw new Error('The aggregate public key cannot be infinity.');
  return { Q, gacc: 1n, tacc: 0n, pubkeys };
}

export function getXonlyPk(ctx) { return xbytes(ctx.Q); }
export function getPlainPk(ctx) { return cbytes(ctx.Q); }

export function applyTweak(ctx, tweak, isXonly) {
  if (tweak.length !== 32) throw new Error('The tweak must be a 32-byte array.');
  const t = bytesToNum(tweak);
  if (t >= n) throw new Error('The tweak must be less than n.');
  const g = (isXonly && !hasEvenY(ctx.Q)) ? n - 1n : 1n;
  const Q = mul(ctx.Q, g).add(mul(G, t));
  if (isInfinity(Q)) throw new Error('The result of tweaking cannot be infinity.');
  return { Q, gacc: Fn.create(g * ctx.gacc), tacc: Fn.create(t + g * ctx.tacc), pubkeys: ctx.pubkeys };
}

export function keyAggAndTweak(pubkeys, tweaks = [], isXonly = []) {
  if (tweaks.length !== isXonly.length) throw new Error('tweaks and isXonly must have the same length');
  let ctx = keyAgg(pubkeys);
  for (let i = 0; i < tweaks.length; i++) ctx = applyTweak(ctx, tweaks[i], isXonly[i]);
  return ctx;
}

// ---- Nonce generation (BIP327 NonceGen) ----

function nonceHash(rand, pk, aggpk, i, msgPrefixed, extraIn) {
  return taggedHash('MuSig/nonce', rand, new Uint8Array([pk.length]), pk, new Uint8Array([aggpk.length]), aggpk,
    msgPrefixed, u32be(extraIn.length), extraIn, new Uint8Array([i]));
}

// Deterministic given `rand`; nonceGen() below draws it. pk is the signer's
// 33-byte plain key, aggpk the optional 32-byte x-only aggregate key, msg the
// optional message (null = absent, which differs from an empty message).
export function nonceGenInternal({ rand, sk = null, pk, aggpk = null, msg = null, extraIn = null }) {
  if (rand.length !== 32) throw new Error('rand must be 32 bytes');
  if (pk.length !== 33) throw new Error('pk must be a 33-byte plain public key');
  if (sk !== null) {
    if (sk.length !== 32) throw new Error('sk must be 32 bytes');
    rand = xor(sk, taggedHash('MuSig/aux', rand));
  }
  aggpk = aggpk ?? new Uint8Array(0);
  extraIn = extraIn ?? new Uint8Array(0);
  const msgPrefixed = msg === null ? new Uint8Array([0]) : concatBytes(new Uint8Array([1]), u64be(msg.length), msg);
  const k1 = Fn.create(bytesToNum(nonceHash(rand, pk, aggpk, 0, msgPrefixed, extraIn)));
  const k2 = Fn.create(bytesToNum(nonceHash(rand, pk, aggpk, 1, msgPrefixed, extraIn)));
  if (k1 === 0n || k2 === 0n) throw new Error('nonce derivation produced zero; retry with fresh randomness');
  const pubNonce = concatBytes(cbytes(mul(G, k1)), cbytes(mul(G, k2)));
  const secNonce = concatBytes(numTo32b(k1), numTo32b(k2), pk);
  return { secNonce, pubNonce };
}

export function nonceGen(opts) { return nonceGenInternal({ ...opts, rand: randomBytes(32) }); }

// ---- Nonce aggregation (BIP327 NonceAgg) ----

export function nonceAgg(pubNonces) {
  const halves = [];
  for (let j = 0; j < 2; j++) {
    let R = ZERO;
    for (let i = 0; i < pubNonces.length; i++) {
      if (pubNonces[i].length !== 66) throw new InvalidContributionError(i, 'pubnonce');
      R = R.add(cpoint(pubNonces[i].slice(33 * j, 33 * j + 33), i, 'pubnonce'));
    }
    halves.push(cbytesExt(R));
  }
  return concatBytes(...halves);
}

// ---- Session context (BIP327 SessionContext, GetSessionValues) ----

// A session is { aggNonce, keyCtx, msg }: the aggregate nonce, the (tweaked)
// key aggregation context and the message.
export function sessionCtx(aggNonce, pubkeys, tweaks, isXonly, msg) {
  return { aggNonce, keyCtx: keyAggAndTweak(pubkeys, tweaks, isXonly), msg };
}

export function getSessionValues(session) {
  const { Q, gacc, tacc } = session.keyCtx;
  const aggNonce = session.aggNonce;
  if (aggNonce.length !== 66) throw new InvalidContributionError(null, 'aggnonce');
  const R1 = cpointExt(aggNonce.slice(0, 33), null, 'aggnonce');
  const R2 = cpointExt(aggNonce.slice(33, 66), null, 'aggnonce');
  const b = Fn.create(bytesToNum(taggedHash('MuSig/noncecoef', aggNonce, xbytes(Q), session.msg)));
  let R = R1.add(mul(R2, b));
  if (isInfinity(R)) R = G;
  const e = Fn.create(bytesToNum(taggedHash('BIP0340/challenge', xbytes(R), xbytes(Q), session.msg)));
  return { Q, gacc, tacc, b, R, e };
}

export function getSessionKeyAggCoeff(session, P) {
  const pk = cbytes(P);
  const { pubkeys } = session.keyCtx;
  if (!pubkeys.some((k) => eq(k, pk))) throw new Error("The signer's pubkey must be included in the list of pubkeys.");
  return keyAggCoeff(pubkeys, pk);
}

// ---- Signing (BIP327 Sign, PartialSigVerify, PartialSigAgg) ----

// Reads and range-checks the secret nonce. With consume (the default) the nonce
// is zeroed: a secret nonce signs exactly once, two partial signatures under
// one nonce reveal the secret key.
export function readSecNonce(secNonce, { consume = true } = {}) {
  if (secNonce.length !== 97) throw new Error('secnonce must be 97 bytes');
  // A consumed (zeroed) nonce fails the range check below.
  const k1 = bytesToNum(secNonce.slice(0, 32));
  const k2 = bytesToNum(secNonce.slice(32, 64));
  if (!(0n < k1 && k1 < n)) throw new Error('first secnonce value is out of range.');
  if (!(0n < k2 && k2 < n)) throw new Error('second secnonce value is out of range.');
  const pk = secNonce.slice(64, 97);
  if (consume) secNonce.fill(0);
  return { k1, k2, pk };
}

export function sign(secNonce, sk, session, opts = {}) {
  const { k1: k1_, k2: k2_, pk } = readSecNonce(secNonce, opts);
  const { Q, gacc, b, R, e } = getSessionValues(session);
  const k1 = hasEvenY(R) ? k1_ : n - k1_;
  const k2 = hasEvenY(R) ? k2_ : n - k2_;
  const d_ = bytesToNum(sk);
  if (!(0n < d_ && d_ < n)) throw new Error('The secret key must be an integer in the range 1..n-1.');
  const P = mul(G, d_);
  if (!eq(cbytes(P), pk)) throw new Error("The signer's pubkey does not match the one in secnonce.");
  const a = getSessionKeyAggCoeff(session, P);
  const g = hasEvenY(Q) ? 1n : n - 1n;
  const d = Fn.create(g * gacc * d_);
  const s = Fn.create(k1 + b * k2 + e * a * d);
  const psig = numTo32b(s);
  const pubNonce = concatBytes(cbytes(mul(G, k1_)), cbytes(mul(G, k2_)));
  if (!partialSigVerifyInternal(psig, pubNonce, cbytes(P), session)) throw new Error('partial signature self-check failed');
  return psig;
}

export function partialSigVerifyInternal(psig, pubNonce, pk, session) {
  const s = bytesToNum(psig);
  if (s >= n) return false;
  const { Q, gacc, b, R, e } = getSessionValues(session);
  const R1 = cpoint(pubNonce.slice(0, 33), null, 'pubnonce');
  const R2 = cpoint(pubNonce.slice(33, 66), null, 'pubnonce');
  let Re = R1.add(mul(R2, b));
  if (!hasEvenY(R)) Re = Re.negate();
  const P = cpoint(pk, null, 'pubkey');
  const a = getSessionKeyAggCoeff(session, P);
  const g = hasEvenY(Q) ? 1n : n - 1n;
  return mul(G, s).equals(Re.add(mul(P, Fn.create(e * a * g * gacc))));
}

// BIP327 PartialSigVerify: validates every contribution, then checks signer i.
export function partialSigVerify(psig, pubNonces, pubkeys, tweaks, isXonly, msg, i) {
  if (pubNonces.length !== pubkeys.length) throw new Error('pubnonces and pubkeys must have the same length');
  const aggNonce = nonceAgg(pubNonces);
  const session = sessionCtx(aggNonce, pubkeys, tweaks, isXonly, msg);
  return partialSigVerifyInternal(psig, pubNonces[i], pubkeys[i], session);
}

export function partialSigAgg(psigs, session) {
  const { Q, tacc, R, e } = getSessionValues(session);
  let s = 0n;
  for (let i = 0; i < psigs.length; i++) {
    const si = bytesToNum(psigs[i]);
    if (si >= n) throw new InvalidContributionError(i, 'psig');
    s = Fn.create(s + si);
  }
  const g = hasEvenY(Q) ? 1n : n - 1n;
  s = Fn.create(s + e * g * tacc);
  return concatBytes(xbytes(R), numTo32b(s));
}

// ---- Deterministic signing (BIP327 DeterministicSign) ----

export function detSign(sk, aggOtherNonce, pubkeys, tweaks, isXonly, msg, rand = null) {
  const skPrime = rand === null ? sk : xor(sk, taggedHash('MuSig/aux', rand));
  const aggpk = getXonlyPk(keyAggAndTweak(pubkeys, tweaks, isXonly));
  const P = mul(G, bytesToNum(sk));
  const pk = cbytes(P);
  const kHash = (i) => taggedHash('MuSig/deterministic/nonce', skPrime, aggOtherNonce, aggpk, u64be(msg.length), msg, new Uint8Array([i]));
  const k1 = Fn.create(bytesToNum(kHash(0)));
  const k2 = Fn.create(bytesToNum(kHash(1)));
  if (k1 === 0n || k2 === 0n) throw new Error('deterministic nonce is zero');
  const pubNonce = concatBytes(cbytes(mul(G, k1)), cbytes(mul(G, k2)));
  const secNonce = concatBytes(numTo32b(k1), numTo32b(k2), pk);
  let aggNonce;
  try { aggNonce = nonceAgg([pubNonce, aggOtherNonce]); } catch { throw new InvalidContributionError(null, 'aggothernonce'); }
  const session = sessionCtx(aggNonce, pubkeys, tweaks, isXonly, msg);
  return { pubNonce, psig: sign(secNonce, sk, session) };
}

export { G, ZERO, n, Fn, taggedHash, cbytes, xbytes, hasEvenY, bytesToNum, numTo32b, concatBytes };
