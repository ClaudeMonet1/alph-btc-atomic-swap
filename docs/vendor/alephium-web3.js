// Bundled by scripts/vendor.mjs from the pinned package in node_modules. Do not edit; rebuild with `npm run vendor`.
// @alephium/web3 2.0.8

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod2) => function __require() {
  try {
    return mod2 || (0, cb[__getOwnPropNames(cb)[0]])((mod2 = { exports: {} }).exports, mod2), mod2.exports;
  } catch (e) {
    throw mod2 = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod2, isNodeMode, target) => (target = mod2 != null ? __create(__getProtoOf(mod2)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod2 || !mod2.__esModule ? __defProp(target, "default", { value: mod2, enumerable: true }) : target,
  mod2
));

// node_modules/@alephium/web3/dist/alephium-web3.min.js
var require_alephium_web3_min = __commonJS({
  "node_modules/@alephium/web3/dist/alephium-web3.min.js"(exports, module) {
    /*! For license information please see alephium-web3.min.js.LICENSE.txt */
    !(function(e, t) {
      "object" == typeof exports && "object" == typeof module ? module.exports = t() : "function" == typeof define && define.amd ? define([], t) : "object" == typeof exports ? exports.alephium = t() : e.alephium = t();
    })(self, (() => (() => {
      var e = { 9695: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.utils = t2.schnorr = t2.verify = t2.signSync = t2.sign = t2.getSharedSecret = t2.recoverPublicKey = t2.getPublicKey = t2.Signature = t2.Point = t2.CURVE = void 0;
        const n = r2(7998), i = BigInt(0), o = BigInt(1), s = BigInt(2), a = BigInt(3), c = BigInt(8), u = Object.freeze({ a: i, b: BigInt(7), P: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), h: o, Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"), Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"), beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee") });
        t2.CURVE = u;
        const d = (e3, t3) => (e3 + t3 / s) / t3, f = { beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"), splitScalar(e3) {
          const { n: t3 } = u, r3 = BigInt("0x3086d221a7d46bcde86c90e49284eb15"), n2 = -o * BigInt("0xe4437ed6010e88286f547fa90abfe4c3"), i2 = BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), s2 = r3, a2 = BigInt("0x100000000000000000000000000000000"), c2 = d(s2 * e3, t3), f2 = d(-n2 * e3, t3);
          let h2 = D(e3 - c2 * r3 - f2 * i2, t3), l2 = D(-c2 * n2 - f2 * s2, t3);
          const p2 = h2 > a2, b2 = l2 > a2;
          if (p2 && (h2 = t3 - h2), b2 && (l2 = t3 - l2), h2 > a2 || l2 > a2) throw new Error("splitScalarEndo: Endomorphism failed, k=" + e3);
          return { k1neg: p2, k1: h2, k2neg: b2, k2: l2 };
        } }, h = 32, l = 32, p = h + 1, b = 2 * h + 1;
        function y(e3) {
          const { a: t3, b: r3 } = u, n2 = D(e3 * e3), i2 = D(n2 * e3);
          return D(i2 + t3 * e3 + r3);
        }
        const m = u.a === i;
        class g extends Error {
          constructor(e3) {
            super(e3);
          }
        }
        function v(e3) {
          if (!(e3 instanceof w)) throw new TypeError("JacobianPoint expected");
        }
        class w {
          constructor(e3, t3, r3) {
            this.x = e3, this.y = t3, this.z = r3;
          }
          static fromAffine(e3) {
            if (!(e3 instanceof S)) throw new TypeError("JacobianPoint#fromAffine: expected Point");
            return e3.equals(S.ZERO) ? w.ZERO : new w(e3.x, e3.y, o);
          }
          static toAffineBatch(e3) {
            const t3 = (function(e4, t4 = u.P) {
              const r3 = new Array(e4.length), n2 = H(e4.reduce(((e5, n3, o2) => n3 === i ? e5 : (r3[o2] = e5, D(e5 * n3, t4))), o), t4);
              return e4.reduceRight(((e5, n3, o2) => n3 === i ? e5 : (r3[o2] = D(e5 * r3[o2], t4), D(e5 * n3, t4))), n2), r3;
            })(e3.map(((e4) => e4.z)));
            return e3.map(((e4, r3) => e4.toAffine(t3[r3])));
          }
          static normalizeZ(e3) {
            return w.toAffineBatch(e3).map(w.fromAffine);
          }
          equals(e3) {
            v(e3);
            const { x: t3, y: r3, z: n2 } = this, { x: i2, y: o2, z: s2 } = e3, a2 = D(n2 * n2), c2 = D(s2 * s2), u2 = D(t3 * c2), d2 = D(i2 * a2), f2 = D(D(r3 * s2) * c2), h2 = D(D(o2 * n2) * a2);
            return u2 === d2 && f2 === h2;
          }
          negate() {
            return new w(this.x, D(-this.y), this.z);
          }
          double() {
            const { x: e3, y: t3, z: r3 } = this, n2 = D(e3 * e3), i2 = D(t3 * t3), o2 = D(i2 * i2), u2 = e3 + i2, d2 = D(s * (D(u2 * u2) - n2 - o2)), f2 = D(a * n2), h2 = D(f2 * f2), l2 = D(h2 - s * d2), p2 = D(f2 * (d2 - l2) - c * o2), b2 = D(s * t3 * r3);
            return new w(l2, p2, b2);
          }
          add(e3) {
            v(e3);
            const { x: t3, y: r3, z: n2 } = this, { x: o2, y: a2, z: c2 } = e3;
            if (o2 === i || a2 === i) return this;
            if (t3 === i || r3 === i) return e3;
            const u2 = D(n2 * n2), d2 = D(c2 * c2), f2 = D(t3 * d2), h2 = D(o2 * u2), l2 = D(D(r3 * c2) * d2), p2 = D(D(a2 * n2) * u2), b2 = D(h2 - f2), y2 = D(p2 - l2);
            if (b2 === i) return y2 === i ? this.double() : w.ZERO;
            const m2 = D(b2 * b2), g2 = D(b2 * m2), _2 = D(f2 * m2), A2 = D(y2 * y2 - g2 - s * _2), S2 = D(y2 * (_2 - A2) - l2 * g2), C2 = D(n2 * c2 * b2);
            return new w(A2, S2, C2);
          }
          subtract(e3) {
            return this.add(e3.negate());
          }
          multiplyUnsafe(e3) {
            const t3 = w.ZERO;
            if ("bigint" == typeof e3 && e3 === i) return t3;
            let r3 = j(e3);
            if (r3 === o) return this;
            if (!m) {
              let e4 = t3, n3 = this;
              for (; r3 > i; ) r3 & o && (e4 = e4.add(n3)), n3 = n3.double(), r3 >>= o;
              return e4;
            }
            let { k1neg: n2, k1: s2, k2neg: a2, k2: c2 } = f.splitScalar(r3), u2 = t3, d2 = t3, h2 = this;
            for (; s2 > i || c2 > i; ) s2 & o && (u2 = u2.add(h2)), c2 & o && (d2 = d2.add(h2)), h2 = h2.double(), s2 >>= o, c2 >>= o;
            return n2 && (u2 = u2.negate()), a2 && (d2 = d2.negate()), d2 = new w(D(d2.x * f.beta), d2.y, d2.z), u2.add(d2);
          }
          precomputeWindow(e3) {
            const t3 = m ? 128 / e3 + 1 : 256 / e3 + 1, r3 = [];
            let n2 = this, i2 = n2;
            for (let o2 = 0; o2 < t3; o2++) {
              i2 = n2, r3.push(i2);
              for (let t4 = 1; t4 < 2 ** (e3 - 1); t4++) i2 = i2.add(n2), r3.push(i2);
              n2 = i2.double();
            }
            return r3;
          }
          wNAF(e3, t3) {
            !t3 && this.equals(w.BASE) && (t3 = S.BASE);
            const r3 = t3 && t3._WINDOW_SIZE || 1;
            if (256 % r3) throw new Error("Point#wNAF: Invalid precomputation window, must be power of 2");
            let n2 = t3 && A.get(t3);
            n2 || (n2 = this.precomputeWindow(r3), t3 && 1 !== r3 && (n2 = w.normalizeZ(n2), A.set(t3, n2)));
            let i2 = w.ZERO, s2 = w.BASE;
            const a2 = 1 + (m ? 128 / r3 : 256 / r3), c2 = 2 ** (r3 - 1), u2 = BigInt(2 ** r3 - 1), d2 = 2 ** r3, f2 = BigInt(r3);
            for (let t4 = 0; t4 < a2; t4++) {
              const r4 = t4 * c2;
              let a3 = Number(e3 & u2);
              e3 >>= f2, a3 > c2 && (a3 -= d2, e3 += o);
              const h2 = r4, l2 = r4 + Math.abs(a3) - 1, p2 = t4 % 2 != 0, b2 = a3 < 0;
              0 === a3 ? s2 = s2.add(_(p2, n2[h2])) : i2 = i2.add(_(b2, n2[l2]));
            }
            return { p: i2, f: s2 };
          }
          multiply(e3, t3) {
            let r3, n2, i2 = j(e3);
            if (m) {
              const { k1neg: e4, k1: o2, k2neg: s2, k2: a2 } = f.splitScalar(i2);
              let { p: c2, f: u2 } = this.wNAF(o2, t3), { p: d2, f: h2 } = this.wNAF(a2, t3);
              c2 = _(e4, c2), d2 = _(s2, d2), d2 = new w(D(d2.x * f.beta), d2.y, d2.z), r3 = c2.add(d2), n2 = u2.add(h2);
            } else {
              const { p: e4, f: o2 } = this.wNAF(i2, t3);
              r3 = e4, n2 = o2;
            }
            return w.normalizeZ([r3, n2])[0];
          }
          toAffine(e3) {
            const { x: t3, y: r3, z: n2 } = this, i2 = this.equals(w.ZERO);
            null == e3 && (e3 = i2 ? c : H(n2));
            const s2 = e3, a2 = D(s2 * s2), u2 = D(a2 * s2), d2 = D(t3 * a2), f2 = D(r3 * u2), h2 = D(n2 * s2);
            if (i2) return S.ZERO;
            if (h2 !== o) throw new Error("invZ was invalid");
            return new S(d2, f2);
          }
        }
        function _(e3, t3) {
          const r3 = t3.negate();
          return e3 ? r3 : t3;
        }
        w.BASE = new w(u.Gx, u.Gy, o), w.ZERO = new w(i, o, i);
        const A = /* @__PURE__ */ new WeakMap();
        class S {
          constructor(e3, t3) {
            this.x = e3, this.y = t3;
          }
          _setWindowSize(e3) {
            this._WINDOW_SIZE = e3, A.delete(this);
          }
          hasEvenY() {
            return this.y % s === i;
          }
          static fromCompressedHex(e3) {
            const t3 = 32 === e3.length, r3 = N(t3 ? e3 : e3.subarray(1));
            if (!K(r3)) throw new Error("Point is not on curve");
            let n2 = (function(e4) {
              const { P: t4 } = u, r4 = BigInt(6), n3 = BigInt(11), i3 = BigInt(22), o2 = BigInt(23), c3 = BigInt(44), d2 = BigInt(88), f2 = e4 * e4 * e4 % t4, h2 = f2 * f2 * e4 % t4, l2 = F(h2, a) * h2 % t4, p2 = F(l2, a) * h2 % t4, b2 = F(p2, s) * f2 % t4, y2 = F(b2, n3) * b2 % t4, m2 = F(y2, i3) * y2 % t4, g2 = F(m2, c3) * m2 % t4, v2 = F(g2, d2) * g2 % t4, w2 = F(v2, c3) * m2 % t4, _2 = F(w2, a) * h2 % t4, A2 = F(_2, o2) * y2 % t4, S2 = F(A2, r4) * f2 % t4, C2 = F(S2, s);
              if (C2 * C2 % t4 !== e4) throw new Error("Cannot find square root");
              return C2;
            })(y(r3));
            const i2 = (n2 & o) === o;
            t3 ? i2 && (n2 = D(-n2)) : !(1 & ~e3[0]) !== i2 && (n2 = D(-n2));
            const c2 = new S(r3, n2);
            return c2.assertValidity(), c2;
          }
          static fromUncompressedHex(e3) {
            const t3 = N(e3.subarray(1, h + 1)), r3 = N(e3.subarray(h + 1, 2 * h + 1)), n2 = new S(t3, r3);
            return n2.assertValidity(), n2;
          }
          static fromHex(e3) {
            const t3 = L(e3), r3 = t3.length, n2 = t3[0];
            if (r3 === h) return this.fromCompressedHex(t3);
            if (r3 === p && (2 === n2 || 3 === n2)) return this.fromCompressedHex(t3);
            if (r3 === b && 4 === n2) return this.fromUncompressedHex(t3);
            throw new Error(`Point.fromHex: received invalid point. Expected 32-${p} compressed bytes or ${b} uncompressed bytes, not ${r3}`);
          }
          static fromPrivateKey(e3) {
            return S.BASE.multiply(J(e3));
          }
          static fromSignature(e3, t3, r3) {
            const { r: n2, s: i2 } = X(t3);
            if (![0, 1, 2, 3].includes(r3)) throw new Error("Cannot recover: invalid recovery bit");
            const o2 = q(L(e3)), { n: s2 } = u, a2 = 2 === r3 || 3 === r3 ? n2 + s2 : n2, c2 = H(a2, s2), d2 = D(-o2 * c2, s2), f2 = D(i2 * c2, s2), h2 = 1 & r3 ? "03" : "02", l2 = S.fromHex(h2 + B(a2)), p2 = S.BASE.multiplyAndAddUnsafe(l2, d2, f2);
            if (!p2) throw new Error("Cannot recover signature: point at infinify");
            return p2.assertValidity(), p2;
          }
          toRawBytes(e3 = false) {
            return R(this.toHex(e3));
          }
          toHex(e3 = false) {
            const t3 = B(this.x);
            return e3 ? `${this.hasEvenY() ? "02" : "03"}${t3}` : `04${t3}${B(this.y)}`;
          }
          toHexX() {
            return this.toHex(true).slice(2);
          }
          toRawX() {
            return this.toRawBytes(true).slice(1);
          }
          assertValidity() {
            const e3 = "Point is not on elliptic curve", { x: t3, y: r3 } = this;
            if (!K(t3) || !K(r3)) throw new Error(e3);
            const n2 = D(r3 * r3);
            if (D(n2 - y(t3)) !== i) throw new Error(e3);
          }
          equals(e3) {
            return this.x === e3.x && this.y === e3.y;
          }
          negate() {
            return new S(this.x, D(-this.y));
          }
          double() {
            return w.fromAffine(this).double().toAffine();
          }
          add(e3) {
            return w.fromAffine(this).add(w.fromAffine(e3)).toAffine();
          }
          subtract(e3) {
            return this.add(e3.negate());
          }
          multiply(e3) {
            return w.fromAffine(this).multiply(e3, this).toAffine();
          }
          multiplyAndAddUnsafe(e3, t3, r3) {
            const n2 = w.fromAffine(this), s2 = t3 === i || t3 === o || this !== S.BASE ? n2.multiplyUnsafe(t3) : n2.multiply(t3), a2 = w.fromAffine(e3).multiplyUnsafe(r3), c2 = s2.add(a2);
            return c2.equals(w.ZERO) ? void 0 : c2.toAffine();
          }
        }
        function C(e3) {
          return Number.parseInt(e3[0], 16) >= 8 ? "00" + e3 : e3;
        }
        function T(e3) {
          if (e3.length < 2 || 2 !== e3[0]) throw new Error(`Invalid signature integer tag: ${x(e3)}`);
          const t3 = e3[1], r3 = e3.subarray(2, t3 + 2);
          if (!t3 || r3.length !== t3) throw new Error("Invalid signature integer: wrong length");
          if (0 === r3[0] && r3[1] <= 127) throw new Error("Invalid signature integer: trailing length");
          return { data: N(r3), left: e3.subarray(t3 + 2) };
        }
        t2.Point = S, S.BASE = new S(u.Gx, u.Gy), S.ZERO = new S(i, i);
        class M {
          constructor(e3, t3) {
            this.r = e3, this.s = t3, this.assertValidity();
          }
          static fromCompact(e3) {
            const t3 = e3 instanceof Uint8Array, r3 = "Signature.fromCompact";
            if ("string" != typeof e3 && !t3) throw new TypeError(`${r3}: Expected string or Uint8Array`);
            const n2 = t3 ? x(e3) : e3;
            if (128 !== n2.length) throw new Error(`${r3}: Expected 64-byte hex`);
            return new M(O(n2.slice(0, 64)), O(n2.slice(64, 128)));
          }
          static fromDER(e3) {
            const t3 = e3 instanceof Uint8Array;
            if ("string" != typeof e3 && !t3) throw new TypeError("Signature.fromDER: Expected string or Uint8Array");
            const { r: r3, s: n2 } = (function(e4) {
              if (e4.length < 2 || 48 != e4[0]) throw new Error(`Invalid signature tag: ${x(e4)}`);
              if (e4[1] !== e4.length - 2) throw new Error("Invalid signature: incorrect length");
              const { data: t4, left: r4 } = T(e4.subarray(2)), { data: n3, left: i2 } = T(r4);
              if (i2.length) throw new Error(`Invalid signature: left bytes after parsing: ${x(i2)}`);
              return { r: t4, s: n3 };
            })(t3 ? e3 : R(e3));
            return new M(r3, n2);
          }
          static fromHex(e3) {
            return this.fromDER(e3);
          }
          assertValidity() {
            const { r: e3, s: t3 } = this;
            if (!z(e3)) throw new Error("Invalid Signature: r must be 0 < r < n");
            if (!z(t3)) throw new Error("Invalid Signature: s must be 0 < s < n");
          }
          hasHighS() {
            const e3 = u.n >> o;
            return this.s > e3;
          }
          normalizeS() {
            return this.hasHighS() ? new M(this.r, D(-this.s, u.n)) : this;
          }
          toDERRawBytes() {
            return R(this.toDERHex());
          }
          toDERHex() {
            const e3 = C(P(this.s)), t3 = C(P(this.r)), r3 = e3.length / 2, n2 = t3.length / 2, i2 = P(r3), o2 = P(n2);
            return `30${P(n2 + r3 + 4)}02${o2}${t3}02${i2}${e3}`;
          }
          toRawBytes() {
            return this.toDERRawBytes();
          }
          toHex() {
            return this.toDERHex();
          }
          toCompactRawBytes() {
            return R(this.toCompactHex());
          }
          toCompactHex() {
            return B(this.r) + B(this.s);
          }
        }
        function E(...e3) {
          if (!e3.every(((e4) => e4 instanceof Uint8Array))) throw new Error("Uint8Array list expected");
          if (1 === e3.length) return e3[0];
          const t3 = e3.reduce(((e4, t4) => e4 + t4.length), 0), r3 = new Uint8Array(t3);
          for (let t4 = 0, n2 = 0; t4 < e3.length; t4++) {
            const i2 = e3[t4];
            r3.set(i2, n2), n2 += i2.length;
          }
          return r3;
        }
        t2.Signature = M;
        const k = Array.from({ length: 256 }, ((e3, t3) => t3.toString(16).padStart(2, "0")));
        function x(e3) {
          if (!(e3 instanceof Uint8Array)) throw new Error("Expected Uint8Array");
          let t3 = "";
          for (let r3 = 0; r3 < e3.length; r3++) t3 += k[e3[r3]];
          return t3;
        }
        const I = BigInt("0x10000000000000000000000000000000000000000000000000000000000000000");
        function B(e3) {
          if ("bigint" != typeof e3) throw new Error("Expected bigint");
          if (!(i <= e3 && e3 < I)) throw new Error("Expected number 0 <= n < 2^256");
          return e3.toString(16).padStart(64, "0");
        }
        function U(e3) {
          const t3 = R(B(e3));
          if (32 !== t3.length) throw new Error("Error: expected 32 bytes");
          return t3;
        }
        function P(e3) {
          const t3 = e3.toString(16);
          return 1 & t3.length ? `0${t3}` : t3;
        }
        function O(e3) {
          if ("string" != typeof e3) throw new TypeError("hexToNumber: expected string, got " + typeof e3);
          return BigInt(`0x${e3}`);
        }
        function R(e3) {
          if ("string" != typeof e3) throw new TypeError("hexToBytes: expected string, got " + typeof e3);
          if (e3.length % 2) throw new Error("hexToBytes: received invalid unpadded hex" + e3.length);
          const t3 = new Uint8Array(e3.length / 2);
          for (let r3 = 0; r3 < t3.length; r3++) {
            const n2 = 2 * r3, i2 = e3.slice(n2, n2 + 2), o2 = Number.parseInt(i2, 16);
            if (Number.isNaN(o2) || o2 < 0) throw new Error("Invalid byte sequence");
            t3[r3] = o2;
          }
          return t3;
        }
        function N(e3) {
          return O(x(e3));
        }
        function L(e3) {
          return e3 instanceof Uint8Array ? Uint8Array.from(e3) : R(e3);
        }
        function j(e3) {
          if ("number" == typeof e3 && Number.isSafeInteger(e3) && e3 > 0) return BigInt(e3);
          if ("bigint" == typeof e3 && z(e3)) return e3;
          throw new TypeError("Expected valid private scalar: 0 < scalar < curve.n");
        }
        function D(e3, t3 = u.P) {
          const r3 = e3 % t3;
          return r3 >= i ? r3 : t3 + r3;
        }
        function F(e3, t3) {
          const { P: r3 } = u;
          let n2 = e3;
          for (; t3-- > i; ) n2 *= n2, n2 %= r3;
          return n2;
        }
        function H(e3, t3 = u.P) {
          if (e3 === i || t3 <= i) throw new Error(`invert: expected positive integers, got n=${e3} mod=${t3}`);
          let r3 = D(e3, t3), n2 = t3, s2 = i, a2 = o, c2 = o, d2 = i;
          for (; r3 !== i; ) {
            const e4 = n2 / r3, t4 = n2 % r3, i2 = s2 - c2 * e4, o2 = a2 - d2 * e4;
            n2 = r3, r3 = t4, s2 = c2, a2 = d2, c2 = i2, d2 = o2;
          }
          if (n2 !== o) throw new Error("invert: does not exist");
          return D(s2, t3);
        }
        function q(e3, t3 = false) {
          const r3 = (function(e4) {
            const t4 = 8 * e4.length - 8 * l, r4 = N(e4);
            return t4 > 0 ? r4 >> BigInt(t4) : r4;
          })(e3);
          if (t3) return r3;
          const { n: n2 } = u;
          return r3 >= n2 ? r3 - n2 : r3;
        }
        let $, V;
        class G {
          constructor(e3, t3) {
            if (this.hashLen = e3, this.qByteLen = t3, "number" != typeof e3 || e3 < 2) throw new Error("hashLen must be a number");
            if ("number" != typeof t3 || t3 < 2) throw new Error("qByteLen must be a number");
            this.v = new Uint8Array(e3).fill(1), this.k = new Uint8Array(e3).fill(0), this.counter = 0;
          }
          hmac(...e3) {
            return t2.utils.hmacSha256(this.k, ...e3);
          }
          hmacSync(...e3) {
            return V(this.k, ...e3);
          }
          checkSync() {
            if ("function" != typeof V) throw new g("hmacSha256Sync needs to be set");
          }
          incr() {
            if (this.counter >= 1e3) throw new Error("Tried 1,000 k values for sign(), all were invalid");
            this.counter += 1;
          }
          async reseed(e3 = new Uint8Array()) {
            this.k = await this.hmac(this.v, Uint8Array.from([0]), e3), this.v = await this.hmac(this.v), 0 !== e3.length && (this.k = await this.hmac(this.v, Uint8Array.from([1]), e3), this.v = await this.hmac(this.v));
          }
          reseedSync(e3 = new Uint8Array()) {
            this.checkSync(), this.k = this.hmacSync(this.v, Uint8Array.from([0]), e3), this.v = this.hmacSync(this.v), 0 !== e3.length && (this.k = this.hmacSync(this.v, Uint8Array.from([1]), e3), this.v = this.hmacSync(this.v));
          }
          async generate() {
            this.incr();
            let e3 = 0;
            const t3 = [];
            for (; e3 < this.qByteLen; ) {
              this.v = await this.hmac(this.v);
              const r3 = this.v.slice();
              t3.push(r3), e3 += this.v.length;
            }
            return E(...t3);
          }
          generateSync() {
            this.checkSync(), this.incr();
            let e3 = 0;
            const t3 = [];
            for (; e3 < this.qByteLen; ) {
              this.v = this.hmacSync(this.v);
              const r3 = this.v.slice();
              t3.push(r3), e3 += this.v.length;
            }
            return E(...t3);
          }
        }
        function z(e3) {
          return i < e3 && e3 < u.n;
        }
        function K(e3) {
          return i < e3 && e3 < u.P;
        }
        function W(e3, t3, r3, n2 = true) {
          const { n: s2 } = u, a2 = q(e3, true);
          if (!z(a2)) return;
          const c2 = H(a2, s2), d2 = S.BASE.multiply(a2), f2 = D(d2.x, s2);
          if (f2 === i) return;
          const h2 = D(c2 * D(t3 + r3 * f2, s2), s2);
          if (h2 === i) return;
          let l2 = new M(f2, h2), p2 = (d2.x === l2.r ? 0 : 2) | Number(d2.y & o);
          return n2 && l2.hasHighS() && (l2 = l2.normalizeS(), p2 ^= 1), { sig: l2, recovery: p2 };
        }
        function J(e3) {
          let t3;
          if ("bigint" == typeof e3) t3 = e3;
          else if ("number" == typeof e3 && Number.isSafeInteger(e3) && e3 > 0) t3 = BigInt(e3);
          else if ("string" == typeof e3) {
            if (e3.length !== 2 * l) throw new Error("Expected 32 bytes of private key");
            t3 = O(e3);
          } else {
            if (!(e3 instanceof Uint8Array)) throw new TypeError("Expected valid private key");
            if (e3.length !== l) throw new Error("Expected 32 bytes of private key");
            t3 = N(e3);
          }
          if (!z(t3)) throw new Error("Expected private key: 0 < key < n");
          return t3;
        }
        function Z(e3) {
          return e3 instanceof S ? (e3.assertValidity(), e3) : S.fromHex(e3);
        }
        function X(e3) {
          if (e3 instanceof M) return e3.assertValidity(), e3;
          try {
            return M.fromDER(e3);
          } catch (t3) {
            return M.fromCompact(e3);
          }
        }
        function Y(e3) {
          const t3 = e3 instanceof Uint8Array, r3 = "string" == typeof e3, n2 = (t3 || r3) && e3.length;
          return t3 ? n2 === p || n2 === b : r3 ? n2 === 2 * p || n2 === 2 * b : e3 instanceof S;
        }
        function Q(e3) {
          return N(e3.length > h ? e3.slice(0, h) : e3);
        }
        function ee(e3) {
          const t3 = Q(e3), r3 = D(t3, u.n);
          return te(r3 < i ? t3 : r3);
        }
        function te(e3) {
          return U(e3);
        }
        function re(e3, r3, n2) {
          if (null == e3) throw new Error(`sign: expected valid message hash, not "${e3}"`);
          const i2 = L(e3), o2 = J(r3), s2 = [te(o2), ee(i2)];
          if (null != n2) {
            true === n2 && (n2 = t2.utils.randomBytes(h));
            const e4 = L(n2);
            if (e4.length !== h) throw new Error(`sign: Expected ${h} bytes of extra data`);
            s2.push(e4);
          }
          return { seed: E(...s2), m: Q(i2), d: o2 };
        }
        function ne(e3, t3) {
          const { sig: r3, recovery: n2 } = e3, { der: i2, recovered: o2 } = Object.assign({ canonical: true, der: true }, t3), s2 = i2 ? r3.toDERRawBytes() : r3.toCompactRawBytes();
          return o2 ? [s2, n2] : s2;
        }
        t2.getPublicKey = function(e3, t3 = false) {
          return S.fromPrivateKey(e3).toRawBytes(t3);
        }, t2.recoverPublicKey = function(e3, t3, r3, n2 = false) {
          return S.fromSignature(e3, t3, r3).toRawBytes(n2);
        }, t2.getSharedSecret = function(e3, t3, r3 = false) {
          if (Y(e3)) throw new TypeError("getSharedSecret: first arg must be private key");
          if (!Y(t3)) throw new TypeError("getSharedSecret: second arg must be public key");
          const n2 = Z(t3);
          return n2.assertValidity(), n2.multiply(J(e3)).toRawBytes(r3);
        }, t2.sign = async function(e3, t3, r3 = {}) {
          const { seed: n2, m: i2, d: o2 } = re(e3, t3, r3.extraEntropy), s2 = new G(32, l);
          let a2;
          for (await s2.reseed(n2); !(a2 = W(await s2.generate(), i2, o2, r3.canonical)); ) await s2.reseed();
          return ne(a2, r3);
        }, t2.signSync = function(e3, t3, r3 = {}) {
          const { seed: n2, m: i2, d: o2 } = re(e3, t3, r3.extraEntropy), s2 = new G(32, l);
          let a2;
          for (s2.reseedSync(n2); !(a2 = W(s2.generateSync(), i2, o2, r3.canonical)); ) s2.reseedSync();
          return ne(a2, r3);
        };
        const ie = { strict: true };
        function oe(e3) {
          return D(N(e3), u.n);
        }
        t2.verify = function(e3, t3, r3, n2 = ie) {
          let i2;
          try {
            i2 = X(e3), t3 = L(t3);
          } catch (e4) {
            return false;
          }
          const { r: o2, s: s2 } = i2;
          if (n2.strict && i2.hasHighS()) return false;
          const a2 = q(t3);
          let c2;
          try {
            c2 = Z(r3);
          } catch (e4) {
            return false;
          }
          const { n: d2 } = u, f2 = H(s2, d2), h2 = D(a2 * f2, d2), l2 = D(o2 * f2, d2), p2 = S.BASE.multiplyAndAddUnsafe(c2, h2, l2);
          return !!p2 && D(p2.x, d2) === o2;
        };
        class se {
          constructor(e3, t3) {
            this.r = e3, this.s = t3, this.assertValidity();
          }
          static fromHex(e3) {
            const t3 = L(e3);
            if (64 !== t3.length) throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${t3.length}`);
            const r3 = N(t3.subarray(0, 32)), n2 = N(t3.subarray(32, 64));
            return new se(r3, n2);
          }
          assertValidity() {
            const { r: e3, s: t3 } = this;
            if (!K(e3) || !z(t3)) throw new Error("Invalid signature");
          }
          toHex() {
            return B(this.r) + B(this.s);
          }
          toRawBytes() {
            return R(this.toHex());
          }
        }
        class ae {
          constructor(e3, r3, n2 = t2.utils.randomBytes()) {
            if (null == e3) throw new TypeError(`sign: Expected valid message, not "${e3}"`);
            this.m = L(e3);
            const { x: i2, scalar: o2 } = this.getScalar(J(r3));
            if (this.px = i2, this.d = o2, this.rand = L(n2), 32 !== this.rand.length) throw new TypeError("sign: Expected 32 bytes of aux randomness");
          }
          getScalar(e3) {
            const t3 = S.fromPrivateKey(e3), r3 = t3.hasEvenY() ? e3 : u.n - e3;
            return { point: t3, scalar: r3, x: t3.toRawX() };
          }
          initNonce(e3, t3) {
            return U(e3 ^ N(t3));
          }
          finalizeNonce(e3) {
            const t3 = D(N(e3), u.n);
            if (t3 === i) throw new Error("sign: Creation of signature failed. k is zero");
            const { point: r3, x: n2, scalar: o2 } = this.getScalar(t3);
            return { R: r3, rx: n2, k: o2 };
          }
          finalizeSig(e3, t3, r3, n2) {
            return new se(e3.x, D(t3 + r3 * n2, u.n)).toRawBytes();
          }
          error() {
            throw new Error("sign: Invalid signature produced");
          }
          async calc() {
            const { m: e3, d: r3, px: n2, rand: i2 } = this, o2 = t2.utils.taggedHash, s2 = this.initNonce(r3, await o2(le.aux, i2)), { R: a2, rx: c2, k: u2 } = this.finalizeNonce(await o2(le.nonce, s2, n2, e3)), d2 = oe(await o2(le.challenge, c2, n2, e3)), f2 = this.finalizeSig(a2, u2, d2, r3);
            return await de(f2, e3, n2) || this.error(), f2;
          }
          calcSync() {
            const { m: e3, d: r3, px: n2, rand: i2 } = this, o2 = t2.utils.taggedHashSync, s2 = this.initNonce(r3, o2(le.aux, i2)), { R: a2, rx: c2, k: u2 } = this.finalizeNonce(o2(le.nonce, s2, n2, e3)), d2 = oe(o2(le.challenge, c2, n2, e3)), f2 = this.finalizeSig(a2, u2, d2, r3);
            return fe(f2, e3, n2) || this.error(), f2;
          }
        }
        function ce(e3, t3, r3) {
          const n2 = e3 instanceof se, i2 = n2 ? e3 : se.fromHex(e3);
          return n2 && i2.assertValidity(), { ...i2, m: L(t3), P: Z(r3) };
        }
        function ue(e3, t3, r3, n2) {
          const i2 = S.BASE.multiplyAndAddUnsafe(t3, J(r3), D(-n2, u.n));
          return !(!i2 || !i2.hasEvenY() || i2.x !== e3);
        }
        async function de(e3, r3, n2) {
          try {
            const { r: i2, s: o2, m: s2, P: a2 } = ce(e3, r3, n2), c2 = oe(await t2.utils.taggedHash(le.challenge, U(i2), a2.toRawX(), s2));
            return ue(i2, a2, o2, c2);
          } catch (e4) {
            return false;
          }
        }
        function fe(e3, r3, n2) {
          try {
            const { r: i2, s: o2, m: s2, P: a2 } = ce(e3, r3, n2), c2 = oe(t2.utils.taggedHashSync(le.challenge, U(i2), a2.toRawX(), s2));
            return ue(i2, a2, o2, c2);
          } catch (e4) {
            if (e4 instanceof g) throw e4;
            return false;
          }
        }
        t2.schnorr = { Signature: se, getPublicKey: function(e3) {
          return S.fromPrivateKey(e3).toRawX();
        }, sign: async function(e3, t3, r3) {
          return new ae(e3, t3, r3).calc();
        }, verify: de, signSync: function(e3, t3, r3) {
          return new ae(e3, t3, r3).calcSync();
        }, verifySync: fe }, S.BASE._setWindowSize(8);
        const he = { node: n, web: "object" == typeof self && "crypto" in self ? self.crypto : void 0 }, le = { challenge: "BIP0340/challenge", aux: "BIP0340/aux", nonce: "BIP0340/nonce" }, pe = {};
        t2.utils = { bytesToHex: x, hexToBytes: R, concatBytes: E, mod: D, invert: H, isValidPrivateKey(e3) {
          try {
            return J(e3), true;
          } catch (e4) {
            return false;
          }
        }, _bigintTo32Bytes: U, _normalizePrivateKey: J, hashToPrivateKey: (e3) => {
          e3 = L(e3);
          const t3 = l + 8;
          if (e3.length < t3 || e3.length > 1024) throw new Error("Expected valid bytes of private key as per FIPS 186");
          return U(D(N(e3), u.n - o) + o);
        }, randomBytes: (e3 = 32) => {
          if (he.web) return he.web.getRandomValues(new Uint8Array(e3));
          if (he.node) {
            const { randomBytes: t3 } = he.node;
            return Uint8Array.from(t3(e3));
          }
          throw new Error("The environment doesn't have randomBytes function");
        }, randomPrivateKey: () => t2.utils.hashToPrivateKey(t2.utils.randomBytes(l + 8)), precompute(e3 = 8, t3 = S.BASE) {
          const r3 = t3 === S.BASE ? t3 : new S(t3.x, t3.y);
          return r3._setWindowSize(e3), r3.multiply(a), r3;
        }, sha256: async (...e3) => {
          if (he.web) {
            const t3 = await he.web.subtle.digest("SHA-256", E(...e3));
            return new Uint8Array(t3);
          }
          if (he.node) {
            const { createHash: t3 } = he.node, r3 = t3("sha256");
            return e3.forEach(((e4) => r3.update(e4))), Uint8Array.from(r3.digest());
          }
          throw new Error("The environment doesn't have sha256 function");
        }, hmacSha256: async (e3, ...t3) => {
          if (he.web) {
            const r3 = await he.web.subtle.importKey("raw", e3, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"]), n2 = E(...t3), i2 = await he.web.subtle.sign("HMAC", r3, n2);
            return new Uint8Array(i2);
          }
          if (he.node) {
            const { createHmac: r3 } = he.node, n2 = r3("sha256", e3);
            return t3.forEach(((e4) => n2.update(e4))), Uint8Array.from(n2.digest());
          }
          throw new Error("The environment doesn't have hmac-sha256 function");
        }, sha256Sync: void 0, hmacSha256Sync: void 0, taggedHash: async (e3, ...r3) => {
          let n2 = pe[e3];
          if (void 0 === n2) {
            const r4 = await t2.utils.sha256(Uint8Array.from(e3, ((e4) => e4.charCodeAt(0))));
            n2 = E(r4, r4), pe[e3] = n2;
          }
          return t2.utils.sha256(n2, ...r3);
        }, taggedHashSync: (e3, ...t3) => {
          if ("function" != typeof $) throw new g("sha256Sync is undefined, you need to set it");
          let r3 = pe[e3];
          if (void 0 === r3) {
            const t4 = $(Uint8Array.from(e3, ((e4) => e4.charCodeAt(0))));
            r3 = E(t4, t4), pe[e3] = r3;
          }
          return $(r3, ...t3);
        }, _JacobianPoint: w }, Object.defineProperties(t2.utils, { sha256Sync: { configurable: false, get: () => $, set(e3) {
          $ || ($ = e3);
        } }, hmacSha256Sync: { configurable: false, get: () => V, set(e3) {
          V || (V = e3);
        } } });
      }, 5737: (e2, t2, r2) => {
        "use strict";
        const n = t2;
        n.bignum = r2(4619), n.define = r2(4082).define, n.base = r2(7594), n.constants = r2(6876), n.decoders = r2(5126), n.encoders = r2(122);
      }, 4082: (e2, t2, r2) => {
        "use strict";
        const n = r2(122), i = r2(5126), o = r2(1193);
        function s(e3, t3) {
          this.name = e3, this.body = t3, this.decoders = {}, this.encoders = {};
        }
        t2.define = function(e3, t3) {
          return new s(e3, t3);
        }, s.prototype._createNamed = function(e3) {
          const t3 = this.name;
          function r3(e4) {
            this._initNamed(e4, t3);
          }
          return o(r3, e3), r3.prototype._initNamed = function(t4, r4) {
            e3.call(this, t4, r4);
          }, new r3(this);
        }, s.prototype._getDecoder = function(e3) {
          return e3 = e3 || "der", this.decoders.hasOwnProperty(e3) || (this.decoders[e3] = this._createNamed(i[e3])), this.decoders[e3];
        }, s.prototype.decode = function(e3, t3, r3) {
          return this._getDecoder(t3).decode(e3, r3);
        }, s.prototype._getEncoder = function(e3) {
          return e3 = e3 || "der", this.encoders.hasOwnProperty(e3) || (this.encoders[e3] = this._createNamed(n[e3])), this.encoders[e3];
        }, s.prototype.encode = function(e3, t3, r3) {
          return this._getEncoder(t3).encode(e3, r3);
        };
      }, 3802: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193), i = r2(8657).a, o = r2(1628).Buffer;
        function s(e3, t3) {
          i.call(this, t3), o.isBuffer(e3) ? (this.base = e3, this.offset = 0, this.length = e3.length) : this.error("Input not Buffer");
        }
        function a(e3, t3) {
          if (Array.isArray(e3)) this.length = 0, this.value = e3.map((function(e4) {
            return a.isEncoderBuffer(e4) || (e4 = new a(e4, t3)), this.length += e4.length, e4;
          }), this);
          else if ("number" == typeof e3) {
            if (!(0 <= e3 && e3 <= 255)) return t3.error("non-byte EncoderBuffer value");
            this.value = e3, this.length = 1;
          } else if ("string" == typeof e3) this.value = e3, this.length = o.byteLength(e3);
          else {
            if (!o.isBuffer(e3)) return t3.error("Unsupported type: " + typeof e3);
            this.value = e3, this.length = e3.length;
          }
        }
        n(s, i), t2.t = s, s.isDecoderBuffer = function(e3) {
          return e3 instanceof s || "object" == typeof e3 && o.isBuffer(e3.base) && "DecoderBuffer" === e3.constructor.name && "number" == typeof e3.offset && "number" == typeof e3.length && "function" == typeof e3.save && "function" == typeof e3.restore && "function" == typeof e3.isEmpty && "function" == typeof e3.readUInt8 && "function" == typeof e3.skip && "function" == typeof e3.raw;
        }, s.prototype.save = function() {
          return { offset: this.offset, reporter: i.prototype.save.call(this) };
        }, s.prototype.restore = function(e3) {
          const t3 = new s(this.base);
          return t3.offset = e3.offset, t3.length = this.offset, this.offset = e3.offset, i.prototype.restore.call(this, e3.reporter), t3;
        }, s.prototype.isEmpty = function() {
          return this.offset === this.length;
        }, s.prototype.readUInt8 = function(e3) {
          return this.offset + 1 <= this.length ? this.base.readUInt8(this.offset++, true) : this.error(e3 || "DecoderBuffer overrun");
        }, s.prototype.skip = function(e3, t3) {
          if (!(this.offset + e3 <= this.length)) return this.error(t3 || "DecoderBuffer overrun");
          const r3 = new s(this.base);
          return r3._reporterState = this._reporterState, r3.offset = this.offset, r3.length = this.offset + e3, this.offset += e3, r3;
        }, s.prototype.raw = function(e3) {
          return this.base.slice(e3 ? e3.offset : this.offset, this.length);
        }, t2.d = a, a.isEncoderBuffer = function(e3) {
          return e3 instanceof a || "object" == typeof e3 && "EncoderBuffer" === e3.constructor.name && "number" == typeof e3.length && "function" == typeof e3.join;
        }, a.prototype.join = function(e3, t3) {
          return e3 || (e3 = o.alloc(this.length)), t3 || (t3 = 0), 0 === this.length || (Array.isArray(this.value) ? this.value.forEach((function(r3) {
            r3.join(e3, t3), t3 += r3.length;
          })) : ("number" == typeof this.value ? e3[t3] = this.value : "string" == typeof this.value ? e3.write(this.value, t3) : o.isBuffer(this.value) && this.value.copy(e3, t3), t3 += this.length)), e3;
        };
      }, 7594: (e2, t2, r2) => {
        "use strict";
        const n = t2;
        n.Reporter = r2(8657).a, n.DecoderBuffer = r2(3802).t, n.EncoderBuffer = r2(3802).d, n.Node = r2(2144);
      }, 2144: (e2, t2, r2) => {
        "use strict";
        const n = r2(8657).a, i = r2(3802).d, o = r2(3802).t, s = r2(5578), a = ["seq", "seqof", "set", "setof", "objid", "bool", "gentime", "utctime", "null_", "enum", "int", "objDesc", "bitstr", "bmpstr", "charstr", "genstr", "graphstr", "ia5str", "iso646str", "numstr", "octstr", "printstr", "t61str", "unistr", "utf8str", "videostr"], c = ["key", "obj", "use", "optional", "explicit", "implicit", "def", "choice", "any", "contains"].concat(a);
        function u(e3, t3, r3) {
          const n2 = {};
          this._baseState = n2, n2.name = r3, n2.enc = e3, n2.parent = t3 || null, n2.children = null, n2.tag = null, n2.args = null, n2.reverseArgs = null, n2.choice = null, n2.optional = false, n2.any = false, n2.obj = false, n2.use = null, n2.useDecoder = null, n2.key = null, n2.default = null, n2.explicit = null, n2.implicit = null, n2.contains = null, n2.parent || (n2.children = [], this._wrap());
        }
        e2.exports = u;
        const d = ["enc", "parent", "children", "tag", "args", "reverseArgs", "choice", "optional", "any", "obj", "use", "alteredUse", "key", "default", "explicit", "implicit", "contains"];
        u.prototype.clone = function() {
          const e3 = this._baseState, t3 = {};
          d.forEach((function(r4) {
            t3[r4] = e3[r4];
          }));
          const r3 = new this.constructor(t3.parent);
          return r3._baseState = t3, r3;
        }, u.prototype._wrap = function() {
          const e3 = this._baseState;
          c.forEach((function(t3) {
            this[t3] = function() {
              const r3 = new this.constructor(this);
              return e3.children.push(r3), r3[t3].apply(r3, arguments);
            };
          }), this);
        }, u.prototype._init = function(e3) {
          const t3 = this._baseState;
          s(null === t3.parent), e3.call(this), t3.children = t3.children.filter((function(e4) {
            return e4._baseState.parent === this;
          }), this), s.equal(t3.children.length, 1, "Root node can have only one child");
        }, u.prototype._useArgs = function(e3) {
          const t3 = this._baseState, r3 = e3.filter((function(e4) {
            return e4 instanceof this.constructor;
          }), this);
          e3 = e3.filter((function(e4) {
            return !(e4 instanceof this.constructor);
          }), this), 0 !== r3.length && (s(null === t3.children), t3.children = r3, r3.forEach((function(e4) {
            e4._baseState.parent = this;
          }), this)), 0 !== e3.length && (s(null === t3.args), t3.args = e3, t3.reverseArgs = e3.map((function(e4) {
            if ("object" != typeof e4 || e4.constructor !== Object) return e4;
            const t4 = {};
            return Object.keys(e4).forEach((function(r4) {
              r4 == (0 | r4) && (r4 |= 0);
              const n2 = e4[r4];
              t4[n2] = r4;
            })), t4;
          })));
        }, ["_peekTag", "_decodeTag", "_use", "_decodeStr", "_decodeObjid", "_decodeTime", "_decodeNull", "_decodeInt", "_decodeBool", "_decodeList", "_encodeComposite", "_encodeStr", "_encodeObjid", "_encodeTime", "_encodeNull", "_encodeInt", "_encodeBool"].forEach((function(e3) {
          u.prototype[e3] = function() {
            const t3 = this._baseState;
            throw new Error(e3 + " not implemented for encoding: " + t3.enc);
          };
        })), a.forEach((function(e3) {
          u.prototype[e3] = function() {
            const t3 = this._baseState, r3 = Array.prototype.slice.call(arguments);
            return s(null === t3.tag), t3.tag = e3, this._useArgs(r3), this;
          };
        })), u.prototype.use = function(e3) {
          s(e3);
          const t3 = this._baseState;
          return s(null === t3.use), t3.use = e3, this;
        }, u.prototype.optional = function() {
          return this._baseState.optional = true, this;
        }, u.prototype.def = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.default), t3.default = e3, t3.optional = true, this;
        }, u.prototype.explicit = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.explicit && null === t3.implicit), t3.explicit = e3, this;
        }, u.prototype.implicit = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.explicit && null === t3.implicit), t3.implicit = e3, this;
        }, u.prototype.obj = function() {
          const e3 = this._baseState, t3 = Array.prototype.slice.call(arguments);
          return e3.obj = true, 0 !== t3.length && this._useArgs(t3), this;
        }, u.prototype.key = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.key), t3.key = e3, this;
        }, u.prototype.any = function() {
          return this._baseState.any = true, this;
        }, u.prototype.choice = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.choice), t3.choice = e3, this._useArgs(Object.keys(e3).map((function(t4) {
            return e3[t4];
          }))), this;
        }, u.prototype.contains = function(e3) {
          const t3 = this._baseState;
          return s(null === t3.use), t3.contains = e3, this;
        }, u.prototype._decode = function(e3, t3) {
          const r3 = this._baseState;
          if (null === r3.parent) return e3.wrapResult(r3.children[0]._decode(e3, t3));
          let n2, i2 = r3.default, s2 = true, a2 = null;
          if (null !== r3.key && (a2 = e3.enterKey(r3.key)), r3.optional) {
            let n3 = null;
            if (null !== r3.explicit ? n3 = r3.explicit : null !== r3.implicit ? n3 = r3.implicit : null !== r3.tag && (n3 = r3.tag), null !== n3 || r3.any) {
              if (s2 = this._peekTag(e3, n3, r3.any), e3.isError(s2)) return s2;
            } else {
              const n4 = e3.save();
              try {
                null === r3.choice ? this._decodeGeneric(r3.tag, e3, t3) : this._decodeChoice(e3, t3), s2 = true;
              } catch (e4) {
                s2 = false;
              }
              e3.restore(n4);
            }
          }
          if (r3.obj && s2 && (n2 = e3.enterObject()), s2) {
            if (null !== r3.explicit) {
              const t4 = this._decodeTag(e3, r3.explicit);
              if (e3.isError(t4)) return t4;
              e3 = t4;
            }
            const n3 = e3.offset;
            if (null === r3.use && null === r3.choice) {
              let t4;
              r3.any && (t4 = e3.save());
              const n4 = this._decodeTag(e3, null !== r3.implicit ? r3.implicit : r3.tag, r3.any);
              if (e3.isError(n4)) return n4;
              r3.any ? i2 = e3.raw(t4) : e3 = n4;
            }
            if (t3 && t3.track && null !== r3.tag && t3.track(e3.path(), n3, e3.length, "tagged"), t3 && t3.track && null !== r3.tag && t3.track(e3.path(), e3.offset, e3.length, "content"), r3.any || (i2 = null === r3.choice ? this._decodeGeneric(r3.tag, e3, t3) : this._decodeChoice(e3, t3)), e3.isError(i2)) return i2;
            if (r3.any || null !== r3.choice || null === r3.children || r3.children.forEach((function(r4) {
              r4._decode(e3, t3);
            })), r3.contains && ("octstr" === r3.tag || "bitstr" === r3.tag)) {
              const n4 = new o(i2);
              i2 = this._getUse(r3.contains, e3._reporterState.obj)._decode(n4, t3);
            }
          }
          return r3.obj && s2 && (i2 = e3.leaveObject(n2)), null === r3.key || null === i2 && true !== s2 ? null !== a2 && e3.exitKey(a2) : e3.leaveKey(a2, r3.key, i2), i2;
        }, u.prototype._decodeGeneric = function(e3, t3, r3) {
          const n2 = this._baseState;
          return "seq" === e3 || "set" === e3 ? null : "seqof" === e3 || "setof" === e3 ? this._decodeList(t3, e3, n2.args[0], r3) : /str$/.test(e3) ? this._decodeStr(t3, e3, r3) : "objid" === e3 && n2.args ? this._decodeObjid(t3, n2.args[0], n2.args[1], r3) : "objid" === e3 ? this._decodeObjid(t3, null, null, r3) : "gentime" === e3 || "utctime" === e3 ? this._decodeTime(t3, e3, r3) : "null_" === e3 ? this._decodeNull(t3, r3) : "bool" === e3 ? this._decodeBool(t3, r3) : "objDesc" === e3 ? this._decodeStr(t3, e3, r3) : "int" === e3 || "enum" === e3 ? this._decodeInt(t3, n2.args && n2.args[0], r3) : null !== n2.use ? this._getUse(n2.use, t3._reporterState.obj)._decode(t3, r3) : t3.error("unknown tag: " + e3);
        }, u.prototype._getUse = function(e3, t3) {
          const r3 = this._baseState;
          return r3.useDecoder = this._use(e3, t3), s(null === r3.useDecoder._baseState.parent), r3.useDecoder = r3.useDecoder._baseState.children[0], r3.implicit !== r3.useDecoder._baseState.implicit && (r3.useDecoder = r3.useDecoder.clone(), r3.useDecoder._baseState.implicit = r3.implicit), r3.useDecoder;
        }, u.prototype._decodeChoice = function(e3, t3) {
          const r3 = this._baseState;
          let n2 = null, i2 = false;
          return Object.keys(r3.choice).some((function(o2) {
            const s2 = e3.save(), a2 = r3.choice[o2];
            try {
              const r4 = a2._decode(e3, t3);
              if (e3.isError(r4)) return false;
              n2 = { type: o2, value: r4 }, i2 = true;
            } catch (t4) {
              return e3.restore(s2), false;
            }
            return true;
          }), this), i2 ? n2 : e3.error("Choice not matched");
        }, u.prototype._createEncoderBuffer = function(e3) {
          return new i(e3, this.reporter);
        }, u.prototype._encode = function(e3, t3, r3) {
          const n2 = this._baseState;
          if (null !== n2.default && n2.default === e3) return;
          const i2 = this._encodeValue(e3, t3, r3);
          return void 0 === i2 || this._skipDefault(i2, t3, r3) ? void 0 : i2;
        }, u.prototype._encodeValue = function(e3, t3, r3) {
          const i2 = this._baseState;
          if (null === i2.parent) return i2.children[0]._encode(e3, t3 || new n());
          let o2 = null;
          if (this.reporter = t3, i2.optional && void 0 === e3) {
            if (null === i2.default) return;
            e3 = i2.default;
          }
          let s2 = null, a2 = false;
          if (i2.any) o2 = this._createEncoderBuffer(e3);
          else if (i2.choice) o2 = this._encodeChoice(e3, t3);
          else if (i2.contains) s2 = this._getUse(i2.contains, r3)._encode(e3, t3), a2 = true;
          else if (i2.children) s2 = i2.children.map((function(r4) {
            if ("null_" === r4._baseState.tag) return r4._encode(null, t3, e3);
            if (null === r4._baseState.key) return t3.error("Child should have a key");
            const n2 = t3.enterKey(r4._baseState.key);
            if ("object" != typeof e3) return t3.error("Child expected, but input is not object");
            const i3 = r4._encode(e3[r4._baseState.key], t3, e3);
            return t3.leaveKey(n2), i3;
          }), this).filter((function(e4) {
            return e4;
          })), s2 = this._createEncoderBuffer(s2);
          else if ("seqof" === i2.tag || "setof" === i2.tag) {
            if (!i2.args || 1 !== i2.args.length) return t3.error("Too many args for : " + i2.tag);
            if (!Array.isArray(e3)) return t3.error("seqof/setof, but data is not Array");
            const r4 = this.clone();
            r4._baseState.implicit = null, s2 = this._createEncoderBuffer(e3.map((function(r5) {
              const n2 = this._baseState;
              return this._getUse(n2.args[0], e3)._encode(r5, t3);
            }), r4));
          } else null !== i2.use ? o2 = this._getUse(i2.use, r3)._encode(e3, t3) : (s2 = this._encodePrimitive(i2.tag, e3), a2 = true);
          if (!i2.any && null === i2.choice) {
            const e4 = null !== i2.implicit ? i2.implicit : i2.tag, r4 = null === i2.implicit ? "universal" : "context";
            null === e4 ? null === i2.use && t3.error("Tag could be omitted only for .use()") : null === i2.use && (o2 = this._encodeComposite(e4, a2, r4, s2));
          }
          return null !== i2.explicit && (o2 = this._encodeComposite(i2.explicit, false, "context", o2)), o2;
        }, u.prototype._encodeChoice = function(e3, t3) {
          const r3 = this._baseState, n2 = r3.choice[e3.type];
          return n2 || s(false, e3.type + " not found in " + JSON.stringify(Object.keys(r3.choice))), n2._encode(e3.value, t3);
        }, u.prototype._encodePrimitive = function(e3, t3) {
          const r3 = this._baseState;
          if (/str$/.test(e3)) return this._encodeStr(t3, e3);
          if ("objid" === e3 && r3.args) return this._encodeObjid(t3, r3.reverseArgs[0], r3.args[1]);
          if ("objid" === e3) return this._encodeObjid(t3, null, null);
          if ("gentime" === e3 || "utctime" === e3) return this._encodeTime(t3, e3);
          if ("null_" === e3) return this._encodeNull();
          if ("int" === e3 || "enum" === e3) return this._encodeInt(t3, r3.args && r3.reverseArgs[0]);
          if ("bool" === e3) return this._encodeBool(t3);
          if ("objDesc" === e3) return this._encodeStr(t3, e3);
          throw new Error("Unsupported tag: " + e3);
        }, u.prototype._isNumstr = function(e3) {
          return /^[0-9 ]*$/.test(e3);
        }, u.prototype._isPrintstr = function(e3) {
          return /^[A-Za-z0-9 '()+,-./:=?]*$/.test(e3);
        };
      }, 8657: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193);
        function i(e3) {
          this._reporterState = { obj: null, path: [], options: e3 || {}, errors: [] };
        }
        function o(e3, t3) {
          this.path = e3, this.rethrow(t3);
        }
        t2.a = i, i.prototype.isError = function(e3) {
          return e3 instanceof o;
        }, i.prototype.save = function() {
          const e3 = this._reporterState;
          return { obj: e3.obj, pathLen: e3.path.length };
        }, i.prototype.restore = function(e3) {
          const t3 = this._reporterState;
          t3.obj = e3.obj, t3.path = t3.path.slice(0, e3.pathLen);
        }, i.prototype.enterKey = function(e3) {
          return this._reporterState.path.push(e3);
        }, i.prototype.exitKey = function(e3) {
          const t3 = this._reporterState;
          t3.path = t3.path.slice(0, e3 - 1);
        }, i.prototype.leaveKey = function(e3, t3, r3) {
          const n2 = this._reporterState;
          this.exitKey(e3), null !== n2.obj && (n2.obj[t3] = r3);
        }, i.prototype.path = function() {
          return this._reporterState.path.join("/");
        }, i.prototype.enterObject = function() {
          const e3 = this._reporterState, t3 = e3.obj;
          return e3.obj = {}, t3;
        }, i.prototype.leaveObject = function(e3) {
          const t3 = this._reporterState, r3 = t3.obj;
          return t3.obj = e3, r3;
        }, i.prototype.error = function(e3) {
          let t3;
          const r3 = this._reporterState, n2 = e3 instanceof o;
          if (t3 = n2 ? e3 : new o(r3.path.map((function(e4) {
            return "[" + JSON.stringify(e4) + "]";
          })).join(""), e3.message || e3, e3.stack), !r3.options.partial) throw t3;
          return n2 || r3.errors.push(t3), t3;
        }, i.prototype.wrapResult = function(e3) {
          const t3 = this._reporterState;
          return t3.options.partial ? { result: this.isError(e3) ? null : e3, errors: t3.errors } : e3;
        }, n(o, Error), o.prototype.rethrow = function(e3) {
          if (this.message = e3 + " at: " + (this.path || "(shallow)"), Error.captureStackTrace && Error.captureStackTrace(this, o), !this.stack) try {
            throw new Error(this.message);
          } catch (e4) {
            this.stack = e4.stack;
          }
          return this;
        };
      }, 1371: (e2, t2) => {
        "use strict";
        function r2(e3) {
          const t3 = {};
          return Object.keys(e3).forEach((function(r3) {
            (0 | r3) == r3 && (r3 |= 0);
            const n = e3[r3];
            t3[n] = r3;
          })), t3;
        }
        t2.tagClass = { 0: "universal", 1: "application", 2: "context", 3: "private" }, t2.tagClassByName = r2(t2.tagClass), t2.tag = { 0: "end", 1: "bool", 2: "int", 3: "bitstr", 4: "octstr", 5: "null_", 6: "objid", 7: "objDesc", 8: "external", 9: "real", 10: "enum", 11: "embed", 12: "utf8str", 13: "relativeOid", 16: "seq", 17: "set", 18: "numstr", 19: "printstr", 20: "t61str", 21: "videostr", 22: "ia5str", 23: "utctime", 24: "gentime", 25: "graphstr", 26: "iso646str", 27: "genstr", 28: "unistr", 29: "charstr", 30: "bmpstr" }, t2.tagByName = r2(t2.tag);
      }, 6876: (e2, t2, r2) => {
        "use strict";
        const n = t2;
        n._reverse = function(e3) {
          const t3 = {};
          return Object.keys(e3).forEach((function(r3) {
            (0 | r3) == r3 && (r3 |= 0);
            const n2 = e3[r3];
            t3[n2] = r3;
          })), t3;
        }, n.der = r2(1371);
      }, 629: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193), i = r2(4619), o = r2(3802).t, s = r2(2144), a = r2(1371);
        function c(e3) {
          this.enc = "der", this.name = e3.name, this.entity = e3, this.tree = new u(), this.tree._init(e3.body);
        }
        function u(e3) {
          s.call(this, "der", e3);
        }
        function d(e3, t3) {
          let r3 = e3.readUInt8(t3);
          if (e3.isError(r3)) return r3;
          const n2 = a.tagClass[r3 >> 6], i2 = !(32 & r3);
          if (31 & ~r3) r3 &= 31;
          else {
            let n3 = r3;
            for (r3 = 0; !(128 & ~n3); ) {
              if (n3 = e3.readUInt8(t3), e3.isError(n3)) return n3;
              r3 <<= 7, r3 |= 127 & n3;
            }
          }
          return { cls: n2, primitive: i2, tag: r3, tagStr: a.tag[r3] };
        }
        function f(e3, t3, r3) {
          let n2 = e3.readUInt8(r3);
          if (e3.isError(n2)) return n2;
          if (!t3 && 128 === n2) return null;
          if (!(128 & n2)) return n2;
          const i2 = 127 & n2;
          if (i2 > 4) return e3.error("length octect is too long");
          n2 = 0;
          for (let t4 = 0; t4 < i2; t4++) {
            n2 <<= 8;
            const t5 = e3.readUInt8(r3);
            if (e3.isError(t5)) return t5;
            n2 |= t5;
          }
          return n2;
        }
        e2.exports = c, c.prototype.decode = function(e3, t3) {
          return o.isDecoderBuffer(e3) || (e3 = new o(e3, t3)), this.tree._decode(e3, t3);
        }, n(u, s), u.prototype._peekTag = function(e3, t3, r3) {
          if (e3.isEmpty()) return false;
          const n2 = e3.save(), i2 = d(e3, 'Failed to peek tag: "' + t3 + '"');
          return e3.isError(i2) ? i2 : (e3.restore(n2), i2.tag === t3 || i2.tagStr === t3 || i2.tagStr + "of" === t3 || r3);
        }, u.prototype._decodeTag = function(e3, t3, r3) {
          const n2 = d(e3, 'Failed to decode tag of "' + t3 + '"');
          if (e3.isError(n2)) return n2;
          let i2 = f(e3, n2.primitive, 'Failed to get length of "' + t3 + '"');
          if (e3.isError(i2)) return i2;
          if (!r3 && n2.tag !== t3 && n2.tagStr !== t3 && n2.tagStr + "of" !== t3) return e3.error('Failed to match tag: "' + t3 + '"');
          if (n2.primitive || null !== i2) return e3.skip(i2, 'Failed to match body of: "' + t3 + '"');
          const o2 = e3.save(), s2 = this._skipUntilEnd(e3, 'Failed to skip indefinite length body: "' + this.tag + '"');
          return e3.isError(s2) ? s2 : (i2 = e3.offset - o2.offset, e3.restore(o2), e3.skip(i2, 'Failed to match body of: "' + t3 + '"'));
        }, u.prototype._skipUntilEnd = function(e3, t3) {
          for (; ; ) {
            const r3 = d(e3, t3);
            if (e3.isError(r3)) return r3;
            const n2 = f(e3, r3.primitive, t3);
            if (e3.isError(n2)) return n2;
            let i2;
            if (i2 = r3.primitive || null !== n2 ? e3.skip(n2) : this._skipUntilEnd(e3, t3), e3.isError(i2)) return i2;
            if ("end" === r3.tagStr) break;
          }
        }, u.prototype._decodeList = function(e3, t3, r3, n2) {
          const i2 = [];
          for (; !e3.isEmpty(); ) {
            const t4 = this._peekTag(e3, "end");
            if (e3.isError(t4)) return t4;
            const o2 = r3.decode(e3, "der", n2);
            if (e3.isError(o2) && t4) break;
            i2.push(o2);
          }
          return i2;
        }, u.prototype._decodeStr = function(e3, t3) {
          if ("bitstr" === t3) {
            const t4 = e3.readUInt8();
            return e3.isError(t4) ? t4 : { unused: t4, data: e3.raw() };
          }
          if ("bmpstr" === t3) {
            const t4 = e3.raw();
            if (t4.length % 2 == 1) return e3.error("Decoding of string type: bmpstr length mismatch");
            let r3 = "";
            for (let e4 = 0; e4 < t4.length / 2; e4++) r3 += String.fromCharCode(t4.readUInt16BE(2 * e4));
            return r3;
          }
          if ("numstr" === t3) {
            const t4 = e3.raw().toString("ascii");
            return this._isNumstr(t4) ? t4 : e3.error("Decoding of string type: numstr unsupported characters");
          }
          if ("octstr" === t3) return e3.raw();
          if ("objDesc" === t3) return e3.raw();
          if ("printstr" === t3) {
            const t4 = e3.raw().toString("ascii");
            return this._isPrintstr(t4) ? t4 : e3.error("Decoding of string type: printstr unsupported characters");
          }
          return /str$/.test(t3) ? e3.raw().toString() : e3.error("Decoding of string type: " + t3 + " unsupported");
        }, u.prototype._decodeObjid = function(e3, t3, r3) {
          let n2;
          const i2 = [];
          let o2 = 0, s2 = 0;
          for (; !e3.isEmpty(); ) s2 = e3.readUInt8(), o2 <<= 7, o2 |= 127 & s2, 128 & s2 || (i2.push(o2), o2 = 0);
          128 & s2 && i2.push(o2);
          const a2 = i2[0] / 40 | 0, c2 = i2[0] % 40;
          if (n2 = r3 ? i2 : [a2, c2].concat(i2.slice(1)), t3) {
            let e4 = t3[n2.join(" ")];
            void 0 === e4 && (e4 = t3[n2.join(".")]), void 0 !== e4 && (n2 = e4);
          }
          return n2;
        }, u.prototype._decodeTime = function(e3, t3) {
          const r3 = e3.raw().toString();
          let n2, i2, o2, s2, a2, c2;
          if ("gentime" === t3) n2 = 0 | r3.slice(0, 4), i2 = 0 | r3.slice(4, 6), o2 = 0 | r3.slice(6, 8), s2 = 0 | r3.slice(8, 10), a2 = 0 | r3.slice(10, 12), c2 = 0 | r3.slice(12, 14);
          else {
            if ("utctime" !== t3) return e3.error("Decoding " + t3 + " time is not supported yet");
            n2 = 0 | r3.slice(0, 2), i2 = 0 | r3.slice(2, 4), o2 = 0 | r3.slice(4, 6), s2 = 0 | r3.slice(6, 8), a2 = 0 | r3.slice(8, 10), c2 = 0 | r3.slice(10, 12), n2 = n2 < 70 ? 2e3 + n2 : 1900 + n2;
          }
          return Date.UTC(n2, i2 - 1, o2, s2, a2, c2, 0);
        }, u.prototype._decodeNull = function() {
          return null;
        }, u.prototype._decodeBool = function(e3) {
          const t3 = e3.readUInt8();
          return e3.isError(t3) ? t3 : 0 !== t3;
        }, u.prototype._decodeInt = function(e3, t3) {
          const r3 = e3.raw();
          let n2 = new i(r3);
          return t3 && (n2 = t3[n2.toString(10)] || n2), n2;
        }, u.prototype._use = function(e3, t3) {
          return "function" == typeof e3 && (e3 = e3(t3)), e3._getDecoder("der").tree;
        };
      }, 5126: (e2, t2, r2) => {
        "use strict";
        const n = t2;
        n.der = r2(629), n.pem = r2(2932);
      }, 2932: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193), i = r2(1628).Buffer, o = r2(629);
        function s(e3) {
          o.call(this, e3), this.enc = "pem";
        }
        n(s, o), e2.exports = s, s.prototype.decode = function(e3, t3) {
          const r3 = e3.toString().split(/[\r\n]+/g), n2 = t3.label.toUpperCase(), s2 = /^-----(BEGIN|END) ([^-]+)-----$/;
          let a = -1, c = -1;
          for (let e4 = 0; e4 < r3.length; e4++) {
            const t4 = r3[e4].match(s2);
            if (null !== t4 && t4[2] === n2) {
              if (-1 !== a) {
                if ("END" !== t4[1]) break;
                c = e4;
                break;
              }
              if ("BEGIN" !== t4[1]) break;
              a = e4;
            }
          }
          if (-1 === a || -1 === c) throw new Error("PEM section not found for: " + n2);
          const u = r3.slice(a + 1, c).join("");
          u.replace(/[^a-z0-9+/=]+/gi, "");
          const d = i.from(u, "base64");
          return o.prototype.decode.call(this, d, t3);
        };
      }, 5841: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193), i = r2(1628).Buffer, o = r2(2144), s = r2(1371);
        function a(e3) {
          this.enc = "der", this.name = e3.name, this.entity = e3, this.tree = new c(), this.tree._init(e3.body);
        }
        function c(e3) {
          o.call(this, "der", e3);
        }
        function u(e3) {
          return e3 < 10 ? "0" + e3 : e3;
        }
        e2.exports = a, a.prototype.encode = function(e3, t3) {
          return this.tree._encode(e3, t3).join();
        }, n(c, o), c.prototype._encodeComposite = function(e3, t3, r3, n2) {
          const o2 = (function(e4, t4, r4, n3) {
            let i2;
            if ("seqof" === e4 ? e4 = "seq" : "setof" === e4 && (e4 = "set"), s.tagByName.hasOwnProperty(e4)) i2 = s.tagByName[e4];
            else {
              if ("number" != typeof e4 || (0 | e4) !== e4) return n3.error("Unknown tag: " + e4);
              i2 = e4;
            }
            return i2 >= 31 ? n3.error("Multi-octet tag encoding unsupported") : (t4 || (i2 |= 32), i2 |= s.tagClassByName[r4 || "universal"] << 6, i2);
          })(e3, t3, r3, this.reporter);
          if (n2.length < 128) {
            const e4 = i.alloc(2);
            return e4[0] = o2, e4[1] = n2.length, this._createEncoderBuffer([e4, n2]);
          }
          let a2 = 1;
          for (let e4 = n2.length; e4 >= 256; e4 >>= 8) a2++;
          const c2 = i.alloc(2 + a2);
          c2[0] = o2, c2[1] = 128 | a2;
          for (let e4 = 1 + a2, t4 = n2.length; t4 > 0; e4--, t4 >>= 8) c2[e4] = 255 & t4;
          return this._createEncoderBuffer([c2, n2]);
        }, c.prototype._encodeStr = function(e3, t3) {
          if ("bitstr" === t3) return this._createEncoderBuffer([0 | e3.unused, e3.data]);
          if ("bmpstr" === t3) {
            const t4 = i.alloc(2 * e3.length);
            for (let r3 = 0; r3 < e3.length; r3++) t4.writeUInt16BE(e3.charCodeAt(r3), 2 * r3);
            return this._createEncoderBuffer(t4);
          }
          return "numstr" === t3 ? this._isNumstr(e3) ? this._createEncoderBuffer(e3) : this.reporter.error("Encoding of string type: numstr supports only digits and space") : "printstr" === t3 ? this._isPrintstr(e3) ? this._createEncoderBuffer(e3) : this.reporter.error("Encoding of string type: printstr supports only latin upper and lower case letters, digits, space, apostrophe, left and rigth parenthesis, plus sign, comma, hyphen, dot, slash, colon, equal sign, question mark") : /str$/.test(t3) || "objDesc" === t3 ? this._createEncoderBuffer(e3) : this.reporter.error("Encoding of string type: " + t3 + " unsupported");
        }, c.prototype._encodeObjid = function(e3, t3, r3) {
          if ("string" == typeof e3) {
            if (!t3) return this.reporter.error("string objid given, but no values map found");
            if (!t3.hasOwnProperty(e3)) return this.reporter.error("objid not found in values map");
            e3 = t3[e3].split(/[\s.]+/g);
            for (let t4 = 0; t4 < e3.length; t4++) e3[t4] |= 0;
          } else if (Array.isArray(e3)) {
            e3 = e3.slice();
            for (let t4 = 0; t4 < e3.length; t4++) e3[t4] |= 0;
          }
          if (!Array.isArray(e3)) return this.reporter.error("objid() should be either array or string, got: " + JSON.stringify(e3));
          if (!r3) {
            if (e3[1] >= 40) return this.reporter.error("Second objid identifier OOB");
            e3.splice(0, 2, 40 * e3[0] + e3[1]);
          }
          let n2 = 0;
          for (let t4 = 0; t4 < e3.length; t4++) {
            let r4 = e3[t4];
            for (n2++; r4 >= 128; r4 >>= 7) n2++;
          }
          const o2 = i.alloc(n2);
          let s2 = o2.length - 1;
          for (let t4 = e3.length - 1; t4 >= 0; t4--) {
            let r4 = e3[t4];
            for (o2[s2--] = 127 & r4; (r4 >>= 7) > 0; ) o2[s2--] = 128 | 127 & r4;
          }
          return this._createEncoderBuffer(o2);
        }, c.prototype._encodeTime = function(e3, t3) {
          let r3;
          const n2 = new Date(e3);
          return "gentime" === t3 ? r3 = [u(n2.getUTCFullYear()), u(n2.getUTCMonth() + 1), u(n2.getUTCDate()), u(n2.getUTCHours()), u(n2.getUTCMinutes()), u(n2.getUTCSeconds()), "Z"].join("") : "utctime" === t3 ? r3 = [u(n2.getUTCFullYear() % 100), u(n2.getUTCMonth() + 1), u(n2.getUTCDate()), u(n2.getUTCHours()), u(n2.getUTCMinutes()), u(n2.getUTCSeconds()), "Z"].join("") : this.reporter.error("Encoding " + t3 + " time is not supported yet"), this._encodeStr(r3, "octstr");
        }, c.prototype._encodeNull = function() {
          return this._createEncoderBuffer("");
        }, c.prototype._encodeInt = function(e3, t3) {
          if ("string" == typeof e3) {
            if (!t3) return this.reporter.error("String int or enum given, but no values map");
            if (!t3.hasOwnProperty(e3)) return this.reporter.error("Values map doesn't contain: " + JSON.stringify(e3));
            e3 = t3[e3];
          }
          if ("number" != typeof e3 && !i.isBuffer(e3)) {
            const t4 = e3.toArray();
            !e3.sign && 128 & t4[0] && t4.unshift(0), e3 = i.from(t4);
          }
          if (i.isBuffer(e3)) {
            let t4 = e3.length;
            0 === e3.length && t4++;
            const r4 = i.alloc(t4);
            return e3.copy(r4), 0 === e3.length && (r4[0] = 0), this._createEncoderBuffer(r4);
          }
          if (e3 < 128) return this._createEncoderBuffer(e3);
          if (e3 < 256) return this._createEncoderBuffer([0, e3]);
          let r3 = 1;
          for (let t4 = e3; t4 >= 256; t4 >>= 8) r3++;
          const n2 = new Array(r3);
          for (let t4 = n2.length - 1; t4 >= 0; t4--) n2[t4] = 255 & e3, e3 >>= 8;
          return 128 & n2[0] && n2.unshift(0), this._createEncoderBuffer(i.from(n2));
        }, c.prototype._encodeBool = function(e3) {
          return this._createEncoderBuffer(e3 ? 255 : 0);
        }, c.prototype._use = function(e3, t3) {
          return "function" == typeof e3 && (e3 = e3(t3)), e3._getEncoder("der").tree;
        }, c.prototype._skipDefault = function(e3, t3, r3) {
          const n2 = this._baseState;
          let i2;
          if (null === n2.default) return false;
          const o2 = e3.join();
          if (void 0 === n2.defaultBuffer && (n2.defaultBuffer = this._encodeValue(n2.default, t3, r3).join()), o2.length !== n2.defaultBuffer.length) return false;
          for (i2 = 0; i2 < o2.length; i2++) if (o2[i2] !== n2.defaultBuffer[i2]) return false;
          return true;
        };
      }, 122: (e2, t2, r2) => {
        "use strict";
        const n = t2;
        n.der = r2(5841), n.pem = r2(8080);
      }, 8080: (e2, t2, r2) => {
        "use strict";
        const n = r2(1193), i = r2(5841);
        function o(e3) {
          i.call(this, e3), this.enc = "pem";
        }
        n(o, i), e2.exports = o, o.prototype.encode = function(e3, t3) {
          const r3 = i.prototype.encode.call(this, e3).toString("base64"), n2 = ["-----BEGIN " + t3.label + "-----"];
          for (let e4 = 0; e4 < r3.length; e4 += 64) n2.push(r3.slice(e4, e4 + 64));
          return n2.push("-----END " + t3.label + "-----"), n2.join("\n");
        };
      }, 1219: (e2) => {
        "use strict";
        e2.exports = function(e3) {
          if (e3.length >= 255) throw new TypeError("Alphabet too long");
          for (var t2 = new Uint8Array(256), r2 = 0; r2 < t2.length; r2++) t2[r2] = 255;
          for (var n = 0; n < e3.length; n++) {
            var i = e3.charAt(n), o = i.charCodeAt(0);
            if (255 !== t2[o]) throw new TypeError(i + " is ambiguous");
            t2[o] = n;
          }
          var s = e3.length, a = e3.charAt(0), c = Math.log(s) / Math.log(256), u = Math.log(256) / Math.log(s);
          function d(e4) {
            if ("string" != typeof e4) throw new TypeError("Expected String");
            if (0 === e4.length) return new Uint8Array();
            for (var r3 = 0, n2 = 0, i2 = 0; e4[r3] === a; ) n2++, r3++;
            for (var o2 = (e4.length - r3) * c + 1 >>> 0, u2 = new Uint8Array(o2); e4[r3]; ) {
              var d2 = t2[e4.charCodeAt(r3)];
              if (255 === d2) return;
              for (var f = 0, h = o2 - 1; (0 !== d2 || f < i2) && -1 !== h; h--, f++) d2 += s * u2[h] >>> 0, u2[h] = d2 % 256 >>> 0, d2 = d2 / 256 >>> 0;
              if (0 !== d2) throw new Error("Non-zero carry");
              i2 = f, r3++;
            }
            for (var l = o2 - i2; l !== o2 && 0 === u2[l]; ) l++;
            for (var p = new Uint8Array(n2 + (o2 - l)), b = n2; l !== o2; ) p[b++] = u2[l++];
            return p;
          }
          return { encode: function(t3) {
            if (t3 instanceof Uint8Array || (ArrayBuffer.isView(t3) ? t3 = new Uint8Array(t3.buffer, t3.byteOffset, t3.byteLength) : Array.isArray(t3) && (t3 = Uint8Array.from(t3))), !(t3 instanceof Uint8Array)) throw new TypeError("Expected Uint8Array");
            if (0 === t3.length) return "";
            for (var r3 = 0, n2 = 0, i2 = 0, o2 = t3.length; i2 !== o2 && 0 === t3[i2]; ) i2++, r3++;
            for (var c2 = (o2 - i2) * u + 1 >>> 0, d2 = new Uint8Array(c2); i2 !== o2; ) {
              for (var f = t3[i2], h = 0, l = c2 - 1; (0 !== f || h < n2) && -1 !== l; l--, h++) f += 256 * d2[l] >>> 0, d2[l] = f % s >>> 0, f = f / s >>> 0;
              if (0 !== f) throw new Error("Non-zero carry");
              n2 = h, i2++;
            }
            for (var p = c2 - n2; p !== c2 && 0 === d2[p]; ) p++;
            for (var b = a.repeat(r3); p < c2; ++p) b += e3.charAt(d2[p]);
            return b;
          }, decodeUnsafe: d, decode: function(e4) {
            var t3 = d(e4);
            if (t3) return t3;
            throw new Error("Non-base" + s + " character");
          } };
        };
      }, 4933: (e2, t2) => {
        "use strict";
        t2.byteLength = function(e3) {
          var t3 = a(e3), r3 = t3[0], n2 = t3[1];
          return 3 * (r3 + n2) / 4 - n2;
        }, t2.toByteArray = function(e3) {
          var t3, r3, o2 = a(e3), s2 = o2[0], c2 = o2[1], u = new i((function(e4, t4, r4) {
            return 3 * (t4 + r4) / 4 - r4;
          })(0, s2, c2)), d = 0, f = c2 > 0 ? s2 - 4 : s2;
          for (r3 = 0; r3 < f; r3 += 4) t3 = n[e3.charCodeAt(r3)] << 18 | n[e3.charCodeAt(r3 + 1)] << 12 | n[e3.charCodeAt(r3 + 2)] << 6 | n[e3.charCodeAt(r3 + 3)], u[d++] = t3 >> 16 & 255, u[d++] = t3 >> 8 & 255, u[d++] = 255 & t3;
          return 2 === c2 && (t3 = n[e3.charCodeAt(r3)] << 2 | n[e3.charCodeAt(r3 + 1)] >> 4, u[d++] = 255 & t3), 1 === c2 && (t3 = n[e3.charCodeAt(r3)] << 10 | n[e3.charCodeAt(r3 + 1)] << 4 | n[e3.charCodeAt(r3 + 2)] >> 2, u[d++] = t3 >> 8 & 255, u[d++] = 255 & t3), u;
        }, t2.fromByteArray = function(e3) {
          for (var t3, n2 = e3.length, i2 = n2 % 3, o2 = [], s2 = 16383, a2 = 0, u = n2 - i2; a2 < u; a2 += s2) o2.push(c(e3, a2, a2 + s2 > u ? u : a2 + s2));
          return 1 === i2 ? (t3 = e3[n2 - 1], o2.push(r2[t3 >> 2] + r2[t3 << 4 & 63] + "==")) : 2 === i2 && (t3 = (e3[n2 - 2] << 8) + e3[n2 - 1], o2.push(r2[t3 >> 10] + r2[t3 >> 4 & 63] + r2[t3 << 2 & 63] + "=")), o2.join("");
        };
        for (var r2 = [], n = [], i = "undefined" != typeof Uint8Array ? Uint8Array : Array, o = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", s = 0; s < 64; ++s) r2[s] = o[s], n[o.charCodeAt(s)] = s;
        function a(e3) {
          var t3 = e3.length;
          if (t3 % 4 > 0) throw new Error("Invalid string. Length must be a multiple of 4");
          var r3 = e3.indexOf("=");
          return -1 === r3 && (r3 = t3), [r3, r3 === t3 ? 0 : 4 - r3 % 4];
        }
        function c(e3, t3, n2) {
          for (var i2, o2, s2 = [], a2 = t3; a2 < n2; a2 += 3) i2 = (e3[a2] << 16 & 16711680) + (e3[a2 + 1] << 8 & 65280) + (255 & e3[a2 + 2]), s2.push(r2[(o2 = i2) >> 18 & 63] + r2[o2 >> 12 & 63] + r2[o2 >> 6 & 63] + r2[63 & o2]);
          return s2.join("");
        }
        n["-".charCodeAt(0)] = 62, n["_".charCodeAt(0)] = 63;
      }, 1594: function(e2, t2, r2) {
        var n;
        !(function() {
          "use strict";
          var i, o = /^-?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i, s = Math.ceil, a = Math.floor, c = "[BigNumber Error] ", u = c + "Number primitive has more than 15 significant digits: ", d = 1e14, f = 14, h = 9007199254740991, l = [1, 10, 100, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13], p = 1e7, b = 1e9;
          function y(e3) {
            var t3 = 0 | e3;
            return e3 > 0 || e3 === t3 ? t3 : t3 - 1;
          }
          function m(e3) {
            for (var t3, r3, n2 = 1, i2 = e3.length, o2 = e3[0] + ""; n2 < i2; ) {
              for (t3 = e3[n2++] + "", r3 = f - t3.length; r3--; t3 = "0" + t3) ;
              o2 += t3;
            }
            for (i2 = o2.length; 48 === o2.charCodeAt(--i2); ) ;
            return o2.slice(0, i2 + 1 || 1);
          }
          function g(e3, t3) {
            var r3, n2, i2 = e3.c, o2 = t3.c, s2 = e3.s, a2 = t3.s, c2 = e3.e, u2 = t3.e;
            if (!s2 || !a2) return null;
            if (r3 = i2 && !i2[0], n2 = o2 && !o2[0], r3 || n2) return r3 ? n2 ? 0 : -a2 : s2;
            if (s2 != a2) return s2;
            if (r3 = s2 < 0, n2 = c2 == u2, !i2 || !o2) return n2 ? 0 : !i2 ^ r3 ? 1 : -1;
            if (!n2) return c2 > u2 ^ r3 ? 1 : -1;
            for (a2 = (c2 = i2.length) < (u2 = o2.length) ? c2 : u2, s2 = 0; s2 < a2; s2++) if (i2[s2] != o2[s2]) return i2[s2] > o2[s2] ^ r3 ? 1 : -1;
            return c2 == u2 ? 0 : c2 > u2 ^ r3 ? 1 : -1;
          }
          function v(e3, t3, r3, n2) {
            if (e3 < t3 || e3 > r3 || e3 !== a(e3)) throw Error(c + (n2 || "Argument") + ("number" == typeof e3 ? e3 < t3 || e3 > r3 ? " out of range: " : " not an integer: " : " not a primitive number: ") + String(e3));
          }
          function w(e3) {
            var t3 = e3.c.length - 1;
            return y(e3.e / f) == t3 && e3.c[t3] % 2 != 0;
          }
          function _(e3, t3) {
            return (e3.length > 1 ? e3.charAt(0) + "." + e3.slice(1) : e3) + (t3 < 0 ? "e" : "e+") + t3;
          }
          function A(e3, t3, r3) {
            var n2, i2;
            if (t3 < 0) {
              for (i2 = r3 + "."; ++t3; i2 += r3) ;
              e3 = i2 + e3;
            } else if (++t3 > (n2 = e3.length)) {
              for (i2 = r3, t3 -= n2; --t3; i2 += r3) ;
              e3 += i2;
            } else t3 < n2 && (e3 = e3.slice(0, t3) + "." + e3.slice(t3));
            return e3;
          }
          i = (function e3(t3) {
            var r3, n2, i2, S, C, T, M, E, k, x, I = V.prototype = { constructor: V, toString: null, valueOf: null }, B = new V(1), U = 20, P = 4, O = -7, R = 21, N = -1e7, L = 1e7, j = false, D = 1, F = 0, H = { prefix: "", groupSize: 3, secondaryGroupSize: 0, groupSeparator: ",", decimalSeparator: ".", fractionGroupSize: 0, fractionGroupSeparator: "\xA0", suffix: "" }, q = "0123456789abcdefghijklmnopqrstuvwxyz", $ = true;
            function V(e4, t4) {
              var r4, s2, c2, d2, l2, p2, b2, y2, m2 = this;
              if (!(m2 instanceof V)) return new V(e4, t4);
              if (null == t4) {
                if (e4 && true === e4._isBigNumber) return m2.s = e4.s, void (!e4.c || e4.e > L ? m2.c = m2.e = null : e4.e < N ? m2.c = [m2.e = 0] : (m2.e = e4.e, m2.c = e4.c.slice()));
                if ((p2 = "number" == typeof e4) && 0 * e4 == 0) {
                  if (m2.s = 1 / e4 < 0 ? (e4 = -e4, -1) : 1, e4 === ~~e4) {
                    for (d2 = 0, l2 = e4; l2 >= 10; l2 /= 10, d2++) ;
                    return void (d2 > L ? m2.c = m2.e = null : (m2.e = d2, m2.c = [e4]));
                  }
                  y2 = String(e4);
                } else {
                  if (!o.test(y2 = String(e4))) return i2(m2, y2, p2);
                  m2.s = 45 == y2.charCodeAt(0) ? (y2 = y2.slice(1), -1) : 1;
                }
                (d2 = y2.indexOf(".")) > -1 && (y2 = y2.replace(".", "")), (l2 = y2.search(/e/i)) > 0 ? (d2 < 0 && (d2 = l2), d2 += +y2.slice(l2 + 1), y2 = y2.substring(0, l2)) : d2 < 0 && (d2 = y2.length);
              } else {
                if (v(t4, 2, q.length, "Base"), 10 == t4 && $) return W(m2 = new V(e4), U + m2.e + 1, P);
                if (y2 = String(e4), p2 = "number" == typeof e4) {
                  if (0 * e4 != 0) return i2(m2, y2, p2, t4);
                  if (m2.s = 1 / e4 < 0 ? (y2 = y2.slice(1), -1) : 1, V.DEBUG && y2.replace(/^0\.0*|\./, "").length > 15) throw Error(u + e4);
                } else m2.s = 45 === y2.charCodeAt(0) ? (y2 = y2.slice(1), -1) : 1;
                for (r4 = q.slice(0, t4), d2 = l2 = 0, b2 = y2.length; l2 < b2; l2++) if (r4.indexOf(s2 = y2.charAt(l2)) < 0) {
                  if ("." == s2) {
                    if (l2 > d2) {
                      d2 = b2;
                      continue;
                    }
                  } else if (!c2 && (y2 == y2.toUpperCase() && (y2 = y2.toLowerCase()) || y2 == y2.toLowerCase() && (y2 = y2.toUpperCase()))) {
                    c2 = true, l2 = -1, d2 = 0;
                    continue;
                  }
                  return i2(m2, String(e4), p2, t4);
                }
                p2 = false, (d2 = (y2 = n2(y2, t4, 10, m2.s)).indexOf(".")) > -1 ? y2 = y2.replace(".", "") : d2 = y2.length;
              }
              for (l2 = 0; 48 === y2.charCodeAt(l2); l2++) ;
              for (b2 = y2.length; 48 === y2.charCodeAt(--b2); ) ;
              if (y2 = y2.slice(l2, ++b2)) {
                if (b2 -= l2, p2 && V.DEBUG && b2 > 15 && (e4 > h || e4 !== a(e4))) throw Error(u + m2.s * e4);
                if ((d2 = d2 - l2 - 1) > L) m2.c = m2.e = null;
                else if (d2 < N) m2.c = [m2.e = 0];
                else {
                  if (m2.e = d2, m2.c = [], l2 = (d2 + 1) % f, d2 < 0 && (l2 += f), l2 < b2) {
                    for (l2 && m2.c.push(+y2.slice(0, l2)), b2 -= f; l2 < b2; ) m2.c.push(+y2.slice(l2, l2 += f));
                    l2 = f - (y2 = y2.slice(l2)).length;
                  } else l2 -= b2;
                  for (; l2--; y2 += "0") ;
                  m2.c.push(+y2);
                }
              } else m2.c = [m2.e = 0];
            }
            function G(e4, t4, r4, n3) {
              var i3, o2, s2, a2, c2;
              if (null == r4 ? r4 = P : v(r4, 0, 8), !e4.c) return e4.toString();
              if (i3 = e4.c[0], s2 = e4.e, null == t4) c2 = m(e4.c), c2 = 1 == n3 || 2 == n3 && (s2 <= O || s2 >= R) ? _(c2, s2) : A(c2, s2, "0");
              else if (o2 = (e4 = W(new V(e4), t4, r4)).e, a2 = (c2 = m(e4.c)).length, 1 == n3 || 2 == n3 && (t4 <= o2 || o2 <= O)) {
                for (; a2 < t4; c2 += "0", a2++) ;
                c2 = _(c2, o2);
              } else if (t4 -= s2, c2 = A(c2, o2, "0"), o2 + 1 > a2) {
                if (--t4 > 0) for (c2 += "."; t4--; c2 += "0") ;
              } else if ((t4 += o2 - a2) > 0) for (o2 + 1 == a2 && (c2 += "."); t4--; c2 += "0") ;
              return e4.s < 0 && i3 ? "-" + c2 : c2;
            }
            function z(e4, t4) {
              for (var r4, n3 = 1, i3 = new V(e4[0]); n3 < e4.length; n3++) {
                if (!(r4 = new V(e4[n3])).s) {
                  i3 = r4;
                  break;
                }
                t4.call(i3, r4) && (i3 = r4);
              }
              return i3;
            }
            function K(e4, t4, r4) {
              for (var n3 = 1, i3 = t4.length; !t4[--i3]; t4.pop()) ;
              for (i3 = t4[0]; i3 >= 10; i3 /= 10, n3++) ;
              return (r4 = n3 + r4 * f - 1) > L ? e4.c = e4.e = null : r4 < N ? e4.c = [e4.e = 0] : (e4.e = r4, e4.c = t4), e4;
            }
            function W(e4, t4, r4, n3) {
              var i3, o2, c2, u2, h2, p2, b2, y2 = e4.c, m2 = l;
              if (y2) {
                e: {
                  for (i3 = 1, u2 = y2[0]; u2 >= 10; u2 /= 10, i3++) ;
                  if ((o2 = t4 - i3) < 0) o2 += f, c2 = t4, b2 = (h2 = y2[p2 = 0]) / m2[i3 - c2 - 1] % 10 | 0;
                  else if ((p2 = s((o2 + 1) / f)) >= y2.length) {
                    if (!n3) break e;
                    for (; y2.length <= p2; y2.push(0)) ;
                    h2 = b2 = 0, i3 = 1, c2 = (o2 %= f) - f + 1;
                  } else {
                    for (h2 = u2 = y2[p2], i3 = 1; u2 >= 10; u2 /= 10, i3++) ;
                    b2 = (c2 = (o2 %= f) - f + i3) < 0 ? 0 : h2 / m2[i3 - c2 - 1] % 10 | 0;
                  }
                  if (n3 = n3 || t4 < 0 || null != y2[p2 + 1] || (c2 < 0 ? h2 : h2 % m2[i3 - c2 - 1]), n3 = r4 < 4 ? (b2 || n3) && (0 == r4 || r4 == (e4.s < 0 ? 3 : 2)) : b2 > 5 || 5 == b2 && (4 == r4 || n3 || 6 == r4 && (o2 > 0 ? c2 > 0 ? h2 / m2[i3 - c2] : 0 : y2[p2 - 1]) % 10 & 1 || r4 == (e4.s < 0 ? 8 : 7)), t4 < 1 || !y2[0]) return y2.length = 0, n3 ? (t4 -= e4.e + 1, y2[0] = m2[(f - t4 % f) % f], e4.e = -t4 || 0) : y2[0] = e4.e = 0, e4;
                  if (0 == o2 ? (y2.length = p2, u2 = 1, p2--) : (y2.length = p2 + 1, u2 = m2[f - o2], y2[p2] = c2 > 0 ? a(h2 / m2[i3 - c2] % m2[c2]) * u2 : 0), n3) for (; ; ) {
                    if (0 == p2) {
                      for (o2 = 1, c2 = y2[0]; c2 >= 10; c2 /= 10, o2++) ;
                      for (c2 = y2[0] += u2, u2 = 1; c2 >= 10; c2 /= 10, u2++) ;
                      o2 != u2 && (e4.e++, y2[0] == d && (y2[0] = 1));
                      break;
                    }
                    if (y2[p2] += u2, y2[p2] != d) break;
                    y2[p2--] = 0, u2 = 1;
                  }
                  for (o2 = y2.length; 0 === y2[--o2]; y2.pop()) ;
                }
                e4.e > L ? e4.c = e4.e = null : e4.e < N && (e4.c = [e4.e = 0]);
              }
              return e4;
            }
            function J(e4) {
              var t4, r4 = e4.e;
              return null === r4 ? e4.toString() : (t4 = m(e4.c), t4 = r4 <= O || r4 >= R ? _(t4, r4) : A(t4, r4, "0"), e4.s < 0 ? "-" + t4 : t4);
            }
            return V.clone = e3, V.ROUND_UP = 0, V.ROUND_DOWN = 1, V.ROUND_CEIL = 2, V.ROUND_FLOOR = 3, V.ROUND_HALF_UP = 4, V.ROUND_HALF_DOWN = 5, V.ROUND_HALF_EVEN = 6, V.ROUND_HALF_CEIL = 7, V.ROUND_HALF_FLOOR = 8, V.EUCLID = 9, V.config = V.set = function(e4) {
              var t4, r4;
              if (null != e4) {
                if ("object" != typeof e4) throw Error(c + "Object expected: " + e4);
                if (e4.hasOwnProperty(t4 = "DECIMAL_PLACES") && (v(r4 = e4[t4], 0, b, t4), U = r4), e4.hasOwnProperty(t4 = "ROUNDING_MODE") && (v(r4 = e4[t4], 0, 8, t4), P = r4), e4.hasOwnProperty(t4 = "EXPONENTIAL_AT") && ((r4 = e4[t4]) && r4.pop ? (v(r4[0], -b, 0, t4), v(r4[1], 0, b, t4), O = r4[0], R = r4[1]) : (v(r4, -b, b, t4), O = -(R = r4 < 0 ? -r4 : r4))), e4.hasOwnProperty(t4 = "RANGE")) if ((r4 = e4[t4]) && r4.pop) v(r4[0], -b, -1, t4), v(r4[1], 1, b, t4), N = r4[0], L = r4[1];
                else {
                  if (v(r4, -b, b, t4), !r4) throw Error(c + t4 + " cannot be zero: " + r4);
                  N = -(L = r4 < 0 ? -r4 : r4);
                }
                if (e4.hasOwnProperty(t4 = "CRYPTO")) {
                  if ((r4 = e4[t4]) !== !!r4) throw Error(c + t4 + " not true or false: " + r4);
                  if (r4) {
                    if ("undefined" == typeof crypto || !crypto || !crypto.getRandomValues && !crypto.randomBytes) throw j = !r4, Error(c + "crypto unavailable");
                    j = r4;
                  } else j = r4;
                }
                if (e4.hasOwnProperty(t4 = "MODULO_MODE") && (v(r4 = e4[t4], 0, 9, t4), D = r4), e4.hasOwnProperty(t4 = "POW_PRECISION") && (v(r4 = e4[t4], 0, b, t4), F = r4), e4.hasOwnProperty(t4 = "FORMAT")) {
                  if ("object" != typeof (r4 = e4[t4])) throw Error(c + t4 + " not an object: " + r4);
                  H = r4;
                }
                if (e4.hasOwnProperty(t4 = "ALPHABET")) {
                  if ("string" != typeof (r4 = e4[t4]) || /^.?$|[+\-.\s]|(.).*\1/.test(r4)) throw Error(c + t4 + " invalid: " + r4);
                  $ = "0123456789" == r4.slice(0, 10), q = r4;
                }
              }
              return { DECIMAL_PLACES: U, ROUNDING_MODE: P, EXPONENTIAL_AT: [O, R], RANGE: [N, L], CRYPTO: j, MODULO_MODE: D, POW_PRECISION: F, FORMAT: H, ALPHABET: q };
            }, V.isBigNumber = function(e4) {
              if (!e4 || true !== e4._isBigNumber) return false;
              if (!V.DEBUG) return true;
              var t4, r4, n3 = e4.c, i3 = e4.e, o2 = e4.s;
              e: if ("[object Array]" == {}.toString.call(n3)) {
                if ((1 === o2 || -1 === o2) && i3 >= -b && i3 <= b && i3 === a(i3)) {
                  if (0 === n3[0]) {
                    if (0 === i3 && 1 === n3.length) return true;
                    break e;
                  }
                  if ((t4 = (i3 + 1) % f) < 1 && (t4 += f), String(n3[0]).length == t4) {
                    for (t4 = 0; t4 < n3.length; t4++) if ((r4 = n3[t4]) < 0 || r4 >= d || r4 !== a(r4)) break e;
                    if (0 !== r4) return true;
                  }
                }
              } else if (null === n3 && null === i3 && (null === o2 || 1 === o2 || -1 === o2)) return true;
              throw Error(c + "Invalid BigNumber: " + e4);
            }, V.maximum = V.max = function() {
              return z(arguments, I.lt);
            }, V.minimum = V.min = function() {
              return z(arguments, I.gt);
            }, V.random = (S = 9007199254740992, C = Math.random() * S & 2097151 ? function() {
              return a(Math.random() * S);
            } : function() {
              return 8388608 * (1073741824 * Math.random() | 0) + (8388608 * Math.random() | 0);
            }, function(e4) {
              var t4, r4, n3, i3, o2, u2 = 0, d2 = [], h2 = new V(B);
              if (null == e4 ? e4 = U : v(e4, 0, b), i3 = s(e4 / f), j) if (crypto.getRandomValues) {
                for (t4 = crypto.getRandomValues(new Uint32Array(i3 *= 2)); u2 < i3; ) (o2 = 131072 * t4[u2] + (t4[u2 + 1] >>> 11)) >= 9e15 ? (r4 = crypto.getRandomValues(new Uint32Array(2)), t4[u2] = r4[0], t4[u2 + 1] = r4[1]) : (d2.push(o2 % 1e14), u2 += 2);
                u2 = i3 / 2;
              } else {
                if (!crypto.randomBytes) throw j = false, Error(c + "crypto unavailable");
                for (t4 = crypto.randomBytes(i3 *= 7); u2 < i3; ) (o2 = 281474976710656 * (31 & t4[u2]) + 1099511627776 * t4[u2 + 1] + 4294967296 * t4[u2 + 2] + 16777216 * t4[u2 + 3] + (t4[u2 + 4] << 16) + (t4[u2 + 5] << 8) + t4[u2 + 6]) >= 9e15 ? crypto.randomBytes(7).copy(t4, u2) : (d2.push(o2 % 1e14), u2 += 7);
                u2 = i3 / 7;
              }
              if (!j) for (; u2 < i3; ) (o2 = C()) < 9e15 && (d2[u2++] = o2 % 1e14);
              for (i3 = d2[--u2], e4 %= f, i3 && e4 && (o2 = l[f - e4], d2[u2] = a(i3 / o2) * o2); 0 === d2[u2]; d2.pop(), u2--) ;
              if (u2 < 0) d2 = [n3 = 0];
              else {
                for (n3 = -1; 0 === d2[0]; d2.splice(0, 1), n3 -= f) ;
                for (u2 = 1, o2 = d2[0]; o2 >= 10; o2 /= 10, u2++) ;
                u2 < f && (n3 -= f - u2);
              }
              return h2.e = n3, h2.c = d2, h2;
            }), V.sum = function() {
              for (var e4 = 1, t4 = arguments, r4 = new V(t4[0]); e4 < t4.length; ) r4 = r4.plus(t4[e4++]);
              return r4;
            }, n2 = /* @__PURE__ */ (function() {
              var e4 = "0123456789";
              function t4(e5, t5, r4, n3) {
                for (var i3, o2, s2 = [0], a2 = 0, c2 = e5.length; a2 < c2; ) {
                  for (o2 = s2.length; o2--; s2[o2] *= t5) ;
                  for (s2[0] += n3.indexOf(e5.charAt(a2++)), i3 = 0; i3 < s2.length; i3++) s2[i3] > r4 - 1 && (null == s2[i3 + 1] && (s2[i3 + 1] = 0), s2[i3 + 1] += s2[i3] / r4 | 0, s2[i3] %= r4);
                }
                return s2.reverse();
              }
              return function(n3, i3, o2, s2, a2) {
                var c2, u2, d2, f2, h2, l2, p2, b2, y2 = n3.indexOf("."), g2 = U, v2 = P;
                for (y2 >= 0 && (f2 = F, F = 0, n3 = n3.replace(".", ""), l2 = (b2 = new V(i3)).pow(n3.length - y2), F = f2, b2.c = t4(A(m(l2.c), l2.e, "0"), 10, o2, e4), b2.e = b2.c.length), d2 = f2 = (p2 = t4(n3, i3, o2, a2 ? (c2 = q, e4) : (c2 = e4, q))).length; 0 == p2[--f2]; p2.pop()) ;
                if (!p2[0]) return c2.charAt(0);
                if (y2 < 0 ? --d2 : (l2.c = p2, l2.e = d2, l2.s = s2, p2 = (l2 = r3(l2, b2, g2, v2, o2)).c, h2 = l2.r, d2 = l2.e), y2 = p2[u2 = d2 + g2 + 1], f2 = o2 / 2, h2 = h2 || u2 < 0 || null != p2[u2 + 1], h2 = v2 < 4 ? (null != y2 || h2) && (0 == v2 || v2 == (l2.s < 0 ? 3 : 2)) : y2 > f2 || y2 == f2 && (4 == v2 || h2 || 6 == v2 && 1 & p2[u2 - 1] || v2 == (l2.s < 0 ? 8 : 7)), u2 < 1 || !p2[0]) n3 = h2 ? A(c2.charAt(1), -g2, c2.charAt(0)) : c2.charAt(0);
                else {
                  if (p2.length = u2, h2) for (--o2; ++p2[--u2] > o2; ) p2[u2] = 0, u2 || (++d2, p2 = [1].concat(p2));
                  for (f2 = p2.length; !p2[--f2]; ) ;
                  for (y2 = 0, n3 = ""; y2 <= f2; n3 += c2.charAt(p2[y2++])) ;
                  n3 = A(n3, d2, c2.charAt(0));
                }
                return n3;
              };
            })(), r3 = /* @__PURE__ */ (function() {
              function e4(e5, t5, r5) {
                var n3, i3, o2, s2, a2 = 0, c2 = e5.length, u2 = t5 % p, d2 = t5 / p | 0;
                for (e5 = e5.slice(); c2--; ) a2 = ((i3 = u2 * (o2 = e5[c2] % p) + (n3 = d2 * o2 + (s2 = e5[c2] / p | 0) * u2) % p * p + a2) / r5 | 0) + (n3 / p | 0) + d2 * s2, e5[c2] = i3 % r5;
                return a2 && (e5 = [a2].concat(e5)), e5;
              }
              function t4(e5, t5, r5, n3) {
                var i3, o2;
                if (r5 != n3) o2 = r5 > n3 ? 1 : -1;
                else for (i3 = o2 = 0; i3 < r5; i3++) if (e5[i3] != t5[i3]) {
                  o2 = e5[i3] > t5[i3] ? 1 : -1;
                  break;
                }
                return o2;
              }
              function r4(e5, t5, r5, n3) {
                for (var i3 = 0; r5--; ) e5[r5] -= i3, i3 = e5[r5] < t5[r5] ? 1 : 0, e5[r5] = i3 * n3 + e5[r5] - t5[r5];
                for (; !e5[0] && e5.length > 1; e5.splice(0, 1)) ;
              }
              return function(n3, i3, o2, s2, c2) {
                var u2, h2, l2, p2, b2, m2, g2, v2, w2, _2, A2, S2, C2, T2, M2, E2, k2, x2 = n3.s == i3.s ? 1 : -1, I2 = n3.c, B2 = i3.c;
                if (!(I2 && I2[0] && B2 && B2[0])) return new V(n3.s && i3.s && (I2 ? !B2 || I2[0] != B2[0] : B2) ? I2 && 0 == I2[0] || !B2 ? 0 * x2 : x2 / 0 : NaN);
                for (w2 = (v2 = new V(x2)).c = [], x2 = o2 + (h2 = n3.e - i3.e) + 1, c2 || (c2 = d, h2 = y(n3.e / f) - y(i3.e / f), x2 = x2 / f | 0), l2 = 0; B2[l2] == (I2[l2] || 0); l2++) ;
                if (B2[l2] > (I2[l2] || 0) && h2--, x2 < 0) w2.push(1), p2 = true;
                else {
                  for (T2 = I2.length, E2 = B2.length, l2 = 0, x2 += 2, (b2 = a(c2 / (B2[0] + 1))) > 1 && (B2 = e4(B2, b2, c2), I2 = e4(I2, b2, c2), E2 = B2.length, T2 = I2.length), C2 = E2, A2 = (_2 = I2.slice(0, E2)).length; A2 < E2; _2[A2++] = 0) ;
                  k2 = B2.slice(), k2 = [0].concat(k2), M2 = B2[0], B2[1] >= c2 / 2 && M2++;
                  do {
                    if (b2 = 0, (u2 = t4(B2, _2, E2, A2)) < 0) {
                      if (S2 = _2[0], E2 != A2 && (S2 = S2 * c2 + (_2[1] || 0)), (b2 = a(S2 / M2)) > 1) for (b2 >= c2 && (b2 = c2 - 1), g2 = (m2 = e4(B2, b2, c2)).length, A2 = _2.length; 1 == t4(m2, _2, g2, A2); ) b2--, r4(m2, E2 < g2 ? k2 : B2, g2, c2), g2 = m2.length, u2 = 1;
                      else 0 == b2 && (u2 = b2 = 1), g2 = (m2 = B2.slice()).length;
                      if (g2 < A2 && (m2 = [0].concat(m2)), r4(_2, m2, A2, c2), A2 = _2.length, -1 == u2) for (; t4(B2, _2, E2, A2) < 1; ) b2++, r4(_2, E2 < A2 ? k2 : B2, A2, c2), A2 = _2.length;
                    } else 0 === u2 && (b2++, _2 = [0]);
                    w2[l2++] = b2, _2[0] ? _2[A2++] = I2[C2] || 0 : (_2 = [I2[C2]], A2 = 1);
                  } while ((C2++ < T2 || null != _2[0]) && x2--);
                  p2 = null != _2[0], w2[0] || w2.splice(0, 1);
                }
                if (c2 == d) {
                  for (l2 = 1, x2 = w2[0]; x2 >= 10; x2 /= 10, l2++) ;
                  W(v2, o2 + (v2.e = l2 + h2 * f - 1) + 1, s2, p2);
                } else v2.e = h2, v2.r = +p2;
                return v2;
              };
            })(), T = /^(-?)0([xbo])(?=\w[\w.]*$)/i, M = /^([^.]+)\.$/, E = /^\.([^.]+)$/, k = /^-?(Infinity|NaN)$/, x = /^\s*\+(?=[\w.])|^\s+|\s+$/g, i2 = function(e4, t4, r4, n3) {
              var i3, o2 = r4 ? t4 : t4.replace(x, "");
              if (k.test(o2)) e4.s = isNaN(o2) ? null : o2 < 0 ? -1 : 1;
              else {
                if (!r4 && (o2 = o2.replace(T, (function(e5, t5, r5) {
                  return i3 = "x" == (r5 = r5.toLowerCase()) ? 16 : "b" == r5 ? 2 : 8, n3 && n3 != i3 ? e5 : t5;
                })), n3 && (i3 = n3, o2 = o2.replace(M, "$1").replace(E, "0.$1")), t4 != o2)) return new V(o2, i3);
                if (V.DEBUG) throw Error(c + "Not a" + (n3 ? " base " + n3 : "") + " number: " + t4);
                e4.s = null;
              }
              e4.c = e4.e = null;
            }, I.absoluteValue = I.abs = function() {
              var e4 = new V(this);
              return e4.s < 0 && (e4.s = 1), e4;
            }, I.comparedTo = function(e4, t4) {
              return g(this, new V(e4, t4));
            }, I.decimalPlaces = I.dp = function(e4, t4) {
              var r4, n3, i3, o2 = this;
              if (null != e4) return v(e4, 0, b), null == t4 ? t4 = P : v(t4, 0, 8), W(new V(o2), e4 + o2.e + 1, t4);
              if (!(r4 = o2.c)) return null;
              if (n3 = ((i3 = r4.length - 1) - y(this.e / f)) * f, i3 = r4[i3]) for (; i3 % 10 == 0; i3 /= 10, n3--) ;
              return n3 < 0 && (n3 = 0), n3;
            }, I.dividedBy = I.div = function(e4, t4) {
              return r3(this, new V(e4, t4), U, P);
            }, I.dividedToIntegerBy = I.idiv = function(e4, t4) {
              return r3(this, new V(e4, t4), 0, 1);
            }, I.exponentiatedBy = I.pow = function(e4, t4) {
              var r4, n3, i3, o2, u2, d2, h2, l2, p2 = this;
              if ((e4 = new V(e4)).c && !e4.isInteger()) throw Error(c + "Exponent not an integer: " + J(e4));
              if (null != t4 && (t4 = new V(t4)), u2 = e4.e > 14, !p2.c || !p2.c[0] || 1 == p2.c[0] && !p2.e && 1 == p2.c.length || !e4.c || !e4.c[0]) return l2 = new V(Math.pow(+J(p2), u2 ? e4.s * (2 - w(e4)) : +J(e4))), t4 ? l2.mod(t4) : l2;
              if (d2 = e4.s < 0, t4) {
                if (t4.c ? !t4.c[0] : !t4.s) return new V(NaN);
                (n3 = !d2 && p2.isInteger() && t4.isInteger()) && (p2 = p2.mod(t4));
              } else {
                if (e4.e > 9 && (p2.e > 0 || p2.e < -1 || (0 == p2.e ? p2.c[0] > 1 || u2 && p2.c[1] >= 24e7 : p2.c[0] < 8e13 || u2 && p2.c[0] <= 9999975e7))) return o2 = p2.s < 0 && w(e4) ? -0 : 0, p2.e > -1 && (o2 = 1 / o2), new V(d2 ? 1 / o2 : o2);
                F && (o2 = s(F / f + 2));
              }
              for (u2 ? (r4 = new V(0.5), d2 && (e4.s = 1), h2 = w(e4)) : h2 = (i3 = Math.abs(+J(e4))) % 2, l2 = new V(B); ; ) {
                if (h2) {
                  if (!(l2 = l2.times(p2)).c) break;
                  o2 ? l2.c.length > o2 && (l2.c.length = o2) : n3 && (l2 = l2.mod(t4));
                }
                if (i3) {
                  if (0 === (i3 = a(i3 / 2))) break;
                  h2 = i3 % 2;
                } else if (W(e4 = e4.times(r4), e4.e + 1, 1), e4.e > 14) h2 = w(e4);
                else {
                  if (0 == (i3 = +J(e4))) break;
                  h2 = i3 % 2;
                }
                p2 = p2.times(p2), o2 ? p2.c && p2.c.length > o2 && (p2.c.length = o2) : n3 && (p2 = p2.mod(t4));
              }
              return n3 ? l2 : (d2 && (l2 = B.div(l2)), t4 ? l2.mod(t4) : o2 ? W(l2, F, P, void 0) : l2);
            }, I.integerValue = function(e4) {
              var t4 = new V(this);
              return null == e4 ? e4 = P : v(e4, 0, 8), W(t4, t4.e + 1, e4);
            }, I.isEqualTo = I.eq = function(e4, t4) {
              return 0 === g(this, new V(e4, t4));
            }, I.isFinite = function() {
              return !!this.c;
            }, I.isGreaterThan = I.gt = function(e4, t4) {
              return g(this, new V(e4, t4)) > 0;
            }, I.isGreaterThanOrEqualTo = I.gte = function(e4, t4) {
              return 1 === (t4 = g(this, new V(e4, t4))) || 0 === t4;
            }, I.isInteger = function() {
              return !!this.c && y(this.e / f) > this.c.length - 2;
            }, I.isLessThan = I.lt = function(e4, t4) {
              return g(this, new V(e4, t4)) < 0;
            }, I.isLessThanOrEqualTo = I.lte = function(e4, t4) {
              return -1 === (t4 = g(this, new V(e4, t4))) || 0 === t4;
            }, I.isNaN = function() {
              return !this.s;
            }, I.isNegative = function() {
              return this.s < 0;
            }, I.isPositive = function() {
              return this.s > 0;
            }, I.isZero = function() {
              return !!this.c && 0 == this.c[0];
            }, I.minus = function(e4, t4) {
              var r4, n3, i3, o2, s2 = this, a2 = s2.s;
              if (t4 = (e4 = new V(e4, t4)).s, !a2 || !t4) return new V(NaN);
              if (a2 != t4) return e4.s = -t4, s2.plus(e4);
              var c2 = s2.e / f, u2 = e4.e / f, h2 = s2.c, l2 = e4.c;
              if (!c2 || !u2) {
                if (!h2 || !l2) return h2 ? (e4.s = -t4, e4) : new V(l2 ? s2 : NaN);
                if (!h2[0] || !l2[0]) return l2[0] ? (e4.s = -t4, e4) : new V(h2[0] ? s2 : 3 == P ? -0 : 0);
              }
              if (c2 = y(c2), u2 = y(u2), h2 = h2.slice(), a2 = c2 - u2) {
                for ((o2 = a2 < 0) ? (a2 = -a2, i3 = h2) : (u2 = c2, i3 = l2), i3.reverse(), t4 = a2; t4--; i3.push(0)) ;
                i3.reverse();
              } else for (n3 = (o2 = (a2 = h2.length) < (t4 = l2.length)) ? a2 : t4, a2 = t4 = 0; t4 < n3; t4++) if (h2[t4] != l2[t4]) {
                o2 = h2[t4] < l2[t4];
                break;
              }
              if (o2 && (i3 = h2, h2 = l2, l2 = i3, e4.s = -e4.s), (t4 = (n3 = l2.length) - (r4 = h2.length)) > 0) for (; t4--; h2[r4++] = 0) ;
              for (t4 = d - 1; n3 > a2; ) {
                if (h2[--n3] < l2[n3]) {
                  for (r4 = n3; r4 && !h2[--r4]; h2[r4] = t4) ;
                  --h2[r4], h2[n3] += d;
                }
                h2[n3] -= l2[n3];
              }
              for (; 0 == h2[0]; h2.splice(0, 1), --u2) ;
              return h2[0] ? K(e4, h2, u2) : (e4.s = 3 == P ? -1 : 1, e4.c = [e4.e = 0], e4);
            }, I.modulo = I.mod = function(e4, t4) {
              var n3, i3, o2 = this;
              return e4 = new V(e4, t4), !o2.c || !e4.s || e4.c && !e4.c[0] ? new V(NaN) : !e4.c || o2.c && !o2.c[0] ? new V(o2) : (9 == D ? (i3 = e4.s, e4.s = 1, n3 = r3(o2, e4, 0, 3), e4.s = i3, n3.s *= i3) : n3 = r3(o2, e4, 0, D), (e4 = o2.minus(n3.times(e4))).c[0] || 1 != D || (e4.s = o2.s), e4);
            }, I.multipliedBy = I.times = function(e4, t4) {
              var r4, n3, i3, o2, s2, a2, c2, u2, h2, l2, b2, m2, g2, v2, w2, _2 = this, A2 = _2.c, S2 = (e4 = new V(e4, t4)).c;
              if (!(A2 && S2 && A2[0] && S2[0])) return !_2.s || !e4.s || A2 && !A2[0] && !S2 || S2 && !S2[0] && !A2 ? e4.c = e4.e = e4.s = null : (e4.s *= _2.s, A2 && S2 ? (e4.c = [0], e4.e = 0) : e4.c = e4.e = null), e4;
              for (n3 = y(_2.e / f) + y(e4.e / f), e4.s *= _2.s, (c2 = A2.length) < (l2 = S2.length) && (g2 = A2, A2 = S2, S2 = g2, i3 = c2, c2 = l2, l2 = i3), i3 = c2 + l2, g2 = []; i3--; g2.push(0)) ;
              for (v2 = d, w2 = p, i3 = l2; --i3 >= 0; ) {
                for (r4 = 0, b2 = S2[i3] % w2, m2 = S2[i3] / w2 | 0, o2 = i3 + (s2 = c2); o2 > i3; ) r4 = ((u2 = b2 * (u2 = A2[--s2] % w2) + (a2 = m2 * u2 + (h2 = A2[s2] / w2 | 0) * b2) % w2 * w2 + g2[o2] + r4) / v2 | 0) + (a2 / w2 | 0) + m2 * h2, g2[o2--] = u2 % v2;
                g2[o2] = r4;
              }
              return r4 ? ++n3 : g2.splice(0, 1), K(e4, g2, n3);
            }, I.negated = function() {
              var e4 = new V(this);
              return e4.s = -e4.s || null, e4;
            }, I.plus = function(e4, t4) {
              var r4, n3 = this, i3 = n3.s;
              if (t4 = (e4 = new V(e4, t4)).s, !i3 || !t4) return new V(NaN);
              if (i3 != t4) return e4.s = -t4, n3.minus(e4);
              var o2 = n3.e / f, s2 = e4.e / f, a2 = n3.c, c2 = e4.c;
              if (!o2 || !s2) {
                if (!a2 || !c2) return new V(i3 / 0);
                if (!a2[0] || !c2[0]) return c2[0] ? e4 : new V(a2[0] ? n3 : 0 * i3);
              }
              if (o2 = y(o2), s2 = y(s2), a2 = a2.slice(), i3 = o2 - s2) {
                for (i3 > 0 ? (s2 = o2, r4 = c2) : (i3 = -i3, r4 = a2), r4.reverse(); i3--; r4.push(0)) ;
                r4.reverse();
              }
              for ((i3 = a2.length) - (t4 = c2.length) < 0 && (r4 = c2, c2 = a2, a2 = r4, t4 = i3), i3 = 0; t4; ) i3 = (a2[--t4] = a2[t4] + c2[t4] + i3) / d | 0, a2[t4] = d === a2[t4] ? 0 : a2[t4] % d;
              return i3 && (a2 = [i3].concat(a2), ++s2), K(e4, a2, s2);
            }, I.precision = I.sd = function(e4, t4) {
              var r4, n3, i3, o2 = this;
              if (null != e4 && e4 !== !!e4) return v(e4, 1, b), null == t4 ? t4 = P : v(t4, 0, 8), W(new V(o2), e4, t4);
              if (!(r4 = o2.c)) return null;
              if (n3 = (i3 = r4.length - 1) * f + 1, i3 = r4[i3]) {
                for (; i3 % 10 == 0; i3 /= 10, n3--) ;
                for (i3 = r4[0]; i3 >= 10; i3 /= 10, n3++) ;
              }
              return e4 && o2.e + 1 > n3 && (n3 = o2.e + 1), n3;
            }, I.shiftedBy = function(e4) {
              return v(e4, -9007199254740991, h), this.times("1e" + e4);
            }, I.squareRoot = I.sqrt = function() {
              var e4, t4, n3, i3, o2, s2 = this, a2 = s2.c, c2 = s2.s, u2 = s2.e, d2 = U + 4, f2 = new V("0.5");
              if (1 !== c2 || !a2 || !a2[0]) return new V(!c2 || c2 < 0 && (!a2 || a2[0]) ? NaN : a2 ? s2 : 1 / 0);
              if (0 == (c2 = Math.sqrt(+J(s2))) || c2 == 1 / 0 ? (((t4 = m(a2)).length + u2) % 2 == 0 && (t4 += "0"), c2 = Math.sqrt(+t4), u2 = y((u2 + 1) / 2) - (u2 < 0 || u2 % 2), n3 = new V(t4 = c2 == 1 / 0 ? "5e" + u2 : (t4 = c2.toExponential()).slice(0, t4.indexOf("e") + 1) + u2)) : n3 = new V(c2 + ""), n3.c[0]) {
                for ((c2 = (u2 = n3.e) + d2) < 3 && (c2 = 0); ; ) if (o2 = n3, n3 = f2.times(o2.plus(r3(s2, o2, d2, 1))), m(o2.c).slice(0, c2) === (t4 = m(n3.c)).slice(0, c2)) {
                  if (n3.e < u2 && --c2, "9999" != (t4 = t4.slice(c2 - 3, c2 + 1)) && (i3 || "4999" != t4)) {
                    +t4 && (+t4.slice(1) || "5" != t4.charAt(0)) || (W(n3, n3.e + U + 2, 1), e4 = !n3.times(n3).eq(s2));
                    break;
                  }
                  if (!i3 && (W(o2, o2.e + U + 2, 0), o2.times(o2).eq(s2))) {
                    n3 = o2;
                    break;
                  }
                  d2 += 4, c2 += 4, i3 = 1;
                }
              }
              return W(n3, n3.e + U + 1, P, e4);
            }, I.toExponential = function(e4, t4) {
              return null != e4 && (v(e4, 0, b), e4++), G(this, e4, t4, 1);
            }, I.toFixed = function(e4, t4) {
              return null != e4 && (v(e4, 0, b), e4 = e4 + this.e + 1), G(this, e4, t4);
            }, I.toFormat = function(e4, t4, r4) {
              var n3, i3 = this;
              if (null == r4) null != e4 && t4 && "object" == typeof t4 ? (r4 = t4, t4 = null) : e4 && "object" == typeof e4 ? (r4 = e4, e4 = t4 = null) : r4 = H;
              else if ("object" != typeof r4) throw Error(c + "Argument not an object: " + r4);
              if (n3 = i3.toFixed(e4, t4), i3.c) {
                var o2, s2 = n3.split("."), a2 = +r4.groupSize, u2 = +r4.secondaryGroupSize, d2 = r4.groupSeparator || "", f2 = s2[0], h2 = s2[1], l2 = i3.s < 0, p2 = l2 ? f2.slice(1) : f2, b2 = p2.length;
                if (u2 && (o2 = a2, a2 = u2, u2 = o2, b2 -= o2), a2 > 0 && b2 > 0) {
                  for (o2 = b2 % a2 || a2, f2 = p2.substr(0, o2); o2 < b2; o2 += a2) f2 += d2 + p2.substr(o2, a2);
                  u2 > 0 && (f2 += d2 + p2.slice(o2)), l2 && (f2 = "-" + f2);
                }
                n3 = h2 ? f2 + (r4.decimalSeparator || "") + ((u2 = +r4.fractionGroupSize) ? h2.replace(new RegExp("\\d{" + u2 + "}\\B", "g"), "$&" + (r4.fractionGroupSeparator || "")) : h2) : f2;
              }
              return (r4.prefix || "") + n3 + (r4.suffix || "");
            }, I.toFraction = function(e4) {
              var t4, n3, i3, o2, s2, a2, u2, d2, h2, p2, b2, y2, g2 = this, v2 = g2.c;
              if (null != e4 && (!(u2 = new V(e4)).isInteger() && (u2.c || 1 !== u2.s) || u2.lt(B))) throw Error(c + "Argument " + (u2.isInteger() ? "out of range: " : "not an integer: ") + J(u2));
              if (!v2) return new V(g2);
              for (t4 = new V(B), h2 = n3 = new V(B), i3 = d2 = new V(B), y2 = m(v2), s2 = t4.e = y2.length - g2.e - 1, t4.c[0] = l[(a2 = s2 % f) < 0 ? f + a2 : a2], e4 = !e4 || u2.comparedTo(t4) > 0 ? s2 > 0 ? t4 : h2 : u2, a2 = L, L = 1 / 0, u2 = new V(y2), d2.c[0] = 0; p2 = r3(u2, t4, 0, 1), 1 != (o2 = n3.plus(p2.times(i3))).comparedTo(e4); ) n3 = i3, i3 = o2, h2 = d2.plus(p2.times(o2 = h2)), d2 = o2, t4 = u2.minus(p2.times(o2 = t4)), u2 = o2;
              return o2 = r3(e4.minus(n3), i3, 0, 1), d2 = d2.plus(o2.times(h2)), n3 = n3.plus(o2.times(i3)), d2.s = h2.s = g2.s, b2 = r3(h2, i3, s2 *= 2, P).minus(g2).abs().comparedTo(r3(d2, n3, s2, P).minus(g2).abs()) < 1 ? [h2, i3] : [d2, n3], L = a2, b2;
            }, I.toNumber = function() {
              return +J(this);
            }, I.toPrecision = function(e4, t4) {
              return null != e4 && v(e4, 1, b), G(this, e4, t4, 2);
            }, I.toString = function(e4) {
              var t4, r4 = this, i3 = r4.s, o2 = r4.e;
              return null === o2 ? i3 ? (t4 = "Infinity", i3 < 0 && (t4 = "-" + t4)) : t4 = "NaN" : (null == e4 ? t4 = o2 <= O || o2 >= R ? _(m(r4.c), o2) : A(m(r4.c), o2, "0") : 10 === e4 && $ ? t4 = A(m((r4 = W(new V(r4), U + o2 + 1, P)).c), r4.e, "0") : (v(e4, 2, q.length, "Base"), t4 = n2(A(m(r4.c), o2, "0"), 10, e4, i3, true)), i3 < 0 && r4.c[0] && (t4 = "-" + t4)), t4;
            }, I.valueOf = I.toJSON = function() {
              return J(this);
            }, I._isBigNumber = true, null != t3 && V.set(t3), V;
          })(), i.default = i.BigNumber = i, void 0 === (n = function() {
            return i;
          }.call(t2, r2, t2, e2)) || (e2.exports = n);
        })();
      }, 8681: (e2, t2, r2) => {
        const n = r2(1878);
        function i(e3, t3, r3) {
          const n2 = e3[t3] + e3[r3];
          let i2 = e3[t3 + 1] + e3[r3 + 1];
          n2 >= 4294967296 && i2++, e3[t3] = n2, e3[t3 + 1] = i2;
        }
        function o(e3, t3, r3, n2) {
          let i2 = e3[t3] + r3;
          r3 < 0 && (i2 += 4294967296);
          let o2 = e3[t3 + 1] + n2;
          i2 >= 4294967296 && o2++, e3[t3] = i2, e3[t3 + 1] = o2;
        }
        function s(e3, t3) {
          return e3[t3] ^ e3[t3 + 1] << 8 ^ e3[t3 + 2] << 16 ^ e3[t3 + 3] << 24;
        }
        function a(e3, t3, r3, n2, s2, a2) {
          const c2 = f[s2], u2 = f[s2 + 1], h2 = f[a2], l2 = f[a2 + 1];
          i(d, e3, t3), o(d, e3, c2, u2);
          let p2 = d[n2] ^ d[e3], b2 = d[n2 + 1] ^ d[e3 + 1];
          d[n2] = b2, d[n2 + 1] = p2, i(d, r3, n2), p2 = d[t3] ^ d[r3], b2 = d[t3 + 1] ^ d[r3 + 1], d[t3] = p2 >>> 24 ^ b2 << 8, d[t3 + 1] = b2 >>> 24 ^ p2 << 8, i(d, e3, t3), o(d, e3, h2, l2), p2 = d[n2] ^ d[e3], b2 = d[n2 + 1] ^ d[e3 + 1], d[n2] = p2 >>> 16 ^ b2 << 16, d[n2 + 1] = b2 >>> 16 ^ p2 << 16, i(d, r3, n2), p2 = d[t3] ^ d[r3], b2 = d[t3 + 1] ^ d[r3 + 1], d[t3] = b2 >>> 31 ^ p2 << 1, d[t3 + 1] = p2 >>> 31 ^ b2 << 1;
        }
        const c = new Uint32Array([4089235720, 1779033703, 2227873595, 3144134277, 4271175723, 1013904242, 1595750129, 2773480762, 2917565137, 1359893119, 725511199, 2600822924, 4215389547, 528734635, 327033209, 1541459225]), u = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3].map((function(e3) {
          return 2 * e3;
        }))), d = new Uint32Array(32), f = new Uint32Array(32);
        function h(e3, t3) {
          let r3 = 0;
          for (r3 = 0; r3 < 16; r3++) d[r3] = e3.h[r3], d[r3 + 16] = c[r3];
          for (d[24] = d[24] ^ e3.t, d[25] = d[25] ^ e3.t / 4294967296, t3 && (d[28] = ~d[28], d[29] = ~d[29]), r3 = 0; r3 < 32; r3++) f[r3] = s(e3.b, 4 * r3);
          for (r3 = 0; r3 < 12; r3++) a(0, 8, 16, 24, u[16 * r3 + 0], u[16 * r3 + 1]), a(2, 10, 18, 26, u[16 * r3 + 2], u[16 * r3 + 3]), a(4, 12, 20, 28, u[16 * r3 + 4], u[16 * r3 + 5]), a(6, 14, 22, 30, u[16 * r3 + 6], u[16 * r3 + 7]), a(0, 10, 20, 30, u[16 * r3 + 8], u[16 * r3 + 9]), a(2, 12, 22, 24, u[16 * r3 + 10], u[16 * r3 + 11]), a(4, 14, 16, 26, u[16 * r3 + 12], u[16 * r3 + 13]), a(6, 8, 18, 28, u[16 * r3 + 14], u[16 * r3 + 15]);
          for (r3 = 0; r3 < 16; r3++) e3.h[r3] = e3.h[r3] ^ d[r3] ^ d[r3 + 16];
        }
        const l = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        function p(e3, t3, r3, n2) {
          if (0 === e3 || e3 > 64) throw new Error("Illegal output length, expected 0 < length <= 64");
          if (t3 && t3.length > 64) throw new Error("Illegal key, expected Uint8Array with 0 < length <= 64");
          if (r3 && 16 !== r3.length) throw new Error("Illegal salt, expected Uint8Array with length is 16");
          if (n2 && 16 !== n2.length) throw new Error("Illegal personal, expected Uint8Array with length is 16");
          const i2 = { b: new Uint8Array(128), h: new Uint32Array(16), t: 0, c: 0, outlen: e3 };
          l.fill(0), l[0] = e3, t3 && (l[1] = t3.length), l[2] = 1, l[3] = 1, r3 && l.set(r3, 32), n2 && l.set(n2, 48);
          for (let e4 = 0; e4 < 16; e4++) i2.h[e4] = c[e4] ^ s(l, 4 * e4);
          return t3 && (b(i2, t3), i2.c = 128), i2;
        }
        function b(e3, t3) {
          for (let r3 = 0; r3 < t3.length; r3++) 128 === e3.c && (e3.t += e3.c, h(e3, false), e3.c = 0), e3.b[e3.c++] = t3[r3];
        }
        function y(e3) {
          for (e3.t += e3.c; e3.c < 128; ) e3.b[e3.c++] = 0;
          h(e3, true);
          const t3 = new Uint8Array(e3.outlen);
          for (let r3 = 0; r3 < e3.outlen; r3++) t3[r3] = e3.h[r3 >> 2] >> 8 * (3 & r3);
          return t3;
        }
        function m(e3, t3, r3, i2, o2) {
          r3 = r3 || 64, e3 = n.normalizeInput(e3), i2 && (i2 = n.normalizeInput(i2)), o2 && (o2 = n.normalizeInput(o2));
          const s2 = p(r3, t3, i2, o2);
          return b(s2, e3), y(s2);
        }
        e2.exports = { blake2b: m, blake2bHex: function(e3, t3, r3, i2, o2) {
          const s2 = m(e3, t3, r3, i2, o2);
          return n.toHex(s2);
        }, blake2bInit: p, blake2bUpdate: b, blake2bFinal: y };
      }, 7690: (e2, t2, r2) => {
        const n = r2(1878);
        function i(e3, t3) {
          return e3[t3] ^ e3[t3 + 1] << 8 ^ e3[t3 + 2] << 16 ^ e3[t3 + 3] << 24;
        }
        function o(e3, t3, r3, n2, i2, o2) {
          u[e3] = u[e3] + u[t3] + i2, u[n2] = s(u[n2] ^ u[e3], 16), u[r3] = u[r3] + u[n2], u[t3] = s(u[t3] ^ u[r3], 12), u[e3] = u[e3] + u[t3] + o2, u[n2] = s(u[n2] ^ u[e3], 8), u[r3] = u[r3] + u[n2], u[t3] = s(u[t3] ^ u[r3], 7);
        }
        function s(e3, t3) {
          return e3 >>> t3 ^ e3 << 32 - t3;
        }
        const a = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]), c = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]), u = new Uint32Array(16), d = new Uint32Array(16);
        function f(e3, t3) {
          let r3 = 0;
          for (r3 = 0; r3 < 8; r3++) u[r3] = e3.h[r3], u[r3 + 8] = a[r3];
          for (u[12] ^= e3.t, u[13] ^= e3.t / 4294967296, t3 && (u[14] = ~u[14]), r3 = 0; r3 < 16; r3++) d[r3] = i(e3.b, 4 * r3);
          for (r3 = 0; r3 < 10; r3++) o(0, 4, 8, 12, d[c[16 * r3 + 0]], d[c[16 * r3 + 1]]), o(1, 5, 9, 13, d[c[16 * r3 + 2]], d[c[16 * r3 + 3]]), o(2, 6, 10, 14, d[c[16 * r3 + 4]], d[c[16 * r3 + 5]]), o(3, 7, 11, 15, d[c[16 * r3 + 6]], d[c[16 * r3 + 7]]), o(0, 5, 10, 15, d[c[16 * r3 + 8]], d[c[16 * r3 + 9]]), o(1, 6, 11, 12, d[c[16 * r3 + 10]], d[c[16 * r3 + 11]]), o(2, 7, 8, 13, d[c[16 * r3 + 12]], d[c[16 * r3 + 13]]), o(3, 4, 9, 14, d[c[16 * r3 + 14]], d[c[16 * r3 + 15]]);
          for (r3 = 0; r3 < 8; r3++) e3.h[r3] ^= u[r3] ^ u[r3 + 8];
        }
        function h(e3, t3) {
          if (!(e3 > 0 && e3 <= 32)) throw new Error("Incorrect output length, should be in [1, 32]");
          const r3 = t3 ? t3.length : 0;
          if (t3 && !(r3 > 0 && r3 <= 32)) throw new Error("Incorrect key length, should be in [1, 32]");
          const n2 = { h: new Uint32Array(a), b: new Uint8Array(64), c: 0, t: 0, outlen: e3 };
          return n2.h[0] ^= 16842752 ^ r3 << 8 ^ e3, r3 > 0 && (l(n2, t3), n2.c = 64), n2;
        }
        function l(e3, t3) {
          for (let r3 = 0; r3 < t3.length; r3++) 64 === e3.c && (e3.t += e3.c, f(e3, false), e3.c = 0), e3.b[e3.c++] = t3[r3];
        }
        function p(e3) {
          for (e3.t += e3.c; e3.c < 64; ) e3.b[e3.c++] = 0;
          f(e3, true);
          const t3 = new Uint8Array(e3.outlen);
          for (let r3 = 0; r3 < e3.outlen; r3++) t3[r3] = e3.h[r3 >> 2] >> 8 * (3 & r3) & 255;
          return t3;
        }
        function b(e3, t3, r3) {
          r3 = r3 || 32, e3 = n.normalizeInput(e3);
          const i2 = h(r3, t3);
          return l(i2, e3), p(i2);
        }
        e2.exports = { blake2s: b, blake2sHex: function(e3, t3, r3) {
          const i2 = b(e3, t3, r3);
          return n.toHex(i2);
        }, blake2sInit: h, blake2sUpdate: l, blake2sFinal: p };
      }, 1540: (e2, t2, r2) => {
        const n = r2(8681), i = r2(7690);
        e2.exports = { blake2b: n.blake2b, blake2bHex: n.blake2bHex, blake2bInit: n.blake2bInit, blake2bUpdate: n.blake2bUpdate, blake2bFinal: n.blake2bFinal, blake2s: i.blake2s, blake2sHex: i.blake2sHex, blake2sInit: i.blake2sInit, blake2sUpdate: i.blake2sUpdate, blake2sFinal: i.blake2sFinal };
      }, 1878: (e2) => {
        function t2(e3) {
          return (4294967296 + e3).toString(16).substring(1);
        }
        e2.exports = { normalizeInput: function(e3) {
          let t3;
          if (e3 instanceof Uint8Array) t3 = e3;
          else {
            if ("string" != typeof e3) throw new Error("Input must be an string, Buffer or Uint8Array");
            t3 = new TextEncoder().encode(e3);
          }
          return t3;
        }, toHex: function(e3) {
          return Array.prototype.map.call(e3, (function(e4) {
            return (e4 < 16 ? "0" : "") + e4.toString(16);
          })).join("");
        }, debugPrint: function(e3, r2, n) {
          let i = "\n" + e3 + " = ";
          for (let o = 0; o < r2.length; o += 2) {
            if (32 === n) i += t2(r2[o]).toUpperCase(), i += " ", i += t2(r2[o + 1]).toUpperCase();
            else {
              if (64 !== n) throw new Error("Invalid size " + n);
              i += t2(r2[o + 1]).toUpperCase(), i += t2(r2[o]).toUpperCase();
            }
            o % 6 == 4 ? i += "\n" + new Array(e3.length + 4).join(" ") : o < r2.length - 2 && (i += " ");
          }
          console.log(i);
        }, testSpeed: function(e3, t3, r2) {
          let n = (/* @__PURE__ */ new Date()).getTime();
          const i = new Uint8Array(t3);
          for (let e4 = 0; e4 < t3; e4++) i[e4] = e4 % 256;
          const o = (/* @__PURE__ */ new Date()).getTime();
          console.log("Generated random input in " + (o - n) + "ms"), n = o;
          for (let o2 = 0; o2 < r2; o2++) {
            const r3 = e3(i), o3 = (/* @__PURE__ */ new Date()).getTime(), s = o3 - n;
            n = o3, console.log("Hashed in " + s + "ms: " + r3.substring(0, 20) + "..."), console.log(Math.round(t3 / (1 << 20) / (s / 1e3) * 100) / 100 + " MB PER SECOND");
          }
        } };
      }, 4619: function(e2, t2, r2) {
        !(function(e3, t3) {
          "use strict";
          function n(e4, t4) {
            if (!e4) throw new Error(t4 || "Assertion failed");
          }
          function i(e4, t4) {
            e4.super_ = t4;
            var r3 = function() {
            };
            r3.prototype = t4.prototype, e4.prototype = new r3(), e4.prototype.constructor = e4;
          }
          function o(e4, t4, r3) {
            if (o.isBN(e4)) return e4;
            this.negative = 0, this.words = null, this.length = 0, this.red = null, null !== e4 && ("le" !== t4 && "be" !== t4 || (r3 = t4, t4 = 10), this._init(e4 || 0, t4 || 10, r3 || "be"));
          }
          var s;
          "object" == typeof e3 ? e3.exports = o : t3.BN = o, o.BN = o, o.wordSize = 26;
          try {
            s = "undefined" != typeof window && void 0 !== window.Buffer ? window.Buffer : r2(7175).Buffer;
          } catch (e4) {
          }
          function a(e4, t4) {
            var r3 = e4.charCodeAt(t4);
            return r3 >= 65 && r3 <= 70 ? r3 - 55 : r3 >= 97 && r3 <= 102 ? r3 - 87 : r3 - 48 & 15;
          }
          function c(e4, t4, r3) {
            var n2 = a(e4, r3);
            return r3 - 1 >= t4 && (n2 |= a(e4, r3 - 1) << 4), n2;
          }
          function u(e4, t4, r3, n2) {
            for (var i2 = 0, o2 = Math.min(e4.length, r3), s2 = t4; s2 < o2; s2++) {
              var a2 = e4.charCodeAt(s2) - 48;
              i2 *= n2, i2 += a2 >= 49 ? a2 - 49 + 10 : a2 >= 17 ? a2 - 17 + 10 : a2;
            }
            return i2;
          }
          o.isBN = function(e4) {
            return e4 instanceof o || null !== e4 && "object" == typeof e4 && e4.constructor.wordSize === o.wordSize && Array.isArray(e4.words);
          }, o.max = function(e4, t4) {
            return e4.cmp(t4) > 0 ? e4 : t4;
          }, o.min = function(e4, t4) {
            return e4.cmp(t4) < 0 ? e4 : t4;
          }, o.prototype._init = function(e4, t4, r3) {
            if ("number" == typeof e4) return this._initNumber(e4, t4, r3);
            if ("object" == typeof e4) return this._initArray(e4, t4, r3);
            "hex" === t4 && (t4 = 16), n(t4 === (0 | t4) && t4 >= 2 && t4 <= 36);
            var i2 = 0;
            "-" === (e4 = e4.toString().replace(/\s+/g, ""))[0] && (i2++, this.negative = 1), i2 < e4.length && (16 === t4 ? this._parseHex(e4, i2, r3) : (this._parseBase(e4, t4, i2), "le" === r3 && this._initArray(this.toArray(), t4, r3)));
          }, o.prototype._initNumber = function(e4, t4, r3) {
            e4 < 0 && (this.negative = 1, e4 = -e4), e4 < 67108864 ? (this.words = [67108863 & e4], this.length = 1) : e4 < 4503599627370496 ? (this.words = [67108863 & e4, e4 / 67108864 & 67108863], this.length = 2) : (n(e4 < 9007199254740992), this.words = [67108863 & e4, e4 / 67108864 & 67108863, 1], this.length = 3), "le" === r3 && this._initArray(this.toArray(), t4, r3);
          }, o.prototype._initArray = function(e4, t4, r3) {
            if (n("number" == typeof e4.length), e4.length <= 0) return this.words = [0], this.length = 1, this;
            this.length = Math.ceil(e4.length / 3), this.words = new Array(this.length);
            for (var i2 = 0; i2 < this.length; i2++) this.words[i2] = 0;
            var o2, s2, a2 = 0;
            if ("be" === r3) for (i2 = e4.length - 1, o2 = 0; i2 >= 0; i2 -= 3) s2 = e4[i2] | e4[i2 - 1] << 8 | e4[i2 - 2] << 16, this.words[o2] |= s2 << a2 & 67108863, this.words[o2 + 1] = s2 >>> 26 - a2 & 67108863, (a2 += 24) >= 26 && (a2 -= 26, o2++);
            else if ("le" === r3) for (i2 = 0, o2 = 0; i2 < e4.length; i2 += 3) s2 = e4[i2] | e4[i2 + 1] << 8 | e4[i2 + 2] << 16, this.words[o2] |= s2 << a2 & 67108863, this.words[o2 + 1] = s2 >>> 26 - a2 & 67108863, (a2 += 24) >= 26 && (a2 -= 26, o2++);
            return this.strip();
          }, o.prototype._parseHex = function(e4, t4, r3) {
            this.length = Math.ceil((e4.length - t4) / 6), this.words = new Array(this.length);
            for (var n2 = 0; n2 < this.length; n2++) this.words[n2] = 0;
            var i2, o2 = 0, s2 = 0;
            if ("be" === r3) for (n2 = e4.length - 1; n2 >= t4; n2 -= 2) i2 = c(e4, t4, n2) << o2, this.words[s2] |= 67108863 & i2, o2 >= 18 ? (o2 -= 18, s2 += 1, this.words[s2] |= i2 >>> 26) : o2 += 8;
            else for (n2 = (e4.length - t4) % 2 == 0 ? t4 + 1 : t4; n2 < e4.length; n2 += 2) i2 = c(e4, t4, n2) << o2, this.words[s2] |= 67108863 & i2, o2 >= 18 ? (o2 -= 18, s2 += 1, this.words[s2] |= i2 >>> 26) : o2 += 8;
            this.strip();
          }, o.prototype._parseBase = function(e4, t4, r3) {
            this.words = [0], this.length = 1;
            for (var n2 = 0, i2 = 1; i2 <= 67108863; i2 *= t4) n2++;
            n2--, i2 = i2 / t4 | 0;
            for (var o2 = e4.length - r3, s2 = o2 % n2, a2 = Math.min(o2, o2 - s2) + r3, c2 = 0, d2 = r3; d2 < a2; d2 += n2) c2 = u(e4, d2, d2 + n2, t4), this.imuln(i2), this.words[0] + c2 < 67108864 ? this.words[0] += c2 : this._iaddn(c2);
            if (0 !== s2) {
              var f2 = 1;
              for (c2 = u(e4, d2, e4.length, t4), d2 = 0; d2 < s2; d2++) f2 *= t4;
              this.imuln(f2), this.words[0] + c2 < 67108864 ? this.words[0] += c2 : this._iaddn(c2);
            }
            this.strip();
          }, o.prototype.copy = function(e4) {
            e4.words = new Array(this.length);
            for (var t4 = 0; t4 < this.length; t4++) e4.words[t4] = this.words[t4];
            e4.length = this.length, e4.negative = this.negative, e4.red = this.red;
          }, o.prototype.clone = function() {
            var e4 = new o(null);
            return this.copy(e4), e4;
          }, o.prototype._expand = function(e4) {
            for (; this.length < e4; ) this.words[this.length++] = 0;
            return this;
          }, o.prototype.strip = function() {
            for (; this.length > 1 && 0 === this.words[this.length - 1]; ) this.length--;
            return this._normSign();
          }, o.prototype._normSign = function() {
            return 1 === this.length && 0 === this.words[0] && (this.negative = 0), this;
          }, o.prototype.inspect = function() {
            return (this.red ? "<BN-R: " : "<BN: ") + this.toString(16) + ">";
          };
          var d = ["", "0", "00", "000", "0000", "00000", "000000", "0000000", "00000000", "000000000", "0000000000", "00000000000", "000000000000", "0000000000000", "00000000000000", "000000000000000", "0000000000000000", "00000000000000000", "000000000000000000", "0000000000000000000", "00000000000000000000", "000000000000000000000", "0000000000000000000000", "00000000000000000000000", "000000000000000000000000", "0000000000000000000000000"], f = [0, 0, 25, 16, 12, 11, 10, 9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], h = [0, 0, 33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216, 43046721, 1e7, 19487171, 35831808, 62748517, 7529536, 11390625, 16777216, 24137569, 34012224, 47045881, 64e6, 4084101, 5153632, 6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149, 243e5, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176];
          function l(e4, t4, r3) {
            r3.negative = t4.negative ^ e4.negative;
            var n2 = e4.length + t4.length | 0;
            r3.length = n2, n2 = n2 - 1 | 0;
            var i2 = 0 | e4.words[0], o2 = 0 | t4.words[0], s2 = i2 * o2, a2 = 67108863 & s2, c2 = s2 / 67108864 | 0;
            r3.words[0] = a2;
            for (var u2 = 1; u2 < n2; u2++) {
              for (var d2 = c2 >>> 26, f2 = 67108863 & c2, h2 = Math.min(u2, t4.length - 1), l2 = Math.max(0, u2 - e4.length + 1); l2 <= h2; l2++) {
                var p2 = u2 - l2 | 0;
                d2 += (s2 = (i2 = 0 | e4.words[p2]) * (o2 = 0 | t4.words[l2]) + f2) / 67108864 | 0, f2 = 67108863 & s2;
              }
              r3.words[u2] = 0 | f2, c2 = 0 | d2;
            }
            return 0 !== c2 ? r3.words[u2] = 0 | c2 : r3.length--, r3.strip();
          }
          o.prototype.toString = function(e4, t4) {
            var r3;
            if (t4 = 0 | t4 || 1, 16 === (e4 = e4 || 10) || "hex" === e4) {
              r3 = "";
              for (var i2 = 0, o2 = 0, s2 = 0; s2 < this.length; s2++) {
                var a2 = this.words[s2], c2 = (16777215 & (a2 << i2 | o2)).toString(16);
                r3 = 0 != (o2 = a2 >>> 24 - i2 & 16777215) || s2 !== this.length - 1 ? d[6 - c2.length] + c2 + r3 : c2 + r3, (i2 += 2) >= 26 && (i2 -= 26, s2--);
              }
              for (0 !== o2 && (r3 = o2.toString(16) + r3); r3.length % t4 != 0; ) r3 = "0" + r3;
              return 0 !== this.negative && (r3 = "-" + r3), r3;
            }
            if (e4 === (0 | e4) && e4 >= 2 && e4 <= 36) {
              var u2 = f[e4], l2 = h[e4];
              r3 = "";
              var p2 = this.clone();
              for (p2.negative = 0; !p2.isZero(); ) {
                var b2 = p2.modn(l2).toString(e4);
                r3 = (p2 = p2.idivn(l2)).isZero() ? b2 + r3 : d[u2 - b2.length] + b2 + r3;
              }
              for (this.isZero() && (r3 = "0" + r3); r3.length % t4 != 0; ) r3 = "0" + r3;
              return 0 !== this.negative && (r3 = "-" + r3), r3;
            }
            n(false, "Base should be between 2 and 36");
          }, o.prototype.toNumber = function() {
            var e4 = this.words[0];
            return 2 === this.length ? e4 += 67108864 * this.words[1] : 3 === this.length && 1 === this.words[2] ? e4 += 4503599627370496 + 67108864 * this.words[1] : this.length > 2 && n(false, "Number can only safely store up to 53 bits"), 0 !== this.negative ? -e4 : e4;
          }, o.prototype.toJSON = function() {
            return this.toString(16);
          }, o.prototype.toBuffer = function(e4, t4) {
            return n(void 0 !== s), this.toArrayLike(s, e4, t4);
          }, o.prototype.toArray = function(e4, t4) {
            return this.toArrayLike(Array, e4, t4);
          }, o.prototype.toArrayLike = function(e4, t4, r3) {
            var i2 = this.byteLength(), o2 = r3 || Math.max(1, i2);
            n(i2 <= o2, "byte array longer than desired length"), n(o2 > 0, "Requested array length <= 0"), this.strip();
            var s2, a2, c2 = "le" === t4, u2 = new e4(o2), d2 = this.clone();
            if (c2) {
              for (a2 = 0; !d2.isZero(); a2++) s2 = d2.andln(255), d2.iushrn(8), u2[a2] = s2;
              for (; a2 < o2; a2++) u2[a2] = 0;
            } else {
              for (a2 = 0; a2 < o2 - i2; a2++) u2[a2] = 0;
              for (a2 = 0; !d2.isZero(); a2++) s2 = d2.andln(255), d2.iushrn(8), u2[o2 - a2 - 1] = s2;
            }
            return u2;
          }, Math.clz32 ? o.prototype._countBits = function(e4) {
            return 32 - Math.clz32(e4);
          } : o.prototype._countBits = function(e4) {
            var t4 = e4, r3 = 0;
            return t4 >= 4096 && (r3 += 13, t4 >>>= 13), t4 >= 64 && (r3 += 7, t4 >>>= 7), t4 >= 8 && (r3 += 4, t4 >>>= 4), t4 >= 2 && (r3 += 2, t4 >>>= 2), r3 + t4;
          }, o.prototype._zeroBits = function(e4) {
            if (0 === e4) return 26;
            var t4 = e4, r3 = 0;
            return 8191 & t4 || (r3 += 13, t4 >>>= 13), 127 & t4 || (r3 += 7, t4 >>>= 7), 15 & t4 || (r3 += 4, t4 >>>= 4), 3 & t4 || (r3 += 2, t4 >>>= 2), 1 & t4 || r3++, r3;
          }, o.prototype.bitLength = function() {
            var e4 = this.words[this.length - 1], t4 = this._countBits(e4);
            return 26 * (this.length - 1) + t4;
          }, o.prototype.zeroBits = function() {
            if (this.isZero()) return 0;
            for (var e4 = 0, t4 = 0; t4 < this.length; t4++) {
              var r3 = this._zeroBits(this.words[t4]);
              if (e4 += r3, 26 !== r3) break;
            }
            return e4;
          }, o.prototype.byteLength = function() {
            return Math.ceil(this.bitLength() / 8);
          }, o.prototype.toTwos = function(e4) {
            return 0 !== this.negative ? this.abs().inotn(e4).iaddn(1) : this.clone();
          }, o.prototype.fromTwos = function(e4) {
            return this.testn(e4 - 1) ? this.notn(e4).iaddn(1).ineg() : this.clone();
          }, o.prototype.isNeg = function() {
            return 0 !== this.negative;
          }, o.prototype.neg = function() {
            return this.clone().ineg();
          }, o.prototype.ineg = function() {
            return this.isZero() || (this.negative ^= 1), this;
          }, o.prototype.iuor = function(e4) {
            for (; this.length < e4.length; ) this.words[this.length++] = 0;
            for (var t4 = 0; t4 < e4.length; t4++) this.words[t4] = this.words[t4] | e4.words[t4];
            return this.strip();
          }, o.prototype.ior = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuor(e4);
          }, o.prototype.or = function(e4) {
            return this.length > e4.length ? this.clone().ior(e4) : e4.clone().ior(this);
          }, o.prototype.uor = function(e4) {
            return this.length > e4.length ? this.clone().iuor(e4) : e4.clone().iuor(this);
          }, o.prototype.iuand = function(e4) {
            var t4;
            t4 = this.length > e4.length ? e4 : this;
            for (var r3 = 0; r3 < t4.length; r3++) this.words[r3] = this.words[r3] & e4.words[r3];
            return this.length = t4.length, this.strip();
          }, o.prototype.iand = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuand(e4);
          }, o.prototype.and = function(e4) {
            return this.length > e4.length ? this.clone().iand(e4) : e4.clone().iand(this);
          }, o.prototype.uand = function(e4) {
            return this.length > e4.length ? this.clone().iuand(e4) : e4.clone().iuand(this);
          }, o.prototype.iuxor = function(e4) {
            var t4, r3;
            this.length > e4.length ? (t4 = this, r3 = e4) : (t4 = e4, r3 = this);
            for (var n2 = 0; n2 < r3.length; n2++) this.words[n2] = t4.words[n2] ^ r3.words[n2];
            if (this !== t4) for (; n2 < t4.length; n2++) this.words[n2] = t4.words[n2];
            return this.length = t4.length, this.strip();
          }, o.prototype.ixor = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuxor(e4);
          }, o.prototype.xor = function(e4) {
            return this.length > e4.length ? this.clone().ixor(e4) : e4.clone().ixor(this);
          }, o.prototype.uxor = function(e4) {
            return this.length > e4.length ? this.clone().iuxor(e4) : e4.clone().iuxor(this);
          }, o.prototype.inotn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = 0 | Math.ceil(e4 / 26), r3 = e4 % 26;
            this._expand(t4), r3 > 0 && t4--;
            for (var i2 = 0; i2 < t4; i2++) this.words[i2] = 67108863 & ~this.words[i2];
            return r3 > 0 && (this.words[i2] = ~this.words[i2] & 67108863 >> 26 - r3), this.strip();
          }, o.prototype.notn = function(e4) {
            return this.clone().inotn(e4);
          }, o.prototype.setn = function(e4, t4) {
            n("number" == typeof e4 && e4 >= 0);
            var r3 = e4 / 26 | 0, i2 = e4 % 26;
            return this._expand(r3 + 1), this.words[r3] = t4 ? this.words[r3] | 1 << i2 : this.words[r3] & ~(1 << i2), this.strip();
          }, o.prototype.iadd = function(e4) {
            var t4, r3, n2;
            if (0 !== this.negative && 0 === e4.negative) return this.negative = 0, t4 = this.isub(e4), this.negative ^= 1, this._normSign();
            if (0 === this.negative && 0 !== e4.negative) return e4.negative = 0, t4 = this.isub(e4), e4.negative = 1, t4._normSign();
            this.length > e4.length ? (r3 = this, n2 = e4) : (r3 = e4, n2 = this);
            for (var i2 = 0, o2 = 0; o2 < n2.length; o2++) t4 = (0 | r3.words[o2]) + (0 | n2.words[o2]) + i2, this.words[o2] = 67108863 & t4, i2 = t4 >>> 26;
            for (; 0 !== i2 && o2 < r3.length; o2++) t4 = (0 | r3.words[o2]) + i2, this.words[o2] = 67108863 & t4, i2 = t4 >>> 26;
            if (this.length = r3.length, 0 !== i2) this.words[this.length] = i2, this.length++;
            else if (r3 !== this) for (; o2 < r3.length; o2++) this.words[o2] = r3.words[o2];
            return this;
          }, o.prototype.add = function(e4) {
            var t4;
            return 0 !== e4.negative && 0 === this.negative ? (e4.negative = 0, t4 = this.sub(e4), e4.negative ^= 1, t4) : 0 === e4.negative && 0 !== this.negative ? (this.negative = 0, t4 = e4.sub(this), this.negative = 1, t4) : this.length > e4.length ? this.clone().iadd(e4) : e4.clone().iadd(this);
          }, o.prototype.isub = function(e4) {
            if (0 !== e4.negative) {
              e4.negative = 0;
              var t4 = this.iadd(e4);
              return e4.negative = 1, t4._normSign();
            }
            if (0 !== this.negative) return this.negative = 0, this.iadd(e4), this.negative = 1, this._normSign();
            var r3, n2, i2 = this.cmp(e4);
            if (0 === i2) return this.negative = 0, this.length = 1, this.words[0] = 0, this;
            i2 > 0 ? (r3 = this, n2 = e4) : (r3 = e4, n2 = this);
            for (var o2 = 0, s2 = 0; s2 < n2.length; s2++) o2 = (t4 = (0 | r3.words[s2]) - (0 | n2.words[s2]) + o2) >> 26, this.words[s2] = 67108863 & t4;
            for (; 0 !== o2 && s2 < r3.length; s2++) o2 = (t4 = (0 | r3.words[s2]) + o2) >> 26, this.words[s2] = 67108863 & t4;
            if (0 === o2 && s2 < r3.length && r3 !== this) for (; s2 < r3.length; s2++) this.words[s2] = r3.words[s2];
            return this.length = Math.max(this.length, s2), r3 !== this && (this.negative = 1), this.strip();
          }, o.prototype.sub = function(e4) {
            return this.clone().isub(e4);
          };
          var p = function(e4, t4, r3) {
            var n2, i2, o2, s2 = e4.words, a2 = t4.words, c2 = r3.words, u2 = 0, d2 = 0 | s2[0], f2 = 8191 & d2, h2 = d2 >>> 13, l2 = 0 | s2[1], p2 = 8191 & l2, b2 = l2 >>> 13, y2 = 0 | s2[2], m2 = 8191 & y2, g2 = y2 >>> 13, v2 = 0 | s2[3], w2 = 8191 & v2, _2 = v2 >>> 13, A2 = 0 | s2[4], S2 = 8191 & A2, C2 = A2 >>> 13, T = 0 | s2[5], M = 8191 & T, E = T >>> 13, k = 0 | s2[6], x = 8191 & k, I = k >>> 13, B = 0 | s2[7], U = 8191 & B, P = B >>> 13, O = 0 | s2[8], R = 8191 & O, N = O >>> 13, L = 0 | s2[9], j = 8191 & L, D = L >>> 13, F = 0 | a2[0], H = 8191 & F, q = F >>> 13, $ = 0 | a2[1], V = 8191 & $, G = $ >>> 13, z = 0 | a2[2], K = 8191 & z, W = z >>> 13, J = 0 | a2[3], Z = 8191 & J, X = J >>> 13, Y = 0 | a2[4], Q = 8191 & Y, ee = Y >>> 13, te = 0 | a2[5], re = 8191 & te, ne = te >>> 13, ie = 0 | a2[6], oe = 8191 & ie, se = ie >>> 13, ae = 0 | a2[7], ce = 8191 & ae, ue = ae >>> 13, de = 0 | a2[8], fe = 8191 & de, he = de >>> 13, le = 0 | a2[9], pe = 8191 & le, be = le >>> 13;
            r3.negative = e4.negative ^ t4.negative, r3.length = 19;
            var ye = (u2 + (n2 = Math.imul(f2, H)) | 0) + ((8191 & (i2 = (i2 = Math.imul(f2, q)) + Math.imul(h2, H) | 0)) << 13) | 0;
            u2 = ((o2 = Math.imul(h2, q)) + (i2 >>> 13) | 0) + (ye >>> 26) | 0, ye &= 67108863, n2 = Math.imul(p2, H), i2 = (i2 = Math.imul(p2, q)) + Math.imul(b2, H) | 0, o2 = Math.imul(b2, q);
            var me = (u2 + (n2 = n2 + Math.imul(f2, V) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, G) | 0) + Math.imul(h2, V) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, G) | 0) + (i2 >>> 13) | 0) + (me >>> 26) | 0, me &= 67108863, n2 = Math.imul(m2, H), i2 = (i2 = Math.imul(m2, q)) + Math.imul(g2, H) | 0, o2 = Math.imul(g2, q), n2 = n2 + Math.imul(p2, V) | 0, i2 = (i2 = i2 + Math.imul(p2, G) | 0) + Math.imul(b2, V) | 0, o2 = o2 + Math.imul(b2, G) | 0;
            var ge = (u2 + (n2 = n2 + Math.imul(f2, K) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, W) | 0) + Math.imul(h2, K) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, W) | 0) + (i2 >>> 13) | 0) + (ge >>> 26) | 0, ge &= 67108863, n2 = Math.imul(w2, H), i2 = (i2 = Math.imul(w2, q)) + Math.imul(_2, H) | 0, o2 = Math.imul(_2, q), n2 = n2 + Math.imul(m2, V) | 0, i2 = (i2 = i2 + Math.imul(m2, G) | 0) + Math.imul(g2, V) | 0, o2 = o2 + Math.imul(g2, G) | 0, n2 = n2 + Math.imul(p2, K) | 0, i2 = (i2 = i2 + Math.imul(p2, W) | 0) + Math.imul(b2, K) | 0, o2 = o2 + Math.imul(b2, W) | 0;
            var ve = (u2 + (n2 = n2 + Math.imul(f2, Z) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, X) | 0) + Math.imul(h2, Z) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, X) | 0) + (i2 >>> 13) | 0) + (ve >>> 26) | 0, ve &= 67108863, n2 = Math.imul(S2, H), i2 = (i2 = Math.imul(S2, q)) + Math.imul(C2, H) | 0, o2 = Math.imul(C2, q), n2 = n2 + Math.imul(w2, V) | 0, i2 = (i2 = i2 + Math.imul(w2, G) | 0) + Math.imul(_2, V) | 0, o2 = o2 + Math.imul(_2, G) | 0, n2 = n2 + Math.imul(m2, K) | 0, i2 = (i2 = i2 + Math.imul(m2, W) | 0) + Math.imul(g2, K) | 0, o2 = o2 + Math.imul(g2, W) | 0, n2 = n2 + Math.imul(p2, Z) | 0, i2 = (i2 = i2 + Math.imul(p2, X) | 0) + Math.imul(b2, Z) | 0, o2 = o2 + Math.imul(b2, X) | 0;
            var we = (u2 + (n2 = n2 + Math.imul(f2, Q) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ee) | 0) + Math.imul(h2, Q) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ee) | 0) + (i2 >>> 13) | 0) + (we >>> 26) | 0, we &= 67108863, n2 = Math.imul(M, H), i2 = (i2 = Math.imul(M, q)) + Math.imul(E, H) | 0, o2 = Math.imul(E, q), n2 = n2 + Math.imul(S2, V) | 0, i2 = (i2 = i2 + Math.imul(S2, G) | 0) + Math.imul(C2, V) | 0, o2 = o2 + Math.imul(C2, G) | 0, n2 = n2 + Math.imul(w2, K) | 0, i2 = (i2 = i2 + Math.imul(w2, W) | 0) + Math.imul(_2, K) | 0, o2 = o2 + Math.imul(_2, W) | 0, n2 = n2 + Math.imul(m2, Z) | 0, i2 = (i2 = i2 + Math.imul(m2, X) | 0) + Math.imul(g2, Z) | 0, o2 = o2 + Math.imul(g2, X) | 0, n2 = n2 + Math.imul(p2, Q) | 0, i2 = (i2 = i2 + Math.imul(p2, ee) | 0) + Math.imul(b2, Q) | 0, o2 = o2 + Math.imul(b2, ee) | 0;
            var _e = (u2 + (n2 = n2 + Math.imul(f2, re) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ne) | 0) + Math.imul(h2, re) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ne) | 0) + (i2 >>> 13) | 0) + (_e >>> 26) | 0, _e &= 67108863, n2 = Math.imul(x, H), i2 = (i2 = Math.imul(x, q)) + Math.imul(I, H) | 0, o2 = Math.imul(I, q), n2 = n2 + Math.imul(M, V) | 0, i2 = (i2 = i2 + Math.imul(M, G) | 0) + Math.imul(E, V) | 0, o2 = o2 + Math.imul(E, G) | 0, n2 = n2 + Math.imul(S2, K) | 0, i2 = (i2 = i2 + Math.imul(S2, W) | 0) + Math.imul(C2, K) | 0, o2 = o2 + Math.imul(C2, W) | 0, n2 = n2 + Math.imul(w2, Z) | 0, i2 = (i2 = i2 + Math.imul(w2, X) | 0) + Math.imul(_2, Z) | 0, o2 = o2 + Math.imul(_2, X) | 0, n2 = n2 + Math.imul(m2, Q) | 0, i2 = (i2 = i2 + Math.imul(m2, ee) | 0) + Math.imul(g2, Q) | 0, o2 = o2 + Math.imul(g2, ee) | 0, n2 = n2 + Math.imul(p2, re) | 0, i2 = (i2 = i2 + Math.imul(p2, ne) | 0) + Math.imul(b2, re) | 0, o2 = o2 + Math.imul(b2, ne) | 0;
            var Ae = (u2 + (n2 = n2 + Math.imul(f2, oe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, se) | 0) + Math.imul(h2, oe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, se) | 0) + (i2 >>> 13) | 0) + (Ae >>> 26) | 0, Ae &= 67108863, n2 = Math.imul(U, H), i2 = (i2 = Math.imul(U, q)) + Math.imul(P, H) | 0, o2 = Math.imul(P, q), n2 = n2 + Math.imul(x, V) | 0, i2 = (i2 = i2 + Math.imul(x, G) | 0) + Math.imul(I, V) | 0, o2 = o2 + Math.imul(I, G) | 0, n2 = n2 + Math.imul(M, K) | 0, i2 = (i2 = i2 + Math.imul(M, W) | 0) + Math.imul(E, K) | 0, o2 = o2 + Math.imul(E, W) | 0, n2 = n2 + Math.imul(S2, Z) | 0, i2 = (i2 = i2 + Math.imul(S2, X) | 0) + Math.imul(C2, Z) | 0, o2 = o2 + Math.imul(C2, X) | 0, n2 = n2 + Math.imul(w2, Q) | 0, i2 = (i2 = i2 + Math.imul(w2, ee) | 0) + Math.imul(_2, Q) | 0, o2 = o2 + Math.imul(_2, ee) | 0, n2 = n2 + Math.imul(m2, re) | 0, i2 = (i2 = i2 + Math.imul(m2, ne) | 0) + Math.imul(g2, re) | 0, o2 = o2 + Math.imul(g2, ne) | 0, n2 = n2 + Math.imul(p2, oe) | 0, i2 = (i2 = i2 + Math.imul(p2, se) | 0) + Math.imul(b2, oe) | 0, o2 = o2 + Math.imul(b2, se) | 0;
            var Se = (u2 + (n2 = n2 + Math.imul(f2, ce) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ue) | 0) + Math.imul(h2, ce) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ue) | 0) + (i2 >>> 13) | 0) + (Se >>> 26) | 0, Se &= 67108863, n2 = Math.imul(R, H), i2 = (i2 = Math.imul(R, q)) + Math.imul(N, H) | 0, o2 = Math.imul(N, q), n2 = n2 + Math.imul(U, V) | 0, i2 = (i2 = i2 + Math.imul(U, G) | 0) + Math.imul(P, V) | 0, o2 = o2 + Math.imul(P, G) | 0, n2 = n2 + Math.imul(x, K) | 0, i2 = (i2 = i2 + Math.imul(x, W) | 0) + Math.imul(I, K) | 0, o2 = o2 + Math.imul(I, W) | 0, n2 = n2 + Math.imul(M, Z) | 0, i2 = (i2 = i2 + Math.imul(M, X) | 0) + Math.imul(E, Z) | 0, o2 = o2 + Math.imul(E, X) | 0, n2 = n2 + Math.imul(S2, Q) | 0, i2 = (i2 = i2 + Math.imul(S2, ee) | 0) + Math.imul(C2, Q) | 0, o2 = o2 + Math.imul(C2, ee) | 0, n2 = n2 + Math.imul(w2, re) | 0, i2 = (i2 = i2 + Math.imul(w2, ne) | 0) + Math.imul(_2, re) | 0, o2 = o2 + Math.imul(_2, ne) | 0, n2 = n2 + Math.imul(m2, oe) | 0, i2 = (i2 = i2 + Math.imul(m2, se) | 0) + Math.imul(g2, oe) | 0, o2 = o2 + Math.imul(g2, se) | 0, n2 = n2 + Math.imul(p2, ce) | 0, i2 = (i2 = i2 + Math.imul(p2, ue) | 0) + Math.imul(b2, ce) | 0, o2 = o2 + Math.imul(b2, ue) | 0;
            var Ce = (u2 + (n2 = n2 + Math.imul(f2, fe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, he) | 0) + Math.imul(h2, fe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, he) | 0) + (i2 >>> 13) | 0) + (Ce >>> 26) | 0, Ce &= 67108863, n2 = Math.imul(j, H), i2 = (i2 = Math.imul(j, q)) + Math.imul(D, H) | 0, o2 = Math.imul(D, q), n2 = n2 + Math.imul(R, V) | 0, i2 = (i2 = i2 + Math.imul(R, G) | 0) + Math.imul(N, V) | 0, o2 = o2 + Math.imul(N, G) | 0, n2 = n2 + Math.imul(U, K) | 0, i2 = (i2 = i2 + Math.imul(U, W) | 0) + Math.imul(P, K) | 0, o2 = o2 + Math.imul(P, W) | 0, n2 = n2 + Math.imul(x, Z) | 0, i2 = (i2 = i2 + Math.imul(x, X) | 0) + Math.imul(I, Z) | 0, o2 = o2 + Math.imul(I, X) | 0, n2 = n2 + Math.imul(M, Q) | 0, i2 = (i2 = i2 + Math.imul(M, ee) | 0) + Math.imul(E, Q) | 0, o2 = o2 + Math.imul(E, ee) | 0, n2 = n2 + Math.imul(S2, re) | 0, i2 = (i2 = i2 + Math.imul(S2, ne) | 0) + Math.imul(C2, re) | 0, o2 = o2 + Math.imul(C2, ne) | 0, n2 = n2 + Math.imul(w2, oe) | 0, i2 = (i2 = i2 + Math.imul(w2, se) | 0) + Math.imul(_2, oe) | 0, o2 = o2 + Math.imul(_2, se) | 0, n2 = n2 + Math.imul(m2, ce) | 0, i2 = (i2 = i2 + Math.imul(m2, ue) | 0) + Math.imul(g2, ce) | 0, o2 = o2 + Math.imul(g2, ue) | 0, n2 = n2 + Math.imul(p2, fe) | 0, i2 = (i2 = i2 + Math.imul(p2, he) | 0) + Math.imul(b2, fe) | 0, o2 = o2 + Math.imul(b2, he) | 0;
            var Te = (u2 + (n2 = n2 + Math.imul(f2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, be) | 0) + Math.imul(h2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, be) | 0) + (i2 >>> 13) | 0) + (Te >>> 26) | 0, Te &= 67108863, n2 = Math.imul(j, V), i2 = (i2 = Math.imul(j, G)) + Math.imul(D, V) | 0, o2 = Math.imul(D, G), n2 = n2 + Math.imul(R, K) | 0, i2 = (i2 = i2 + Math.imul(R, W) | 0) + Math.imul(N, K) | 0, o2 = o2 + Math.imul(N, W) | 0, n2 = n2 + Math.imul(U, Z) | 0, i2 = (i2 = i2 + Math.imul(U, X) | 0) + Math.imul(P, Z) | 0, o2 = o2 + Math.imul(P, X) | 0, n2 = n2 + Math.imul(x, Q) | 0, i2 = (i2 = i2 + Math.imul(x, ee) | 0) + Math.imul(I, Q) | 0, o2 = o2 + Math.imul(I, ee) | 0, n2 = n2 + Math.imul(M, re) | 0, i2 = (i2 = i2 + Math.imul(M, ne) | 0) + Math.imul(E, re) | 0, o2 = o2 + Math.imul(E, ne) | 0, n2 = n2 + Math.imul(S2, oe) | 0, i2 = (i2 = i2 + Math.imul(S2, se) | 0) + Math.imul(C2, oe) | 0, o2 = o2 + Math.imul(C2, se) | 0, n2 = n2 + Math.imul(w2, ce) | 0, i2 = (i2 = i2 + Math.imul(w2, ue) | 0) + Math.imul(_2, ce) | 0, o2 = o2 + Math.imul(_2, ue) | 0, n2 = n2 + Math.imul(m2, fe) | 0, i2 = (i2 = i2 + Math.imul(m2, he) | 0) + Math.imul(g2, fe) | 0, o2 = o2 + Math.imul(g2, he) | 0;
            var Me = (u2 + (n2 = n2 + Math.imul(p2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(p2, be) | 0) + Math.imul(b2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(b2, be) | 0) + (i2 >>> 13) | 0) + (Me >>> 26) | 0, Me &= 67108863, n2 = Math.imul(j, K), i2 = (i2 = Math.imul(j, W)) + Math.imul(D, K) | 0, o2 = Math.imul(D, W), n2 = n2 + Math.imul(R, Z) | 0, i2 = (i2 = i2 + Math.imul(R, X) | 0) + Math.imul(N, Z) | 0, o2 = o2 + Math.imul(N, X) | 0, n2 = n2 + Math.imul(U, Q) | 0, i2 = (i2 = i2 + Math.imul(U, ee) | 0) + Math.imul(P, Q) | 0, o2 = o2 + Math.imul(P, ee) | 0, n2 = n2 + Math.imul(x, re) | 0, i2 = (i2 = i2 + Math.imul(x, ne) | 0) + Math.imul(I, re) | 0, o2 = o2 + Math.imul(I, ne) | 0, n2 = n2 + Math.imul(M, oe) | 0, i2 = (i2 = i2 + Math.imul(M, se) | 0) + Math.imul(E, oe) | 0, o2 = o2 + Math.imul(E, se) | 0, n2 = n2 + Math.imul(S2, ce) | 0, i2 = (i2 = i2 + Math.imul(S2, ue) | 0) + Math.imul(C2, ce) | 0, o2 = o2 + Math.imul(C2, ue) | 0, n2 = n2 + Math.imul(w2, fe) | 0, i2 = (i2 = i2 + Math.imul(w2, he) | 0) + Math.imul(_2, fe) | 0, o2 = o2 + Math.imul(_2, he) | 0;
            var Ee = (u2 + (n2 = n2 + Math.imul(m2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(m2, be) | 0) + Math.imul(g2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(g2, be) | 0) + (i2 >>> 13) | 0) + (Ee >>> 26) | 0, Ee &= 67108863, n2 = Math.imul(j, Z), i2 = (i2 = Math.imul(j, X)) + Math.imul(D, Z) | 0, o2 = Math.imul(D, X), n2 = n2 + Math.imul(R, Q) | 0, i2 = (i2 = i2 + Math.imul(R, ee) | 0) + Math.imul(N, Q) | 0, o2 = o2 + Math.imul(N, ee) | 0, n2 = n2 + Math.imul(U, re) | 0, i2 = (i2 = i2 + Math.imul(U, ne) | 0) + Math.imul(P, re) | 0, o2 = o2 + Math.imul(P, ne) | 0, n2 = n2 + Math.imul(x, oe) | 0, i2 = (i2 = i2 + Math.imul(x, se) | 0) + Math.imul(I, oe) | 0, o2 = o2 + Math.imul(I, se) | 0, n2 = n2 + Math.imul(M, ce) | 0, i2 = (i2 = i2 + Math.imul(M, ue) | 0) + Math.imul(E, ce) | 0, o2 = o2 + Math.imul(E, ue) | 0, n2 = n2 + Math.imul(S2, fe) | 0, i2 = (i2 = i2 + Math.imul(S2, he) | 0) + Math.imul(C2, fe) | 0, o2 = o2 + Math.imul(C2, he) | 0;
            var ke = (u2 + (n2 = n2 + Math.imul(w2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(w2, be) | 0) + Math.imul(_2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(_2, be) | 0) + (i2 >>> 13) | 0) + (ke >>> 26) | 0, ke &= 67108863, n2 = Math.imul(j, Q), i2 = (i2 = Math.imul(j, ee)) + Math.imul(D, Q) | 0, o2 = Math.imul(D, ee), n2 = n2 + Math.imul(R, re) | 0, i2 = (i2 = i2 + Math.imul(R, ne) | 0) + Math.imul(N, re) | 0, o2 = o2 + Math.imul(N, ne) | 0, n2 = n2 + Math.imul(U, oe) | 0, i2 = (i2 = i2 + Math.imul(U, se) | 0) + Math.imul(P, oe) | 0, o2 = o2 + Math.imul(P, se) | 0, n2 = n2 + Math.imul(x, ce) | 0, i2 = (i2 = i2 + Math.imul(x, ue) | 0) + Math.imul(I, ce) | 0, o2 = o2 + Math.imul(I, ue) | 0, n2 = n2 + Math.imul(M, fe) | 0, i2 = (i2 = i2 + Math.imul(M, he) | 0) + Math.imul(E, fe) | 0, o2 = o2 + Math.imul(E, he) | 0;
            var xe = (u2 + (n2 = n2 + Math.imul(S2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(S2, be) | 0) + Math.imul(C2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(C2, be) | 0) + (i2 >>> 13) | 0) + (xe >>> 26) | 0, xe &= 67108863, n2 = Math.imul(j, re), i2 = (i2 = Math.imul(j, ne)) + Math.imul(D, re) | 0, o2 = Math.imul(D, ne), n2 = n2 + Math.imul(R, oe) | 0, i2 = (i2 = i2 + Math.imul(R, se) | 0) + Math.imul(N, oe) | 0, o2 = o2 + Math.imul(N, se) | 0, n2 = n2 + Math.imul(U, ce) | 0, i2 = (i2 = i2 + Math.imul(U, ue) | 0) + Math.imul(P, ce) | 0, o2 = o2 + Math.imul(P, ue) | 0, n2 = n2 + Math.imul(x, fe) | 0, i2 = (i2 = i2 + Math.imul(x, he) | 0) + Math.imul(I, fe) | 0, o2 = o2 + Math.imul(I, he) | 0;
            var Ie = (u2 + (n2 = n2 + Math.imul(M, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(M, be) | 0) + Math.imul(E, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(E, be) | 0) + (i2 >>> 13) | 0) + (Ie >>> 26) | 0, Ie &= 67108863, n2 = Math.imul(j, oe), i2 = (i2 = Math.imul(j, se)) + Math.imul(D, oe) | 0, o2 = Math.imul(D, se), n2 = n2 + Math.imul(R, ce) | 0, i2 = (i2 = i2 + Math.imul(R, ue) | 0) + Math.imul(N, ce) | 0, o2 = o2 + Math.imul(N, ue) | 0, n2 = n2 + Math.imul(U, fe) | 0, i2 = (i2 = i2 + Math.imul(U, he) | 0) + Math.imul(P, fe) | 0, o2 = o2 + Math.imul(P, he) | 0;
            var Be = (u2 + (n2 = n2 + Math.imul(x, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(x, be) | 0) + Math.imul(I, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(I, be) | 0) + (i2 >>> 13) | 0) + (Be >>> 26) | 0, Be &= 67108863, n2 = Math.imul(j, ce), i2 = (i2 = Math.imul(j, ue)) + Math.imul(D, ce) | 0, o2 = Math.imul(D, ue), n2 = n2 + Math.imul(R, fe) | 0, i2 = (i2 = i2 + Math.imul(R, he) | 0) + Math.imul(N, fe) | 0, o2 = o2 + Math.imul(N, he) | 0;
            var Ue = (u2 + (n2 = n2 + Math.imul(U, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(U, be) | 0) + Math.imul(P, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(P, be) | 0) + (i2 >>> 13) | 0) + (Ue >>> 26) | 0, Ue &= 67108863, n2 = Math.imul(j, fe), i2 = (i2 = Math.imul(j, he)) + Math.imul(D, fe) | 0, o2 = Math.imul(D, he);
            var Pe = (u2 + (n2 = n2 + Math.imul(R, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(R, be) | 0) + Math.imul(N, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(N, be) | 0) + (i2 >>> 13) | 0) + (Pe >>> 26) | 0, Pe &= 67108863;
            var Oe = (u2 + (n2 = Math.imul(j, pe)) | 0) + ((8191 & (i2 = (i2 = Math.imul(j, be)) + Math.imul(D, pe) | 0)) << 13) | 0;
            return u2 = ((o2 = Math.imul(D, be)) + (i2 >>> 13) | 0) + (Oe >>> 26) | 0, Oe &= 67108863, c2[0] = ye, c2[1] = me, c2[2] = ge, c2[3] = ve, c2[4] = we, c2[5] = _e, c2[6] = Ae, c2[7] = Se, c2[8] = Ce, c2[9] = Te, c2[10] = Me, c2[11] = Ee, c2[12] = ke, c2[13] = xe, c2[14] = Ie, c2[15] = Be, c2[16] = Ue, c2[17] = Pe, c2[18] = Oe, 0 !== u2 && (c2[19] = u2, r3.length++), r3;
          };
          function b(e4, t4, r3) {
            return new y().mulp(e4, t4, r3);
          }
          function y(e4, t4) {
            this.x = e4, this.y = t4;
          }
          Math.imul || (p = l), o.prototype.mulTo = function(e4, t4) {
            var r3, n2 = this.length + e4.length;
            return r3 = 10 === this.length && 10 === e4.length ? p(this, e4, t4) : n2 < 63 ? l(this, e4, t4) : n2 < 1024 ? (function(e5, t5, r4) {
              r4.negative = t5.negative ^ e5.negative, r4.length = e5.length + t5.length;
              for (var n3 = 0, i2 = 0, o2 = 0; o2 < r4.length - 1; o2++) {
                var s2 = i2;
                i2 = 0;
                for (var a2 = 67108863 & n3, c2 = Math.min(o2, t5.length - 1), u2 = Math.max(0, o2 - e5.length + 1); u2 <= c2; u2++) {
                  var d2 = o2 - u2, f2 = (0 | e5.words[d2]) * (0 | t5.words[u2]), h2 = 67108863 & f2;
                  a2 = 67108863 & (h2 = h2 + a2 | 0), i2 += (s2 = (s2 = s2 + (f2 / 67108864 | 0) | 0) + (h2 >>> 26) | 0) >>> 26, s2 &= 67108863;
                }
                r4.words[o2] = a2, n3 = s2, s2 = i2;
              }
              return 0 !== n3 ? r4.words[o2] = n3 : r4.length--, r4.strip();
            })(this, e4, t4) : b(this, e4, t4), r3;
          }, y.prototype.makeRBT = function(e4) {
            for (var t4 = new Array(e4), r3 = o.prototype._countBits(e4) - 1, n2 = 0; n2 < e4; n2++) t4[n2] = this.revBin(n2, r3, e4);
            return t4;
          }, y.prototype.revBin = function(e4, t4, r3) {
            if (0 === e4 || e4 === r3 - 1) return e4;
            for (var n2 = 0, i2 = 0; i2 < t4; i2++) n2 |= (1 & e4) << t4 - i2 - 1, e4 >>= 1;
            return n2;
          }, y.prototype.permute = function(e4, t4, r3, n2, i2, o2) {
            for (var s2 = 0; s2 < o2; s2++) n2[s2] = t4[e4[s2]], i2[s2] = r3[e4[s2]];
          }, y.prototype.transform = function(e4, t4, r3, n2, i2, o2) {
            this.permute(o2, e4, t4, r3, n2, i2);
            for (var s2 = 1; s2 < i2; s2 <<= 1) for (var a2 = s2 << 1, c2 = Math.cos(2 * Math.PI / a2), u2 = Math.sin(2 * Math.PI / a2), d2 = 0; d2 < i2; d2 += a2) for (var f2 = c2, h2 = u2, l2 = 0; l2 < s2; l2++) {
              var p2 = r3[d2 + l2], b2 = n2[d2 + l2], y2 = r3[d2 + l2 + s2], m2 = n2[d2 + l2 + s2], g2 = f2 * y2 - h2 * m2;
              m2 = f2 * m2 + h2 * y2, y2 = g2, r3[d2 + l2] = p2 + y2, n2[d2 + l2] = b2 + m2, r3[d2 + l2 + s2] = p2 - y2, n2[d2 + l2 + s2] = b2 - m2, l2 !== a2 && (g2 = c2 * f2 - u2 * h2, h2 = c2 * h2 + u2 * f2, f2 = g2);
            }
          }, y.prototype.guessLen13b = function(e4, t4) {
            var r3 = 1 | Math.max(t4, e4), n2 = 1 & r3, i2 = 0;
            for (r3 = r3 / 2 | 0; r3; r3 >>>= 1) i2++;
            return 1 << i2 + 1 + n2;
          }, y.prototype.conjugate = function(e4, t4, r3) {
            if (!(r3 <= 1)) for (var n2 = 0; n2 < r3 / 2; n2++) {
              var i2 = e4[n2];
              e4[n2] = e4[r3 - n2 - 1], e4[r3 - n2 - 1] = i2, i2 = t4[n2], t4[n2] = -t4[r3 - n2 - 1], t4[r3 - n2 - 1] = -i2;
            }
          }, y.prototype.normalize13b = function(e4, t4) {
            for (var r3 = 0, n2 = 0; n2 < t4 / 2; n2++) {
              var i2 = 8192 * Math.round(e4[2 * n2 + 1] / t4) + Math.round(e4[2 * n2] / t4) + r3;
              e4[n2] = 67108863 & i2, r3 = i2 < 67108864 ? 0 : i2 / 67108864 | 0;
            }
            return e4;
          }, y.prototype.convert13b = function(e4, t4, r3, i2) {
            for (var o2 = 0, s2 = 0; s2 < t4; s2++) o2 += 0 | e4[s2], r3[2 * s2] = 8191 & o2, o2 >>>= 13, r3[2 * s2 + 1] = 8191 & o2, o2 >>>= 13;
            for (s2 = 2 * t4; s2 < i2; ++s2) r3[s2] = 0;
            n(0 === o2), n(!(-8192 & o2));
          }, y.prototype.stub = function(e4) {
            for (var t4 = new Array(e4), r3 = 0; r3 < e4; r3++) t4[r3] = 0;
            return t4;
          }, y.prototype.mulp = function(e4, t4, r3) {
            var n2 = 2 * this.guessLen13b(e4.length, t4.length), i2 = this.makeRBT(n2), o2 = this.stub(n2), s2 = new Array(n2), a2 = new Array(n2), c2 = new Array(n2), u2 = new Array(n2), d2 = new Array(n2), f2 = new Array(n2), h2 = r3.words;
            h2.length = n2, this.convert13b(e4.words, e4.length, s2, n2), this.convert13b(t4.words, t4.length, u2, n2), this.transform(s2, o2, a2, c2, n2, i2), this.transform(u2, o2, d2, f2, n2, i2);
            for (var l2 = 0; l2 < n2; l2++) {
              var p2 = a2[l2] * d2[l2] - c2[l2] * f2[l2];
              c2[l2] = a2[l2] * f2[l2] + c2[l2] * d2[l2], a2[l2] = p2;
            }
            return this.conjugate(a2, c2, n2), this.transform(a2, c2, h2, o2, n2, i2), this.conjugate(h2, o2, n2), this.normalize13b(h2, n2), r3.negative = e4.negative ^ t4.negative, r3.length = e4.length + t4.length, r3.strip();
          }, o.prototype.mul = function(e4) {
            var t4 = new o(null);
            return t4.words = new Array(this.length + e4.length), this.mulTo(e4, t4);
          }, o.prototype.mulf = function(e4) {
            var t4 = new o(null);
            return t4.words = new Array(this.length + e4.length), b(this, e4, t4);
          }, o.prototype.imul = function(e4) {
            return this.clone().mulTo(e4, this);
          }, o.prototype.imuln = function(e4) {
            n("number" == typeof e4), n(e4 < 67108864);
            for (var t4 = 0, r3 = 0; r3 < this.length; r3++) {
              var i2 = (0 | this.words[r3]) * e4, o2 = (67108863 & i2) + (67108863 & t4);
              t4 >>= 26, t4 += i2 / 67108864 | 0, t4 += o2 >>> 26, this.words[r3] = 67108863 & o2;
            }
            return 0 !== t4 && (this.words[r3] = t4, this.length++), this;
          }, o.prototype.muln = function(e4) {
            return this.clone().imuln(e4);
          }, o.prototype.sqr = function() {
            return this.mul(this);
          }, o.prototype.isqr = function() {
            return this.imul(this.clone());
          }, o.prototype.pow = function(e4) {
            var t4 = (function(e5) {
              for (var t5 = new Array(e5.bitLength()), r4 = 0; r4 < t5.length; r4++) {
                var n3 = r4 / 26 | 0, i3 = r4 % 26;
                t5[r4] = (e5.words[n3] & 1 << i3) >>> i3;
              }
              return t5;
            })(e4);
            if (0 === t4.length) return new o(1);
            for (var r3 = this, n2 = 0; n2 < t4.length && 0 === t4[n2]; n2++, r3 = r3.sqr()) ;
            if (++n2 < t4.length) for (var i2 = r3.sqr(); n2 < t4.length; n2++, i2 = i2.sqr()) 0 !== t4[n2] && (r3 = r3.mul(i2));
            return r3;
          }, o.prototype.iushln = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4, r3 = e4 % 26, i2 = (e4 - r3) / 26, o2 = 67108863 >>> 26 - r3 << 26 - r3;
            if (0 !== r3) {
              var s2 = 0;
              for (t4 = 0; t4 < this.length; t4++) {
                var a2 = this.words[t4] & o2, c2 = (0 | this.words[t4]) - a2 << r3;
                this.words[t4] = c2 | s2, s2 = a2 >>> 26 - r3;
              }
              s2 && (this.words[t4] = s2, this.length++);
            }
            if (0 !== i2) {
              for (t4 = this.length - 1; t4 >= 0; t4--) this.words[t4 + i2] = this.words[t4];
              for (t4 = 0; t4 < i2; t4++) this.words[t4] = 0;
              this.length += i2;
            }
            return this.strip();
          }, o.prototype.ishln = function(e4) {
            return n(0 === this.negative), this.iushln(e4);
          }, o.prototype.iushrn = function(e4, t4, r3) {
            var i2;
            n("number" == typeof e4 && e4 >= 0), i2 = t4 ? (t4 - t4 % 26) / 26 : 0;
            var o2 = e4 % 26, s2 = Math.min((e4 - o2) / 26, this.length), a2 = 67108863 ^ 67108863 >>> o2 << o2, c2 = r3;
            if (i2 -= s2, i2 = Math.max(0, i2), c2) {
              for (var u2 = 0; u2 < s2; u2++) c2.words[u2] = this.words[u2];
              c2.length = s2;
            }
            if (0 === s2) ;
            else if (this.length > s2) for (this.length -= s2, u2 = 0; u2 < this.length; u2++) this.words[u2] = this.words[u2 + s2];
            else this.words[0] = 0, this.length = 1;
            var d2 = 0;
            for (u2 = this.length - 1; u2 >= 0 && (0 !== d2 || u2 >= i2); u2--) {
              var f2 = 0 | this.words[u2];
              this.words[u2] = d2 << 26 - o2 | f2 >>> o2, d2 = f2 & a2;
            }
            return c2 && 0 !== d2 && (c2.words[c2.length++] = d2), 0 === this.length && (this.words[0] = 0, this.length = 1), this.strip();
          }, o.prototype.ishrn = function(e4, t4, r3) {
            return n(0 === this.negative), this.iushrn(e4, t4, r3);
          }, o.prototype.shln = function(e4) {
            return this.clone().ishln(e4);
          }, o.prototype.ushln = function(e4) {
            return this.clone().iushln(e4);
          }, o.prototype.shrn = function(e4) {
            return this.clone().ishrn(e4);
          }, o.prototype.ushrn = function(e4) {
            return this.clone().iushrn(e4);
          }, o.prototype.testn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26, i2 = 1 << t4;
            return !(this.length <= r3 || !(this.words[r3] & i2));
          }, o.prototype.imaskn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26;
            if (n(0 === this.negative, "imaskn works only with positive numbers"), this.length <= r3) return this;
            if (0 !== t4 && r3++, this.length = Math.min(r3, this.length), 0 !== t4) {
              var i2 = 67108863 ^ 67108863 >>> t4 << t4;
              this.words[this.length - 1] &= i2;
            }
            return this.strip();
          }, o.prototype.maskn = function(e4) {
            return this.clone().imaskn(e4);
          }, o.prototype.iaddn = function(e4) {
            return n("number" == typeof e4), n(e4 < 67108864), e4 < 0 ? this.isubn(-e4) : 0 !== this.negative ? 1 === this.length && (0 | this.words[0]) < e4 ? (this.words[0] = e4 - (0 | this.words[0]), this.negative = 0, this) : (this.negative = 0, this.isubn(e4), this.negative = 1, this) : this._iaddn(e4);
          }, o.prototype._iaddn = function(e4) {
            this.words[0] += e4;
            for (var t4 = 0; t4 < this.length && this.words[t4] >= 67108864; t4++) this.words[t4] -= 67108864, t4 === this.length - 1 ? this.words[t4 + 1] = 1 : this.words[t4 + 1]++;
            return this.length = Math.max(this.length, t4 + 1), this;
          }, o.prototype.isubn = function(e4) {
            if (n("number" == typeof e4), n(e4 < 67108864), e4 < 0) return this.iaddn(-e4);
            if (0 !== this.negative) return this.negative = 0, this.iaddn(e4), this.negative = 1, this;
            if (this.words[0] -= e4, 1 === this.length && this.words[0] < 0) this.words[0] = -this.words[0], this.negative = 1;
            else for (var t4 = 0; t4 < this.length && this.words[t4] < 0; t4++) this.words[t4] += 67108864, this.words[t4 + 1] -= 1;
            return this.strip();
          }, o.prototype.addn = function(e4) {
            return this.clone().iaddn(e4);
          }, o.prototype.subn = function(e4) {
            return this.clone().isubn(e4);
          }, o.prototype.iabs = function() {
            return this.negative = 0, this;
          }, o.prototype.abs = function() {
            return this.clone().iabs();
          }, o.prototype._ishlnsubmul = function(e4, t4, r3) {
            var i2, o2, s2 = e4.length + r3;
            this._expand(s2);
            var a2 = 0;
            for (i2 = 0; i2 < e4.length; i2++) {
              o2 = (0 | this.words[i2 + r3]) + a2;
              var c2 = (0 | e4.words[i2]) * t4;
              a2 = ((o2 -= 67108863 & c2) >> 26) - (c2 / 67108864 | 0), this.words[i2 + r3] = 67108863 & o2;
            }
            for (; i2 < this.length - r3; i2++) a2 = (o2 = (0 | this.words[i2 + r3]) + a2) >> 26, this.words[i2 + r3] = 67108863 & o2;
            if (0 === a2) return this.strip();
            for (n(-1 === a2), a2 = 0, i2 = 0; i2 < this.length; i2++) a2 = (o2 = -(0 | this.words[i2]) + a2) >> 26, this.words[i2] = 67108863 & o2;
            return this.negative = 1, this.strip();
          }, o.prototype._wordDiv = function(e4, t4) {
            var r3 = (this.length, e4.length), n2 = this.clone(), i2 = e4, s2 = 0 | i2.words[i2.length - 1];
            0 != (r3 = 26 - this._countBits(s2)) && (i2 = i2.ushln(r3), n2.iushln(r3), s2 = 0 | i2.words[i2.length - 1]);
            var a2, c2 = n2.length - i2.length;
            if ("mod" !== t4) {
              (a2 = new o(null)).length = c2 + 1, a2.words = new Array(a2.length);
              for (var u2 = 0; u2 < a2.length; u2++) a2.words[u2] = 0;
            }
            var d2 = n2.clone()._ishlnsubmul(i2, 1, c2);
            0 === d2.negative && (n2 = d2, a2 && (a2.words[c2] = 1));
            for (var f2 = c2 - 1; f2 >= 0; f2--) {
              var h2 = 67108864 * (0 | n2.words[i2.length + f2]) + (0 | n2.words[i2.length + f2 - 1]);
              for (h2 = Math.min(h2 / s2 | 0, 67108863), n2._ishlnsubmul(i2, h2, f2); 0 !== n2.negative; ) h2--, n2.negative = 0, n2._ishlnsubmul(i2, 1, f2), n2.isZero() || (n2.negative ^= 1);
              a2 && (a2.words[f2] = h2);
            }
            return a2 && a2.strip(), n2.strip(), "div" !== t4 && 0 !== r3 && n2.iushrn(r3), { div: a2 || null, mod: n2 };
          }, o.prototype.divmod = function(e4, t4, r3) {
            return n(!e4.isZero()), this.isZero() ? { div: new o(0), mod: new o(0) } : 0 !== this.negative && 0 === e4.negative ? (a2 = this.neg().divmod(e4, t4), "mod" !== t4 && (i2 = a2.div.neg()), "div" !== t4 && (s2 = a2.mod.neg(), r3 && 0 !== s2.negative && s2.iadd(e4)), { div: i2, mod: s2 }) : 0 === this.negative && 0 !== e4.negative ? (a2 = this.divmod(e4.neg(), t4), "mod" !== t4 && (i2 = a2.div.neg()), { div: i2, mod: a2.mod }) : this.negative & e4.negative ? (a2 = this.neg().divmod(e4.neg(), t4), "div" !== t4 && (s2 = a2.mod.neg(), r3 && 0 !== s2.negative && s2.isub(e4)), { div: a2.div, mod: s2 }) : e4.length > this.length || this.cmp(e4) < 0 ? { div: new o(0), mod: this } : 1 === e4.length ? "div" === t4 ? { div: this.divn(e4.words[0]), mod: null } : "mod" === t4 ? { div: null, mod: new o(this.modn(e4.words[0])) } : { div: this.divn(e4.words[0]), mod: new o(this.modn(e4.words[0])) } : this._wordDiv(e4, t4);
            var i2, s2, a2;
          }, o.prototype.div = function(e4) {
            return this.divmod(e4, "div", false).div;
          }, o.prototype.mod = function(e4) {
            return this.divmod(e4, "mod", false).mod;
          }, o.prototype.umod = function(e4) {
            return this.divmod(e4, "mod", true).mod;
          }, o.prototype.divRound = function(e4) {
            var t4 = this.divmod(e4);
            if (t4.mod.isZero()) return t4.div;
            var r3 = 0 !== t4.div.negative ? t4.mod.isub(e4) : t4.mod, n2 = e4.ushrn(1), i2 = e4.andln(1), o2 = r3.cmp(n2);
            return o2 < 0 || 1 === i2 && 0 === o2 ? t4.div : 0 !== t4.div.negative ? t4.div.isubn(1) : t4.div.iaddn(1);
          }, o.prototype.modn = function(e4) {
            n(e4 <= 67108863);
            for (var t4 = (1 << 26) % e4, r3 = 0, i2 = this.length - 1; i2 >= 0; i2--) r3 = (t4 * r3 + (0 | this.words[i2])) % e4;
            return r3;
          }, o.prototype.idivn = function(e4) {
            n(e4 <= 67108863);
            for (var t4 = 0, r3 = this.length - 1; r3 >= 0; r3--) {
              var i2 = (0 | this.words[r3]) + 67108864 * t4;
              this.words[r3] = i2 / e4 | 0, t4 = i2 % e4;
            }
            return this.strip();
          }, o.prototype.divn = function(e4) {
            return this.clone().idivn(e4);
          }, o.prototype.egcd = function(e4) {
            n(0 === e4.negative), n(!e4.isZero());
            var t4 = this, r3 = e4.clone();
            t4 = 0 !== t4.negative ? t4.umod(e4) : t4.clone();
            for (var i2 = new o(1), s2 = new o(0), a2 = new o(0), c2 = new o(1), u2 = 0; t4.isEven() && r3.isEven(); ) t4.iushrn(1), r3.iushrn(1), ++u2;
            for (var d2 = r3.clone(), f2 = t4.clone(); !t4.isZero(); ) {
              for (var h2 = 0, l2 = 1; !(t4.words[0] & l2) && h2 < 26; ++h2, l2 <<= 1) ;
              if (h2 > 0) for (t4.iushrn(h2); h2-- > 0; ) (i2.isOdd() || s2.isOdd()) && (i2.iadd(d2), s2.isub(f2)), i2.iushrn(1), s2.iushrn(1);
              for (var p2 = 0, b2 = 1; !(r3.words[0] & b2) && p2 < 26; ++p2, b2 <<= 1) ;
              if (p2 > 0) for (r3.iushrn(p2); p2-- > 0; ) (a2.isOdd() || c2.isOdd()) && (a2.iadd(d2), c2.isub(f2)), a2.iushrn(1), c2.iushrn(1);
              t4.cmp(r3) >= 0 ? (t4.isub(r3), i2.isub(a2), s2.isub(c2)) : (r3.isub(t4), a2.isub(i2), c2.isub(s2));
            }
            return { a: a2, b: c2, gcd: r3.iushln(u2) };
          }, o.prototype._invmp = function(e4) {
            n(0 === e4.negative), n(!e4.isZero());
            var t4 = this, r3 = e4.clone();
            t4 = 0 !== t4.negative ? t4.umod(e4) : t4.clone();
            for (var i2, s2 = new o(1), a2 = new o(0), c2 = r3.clone(); t4.cmpn(1) > 0 && r3.cmpn(1) > 0; ) {
              for (var u2 = 0, d2 = 1; !(t4.words[0] & d2) && u2 < 26; ++u2, d2 <<= 1) ;
              if (u2 > 0) for (t4.iushrn(u2); u2-- > 0; ) s2.isOdd() && s2.iadd(c2), s2.iushrn(1);
              for (var f2 = 0, h2 = 1; !(r3.words[0] & h2) && f2 < 26; ++f2, h2 <<= 1) ;
              if (f2 > 0) for (r3.iushrn(f2); f2-- > 0; ) a2.isOdd() && a2.iadd(c2), a2.iushrn(1);
              t4.cmp(r3) >= 0 ? (t4.isub(r3), s2.isub(a2)) : (r3.isub(t4), a2.isub(s2));
            }
            return (i2 = 0 === t4.cmpn(1) ? s2 : a2).cmpn(0) < 0 && i2.iadd(e4), i2;
          }, o.prototype.gcd = function(e4) {
            if (this.isZero()) return e4.abs();
            if (e4.isZero()) return this.abs();
            var t4 = this.clone(), r3 = e4.clone();
            t4.negative = 0, r3.negative = 0;
            for (var n2 = 0; t4.isEven() && r3.isEven(); n2++) t4.iushrn(1), r3.iushrn(1);
            for (; ; ) {
              for (; t4.isEven(); ) t4.iushrn(1);
              for (; r3.isEven(); ) r3.iushrn(1);
              var i2 = t4.cmp(r3);
              if (i2 < 0) {
                var o2 = t4;
                t4 = r3, r3 = o2;
              } else if (0 === i2 || 0 === r3.cmpn(1)) break;
              t4.isub(r3);
            }
            return r3.iushln(n2);
          }, o.prototype.invm = function(e4) {
            return this.egcd(e4).a.umod(e4);
          }, o.prototype.isEven = function() {
            return !(1 & this.words[0]);
          }, o.prototype.isOdd = function() {
            return !(1 & ~this.words[0]);
          }, o.prototype.andln = function(e4) {
            return this.words[0] & e4;
          }, o.prototype.bincn = function(e4) {
            n("number" == typeof e4);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26, i2 = 1 << t4;
            if (this.length <= r3) return this._expand(r3 + 1), this.words[r3] |= i2, this;
            for (var o2 = i2, s2 = r3; 0 !== o2 && s2 < this.length; s2++) {
              var a2 = 0 | this.words[s2];
              o2 = (a2 += o2) >>> 26, a2 &= 67108863, this.words[s2] = a2;
            }
            return 0 !== o2 && (this.words[s2] = o2, this.length++), this;
          }, o.prototype.isZero = function() {
            return 1 === this.length && 0 === this.words[0];
          }, o.prototype.cmpn = function(e4) {
            var t4, r3 = e4 < 0;
            if (0 !== this.negative && !r3) return -1;
            if (0 === this.negative && r3) return 1;
            if (this.strip(), this.length > 1) t4 = 1;
            else {
              r3 && (e4 = -e4), n(e4 <= 67108863, "Number is too big");
              var i2 = 0 | this.words[0];
              t4 = i2 === e4 ? 0 : i2 < e4 ? -1 : 1;
            }
            return 0 !== this.negative ? 0 | -t4 : t4;
          }, o.prototype.cmp = function(e4) {
            if (0 !== this.negative && 0 === e4.negative) return -1;
            if (0 === this.negative && 0 !== e4.negative) return 1;
            var t4 = this.ucmp(e4);
            return 0 !== this.negative ? 0 | -t4 : t4;
          }, o.prototype.ucmp = function(e4) {
            if (this.length > e4.length) return 1;
            if (this.length < e4.length) return -1;
            for (var t4 = 0, r3 = this.length - 1; r3 >= 0; r3--) {
              var n2 = 0 | this.words[r3], i2 = 0 | e4.words[r3];
              if (n2 !== i2) {
                n2 < i2 ? t4 = -1 : n2 > i2 && (t4 = 1);
                break;
              }
            }
            return t4;
          }, o.prototype.gtn = function(e4) {
            return 1 === this.cmpn(e4);
          }, o.prototype.gt = function(e4) {
            return 1 === this.cmp(e4);
          }, o.prototype.gten = function(e4) {
            return this.cmpn(e4) >= 0;
          }, o.prototype.gte = function(e4) {
            return this.cmp(e4) >= 0;
          }, o.prototype.ltn = function(e4) {
            return -1 === this.cmpn(e4);
          }, o.prototype.lt = function(e4) {
            return -1 === this.cmp(e4);
          }, o.prototype.lten = function(e4) {
            return this.cmpn(e4) <= 0;
          }, o.prototype.lte = function(e4) {
            return this.cmp(e4) <= 0;
          }, o.prototype.eqn = function(e4) {
            return 0 === this.cmpn(e4);
          }, o.prototype.eq = function(e4) {
            return 0 === this.cmp(e4);
          }, o.red = function(e4) {
            return new S(e4);
          }, o.prototype.toRed = function(e4) {
            return n(!this.red, "Already a number in reduction context"), n(0 === this.negative, "red works only with positives"), e4.convertTo(this)._forceRed(e4);
          }, o.prototype.fromRed = function() {
            return n(this.red, "fromRed works only with numbers in reduction context"), this.red.convertFrom(this);
          }, o.prototype._forceRed = function(e4) {
            return this.red = e4, this;
          }, o.prototype.forceRed = function(e4) {
            return n(!this.red, "Already a number in reduction context"), this._forceRed(e4);
          }, o.prototype.redAdd = function(e4) {
            return n(this.red, "redAdd works only with red numbers"), this.red.add(this, e4);
          }, o.prototype.redIAdd = function(e4) {
            return n(this.red, "redIAdd works only with red numbers"), this.red.iadd(this, e4);
          }, o.prototype.redSub = function(e4) {
            return n(this.red, "redSub works only with red numbers"), this.red.sub(this, e4);
          }, o.prototype.redISub = function(e4) {
            return n(this.red, "redISub works only with red numbers"), this.red.isub(this, e4);
          }, o.prototype.redShl = function(e4) {
            return n(this.red, "redShl works only with red numbers"), this.red.shl(this, e4);
          }, o.prototype.redMul = function(e4) {
            return n(this.red, "redMul works only with red numbers"), this.red._verify2(this, e4), this.red.mul(this, e4);
          }, o.prototype.redIMul = function(e4) {
            return n(this.red, "redMul works only with red numbers"), this.red._verify2(this, e4), this.red.imul(this, e4);
          }, o.prototype.redSqr = function() {
            return n(this.red, "redSqr works only with red numbers"), this.red._verify1(this), this.red.sqr(this);
          }, o.prototype.redISqr = function() {
            return n(this.red, "redISqr works only with red numbers"), this.red._verify1(this), this.red.isqr(this);
          }, o.prototype.redSqrt = function() {
            return n(this.red, "redSqrt works only with red numbers"), this.red._verify1(this), this.red.sqrt(this);
          }, o.prototype.redInvm = function() {
            return n(this.red, "redInvm works only with red numbers"), this.red._verify1(this), this.red.invm(this);
          }, o.prototype.redNeg = function() {
            return n(this.red, "redNeg works only with red numbers"), this.red._verify1(this), this.red.neg(this);
          }, o.prototype.redPow = function(e4) {
            return n(this.red && !e4.red, "redPow(normalNum)"), this.red._verify1(this), this.red.pow(this, e4);
          };
          var m = { k256: null, p224: null, p192: null, p25519: null };
          function g(e4, t4) {
            this.name = e4, this.p = new o(t4, 16), this.n = this.p.bitLength(), this.k = new o(1).iushln(this.n).isub(this.p), this.tmp = this._tmp();
          }
          function v() {
            g.call(this, "k256", "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f");
          }
          function w() {
            g.call(this, "p224", "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001");
          }
          function _() {
            g.call(this, "p192", "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff");
          }
          function A() {
            g.call(this, "25519", "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed");
          }
          function S(e4) {
            if ("string" == typeof e4) {
              var t4 = o._prime(e4);
              this.m = t4.p, this.prime = t4;
            } else n(e4.gtn(1), "modulus must be greater than 1"), this.m = e4, this.prime = null;
          }
          function C(e4) {
            S.call(this, e4), this.shift = this.m.bitLength(), this.shift % 26 != 0 && (this.shift += 26 - this.shift % 26), this.r = new o(1).iushln(this.shift), this.r2 = this.imod(this.r.sqr()), this.rinv = this.r._invmp(this.m), this.minv = this.rinv.mul(this.r).isubn(1).div(this.m), this.minv = this.minv.umod(this.r), this.minv = this.r.sub(this.minv);
          }
          g.prototype._tmp = function() {
            var e4 = new o(null);
            return e4.words = new Array(Math.ceil(this.n / 13)), e4;
          }, g.prototype.ireduce = function(e4) {
            var t4, r3 = e4;
            do {
              this.split(r3, this.tmp), t4 = (r3 = (r3 = this.imulK(r3)).iadd(this.tmp)).bitLength();
            } while (t4 > this.n);
            var n2 = t4 < this.n ? -1 : r3.ucmp(this.p);
            return 0 === n2 ? (r3.words[0] = 0, r3.length = 1) : n2 > 0 ? r3.isub(this.p) : void 0 !== r3.strip ? r3.strip() : r3._strip(), r3;
          }, g.prototype.split = function(e4, t4) {
            e4.iushrn(this.n, 0, t4);
          }, g.prototype.imulK = function(e4) {
            return e4.imul(this.k);
          }, i(v, g), v.prototype.split = function(e4, t4) {
            for (var r3 = 4194303, n2 = Math.min(e4.length, 9), i2 = 0; i2 < n2; i2++) t4.words[i2] = e4.words[i2];
            if (t4.length = n2, e4.length <= 9) return e4.words[0] = 0, void (e4.length = 1);
            var o2 = e4.words[9];
            for (t4.words[t4.length++] = o2 & r3, i2 = 10; i2 < e4.length; i2++) {
              var s2 = 0 | e4.words[i2];
              e4.words[i2 - 10] = (s2 & r3) << 4 | o2 >>> 22, o2 = s2;
            }
            o2 >>>= 22, e4.words[i2 - 10] = o2, 0 === o2 && e4.length > 10 ? e4.length -= 10 : e4.length -= 9;
          }, v.prototype.imulK = function(e4) {
            e4.words[e4.length] = 0, e4.words[e4.length + 1] = 0, e4.length += 2;
            for (var t4 = 0, r3 = 0; r3 < e4.length; r3++) {
              var n2 = 0 | e4.words[r3];
              t4 += 977 * n2, e4.words[r3] = 67108863 & t4, t4 = 64 * n2 + (t4 / 67108864 | 0);
            }
            return 0 === e4.words[e4.length - 1] && (e4.length--, 0 === e4.words[e4.length - 1] && e4.length--), e4;
          }, i(w, g), i(_, g), i(A, g), A.prototype.imulK = function(e4) {
            for (var t4 = 0, r3 = 0; r3 < e4.length; r3++) {
              var n2 = 19 * (0 | e4.words[r3]) + t4, i2 = 67108863 & n2;
              n2 >>>= 26, e4.words[r3] = i2, t4 = n2;
            }
            return 0 !== t4 && (e4.words[e4.length++] = t4), e4;
          }, o._prime = function(e4) {
            if (m[e4]) return m[e4];
            var t4;
            if ("k256" === e4) t4 = new v();
            else if ("p224" === e4) t4 = new w();
            else if ("p192" === e4) t4 = new _();
            else {
              if ("p25519" !== e4) throw new Error("Unknown prime " + e4);
              t4 = new A();
            }
            return m[e4] = t4, t4;
          }, S.prototype._verify1 = function(e4) {
            n(0 === e4.negative, "red works only with positives"), n(e4.red, "red works only with red numbers");
          }, S.prototype._verify2 = function(e4, t4) {
            n(!(e4.negative | t4.negative), "red works only with positives"), n(e4.red && e4.red === t4.red, "red works only with red numbers");
          }, S.prototype.imod = function(e4) {
            return this.prime ? this.prime.ireduce(e4)._forceRed(this) : e4.umod(this.m)._forceRed(this);
          }, S.prototype.neg = function(e4) {
            return e4.isZero() ? e4.clone() : this.m.sub(e4)._forceRed(this);
          }, S.prototype.add = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.add(t4);
            return r3.cmp(this.m) >= 0 && r3.isub(this.m), r3._forceRed(this);
          }, S.prototype.iadd = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.iadd(t4);
            return r3.cmp(this.m) >= 0 && r3.isub(this.m), r3;
          }, S.prototype.sub = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.sub(t4);
            return r3.cmpn(0) < 0 && r3.iadd(this.m), r3._forceRed(this);
          }, S.prototype.isub = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.isub(t4);
            return r3.cmpn(0) < 0 && r3.iadd(this.m), r3;
          }, S.prototype.shl = function(e4, t4) {
            return this._verify1(e4), this.imod(e4.ushln(t4));
          }, S.prototype.imul = function(e4, t4) {
            return this._verify2(e4, t4), this.imod(e4.imul(t4));
          }, S.prototype.mul = function(e4, t4) {
            return this._verify2(e4, t4), this.imod(e4.mul(t4));
          }, S.prototype.isqr = function(e4) {
            return this.imul(e4, e4.clone());
          }, S.prototype.sqr = function(e4) {
            return this.mul(e4, e4);
          }, S.prototype.sqrt = function(e4) {
            if (e4.isZero()) return e4.clone();
            var t4 = this.m.andln(3);
            if (n(t4 % 2 == 1), 3 === t4) {
              var r3 = this.m.add(new o(1)).iushrn(2);
              return this.pow(e4, r3);
            }
            for (var i2 = this.m.subn(1), s2 = 0; !i2.isZero() && 0 === i2.andln(1); ) s2++, i2.iushrn(1);
            n(!i2.isZero());
            var a2 = new o(1).toRed(this), c2 = a2.redNeg(), u2 = this.m.subn(1).iushrn(1), d2 = this.m.bitLength();
            for (d2 = new o(2 * d2 * d2).toRed(this); 0 !== this.pow(d2, u2).cmp(c2); ) d2.redIAdd(c2);
            for (var f2 = this.pow(d2, i2), h2 = this.pow(e4, i2.addn(1).iushrn(1)), l2 = this.pow(e4, i2), p2 = s2; 0 !== l2.cmp(a2); ) {
              for (var b2 = l2, y2 = 0; 0 !== b2.cmp(a2); y2++) b2 = b2.redSqr();
              n(y2 < p2);
              var m2 = this.pow(f2, new o(1).iushln(p2 - y2 - 1));
              h2 = h2.redMul(m2), f2 = m2.redSqr(), l2 = l2.redMul(f2), p2 = y2;
            }
            return h2;
          }, S.prototype.invm = function(e4) {
            var t4 = e4._invmp(this.m);
            return 0 !== t4.negative ? (t4.negative = 0, this.imod(t4).redNeg()) : this.imod(t4);
          }, S.prototype.pow = function(e4, t4) {
            if (t4.isZero()) return new o(1).toRed(this);
            if (0 === t4.cmpn(1)) return e4.clone();
            var r3 = new Array(16);
            r3[0] = new o(1).toRed(this), r3[1] = e4;
            for (var n2 = 2; n2 < r3.length; n2++) r3[n2] = this.mul(r3[n2 - 1], e4);
            var i2 = r3[0], s2 = 0, a2 = 0, c2 = t4.bitLength() % 26;
            for (0 === c2 && (c2 = 26), n2 = t4.length - 1; n2 >= 0; n2--) {
              for (var u2 = t4.words[n2], d2 = c2 - 1; d2 >= 0; d2--) {
                var f2 = u2 >> d2 & 1;
                i2 !== r3[0] && (i2 = this.sqr(i2)), 0 !== f2 || 0 !== s2 ? (s2 <<= 1, s2 |= f2, (4 == ++a2 || 0 === n2 && 0 === d2) && (i2 = this.mul(i2, r3[s2]), a2 = 0, s2 = 0)) : a2 = 0;
              }
              c2 = 26;
            }
            return i2;
          }, S.prototype.convertTo = function(e4) {
            var t4 = e4.umod(this.m);
            return t4 === e4 ? t4.clone() : t4;
          }, S.prototype.convertFrom = function(e4) {
            var t4 = e4.clone();
            return t4.red = null, t4;
          }, o.mont = function(e4) {
            return new C(e4);
          }, i(C, S), C.prototype.convertTo = function(e4) {
            return this.imod(e4.ushln(this.shift));
          }, C.prototype.convertFrom = function(e4) {
            var t4 = this.imod(e4.mul(this.rinv));
            return t4.red = null, t4;
          }, C.prototype.imul = function(e4, t4) {
            if (e4.isZero() || t4.isZero()) return e4.words[0] = 0, e4.length = 1, e4;
            var r3 = e4.imul(t4), n2 = r3.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), i2 = r3.isub(n2).iushrn(this.shift), o2 = i2;
            return i2.cmp(this.m) >= 0 ? o2 = i2.isub(this.m) : i2.cmpn(0) < 0 && (o2 = i2.iadd(this.m)), o2._forceRed(this);
          }, C.prototype.mul = function(e4, t4) {
            if (e4.isZero() || t4.isZero()) return new o(0)._forceRed(this);
            var r3 = e4.mul(t4), n2 = r3.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), i2 = r3.isub(n2).iushrn(this.shift), s2 = i2;
            return i2.cmp(this.m) >= 0 ? s2 = i2.isub(this.m) : i2.cmpn(0) < 0 && (s2 = i2.iadd(this.m)), s2._forceRed(this);
          }, C.prototype.invm = function(e4) {
            return this.imod(e4._invmp(this.m).mul(this.r2))._forceRed(this);
          };
        })(e2 = r2.nmd(e2), this);
      }, 3900: function(e2, t2, r2) {
        !(function(e3, t3) {
          "use strict";
          function n(e4, t4) {
            if (!e4) throw new Error(t4 || "Assertion failed");
          }
          function i(e4, t4) {
            e4.super_ = t4;
            var r3 = function() {
            };
            r3.prototype = t4.prototype, e4.prototype = new r3(), e4.prototype.constructor = e4;
          }
          function o(e4, t4, r3) {
            if (o.isBN(e4)) return e4;
            this.negative = 0, this.words = null, this.length = 0, this.red = null, null !== e4 && ("le" !== t4 && "be" !== t4 || (r3 = t4, t4 = 10), this._init(e4 || 0, t4 || 10, r3 || "be"));
          }
          var s;
          "object" == typeof e3 ? e3.exports = o : t3.BN = o, o.BN = o, o.wordSize = 26;
          try {
            s = "undefined" != typeof window && void 0 !== window.Buffer ? window.Buffer : r2(9322).Buffer;
          } catch (e4) {
          }
          function a(e4, t4) {
            var r3 = e4.charCodeAt(t4);
            return r3 >= 48 && r3 <= 57 ? r3 - 48 : r3 >= 65 && r3 <= 70 ? r3 - 55 : r3 >= 97 && r3 <= 102 ? r3 - 87 : void n(false, "Invalid character in " + e4);
          }
          function c(e4, t4, r3) {
            var n2 = a(e4, r3);
            return r3 - 1 >= t4 && (n2 |= a(e4, r3 - 1) << 4), n2;
          }
          function u(e4, t4, r3, i2) {
            for (var o2 = 0, s2 = 0, a2 = Math.min(e4.length, r3), c2 = t4; c2 < a2; c2++) {
              var u2 = e4.charCodeAt(c2) - 48;
              o2 *= i2, s2 = u2 >= 49 ? u2 - 49 + 10 : u2 >= 17 ? u2 - 17 + 10 : u2, n(u2 >= 0 && s2 < i2, "Invalid character"), o2 += s2;
            }
            return o2;
          }
          function d(e4, t4) {
            e4.words = t4.words, e4.length = t4.length, e4.negative = t4.negative, e4.red = t4.red;
          }
          if (o.isBN = function(e4) {
            return e4 instanceof o || null !== e4 && "object" == typeof e4 && e4.constructor.wordSize === o.wordSize && Array.isArray(e4.words);
          }, o.max = function(e4, t4) {
            return e4.cmp(t4) > 0 ? e4 : t4;
          }, o.min = function(e4, t4) {
            return e4.cmp(t4) < 0 ? e4 : t4;
          }, o.prototype._init = function(e4, t4, r3) {
            if ("number" == typeof e4) return this._initNumber(e4, t4, r3);
            if ("object" == typeof e4) return this._initArray(e4, t4, r3);
            "hex" === t4 && (t4 = 16), n(t4 === (0 | t4) && t4 >= 2 && t4 <= 36);
            var i2 = 0;
            "-" === (e4 = e4.toString().replace(/\s+/g, ""))[0] && (i2++, this.negative = 1), i2 < e4.length && (16 === t4 ? this._parseHex(e4, i2, r3) : (this._parseBase(e4, t4, i2), "le" === r3 && this._initArray(this.toArray(), t4, r3)));
          }, o.prototype._initNumber = function(e4, t4, r3) {
            e4 < 0 && (this.negative = 1, e4 = -e4), e4 < 67108864 ? (this.words = [67108863 & e4], this.length = 1) : e4 < 4503599627370496 ? (this.words = [67108863 & e4, e4 / 67108864 & 67108863], this.length = 2) : (n(e4 < 9007199254740992), this.words = [67108863 & e4, e4 / 67108864 & 67108863, 1], this.length = 3), "le" === r3 && this._initArray(this.toArray(), t4, r3);
          }, o.prototype._initArray = function(e4, t4, r3) {
            if (n("number" == typeof e4.length), e4.length <= 0) return this.words = [0], this.length = 1, this;
            this.length = Math.ceil(e4.length / 3), this.words = new Array(this.length);
            for (var i2 = 0; i2 < this.length; i2++) this.words[i2] = 0;
            var o2, s2, a2 = 0;
            if ("be" === r3) for (i2 = e4.length - 1, o2 = 0; i2 >= 0; i2 -= 3) s2 = e4[i2] | e4[i2 - 1] << 8 | e4[i2 - 2] << 16, this.words[o2] |= s2 << a2 & 67108863, this.words[o2 + 1] = s2 >>> 26 - a2 & 67108863, (a2 += 24) >= 26 && (a2 -= 26, o2++);
            else if ("le" === r3) for (i2 = 0, o2 = 0; i2 < e4.length; i2 += 3) s2 = e4[i2] | e4[i2 + 1] << 8 | e4[i2 + 2] << 16, this.words[o2] |= s2 << a2 & 67108863, this.words[o2 + 1] = s2 >>> 26 - a2 & 67108863, (a2 += 24) >= 26 && (a2 -= 26, o2++);
            return this._strip();
          }, o.prototype._parseHex = function(e4, t4, r3) {
            this.length = Math.ceil((e4.length - t4) / 6), this.words = new Array(this.length);
            for (var n2 = 0; n2 < this.length; n2++) this.words[n2] = 0;
            var i2, o2 = 0, s2 = 0;
            if ("be" === r3) for (n2 = e4.length - 1; n2 >= t4; n2 -= 2) i2 = c(e4, t4, n2) << o2, this.words[s2] |= 67108863 & i2, o2 >= 18 ? (o2 -= 18, s2 += 1, this.words[s2] |= i2 >>> 26) : o2 += 8;
            else for (n2 = (e4.length - t4) % 2 == 0 ? t4 + 1 : t4; n2 < e4.length; n2 += 2) i2 = c(e4, t4, n2) << o2, this.words[s2] |= 67108863 & i2, o2 >= 18 ? (o2 -= 18, s2 += 1, this.words[s2] |= i2 >>> 26) : o2 += 8;
            this._strip();
          }, o.prototype._parseBase = function(e4, t4, r3) {
            this.words = [0], this.length = 1;
            for (var n2 = 0, i2 = 1; i2 <= 67108863; i2 *= t4) n2++;
            n2--, i2 = i2 / t4 | 0;
            for (var o2 = e4.length - r3, s2 = o2 % n2, a2 = Math.min(o2, o2 - s2) + r3, c2 = 0, d2 = r3; d2 < a2; d2 += n2) c2 = u(e4, d2, d2 + n2, t4), this.imuln(i2), this.words[0] + c2 < 67108864 ? this.words[0] += c2 : this._iaddn(c2);
            if (0 !== s2) {
              var f2 = 1;
              for (c2 = u(e4, d2, e4.length, t4), d2 = 0; d2 < s2; d2++) f2 *= t4;
              this.imuln(f2), this.words[0] + c2 < 67108864 ? this.words[0] += c2 : this._iaddn(c2);
            }
            this._strip();
          }, o.prototype.copy = function(e4) {
            e4.words = new Array(this.length);
            for (var t4 = 0; t4 < this.length; t4++) e4.words[t4] = this.words[t4];
            e4.length = this.length, e4.negative = this.negative, e4.red = this.red;
          }, o.prototype._move = function(e4) {
            d(e4, this);
          }, o.prototype.clone = function() {
            var e4 = new o(null);
            return this.copy(e4), e4;
          }, o.prototype._expand = function(e4) {
            for (; this.length < e4; ) this.words[this.length++] = 0;
            return this;
          }, o.prototype._strip = function() {
            for (; this.length > 1 && 0 === this.words[this.length - 1]; ) this.length--;
            return this._normSign();
          }, o.prototype._normSign = function() {
            return 1 === this.length && 0 === this.words[0] && (this.negative = 0), this;
          }, "undefined" != typeof Symbol && "function" == typeof Symbol.for) try {
            o.prototype[/* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom")] = f;
          } catch (e4) {
            o.prototype.inspect = f;
          }
          else o.prototype.inspect = f;
          function f() {
            return (this.red ? "<BN-R: " : "<BN: ") + this.toString(16) + ">";
          }
          var h = ["", "0", "00", "000", "0000", "00000", "000000", "0000000", "00000000", "000000000", "0000000000", "00000000000", "000000000000", "0000000000000", "00000000000000", "000000000000000", "0000000000000000", "00000000000000000", "000000000000000000", "0000000000000000000", "00000000000000000000", "000000000000000000000", "0000000000000000000000", "00000000000000000000000", "000000000000000000000000", "0000000000000000000000000"], l = [0, 0, 25, 16, 12, 11, 10, 9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5], p = [0, 0, 33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216, 43046721, 1e7, 19487171, 35831808, 62748517, 7529536, 11390625, 16777216, 24137569, 34012224, 47045881, 64e6, 4084101, 5153632, 6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149, 243e5, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176];
          function b(e4, t4, r3) {
            r3.negative = t4.negative ^ e4.negative;
            var n2 = e4.length + t4.length | 0;
            r3.length = n2, n2 = n2 - 1 | 0;
            var i2 = 0 | e4.words[0], o2 = 0 | t4.words[0], s2 = i2 * o2, a2 = 67108863 & s2, c2 = s2 / 67108864 | 0;
            r3.words[0] = a2;
            for (var u2 = 1; u2 < n2; u2++) {
              for (var d2 = c2 >>> 26, f2 = 67108863 & c2, h2 = Math.min(u2, t4.length - 1), l2 = Math.max(0, u2 - e4.length + 1); l2 <= h2; l2++) {
                var p2 = u2 - l2 | 0;
                d2 += (s2 = (i2 = 0 | e4.words[p2]) * (o2 = 0 | t4.words[l2]) + f2) / 67108864 | 0, f2 = 67108863 & s2;
              }
              r3.words[u2] = 0 | f2, c2 = 0 | d2;
            }
            return 0 !== c2 ? r3.words[u2] = 0 | c2 : r3.length--, r3._strip();
          }
          o.prototype.toString = function(e4, t4) {
            var r3;
            if (t4 = 0 | t4 || 1, 16 === (e4 = e4 || 10) || "hex" === e4) {
              r3 = "";
              for (var i2 = 0, o2 = 0, s2 = 0; s2 < this.length; s2++) {
                var a2 = this.words[s2], c2 = (16777215 & (a2 << i2 | o2)).toString(16);
                o2 = a2 >>> 24 - i2 & 16777215, (i2 += 2) >= 26 && (i2 -= 26, s2--), r3 = 0 !== o2 || s2 !== this.length - 1 ? h[6 - c2.length] + c2 + r3 : c2 + r3;
              }
              for (0 !== o2 && (r3 = o2.toString(16) + r3); r3.length % t4 != 0; ) r3 = "0" + r3;
              return 0 !== this.negative && (r3 = "-" + r3), r3;
            }
            if (e4 === (0 | e4) && e4 >= 2 && e4 <= 36) {
              var u2 = l[e4], d2 = p[e4];
              r3 = "";
              var f2 = this.clone();
              for (f2.negative = 0; !f2.isZero(); ) {
                var b2 = f2.modrn(d2).toString(e4);
                r3 = (f2 = f2.idivn(d2)).isZero() ? b2 + r3 : h[u2 - b2.length] + b2 + r3;
              }
              for (this.isZero() && (r3 = "0" + r3); r3.length % t4 != 0; ) r3 = "0" + r3;
              return 0 !== this.negative && (r3 = "-" + r3), r3;
            }
            n(false, "Base should be between 2 and 36");
          }, o.prototype.toNumber = function() {
            var e4 = this.words[0];
            return 2 === this.length ? e4 += 67108864 * this.words[1] : 3 === this.length && 1 === this.words[2] ? e4 += 4503599627370496 + 67108864 * this.words[1] : this.length > 2 && n(false, "Number can only safely store up to 53 bits"), 0 !== this.negative ? -e4 : e4;
          }, o.prototype.toJSON = function() {
            return this.toString(16, 2);
          }, s && (o.prototype.toBuffer = function(e4, t4) {
            return this.toArrayLike(s, e4, t4);
          }), o.prototype.toArray = function(e4, t4) {
            return this.toArrayLike(Array, e4, t4);
          }, o.prototype.toArrayLike = function(e4, t4, r3) {
            this._strip();
            var i2 = this.byteLength(), o2 = r3 || Math.max(1, i2);
            n(i2 <= o2, "byte array longer than desired length"), n(o2 > 0, "Requested array length <= 0");
            var s2 = (function(e5, t5) {
              return e5.allocUnsafe ? e5.allocUnsafe(t5) : new e5(t5);
            })(e4, o2);
            return this["_toArrayLike" + ("le" === t4 ? "LE" : "BE")](s2, i2), s2;
          }, o.prototype._toArrayLikeLE = function(e4, t4) {
            for (var r3 = 0, n2 = 0, i2 = 0, o2 = 0; i2 < this.length; i2++) {
              var s2 = this.words[i2] << o2 | n2;
              e4[r3++] = 255 & s2, r3 < e4.length && (e4[r3++] = s2 >> 8 & 255), r3 < e4.length && (e4[r3++] = s2 >> 16 & 255), 6 === o2 ? (r3 < e4.length && (e4[r3++] = s2 >> 24 & 255), n2 = 0, o2 = 0) : (n2 = s2 >>> 24, o2 += 2);
            }
            if (r3 < e4.length) for (e4[r3++] = n2; r3 < e4.length; ) e4[r3++] = 0;
          }, o.prototype._toArrayLikeBE = function(e4, t4) {
            for (var r3 = e4.length - 1, n2 = 0, i2 = 0, o2 = 0; i2 < this.length; i2++) {
              var s2 = this.words[i2] << o2 | n2;
              e4[r3--] = 255 & s2, r3 >= 0 && (e4[r3--] = s2 >> 8 & 255), r3 >= 0 && (e4[r3--] = s2 >> 16 & 255), 6 === o2 ? (r3 >= 0 && (e4[r3--] = s2 >> 24 & 255), n2 = 0, o2 = 0) : (n2 = s2 >>> 24, o2 += 2);
            }
            if (r3 >= 0) for (e4[r3--] = n2; r3 >= 0; ) e4[r3--] = 0;
          }, Math.clz32 ? o.prototype._countBits = function(e4) {
            return 32 - Math.clz32(e4);
          } : o.prototype._countBits = function(e4) {
            var t4 = e4, r3 = 0;
            return t4 >= 4096 && (r3 += 13, t4 >>>= 13), t4 >= 64 && (r3 += 7, t4 >>>= 7), t4 >= 8 && (r3 += 4, t4 >>>= 4), t4 >= 2 && (r3 += 2, t4 >>>= 2), r3 + t4;
          }, o.prototype._zeroBits = function(e4) {
            if (0 === e4) return 26;
            var t4 = e4, r3 = 0;
            return 8191 & t4 || (r3 += 13, t4 >>>= 13), 127 & t4 || (r3 += 7, t4 >>>= 7), 15 & t4 || (r3 += 4, t4 >>>= 4), 3 & t4 || (r3 += 2, t4 >>>= 2), 1 & t4 || r3++, r3;
          }, o.prototype.bitLength = function() {
            var e4 = this.words[this.length - 1], t4 = this._countBits(e4);
            return 26 * (this.length - 1) + t4;
          }, o.prototype.zeroBits = function() {
            if (this.isZero()) return 0;
            for (var e4 = 0, t4 = 0; t4 < this.length; t4++) {
              var r3 = this._zeroBits(this.words[t4]);
              if (e4 += r3, 26 !== r3) break;
            }
            return e4;
          }, o.prototype.byteLength = function() {
            return Math.ceil(this.bitLength() / 8);
          }, o.prototype.toTwos = function(e4) {
            return 0 !== this.negative ? this.abs().inotn(e4).iaddn(1) : this.clone();
          }, o.prototype.fromTwos = function(e4) {
            return this.testn(e4 - 1) ? this.notn(e4).iaddn(1).ineg() : this.clone();
          }, o.prototype.isNeg = function() {
            return 0 !== this.negative;
          }, o.prototype.neg = function() {
            return this.clone().ineg();
          }, o.prototype.ineg = function() {
            return this.isZero() || (this.negative ^= 1), this;
          }, o.prototype.iuor = function(e4) {
            for (; this.length < e4.length; ) this.words[this.length++] = 0;
            for (var t4 = 0; t4 < e4.length; t4++) this.words[t4] = this.words[t4] | e4.words[t4];
            return this._strip();
          }, o.prototype.ior = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuor(e4);
          }, o.prototype.or = function(e4) {
            return this.length > e4.length ? this.clone().ior(e4) : e4.clone().ior(this);
          }, o.prototype.uor = function(e4) {
            return this.length > e4.length ? this.clone().iuor(e4) : e4.clone().iuor(this);
          }, o.prototype.iuand = function(e4) {
            var t4;
            t4 = this.length > e4.length ? e4 : this;
            for (var r3 = 0; r3 < t4.length; r3++) this.words[r3] = this.words[r3] & e4.words[r3];
            return this.length = t4.length, this._strip();
          }, o.prototype.iand = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuand(e4);
          }, o.prototype.and = function(e4) {
            return this.length > e4.length ? this.clone().iand(e4) : e4.clone().iand(this);
          }, o.prototype.uand = function(e4) {
            return this.length > e4.length ? this.clone().iuand(e4) : e4.clone().iuand(this);
          }, o.prototype.iuxor = function(e4) {
            var t4, r3;
            this.length > e4.length ? (t4 = this, r3 = e4) : (t4 = e4, r3 = this);
            for (var n2 = 0; n2 < r3.length; n2++) this.words[n2] = t4.words[n2] ^ r3.words[n2];
            if (this !== t4) for (; n2 < t4.length; n2++) this.words[n2] = t4.words[n2];
            return this.length = t4.length, this._strip();
          }, o.prototype.ixor = function(e4) {
            return n(!(this.negative | e4.negative)), this.iuxor(e4);
          }, o.prototype.xor = function(e4) {
            return this.length > e4.length ? this.clone().ixor(e4) : e4.clone().ixor(this);
          }, o.prototype.uxor = function(e4) {
            return this.length > e4.length ? this.clone().iuxor(e4) : e4.clone().iuxor(this);
          }, o.prototype.inotn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = 0 | Math.ceil(e4 / 26), r3 = e4 % 26;
            this._expand(t4), r3 > 0 && t4--;
            for (var i2 = 0; i2 < t4; i2++) this.words[i2] = 67108863 & ~this.words[i2];
            return r3 > 0 && (this.words[i2] = ~this.words[i2] & 67108863 >> 26 - r3), this._strip();
          }, o.prototype.notn = function(e4) {
            return this.clone().inotn(e4);
          }, o.prototype.setn = function(e4, t4) {
            n("number" == typeof e4 && e4 >= 0);
            var r3 = e4 / 26 | 0, i2 = e4 % 26;
            return this._expand(r3 + 1), this.words[r3] = t4 ? this.words[r3] | 1 << i2 : this.words[r3] & ~(1 << i2), this._strip();
          }, o.prototype.iadd = function(e4) {
            var t4, r3, n2;
            if (0 !== this.negative && 0 === e4.negative) return this.negative = 0, t4 = this.isub(e4), this.negative ^= 1, this._normSign();
            if (0 === this.negative && 0 !== e4.negative) return e4.negative = 0, t4 = this.isub(e4), e4.negative = 1, t4._normSign();
            this.length > e4.length ? (r3 = this, n2 = e4) : (r3 = e4, n2 = this);
            for (var i2 = 0, o2 = 0; o2 < n2.length; o2++) t4 = (0 | r3.words[o2]) + (0 | n2.words[o2]) + i2, this.words[o2] = 67108863 & t4, i2 = t4 >>> 26;
            for (; 0 !== i2 && o2 < r3.length; o2++) t4 = (0 | r3.words[o2]) + i2, this.words[o2] = 67108863 & t4, i2 = t4 >>> 26;
            if (this.length = r3.length, 0 !== i2) this.words[this.length] = i2, this.length++;
            else if (r3 !== this) for (; o2 < r3.length; o2++) this.words[o2] = r3.words[o2];
            return this;
          }, o.prototype.add = function(e4) {
            var t4;
            return 0 !== e4.negative && 0 === this.negative ? (e4.negative = 0, t4 = this.sub(e4), e4.negative ^= 1, t4) : 0 === e4.negative && 0 !== this.negative ? (this.negative = 0, t4 = e4.sub(this), this.negative = 1, t4) : this.length > e4.length ? this.clone().iadd(e4) : e4.clone().iadd(this);
          }, o.prototype.isub = function(e4) {
            if (0 !== e4.negative) {
              e4.negative = 0;
              var t4 = this.iadd(e4);
              return e4.negative = 1, t4._normSign();
            }
            if (0 !== this.negative) return this.negative = 0, this.iadd(e4), this.negative = 1, this._normSign();
            var r3, n2, i2 = this.cmp(e4);
            if (0 === i2) return this.negative = 0, this.length = 1, this.words[0] = 0, this;
            i2 > 0 ? (r3 = this, n2 = e4) : (r3 = e4, n2 = this);
            for (var o2 = 0, s2 = 0; s2 < n2.length; s2++) o2 = (t4 = (0 | r3.words[s2]) - (0 | n2.words[s2]) + o2) >> 26, this.words[s2] = 67108863 & t4;
            for (; 0 !== o2 && s2 < r3.length; s2++) o2 = (t4 = (0 | r3.words[s2]) + o2) >> 26, this.words[s2] = 67108863 & t4;
            if (0 === o2 && s2 < r3.length && r3 !== this) for (; s2 < r3.length; s2++) this.words[s2] = r3.words[s2];
            return this.length = Math.max(this.length, s2), r3 !== this && (this.negative = 1), this._strip();
          }, o.prototype.sub = function(e4) {
            return this.clone().isub(e4);
          };
          var y = function(e4, t4, r3) {
            var n2, i2, o2, s2 = e4.words, a2 = t4.words, c2 = r3.words, u2 = 0, d2 = 0 | s2[0], f2 = 8191 & d2, h2 = d2 >>> 13, l2 = 0 | s2[1], p2 = 8191 & l2, b2 = l2 >>> 13, y2 = 0 | s2[2], m2 = 8191 & y2, g2 = y2 >>> 13, v2 = 0 | s2[3], w2 = 8191 & v2, _2 = v2 >>> 13, A2 = 0 | s2[4], S2 = 8191 & A2, C2 = A2 >>> 13, T2 = 0 | s2[5], M2 = 8191 & T2, E2 = T2 >>> 13, k = 0 | s2[6], x = 8191 & k, I = k >>> 13, B = 0 | s2[7], U = 8191 & B, P = B >>> 13, O = 0 | s2[8], R = 8191 & O, N = O >>> 13, L = 0 | s2[9], j = 8191 & L, D = L >>> 13, F = 0 | a2[0], H = 8191 & F, q = F >>> 13, $ = 0 | a2[1], V = 8191 & $, G = $ >>> 13, z = 0 | a2[2], K = 8191 & z, W = z >>> 13, J = 0 | a2[3], Z = 8191 & J, X = J >>> 13, Y = 0 | a2[4], Q = 8191 & Y, ee = Y >>> 13, te = 0 | a2[5], re = 8191 & te, ne = te >>> 13, ie = 0 | a2[6], oe = 8191 & ie, se = ie >>> 13, ae = 0 | a2[7], ce = 8191 & ae, ue = ae >>> 13, de = 0 | a2[8], fe = 8191 & de, he = de >>> 13, le = 0 | a2[9], pe = 8191 & le, be = le >>> 13;
            r3.negative = e4.negative ^ t4.negative, r3.length = 19;
            var ye = (u2 + (n2 = Math.imul(f2, H)) | 0) + ((8191 & (i2 = (i2 = Math.imul(f2, q)) + Math.imul(h2, H) | 0)) << 13) | 0;
            u2 = ((o2 = Math.imul(h2, q)) + (i2 >>> 13) | 0) + (ye >>> 26) | 0, ye &= 67108863, n2 = Math.imul(p2, H), i2 = (i2 = Math.imul(p2, q)) + Math.imul(b2, H) | 0, o2 = Math.imul(b2, q);
            var me = (u2 + (n2 = n2 + Math.imul(f2, V) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, G) | 0) + Math.imul(h2, V) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, G) | 0) + (i2 >>> 13) | 0) + (me >>> 26) | 0, me &= 67108863, n2 = Math.imul(m2, H), i2 = (i2 = Math.imul(m2, q)) + Math.imul(g2, H) | 0, o2 = Math.imul(g2, q), n2 = n2 + Math.imul(p2, V) | 0, i2 = (i2 = i2 + Math.imul(p2, G) | 0) + Math.imul(b2, V) | 0, o2 = o2 + Math.imul(b2, G) | 0;
            var ge = (u2 + (n2 = n2 + Math.imul(f2, K) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, W) | 0) + Math.imul(h2, K) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, W) | 0) + (i2 >>> 13) | 0) + (ge >>> 26) | 0, ge &= 67108863, n2 = Math.imul(w2, H), i2 = (i2 = Math.imul(w2, q)) + Math.imul(_2, H) | 0, o2 = Math.imul(_2, q), n2 = n2 + Math.imul(m2, V) | 0, i2 = (i2 = i2 + Math.imul(m2, G) | 0) + Math.imul(g2, V) | 0, o2 = o2 + Math.imul(g2, G) | 0, n2 = n2 + Math.imul(p2, K) | 0, i2 = (i2 = i2 + Math.imul(p2, W) | 0) + Math.imul(b2, K) | 0, o2 = o2 + Math.imul(b2, W) | 0;
            var ve = (u2 + (n2 = n2 + Math.imul(f2, Z) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, X) | 0) + Math.imul(h2, Z) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, X) | 0) + (i2 >>> 13) | 0) + (ve >>> 26) | 0, ve &= 67108863, n2 = Math.imul(S2, H), i2 = (i2 = Math.imul(S2, q)) + Math.imul(C2, H) | 0, o2 = Math.imul(C2, q), n2 = n2 + Math.imul(w2, V) | 0, i2 = (i2 = i2 + Math.imul(w2, G) | 0) + Math.imul(_2, V) | 0, o2 = o2 + Math.imul(_2, G) | 0, n2 = n2 + Math.imul(m2, K) | 0, i2 = (i2 = i2 + Math.imul(m2, W) | 0) + Math.imul(g2, K) | 0, o2 = o2 + Math.imul(g2, W) | 0, n2 = n2 + Math.imul(p2, Z) | 0, i2 = (i2 = i2 + Math.imul(p2, X) | 0) + Math.imul(b2, Z) | 0, o2 = o2 + Math.imul(b2, X) | 0;
            var we = (u2 + (n2 = n2 + Math.imul(f2, Q) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ee) | 0) + Math.imul(h2, Q) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ee) | 0) + (i2 >>> 13) | 0) + (we >>> 26) | 0, we &= 67108863, n2 = Math.imul(M2, H), i2 = (i2 = Math.imul(M2, q)) + Math.imul(E2, H) | 0, o2 = Math.imul(E2, q), n2 = n2 + Math.imul(S2, V) | 0, i2 = (i2 = i2 + Math.imul(S2, G) | 0) + Math.imul(C2, V) | 0, o2 = o2 + Math.imul(C2, G) | 0, n2 = n2 + Math.imul(w2, K) | 0, i2 = (i2 = i2 + Math.imul(w2, W) | 0) + Math.imul(_2, K) | 0, o2 = o2 + Math.imul(_2, W) | 0, n2 = n2 + Math.imul(m2, Z) | 0, i2 = (i2 = i2 + Math.imul(m2, X) | 0) + Math.imul(g2, Z) | 0, o2 = o2 + Math.imul(g2, X) | 0, n2 = n2 + Math.imul(p2, Q) | 0, i2 = (i2 = i2 + Math.imul(p2, ee) | 0) + Math.imul(b2, Q) | 0, o2 = o2 + Math.imul(b2, ee) | 0;
            var _e = (u2 + (n2 = n2 + Math.imul(f2, re) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ne) | 0) + Math.imul(h2, re) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ne) | 0) + (i2 >>> 13) | 0) + (_e >>> 26) | 0, _e &= 67108863, n2 = Math.imul(x, H), i2 = (i2 = Math.imul(x, q)) + Math.imul(I, H) | 0, o2 = Math.imul(I, q), n2 = n2 + Math.imul(M2, V) | 0, i2 = (i2 = i2 + Math.imul(M2, G) | 0) + Math.imul(E2, V) | 0, o2 = o2 + Math.imul(E2, G) | 0, n2 = n2 + Math.imul(S2, K) | 0, i2 = (i2 = i2 + Math.imul(S2, W) | 0) + Math.imul(C2, K) | 0, o2 = o2 + Math.imul(C2, W) | 0, n2 = n2 + Math.imul(w2, Z) | 0, i2 = (i2 = i2 + Math.imul(w2, X) | 0) + Math.imul(_2, Z) | 0, o2 = o2 + Math.imul(_2, X) | 0, n2 = n2 + Math.imul(m2, Q) | 0, i2 = (i2 = i2 + Math.imul(m2, ee) | 0) + Math.imul(g2, Q) | 0, o2 = o2 + Math.imul(g2, ee) | 0, n2 = n2 + Math.imul(p2, re) | 0, i2 = (i2 = i2 + Math.imul(p2, ne) | 0) + Math.imul(b2, re) | 0, o2 = o2 + Math.imul(b2, ne) | 0;
            var Ae = (u2 + (n2 = n2 + Math.imul(f2, oe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, se) | 0) + Math.imul(h2, oe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, se) | 0) + (i2 >>> 13) | 0) + (Ae >>> 26) | 0, Ae &= 67108863, n2 = Math.imul(U, H), i2 = (i2 = Math.imul(U, q)) + Math.imul(P, H) | 0, o2 = Math.imul(P, q), n2 = n2 + Math.imul(x, V) | 0, i2 = (i2 = i2 + Math.imul(x, G) | 0) + Math.imul(I, V) | 0, o2 = o2 + Math.imul(I, G) | 0, n2 = n2 + Math.imul(M2, K) | 0, i2 = (i2 = i2 + Math.imul(M2, W) | 0) + Math.imul(E2, K) | 0, o2 = o2 + Math.imul(E2, W) | 0, n2 = n2 + Math.imul(S2, Z) | 0, i2 = (i2 = i2 + Math.imul(S2, X) | 0) + Math.imul(C2, Z) | 0, o2 = o2 + Math.imul(C2, X) | 0, n2 = n2 + Math.imul(w2, Q) | 0, i2 = (i2 = i2 + Math.imul(w2, ee) | 0) + Math.imul(_2, Q) | 0, o2 = o2 + Math.imul(_2, ee) | 0, n2 = n2 + Math.imul(m2, re) | 0, i2 = (i2 = i2 + Math.imul(m2, ne) | 0) + Math.imul(g2, re) | 0, o2 = o2 + Math.imul(g2, ne) | 0, n2 = n2 + Math.imul(p2, oe) | 0, i2 = (i2 = i2 + Math.imul(p2, se) | 0) + Math.imul(b2, oe) | 0, o2 = o2 + Math.imul(b2, se) | 0;
            var Se = (u2 + (n2 = n2 + Math.imul(f2, ce) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, ue) | 0) + Math.imul(h2, ce) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, ue) | 0) + (i2 >>> 13) | 0) + (Se >>> 26) | 0, Se &= 67108863, n2 = Math.imul(R, H), i2 = (i2 = Math.imul(R, q)) + Math.imul(N, H) | 0, o2 = Math.imul(N, q), n2 = n2 + Math.imul(U, V) | 0, i2 = (i2 = i2 + Math.imul(U, G) | 0) + Math.imul(P, V) | 0, o2 = o2 + Math.imul(P, G) | 0, n2 = n2 + Math.imul(x, K) | 0, i2 = (i2 = i2 + Math.imul(x, W) | 0) + Math.imul(I, K) | 0, o2 = o2 + Math.imul(I, W) | 0, n2 = n2 + Math.imul(M2, Z) | 0, i2 = (i2 = i2 + Math.imul(M2, X) | 0) + Math.imul(E2, Z) | 0, o2 = o2 + Math.imul(E2, X) | 0, n2 = n2 + Math.imul(S2, Q) | 0, i2 = (i2 = i2 + Math.imul(S2, ee) | 0) + Math.imul(C2, Q) | 0, o2 = o2 + Math.imul(C2, ee) | 0, n2 = n2 + Math.imul(w2, re) | 0, i2 = (i2 = i2 + Math.imul(w2, ne) | 0) + Math.imul(_2, re) | 0, o2 = o2 + Math.imul(_2, ne) | 0, n2 = n2 + Math.imul(m2, oe) | 0, i2 = (i2 = i2 + Math.imul(m2, se) | 0) + Math.imul(g2, oe) | 0, o2 = o2 + Math.imul(g2, se) | 0, n2 = n2 + Math.imul(p2, ce) | 0, i2 = (i2 = i2 + Math.imul(p2, ue) | 0) + Math.imul(b2, ce) | 0, o2 = o2 + Math.imul(b2, ue) | 0;
            var Ce = (u2 + (n2 = n2 + Math.imul(f2, fe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, he) | 0) + Math.imul(h2, fe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, he) | 0) + (i2 >>> 13) | 0) + (Ce >>> 26) | 0, Ce &= 67108863, n2 = Math.imul(j, H), i2 = (i2 = Math.imul(j, q)) + Math.imul(D, H) | 0, o2 = Math.imul(D, q), n2 = n2 + Math.imul(R, V) | 0, i2 = (i2 = i2 + Math.imul(R, G) | 0) + Math.imul(N, V) | 0, o2 = o2 + Math.imul(N, G) | 0, n2 = n2 + Math.imul(U, K) | 0, i2 = (i2 = i2 + Math.imul(U, W) | 0) + Math.imul(P, K) | 0, o2 = o2 + Math.imul(P, W) | 0, n2 = n2 + Math.imul(x, Z) | 0, i2 = (i2 = i2 + Math.imul(x, X) | 0) + Math.imul(I, Z) | 0, o2 = o2 + Math.imul(I, X) | 0, n2 = n2 + Math.imul(M2, Q) | 0, i2 = (i2 = i2 + Math.imul(M2, ee) | 0) + Math.imul(E2, Q) | 0, o2 = o2 + Math.imul(E2, ee) | 0, n2 = n2 + Math.imul(S2, re) | 0, i2 = (i2 = i2 + Math.imul(S2, ne) | 0) + Math.imul(C2, re) | 0, o2 = o2 + Math.imul(C2, ne) | 0, n2 = n2 + Math.imul(w2, oe) | 0, i2 = (i2 = i2 + Math.imul(w2, se) | 0) + Math.imul(_2, oe) | 0, o2 = o2 + Math.imul(_2, se) | 0, n2 = n2 + Math.imul(m2, ce) | 0, i2 = (i2 = i2 + Math.imul(m2, ue) | 0) + Math.imul(g2, ce) | 0, o2 = o2 + Math.imul(g2, ue) | 0, n2 = n2 + Math.imul(p2, fe) | 0, i2 = (i2 = i2 + Math.imul(p2, he) | 0) + Math.imul(b2, fe) | 0, o2 = o2 + Math.imul(b2, he) | 0;
            var Te = (u2 + (n2 = n2 + Math.imul(f2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(f2, be) | 0) + Math.imul(h2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(h2, be) | 0) + (i2 >>> 13) | 0) + (Te >>> 26) | 0, Te &= 67108863, n2 = Math.imul(j, V), i2 = (i2 = Math.imul(j, G)) + Math.imul(D, V) | 0, o2 = Math.imul(D, G), n2 = n2 + Math.imul(R, K) | 0, i2 = (i2 = i2 + Math.imul(R, W) | 0) + Math.imul(N, K) | 0, o2 = o2 + Math.imul(N, W) | 0, n2 = n2 + Math.imul(U, Z) | 0, i2 = (i2 = i2 + Math.imul(U, X) | 0) + Math.imul(P, Z) | 0, o2 = o2 + Math.imul(P, X) | 0, n2 = n2 + Math.imul(x, Q) | 0, i2 = (i2 = i2 + Math.imul(x, ee) | 0) + Math.imul(I, Q) | 0, o2 = o2 + Math.imul(I, ee) | 0, n2 = n2 + Math.imul(M2, re) | 0, i2 = (i2 = i2 + Math.imul(M2, ne) | 0) + Math.imul(E2, re) | 0, o2 = o2 + Math.imul(E2, ne) | 0, n2 = n2 + Math.imul(S2, oe) | 0, i2 = (i2 = i2 + Math.imul(S2, se) | 0) + Math.imul(C2, oe) | 0, o2 = o2 + Math.imul(C2, se) | 0, n2 = n2 + Math.imul(w2, ce) | 0, i2 = (i2 = i2 + Math.imul(w2, ue) | 0) + Math.imul(_2, ce) | 0, o2 = o2 + Math.imul(_2, ue) | 0, n2 = n2 + Math.imul(m2, fe) | 0, i2 = (i2 = i2 + Math.imul(m2, he) | 0) + Math.imul(g2, fe) | 0, o2 = o2 + Math.imul(g2, he) | 0;
            var Me = (u2 + (n2 = n2 + Math.imul(p2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(p2, be) | 0) + Math.imul(b2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(b2, be) | 0) + (i2 >>> 13) | 0) + (Me >>> 26) | 0, Me &= 67108863, n2 = Math.imul(j, K), i2 = (i2 = Math.imul(j, W)) + Math.imul(D, K) | 0, o2 = Math.imul(D, W), n2 = n2 + Math.imul(R, Z) | 0, i2 = (i2 = i2 + Math.imul(R, X) | 0) + Math.imul(N, Z) | 0, o2 = o2 + Math.imul(N, X) | 0, n2 = n2 + Math.imul(U, Q) | 0, i2 = (i2 = i2 + Math.imul(U, ee) | 0) + Math.imul(P, Q) | 0, o2 = o2 + Math.imul(P, ee) | 0, n2 = n2 + Math.imul(x, re) | 0, i2 = (i2 = i2 + Math.imul(x, ne) | 0) + Math.imul(I, re) | 0, o2 = o2 + Math.imul(I, ne) | 0, n2 = n2 + Math.imul(M2, oe) | 0, i2 = (i2 = i2 + Math.imul(M2, se) | 0) + Math.imul(E2, oe) | 0, o2 = o2 + Math.imul(E2, se) | 0, n2 = n2 + Math.imul(S2, ce) | 0, i2 = (i2 = i2 + Math.imul(S2, ue) | 0) + Math.imul(C2, ce) | 0, o2 = o2 + Math.imul(C2, ue) | 0, n2 = n2 + Math.imul(w2, fe) | 0, i2 = (i2 = i2 + Math.imul(w2, he) | 0) + Math.imul(_2, fe) | 0, o2 = o2 + Math.imul(_2, he) | 0;
            var Ee = (u2 + (n2 = n2 + Math.imul(m2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(m2, be) | 0) + Math.imul(g2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(g2, be) | 0) + (i2 >>> 13) | 0) + (Ee >>> 26) | 0, Ee &= 67108863, n2 = Math.imul(j, Z), i2 = (i2 = Math.imul(j, X)) + Math.imul(D, Z) | 0, o2 = Math.imul(D, X), n2 = n2 + Math.imul(R, Q) | 0, i2 = (i2 = i2 + Math.imul(R, ee) | 0) + Math.imul(N, Q) | 0, o2 = o2 + Math.imul(N, ee) | 0, n2 = n2 + Math.imul(U, re) | 0, i2 = (i2 = i2 + Math.imul(U, ne) | 0) + Math.imul(P, re) | 0, o2 = o2 + Math.imul(P, ne) | 0, n2 = n2 + Math.imul(x, oe) | 0, i2 = (i2 = i2 + Math.imul(x, se) | 0) + Math.imul(I, oe) | 0, o2 = o2 + Math.imul(I, se) | 0, n2 = n2 + Math.imul(M2, ce) | 0, i2 = (i2 = i2 + Math.imul(M2, ue) | 0) + Math.imul(E2, ce) | 0, o2 = o2 + Math.imul(E2, ue) | 0, n2 = n2 + Math.imul(S2, fe) | 0, i2 = (i2 = i2 + Math.imul(S2, he) | 0) + Math.imul(C2, fe) | 0, o2 = o2 + Math.imul(C2, he) | 0;
            var ke = (u2 + (n2 = n2 + Math.imul(w2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(w2, be) | 0) + Math.imul(_2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(_2, be) | 0) + (i2 >>> 13) | 0) + (ke >>> 26) | 0, ke &= 67108863, n2 = Math.imul(j, Q), i2 = (i2 = Math.imul(j, ee)) + Math.imul(D, Q) | 0, o2 = Math.imul(D, ee), n2 = n2 + Math.imul(R, re) | 0, i2 = (i2 = i2 + Math.imul(R, ne) | 0) + Math.imul(N, re) | 0, o2 = o2 + Math.imul(N, ne) | 0, n2 = n2 + Math.imul(U, oe) | 0, i2 = (i2 = i2 + Math.imul(U, se) | 0) + Math.imul(P, oe) | 0, o2 = o2 + Math.imul(P, se) | 0, n2 = n2 + Math.imul(x, ce) | 0, i2 = (i2 = i2 + Math.imul(x, ue) | 0) + Math.imul(I, ce) | 0, o2 = o2 + Math.imul(I, ue) | 0, n2 = n2 + Math.imul(M2, fe) | 0, i2 = (i2 = i2 + Math.imul(M2, he) | 0) + Math.imul(E2, fe) | 0, o2 = o2 + Math.imul(E2, he) | 0;
            var xe = (u2 + (n2 = n2 + Math.imul(S2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(S2, be) | 0) + Math.imul(C2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(C2, be) | 0) + (i2 >>> 13) | 0) + (xe >>> 26) | 0, xe &= 67108863, n2 = Math.imul(j, re), i2 = (i2 = Math.imul(j, ne)) + Math.imul(D, re) | 0, o2 = Math.imul(D, ne), n2 = n2 + Math.imul(R, oe) | 0, i2 = (i2 = i2 + Math.imul(R, se) | 0) + Math.imul(N, oe) | 0, o2 = o2 + Math.imul(N, se) | 0, n2 = n2 + Math.imul(U, ce) | 0, i2 = (i2 = i2 + Math.imul(U, ue) | 0) + Math.imul(P, ce) | 0, o2 = o2 + Math.imul(P, ue) | 0, n2 = n2 + Math.imul(x, fe) | 0, i2 = (i2 = i2 + Math.imul(x, he) | 0) + Math.imul(I, fe) | 0, o2 = o2 + Math.imul(I, he) | 0;
            var Ie = (u2 + (n2 = n2 + Math.imul(M2, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(M2, be) | 0) + Math.imul(E2, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(E2, be) | 0) + (i2 >>> 13) | 0) + (Ie >>> 26) | 0, Ie &= 67108863, n2 = Math.imul(j, oe), i2 = (i2 = Math.imul(j, se)) + Math.imul(D, oe) | 0, o2 = Math.imul(D, se), n2 = n2 + Math.imul(R, ce) | 0, i2 = (i2 = i2 + Math.imul(R, ue) | 0) + Math.imul(N, ce) | 0, o2 = o2 + Math.imul(N, ue) | 0, n2 = n2 + Math.imul(U, fe) | 0, i2 = (i2 = i2 + Math.imul(U, he) | 0) + Math.imul(P, fe) | 0, o2 = o2 + Math.imul(P, he) | 0;
            var Be = (u2 + (n2 = n2 + Math.imul(x, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(x, be) | 0) + Math.imul(I, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(I, be) | 0) + (i2 >>> 13) | 0) + (Be >>> 26) | 0, Be &= 67108863, n2 = Math.imul(j, ce), i2 = (i2 = Math.imul(j, ue)) + Math.imul(D, ce) | 0, o2 = Math.imul(D, ue), n2 = n2 + Math.imul(R, fe) | 0, i2 = (i2 = i2 + Math.imul(R, he) | 0) + Math.imul(N, fe) | 0, o2 = o2 + Math.imul(N, he) | 0;
            var Ue = (u2 + (n2 = n2 + Math.imul(U, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(U, be) | 0) + Math.imul(P, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(P, be) | 0) + (i2 >>> 13) | 0) + (Ue >>> 26) | 0, Ue &= 67108863, n2 = Math.imul(j, fe), i2 = (i2 = Math.imul(j, he)) + Math.imul(D, fe) | 0, o2 = Math.imul(D, he);
            var Pe = (u2 + (n2 = n2 + Math.imul(R, pe) | 0) | 0) + ((8191 & (i2 = (i2 = i2 + Math.imul(R, be) | 0) + Math.imul(N, pe) | 0)) << 13) | 0;
            u2 = ((o2 = o2 + Math.imul(N, be) | 0) + (i2 >>> 13) | 0) + (Pe >>> 26) | 0, Pe &= 67108863;
            var Oe = (u2 + (n2 = Math.imul(j, pe)) | 0) + ((8191 & (i2 = (i2 = Math.imul(j, be)) + Math.imul(D, pe) | 0)) << 13) | 0;
            return u2 = ((o2 = Math.imul(D, be)) + (i2 >>> 13) | 0) + (Oe >>> 26) | 0, Oe &= 67108863, c2[0] = ye, c2[1] = me, c2[2] = ge, c2[3] = ve, c2[4] = we, c2[5] = _e, c2[6] = Ae, c2[7] = Se, c2[8] = Ce, c2[9] = Te, c2[10] = Me, c2[11] = Ee, c2[12] = ke, c2[13] = xe, c2[14] = Ie, c2[15] = Be, c2[16] = Ue, c2[17] = Pe, c2[18] = Oe, 0 !== u2 && (c2[19] = u2, r3.length++), r3;
          };
          function m(e4, t4, r3) {
            r3.negative = t4.negative ^ e4.negative, r3.length = e4.length + t4.length;
            for (var n2 = 0, i2 = 0, o2 = 0; o2 < r3.length - 1; o2++) {
              var s2 = i2;
              i2 = 0;
              for (var a2 = 67108863 & n2, c2 = Math.min(o2, t4.length - 1), u2 = Math.max(0, o2 - e4.length + 1); u2 <= c2; u2++) {
                var d2 = o2 - u2, f2 = (0 | e4.words[d2]) * (0 | t4.words[u2]), h2 = 67108863 & f2;
                a2 = 67108863 & (h2 = h2 + a2 | 0), i2 += (s2 = (s2 = s2 + (f2 / 67108864 | 0) | 0) + (h2 >>> 26) | 0) >>> 26, s2 &= 67108863;
              }
              r3.words[o2] = a2, n2 = s2, s2 = i2;
            }
            return 0 !== n2 ? r3.words[o2] = n2 : r3.length--, r3._strip();
          }
          function g(e4, t4, r3) {
            return m(e4, t4, r3);
          }
          function v(e4, t4) {
            this.x = e4, this.y = t4;
          }
          Math.imul || (y = b), o.prototype.mulTo = function(e4, t4) {
            var r3 = this.length + e4.length;
            return 10 === this.length && 10 === e4.length ? y(this, e4, t4) : r3 < 63 ? b(this, e4, t4) : r3 < 1024 ? m(this, e4, t4) : g(this, e4, t4);
          }, v.prototype.makeRBT = function(e4) {
            for (var t4 = new Array(e4), r3 = o.prototype._countBits(e4) - 1, n2 = 0; n2 < e4; n2++) t4[n2] = this.revBin(n2, r3, e4);
            return t4;
          }, v.prototype.revBin = function(e4, t4, r3) {
            if (0 === e4 || e4 === r3 - 1) return e4;
            for (var n2 = 0, i2 = 0; i2 < t4; i2++) n2 |= (1 & e4) << t4 - i2 - 1, e4 >>= 1;
            return n2;
          }, v.prototype.permute = function(e4, t4, r3, n2, i2, o2) {
            for (var s2 = 0; s2 < o2; s2++) n2[s2] = t4[e4[s2]], i2[s2] = r3[e4[s2]];
          }, v.prototype.transform = function(e4, t4, r3, n2, i2, o2) {
            this.permute(o2, e4, t4, r3, n2, i2);
            for (var s2 = 1; s2 < i2; s2 <<= 1) for (var a2 = s2 << 1, c2 = Math.cos(2 * Math.PI / a2), u2 = Math.sin(2 * Math.PI / a2), d2 = 0; d2 < i2; d2 += a2) for (var f2 = c2, h2 = u2, l2 = 0; l2 < s2; l2++) {
              var p2 = r3[d2 + l2], b2 = n2[d2 + l2], y2 = r3[d2 + l2 + s2], m2 = n2[d2 + l2 + s2], g2 = f2 * y2 - h2 * m2;
              m2 = f2 * m2 + h2 * y2, y2 = g2, r3[d2 + l2] = p2 + y2, n2[d2 + l2] = b2 + m2, r3[d2 + l2 + s2] = p2 - y2, n2[d2 + l2 + s2] = b2 - m2, l2 !== a2 && (g2 = c2 * f2 - u2 * h2, h2 = c2 * h2 + u2 * f2, f2 = g2);
            }
          }, v.prototype.guessLen13b = function(e4, t4) {
            var r3 = 1 | Math.max(t4, e4), n2 = 1 & r3, i2 = 0;
            for (r3 = r3 / 2 | 0; r3; r3 >>>= 1) i2++;
            return 1 << i2 + 1 + n2;
          }, v.prototype.conjugate = function(e4, t4, r3) {
            if (!(r3 <= 1)) for (var n2 = 0; n2 < r3 / 2; n2++) {
              var i2 = e4[n2];
              e4[n2] = e4[r3 - n2 - 1], e4[r3 - n2 - 1] = i2, i2 = t4[n2], t4[n2] = -t4[r3 - n2 - 1], t4[r3 - n2 - 1] = -i2;
            }
          }, v.prototype.normalize13b = function(e4, t4) {
            for (var r3 = 0, n2 = 0; n2 < t4 / 2; n2++) {
              var i2 = 8192 * Math.round(e4[2 * n2 + 1] / t4) + Math.round(e4[2 * n2] / t4) + r3;
              e4[n2] = 67108863 & i2, r3 = i2 < 67108864 ? 0 : i2 / 67108864 | 0;
            }
            return e4;
          }, v.prototype.convert13b = function(e4, t4, r3, i2) {
            for (var o2 = 0, s2 = 0; s2 < t4; s2++) o2 += 0 | e4[s2], r3[2 * s2] = 8191 & o2, o2 >>>= 13, r3[2 * s2 + 1] = 8191 & o2, o2 >>>= 13;
            for (s2 = 2 * t4; s2 < i2; ++s2) r3[s2] = 0;
            n(0 === o2), n(!(-8192 & o2));
          }, v.prototype.stub = function(e4) {
            for (var t4 = new Array(e4), r3 = 0; r3 < e4; r3++) t4[r3] = 0;
            return t4;
          }, v.prototype.mulp = function(e4, t4, r3) {
            var n2 = 2 * this.guessLen13b(e4.length, t4.length), i2 = this.makeRBT(n2), o2 = this.stub(n2), s2 = new Array(n2), a2 = new Array(n2), c2 = new Array(n2), u2 = new Array(n2), d2 = new Array(n2), f2 = new Array(n2), h2 = r3.words;
            h2.length = n2, this.convert13b(e4.words, e4.length, s2, n2), this.convert13b(t4.words, t4.length, u2, n2), this.transform(s2, o2, a2, c2, n2, i2), this.transform(u2, o2, d2, f2, n2, i2);
            for (var l2 = 0; l2 < n2; l2++) {
              var p2 = a2[l2] * d2[l2] - c2[l2] * f2[l2];
              c2[l2] = a2[l2] * f2[l2] + c2[l2] * d2[l2], a2[l2] = p2;
            }
            return this.conjugate(a2, c2, n2), this.transform(a2, c2, h2, o2, n2, i2), this.conjugate(h2, o2, n2), this.normalize13b(h2, n2), r3.negative = e4.negative ^ t4.negative, r3.length = e4.length + t4.length, r3._strip();
          }, o.prototype.mul = function(e4) {
            var t4 = new o(null);
            return t4.words = new Array(this.length + e4.length), this.mulTo(e4, t4);
          }, o.prototype.mulf = function(e4) {
            var t4 = new o(null);
            return t4.words = new Array(this.length + e4.length), g(this, e4, t4);
          }, o.prototype.imul = function(e4) {
            return this.clone().mulTo(e4, this);
          }, o.prototype.imuln = function(e4) {
            var t4 = e4 < 0;
            t4 && (e4 = -e4), n("number" == typeof e4), n(e4 < 67108864);
            for (var r3 = 0, i2 = 0; i2 < this.length; i2++) {
              var o2 = (0 | this.words[i2]) * e4, s2 = (67108863 & o2) + (67108863 & r3);
              r3 >>= 26, r3 += o2 / 67108864 | 0, r3 += s2 >>> 26, this.words[i2] = 67108863 & s2;
            }
            return 0 !== r3 && (this.words[i2] = r3, this.length++), t4 ? this.ineg() : this;
          }, o.prototype.muln = function(e4) {
            return this.clone().imuln(e4);
          }, o.prototype.sqr = function() {
            return this.mul(this);
          }, o.prototype.isqr = function() {
            return this.imul(this.clone());
          }, o.prototype.pow = function(e4) {
            var t4 = (function(e5) {
              for (var t5 = new Array(e5.bitLength()), r4 = 0; r4 < t5.length; r4++) {
                var n3 = r4 / 26 | 0, i3 = r4 % 26;
                t5[r4] = e5.words[n3] >>> i3 & 1;
              }
              return t5;
            })(e4);
            if (0 === t4.length) return new o(1);
            for (var r3 = this, n2 = 0; n2 < t4.length && 0 === t4[n2]; n2++, r3 = r3.sqr()) ;
            if (++n2 < t4.length) for (var i2 = r3.sqr(); n2 < t4.length; n2++, i2 = i2.sqr()) 0 !== t4[n2] && (r3 = r3.mul(i2));
            return r3;
          }, o.prototype.iushln = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4, r3 = e4 % 26, i2 = (e4 - r3) / 26, o2 = 67108863 >>> 26 - r3 << 26 - r3;
            if (0 !== r3) {
              var s2 = 0;
              for (t4 = 0; t4 < this.length; t4++) {
                var a2 = this.words[t4] & o2, c2 = (0 | this.words[t4]) - a2 << r3;
                this.words[t4] = c2 | s2, s2 = a2 >>> 26 - r3;
              }
              s2 && (this.words[t4] = s2, this.length++);
            }
            if (0 !== i2) {
              for (t4 = this.length - 1; t4 >= 0; t4--) this.words[t4 + i2] = this.words[t4];
              for (t4 = 0; t4 < i2; t4++) this.words[t4] = 0;
              this.length += i2;
            }
            return this._strip();
          }, o.prototype.ishln = function(e4) {
            return n(0 === this.negative), this.iushln(e4);
          }, o.prototype.iushrn = function(e4, t4, r3) {
            var i2;
            n("number" == typeof e4 && e4 >= 0), i2 = t4 ? (t4 - t4 % 26) / 26 : 0;
            var o2 = e4 % 26, s2 = Math.min((e4 - o2) / 26, this.length), a2 = 67108863 ^ 67108863 >>> o2 << o2, c2 = r3;
            if (i2 -= s2, i2 = Math.max(0, i2), c2) {
              for (var u2 = 0; u2 < s2; u2++) c2.words[u2] = this.words[u2];
              c2.length = s2;
            }
            if (0 === s2) ;
            else if (this.length > s2) for (this.length -= s2, u2 = 0; u2 < this.length; u2++) this.words[u2] = this.words[u2 + s2];
            else this.words[0] = 0, this.length = 1;
            var d2 = 0;
            for (u2 = this.length - 1; u2 >= 0 && (0 !== d2 || u2 >= i2); u2--) {
              var f2 = 0 | this.words[u2];
              this.words[u2] = d2 << 26 - o2 | f2 >>> o2, d2 = f2 & a2;
            }
            return c2 && 0 !== d2 && (c2.words[c2.length++] = d2), 0 === this.length && (this.words[0] = 0, this.length = 1), this._strip();
          }, o.prototype.ishrn = function(e4, t4, r3) {
            return n(0 === this.negative), this.iushrn(e4, t4, r3);
          }, o.prototype.shln = function(e4) {
            return this.clone().ishln(e4);
          }, o.prototype.ushln = function(e4) {
            return this.clone().iushln(e4);
          }, o.prototype.shrn = function(e4) {
            return this.clone().ishrn(e4);
          }, o.prototype.ushrn = function(e4) {
            return this.clone().iushrn(e4);
          }, o.prototype.testn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26, i2 = 1 << t4;
            return !(this.length <= r3 || !(this.words[r3] & i2));
          }, o.prototype.imaskn = function(e4) {
            n("number" == typeof e4 && e4 >= 0);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26;
            if (n(0 === this.negative, "imaskn works only with positive numbers"), this.length <= r3) return this;
            if (0 !== t4 && r3++, this.length = Math.min(r3, this.length), 0 !== t4) {
              var i2 = 67108863 ^ 67108863 >>> t4 << t4;
              this.words[this.length - 1] &= i2;
            }
            return this._strip();
          }, o.prototype.maskn = function(e4) {
            return this.clone().imaskn(e4);
          }, o.prototype.iaddn = function(e4) {
            return n("number" == typeof e4), n(e4 < 67108864), e4 < 0 ? this.isubn(-e4) : 0 !== this.negative ? 1 === this.length && (0 | this.words[0]) <= e4 ? (this.words[0] = e4 - (0 | this.words[0]), this.negative = 0, this) : (this.negative = 0, this.isubn(e4), this.negative = 1, this) : this._iaddn(e4);
          }, o.prototype._iaddn = function(e4) {
            this.words[0] += e4;
            for (var t4 = 0; t4 < this.length && this.words[t4] >= 67108864; t4++) this.words[t4] -= 67108864, t4 === this.length - 1 ? this.words[t4 + 1] = 1 : this.words[t4 + 1]++;
            return this.length = Math.max(this.length, t4 + 1), this;
          }, o.prototype.isubn = function(e4) {
            if (n("number" == typeof e4), n(e4 < 67108864), e4 < 0) return this.iaddn(-e4);
            if (0 !== this.negative) return this.negative = 0, this.iaddn(e4), this.negative = 1, this;
            if (this.words[0] -= e4, 1 === this.length && this.words[0] < 0) this.words[0] = -this.words[0], this.negative = 1;
            else for (var t4 = 0; t4 < this.length && this.words[t4] < 0; t4++) this.words[t4] += 67108864, this.words[t4 + 1] -= 1;
            return this._strip();
          }, o.prototype.addn = function(e4) {
            return this.clone().iaddn(e4);
          }, o.prototype.subn = function(e4) {
            return this.clone().isubn(e4);
          }, o.prototype.iabs = function() {
            return this.negative = 0, this;
          }, o.prototype.abs = function() {
            return this.clone().iabs();
          }, o.prototype._ishlnsubmul = function(e4, t4, r3) {
            var i2, o2, s2 = e4.length + r3;
            this._expand(s2);
            var a2 = 0;
            for (i2 = 0; i2 < e4.length; i2++) {
              o2 = (0 | this.words[i2 + r3]) + a2;
              var c2 = (0 | e4.words[i2]) * t4;
              a2 = ((o2 -= 67108863 & c2) >> 26) - (c2 / 67108864 | 0), this.words[i2 + r3] = 67108863 & o2;
            }
            for (; i2 < this.length - r3; i2++) a2 = (o2 = (0 | this.words[i2 + r3]) + a2) >> 26, this.words[i2 + r3] = 67108863 & o2;
            if (0 === a2) return this._strip();
            for (n(-1 === a2), a2 = 0, i2 = 0; i2 < this.length; i2++) a2 = (o2 = -(0 | this.words[i2]) + a2) >> 26, this.words[i2] = 67108863 & o2;
            return this.negative = 1, this._strip();
          }, o.prototype._wordDiv = function(e4, t4) {
            var r3 = (this.length, e4.length), n2 = this.clone(), i2 = e4, s2 = 0 | i2.words[i2.length - 1];
            0 != (r3 = 26 - this._countBits(s2)) && (i2 = i2.ushln(r3), n2.iushln(r3), s2 = 0 | i2.words[i2.length - 1]);
            var a2, c2 = n2.length - i2.length;
            if ("mod" !== t4) {
              (a2 = new o(null)).length = c2 + 1, a2.words = new Array(a2.length);
              for (var u2 = 0; u2 < a2.length; u2++) a2.words[u2] = 0;
            }
            var d2 = n2.clone()._ishlnsubmul(i2, 1, c2);
            0 === d2.negative && (n2 = d2, a2 && (a2.words[c2] = 1));
            for (var f2 = c2 - 1; f2 >= 0; f2--) {
              var h2 = 67108864 * (0 | n2.words[i2.length + f2]) + (0 | n2.words[i2.length + f2 - 1]);
              for (h2 = Math.min(h2 / s2 | 0, 67108863), n2._ishlnsubmul(i2, h2, f2); 0 !== n2.negative; ) h2--, n2.negative = 0, n2._ishlnsubmul(i2, 1, f2), n2.isZero() || (n2.negative ^= 1);
              a2 && (a2.words[f2] = h2);
            }
            return a2 && a2._strip(), n2._strip(), "div" !== t4 && 0 !== r3 && n2.iushrn(r3), { div: a2 || null, mod: n2 };
          }, o.prototype.divmod = function(e4, t4, r3) {
            return n(!e4.isZero()), this.isZero() ? { div: new o(0), mod: new o(0) } : 0 !== this.negative && 0 === e4.negative ? (a2 = this.neg().divmod(e4, t4), "mod" !== t4 && (i2 = a2.div.neg()), "div" !== t4 && (s2 = a2.mod.neg(), r3 && 0 !== s2.negative && s2.iadd(e4)), { div: i2, mod: s2 }) : 0 === this.negative && 0 !== e4.negative ? (a2 = this.divmod(e4.neg(), t4), "mod" !== t4 && (i2 = a2.div.neg()), { div: i2, mod: a2.mod }) : this.negative & e4.negative ? (a2 = this.neg().divmod(e4.neg(), t4), "div" !== t4 && (s2 = a2.mod.neg(), r3 && 0 !== s2.negative && s2.isub(e4)), { div: a2.div, mod: s2 }) : e4.length > this.length || this.cmp(e4) < 0 ? { div: new o(0), mod: this } : 1 === e4.length ? "div" === t4 ? { div: this.divn(e4.words[0]), mod: null } : "mod" === t4 ? { div: null, mod: new o(this.modrn(e4.words[0])) } : { div: this.divn(e4.words[0]), mod: new o(this.modrn(e4.words[0])) } : this._wordDiv(e4, t4);
            var i2, s2, a2;
          }, o.prototype.div = function(e4) {
            return this.divmod(e4, "div", false).div;
          }, o.prototype.mod = function(e4) {
            return this.divmod(e4, "mod", false).mod;
          }, o.prototype.umod = function(e4) {
            return this.divmod(e4, "mod", true).mod;
          }, o.prototype.divRound = function(e4) {
            var t4 = this.divmod(e4);
            if (t4.mod.isZero()) return t4.div;
            var r3 = 0 !== t4.div.negative ? t4.mod.isub(e4) : t4.mod, n2 = e4.ushrn(1), i2 = e4.andln(1), o2 = r3.cmp(n2);
            return o2 < 0 || 1 === i2 && 0 === o2 ? t4.div : 0 !== t4.div.negative ? t4.div.isubn(1) : t4.div.iaddn(1);
          }, o.prototype.modrn = function(e4) {
            var t4 = e4 < 0;
            t4 && (e4 = -e4), n(e4 <= 67108863);
            for (var r3 = (1 << 26) % e4, i2 = 0, o2 = this.length - 1; o2 >= 0; o2--) i2 = (r3 * i2 + (0 | this.words[o2])) % e4;
            return t4 ? -i2 : i2;
          }, o.prototype.modn = function(e4) {
            return this.modrn(e4);
          }, o.prototype.idivn = function(e4) {
            var t4 = e4 < 0;
            t4 && (e4 = -e4), n(e4 <= 67108863);
            for (var r3 = 0, i2 = this.length - 1; i2 >= 0; i2--) {
              var o2 = (0 | this.words[i2]) + 67108864 * r3;
              this.words[i2] = o2 / e4 | 0, r3 = o2 % e4;
            }
            return this._strip(), t4 ? this.ineg() : this;
          }, o.prototype.divn = function(e4) {
            return this.clone().idivn(e4);
          }, o.prototype.egcd = function(e4) {
            n(0 === e4.negative), n(!e4.isZero());
            var t4 = this, r3 = e4.clone();
            t4 = 0 !== t4.negative ? t4.umod(e4) : t4.clone();
            for (var i2 = new o(1), s2 = new o(0), a2 = new o(0), c2 = new o(1), u2 = 0; t4.isEven() && r3.isEven(); ) t4.iushrn(1), r3.iushrn(1), ++u2;
            for (var d2 = r3.clone(), f2 = t4.clone(); !t4.isZero(); ) {
              for (var h2 = 0, l2 = 1; !(t4.words[0] & l2) && h2 < 26; ++h2, l2 <<= 1) ;
              if (h2 > 0) for (t4.iushrn(h2); h2-- > 0; ) (i2.isOdd() || s2.isOdd()) && (i2.iadd(d2), s2.isub(f2)), i2.iushrn(1), s2.iushrn(1);
              for (var p2 = 0, b2 = 1; !(r3.words[0] & b2) && p2 < 26; ++p2, b2 <<= 1) ;
              if (p2 > 0) for (r3.iushrn(p2); p2-- > 0; ) (a2.isOdd() || c2.isOdd()) && (a2.iadd(d2), c2.isub(f2)), a2.iushrn(1), c2.iushrn(1);
              t4.cmp(r3) >= 0 ? (t4.isub(r3), i2.isub(a2), s2.isub(c2)) : (r3.isub(t4), a2.isub(i2), c2.isub(s2));
            }
            return { a: a2, b: c2, gcd: r3.iushln(u2) };
          }, o.prototype._invmp = function(e4) {
            n(0 === e4.negative), n(!e4.isZero());
            var t4 = this, r3 = e4.clone();
            t4 = 0 !== t4.negative ? t4.umod(e4) : t4.clone();
            for (var i2, s2 = new o(1), a2 = new o(0), c2 = r3.clone(); t4.cmpn(1) > 0 && r3.cmpn(1) > 0; ) {
              for (var u2 = 0, d2 = 1; !(t4.words[0] & d2) && u2 < 26; ++u2, d2 <<= 1) ;
              if (u2 > 0) for (t4.iushrn(u2); u2-- > 0; ) s2.isOdd() && s2.iadd(c2), s2.iushrn(1);
              for (var f2 = 0, h2 = 1; !(r3.words[0] & h2) && f2 < 26; ++f2, h2 <<= 1) ;
              if (f2 > 0) for (r3.iushrn(f2); f2-- > 0; ) a2.isOdd() && a2.iadd(c2), a2.iushrn(1);
              t4.cmp(r3) >= 0 ? (t4.isub(r3), s2.isub(a2)) : (r3.isub(t4), a2.isub(s2));
            }
            return (i2 = 0 === t4.cmpn(1) ? s2 : a2).cmpn(0) < 0 && i2.iadd(e4), i2;
          }, o.prototype.gcd = function(e4) {
            if (this.isZero()) return e4.abs();
            if (e4.isZero()) return this.abs();
            var t4 = this.clone(), r3 = e4.clone();
            t4.negative = 0, r3.negative = 0;
            for (var n2 = 0; t4.isEven() && r3.isEven(); n2++) t4.iushrn(1), r3.iushrn(1);
            for (; ; ) {
              for (; t4.isEven(); ) t4.iushrn(1);
              for (; r3.isEven(); ) r3.iushrn(1);
              var i2 = t4.cmp(r3);
              if (i2 < 0) {
                var o2 = t4;
                t4 = r3, r3 = o2;
              } else if (0 === i2 || 0 === r3.cmpn(1)) break;
              t4.isub(r3);
            }
            return r3.iushln(n2);
          }, o.prototype.invm = function(e4) {
            return this.egcd(e4).a.umod(e4);
          }, o.prototype.isEven = function() {
            return !(1 & this.words[0]);
          }, o.prototype.isOdd = function() {
            return !(1 & ~this.words[0]);
          }, o.prototype.andln = function(e4) {
            return this.words[0] & e4;
          }, o.prototype.bincn = function(e4) {
            n("number" == typeof e4);
            var t4 = e4 % 26, r3 = (e4 - t4) / 26, i2 = 1 << t4;
            if (this.length <= r3) return this._expand(r3 + 1), this.words[r3] |= i2, this;
            for (var o2 = i2, s2 = r3; 0 !== o2 && s2 < this.length; s2++) {
              var a2 = 0 | this.words[s2];
              o2 = (a2 += o2) >>> 26, a2 &= 67108863, this.words[s2] = a2;
            }
            return 0 !== o2 && (this.words[s2] = o2, this.length++), this;
          }, o.prototype.isZero = function() {
            return 1 === this.length && 0 === this.words[0];
          }, o.prototype.cmpn = function(e4) {
            var t4, r3 = e4 < 0;
            if (0 !== this.negative && !r3) return -1;
            if (0 === this.negative && r3) return 1;
            if (this._strip(), this.length > 1) t4 = 1;
            else {
              r3 && (e4 = -e4), n(e4 <= 67108863, "Number is too big");
              var i2 = 0 | this.words[0];
              t4 = i2 === e4 ? 0 : i2 < e4 ? -1 : 1;
            }
            return 0 !== this.negative ? 0 | -t4 : t4;
          }, o.prototype.cmp = function(e4) {
            if (0 !== this.negative && 0 === e4.negative) return -1;
            if (0 === this.negative && 0 !== e4.negative) return 1;
            var t4 = this.ucmp(e4);
            return 0 !== this.negative ? 0 | -t4 : t4;
          }, o.prototype.ucmp = function(e4) {
            if (this.length > e4.length) return 1;
            if (this.length < e4.length) return -1;
            for (var t4 = 0, r3 = this.length - 1; r3 >= 0; r3--) {
              var n2 = 0 | this.words[r3], i2 = 0 | e4.words[r3];
              if (n2 !== i2) {
                n2 < i2 ? t4 = -1 : n2 > i2 && (t4 = 1);
                break;
              }
            }
            return t4;
          }, o.prototype.gtn = function(e4) {
            return 1 === this.cmpn(e4);
          }, o.prototype.gt = function(e4) {
            return 1 === this.cmp(e4);
          }, o.prototype.gten = function(e4) {
            return this.cmpn(e4) >= 0;
          }, o.prototype.gte = function(e4) {
            return this.cmp(e4) >= 0;
          }, o.prototype.ltn = function(e4) {
            return -1 === this.cmpn(e4);
          }, o.prototype.lt = function(e4) {
            return -1 === this.cmp(e4);
          }, o.prototype.lten = function(e4) {
            return this.cmpn(e4) <= 0;
          }, o.prototype.lte = function(e4) {
            return this.cmp(e4) <= 0;
          }, o.prototype.eqn = function(e4) {
            return 0 === this.cmpn(e4);
          }, o.prototype.eq = function(e4) {
            return 0 === this.cmp(e4);
          }, o.red = function(e4) {
            return new M(e4);
          }, o.prototype.toRed = function(e4) {
            return n(!this.red, "Already a number in reduction context"), n(0 === this.negative, "red works only with positives"), e4.convertTo(this)._forceRed(e4);
          }, o.prototype.fromRed = function() {
            return n(this.red, "fromRed works only with numbers in reduction context"), this.red.convertFrom(this);
          }, o.prototype._forceRed = function(e4) {
            return this.red = e4, this;
          }, o.prototype.forceRed = function(e4) {
            return n(!this.red, "Already a number in reduction context"), this._forceRed(e4);
          }, o.prototype.redAdd = function(e4) {
            return n(this.red, "redAdd works only with red numbers"), this.red.add(this, e4);
          }, o.prototype.redIAdd = function(e4) {
            return n(this.red, "redIAdd works only with red numbers"), this.red.iadd(this, e4);
          }, o.prototype.redSub = function(e4) {
            return n(this.red, "redSub works only with red numbers"), this.red.sub(this, e4);
          }, o.prototype.redISub = function(e4) {
            return n(this.red, "redISub works only with red numbers"), this.red.isub(this, e4);
          }, o.prototype.redShl = function(e4) {
            return n(this.red, "redShl works only with red numbers"), this.red.shl(this, e4);
          }, o.prototype.redMul = function(e4) {
            return n(this.red, "redMul works only with red numbers"), this.red._verify2(this, e4), this.red.mul(this, e4);
          }, o.prototype.redIMul = function(e4) {
            return n(this.red, "redMul works only with red numbers"), this.red._verify2(this, e4), this.red.imul(this, e4);
          }, o.prototype.redSqr = function() {
            return n(this.red, "redSqr works only with red numbers"), this.red._verify1(this), this.red.sqr(this);
          }, o.prototype.redISqr = function() {
            return n(this.red, "redISqr works only with red numbers"), this.red._verify1(this), this.red.isqr(this);
          }, o.prototype.redSqrt = function() {
            return n(this.red, "redSqrt works only with red numbers"), this.red._verify1(this), this.red.sqrt(this);
          }, o.prototype.redInvm = function() {
            return n(this.red, "redInvm works only with red numbers"), this.red._verify1(this), this.red.invm(this);
          }, o.prototype.redNeg = function() {
            return n(this.red, "redNeg works only with red numbers"), this.red._verify1(this), this.red.neg(this);
          }, o.prototype.redPow = function(e4) {
            return n(this.red && !e4.red, "redPow(normalNum)"), this.red._verify1(this), this.red.pow(this, e4);
          };
          var w = { k256: null, p224: null, p192: null, p25519: null };
          function _(e4, t4) {
            this.name = e4, this.p = new o(t4, 16), this.n = this.p.bitLength(), this.k = new o(1).iushln(this.n).isub(this.p), this.tmp = this._tmp();
          }
          function A() {
            _.call(this, "k256", "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f");
          }
          function S() {
            _.call(this, "p224", "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001");
          }
          function C() {
            _.call(this, "p192", "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff");
          }
          function T() {
            _.call(this, "25519", "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed");
          }
          function M(e4) {
            if ("string" == typeof e4) {
              var t4 = o._prime(e4);
              this.m = t4.p, this.prime = t4;
            } else n(e4.gtn(1), "modulus must be greater than 1"), this.m = e4, this.prime = null;
          }
          function E(e4) {
            M.call(this, e4), this.shift = this.m.bitLength(), this.shift % 26 != 0 && (this.shift += 26 - this.shift % 26), this.r = new o(1).iushln(this.shift), this.r2 = this.imod(this.r.sqr()), this.rinv = this.r._invmp(this.m), this.minv = this.rinv.mul(this.r).isubn(1).div(this.m), this.minv = this.minv.umod(this.r), this.minv = this.r.sub(this.minv);
          }
          _.prototype._tmp = function() {
            var e4 = new o(null);
            return e4.words = new Array(Math.ceil(this.n / 13)), e4;
          }, _.prototype.ireduce = function(e4) {
            var t4, r3 = e4;
            do {
              this.split(r3, this.tmp), t4 = (r3 = (r3 = this.imulK(r3)).iadd(this.tmp)).bitLength();
            } while (t4 > this.n);
            var n2 = t4 < this.n ? -1 : r3.ucmp(this.p);
            return 0 === n2 ? (r3.words[0] = 0, r3.length = 1) : n2 > 0 ? r3.isub(this.p) : void 0 !== r3.strip ? r3.strip() : r3._strip(), r3;
          }, _.prototype.split = function(e4, t4) {
            e4.iushrn(this.n, 0, t4);
          }, _.prototype.imulK = function(e4) {
            return e4.imul(this.k);
          }, i(A, _), A.prototype.split = function(e4, t4) {
            for (var r3 = 4194303, n2 = Math.min(e4.length, 9), i2 = 0; i2 < n2; i2++) t4.words[i2] = e4.words[i2];
            if (t4.length = n2, e4.length <= 9) return e4.words[0] = 0, void (e4.length = 1);
            var o2 = e4.words[9];
            for (t4.words[t4.length++] = o2 & r3, i2 = 10; i2 < e4.length; i2++) {
              var s2 = 0 | e4.words[i2];
              e4.words[i2 - 10] = (s2 & r3) << 4 | o2 >>> 22, o2 = s2;
            }
            o2 >>>= 22, e4.words[i2 - 10] = o2, 0 === o2 && e4.length > 10 ? e4.length -= 10 : e4.length -= 9;
          }, A.prototype.imulK = function(e4) {
            e4.words[e4.length] = 0, e4.words[e4.length + 1] = 0, e4.length += 2;
            for (var t4 = 0, r3 = 0; r3 < e4.length; r3++) {
              var n2 = 0 | e4.words[r3];
              t4 += 977 * n2, e4.words[r3] = 67108863 & t4, t4 = 64 * n2 + (t4 / 67108864 | 0);
            }
            return 0 === e4.words[e4.length - 1] && (e4.length--, 0 === e4.words[e4.length - 1] && e4.length--), e4;
          }, i(S, _), i(C, _), i(T, _), T.prototype.imulK = function(e4) {
            for (var t4 = 0, r3 = 0; r3 < e4.length; r3++) {
              var n2 = 19 * (0 | e4.words[r3]) + t4, i2 = 67108863 & n2;
              n2 >>>= 26, e4.words[r3] = i2, t4 = n2;
            }
            return 0 !== t4 && (e4.words[e4.length++] = t4), e4;
          }, o._prime = function(e4) {
            if (w[e4]) return w[e4];
            var t4;
            if ("k256" === e4) t4 = new A();
            else if ("p224" === e4) t4 = new S();
            else if ("p192" === e4) t4 = new C();
            else {
              if ("p25519" !== e4) throw new Error("Unknown prime " + e4);
              t4 = new T();
            }
            return w[e4] = t4, t4;
          }, M.prototype._verify1 = function(e4) {
            n(0 === e4.negative, "red works only with positives"), n(e4.red, "red works only with red numbers");
          }, M.prototype._verify2 = function(e4, t4) {
            n(!(e4.negative | t4.negative), "red works only with positives"), n(e4.red && e4.red === t4.red, "red works only with red numbers");
          }, M.prototype.imod = function(e4) {
            return this.prime ? this.prime.ireduce(e4)._forceRed(this) : (d(e4, e4.umod(this.m)._forceRed(this)), e4);
          }, M.prototype.neg = function(e4) {
            return e4.isZero() ? e4.clone() : this.m.sub(e4)._forceRed(this);
          }, M.prototype.add = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.add(t4);
            return r3.cmp(this.m) >= 0 && r3.isub(this.m), r3._forceRed(this);
          }, M.prototype.iadd = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.iadd(t4);
            return r3.cmp(this.m) >= 0 && r3.isub(this.m), r3;
          }, M.prototype.sub = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.sub(t4);
            return r3.cmpn(0) < 0 && r3.iadd(this.m), r3._forceRed(this);
          }, M.prototype.isub = function(e4, t4) {
            this._verify2(e4, t4);
            var r3 = e4.isub(t4);
            return r3.cmpn(0) < 0 && r3.iadd(this.m), r3;
          }, M.prototype.shl = function(e4, t4) {
            return this._verify1(e4), this.imod(e4.ushln(t4));
          }, M.prototype.imul = function(e4, t4) {
            return this._verify2(e4, t4), this.imod(e4.imul(t4));
          }, M.prototype.mul = function(e4, t4) {
            return this._verify2(e4, t4), this.imod(e4.mul(t4));
          }, M.prototype.isqr = function(e4) {
            return this.imul(e4, e4.clone());
          }, M.prototype.sqr = function(e4) {
            return this.mul(e4, e4);
          }, M.prototype.sqrt = function(e4) {
            if (e4.isZero()) return e4.clone();
            var t4 = this.m.andln(3);
            if (n(t4 % 2 == 1), 3 === t4) {
              var r3 = this.m.add(new o(1)).iushrn(2);
              return this.pow(e4, r3);
            }
            for (var i2 = this.m.subn(1), s2 = 0; !i2.isZero() && 0 === i2.andln(1); ) s2++, i2.iushrn(1);
            n(!i2.isZero());
            var a2 = new o(1).toRed(this), c2 = a2.redNeg(), u2 = this.m.subn(1).iushrn(1), d2 = this.m.bitLength();
            for (d2 = new o(2 * d2 * d2).toRed(this); 0 !== this.pow(d2, u2).cmp(c2); ) d2.redIAdd(c2);
            for (var f2 = this.pow(d2, i2), h2 = this.pow(e4, i2.addn(1).iushrn(1)), l2 = this.pow(e4, i2), p2 = s2; 0 !== l2.cmp(a2); ) {
              for (var b2 = l2, y2 = 0; 0 !== b2.cmp(a2); y2++) b2 = b2.redSqr();
              n(y2 < p2);
              var m2 = this.pow(f2, new o(1).iushln(p2 - y2 - 1));
              h2 = h2.redMul(m2), f2 = m2.redSqr(), l2 = l2.redMul(f2), p2 = y2;
            }
            return h2;
          }, M.prototype.invm = function(e4) {
            var t4 = e4._invmp(this.m);
            return 0 !== t4.negative ? (t4.negative = 0, this.imod(t4).redNeg()) : this.imod(t4);
          }, M.prototype.pow = function(e4, t4) {
            if (t4.isZero()) return new o(1).toRed(this);
            if (0 === t4.cmpn(1)) return e4.clone();
            var r3 = new Array(16);
            r3[0] = new o(1).toRed(this), r3[1] = e4;
            for (var n2 = 2; n2 < r3.length; n2++) r3[n2] = this.mul(r3[n2 - 1], e4);
            var i2 = r3[0], s2 = 0, a2 = 0, c2 = t4.bitLength() % 26;
            for (0 === c2 && (c2 = 26), n2 = t4.length - 1; n2 >= 0; n2--) {
              for (var u2 = t4.words[n2], d2 = c2 - 1; d2 >= 0; d2--) {
                var f2 = u2 >> d2 & 1;
                i2 !== r3[0] && (i2 = this.sqr(i2)), 0 !== f2 || 0 !== s2 ? (s2 <<= 1, s2 |= f2, (4 == ++a2 || 0 === n2 && 0 === d2) && (i2 = this.mul(i2, r3[s2]), a2 = 0, s2 = 0)) : a2 = 0;
              }
              c2 = 26;
            }
            return i2;
          }, M.prototype.convertTo = function(e4) {
            var t4 = e4.umod(this.m);
            return t4 === e4 ? t4.clone() : t4;
          }, M.prototype.convertFrom = function(e4) {
            var t4 = e4.clone();
            return t4.red = null, t4;
          }, o.mont = function(e4) {
            return new E(e4);
          }, i(E, M), E.prototype.convertTo = function(e4) {
            return this.imod(e4.ushln(this.shift));
          }, E.prototype.convertFrom = function(e4) {
            var t4 = this.imod(e4.mul(this.rinv));
            return t4.red = null, t4;
          }, E.prototype.imul = function(e4, t4) {
            if (e4.isZero() || t4.isZero()) return e4.words[0] = 0, e4.length = 1, e4;
            var r3 = e4.imul(t4), n2 = r3.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), i2 = r3.isub(n2).iushrn(this.shift), o2 = i2;
            return i2.cmp(this.m) >= 0 ? o2 = i2.isub(this.m) : i2.cmpn(0) < 0 && (o2 = i2.iadd(this.m)), o2._forceRed(this);
          }, E.prototype.mul = function(e4, t4) {
            if (e4.isZero() || t4.isZero()) return new o(0)._forceRed(this);
            var r3 = e4.mul(t4), n2 = r3.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), i2 = r3.isub(n2).iushrn(this.shift), s2 = i2;
            return i2.cmp(this.m) >= 0 ? s2 = i2.isub(this.m) : i2.cmpn(0) < 0 && (s2 = i2.iadd(this.m)), s2._forceRed(this);
          }, E.prototype.invm = function(e4) {
            return this.imod(e4._invmp(this.m).mul(this.r2))._forceRed(this);
          };
        })(e2 = r2.nmd(e2), this);
      }, 5442: (e2, t2, r2) => {
        var n;
        function i(e3) {
          this.rand = e3;
        }
        if (e2.exports = function(e3) {
          return n || (n = new i(null)), n.generate(e3);
        }, e2.exports.Rand = i, i.prototype.generate = function(e3) {
          return this._rand(e3);
        }, i.prototype._rand = function(e3) {
          if (this.rand.getBytes) return this.rand.getBytes(e3);
          for (var t3 = new Uint8Array(e3), r3 = 0; r3 < t3.length; r3++) t3[r3] = this.rand.getByte();
          return t3;
        }, "object" == typeof self) self.crypto && self.crypto.getRandomValues ? i.prototype._rand = function(e3) {
          var t3 = new Uint8Array(e3);
          return self.crypto.getRandomValues(t3), t3;
        } : self.msCrypto && self.msCrypto.getRandomValues ? i.prototype._rand = function(e3) {
          var t3 = new Uint8Array(e3);
          return self.msCrypto.getRandomValues(t3), t3;
        } : "object" == typeof window && (i.prototype._rand = function() {
          throw new Error("Not implemented yet");
        });
        else try {
          var o = r2(4507);
          if ("function" != typeof o.randomBytes) throw new Error("Not supported");
          i.prototype._rand = function(e3) {
            return o.randomBytes(e3);
          };
        } catch (e3) {
        }
      }, 7088: (e2, t2, r2) => {
        var n = r2(6608).Buffer;
        function i(e3) {
          n.isBuffer(e3) || (e3 = n.from(e3));
          for (var t3 = e3.length / 4 | 0, r3 = new Array(t3), i2 = 0; i2 < t3; i2++) r3[i2] = e3.readUInt32BE(4 * i2);
          return r3;
        }
        function o(e3) {
          for (; 0 < e3.length; e3++) e3[0] = 0;
        }
        function s(e3, t3, r3, n2, i2) {
          for (var o2, s2, a2, c2, u2 = r3[0], d = r3[1], f = r3[2], h = r3[3], l = e3[0] ^ t3[0], p = e3[1] ^ t3[1], b = e3[2] ^ t3[2], y = e3[3] ^ t3[3], m = 4, g = 1; g < i2; g++) o2 = u2[l >>> 24] ^ d[p >>> 16 & 255] ^ f[b >>> 8 & 255] ^ h[255 & y] ^ t3[m++], s2 = u2[p >>> 24] ^ d[b >>> 16 & 255] ^ f[y >>> 8 & 255] ^ h[255 & l] ^ t3[m++], a2 = u2[b >>> 24] ^ d[y >>> 16 & 255] ^ f[l >>> 8 & 255] ^ h[255 & p] ^ t3[m++], c2 = u2[y >>> 24] ^ d[l >>> 16 & 255] ^ f[p >>> 8 & 255] ^ h[255 & b] ^ t3[m++], l = o2, p = s2, b = a2, y = c2;
          return o2 = (n2[l >>> 24] << 24 | n2[p >>> 16 & 255] << 16 | n2[b >>> 8 & 255] << 8 | n2[255 & y]) ^ t3[m++], s2 = (n2[p >>> 24] << 24 | n2[b >>> 16 & 255] << 16 | n2[y >>> 8 & 255] << 8 | n2[255 & l]) ^ t3[m++], a2 = (n2[b >>> 24] << 24 | n2[y >>> 16 & 255] << 16 | n2[l >>> 8 & 255] << 8 | n2[255 & p]) ^ t3[m++], c2 = (n2[y >>> 24] << 24 | n2[l >>> 16 & 255] << 16 | n2[p >>> 8 & 255] << 8 | n2[255 & b]) ^ t3[m++], [o2 >>>= 0, s2 >>>= 0, a2 >>>= 0, c2 >>>= 0];
        }
        var a = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54], c = (function() {
          for (var e3 = new Array(256), t3 = 0; t3 < 256; t3++) e3[t3] = t3 < 128 ? t3 << 1 : t3 << 1 ^ 283;
          for (var r3 = [], n2 = [], i2 = [[], [], [], []], o2 = [[], [], [], []], s2 = 0, a2 = 0, c2 = 0; c2 < 256; ++c2) {
            var u2 = a2 ^ a2 << 1 ^ a2 << 2 ^ a2 << 3 ^ a2 << 4;
            u2 = u2 >>> 8 ^ 255 & u2 ^ 99, r3[s2] = u2, n2[u2] = s2;
            var d = e3[s2], f = e3[d], h = e3[f], l = 257 * e3[u2] ^ 16843008 * u2;
            i2[0][s2] = l << 24 | l >>> 8, i2[1][s2] = l << 16 | l >>> 16, i2[2][s2] = l << 8 | l >>> 24, i2[3][s2] = l, l = 16843009 * h ^ 65537 * f ^ 257 * d ^ 16843008 * s2, o2[0][u2] = l << 24 | l >>> 8, o2[1][u2] = l << 16 | l >>> 16, o2[2][u2] = l << 8 | l >>> 24, o2[3][u2] = l, 0 === s2 ? s2 = a2 = 1 : (s2 = d ^ e3[e3[e3[h ^ d]]], a2 ^= e3[e3[a2]]);
          }
          return { SBOX: r3, INV_SBOX: n2, SUB_MIX: i2, INV_SUB_MIX: o2 };
        })();
        function u(e3) {
          this._key = i(e3), this._reset();
        }
        u.blockSize = 16, u.keySize = 32, u.prototype.blockSize = u.blockSize, u.prototype.keySize = u.keySize, u.prototype._reset = function() {
          for (var e3 = this._key, t3 = e3.length, r3 = t3 + 6, n2 = 4 * (r3 + 1), i2 = [], o2 = 0; o2 < t3; o2++) i2[o2] = e3[o2];
          for (o2 = t3; o2 < n2; o2++) {
            var s2 = i2[o2 - 1];
            o2 % t3 == 0 ? (s2 = s2 << 8 | s2 >>> 24, s2 = c.SBOX[s2 >>> 24] << 24 | c.SBOX[s2 >>> 16 & 255] << 16 | c.SBOX[s2 >>> 8 & 255] << 8 | c.SBOX[255 & s2], s2 ^= a[o2 / t3 | 0] << 24) : t3 > 6 && o2 % t3 == 4 && (s2 = c.SBOX[s2 >>> 24] << 24 | c.SBOX[s2 >>> 16 & 255] << 16 | c.SBOX[s2 >>> 8 & 255] << 8 | c.SBOX[255 & s2]), i2[o2] = i2[o2 - t3] ^ s2;
          }
          for (var u2 = [], d = 0; d < n2; d++) {
            var f = n2 - d, h = i2[f - (d % 4 ? 0 : 4)];
            u2[d] = d < 4 || f <= 4 ? h : c.INV_SUB_MIX[0][c.SBOX[h >>> 24]] ^ c.INV_SUB_MIX[1][c.SBOX[h >>> 16 & 255]] ^ c.INV_SUB_MIX[2][c.SBOX[h >>> 8 & 255]] ^ c.INV_SUB_MIX[3][c.SBOX[255 & h]];
          }
          this._nRounds = r3, this._keySchedule = i2, this._invKeySchedule = u2;
        }, u.prototype.encryptBlockRaw = function(e3) {
          return s(e3 = i(e3), this._keySchedule, c.SUB_MIX, c.SBOX, this._nRounds);
        }, u.prototype.encryptBlock = function(e3) {
          var t3 = this.encryptBlockRaw(e3), r3 = n.allocUnsafe(16);
          return r3.writeUInt32BE(t3[0], 0), r3.writeUInt32BE(t3[1], 4), r3.writeUInt32BE(t3[2], 8), r3.writeUInt32BE(t3[3], 12), r3;
        }, u.prototype.decryptBlock = function(e3) {
          var t3 = (e3 = i(e3))[1];
          e3[1] = e3[3], e3[3] = t3;
          var r3 = s(e3, this._invKeySchedule, c.INV_SUB_MIX, c.INV_SBOX, this._nRounds), o2 = n.allocUnsafe(16);
          return o2.writeUInt32BE(r3[0], 0), o2.writeUInt32BE(r3[3], 4), o2.writeUInt32BE(r3[2], 8), o2.writeUInt32BE(r3[1], 12), o2;
        }, u.prototype.scrub = function() {
          o(this._keySchedule), o(this._invKeySchedule), o(this._key);
        }, e2.exports.AES = u;
      }, 8182: (e2, t2, r2) => {
        var n = r2(7088), i = r2(6608).Buffer, o = r2(4705), s = r2(1193), a = r2(50), c = r2(460), u = r2(6696);
        function d(e3, t3, r3, s2) {
          o.call(this);
          var c2 = i.alloc(4, 0);
          this._cipher = new n.AES(t3);
          var d2 = this._cipher.encryptBlock(c2);
          this._ghash = new a(d2), r3 = (function(e4, t4, r4) {
            if (12 === t4.length) return e4._finID = i.concat([t4, i.from([0, 0, 0, 1])]), i.concat([t4, i.from([0, 0, 0, 2])]);
            var n2 = new a(r4), o2 = t4.length, s3 = o2 % 16;
            n2.update(t4), s3 && (s3 = 16 - s3, n2.update(i.alloc(s3, 0))), n2.update(i.alloc(8, 0));
            var c3 = 8 * o2, d3 = i.alloc(8);
            d3.writeUIntBE(c3, 0, 8), n2.update(d3), e4._finID = n2.state;
            var f = i.from(e4._finID);
            return u(f), f;
          })(this, r3, d2), this._prev = i.from(r3), this._cache = i.allocUnsafe(0), this._secCache = i.allocUnsafe(0), this._decrypt = s2, this._alen = 0, this._len = 0, this._mode = e3, this._authTag = null, this._called = false;
        }
        s(d, o), d.prototype._update = function(e3) {
          if (!this._called && this._alen) {
            var t3 = 16 - this._alen % 16;
            t3 < 16 && (t3 = i.alloc(t3, 0), this._ghash.update(t3));
          }
          this._called = true;
          var r3 = this._mode.encrypt(this, e3);
          return this._decrypt ? this._ghash.update(e3) : this._ghash.update(r3), this._len += e3.length, r3;
        }, d.prototype._final = function() {
          if (this._decrypt && !this._authTag) throw new Error("Unsupported state or unable to authenticate data");
          var e3 = c(this._ghash.final(8 * this._alen, 8 * this._len), this._cipher.encryptBlock(this._finID));
          if (this._decrypt && (function(e4, t3) {
            var r3 = 0;
            e4.length !== t3.length && r3++;
            for (var n2 = Math.min(e4.length, t3.length), i2 = 0; i2 < n2; ++i2) r3 += e4[i2] ^ t3[i2];
            return r3;
          })(e3, this._authTag)) throw new Error("Unsupported state or unable to authenticate data");
          this._authTag = e3, this._cipher.scrub();
        }, d.prototype.getAuthTag = function() {
          if (this._decrypt || !i.isBuffer(this._authTag)) throw new Error("Attempting to get auth tag in unsupported state");
          return this._authTag;
        }, d.prototype.setAuthTag = function(e3) {
          if (!this._decrypt) throw new Error("Attempting to set auth tag in unsupported state");
          this._authTag = e3;
        }, d.prototype.setAAD = function(e3) {
          if (this._called) throw new Error("Attempting to set AAD in unsupported state");
          this._ghash.update(e3), this._alen += e3.length;
        }, e2.exports = d;
      }, 5007: (e2, t2, r2) => {
        var n = r2(5173), i = r2(8733), o = r2(3349);
        t2.createCipher = t2.Cipher = n.createCipher, t2.createCipheriv = t2.Cipheriv = n.createCipheriv, t2.createDecipher = t2.Decipher = i.createDecipher, t2.createDecipheriv = t2.Decipheriv = i.createDecipheriv, t2.listCiphers = t2.getCiphers = function() {
          return Object.keys(o);
        };
      }, 8733: (e2, t2, r2) => {
        var n = r2(8182), i = r2(6608).Buffer, o = r2(6200), s = r2(8116), a = r2(4705), c = r2(7088), u = r2(1804);
        function d(e3, t3, r3) {
          a.call(this), this._cache = new f(), this._last = void 0, this._cipher = new c.AES(t3), this._prev = i.from(r3), this._mode = e3, this._autopadding = true;
        }
        function f() {
          this.cache = i.allocUnsafe(0);
        }
        function h(e3, t3, r3) {
          var a2 = o[e3.toLowerCase()];
          if (!a2) throw new TypeError("invalid suite type");
          if ("string" == typeof r3 && (r3 = i.from(r3)), "GCM" !== a2.mode && r3.length !== a2.iv) throw new TypeError("invalid iv length " + r3.length);
          if ("string" == typeof t3 && (t3 = i.from(t3)), t3.length !== a2.key / 8) throw new TypeError("invalid key length " + t3.length);
          return "stream" === a2.type ? new s(a2.module, t3, r3, true) : "auth" === a2.type ? new n(a2.module, t3, r3, true) : new d(a2.module, t3, r3);
        }
        r2(1193)(d, a), d.prototype._update = function(e3) {
          var t3, r3;
          this._cache.add(e3);
          for (var n2 = []; t3 = this._cache.get(this._autopadding); ) r3 = this._mode.decrypt(this, t3), n2.push(r3);
          return i.concat(n2);
        }, d.prototype._final = function() {
          var e3 = this._cache.flush();
          if (this._autopadding) return (function(e4) {
            var t3 = e4[15];
            if (t3 < 1 || t3 > 16) throw new Error("unable to decrypt data");
            for (var r3 = -1; ++r3 < t3; ) if (e4[r3 + (16 - t3)] !== t3) throw new Error("unable to decrypt data");
            if (16 !== t3) return e4.slice(0, 16 - t3);
          })(this._mode.decrypt(this, e3));
          if (e3) throw new Error("data not multiple of block length");
        }, d.prototype.setAutoPadding = function(e3) {
          return this._autopadding = !!e3, this;
        }, f.prototype.add = function(e3) {
          this.cache = i.concat([this.cache, e3]);
        }, f.prototype.get = function(e3) {
          var t3;
          if (e3) {
            if (this.cache.length > 16) return t3 = this.cache.slice(0, 16), this.cache = this.cache.slice(16), t3;
          } else if (this.cache.length >= 16) return t3 = this.cache.slice(0, 16), this.cache = this.cache.slice(16), t3;
          return null;
        }, f.prototype.flush = function() {
          if (this.cache.length) return this.cache;
        }, t2.createDecipher = function(e3, t3) {
          var r3 = o[e3.toLowerCase()];
          if (!r3) throw new TypeError("invalid suite type");
          var n2 = u(t3, false, r3.key, r3.iv);
          return h(e3, n2.key, n2.iv);
        }, t2.createDecipheriv = h;
      }, 5173: (e2, t2, r2) => {
        var n = r2(6200), i = r2(8182), o = r2(6608).Buffer, s = r2(8116), a = r2(4705), c = r2(7088), u = r2(1804);
        function d(e3, t3, r3) {
          a.call(this), this._cache = new h(), this._cipher = new c.AES(t3), this._prev = o.from(r3), this._mode = e3, this._autopadding = true;
        }
        r2(1193)(d, a), d.prototype._update = function(e3) {
          var t3, r3;
          this._cache.add(e3);
          for (var n2 = []; t3 = this._cache.get(); ) r3 = this._mode.encrypt(this, t3), n2.push(r3);
          return o.concat(n2);
        };
        var f = o.alloc(16, 16);
        function h() {
          this.cache = o.allocUnsafe(0);
        }
        function l(e3, t3, r3) {
          var a2 = n[e3.toLowerCase()];
          if (!a2) throw new TypeError("invalid suite type");
          if ("string" == typeof t3 && (t3 = o.from(t3)), t3.length !== a2.key / 8) throw new TypeError("invalid key length " + t3.length);
          if ("string" == typeof r3 && (r3 = o.from(r3)), "GCM" !== a2.mode && r3.length !== a2.iv) throw new TypeError("invalid iv length " + r3.length);
          return "stream" === a2.type ? new s(a2.module, t3, r3) : "auth" === a2.type ? new i(a2.module, t3, r3) : new d(a2.module, t3, r3);
        }
        d.prototype._final = function() {
          var e3 = this._cache.flush();
          if (this._autopadding) return e3 = this._mode.encrypt(this, e3), this._cipher.scrub(), e3;
          if (!e3.equals(f)) throw this._cipher.scrub(), new Error("data not multiple of block length");
        }, d.prototype.setAutoPadding = function(e3) {
          return this._autopadding = !!e3, this;
        }, h.prototype.add = function(e3) {
          this.cache = o.concat([this.cache, e3]);
        }, h.prototype.get = function() {
          if (this.cache.length > 15) {
            var e3 = this.cache.slice(0, 16);
            return this.cache = this.cache.slice(16), e3;
          }
          return null;
        }, h.prototype.flush = function() {
          for (var e3 = 16 - this.cache.length, t3 = o.allocUnsafe(e3), r3 = -1; ++r3 < e3; ) t3.writeUInt8(e3, r3);
          return o.concat([this.cache, t3]);
        }, t2.createCipheriv = l, t2.createCipher = function(e3, t3) {
          var r3 = n[e3.toLowerCase()];
          if (!r3) throw new TypeError("invalid suite type");
          var i2 = u(t3, false, r3.key, r3.iv);
          return l(e3, i2.key, i2.iv);
        };
      }, 50: (e2, t2, r2) => {
        var n = r2(6608).Buffer, i = n.alloc(16, 0);
        function o(e3) {
          var t3 = n.allocUnsafe(16);
          return t3.writeUInt32BE(e3[0] >>> 0, 0), t3.writeUInt32BE(e3[1] >>> 0, 4), t3.writeUInt32BE(e3[2] >>> 0, 8), t3.writeUInt32BE(e3[3] >>> 0, 12), t3;
        }
        function s(e3) {
          this.h = e3, this.state = n.alloc(16, 0), this.cache = n.allocUnsafe(0);
        }
        s.prototype.ghash = function(e3) {
          for (var t3 = -1; ++t3 < e3.length; ) this.state[t3] ^= e3[t3];
          this._multiply();
        }, s.prototype._multiply = function() {
          for (var e3, t3, r3, n2 = [(e3 = this.h).readUInt32BE(0), e3.readUInt32BE(4), e3.readUInt32BE(8), e3.readUInt32BE(12)], i2 = [0, 0, 0, 0], s2 = -1; ++s2 < 128; ) {
            for (!!(this.state[~~(s2 / 8)] & 1 << 7 - s2 % 8) && (i2[0] ^= n2[0], i2[1] ^= n2[1], i2[2] ^= n2[2], i2[3] ^= n2[3]), r3 = !!(1 & n2[3]), t3 = 3; t3 > 0; t3--) n2[t3] = n2[t3] >>> 1 | (1 & n2[t3 - 1]) << 31;
            n2[0] = n2[0] >>> 1, r3 && (n2[0] = n2[0] ^ 225 << 24);
          }
          this.state = o(i2);
        }, s.prototype.update = function(e3) {
          var t3;
          for (this.cache = n.concat([this.cache, e3]); this.cache.length >= 16; ) t3 = this.cache.slice(0, 16), this.cache = this.cache.slice(16), this.ghash(t3);
        }, s.prototype.final = function(e3, t3) {
          return this.cache.length && this.ghash(n.concat([this.cache, i], 16)), this.ghash(o([0, e3, 0, t3])), this.state;
        }, e2.exports = s;
      }, 6696: (e2) => {
        e2.exports = function(e3) {
          for (var t2, r2 = e3.length; r2--; ) {
            if (255 !== (t2 = e3.readUInt8(r2))) {
              t2++, e3.writeUInt8(t2, r2);
              break;
            }
            e3.writeUInt8(0, r2);
          }
        };
      }, 3506: (e2, t2, r2) => {
        var n = r2(460);
        t2.encrypt = function(e3, t3) {
          var r3 = n(t3, e3._prev);
          return e3._prev = e3._cipher.encryptBlock(r3), e3._prev;
        }, t2.decrypt = function(e3, t3) {
          var r3 = e3._prev;
          e3._prev = t3;
          var i = e3._cipher.decryptBlock(t3);
          return n(i, r3);
        };
      }, 6149: (e2, t2, r2) => {
        var n = r2(6608).Buffer, i = r2(460);
        function o(e3, t3, r3) {
          var o2 = t3.length, s = i(t3, e3._cache);
          return e3._cache = e3._cache.slice(o2), e3._prev = n.concat([e3._prev, r3 ? t3 : s]), s;
        }
        t2.encrypt = function(e3, t3, r3) {
          for (var i2, s = n.allocUnsafe(0); t3.length; ) {
            if (0 === e3._cache.length && (e3._cache = e3._cipher.encryptBlock(e3._prev), e3._prev = n.allocUnsafe(0)), !(e3._cache.length <= t3.length)) {
              s = n.concat([s, o(e3, t3, r3)]);
              break;
            }
            i2 = e3._cache.length, s = n.concat([s, o(e3, t3.slice(0, i2), r3)]), t3 = t3.slice(i2);
          }
          return s;
        };
      }, 8394: (e2, t2, r2) => {
        var n = r2(6608).Buffer;
        function i(e3, t3, r3) {
          for (var n2, i2, s = -1, a = 0; ++s < 8; ) n2 = t3 & 1 << 7 - s ? 128 : 0, a += (128 & (i2 = e3._cipher.encryptBlock(e3._prev)[0] ^ n2)) >> s % 8, e3._prev = o(e3._prev, r3 ? n2 : i2);
          return a;
        }
        function o(e3, t3) {
          var r3 = e3.length, i2 = -1, o2 = n.allocUnsafe(e3.length);
          for (e3 = n.concat([e3, n.from([t3])]); ++i2 < r3; ) o2[i2] = e3[i2] << 1 | e3[i2 + 1] >> 7;
          return o2;
        }
        t2.encrypt = function(e3, t3, r3) {
          for (var o2 = t3.length, s = n.allocUnsafe(o2), a = -1; ++a < o2; ) s[a] = i(e3, t3[a], r3);
          return s;
        };
      }, 193: (e2, t2, r2) => {
        var n = r2(6608).Buffer;
        function i(e3, t3, r3) {
          var i2 = e3._cipher.encryptBlock(e3._prev)[0] ^ t3;
          return e3._prev = n.concat([e3._prev.slice(1), n.from([r3 ? t3 : i2])]), i2;
        }
        t2.encrypt = function(e3, t3, r3) {
          for (var o = t3.length, s = n.allocUnsafe(o), a = -1; ++a < o; ) s[a] = i(e3, t3[a], r3);
          return s;
        };
      }, 5527: (e2, t2, r2) => {
        var n = r2(460), i = r2(6608).Buffer, o = r2(6696);
        function s(e3) {
          var t3 = e3._cipher.encryptBlockRaw(e3._prev);
          return o(e3._prev), t3;
        }
        t2.encrypt = function(e3, t3) {
          var r3 = Math.ceil(t3.length / 16), o2 = e3._cache.length;
          e3._cache = i.concat([e3._cache, i.allocUnsafe(16 * r3)]);
          for (var a = 0; a < r3; a++) {
            var c = s(e3), u = o2 + 16 * a;
            e3._cache.writeUInt32BE(c[0], u + 0), e3._cache.writeUInt32BE(c[1], u + 4), e3._cache.writeUInt32BE(c[2], u + 8), e3._cache.writeUInt32BE(c[3], u + 12);
          }
          var d = e3._cache.slice(0, t3.length);
          return e3._cache = e3._cache.slice(t3.length), n(t3, d);
        };
      }, 882: (e2, t2) => {
        t2.encrypt = function(e3, t3) {
          return e3._cipher.encryptBlock(t3);
        }, t2.decrypt = function(e3, t3) {
          return e3._cipher.decryptBlock(t3);
        };
      }, 6200: (e2, t2, r2) => {
        var n = { ECB: r2(882), CBC: r2(3506), CFB: r2(6149), CFB8: r2(193), CFB1: r2(8394), OFB: r2(7481), CTR: r2(5527), GCM: r2(5527) }, i = r2(3349);
        for (var o in i) i[o].module = n[i[o].mode];
        e2.exports = i;
      }, 7481: (e2, t2, r2) => {
        var n = r2(460);
        function i(e3) {
          return e3._prev = e3._cipher.encryptBlock(e3._prev), e3._prev;
        }
        t2.encrypt = function(e3, t3) {
          for (; e3._cache.length < t3.length; ) e3._cache = Buffer.concat([e3._cache, i(e3)]);
          var r3 = e3._cache.slice(0, t3.length);
          return e3._cache = e3._cache.slice(t3.length), n(t3, r3);
        };
      }, 8116: (e2, t2, r2) => {
        var n = r2(7088), i = r2(6608).Buffer, o = r2(4705);
        function s(e3, t3, r3, s2) {
          o.call(this), this._cipher = new n.AES(t3), this._prev = i.from(r3), this._cache = i.allocUnsafe(0), this._secCache = i.allocUnsafe(0), this._decrypt = s2, this._mode = e3;
        }
        r2(1193)(s, o), s.prototype._update = function(e3) {
          return this._mode.encrypt(this, e3, this._decrypt);
        }, s.prototype._final = function() {
          this._cipher.scrub();
        }, e2.exports = s;
      }, 8350: (e2, t2, r2) => {
        var n = r2(4487), i = r2(5007), o = r2(6200), s = r2(3811), a = r2(1804);
        function c(e3, t3, r3) {
          if (e3 = e3.toLowerCase(), o[e3]) return i.createCipheriv(e3, t3, r3);
          if (s[e3]) return new n({ key: t3, iv: r3, mode: e3 });
          throw new TypeError("invalid suite type");
        }
        function u(e3, t3, r3) {
          if (e3 = e3.toLowerCase(), o[e3]) return i.createDecipheriv(e3, t3, r3);
          if (s[e3]) return new n({ key: t3, iv: r3, mode: e3, decrypt: true });
          throw new TypeError("invalid suite type");
        }
        t2.createCipher = t2.Cipher = function(e3, t3) {
          var r3, n2;
          if (e3 = e3.toLowerCase(), o[e3]) r3 = o[e3].key, n2 = o[e3].iv;
          else {
            if (!s[e3]) throw new TypeError("invalid suite type");
            r3 = 8 * s[e3].key, n2 = s[e3].iv;
          }
          var i2 = a(t3, false, r3, n2);
          return c(e3, i2.key, i2.iv);
        }, t2.createCipheriv = t2.Cipheriv = c, t2.createDecipher = t2.Decipher = function(e3, t3) {
          var r3, n2;
          if (e3 = e3.toLowerCase(), o[e3]) r3 = o[e3].key, n2 = o[e3].iv;
          else {
            if (!s[e3]) throw new TypeError("invalid suite type");
            r3 = 8 * s[e3].key, n2 = s[e3].iv;
          }
          var i2 = a(t3, false, r3, n2);
          return u(e3, i2.key, i2.iv);
        }, t2.createDecipheriv = t2.Decipheriv = u, t2.listCiphers = t2.getCiphers = function() {
          return Object.keys(s).concat(i.getCiphers());
        };
      }, 4487: (e2, t2, r2) => {
        var n = r2(4705), i = r2(2398), o = r2(1193), s = r2(6608).Buffer, a = { "des-ede3-cbc": i.CBC.instantiate(i.EDE), "des-ede3": i.EDE, "des-ede-cbc": i.CBC.instantiate(i.EDE), "des-ede": i.EDE, "des-cbc": i.CBC.instantiate(i.DES), "des-ecb": i.DES };
        function c(e3) {
          n.call(this);
          var t3, r3 = e3.mode.toLowerCase(), i2 = a[r3];
          t3 = e3.decrypt ? "decrypt" : "encrypt";
          var o2 = e3.key;
          s.isBuffer(o2) || (o2 = s.from(o2)), "des-ede" !== r3 && "des-ede-cbc" !== r3 || (o2 = s.concat([o2, o2.slice(0, 8)]));
          var c2 = e3.iv;
          s.isBuffer(c2) || (c2 = s.from(c2)), this._des = i2.create({ key: o2, iv: c2, type: t3 });
        }
        a.des = a["des-cbc"], a.des3 = a["des-ede3-cbc"], e2.exports = c, o(c, n), c.prototype._update = function(e3) {
          return s.from(this._des.update(e3));
        }, c.prototype._final = function() {
          return s.from(this._des.final());
        };
      }, 3811: (e2, t2) => {
        t2["des-ecb"] = { key: 8, iv: 0 }, t2["des-cbc"] = t2.des = { key: 8, iv: 8 }, t2["des-ede3-cbc"] = t2.des3 = { key: 24, iv: 8 }, t2["des-ede3"] = { key: 24, iv: 0 }, t2["des-ede-cbc"] = { key: 16, iv: 8 }, t2["des-ede"] = { key: 16, iv: 0 };
      }, 1377: (e2, t2, r2) => {
        var n = r2(3900), i = r2(2869);
        function o(e3) {
          var t3, r3 = e3.modulus.byteLength();
          do {
            t3 = new n(i(r3));
          } while (t3.cmp(e3.modulus) >= 0 || !t3.umod(e3.prime1) || !t3.umod(e3.prime2));
          return t3;
        }
        function s(e3, t3) {
          var r3 = (function(e4) {
            var t4 = o(e4);
            return { blinder: t4.toRed(n.mont(e4.modulus)).redPow(new n(e4.publicExponent)).fromRed(), unblinder: t4.invm(e4.modulus) };
          })(t3), i2 = t3.modulus.byteLength(), s2 = new n(e3).mul(r3.blinder).umod(t3.modulus), a = s2.toRed(n.mont(t3.prime1)), c = s2.toRed(n.mont(t3.prime2)), u = t3.coefficient, d = t3.prime1, f = t3.prime2, h = a.redPow(t3.exponent1).fromRed(), l = c.redPow(t3.exponent2).fromRed(), p = h.isub(l).imul(u).umod(d).imul(f);
          return l.iadd(p).imul(r3.unblinder).umod(t3.modulus).toArrayLike(Buffer, "be", i2);
        }
        s.getr = o, e2.exports = s;
      }, 8950: (e2, t2, r2) => {
        "use strict";
        e2.exports = r2(6980);
      }, 6105: (e2, t2, r2) => {
        "use strict";
        var n = r2(6608).Buffer, i = r2(8955), o = r2(1094), s = r2(1193), a = r2(9508), c = r2(5504), u = r2(6980);
        function d(e3) {
          o.Writable.call(this);
          var t3 = u[e3];
          if (!t3) throw new Error("Unknown message digest");
          this._hashType = t3.hash, this._hash = i(t3.hash), this._tag = t3.id, this._signType = t3.sign;
        }
        function f(e3) {
          o.Writable.call(this);
          var t3 = u[e3];
          if (!t3) throw new Error("Unknown message digest");
          this._hash = i(t3.hash), this._tag = t3.id, this._signType = t3.sign;
        }
        function h(e3) {
          return new d(e3);
        }
        function l(e3) {
          return new f(e3);
        }
        Object.keys(u).forEach((function(e3) {
          u[e3].id = n.from(u[e3].id, "hex"), u[e3.toLowerCase()] = u[e3];
        })), s(d, o.Writable), d.prototype._write = function(e3, t3, r3) {
          this._hash.update(e3), r3();
        }, d.prototype.update = function(e3, t3) {
          return this._hash.update("string" == typeof e3 ? n.from(e3, t3) : e3), this;
        }, d.prototype.sign = function(e3, t3) {
          this.end();
          var r3 = this._hash.digest(), n2 = a(r3, e3, this._hashType, this._signType, this._tag);
          return t3 ? n2.toString(t3) : n2;
        }, s(f, o.Writable), f.prototype._write = function(e3, t3, r3) {
          this._hash.update(e3), r3();
        }, f.prototype.update = function(e3, t3) {
          return this._hash.update("string" == typeof e3 ? n.from(e3, t3) : e3), this;
        }, f.prototype.verify = function(e3, t3, r3) {
          var i2 = "string" == typeof t3 ? n.from(t3, r3) : t3;
          this.end();
          var o2 = this._hash.digest();
          return c(i2, o2, e3, this._signType, this._tag);
        }, e2.exports = { Sign: h, Verify: l, createSign: h, createVerify: l };
      }, 9508: (e2, t2, r2) => {
        "use strict";
        var n = r2(6608).Buffer, i = r2(3053), o = r2(1377), s = r2(3071).ec, a = r2(3900), c = r2(780), u = r2(9262);
        function d(e3, t3, r3, o2) {
          if ((e3 = n.from(e3.toArray())).length < t3.byteLength()) {
            var s2 = n.alloc(t3.byteLength() - e3.length);
            e3 = n.concat([s2, e3]);
          }
          var a2 = r3.length, c2 = (function(e4, t4) {
            e4 = (e4 = f(e4, t4)).mod(t4);
            var r4 = n.from(e4.toArray());
            if (r4.length < t4.byteLength()) {
              var i2 = n.alloc(t4.byteLength() - r4.length);
              r4 = n.concat([i2, r4]);
            }
            return r4;
          })(r3, t3), u2 = n.alloc(a2);
          u2.fill(1);
          var d2 = n.alloc(a2);
          return d2 = i(o2, d2).update(u2).update(n.from([0])).update(e3).update(c2).digest(), u2 = i(o2, d2).update(u2).digest(), { k: d2 = i(o2, d2).update(u2).update(n.from([1])).update(e3).update(c2).digest(), v: u2 = i(o2, d2).update(u2).digest() };
        }
        function f(e3, t3) {
          var r3 = new a(e3), n2 = (e3.length << 3) - t3.bitLength();
          return n2 > 0 && r3.ishrn(n2), r3;
        }
        function h(e3, t3, r3) {
          var o2, s2;
          do {
            for (o2 = n.alloc(0); 8 * o2.length < e3.bitLength(); ) t3.v = i(r3, t3.k).update(t3.v).digest(), o2 = n.concat([o2, t3.v]);
            s2 = f(o2, e3), t3.k = i(r3, t3.k).update(t3.v).update(n.from([0])).digest(), t3.v = i(r3, t3.k).update(t3.v).digest();
          } while (-1 !== s2.cmp(e3));
          return s2;
        }
        function l(e3, t3, r3, n2) {
          return e3.toRed(a.mont(r3)).redPow(t3).fromRed().mod(n2);
        }
        e2.exports = function(e3, t3, r3, i2, p) {
          var b = c(t3);
          if (b.curve) {
            if ("ecdsa" !== i2 && "ecdsa/rsa" !== i2) throw new Error("wrong private key type");
            return (function(e4, t4) {
              var r4 = u[t4.curve.join(".")];
              if (!r4) throw new Error("unknown curve " + t4.curve.join("."));
              var i3 = new s(r4).keyFromPrivate(t4.privateKey).sign(e4);
              return n.from(i3.toDER());
            })(e3, b);
          }
          if ("dsa" === b.type) {
            if ("dsa" !== i2) throw new Error("wrong private key type");
            return (function(e4, t4, r4) {
              for (var i3, o2 = t4.params.priv_key, s2 = t4.params.p, c2 = t4.params.q, u2 = t4.params.g, p2 = new a(0), b2 = f(e4, c2).mod(c2), y2 = false, m2 = d(o2, c2, e4, r4); false === y2; ) p2 = l(u2, i3 = h(c2, m2, r4), s2, c2), 0 === (y2 = i3.invm(c2).imul(b2.add(o2.mul(p2))).mod(c2)).cmpn(0) && (y2 = false, p2 = new a(0));
              return (function(e5, t5) {
                e5 = e5.toArray(), t5 = t5.toArray(), 128 & e5[0] && (e5 = [0].concat(e5)), 128 & t5[0] && (t5 = [0].concat(t5));
                var r5 = [48, e5.length + t5.length + 4, 2, e5.length];
                return r5 = r5.concat(e5, [2, t5.length], t5), n.from(r5);
              })(p2, y2);
            })(e3, b, r3);
          }
          if ("rsa" !== i2 && "ecdsa/rsa" !== i2) throw new Error("wrong private key type");
          if (void 0 !== t3.padding && 1 !== t3.padding) throw new Error("illegal or unsupported padding mode");
          e3 = n.concat([p, e3]);
          for (var y = b.modulus.byteLength(), m = [0, 1]; e3.length + m.length + 1 < y; ) m.push(255);
          m.push(0);
          for (var g = -1; ++g < e3.length; ) m.push(e3[g]);
          return o(m, b);
        }, e2.exports.getKey = d, e2.exports.makeKey = h;
      }, 5504: (e2, t2, r2) => {
        "use strict";
        var n = r2(6608).Buffer, i = r2(3900), o = r2(3071).ec, s = r2(780), a = r2(9262);
        function c(e3, t3) {
          if (e3.cmpn(0) <= 0) throw new Error("invalid sig");
          if (e3.cmp(t3) >= 0) throw new Error("invalid sig");
        }
        e2.exports = function(e3, t3, r3, u, d) {
          var f = s(r3);
          if ("ec" === f.type) {
            if ("ecdsa" !== u && "ecdsa/rsa" !== u) throw new Error("wrong public key type");
            return (function(e4, t4, r4) {
              var n2 = a[r4.data.algorithm.curve.join(".")];
              if (!n2) throw new Error("unknown curve " + r4.data.algorithm.curve.join("."));
              var i2 = new o(n2), s2 = r4.data.subjectPrivateKey.data;
              return i2.verify(t4, e4, s2);
            })(e3, t3, f);
          }
          if ("dsa" === f.type) {
            if ("dsa" !== u) throw new Error("wrong public key type");
            return (function(e4, t4, r4) {
              var n2 = r4.data.p, o2 = r4.data.q, a2 = r4.data.g, u2 = r4.data.pub_key, d2 = s.signature.decode(e4, "der"), f2 = d2.s, h2 = d2.r;
              c(f2, o2), c(h2, o2);
              var l2 = i.mont(n2), p2 = f2.invm(o2);
              return 0 === a2.toRed(l2).redPow(new i(t4).mul(p2).mod(o2)).fromRed().mul(u2.toRed(l2).redPow(h2.mul(p2).mod(o2)).fromRed()).mod(n2).mod(o2).cmp(h2);
            })(e3, t3, f);
          }
          if ("rsa" !== u && "ecdsa/rsa" !== u) throw new Error("wrong public key type");
          t3 = n.concat([d, t3]);
          for (var h = f.modulus.byteLength(), l = [1], p = 0; t3.length + l.length + 2 < h; ) l.push(255), p += 1;
          l.push(0);
          for (var b = -1; ++b < t3.length; ) l.push(t3[b]);
          l = n.from(l);
          var y = i.mont(f.modulus);
          e3 = (e3 = new i(e3).toRed(y)).redPow(new i(f.publicExponent)), e3 = n.from(e3.fromRed().toArray());
          var m = p < 8 ? 1 : 0;
          for (h = Math.min(e3.length, l.length), e3.length !== l.length && (m = 1), b = -1; ++b < h; ) m |= e3[b] ^ l[b];
          return 0 === m;
        };
      }, 460: (e2) => {
        e2.exports = function(e3, t2) {
          for (var r2 = Math.min(e3.length, t2.length), n = new Buffer(r2), i = 0; i < r2; ++i) n[i] = e3[i] ^ t2[i];
          return n;
        };
      }, 6533: (e2, t2, r2) => {
        "use strict";
        const n = r2(4933), i = r2(3328), o = "function" == typeof Symbol && "function" == typeof Symbol.for ? /* @__PURE__ */ Symbol.for("nodejs.util.inspect.custom") : null;
        t2.Buffer = c, t2.SlowBuffer = function(e3) {
          return +e3 != e3 && (e3 = 0), c.alloc(+e3);
        }, t2.INSPECT_MAX_BYTES = 50;
        const s = 2147483647;
        function a(e3) {
          if (e3 > s) throw new RangeError('The value "' + e3 + '" is invalid for option "size"');
          const t3 = new Uint8Array(e3);
          return Object.setPrototypeOf(t3, c.prototype), t3;
        }
        function c(e3, t3, r3) {
          if ("number" == typeof e3) {
            if ("string" == typeof t3) throw new TypeError('The "string" argument must be of type string. Received type number');
            return f(e3);
          }
          return u(e3, t3, r3);
        }
        function u(e3, t3, r3) {
          if ("string" == typeof e3) return (function(e4, t4) {
            if ("string" == typeof t4 && "" !== t4 || (t4 = "utf8"), !c.isEncoding(t4)) throw new TypeError("Unknown encoding: " + t4);
            const r4 = 0 | b(e4, t4);
            let n3 = a(r4);
            const i3 = n3.write(e4, t4);
            return i3 !== r4 && (n3 = n3.slice(0, i3)), n3;
          })(e3, t3);
          if (ArrayBuffer.isView(e3)) return (function(e4) {
            if (J(e4, Uint8Array)) {
              const t4 = new Uint8Array(e4);
              return l(t4.buffer, t4.byteOffset, t4.byteLength);
            }
            return h(e4);
          })(e3);
          if (null == e3) throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e3);
          if (J(e3, ArrayBuffer) || e3 && J(e3.buffer, ArrayBuffer)) return l(e3, t3, r3);
          if ("undefined" != typeof SharedArrayBuffer && (J(e3, SharedArrayBuffer) || e3 && J(e3.buffer, SharedArrayBuffer))) return l(e3, t3, r3);
          if ("number" == typeof e3) throw new TypeError('The "value" argument must not be of type number. Received type number');
          const n2 = e3.valueOf && e3.valueOf();
          if (null != n2 && n2 !== e3) return c.from(n2, t3, r3);
          const i2 = (function(e4) {
            if (c.isBuffer(e4)) {
              const t4 = 0 | p(e4.length), r4 = a(t4);
              return 0 === r4.length || e4.copy(r4, 0, 0, t4), r4;
            }
            return void 0 !== e4.length ? "number" != typeof e4.length || Z(e4.length) ? a(0) : h(e4) : "Buffer" === e4.type && Array.isArray(e4.data) ? h(e4.data) : void 0;
          })(e3);
          if (i2) return i2;
          if ("undefined" != typeof Symbol && null != Symbol.toPrimitive && "function" == typeof e3[Symbol.toPrimitive]) return c.from(e3[Symbol.toPrimitive]("string"), t3, r3);
          throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e3);
        }
        function d(e3) {
          if ("number" != typeof e3) throw new TypeError('"size" argument must be of type number');
          if (e3 < 0) throw new RangeError('The value "' + e3 + '" is invalid for option "size"');
        }
        function f(e3) {
          return d(e3), a(e3 < 0 ? 0 : 0 | p(e3));
        }
        function h(e3) {
          const t3 = e3.length < 0 ? 0 : 0 | p(e3.length), r3 = a(t3);
          for (let n2 = 0; n2 < t3; n2 += 1) r3[n2] = 255 & e3[n2];
          return r3;
        }
        function l(e3, t3, r3) {
          if (t3 < 0 || e3.byteLength < t3) throw new RangeError('"offset" is outside of buffer bounds');
          if (e3.byteLength < t3 + (r3 || 0)) throw new RangeError('"length" is outside of buffer bounds');
          let n2;
          return n2 = void 0 === t3 && void 0 === r3 ? new Uint8Array(e3) : void 0 === r3 ? new Uint8Array(e3, t3) : new Uint8Array(e3, t3, r3), Object.setPrototypeOf(n2, c.prototype), n2;
        }
        function p(e3) {
          if (e3 >= s) throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + s.toString(16) + " bytes");
          return 0 | e3;
        }
        function b(e3, t3) {
          if (c.isBuffer(e3)) return e3.length;
          if (ArrayBuffer.isView(e3) || J(e3, ArrayBuffer)) return e3.byteLength;
          if ("string" != typeof e3) throw new TypeError('The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof e3);
          const r3 = e3.length, n2 = arguments.length > 2 && true === arguments[2];
          if (!n2 && 0 === r3) return 0;
          let i2 = false;
          for (; ; ) switch (t3) {
            case "ascii":
            case "latin1":
            case "binary":
              return r3;
            case "utf8":
            case "utf-8":
              return z(e3).length;
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return 2 * r3;
            case "hex":
              return r3 >>> 1;
            case "base64":
              return K(e3).length;
            default:
              if (i2) return n2 ? -1 : z(e3).length;
              t3 = ("" + t3).toLowerCase(), i2 = true;
          }
        }
        function y(e3, t3, r3) {
          let n2 = false;
          if ((void 0 === t3 || t3 < 0) && (t3 = 0), t3 > this.length) return "";
          if ((void 0 === r3 || r3 > this.length) && (r3 = this.length), r3 <= 0) return "";
          if ((r3 >>>= 0) <= (t3 >>>= 0)) return "";
          for (e3 || (e3 = "utf8"); ; ) switch (e3) {
            case "hex":
              return I(this, t3, r3);
            case "utf8":
            case "utf-8":
              return M(this, t3, r3);
            case "ascii":
              return k(this, t3, r3);
            case "latin1":
            case "binary":
              return x(this, t3, r3);
            case "base64":
              return T(this, t3, r3);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return B(this, t3, r3);
            default:
              if (n2) throw new TypeError("Unknown encoding: " + e3);
              e3 = (e3 + "").toLowerCase(), n2 = true;
          }
        }
        function m(e3, t3, r3) {
          const n2 = e3[t3];
          e3[t3] = e3[r3], e3[r3] = n2;
        }
        function g(e3, t3, r3, n2, i2) {
          if (0 === e3.length) return -1;
          if ("string" == typeof r3 ? (n2 = r3, r3 = 0) : r3 > 2147483647 ? r3 = 2147483647 : r3 < -2147483648 && (r3 = -2147483648), Z(r3 = +r3) && (r3 = i2 ? 0 : e3.length - 1), r3 < 0 && (r3 = e3.length + r3), r3 >= e3.length) {
            if (i2) return -1;
            r3 = e3.length - 1;
          } else if (r3 < 0) {
            if (!i2) return -1;
            r3 = 0;
          }
          if ("string" == typeof t3 && (t3 = c.from(t3, n2)), c.isBuffer(t3)) return 0 === t3.length ? -1 : v(e3, t3, r3, n2, i2);
          if ("number" == typeof t3) return t3 &= 255, "function" == typeof Uint8Array.prototype.indexOf ? i2 ? Uint8Array.prototype.indexOf.call(e3, t3, r3) : Uint8Array.prototype.lastIndexOf.call(e3, t3, r3) : v(e3, [t3], r3, n2, i2);
          throw new TypeError("val must be string, number or Buffer");
        }
        function v(e3, t3, r3, n2, i2) {
          let o2, s2 = 1, a2 = e3.length, c2 = t3.length;
          if (void 0 !== n2 && ("ucs2" === (n2 = String(n2).toLowerCase()) || "ucs-2" === n2 || "utf16le" === n2 || "utf-16le" === n2)) {
            if (e3.length < 2 || t3.length < 2) return -1;
            s2 = 2, a2 /= 2, c2 /= 2, r3 /= 2;
          }
          function u2(e4, t4) {
            return 1 === s2 ? e4[t4] : e4.readUInt16BE(t4 * s2);
          }
          if (i2) {
            let n3 = -1;
            for (o2 = r3; o2 < a2; o2++) if (u2(e3, o2) === u2(t3, -1 === n3 ? 0 : o2 - n3)) {
              if (-1 === n3 && (n3 = o2), o2 - n3 + 1 === c2) return n3 * s2;
            } else -1 !== n3 && (o2 -= o2 - n3), n3 = -1;
          } else for (r3 + c2 > a2 && (r3 = a2 - c2), o2 = r3; o2 >= 0; o2--) {
            let r4 = true;
            for (let n3 = 0; n3 < c2; n3++) if (u2(e3, o2 + n3) !== u2(t3, n3)) {
              r4 = false;
              break;
            }
            if (r4) return o2;
          }
          return -1;
        }
        function w(e3, t3, r3, n2) {
          r3 = Number(r3) || 0;
          const i2 = e3.length - r3;
          n2 ? (n2 = Number(n2)) > i2 && (n2 = i2) : n2 = i2;
          const o2 = t3.length;
          let s2;
          for (n2 > o2 / 2 && (n2 = o2 / 2), s2 = 0; s2 < n2; ++s2) {
            const n3 = parseInt(t3.substr(2 * s2, 2), 16);
            if (Z(n3)) return s2;
            e3[r3 + s2] = n3;
          }
          return s2;
        }
        function _(e3, t3, r3, n2) {
          return W(z(t3, e3.length - r3), e3, r3, n2);
        }
        function A(e3, t3, r3, n2) {
          return W((function(e4) {
            const t4 = [];
            for (let r4 = 0; r4 < e4.length; ++r4) t4.push(255 & e4.charCodeAt(r4));
            return t4;
          })(t3), e3, r3, n2);
        }
        function S(e3, t3, r3, n2) {
          return W(K(t3), e3, r3, n2);
        }
        function C(e3, t3, r3, n2) {
          return W((function(e4, t4) {
            let r4, n3, i2;
            const o2 = [];
            for (let s2 = 0; s2 < e4.length && !((t4 -= 2) < 0); ++s2) r4 = e4.charCodeAt(s2), n3 = r4 >> 8, i2 = r4 % 256, o2.push(i2), o2.push(n3);
            return o2;
          })(t3, e3.length - r3), e3, r3, n2);
        }
        function T(e3, t3, r3) {
          return 0 === t3 && r3 === e3.length ? n.fromByteArray(e3) : n.fromByteArray(e3.slice(t3, r3));
        }
        function M(e3, t3, r3) {
          r3 = Math.min(e3.length, r3);
          const n2 = [];
          let i2 = t3;
          for (; i2 < r3; ) {
            const t4 = e3[i2];
            let o2 = null, s2 = t4 > 239 ? 4 : t4 > 223 ? 3 : t4 > 191 ? 2 : 1;
            if (i2 + s2 <= r3) {
              let r4, n3, a2, c2;
              switch (s2) {
                case 1:
                  t4 < 128 && (o2 = t4);
                  break;
                case 2:
                  r4 = e3[i2 + 1], 128 == (192 & r4) && (c2 = (31 & t4) << 6 | 63 & r4, c2 > 127 && (o2 = c2));
                  break;
                case 3:
                  r4 = e3[i2 + 1], n3 = e3[i2 + 2], 128 == (192 & r4) && 128 == (192 & n3) && (c2 = (15 & t4) << 12 | (63 & r4) << 6 | 63 & n3, c2 > 2047 && (c2 < 55296 || c2 > 57343) && (o2 = c2));
                  break;
                case 4:
                  r4 = e3[i2 + 1], n3 = e3[i2 + 2], a2 = e3[i2 + 3], 128 == (192 & r4) && 128 == (192 & n3) && 128 == (192 & a2) && (c2 = (15 & t4) << 18 | (63 & r4) << 12 | (63 & n3) << 6 | 63 & a2, c2 > 65535 && c2 < 1114112 && (o2 = c2));
              }
            }
            null === o2 ? (o2 = 65533, s2 = 1) : o2 > 65535 && (o2 -= 65536, n2.push(o2 >>> 10 & 1023 | 55296), o2 = 56320 | 1023 & o2), n2.push(o2), i2 += s2;
          }
          return (function(e4) {
            const t4 = e4.length;
            if (t4 <= E) return String.fromCharCode.apply(String, e4);
            let r4 = "", n3 = 0;
            for (; n3 < t4; ) r4 += String.fromCharCode.apply(String, e4.slice(n3, n3 += E));
            return r4;
          })(n2);
        }
        t2.kMaxLength = s, c.TYPED_ARRAY_SUPPORT = (function() {
          try {
            const e3 = new Uint8Array(1), t3 = { foo: function() {
              return 42;
            } };
            return Object.setPrototypeOf(t3, Uint8Array.prototype), Object.setPrototypeOf(e3, t3), 42 === e3.foo();
          } catch (e3) {
            return false;
          }
        })(), c.TYPED_ARRAY_SUPPORT || "undefined" == typeof console || "function" != typeof console.error || console.error("This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support."), Object.defineProperty(c.prototype, "parent", { enumerable: true, get: function() {
          if (c.isBuffer(this)) return this.buffer;
        } }), Object.defineProperty(c.prototype, "offset", { enumerable: true, get: function() {
          if (c.isBuffer(this)) return this.byteOffset;
        } }), c.poolSize = 8192, c.from = function(e3, t3, r3) {
          return u(e3, t3, r3);
        }, Object.setPrototypeOf(c.prototype, Uint8Array.prototype), Object.setPrototypeOf(c, Uint8Array), c.alloc = function(e3, t3, r3) {
          return (function(e4, t4, r4) {
            return d(e4), e4 <= 0 ? a(e4) : void 0 !== t4 ? "string" == typeof r4 ? a(e4).fill(t4, r4) : a(e4).fill(t4) : a(e4);
          })(e3, t3, r3);
        }, c.allocUnsafe = function(e3) {
          return f(e3);
        }, c.allocUnsafeSlow = function(e3) {
          return f(e3);
        }, c.isBuffer = function(e3) {
          return null != e3 && true === e3._isBuffer && e3 !== c.prototype;
        }, c.compare = function(e3, t3) {
          if (J(e3, Uint8Array) && (e3 = c.from(e3, e3.offset, e3.byteLength)), J(t3, Uint8Array) && (t3 = c.from(t3, t3.offset, t3.byteLength)), !c.isBuffer(e3) || !c.isBuffer(t3)) throw new TypeError('The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array');
          if (e3 === t3) return 0;
          let r3 = e3.length, n2 = t3.length;
          for (let i2 = 0, o2 = Math.min(r3, n2); i2 < o2; ++i2) if (e3[i2] !== t3[i2]) {
            r3 = e3[i2], n2 = t3[i2];
            break;
          }
          return r3 < n2 ? -1 : n2 < r3 ? 1 : 0;
        }, c.isEncoding = function(e3) {
          switch (String(e3).toLowerCase()) {
            case "hex":
            case "utf8":
            case "utf-8":
            case "ascii":
            case "latin1":
            case "binary":
            case "base64":
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return true;
            default:
              return false;
          }
        }, c.concat = function(e3, t3) {
          if (!Array.isArray(e3)) throw new TypeError('"list" argument must be an Array of Buffers');
          if (0 === e3.length) return c.alloc(0);
          let r3;
          if (void 0 === t3) for (t3 = 0, r3 = 0; r3 < e3.length; ++r3) t3 += e3[r3].length;
          const n2 = c.allocUnsafe(t3);
          let i2 = 0;
          for (r3 = 0; r3 < e3.length; ++r3) {
            let t4 = e3[r3];
            if (J(t4, Uint8Array)) i2 + t4.length > n2.length ? (c.isBuffer(t4) || (t4 = c.from(t4)), t4.copy(n2, i2)) : Uint8Array.prototype.set.call(n2, t4, i2);
            else {
              if (!c.isBuffer(t4)) throw new TypeError('"list" argument must be an Array of Buffers');
              t4.copy(n2, i2);
            }
            i2 += t4.length;
          }
          return n2;
        }, c.byteLength = b, c.prototype._isBuffer = true, c.prototype.swap16 = function() {
          const e3 = this.length;
          if (e3 % 2 != 0) throw new RangeError("Buffer size must be a multiple of 16-bits");
          for (let t3 = 0; t3 < e3; t3 += 2) m(this, t3, t3 + 1);
          return this;
        }, c.prototype.swap32 = function() {
          const e3 = this.length;
          if (e3 % 4 != 0) throw new RangeError("Buffer size must be a multiple of 32-bits");
          for (let t3 = 0; t3 < e3; t3 += 4) m(this, t3, t3 + 3), m(this, t3 + 1, t3 + 2);
          return this;
        }, c.prototype.swap64 = function() {
          const e3 = this.length;
          if (e3 % 8 != 0) throw new RangeError("Buffer size must be a multiple of 64-bits");
          for (let t3 = 0; t3 < e3; t3 += 8) m(this, t3, t3 + 7), m(this, t3 + 1, t3 + 6), m(this, t3 + 2, t3 + 5), m(this, t3 + 3, t3 + 4);
          return this;
        }, c.prototype.toString = function() {
          const e3 = this.length;
          return 0 === e3 ? "" : 0 === arguments.length ? M(this, 0, e3) : y.apply(this, arguments);
        }, c.prototype.toLocaleString = c.prototype.toString, c.prototype.equals = function(e3) {
          if (!c.isBuffer(e3)) throw new TypeError("Argument must be a Buffer");
          return this === e3 || 0 === c.compare(this, e3);
        }, c.prototype.inspect = function() {
          let e3 = "";
          const r3 = t2.INSPECT_MAX_BYTES;
          return e3 = this.toString("hex", 0, r3).replace(/(.{2})/g, "$1 ").trim(), this.length > r3 && (e3 += " ... "), "<Buffer " + e3 + ">";
        }, o && (c.prototype[o] = c.prototype.inspect), c.prototype.compare = function(e3, t3, r3, n2, i2) {
          if (J(e3, Uint8Array) && (e3 = c.from(e3, e3.offset, e3.byteLength)), !c.isBuffer(e3)) throw new TypeError('The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof e3);
          if (void 0 === t3 && (t3 = 0), void 0 === r3 && (r3 = e3 ? e3.length : 0), void 0 === n2 && (n2 = 0), void 0 === i2 && (i2 = this.length), t3 < 0 || r3 > e3.length || n2 < 0 || i2 > this.length) throw new RangeError("out of range index");
          if (n2 >= i2 && t3 >= r3) return 0;
          if (n2 >= i2) return -1;
          if (t3 >= r3) return 1;
          if (this === e3) return 0;
          let o2 = (i2 >>>= 0) - (n2 >>>= 0), s2 = (r3 >>>= 0) - (t3 >>>= 0);
          const a2 = Math.min(o2, s2), u2 = this.slice(n2, i2), d2 = e3.slice(t3, r3);
          for (let e4 = 0; e4 < a2; ++e4) if (u2[e4] !== d2[e4]) {
            o2 = u2[e4], s2 = d2[e4];
            break;
          }
          return o2 < s2 ? -1 : s2 < o2 ? 1 : 0;
        }, c.prototype.includes = function(e3, t3, r3) {
          return -1 !== this.indexOf(e3, t3, r3);
        }, c.prototype.indexOf = function(e3, t3, r3) {
          return g(this, e3, t3, r3, true);
        }, c.prototype.lastIndexOf = function(e3, t3, r3) {
          return g(this, e3, t3, r3, false);
        }, c.prototype.write = function(e3, t3, r3, n2) {
          if (void 0 === t3) n2 = "utf8", r3 = this.length, t3 = 0;
          else if (void 0 === r3 && "string" == typeof t3) n2 = t3, r3 = this.length, t3 = 0;
          else {
            if (!isFinite(t3)) throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
            t3 >>>= 0, isFinite(r3) ? (r3 >>>= 0, void 0 === n2 && (n2 = "utf8")) : (n2 = r3, r3 = void 0);
          }
          const i2 = this.length - t3;
          if ((void 0 === r3 || r3 > i2) && (r3 = i2), e3.length > 0 && (r3 < 0 || t3 < 0) || t3 > this.length) throw new RangeError("Attempt to write outside buffer bounds");
          n2 || (n2 = "utf8");
          let o2 = false;
          for (; ; ) switch (n2) {
            case "hex":
              return w(this, e3, t3, r3);
            case "utf8":
            case "utf-8":
              return _(this, e3, t3, r3);
            case "ascii":
            case "latin1":
            case "binary":
              return A(this, e3, t3, r3);
            case "base64":
              return S(this, e3, t3, r3);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return C(this, e3, t3, r3);
            default:
              if (o2) throw new TypeError("Unknown encoding: " + n2);
              n2 = ("" + n2).toLowerCase(), o2 = true;
          }
        }, c.prototype.toJSON = function() {
          return { type: "Buffer", data: Array.prototype.slice.call(this._arr || this, 0) };
        };
        const E = 4096;
        function k(e3, t3, r3) {
          let n2 = "";
          r3 = Math.min(e3.length, r3);
          for (let i2 = t3; i2 < r3; ++i2) n2 += String.fromCharCode(127 & e3[i2]);
          return n2;
        }
        function x(e3, t3, r3) {
          let n2 = "";
          r3 = Math.min(e3.length, r3);
          for (let i2 = t3; i2 < r3; ++i2) n2 += String.fromCharCode(e3[i2]);
          return n2;
        }
        function I(e3, t3, r3) {
          const n2 = e3.length;
          (!t3 || t3 < 0) && (t3 = 0), (!r3 || r3 < 0 || r3 > n2) && (r3 = n2);
          let i2 = "";
          for (let n3 = t3; n3 < r3; ++n3) i2 += X[e3[n3]];
          return i2;
        }
        function B(e3, t3, r3) {
          const n2 = e3.slice(t3, r3);
          let i2 = "";
          for (let e4 = 0; e4 < n2.length - 1; e4 += 2) i2 += String.fromCharCode(n2[e4] + 256 * n2[e4 + 1]);
          return i2;
        }
        function U(e3, t3, r3) {
          if (e3 % 1 != 0 || e3 < 0) throw new RangeError("offset is not uint");
          if (e3 + t3 > r3) throw new RangeError("Trying to access beyond buffer length");
        }
        function P(e3, t3, r3, n2, i2, o2) {
          if (!c.isBuffer(e3)) throw new TypeError('"buffer" argument must be a Buffer instance');
          if (t3 > i2 || t3 < o2) throw new RangeError('"value" argument is out of bounds');
          if (r3 + n2 > e3.length) throw new RangeError("Index out of range");
        }
        function O(e3, t3, r3, n2, i2) {
          q(t3, n2, i2, e3, r3, 7);
          let o2 = Number(t3 & BigInt(4294967295));
          e3[r3++] = o2, o2 >>= 8, e3[r3++] = o2, o2 >>= 8, e3[r3++] = o2, o2 >>= 8, e3[r3++] = o2;
          let s2 = Number(t3 >> BigInt(32) & BigInt(4294967295));
          return e3[r3++] = s2, s2 >>= 8, e3[r3++] = s2, s2 >>= 8, e3[r3++] = s2, s2 >>= 8, e3[r3++] = s2, r3;
        }
        function R(e3, t3, r3, n2, i2) {
          q(t3, n2, i2, e3, r3, 7);
          let o2 = Number(t3 & BigInt(4294967295));
          e3[r3 + 7] = o2, o2 >>= 8, e3[r3 + 6] = o2, o2 >>= 8, e3[r3 + 5] = o2, o2 >>= 8, e3[r3 + 4] = o2;
          let s2 = Number(t3 >> BigInt(32) & BigInt(4294967295));
          return e3[r3 + 3] = s2, s2 >>= 8, e3[r3 + 2] = s2, s2 >>= 8, e3[r3 + 1] = s2, s2 >>= 8, e3[r3] = s2, r3 + 8;
        }
        function N(e3, t3, r3, n2, i2, o2) {
          if (r3 + n2 > e3.length) throw new RangeError("Index out of range");
          if (r3 < 0) throw new RangeError("Index out of range");
        }
        function L(e3, t3, r3, n2, o2) {
          return t3 = +t3, r3 >>>= 0, o2 || N(e3, 0, r3, 4), i.write(e3, t3, r3, n2, 23, 4), r3 + 4;
        }
        function j(e3, t3, r3, n2, o2) {
          return t3 = +t3, r3 >>>= 0, o2 || N(e3, 0, r3, 8), i.write(e3, t3, r3, n2, 52, 8), r3 + 8;
        }
        c.prototype.slice = function(e3, t3) {
          const r3 = this.length;
          (e3 = ~~e3) < 0 ? (e3 += r3) < 0 && (e3 = 0) : e3 > r3 && (e3 = r3), (t3 = void 0 === t3 ? r3 : ~~t3) < 0 ? (t3 += r3) < 0 && (t3 = 0) : t3 > r3 && (t3 = r3), t3 < e3 && (t3 = e3);
          const n2 = this.subarray(e3, t3);
          return Object.setPrototypeOf(n2, c.prototype), n2;
        }, c.prototype.readUintLE = c.prototype.readUIntLE = function(e3, t3, r3) {
          e3 >>>= 0, t3 >>>= 0, r3 || U(e3, t3, this.length);
          let n2 = this[e3], i2 = 1, o2 = 0;
          for (; ++o2 < t3 && (i2 *= 256); ) n2 += this[e3 + o2] * i2;
          return n2;
        }, c.prototype.readUintBE = c.prototype.readUIntBE = function(e3, t3, r3) {
          e3 >>>= 0, t3 >>>= 0, r3 || U(e3, t3, this.length);
          let n2 = this[e3 + --t3], i2 = 1;
          for (; t3 > 0 && (i2 *= 256); ) n2 += this[e3 + --t3] * i2;
          return n2;
        }, c.prototype.readUint8 = c.prototype.readUInt8 = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 1, this.length), this[e3];
        }, c.prototype.readUint16LE = c.prototype.readUInt16LE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 2, this.length), this[e3] | this[e3 + 1] << 8;
        }, c.prototype.readUint16BE = c.prototype.readUInt16BE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 2, this.length), this[e3] << 8 | this[e3 + 1];
        }, c.prototype.readUint32LE = c.prototype.readUInt32LE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), (this[e3] | this[e3 + 1] << 8 | this[e3 + 2] << 16) + 16777216 * this[e3 + 3];
        }, c.prototype.readUint32BE = c.prototype.readUInt32BE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), 16777216 * this[e3] + (this[e3 + 1] << 16 | this[e3 + 2] << 8 | this[e3 + 3]);
        }, c.prototype.readBigUInt64LE = Y((function(e3) {
          $(e3 >>>= 0, "offset");
          const t3 = this[e3], r3 = this[e3 + 7];
          void 0 !== t3 && void 0 !== r3 || V(e3, this.length - 8);
          const n2 = t3 + 256 * this[++e3] + 65536 * this[++e3] + this[++e3] * 2 ** 24, i2 = this[++e3] + 256 * this[++e3] + 65536 * this[++e3] + r3 * 2 ** 24;
          return BigInt(n2) + (BigInt(i2) << BigInt(32));
        })), c.prototype.readBigUInt64BE = Y((function(e3) {
          $(e3 >>>= 0, "offset");
          const t3 = this[e3], r3 = this[e3 + 7];
          void 0 !== t3 && void 0 !== r3 || V(e3, this.length - 8);
          const n2 = t3 * 2 ** 24 + 65536 * this[++e3] + 256 * this[++e3] + this[++e3], i2 = this[++e3] * 2 ** 24 + 65536 * this[++e3] + 256 * this[++e3] + r3;
          return (BigInt(n2) << BigInt(32)) + BigInt(i2);
        })), c.prototype.readIntLE = function(e3, t3, r3) {
          e3 >>>= 0, t3 >>>= 0, r3 || U(e3, t3, this.length);
          let n2 = this[e3], i2 = 1, o2 = 0;
          for (; ++o2 < t3 && (i2 *= 256); ) n2 += this[e3 + o2] * i2;
          return i2 *= 128, n2 >= i2 && (n2 -= Math.pow(2, 8 * t3)), n2;
        }, c.prototype.readIntBE = function(e3, t3, r3) {
          e3 >>>= 0, t3 >>>= 0, r3 || U(e3, t3, this.length);
          let n2 = t3, i2 = 1, o2 = this[e3 + --n2];
          for (; n2 > 0 && (i2 *= 256); ) o2 += this[e3 + --n2] * i2;
          return i2 *= 128, o2 >= i2 && (o2 -= Math.pow(2, 8 * t3)), o2;
        }, c.prototype.readInt8 = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 1, this.length), 128 & this[e3] ? -1 * (255 - this[e3] + 1) : this[e3];
        }, c.prototype.readInt16LE = function(e3, t3) {
          e3 >>>= 0, t3 || U(e3, 2, this.length);
          const r3 = this[e3] | this[e3 + 1] << 8;
          return 32768 & r3 ? 4294901760 | r3 : r3;
        }, c.prototype.readInt16BE = function(e3, t3) {
          e3 >>>= 0, t3 || U(e3, 2, this.length);
          const r3 = this[e3 + 1] | this[e3] << 8;
          return 32768 & r3 ? 4294901760 | r3 : r3;
        }, c.prototype.readInt32LE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), this[e3] | this[e3 + 1] << 8 | this[e3 + 2] << 16 | this[e3 + 3] << 24;
        }, c.prototype.readInt32BE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), this[e3] << 24 | this[e3 + 1] << 16 | this[e3 + 2] << 8 | this[e3 + 3];
        }, c.prototype.readBigInt64LE = Y((function(e3) {
          $(e3 >>>= 0, "offset");
          const t3 = this[e3], r3 = this[e3 + 7];
          void 0 !== t3 && void 0 !== r3 || V(e3, this.length - 8);
          const n2 = this[e3 + 4] + 256 * this[e3 + 5] + 65536 * this[e3 + 6] + (r3 << 24);
          return (BigInt(n2) << BigInt(32)) + BigInt(t3 + 256 * this[++e3] + 65536 * this[++e3] + this[++e3] * 2 ** 24);
        })), c.prototype.readBigInt64BE = Y((function(e3) {
          $(e3 >>>= 0, "offset");
          const t3 = this[e3], r3 = this[e3 + 7];
          void 0 !== t3 && void 0 !== r3 || V(e3, this.length - 8);
          const n2 = (t3 << 24) + 65536 * this[++e3] + 256 * this[++e3] + this[++e3];
          return (BigInt(n2) << BigInt(32)) + BigInt(this[++e3] * 2 ** 24 + 65536 * this[++e3] + 256 * this[++e3] + r3);
        })), c.prototype.readFloatLE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), i.read(this, e3, true, 23, 4);
        }, c.prototype.readFloatBE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 4, this.length), i.read(this, e3, false, 23, 4);
        }, c.prototype.readDoubleLE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 8, this.length), i.read(this, e3, true, 52, 8);
        }, c.prototype.readDoubleBE = function(e3, t3) {
          return e3 >>>= 0, t3 || U(e3, 8, this.length), i.read(this, e3, false, 52, 8);
        }, c.prototype.writeUintLE = c.prototype.writeUIntLE = function(e3, t3, r3, n2) {
          e3 = +e3, t3 >>>= 0, r3 >>>= 0, n2 || P(this, e3, t3, r3, Math.pow(2, 8 * r3) - 1, 0);
          let i2 = 1, o2 = 0;
          for (this[t3] = 255 & e3; ++o2 < r3 && (i2 *= 256); ) this[t3 + o2] = e3 / i2 & 255;
          return t3 + r3;
        }, c.prototype.writeUintBE = c.prototype.writeUIntBE = function(e3, t3, r3, n2) {
          e3 = +e3, t3 >>>= 0, r3 >>>= 0, n2 || P(this, e3, t3, r3, Math.pow(2, 8 * r3) - 1, 0);
          let i2 = r3 - 1, o2 = 1;
          for (this[t3 + i2] = 255 & e3; --i2 >= 0 && (o2 *= 256); ) this[t3 + i2] = e3 / o2 & 255;
          return t3 + r3;
        }, c.prototype.writeUint8 = c.prototype.writeUInt8 = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 1, 255, 0), this[t3] = 255 & e3, t3 + 1;
        }, c.prototype.writeUint16LE = c.prototype.writeUInt16LE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 2, 65535, 0), this[t3] = 255 & e3, this[t3 + 1] = e3 >>> 8, t3 + 2;
        }, c.prototype.writeUint16BE = c.prototype.writeUInt16BE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 2, 65535, 0), this[t3] = e3 >>> 8, this[t3 + 1] = 255 & e3, t3 + 2;
        }, c.prototype.writeUint32LE = c.prototype.writeUInt32LE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 4, 4294967295, 0), this[t3 + 3] = e3 >>> 24, this[t3 + 2] = e3 >>> 16, this[t3 + 1] = e3 >>> 8, this[t3] = 255 & e3, t3 + 4;
        }, c.prototype.writeUint32BE = c.prototype.writeUInt32BE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 4, 4294967295, 0), this[t3] = e3 >>> 24, this[t3 + 1] = e3 >>> 16, this[t3 + 2] = e3 >>> 8, this[t3 + 3] = 255 & e3, t3 + 4;
        }, c.prototype.writeBigUInt64LE = Y((function(e3, t3 = 0) {
          return O(this, e3, t3, BigInt(0), BigInt("0xffffffffffffffff"));
        })), c.prototype.writeBigUInt64BE = Y((function(e3, t3 = 0) {
          return R(this, e3, t3, BigInt(0), BigInt("0xffffffffffffffff"));
        })), c.prototype.writeIntLE = function(e3, t3, r3, n2) {
          if (e3 = +e3, t3 >>>= 0, !n2) {
            const n3 = Math.pow(2, 8 * r3 - 1);
            P(this, e3, t3, r3, n3 - 1, -n3);
          }
          let i2 = 0, o2 = 1, s2 = 0;
          for (this[t3] = 255 & e3; ++i2 < r3 && (o2 *= 256); ) e3 < 0 && 0 === s2 && 0 !== this[t3 + i2 - 1] && (s2 = 1), this[t3 + i2] = (e3 / o2 | 0) - s2 & 255;
          return t3 + r3;
        }, c.prototype.writeIntBE = function(e3, t3, r3, n2) {
          if (e3 = +e3, t3 >>>= 0, !n2) {
            const n3 = Math.pow(2, 8 * r3 - 1);
            P(this, e3, t3, r3, n3 - 1, -n3);
          }
          let i2 = r3 - 1, o2 = 1, s2 = 0;
          for (this[t3 + i2] = 255 & e3; --i2 >= 0 && (o2 *= 256); ) e3 < 0 && 0 === s2 && 0 !== this[t3 + i2 + 1] && (s2 = 1), this[t3 + i2] = (e3 / o2 | 0) - s2 & 255;
          return t3 + r3;
        }, c.prototype.writeInt8 = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 1, 127, -128), e3 < 0 && (e3 = 255 + e3 + 1), this[t3] = 255 & e3, t3 + 1;
        }, c.prototype.writeInt16LE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 2, 32767, -32768), this[t3] = 255 & e3, this[t3 + 1] = e3 >>> 8, t3 + 2;
        }, c.prototype.writeInt16BE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 2, 32767, -32768), this[t3] = e3 >>> 8, this[t3 + 1] = 255 & e3, t3 + 2;
        }, c.prototype.writeInt32LE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 4, 2147483647, -2147483648), this[t3] = 255 & e3, this[t3 + 1] = e3 >>> 8, this[t3 + 2] = e3 >>> 16, this[t3 + 3] = e3 >>> 24, t3 + 4;
        }, c.prototype.writeInt32BE = function(e3, t3, r3) {
          return e3 = +e3, t3 >>>= 0, r3 || P(this, e3, t3, 4, 2147483647, -2147483648), e3 < 0 && (e3 = 4294967295 + e3 + 1), this[t3] = e3 >>> 24, this[t3 + 1] = e3 >>> 16, this[t3 + 2] = e3 >>> 8, this[t3 + 3] = 255 & e3, t3 + 4;
        }, c.prototype.writeBigInt64LE = Y((function(e3, t3 = 0) {
          return O(this, e3, t3, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
        })), c.prototype.writeBigInt64BE = Y((function(e3, t3 = 0) {
          return R(this, e3, t3, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
        })), c.prototype.writeFloatLE = function(e3, t3, r3) {
          return L(this, e3, t3, true, r3);
        }, c.prototype.writeFloatBE = function(e3, t3, r3) {
          return L(this, e3, t3, false, r3);
        }, c.prototype.writeDoubleLE = function(e3, t3, r3) {
          return j(this, e3, t3, true, r3);
        }, c.prototype.writeDoubleBE = function(e3, t3, r3) {
          return j(this, e3, t3, false, r3);
        }, c.prototype.copy = function(e3, t3, r3, n2) {
          if (!c.isBuffer(e3)) throw new TypeError("argument should be a Buffer");
          if (r3 || (r3 = 0), n2 || 0 === n2 || (n2 = this.length), t3 >= e3.length && (t3 = e3.length), t3 || (t3 = 0), n2 > 0 && n2 < r3 && (n2 = r3), n2 === r3) return 0;
          if (0 === e3.length || 0 === this.length) return 0;
          if (t3 < 0) throw new RangeError("targetStart out of bounds");
          if (r3 < 0 || r3 >= this.length) throw new RangeError("Index out of range");
          if (n2 < 0) throw new RangeError("sourceEnd out of bounds");
          n2 > this.length && (n2 = this.length), e3.length - t3 < n2 - r3 && (n2 = e3.length - t3 + r3);
          const i2 = n2 - r3;
          return this === e3 && "function" == typeof Uint8Array.prototype.copyWithin ? this.copyWithin(t3, r3, n2) : Uint8Array.prototype.set.call(e3, this.subarray(r3, n2), t3), i2;
        }, c.prototype.fill = function(e3, t3, r3, n2) {
          if ("string" == typeof e3) {
            if ("string" == typeof t3 ? (n2 = t3, t3 = 0, r3 = this.length) : "string" == typeof r3 && (n2 = r3, r3 = this.length), void 0 !== n2 && "string" != typeof n2) throw new TypeError("encoding must be a string");
            if ("string" == typeof n2 && !c.isEncoding(n2)) throw new TypeError("Unknown encoding: " + n2);
            if (1 === e3.length) {
              const t4 = e3.charCodeAt(0);
              ("utf8" === n2 && t4 < 128 || "latin1" === n2) && (e3 = t4);
            }
          } else "number" == typeof e3 ? e3 &= 255 : "boolean" == typeof e3 && (e3 = Number(e3));
          if (t3 < 0 || this.length < t3 || this.length < r3) throw new RangeError("Out of range index");
          if (r3 <= t3) return this;
          let i2;
          if (t3 >>>= 0, r3 = void 0 === r3 ? this.length : r3 >>> 0, e3 || (e3 = 0), "number" == typeof e3) for (i2 = t3; i2 < r3; ++i2) this[i2] = e3;
          else {
            const o2 = c.isBuffer(e3) ? e3 : c.from(e3, n2), s2 = o2.length;
            if (0 === s2) throw new TypeError('The value "' + e3 + '" is invalid for argument "value"');
            for (i2 = 0; i2 < r3 - t3; ++i2) this[i2 + t3] = o2[i2 % s2];
          }
          return this;
        };
        const D = {};
        function F(e3, t3, r3) {
          D[e3] = class extends r3 {
            constructor() {
              super(), Object.defineProperty(this, "message", { value: t3.apply(this, arguments), writable: true, configurable: true }), this.name = `${this.name} [${e3}]`, this.stack, delete this.name;
            }
            get code() {
              return e3;
            }
            set code(e4) {
              Object.defineProperty(this, "code", { configurable: true, enumerable: true, value: e4, writable: true });
            }
            toString() {
              return `${this.name} [${e3}]: ${this.message}`;
            }
          };
        }
        function H(e3) {
          let t3 = "", r3 = e3.length;
          const n2 = "-" === e3[0] ? 1 : 0;
          for (; r3 >= n2 + 4; r3 -= 3) t3 = `_${e3.slice(r3 - 3, r3)}${t3}`;
          return `${e3.slice(0, r3)}${t3}`;
        }
        function q(e3, t3, r3, n2, i2, o2) {
          if (e3 > r3 || e3 < t3) {
            const n3 = "bigint" == typeof t3 ? "n" : "";
            let i3;
            throw i3 = o2 > 3 ? 0 === t3 || t3 === BigInt(0) ? `>= 0${n3} and < 2${n3} ** ${8 * (o2 + 1)}${n3}` : `>= -(2${n3} ** ${8 * (o2 + 1) - 1}${n3}) and < 2 ** ${8 * (o2 + 1) - 1}${n3}` : `>= ${t3}${n3} and <= ${r3}${n3}`, new D.ERR_OUT_OF_RANGE("value", i3, e3);
          }
          !(function(e4, t4, r4) {
            $(t4, "offset"), void 0 !== e4[t4] && void 0 !== e4[t4 + r4] || V(t4, e4.length - (r4 + 1));
          })(n2, i2, o2);
        }
        function $(e3, t3) {
          if ("number" != typeof e3) throw new D.ERR_INVALID_ARG_TYPE(t3, "number", e3);
        }
        function V(e3, t3, r3) {
          if (Math.floor(e3) !== e3) throw $(e3, r3), new D.ERR_OUT_OF_RANGE(r3 || "offset", "an integer", e3);
          if (t3 < 0) throw new D.ERR_BUFFER_OUT_OF_BOUNDS();
          throw new D.ERR_OUT_OF_RANGE(r3 || "offset", `>= ${r3 ? 1 : 0} and <= ${t3}`, e3);
        }
        F("ERR_BUFFER_OUT_OF_BOUNDS", (function(e3) {
          return e3 ? `${e3} is outside of buffer bounds` : "Attempt to access memory outside buffer bounds";
        }), RangeError), F("ERR_INVALID_ARG_TYPE", (function(e3, t3) {
          return `The "${e3}" argument must be of type number. Received type ${typeof t3}`;
        }), TypeError), F("ERR_OUT_OF_RANGE", (function(e3, t3, r3) {
          let n2 = `The value of "${e3}" is out of range.`, i2 = r3;
          return Number.isInteger(r3) && Math.abs(r3) > 2 ** 32 ? i2 = H(String(r3)) : "bigint" == typeof r3 && (i2 = String(r3), (r3 > BigInt(2) ** BigInt(32) || r3 < -(BigInt(2) ** BigInt(32))) && (i2 = H(i2)), i2 += "n"), n2 += ` It must be ${t3}. Received ${i2}`, n2;
        }), RangeError);
        const G = /[^+/0-9A-Za-z-_]/g;
        function z(e3, t3) {
          let r3;
          t3 = t3 || 1 / 0;
          const n2 = e3.length;
          let i2 = null;
          const o2 = [];
          for (let s2 = 0; s2 < n2; ++s2) {
            if (r3 = e3.charCodeAt(s2), r3 > 55295 && r3 < 57344) {
              if (!i2) {
                if (r3 > 56319) {
                  (t3 -= 3) > -1 && o2.push(239, 191, 189);
                  continue;
                }
                if (s2 + 1 === n2) {
                  (t3 -= 3) > -1 && o2.push(239, 191, 189);
                  continue;
                }
                i2 = r3;
                continue;
              }
              if (r3 < 56320) {
                (t3 -= 3) > -1 && o2.push(239, 191, 189), i2 = r3;
                continue;
              }
              r3 = 65536 + (i2 - 55296 << 10 | r3 - 56320);
            } else i2 && (t3 -= 3) > -1 && o2.push(239, 191, 189);
            if (i2 = null, r3 < 128) {
              if ((t3 -= 1) < 0) break;
              o2.push(r3);
            } else if (r3 < 2048) {
              if ((t3 -= 2) < 0) break;
              o2.push(r3 >> 6 | 192, 63 & r3 | 128);
            } else if (r3 < 65536) {
              if ((t3 -= 3) < 0) break;
              o2.push(r3 >> 12 | 224, r3 >> 6 & 63 | 128, 63 & r3 | 128);
            } else {
              if (!(r3 < 1114112)) throw new Error("Invalid code point");
              if ((t3 -= 4) < 0) break;
              o2.push(r3 >> 18 | 240, r3 >> 12 & 63 | 128, r3 >> 6 & 63 | 128, 63 & r3 | 128);
            }
          }
          return o2;
        }
        function K(e3) {
          return n.toByteArray((function(e4) {
            if ((e4 = (e4 = e4.split("=")[0]).trim().replace(G, "")).length < 2) return "";
            for (; e4.length % 4 != 0; ) e4 += "=";
            return e4;
          })(e3));
        }
        function W(e3, t3, r3, n2) {
          let i2;
          for (i2 = 0; i2 < n2 && !(i2 + r3 >= t3.length || i2 >= e3.length); ++i2) t3[i2 + r3] = e3[i2];
          return i2;
        }
        function J(e3, t3) {
          return e3 instanceof t3 || null != e3 && null != e3.constructor && null != e3.constructor.name && e3.constructor.name === t3.name;
        }
        function Z(e3) {
          return e3 != e3;
        }
        const X = (function() {
          const e3 = "0123456789abcdef", t3 = new Array(256);
          for (let r3 = 0; r3 < 16; ++r3) {
            const n2 = 16 * r3;
            for (let i2 = 0; i2 < 16; ++i2) t3[n2 + i2] = e3[r3] + e3[i2];
          }
          return t3;
        })();
        function Y(e3) {
          return "undefined" == typeof BigInt ? Q : e3;
        }
        function Q() {
          throw new Error("BigInt not supported");
        }
      }, 4705: (e2, t2, r2) => {
        var n = r2(6608).Buffer, i = r2(3803).Transform, o = r2(6704).I;
        function s(e3) {
          i.call(this), this.hashMode = "string" == typeof e3, this.hashMode ? this[e3] = this._finalOrDigest : this.final = this._finalOrDigest, this._final && (this.__final = this._final, this._final = null), this._decoder = null, this._encoding = null;
        }
        r2(1193)(s, i), s.prototype.update = function(e3, t3, r3) {
          "string" == typeof e3 && (e3 = n.from(e3, t3));
          var i2 = this._update(e3);
          return this.hashMode ? this : (r3 && (i2 = this._toString(i2, r3)), i2);
        }, s.prototype.setAutoPadding = function() {
        }, s.prototype.getAuthTag = function() {
          throw new Error("trying to get auth tag in unsupported state");
        }, s.prototype.setAuthTag = function() {
          throw new Error("trying to set auth tag in unsupported state");
        }, s.prototype.setAAD = function() {
          throw new Error("trying to set aad in unsupported state");
        }, s.prototype._transform = function(e3, t3, r3) {
          var n2;
          try {
            this.hashMode ? this._update(e3) : this.push(this._update(e3));
          } catch (e4) {
            n2 = e4;
          } finally {
            r3(n2);
          }
        }, s.prototype._flush = function(e3) {
          var t3;
          try {
            this.push(this.__final());
          } catch (e4) {
            t3 = e4;
          }
          e3(t3);
        }, s.prototype._finalOrDigest = function(e3) {
          var t3 = this.__final() || n.alloc(0);
          return e3 && (t3 = this._toString(t3, e3, true)), t3;
        }, s.prototype._toString = function(e3, t3, r3) {
          if (this._decoder || (this._decoder = new o(t3), this._encoding = t3), this._encoding !== t3) throw new Error("can't switch encodings");
          var n2 = this._decoder.write(e3);
          return r3 && (n2 += this._decoder.end()), n2;
        }, e2.exports = s;
      }, 9520: (e2, t2, r2) => {
        var n = r2(3071), i = r2(4619);
        e2.exports = function(e3) {
          return new s(e3);
        };
        var o = { secp256k1: { name: "secp256k1", byteLength: 32 }, secp224r1: { name: "p224", byteLength: 28 }, prime256v1: { name: "p256", byteLength: 32 }, prime192v1: { name: "p192", byteLength: 24 }, ed25519: { name: "ed25519", byteLength: 32 }, secp384r1: { name: "p384", byteLength: 48 }, secp521r1: { name: "p521", byteLength: 66 } };
        function s(e3) {
          this.curveType = o[e3], this.curveType || (this.curveType = { name: e3 }), this.curve = new n.ec(this.curveType.name), this.keys = void 0;
        }
        function a(e3, t3, r3) {
          Array.isArray(e3) || (e3 = e3.toArray());
          var n2 = new Buffer(e3);
          if (r3 && n2.length < r3) {
            var i2 = new Buffer(r3 - n2.length);
            i2.fill(0), n2 = Buffer.concat([i2, n2]);
          }
          return t3 ? n2.toString(t3) : n2;
        }
        o.p224 = o.secp224r1, o.p256 = o.secp256r1 = o.prime256v1, o.p192 = o.secp192r1 = o.prime192v1, o.p384 = o.secp384r1, o.p521 = o.secp521r1, s.prototype.generateKeys = function(e3, t3) {
          return this.keys = this.curve.genKeyPair(), this.getPublicKey(e3, t3);
        }, s.prototype.computeSecret = function(e3, t3, r3) {
          return t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3)), a(this.curve.keyFromPublic(e3).getPublic().mul(this.keys.getPrivate()).getX(), r3, this.curveType.byteLength);
        }, s.prototype.getPublicKey = function(e3, t3) {
          var r3 = this.keys.getPublic("compressed" === t3, true);
          return "hybrid" === t3 && (r3[r3.length - 1] % 2 ? r3[0] = 7 : r3[0] = 6), a(r3, e3);
        }, s.prototype.getPrivateKey = function(e3) {
          return a(this.keys.getPrivate(), e3);
        }, s.prototype.setPublicKey = function(e3, t3) {
          return t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3)), this.keys._importPublic(e3), this;
        }, s.prototype.setPrivateKey = function(e3, t3) {
          t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3));
          var r3 = new i(e3);
          return r3 = r3.toString(16), this.keys = this.curve.genKeyPair(), this.keys._importPrivate(r3), this;
        };
      }, 8955: (e2, t2, r2) => {
        "use strict";
        var n = r2(1193), i = r2(5035), o = r2(3934), s = r2(5244), a = r2(4705);
        function c(e3) {
          a.call(this, "digest"), this._hash = e3;
        }
        n(c, a), c.prototype._update = function(e3) {
          this._hash.update(e3);
        }, c.prototype._final = function() {
          return this._hash.digest();
        }, e2.exports = function(e3) {
          return "md5" === (e3 = e3.toLowerCase()) ? new i() : "rmd160" === e3 || "ripemd160" === e3 ? new o() : new c(s(e3));
        };
      }, 6159: (e2, t2, r2) => {
        var n = r2(5035);
        e2.exports = function(e3) {
          return new n().update(e3).digest();
        };
      }, 3053: (e2, t2, r2) => {
        "use strict";
        var n = r2(1193), i = r2(670), o = r2(4705), s = r2(6608).Buffer, a = r2(6159), c = r2(3934), u = r2(5244), d = s.alloc(128);
        function f(e3, t3) {
          o.call(this, "digest"), "string" == typeof t3 && (t3 = s.from(t3));
          var r3 = "sha512" === e3 || "sha384" === e3 ? 128 : 64;
          this._alg = e3, this._key = t3, t3.length > r3 ? t3 = ("rmd160" === e3 ? new c() : u(e3)).update(t3).digest() : t3.length < r3 && (t3 = s.concat([t3, d], r3));
          for (var n2 = this._ipad = s.allocUnsafe(r3), i2 = this._opad = s.allocUnsafe(r3), a2 = 0; a2 < r3; a2++) n2[a2] = 54 ^ t3[a2], i2[a2] = 92 ^ t3[a2];
          this._hash = "rmd160" === e3 ? new c() : u(e3), this._hash.update(n2);
        }
        n(f, o), f.prototype._update = function(e3) {
          this._hash.update(e3);
        }, f.prototype._final = function() {
          var e3 = this._hash.digest();
          return ("rmd160" === this._alg ? new c() : u(this._alg)).update(this._opad).update(e3).digest();
        }, e2.exports = function(e3, t3) {
          return "rmd160" === (e3 = e3.toLowerCase()) || "ripemd160" === e3 ? new f("rmd160", t3) : "md5" === e3 ? new i(a, t3) : new f(e3, t3);
        };
      }, 670: (e2, t2, r2) => {
        "use strict";
        var n = r2(1193), i = r2(6608).Buffer, o = r2(4705), s = i.alloc(128), a = 64;
        function c(e3, t3) {
          o.call(this, "digest"), "string" == typeof t3 && (t3 = i.from(t3)), this._alg = e3, this._key = t3, t3.length > a ? t3 = e3(t3) : t3.length < a && (t3 = i.concat([t3, s], a));
          for (var r3 = this._ipad = i.allocUnsafe(a), n2 = this._opad = i.allocUnsafe(a), c2 = 0; c2 < a; c2++) r3[c2] = 54 ^ t3[c2], n2[c2] = 92 ^ t3[c2];
          this._hash = [r3];
        }
        n(c, o), c.prototype._update = function(e3) {
          this._hash.push(e3);
        }, c.prototype._final = function() {
          var e3 = this._alg(i.concat(this._hash));
          return this._alg(i.concat([this._opad, e3]));
        }, e2.exports = c;
      }, 9114: function() {
        !(function(e2) {
          !(function(t2) {
            var r2 = "URLSearchParams" in e2, n = "Symbol" in e2 && "iterator" in Symbol, i = "FileReader" in e2 && "Blob" in e2 && (function() {
              try {
                return new Blob(), true;
              } catch (e3) {
                return false;
              }
            })(), o = "FormData" in e2, s = "ArrayBuffer" in e2;
            if (s) var a = ["[object Int8Array]", "[object Uint8Array]", "[object Uint8ClampedArray]", "[object Int16Array]", "[object Uint16Array]", "[object Int32Array]", "[object Uint32Array]", "[object Float32Array]", "[object Float64Array]"], c = ArrayBuffer.isView || function(e3) {
              return e3 && a.indexOf(Object.prototype.toString.call(e3)) > -1;
            };
            function u(e3) {
              if ("string" != typeof e3 && (e3 = String(e3)), /[^a-z0-9\-#$%&'*+.^_`|~]/i.test(e3)) throw new TypeError("Invalid character in header field name");
              return e3.toLowerCase();
            }
            function d(e3) {
              return "string" != typeof e3 && (e3 = String(e3)), e3;
            }
            function f(e3) {
              var t3 = { next: function() {
                var t4 = e3.shift();
                return { done: void 0 === t4, value: t4 };
              } };
              return n && (t3[Symbol.iterator] = function() {
                return t3;
              }), t3;
            }
            function h(e3) {
              this.map = {}, e3 instanceof h ? e3.forEach((function(e4, t3) {
                this.append(t3, e4);
              }), this) : Array.isArray(e3) ? e3.forEach((function(e4) {
                this.append(e4[0], e4[1]);
              }), this) : e3 && Object.getOwnPropertyNames(e3).forEach((function(t3) {
                this.append(t3, e3[t3]);
              }), this);
            }
            function l(e3) {
              if (e3.bodyUsed) return Promise.reject(new TypeError("Already read"));
              e3.bodyUsed = true;
            }
            function p(e3) {
              return new Promise((function(t3, r3) {
                e3.onload = function() {
                  t3(e3.result);
                }, e3.onerror = function() {
                  r3(e3.error);
                };
              }));
            }
            function b(e3) {
              var t3 = new FileReader(), r3 = p(t3);
              return t3.readAsArrayBuffer(e3), r3;
            }
            function y(e3) {
              if (e3.slice) return e3.slice(0);
              var t3 = new Uint8Array(e3.byteLength);
              return t3.set(new Uint8Array(e3)), t3.buffer;
            }
            function m() {
              return this.bodyUsed = false, this._initBody = function(e3) {
                var t3;
                this._bodyInit = e3, e3 ? "string" == typeof e3 ? this._bodyText = e3 : i && Blob.prototype.isPrototypeOf(e3) ? this._bodyBlob = e3 : o && FormData.prototype.isPrototypeOf(e3) ? this._bodyFormData = e3 : r2 && URLSearchParams.prototype.isPrototypeOf(e3) ? this._bodyText = e3.toString() : s && i && (t3 = e3) && DataView.prototype.isPrototypeOf(t3) ? (this._bodyArrayBuffer = y(e3.buffer), this._bodyInit = new Blob([this._bodyArrayBuffer])) : s && (ArrayBuffer.prototype.isPrototypeOf(e3) || c(e3)) ? this._bodyArrayBuffer = y(e3) : this._bodyText = e3 = Object.prototype.toString.call(e3) : this._bodyText = "", this.headers.get("content-type") || ("string" == typeof e3 ? this.headers.set("content-type", "text/plain;charset=UTF-8") : this._bodyBlob && this._bodyBlob.type ? this.headers.set("content-type", this._bodyBlob.type) : r2 && URLSearchParams.prototype.isPrototypeOf(e3) && this.headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8"));
              }, i && (this.blob = function() {
                var e3 = l(this);
                if (e3) return e3;
                if (this._bodyBlob) return Promise.resolve(this._bodyBlob);
                if (this._bodyArrayBuffer) return Promise.resolve(new Blob([this._bodyArrayBuffer]));
                if (this._bodyFormData) throw new Error("could not read FormData body as blob");
                return Promise.resolve(new Blob([this._bodyText]));
              }, this.arrayBuffer = function() {
                return this._bodyArrayBuffer ? l(this) || Promise.resolve(this._bodyArrayBuffer) : this.blob().then(b);
              }), this.text = function() {
                var e3, t3, r3, n2 = l(this);
                if (n2) return n2;
                if (this._bodyBlob) return e3 = this._bodyBlob, r3 = p(t3 = new FileReader()), t3.readAsText(e3), r3;
                if (this._bodyArrayBuffer) return Promise.resolve((function(e4) {
                  for (var t4 = new Uint8Array(e4), r4 = new Array(t4.length), n3 = 0; n3 < t4.length; n3++) r4[n3] = String.fromCharCode(t4[n3]);
                  return r4.join("");
                })(this._bodyArrayBuffer));
                if (this._bodyFormData) throw new Error("could not read FormData body as text");
                return Promise.resolve(this._bodyText);
              }, o && (this.formData = function() {
                return this.text().then(w);
              }), this.json = function() {
                return this.text().then(JSON.parse);
              }, this;
            }
            h.prototype.append = function(e3, t3) {
              e3 = u(e3), t3 = d(t3);
              var r3 = this.map[e3];
              this.map[e3] = r3 ? r3 + ", " + t3 : t3;
            }, h.prototype.delete = function(e3) {
              delete this.map[u(e3)];
            }, h.prototype.get = function(e3) {
              return e3 = u(e3), this.has(e3) ? this.map[e3] : null;
            }, h.prototype.has = function(e3) {
              return this.map.hasOwnProperty(u(e3));
            }, h.prototype.set = function(e3, t3) {
              this.map[u(e3)] = d(t3);
            }, h.prototype.forEach = function(e3, t3) {
              for (var r3 in this.map) this.map.hasOwnProperty(r3) && e3.call(t3, this.map[r3], r3, this);
            }, h.prototype.keys = function() {
              var e3 = [];
              return this.forEach((function(t3, r3) {
                e3.push(r3);
              })), f(e3);
            }, h.prototype.values = function() {
              var e3 = [];
              return this.forEach((function(t3) {
                e3.push(t3);
              })), f(e3);
            }, h.prototype.entries = function() {
              var e3 = [];
              return this.forEach((function(t3, r3) {
                e3.push([r3, t3]);
              })), f(e3);
            }, n && (h.prototype[Symbol.iterator] = h.prototype.entries);
            var g = ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"];
            function v(e3, t3) {
              var r3, n2, i2 = (t3 = t3 || {}).body;
              if (e3 instanceof v) {
                if (e3.bodyUsed) throw new TypeError("Already read");
                this.url = e3.url, this.credentials = e3.credentials, t3.headers || (this.headers = new h(e3.headers)), this.method = e3.method, this.mode = e3.mode, this.signal = e3.signal, i2 || null == e3._bodyInit || (i2 = e3._bodyInit, e3.bodyUsed = true);
              } else this.url = String(e3);
              if (this.credentials = t3.credentials || this.credentials || "same-origin", !t3.headers && this.headers || (this.headers = new h(t3.headers)), this.method = (n2 = (r3 = t3.method || this.method || "GET").toUpperCase(), g.indexOf(n2) > -1 ? n2 : r3), this.mode = t3.mode || this.mode || null, this.signal = t3.signal || this.signal, this.referrer = null, ("GET" === this.method || "HEAD" === this.method) && i2) throw new TypeError("Body not allowed for GET or HEAD requests");
              this._initBody(i2);
            }
            function w(e3) {
              var t3 = new FormData();
              return e3.trim().split("&").forEach((function(e4) {
                if (e4) {
                  var r3 = e4.split("="), n2 = r3.shift().replace(/\+/g, " "), i2 = r3.join("=").replace(/\+/g, " ");
                  t3.append(decodeURIComponent(n2), decodeURIComponent(i2));
                }
              })), t3;
            }
            function _(e3, t3) {
              t3 || (t3 = {}), this.type = "default", this.status = void 0 === t3.status ? 200 : t3.status, this.ok = this.status >= 200 && this.status < 300, this.statusText = "statusText" in t3 ? t3.statusText : "OK", this.headers = new h(t3.headers), this.url = t3.url || "", this._initBody(e3);
            }
            v.prototype.clone = function() {
              return new v(this, { body: this._bodyInit });
            }, m.call(v.prototype), m.call(_.prototype), _.prototype.clone = function() {
              return new _(this._bodyInit, { status: this.status, statusText: this.statusText, headers: new h(this.headers), url: this.url });
            }, _.error = function() {
              var e3 = new _(null, { status: 0, statusText: "" });
              return e3.type = "error", e3;
            };
            var A = [301, 302, 303, 307, 308];
            _.redirect = function(e3, t3) {
              if (-1 === A.indexOf(t3)) throw new RangeError("Invalid status code");
              return new _(null, { status: t3, headers: { location: e3 } });
            }, t2.DOMException = e2.DOMException;
            try {
              new t2.DOMException();
            } catch (e3) {
              t2.DOMException = function(e4, t3) {
                this.message = e4, this.name = t3;
                var r3 = Error(e4);
                this.stack = r3.stack;
              }, t2.DOMException.prototype = Object.create(Error.prototype), t2.DOMException.prototype.constructor = t2.DOMException;
            }
            function S(e3, r3) {
              return new Promise((function(n2, o2) {
                var s2 = new v(e3, r3);
                if (s2.signal && s2.signal.aborted) return o2(new t2.DOMException("Aborted", "AbortError"));
                var a2 = new XMLHttpRequest();
                function c2() {
                  a2.abort();
                }
                a2.onload = function() {
                  var e4, t3, r4 = { status: a2.status, statusText: a2.statusText, headers: (e4 = a2.getAllResponseHeaders() || "", t3 = new h(), e4.replace(/\r?\n[\t ]+/g, " ").split(/\r?\n/).forEach((function(e5) {
                    var r5 = e5.split(":"), n3 = r5.shift().trim();
                    if (n3) {
                      var i3 = r5.join(":").trim();
                      t3.append(n3, i3);
                    }
                  })), t3) };
                  r4.url = "responseURL" in a2 ? a2.responseURL : r4.headers.get("X-Request-URL");
                  var i2 = "response" in a2 ? a2.response : a2.responseText;
                  n2(new _(i2, r4));
                }, a2.onerror = function() {
                  o2(new TypeError("Network request failed"));
                }, a2.ontimeout = function() {
                  o2(new TypeError("Network request failed"));
                }, a2.onabort = function() {
                  o2(new t2.DOMException("Aborted", "AbortError"));
                }, a2.open(s2.method, s2.url, true), "include" === s2.credentials ? a2.withCredentials = true : "omit" === s2.credentials && (a2.withCredentials = false), "responseType" in a2 && i && (a2.responseType = "blob"), s2.headers.forEach((function(e4, t3) {
                  a2.setRequestHeader(t3, e4);
                })), s2.signal && (s2.signal.addEventListener("abort", c2), a2.onreadystatechange = function() {
                  4 === a2.readyState && s2.signal.removeEventListener("abort", c2);
                }), a2.send(void 0 === s2._bodyInit ? null : s2._bodyInit);
              }));
            }
            S.polyfill = true, e2.fetch || (e2.fetch = S, e2.Headers = h, e2.Request = v, e2.Response = _), t2.Headers = h, t2.Request = v, t2.Response = _, t2.fetch = S, Object.defineProperty(t2, "__esModule", { value: true });
          })({});
        })("undefined" != typeof self ? self : this);
      }, 4062: (e2, t2, r2) => {
        "use strict";
        t2.randomBytes = t2.rng = t2.pseudoRandomBytes = t2.prng = r2(2869), t2.createHash = t2.Hash = r2(8955), t2.createHmac = t2.Hmac = r2(3053);
        var n = r2(8950), i = Object.keys(n), o = ["sha1", "sha224", "sha256", "sha384", "sha512", "md5", "rmd160"].concat(i);
        t2.getHashes = function() {
          return o;
        };
        var s = r2(3166);
        t2.pbkdf2 = s.pbkdf2, t2.pbkdf2Sync = s.pbkdf2Sync;
        var a = r2(8350);
        t2.Cipher = a.Cipher, t2.createCipher = a.createCipher, t2.Cipheriv = a.Cipheriv, t2.createCipheriv = a.createCipheriv, t2.Decipher = a.Decipher, t2.createDecipher = a.createDecipher, t2.Decipheriv = a.Decipheriv, t2.createDecipheriv = a.createDecipheriv, t2.getCiphers = a.getCiphers, t2.listCiphers = a.listCiphers;
        var c = r2(8216);
        t2.DiffieHellmanGroup = c.DiffieHellmanGroup, t2.createDiffieHellmanGroup = c.createDiffieHellmanGroup, t2.getDiffieHellman = c.getDiffieHellman, t2.createDiffieHellman = c.createDiffieHellman, t2.DiffieHellman = c.DiffieHellman;
        var u = r2(6105);
        t2.createSign = u.createSign, t2.Sign = u.Sign, t2.createVerify = u.createVerify, t2.Verify = u.Verify, t2.createECDH = r2(9520);
        var d = r2(2211);
        t2.publicEncrypt = d.publicEncrypt, t2.privateEncrypt = d.privateEncrypt, t2.publicDecrypt = d.publicDecrypt, t2.privateDecrypt = d.privateDecrypt;
        var f = r2(4925);
        t2.randomFill = f.randomFill, t2.randomFillSync = f.randomFillSync, t2.createCredentials = function() {
          throw new Error(["sorry, createCredentials is not implemented yet", "we accept pull requests", "https://github.com/crypto-browserify/crypto-browserify"].join("\n"));
        }, t2.constants = { DH_CHECK_P_NOT_SAFE_PRIME: 2, DH_CHECK_P_NOT_PRIME: 1, DH_UNABLE_TO_CHECK_GENERATOR: 4, DH_NOT_SUITABLE_GENERATOR: 8, NPN_ENABLED: 1, ALPN_ENABLED: 1, RSA_PKCS1_PADDING: 1, RSA_SSLV23_PADDING: 2, RSA_NO_PADDING: 3, RSA_PKCS1_OAEP_PADDING: 4, RSA_X931_PADDING: 5, RSA_PKCS1_PSS_PADDING: 6, POINT_CONVERSION_COMPRESSED: 2, POINT_CONVERSION_UNCOMPRESSED: 4, POINT_CONVERSION_HYBRID: 6 };
      }, 2398: (e2, t2, r2) => {
        "use strict";
        t2.utils = r2(1496), t2.Cipher = r2(5958), t2.DES = r2(9409), t2.CBC = r2(6779), t2.EDE = r2(6625);
      }, 6779: (e2, t2, r2) => {
        "use strict";
        var n = r2(5578), i = r2(1193), o = {};
        function s(e3) {
          n.equal(e3.length, 8, "Invalid IV length"), this.iv = new Array(8);
          for (var t3 = 0; t3 < this.iv.length; t3++) this.iv[t3] = e3[t3];
        }
        t2.instantiate = function(e3) {
          function t3(t4) {
            e3.call(this, t4), this._cbcInit();
          }
          i(t3, e3);
          for (var r3 = Object.keys(o), n2 = 0; n2 < r3.length; n2++) {
            var s2 = r3[n2];
            t3.prototype[s2] = o[s2];
          }
          return t3.create = function(e4) {
            return new t3(e4);
          }, t3;
        }, o._cbcInit = function() {
          var e3 = new s(this.options.iv);
          this._cbcState = e3;
        }, o._update = function(e3, t3, r3, n2) {
          var i2 = this._cbcState, o2 = this.constructor.super_.prototype, s2 = i2.iv;
          if ("encrypt" === this.type) {
            for (var a = 0; a < this.blockSize; a++) s2[a] ^= e3[t3 + a];
            for (o2._update.call(this, s2, 0, r3, n2), a = 0; a < this.blockSize; a++) s2[a] = r3[n2 + a];
          } else {
            for (o2._update.call(this, e3, t3, r3, n2), a = 0; a < this.blockSize; a++) r3[n2 + a] ^= s2[a];
            for (a = 0; a < this.blockSize; a++) s2[a] = e3[t3 + a];
          }
        };
      }, 5958: (e2, t2, r2) => {
        "use strict";
        var n = r2(5578);
        function i(e3) {
          this.options = e3, this.type = this.options.type, this.blockSize = 8, this._init(), this.buffer = new Array(this.blockSize), this.bufferOff = 0;
        }
        e2.exports = i, i.prototype._init = function() {
        }, i.prototype.update = function(e3) {
          return 0 === e3.length ? [] : "decrypt" === this.type ? this._updateDecrypt(e3) : this._updateEncrypt(e3);
        }, i.prototype._buffer = function(e3, t3) {
          for (var r3 = Math.min(this.buffer.length - this.bufferOff, e3.length - t3), n2 = 0; n2 < r3; n2++) this.buffer[this.bufferOff + n2] = e3[t3 + n2];
          return this.bufferOff += r3, r3;
        }, i.prototype._flushBuffer = function(e3, t3) {
          return this._update(this.buffer, 0, e3, t3), this.bufferOff = 0, this.blockSize;
        }, i.prototype._updateEncrypt = function(e3) {
          var t3 = 0, r3 = 0, n2 = (this.bufferOff + e3.length) / this.blockSize | 0, i2 = new Array(n2 * this.blockSize);
          0 !== this.bufferOff && (t3 += this._buffer(e3, t3), this.bufferOff === this.buffer.length && (r3 += this._flushBuffer(i2, r3)));
          for (var o = e3.length - (e3.length - t3) % this.blockSize; t3 < o; t3 += this.blockSize) this._update(e3, t3, i2, r3), r3 += this.blockSize;
          for (; t3 < e3.length; t3++, this.bufferOff++) this.buffer[this.bufferOff] = e3[t3];
          return i2;
        }, i.prototype._updateDecrypt = function(e3) {
          for (var t3 = 0, r3 = 0, n2 = Math.ceil((this.bufferOff + e3.length) / this.blockSize) - 1, i2 = new Array(n2 * this.blockSize); n2 > 0; n2--) t3 += this._buffer(e3, t3), r3 += this._flushBuffer(i2, r3);
          return t3 += this._buffer(e3, t3), i2;
        }, i.prototype.final = function(e3) {
          var t3, r3;
          return e3 && (t3 = this.update(e3)), r3 = "encrypt" === this.type ? this._finalEncrypt() : this._finalDecrypt(), t3 ? t3.concat(r3) : r3;
        }, i.prototype._pad = function(e3, t3) {
          if (0 === t3) return false;
          for (; t3 < e3.length; ) e3[t3++] = 0;
          return true;
        }, i.prototype._finalEncrypt = function() {
          if (!this._pad(this.buffer, this.bufferOff)) return [];
          var e3 = new Array(this.blockSize);
          return this._update(this.buffer, 0, e3, 0), e3;
        }, i.prototype._unpad = function(e3) {
          return e3;
        }, i.prototype._finalDecrypt = function() {
          n.equal(this.bufferOff, this.blockSize, "Not enough data to decrypt");
          var e3 = new Array(this.blockSize);
          return this._flushBuffer(e3, 0), this._unpad(e3);
        };
      }, 9409: (e2, t2, r2) => {
        "use strict";
        var n = r2(5578), i = r2(1193), o = r2(1496), s = r2(5958);
        function a() {
          this.tmp = new Array(2), this.keys = null;
        }
        function c(e3) {
          s.call(this, e3);
          var t3 = new a();
          this._desState = t3, this.deriveKeys(t3, e3.key);
        }
        i(c, s), e2.exports = c, c.create = function(e3) {
          return new c(e3);
        };
        var u = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
        c.prototype.deriveKeys = function(e3, t3) {
          e3.keys = new Array(32), n.equal(t3.length, this.blockSize, "Invalid key length");
          var r3 = o.readUInt32BE(t3, 0), i2 = o.readUInt32BE(t3, 4);
          o.pc1(r3, i2, e3.tmp, 0), r3 = e3.tmp[0], i2 = e3.tmp[1];
          for (var s2 = 0; s2 < e3.keys.length; s2 += 2) {
            var a2 = u[s2 >>> 1];
            r3 = o.r28shl(r3, a2), i2 = o.r28shl(i2, a2), o.pc2(r3, i2, e3.keys, s2);
          }
        }, c.prototype._update = function(e3, t3, r3, n2) {
          var i2 = this._desState, s2 = o.readUInt32BE(e3, t3), a2 = o.readUInt32BE(e3, t3 + 4);
          o.ip(s2, a2, i2.tmp, 0), s2 = i2.tmp[0], a2 = i2.tmp[1], "encrypt" === this.type ? this._encrypt(i2, s2, a2, i2.tmp, 0) : this._decrypt(i2, s2, a2, i2.tmp, 0), s2 = i2.tmp[0], a2 = i2.tmp[1], o.writeUInt32BE(r3, s2, n2), o.writeUInt32BE(r3, a2, n2 + 4);
        }, c.prototype._pad = function(e3, t3) {
          for (var r3 = e3.length - t3, n2 = t3; n2 < e3.length; n2++) e3[n2] = r3;
          return true;
        }, c.prototype._unpad = function(e3) {
          for (var t3 = e3[e3.length - 1], r3 = e3.length - t3; r3 < e3.length; r3++) n.equal(e3[r3], t3);
          return e3.slice(0, e3.length - t3);
        }, c.prototype._encrypt = function(e3, t3, r3, n2, i2) {
          for (var s2 = t3, a2 = r3, c2 = 0; c2 < e3.keys.length; c2 += 2) {
            var u2 = e3.keys[c2], d = e3.keys[c2 + 1];
            o.expand(a2, e3.tmp, 0), u2 ^= e3.tmp[0], d ^= e3.tmp[1];
            var f = o.substitute(u2, d), h = a2;
            a2 = (s2 ^ o.permute(f)) >>> 0, s2 = h;
          }
          o.rip(a2, s2, n2, i2);
        }, c.prototype._decrypt = function(e3, t3, r3, n2, i2) {
          for (var s2 = r3, a2 = t3, c2 = e3.keys.length - 2; c2 >= 0; c2 -= 2) {
            var u2 = e3.keys[c2], d = e3.keys[c2 + 1];
            o.expand(s2, e3.tmp, 0), u2 ^= e3.tmp[0], d ^= e3.tmp[1];
            var f = o.substitute(u2, d), h = s2;
            s2 = (a2 ^ o.permute(f)) >>> 0, a2 = h;
          }
          o.rip(s2, a2, n2, i2);
        };
      }, 6625: (e2, t2, r2) => {
        "use strict";
        var n = r2(5578), i = r2(1193), o = r2(5958), s = r2(9409);
        function a(e3, t3) {
          n.equal(t3.length, 24, "Invalid key length");
          var r3 = t3.slice(0, 8), i2 = t3.slice(8, 16), o2 = t3.slice(16, 24);
          this.ciphers = "encrypt" === e3 ? [s.create({ type: "encrypt", key: r3 }), s.create({ type: "decrypt", key: i2 }), s.create({ type: "encrypt", key: o2 })] : [s.create({ type: "decrypt", key: o2 }), s.create({ type: "encrypt", key: i2 }), s.create({ type: "decrypt", key: r3 })];
        }
        function c(e3) {
          o.call(this, e3);
          var t3 = new a(this.type, this.options.key);
          this._edeState = t3;
        }
        i(c, o), e2.exports = c, c.create = function(e3) {
          return new c(e3);
        }, c.prototype._update = function(e3, t3, r3, n2) {
          var i2 = this._edeState;
          i2.ciphers[0]._update(e3, t3, r3, n2), i2.ciphers[1]._update(r3, n2, r3, n2), i2.ciphers[2]._update(r3, n2, r3, n2);
        }, c.prototype._pad = s.prototype._pad, c.prototype._unpad = s.prototype._unpad;
      }, 1496: (e2, t2) => {
        "use strict";
        t2.readUInt32BE = function(e3, t3) {
          return (e3[0 + t3] << 24 | e3[1 + t3] << 16 | e3[2 + t3] << 8 | e3[3 + t3]) >>> 0;
        }, t2.writeUInt32BE = function(e3, t3, r3) {
          e3[0 + r3] = t3 >>> 24, e3[1 + r3] = t3 >>> 16 & 255, e3[2 + r3] = t3 >>> 8 & 255, e3[3 + r3] = 255 & t3;
        }, t2.ip = function(e3, t3, r3, n2) {
          for (var i2 = 0, o = 0, s = 6; s >= 0; s -= 2) {
            for (var a = 0; a <= 24; a += 8) i2 <<= 1, i2 |= t3 >>> a + s & 1;
            for (a = 0; a <= 24; a += 8) i2 <<= 1, i2 |= e3 >>> a + s & 1;
          }
          for (s = 6; s >= 0; s -= 2) {
            for (a = 1; a <= 25; a += 8) o <<= 1, o |= t3 >>> a + s & 1;
            for (a = 1; a <= 25; a += 8) o <<= 1, o |= e3 >>> a + s & 1;
          }
          r3[n2 + 0] = i2 >>> 0, r3[n2 + 1] = o >>> 0;
        }, t2.rip = function(e3, t3, r3, n2) {
          for (var i2 = 0, o = 0, s = 0; s < 4; s++) for (var a = 24; a >= 0; a -= 8) i2 <<= 1, i2 |= t3 >>> a + s & 1, i2 <<= 1, i2 |= e3 >>> a + s & 1;
          for (s = 4; s < 8; s++) for (a = 24; a >= 0; a -= 8) o <<= 1, o |= t3 >>> a + s & 1, o <<= 1, o |= e3 >>> a + s & 1;
          r3[n2 + 0] = i2 >>> 0, r3[n2 + 1] = o >>> 0;
        }, t2.pc1 = function(e3, t3, r3, n2) {
          for (var i2 = 0, o = 0, s = 7; s >= 5; s--) {
            for (var a = 0; a <= 24; a += 8) i2 <<= 1, i2 |= t3 >> a + s & 1;
            for (a = 0; a <= 24; a += 8) i2 <<= 1, i2 |= e3 >> a + s & 1;
          }
          for (a = 0; a <= 24; a += 8) i2 <<= 1, i2 |= t3 >> a + s & 1;
          for (s = 1; s <= 3; s++) {
            for (a = 0; a <= 24; a += 8) o <<= 1, o |= t3 >> a + s & 1;
            for (a = 0; a <= 24; a += 8) o <<= 1, o |= e3 >> a + s & 1;
          }
          for (a = 0; a <= 24; a += 8) o <<= 1, o |= e3 >> a + s & 1;
          r3[n2 + 0] = i2 >>> 0, r3[n2 + 1] = o >>> 0;
        }, t2.r28shl = function(e3, t3) {
          return e3 << t3 & 268435455 | e3 >>> 28 - t3;
        };
        var r2 = [14, 11, 17, 4, 27, 23, 25, 0, 13, 22, 7, 18, 5, 9, 16, 24, 2, 20, 12, 21, 1, 8, 15, 26, 15, 4, 25, 19, 9, 1, 26, 16, 5, 11, 23, 8, 12, 7, 17, 0, 22, 3, 10, 14, 6, 20, 27, 24];
        t2.pc2 = function(e3, t3, n2, i2) {
          for (var o = 0, s = 0, a = r2.length >>> 1, c = 0; c < a; c++) o <<= 1, o |= e3 >>> r2[c] & 1;
          for (c = a; c < r2.length; c++) s <<= 1, s |= t3 >>> r2[c] & 1;
          n2[i2 + 0] = o >>> 0, n2[i2 + 1] = s >>> 0;
        }, t2.expand = function(e3, t3, r3) {
          var n2 = 0, i2 = 0;
          n2 = (1 & e3) << 5 | e3 >>> 27;
          for (var o = 23; o >= 15; o -= 4) n2 <<= 6, n2 |= e3 >>> o & 63;
          for (o = 11; o >= 3; o -= 4) i2 |= e3 >>> o & 63, i2 <<= 6;
          i2 |= (31 & e3) << 1 | e3 >>> 31, t3[r3 + 0] = n2 >>> 0, t3[r3 + 1] = i2 >>> 0;
        };
        var n = [14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13, 15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9, 10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12, 7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14, 2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3, 12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13, 4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12, 13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11];
        t2.substitute = function(e3, t3) {
          for (var r3 = 0, i2 = 0; i2 < 4; i2++) r3 <<= 4, r3 |= n[64 * i2 + (e3 >>> 18 - 6 * i2 & 63)];
          for (i2 = 0; i2 < 4; i2++) r3 <<= 4, r3 |= n[256 + 64 * i2 + (t3 >>> 18 - 6 * i2 & 63)];
          return r3 >>> 0;
        };
        var i = [16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22, 30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2, 26, 10, 21, 28, 7];
        t2.permute = function(e3) {
          for (var t3 = 0, r3 = 0; r3 < i.length; r3++) t3 <<= 1, t3 |= e3 >>> i[r3] & 1;
          return t3 >>> 0;
        }, t2.padSplit = function(e3, t3, r3) {
          for (var n2 = e3.toString(2); n2.length < t3; ) n2 = "0" + n2;
          for (var i2 = [], o = 0; o < t3; o += r3) i2.push(n2.slice(o, o + r3));
          return i2.join(" ");
        };
      }, 8216: (e2, t2, r2) => {
        var n = r2(5122), i = r2(7821), o = r2(9242), s = { binary: true, hex: true, base64: true };
        t2.DiffieHellmanGroup = t2.createDiffieHellmanGroup = t2.getDiffieHellman = function(e3) {
          var t3 = new Buffer(i[e3].prime, "hex"), r3 = new Buffer(i[e3].gen, "hex");
          return new o(t3, r3);
        }, t2.createDiffieHellman = t2.DiffieHellman = function e3(t3, r3, i2, a) {
          return Buffer.isBuffer(r3) || void 0 === s[r3] ? e3(t3, "binary", r3, i2) : (r3 = r3 || "binary", a = a || "binary", i2 = i2 || new Buffer([2]), Buffer.isBuffer(i2) || (i2 = new Buffer(i2, a)), "number" == typeof t3 ? new o(n(t3, i2), i2, true) : (Buffer.isBuffer(t3) || (t3 = new Buffer(t3, r3)), new o(t3, i2, true)));
        };
      }, 9242: (e2, t2, r2) => {
        var n = r2(4619), i = new (r2(4442))(), o = new n(24), s = new n(11), a = new n(10), c = new n(3), u = new n(7), d = r2(5122), f = r2(2869);
        function h(e3, t3) {
          return t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3)), this._pub = new n(e3), this;
        }
        function l(e3, t3) {
          return t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3)), this._priv = new n(e3), this;
        }
        e2.exports = b;
        var p = {};
        function b(e3, t3, r3) {
          this.setGenerator(t3), this.__prime = new n(e3), this._prime = n.mont(this.__prime), this._primeLen = e3.length, this._pub = void 0, this._priv = void 0, this._primeCode = void 0, r3 ? (this.setPublicKey = h, this.setPrivateKey = l) : this._primeCode = 8;
        }
        function y(e3, t3) {
          var r3 = new Buffer(e3.toArray());
          return t3 ? r3.toString(t3) : r3;
        }
        Object.defineProperty(b.prototype, "verifyError", { enumerable: true, get: function() {
          return "number" != typeof this._primeCode && (this._primeCode = (function(e3, t3) {
            var r3 = t3.toString("hex"), n2 = [r3, e3.toString(16)].join("_");
            if (n2 in p) return p[n2];
            var f2, h2 = 0;
            if (e3.isEven() || !d.simpleSieve || !d.fermatTest(e3) || !i.test(e3)) return h2 += 1, h2 += "02" === r3 || "05" === r3 ? 8 : 4, p[n2] = h2, h2;
            switch (i.test(e3.shrn(1)) || (h2 += 2), r3) {
              case "02":
                e3.mod(o).cmp(s) && (h2 += 8);
                break;
              case "05":
                (f2 = e3.mod(a)).cmp(c) && f2.cmp(u) && (h2 += 8);
                break;
              default:
                h2 += 4;
            }
            return p[n2] = h2, h2;
          })(this.__prime, this.__gen)), this._primeCode;
        } }), b.prototype.generateKeys = function() {
          return this._priv || (this._priv = new n(f(this._primeLen))), this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed(), this.getPublicKey();
        }, b.prototype.computeSecret = function(e3) {
          var t3 = (e3 = (e3 = new n(e3)).toRed(this._prime)).redPow(this._priv).fromRed(), r3 = new Buffer(t3.toArray()), i2 = this.getPrime();
          if (r3.length < i2.length) {
            var o2 = new Buffer(i2.length - r3.length);
            o2.fill(0), r3 = Buffer.concat([o2, r3]);
          }
          return r3;
        }, b.prototype.getPublicKey = function(e3) {
          return y(this._pub, e3);
        }, b.prototype.getPrivateKey = function(e3) {
          return y(this._priv, e3);
        }, b.prototype.getPrime = function(e3) {
          return y(this.__prime, e3);
        }, b.prototype.getGenerator = function(e3) {
          return y(this._gen, e3);
        }, b.prototype.setGenerator = function(e3, t3) {
          return t3 = t3 || "utf8", Buffer.isBuffer(e3) || (e3 = new Buffer(e3, t3)), this.__gen = e3, this._gen = new n(e3), this;
        };
      }, 5122: (e2, t2, r2) => {
        var n = r2(2869);
        e2.exports = g, g.simpleSieve = y, g.fermatTest = m;
        var i = r2(4619), o = new i(24), s = new (r2(4442))(), a = new i(1), c = new i(2), u = new i(5), d = (new i(16), new i(8), new i(10)), f = new i(3), h = (new i(7), new i(11)), l = new i(4), p = (new i(12), null);
        function b() {
          if (null !== p) return p;
          var e3 = [];
          e3[0] = 2;
          for (var t3 = 1, r3 = 3; r3 < 1048576; r3 += 2) {
            for (var n2 = Math.ceil(Math.sqrt(r3)), i2 = 0; i2 < t3 && e3[i2] <= n2 && r3 % e3[i2] != 0; i2++) ;
            t3 !== i2 && e3[i2] <= n2 || (e3[t3++] = r3);
          }
          return p = e3, e3;
        }
        function y(e3) {
          for (var t3 = b(), r3 = 0; r3 < t3.length; r3++) if (0 === e3.modn(t3[r3])) return 0 === e3.cmpn(t3[r3]);
          return true;
        }
        function m(e3) {
          var t3 = i.mont(e3);
          return 0 === c.toRed(t3).redPow(e3.subn(1)).fromRed().cmpn(1);
        }
        function g(e3, t3) {
          if (e3 < 16) return new i(2 === t3 || 5 === t3 ? [140, 123] : [140, 39]);
          var r3, p2;
          for (t3 = new i(t3); ; ) {
            for (r3 = new i(n(Math.ceil(e3 / 8))); r3.bitLength() > e3; ) r3.ishrn(1);
            if (r3.isEven() && r3.iadd(a), r3.testn(1) || r3.iadd(c), t3.cmp(c)) {
              if (!t3.cmp(u)) for (; r3.mod(d).cmp(f); ) r3.iadd(l);
            } else for (; r3.mod(o).cmp(h); ) r3.iadd(l);
            if (y(p2 = r3.shrn(1)) && y(r3) && m(p2) && m(r3) && s.test(p2) && s.test(r3)) return r3;
          }
        }
      }, 3071: (e2, t2, r2) => {
        "use strict";
        var n = t2;
        n.version = r2(3718).rE, n.utils = r2(9185), n.rand = r2(5442), n.curve = r2(5228), n.curves = r2(5366), n.ec = r2(2961), n.eddsa = r2(7808);
      }, 4499: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(9185), o = i.getNAF, s = i.getJSF, a = i.assert;
        function c(e3, t3) {
          this.type = e3, this.p = new n(t3.p, 16), this.red = t3.prime ? n.red(t3.prime) : n.mont(this.p), this.zero = new n(0).toRed(this.red), this.one = new n(1).toRed(this.red), this.two = new n(2).toRed(this.red), this.n = t3.n && new n(t3.n, 16), this.g = t3.g && this.pointFromJSON(t3.g, t3.gRed), this._wnafT1 = new Array(4), this._wnafT2 = new Array(4), this._wnafT3 = new Array(4), this._wnafT4 = new Array(4), this._bitLength = this.n ? this.n.bitLength() : 0;
          var r3 = this.n && this.p.div(this.n);
          !r3 || r3.cmpn(100) > 0 ? this.redN = null : (this._maxwellTrick = true, this.redN = this.n.toRed(this.red));
        }
        function u(e3, t3) {
          this.curve = e3, this.type = t3, this.precomputed = null;
        }
        e2.exports = c, c.prototype.point = function() {
          throw new Error("Not implemented");
        }, c.prototype.validate = function() {
          throw new Error("Not implemented");
        }, c.prototype._fixedNafMul = function(e3, t3) {
          a(e3.precomputed);
          var r3 = e3._getDoubles(), n2 = o(t3, 1, this._bitLength), i2 = (1 << r3.step + 1) - (r3.step % 2 == 0 ? 2 : 1);
          i2 /= 3;
          var s2, c2, u2 = [];
          for (s2 = 0; s2 < n2.length; s2 += r3.step) {
            c2 = 0;
            for (var d = s2 + r3.step - 1; d >= s2; d--) c2 = (c2 << 1) + n2[d];
            u2.push(c2);
          }
          for (var f = this.jpoint(null, null, null), h = this.jpoint(null, null, null), l = i2; l > 0; l--) {
            for (s2 = 0; s2 < u2.length; s2++) (c2 = u2[s2]) === l ? h = h.mixedAdd(r3.points[s2]) : c2 === -l && (h = h.mixedAdd(r3.points[s2].neg()));
            f = f.add(h);
          }
          return f.toP();
        }, c.prototype._wnafMul = function(e3, t3) {
          var r3 = 4, n2 = e3._getNAFPoints(r3);
          r3 = n2.wnd;
          for (var i2 = n2.points, s2 = o(t3, r3, this._bitLength), c2 = this.jpoint(null, null, null), u2 = s2.length - 1; u2 >= 0; u2--) {
            for (var d = 0; u2 >= 0 && 0 === s2[u2]; u2--) d++;
            if (u2 >= 0 && d++, c2 = c2.dblp(d), u2 < 0) break;
            var f = s2[u2];
            a(0 !== f), c2 = "affine" === e3.type ? f > 0 ? c2.mixedAdd(i2[f - 1 >> 1]) : c2.mixedAdd(i2[-f - 1 >> 1].neg()) : f > 0 ? c2.add(i2[f - 1 >> 1]) : c2.add(i2[-f - 1 >> 1].neg());
          }
          return "affine" === e3.type ? c2.toP() : c2;
        }, c.prototype._wnafMulAdd = function(e3, t3, r3, n2, i2) {
          var a2, c2, u2, d = this._wnafT1, f = this._wnafT2, h = this._wnafT3, l = 0;
          for (a2 = 0; a2 < n2; a2++) {
            var p = (u2 = t3[a2])._getNAFPoints(e3);
            d[a2] = p.wnd, f[a2] = p.points;
          }
          for (a2 = n2 - 1; a2 >= 1; a2 -= 2) {
            var b = a2 - 1, y = a2;
            if (1 === d[b] && 1 === d[y]) {
              var m = [t3[b], null, null, t3[y]];
              0 === t3[b].y.cmp(t3[y].y) ? (m[1] = t3[b].add(t3[y]), m[2] = t3[b].toJ().mixedAdd(t3[y].neg())) : 0 === t3[b].y.cmp(t3[y].y.redNeg()) ? (m[1] = t3[b].toJ().mixedAdd(t3[y]), m[2] = t3[b].add(t3[y].neg())) : (m[1] = t3[b].toJ().mixedAdd(t3[y]), m[2] = t3[b].toJ().mixedAdd(t3[y].neg()));
              var g = [-3, -1, -5, -7, 0, 7, 5, 1, 3], v = s(r3[b], r3[y]);
              for (l = Math.max(v[0].length, l), h[b] = new Array(l), h[y] = new Array(l), c2 = 0; c2 < l; c2++) {
                var w = 0 | v[0][c2], _ = 0 | v[1][c2];
                h[b][c2] = g[3 * (w + 1) + (_ + 1)], h[y][c2] = 0, f[b] = m;
              }
            } else h[b] = o(r3[b], d[b], this._bitLength), h[y] = o(r3[y], d[y], this._bitLength), l = Math.max(h[b].length, l), l = Math.max(h[y].length, l);
          }
          var A = this.jpoint(null, null, null), S = this._wnafT4;
          for (a2 = l; a2 >= 0; a2--) {
            for (var C = 0; a2 >= 0; ) {
              var T = true;
              for (c2 = 0; c2 < n2; c2++) S[c2] = 0 | h[c2][a2], 0 !== S[c2] && (T = false);
              if (!T) break;
              C++, a2--;
            }
            if (a2 >= 0 && C++, A = A.dblp(C), a2 < 0) break;
            for (c2 = 0; c2 < n2; c2++) {
              var M = S[c2];
              0 !== M && (M > 0 ? u2 = f[c2][M - 1 >> 1] : M < 0 && (u2 = f[c2][-M - 1 >> 1].neg()), A = "affine" === u2.type ? A.mixedAdd(u2) : A.add(u2));
            }
          }
          for (a2 = 0; a2 < n2; a2++) f[a2] = null;
          return i2 ? A : A.toP();
        }, c.BasePoint = u, u.prototype.eq = function() {
          throw new Error("Not implemented");
        }, u.prototype.validate = function() {
          return this.curve.validate(this);
        }, c.prototype.decodePoint = function(e3, t3) {
          e3 = i.toArray(e3, t3);
          var r3 = this.p.byteLength();
          if ((4 === e3[0] || 6 === e3[0] || 7 === e3[0]) && e3.length - 1 == 2 * r3) return 6 === e3[0] ? a(e3[e3.length - 1] % 2 == 0) : 7 === e3[0] && a(e3[e3.length - 1] % 2 == 1), this.point(e3.slice(1, 1 + r3), e3.slice(1 + r3, 1 + 2 * r3));
          if ((2 === e3[0] || 3 === e3[0]) && e3.length - 1 === r3) return this.pointFromX(e3.slice(1, 1 + r3), 3 === e3[0]);
          throw new Error("Unknown point format");
        }, u.prototype.encodeCompressed = function(e3) {
          return this.encode(e3, true);
        }, u.prototype._encode = function(e3) {
          var t3 = this.curve.p.byteLength(), r3 = this.getX().toArray("be", t3);
          return e3 ? [this.getY().isEven() ? 2 : 3].concat(r3) : [4].concat(r3, this.getY().toArray("be", t3));
        }, u.prototype.encode = function(e3, t3) {
          return i.encode(this._encode(t3), e3);
        }, u.prototype.precompute = function(e3) {
          if (this.precomputed) return this;
          var t3 = { doubles: null, naf: null, beta: null };
          return t3.naf = this._getNAFPoints(8), t3.doubles = this._getDoubles(4, e3), t3.beta = this._getBeta(), this.precomputed = t3, this;
        }, u.prototype._hasDoubles = function(e3) {
          if (!this.precomputed) return false;
          var t3 = this.precomputed.doubles;
          return !!t3 && t3.points.length >= Math.ceil((e3.bitLength() + 1) / t3.step);
        }, u.prototype._getDoubles = function(e3, t3) {
          if (this.precomputed && this.precomputed.doubles) return this.precomputed.doubles;
          for (var r3 = [this], n2 = this, i2 = 0; i2 < t3; i2 += e3) {
            for (var o2 = 0; o2 < e3; o2++) n2 = n2.dbl();
            r3.push(n2);
          }
          return { step: e3, points: r3 };
        }, u.prototype._getNAFPoints = function(e3) {
          if (this.precomputed && this.precomputed.naf) return this.precomputed.naf;
          for (var t3 = [this], r3 = (1 << e3) - 1, n2 = 1 === r3 ? null : this.dbl(), i2 = 1; i2 < r3; i2++) t3[i2] = t3[i2 - 1].add(n2);
          return { wnd: e3, points: t3 };
        }, u.prototype._getBeta = function() {
          return null;
        }, u.prototype.dblp = function(e3) {
          for (var t3 = this, r3 = 0; r3 < e3; r3++) t3 = t3.dbl();
          return t3;
        };
      }, 3544: (e2, t2, r2) => {
        "use strict";
        var n = r2(9185), i = r2(4619), o = r2(1193), s = r2(4499), a = n.assert;
        function c(e3) {
          this.twisted = 1 != (0 | e3.a), this.mOneA = this.twisted && -1 == (0 | e3.a), this.extended = this.mOneA, s.call(this, "edwards", e3), this.a = new i(e3.a, 16).umod(this.red.m), this.a = this.a.toRed(this.red), this.c = new i(e3.c, 16).toRed(this.red), this.c2 = this.c.redSqr(), this.d = new i(e3.d, 16).toRed(this.red), this.dd = this.d.redAdd(this.d), a(!this.twisted || 0 === this.c.fromRed().cmpn(1)), this.oneC = 1 == (0 | e3.c);
        }
        function u(e3, t3, r3, n2, o2) {
          s.BasePoint.call(this, e3, "projective"), null === t3 && null === r3 && null === n2 ? (this.x = this.curve.zero, this.y = this.curve.one, this.z = this.curve.one, this.t = this.curve.zero, this.zOne = true) : (this.x = new i(t3, 16), this.y = new i(r3, 16), this.z = n2 ? new i(n2, 16) : this.curve.one, this.t = o2 && new i(o2, 16), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)), this.t && !this.t.red && (this.t = this.t.toRed(this.curve.red)), this.zOne = this.z === this.curve.one, this.curve.extended && !this.t && (this.t = this.x.redMul(this.y), this.zOne || (this.t = this.t.redMul(this.z.redInvm()))));
        }
        o(c, s), e2.exports = c, c.prototype._mulA = function(e3) {
          return this.mOneA ? e3.redNeg() : this.a.redMul(e3);
        }, c.prototype._mulC = function(e3) {
          return this.oneC ? e3 : this.c.redMul(e3);
        }, c.prototype.jpoint = function(e3, t3, r3, n2) {
          return this.point(e3, t3, r3, n2);
        }, c.prototype.pointFromX = function(e3, t3) {
          (e3 = new i(e3, 16)).red || (e3 = e3.toRed(this.red));
          var r3 = e3.redSqr(), n2 = this.c2.redSub(this.a.redMul(r3)), o2 = this.one.redSub(this.c2.redMul(this.d).redMul(r3)), s2 = n2.redMul(o2.redInvm()), a2 = s2.redSqrt();
          if (0 !== a2.redSqr().redSub(s2).cmp(this.zero)) throw new Error("invalid point");
          var c2 = a2.fromRed().isOdd();
          return (t3 && !c2 || !t3 && c2) && (a2 = a2.redNeg()), this.point(e3, a2);
        }, c.prototype.pointFromY = function(e3, t3) {
          (e3 = new i(e3, 16)).red || (e3 = e3.toRed(this.red));
          var r3 = e3.redSqr(), n2 = r3.redSub(this.c2), o2 = r3.redMul(this.d).redMul(this.c2).redSub(this.a), s2 = n2.redMul(o2.redInvm());
          if (0 === s2.cmp(this.zero)) {
            if (t3) throw new Error("invalid point");
            return this.point(this.zero, e3);
          }
          var a2 = s2.redSqrt();
          if (0 !== a2.redSqr().redSub(s2).cmp(this.zero)) throw new Error("invalid point");
          return a2.fromRed().isOdd() !== t3 && (a2 = a2.redNeg()), this.point(a2, e3);
        }, c.prototype.validate = function(e3) {
          if (e3.isInfinity()) return true;
          e3.normalize();
          var t3 = e3.x.redSqr(), r3 = e3.y.redSqr(), n2 = t3.redMul(this.a).redAdd(r3), i2 = this.c2.redMul(this.one.redAdd(this.d.redMul(t3).redMul(r3)));
          return 0 === n2.cmp(i2);
        }, o(u, s.BasePoint), c.prototype.pointFromJSON = function(e3) {
          return u.fromJSON(this, e3);
        }, c.prototype.point = function(e3, t3, r3, n2) {
          return new u(this, e3, t3, r3, n2);
        }, u.fromJSON = function(e3, t3) {
          return new u(e3, t3[0], t3[1], t3[2]);
        }, u.prototype.inspect = function() {
          return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
        }, u.prototype.isInfinity = function() {
          return 0 === this.x.cmpn(0) && (0 === this.y.cmp(this.z) || this.zOne && 0 === this.y.cmp(this.curve.c));
        }, u.prototype._extDbl = function() {
          var e3 = this.x.redSqr(), t3 = this.y.redSqr(), r3 = this.z.redSqr();
          r3 = r3.redIAdd(r3);
          var n2 = this.curve._mulA(e3), i2 = this.x.redAdd(this.y).redSqr().redISub(e3).redISub(t3), o2 = n2.redAdd(t3), s2 = o2.redSub(r3), a2 = n2.redSub(t3), c2 = i2.redMul(s2), u2 = o2.redMul(a2), d = i2.redMul(a2), f = s2.redMul(o2);
          return this.curve.point(c2, u2, f, d);
        }, u.prototype._projDbl = function() {
          var e3, t3, r3, n2, i2, o2, s2 = this.x.redAdd(this.y).redSqr(), a2 = this.x.redSqr(), c2 = this.y.redSqr();
          if (this.curve.twisted) {
            var u2 = (n2 = this.curve._mulA(a2)).redAdd(c2);
            this.zOne ? (e3 = s2.redSub(a2).redSub(c2).redMul(u2.redSub(this.curve.two)), t3 = u2.redMul(n2.redSub(c2)), r3 = u2.redSqr().redSub(u2).redSub(u2)) : (i2 = this.z.redSqr(), o2 = u2.redSub(i2).redISub(i2), e3 = s2.redSub(a2).redISub(c2).redMul(o2), t3 = u2.redMul(n2.redSub(c2)), r3 = u2.redMul(o2));
          } else n2 = a2.redAdd(c2), i2 = this.curve._mulC(this.z).redSqr(), o2 = n2.redSub(i2).redSub(i2), e3 = this.curve._mulC(s2.redISub(n2)).redMul(o2), t3 = this.curve._mulC(n2).redMul(a2.redISub(c2)), r3 = n2.redMul(o2);
          return this.curve.point(e3, t3, r3);
        }, u.prototype.dbl = function() {
          return this.isInfinity() ? this : this.curve.extended ? this._extDbl() : this._projDbl();
        }, u.prototype._extAdd = function(e3) {
          var t3 = this.y.redSub(this.x).redMul(e3.y.redSub(e3.x)), r3 = this.y.redAdd(this.x).redMul(e3.y.redAdd(e3.x)), n2 = this.t.redMul(this.curve.dd).redMul(e3.t), i2 = this.z.redMul(e3.z.redAdd(e3.z)), o2 = r3.redSub(t3), s2 = i2.redSub(n2), a2 = i2.redAdd(n2), c2 = r3.redAdd(t3), u2 = o2.redMul(s2), d = a2.redMul(c2), f = o2.redMul(c2), h = s2.redMul(a2);
          return this.curve.point(u2, d, h, f);
        }, u.prototype._projAdd = function(e3) {
          var t3, r3, n2 = this.z.redMul(e3.z), i2 = n2.redSqr(), o2 = this.x.redMul(e3.x), s2 = this.y.redMul(e3.y), a2 = this.curve.d.redMul(o2).redMul(s2), c2 = i2.redSub(a2), u2 = i2.redAdd(a2), d = this.x.redAdd(this.y).redMul(e3.x.redAdd(e3.y)).redISub(o2).redISub(s2), f = n2.redMul(c2).redMul(d);
          return this.curve.twisted ? (t3 = n2.redMul(u2).redMul(s2.redSub(this.curve._mulA(o2))), r3 = c2.redMul(u2)) : (t3 = n2.redMul(u2).redMul(s2.redSub(o2)), r3 = this.curve._mulC(c2).redMul(u2)), this.curve.point(f, t3, r3);
        }, u.prototype.add = function(e3) {
          return this.isInfinity() ? e3 : e3.isInfinity() ? this : this.curve.extended ? this._extAdd(e3) : this._projAdd(e3);
        }, u.prototype.mul = function(e3) {
          return this._hasDoubles(e3) ? this.curve._fixedNafMul(this, e3) : this.curve._wnafMul(this, e3);
        }, u.prototype.mulAdd = function(e3, t3, r3) {
          return this.curve._wnafMulAdd(1, [this, t3], [e3, r3], 2, false);
        }, u.prototype.jmulAdd = function(e3, t3, r3) {
          return this.curve._wnafMulAdd(1, [this, t3], [e3, r3], 2, true);
        }, u.prototype.normalize = function() {
          if (this.zOne) return this;
          var e3 = this.z.redInvm();
          return this.x = this.x.redMul(e3), this.y = this.y.redMul(e3), this.t && (this.t = this.t.redMul(e3)), this.z = this.curve.one, this.zOne = true, this;
        }, u.prototype.neg = function() {
          return this.curve.point(this.x.redNeg(), this.y, this.z, this.t && this.t.redNeg());
        }, u.prototype.getX = function() {
          return this.normalize(), this.x.fromRed();
        }, u.prototype.getY = function() {
          return this.normalize(), this.y.fromRed();
        }, u.prototype.eq = function(e3) {
          return this === e3 || 0 === this.getX().cmp(e3.getX()) && 0 === this.getY().cmp(e3.getY());
        }, u.prototype.eqXToP = function(e3) {
          var t3 = e3.toRed(this.curve.red).redMul(this.z);
          if (0 === this.x.cmp(t3)) return true;
          for (var r3 = e3.clone(), n2 = this.curve.redN.redMul(this.z); ; ) {
            if (r3.iadd(this.curve.n), r3.cmp(this.curve.p) >= 0) return false;
            if (t3.redIAdd(n2), 0 === this.x.cmp(t3)) return true;
          }
        }, u.prototype.toP = u.prototype.normalize, u.prototype.mixedAdd = u.prototype.add;
      }, 5228: (e2, t2, r2) => {
        "use strict";
        var n = t2;
        n.base = r2(4499), n.short = r2(3970), n.mont = r2(536), n.edwards = r2(3544);
      }, 536: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(1193), o = r2(4499), s = r2(9185);
        function a(e3) {
          o.call(this, "mont", e3), this.a = new n(e3.a, 16).toRed(this.red), this.b = new n(e3.b, 16).toRed(this.red), this.i4 = new n(4).toRed(this.red).redInvm(), this.two = new n(2).toRed(this.red), this.a24 = this.i4.redMul(this.a.redAdd(this.two));
        }
        function c(e3, t3, r3) {
          o.BasePoint.call(this, e3, "projective"), null === t3 && null === r3 ? (this.x = this.curve.one, this.z = this.curve.zero) : (this.x = new n(t3, 16), this.z = new n(r3, 16), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)));
        }
        i(a, o), e2.exports = a, a.prototype.validate = function(e3) {
          var t3 = e3.normalize().x, r3 = t3.redSqr(), n2 = r3.redMul(t3).redAdd(r3.redMul(this.a)).redAdd(t3);
          return 0 === n2.redSqrt().redSqr().cmp(n2);
        }, i(c, o.BasePoint), a.prototype.decodePoint = function(e3, t3) {
          return this.point(s.toArray(e3, t3), 1);
        }, a.prototype.point = function(e3, t3) {
          return new c(this, e3, t3);
        }, a.prototype.pointFromJSON = function(e3) {
          return c.fromJSON(this, e3);
        }, c.prototype.precompute = function() {
        }, c.prototype._encode = function() {
          return this.getX().toArray("be", this.curve.p.byteLength());
        }, c.fromJSON = function(e3, t3) {
          return new c(e3, t3[0], t3[1] || e3.one);
        }, c.prototype.inspect = function() {
          return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
        }, c.prototype.isInfinity = function() {
          return 0 === this.z.cmpn(0);
        }, c.prototype.dbl = function() {
          var e3 = this.x.redAdd(this.z).redSqr(), t3 = this.x.redSub(this.z).redSqr(), r3 = e3.redSub(t3), n2 = e3.redMul(t3), i2 = r3.redMul(t3.redAdd(this.curve.a24.redMul(r3)));
          return this.curve.point(n2, i2);
        }, c.prototype.add = function() {
          throw new Error("Not supported on Montgomery curve");
        }, c.prototype.diffAdd = function(e3, t3) {
          var r3 = this.x.redAdd(this.z), n2 = this.x.redSub(this.z), i2 = e3.x.redAdd(e3.z), o2 = e3.x.redSub(e3.z).redMul(r3), s2 = i2.redMul(n2), a2 = t3.z.redMul(o2.redAdd(s2).redSqr()), c2 = t3.x.redMul(o2.redISub(s2).redSqr());
          return this.curve.point(a2, c2);
        }, c.prototype.mul = function(e3) {
          for (var t3 = e3.clone(), r3 = this, n2 = this.curve.point(null, null), i2 = []; 0 !== t3.cmpn(0); t3.iushrn(1)) i2.push(t3.andln(1));
          for (var o2 = i2.length - 1; o2 >= 0; o2--) 0 === i2[o2] ? (r3 = r3.diffAdd(n2, this), n2 = n2.dbl()) : (n2 = r3.diffAdd(n2, this), r3 = r3.dbl());
          return n2;
        }, c.prototype.mulAdd = function() {
          throw new Error("Not supported on Montgomery curve");
        }, c.prototype.jumlAdd = function() {
          throw new Error("Not supported on Montgomery curve");
        }, c.prototype.eq = function(e3) {
          return 0 === this.getX().cmp(e3.getX());
        }, c.prototype.normalize = function() {
          return this.x = this.x.redMul(this.z.redInvm()), this.z = this.curve.one, this;
        }, c.prototype.getX = function() {
          return this.normalize(), this.x.fromRed();
        };
      }, 3970: (e2, t2, r2) => {
        "use strict";
        var n = r2(9185), i = r2(4619), o = r2(1193), s = r2(4499), a = n.assert;
        function c(e3) {
          s.call(this, "short", e3), this.a = new i(e3.a, 16).toRed(this.red), this.b = new i(e3.b, 16).toRed(this.red), this.tinv = this.two.redInvm(), this.zeroA = 0 === this.a.fromRed().cmpn(0), this.threeA = 0 === this.a.fromRed().sub(this.p).cmpn(-3), this.endo = this._getEndomorphism(e3), this._endoWnafT1 = new Array(4), this._endoWnafT2 = new Array(4);
        }
        function u(e3, t3, r3, n2) {
          s.BasePoint.call(this, e3, "affine"), null === t3 && null === r3 ? (this.x = null, this.y = null, this.inf = true) : (this.x = new i(t3, 16), this.y = new i(r3, 16), n2 && (this.x.forceRed(this.curve.red), this.y.forceRed(this.curve.red)), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.inf = false);
        }
        function d(e3, t3, r3, n2) {
          s.BasePoint.call(this, e3, "jacobian"), null === t3 && null === r3 && null === n2 ? (this.x = this.curve.one, this.y = this.curve.one, this.z = new i(0)) : (this.x = new i(t3, 16), this.y = new i(r3, 16), this.z = new i(n2, 16)), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)), this.zOne = this.z === this.curve.one;
        }
        o(c, s), e2.exports = c, c.prototype._getEndomorphism = function(e3) {
          if (this.zeroA && this.g && this.n && 1 === this.p.modn(3)) {
            var t3, r3;
            if (e3.beta) t3 = new i(e3.beta, 16).toRed(this.red);
            else {
              var n2 = this._getEndoRoots(this.p);
              t3 = (t3 = n2[0].cmp(n2[1]) < 0 ? n2[0] : n2[1]).toRed(this.red);
            }
            if (e3.lambda) r3 = new i(e3.lambda, 16);
            else {
              var o2 = this._getEndoRoots(this.n);
              0 === this.g.mul(o2[0]).x.cmp(this.g.x.redMul(t3)) ? r3 = o2[0] : (r3 = o2[1], a(0 === this.g.mul(r3).x.cmp(this.g.x.redMul(t3))));
            }
            return { beta: t3, lambda: r3, basis: e3.basis ? e3.basis.map((function(e4) {
              return { a: new i(e4.a, 16), b: new i(e4.b, 16) };
            })) : this._getEndoBasis(r3) };
          }
        }, c.prototype._getEndoRoots = function(e3) {
          var t3 = e3 === this.p ? this.red : i.mont(e3), r3 = new i(2).toRed(t3).redInvm(), n2 = r3.redNeg(), o2 = new i(3).toRed(t3).redNeg().redSqrt().redMul(r3);
          return [n2.redAdd(o2).fromRed(), n2.redSub(o2).fromRed()];
        }, c.prototype._getEndoBasis = function(e3) {
          for (var t3, r3, n2, o2, s2, a2, c2, u2, d2, f = this.n.ushrn(Math.floor(this.n.bitLength() / 2)), h = e3, l = this.n.clone(), p = new i(1), b = new i(0), y = new i(0), m = new i(1), g = 0; 0 !== h.cmpn(0); ) {
            var v = l.div(h);
            u2 = l.sub(v.mul(h)), d2 = y.sub(v.mul(p));
            var w = m.sub(v.mul(b));
            if (!n2 && u2.cmp(f) < 0) t3 = c2.neg(), r3 = p, n2 = u2.neg(), o2 = d2;
            else if (n2 && 2 == ++g) break;
            c2 = u2, l = h, h = u2, y = p, p = d2, m = b, b = w;
          }
          s2 = u2.neg(), a2 = d2;
          var _ = n2.sqr().add(o2.sqr());
          return s2.sqr().add(a2.sqr()).cmp(_) >= 0 && (s2 = t3, a2 = r3), n2.negative && (n2 = n2.neg(), o2 = o2.neg()), s2.negative && (s2 = s2.neg(), a2 = a2.neg()), [{ a: n2, b: o2 }, { a: s2, b: a2 }];
        }, c.prototype._endoSplit = function(e3) {
          var t3 = this.endo.basis, r3 = t3[0], n2 = t3[1], i2 = n2.b.mul(e3).divRound(this.n), o2 = r3.b.neg().mul(e3).divRound(this.n), s2 = i2.mul(r3.a), a2 = o2.mul(n2.a), c2 = i2.mul(r3.b), u2 = o2.mul(n2.b);
          return { k1: e3.sub(s2).sub(a2), k2: c2.add(u2).neg() };
        }, c.prototype.pointFromX = function(e3, t3) {
          (e3 = new i(e3, 16)).red || (e3 = e3.toRed(this.red));
          var r3 = e3.redSqr().redMul(e3).redIAdd(e3.redMul(this.a)).redIAdd(this.b), n2 = r3.redSqrt();
          if (0 !== n2.redSqr().redSub(r3).cmp(this.zero)) throw new Error("invalid point");
          var o2 = n2.fromRed().isOdd();
          return (t3 && !o2 || !t3 && o2) && (n2 = n2.redNeg()), this.point(e3, n2);
        }, c.prototype.validate = function(e3) {
          if (e3.inf) return true;
          var t3 = e3.x, r3 = e3.y, n2 = this.a.redMul(t3), i2 = t3.redSqr().redMul(t3).redIAdd(n2).redIAdd(this.b);
          return 0 === r3.redSqr().redISub(i2).cmpn(0);
        }, c.prototype._endoWnafMulAdd = function(e3, t3, r3) {
          for (var n2 = this._endoWnafT1, i2 = this._endoWnafT2, o2 = 0; o2 < e3.length; o2++) {
            var s2 = this._endoSplit(t3[o2]), a2 = e3[o2], c2 = a2._getBeta();
            s2.k1.negative && (s2.k1.ineg(), a2 = a2.neg(true)), s2.k2.negative && (s2.k2.ineg(), c2 = c2.neg(true)), n2[2 * o2] = a2, n2[2 * o2 + 1] = c2, i2[2 * o2] = s2.k1, i2[2 * o2 + 1] = s2.k2;
          }
          for (var u2 = this._wnafMulAdd(1, n2, i2, 2 * o2, r3), d2 = 0; d2 < 2 * o2; d2++) n2[d2] = null, i2[d2] = null;
          return u2;
        }, o(u, s.BasePoint), c.prototype.point = function(e3, t3, r3) {
          return new u(this, e3, t3, r3);
        }, c.prototype.pointFromJSON = function(e3, t3) {
          return u.fromJSON(this, e3, t3);
        }, u.prototype._getBeta = function() {
          if (this.curve.endo) {
            var e3 = this.precomputed;
            if (e3 && e3.beta) return e3.beta;
            var t3 = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
            if (e3) {
              var r3 = this.curve, n2 = function(e4) {
                return r3.point(e4.x.redMul(r3.endo.beta), e4.y);
              };
              e3.beta = t3, t3.precomputed = { beta: null, naf: e3.naf && { wnd: e3.naf.wnd, points: e3.naf.points.map(n2) }, doubles: e3.doubles && { step: e3.doubles.step, points: e3.doubles.points.map(n2) } };
            }
            return t3;
          }
        }, u.prototype.toJSON = function() {
          return this.precomputed ? [this.x, this.y, this.precomputed && { doubles: this.precomputed.doubles && { step: this.precomputed.doubles.step, points: this.precomputed.doubles.points.slice(1) }, naf: this.precomputed.naf && { wnd: this.precomputed.naf.wnd, points: this.precomputed.naf.points.slice(1) } }] : [this.x, this.y];
        }, u.fromJSON = function(e3, t3, r3) {
          "string" == typeof t3 && (t3 = JSON.parse(t3));
          var n2 = e3.point(t3[0], t3[1], r3);
          if (!t3[2]) return n2;
          function i2(t4) {
            return e3.point(t4[0], t4[1], r3);
          }
          var o2 = t3[2];
          return n2.precomputed = { beta: null, doubles: o2.doubles && { step: o2.doubles.step, points: [n2].concat(o2.doubles.points.map(i2)) }, naf: o2.naf && { wnd: o2.naf.wnd, points: [n2].concat(o2.naf.points.map(i2)) } }, n2;
        }, u.prototype.inspect = function() {
          return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + ">";
        }, u.prototype.isInfinity = function() {
          return this.inf;
        }, u.prototype.add = function(e3) {
          if (this.inf) return e3;
          if (e3.inf) return this;
          if (this.eq(e3)) return this.dbl();
          if (this.neg().eq(e3)) return this.curve.point(null, null);
          if (0 === this.x.cmp(e3.x)) return this.curve.point(null, null);
          var t3 = this.y.redSub(e3.y);
          0 !== t3.cmpn(0) && (t3 = t3.redMul(this.x.redSub(e3.x).redInvm()));
          var r3 = t3.redSqr().redISub(this.x).redISub(e3.x), n2 = t3.redMul(this.x.redSub(r3)).redISub(this.y);
          return this.curve.point(r3, n2);
        }, u.prototype.dbl = function() {
          if (this.inf) return this;
          var e3 = this.y.redAdd(this.y);
          if (0 === e3.cmpn(0)) return this.curve.point(null, null);
          var t3 = this.curve.a, r3 = this.x.redSqr(), n2 = e3.redInvm(), i2 = r3.redAdd(r3).redIAdd(r3).redIAdd(t3).redMul(n2), o2 = i2.redSqr().redISub(this.x.redAdd(this.x)), s2 = i2.redMul(this.x.redSub(o2)).redISub(this.y);
          return this.curve.point(o2, s2);
        }, u.prototype.getX = function() {
          return this.x.fromRed();
        }, u.prototype.getY = function() {
          return this.y.fromRed();
        }, u.prototype.mul = function(e3) {
          return e3 = new i(e3, 16), this.isInfinity() ? this : this._hasDoubles(e3) ? this.curve._fixedNafMul(this, e3) : this.curve.endo ? this.curve._endoWnafMulAdd([this], [e3]) : this.curve._wnafMul(this, e3);
        }, u.prototype.mulAdd = function(e3, t3, r3) {
          var n2 = [this, t3], i2 = [e3, r3];
          return this.curve.endo ? this.curve._endoWnafMulAdd(n2, i2) : this.curve._wnafMulAdd(1, n2, i2, 2);
        }, u.prototype.jmulAdd = function(e3, t3, r3) {
          var n2 = [this, t3], i2 = [e3, r3];
          return this.curve.endo ? this.curve._endoWnafMulAdd(n2, i2, true) : this.curve._wnafMulAdd(1, n2, i2, 2, true);
        }, u.prototype.eq = function(e3) {
          return this === e3 || this.inf === e3.inf && (this.inf || 0 === this.x.cmp(e3.x) && 0 === this.y.cmp(e3.y));
        }, u.prototype.neg = function(e3) {
          if (this.inf) return this;
          var t3 = this.curve.point(this.x, this.y.redNeg());
          if (e3 && this.precomputed) {
            var r3 = this.precomputed, n2 = function(e4) {
              return e4.neg();
            };
            t3.precomputed = { naf: r3.naf && { wnd: r3.naf.wnd, points: r3.naf.points.map(n2) }, doubles: r3.doubles && { step: r3.doubles.step, points: r3.doubles.points.map(n2) } };
          }
          return t3;
        }, u.prototype.toJ = function() {
          return this.inf ? this.curve.jpoint(null, null, null) : this.curve.jpoint(this.x, this.y, this.curve.one);
        }, o(d, s.BasePoint), c.prototype.jpoint = function(e3, t3, r3) {
          return new d(this, e3, t3, r3);
        }, d.prototype.toP = function() {
          if (this.isInfinity()) return this.curve.point(null, null);
          var e3 = this.z.redInvm(), t3 = e3.redSqr(), r3 = this.x.redMul(t3), n2 = this.y.redMul(t3).redMul(e3);
          return this.curve.point(r3, n2);
        }, d.prototype.neg = function() {
          return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
        }, d.prototype.add = function(e3) {
          if (this.isInfinity()) return e3;
          if (e3.isInfinity()) return this;
          var t3 = e3.z.redSqr(), r3 = this.z.redSqr(), n2 = this.x.redMul(t3), i2 = e3.x.redMul(r3), o2 = this.y.redMul(t3.redMul(e3.z)), s2 = e3.y.redMul(r3.redMul(this.z)), a2 = n2.redSub(i2), c2 = o2.redSub(s2);
          if (0 === a2.cmpn(0)) return 0 !== c2.cmpn(0) ? this.curve.jpoint(null, null, null) : this.dbl();
          var u2 = a2.redSqr(), d2 = u2.redMul(a2), f = n2.redMul(u2), h = c2.redSqr().redIAdd(d2).redISub(f).redISub(f), l = c2.redMul(f.redISub(h)).redISub(o2.redMul(d2)), p = this.z.redMul(e3.z).redMul(a2);
          return this.curve.jpoint(h, l, p);
        }, d.prototype.mixedAdd = function(e3) {
          if (this.isInfinity()) return e3.toJ();
          if (e3.isInfinity()) return this;
          var t3 = this.z.redSqr(), r3 = this.x, n2 = e3.x.redMul(t3), i2 = this.y, o2 = e3.y.redMul(t3).redMul(this.z), s2 = r3.redSub(n2), a2 = i2.redSub(o2);
          if (0 === s2.cmpn(0)) return 0 !== a2.cmpn(0) ? this.curve.jpoint(null, null, null) : this.dbl();
          var c2 = s2.redSqr(), u2 = c2.redMul(s2), d2 = r3.redMul(c2), f = a2.redSqr().redIAdd(u2).redISub(d2).redISub(d2), h = a2.redMul(d2.redISub(f)).redISub(i2.redMul(u2)), l = this.z.redMul(s2);
          return this.curve.jpoint(f, h, l);
        }, d.prototype.dblp = function(e3) {
          if (0 === e3) return this;
          if (this.isInfinity()) return this;
          if (!e3) return this.dbl();
          var t3;
          if (this.curve.zeroA || this.curve.threeA) {
            var r3 = this;
            for (t3 = 0; t3 < e3; t3++) r3 = r3.dbl();
            return r3;
          }
          var n2 = this.curve.a, i2 = this.curve.tinv, o2 = this.x, s2 = this.y, a2 = this.z, c2 = a2.redSqr().redSqr(), u2 = s2.redAdd(s2);
          for (t3 = 0; t3 < e3; t3++) {
            var d2 = o2.redSqr(), f = u2.redSqr(), h = f.redSqr(), l = d2.redAdd(d2).redIAdd(d2).redIAdd(n2.redMul(c2)), p = o2.redMul(f), b = l.redSqr().redISub(p.redAdd(p)), y = p.redISub(b), m = l.redMul(y);
            m = m.redIAdd(m).redISub(h);
            var g = u2.redMul(a2);
            t3 + 1 < e3 && (c2 = c2.redMul(h)), o2 = b, a2 = g, u2 = m;
          }
          return this.curve.jpoint(o2, u2.redMul(i2), a2);
        }, d.prototype.dbl = function() {
          return this.isInfinity() ? this : this.curve.zeroA ? this._zeroDbl() : this.curve.threeA ? this._threeDbl() : this._dbl();
        }, d.prototype._zeroDbl = function() {
          var e3, t3, r3;
          if (this.zOne) {
            var n2 = this.x.redSqr(), i2 = this.y.redSqr(), o2 = i2.redSqr(), s2 = this.x.redAdd(i2).redSqr().redISub(n2).redISub(o2);
            s2 = s2.redIAdd(s2);
            var a2 = n2.redAdd(n2).redIAdd(n2), c2 = a2.redSqr().redISub(s2).redISub(s2), u2 = o2.redIAdd(o2);
            u2 = (u2 = u2.redIAdd(u2)).redIAdd(u2), e3 = c2, t3 = a2.redMul(s2.redISub(c2)).redISub(u2), r3 = this.y.redAdd(this.y);
          } else {
            var d2 = this.x.redSqr(), f = this.y.redSqr(), h = f.redSqr(), l = this.x.redAdd(f).redSqr().redISub(d2).redISub(h);
            l = l.redIAdd(l);
            var p = d2.redAdd(d2).redIAdd(d2), b = p.redSqr(), y = h.redIAdd(h);
            y = (y = y.redIAdd(y)).redIAdd(y), e3 = b.redISub(l).redISub(l), t3 = p.redMul(l.redISub(e3)).redISub(y), r3 = (r3 = this.y.redMul(this.z)).redIAdd(r3);
          }
          return this.curve.jpoint(e3, t3, r3);
        }, d.prototype._threeDbl = function() {
          var e3, t3, r3;
          if (this.zOne) {
            var n2 = this.x.redSqr(), i2 = this.y.redSqr(), o2 = i2.redSqr(), s2 = this.x.redAdd(i2).redSqr().redISub(n2).redISub(o2);
            s2 = s2.redIAdd(s2);
            var a2 = n2.redAdd(n2).redIAdd(n2).redIAdd(this.curve.a), c2 = a2.redSqr().redISub(s2).redISub(s2);
            e3 = c2;
            var u2 = o2.redIAdd(o2);
            u2 = (u2 = u2.redIAdd(u2)).redIAdd(u2), t3 = a2.redMul(s2.redISub(c2)).redISub(u2), r3 = this.y.redAdd(this.y);
          } else {
            var d2 = this.z.redSqr(), f = this.y.redSqr(), h = this.x.redMul(f), l = this.x.redSub(d2).redMul(this.x.redAdd(d2));
            l = l.redAdd(l).redIAdd(l);
            var p = h.redIAdd(h), b = (p = p.redIAdd(p)).redAdd(p);
            e3 = l.redSqr().redISub(b), r3 = this.y.redAdd(this.z).redSqr().redISub(f).redISub(d2);
            var y = f.redSqr();
            y = (y = (y = y.redIAdd(y)).redIAdd(y)).redIAdd(y), t3 = l.redMul(p.redISub(e3)).redISub(y);
          }
          return this.curve.jpoint(e3, t3, r3);
        }, d.prototype._dbl = function() {
          var e3 = this.curve.a, t3 = this.x, r3 = this.y, n2 = this.z, i2 = n2.redSqr().redSqr(), o2 = t3.redSqr(), s2 = r3.redSqr(), a2 = o2.redAdd(o2).redIAdd(o2).redIAdd(e3.redMul(i2)), c2 = t3.redAdd(t3), u2 = (c2 = c2.redIAdd(c2)).redMul(s2), d2 = a2.redSqr().redISub(u2.redAdd(u2)), f = u2.redISub(d2), h = s2.redSqr();
          h = (h = (h = h.redIAdd(h)).redIAdd(h)).redIAdd(h);
          var l = a2.redMul(f).redISub(h), p = r3.redAdd(r3).redMul(n2);
          return this.curve.jpoint(d2, l, p);
        }, d.prototype.trpl = function() {
          if (!this.curve.zeroA) return this.dbl().add(this);
          var e3 = this.x.redSqr(), t3 = this.y.redSqr(), r3 = this.z.redSqr(), n2 = t3.redSqr(), i2 = e3.redAdd(e3).redIAdd(e3), o2 = i2.redSqr(), s2 = this.x.redAdd(t3).redSqr().redISub(e3).redISub(n2), a2 = (s2 = (s2 = (s2 = s2.redIAdd(s2)).redAdd(s2).redIAdd(s2)).redISub(o2)).redSqr(), c2 = n2.redIAdd(n2);
          c2 = (c2 = (c2 = c2.redIAdd(c2)).redIAdd(c2)).redIAdd(c2);
          var u2 = i2.redIAdd(s2).redSqr().redISub(o2).redISub(a2).redISub(c2), d2 = t3.redMul(u2);
          d2 = (d2 = d2.redIAdd(d2)).redIAdd(d2);
          var f = this.x.redMul(a2).redISub(d2);
          f = (f = f.redIAdd(f)).redIAdd(f);
          var h = this.y.redMul(u2.redMul(c2.redISub(u2)).redISub(s2.redMul(a2)));
          h = (h = (h = h.redIAdd(h)).redIAdd(h)).redIAdd(h);
          var l = this.z.redAdd(s2).redSqr().redISub(r3).redISub(a2);
          return this.curve.jpoint(f, h, l);
        }, d.prototype.mul = function(e3, t3) {
          return e3 = new i(e3, t3), this.curve._wnafMul(this, e3);
        }, d.prototype.eq = function(e3) {
          if ("affine" === e3.type) return this.eq(e3.toJ());
          if (this === e3) return true;
          var t3 = this.z.redSqr(), r3 = e3.z.redSqr();
          if (0 !== this.x.redMul(r3).redISub(e3.x.redMul(t3)).cmpn(0)) return false;
          var n2 = t3.redMul(this.z), i2 = r3.redMul(e3.z);
          return 0 === this.y.redMul(i2).redISub(e3.y.redMul(n2)).cmpn(0);
        }, d.prototype.eqXToP = function(e3) {
          var t3 = this.z.redSqr(), r3 = e3.toRed(this.curve.red).redMul(t3);
          if (0 === this.x.cmp(r3)) return true;
          for (var n2 = e3.clone(), i2 = this.curve.redN.redMul(t3); ; ) {
            if (n2.iadd(this.curve.n), n2.cmp(this.curve.p) >= 0) return false;
            if (r3.redIAdd(i2), 0 === this.x.cmp(r3)) return true;
          }
        }, d.prototype.inspect = function() {
          return this.isInfinity() ? "<EC JPoint Infinity>" : "<EC JPoint x: " + this.x.toString(16, 2) + " y: " + this.y.toString(16, 2) + " z: " + this.z.toString(16, 2) + ">";
        }, d.prototype.isInfinity = function() {
          return 0 === this.z.cmpn(0);
        };
      }, 5366: (e2, t2, r2) => {
        "use strict";
        var n, i = t2, o = r2(1631), s = r2(5228), a = r2(9185).assert;
        function c(e3) {
          "short" === e3.type ? this.curve = new s.short(e3) : "edwards" === e3.type ? this.curve = new s.edwards(e3) : this.curve = new s.mont(e3), this.g = this.curve.g, this.n = this.curve.n, this.hash = e3.hash, a(this.g.validate(), "Invalid curve"), a(this.g.mul(this.n).isInfinity(), "Invalid curve, G*N != O");
        }
        function u(e3, t3) {
          Object.defineProperty(i, e3, { configurable: true, enumerable: true, get: function() {
            var r3 = new c(t3);
            return Object.defineProperty(i, e3, { configurable: true, enumerable: true, value: r3 }), r3;
          } });
        }
        i.PresetCurve = c, u("p192", { type: "short", prime: "p192", p: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff", a: "ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc", b: "64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1", n: "ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831", hash: o.sha256, gRed: false, g: ["188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012", "07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811"] }), u("p224", { type: "short", prime: "p224", p: "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001", a: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe", b: "b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4", n: "ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d", hash: o.sha256, gRed: false, g: ["b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21", "bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34"] }), u("p256", { type: "short", prime: null, p: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff", a: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc", b: "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b", n: "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551", hash: o.sha256, gRed: false, g: ["6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296", "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5"] }), u("p384", { type: "short", prime: null, p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff", a: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc", b: "b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef", n: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973", hash: o.sha384, gRed: false, g: ["aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7", "3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f"] }), u("p521", { type: "short", prime: null, p: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff", a: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc", b: "00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00", n: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409", hash: o.sha512, gRed: false, g: ["000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66", "00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650"] }), u("curve25519", { type: "mont", prime: "p25519", p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed", a: "76d06", b: "1", n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed", hash: o.sha256, gRed: false, g: ["9"] }), u("ed25519", { type: "edwards", prime: "p25519", p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed", a: "-1", c: "1", d: "52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3", n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed", hash: o.sha256, gRed: false, g: ["216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", "6666666666666666666666666666666666666666666666666666666666666658"] });
        try {
          n = r2(7153);
        } catch (e3) {
          n = void 0;
        }
        u("secp256k1", { type: "short", prime: "k256", p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f", a: "0", b: "7", n: "ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141", h: "1", hash: o.sha256, beta: "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", lambda: "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", basis: [{ a: "3086d221a7d46bcde86c90e49284eb15", b: "-e4437ed6010e88286f547fa90abfe4c3" }, { a: "114ca50f7a8e2f3f657c1108d9d44cfd8", b: "3086d221a7d46bcde86c90e49284eb15" }], gRed: false, g: ["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", n] });
      }, 2961: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(2519), o = r2(9185), s = r2(5366), a = r2(5442), c = o.assert, u = r2(5666), d = r2(4375);
        function f(e3) {
          if (!(this instanceof f)) return new f(e3);
          "string" == typeof e3 && (c(Object.prototype.hasOwnProperty.call(s, e3), "Unknown curve " + e3), e3 = s[e3]), e3 instanceof s.PresetCurve && (e3 = { curve: e3 }), this.curve = e3.curve.curve, this.n = this.curve.n, this.nh = this.n.ushrn(1), this.g = this.curve.g, this.g = e3.curve.g, this.g.precompute(e3.curve.n.bitLength() + 1), this.hash = e3.hash || e3.curve.hash;
        }
        e2.exports = f, f.prototype.keyPair = function(e3) {
          return new u(this, e3);
        }, f.prototype.keyFromPrivate = function(e3, t3) {
          return u.fromPrivate(this, e3, t3);
        }, f.prototype.keyFromPublic = function(e3, t3) {
          return u.fromPublic(this, e3, t3);
        }, f.prototype.genKeyPair = function(e3) {
          e3 || (e3 = {});
          for (var t3 = new i({ hash: this.hash, pers: e3.pers, persEnc: e3.persEnc || "utf8", entropy: e3.entropy || a(this.hash.hmacStrength), entropyEnc: e3.entropy && e3.entropyEnc || "utf8", nonce: this.n.toArray() }), r3 = this.n.byteLength(), o2 = this.n.sub(new n(2)); ; ) {
            var s2 = new n(t3.generate(r3));
            if (!(s2.cmp(o2) > 0)) return s2.iaddn(1), this.keyFromPrivate(s2);
          }
        }, f.prototype._truncateToN = function(e3, t3, r3) {
          var i2;
          if (n.isBN(e3) || "number" == typeof e3) i2 = (e3 = new n(e3, 16)).byteLength();
          else if ("object" == typeof e3) i2 = e3.length, e3 = new n(e3, 16);
          else {
            var o2 = e3.toString();
            i2 = o2.length + 1 >>> 1, e3 = new n(o2, 16);
          }
          "number" != typeof r3 && (r3 = 8 * i2);
          var s2 = r3 - this.n.bitLength();
          return s2 > 0 && (e3 = e3.ushrn(s2)), !t3 && e3.cmp(this.n) >= 0 ? e3.sub(this.n) : e3;
        }, f.prototype.sign = function(e3, t3, r3, o2) {
          if ("object" == typeof r3 && (o2 = r3, r3 = null), o2 || (o2 = {}), "string" != typeof e3 && "number" != typeof e3 && !n.isBN(e3)) {
            c("object" == typeof e3 && e3 && "number" == typeof e3.length, "Expected message to be an array-like, a hex string, or a BN instance"), c(e3.length >>> 0 === e3.length);
            for (var s2 = 0; s2 < e3.length; s2++) c((255 & e3[s2]) === e3[s2]);
          }
          t3 = this.keyFromPrivate(t3, r3), e3 = this._truncateToN(e3, false, o2.msgBitLength), c(!e3.isNeg(), "Can not sign a negative message");
          var a2 = this.n.byteLength(), u2 = t3.getPrivate().toArray("be", a2), f2 = e3.toArray("be", a2);
          c(new n(f2).eq(e3), "Can not sign message");
          for (var h = new i({ hash: this.hash, entropy: u2, nonce: f2, pers: o2.pers, persEnc: o2.persEnc || "utf8" }), l = this.n.sub(new n(1)), p = 0; ; p++) {
            var b = o2.k ? o2.k(p) : new n(h.generate(this.n.byteLength()));
            if (!((b = this._truncateToN(b, true)).cmpn(1) <= 0 || b.cmp(l) >= 0)) {
              var y = this.g.mul(b);
              if (!y.isInfinity()) {
                var m = y.getX(), g = m.umod(this.n);
                if (0 !== g.cmpn(0)) {
                  var v = b.invm(this.n).mul(g.mul(t3.getPrivate()).iadd(e3));
                  if (0 !== (v = v.umod(this.n)).cmpn(0)) {
                    var w = (y.getY().isOdd() ? 1 : 0) | (0 !== m.cmp(g) ? 2 : 0);
                    return o2.canonical && v.cmp(this.nh) > 0 && (v = this.n.sub(v), w ^= 1), new d({ r: g, s: v, recoveryParam: w });
                  }
                }
              }
            }
          }
        }, f.prototype.verify = function(e3, t3, r3, n2, i2) {
          i2 || (i2 = {}), e3 = this._truncateToN(e3, false, i2.msgBitLength), r3 = this.keyFromPublic(r3, n2);
          var o2 = (t3 = new d(t3, "hex")).r, s2 = t3.s;
          if (o2.cmpn(1) < 0 || o2.cmp(this.n) >= 0) return false;
          if (s2.cmpn(1) < 0 || s2.cmp(this.n) >= 0) return false;
          var a2, c2 = s2.invm(this.n), u2 = c2.mul(e3).umod(this.n), f2 = c2.mul(o2).umod(this.n);
          return this.curve._maxwellTrick ? !(a2 = this.g.jmulAdd(u2, r3.getPublic(), f2)).isInfinity() && a2.eqXToP(o2) : !(a2 = this.g.mulAdd(u2, r3.getPublic(), f2)).isInfinity() && 0 === a2.getX().umod(this.n).cmp(o2);
        }, f.prototype.recoverPubKey = function(e3, t3, r3, i2) {
          c((3 & r3) === r3, "The recovery param is more than two bits"), t3 = new d(t3, i2);
          var o2 = this.n, s2 = new n(e3), a2 = t3.r, u2 = t3.s, f2 = 1 & r3, h = r3 >> 1;
          if (a2.cmp(this.curve.p.umod(this.curve.n)) >= 0 && h) throw new Error("Unable to find sencond key candinate");
          a2 = h ? this.curve.pointFromX(a2.add(this.curve.n), f2) : this.curve.pointFromX(a2, f2);
          var l = t3.r.invm(o2), p = o2.sub(s2).mul(l).umod(o2), b = u2.mul(l).umod(o2);
          return this.g.mulAdd(p, a2, b);
        }, f.prototype.getKeyRecoveryParam = function(e3, t3, r3, n2) {
          if (null !== (t3 = new d(t3, n2)).recoveryParam) return t3.recoveryParam;
          for (var i2 = 0; i2 < 4; i2++) {
            var o2;
            try {
              o2 = this.recoverPubKey(e3, t3, i2);
            } catch (e4) {
              continue;
            }
            if (o2.eq(r3)) return i2;
          }
          throw new Error("Unable to find valid recovery factor");
        };
      }, 5666: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(9185).assert;
        function o(e3, t3) {
          this.ec = e3, this.priv = null, this.pub = null, t3.priv && this._importPrivate(t3.priv, t3.privEnc), t3.pub && this._importPublic(t3.pub, t3.pubEnc);
        }
        e2.exports = o, o.fromPublic = function(e3, t3, r3) {
          return t3 instanceof o ? t3 : new o(e3, { pub: t3, pubEnc: r3 });
        }, o.fromPrivate = function(e3, t3, r3) {
          return t3 instanceof o ? t3 : new o(e3, { priv: t3, privEnc: r3 });
        }, o.prototype.validate = function() {
          var e3 = this.getPublic();
          return e3.isInfinity() ? { result: false, reason: "Invalid public key" } : e3.validate() ? e3.mul(this.ec.curve.n).isInfinity() ? { result: true, reason: null } : { result: false, reason: "Public key * N != O" } : { result: false, reason: "Public key is not a point" };
        }, o.prototype.getPublic = function(e3, t3) {
          return "string" == typeof e3 && (t3 = e3, e3 = null), this.pub || (this.pub = this.ec.g.mul(this.priv)), t3 ? this.pub.encode(t3, e3) : this.pub;
        }, o.prototype.getPrivate = function(e3) {
          return "hex" === e3 ? this.priv.toString(16, 2) : this.priv;
        }, o.prototype._importPrivate = function(e3, t3) {
          this.priv = new n(e3, t3 || 16), this.priv = this.priv.umod(this.ec.curve.n);
        }, o.prototype._importPublic = function(e3, t3) {
          if (e3.x || e3.y) return "mont" === this.ec.curve.type ? i(e3.x, "Need x coordinate") : "short" !== this.ec.curve.type && "edwards" !== this.ec.curve.type || i(e3.x && e3.y, "Need both x and y coordinate"), void (this.pub = this.ec.curve.point(e3.x, e3.y));
          this.pub = this.ec.curve.decodePoint(e3, t3);
        }, o.prototype.derive = function(e3) {
          return e3.validate() || i(e3.validate(), "public point not validated"), e3.mul(this.priv).getX();
        }, o.prototype.sign = function(e3, t3, r3) {
          return this.ec.sign(e3, this, t3, r3);
        }, o.prototype.verify = function(e3, t3, r3) {
          return this.ec.verify(e3, t3, this, void 0, r3);
        }, o.prototype.inspect = function() {
          return "<Key priv: " + (this.priv && this.priv.toString(16, 2)) + " pub: " + (this.pub && this.pub.inspect()) + " >";
        };
      }, 4375: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(9185), o = i.assert;
        function s(e3, t3) {
          if (e3 instanceof s) return e3;
          this._importDER(e3, t3) || (o(e3.r && e3.s, "Signature without r or s"), this.r = new n(e3.r, 16), this.s = new n(e3.s, 16), void 0 === e3.recoveryParam ? this.recoveryParam = null : this.recoveryParam = e3.recoveryParam);
        }
        function a() {
          this.place = 0;
        }
        function c(e3, t3) {
          var r3 = e3[t3.place++];
          if (!(128 & r3)) return r3;
          var n2 = 15 & r3;
          if (0 === n2 || n2 > 4) return false;
          if (0 === e3[t3.place]) return false;
          for (var i2 = 0, o2 = 0, s2 = t3.place; o2 < n2; o2++, s2++) i2 <<= 8, i2 |= e3[s2], i2 >>>= 0;
          return !(i2 <= 127) && (t3.place = s2, i2);
        }
        function u(e3) {
          for (var t3 = 0, r3 = e3.length - 1; !e3[t3] && !(128 & e3[t3 + 1]) && t3 < r3; ) t3++;
          return 0 === t3 ? e3 : e3.slice(t3);
        }
        function d(e3, t3) {
          if (t3 < 128) e3.push(t3);
          else {
            var r3 = 1 + (Math.log(t3) / Math.LN2 >>> 3);
            for (e3.push(128 | r3); --r3; ) e3.push(t3 >>> (r3 << 3) & 255);
            e3.push(t3);
          }
        }
        e2.exports = s, s.prototype._importDER = function(e3, t3) {
          e3 = i.toArray(e3, t3);
          var r3 = new a();
          if (48 !== e3[r3.place++]) return false;
          var o2 = c(e3, r3);
          if (false === o2) return false;
          if (o2 + r3.place !== e3.length) return false;
          if (2 !== e3[r3.place++]) return false;
          var s2 = c(e3, r3);
          if (false === s2) return false;
          if (128 & e3[r3.place]) return false;
          var u2 = e3.slice(r3.place, s2 + r3.place);
          if (r3.place += s2, 2 !== e3[r3.place++]) return false;
          var d2 = c(e3, r3);
          if (false === d2) return false;
          if (e3.length !== d2 + r3.place) return false;
          if (128 & e3[r3.place]) return false;
          var f = e3.slice(r3.place, d2 + r3.place);
          if (0 === u2[0]) {
            if (!(128 & u2[1])) return false;
            u2 = u2.slice(1);
          }
          if (0 === f[0]) {
            if (!(128 & f[1])) return false;
            f = f.slice(1);
          }
          return this.r = new n(u2), this.s = new n(f), this.recoveryParam = null, true;
        }, s.prototype.toDER = function(e3) {
          var t3 = this.r.toArray(), r3 = this.s.toArray();
          for (128 & t3[0] && (t3 = [0].concat(t3)), 128 & r3[0] && (r3 = [0].concat(r3)), t3 = u(t3), r3 = u(r3); !(r3[0] || 128 & r3[1]); ) r3 = r3.slice(1);
          var n2 = [2];
          d(n2, t3.length), (n2 = n2.concat(t3)).push(2), d(n2, r3.length);
          var o2 = n2.concat(r3), s2 = [48];
          return d(s2, o2.length), s2 = s2.concat(o2), i.encode(s2, e3);
        };
      }, 7808: (e2, t2, r2) => {
        "use strict";
        var n = r2(1631), i = r2(5366), o = r2(9185), s = o.assert, a = o.parseBytes, c = r2(6419), u = r2(5406);
        function d(e3) {
          if (s("ed25519" === e3, "only tested with ed25519 so far"), !(this instanceof d)) return new d(e3);
          e3 = i[e3].curve, this.curve = e3, this.g = e3.g, this.g.precompute(e3.n.bitLength() + 1), this.pointClass = e3.point().constructor, this.encodingLength = Math.ceil(e3.n.bitLength() / 8), this.hash = n.sha512;
        }
        e2.exports = d, d.prototype.sign = function(e3, t3) {
          e3 = a(e3);
          var r3 = this.keyFromSecret(t3), n2 = this.hashInt(r3.messagePrefix(), e3), i2 = this.g.mul(n2), o2 = this.encodePoint(i2), s2 = this.hashInt(o2, r3.pubBytes(), e3).mul(r3.priv()), c2 = n2.add(s2).umod(this.curve.n);
          return this.makeSignature({ R: i2, S: c2, Rencoded: o2 });
        }, d.prototype.verify = function(e3, t3, r3) {
          if (e3 = a(e3), (t3 = this.makeSignature(t3)).S().gte(t3.eddsa.curve.n) || t3.S().isNeg()) return false;
          var n2 = this.keyFromPublic(r3), i2 = this.hashInt(t3.Rencoded(), n2.pubBytes(), e3), o2 = this.g.mul(t3.S());
          return t3.R().add(n2.pub().mul(i2)).eq(o2);
        }, d.prototype.hashInt = function() {
          for (var e3 = this.hash(), t3 = 0; t3 < arguments.length; t3++) e3.update(arguments[t3]);
          return o.intFromLE(e3.digest()).umod(this.curve.n);
        }, d.prototype.keyFromPublic = function(e3) {
          return c.fromPublic(this, e3);
        }, d.prototype.keyFromSecret = function(e3) {
          return c.fromSecret(this, e3);
        }, d.prototype.makeSignature = function(e3) {
          return e3 instanceof u ? e3 : new u(this, e3);
        }, d.prototype.encodePoint = function(e3) {
          var t3 = e3.getY().toArray("le", this.encodingLength);
          return t3[this.encodingLength - 1] |= e3.getX().isOdd() ? 128 : 0, t3;
        }, d.prototype.decodePoint = function(e3) {
          var t3 = (e3 = o.parseBytes(e3)).length - 1, r3 = e3.slice(0, t3).concat(-129 & e3[t3]), n2 = !!(128 & e3[t3]), i2 = o.intFromLE(r3);
          return this.curve.pointFromY(i2, n2);
        }, d.prototype.encodeInt = function(e3) {
          return e3.toArray("le", this.encodingLength);
        }, d.prototype.decodeInt = function(e3) {
          return o.intFromLE(e3);
        }, d.prototype.isPoint = function(e3) {
          return e3 instanceof this.pointClass;
        };
      }, 6419: (e2, t2, r2) => {
        "use strict";
        var n = r2(9185), i = n.assert, o = n.parseBytes, s = n.cachedProperty;
        function a(e3, t3) {
          this.eddsa = e3, this._secret = o(t3.secret), e3.isPoint(t3.pub) ? this._pub = t3.pub : this._pubBytes = o(t3.pub);
        }
        a.fromPublic = function(e3, t3) {
          return t3 instanceof a ? t3 : new a(e3, { pub: t3 });
        }, a.fromSecret = function(e3, t3) {
          return t3 instanceof a ? t3 : new a(e3, { secret: t3 });
        }, a.prototype.secret = function() {
          return this._secret;
        }, s(a, "pubBytes", (function() {
          return this.eddsa.encodePoint(this.pub());
        })), s(a, "pub", (function() {
          return this._pubBytes ? this.eddsa.decodePoint(this._pubBytes) : this.eddsa.g.mul(this.priv());
        })), s(a, "privBytes", (function() {
          var e3 = this.eddsa, t3 = this.hash(), r3 = e3.encodingLength - 1, n2 = t3.slice(0, e3.encodingLength);
          return n2[0] &= 248, n2[r3] &= 127, n2[r3] |= 64, n2;
        })), s(a, "priv", (function() {
          return this.eddsa.decodeInt(this.privBytes());
        })), s(a, "hash", (function() {
          return this.eddsa.hash().update(this.secret()).digest();
        })), s(a, "messagePrefix", (function() {
          return this.hash().slice(this.eddsa.encodingLength);
        })), a.prototype.sign = function(e3) {
          return i(this._secret, "KeyPair can only verify"), this.eddsa.sign(e3, this);
        }, a.prototype.verify = function(e3, t3) {
          return this.eddsa.verify(e3, t3, this);
        }, a.prototype.getSecret = function(e3) {
          return i(this._secret, "KeyPair is public only"), n.encode(this.secret(), e3);
        }, a.prototype.getPublic = function(e3) {
          return n.encode(this.pubBytes(), e3);
        }, e2.exports = a;
      }, 5406: (e2, t2, r2) => {
        "use strict";
        var n = r2(4619), i = r2(9185), o = i.assert, s = i.cachedProperty, a = i.parseBytes;
        function c(e3, t3) {
          this.eddsa = e3, "object" != typeof t3 && (t3 = a(t3)), Array.isArray(t3) && (o(t3.length === 2 * e3.encodingLength, "Signature has invalid size"), t3 = { R: t3.slice(0, e3.encodingLength), S: t3.slice(e3.encodingLength) }), o(t3.R && t3.S, "Signature without R or S"), e3.isPoint(t3.R) && (this._R = t3.R), t3.S instanceof n && (this._S = t3.S), this._Rencoded = Array.isArray(t3.R) ? t3.R : t3.Rencoded, this._Sencoded = Array.isArray(t3.S) ? t3.S : t3.Sencoded;
        }
        s(c, "S", (function() {
          return this.eddsa.decodeInt(this.Sencoded());
        })), s(c, "R", (function() {
          return this.eddsa.decodePoint(this.Rencoded());
        })), s(c, "Rencoded", (function() {
          return this.eddsa.encodePoint(this.R());
        })), s(c, "Sencoded", (function() {
          return this.eddsa.encodeInt(this.S());
        })), c.prototype.toBytes = function() {
          return this.Rencoded().concat(this.Sencoded());
        }, c.prototype.toHex = function() {
          return i.encode(this.toBytes(), "hex").toUpperCase();
        }, e2.exports = c;
      }, 7153: (e2) => {
        e2.exports = { doubles: { step: 4, points: [["e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a", "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821"], ["8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508", "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"], ["175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739", "d3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695"], ["363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640", "4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9"], ["8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c", "4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36"], ["723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda", "96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f"], ["eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa", "5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999"], ["100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0", "cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09"], ["e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d", "9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d"], ["feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d", "e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088"], ["da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1", "9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d"], ["53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0", "5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8"], ["8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047", "10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a"], ["385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862", "283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453"], ["6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7", "7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160"], ["3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd", "56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0"], ["85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83", "7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6"], ["948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a", "53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589"], ["6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8", "bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17"], ["e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d", "4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda"], ["e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725", "7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd"], ["213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754", "4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2"], ["4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c", "17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6"], ["fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6", "6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f"], ["76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39", "c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01"], ["c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891", "893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3"], ["d895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b", "febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f"], ["b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03", "2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7"], ["e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d", "eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78"], ["a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070", "7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1"], ["90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4", "e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150"], ["8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da", "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82"], ["e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11", "1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc"], ["8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e", "efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b"], ["e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41", "2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51"], ["b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef", "67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45"], ["d68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8", "db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120"], ["324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d", "648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84"], ["4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96", "35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d"], ["9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd", "ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d"], ["6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5", "9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8"], ["a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266", "40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8"], ["7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71", "34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac"], ["928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac", "c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f"], ["85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751", "1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962"], ["ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e", "493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907"], ["827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241", "c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec"], ["eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3", "be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d"], ["e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f", "4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414"], ["1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19", "aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd"], ["146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be", "b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0"], ["fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9", "6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811"], ["da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2", "8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1"], ["a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13", "7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c"], ["174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c", "ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73"], ["959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba", "2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd"], ["d2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151", "e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405"], ["64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073", "d99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589"], ["8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458", "38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e"], ["13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b", "69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27"], ["bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366", "d3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1"], ["8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa", "40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482"], ["8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0", "620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945"], ["dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787", "7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573"], ["f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e", "ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82"]] }, naf: { wnd: 7, points: [["f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"], ["2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4", "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"], ["5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"], ["acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe", "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37"], ["774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb", "d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b"], ["f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8", "ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"], ["d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e", "581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58"], ["defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", "4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77"], ["2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c", "85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a"], ["352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5", "321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c"], ["2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f", "2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67"], ["9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714", "73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402"], ["daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729", "a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55"], ["c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db", "2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482"], ["6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4", "e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82"], ["1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5", "b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396"], ["605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479", "2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49"], ["62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d", "80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf"], ["80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f", "1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a"], ["7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb", "d0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7"], ["d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9", "eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933"], ["49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963", "758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a"], ["77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74", "958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6"], ["f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530", "e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37"], ["463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b", "5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e"], ["f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247", "cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6"], ["caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1", "cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476"], ["2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120", "4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40"], ["7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435", "91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61"], ["754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18", "673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683"], ["e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8", "59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5"], ["186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb", "3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b"], ["df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f", "55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417"], ["5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143", "efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868"], ["290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba", "e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a"], ["af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45", "f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6"], ["766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a", "744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996"], ["59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e", "c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e"], ["f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8", "e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d"], ["7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c", "30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2"], ["948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519", "e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e"], ["7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab", "100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437"], ["3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca", "ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311"], ["d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf", "8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4"], ["1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610", "68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575"], ["733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4", "f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d"], ["15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c", "d56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d"], ["a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940", "edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629"], ["e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980", "a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06"], ["311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3", "66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374"], ["34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf", "9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee"], ["f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63", "4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1"], ["d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448", "fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b"], ["32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf", "5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661"], ["7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5", "8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6"], ["ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6", "8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e"], ["16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5", "5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d"], ["eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99", "f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc"], ["78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51", "f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4"], ["494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5", "42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c"], ["a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5", "204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b"], ["c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997", "4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913"], ["841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881", "73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154"], ["5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5", "39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865"], ["36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66", "d2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc"], ["336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726", "ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224"], ["8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede", "6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e"], ["1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94", "60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6"], ["85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31", "3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511"], ["29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51", "b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b"], ["a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252", "ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2"], ["4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5", "cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c"], ["d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b", "6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3"], ["ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4", "322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d"], ["af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f", "6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700"], ["e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889", "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4"], ["591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246", "b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196"], ["11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984", "998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4"], ["3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a", "b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257"], ["cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030", "bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13"], ["c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197", "6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096"], ["c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593", "c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38"], ["a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef", "21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f"], ["347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38", "60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448"], ["da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a", "49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a"], ["c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111", "5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4"], ["4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502", "7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437"], ["3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea", "be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7"], ["cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26", "8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d"], ["b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986", "39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a"], ["d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e", "62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54"], ["48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4", "25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77"], ["dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda", "ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517"], ["6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859", "cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10"], ["e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f", "f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125"], ["eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c", "6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e"], ["13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942", "fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1"], ["ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a", "1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2"], ["b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80", "5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423"], ["ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d", "438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8"], ["8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1", "cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758"], ["52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63", "c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375"], ["e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352", "6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d"], ["7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193", "ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec"], ["5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00", "9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0"], ["32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58", "ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c"], ["e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7", "d3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4"], ["8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8", "c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f"], ["4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e", "67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649"], ["3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d", "cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826"], ["674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b", "299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5"], ["d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f", "f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87"], ["30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6", "462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b"], ["be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297", "62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc"], ["93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a", "7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c"], ["b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c", "ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f"], ["d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52", "4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a"], ["d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb", "bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46"], ["463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065", "bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f"], ["7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917", "603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03"], ["74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9", "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08"], ["30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3", "553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8"], ["9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57", "712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373"], ["176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66", "ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3"], ["75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8", "9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8"], ["809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721", "9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1"], ["1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180", "4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9"]] } };
      }, 9185: (e2, t2, r2) => {
        "use strict";
        var n = t2, i = r2(4619), o = r2(5578), s = r2(4209);
        n.assert = o, n.toArray = s.toArray, n.zero2 = s.zero2, n.toHex = s.toHex, n.encode = s.encode, n.getNAF = function(e3, t3, r3) {
          var n2, i2 = new Array(Math.max(e3.bitLength(), r3) + 1);
          for (n2 = 0; n2 < i2.length; n2 += 1) i2[n2] = 0;
          var o2 = 1 << t3 + 1, s2 = e3.clone();
          for (n2 = 0; n2 < i2.length; n2++) {
            var a, c = s2.andln(o2 - 1);
            s2.isOdd() ? (a = c > (o2 >> 1) - 1 ? (o2 >> 1) - c : c, s2.isubn(a)) : a = 0, i2[n2] = a, s2.iushrn(1);
          }
          return i2;
        }, n.getJSF = function(e3, t3) {
          var r3 = [[], []];
          e3 = e3.clone(), t3 = t3.clone();
          for (var n2, i2 = 0, o2 = 0; e3.cmpn(-i2) > 0 || t3.cmpn(-o2) > 0; ) {
            var s2, a, c = e3.andln(3) + i2 & 3, u = t3.andln(3) + o2 & 3;
            3 === c && (c = -1), 3 === u && (u = -1), s2 = 1 & c ? 3 != (n2 = e3.andln(7) + i2 & 7) && 5 !== n2 || 2 !== u ? c : -c : 0, r3[0].push(s2), a = 1 & u ? 3 != (n2 = t3.andln(7) + o2 & 7) && 5 !== n2 || 2 !== c ? u : -u : 0, r3[1].push(a), 2 * i2 === s2 + 1 && (i2 = 1 - i2), 2 * o2 === a + 1 && (o2 = 1 - o2), e3.iushrn(1), t3.iushrn(1);
          }
          return r3;
        }, n.cachedProperty = function(e3, t3, r3) {
          var n2 = "_" + t3;
          e3.prototype[t3] = function() {
            return void 0 !== this[n2] ? this[n2] : this[n2] = r3.call(this);
          };
        }, n.parseBytes = function(e3) {
          return "string" == typeof e3 ? n.toArray(e3, "hex") : e3;
        }, n.intFromLE = function(e3) {
          return new i(e3, "hex", "le");
        };
      }, 2579: (e2) => {
        "use strict";
        var t2 = Object.prototype.hasOwnProperty, r2 = "~";
        function n() {
        }
        function i(e3, t3, r3) {
          this.fn = e3, this.context = t3, this.once = r3 || false;
        }
        function o(e3, t3, n2, o2, s2) {
          if ("function" != typeof n2) throw new TypeError("The listener must be a function");
          var a2 = new i(n2, o2 || e3, s2), c = r2 ? r2 + t3 : t3;
          return e3._events[c] ? e3._events[c].fn ? e3._events[c] = [e3._events[c], a2] : e3._events[c].push(a2) : (e3._events[c] = a2, e3._eventsCount++), e3;
        }
        function s(e3, t3) {
          0 == --e3._eventsCount ? e3._events = new n() : delete e3._events[t3];
        }
        function a() {
          this._events = new n(), this._eventsCount = 0;
        }
        Object.create && (n.prototype = /* @__PURE__ */ Object.create(null), new n().__proto__ || (r2 = false)), a.prototype.eventNames = function() {
          var e3, n2, i2 = [];
          if (0 === this._eventsCount) return i2;
          for (n2 in e3 = this._events) t2.call(e3, n2) && i2.push(r2 ? n2.slice(1) : n2);
          return Object.getOwnPropertySymbols ? i2.concat(Object.getOwnPropertySymbols(e3)) : i2;
        }, a.prototype.listeners = function(e3) {
          var t3 = r2 ? r2 + e3 : e3, n2 = this._events[t3];
          if (!n2) return [];
          if (n2.fn) return [n2.fn];
          for (var i2 = 0, o2 = n2.length, s2 = new Array(o2); i2 < o2; i2++) s2[i2] = n2[i2].fn;
          return s2;
        }, a.prototype.listenerCount = function(e3) {
          var t3 = r2 ? r2 + e3 : e3, n2 = this._events[t3];
          return n2 ? n2.fn ? 1 : n2.length : 0;
        }, a.prototype.emit = function(e3, t3, n2, i2, o2, s2) {
          var a2 = r2 ? r2 + e3 : e3;
          if (!this._events[a2]) return false;
          var c, u, d = this._events[a2], f = arguments.length;
          if (d.fn) {
            switch (d.once && this.removeListener(e3, d.fn, void 0, true), f) {
              case 1:
                return d.fn.call(d.context), true;
              case 2:
                return d.fn.call(d.context, t3), true;
              case 3:
                return d.fn.call(d.context, t3, n2), true;
              case 4:
                return d.fn.call(d.context, t3, n2, i2), true;
              case 5:
                return d.fn.call(d.context, t3, n2, i2, o2), true;
              case 6:
                return d.fn.call(d.context, t3, n2, i2, o2, s2), true;
            }
            for (u = 1, c = new Array(f - 1); u < f; u++) c[u - 1] = arguments[u];
            d.fn.apply(d.context, c);
          } else {
            var h, l = d.length;
            for (u = 0; u < l; u++) switch (d[u].once && this.removeListener(e3, d[u].fn, void 0, true), f) {
              case 1:
                d[u].fn.call(d[u].context);
                break;
              case 2:
                d[u].fn.call(d[u].context, t3);
                break;
              case 3:
                d[u].fn.call(d[u].context, t3, n2);
                break;
              case 4:
                d[u].fn.call(d[u].context, t3, n2, i2);
                break;
              default:
                if (!c) for (h = 1, c = new Array(f - 1); h < f; h++) c[h - 1] = arguments[h];
                d[u].fn.apply(d[u].context, c);
            }
          }
          return true;
        }, a.prototype.on = function(e3, t3, r3) {
          return o(this, e3, t3, r3, false);
        }, a.prototype.once = function(e3, t3, r3) {
          return o(this, e3, t3, r3, true);
        }, a.prototype.removeListener = function(e3, t3, n2, i2) {
          var o2 = r2 ? r2 + e3 : e3;
          if (!this._events[o2]) return this;
          if (!t3) return s(this, o2), this;
          var a2 = this._events[o2];
          if (a2.fn) a2.fn !== t3 || i2 && !a2.once || n2 && a2.context !== n2 || s(this, o2);
          else {
            for (var c = 0, u = [], d = a2.length; c < d; c++) (a2[c].fn !== t3 || i2 && !a2[c].once || n2 && a2[c].context !== n2) && u.push(a2[c]);
            u.length ? this._events[o2] = 1 === u.length ? u[0] : u : s(this, o2);
          }
          return this;
        }, a.prototype.removeAllListeners = function(e3) {
          var t3;
          return e3 ? (t3 = r2 ? r2 + e3 : e3, this._events[t3] && s(this, t3)) : (this._events = new n(), this._eventsCount = 0), this;
        }, a.prototype.off = a.prototype.removeListener, a.prototype.addListener = a.prototype.on, a.prefixed = r2, a.EventEmitter = a, e2.exports = a;
      }, 381: (e2) => {
        "use strict";
        var t2, r2 = "object" == typeof Reflect ? Reflect : null, n = r2 && "function" == typeof r2.apply ? r2.apply : function(e3, t3, r3) {
          return Function.prototype.apply.call(e3, t3, r3);
        };
        t2 = r2 && "function" == typeof r2.ownKeys ? r2.ownKeys : Object.getOwnPropertySymbols ? function(e3) {
          return Object.getOwnPropertyNames(e3).concat(Object.getOwnPropertySymbols(e3));
        } : function(e3) {
          return Object.getOwnPropertyNames(e3);
        };
        var i = Number.isNaN || function(e3) {
          return e3 != e3;
        };
        function o() {
          o.init.call(this);
        }
        e2.exports = o, e2.exports.once = function(e3, t3) {
          return new Promise((function(r3, n2) {
            function i2(r4) {
              e3.removeListener(t3, o2), n2(r4);
            }
            function o2() {
              "function" == typeof e3.removeListener && e3.removeListener("error", i2), r3([].slice.call(arguments));
            }
            b(e3, t3, o2, { once: true }), "error" !== t3 && (function(e4, t4) {
              "function" == typeof e4.on && b(e4, "error", t4, { once: true });
            })(e3, i2);
          }));
        }, o.EventEmitter = o, o.prototype._events = void 0, o.prototype._eventsCount = 0, o.prototype._maxListeners = void 0;
        var s = 10;
        function a(e3) {
          if ("function" != typeof e3) throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof e3);
        }
        function c(e3) {
          return void 0 === e3._maxListeners ? o.defaultMaxListeners : e3._maxListeners;
        }
        function u(e3, t3, r3, n2) {
          var i2, o2, s2, u2;
          if (a(r3), void 0 === (o2 = e3._events) ? (o2 = e3._events = /* @__PURE__ */ Object.create(null), e3._eventsCount = 0) : (void 0 !== o2.newListener && (e3.emit("newListener", t3, r3.listener ? r3.listener : r3), o2 = e3._events), s2 = o2[t3]), void 0 === s2) s2 = o2[t3] = r3, ++e3._eventsCount;
          else if ("function" == typeof s2 ? s2 = o2[t3] = n2 ? [r3, s2] : [s2, r3] : n2 ? s2.unshift(r3) : s2.push(r3), (i2 = c(e3)) > 0 && s2.length > i2 && !s2.warned) {
            s2.warned = true;
            var d2 = new Error("Possible EventEmitter memory leak detected. " + s2.length + " " + String(t3) + " listeners added. Use emitter.setMaxListeners() to increase limit");
            d2.name = "MaxListenersExceededWarning", d2.emitter = e3, d2.type = t3, d2.count = s2.length, u2 = d2, console && console.warn && console.warn(u2);
          }
          return e3;
        }
        function d() {
          if (!this.fired) return this.target.removeListener(this.type, this.wrapFn), this.fired = true, 0 === arguments.length ? this.listener.call(this.target) : this.listener.apply(this.target, arguments);
        }
        function f(e3, t3, r3) {
          var n2 = { fired: false, wrapFn: void 0, target: e3, type: t3, listener: r3 }, i2 = d.bind(n2);
          return i2.listener = r3, n2.wrapFn = i2, i2;
        }
        function h(e3, t3, r3) {
          var n2 = e3._events;
          if (void 0 === n2) return [];
          var i2 = n2[t3];
          return void 0 === i2 ? [] : "function" == typeof i2 ? r3 ? [i2.listener || i2] : [i2] : r3 ? (function(e4) {
            for (var t4 = new Array(e4.length), r4 = 0; r4 < t4.length; ++r4) t4[r4] = e4[r4].listener || e4[r4];
            return t4;
          })(i2) : p(i2, i2.length);
        }
        function l(e3) {
          var t3 = this._events;
          if (void 0 !== t3) {
            var r3 = t3[e3];
            if ("function" == typeof r3) return 1;
            if (void 0 !== r3) return r3.length;
          }
          return 0;
        }
        function p(e3, t3) {
          for (var r3 = new Array(t3), n2 = 0; n2 < t3; ++n2) r3[n2] = e3[n2];
          return r3;
        }
        function b(e3, t3, r3, n2) {
          if ("function" == typeof e3.on) n2.once ? e3.once(t3, r3) : e3.on(t3, r3);
          else {
            if ("function" != typeof e3.addEventListener) throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof e3);
            e3.addEventListener(t3, (function i2(o2) {
              n2.once && e3.removeEventListener(t3, i2), r3(o2);
            }));
          }
        }
        Object.defineProperty(o, "defaultMaxListeners", { enumerable: true, get: function() {
          return s;
        }, set: function(e3) {
          if ("number" != typeof e3 || e3 < 0 || i(e3)) throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + e3 + ".");
          s = e3;
        } }), o.init = function() {
          void 0 !== this._events && this._events !== Object.getPrototypeOf(this)._events || (this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0), this._maxListeners = this._maxListeners || void 0;
        }, o.prototype.setMaxListeners = function(e3) {
          if ("number" != typeof e3 || e3 < 0 || i(e3)) throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + e3 + ".");
          return this._maxListeners = e3, this;
        }, o.prototype.getMaxListeners = function() {
          return c(this);
        }, o.prototype.emit = function(e3) {
          for (var t3 = [], r3 = 1; r3 < arguments.length; r3++) t3.push(arguments[r3]);
          var i2 = "error" === e3, o2 = this._events;
          if (void 0 !== o2) i2 = i2 && void 0 === o2.error;
          else if (!i2) return false;
          if (i2) {
            var s2;
            if (t3.length > 0 && (s2 = t3[0]), s2 instanceof Error) throw s2;
            var a2 = new Error("Unhandled error." + (s2 ? " (" + s2.message + ")" : ""));
            throw a2.context = s2, a2;
          }
          var c2 = o2[e3];
          if (void 0 === c2) return false;
          if ("function" == typeof c2) n(c2, this, t3);
          else {
            var u2 = c2.length, d2 = p(c2, u2);
            for (r3 = 0; r3 < u2; ++r3) n(d2[r3], this, t3);
          }
          return true;
        }, o.prototype.addListener = function(e3, t3) {
          return u(this, e3, t3, false);
        }, o.prototype.on = o.prototype.addListener, o.prototype.prependListener = function(e3, t3) {
          return u(this, e3, t3, true);
        }, o.prototype.once = function(e3, t3) {
          return a(t3), this.on(e3, f(this, e3, t3)), this;
        }, o.prototype.prependOnceListener = function(e3, t3) {
          return a(t3), this.prependListener(e3, f(this, e3, t3)), this;
        }, o.prototype.removeListener = function(e3, t3) {
          var r3, n2, i2, o2, s2;
          if (a(t3), void 0 === (n2 = this._events)) return this;
          if (void 0 === (r3 = n2[e3])) return this;
          if (r3 === t3 || r3.listener === t3) 0 == --this._eventsCount ? this._events = /* @__PURE__ */ Object.create(null) : (delete n2[e3], n2.removeListener && this.emit("removeListener", e3, r3.listener || t3));
          else if ("function" != typeof r3) {
            for (i2 = -1, o2 = r3.length - 1; o2 >= 0; o2--) if (r3[o2] === t3 || r3[o2].listener === t3) {
              s2 = r3[o2].listener, i2 = o2;
              break;
            }
            if (i2 < 0) return this;
            0 === i2 ? r3.shift() : (function(e4, t4) {
              for (; t4 + 1 < e4.length; t4++) e4[t4] = e4[t4 + 1];
              e4.pop();
            })(r3, i2), 1 === r3.length && (n2[e3] = r3[0]), void 0 !== n2.removeListener && this.emit("removeListener", e3, s2 || t3);
          }
          return this;
        }, o.prototype.off = o.prototype.removeListener, o.prototype.removeAllListeners = function(e3) {
          var t3, r3, n2;
          if (void 0 === (r3 = this._events)) return this;
          if (void 0 === r3.removeListener) return 0 === arguments.length ? (this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0) : void 0 !== r3[e3] && (0 == --this._eventsCount ? this._events = /* @__PURE__ */ Object.create(null) : delete r3[e3]), this;
          if (0 === arguments.length) {
            var i2, o2 = Object.keys(r3);
            for (n2 = 0; n2 < o2.length; ++n2) "removeListener" !== (i2 = o2[n2]) && this.removeAllListeners(i2);
            return this.removeAllListeners("removeListener"), this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0, this;
          }
          if ("function" == typeof (t3 = r3[e3])) this.removeListener(e3, t3);
          else if (void 0 !== t3) for (n2 = t3.length - 1; n2 >= 0; n2--) this.removeListener(e3, t3[n2]);
          return this;
        }, o.prototype.listeners = function(e3) {
          return h(this, e3, true);
        }, o.prototype.rawListeners = function(e3) {
          return h(this, e3, false);
        }, o.listenerCount = function(e3, t3) {
          return "function" == typeof e3.listenerCount ? e3.listenerCount(t3) : l.call(e3, t3);
        }, o.prototype.listenerCount = l, o.prototype.eventNames = function() {
          return this._eventsCount > 0 ? t2(this._events) : [];
        };
      }, 1804: (e2, t2, r2) => {
        var n = r2(6608).Buffer, i = r2(5035);
        e2.exports = function(e3, t3, r3, o) {
          if (n.isBuffer(e3) || (e3 = n.from(e3, "binary")), t3 && (n.isBuffer(t3) || (t3 = n.from(t3, "binary")), 8 !== t3.length)) throw new RangeError("salt should be Buffer with 8 byte length");
          for (var s = r3 / 8, a = n.alloc(s), c = n.alloc(o || 0), u = n.alloc(0); s > 0 || o > 0; ) {
            var d = new i();
            d.update(u), d.update(e3), t3 && d.update(t3), u = d.digest();
            var f = 0;
            if (s > 0) {
              var h = a.length - s;
              f = Math.min(s, u.length), u.copy(a, h, 0, f), s -= f;
            }
            if (f < u.length && o > 0) {
              var l = c.length - o, p = Math.min(o, u.length - f);
              u.copy(c, l, f, f + p), o -= p;
            }
          }
          return u.fill(0), { key: a, iv: c };
        };
      }, 800: (e2, t2, r2) => {
        "use strict";
        var n = r2(6608).Buffer, i = r2(1094).Transform;
        function o(e3) {
          i.call(this), this._block = n.allocUnsafe(e3), this._blockSize = e3, this._blockOffset = 0, this._length = [0, 0, 0, 0], this._finalized = false;
        }
        r2(1193)(o, i), o.prototype._transform = function(e3, t3, r3) {
          var n2 = null;
          try {
            this.update(e3, t3);
          } catch (e4) {
            n2 = e4;
          }
          r3(n2);
        }, o.prototype._flush = function(e3) {
          var t3 = null;
          try {
            this.push(this.digest());
          } catch (e4) {
            t3 = e4;
          }
          e3(t3);
        }, o.prototype.update = function(e3, t3) {
          if ((function(e4) {
            if (!n.isBuffer(e4) && "string" != typeof e4) throw new TypeError("Data must be a string or a buffer");
          })(e3), this._finalized) throw new Error("Digest already called");
          n.isBuffer(e3) || (e3 = n.from(e3, t3));
          for (var r3 = this._block, i2 = 0; this._blockOffset + e3.length - i2 >= this._blockSize; ) {
            for (var o2 = this._blockOffset; o2 < this._blockSize; ) r3[o2++] = e3[i2++];
            this._update(), this._blockOffset = 0;
          }
          for (; i2 < e3.length; ) r3[this._blockOffset++] = e3[i2++];
          for (var s = 0, a = 8 * e3.length; a > 0; ++s) this._length[s] += a, (a = this._length[s] / 4294967296 | 0) > 0 && (this._length[s] -= 4294967296 * a);
          return this;
        }, o.prototype._update = function() {
          throw new Error("_update is not implemented");
        }, o.prototype.digest = function(e3) {
          if (this._finalized) throw new Error("Digest already called");
          this._finalized = true;
          var t3 = this._digest();
          void 0 !== e3 && (t3 = t3.toString(e3)), this._block.fill(0), this._blockOffset = 0;
          for (var r3 = 0; r3 < 4; ++r3) this._length[r3] = 0;
          return t3;
        }, o.prototype._digest = function() {
          throw new Error("_digest is not implemented");
        }, e2.exports = o;
      }, 1631: (e2, t2, r2) => {
        var n = t2;
        n.utils = r2(7905), n.common = r2(4427), n.sha = r2(1822), n.ripemd = r2(7317), n.hmac = r2(7309), n.sha1 = n.sha.sha1, n.sha256 = n.sha.sha256, n.sha224 = n.sha.sha224, n.sha384 = n.sha.sha384, n.sha512 = n.sha.sha512, n.ripemd160 = n.ripemd.ripemd160;
      }, 4427: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(5578);
        function o() {
          this.pending = null, this.pendingTotal = 0, this.blockSize = this.constructor.blockSize, this.outSize = this.constructor.outSize, this.hmacStrength = this.constructor.hmacStrength, this.padLength = this.constructor.padLength / 8, this.endian = "big", this._delta8 = this.blockSize / 8, this._delta32 = this.blockSize / 32;
        }
        t2.BlockHash = o, o.prototype.update = function(e3, t3) {
          if (e3 = n.toArray(e3, t3), this.pending ? this.pending = this.pending.concat(e3) : this.pending = e3, this.pendingTotal += e3.length, this.pending.length >= this._delta8) {
            var r3 = (e3 = this.pending).length % this._delta8;
            this.pending = e3.slice(e3.length - r3, e3.length), 0 === this.pending.length && (this.pending = null), e3 = n.join32(e3, 0, e3.length - r3, this.endian);
            for (var i2 = 0; i2 < e3.length; i2 += this._delta32) this._update(e3, i2, i2 + this._delta32);
          }
          return this;
        }, o.prototype.digest = function(e3) {
          return this.update(this._pad()), i(null === this.pending), this._digest(e3);
        }, o.prototype._pad = function() {
          var e3 = this.pendingTotal, t3 = this._delta8, r3 = t3 - (e3 + this.padLength) % t3, n2 = new Array(r3 + this.padLength);
          n2[0] = 128;
          for (var i2 = 1; i2 < r3; i2++) n2[i2] = 0;
          if (e3 <<= 3, "big" === this.endian) {
            for (var o2 = 8; o2 < this.padLength; o2++) n2[i2++] = 0;
            n2[i2++] = 0, n2[i2++] = 0, n2[i2++] = 0, n2[i2++] = 0, n2[i2++] = e3 >>> 24 & 255, n2[i2++] = e3 >>> 16 & 255, n2[i2++] = e3 >>> 8 & 255, n2[i2++] = 255 & e3;
          } else for (n2[i2++] = 255 & e3, n2[i2++] = e3 >>> 8 & 255, n2[i2++] = e3 >>> 16 & 255, n2[i2++] = e3 >>> 24 & 255, n2[i2++] = 0, n2[i2++] = 0, n2[i2++] = 0, n2[i2++] = 0, o2 = 8; o2 < this.padLength; o2++) n2[i2++] = 0;
          return n2;
        };
      }, 7309: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(5578);
        function o(e3, t3, r3) {
          if (!(this instanceof o)) return new o(e3, t3, r3);
          this.Hash = e3, this.blockSize = e3.blockSize / 8, this.outSize = e3.outSize / 8, this.inner = null, this.outer = null, this._init(n.toArray(t3, r3));
        }
        e2.exports = o, o.prototype._init = function(e3) {
          e3.length > this.blockSize && (e3 = new this.Hash().update(e3).digest()), i(e3.length <= this.blockSize);
          for (var t3 = e3.length; t3 < this.blockSize; t3++) e3.push(0);
          for (t3 = 0; t3 < e3.length; t3++) e3[t3] ^= 54;
          for (this.inner = new this.Hash().update(e3), t3 = 0; t3 < e3.length; t3++) e3[t3] ^= 106;
          this.outer = new this.Hash().update(e3);
        }, o.prototype.update = function(e3, t3) {
          return this.inner.update(e3, t3), this;
        }, o.prototype.digest = function(e3) {
          return this.outer.update(this.inner.digest()), this.outer.digest(e3);
        };
      }, 7317: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(4427), o = n.rotl32, s = n.sum32, a = n.sum32_3, c = n.sum32_4, u = i.BlockHash;
        function d() {
          if (!(this instanceof d)) return new d();
          u.call(this), this.h = [1732584193, 4023233417, 2562383102, 271733878, 3285377520], this.endian = "little";
        }
        function f(e3, t3, r3, n2) {
          return e3 <= 15 ? t3 ^ r3 ^ n2 : e3 <= 31 ? t3 & r3 | ~t3 & n2 : e3 <= 47 ? (t3 | ~r3) ^ n2 : e3 <= 63 ? t3 & n2 | r3 & ~n2 : t3 ^ (r3 | ~n2);
        }
        function h(e3) {
          return e3 <= 15 ? 0 : e3 <= 31 ? 1518500249 : e3 <= 47 ? 1859775393 : e3 <= 63 ? 2400959708 : 2840853838;
        }
        function l(e3) {
          return e3 <= 15 ? 1352829926 : e3 <= 31 ? 1548603684 : e3 <= 47 ? 1836072691 : e3 <= 63 ? 2053994217 : 0;
        }
        n.inherits(d, u), t2.ripemd160 = d, d.blockSize = 512, d.outSize = 160, d.hmacStrength = 192, d.padLength = 64, d.prototype._update = function(e3, t3) {
          for (var r3 = this.h[0], n2 = this.h[1], i2 = this.h[2], u2 = this.h[3], d2 = this.h[4], g = r3, v = n2, w = i2, _ = u2, A = d2, S = 0; S < 80; S++) {
            var C = s(o(c(r3, f(S, n2, i2, u2), e3[p[S] + t3], h(S)), y[S]), d2);
            r3 = d2, d2 = u2, u2 = o(i2, 10), i2 = n2, n2 = C, C = s(o(c(g, f(79 - S, v, w, _), e3[b[S] + t3], l(S)), m[S]), A), g = A, A = _, _ = o(w, 10), w = v, v = C;
          }
          C = a(this.h[1], i2, _), this.h[1] = a(this.h[2], u2, A), this.h[2] = a(this.h[3], d2, g), this.h[3] = a(this.h[4], r3, v), this.h[4] = a(this.h[0], n2, w), this.h[0] = C;
        }, d.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h, "little") : n.split32(this.h, "little");
        };
        var p = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13], b = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11], y = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6], m = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
      }, 1822: (e2, t2, r2) => {
        "use strict";
        t2.sha1 = r2(2750), t2.sha224 = r2(7485), t2.sha256 = r2(7292), t2.sha384 = r2(696), t2.sha512 = r2(8889);
      }, 2750: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(4427), o = r2(5660), s = n.rotl32, a = n.sum32, c = n.sum32_5, u = o.ft_1, d = i.BlockHash, f = [1518500249, 1859775393, 2400959708, 3395469782];
        function h() {
          if (!(this instanceof h)) return new h();
          d.call(this), this.h = [1732584193, 4023233417, 2562383102, 271733878, 3285377520], this.W = new Array(80);
        }
        n.inherits(h, d), e2.exports = h, h.blockSize = 512, h.outSize = 160, h.hmacStrength = 80, h.padLength = 64, h.prototype._update = function(e3, t3) {
          for (var r3 = this.W, n2 = 0; n2 < 16; n2++) r3[n2] = e3[t3 + n2];
          for (; n2 < r3.length; n2++) r3[n2] = s(r3[n2 - 3] ^ r3[n2 - 8] ^ r3[n2 - 14] ^ r3[n2 - 16], 1);
          var i2 = this.h[0], o2 = this.h[1], d2 = this.h[2], h2 = this.h[3], l = this.h[4];
          for (n2 = 0; n2 < r3.length; n2++) {
            var p = ~~(n2 / 20), b = c(s(i2, 5), u(p, o2, d2, h2), l, r3[n2], f[p]);
            l = h2, h2 = d2, d2 = s(o2, 30), o2 = i2, i2 = b;
          }
          this.h[0] = a(this.h[0], i2), this.h[1] = a(this.h[1], o2), this.h[2] = a(this.h[2], d2), this.h[3] = a(this.h[3], h2), this.h[4] = a(this.h[4], l);
        }, h.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h, "big") : n.split32(this.h, "big");
        };
      }, 7485: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(7292);
        function o() {
          if (!(this instanceof o)) return new o();
          i.call(this), this.h = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428];
        }
        n.inherits(o, i), e2.exports = o, o.blockSize = 512, o.outSize = 224, o.hmacStrength = 192, o.padLength = 64, o.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h.slice(0, 7), "big") : n.split32(this.h.slice(0, 7), "big");
        };
      }, 7292: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(4427), o = r2(5660), s = r2(5578), a = n.sum32, c = n.sum32_4, u = n.sum32_5, d = o.ch32, f = o.maj32, h = o.s0_256, l = o.s1_256, p = o.g0_256, b = o.g1_256, y = i.BlockHash, m = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298];
        function g() {
          if (!(this instanceof g)) return new g();
          y.call(this), this.h = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225], this.k = m, this.W = new Array(64);
        }
        n.inherits(g, y), e2.exports = g, g.blockSize = 512, g.outSize = 256, g.hmacStrength = 192, g.padLength = 64, g.prototype._update = function(e3, t3) {
          for (var r3 = this.W, n2 = 0; n2 < 16; n2++) r3[n2] = e3[t3 + n2];
          for (; n2 < r3.length; n2++) r3[n2] = c(b(r3[n2 - 2]), r3[n2 - 7], p(r3[n2 - 15]), r3[n2 - 16]);
          var i2 = this.h[0], o2 = this.h[1], y2 = this.h[2], m2 = this.h[3], g2 = this.h[4], v = this.h[5], w = this.h[6], _ = this.h[7];
          for (s(this.k.length === r3.length), n2 = 0; n2 < r3.length; n2++) {
            var A = u(_, l(g2), d(g2, v, w), this.k[n2], r3[n2]), S = a(h(i2), f(i2, o2, y2));
            _ = w, w = v, v = g2, g2 = a(m2, A), m2 = y2, y2 = o2, o2 = i2, i2 = a(A, S);
          }
          this.h[0] = a(this.h[0], i2), this.h[1] = a(this.h[1], o2), this.h[2] = a(this.h[2], y2), this.h[3] = a(this.h[3], m2), this.h[4] = a(this.h[4], g2), this.h[5] = a(this.h[5], v), this.h[6] = a(this.h[6], w), this.h[7] = a(this.h[7], _);
        }, g.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h, "big") : n.split32(this.h, "big");
        };
      }, 696: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(8889);
        function o() {
          if (!(this instanceof o)) return new o();
          i.call(this), this.h = [3418070365, 3238371032, 1654270250, 914150663, 2438529370, 812702999, 355462360, 4144912697, 1731405415, 4290775857, 2394180231, 1750603025, 3675008525, 1694076839, 1203062813, 3204075428];
        }
        n.inherits(o, i), e2.exports = o, o.blockSize = 1024, o.outSize = 384, o.hmacStrength = 192, o.padLength = 128, o.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h.slice(0, 12), "big") : n.split32(this.h.slice(0, 12), "big");
        };
      }, 8889: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905), i = r2(4427), o = r2(5578), s = n.rotr64_hi, a = n.rotr64_lo, c = n.shr64_hi, u = n.shr64_lo, d = n.sum64, f = n.sum64_hi, h = n.sum64_lo, l = n.sum64_4_hi, p = n.sum64_4_lo, b = n.sum64_5_hi, y = n.sum64_5_lo, m = i.BlockHash, g = [1116352408, 3609767458, 1899447441, 602891725, 3049323471, 3964484399, 3921009573, 2173295548, 961987163, 4081628472, 1508970993, 3053834265, 2453635748, 2937671579, 2870763221, 3664609560, 3624381080, 2734883394, 310598401, 1164996542, 607225278, 1323610764, 1426881987, 3590304994, 1925078388, 4068182383, 2162078206, 991336113, 2614888103, 633803317, 3248222580, 3479774868, 3835390401, 2666613458, 4022224774, 944711139, 264347078, 2341262773, 604807628, 2007800933, 770255983, 1495990901, 1249150122, 1856431235, 1555081692, 3175218132, 1996064986, 2198950837, 2554220882, 3999719339, 2821834349, 766784016, 2952996808, 2566594879, 3210313671, 3203337956, 3336571891, 1034457026, 3584528711, 2466948901, 113926993, 3758326383, 338241895, 168717936, 666307205, 1188179964, 773529912, 1546045734, 1294757372, 1522805485, 1396182291, 2643833823, 1695183700, 2343527390, 1986661051, 1014477480, 2177026350, 1206759142, 2456956037, 344077627, 2730485921, 1290863460, 2820302411, 3158454273, 3259730800, 3505952657, 3345764771, 106217008, 3516065817, 3606008344, 3600352804, 1432725776, 4094571909, 1467031594, 275423344, 851169720, 430227734, 3100823752, 506948616, 1363258195, 659060556, 3750685593, 883997877, 3785050280, 958139571, 3318307427, 1322822218, 3812723403, 1537002063, 2003034995, 1747873779, 3602036899, 1955562222, 1575990012, 2024104815, 1125592928, 2227730452, 2716904306, 2361852424, 442776044, 2428436474, 593698344, 2756734187, 3733110249, 3204031479, 2999351573, 3329325298, 3815920427, 3391569614, 3928383900, 3515267271, 566280711, 3940187606, 3454069534, 4118630271, 4000239992, 116418474, 1914138554, 174292421, 2731055270, 289380356, 3203993006, 460393269, 320620315, 685471733, 587496836, 852142971, 1086792851, 1017036298, 365543100, 1126000580, 2618297676, 1288033470, 3409855158, 1501505948, 4234509866, 1607167915, 987167468, 1816402316, 1246189591];
        function v() {
          if (!(this instanceof v)) return new v();
          m.call(this), this.h = [1779033703, 4089235720, 3144134277, 2227873595, 1013904242, 4271175723, 2773480762, 1595750129, 1359893119, 2917565137, 2600822924, 725511199, 528734635, 4215389547, 1541459225, 327033209], this.k = g, this.W = new Array(160);
        }
        function w(e3, t3, r3, n2, i2) {
          var o2 = e3 & r3 ^ ~e3 & i2;
          return o2 < 0 && (o2 += 4294967296), o2;
        }
        function _(e3, t3, r3, n2, i2, o2) {
          var s2 = t3 & n2 ^ ~t3 & o2;
          return s2 < 0 && (s2 += 4294967296), s2;
        }
        function A(e3, t3, r3, n2, i2) {
          var o2 = e3 & r3 ^ e3 & i2 ^ r3 & i2;
          return o2 < 0 && (o2 += 4294967296), o2;
        }
        function S(e3, t3, r3, n2, i2, o2) {
          var s2 = t3 & n2 ^ t3 & o2 ^ n2 & o2;
          return s2 < 0 && (s2 += 4294967296), s2;
        }
        function C(e3, t3) {
          var r3 = s(e3, t3, 28) ^ s(t3, e3, 2) ^ s(t3, e3, 7);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        function T(e3, t3) {
          var r3 = a(e3, t3, 28) ^ a(t3, e3, 2) ^ a(t3, e3, 7);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        function M(e3, t3) {
          var r3 = a(e3, t3, 14) ^ a(e3, t3, 18) ^ a(t3, e3, 9);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        function E(e3, t3) {
          var r3 = s(e3, t3, 1) ^ s(e3, t3, 8) ^ c(e3, t3, 7);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        function k(e3, t3) {
          var r3 = a(e3, t3, 1) ^ a(e3, t3, 8) ^ u(e3, t3, 7);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        function x(e3, t3) {
          var r3 = a(e3, t3, 19) ^ a(t3, e3, 29) ^ u(e3, t3, 6);
          return r3 < 0 && (r3 += 4294967296), r3;
        }
        n.inherits(v, m), e2.exports = v, v.blockSize = 1024, v.outSize = 512, v.hmacStrength = 192, v.padLength = 128, v.prototype._prepareBlock = function(e3, t3) {
          for (var r3 = this.W, n2 = 0; n2 < 32; n2++) r3[n2] = e3[t3 + n2];
          for (; n2 < r3.length; n2 += 2) {
            var i2 = (y2 = r3[n2 - 4], m2 = r3[n2 - 3], g2 = void 0, (g2 = s(y2, m2, 19) ^ s(m2, y2, 29) ^ c(y2, m2, 6)) < 0 && (g2 += 4294967296), g2), o2 = x(r3[n2 - 4], r3[n2 - 3]), a2 = r3[n2 - 14], u2 = r3[n2 - 13], d2 = E(r3[n2 - 30], r3[n2 - 29]), f2 = k(r3[n2 - 30], r3[n2 - 29]), h2 = r3[n2 - 32], b2 = r3[n2 - 31];
            r3[n2] = l(i2, o2, a2, u2, d2, f2, h2, b2), r3[n2 + 1] = p(i2, o2, a2, u2, d2, f2, h2, b2);
          }
          var y2, m2, g2;
        }, v.prototype._update = function(e3, t3) {
          this._prepareBlock(e3, t3);
          var r3, n2, i2, a2 = this.W, c2 = this.h[0], u2 = this.h[1], l2 = this.h[2], p2 = this.h[3], m2 = this.h[4], g2 = this.h[5], v2 = this.h[6], E2 = this.h[7], k2 = this.h[8], x2 = this.h[9], I = this.h[10], B = this.h[11], U = this.h[12], P = this.h[13], O = this.h[14], R = this.h[15];
          o(this.k.length === a2.length);
          for (var N = 0; N < a2.length; N += 2) {
            var L = O, j = R, D = (i2 = void 0, (i2 = s(r3 = k2, n2 = x2, 14) ^ s(r3, n2, 18) ^ s(n2, r3, 9)) < 0 && (i2 += 4294967296), i2), F = M(k2, x2), H = w(k2, 0, I, 0, U), q = _(0, x2, 0, B, 0, P), $ = this.k[N], V = this.k[N + 1], G = a2[N], z = a2[N + 1], K = b(L, j, D, F, H, q, $, V, G, z), W = y(L, j, D, F, H, q, $, V, G, z);
            L = C(c2, u2), j = T(c2, u2), D = A(c2, 0, l2, 0, m2), F = S(0, u2, 0, p2, 0, g2);
            var J = f(L, j, D, F), Z = h(L, j, D, F);
            O = U, R = P, U = I, P = B, I = k2, B = x2, k2 = f(v2, E2, K, W), x2 = h(E2, E2, K, W), v2 = m2, E2 = g2, m2 = l2, g2 = p2, l2 = c2, p2 = u2, c2 = f(K, W, J, Z), u2 = h(K, W, J, Z);
          }
          d(this.h, 0, c2, u2), d(this.h, 2, l2, p2), d(this.h, 4, m2, g2), d(this.h, 6, v2, E2), d(this.h, 8, k2, x2), d(this.h, 10, I, B), d(this.h, 12, U, P), d(this.h, 14, O, R);
        }, v.prototype._digest = function(e3) {
          return "hex" === e3 ? n.toHex32(this.h, "big") : n.split32(this.h, "big");
        };
      }, 5660: (e2, t2, r2) => {
        "use strict";
        var n = r2(7905).rotr32;
        function i(e3, t3, r3) {
          return e3 & t3 ^ ~e3 & r3;
        }
        function o(e3, t3, r3) {
          return e3 & t3 ^ e3 & r3 ^ t3 & r3;
        }
        function s(e3, t3, r3) {
          return e3 ^ t3 ^ r3;
        }
        t2.ft_1 = function(e3, t3, r3, n2) {
          return 0 === e3 ? i(t3, r3, n2) : 1 === e3 || 3 === e3 ? s(t3, r3, n2) : 2 === e3 ? o(t3, r3, n2) : void 0;
        }, t2.ch32 = i, t2.maj32 = o, t2.p32 = s, t2.s0_256 = function(e3) {
          return n(e3, 2) ^ n(e3, 13) ^ n(e3, 22);
        }, t2.s1_256 = function(e3) {
          return n(e3, 6) ^ n(e3, 11) ^ n(e3, 25);
        }, t2.g0_256 = function(e3) {
          return n(e3, 7) ^ n(e3, 18) ^ e3 >>> 3;
        }, t2.g1_256 = function(e3) {
          return n(e3, 17) ^ n(e3, 19) ^ e3 >>> 10;
        };
      }, 7905: (e2, t2, r2) => {
        "use strict";
        var n = r2(5578), i = r2(1193);
        function o(e3, t3) {
          return 55296 == (64512 & e3.charCodeAt(t3)) && !(t3 < 0 || t3 + 1 >= e3.length) && 56320 == (64512 & e3.charCodeAt(t3 + 1));
        }
        function s(e3) {
          return (e3 >>> 24 | e3 >>> 8 & 65280 | e3 << 8 & 16711680 | (255 & e3) << 24) >>> 0;
        }
        function a(e3) {
          return 1 === e3.length ? "0" + e3 : e3;
        }
        function c(e3) {
          return 7 === e3.length ? "0" + e3 : 6 === e3.length ? "00" + e3 : 5 === e3.length ? "000" + e3 : 4 === e3.length ? "0000" + e3 : 3 === e3.length ? "00000" + e3 : 2 === e3.length ? "000000" + e3 : 1 === e3.length ? "0000000" + e3 : e3;
        }
        t2.inherits = i, t2.toArray = function(e3, t3) {
          if (Array.isArray(e3)) return e3.slice();
          if (!e3) return [];
          var r3 = [];
          if ("string" == typeof e3) if (t3) {
            if ("hex" === t3) for ((e3 = e3.replace(/[^a-z0-9]+/gi, "")).length % 2 != 0 && (e3 = "0" + e3), i2 = 0; i2 < e3.length; i2 += 2) r3.push(parseInt(e3[i2] + e3[i2 + 1], 16));
          } else for (var n2 = 0, i2 = 0; i2 < e3.length; i2++) {
            var s2 = e3.charCodeAt(i2);
            s2 < 128 ? r3[n2++] = s2 : s2 < 2048 ? (r3[n2++] = s2 >> 6 | 192, r3[n2++] = 63 & s2 | 128) : o(e3, i2) ? (s2 = 65536 + ((1023 & s2) << 10) + (1023 & e3.charCodeAt(++i2)), r3[n2++] = s2 >> 18 | 240, r3[n2++] = s2 >> 12 & 63 | 128, r3[n2++] = s2 >> 6 & 63 | 128, r3[n2++] = 63 & s2 | 128) : (r3[n2++] = s2 >> 12 | 224, r3[n2++] = s2 >> 6 & 63 | 128, r3[n2++] = 63 & s2 | 128);
          }
          else for (i2 = 0; i2 < e3.length; i2++) r3[i2] = 0 | e3[i2];
          return r3;
        }, t2.toHex = function(e3) {
          for (var t3 = "", r3 = 0; r3 < e3.length; r3++) t3 += a(e3[r3].toString(16));
          return t3;
        }, t2.htonl = s, t2.toHex32 = function(e3, t3) {
          for (var r3 = "", n2 = 0; n2 < e3.length; n2++) {
            var i2 = e3[n2];
            "little" === t3 && (i2 = s(i2)), r3 += c(i2.toString(16));
          }
          return r3;
        }, t2.zero2 = a, t2.zero8 = c, t2.join32 = function(e3, t3, r3, i2) {
          var o2 = r3 - t3;
          n(o2 % 4 == 0);
          for (var s2 = new Array(o2 / 4), a2 = 0, c2 = t3; a2 < s2.length; a2++, c2 += 4) {
            var u;
            u = "big" === i2 ? e3[c2] << 24 | e3[c2 + 1] << 16 | e3[c2 + 2] << 8 | e3[c2 + 3] : e3[c2 + 3] << 24 | e3[c2 + 2] << 16 | e3[c2 + 1] << 8 | e3[c2], s2[a2] = u >>> 0;
          }
          return s2;
        }, t2.split32 = function(e3, t3) {
          for (var r3 = new Array(4 * e3.length), n2 = 0, i2 = 0; n2 < e3.length; n2++, i2 += 4) {
            var o2 = e3[n2];
            "big" === t3 ? (r3[i2] = o2 >>> 24, r3[i2 + 1] = o2 >>> 16 & 255, r3[i2 + 2] = o2 >>> 8 & 255, r3[i2 + 3] = 255 & o2) : (r3[i2 + 3] = o2 >>> 24, r3[i2 + 2] = o2 >>> 16 & 255, r3[i2 + 1] = o2 >>> 8 & 255, r3[i2] = 255 & o2);
          }
          return r3;
        }, t2.rotr32 = function(e3, t3) {
          return e3 >>> t3 | e3 << 32 - t3;
        }, t2.rotl32 = function(e3, t3) {
          return e3 << t3 | e3 >>> 32 - t3;
        }, t2.sum32 = function(e3, t3) {
          return e3 + t3 >>> 0;
        }, t2.sum32_3 = function(e3, t3, r3) {
          return e3 + t3 + r3 >>> 0;
        }, t2.sum32_4 = function(e3, t3, r3, n2) {
          return e3 + t3 + r3 + n2 >>> 0;
        }, t2.sum32_5 = function(e3, t3, r3, n2, i2) {
          return e3 + t3 + r3 + n2 + i2 >>> 0;
        }, t2.sum64 = function(e3, t3, r3, n2) {
          var i2 = e3[t3], o2 = n2 + e3[t3 + 1] >>> 0, s2 = (o2 < n2 ? 1 : 0) + r3 + i2;
          e3[t3] = s2 >>> 0, e3[t3 + 1] = o2;
        }, t2.sum64_hi = function(e3, t3, r3, n2) {
          return (t3 + n2 >>> 0 < t3 ? 1 : 0) + e3 + r3 >>> 0;
        }, t2.sum64_lo = function(e3, t3, r3, n2) {
          return t3 + n2 >>> 0;
        }, t2.sum64_4_hi = function(e3, t3, r3, n2, i2, o2, s2, a2) {
          var c2 = 0, u = t3;
          return c2 += (u = u + n2 >>> 0) < t3 ? 1 : 0, c2 += (u = u + o2 >>> 0) < o2 ? 1 : 0, e3 + r3 + i2 + s2 + (c2 += (u = u + a2 >>> 0) < a2 ? 1 : 0) >>> 0;
        }, t2.sum64_4_lo = function(e3, t3, r3, n2, i2, o2, s2, a2) {
          return t3 + n2 + o2 + a2 >>> 0;
        }, t2.sum64_5_hi = function(e3, t3, r3, n2, i2, o2, s2, a2, c2, u) {
          var d = 0, f = t3;
          return d += (f = f + n2 >>> 0) < t3 ? 1 : 0, d += (f = f + o2 >>> 0) < o2 ? 1 : 0, d += (f = f + a2 >>> 0) < a2 ? 1 : 0, e3 + r3 + i2 + s2 + c2 + (d += (f = f + u >>> 0) < u ? 1 : 0) >>> 0;
        }, t2.sum64_5_lo = function(e3, t3, r3, n2, i2, o2, s2, a2, c2, u) {
          return t3 + n2 + o2 + a2 + u >>> 0;
        }, t2.rotr64_hi = function(e3, t3, r3) {
          return (t3 << 32 - r3 | e3 >>> r3) >>> 0;
        }, t2.rotr64_lo = function(e3, t3, r3) {
          return (e3 << 32 - r3 | t3 >>> r3) >>> 0;
        }, t2.shr64_hi = function(e3, t3, r3) {
          return e3 >>> r3;
        }, t2.shr64_lo = function(e3, t3, r3) {
          return (e3 << 32 - r3 | t3 >>> r3) >>> 0;
        };
      }, 2519: (e2, t2, r2) => {
        "use strict";
        var n = r2(1631), i = r2(4209), o = r2(5578);
        function s(e3) {
          if (!(this instanceof s)) return new s(e3);
          this.hash = e3.hash, this.predResist = !!e3.predResist, this.outLen = this.hash.outSize, this.minEntropy = e3.minEntropy || this.hash.hmacStrength, this._reseed = null, this.reseedInterval = null, this.K = null, this.V = null;
          var t3 = i.toArray(e3.entropy, e3.entropyEnc || "hex"), r3 = i.toArray(e3.nonce, e3.nonceEnc || "hex"), n2 = i.toArray(e3.pers, e3.persEnc || "hex");
          o(t3.length >= this.minEntropy / 8, "Not enough entropy. Minimum is: " + this.minEntropy + " bits"), this._init(t3, r3, n2);
        }
        e2.exports = s, s.prototype._init = function(e3, t3, r3) {
          var n2 = e3.concat(t3).concat(r3);
          this.K = new Array(this.outLen / 8), this.V = new Array(this.outLen / 8);
          for (var i2 = 0; i2 < this.V.length; i2++) this.K[i2] = 0, this.V[i2] = 1;
          this._update(n2), this._reseed = 1, this.reseedInterval = 281474976710656;
        }, s.prototype._hmac = function() {
          return new n.hmac(this.hash, this.K);
        }, s.prototype._update = function(e3) {
          var t3 = this._hmac().update(this.V).update([0]);
          e3 && (t3 = t3.update(e3)), this.K = t3.digest(), this.V = this._hmac().update(this.V).digest(), e3 && (this.K = this._hmac().update(this.V).update([1]).update(e3).digest(), this.V = this._hmac().update(this.V).digest());
        }, s.prototype.reseed = function(e3, t3, r3, n2) {
          "string" != typeof t3 && (n2 = r3, r3 = t3, t3 = null), e3 = i.toArray(e3, t3), r3 = i.toArray(r3, n2), o(e3.length >= this.minEntropy / 8, "Not enough entropy. Minimum is: " + this.minEntropy + " bits"), this._update(e3.concat(r3 || [])), this._reseed = 1;
        }, s.prototype.generate = function(e3, t3, r3, n2) {
          if (this._reseed > this.reseedInterval) throw new Error("Reseed is required");
          "string" != typeof t3 && (n2 = r3, r3 = t3, t3 = null), r3 && (r3 = i.toArray(r3, n2 || "hex"), this._update(r3));
          for (var o2 = []; o2.length < e3; ) this.V = this._hmac().update(this.V).digest(), o2 = o2.concat(this.V);
          var s2 = o2.slice(0, e3);
          return this._update(r3), this._reseed++, i.encode(s2, t3);
        };
      }, 3328: (e2, t2) => {
        t2.read = function(e3, t3, r2, n, i) {
          var o, s, a = 8 * i - n - 1, c = (1 << a) - 1, u = c >> 1, d = -7, f = r2 ? i - 1 : 0, h = r2 ? -1 : 1, l = e3[t3 + f];
          for (f += h, o = l & (1 << -d) - 1, l >>= -d, d += a; d > 0; o = 256 * o + e3[t3 + f], f += h, d -= 8) ;
          for (s = o & (1 << -d) - 1, o >>= -d, d += n; d > 0; s = 256 * s + e3[t3 + f], f += h, d -= 8) ;
          if (0 === o) o = 1 - u;
          else {
            if (o === c) return s ? NaN : 1 / 0 * (l ? -1 : 1);
            s += Math.pow(2, n), o -= u;
          }
          return (l ? -1 : 1) * s * Math.pow(2, o - n);
        }, t2.write = function(e3, t3, r2, n, i, o) {
          var s, a, c, u = 8 * o - i - 1, d = (1 << u) - 1, f = d >> 1, h = 23 === i ? Math.pow(2, -24) - Math.pow(2, -77) : 0, l = n ? 0 : o - 1, p = n ? 1 : -1, b = t3 < 0 || 0 === t3 && 1 / t3 < 0 ? 1 : 0;
          for (t3 = Math.abs(t3), isNaN(t3) || t3 === 1 / 0 ? (a = isNaN(t3) ? 1 : 0, s = d) : (s = Math.floor(Math.log(t3) / Math.LN2), t3 * (c = Math.pow(2, -s)) < 1 && (s--, c *= 2), (t3 += s + f >= 1 ? h / c : h * Math.pow(2, 1 - f)) * c >= 2 && (s++, c /= 2), s + f >= d ? (a = 0, s = d) : s + f >= 1 ? (a = (t3 * c - 1) * Math.pow(2, i), s += f) : (a = t3 * Math.pow(2, f - 1) * Math.pow(2, i), s = 0)); i >= 8; e3[r2 + l] = 255 & a, l += p, a /= 256, i -= 8) ;
          for (s = s << i | a, u += i; u > 0; e3[r2 + l] = 255 & s, l += p, s /= 256, u -= 8) ;
          e3[r2 + l - p] |= 128 * b;
        };
      }, 1193: (e2) => {
        "function" == typeof Object.create ? e2.exports = function(e3, t2) {
          t2 && (e3.super_ = t2, e3.prototype = Object.create(t2.prototype, { constructor: { value: e3, enumerable: false, writable: true, configurable: true } }));
        } : e2.exports = function(e3, t2) {
          if (t2) {
            e3.super_ = t2;
            var r2 = function() {
            };
            r2.prototype = t2.prototype, e3.prototype = new r2(), e3.prototype.constructor = e3;
          }
        };
      }, 5035: (e2, t2, r2) => {
        "use strict";
        var n = r2(1193), i = r2(800), o = r2(6608).Buffer, s = new Array(16);
        function a() {
          i.call(this, 64), this._a = 1732584193, this._b = 4023233417, this._c = 2562383102, this._d = 271733878;
        }
        function c(e3, t3) {
          return e3 << t3 | e3 >>> 32 - t3;
        }
        function u(e3, t3, r3, n2, i2, o2, s2) {
          return c(e3 + (t3 & r3 | ~t3 & n2) + i2 + o2 | 0, s2) + t3 | 0;
        }
        function d(e3, t3, r3, n2, i2, o2, s2) {
          return c(e3 + (t3 & n2 | r3 & ~n2) + i2 + o2 | 0, s2) + t3 | 0;
        }
        function f(e3, t3, r3, n2, i2, o2, s2) {
          return c(e3 + (t3 ^ r3 ^ n2) + i2 + o2 | 0, s2) + t3 | 0;
        }
        function h(e3, t3, r3, n2, i2, o2, s2) {
          return c(e3 + (r3 ^ (t3 | ~n2)) + i2 + o2 | 0, s2) + t3 | 0;
        }
        n(a, i), a.prototype._update = function() {
          for (var e3 = s, t3 = 0; t3 < 16; ++t3) e3[t3] = this._block.readInt32LE(4 * t3);
          var r3 = this._a, n2 = this._b, i2 = this._c, o2 = this._d;
          r3 = u(r3, n2, i2, o2, e3[0], 3614090360, 7), o2 = u(o2, r3, n2, i2, e3[1], 3905402710, 12), i2 = u(i2, o2, r3, n2, e3[2], 606105819, 17), n2 = u(n2, i2, o2, r3, e3[3], 3250441966, 22), r3 = u(r3, n2, i2, o2, e3[4], 4118548399, 7), o2 = u(o2, r3, n2, i2, e3[5], 1200080426, 12), i2 = u(i2, o2, r3, n2, e3[6], 2821735955, 17), n2 = u(n2, i2, o2, r3, e3[7], 4249261313, 22), r3 = u(r3, n2, i2, o2, e3[8], 1770035416, 7), o2 = u(o2, r3, n2, i2, e3[9], 2336552879, 12), i2 = u(i2, o2, r3, n2, e3[10], 4294925233, 17), n2 = u(n2, i2, o2, r3, e3[11], 2304563134, 22), r3 = u(r3, n2, i2, o2, e3[12], 1804603682, 7), o2 = u(o2, r3, n2, i2, e3[13], 4254626195, 12), i2 = u(i2, o2, r3, n2, e3[14], 2792965006, 17), r3 = d(r3, n2 = u(n2, i2, o2, r3, e3[15], 1236535329, 22), i2, o2, e3[1], 4129170786, 5), o2 = d(o2, r3, n2, i2, e3[6], 3225465664, 9), i2 = d(i2, o2, r3, n2, e3[11], 643717713, 14), n2 = d(n2, i2, o2, r3, e3[0], 3921069994, 20), r3 = d(r3, n2, i2, o2, e3[5], 3593408605, 5), o2 = d(o2, r3, n2, i2, e3[10], 38016083, 9), i2 = d(i2, o2, r3, n2, e3[15], 3634488961, 14), n2 = d(n2, i2, o2, r3, e3[4], 3889429448, 20), r3 = d(r3, n2, i2, o2, e3[9], 568446438, 5), o2 = d(o2, r3, n2, i2, e3[14], 3275163606, 9), i2 = d(i2, o2, r3, n2, e3[3], 4107603335, 14), n2 = d(n2, i2, o2, r3, e3[8], 1163531501, 20), r3 = d(r3, n2, i2, o2, e3[13], 2850285829, 5), o2 = d(o2, r3, n2, i2, e3[2], 4243563512, 9), i2 = d(i2, o2, r3, n2, e3[7], 1735328473, 14), r3 = f(r3, n2 = d(n2, i2, o2, r3, e3[12], 2368359562, 20), i2, o2, e3[5], 4294588738, 4), o2 = f(o2, r3, n2, i2, e3[8], 2272392833, 11), i2 = f(i2, o2, r3, n2, e3[11], 1839030562, 16), n2 = f(n2, i2, o2, r3, e3[14], 4259657740, 23), r3 = f(r3, n2, i2, o2, e3[1], 2763975236, 4), o2 = f(o2, r3, n2, i2, e3[4], 1272893353, 11), i2 = f(i2, o2, r3, n2, e3[7], 4139469664, 16), n2 = f(n2, i2, o2, r3, e3[10], 3200236656, 23), r3 = f(r3, n2, i2, o2, e3[13], 681279174, 4), o2 = f(o2, r3, n2, i2, e3[0], 3936430074, 11), i2 = f(i2, o2, r3, n2, e3[3], 3572445317, 16), n2 = f(n2, i2, o2, r3, e3[6], 76029189, 23), r3 = f(r3, n2, i2, o2, e3[9], 3654602809, 4), o2 = f(o2, r3, n2, i2, e3[12], 3873151461, 11), i2 = f(i2, o2, r3, n2, e3[15], 530742520, 16), r3 = h(r3, n2 = f(n2, i2, o2, r3, e3[2], 3299628645, 23), i2, o2, e3[0], 4096336452, 6), o2 = h(o2, r3, n2, i2, e3[7], 1126891415, 10), i2 = h(i2, o2, r3, n2, e3[14], 2878612391, 15), n2 = h(n2, i2, o2, r3, e3[5], 4237533241, 21), r3 = h(r3, n2, i2, o2, e3[12], 1700485571, 6), o2 = h(o2, r3, n2, i2, e3[3], 2399980690, 10), i2 = h(i2, o2, r3, n2, e3[10], 4293915773, 15), n2 = h(n2, i2, o2, r3, e3[1], 2240044497, 21), r3 = h(r3, n2, i2, o2, e3[8], 1873313359, 6), o2 = h(o2, r3, n2, i2, e3[15], 4264355552, 10), i2 = h(i2, o2, r3, n2, e3[6], 2734768916, 15), n2 = h(n2, i2, o2, r3, e3[13], 1309151649, 21), r3 = h(r3, n2, i2, o2, e3[4], 4149444226, 6), o2 = h(o2, r3, n2, i2, e3[11], 3174756917, 10), i2 = h(i2, o2, r3, n2, e3[2], 718787259, 15), n2 = h(n2, i2, o2, r3, e3[9], 3951481745, 21), this._a = this._a + r3 | 0, this._b = this._b + n2 | 0, this._c = this._c + i2 | 0, this._d = this._d + o2 | 0;
        }, a.prototype._digest = function() {
          this._block[this._blockOffset++] = 128, this._blockOffset > 56 && (this._block.fill(0, this._blockOffset, 64), this._update(), this._blockOffset = 0), this._block.fill(0, this._blockOffset, 56), this._block.writeUInt32LE(this._length[0], 56), this._block.writeUInt32LE(this._length[1], 60), this._update();
          var e3 = o.allocUnsafe(16);
          return e3.writeInt32LE(this._a, 0), e3.writeInt32LE(this._b, 4), e3.writeInt32LE(this._c, 8), e3.writeInt32LE(this._d, 12), e3;
        }, e2.exports = a;
      }, 4442: (e2, t2, r2) => {
        var n = r2(4619), i = r2(5442);
        function o(e3) {
          this.rand = e3 || new i.Rand();
        }
        e2.exports = o, o.create = function(e3) {
          return new o(e3);
        }, o.prototype._randbelow = function(e3) {
          var t3 = e3.bitLength(), r3 = Math.ceil(t3 / 8);
          do {
            var i2 = new n(this.rand.generate(r3));
          } while (i2.cmp(e3) >= 0);
          return i2;
        }, o.prototype._randrange = function(e3, t3) {
          var r3 = t3.sub(e3);
          return e3.add(this._randbelow(r3));
        }, o.prototype.test = function(e3, t3, r3) {
          var i2 = e3.bitLength(), o2 = n.mont(e3), s = new n(1).toRed(o2);
          t3 || (t3 = Math.max(1, i2 / 48 | 0));
          for (var a = e3.subn(1), c = 0; !a.testn(c); c++) ;
          for (var u = e3.shrn(c), d = a.toRed(o2); t3 > 0; t3--) {
            var f = this._randrange(new n(2), a);
            r3 && r3(f);
            var h = f.toRed(o2).redPow(u);
            if (0 !== h.cmp(s) && 0 !== h.cmp(d)) {
              for (var l = 1; l < c; l++) {
                if (0 === (h = h.redSqr()).cmp(s)) return false;
                if (0 === h.cmp(d)) break;
              }
              if (l === c) return false;
            }
          }
          return true;
        }, o.prototype.getDivisor = function(e3, t3) {
          var r3 = e3.bitLength(), i2 = n.mont(e3), o2 = new n(1).toRed(i2);
          t3 || (t3 = Math.max(1, r3 / 48 | 0));
          for (var s = e3.subn(1), a = 0; !s.testn(a); a++) ;
          for (var c = e3.shrn(a), u = s.toRed(i2); t3 > 0; t3--) {
            var d = this._randrange(new n(2), s), f = e3.gcd(d);
            if (0 !== f.cmpn(1)) return f;
            var h = d.toRed(i2).redPow(c);
            if (0 !== h.cmp(o2) && 0 !== h.cmp(u)) {
              for (var l = 1; l < a; l++) {
                if (0 === (h = h.redSqr()).cmp(o2)) return h.fromRed().subn(1).gcd(e3);
                if (0 === h.cmp(u)) break;
              }
              if (l === a) return (h = h.redSqr()).fromRed().subn(1).gcd(e3);
            }
          }
          return false;
        };
      }, 5578: (e2) => {
        function t2(e3, t3) {
          if (!e3) throw new Error(t3 || "Assertion failed");
        }
        e2.exports = t2, t2.equal = function(e3, t3, r2) {
          if (e3 != t3) throw new Error(r2 || "Assertion failed: " + e3 + " != " + t3);
        };
      }, 4209: (e2, t2) => {
        "use strict";
        var r2 = t2;
        function n(e3) {
          return 1 === e3.length ? "0" + e3 : e3;
        }
        function i(e3) {
          for (var t3 = "", r3 = 0; r3 < e3.length; r3++) t3 += n(e3[r3].toString(16));
          return t3;
        }
        r2.toArray = function(e3, t3) {
          if (Array.isArray(e3)) return e3.slice();
          if (!e3) return [];
          var r3 = [];
          if ("string" != typeof e3) {
            for (var n2 = 0; n2 < e3.length; n2++) r3[n2] = 0 | e3[n2];
            return r3;
          }
          if ("hex" === t3) for ((e3 = e3.replace(/[^a-z0-9]+/gi, "")).length % 2 != 0 && (e3 = "0" + e3), n2 = 0; n2 < e3.length; n2 += 2) r3.push(parseInt(e3[n2] + e3[n2 + 1], 16));
          else for (n2 = 0; n2 < e3.length; n2++) {
            var i2 = e3.charCodeAt(n2), o = i2 >> 8, s = 255 & i2;
            o ? r3.push(o, s) : r3.push(s);
          }
          return r3;
        }, r2.zero2 = n, r2.toHex = i, r2.encode = function(e3, t3) {
          return "hex" === t3 ? i(e3) : e3;
        };
      }, 5651: (e2, t2, r2) => {
        "use strict";
        var n = r2(5737);
        t2.certificate = r2(7467);
        var i = n.define("RSAPrivateKey", (function() {
          this.seq().obj(this.key("version").int(), this.key("modulus").int(), this.key("publicExponent").int(), this.key("privateExponent").int(), this.key("prime1").int(), this.key("prime2").int(), this.key("exponent1").int(), this.key("exponent2").int(), this.key("coefficient").int());
        }));
        t2.RSAPrivateKey = i;
        var o = n.define("RSAPublicKey", (function() {
          this.seq().obj(this.key("modulus").int(), this.key("publicExponent").int());
        }));
        t2.RSAPublicKey = o;
        var s = n.define("SubjectPublicKeyInfo", (function() {
          this.seq().obj(this.key("algorithm").use(a), this.key("subjectPublicKey").bitstr());
        }));
        t2.PublicKey = s;
        var a = n.define("AlgorithmIdentifier", (function() {
          this.seq().obj(this.key("algorithm").objid(), this.key("none").null_().optional(), this.key("curve").objid().optional(), this.key("params").seq().obj(this.key("p").int(), this.key("q").int(), this.key("g").int()).optional());
        })), c = n.define("PrivateKeyInfo", (function() {
          this.seq().obj(this.key("version").int(), this.key("algorithm").use(a), this.key("subjectPrivateKey").octstr());
        }));
        t2.PrivateKey = c;
        var u = n.define("EncryptedPrivateKeyInfo", (function() {
          this.seq().obj(this.key("algorithm").seq().obj(this.key("id").objid(), this.key("decrypt").seq().obj(this.key("kde").seq().obj(this.key("id").objid(), this.key("kdeparams").seq().obj(this.key("salt").octstr(), this.key("iters").int())), this.key("cipher").seq().obj(this.key("algo").objid(), this.key("iv").octstr()))), this.key("subjectPrivateKey").octstr());
        }));
        t2.EncryptedPrivateKey = u;
        var d = n.define("DSAPrivateKey", (function() {
          this.seq().obj(this.key("version").int(), this.key("p").int(), this.key("q").int(), this.key("g").int(), this.key("pub_key").int(), this.key("priv_key").int());
        }));
        t2.DSAPrivateKey = d, t2.DSAparam = n.define("DSAparam", (function() {
          this.int();
        }));
        var f = n.define("ECPrivateKey", (function() {
          this.seq().obj(this.key("version").int(), this.key("privateKey").octstr(), this.key("parameters").optional().explicit(0).use(h), this.key("publicKey").optional().explicit(1).bitstr());
        }));
        t2.ECPrivateKey = f;
        var h = n.define("ECParameters", (function() {
          this.choice({ namedCurve: this.objid() });
        }));
        t2.signature = n.define("signature", (function() {
          this.seq().obj(this.key("r").int(), this.key("s").int());
        }));
      }, 7467: (e2, t2, r2) => {
        "use strict";
        var n = r2(5737), i = n.define("Time", (function() {
          this.choice({ utcTime: this.utctime(), generalTime: this.gentime() });
        })), o = n.define("AttributeTypeValue", (function() {
          this.seq().obj(this.key("type").objid(), this.key("value").any());
        })), s = n.define("AlgorithmIdentifier", (function() {
          this.seq().obj(this.key("algorithm").objid(), this.key("parameters").optional(), this.key("curve").objid().optional());
        })), a = n.define("SubjectPublicKeyInfo", (function() {
          this.seq().obj(this.key("algorithm").use(s), this.key("subjectPublicKey").bitstr());
        })), c = n.define("RelativeDistinguishedName", (function() {
          this.setof(o);
        })), u = n.define("RDNSequence", (function() {
          this.seqof(c);
        })), d = n.define("Name", (function() {
          this.choice({ rdnSequence: this.use(u) });
        })), f = n.define("Validity", (function() {
          this.seq().obj(this.key("notBefore").use(i), this.key("notAfter").use(i));
        })), h = n.define("Extension", (function() {
          this.seq().obj(this.key("extnID").objid(), this.key("critical").bool().def(false), this.key("extnValue").octstr());
        })), l = n.define("TBSCertificate", (function() {
          this.seq().obj(this.key("version").explicit(0).int().optional(), this.key("serialNumber").int(), this.key("signature").use(s), this.key("issuer").use(d), this.key("validity").use(f), this.key("subject").use(d), this.key("subjectPublicKeyInfo").use(a), this.key("issuerUniqueID").implicit(1).bitstr().optional(), this.key("subjectUniqueID").implicit(2).bitstr().optional(), this.key("extensions").explicit(3).seqof(h).optional());
        })), p = n.define("X509Certificate", (function() {
          this.seq().obj(this.key("tbsCertificate").use(l), this.key("signatureAlgorithm").use(s), this.key("signatureValue").bitstr());
        }));
        e2.exports = p;
      }, 2011: (e2, t2, r2) => {
        var n = /Proc-Type: 4,ENCRYPTED[\n\r]+DEK-Info: AES-((?:128)|(?:192)|(?:256))-CBC,([0-9A-H]+)[\n\r]+([0-9A-z\n\r+/=]+)[\n\r]+/m, i = /^-----BEGIN ((?:.*? KEY)|CERTIFICATE)-----/m, o = /^-----BEGIN ((?:.*? KEY)|CERTIFICATE)-----([0-9A-z\n\r+/=]+)-----END \1-----$/m, s = r2(1804), a = r2(5007), c = r2(6608).Buffer;
        e2.exports = function(e3, t3) {
          var r3, u = e3.toString(), d = u.match(n);
          if (d) {
            var f = "aes" + d[1], h = c.from(d[2], "hex"), l = c.from(d[3].replace(/[\r\n]/g, ""), "base64"), p = s(t3, h.slice(0, 8), parseInt(d[1], 10)).key, b = [], y = a.createDecipheriv(f, p, h);
            b.push(y.update(l)), b.push(y.final()), r3 = c.concat(b);
          } else {
            var m = u.match(o);
            r3 = c.from(m[2].replace(/[\r\n]/g, ""), "base64");
          }
          return { tag: u.match(i)[1], data: r3 };
        };
      }, 780: (e2, t2, r2) => {
        var n = r2(5651), i = r2(2853), o = r2(2011), s = r2(5007), a = r2(3166), c = r2(6608).Buffer;
        function u(e3) {
          var t3;
          "object" != typeof e3 || c.isBuffer(e3) || (t3 = e3.passphrase, e3 = e3.key), "string" == typeof e3 && (e3 = c.from(e3));
          var r3, u2, d = o(e3, t3), f = d.tag, h = d.data;
          switch (f) {
            case "CERTIFICATE":
              u2 = n.certificate.decode(h, "der").tbsCertificate.subjectPublicKeyInfo;
            case "PUBLIC KEY":
              switch (u2 || (u2 = n.PublicKey.decode(h, "der")), r3 = u2.algorithm.algorithm.join(".")) {
                case "1.2.840.113549.1.1.1":
                  return n.RSAPublicKey.decode(u2.subjectPublicKey.data, "der");
                case "1.2.840.10045.2.1":
                  return u2.subjectPrivateKey = u2.subjectPublicKey, { type: "ec", data: u2 };
                case "1.2.840.10040.4.1":
                  return u2.algorithm.params.pub_key = n.DSAparam.decode(u2.subjectPublicKey.data, "der"), { type: "dsa", data: u2.algorithm.params };
                default:
                  throw new Error("unknown key id " + r3);
              }
            case "ENCRYPTED PRIVATE KEY":
              h = (function(e4, t4) {
                var r4 = e4.algorithm.decrypt.kde.kdeparams.salt, n2 = parseInt(e4.algorithm.decrypt.kde.kdeparams.iters.toString(), 10), o2 = i[e4.algorithm.decrypt.cipher.algo.join(".")], u3 = e4.algorithm.decrypt.cipher.iv, d2 = e4.subjectPrivateKey, f2 = parseInt(o2.split("-")[1], 10) / 8, h2 = a.pbkdf2Sync(t4, r4, n2, f2, "sha1"), l = s.createDecipheriv(o2, h2, u3), p = [];
                return p.push(l.update(d2)), p.push(l.final()), c.concat(p);
              })(h = n.EncryptedPrivateKey.decode(h, "der"), t3);
            case "PRIVATE KEY":
              switch (r3 = (u2 = n.PrivateKey.decode(h, "der")).algorithm.algorithm.join(".")) {
                case "1.2.840.113549.1.1.1":
                  return n.RSAPrivateKey.decode(u2.subjectPrivateKey, "der");
                case "1.2.840.10045.2.1":
                  return { curve: u2.algorithm.curve, privateKey: n.ECPrivateKey.decode(u2.subjectPrivateKey, "der").privateKey };
                case "1.2.840.10040.4.1":
                  return u2.algorithm.params.priv_key = n.DSAparam.decode(u2.subjectPrivateKey, "der"), { type: "dsa", params: u2.algorithm.params };
                default:
                  throw new Error("unknown key id " + r3);
              }
            case "RSA PUBLIC KEY":
              return n.RSAPublicKey.decode(h, "der");
            case "RSA PRIVATE KEY":
              return n.RSAPrivateKey.decode(h, "der");
            case "DSA PRIVATE KEY":
              return { type: "dsa", params: n.DSAPrivateKey.decode(h, "der") };
            case "EC PRIVATE KEY":
              return { curve: (h = n.ECPrivateKey.decode(h, "der")).parameters.value, privateKey: h.privateKey };
            default:
              throw new Error("unknown key type " + f);
          }
        }
        e2.exports = u, u.signature = n.signature;
      }, 3166: (e2, t2, r2) => {
        t2.pbkdf2 = r2(7638), t2.pbkdf2Sync = r2(8674);
      }, 7638: (e2, t2, r2) => {
        var n, i, o = r2(6608).Buffer, s = r2(362), a = r2(9749), c = r2(8674), u = r2(4300), d = r2.g.crypto && r2.g.crypto.subtle, f = { sha: "SHA-1", "sha-1": "SHA-1", sha1: "SHA-1", sha256: "SHA-256", "sha-256": "SHA-256", sha384: "SHA-384", "sha-384": "SHA-384", "sha-512": "SHA-512", sha512: "SHA-512" }, h = [];
        function l() {
          return i || (i = r2.g.process && r2.g.process.nextTick ? r2.g.process.nextTick : r2.g.queueMicrotask ? r2.g.queueMicrotask : r2.g.setImmediate ? r2.g.setImmediate : r2.g.setTimeout);
        }
        function p(e3, t3, r3, n2, i2) {
          return d.importKey("raw", e3, { name: "PBKDF2" }, false, ["deriveBits"]).then((function(e4) {
            return d.deriveBits({ name: "PBKDF2", salt: t3, iterations: r3, hash: { name: i2 } }, e4, n2 << 3);
          })).then((function(e4) {
            return o.from(e4);
          }));
        }
        e2.exports = function(e3, t3, i2, b, y, m) {
          "function" == typeof y && (m = y, y = void 0);
          var g = f[(y = y || "sha1").toLowerCase()];
          if (g && "function" == typeof r2.g.Promise) {
            if (s(i2, b), e3 = u(e3, a, "Password"), t3 = u(t3, a, "Salt"), "function" != typeof m) throw new Error("No callback provided to pbkdf2");
            !(function(e4, t4) {
              e4.then((function(e5) {
                l()((function() {
                  t4(null, e5);
                }));
              }), (function(e5) {
                l()((function() {
                  t4(e5);
                }));
              }));
            })((function(e4) {
              if (r2.g.process && !r2.g.process.browser) return Promise.resolve(false);
              if (!d || !d.importKey || !d.deriveBits) return Promise.resolve(false);
              if (void 0 !== h[e4]) return h[e4];
              var t4 = p(n = n || o.alloc(8), n, 10, 128, e4).then((function() {
                return true;
              })).catch((function() {
                return false;
              }));
              return h[e4] = t4, t4;
            })(g).then((function(r3) {
              return r3 ? p(e3, t3, i2, b, g) : c(e3, t3, i2, b, y);
            })), m);
          } else l()((function() {
            var r3;
            try {
              r3 = c(e3, t3, i2, b, y);
            } catch (e4) {
              return m(e4);
            }
            m(null, r3);
          }));
        };
      }, 9749: (e2, t2, r2) => {
        var n;
        n = r2.g.process && r2.g.process.browser ? "utf-8" : r2.g.process && r2.g.process.version ? parseInt(process.version.split(".")[0].slice(1), 10) >= 6 ? "utf-8" : "binary" : "utf-8", e2.exports = n;
      }, 362: (e2) => {
        var t2 = Math.pow(2, 30) - 1;
        e2.exports = function(e3, r2) {
          if ("number" != typeof e3) throw new TypeError("Iterations not a number");
          if (e3 < 0) throw new TypeError("Bad iterations");
          if ("number" != typeof r2) throw new TypeError("Key length not a number");
          if (r2 < 0 || r2 > t2 || r2 != r2) throw new TypeError("Bad key length");
        };
      }, 8674: (e2, t2, r2) => {
        var n = r2(6159), i = r2(3934), o = r2(5244), s = r2(6608).Buffer, a = r2(362), c = r2(9749), u = r2(4300), d = s.alloc(128), f = { md5: 16, sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64, rmd160: 20, ripemd160: 20 };
        function h(e3, t3, r3) {
          var a2 = /* @__PURE__ */ (function(e4) {
            return "rmd160" === e4 || "ripemd160" === e4 ? function(e5) {
              return new i().update(e5).digest();
            } : "md5" === e4 ? n : function(t4) {
              return o(e4).update(t4).digest();
            };
          })(e3), c2 = "sha512" === e3 || "sha384" === e3 ? 128 : 64;
          t3.length > c2 ? t3 = a2(t3) : t3.length < c2 && (t3 = s.concat([t3, d], c2));
          for (var u2 = s.allocUnsafe(c2 + f[e3]), h2 = s.allocUnsafe(c2 + f[e3]), l = 0; l < c2; l++) u2[l] = 54 ^ t3[l], h2[l] = 92 ^ t3[l];
          var p = s.allocUnsafe(c2 + r3 + 4);
          u2.copy(p, 0, 0, c2), this.ipad1 = p, this.ipad2 = u2, this.opad = h2, this.alg = e3, this.blocksize = c2, this.hash = a2, this.size = f[e3];
        }
        h.prototype.run = function(e3, t3) {
          return e3.copy(t3, this.blocksize), this.hash(t3).copy(this.opad, this.blocksize), this.hash(this.opad);
        }, e2.exports = function(e3, t3, r3, n2, i2) {
          a(r3, n2);
          var o2 = new h(i2 = i2 || "sha1", e3 = u(e3, c, "Password"), (t3 = u(t3, c, "Salt")).length), d2 = s.allocUnsafe(n2), l = s.allocUnsafe(t3.length + 4);
          t3.copy(l, 0, 0, t3.length);
          for (var p = 0, b = f[i2], y = Math.ceil(n2 / b), m = 1; m <= y; m++) {
            l.writeUInt32BE(m, t3.length);
            for (var g = o2.run(l, o2.ipad1), v = g, w = 1; w < r3; w++) {
              v = o2.run(v, o2.ipad2);
              for (var _ = 0; _ < b; _++) g[_] ^= v[_];
            }
            g.copy(d2, p), p += b;
          }
          return d2;
        };
      }, 4300: (e2, t2, r2) => {
        var n = r2(6608).Buffer;
        e2.exports = function(e3, t3, r3) {
          if (n.isBuffer(e3)) return e3;
          if ("string" == typeof e3) return n.from(e3, t3);
          if (ArrayBuffer.isView(e3)) return n.from(e3.buffer);
          throw new TypeError(r3 + " must be a string, a Buffer, a typed array or a DataView");
        };
      }, 2211: (e2, t2, r2) => {
        t2.publicEncrypt = r2(3909), t2.privateDecrypt = r2(2399), t2.privateEncrypt = function(e3, r3) {
          return t2.publicEncrypt(e3, r3, true);
        }, t2.publicDecrypt = function(e3, r3) {
          return t2.privateDecrypt(e3, r3, true);
        };
      }, 8929: (e2, t2, r2) => {
        var n = r2(8955), i = r2(6608).Buffer;
        function o(e3) {
          var t3 = i.allocUnsafe(4);
          return t3.writeUInt32BE(e3, 0), t3;
        }
        e2.exports = function(e3, t3) {
          for (var r3, s = i.alloc(0), a = 0; s.length < t3; ) r3 = o(a++), s = i.concat([s, n("sha1").update(e3).update(r3).digest()]);
          return s.slice(0, t3);
        };
      }, 2399: (e2, t2, r2) => {
        var n = r2(780), i = r2(8929), o = r2(7794), s = r2(4619), a = r2(1377), c = r2(8955), u = r2(7390), d = r2(6608).Buffer;
        e2.exports = function(e3, t3, r3) {
          var f;
          f = e3.padding ? e3.padding : r3 ? 1 : 4;
          var h, l = n(e3), p = l.modulus.byteLength();
          if (t3.length > p || new s(t3).cmp(l.modulus) >= 0) throw new Error("decryption error");
          h = r3 ? u(new s(t3), l) : a(t3, l);
          var b = d.alloc(p - h.length);
          if (h = d.concat([b, h], p), 4 === f) return (function(e4, t4) {
            var r4 = e4.modulus.byteLength(), n2 = c("sha1").update(d.alloc(0)).digest(), s2 = n2.length;
            if (0 !== t4[0]) throw new Error("decryption error");
            var a2 = t4.slice(1, s2 + 1), u2 = t4.slice(s2 + 1), f2 = o(a2, i(u2, s2)), h2 = o(u2, i(f2, r4 - s2 - 1));
            if ((function(e5, t5) {
              e5 = d.from(e5), t5 = d.from(t5);
              var r5 = 0, n3 = e5.length;
              e5.length !== t5.length && (r5++, n3 = Math.min(e5.length, t5.length));
              for (var i2 = -1; ++i2 < n3; ) r5 += e5[i2] ^ t5[i2];
              return r5;
            })(n2, h2.slice(0, s2))) throw new Error("decryption error");
            for (var l2 = s2; 0 === h2[l2]; ) l2++;
            if (1 !== h2[l2++]) throw new Error("decryption error");
            return h2.slice(l2);
          })(l, h);
          if (1 === f) return (function(e4, t4, r4) {
            for (var n2 = t4.slice(0, 2), i2 = 2, o2 = 0; 0 !== t4[i2++]; ) if (i2 >= t4.length) {
              o2++;
              break;
            }
            var s2 = t4.slice(2, i2 - 1);
            if (("0002" !== n2.toString("hex") && !r4 || "0001" !== n2.toString("hex") && r4) && o2++, s2.length < 8 && o2++, o2) throw new Error("decryption error");
            return t4.slice(i2);
          })(0, h, r3);
          if (3 === f) return h;
          throw new Error("unknown padding");
        };
      }, 3909: (e2, t2, r2) => {
        var n = r2(780), i = r2(2869), o = r2(8955), s = r2(8929), a = r2(7794), c = r2(4619), u = r2(7390), d = r2(1377), f = r2(6608).Buffer;
        e2.exports = function(e3, t3, r3) {
          var h;
          h = e3.padding ? e3.padding : r3 ? 1 : 4;
          var l, p = n(e3);
          if (4 === h) l = (function(e4, t4) {
            var r4 = e4.modulus.byteLength(), n2 = t4.length, u2 = o("sha1").update(f.alloc(0)).digest(), d2 = u2.length, h2 = 2 * d2;
            if (n2 > r4 - h2 - 2) throw new Error("message too long");
            var l2 = f.alloc(r4 - n2 - h2 - 2), p2 = r4 - d2 - 1, b = i(d2), y = a(f.concat([u2, l2, f.alloc(1, 1), t4], p2), s(b, p2)), m = a(b, s(y, d2));
            return new c(f.concat([f.alloc(1), m, y], r4));
          })(p, t3);
          else if (1 === h) l = (function(e4, t4, r4) {
            var n2, o2 = t4.length, s2 = e4.modulus.byteLength();
            if (o2 > s2 - 11) throw new Error("message too long");
            return n2 = r4 ? f.alloc(s2 - o2 - 3, 255) : (function(e5) {
              for (var t5, r5 = f.allocUnsafe(e5), n3 = 0, o3 = i(2 * e5), s3 = 0; n3 < e5; ) s3 === o3.length && (o3 = i(2 * e5), s3 = 0), (t5 = o3[s3++]) && (r5[n3++] = t5);
              return r5;
            })(s2 - o2 - 3), new c(f.concat([f.from([0, r4 ? 1 : 2]), n2, f.alloc(1), t4], s2));
          })(p, t3, r3);
          else {
            if (3 !== h) throw new Error("unknown padding");
            if ((l = new c(t3)).cmp(p.modulus) >= 0) throw new Error("data too long for modulus");
          }
          return r3 ? d(l, p) : u(l, p);
        };
      }, 7390: (e2, t2, r2) => {
        var n = r2(4619), i = r2(6608).Buffer;
        e2.exports = function(e3, t3) {
          return i.from(e3.toRed(n.mont(t3.modulus)).redPow(new n(t3.publicExponent)).fromRed().toArray());
        };
      }, 7794: (e2) => {
        e2.exports = function(e3, t2) {
          for (var r2 = e3.length, n = -1; ++n < r2; ) e3[n] ^= t2[n];
          return e3;
        };
      }, 2869: (e2, t2, r2) => {
        "use strict";
        var n = 65536, i = r2(6608).Buffer, o = r2.g.crypto || r2.g.msCrypto;
        o && o.getRandomValues ? e2.exports = function(e3, t3) {
          if (e3 > 4294967295) throw new RangeError("requested too many random bytes");
          var r3 = i.allocUnsafe(e3);
          if (e3 > 0) if (e3 > n) for (var s = 0; s < e3; s += n) o.getRandomValues(r3.slice(s, s + n));
          else o.getRandomValues(r3);
          return "function" == typeof t3 ? process.nextTick((function() {
            t3(null, r3);
          })) : r3;
        } : e2.exports = function() {
          throw new Error("Secure random number generation is not supported by this browser.\nUse Chrome, Firefox or Internet Explorer 11");
        };
      }, 4925: (e2, t2, r2) => {
        "use strict";
        function n() {
          throw new Error("secure random number generation not supported by this browser\nuse chrome, FireFox or Internet Explorer 11");
        }
        var i = r2(6608), o = r2(2869), s = i.Buffer, a = i.kMaxLength, c = r2.g.crypto || r2.g.msCrypto, u = Math.pow(2, 32) - 1;
        function d(e3, t3) {
          if ("number" != typeof e3 || e3 != e3) throw new TypeError("offset must be a number");
          if (e3 > u || e3 < 0) throw new TypeError("offset must be a uint32");
          if (e3 > a || e3 > t3) throw new RangeError("offset out of range");
        }
        function f(e3, t3, r3) {
          if ("number" != typeof e3 || e3 != e3) throw new TypeError("size must be a number");
          if (e3 > u || e3 < 0) throw new TypeError("size must be a uint32");
          if (e3 + t3 > r3 || e3 > a) throw new RangeError("buffer too small");
        }
        function h(e3, t3, r3, n2) {
          if (process.browser) {
            var i2 = e3.buffer, s2 = new Uint8Array(i2, t3, r3);
            return c.getRandomValues(s2), n2 ? void process.nextTick((function() {
              n2(null, e3);
            })) : e3;
          }
          if (!n2) return o(r3).copy(e3, t3), e3;
          o(r3, (function(r4, i3) {
            if (r4) return n2(r4);
            i3.copy(e3, t3), n2(null, e3);
          }));
        }
        c && c.getRandomValues || !process.browser ? (t2.randomFill = function(e3, t3, n2, i2) {
          if (!(s.isBuffer(e3) || e3 instanceof r2.g.Uint8Array)) throw new TypeError('"buf" argument must be a Buffer or Uint8Array');
          if ("function" == typeof t3) i2 = t3, t3 = 0, n2 = e3.length;
          else if ("function" == typeof n2) i2 = n2, n2 = e3.length - t3;
          else if ("function" != typeof i2) throw new TypeError('"cb" argument must be a function');
          return d(t3, e3.length), f(n2, t3, e3.length), h(e3, t3, n2, i2);
        }, t2.randomFillSync = function(e3, t3, n2) {
          if (void 0 === t3 && (t3 = 0), !(s.isBuffer(e3) || e3 instanceof r2.g.Uint8Array)) throw new TypeError('"buf" argument must be a Buffer or Uint8Array');
          return d(t3, e3.length), void 0 === n2 && (n2 = e3.length - t3), f(n2, t3, e3.length), h(e3, t3, n2);
        }) : (t2.randomFill = n, t2.randomFillSync = n);
      }, 289: (e2) => {
        "use strict";
        var t2 = {};
        function r2(e3, r3, n2) {
          n2 || (n2 = Error);
          var i = (function(e4) {
            var t3, n3;
            function i2(t4, n4, i3) {
              return e4.call(this, (function(e5, t5, n5) {
                return "string" == typeof r3 ? r3 : r3(e5, t5, n5);
              })(t4, n4, i3)) || this;
            }
            return n3 = e4, (t3 = i2).prototype = Object.create(n3.prototype), t3.prototype.constructor = t3, t3.__proto__ = n3, i2;
          })(n2);
          i.prototype.name = n2.name, i.prototype.code = e3, t2[e3] = i;
        }
        function n(e3, t3) {
          if (Array.isArray(e3)) {
            var r3 = e3.length;
            return e3 = e3.map((function(e4) {
              return String(e4);
            })), r3 > 2 ? "one of ".concat(t3, " ").concat(e3.slice(0, r3 - 1).join(", "), ", or ") + e3[r3 - 1] : 2 === r3 ? "one of ".concat(t3, " ").concat(e3[0], " or ").concat(e3[1]) : "of ".concat(t3, " ").concat(e3[0]);
          }
          return "of ".concat(t3, " ").concat(String(e3));
        }
        r2("ERR_INVALID_OPT_VALUE", (function(e3, t3) {
          return 'The value "' + t3 + '" is invalid for option "' + e3 + '"';
        }), TypeError), r2("ERR_INVALID_ARG_TYPE", (function(e3, t3, r3) {
          var i, o, s, a, c;
          if ("string" == typeof t3 && (o = "not ", t3.substr(0, 4) === o) ? (i = "must not be", t3 = t3.replace(/^not /, "")) : i = "must be", (function(e4, t4, r4) {
            return (void 0 === r4 || r4 > e4.length) && (r4 = e4.length), e4.substring(r4 - 9, r4) === t4;
          })(e3, " argument")) s = "The ".concat(e3, " ").concat(i, " ").concat(n(t3, "type"));
          else {
            var u = ("number" != typeof c && (c = 0), c + 1 > (a = e3).length || -1 === a.indexOf(".", c) ? "argument" : "property");
            s = 'The "'.concat(e3, '" ').concat(u, " ").concat(i, " ").concat(n(t3, "type"));
          }
          return s + ". Received type ".concat(typeof r3);
        }), TypeError), r2("ERR_STREAM_PUSH_AFTER_EOF", "stream.push() after EOF"), r2("ERR_METHOD_NOT_IMPLEMENTED", (function(e3) {
          return "The " + e3 + " method is not implemented";
        })), r2("ERR_STREAM_PREMATURE_CLOSE", "Premature close"), r2("ERR_STREAM_DESTROYED", (function(e3) {
          return "Cannot call " + e3 + " after a stream was destroyed";
        })), r2("ERR_MULTIPLE_CALLBACK", "Callback called multiple times"), r2("ERR_STREAM_CANNOT_PIPE", "Cannot pipe, not readable"), r2("ERR_STREAM_WRITE_AFTER_END", "write after end"), r2("ERR_STREAM_NULL_VALUES", "May not write null values to stream", TypeError), r2("ERR_UNKNOWN_ENCODING", (function(e3) {
          return "Unknown encoding: " + e3;
        }), TypeError), r2("ERR_STREAM_UNSHIFT_AFTER_END_EVENT", "stream.unshift() after end event"), e2.exports.F = t2;
      }, 5707: (e2, t2, r2) => {
        "use strict";
        var n = Object.keys || function(e3) {
          var t3 = [];
          for (var r3 in e3) t3.push(r3);
          return t3;
        };
        e2.exports = u;
        var i = r2(3033), o = r2(2553);
        r2(1193)(u, i);
        for (var s = n(o.prototype), a = 0; a < s.length; a++) {
          var c = s[a];
          u.prototype[c] || (u.prototype[c] = o.prototype[c]);
        }
        function u(e3) {
          if (!(this instanceof u)) return new u(e3);
          i.call(this, e3), o.call(this, e3), this.allowHalfOpen = true, e3 && (false === e3.readable && (this.readable = false), false === e3.writable && (this.writable = false), false === e3.allowHalfOpen && (this.allowHalfOpen = false, this.once("end", d)));
        }
        function d() {
          this._writableState.ended || process.nextTick(f, this);
        }
        function f(e3) {
          e3.end();
        }
        Object.defineProperty(u.prototype, "writableHighWaterMark", { enumerable: false, get: function() {
          return this._writableState.highWaterMark;
        } }), Object.defineProperty(u.prototype, "writableBuffer", { enumerable: false, get: function() {
          return this._writableState && this._writableState.getBuffer();
        } }), Object.defineProperty(u.prototype, "writableLength", { enumerable: false, get: function() {
          return this._writableState.length;
        } }), Object.defineProperty(u.prototype, "destroyed", { enumerable: false, get: function() {
          return void 0 !== this._readableState && void 0 !== this._writableState && this._readableState.destroyed && this._writableState.destroyed;
        }, set: function(e3) {
          void 0 !== this._readableState && void 0 !== this._writableState && (this._readableState.destroyed = e3, this._writableState.destroyed = e3);
        } });
      }, 5271: (e2, t2, r2) => {
        "use strict";
        e2.exports = i;
        var n = r2(141);
        function i(e3) {
          if (!(this instanceof i)) return new i(e3);
          n.call(this, e3);
        }
        r2(1193)(i, n), i.prototype._transform = function(e3, t3, r3) {
          r3(null, e3);
        };
      }, 3033: (e2, t2, r2) => {
        "use strict";
        var n;
        e2.exports = C, C.ReadableState = S, r2(381).EventEmitter;
        var i, o = function(e3, t3) {
          return e3.listeners(t3).length;
        }, s = r2(2534), a = r2(6533).Buffer, c = (void 0 !== r2.g ? r2.g : "undefined" != typeof window ? window : "undefined" != typeof self ? self : {}).Uint8Array || function() {
        }, u = r2(6429);
        i = u && u.debuglog ? u.debuglog("stream") : function() {
        };
        var d, f, h, l = r2(20), p = r2(917), b = r2(5750).getHighWaterMark, y = r2(289).F, m = y.ERR_INVALID_ARG_TYPE, g = y.ERR_STREAM_PUSH_AFTER_EOF, v = y.ERR_METHOD_NOT_IMPLEMENTED, w = y.ERR_STREAM_UNSHIFT_AFTER_END_EVENT;
        r2(1193)(C, s);
        var _ = p.errorOrDestroy, A = ["error", "close", "destroy", "pause", "resume"];
        function S(e3, t3, i2) {
          n = n || r2(5707), e3 = e3 || {}, "boolean" != typeof i2 && (i2 = t3 instanceof n), this.objectMode = !!e3.objectMode, i2 && (this.objectMode = this.objectMode || !!e3.readableObjectMode), this.highWaterMark = b(this, e3, "readableHighWaterMark", i2), this.buffer = new l(), this.length = 0, this.pipes = null, this.pipesCount = 0, this.flowing = null, this.ended = false, this.endEmitted = false, this.reading = false, this.sync = true, this.needReadable = false, this.emittedReadable = false, this.readableListening = false, this.resumeScheduled = false, this.paused = true, this.emitClose = false !== e3.emitClose, this.autoDestroy = !!e3.autoDestroy, this.destroyed = false, this.defaultEncoding = e3.defaultEncoding || "utf8", this.awaitDrain = 0, this.readingMore = false, this.decoder = null, this.encoding = null, e3.encoding && (d || (d = r2(6704).I), this.decoder = new d(e3.encoding), this.encoding = e3.encoding);
        }
        function C(e3) {
          if (n = n || r2(5707), !(this instanceof C)) return new C(e3);
          var t3 = this instanceof n;
          this._readableState = new S(e3, this, t3), this.readable = true, e3 && ("function" == typeof e3.read && (this._read = e3.read), "function" == typeof e3.destroy && (this._destroy = e3.destroy)), s.call(this);
        }
        function T(e3, t3, r3, n2, o2) {
          i("readableAddChunk", t3);
          var s2, u2 = e3._readableState;
          if (null === t3) u2.reading = false, (function(e4, t4) {
            if (i("onEofChunk"), !t4.ended) {
              if (t4.decoder) {
                var r4 = t4.decoder.end();
                r4 && r4.length && (t4.buffer.push(r4), t4.length += t4.objectMode ? 1 : r4.length);
              }
              t4.ended = true, t4.sync ? x(e4) : (t4.needReadable = false, t4.emittedReadable || (t4.emittedReadable = true, I(e4)));
            }
          })(e3, u2);
          else if (o2 || (s2 = (function(e4, t4) {
            var r4, n3;
            return n3 = t4, a.isBuffer(n3) || n3 instanceof c || "string" == typeof t4 || void 0 === t4 || e4.objectMode || (r4 = new m("chunk", ["string", "Buffer", "Uint8Array"], t4)), r4;
          })(u2, t3)), s2) _(e3, s2);
          else if (u2.objectMode || t3 && t3.length > 0) if ("string" == typeof t3 || u2.objectMode || Object.getPrototypeOf(t3) === a.prototype || (t3 = (function(e4) {
            return a.from(e4);
          })(t3)), n2) u2.endEmitted ? _(e3, new w()) : M(e3, u2, t3, true);
          else if (u2.ended) _(e3, new g());
          else {
            if (u2.destroyed) return false;
            u2.reading = false, u2.decoder && !r3 ? (t3 = u2.decoder.write(t3), u2.objectMode || 0 !== t3.length ? M(e3, u2, t3, false) : B(e3, u2)) : M(e3, u2, t3, false);
          }
          else n2 || (u2.reading = false, B(e3, u2));
          return !u2.ended && (u2.length < u2.highWaterMark || 0 === u2.length);
        }
        function M(e3, t3, r3, n2) {
          t3.flowing && 0 === t3.length && !t3.sync ? (t3.awaitDrain = 0, e3.emit("data", r3)) : (t3.length += t3.objectMode ? 1 : r3.length, n2 ? t3.buffer.unshift(r3) : t3.buffer.push(r3), t3.needReadable && x(e3)), B(e3, t3);
        }
        Object.defineProperty(C.prototype, "destroyed", { enumerable: false, get: function() {
          return void 0 !== this._readableState && this._readableState.destroyed;
        }, set: function(e3) {
          this._readableState && (this._readableState.destroyed = e3);
        } }), C.prototype.destroy = p.destroy, C.prototype._undestroy = p.undestroy, C.prototype._destroy = function(e3, t3) {
          t3(e3);
        }, C.prototype.push = function(e3, t3) {
          var r3, n2 = this._readableState;
          return n2.objectMode ? r3 = true : "string" == typeof e3 && ((t3 = t3 || n2.defaultEncoding) !== n2.encoding && (e3 = a.from(e3, t3), t3 = ""), r3 = true), T(this, e3, t3, false, r3);
        }, C.prototype.unshift = function(e3) {
          return T(this, e3, null, true, false);
        }, C.prototype.isPaused = function() {
          return false === this._readableState.flowing;
        }, C.prototype.setEncoding = function(e3) {
          d || (d = r2(6704).I);
          var t3 = new d(e3);
          this._readableState.decoder = t3, this._readableState.encoding = this._readableState.decoder.encoding;
          for (var n2 = this._readableState.buffer.head, i2 = ""; null !== n2; ) i2 += t3.write(n2.data), n2 = n2.next;
          return this._readableState.buffer.clear(), "" !== i2 && this._readableState.buffer.push(i2), this._readableState.length = i2.length, this;
        };
        var E = 1073741824;
        function k(e3, t3) {
          return e3 <= 0 || 0 === t3.length && t3.ended ? 0 : t3.objectMode ? 1 : e3 != e3 ? t3.flowing && t3.length ? t3.buffer.head.data.length : t3.length : (e3 > t3.highWaterMark && (t3.highWaterMark = (function(e4) {
            return e4 >= E ? e4 = E : (e4--, e4 |= e4 >>> 1, e4 |= e4 >>> 2, e4 |= e4 >>> 4, e4 |= e4 >>> 8, e4 |= e4 >>> 16, e4++), e4;
          })(e3)), e3 <= t3.length ? e3 : t3.ended ? t3.length : (t3.needReadable = true, 0));
        }
        function x(e3) {
          var t3 = e3._readableState;
          i("emitReadable", t3.needReadable, t3.emittedReadable), t3.needReadable = false, t3.emittedReadable || (i("emitReadable", t3.flowing), t3.emittedReadable = true, process.nextTick(I, e3));
        }
        function I(e3) {
          var t3 = e3._readableState;
          i("emitReadable_", t3.destroyed, t3.length, t3.ended), t3.destroyed || !t3.length && !t3.ended || (e3.emit("readable"), t3.emittedReadable = false), t3.needReadable = !t3.flowing && !t3.ended && t3.length <= t3.highWaterMark, N(e3);
        }
        function B(e3, t3) {
          t3.readingMore || (t3.readingMore = true, process.nextTick(U, e3, t3));
        }
        function U(e3, t3) {
          for (; !t3.reading && !t3.ended && (t3.length < t3.highWaterMark || t3.flowing && 0 === t3.length); ) {
            var r3 = t3.length;
            if (i("maybeReadMore read 0"), e3.read(0), r3 === t3.length) break;
          }
          t3.readingMore = false;
        }
        function P(e3) {
          var t3 = e3._readableState;
          t3.readableListening = e3.listenerCount("readable") > 0, t3.resumeScheduled && !t3.paused ? t3.flowing = true : e3.listenerCount("data") > 0 && e3.resume();
        }
        function O(e3) {
          i("readable nexttick read 0"), e3.read(0);
        }
        function R(e3, t3) {
          i("resume", t3.reading), t3.reading || e3.read(0), t3.resumeScheduled = false, e3.emit("resume"), N(e3), t3.flowing && !t3.reading && e3.read(0);
        }
        function N(e3) {
          var t3 = e3._readableState;
          for (i("flow", t3.flowing); t3.flowing && null !== e3.read(); ) ;
        }
        function L(e3, t3) {
          return 0 === t3.length ? null : (t3.objectMode ? r3 = t3.buffer.shift() : !e3 || e3 >= t3.length ? (r3 = t3.decoder ? t3.buffer.join("") : 1 === t3.buffer.length ? t3.buffer.first() : t3.buffer.concat(t3.length), t3.buffer.clear()) : r3 = t3.buffer.consume(e3, t3.decoder), r3);
          var r3;
        }
        function j(e3) {
          var t3 = e3._readableState;
          i("endReadable", t3.endEmitted), t3.endEmitted || (t3.ended = true, process.nextTick(D, t3, e3));
        }
        function D(e3, t3) {
          if (i("endReadableNT", e3.endEmitted, e3.length), !e3.endEmitted && 0 === e3.length && (e3.endEmitted = true, t3.readable = false, t3.emit("end"), e3.autoDestroy)) {
            var r3 = t3._writableState;
            (!r3 || r3.autoDestroy && r3.finished) && t3.destroy();
          }
        }
        function F(e3, t3) {
          for (var r3 = 0, n2 = e3.length; r3 < n2; r3++) if (e3[r3] === t3) return r3;
          return -1;
        }
        C.prototype.read = function(e3) {
          i("read", e3), e3 = parseInt(e3, 10);
          var t3 = this._readableState, r3 = e3;
          if (0 !== e3 && (t3.emittedReadable = false), 0 === e3 && t3.needReadable && ((0 !== t3.highWaterMark ? t3.length >= t3.highWaterMark : t3.length > 0) || t3.ended)) return i("read: emitReadable", t3.length, t3.ended), 0 === t3.length && t3.ended ? j(this) : x(this), null;
          if (0 === (e3 = k(e3, t3)) && t3.ended) return 0 === t3.length && j(this), null;
          var n2, o2 = t3.needReadable;
          return i("need readable", o2), (0 === t3.length || t3.length - e3 < t3.highWaterMark) && i("length less than watermark", o2 = true), t3.ended || t3.reading ? i("reading or ended", o2 = false) : o2 && (i("do read"), t3.reading = true, t3.sync = true, 0 === t3.length && (t3.needReadable = true), this._read(t3.highWaterMark), t3.sync = false, t3.reading || (e3 = k(r3, t3))), null === (n2 = e3 > 0 ? L(e3, t3) : null) ? (t3.needReadable = t3.length <= t3.highWaterMark, e3 = 0) : (t3.length -= e3, t3.awaitDrain = 0), 0 === t3.length && (t3.ended || (t3.needReadable = true), r3 !== e3 && t3.ended && j(this)), null !== n2 && this.emit("data", n2), n2;
        }, C.prototype._read = function(e3) {
          _(this, new v("_read()"));
        }, C.prototype.pipe = function(e3, t3) {
          var r3 = this, n2 = this._readableState;
          switch (n2.pipesCount) {
            case 0:
              n2.pipes = e3;
              break;
            case 1:
              n2.pipes = [n2.pipes, e3];
              break;
            default:
              n2.pipes.push(e3);
          }
          n2.pipesCount += 1, i("pipe count=%d opts=%j", n2.pipesCount, t3);
          var s2 = t3 && false === t3.end || e3 === process.stdout || e3 === process.stderr ? p2 : a2;
          function a2() {
            i("onend"), e3.end();
          }
          n2.endEmitted ? process.nextTick(s2) : r3.once("end", s2), e3.on("unpipe", (function t4(o2, s3) {
            i("onunpipe"), o2 === r3 && s3 && false === s3.hasUnpiped && (s3.hasUnpiped = true, i("cleanup"), e3.removeListener("close", h2), e3.removeListener("finish", l2), e3.removeListener("drain", c2), e3.removeListener("error", f2), e3.removeListener("unpipe", t4), r3.removeListener("end", a2), r3.removeListener("end", p2), r3.removeListener("data", d2), u2 = true, !n2.awaitDrain || e3._writableState && !e3._writableState.needDrain || c2());
          }));
          var c2 = /* @__PURE__ */ (function(e4) {
            return function() {
              var t4 = e4._readableState;
              i("pipeOnDrain", t4.awaitDrain), t4.awaitDrain && t4.awaitDrain--, 0 === t4.awaitDrain && o(e4, "data") && (t4.flowing = true, N(e4));
            };
          })(r3);
          e3.on("drain", c2);
          var u2 = false;
          function d2(t4) {
            i("ondata");
            var o2 = e3.write(t4);
            i("dest.write", o2), false === o2 && ((1 === n2.pipesCount && n2.pipes === e3 || n2.pipesCount > 1 && -1 !== F(n2.pipes, e3)) && !u2 && (i("false write response, pause", n2.awaitDrain), n2.awaitDrain++), r3.pause());
          }
          function f2(t4) {
            i("onerror", t4), p2(), e3.removeListener("error", f2), 0 === o(e3, "error") && _(e3, t4);
          }
          function h2() {
            e3.removeListener("finish", l2), p2();
          }
          function l2() {
            i("onfinish"), e3.removeListener("close", h2), p2();
          }
          function p2() {
            i("unpipe"), r3.unpipe(e3);
          }
          return r3.on("data", d2), (function(e4, t4, r4) {
            if ("function" == typeof e4.prependListener) return e4.prependListener(t4, r4);
            e4._events && e4._events[t4] ? Array.isArray(e4._events[t4]) ? e4._events[t4].unshift(r4) : e4._events[t4] = [r4, e4._events[t4]] : e4.on(t4, r4);
          })(e3, "error", f2), e3.once("close", h2), e3.once("finish", l2), e3.emit("pipe", r3), n2.flowing || (i("pipe resume"), r3.resume()), e3;
        }, C.prototype.unpipe = function(e3) {
          var t3 = this._readableState, r3 = { hasUnpiped: false };
          if (0 === t3.pipesCount) return this;
          if (1 === t3.pipesCount) return e3 && e3 !== t3.pipes || (e3 || (e3 = t3.pipes), t3.pipes = null, t3.pipesCount = 0, t3.flowing = false, e3 && e3.emit("unpipe", this, r3)), this;
          if (!e3) {
            var n2 = t3.pipes, i2 = t3.pipesCount;
            t3.pipes = null, t3.pipesCount = 0, t3.flowing = false;
            for (var o2 = 0; o2 < i2; o2++) n2[o2].emit("unpipe", this, { hasUnpiped: false });
            return this;
          }
          var s2 = F(t3.pipes, e3);
          return -1 === s2 || (t3.pipes.splice(s2, 1), t3.pipesCount -= 1, 1 === t3.pipesCount && (t3.pipes = t3.pipes[0]), e3.emit("unpipe", this, r3)), this;
        }, C.prototype.on = function(e3, t3) {
          var r3 = s.prototype.on.call(this, e3, t3), n2 = this._readableState;
          return "data" === e3 ? (n2.readableListening = this.listenerCount("readable") > 0, false !== n2.flowing && this.resume()) : "readable" === e3 && (n2.endEmitted || n2.readableListening || (n2.readableListening = n2.needReadable = true, n2.flowing = false, n2.emittedReadable = false, i("on readable", n2.length, n2.reading), n2.length ? x(this) : n2.reading || process.nextTick(O, this))), r3;
        }, C.prototype.addListener = C.prototype.on, C.prototype.removeListener = function(e3, t3) {
          var r3 = s.prototype.removeListener.call(this, e3, t3);
          return "readable" === e3 && process.nextTick(P, this), r3;
        }, C.prototype.removeAllListeners = function(e3) {
          var t3 = s.prototype.removeAllListeners.apply(this, arguments);
          return "readable" !== e3 && void 0 !== e3 || process.nextTick(P, this), t3;
        }, C.prototype.resume = function() {
          var e3 = this._readableState;
          return e3.flowing || (i("resume"), e3.flowing = !e3.readableListening, (function(e4, t3) {
            t3.resumeScheduled || (t3.resumeScheduled = true, process.nextTick(R, e4, t3));
          })(this, e3)), e3.paused = false, this;
        }, C.prototype.pause = function() {
          return i("call pause flowing=%j", this._readableState.flowing), false !== this._readableState.flowing && (i("pause"), this._readableState.flowing = false, this.emit("pause")), this._readableState.paused = true, this;
        }, C.prototype.wrap = function(e3) {
          var t3 = this, r3 = this._readableState, n2 = false;
          for (var o2 in e3.on("end", (function() {
            if (i("wrapped end"), r3.decoder && !r3.ended) {
              var e4 = r3.decoder.end();
              e4 && e4.length && t3.push(e4);
            }
            t3.push(null);
          })), e3.on("data", (function(o3) {
            i("wrapped data"), r3.decoder && (o3 = r3.decoder.write(o3)), r3.objectMode && null == o3 || (r3.objectMode || o3 && o3.length) && (t3.push(o3) || (n2 = true, e3.pause()));
          })), e3) void 0 === this[o2] && "function" == typeof e3[o2] && (this[o2] = /* @__PURE__ */ (function(t4) {
            return function() {
              return e3[t4].apply(e3, arguments);
            };
          })(o2));
          for (var s2 = 0; s2 < A.length; s2++) e3.on(A[s2], this.emit.bind(this, A[s2]));
          return this._read = function(t4) {
            i("wrapped _read", t4), n2 && (n2 = false, e3.resume());
          }, this;
        }, "function" == typeof Symbol && (C.prototype[Symbol.asyncIterator] = function() {
          return void 0 === f && (f = r2(9536)), f(this);
        }), Object.defineProperty(C.prototype, "readableHighWaterMark", { enumerable: false, get: function() {
          return this._readableState.highWaterMark;
        } }), Object.defineProperty(C.prototype, "readableBuffer", { enumerable: false, get: function() {
          return this._readableState && this._readableState.buffer;
        } }), Object.defineProperty(C.prototype, "readableFlowing", { enumerable: false, get: function() {
          return this._readableState.flowing;
        }, set: function(e3) {
          this._readableState && (this._readableState.flowing = e3);
        } }), C._fromList = L, Object.defineProperty(C.prototype, "readableLength", { enumerable: false, get: function() {
          return this._readableState.length;
        } }), "function" == typeof Symbol && (C.from = function(e3, t3) {
          return void 0 === h && (h = r2(4918)), h(C, e3, t3);
        });
      }, 141: (e2, t2, r2) => {
        "use strict";
        e2.exports = d;
        var n = r2(289).F, i = n.ERR_METHOD_NOT_IMPLEMENTED, o = n.ERR_MULTIPLE_CALLBACK, s = n.ERR_TRANSFORM_ALREADY_TRANSFORMING, a = n.ERR_TRANSFORM_WITH_LENGTH_0, c = r2(5707);
        function u(e3, t3) {
          var r3 = this._transformState;
          r3.transforming = false;
          var n2 = r3.writecb;
          if (null === n2) return this.emit("error", new o());
          r3.writechunk = null, r3.writecb = null, null != t3 && this.push(t3), n2(e3);
          var i2 = this._readableState;
          i2.reading = false, (i2.needReadable || i2.length < i2.highWaterMark) && this._read(i2.highWaterMark);
        }
        function d(e3) {
          if (!(this instanceof d)) return new d(e3);
          c.call(this, e3), this._transformState = { afterTransform: u.bind(this), needTransform: false, transforming: false, writecb: null, writechunk: null, writeencoding: null }, this._readableState.needReadable = true, this._readableState.sync = false, e3 && ("function" == typeof e3.transform && (this._transform = e3.transform), "function" == typeof e3.flush && (this._flush = e3.flush)), this.on("prefinish", f);
        }
        function f() {
          var e3 = this;
          "function" != typeof this._flush || this._readableState.destroyed ? h(this, null, null) : this._flush((function(t3, r3) {
            h(e3, t3, r3);
          }));
        }
        function h(e3, t3, r3) {
          if (t3) return e3.emit("error", t3);
          if (null != r3 && e3.push(r3), e3._writableState.length) throw new a();
          if (e3._transformState.transforming) throw new s();
          return e3.push(null);
        }
        r2(1193)(d, c), d.prototype.push = function(e3, t3) {
          return this._transformState.needTransform = false, c.prototype.push.call(this, e3, t3);
        }, d.prototype._transform = function(e3, t3, r3) {
          r3(new i("_transform()"));
        }, d.prototype._write = function(e3, t3, r3) {
          var n2 = this._transformState;
          if (n2.writecb = r3, n2.writechunk = e3, n2.writeencoding = t3, !n2.transforming) {
            var i2 = this._readableState;
            (n2.needTransform || i2.needReadable || i2.length < i2.highWaterMark) && this._read(i2.highWaterMark);
          }
        }, d.prototype._read = function(e3) {
          var t3 = this._transformState;
          null === t3.writechunk || t3.transforming ? t3.needTransform = true : (t3.transforming = true, this._transform(t3.writechunk, t3.writeencoding, t3.afterTransform));
        }, d.prototype._destroy = function(e3, t3) {
          c.prototype._destroy.call(this, e3, (function(e4) {
            t3(e4);
          }));
        };
      }, 2553: (e2, t2, r2) => {
        "use strict";
        function n(e3) {
          var t3 = this;
          this.next = null, this.entry = null, this.finish = function() {
            !(function(e4, t4) {
              var r3 = e4.entry;
              for (e4.entry = null; r3; ) {
                var n2 = r3.callback;
                t4.pendingcb--, n2(void 0), r3 = r3.next;
              }
              t4.corkedRequestsFree.next = e4;
            })(t3, e3);
          };
        }
        var i;
        e2.exports = C, C.WritableState = S;
        var o, s = { deprecate: r2(1947) }, a = r2(2534), c = r2(6533).Buffer, u = (void 0 !== r2.g ? r2.g : "undefined" != typeof window ? window : "undefined" != typeof self ? self : {}).Uint8Array || function() {
        }, d = r2(917), f = r2(5750).getHighWaterMark, h = r2(289).F, l = h.ERR_INVALID_ARG_TYPE, p = h.ERR_METHOD_NOT_IMPLEMENTED, b = h.ERR_MULTIPLE_CALLBACK, y = h.ERR_STREAM_CANNOT_PIPE, m = h.ERR_STREAM_DESTROYED, g = h.ERR_STREAM_NULL_VALUES, v = h.ERR_STREAM_WRITE_AFTER_END, w = h.ERR_UNKNOWN_ENCODING, _ = d.errorOrDestroy;
        function A() {
        }
        function S(e3, t3, o2) {
          i = i || r2(5707), e3 = e3 || {}, "boolean" != typeof o2 && (o2 = t3 instanceof i), this.objectMode = !!e3.objectMode, o2 && (this.objectMode = this.objectMode || !!e3.writableObjectMode), this.highWaterMark = f(this, e3, "writableHighWaterMark", o2), this.finalCalled = false, this.needDrain = false, this.ending = false, this.ended = false, this.finished = false, this.destroyed = false;
          var s2 = false === e3.decodeStrings;
          this.decodeStrings = !s2, this.defaultEncoding = e3.defaultEncoding || "utf8", this.length = 0, this.writing = false, this.corked = 0, this.sync = true, this.bufferProcessing = false, this.onwrite = function(e4) {
            !(function(e5, t4) {
              var r3 = e5._writableState, n2 = r3.sync, i2 = r3.writecb;
              if ("function" != typeof i2) throw new b();
              if ((function(e6) {
                e6.writing = false, e6.writecb = null, e6.length -= e6.writelen, e6.writelen = 0;
              })(r3), t4) !(function(e6, t5, r4, n3, i3) {
                --t5.pendingcb, r4 ? (process.nextTick(i3, n3), process.nextTick(I, e6, t5), e6._writableState.errorEmitted = true, _(e6, n3)) : (i3(n3), e6._writableState.errorEmitted = true, _(e6, n3), I(e6, t5));
              })(e5, r3, n2, t4, i2);
              else {
                var o3 = k(r3) || e5.destroyed;
                o3 || r3.corked || r3.bufferProcessing || !r3.bufferedRequest || E(e5, r3), n2 ? process.nextTick(M, e5, r3, o3, i2) : M(e5, r3, o3, i2);
              }
            })(t3, e4);
          }, this.writecb = null, this.writelen = 0, this.bufferedRequest = null, this.lastBufferedRequest = null, this.pendingcb = 0, this.prefinished = false, this.errorEmitted = false, this.emitClose = false !== e3.emitClose, this.autoDestroy = !!e3.autoDestroy, this.bufferedRequestCount = 0, this.corkedRequestsFree = new n(this);
        }
        function C(e3) {
          var t3 = this instanceof (i = i || r2(5707));
          if (!t3 && !o.call(C, this)) return new C(e3);
          this._writableState = new S(e3, this, t3), this.writable = true, e3 && ("function" == typeof e3.write && (this._write = e3.write), "function" == typeof e3.writev && (this._writev = e3.writev), "function" == typeof e3.destroy && (this._destroy = e3.destroy), "function" == typeof e3.final && (this._final = e3.final)), a.call(this);
        }
        function T(e3, t3, r3, n2, i2, o2, s2) {
          t3.writelen = n2, t3.writecb = s2, t3.writing = true, t3.sync = true, t3.destroyed ? t3.onwrite(new m("write")) : r3 ? e3._writev(i2, t3.onwrite) : e3._write(i2, o2, t3.onwrite), t3.sync = false;
        }
        function M(e3, t3, r3, n2) {
          r3 || (function(e4, t4) {
            0 === t4.length && t4.needDrain && (t4.needDrain = false, e4.emit("drain"));
          })(e3, t3), t3.pendingcb--, n2(), I(e3, t3);
        }
        function E(e3, t3) {
          t3.bufferProcessing = true;
          var r3 = t3.bufferedRequest;
          if (e3._writev && r3 && r3.next) {
            var i2 = t3.bufferedRequestCount, o2 = new Array(i2), s2 = t3.corkedRequestsFree;
            s2.entry = r3;
            for (var a2 = 0, c2 = true; r3; ) o2[a2] = r3, r3.isBuf || (c2 = false), r3 = r3.next, a2 += 1;
            o2.allBuffers = c2, T(e3, t3, true, t3.length, o2, "", s2.finish), t3.pendingcb++, t3.lastBufferedRequest = null, s2.next ? (t3.corkedRequestsFree = s2.next, s2.next = null) : t3.corkedRequestsFree = new n(t3), t3.bufferedRequestCount = 0;
          } else {
            for (; r3; ) {
              var u2 = r3.chunk, d2 = r3.encoding, f2 = r3.callback;
              if (T(e3, t3, false, t3.objectMode ? 1 : u2.length, u2, d2, f2), r3 = r3.next, t3.bufferedRequestCount--, t3.writing) break;
            }
            null === r3 && (t3.lastBufferedRequest = null);
          }
          t3.bufferedRequest = r3, t3.bufferProcessing = false;
        }
        function k(e3) {
          return e3.ending && 0 === e3.length && null === e3.bufferedRequest && !e3.finished && !e3.writing;
        }
        function x(e3, t3) {
          e3._final((function(r3) {
            t3.pendingcb--, r3 && _(e3, r3), t3.prefinished = true, e3.emit("prefinish"), I(e3, t3);
          }));
        }
        function I(e3, t3) {
          var r3 = k(t3);
          if (r3 && ((function(e4, t4) {
            t4.prefinished || t4.finalCalled || ("function" != typeof e4._final || t4.destroyed ? (t4.prefinished = true, e4.emit("prefinish")) : (t4.pendingcb++, t4.finalCalled = true, process.nextTick(x, e4, t4)));
          })(e3, t3), 0 === t3.pendingcb && (t3.finished = true, e3.emit("finish"), t3.autoDestroy))) {
            var n2 = e3._readableState;
            (!n2 || n2.autoDestroy && n2.endEmitted) && e3.destroy();
          }
          return r3;
        }
        r2(1193)(C, a), S.prototype.getBuffer = function() {
          for (var e3 = this.bufferedRequest, t3 = []; e3; ) t3.push(e3), e3 = e3.next;
          return t3;
        }, (function() {
          try {
            Object.defineProperty(S.prototype, "buffer", { get: s.deprecate((function() {
              return this.getBuffer();
            }), "_writableState.buffer is deprecated. Use _writableState.getBuffer instead.", "DEP0003") });
          } catch (e3) {
          }
        })(), "function" == typeof Symbol && Symbol.hasInstance && "function" == typeof Function.prototype[Symbol.hasInstance] ? (o = Function.prototype[Symbol.hasInstance], Object.defineProperty(C, Symbol.hasInstance, { value: function(e3) {
          return !!o.call(this, e3) || this === C && e3 && e3._writableState instanceof S;
        } })) : o = function(e3) {
          return e3 instanceof this;
        }, C.prototype.pipe = function() {
          _(this, new y());
        }, C.prototype.write = function(e3, t3, r3) {
          var n2, i2 = this._writableState, o2 = false, s2 = !i2.objectMode && (n2 = e3, c.isBuffer(n2) || n2 instanceof u);
          return s2 && !c.isBuffer(e3) && (e3 = (function(e4) {
            return c.from(e4);
          })(e3)), "function" == typeof t3 && (r3 = t3, t3 = null), s2 ? t3 = "buffer" : t3 || (t3 = i2.defaultEncoding), "function" != typeof r3 && (r3 = A), i2.ending ? (function(e4, t4) {
            var r4 = new v();
            _(e4, r4), process.nextTick(t4, r4);
          })(this, r3) : (s2 || (function(e4, t4, r4, n3) {
            var i3;
            return null === r4 ? i3 = new g() : "string" == typeof r4 || t4.objectMode || (i3 = new l("chunk", ["string", "Buffer"], r4)), !i3 || (_(e4, i3), process.nextTick(n3, i3), false);
          })(this, i2, e3, r3)) && (i2.pendingcb++, o2 = (function(e4, t4, r4, n3, i3, o3) {
            if (!r4) {
              var s3 = (function(e5, t5, r5) {
                return e5.objectMode || false === e5.decodeStrings || "string" != typeof t5 || (t5 = c.from(t5, r5)), t5;
              })(t4, n3, i3);
              n3 !== s3 && (r4 = true, i3 = "buffer", n3 = s3);
            }
            var a2 = t4.objectMode ? 1 : n3.length;
            t4.length += a2;
            var u2 = t4.length < t4.highWaterMark;
            if (u2 || (t4.needDrain = true), t4.writing || t4.corked) {
              var d2 = t4.lastBufferedRequest;
              t4.lastBufferedRequest = { chunk: n3, encoding: i3, isBuf: r4, callback: o3, next: null }, d2 ? d2.next = t4.lastBufferedRequest : t4.bufferedRequest = t4.lastBufferedRequest, t4.bufferedRequestCount += 1;
            } else T(e4, t4, false, a2, n3, i3, o3);
            return u2;
          })(this, i2, s2, e3, t3, r3)), o2;
        }, C.prototype.cork = function() {
          this._writableState.corked++;
        }, C.prototype.uncork = function() {
          var e3 = this._writableState;
          e3.corked && (e3.corked--, e3.writing || e3.corked || e3.bufferProcessing || !e3.bufferedRequest || E(this, e3));
        }, C.prototype.setDefaultEncoding = function(e3) {
          if ("string" == typeof e3 && (e3 = e3.toLowerCase()), !(["hex", "utf8", "utf-8", "ascii", "binary", "base64", "ucs2", "ucs-2", "utf16le", "utf-16le", "raw"].indexOf((e3 + "").toLowerCase()) > -1)) throw new w(e3);
          return this._writableState.defaultEncoding = e3, this;
        }, Object.defineProperty(C.prototype, "writableBuffer", { enumerable: false, get: function() {
          return this._writableState && this._writableState.getBuffer();
        } }), Object.defineProperty(C.prototype, "writableHighWaterMark", { enumerable: false, get: function() {
          return this._writableState.highWaterMark;
        } }), C.prototype._write = function(e3, t3, r3) {
          r3(new p("_write()"));
        }, C.prototype._writev = null, C.prototype.end = function(e3, t3, r3) {
          var n2 = this._writableState;
          return "function" == typeof e3 ? (r3 = e3, e3 = null, t3 = null) : "function" == typeof t3 && (r3 = t3, t3 = null), null != e3 && this.write(e3, t3), n2.corked && (n2.corked = 1, this.uncork()), n2.ending || (function(e4, t4, r4) {
            t4.ending = true, I(e4, t4), r4 && (t4.finished ? process.nextTick(r4) : e4.once("finish", r4)), t4.ended = true, e4.writable = false;
          })(this, n2, r3), this;
        }, Object.defineProperty(C.prototype, "writableLength", { enumerable: false, get: function() {
          return this._writableState.length;
        } }), Object.defineProperty(C.prototype, "destroyed", { enumerable: false, get: function() {
          return void 0 !== this._writableState && this._writableState.destroyed;
        }, set: function(e3) {
          this._writableState && (this._writableState.destroyed = e3);
        } }), C.prototype.destroy = d.destroy, C.prototype._undestroy = d.undestroy, C.prototype._destroy = function(e3, t3) {
          t3(e3);
        };
      }, 9536: (e2, t2, r2) => {
        "use strict";
        var n;
        function i(e3, t3, r3) {
          return (t3 = (function(e4) {
            var t4 = (function(e5) {
              if ("object" != typeof e5 || null === e5) return e5;
              var t5 = e5[Symbol.toPrimitive];
              if (void 0 !== t5) {
                var r4 = t5.call(e5, "string");
                if ("object" != typeof r4) return r4;
                throw new TypeError("@@toPrimitive must return a primitive value.");
              }
              return String(e5);
            })(e4);
            return "symbol" == typeof t4 ? t4 : String(t4);
          })(t3)) in e3 ? Object.defineProperty(e3, t3, { value: r3, enumerable: true, configurable: true, writable: true }) : e3[t3] = r3, e3;
        }
        var o = r2(2339), s = /* @__PURE__ */ Symbol("lastResolve"), a = /* @__PURE__ */ Symbol("lastReject"), c = /* @__PURE__ */ Symbol("error"), u = /* @__PURE__ */ Symbol("ended"), d = /* @__PURE__ */ Symbol("lastPromise"), f = /* @__PURE__ */ Symbol("handlePromise"), h = /* @__PURE__ */ Symbol("stream");
        function l(e3, t3) {
          return { value: e3, done: t3 };
        }
        function p(e3) {
          var t3 = e3[s];
          if (null !== t3) {
            var r3 = e3[h].read();
            null !== r3 && (e3[d] = null, e3[s] = null, e3[a] = null, t3(l(r3, false)));
          }
        }
        function b(e3) {
          process.nextTick(p, e3);
        }
        var y = Object.getPrototypeOf((function() {
        })), m = Object.setPrototypeOf((i(n = { get stream() {
          return this[h];
        }, next: function() {
          var e3 = this, t3 = this[c];
          if (null !== t3) return Promise.reject(t3);
          if (this[u]) return Promise.resolve(l(void 0, true));
          if (this[h].destroyed) return new Promise((function(t4, r4) {
            process.nextTick((function() {
              e3[c] ? r4(e3[c]) : t4(l(void 0, true));
            }));
          }));
          var r3, n2 = this[d];
          if (n2) r3 = new Promise(/* @__PURE__ */ (function(e4, t4) {
            return function(r4, n3) {
              e4.then((function() {
                t4[u] ? r4(l(void 0, true)) : t4[f](r4, n3);
              }), n3);
            };
          })(n2, this));
          else {
            var i2 = this[h].read();
            if (null !== i2) return Promise.resolve(l(i2, false));
            r3 = new Promise(this[f]);
          }
          return this[d] = r3, r3;
        } }, Symbol.asyncIterator, (function() {
          return this;
        })), i(n, "return", (function() {
          var e3 = this;
          return new Promise((function(t3, r3) {
            e3[h].destroy(null, (function(e4) {
              e4 ? r3(e4) : t3(l(void 0, true));
            }));
          }));
        })), n), y);
        e2.exports = function(e3) {
          var t3, r3 = Object.create(m, (i(t3 = {}, h, { value: e3, writable: true }), i(t3, s, { value: null, writable: true }), i(t3, a, { value: null, writable: true }), i(t3, c, { value: null, writable: true }), i(t3, u, { value: e3._readableState.endEmitted, writable: true }), i(t3, f, { value: function(e4, t4) {
            var n2 = r3[h].read();
            n2 ? (r3[d] = null, r3[s] = null, r3[a] = null, e4(l(n2, false))) : (r3[s] = e4, r3[a] = t4);
          }, writable: true }), t3));
          return r3[d] = null, o(e3, (function(e4) {
            if (e4 && "ERR_STREAM_PREMATURE_CLOSE" !== e4.code) {
              var t4 = r3[a];
              return null !== t4 && (r3[d] = null, r3[s] = null, r3[a] = null, t4(e4)), void (r3[c] = e4);
            }
            var n2 = r3[s];
            null !== n2 && (r3[d] = null, r3[s] = null, r3[a] = null, n2(l(void 0, true))), r3[u] = true;
          })), e3.on("readable", b.bind(null, r3)), r3;
        };
      }, 20: (e2, t2, r2) => {
        "use strict";
        function n(e3, t3) {
          var r3 = Object.keys(e3);
          if (Object.getOwnPropertySymbols) {
            var n2 = Object.getOwnPropertySymbols(e3);
            t3 && (n2 = n2.filter((function(t4) {
              return Object.getOwnPropertyDescriptor(e3, t4).enumerable;
            }))), r3.push.apply(r3, n2);
          }
          return r3;
        }
        function i(e3) {
          for (var t3 = 1; t3 < arguments.length; t3++) {
            var r3 = null != arguments[t3] ? arguments[t3] : {};
            t3 % 2 ? n(Object(r3), true).forEach((function(t4) {
              o(e3, t4, r3[t4]);
            })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e3, Object.getOwnPropertyDescriptors(r3)) : n(Object(r3)).forEach((function(t4) {
              Object.defineProperty(e3, t4, Object.getOwnPropertyDescriptor(r3, t4));
            }));
          }
          return e3;
        }
        function o(e3, t3, r3) {
          return (t3 = a(t3)) in e3 ? Object.defineProperty(e3, t3, { value: r3, enumerable: true, configurable: true, writable: true }) : e3[t3] = r3, e3;
        }
        function s(e3, t3) {
          for (var r3 = 0; r3 < t3.length; r3++) {
            var n2 = t3[r3];
            n2.enumerable = n2.enumerable || false, n2.configurable = true, "value" in n2 && (n2.writable = true), Object.defineProperty(e3, a(n2.key), n2);
          }
        }
        function a(e3) {
          var t3 = (function(e4) {
            if ("object" != typeof e4 || null === e4) return e4;
            var t4 = e4[Symbol.toPrimitive];
            if (void 0 !== t4) {
              var r3 = t4.call(e4, "string");
              if ("object" != typeof r3) return r3;
              throw new TypeError("@@toPrimitive must return a primitive value.");
            }
            return String(e4);
          })(e3);
          return "symbol" == typeof t3 ? t3 : String(t3);
        }
        var c = r2(6533).Buffer, u = r2(3541).inspect, d = u && u.custom || "inspect";
        e2.exports = (function() {
          function e3() {
            !(function(e4, t4) {
              if (!(e4 instanceof t4)) throw new TypeError("Cannot call a class as a function");
            })(this, e3), this.head = null, this.tail = null, this.length = 0;
          }
          var t3, r3;
          return t3 = e3, (r3 = [{ key: "push", value: function(e4) {
            var t4 = { data: e4, next: null };
            this.length > 0 ? this.tail.next = t4 : this.head = t4, this.tail = t4, ++this.length;
          } }, { key: "unshift", value: function(e4) {
            var t4 = { data: e4, next: this.head };
            0 === this.length && (this.tail = t4), this.head = t4, ++this.length;
          } }, { key: "shift", value: function() {
            if (0 !== this.length) {
              var e4 = this.head.data;
              return 1 === this.length ? this.head = this.tail = null : this.head = this.head.next, --this.length, e4;
            }
          } }, { key: "clear", value: function() {
            this.head = this.tail = null, this.length = 0;
          } }, { key: "join", value: function(e4) {
            if (0 === this.length) return "";
            for (var t4 = this.head, r4 = "" + t4.data; t4 = t4.next; ) r4 += e4 + t4.data;
            return r4;
          } }, { key: "concat", value: function(e4) {
            if (0 === this.length) return c.alloc(0);
            for (var t4, r4, n2, i2 = c.allocUnsafe(e4 >>> 0), o2 = this.head, s2 = 0; o2; ) t4 = o2.data, r4 = i2, n2 = s2, c.prototype.copy.call(t4, r4, n2), s2 += o2.data.length, o2 = o2.next;
            return i2;
          } }, { key: "consume", value: function(e4, t4) {
            var r4;
            return e4 < this.head.data.length ? (r4 = this.head.data.slice(0, e4), this.head.data = this.head.data.slice(e4)) : r4 = e4 === this.head.data.length ? this.shift() : t4 ? this._getString(e4) : this._getBuffer(e4), r4;
          } }, { key: "first", value: function() {
            return this.head.data;
          } }, { key: "_getString", value: function(e4) {
            var t4 = this.head, r4 = 1, n2 = t4.data;
            for (e4 -= n2.length; t4 = t4.next; ) {
              var i2 = t4.data, o2 = e4 > i2.length ? i2.length : e4;
              if (o2 === i2.length ? n2 += i2 : n2 += i2.slice(0, e4), 0 == (e4 -= o2)) {
                o2 === i2.length ? (++r4, t4.next ? this.head = t4.next : this.head = this.tail = null) : (this.head = t4, t4.data = i2.slice(o2));
                break;
              }
              ++r4;
            }
            return this.length -= r4, n2;
          } }, { key: "_getBuffer", value: function(e4) {
            var t4 = c.allocUnsafe(e4), r4 = this.head, n2 = 1;
            for (r4.data.copy(t4), e4 -= r4.data.length; r4 = r4.next; ) {
              var i2 = r4.data, o2 = e4 > i2.length ? i2.length : e4;
              if (i2.copy(t4, t4.length - e4, 0, o2), 0 == (e4 -= o2)) {
                o2 === i2.length ? (++n2, r4.next ? this.head = r4.next : this.head = this.tail = null) : (this.head = r4, r4.data = i2.slice(o2));
                break;
              }
              ++n2;
            }
            return this.length -= n2, t4;
          } }, { key: d, value: function(e4, t4) {
            return u(this, i(i({}, t4), {}, { depth: 0, customInspect: false }));
          } }]) && s(t3.prototype, r3), Object.defineProperty(t3, "prototype", { writable: false }), e3;
        })();
      }, 917: (e2) => {
        "use strict";
        function t2(e3, t3) {
          n(e3, t3), r2(e3);
        }
        function r2(e3) {
          e3._writableState && !e3._writableState.emitClose || e3._readableState && !e3._readableState.emitClose || e3.emit("close");
        }
        function n(e3, t3) {
          e3.emit("error", t3);
        }
        e2.exports = { destroy: function(e3, i) {
          var o = this, s = this._readableState && this._readableState.destroyed, a = this._writableState && this._writableState.destroyed;
          return s || a ? (i ? i(e3) : e3 && (this._writableState ? this._writableState.errorEmitted || (this._writableState.errorEmitted = true, process.nextTick(n, this, e3)) : process.nextTick(n, this, e3)), this) : (this._readableState && (this._readableState.destroyed = true), this._writableState && (this._writableState.destroyed = true), this._destroy(e3 || null, (function(e4) {
            !i && e4 ? o._writableState ? o._writableState.errorEmitted ? process.nextTick(r2, o) : (o._writableState.errorEmitted = true, process.nextTick(t2, o, e4)) : process.nextTick(t2, o, e4) : i ? (process.nextTick(r2, o), i(e4)) : process.nextTick(r2, o);
          })), this);
        }, undestroy: function() {
          this._readableState && (this._readableState.destroyed = false, this._readableState.reading = false, this._readableState.ended = false, this._readableState.endEmitted = false), this._writableState && (this._writableState.destroyed = false, this._writableState.ended = false, this._writableState.ending = false, this._writableState.finalCalled = false, this._writableState.prefinished = false, this._writableState.finished = false, this._writableState.errorEmitted = false);
        }, errorOrDestroy: function(e3, t3) {
          var r3 = e3._readableState, n2 = e3._writableState;
          r3 && r3.autoDestroy || n2 && n2.autoDestroy ? e3.destroy(t3) : e3.emit("error", t3);
        } };
      }, 2339: (e2, t2, r2) => {
        "use strict";
        var n = r2(289).F.ERR_STREAM_PREMATURE_CLOSE;
        function i() {
        }
        e2.exports = function e3(t3, r3, o) {
          if ("function" == typeof r3) return e3(t3, null, r3);
          r3 || (r3 = {}), o = /* @__PURE__ */ (function(e4) {
            var t4 = false;
            return function() {
              if (!t4) {
                t4 = true;
                for (var r4 = arguments.length, n2 = new Array(r4), i2 = 0; i2 < r4; i2++) n2[i2] = arguments[i2];
                e4.apply(this, n2);
              }
            };
          })(o || i);
          var s = r3.readable || false !== r3.readable && t3.readable, a = r3.writable || false !== r3.writable && t3.writable, c = function() {
            t3.writable || d();
          }, u = t3._writableState && t3._writableState.finished, d = function() {
            a = false, u = true, s || o.call(t3);
          }, f = t3._readableState && t3._readableState.endEmitted, h = function() {
            s = false, f = true, a || o.call(t3);
          }, l = function(e4) {
            o.call(t3, e4);
          }, p = function() {
            var e4;
            return s && !f ? (t3._readableState && t3._readableState.ended || (e4 = new n()), o.call(t3, e4)) : a && !u ? (t3._writableState && t3._writableState.ended || (e4 = new n()), o.call(t3, e4)) : void 0;
          }, b = function() {
            t3.req.on("finish", d);
          };
          return (function(e4) {
            return e4.setHeader && "function" == typeof e4.abort;
          })(t3) ? (t3.on("complete", d), t3.on("abort", p), t3.req ? b() : t3.on("request", b)) : a && !t3._writableState && (t3.on("end", c), t3.on("close", c)), t3.on("end", h), t3.on("finish", d), false !== r3.error && t3.on("error", l), t3.on("close", p), function() {
            t3.removeListener("complete", d), t3.removeListener("abort", p), t3.removeListener("request", b), t3.req && t3.req.removeListener("finish", d), t3.removeListener("end", c), t3.removeListener("close", c), t3.removeListener("finish", d), t3.removeListener("end", h), t3.removeListener("error", l), t3.removeListener("close", p);
          };
        };
      }, 4918: (e2) => {
        e2.exports = function() {
          throw new Error("Readable.from is not available in the browser");
        };
      }, 5481: (e2, t2, r2) => {
        "use strict";
        var n, i = r2(289).F, o = i.ERR_MISSING_ARGS, s = i.ERR_STREAM_DESTROYED;
        function a(e3) {
          if (e3) throw e3;
        }
        function c(e3) {
          e3();
        }
        function u(e3, t3) {
          return e3.pipe(t3);
        }
        e2.exports = function() {
          for (var e3 = arguments.length, t3 = new Array(e3), i2 = 0; i2 < e3; i2++) t3[i2] = arguments[i2];
          var d, f = (function(e4) {
            return e4.length ? "function" != typeof e4[e4.length - 1] ? a : e4.pop() : a;
          })(t3);
          if (Array.isArray(t3[0]) && (t3 = t3[0]), t3.length < 2) throw new o("streams");
          var h = t3.map((function(e4, i3) {
            var o2 = i3 < t3.length - 1;
            return (function(e5, t4, i4, o3) {
              o3 = /* @__PURE__ */ (function(e6) {
                var t5 = false;
                return function() {
                  t5 || (t5 = true, e6.apply(void 0, arguments));
                };
              })(o3);
              var a2 = false;
              e5.on("close", (function() {
                a2 = true;
              })), void 0 === n && (n = r2(2339)), n(e5, { readable: t4, writable: i4 }, (function(e6) {
                if (e6) return o3(e6);
                a2 = true, o3();
              }));
              var c2 = false;
              return function(t5) {
                if (!a2 && !c2) return c2 = true, (function(e6) {
                  return e6.setHeader && "function" == typeof e6.abort;
                })(e5) ? e5.abort() : "function" == typeof e5.destroy ? e5.destroy() : void o3(t5 || new s("pipe"));
              };
            })(e4, o2, i3 > 0, (function(e5) {
              d || (d = e5), e5 && h.forEach(c), o2 || (h.forEach(c), f(d));
            }));
          }));
          return t3.reduce(u);
        };
      }, 5750: (e2, t2, r2) => {
        "use strict";
        var n = r2(289).F.ERR_INVALID_OPT_VALUE;
        e2.exports = { getHighWaterMark: function(e3, t3, r3, i) {
          var o = (function(e4, t4, r4) {
            return null != e4.highWaterMark ? e4.highWaterMark : t4 ? e4[r4] : null;
          })(t3, i, r3);
          if (null != o) {
            if (!isFinite(o) || Math.floor(o) !== o || o < 0) throw new n(i ? r3 : "highWaterMark", o);
            return Math.floor(o);
          }
          return e3.objectMode ? 16 : 16384;
        } };
      }, 2534: (e2, t2, r2) => {
        e2.exports = r2(381).EventEmitter;
      }, 1094: (e2, t2, r2) => {
        (t2 = e2.exports = r2(3033)).Stream = t2, t2.Readable = t2, t2.Writable = r2(2553), t2.Duplex = r2(5707), t2.Transform = r2(141), t2.PassThrough = r2(5271), t2.finished = r2(2339), t2.pipeline = r2(5481);
      }, 3934: (e2, t2, r2) => {
        "use strict";
        var n = r2(6533).Buffer, i = r2(1193), o = r2(800), s = new Array(16), a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13], c = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11], u = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6], d = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11], f = [0, 1518500249, 1859775393, 2400959708, 2840853838], h = [1352829926, 1548603684, 1836072691, 2053994217, 0];
        function l() {
          o.call(this, 64), this._a = 1732584193, this._b = 4023233417, this._c = 2562383102, this._d = 271733878, this._e = 3285377520;
        }
        function p(e3, t3) {
          return e3 << t3 | e3 >>> 32 - t3;
        }
        function b(e3, t3, r3, n2, i2, o2, s2, a2) {
          return p(e3 + (t3 ^ r3 ^ n2) + o2 + s2 | 0, a2) + i2 | 0;
        }
        function y(e3, t3, r3, n2, i2, o2, s2, a2) {
          return p(e3 + (t3 & r3 | ~t3 & n2) + o2 + s2 | 0, a2) + i2 | 0;
        }
        function m(e3, t3, r3, n2, i2, o2, s2, a2) {
          return p(e3 + ((t3 | ~r3) ^ n2) + o2 + s2 | 0, a2) + i2 | 0;
        }
        function g(e3, t3, r3, n2, i2, o2, s2, a2) {
          return p(e3 + (t3 & n2 | r3 & ~n2) + o2 + s2 | 0, a2) + i2 | 0;
        }
        function v(e3, t3, r3, n2, i2, o2, s2, a2) {
          return p(e3 + (t3 ^ (r3 | ~n2)) + o2 + s2 | 0, a2) + i2 | 0;
        }
        i(l, o), l.prototype._update = function() {
          for (var e3 = s, t3 = 0; t3 < 16; ++t3) e3[t3] = this._block.readInt32LE(4 * t3);
          for (var r3 = 0 | this._a, n2 = 0 | this._b, i2 = 0 | this._c, o2 = 0 | this._d, l2 = 0 | this._e, w = 0 | this._a, _ = 0 | this._b, A = 0 | this._c, S = 0 | this._d, C = 0 | this._e, T = 0; T < 80; T += 1) {
            var M, E;
            T < 16 ? (M = b(r3, n2, i2, o2, l2, e3[a[T]], f[0], u[T]), E = v(w, _, A, S, C, e3[c[T]], h[0], d[T])) : T < 32 ? (M = y(r3, n2, i2, o2, l2, e3[a[T]], f[1], u[T]), E = g(w, _, A, S, C, e3[c[T]], h[1], d[T])) : T < 48 ? (M = m(r3, n2, i2, o2, l2, e3[a[T]], f[2], u[T]), E = m(w, _, A, S, C, e3[c[T]], h[2], d[T])) : T < 64 ? (M = g(r3, n2, i2, o2, l2, e3[a[T]], f[3], u[T]), E = y(w, _, A, S, C, e3[c[T]], h[3], d[T])) : (M = v(r3, n2, i2, o2, l2, e3[a[T]], f[4], u[T]), E = b(w, _, A, S, C, e3[c[T]], h[4], d[T])), r3 = l2, l2 = o2, o2 = p(i2, 10), i2 = n2, n2 = M, w = C, C = S, S = p(A, 10), A = _, _ = E;
          }
          var k = this._b + i2 + S | 0;
          this._b = this._c + o2 + C | 0, this._c = this._d + l2 + w | 0, this._d = this._e + r3 + _ | 0, this._e = this._a + n2 + A | 0, this._a = k;
        }, l.prototype._digest = function() {
          this._block[this._blockOffset++] = 128, this._blockOffset > 56 && (this._block.fill(0, this._blockOffset, 64), this._update(), this._blockOffset = 0), this._block.fill(0, this._blockOffset, 56), this._block.writeUInt32LE(this._length[0], 56), this._block.writeUInt32LE(this._length[1], 60), this._update();
          var e3 = n.alloc ? n.alloc(20) : new n(20);
          return e3.writeInt32LE(this._a, 0), e3.writeInt32LE(this._b, 4), e3.writeInt32LE(this._c, 8), e3.writeInt32LE(this._d, 12), e3.writeInt32LE(this._e, 16), e3;
        }, e2.exports = l;
      }, 6608: (e2, t2, r2) => {
        var n = r2(6533), i = n.Buffer;
        function o(e3, t3) {
          for (var r3 in e3) t3[r3] = e3[r3];
        }
        function s(e3, t3, r3) {
          return i(e3, t3, r3);
        }
        i.from && i.alloc && i.allocUnsafe && i.allocUnsafeSlow ? e2.exports = n : (o(n, t2), t2.Buffer = s), s.prototype = Object.create(i.prototype), o(i, s), s.from = function(e3, t3, r3) {
          if ("number" == typeof e3) throw new TypeError("Argument must not be a number");
          return i(e3, t3, r3);
        }, s.alloc = function(e3, t3, r3) {
          if ("number" != typeof e3) throw new TypeError("Argument must be a number");
          var n2 = i(e3);
          return void 0 !== t3 ? "string" == typeof r3 ? n2.fill(t3, r3) : n2.fill(t3) : n2.fill(0), n2;
        }, s.allocUnsafe = function(e3) {
          if ("number" != typeof e3) throw new TypeError("Argument must be a number");
          return i(e3);
        }, s.allocUnsafeSlow = function(e3) {
          if ("number" != typeof e3) throw new TypeError("Argument must be a number");
          return n.SlowBuffer(e3);
        };
      }, 1628: (e2, t2, r2) => {
        "use strict";
        var n, i = r2(6533), o = i.Buffer, s = {};
        for (n in i) i.hasOwnProperty(n) && "SlowBuffer" !== n && "Buffer" !== n && (s[n] = i[n]);
        var a = s.Buffer = {};
        for (n in o) o.hasOwnProperty(n) && "allocUnsafe" !== n && "allocUnsafeSlow" !== n && (a[n] = o[n]);
        if (s.Buffer.prototype = o.prototype, a.from && a.from !== Uint8Array.from || (a.from = function(e3, t3, r3) {
          if ("number" == typeof e3) throw new TypeError('The "value" argument must not be of type number. Received type ' + typeof e3);
          if (e3 && void 0 === e3.length) throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e3);
          return o(e3, t3, r3);
        }), a.alloc || (a.alloc = function(e3, t3, r3) {
          if ("number" != typeof e3) throw new TypeError('The "size" argument must be of type number. Received type ' + typeof e3);
          if (e3 < 0 || e3 >= 2 * (1 << 30)) throw new RangeError('The value "' + e3 + '" is invalid for option "size"');
          var n2 = o(e3);
          return t3 && 0 !== t3.length ? "string" == typeof r3 ? n2.fill(t3, r3) : n2.fill(t3) : n2.fill(0), n2;
        }), !s.kStringMaxLength) try {
          s.kStringMaxLength = process.binding("buffer").kStringMaxLength;
        } catch (e3) {
        }
        s.constants || (s.constants = { MAX_LENGTH: s.kMaxLength }, s.kStringMaxLength && (s.constants.MAX_STRING_LENGTH = s.kStringMaxLength)), e2.exports = s;
      }, 3366: (e2, t2, r2) => {
        var n = r2(6608).Buffer;
        function i(e3, t3) {
          this._block = n.alloc(e3), this._finalSize = t3, this._blockSize = e3, this._len = 0;
        }
        i.prototype.update = function(e3, t3) {
          "string" == typeof e3 && (t3 = t3 || "utf8", e3 = n.from(e3, t3));
          for (var r3 = this._block, i2 = this._blockSize, o = e3.length, s = this._len, a = 0; a < o; ) {
            for (var c = s % i2, u = Math.min(o - a, i2 - c), d = 0; d < u; d++) r3[c + d] = e3[a + d];
            a += u, (s += u) % i2 == 0 && this._update(r3);
          }
          return this._len += o, this;
        }, i.prototype.digest = function(e3) {
          var t3 = this._len % this._blockSize;
          this._block[t3] = 128, this._block.fill(0, t3 + 1), t3 >= this._finalSize && (this._update(this._block), this._block.fill(0));
          var r3 = 8 * this._len;
          if (r3 <= 4294967295) this._block.writeUInt32BE(r3, this._blockSize - 4);
          else {
            var n2 = (4294967295 & r3) >>> 0, i2 = (r3 - n2) / 4294967296;
            this._block.writeUInt32BE(i2, this._blockSize - 8), this._block.writeUInt32BE(n2, this._blockSize - 4);
          }
          this._update(this._block);
          var o = this._hash();
          return e3 ? o.toString(e3) : o;
        }, i.prototype._update = function() {
          throw new Error("_update must be implemented by subclass");
        }, e2.exports = i;
      }, 5244: (e2, t2, r2) => {
        var n = e2.exports = function(e3) {
          e3 = e3.toLowerCase();
          var t3 = n[e3];
          if (!t3) throw new Error(e3 + " is not supported (we accept pull requests)");
          return new t3();
        };
        n.sha = r2(2954), n.sha1 = r2(6375), n.sha224 = r2(4012), n.sha256 = r2(8729), n.sha384 = r2(1453), n.sha512 = r2(1756);
      }, 2954: (e2, t2, r2) => {
        var n = r2(1193), i = r2(3366), o = r2(6608).Buffer, s = [1518500249, 1859775393, -1894007588, -899497514], a = new Array(80);
        function c() {
          this.init(), this._w = a, i.call(this, 64, 56);
        }
        function u(e3) {
          return e3 << 30 | e3 >>> 2;
        }
        function d(e3, t3, r3, n2) {
          return 0 === e3 ? t3 & r3 | ~t3 & n2 : 2 === e3 ? t3 & r3 | t3 & n2 | r3 & n2 : t3 ^ r3 ^ n2;
        }
        n(c, i), c.prototype.init = function() {
          return this._a = 1732584193, this._b = 4023233417, this._c = 2562383102, this._d = 271733878, this._e = 3285377520, this;
        }, c.prototype._update = function(e3) {
          for (var t3, r3 = this._w, n2 = 0 | this._a, i2 = 0 | this._b, o2 = 0 | this._c, a2 = 0 | this._d, c2 = 0 | this._e, f = 0; f < 16; ++f) r3[f] = e3.readInt32BE(4 * f);
          for (; f < 80; ++f) r3[f] = r3[f - 3] ^ r3[f - 8] ^ r3[f - 14] ^ r3[f - 16];
          for (var h = 0; h < 80; ++h) {
            var l = ~~(h / 20), p = 0 | ((t3 = n2) << 5 | t3 >>> 27) + d(l, i2, o2, a2) + c2 + r3[h] + s[l];
            c2 = a2, a2 = o2, o2 = u(i2), i2 = n2, n2 = p;
          }
          this._a = n2 + this._a | 0, this._b = i2 + this._b | 0, this._c = o2 + this._c | 0, this._d = a2 + this._d | 0, this._e = c2 + this._e | 0;
        }, c.prototype._hash = function() {
          var e3 = o.allocUnsafe(20);
          return e3.writeInt32BE(0 | this._a, 0), e3.writeInt32BE(0 | this._b, 4), e3.writeInt32BE(0 | this._c, 8), e3.writeInt32BE(0 | this._d, 12), e3.writeInt32BE(0 | this._e, 16), e3;
        }, e2.exports = c;
      }, 6375: (e2, t2, r2) => {
        var n = r2(1193), i = r2(3366), o = r2(6608).Buffer, s = [1518500249, 1859775393, -1894007588, -899497514], a = new Array(80);
        function c() {
          this.init(), this._w = a, i.call(this, 64, 56);
        }
        function u(e3) {
          return e3 << 5 | e3 >>> 27;
        }
        function d(e3) {
          return e3 << 30 | e3 >>> 2;
        }
        function f(e3, t3, r3, n2) {
          return 0 === e3 ? t3 & r3 | ~t3 & n2 : 2 === e3 ? t3 & r3 | t3 & n2 | r3 & n2 : t3 ^ r3 ^ n2;
        }
        n(c, i), c.prototype.init = function() {
          return this._a = 1732584193, this._b = 4023233417, this._c = 2562383102, this._d = 271733878, this._e = 3285377520, this;
        }, c.prototype._update = function(e3) {
          for (var t3, r3 = this._w, n2 = 0 | this._a, i2 = 0 | this._b, o2 = 0 | this._c, a2 = 0 | this._d, c2 = 0 | this._e, h = 0; h < 16; ++h) r3[h] = e3.readInt32BE(4 * h);
          for (; h < 80; ++h) r3[h] = (t3 = r3[h - 3] ^ r3[h - 8] ^ r3[h - 14] ^ r3[h - 16]) << 1 | t3 >>> 31;
          for (var l = 0; l < 80; ++l) {
            var p = ~~(l / 20), b = u(n2) + f(p, i2, o2, a2) + c2 + r3[l] + s[p] | 0;
            c2 = a2, a2 = o2, o2 = d(i2), i2 = n2, n2 = b;
          }
          this._a = n2 + this._a | 0, this._b = i2 + this._b | 0, this._c = o2 + this._c | 0, this._d = a2 + this._d | 0, this._e = c2 + this._e | 0;
        }, c.prototype._hash = function() {
          var e3 = o.allocUnsafe(20);
          return e3.writeInt32BE(0 | this._a, 0), e3.writeInt32BE(0 | this._b, 4), e3.writeInt32BE(0 | this._c, 8), e3.writeInt32BE(0 | this._d, 12), e3.writeInt32BE(0 | this._e, 16), e3;
        }, e2.exports = c;
      }, 4012: (e2, t2, r2) => {
        var n = r2(1193), i = r2(8729), o = r2(3366), s = r2(6608).Buffer, a = new Array(64);
        function c() {
          this.init(), this._w = a, o.call(this, 64, 56);
        }
        n(c, i), c.prototype.init = function() {
          return this._a = 3238371032, this._b = 914150663, this._c = 812702999, this._d = 4144912697, this._e = 4290775857, this._f = 1750603025, this._g = 1694076839, this._h = 3204075428, this;
        }, c.prototype._hash = function() {
          var e3 = s.allocUnsafe(28);
          return e3.writeInt32BE(this._a, 0), e3.writeInt32BE(this._b, 4), e3.writeInt32BE(this._c, 8), e3.writeInt32BE(this._d, 12), e3.writeInt32BE(this._e, 16), e3.writeInt32BE(this._f, 20), e3.writeInt32BE(this._g, 24), e3;
        }, e2.exports = c;
      }, 8729: (e2, t2, r2) => {
        var n = r2(1193), i = r2(3366), o = r2(6608).Buffer, s = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298], a = new Array(64);
        function c() {
          this.init(), this._w = a, i.call(this, 64, 56);
        }
        function u(e3, t3, r3) {
          return r3 ^ e3 & (t3 ^ r3);
        }
        function d(e3, t3, r3) {
          return e3 & t3 | r3 & (e3 | t3);
        }
        function f(e3) {
          return (e3 >>> 2 | e3 << 30) ^ (e3 >>> 13 | e3 << 19) ^ (e3 >>> 22 | e3 << 10);
        }
        function h(e3) {
          return (e3 >>> 6 | e3 << 26) ^ (e3 >>> 11 | e3 << 21) ^ (e3 >>> 25 | e3 << 7);
        }
        function l(e3) {
          return (e3 >>> 7 | e3 << 25) ^ (e3 >>> 18 | e3 << 14) ^ e3 >>> 3;
        }
        n(c, i), c.prototype.init = function() {
          return this._a = 1779033703, this._b = 3144134277, this._c = 1013904242, this._d = 2773480762, this._e = 1359893119, this._f = 2600822924, this._g = 528734635, this._h = 1541459225, this;
        }, c.prototype._update = function(e3) {
          for (var t3, r3 = this._w, n2 = 0 | this._a, i2 = 0 | this._b, o2 = 0 | this._c, a2 = 0 | this._d, c2 = 0 | this._e, p = 0 | this._f, b = 0 | this._g, y = 0 | this._h, m = 0; m < 16; ++m) r3[m] = e3.readInt32BE(4 * m);
          for (; m < 64; ++m) r3[m] = 0 | (((t3 = r3[m - 2]) >>> 17 | t3 << 15) ^ (t3 >>> 19 | t3 << 13) ^ t3 >>> 10) + r3[m - 7] + l(r3[m - 15]) + r3[m - 16];
          for (var g = 0; g < 64; ++g) {
            var v = y + h(c2) + u(c2, p, b) + s[g] + r3[g] | 0, w = f(n2) + d(n2, i2, o2) | 0;
            y = b, b = p, p = c2, c2 = a2 + v | 0, a2 = o2, o2 = i2, i2 = n2, n2 = v + w | 0;
          }
          this._a = n2 + this._a | 0, this._b = i2 + this._b | 0, this._c = o2 + this._c | 0, this._d = a2 + this._d | 0, this._e = c2 + this._e | 0, this._f = p + this._f | 0, this._g = b + this._g | 0, this._h = y + this._h | 0;
        }, c.prototype._hash = function() {
          var e3 = o.allocUnsafe(32);
          return e3.writeInt32BE(this._a, 0), e3.writeInt32BE(this._b, 4), e3.writeInt32BE(this._c, 8), e3.writeInt32BE(this._d, 12), e3.writeInt32BE(this._e, 16), e3.writeInt32BE(this._f, 20), e3.writeInt32BE(this._g, 24), e3.writeInt32BE(this._h, 28), e3;
        }, e2.exports = c;
      }, 1453: (e2, t2, r2) => {
        var n = r2(1193), i = r2(1756), o = r2(3366), s = r2(6608).Buffer, a = new Array(160);
        function c() {
          this.init(), this._w = a, o.call(this, 128, 112);
        }
        n(c, i), c.prototype.init = function() {
          return this._ah = 3418070365, this._bh = 1654270250, this._ch = 2438529370, this._dh = 355462360, this._eh = 1731405415, this._fh = 2394180231, this._gh = 3675008525, this._hh = 1203062813, this._al = 3238371032, this._bl = 914150663, this._cl = 812702999, this._dl = 4144912697, this._el = 4290775857, this._fl = 1750603025, this._gl = 1694076839, this._hl = 3204075428, this;
        }, c.prototype._hash = function() {
          var e3 = s.allocUnsafe(48);
          function t3(t4, r3, n2) {
            e3.writeInt32BE(t4, n2), e3.writeInt32BE(r3, n2 + 4);
          }
          return t3(this._ah, this._al, 0), t3(this._bh, this._bl, 8), t3(this._ch, this._cl, 16), t3(this._dh, this._dl, 24), t3(this._eh, this._el, 32), t3(this._fh, this._fl, 40), e3;
        }, e2.exports = c;
      }, 1756: (e2, t2, r2) => {
        var n = r2(1193), i = r2(3366), o = r2(6608).Buffer, s = [1116352408, 3609767458, 1899447441, 602891725, 3049323471, 3964484399, 3921009573, 2173295548, 961987163, 4081628472, 1508970993, 3053834265, 2453635748, 2937671579, 2870763221, 3664609560, 3624381080, 2734883394, 310598401, 1164996542, 607225278, 1323610764, 1426881987, 3590304994, 1925078388, 4068182383, 2162078206, 991336113, 2614888103, 633803317, 3248222580, 3479774868, 3835390401, 2666613458, 4022224774, 944711139, 264347078, 2341262773, 604807628, 2007800933, 770255983, 1495990901, 1249150122, 1856431235, 1555081692, 3175218132, 1996064986, 2198950837, 2554220882, 3999719339, 2821834349, 766784016, 2952996808, 2566594879, 3210313671, 3203337956, 3336571891, 1034457026, 3584528711, 2466948901, 113926993, 3758326383, 338241895, 168717936, 666307205, 1188179964, 773529912, 1546045734, 1294757372, 1522805485, 1396182291, 2643833823, 1695183700, 2343527390, 1986661051, 1014477480, 2177026350, 1206759142, 2456956037, 344077627, 2730485921, 1290863460, 2820302411, 3158454273, 3259730800, 3505952657, 3345764771, 106217008, 3516065817, 3606008344, 3600352804, 1432725776, 4094571909, 1467031594, 275423344, 851169720, 430227734, 3100823752, 506948616, 1363258195, 659060556, 3750685593, 883997877, 3785050280, 958139571, 3318307427, 1322822218, 3812723403, 1537002063, 2003034995, 1747873779, 3602036899, 1955562222, 1575990012, 2024104815, 1125592928, 2227730452, 2716904306, 2361852424, 442776044, 2428436474, 593698344, 2756734187, 3733110249, 3204031479, 2999351573, 3329325298, 3815920427, 3391569614, 3928383900, 3515267271, 566280711, 3940187606, 3454069534, 4118630271, 4000239992, 116418474, 1914138554, 174292421, 2731055270, 289380356, 3203993006, 460393269, 320620315, 685471733, 587496836, 852142971, 1086792851, 1017036298, 365543100, 1126000580, 2618297676, 1288033470, 3409855158, 1501505948, 4234509866, 1607167915, 987167468, 1816402316, 1246189591], a = new Array(160);
        function c() {
          this.init(), this._w = a, i.call(this, 128, 112);
        }
        function u(e3, t3, r3) {
          return r3 ^ e3 & (t3 ^ r3);
        }
        function d(e3, t3, r3) {
          return e3 & t3 | r3 & (e3 | t3);
        }
        function f(e3, t3) {
          return (e3 >>> 28 | t3 << 4) ^ (t3 >>> 2 | e3 << 30) ^ (t3 >>> 7 | e3 << 25);
        }
        function h(e3, t3) {
          return (e3 >>> 14 | t3 << 18) ^ (e3 >>> 18 | t3 << 14) ^ (t3 >>> 9 | e3 << 23);
        }
        function l(e3, t3) {
          return (e3 >>> 1 | t3 << 31) ^ (e3 >>> 8 | t3 << 24) ^ e3 >>> 7;
        }
        function p(e3, t3) {
          return (e3 >>> 1 | t3 << 31) ^ (e3 >>> 8 | t3 << 24) ^ (e3 >>> 7 | t3 << 25);
        }
        function b(e3, t3) {
          return (e3 >>> 19 | t3 << 13) ^ (t3 >>> 29 | e3 << 3) ^ e3 >>> 6;
        }
        function y(e3, t3) {
          return (e3 >>> 19 | t3 << 13) ^ (t3 >>> 29 | e3 << 3) ^ (e3 >>> 6 | t3 << 26);
        }
        function m(e3, t3) {
          return e3 >>> 0 < t3 >>> 0 ? 1 : 0;
        }
        n(c, i), c.prototype.init = function() {
          return this._ah = 1779033703, this._bh = 3144134277, this._ch = 1013904242, this._dh = 2773480762, this._eh = 1359893119, this._fh = 2600822924, this._gh = 528734635, this._hh = 1541459225, this._al = 4089235720, this._bl = 2227873595, this._cl = 4271175723, this._dl = 1595750129, this._el = 2917565137, this._fl = 725511199, this._gl = 4215389547, this._hl = 327033209, this;
        }, c.prototype._update = function(e3) {
          for (var t3 = this._w, r3 = 0 | this._ah, n2 = 0 | this._bh, i2 = 0 | this._ch, o2 = 0 | this._dh, a2 = 0 | this._eh, c2 = 0 | this._fh, g = 0 | this._gh, v = 0 | this._hh, w = 0 | this._al, _ = 0 | this._bl, A = 0 | this._cl, S = 0 | this._dl, C = 0 | this._el, T = 0 | this._fl, M = 0 | this._gl, E = 0 | this._hl, k = 0; k < 32; k += 2) t3[k] = e3.readInt32BE(4 * k), t3[k + 1] = e3.readInt32BE(4 * k + 4);
          for (; k < 160; k += 2) {
            var x = t3[k - 30], I = t3[k - 30 + 1], B = l(x, I), U = p(I, x), P = b(x = t3[k - 4], I = t3[k - 4 + 1]), O = y(I, x), R = t3[k - 14], N = t3[k - 14 + 1], L = t3[k - 32], j = t3[k - 32 + 1], D = U + N | 0, F = B + R + m(D, U) | 0;
            F = (F = F + P + m(D = D + O | 0, O) | 0) + L + m(D = D + j | 0, j) | 0, t3[k] = F, t3[k + 1] = D;
          }
          for (var H = 0; H < 160; H += 2) {
            F = t3[H], D = t3[H + 1];
            var q = d(r3, n2, i2), $ = d(w, _, A), V = f(r3, w), G = f(w, r3), z = h(a2, C), K = h(C, a2), W = s[H], J = s[H + 1], Z = u(a2, c2, g), X = u(C, T, M), Y = E + K | 0, Q = v + z + m(Y, E) | 0;
            Q = (Q = (Q = Q + Z + m(Y = Y + X | 0, X) | 0) + W + m(Y = Y + J | 0, J) | 0) + F + m(Y = Y + D | 0, D) | 0;
            var ee = G + $ | 0, te = V + q + m(ee, G) | 0;
            v = g, E = M, g = c2, M = T, c2 = a2, T = C, a2 = o2 + Q + m(C = S + Y | 0, S) | 0, o2 = i2, S = A, i2 = n2, A = _, n2 = r3, _ = w, r3 = Q + te + m(w = Y + ee | 0, Y) | 0;
          }
          this._al = this._al + w | 0, this._bl = this._bl + _ | 0, this._cl = this._cl + A | 0, this._dl = this._dl + S | 0, this._el = this._el + C | 0, this._fl = this._fl + T | 0, this._gl = this._gl + M | 0, this._hl = this._hl + E | 0, this._ah = this._ah + r3 + m(this._al, w) | 0, this._bh = this._bh + n2 + m(this._bl, _) | 0, this._ch = this._ch + i2 + m(this._cl, A) | 0, this._dh = this._dh + o2 + m(this._dl, S) | 0, this._eh = this._eh + a2 + m(this._el, C) | 0, this._fh = this._fh + c2 + m(this._fl, T) | 0, this._gh = this._gh + g + m(this._gl, M) | 0, this._hh = this._hh + v + m(this._hl, E) | 0;
        }, c.prototype._hash = function() {
          var e3 = o.allocUnsafe(64);
          function t3(t4, r3, n2) {
            e3.writeInt32BE(t4, n2), e3.writeInt32BE(r3, n2 + 4);
          }
          return t3(this._ah, this._al, 0), t3(this._bh, this._bl, 8), t3(this._ch, this._cl, 16), t3(this._dh, this._dl, 24), t3(this._eh, this._el, 32), t3(this._fh, this._fl, 40), t3(this._gh, this._gl, 48), t3(this._hh, this._hl, 56), e3;
        }, e2.exports = c;
      }, 3803: (e2, t2, r2) => {
        e2.exports = i;
        var n = r2(381).EventEmitter;
        function i() {
          n.call(this);
        }
        r2(1193)(i, n), i.Readable = r2(3033), i.Writable = r2(2553), i.Duplex = r2(5707), i.Transform = r2(141), i.PassThrough = r2(5271), i.finished = r2(2339), i.pipeline = r2(5481), i.Stream = i, i.prototype.pipe = function(e3, t3) {
          var r3 = this;
          function i2(t4) {
            e3.writable && false === e3.write(t4) && r3.pause && r3.pause();
          }
          function o() {
            r3.readable && r3.resume && r3.resume();
          }
          r3.on("data", i2), e3.on("drain", o), e3._isStdio || t3 && false === t3.end || (r3.on("end", a), r3.on("close", c));
          var s = false;
          function a() {
            s || (s = true, e3.end());
          }
          function c() {
            s || (s = true, "function" == typeof e3.destroy && e3.destroy());
          }
          function u(e4) {
            if (d(), 0 === n.listenerCount(this, "error")) throw e4;
          }
          function d() {
            r3.removeListener("data", i2), e3.removeListener("drain", o), r3.removeListener("end", a), r3.removeListener("close", c), r3.removeListener("error", u), e3.removeListener("error", u), r3.removeListener("end", d), r3.removeListener("close", d), e3.removeListener("close", d);
          }
          return r3.on("error", u), e3.on("error", u), r3.on("end", d), r3.on("close", d), e3.on("close", d), e3.emit("pipe", r3), e3;
        };
      }, 6704: (e2, t2, r2) => {
        "use strict";
        var n = r2(6608).Buffer, i = n.isEncoding || function(e3) {
          switch ((e3 = "" + e3) && e3.toLowerCase()) {
            case "hex":
            case "utf8":
            case "utf-8":
            case "ascii":
            case "binary":
            case "base64":
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
            case "raw":
              return true;
            default:
              return false;
          }
        };
        function o(e3) {
          var t3;
          switch (this.encoding = (function(e4) {
            var t4 = (function(e5) {
              if (!e5) return "utf8";
              for (var t5; ; ) switch (e5) {
                case "utf8":
                case "utf-8":
                  return "utf8";
                case "ucs2":
                case "ucs-2":
                case "utf16le":
                case "utf-16le":
                  return "utf16le";
                case "latin1":
                case "binary":
                  return "latin1";
                case "base64":
                case "ascii":
                case "hex":
                  return e5;
                default:
                  if (t5) return;
                  e5 = ("" + e5).toLowerCase(), t5 = true;
              }
            })(e4);
            if ("string" != typeof t4 && (n.isEncoding === i || !i(e4))) throw new Error("Unknown encoding: " + e4);
            return t4 || e4;
          })(e3), this.encoding) {
            case "utf16le":
              this.text = c, this.end = u, t3 = 4;
              break;
            case "utf8":
              this.fillLast = a, t3 = 4;
              break;
            case "base64":
              this.text = d, this.end = f, t3 = 3;
              break;
            default:
              return this.write = h, void (this.end = l);
          }
          this.lastNeed = 0, this.lastTotal = 0, this.lastChar = n.allocUnsafe(t3);
        }
        function s(e3) {
          return e3 <= 127 ? 0 : e3 >> 5 == 6 ? 2 : e3 >> 4 == 14 ? 3 : e3 >> 3 == 30 ? 4 : e3 >> 6 == 2 ? -1 : -2;
        }
        function a(e3) {
          var t3 = this.lastTotal - this.lastNeed, r3 = (function(e4, t4) {
            if (128 != (192 & t4[0])) return e4.lastNeed = 0, "\uFFFD";
            if (e4.lastNeed > 1 && t4.length > 1) {
              if (128 != (192 & t4[1])) return e4.lastNeed = 1, "\uFFFD";
              if (e4.lastNeed > 2 && t4.length > 2 && 128 != (192 & t4[2])) return e4.lastNeed = 2, "\uFFFD";
            }
          })(this, e3);
          return void 0 !== r3 ? r3 : this.lastNeed <= e3.length ? (e3.copy(this.lastChar, t3, 0, this.lastNeed), this.lastChar.toString(this.encoding, 0, this.lastTotal)) : (e3.copy(this.lastChar, t3, 0, e3.length), void (this.lastNeed -= e3.length));
        }
        function c(e3, t3) {
          if ((e3.length - t3) % 2 == 0) {
            var r3 = e3.toString("utf16le", t3);
            if (r3) {
              var n2 = r3.charCodeAt(r3.length - 1);
              if (n2 >= 55296 && n2 <= 56319) return this.lastNeed = 2, this.lastTotal = 4, this.lastChar[0] = e3[e3.length - 2], this.lastChar[1] = e3[e3.length - 1], r3.slice(0, -1);
            }
            return r3;
          }
          return this.lastNeed = 1, this.lastTotal = 2, this.lastChar[0] = e3[e3.length - 1], e3.toString("utf16le", t3, e3.length - 1);
        }
        function u(e3) {
          var t3 = e3 && e3.length ? this.write(e3) : "";
          if (this.lastNeed) {
            var r3 = this.lastTotal - this.lastNeed;
            return t3 + this.lastChar.toString("utf16le", 0, r3);
          }
          return t3;
        }
        function d(e3, t3) {
          var r3 = (e3.length - t3) % 3;
          return 0 === r3 ? e3.toString("base64", t3) : (this.lastNeed = 3 - r3, this.lastTotal = 3, 1 === r3 ? this.lastChar[0] = e3[e3.length - 1] : (this.lastChar[0] = e3[e3.length - 2], this.lastChar[1] = e3[e3.length - 1]), e3.toString("base64", t3, e3.length - r3));
        }
        function f(e3) {
          var t3 = e3 && e3.length ? this.write(e3) : "";
          return this.lastNeed ? t3 + this.lastChar.toString("base64", 0, 3 - this.lastNeed) : t3;
        }
        function h(e3) {
          return e3.toString(this.encoding);
        }
        function l(e3) {
          return e3 && e3.length ? this.write(e3) : "";
        }
        t2.I = o, o.prototype.write = function(e3) {
          if (0 === e3.length) return "";
          var t3, r3;
          if (this.lastNeed) {
            if (void 0 === (t3 = this.fillLast(e3))) return "";
            r3 = this.lastNeed, this.lastNeed = 0;
          } else r3 = 0;
          return r3 < e3.length ? t3 ? t3 + this.text(e3, r3) : this.text(e3, r3) : t3 || "";
        }, o.prototype.end = function(e3) {
          var t3 = e3 && e3.length ? this.write(e3) : "";
          return this.lastNeed ? t3 + "\uFFFD" : t3;
        }, o.prototype.text = function(e3, t3) {
          var r3 = (function(e4, t4, r4) {
            var n3 = t4.length - 1;
            if (n3 < r4) return 0;
            var i2 = s(t4[n3]);
            return i2 >= 0 ? (i2 > 0 && (e4.lastNeed = i2 - 1), i2) : --n3 < r4 || -2 === i2 ? 0 : (i2 = s(t4[n3])) >= 0 ? (i2 > 0 && (e4.lastNeed = i2 - 2), i2) : --n3 < r4 || -2 === i2 ? 0 : (i2 = s(t4[n3])) >= 0 ? (i2 > 0 && (2 === i2 ? i2 = 0 : e4.lastNeed = i2 - 3), i2) : 0;
          })(this, e3, t3);
          if (!this.lastNeed) return e3.toString("utf8", t3);
          this.lastTotal = r3;
          var n2 = e3.length - (r3 - this.lastNeed);
          return e3.copy(this.lastChar, 0, n2), e3.toString("utf8", t3, n2);
        }, o.prototype.fillLast = function(e3) {
          if (this.lastNeed <= e3.length) return e3.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed), this.lastChar.toString(this.encoding, 0, this.lastTotal);
          e3.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, e3.length), this.lastNeed -= e3.length;
        };
      }, 1947: (e2, t2, r2) => {
        function n(e3) {
          try {
            if (!r2.g.localStorage) return false;
          } catch (e4) {
            return false;
          }
          var t3 = r2.g.localStorage[e3];
          return null != t3 && "true" === String(t3).toLowerCase();
        }
        e2.exports = function(e3, t3) {
          if (n("noDeprecation")) return e3;
          var r3 = false;
          return function() {
            if (!r3) {
              if (n("throwDeprecation")) throw new Error(t3);
              n("traceDeprecation") ? console.trace(t3) : console.warn(t3), r3 = true;
            }
            return e3.apply(this, arguments);
          };
        };
      }, 7998: () => {
      }, 7175: () => {
      }, 9322: () => {
      }, 4507: () => {
      }, 3541: () => {
      }, 6429: () => {
      }, 7077: () => {
      }, 5569: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        }, s = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.addressFromLockupScript = t2.addressWithoutExplicitGroupIndex = t2.hasExplicitGroupIndex = t2.groupFromHint = t2.groupFromBytes = t2.groupOfLockupScript = t2.subContractId = t2.contractIdFromTx = t2.addressFromTokenId = t2.addressFromContractId = t2.addressFromScript = t2.addressFromPublicKey = t2.publicKeyFromPrivateKey = t2.groupOfPrivateKey = t2.tokenIdFromAddress = t2.contractIdFromAddress = t2.groupOfAddress = t2.isContractAddress = t2.defaultGroupOfGrouplessAddress = t2.isGrouplessAddressWithGroupIndex = t2.isGrouplessAddressWithoutGroupIndex = t2.isGrouplessAddress = t2.isAssetAddress = t2.addressToBytes = t2.isValidAddress = t2.validateAddress = t2.AddressType = void 0;
        const a = r2(3071), c = s(r2(3900)), u = r2(7695), d = s(r2(1540)), f = o(r2(4468)), h = r2(664), l = r2(1678), p = r2(3651), b = s(r2(160)), y = r2(4652), m = r2(2709), g = r2(5441), v = new a.ec("secp256k1"), w = new a.ec("p256"), _ = new a.eddsa("ed25519"), A = 32;
        var S;
        function C(e3) {
          T(e3);
        }
        function T(e3) {
          const t3 = M(e3);
          if (0 === t3.length) throw new Error("Address is empty");
          const r3 = t3[0];
          if (r3 === S.P2MPKH) {
            let r4;
            try {
              r4 = l.lockupScriptCodec.decode(t3).value;
            } catch (t4) {
              throw new y.TraceableError(`Invalid multisig address: ${e3}`, t4);
            }
            const n2 = r4.publicKeyHashes.length, i2 = r4.m;
            if (n2 < i2 || i2 <= 0) throw new Error(`Invalid multisig address, n: ${n2}, m: ${i2}`);
            const o2 = p.i32Codec.encode(n2).length, s2 = p.i32Codec.encode(i2).length, a2 = o2 + A * n2 + s2 + 1;
            if (t3.length === a2) return t3;
          } else if (r3 === S.P2PKH || r3 === S.P2SH || r3 === S.P2C) {
            if (33 === t3.length) return t3;
          } else {
            if (r3 === S.P2PK) return F(l.lockupScriptCodec.decode(t3).value.group), t3;
            if (r3 === S.P2HMPK) return F(l.lockupScriptCodec.decode(t3).value.group), t3;
          }
          throw new Error(`Invalid address: ${e3}`);
        }
        function M(e3) {
          if (D(e3)) {
            const r3 = (t3 = e3[e3.length - 1], F(parseInt(t3), t3)), n2 = (0, f.base58ToBytes)(e3.slice(0, e3.length - 2));
            if (n2.length > 0 && E(n2[0])) {
              const e4 = m.byteCodec.encode(r3);
              return new Uint8Array([...n2, ...e4]);
            }
            throw new Error(`Invalid groupless address: ${e3}`);
          }
          {
            const t4 = (0, f.base58ToBytes)(e3);
            if (t4.length > 0 && E(t4[0])) {
              const e4 = x(t4.slice(2, t4.length - 4)), r3 = m.byteCodec.encode(e4);
              return new Uint8Array([...t4, ...r3]);
            }
            return t4;
          }
          var t3;
        }
        function E(e3) {
          return e3 === S.P2PK || e3 === S.P2HMPK;
        }
        function k(e3) {
          return E(T(e3)[0]);
        }
        function x(e3) {
          return (255 & e3[e3.length - 1]) % u.TOTAL_NUMBER_OF_GROUPS;
        }
        function I(e3) {
          const t3 = T(e3), r3 = t3[0], n2 = t3.slice(1);
          if (r3 === S.P2PKH) return (function(e4) {
            return L(e4);
          })(n2);
          if (r3 === S.P2MPKH) return (function(e4) {
            return L(e4.slice(1, 33));
          })(n2);
          if (r3 === S.P2SH) return (function(e4) {
            return L(e4);
          })(n2);
          if (E(r3)) return (function(e4) {
            return e4[e4.length - 1] % u.TOTAL_NUMBER_OF_GROUPS;
          })(n2);
          {
            const t4 = B(e3);
            return t4["" + (t4.length - 1)];
          }
        }
        function B(e3) {
          return U(e3);
        }
        function U(e3) {
          const t3 = (0, f.base58ToBytes)(e3);
          if (0 == t3.length) throw new Error("Address string is empty");
          const r3 = t3[0], n2 = t3.slice(1);
          if (r3 == S.P2C) return n2;
          throw new Error(`Invalid contract address type: ${r3}`);
        }
        function P(e3, t3) {
          switch (t3 ?? "default") {
            case "default":
            case "gl-secp256k1":
              return v.keyFromPrivate(e3).getPublic(true, "hex");
            case "gl-secp256r1":
            case "gl-webauthn":
              return w.keyFromPrivate(e3).getPublic(true, "hex");
            case "gl-ed25519":
              return _.keyFromSecret(e3).getPublic("hex");
            case "bip340-schnorr":
              return v.g.mul(new c.default(e3, 16)).encode("hex", true).slice(2);
          }
        }
        function O(e3, t3) {
          const r3 = t3 ?? "default";
          switch (r3) {
            case "default": {
              const t4 = d.default.blake2b((0, h.hexToBinUnsafe)(e3), void 0, 32), r4 = new Uint8Array([S.P2PKH, ...t4]);
              return f.default.encode(r4);
            }
            case "bip340-schnorr":
              return R((0, h.hexToBinUnsafe)(`0101000000000458144020${e3}8685`));
            default:
              return (function(e4, t4) {
                const r4 = (0, h.hexToBinUnsafe)(e4), n2 = "gl-secp256k1" === t4 ? { kind: "SecP256K1", value: r4 } : "gl-secp256r1" === t4 ? { kind: "SecP256R1", value: r4 } : "gl-ed25519" === t4 ? { kind: "ED25519", value: r4 } : { kind: "WebAuthn", value: r4 }, i2 = g.safePublicKeyLikeCodec.encode(n2), o2 = new Uint8Array([S.P2PK, ...i2]);
                return f.default.encode(o2);
              })(e3, r3);
          }
        }
        function R(e3) {
          const t3 = d.default.blake2b(e3, void 0, 32);
          return f.default.encode(new Uint8Array([S.P2SH, ...t3]));
        }
        function N(e3) {
          const t3 = (0, h.hexToBinUnsafe)(e3), r3 = new Uint8Array([S.P2C, ...t3]);
          return f.default.encode(r3);
        }
        function L(e3) {
          return j(1 | (0, b.default)(e3));
        }
        function j(e3) {
          return (0, h.xorByte)(e3) % u.TOTAL_NUMBER_OF_GROUPS;
        }
        function D(e3) {
          return e3.length > 2 && ":" === e3[e3.length - 2];
        }
        function F(e3, t3) {
          if (isNaN(e3) || e3 < 0 || e3 >= u.TOTAL_NUMBER_OF_GROUPS) throw new Error(`Invalid group index: ${t3 ?? e3}`);
          return e3;
        }
        !(function(e3) {
          e3[e3.P2PKH = 0] = "P2PKH", e3[e3.P2MPKH = 1] = "P2MPKH", e3[e3.P2SH = 2] = "P2SH", e3[e3.P2C = 3] = "P2C", e3[e3.P2PK = 4] = "P2PK", e3[e3.P2HMPK = 5] = "P2HMPK";
        })(S = t2.AddressType || (t2.AddressType = {})), t2.validateAddress = C, t2.isValidAddress = function(e3) {
          try {
            return C(e3), true;
          } catch {
            return false;
          }
        }, t2.addressToBytes = M, t2.isAssetAddress = function(e3) {
          const t3 = T(e3)[0];
          return t3 === S.P2PKH || t3 === S.P2MPKH || t3 === S.P2SH || t3 === S.P2PK || t3 === S.P2HMPK;
        }, t2.isGrouplessAddress = k, t2.isGrouplessAddressWithoutGroupIndex = function(e3) {
          return !D(e3) && k(e3);
        }, t2.isGrouplessAddressWithGroupIndex = function(e3) {
          return D(e3) && k(e3);
        }, t2.defaultGroupOfGrouplessAddress = x, t2.isContractAddress = function(e3) {
          return T(e3)[0] === S.P2C;
        }, t2.groupOfAddress = I, t2.contractIdFromAddress = B, t2.tokenIdFromAddress = function(e3) {
          return U(e3);
        }, t2.groupOfPrivateKey = function(e3, t3) {
          return I(O(P(e3, t3), t3));
        }, t2.publicKeyFromPrivateKey = P, t2.addressFromPublicKey = O, t2.addressFromScript = R, t2.addressFromContractId = N, t2.addressFromTokenId = function(e3) {
          return N(e3);
        }, t2.contractIdFromTx = function(e3, t3) {
          const r3 = (0, h.hexToBinUnsafe)(e3), n2 = new Uint8Array([...r3, t3]), i2 = d.default.blake2b(n2, void 0, 32);
          return (0, h.binToHex)(i2);
        }, t2.subContractId = function(e3, t3, r3) {
          if (r3 < 0 || r3 >= u.TOTAL_NUMBER_OF_GROUPS) throw new Error(`Invalid group ${r3}`);
          if (!(0, h.isHexString)(e3)) throw new Error(`Invalid parent contract ID: ${e3}, expected hex string`);
          if (!(0, h.isHexString)(t3)) throw new Error(`Invalid path: ${t3}, expected hex string`);
          const n2 = (0, h.concatBytes)([(0, h.hexToBinUnsafe)(e3), (0, h.hexToBinUnsafe)(t3)]), i2 = new Uint8Array([...d.default.blake2b(d.default.blake2b(n2, void 0, 32), void 0, 32).slice(0, -1), r3]);
          return (0, h.binToHex)(i2);
        }, t2.groupOfLockupScript = function(e3) {
          if ("P2PKH" === e3.kind) return L(e3.value);
          if ("P2MPKH" === e3.kind) return L(e3.value.publicKeyHashes[0]);
          if ("P2SH" === e3.kind) return L(e3.value);
          if ("P2PK" === e3.kind || "P2HMPK" === e3.kind) return e3.value.group % u.TOTAL_NUMBER_OF_GROUPS;
          {
            const t3 = e3.value;
            return t3["" + (t3.length - 1)];
          }
        }, t2.groupFromBytes = L, t2.groupFromHint = j, t2.hasExplicitGroupIndex = D, t2.addressWithoutExplicitGroupIndex = function(e3) {
          return D(e3) ? e3.slice(0, e3.length - 2) : e3;
        }, t2.addressFromLockupScript = function(e3) {
          if ("P2PK" === e3.kind || "P2HMPK" === e3.kind) {
            const t3 = l.lockupScriptCodec.encode(e3).slice(-1);
            return `${f.default.encode(l.lockupScriptCodec.encode(e3).slice(0, -1))}:${t3}`;
          }
          return f.default.encode(l.lockupScriptCodec.encode(e3));
        };
      }, 2581: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), i(r2(5569), t2);
      }, 127: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.Api = t2.HttpClient = t2.ContentType = void 0, r2(9114);
        const n = r2(3760);
        var i;
        !(function(e3) {
          e3.Json = "application/json", e3.FormData = "multipart/form-data", e3.UrlEncoded = "application/x-www-form-urlencoded", e3.Text = "text/plain";
        })(i = t2.ContentType || (t2.ContentType = {}));
        class o {
          constructor(e3 = {}) {
            this.baseUrl = "../", this.securityData = null, this.abortControllers = /* @__PURE__ */ new Map(), this.customFetch = (...e4) => fetch(...e4), this.baseApiParams = { credentials: "same-origin", headers: {}, redirect: "follow", referrerPolicy: "no-referrer" }, this.setSecurityData = (e4) => {
              this.securityData = e4;
            }, this.contentFormatters = { [i.Json]: (e4) => null === e4 || "object" != typeof e4 && "string" != typeof e4 ? e4 : JSON.stringify(e4), [i.Text]: (e4) => null !== e4 && "string" != typeof e4 ? JSON.stringify(e4) : e4, [i.FormData]: (e4) => Object.keys(e4 || {}).reduce(((t3, r3) => {
              const n2 = e4[r3];
              return t3.append(r3, n2 instanceof Blob ? n2 : "object" == typeof n2 && null !== n2 ? JSON.stringify(n2) : `${n2}`), t3;
            }), new FormData()), [i.UrlEncoded]: (e4) => this.toQueryString(e4) }, this.createAbortSignal = (e4) => {
              if (this.abortControllers.has(e4)) {
                const t4 = this.abortControllers.get(e4);
                return t4 ? t4.signal : void 0;
              }
              const t3 = new AbortController();
              return this.abortControllers.set(e4, t3), t3.signal;
            }, this.abortRequest = (e4) => {
              const t3 = this.abortControllers.get(e4);
              t3 && (t3.abort(), this.abortControllers.delete(e4));
            }, this.request = async ({ body: e4, secure: t3, path: r3, type: n2, query: o2, format: s, baseUrl: a, cancelToken: c, ...u }) => {
              const d = ("boolean" == typeof t3 ? t3 : this.baseApiParams.secure) && this.securityWorker && await this.securityWorker(this.securityData) || {}, f = this.mergeRequestParams(u, d), h = o2 && this.toQueryString(o2), l = this.contentFormatters[n2 || i.Json], p = s || f.format;
              return this.customFetch(`${a || this.baseUrl || ""}${r3}${h ? `?${h}` : ""}`, { ...f, headers: { ...f.headers || {}, ...n2 && n2 !== i.FormData ? { "Content-Type": n2 } : {} }, signal: c ? this.createAbortSignal(c) : f.signal, body: null == e4 ? null : l(e4) }).then((async (e5) => {
                const t4 = e5;
                t4.data = null, t4.error = null;
                const r4 = p ? await e5[p]().then(((e6) => (t4.ok ? t4.data = e6 : t4.error = e6, t4))).catch(((e6) => (t4.error = e6, t4))) : t4;
                return c && this.abortControllers.delete(c), r4;
              }));
            }, Object.assign(this, e3);
          }
          encodeQueryParam(e3, t3) {
            return `${encodeURIComponent(e3)}=${encodeURIComponent("number" == typeof t3 ? t3 : `${t3}`)}`;
          }
          addQueryParam(e3, t3) {
            return this.encodeQueryParam(t3, e3[t3]);
          }
          addArrayQueryParam(e3, t3) {
            return e3[t3].map(((e4) => this.encodeQueryParam(t3, e4))).join("&");
          }
          toQueryString(e3) {
            const t3 = e3 || {};
            return Object.keys(t3).filter(((e4) => void 0 !== t3[e4])).map(((e4) => Array.isArray(t3[e4]) ? this.addArrayQueryParam(t3, e4) : this.addQueryParam(t3, e4))).join("&");
          }
          addQueryParams(e3) {
            const t3 = this.toQueryString(e3);
            return t3 ? `?${t3}` : "";
          }
          mergeRequestParams(e3, t3) {
            return { ...this.baseApiParams, ...e3, ...t3 || {}, headers: { ...this.baseApiParams.headers || {}, ...e3.headers || {}, ...t3 && t3.headers || {} } };
          }
        }
        t2.HttpClient = o, t2.Api = class extends o {
          constructor() {
            super(...arguments), this.wallets = { getWallets: (e3 = {}) => this.request({ path: "/wallets", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), putWallets: (e3, t3 = {}) => this.request({ path: "/wallets", method: "PUT", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postWallets: (e3, t3 = {}) => this.request({ path: "/wallets", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), getWalletsWalletName: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), deleteWalletsWalletName: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}`, method: "DELETE", query: t3, ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameLock: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}/lock`, method: "POST", ...t3 }).then(n.convertHttpResponse), postWalletsWalletNameUnlock: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/unlock`, method: "POST", body: t3, type: i.Json, ...r3 }).then(n.convertHttpResponse), getWalletsWalletNameBalances: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}/balances`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), postWalletsWalletNameRevealMnemonic: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/reveal-mnemonic`, method: "POST", body: t3, type: i.Json, format: "json", ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameTransfer: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/transfer`, method: "POST", body: t3, type: i.Json, format: "json", ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameSweepActiveAddress: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/sweep-active-address`, method: "POST", body: t3, type: i.Json, format: "json", ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameSweepAllAddresses: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/sweep-all-addresses`, method: "POST", body: t3, type: i.Json, format: "json", ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameSign: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/sign`, method: "POST", body: t3, type: i.Json, format: "json", ...r3 }).then(n.convertHttpResponse), getWalletsWalletNameAddresses: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}/addresses`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getWalletsWalletNameAddressesAddress: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/addresses/${t3}`, method: "GET", format: "json", ...r3 }).then(n.convertHttpResponse), getWalletsWalletNameMinerAddresses: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}/miner-addresses`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), postWalletsWalletNameDeriveNextAddress: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/derive-next-address`, method: "POST", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), postWalletsWalletNameDeriveNextMinerAddresses: (e3, t3 = {}) => this.request({ path: `/wallets/${e3}/derive-next-miner-addresses`, method: "POST", format: "json", ...t3 }).then(n.convertHttpResponse), postWalletsWalletNameChangeActiveAddress: (e3, t3, r3 = {}) => this.request({ path: `/wallets/${e3}/change-active-address`, method: "POST", body: t3, type: i.Json, ...r3 }).then(n.convertHttpResponse) }, this.infos = { getInfosNode: (e3 = {}) => this.request({ path: "/infos/node", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosVersion: (e3 = {}) => this.request({ path: "/infos/version", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosChainParams: (e3 = {}) => this.request({ path: "/infos/chain-params", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosSelfClique: (e3 = {}) => this.request({ path: "/infos/self-clique", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosInterCliquePeerInfo: (e3 = {}) => this.request({ path: "/infos/inter-clique-peer-info", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosDiscoveredNeighbors: (e3 = {}) => this.request({ path: "/infos/discovered-neighbors", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), getInfosMisbehaviors: (e3 = {}) => this.request({ path: "/infos/misbehaviors", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), postInfosMisbehaviors: (e3, t3 = {}) => this.request({ path: "/infos/misbehaviors", method: "POST", body: e3, type: i.Json, ...t3 }).then(n.convertHttpResponse), getInfosUnreachable: (e3 = {}) => this.request({ path: "/infos/unreachable", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), postInfosDiscovery: (e3, t3 = {}) => this.request({ path: "/infos/discovery", method: "POST", body: e3, type: i.Json, ...t3 }).then(n.convertHttpResponse), getInfosHistoryHashrate: (e3, t3 = {}) => this.request({ path: "/infos/history-hashrate", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getInfosCurrentHashrate: (e3, t3 = {}) => this.request({ path: "/infos/current-hashrate", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getInfosCurrentDifficulty: (e3 = {}) => this.request({ path: "/infos/current-difficulty", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse) }, this.blockflow = { getBlockflowBlocks: (e3, t3 = {}) => this.request({ path: "/blockflow/blocks", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowBlocksWithEvents: (e3, t3 = {}) => this.request({ path: "/blockflow/blocks-with-events", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowRichBlocks: (e3, t3 = {}) => this.request({ path: "/blockflow/rich-blocks", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowBlocksBlockHash: (e3, t3 = {}) => this.request({ path: `/blockflow/blocks/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowMainChainBlockByGhostUncleGhostUncleHash: (e3, t3 = {}) => this.request({ path: `/blockflow/main-chain-block-by-ghost-uncle/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowBlocksWithEventsBlockHash: (e3, t3 = {}) => this.request({ path: `/blockflow/blocks-with-events/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowRichBlocksBlockHash: (e3, t3 = {}) => this.request({ path: `/blockflow/rich-blocks/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowIsBlockInMainChain: (e3, t3 = {}) => this.request({ path: "/blockflow/is-block-in-main-chain", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowHashes: (e3, t3 = {}) => this.request({ path: "/blockflow/hashes", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowChainInfo: (e3, t3 = {}) => this.request({ path: "/blockflow/chain-info", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowHeadersBlockHash: (e3, t3 = {}) => this.request({ path: `/blockflow/headers/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getBlockflowRawBlocksBlockHash: (e3, t3 = {}) => this.request({ path: `/blockflow/raw-blocks/${e3}`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse) }, this.addresses = { getAddressesAddressBalance: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/balance`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getAddressesAddressUtxos: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/utxos`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getAddressesAddressGroup: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/group`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse) }, this.transactions = { postTransactionsBuild: (e3, t3 = {}) => this.request({ path: "/transactions/build", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsBuildTransferFromOneToManyGroups: (e3, t3 = {}) => this.request({ path: "/transactions/build-transfer-from-one-to-many-groups", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsBuildMultiAddresses: (e3, t3 = {}) => this.request({ path: "/transactions/build-multi-addresses", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsSweepAddressBuild: (e3, t3 = {}) => this.request({ path: "/transactions/sweep-address/build", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsSubmit: (e3, t3 = {}) => this.request({ path: "/transactions/submit", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsDecodeUnsignedTx: (e3, t3 = {}) => this.request({ path: "/transactions/decode-unsigned-tx", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), getTransactionsDetailsTxid: (e3, t3, r3 = {}) => this.request({ path: `/transactions/details/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getTransactionsRichDetailsTxid: (e3, t3, r3 = {}) => this.request({ path: `/transactions/rich-details/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getTransactionsRawTxid: (e3, t3, r3 = {}) => this.request({ path: `/transactions/raw/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getTransactionsStatus: (e3, t3 = {}) => this.request({ path: "/transactions/status", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getTransactionsTxIdFromOutputref: (e3, t3 = {}) => this.request({ path: "/transactions/tx-id-from-outputref", method: "GET", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), postTransactionsBuildChained: (e3, t3 = {}) => this.request({ path: "/transactions/build-chained", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse) }, this.mempool = { getMempoolTransactions: (e3 = {}) => this.request({ path: "/mempool/transactions", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), deleteMempoolTransactions: (e3 = {}) => this.request({ path: "/mempool/transactions", method: "DELETE", ...e3 }).then(n.convertHttpResponse), putMempoolTransactionsRebroadcast: (e3, t3 = {}) => this.request({ path: "/mempool/transactions/rebroadcast", method: "PUT", query: e3, ...t3 }).then(n.convertHttpResponse), putMempoolTransactionsValidate: (e3 = {}) => this.request({ path: "/mempool/transactions/validate", method: "PUT", ...e3 }).then(n.convertHttpResponse) }, this.contracts = { postContractsCompileScript: (e3, t3 = {}) => this.request({ path: "/contracts/compile-script", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsUnsignedTxExecuteScript: (e3, t3 = {}) => this.request({ path: "/contracts/unsigned-tx/execute-script", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsCompileContract: (e3, t3 = {}) => this.request({ path: "/contracts/compile-contract", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsCompileProject: (e3, t3 = {}) => this.request({ path: "/contracts/compile-project", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsUnsignedTxDeployContract: (e3, t3 = {}) => this.request({ path: "/contracts/unsigned-tx/deploy-contract", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), getContractsAddressState: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/state`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getContractsCodehashCode: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/code`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), postContractsTestContract: (e3, t3 = {}) => this.request({ path: "/contracts/test-contract", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsCallContract: (e3, t3 = {}) => this.request({ path: "/contracts/call-contract", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postContractsMulticallContract: (e3, t3 = {}) => this.request({ path: "/contracts/multicall-contract", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), getContractsAddressParent: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/parent`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getContractsAddressSubContracts: (e3, t3, r3 = {}) => this.request({ path: `/contracts/${e3}/sub-contracts`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getContractsAddressSubContractsCurrentCount: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/sub-contracts/current-count`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), postContractsCallTxScript: (e3, t3 = {}) => this.request({ path: "/contracts/call-tx-script", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse) }, this.multisig = { postMultisigAddress: (e3, t3 = {}) => this.request({ path: "/multisig/address", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postMultisigBuild: (e3, t3 = {}) => this.request({ path: "/multisig/build", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postMultisigSweep: (e3, t3 = {}) => this.request({ path: "/multisig/sweep", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postMultisigSubmit: (e3, t3 = {}) => this.request({ path: "/multisig/submit", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse) }, this.miners = { postMinersCpuMining: (e3, t3 = {}) => this.request({ path: "/miners/cpu-mining", method: "POST", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), postMinersCpuMiningMineOneBlock: (e3, t3 = {}) => this.request({ path: "/miners/cpu-mining/mine-one-block", method: "POST", query: e3, format: "json", ...t3 }).then(n.convertHttpResponse), getMinersAddresses: (e3 = {}) => this.request({ path: "/miners/addresses", method: "GET", format: "json", ...e3 }).then(n.convertHttpResponse), putMinersAddresses: (e3, t3 = {}) => this.request({ path: "/miners/addresses", method: "PUT", body: e3, type: i.Json, ...t3 }).then(n.convertHttpResponse) }, this.events = { getEventsContractContractaddress: (e3, t3, r3 = {}) => this.request({ path: `/events/contract/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getEventsContractContractaddressCurrentCount: (e3, t3 = {}) => this.request({ path: `/events/contract/${e3}/current-count`, method: "GET", format: "json", ...t3 }).then(n.convertHttpResponse), getEventsTxIdTxid: (e3, t3, r3 = {}) => this.request({ path: `/events/tx-id/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse), getEventsBlockHashBlockhash: (e3, t3, r3 = {}) => this.request({ path: `/events/block-hash/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(n.convertHttpResponse) }, this.utils = { postUtilsVerifySignature: (e3, t3 = {}) => this.request({ path: "/utils/verify-signature", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), postUtilsTargetToHashrate: (e3, t3 = {}) => this.request({ path: "/utils/target-to-hashrate", method: "POST", body: e3, type: i.Json, format: "json", ...t3 }).then(n.convertHttpResponse), putUtilsCheckHashIndexing: (e3 = {}) => this.request({ path: "/utils/check-hash-indexing", method: "PUT", ...e3 }).then(n.convertHttpResponse) };
          }
        };
      }, 3877: (e2, t2, r2) => {
        "use strict";
        var n, i, o, s, a, c, u, d, f;
        Object.defineProperty(t2, "__esModule", { value: true }), t2.Api = t2.HttpClient = t2.ContentType = t2.Currencies = t2.MaxSizeAddresses = t2.MaxSizeAddressesForTokens = t2.MaxSizeTokens = t2.PaginationPageDefault = t2.PaginationLimitMax = t2.PaginationLimitDefault = t2.TokenStdInterfaceId = t2.IntervalType = void 0, (f = t2.IntervalType || (t2.IntervalType = {})).Daily = "daily", f.Hourly = "hourly", f.Weekly = "weekly", (d = t2.TokenStdInterfaceId || (t2.TokenStdInterfaceId = {})).Fungible = "fungible", d.NonFungible = "non-fungible", d.NonStandard = "non-standard", (u = t2.PaginationLimitDefault || (t2.PaginationLimitDefault = {}))[u.Value20 = 20] = "Value20", u[u.Value10 = 10] = "Value10", (c = t2.PaginationLimitMax || (t2.PaginationLimitMax = {}))[c.Value100 = 100] = "Value100", c[c.Value20 = 20] = "Value20", (a = t2.PaginationPageDefault || (t2.PaginationPageDefault = {}))[a.Value1 = 1] = "Value1", (s = t2.MaxSizeTokens || (t2.MaxSizeTokens = {}))[s.Value80 = 80] = "Value80", (o = t2.MaxSizeAddressesForTokens || (t2.MaxSizeAddressesForTokens = {}))[o.Value80 = 80] = "Value80", (i = t2.MaxSizeAddresses || (t2.MaxSizeAddresses = {}))[i.Value80 = 80] = "Value80", (n = t2.Currencies || (t2.Currencies = {})).Btc = "btc", n.Eth = "eth", n.Usd = "usd", n.Eur = "eur", n.Chf = "chf", n.Gbp = "gbp", n.Idr = "idr", n.Vnd = "vnd", n.Rub = "rub", n.Try = "try", n.Cad = "cad", n.Aud = "aud", n.Hkd = "hkd", n.Thb = "thb", n.Cny = "cny", r2(9114);
        const h = r2(3760);
        var l;
        !(function(e3) {
          e3.Json = "application/json", e3.FormData = "multipart/form-data", e3.UrlEncoded = "application/x-www-form-urlencoded", e3.Text = "text/plain";
        })(l = t2.ContentType || (t2.ContentType = {}));
        class p {
          constructor(e3 = {}) {
            this.baseUrl = "", this.securityData = null, this.abortControllers = /* @__PURE__ */ new Map(), this.customFetch = (...e4) => fetch(...e4), this.baseApiParams = { credentials: "same-origin", headers: {}, redirect: "follow", referrerPolicy: "no-referrer" }, this.setSecurityData = (e4) => {
              this.securityData = e4;
            }, this.contentFormatters = { [l.Json]: (e4) => null === e4 || "object" != typeof e4 && "string" != typeof e4 ? e4 : JSON.stringify(e4), [l.Text]: (e4) => null !== e4 && "string" != typeof e4 ? JSON.stringify(e4) : e4, [l.FormData]: (e4) => Object.keys(e4 || {}).reduce(((t3, r3) => {
              const n2 = e4[r3];
              return t3.append(r3, n2 instanceof Blob ? n2 : "object" == typeof n2 && null !== n2 ? JSON.stringify(n2) : `${n2}`), t3;
            }), new FormData()), [l.UrlEncoded]: (e4) => this.toQueryString(e4) }, this.createAbortSignal = (e4) => {
              if (this.abortControllers.has(e4)) {
                const t4 = this.abortControllers.get(e4);
                return t4 ? t4.signal : void 0;
              }
              const t3 = new AbortController();
              return this.abortControllers.set(e4, t3), t3.signal;
            }, this.abortRequest = (e4) => {
              const t3 = this.abortControllers.get(e4);
              t3 && (t3.abort(), this.abortControllers.delete(e4));
            }, this.request = async ({ body: e4, secure: t3, path: r3, type: n2, query: i2, format: o2, baseUrl: s2, cancelToken: a2, ...c2 }) => {
              const u2 = ("boolean" == typeof t3 ? t3 : this.baseApiParams.secure) && this.securityWorker && await this.securityWorker(this.securityData) || {}, d2 = this.mergeRequestParams(c2, u2), f2 = i2 && this.toQueryString(i2), h2 = this.contentFormatters[n2 || l.Json], p2 = o2 || d2.format;
              return this.customFetch(`${s2 || this.baseUrl || ""}${r3}${f2 ? `?${f2}` : ""}`, { ...d2, headers: { ...d2.headers || {}, ...n2 && n2 !== l.FormData ? { "Content-Type": n2 } : {} }, signal: a2 ? this.createAbortSignal(a2) : d2.signal, body: null == e4 ? null : h2(e4) }).then((async (e5) => {
                const t4 = e5;
                t4.data = null, t4.error = null;
                const r4 = p2 ? await e5[p2]().then(((e6) => (t4.ok ? t4.data = e6 : t4.error = e6, t4))).catch(((e6) => (t4.error = e6, t4))) : t4;
                return a2 && this.abortControllers.delete(a2), r4;
              }));
            }, Object.assign(this, e3);
          }
          encodeQueryParam(e3, t3) {
            return `${encodeURIComponent(e3)}=${encodeURIComponent("number" == typeof t3 ? t3 : `${t3}`)}`;
          }
          addQueryParam(e3, t3) {
            return this.encodeQueryParam(t3, e3[t3]);
          }
          addArrayQueryParam(e3, t3) {
            return e3[t3].map(((e4) => this.encodeQueryParam(t3, e4))).join("&");
          }
          toQueryString(e3) {
            const t3 = e3 || {};
            return Object.keys(t3).filter(((e4) => void 0 !== t3[e4])).map(((e4) => Array.isArray(t3[e4]) ? this.addArrayQueryParam(t3, e4) : this.addQueryParam(t3, e4))).join("&");
          }
          addQueryParams(e3) {
            const t3 = this.toQueryString(e3);
            return t3 ? `?${t3}` : "";
          }
          mergeRequestParams(e3, t3) {
            return { ...this.baseApiParams, ...e3, ...t3 || {}, headers: { ...this.baseApiParams.headers || {}, ...e3.headers || {}, ...t3 && t3.headers || {} } };
          }
        }
        t2.HttpClient = p, t2.Api = class extends p {
          constructor() {
            super(...arguments), this.blocks = { getBlocks: (e3, t3 = {}) => this.request({ path: "/blocks", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), getBlocksBlockHash: (e3, t3 = {}) => this.request({ path: `/blocks/${e3}`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getBlocksBlockHashTransactions: (e3, t3, r3 = {}) => this.request({ path: `/blocks/${e3}/transactions`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse) }, this.transactions = { getTransactionsTransactionHash: (e3, t3 = {}) => this.request({ path: `/transactions/${e3}`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse) }, this.addresses = { getAddressesAddress: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressTransactions: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/transactions`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), postAddressesTransactions: (e3, t3, r3 = {}) => this.request({ path: "/addresses/transactions", method: "POST", query: e3, body: t3, type: l.Json, format: "json", ...r3 }).then(h.convertHttpResponse), getAddressesAddressTimerangedTransactions: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/timeranged-transactions`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), getAddressesAddressTotalTransactions: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/total-transactions`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressLatestTransaction: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/latest-transaction`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressMempoolTransactions: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/mempool/transactions`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressBalance: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/balance`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressTokens: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/tokens`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), getAddressesAddressTokensTokenIdTransactions: (e3, t3, r3, n2 = {}) => this.request({ path: `/addresses/${e3}/tokens/${t3}/transactions`, method: "GET", query: r3, format: "json", ...n2 }).then(h.convertHttpResponse), getAddressesAddressTokensTokenIdBalance: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/tokens/${t3}/balance`, method: "GET", format: "json", ...r3 }).then(h.convertHttpResponse), getAddressesAddressPublicKey: (e3, t3 = {}) => this.request({ path: `/addresses/${e3}/public-key`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressTokensBalance: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/tokens-balance`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), postAddressesUsed: (e3, t3 = {}) => this.request({ path: "/addresses/used", method: "POST", body: e3, type: l.Json, format: "json", ...t3 }).then(h.convertHttpResponse), getAddressesAddressExportTransactionsCsv: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/export-transactions/csv`, method: "GET", query: t3, format: "text", ...r3 }).then(h.convertHttpResponse), getAddressesAddressAmountHistory: (e3, t3, r3 = {}) => this.request({ path: `/addresses/${e3}/amount-history`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse) }, this.infos = { getInfos: (e3 = {}) => this.request({ path: "/infos", method: "GET", format: "json", ...e3 }).then(h.convertHttpResponse), getInfosHeights: (e3 = {}) => this.request({ path: "/infos/heights", method: "GET", format: "json", ...e3 }).then(h.convertHttpResponse), getInfosSupply: (e3, t3 = {}) => this.request({ path: "/infos/supply", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), getInfosSupplyTotalAlph: (e3 = {}) => this.request({ path: "/infos/supply/total-alph", method: "GET", format: "text", ...e3 }).then(h.convertHttpResponse), getInfosSupplyCirculatingAlph: (e3 = {}) => this.request({ path: "/infos/supply/circulating-alph", method: "GET", format: "text", ...e3 }).then(h.convertHttpResponse), getInfosSupplyReservedAlph: (e3 = {}) => this.request({ path: "/infos/supply/reserved-alph", method: "GET", format: "text", ...e3 }).then(h.convertHttpResponse), getInfosSupplyLockedAlph: (e3 = {}) => this.request({ path: "/infos/supply/locked-alph", method: "GET", format: "text", ...e3 }).then(h.convertHttpResponse), getInfosTotalTransactions: (e3 = {}) => this.request({ path: "/infos/total-transactions", method: "GET", format: "text", ...e3 }).then(h.convertHttpResponse), getInfosAverageBlockTimes: (e3 = {}) => this.request({ path: "/infos/average-block-times", method: "GET", format: "json", ...e3 }).then(h.convertHttpResponse) }, this.mempool = { getMempoolTransactions: (e3, t3 = {}) => this.request({ path: "/mempool/transactions", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse) }, this.tokens = { getTokens: (e3, t3 = {}) => this.request({ path: "/tokens", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), postTokens: (e3, t3 = {}) => this.request({ path: "/tokens", method: "POST", body: e3, type: l.Json, format: "json", ...t3 }).then(h.convertHttpResponse), getTokensTokenIdTransactions: (e3, t3, r3 = {}) => this.request({ path: `/tokens/${e3}/transactions`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), getTokensTokenIdAddresses: (e3, t3, r3 = {}) => this.request({ path: `/tokens/${e3}/addresses`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), postTokensFungibleMetadata: (e3, t3 = {}) => this.request({ path: "/tokens/fungible-metadata", method: "POST", body: e3, type: l.Json, format: "json", ...t3 }).then(h.convertHttpResponse), postTokensNftMetadata: (e3, t3 = {}) => this.request({ path: "/tokens/nft-metadata", method: "POST", body: e3, type: l.Json, format: "json", ...t3 }).then(h.convertHttpResponse), postTokensNftCollectionMetadata: (e3, t3 = {}) => this.request({ path: "/tokens/nft-collection-metadata", method: "POST", body: e3, type: l.Json, format: "json", ...t3 }).then(h.convertHttpResponse), getTokensHoldersAlph: (e3, t3 = {}) => this.request({ path: "/tokens/holders/alph", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), getTokensHoldersTokenTokenId: (e3, t3, r3 = {}) => this.request({ path: `/tokens/holders/token/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse) }, this.charts = { getChartsHashrates: (e3, t3 = {}) => this.request({ path: "/charts/hashrates", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), getChartsTransactionsCount: (e3, t3 = {}) => this.request({ path: "/charts/transactions-count", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse), getChartsTransactionsCountPerChain: (e3, t3 = {}) => this.request({ path: "/charts/transactions-count-per-chain", method: "GET", query: e3, format: "json", ...t3 }).then(h.convertHttpResponse) }, this.contractEvents = { getContractEventsTransactionIdTransactionId: (e3, t3 = {}) => this.request({ path: `/contract-events/transaction-id/${e3}`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getContractEventsContractAddressContractAddress: (e3, t3, r3 = {}) => this.request({ path: `/contract-events/contract-address/${e3}`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse), getContractEventsContractAddressContractAddressInputAddressInputAddress: (e3, t3, r3, n2 = {}) => this.request({ path: `/contract-events/contract-address/${e3}/input-address/${t3}`, method: "GET", query: r3, format: "json", ...n2 }).then(h.convertHttpResponse) }, this.contracts = { getContractsContractAddressCurrentLiveness: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/current-liveness`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getContractsContractAddressParent: (e3, t3 = {}) => this.request({ path: `/contracts/${e3}/parent`, method: "GET", format: "json", ...t3 }).then(h.convertHttpResponse), getContractsContractAddressSubContracts: (e3, t3, r3 = {}) => this.request({ path: `/contracts/${e3}/sub-contracts`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse) }, this.market = { postMarketPrices: (e3, t3, r3 = {}) => this.request({ path: "/market/prices", method: "POST", query: e3, body: t3, type: l.Json, format: "json", ...r3 }).then(h.convertHttpResponse), getMarketPricesSymbolCharts: (e3, t3, r3 = {}) => this.request({ path: `/market/prices/${e3}/charts`, method: "GET", query: t3, format: "json", ...r3 }).then(h.convertHttpResponse) }, this.utils = { putUtilsSanityCheck: (e3 = {}) => this.request({ path: "/utils/sanity-check", method: "PUT", ...e3 }).then(h.convertHttpResponse), putUtilsUpdateGlobalLoglevel: (e3, t3 = {}) => this.request({ path: "/utils/update-global-loglevel", method: "PUT", body: e3, ...t3 }).then(h.convertHttpResponse), putUtilsUpdateLogConfig: (e3, t3 = {}) => this.request({ path: "/utils/update-log-config", method: "PUT", body: e3, type: l.Json, ...t3 }).then(h.convertHttpResponse) };
          }
        };
      }, 1442: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.ExplorerProvider = void 0;
        const n = r2(4156), i = r2(3877);
        class o {
          constructor(e3, t3, r3) {
            let s;
            this.request = (e4) => (0, n.request)(this, e4), "string" == typeof e3 ? s = (function(e4, t4, r4) {
              const n2 = new i.Api({ baseUrl: e4, baseApiParams: { secure: true }, securityWorker: (e5) => null !== e5 ? { headers: { "X-API-KEY": `${e5}` } } : {}, customFetch: r4 ?? ((...e5) => fetch(...e5)) });
              return n2.setSecurityData(t4 ?? null), n2;
            })(e3, t3, r3) : "function" == typeof e3 ? (s = new o("https://1.2.3.4:0"), (0, n.forwardRequests)(s, e3)) : s = e3, this.blocks = { ...s.blocks }, this.transactions = { ...s.transactions }, this.addresses = { ...s.addresses }, this.infos = { ...s.infos }, this.mempool = { ...s.mempool }, this.tokens = { ...s.tokens }, this.charts = { ...s.charts }, this.utils = { ...s.utils }, this.contracts = { ...s.contracts }, this.market = { ...s.market }, this.contractEvents = { ...s.contractEvents };
          }
          static Proxy(e3) {
            return new o(e3);
          }
          static Remote(e3) {
            return new o(e3);
          }
        }
        t2.ExplorerProvider = o;
      }, 3749: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        }, s = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.explorer = t2.node = void 0, o(r2(2707), t2), o(r2(1442), t2), t2.node = s(r2(127)), t2.explorer = s(r2(3877)), o(r2(4156), t2), o(r2(3760), t2);
      }, 2707: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.tryGetCallResult = t2.NodeProvider = void 0;
        const n = r2(4156), i = r2(127), o = r2(664), s = r2(2581);
        class a {
          constructor(e3, t3, r3) {
            let u;
            this.request = (e4) => (0, n.request)(this, e4), this.fetchFungibleTokenMetaData = async (e4) => {
              const t4 = (0, s.addressFromTokenId)(e4), r4 = (0, s.groupOfAddress)(t4), n2 = Array.from([0, 1, 2, 3], ((e5) => ({ methodIndex: e5, group: r4, address: t4 }))), i2 = (await this.contracts.postContractsMulticallContract({ calls: n2 })).results.map(((e5) => c(e5)));
              return { symbol: i2[0].returns[0].value, name: i2[1].returns[0].value, decimals: Number(i2[2].returns[0].value), totalSupply: BigInt(i2[3].returns[0].value) };
            }, this.fetchNFTMetaData = async (e4) => {
              const t4 = (0, s.addressFromTokenId)(e4), r4 = (0, s.groupOfAddress)(t4), n2 = Array.from([0, 1], ((e5) => ({ methodIndex: e5, group: r4, address: t4 }))), i2 = await this.contracts.postContractsMulticallContract({ calls: n2 }), a2 = (0, o.hexToString)(c(i2.results[0]).returns[0].value);
              if ("CallContractSucceeded" === i2.results[1].type) {
                const e5 = i2.results[1];
                if (void 0 === e5.returns[0]) throw new Error("Deprecated NFT contract");
                const t5 = e5.returns[0].value;
                if (void 0 === t5 || !(0, o.isHexString)(t5) || 64 !== t5.length) throw new Error("Deprecated NFT contract");
                const r5 = e5.returns[1];
                if (void 0 === r5) throw new Error("Deprecated NFT contract");
                const n3 = (0, o.toNonNegativeBigInt)(r5.value);
                if (void 0 === n3) throw new Error("Deprecated NFT contract");
                if (void 0 !== e5.returns[2]) throw new Error("Deprecated NFT contract");
                return { tokenUri: a2, collectionId: t5, nftIndex: n3 };
              }
              {
                const e5 = i2.results[1];
                throw e5.error.startsWith("VM execution error: Invalid method index") ? new Error("Deprecated NFT contract") : new Error(`Failed to call contract, error: ${e5.error}`);
              }
            }, this.fetchNFTCollectionMetaData = async (e4) => {
              const t4 = (0, s.addressFromContractId)(e4), r4 = (0, s.groupOfAddress)(t4), n2 = Array.from([0, 1], ((e5) => ({ methodIndex: e5, group: r4, address: t4 }))), i2 = (await this.contracts.postContractsMulticallContract({ calls: n2 })).results.map(((e5) => c(e5)));
              return { collectionUri: (0, o.hexToString)(i2[0].returns[0].value), totalSupply: BigInt(i2[1].returns[0].value) };
            }, this.fetchNFTRoyaltyAmount = async (e4, t4, r4) => {
              const n2 = (0, s.addressFromContractId)(e4), i2 = (0, s.groupOfAddress)(n2), o2 = c(await this.contracts.postContractsCallContract({ address: n2, group: i2, methodIndex: 4, args: [{ type: "ByteVec", value: t4 }, { type: "U256", value: r4.toString() }] }));
              return BigInt(o2.returns[0].value);
            }, this.guessStdInterfaceId = async (e4) => {
              const t4 = (0, s.addressFromTokenId)(e4), r4 = await this.contracts.getContractsAddressState(t4), n2 = r4.immFields.slice(-1).pop()?.value;
              return "string" == typeof n2 && n2.startsWith("414c5048") ? n2.slice(8) : void 0;
            }, this.guessFollowsNFTCollectionStd = async (e4) => {
              const t4 = await this.guessStdInterfaceId(e4);
              return !!t4 && t4.startsWith(n.StdInterfaceIds.NFTCollection);
            }, this.guessFollowsNFTCollectionWithRoyaltyStd = async (e4) => await this.guessStdInterfaceId(e4) === n.StdInterfaceIds.NFTCollectionWithRoyalty, this.guessStdTokenType = async (e4) => {
              const t4 = await this.guessStdInterfaceId(e4);
              switch (true) {
                case t4?.startsWith(n.StdInterfaceIds.FungibleToken):
                  return "fungible";
                case t4?.startsWith(n.StdInterfaceIds.NFT):
                  return "non-fungible";
                default:
                  return;
              }
            }, "string" == typeof e3 ? u = (function(e4, t4, r4) {
              const n2 = new i.Api({ baseUrl: e4, baseApiParams: { secure: true }, securityWorker: (e5) => null !== e5 ? { headers: { "X-API-KEY": `${e5}` } } : {}, customFetch: r4 ?? ((...e5) => fetch(...e5)) });
              return n2.setSecurityData(t4 ?? null), n2;
            })(e3, t3, r3) : "function" == typeof e3 ? (u = new a("https://1.2.3.4:0"), (0, n.forwardRequests)(u, e3)) : u = e3, this.wallets = { ...u.wallets }, this.infos = { ...u.infos }, this.blockflow = { ...u.blockflow }, this.addresses = { ...u.addresses }, this.transactions = { ...u.transactions }, this.mempool = { ...u.mempool }, this.contracts = { ...u.contracts }, this.multisig = { ...u.multisig }, this.utils = { ...u.utils }, this.miners = { ...u.miners }, this.events = { ...u.events }, (0, n.requestWithLog)(this);
          }
          static Proxy(e3) {
            return new a(e3);
          }
          static Remote(e3) {
            return new a(e3);
          }
        }
        function c(e3) {
          if ("CallContractFailed" === e3.type) throw new Error(`Failed to call contract, error: ${e3.error}`);
          return e3;
        }
        t2.NodeProvider = a, t2.tryGetCallResult = c;
      }, 4156: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.StdInterfaceIds = t2.request = t2.requestWithLog = t2.forwardRequests = t2.getDefaultPrimitiveValue = t2.decodeArrayType = t2.decodeTupleType = t2.fromApiPrimitiveVal = t2.toApiVal = t2.toApiArray = t2.toApiAddress = t2.toApiByteVec = t2.fromApiNumber256 = t2.toApiNumber256Optional = t2.toApiNumber256 = t2.toApiBoolean = t2.fromApiTokens = t2.fromApiToken = t2.toApiTokens = t2.toApiToken = t2.PrimitiveTypes = void 0;
        const n = r2(2581), i = r2(7695), o = r2(2505), s = r2(4652), a = r2(664);
        function c(e3) {
          return { id: e3.id, amount: f(e3.amount) };
        }
        function u(e3) {
          return { id: e3.id, amount: h(e3.amount) };
        }
        function d(e3) {
          if ("boolean" == typeof e3) return e3;
          throw new Error(`Invalid boolean value: ${e3}`);
        }
        function f(e3) {
          if ("number" == typeof e3 && Number.isInteger(e3) || "bigint" == typeof e3) return e3.toString();
          if ("string" == typeof e3) try {
            if (BigInt(e3).toString() === e3) return e3;
          } catch (t3) {
            throw new s.TraceableError(`Invalid value: ${e3}, expected a 256 bit number`, t3);
          }
          throw new Error(`Invalid value: ${e3}, expected a 256 bit number`);
        }
        function h(e3) {
          return BigInt(e3);
        }
        function l(e3) {
          if ("string" != typeof e3) throw new Error(`Invalid value: ${e3}, expected a hex-string`);
          if ((0, a.isHexString)(e3)) return e3;
          if ((0, a.isBase58)(e3)) {
            const t3 = (0, a.base58ToBytes)(e3);
            if (33 === t3.length && 3 === t3[0]) return (0, a.binToHex)(t3.slice(1));
          }
          throw new Error(`Invalid hex-string: ${e3}`);
        }
        function p(e3) {
          if ("string" == typeof e3) {
            let t3 = e3;
            if ((0, n.hasExplicitGroupIndex)(t3) && (t3 = t3.slice(0, -2)), (0, a.isBase58)(t3)) return e3;
            throw new Error(`Invalid base58 string: ${e3}`);
          }
          throw new Error(`Invalid value: ${e3}, expected a base58 string`);
        }
        function b(e3, t3) {
          if (!Array.isArray(t3)) throw new Error(`Expected array, got ${t3}`);
          const r3 = e3.lastIndexOf(";");
          if (-1 == r3) throw new Error(`Invalid Val type: ${e3}`);
          const n2 = e3.slice(1, r3), i2 = parseInt(e3.slice(r3 + 1, -1));
          if (t3.length != i2) throw new Error(`Invalid val dimension: ${t3}`);
          return { value: t3.map(((e4) => y(e4, n2))), type: "Array" };
        }
        function y(e3, t3) {
          return "Bool" === t3 ? { value: d(e3), type: t3 } : "U256" === t3 || "I256" === t3 ? { value: f(e3), type: t3 } : "ByteVec" === t3 ? { value: l(e3), type: t3 } : "Address" === t3 ? { value: p(e3), type: t3 } : b(t3, e3);
        }
        async function m(e3, t3) {
          const r3 = (0, o.isDebugModeEnabled)(), { path: n2, method: i2, params: a2 } = e3;
          r3 && console.log(`[REQUEST] ${n2} ${i2} ${JSON.stringify(a2)}`);
          try {
            const o2 = await t3(e3);
            return r3 && console.log(`[RESPONSE] ${n2} ${i2} ${JSON.stringify(o2)}`), o2;
          } catch (e4) {
            throw r3 && console.error(`[ERROR] ${n2} ${i2} `, e4), new s.TraceableError(`Failed to request ${i2}`, e4);
          }
        }
        var g;
        t2.PrimitiveTypes = ["U256", "I256", "Bool", "ByteVec", "Address"], a.assertType, t2.toApiToken = c, t2.toApiTokens = function(e3) {
          return e3?.map(c);
        }, t2.fromApiToken = u, t2.fromApiTokens = function(e3) {
          return e3?.map(u);
        }, t2.toApiBoolean = d, t2.toApiNumber256 = f, t2.toApiNumber256Optional = function(e3) {
          return void 0 === e3 ? void 0 : f(e3);
        }, t2.fromApiNumber256 = h, t2.toApiByteVec = l, t2.toApiAddress = p, t2.toApiArray = b, t2.toApiVal = y, t2.fromApiPrimitiveVal = function(e3, t3, r3 = false) {
          if ("Bool" === t3 && e3.type === t3) return e3.value;
          if ("U256" !== t3 && "I256" !== t3 || e3.type !== t3) {
            if ("ByteVec" !== t3 && "Address" !== t3 || e3.type !== t3 && !r3) throw new Error(`Expected primitive type, got ${t3}`);
            return e3.value;
          }
          return h(e3.value);
        }, t2.decodeTupleType = function(e3) {
          const t3 = e3.slice(1, -1), r3 = [];
          let n2 = "", i2 = 0;
          for (const e4 of t3) "," === e4 && 0 === i2 ? (r3.push(n2), n2 = "") : ("(" === e4 && i2++, ")" === e4 && i2--, n2 += e4);
          return "" !== n2 && r3.push(n2), r3;
        }, t2.decodeArrayType = function(e3) {
          const t3 = e3.lastIndexOf(";");
          if (-1 === t3) throw new Error(`Invalid array type: ${e3}`);
          return [e3.slice(1, t3), parseInt(e3.slice(t3 + 1, -1))];
        }, t2.getDefaultPrimitiveValue = function(e3) {
          if ("U256" === e3 || "I256" === e3) return 0n;
          if ("Bool" === e3) return false;
          if ("ByteVec" === e3) return "";
          if ("Address" === e3) return i.ZERO_ADDRESS;
          throw Error(`Expected primitive type, got ${e3}`);
        }, t2.forwardRequests = function(e3, t3) {
          for (const [r3, n2] of Object.entries(e3)) for (const e4 of Object.keys(n2)) n2[`${e4}`] = async (...n3) => m({ path: r3, method: e4, params: n3 }, t3);
        }, t2.requestWithLog = function(e3) {
          for (const [t3, r3] of Object.entries(e3)) for (const [e4, n2] of Object.entries(r3)) r3[`${e4}`] = async (...r4) => m({ path: t3, method: e4, params: r4 }, (() => n2(...r4)));
        }, t2.request = async function(e3, t3) {
          return (0, e3[`${t3.path}`][`${t3.method}`])(...t3.params);
        }, (g = t2.StdInterfaceIds || (t2.StdInterfaceIds = {})).FungibleToken = "0001", g.NFTCollection = "0002", g.NFT = "0003", g.NFTCollectionWithRoyalty = "000201";
      }, 3760: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.isBalanceEqual = t2.convertHttpResponse = void 0, r2(9114), t2.convertHttpResponse = function(e3) {
          if (e3.error) {
            const t3 = e3.error.detail ?? "Unknown error";
            throw new Error(`[API Error] - ${t3} - Status code: ${e3.status}`);
          }
          return e3.data;
        }, t2.isBalanceEqual = function(e3, t3) {
          const r3 = (e4, t4) => {
            const r4 = e4?.length ?? 0;
            if (r4 !== (t4?.length ?? 0)) return false;
            if (0 === r4) return true;
            const n2 = t4.map(((e5) => ({ ...e5, used: false })));
            return e4.every(((e5) => {
              const t5 = n2.find(((t6) => !t6.used && e5.id === t6.id && e5.amount === t6.amount));
              return void 0 !== t5 && (t5.used = true, true);
            }));
          }, n = e3.balance === t3.balance && e3.lockedBalance === t3.lockedBalance;
          return e3.utxoNum === t3.utxoNum && n && r3(e3.tokenBalances, t3.tokenBalances) && r3(e3.lockedTokenBalances, t3.lockedTokenBalances);
        };
      }, 645: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.BlockSubscription = t2.BlockSubscriptionBase = void 0;
        const s = r2(531), a = o(r2(307)), c = r2(7695), u = 2e4;
        class d extends s.Subscription {
          getParentHash(e3) {
            const t3 = Math.floor(e3.deps.length / 2) + e3.chainTo;
            return e3.deps[t3];
          }
          async handleReorg(e3, t3, r3, n2) {
            if (console.info(`reorg occur in chain ${e3} -> ${t3}, orphan hash: ${r3}, new hash: ${n2}`), void 0 === this.reorgCallback) return;
            const i2 = [];
            let o2, s2 = r3;
            for (; ; ) {
              const r4 = await this.getBlockByHash(s2);
              i2.push(r4);
              const n3 = await this.getHashesAtHeight(e3, t3, r4.height - 1), a3 = this.getParentHash(r4);
              if (n3[0] === a3) {
                o2 = n3[0];
                break;
              }
              s2 = a3;
            }
            const a2 = [];
            for (s2 = n2; s2 !== o2; ) {
              const e4 = await this.getBlockByHash(s2);
              a2.push(e4), s2 = this.getParentHash(e4);
            }
            const c2 = i2.reverse(), u2 = a2.reverse();
            console.info(`orphan hashes: ${c2.map(((e4) => e4.hash))}, new hashes: ${u2.map(((e4) => e4.hash))}`), await this.reorgCallback(e3, t3, c2, u2);
          }
        }
        t2.BlockSubscriptionBase = d, t2.BlockSubscription = class extends d {
          constructor(e3, t3, r3 = void 0) {
            super(e3), this.nodeProvider = r3 ?? a.getCurrentNodeProvider(), this.reorgCallback = e3.reorgCallback, this.fromTimeStamp = t3, this.parents = new Array(c.TOTAL_NUMBER_OF_CHAINS).fill(void 0), this.cache = /* @__PURE__ */ new Map();
          }
          async getHashesAtHeight(e3, t3, r3) {
            return (await this.nodeProvider.blockflow.getBlockflowHashes({ fromGroup: e3, toGroup: t3, height: r3 })).headers;
          }
          async getBlockByHash(e3) {
            return await this.nodeProvider.blockflow.getBlockflowBlocksBlockHash(e3);
          }
          async getMissingBlocksAndHandleReorg(e3, t3, r3) {
            const n2 = [];
            let i2 = r3;
            for (; i2.height - 1 > t3; ) {
              const e4 = this.getParentHash(i2), t4 = await this.getBlockByHash(e4);
              n2.push(t4), i2 = t4;
            }
            const o2 = this.getParentHash(i2);
            return o2 !== e3 && await this.handleReorg(r3.chainFrom, r3.chainTo, e3, o2), n2.reverse();
          }
          async handleBlocks(e3, t3) {
            const r3 = [];
            for (let t4 = 0; t4 < e3.length; t4 += 1) {
              const n3 = e3[t4].filter(((e4) => !this.cache.has(e4.hash)));
              if (0 === n3.length) continue;
              r3.push(...n3);
              const i2 = this.parents[t4];
              if (void 0 !== i2) {
                const e4 = await this.getMissingBlocksAndHandleReorg(i2.hash, i2.height, n3[0]);
                r3.push(...e4);
              }
              const o2 = n3[n3.length - 1];
              this.parents[t4] = { hash: o2.hash, height: o2.height };
            }
            const n2 = r3.sort(((e4, t4) => e4.timestamp - t4.timestamp));
            try {
              await this.messageCallback(n2);
            } finally {
              const e4 = t3 - u;
              Array.from(this.cache.entries()).forEach((([t4, r5]) => {
                r5 < e4 && this.cache.delete(t4);
              }));
              const r4 = n2.findIndex(((t4) => t4.timestamp >= e4));
              -1 !== r4 && n2.slice(r4).forEach(((e5) => this.cache.set(e5.hash, e5.timestamp)));
            }
          }
          async polling() {
            const e3 = Date.now();
            if (!(this.fromTimeStamp >= e3)) for (; this.fromTimeStamp < e3; ) {
              if (this.isCancelled()) return;
              const t3 = Math.min(this.fromTimeStamp + 6e4, e3);
              try {
                const r3 = await this.nodeProvider.blockflow.getBlockflowBlocks({ fromTs: this.fromTimeStamp, toTs: t3 });
                await this.handleBlocks(r3.blocks, e3);
              } catch (e4) {
                await this.errorCallback(e4, this);
              }
              if (!(this.fromTimeStamp + u < e3)) return;
              this.fromTimeStamp = Math.min(t3 + 1, e3 - u);
            }
          }
        };
      }, 4648: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.BlockSubscription = void 0;
        var n = r2(645);
        Object.defineProperty(t2, "BlockSubscription", { enumerable: true, get: function() {
          return n.BlockSubscription;
        } });
      }, 2205: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.ArrayCodec = void 0;
        const n = r2(5617), i = r2(2709), o = r2(664);
        class s extends i.Codec {
          constructor(e3) {
            super(), this.childCodec = e3;
          }
          encode(e3) {
            const t3 = [n.i32Codec.encode(e3.length)];
            for (const r3 of e3) t3.push(this.childCodec.encode(r3));
            return (0, o.concatBytes)(t3);
          }
          _decode(e3) {
            const t3 = n.i32Codec._decode(e3), r3 = [];
            for (let n2 = 0; n2 < t3; n2 += 1) r3.push(this.childCodec._decode(e3));
            return r3;
          }
        }
        t2.ArrayCodec = s;
      }, 406: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.assetOutputsCodec = t2.assetOutputCodec = t2.AssetOutputCodec = void 0;
        const n = r2(2205), i = r2(5617), o = r2(2768), s = r2(7500), a = r2(5675), c = r2(1678), u = r2(7007), d = r2(664), f = r2(2709), h = r2(6341);
        class l extends f.ObjectCodec {
          static toFixedAssetOutputs(e3, t3) {
            return t3.map(((t4, r3) => l.toFixedAssetOutput(e3, t4, r3)));
          }
          static toFixedAssetOutput(e3, t3, r3) {
            const n2 = t3.amount.toString(), i2 = Number(t3.lockTime), s2 = t3.tokens.map(((e4) => ({ id: (0, d.binToHex)(e4.tokenId), amount: e4.amount.toString() }))), a2 = (0, d.binToHex)(t3.additionalData), f2 = t3.lockupScript.kind, h2 = (0, d.binToHex)((0, u.blakeHash)((0, d.concatBytes)([e3, o.intAs4BytesCodec.encode(r3)]))), l2 = t3.lockupScript.value, p = d.bs58.encode(c.lockupScriptCodec.encode(t3.lockupScript));
            let b;
            if ("P2PKH" === f2) b = (0, u.createHint)(l2);
            else if ("P2MPKH" === f2) b = (0, u.createHint)(l2.publicKeyHashes[0]);
            else {
              if ("P2SH" !== f2) throw "P2C" === f2 ? new Error("P2C script type not allowed for asset output") : new Error(`Unexpected output script type: ${f2}`);
              b = (0, u.createHint)(l2);
            }
            return { hint: b, key: h2, attoAlphAmount: n2, lockTime: i2, tokens: s2, address: p, message: a2 };
          }
          static fromFixedAssetOutputs(e3) {
            return e3.map(((e4) => l.fromFixedAssetOutput(e4)));
          }
          static fromFixedAssetOutput(e3) {
            const t3 = BigInt(e3.attoAlphAmount), r3 = BigInt(e3.lockTime);
            return { amount: t3, lockupScript: c.lockupScriptCodec.decode(d.bs58.decode(e3.address)), lockTime: r3, tokens: e3.tokens.map(((e4) => ({ tokenId: (0, d.hexToBinUnsafe)(e4.id), amount: BigInt(e4.amount) }))), additionalData: (0, d.hexToBinUnsafe)(e3.message) };
          }
        }
        t2.AssetOutputCodec = l, t2.assetOutputCodec = new l({ amount: i.u256Codec, lockupScript: c.lockupScriptCodec, lockTime: s.timestampCodec, tokens: h.tokensCodec, additionalData: a.byteStringCodec }), t2.assetOutputsCodec = new n.ArrayCodec(t2.assetOutputCodec);
      }, 3567: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.BigIntCodec = void 0, t2.BigIntCodec = class {
          static encode(e3) {
            if (0n === e3) return new Uint8Array([0]);
            const t3 = e3 < 0n;
            let r2 = t3 ? -e3 : e3;
            const n = [];
            for (; r2 > 0n; ) n.push(Number(0xffn & r2)), r2 >>= 8n;
            if (!t3 && 128 & n[n.length - 1] && n.push(0), t3) {
              let e4 = true;
              for (let t4 = 0; t4 < n.length; t4++) n[t4] = 255 & ~n[t4], e4 && (255 === n[t4] ? n[t4] = 0 : (n[t4] += 1, e4 = false));
              !e4 && 0 !== n.length && 128 & n[n.length - 1] || n.push(255);
            }
            return new Uint8Array(n.reverse());
          }
          static decodeUnsigned(e3) {
            if (1 === e3.length && 0 === e3[0]) return 0n;
            let t3 = 0n;
            for (const r2 of e3) t3 = t3 << 8n | BigInt(r2);
            return t3;
          }
          static decodeSigned(e3) {
            if (1 === e3.length && 0 === e3[0]) return 0n;
            const t3 = !!(128 & e3[0]);
            let r2 = 0n;
            for (const t4 of e3) r2 = r2 << 8n | BigInt(t4);
            return t3 && (r2 = -(~r2 & (1n << 8n * BigInt(e3.length)) - 1n) - 1n), r2;
          }
        };
      }, 5675: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.byteStringsCodec = t2.byteStringCodec = t2.ByteStringCodec = void 0;
        const n = r2(5617), i = r2(2709), o = r2(664), s = r2(2205);
        class a extends i.Codec {
          encode(e3) {
            return (0, o.concatBytes)([n.i32Codec.encode(e3.length), e3]);
          }
          _decode(e3) {
            const t3 = n.i32Codec._decode(e3);
            return e3.consumeBytes(t3);
          }
        }
        t2.ByteStringCodec = a, t2.byteStringCodec = new a(), t2.byteStringsCodec = new s.ArrayCodec(t2.byteStringCodec);
      }, 4299: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.Checksum = void 0;
        const i = r2(664), o = n(r2(160)), s = r2(2768), a = r2(2709);
        class c extends a.Codec {
          constructor(e3) {
            super(), this.rawCodec = e3;
          }
          encode(e3) {
            const t3 = this.rawCodec.encode(e3), r3 = s.intAs4BytesCodec.encode((0, o.default)(t3));
            return (0, i.concatBytes)([t3, r3]);
          }
          _decode(e3) {
            const t3 = e3.getIndex(), r3 = this.rawCodec._decode(e3), n2 = e3.getIndex(), i2 = s.intAs4BytesCodec._decode(e3), a2 = (0, o.default)(e3.getBytes(t3, n2));
            if (a2 != i2) throw new Error(`Invalid checksum: expected ${a2}, but got ${i2}`);
            return r3;
          }
        }
        t2.Checksum = c;
      }, 2709: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.boolCodec = t2.byteCodec = t2.byte32Codec = t2.EnumCodec = t2.ObjectCodec = t2.FixedSizeCodec = t2.assert = t2.Codec = void 0;
        const n = r2(664), i = r2(7248);
        class o {
          decode(e3) {
            const t3 = new i.Reader(e3);
            return this._decode(t3);
          }
          bimap(e3, t3) {
            return new class extends o {
              constructor(e4) {
                super(), this.codecT = e4;
              }
              encode(e4) {
                return this.codecT.encode(t3(e4));
              }
              _decode(t4) {
                return e3(this.codecT._decode(t4));
              }
            }(this);
          }
        }
        function s(e3, t3) {
          if (!e3) throw new Error(t3);
        }
        t2.Codec = o, t2.assert = s;
        class a extends o {
          constructor(e3) {
            super(), this.size = e3;
          }
          encode(e3) {
            return s(e3.length === this.size, `Invalid length, expected ${this.size}, got ${e3.length}`), e3;
          }
          _decode(e3) {
            return e3.consumeBytes(this.size);
          }
        }
        t2.FixedSizeCodec = a, t2.ObjectCodec = class extends o {
          constructor(e3) {
            super(), this.codecs = e3, this.keys = Object.keys(e3);
          }
          encode(e3) {
            const t3 = [];
            for (const r3 of this.keys) t3.push(this.codecs[r3].encode(e3[r3]));
            return (0, n.concatBytes)(t3);
          }
          _decode(e3) {
            const t3 = {};
            for (const r3 of this.keys) t3[r3] = this.codecs[r3]._decode(e3);
            return t3;
          }
        }, t2.EnumCodec = class extends o {
          constructor(e3, t3) {
            super(), this.name = e3, this.codecs = t3, this.kinds = Object.keys(t3);
          }
          encode(e3) {
            const t3 = this.kinds.findIndex(((t4) => t4 === e3.kind));
            if (-1 === t3) throw new Error(`Invalid ${this.name} kind ${e3.kind}, expected one of ${this.kinds}`);
            const r3 = this.codecs[e3.kind];
            return new Uint8Array([t3, ...r3.encode(e3.value)]);
          }
          _decode(e3) {
            const t3 = e3.consumeByte();
            if (t3 >= 0 && t3 < this.kinds.length) {
              const r3 = this.kinds[`${t3}`];
              return { kind: r3, value: this.codecs[r3]._decode(e3) };
            }
            throw new Error(`Invalid encoded ${this.name} kind: ${t3}`);
          }
        }, t2.byte32Codec = new a(32), t2.byteCodec = new class extends o {
          encode(e3) {
            return s(e3 >= 0 && e3 < 256, `Invalid byte: ${e3}`), new Uint8Array([e3]);
          }
          _decode(e3) {
            return e3.consumeByte();
          }
        }(), t2.boolCodec = new class extends o {
          encode(e3) {
            return new Uint8Array([e3 ? 1 : 0]);
          }
          _decode(e3) {
            const t3 = e3.consumeByte();
            if (1 === t3) return true;
            if (0 === t3) return false;
            throw new Error(`Invalid encoded bool value ${t3}, expected 0 or 1`);
          }
        }();
      }, 5617: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.i32Codec = t2.i256Codec = t2.Signed = t2.u32Codec = t2.u256Codec = t2.UnSigned = void 0;
        const n = r2(2709), i = r2(3567), o = 4294967232, s = { type: "SingleByte", prefix: 0, negPrefix: 192 }, a = { type: "TwoByte", prefix: 64, negPrefix: 128 }, c = { type: "FourByte", prefix: 128, negPrefix: 64 }, u = { type: "MultiByte", prefix: 192 };
        function d(e3) {
          const t3 = e3.consumeByte();
          switch (192 & t3) {
            case s.prefix:
              return { mode: s, body: new Uint8Array([t3]) };
            case a.prefix:
              return { mode: a, body: new Uint8Array([t3, ...e3.consumeBytes(1)]) };
            case c.prefix:
              return { mode: c, body: new Uint8Array([t3, ...e3.consumeBytes(3)]) };
            default: {
              const r3 = 4 + (63 & t3);
              return { mode: u, body: new Uint8Array([t3, ...e3.consumeBytes(r3)]) };
            }
          }
        }
        class f {
          static encodeU32(e3) {
            return (0, n.assert)(e3 >= 0 && e3 < f.u32UpperBound, `Invalid u32 value: ${e3}`), e3 < f.oneByteBound ? new Uint8Array([s.prefix + e3 & 255]) : e3 < f.twoByteBound ? new Uint8Array([a.prefix + (e3 >> 8) & 255, 255 & e3]) : e3 < f.fourByteBound ? new Uint8Array([c.prefix + (e3 >> 24) & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]) : new Uint8Array([u.prefix, e3 >> 24 & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]);
          }
          static encodeU256(e3) {
            if ((0, n.assert)(e3 >= 0n && e3 < f.u256UpperBound, `Invalid u256 value: ${e3}`), e3 < f.fourByteBound) return f.encodeU32(Number(e3));
            {
              let t3 = i.BigIntCodec.encode(e3);
              0 === t3[0] && (t3 = t3.slice(1));
              const r3 = t3.length - 4 + u.prefix & 255;
              return new Uint8Array([r3, ...t3]);
            }
          }
          static decodeInt(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
                return (0, n.assert)(1 === t3.length, "Length should be 2"), t3[0];
              case "TwoByte":
                return (0, n.assert)(2 === t3.length, "Length should be 2"), (63 & t3[0]) << 8 | 255 & t3[1];
              case "FourByte":
                return (0, n.assert)(4 === t3.length, "Length should be 4"), ((63 & t3[0]) << 24 | (255 & t3[1]) << 16 | (255 & t3[2]) << 8 | 255 & t3[3]) >>> 0;
            }
          }
          static decodeU32(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
              case "TwoByte":
              case "FourByte":
                return f.decodeInt(e3, t3);
              case "MultiByte":
                if ((0, n.assert)(t3.length >= 5, "Length should be greater than 5"), 5 === t3.length) return (t3[1] << 24 | (255 & t3[2]) << 16 | (255 & t3[3]) << 8 | 255 & t3[4]) >>> 0;
                throw new Error(`Expect 4 bytes int, but get ${t3.length - 1} bytes int`);
            }
          }
          static decodeU256(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
              case "TwoByte":
              case "FourByte":
                return BigInt(f.decodeInt(e3, t3));
              case "MultiByte":
                return i.BigIntCodec.decodeUnsigned(t3.slice(1, t3.length));
            }
          }
        }
        t2.UnSigned = f, f.oneByteBound = BigInt(64), f.twoByteBound = f.oneByteBound << BigInt(8), f.fourByteBound = f.oneByteBound << BigInt(24), f.u256UpperBound = BigInt(1) << BigInt(256), f.u32UpperBound = 2 ** 32, t2.u256Codec = new class extends n.Codec {
          encode(e3) {
            return f.encodeU256(e3);
          }
          _decode(e3) {
            const { mode: t3, body: r3 } = d(e3);
            return f.decodeU256(t3, r3);
          }
        }(), t2.u32Codec = new class extends n.Codec {
          encode(e3) {
            return f.encodeU32(e3);
          }
          _decode(e3) {
            const { mode: t3, body: r3 } = d(e3);
            return f.decodeU32(t3, r3);
          }
        }();
        class h {
          static encodeI32(e3) {
            return (0, n.assert)(e3 >= h.i32LowerBound && e3 < h.i32UpperBound, `Invalid i32 value: ${e3}`), e3 >= 0 ? h.encodePositiveI32(e3) : h.encodeNegativeI32(e3);
          }
          static encodePositiveI32(e3) {
            return e3 < this.oneByteBound ? new Uint8Array([s.prefix + e3 & 255]) : e3 < this.twoByteBound ? new Uint8Array([a.prefix + (e3 >> 8) & 255, 255 & e3]) : e3 < this.fourByteBound ? new Uint8Array([c.prefix + (e3 >> 24) & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]) : new Uint8Array([u.prefix, e3 >> 24 & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]);
          }
          static encodeNegativeI32(e3) {
            return e3 >= -this.oneByteBound ? new Uint8Array([255 & (e3 ^ s.negPrefix)]) : e3 >= -this.twoByteBound ? new Uint8Array([255 & (e3 >> 8 ^ a.negPrefix), 255 & e3]) : e3 >= -this.fourByteBound ? new Uint8Array([255 & (e3 >> 24 ^ c.negPrefix), e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]) : new Uint8Array([u.prefix, e3 >> 24 & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]);
          }
          static encodeI256(e3) {
            if ((0, n.assert)(e3 >= h.i256LowerBound && e3 < h.i256UpperBound, `Invalid i256 value: ${e3}`), e3 >= -536870912 && e3 < 536870912) return this.encodeI32(Number(e3));
            {
              const t3 = i.BigIntCodec.encode(e3), r3 = t3.length - 4 + u.prefix & 255;
              return new Uint8Array([r3, ...t3]);
            }
          }
          static decodeInt(e3, t3) {
            return t3[0] & h.signFlag ? h.decodeNegativeInt(e3, t3) : h.decodePositiveInt(e3, t3);
          }
          static decodePositiveInt(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
                return t3[0];
              case "TwoByte":
                return (0, n.assert)(2 === t3.length, "Length should be 2"), (63 & t3[0]) << 8 | 255 & t3[1];
              case "FourByte":
                return (0, n.assert)(4 === t3.length, "Length should be 4"), (63 & t3[0]) << 24 | (255 & t3[1]) << 16 | (255 & t3[2]) << 8 | 255 & t3[3];
            }
          }
          static decodeNegativeInt(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
                return t3[0] | o;
              case "TwoByte":
                return (0, n.assert)(2 === t3.length, "Length should be 2"), (t3[0] | o) << 8 | 255 & t3[1];
              case "FourByte":
                return (0, n.assert)(4 === t3.length, "Length should be 4"), (t3[0] | o) << 24 | (255 & t3[1]) << 16 | (255 & t3[2]) << 8 | 255 & t3[3];
            }
          }
          static decodeI32(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
              case "TwoByte":
              case "FourByte":
                return h.decodeInt(e3, t3);
              case "MultiByte":
                if (5 === t3.length) return t3[1] << 24 | (255 & t3[2]) << 16 | (255 & t3[3]) << 8 | 255 & t3[4];
                throw new Error(`Expect 4 bytes int, but get ${t3.length - 1} bytes int`);
            }
          }
          static decodeI256(e3, t3) {
            switch (e3.type) {
              case "SingleByte":
              case "TwoByte":
              case "FourByte":
                return BigInt(h.decodeInt(e3, t3));
              case "MultiByte":
                const r3 = t3.slice(1, t3.length);
                return (0, n.assert)(r3.length <= 32, "Expect <= 32 bytes for I256"), i.BigIntCodec.decodeSigned(r3);
            }
          }
        }
        t2.Signed = h, h.signFlag = 32, h.oneByteBound = BigInt(32), h.twoByteBound = h.oneByteBound << BigInt(8), h.fourByteBound = h.oneByteBound << BigInt(24), h.i256UpperBound = BigInt(1) << BigInt(255), h.i256LowerBound = -h.i256UpperBound, h.i32UpperBound = 2 ** 31, h.i32LowerBound = -h.i32UpperBound, t2.i256Codec = new class extends n.Codec {
          encode(e3) {
            return h.encodeI256(e3);
          }
          _decode(e3) {
            const { mode: t3, body: r3 } = d(e3);
            return h.decodeI256(t3, r3);
          }
        }(), t2.i32Codec = new class extends n.Codec {
          encode(e3) {
            return h.encodeI32(e3);
          }
          _decode(e3) {
            const { mode: t3, body: r3 } = d(e3);
            return h.decodeI32(t3, r3);
          }
        }();
      }, 1486: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.contractCodec = t2.ContractCodec = void 0;
        const n = r2(2205), i = r2(2709), o = r2(5617), s = r2(3049), a = r2(664), c = new n.ArrayCodec(o.i32Codec);
        class u extends i.Codec {
          encode(e3) {
            return (0, a.concatBytes)([o.i32Codec.encode(e3.fieldLength), c.encode(e3.methodIndexes), e3.methods]);
          }
          _decode(e3) {
            return { fieldLength: o.i32Codec._decode(e3), methodIndexes: c._decode(e3), methods: e3.consumeAll() };
          }
          decodeContract(e3) {
            const t3 = this.decode(e3), r3 = t3.fieldLength, n2 = t3.methodIndexes, i2 = [];
            for (let e4 = 0, r4 = 0; e4 < n2.length; e4++) {
              const o2 = n2[e4], a2 = s.methodCodec.decode(t3.methods.slice(r4, o2));
              i2.push(a2), r4 = o2;
            }
            return { fieldLength: r3, methods: i2 };
          }
          encodeContract(e3) {
            const t3 = e3.fieldLength, r3 = e3.methods.map(((e4) => s.methodCodec.encode(e4)));
            let n2 = 0;
            const i2 = { fieldLength: t3, methodIndexes: Array.from(Array(r3.length).keys()).map(((e4) => (n2 += r3[`${e4}`].length, n2))), methods: (0, a.concatBytes)(r3) };
            return this.encode(i2);
          }
        }
        t2.ContractCodec = u, t2.contractCodec = new u();
      }, 1672: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.contractOutputCodec = t2.ContractOutputCodec = void 0;
        const n = r2(5617), i = r2(1678), o = r2(2709), s = r2(6341), a = r2(7007), c = r2(664), u = r2(2768), d = r2(1678);
        class f extends o.ObjectCodec {
          static convertToApiContractOutput(e3, t3, r3) {
            return { hint: (0, a.createHint)(t3.lockupScript), key: (0, c.binToHex)((0, a.blakeHash)((0, c.concatBytes)([e3, u.intAs4BytesCodec.encode(r3)]))), attoAlphAmount: t3.amount.toString(), address: c.bs58.encode(new Uint8Array([3, ...t3.lockupScript])), tokens: t3.tokens.map(((e4) => ({ id: (0, c.binToHex)(e4.tokenId), amount: e4.amount.toString() }))), type: "ContractOutput" };
          }
          static convertToOutput(e3) {
            return { amount: BigInt(e3.attoAlphAmount), lockupScript: d.lockupScriptCodec.decode(c.bs58.decode(e3.address)).value, tokens: e3.tokens.map(((e4) => ({ tokenId: (0, c.hexToBinUnsafe)(e4.id), amount: BigInt(e4.amount) }))) };
          }
        }
        t2.ContractOutputCodec = f, t2.contractOutputCodec = new f({ amount: n.u256Codec, lockupScript: i.p2cCodec, tokens: s.tokensCodec });
      }, 4464: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.contractOutputRefsCodec = t2.contractOutputRefCodec = void 0;
        const n = r2(2205), i = r2(2709), o = r2(2768);
        t2.contractOutputRefCodec = new i.ObjectCodec({ hint: o.intAs4BytesCodec, key: i.byte32Codec }), t2.contractOutputRefsCodec = new n.ArrayCodec(t2.contractOutputRefCodec);
      }, 2577: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.either = void 0;
        const n = r2(2709);
        t2.either = function(e3, t3, r3) {
          return new n.EnumCodec(e3, { Left: t3, Right: r3 });
        };
      }, 7007: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.createHint = t2.djbIntHash = t2.blakeHash = void 0;
        const i = n(r2(1540));
        function o(e3) {
          let t3 = 5381;
          return e3.forEach(((e4) => {
            t3 = (t3 << 5) + t3 + (255 & e4);
          })), t3;
        }
        t2.blakeHash = function(e3) {
          return i.default.blake2b(e3, void 0, 32);
        }, t2.djbIntHash = o, t2.createHint = function(e3) {
          return 1 | o(e3);
        };
      }, 3651: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        }, s = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.contract = t2.token = t2.script = t2.val = t2.unlockScript = t2.lockupScript = t2.contractOutput = t2.boolCodec = t2.Codec = t2.assetOutput = void 0, o(r2(2205), t2), t2.assetOutput = s(r2(406)), o(r2(3567), t2), o(r2(5675), t2);
        var a = r2(2709);
        Object.defineProperty(t2, "Codec", { enumerable: true, get: function() {
          return a.Codec;
        } }), Object.defineProperty(t2, "boolCodec", { enumerable: true, get: function() {
          return a.boolCodec;
        } }), o(r2(5617), t2), t2.contractOutput = s(r2(1672)), o(r2(4464), t2), o(r2(2577), t2), o(r2(7544), t2), o(r2(6210), t2), t2.lockupScript = s(r2(1678)), t2.unlockScript = s(r2(2976)), t2.val = s(r2(1924)), o(r2(7500), t2), o(r2(3049), t2), o(r2(6633), t2), t2.script = s(r2(4459)), o(r2(9510), t2), o(r2(2768), t2), t2.token = s(r2(6341)), o(r2(1092), t2), o(r2(2190), t2), t2.contract = s(r2(1486));
      }, 7544: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.inputsCodec = t2.inputCodec = t2.InputCodec = void 0;
        const n = r2(664), i = r2(2976), o = r2(2709), s = r2(2205), a = r2(2768);
        class c extends o.ObjectCodec {
          static toAssetInputs(e3) {
            return e3.map(((e4) => {
              const t3 = e4.hint, r3 = (0, n.binToHex)(e4.key), o2 = i.unlockScriptCodec.encode(e4.unlockScript);
              return { outputRef: { hint: t3, key: r3 }, unlockScript: (0, n.binToHex)(o2) };
            }));
          }
          static fromAssetInputs(e3) {
            return e3.map(((e4) => ({ hint: e4.outputRef.hint, key: (0, n.hexToBinUnsafe)(e4.outputRef.key), unlockScript: i.unlockScriptCodec.decode((0, n.hexToBinUnsafe)(e4.unlockScript)) })));
          }
        }
        t2.InputCodec = c, t2.inputCodec = new c({ hint: a.intAs4BytesCodec, key: o.byte32Codec, unlockScript: i.unlockScriptCodec }), t2.inputsCodec = new s.ArrayCodec(t2.inputCodec);
      }, 6210: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.BoolToByteVec = t2.BoolNeq = t2.BoolEq = t2.BoolOr = t2.BoolAnd = t2.BoolNot = t2.Pop = t2.StoreLocal = t2.LoadLocal = t2.AddressConst = t2.BytesConst = t2.U256Const = t2.I256Const = t2.U256Const5 = t2.U256Const4 = t2.U256Const3 = t2.U256Const2 = t2.U256Const1 = t2.U256Const0 = t2.I256ConstN1 = t2.I256Const5 = t2.I256Const4 = t2.I256Const3 = t2.I256Const2 = t2.I256Const1 = t2.I256Const0 = t2.ConstFalse = t2.ConstTrue = t2.Return = t2.CallExternal = t2.CallLocal = t2.CallExternalBySelectorCode = t2.MethodSelectorCode = t2.CreateMapEntryCode = t2.LoadImmFieldCode = t2.StoreMutFieldCode = t2.LoadMutFieldCode = t2.DevInstrCode = t2.DEBUGCode = t2.IfFalseCode = t2.IfTrueCode = t2.JumpCode = t2.StoreLocalCode = t2.LoadLocalCode = t2.AddressConstCode = t2.BytesConstCode = t2.U256ConstCode = t2.I256ConstCode = t2.CallExternalCode = t2.CallLocalCode = void 0, t2.Sha256 = t2.Keccak256 = t2.Blake2b = t2.Assert = t2.IfFalse = t2.IfTrue = t2.Jump = t2.IsContractAddress = t2.IsAssetAddress = t2.AddressToByteVec = t2.AddressNeq = t2.AddressEq = t2.ByteVecConcat = t2.ByteVecSize = t2.ByteVecNeq = t2.ByteVecEq = t2.U256ToByteVec = t2.U256ToI256 = t2.I256ToByteVec = t2.I256ToU256 = t2.NumericSHR = t2.NumericSHL = t2.NumericXor = t2.NumericBitOr = t2.NumericBitAnd = t2.U256ModMul = t2.U256ModSub = t2.U256ModAdd = t2.U256Ge = t2.U256Gt = t2.U256Le = t2.U256Lt = t2.U256Neq = t2.U256Eq = t2.U256Mod = t2.U256Div = t2.U256Mul = t2.U256Sub = t2.U256Add = t2.I256Ge = t2.I256Gt = t2.I256Le = t2.I256Lt = t2.I256Neq = t2.I256Eq = t2.I256Mod = t2.I256Div = t2.I256Mul = t2.I256Sub = t2.I256Add = void 0, t2.I256Exp = t2.TxGasFee = t2.TxGasAmount = t2.TxGasPrice = t2.DEBUG = t2.BlockHash = t2.Swap = t2.AssertWithErrorCode = t2.Dup = t2.StoreLocalByIndex = t2.LoadLocalByIndex = t2.ContractIdToAddress = t2.Log9 = t2.Log8 = t2.Log7 = t2.Log6 = t2.EthEcRecover = t2.U256From32Byte = t2.U256From16Byte = t2.U256From8Byte = t2.U256From4Byte = t2.U256From2Byte = t2.U256From1Byte = t2.U256To32Byte = t2.U256To16Byte = t2.U256To8Byte = t2.U256To4Byte = t2.U256To2Byte = t2.U256To1Byte = t2.Zeros = t2.Encode = t2.ByteVecToAddress = t2.ByteVecSlice = t2.Log5 = t2.Log4 = t2.Log3 = t2.Log2 = t2.Log1 = t2.VerifyRelativeLocktime = t2.VerifyAbsoluteLocktime = t2.TxInputsSize = t2.TxInputAddressAt = t2.TxId = t2.BlockTarget = t2.BlockTimeStamp = t2.NetworkId = t2.VerifyED25519 = t2.VerifySecP256K1 = t2.VerifyTxSignature = t2.Sha3 = void 0, t2.CopyCreateSubContractWithToken = t2.CopyCreateSubContract = t2.CreateSubContractWithToken = t2.CreateSubContract = t2.LockApprovedAssets = t2.BurnToken = t2.CopyCreateContractWithToken = t2.MigrateWithFields = t2.MigrateSimple = t2.ContractCodeHash = t2.ContractInitialStateHash = t2.CallerCodeHash = t2.CallerInitialStateHash = t2.IsCalledFromTxScript = t2.CallerAddress = t2.CallerContractId = t2.SelfAddress = t2.SelfContractId = t2.DestroySelf = t2.CopyCreateContract = t2.CreateContractWithToken = t2.CreateContract = t2.TransferTokenToSelf = t2.TransferTokenFromSelf = t2.TransferToken = t2.TransferAlphToSelf = t2.TransferAlphFromSelf = t2.TransferAlph = t2.IsPaying = t2.TokenRemaining = t2.AlphRemaining = t2.ApproveToken = t2.ApproveAlph = t2.StoreMutField = t2.LoadMutField = t2.U256RoundInfinityDiv = t2.I256RoundInfinityDiv = t2.DevInstr = t2.GetSegregatedWebAuthnSignature = t2.VerifySignature = t2.GroupOfAddress = t2.BoolToString = t2.I256ToString = t2.U256ToString = t2.AddModN = t2.MulModN = t2.GetSegregatedSignature = t2.VerifyBIP340Schnorr = t2.U256ModExp = t2.U256Exp = void 0, t2.toI256 = t2.toU256 = t2.instrsCodec = t2.instrCodec = t2.InstrCodec = t2.ExternalCallerAddress = t2.ExternalCallerContractId = t2.CallExternalBySelector = t2.MethodSelector = t2.CreateMapEntry = t2.MinimalContractDeposit = t2.PayGasFee = t2.LoadImmFieldByIndex = t2.LoadImmField = t2.ALPHTokenId = t2.SubContractIdOf = t2.SubContractId = t2.NullContractAddress = t2.CopyCreateSubContractAndTransferToken = t2.CreateSubContractAndTransferToken = t2.CopyCreateContractAndTransferToken = t2.CreateContractAndTransferToken = t2.ContractExists = t2.StoreMutFieldByIndex = t2.LoadMutFieldByIndex = void 0;
        const n = r2(2205), i = r2(5617), o = r2(5675), s = r2(1678), a = r2(2709), c = r2(2768);
        t2.CallLocalCode = 0, t2.CallExternalCode = 1, t2.I256ConstCode = 18, t2.U256ConstCode = 19, t2.BytesConstCode = 20, t2.AddressConstCode = 21, t2.LoadLocalCode = 22, t2.StoreLocalCode = 23, t2.JumpCode = 74, t2.IfTrueCode = 75, t2.IfFalseCode = 76, t2.DEBUGCode = 126, t2.DevInstrCode = 143, t2.LoadMutFieldCode = 160, t2.StoreMutFieldCode = 161, t2.LoadImmFieldCode = 206, t2.CreateMapEntryCode = 210, t2.MethodSelectorCode = 211, t2.CallExternalBySelectorCode = 212, t2.CallLocal = (e3) => ({ name: "CallLocal", code: 0, index: e3 }), t2.CallExternal = (e3) => ({ name: "CallExternal", code: 1, index: e3 }), t2.Return = { name: "Return", code: 2 }, t2.ConstTrue = { name: "ConstTrue", code: 3 }, t2.ConstFalse = { name: "ConstFalse", code: 4 }, t2.I256Const0 = { name: "I256Const0", code: 5 }, t2.I256Const1 = { name: "I256Const1", code: 6 }, t2.I256Const2 = { name: "I256Const2", code: 7 }, t2.I256Const3 = { name: "I256Const3", code: 8 }, t2.I256Const4 = { name: "I256Const4", code: 9 }, t2.I256Const5 = { name: "I256Const5", code: 10 }, t2.I256ConstN1 = { name: "I256ConstN1", code: 11 }, t2.U256Const0 = { name: "U256Const0", code: 12 }, t2.U256Const1 = { name: "U256Const1", code: 13 }, t2.U256Const2 = { name: "U256Const2", code: 14 }, t2.U256Const3 = { name: "U256Const3", code: 15 }, t2.U256Const4 = { name: "U256Const4", code: 16 }, t2.U256Const5 = { name: "U256Const5", code: 17 }, t2.I256Const = (e3) => ({ name: "I256Const", code: 18, value: e3 }), t2.U256Const = (e3) => ({ name: "U256Const", code: 19, value: e3 }), t2.BytesConst = (e3) => ({ name: "BytesConst", code: 20, value: e3 }), t2.AddressConst = (e3) => ({ name: "AddressConst", code: 21, value: e3 }), t2.LoadLocal = (e3) => ({ name: "LoadLocal", code: 22, index: e3 }), t2.StoreLocal = (e3) => ({ name: "StoreLocal", code: 23, index: e3 }), t2.Pop = { name: "Pop", code: 24 }, t2.BoolNot = { name: "BoolNot", code: 25 }, t2.BoolAnd = { name: "BoolAnd", code: 26 }, t2.BoolOr = { name: "BoolOr", code: 27 }, t2.BoolEq = { name: "BoolEq", code: 28 }, t2.BoolNeq = { name: "BoolNeq", code: 29 }, t2.BoolToByteVec = { name: "BoolToByteVec", code: 30 }, t2.I256Add = { name: "I256Add", code: 31 }, t2.I256Sub = { name: "I256Sub", code: 32 }, t2.I256Mul = { name: "I256Mul", code: 33 }, t2.I256Div = { name: "I256Div", code: 34 }, t2.I256Mod = { name: "I256Mod", code: 35 }, t2.I256Eq = { name: "I256Eq", code: 36 }, t2.I256Neq = { name: "I256Neq", code: 37 }, t2.I256Lt = { name: "I256Lt", code: 38 }, t2.I256Le = { name: "I256Le", code: 39 }, t2.I256Gt = { name: "I256Gt", code: 40 }, t2.I256Ge = { name: "I256Ge", code: 41 }, t2.U256Add = { name: "U256Add", code: 42 }, t2.U256Sub = { name: "U256Sub", code: 43 }, t2.U256Mul = { name: "U256Mul", code: 44 }, t2.U256Div = { name: "U256Div", code: 45 }, t2.U256Mod = { name: "U256Mod", code: 46 }, t2.U256Eq = { name: "U256Eq", code: 47 }, t2.U256Neq = { name: "U256Neq", code: 48 }, t2.U256Lt = { name: "U256Lt", code: 49 }, t2.U256Le = { name: "U256Le", code: 50 }, t2.U256Gt = { name: "U256Gt", code: 51 }, t2.U256Ge = { name: "U256Ge", code: 52 }, t2.U256ModAdd = { name: "U256ModAdd", code: 53 }, t2.U256ModSub = { name: "U256ModSub", code: 54 }, t2.U256ModMul = { name: "U256ModMul", code: 55 }, t2.NumericBitAnd = { name: "NumericBitAnd", code: 56 }, t2.NumericBitOr = { name: "NumericBitOr", code: 57 }, t2.NumericXor = { name: "NumericXor", code: 58 }, t2.NumericSHL = { name: "NumericSHL", code: 59 }, t2.NumericSHR = { name: "NumericSHR", code: 60 }, t2.I256ToU256 = { name: "I256ToU256", code: 61 }, t2.I256ToByteVec = { name: "I256ToByteVec", code: 62 }, t2.U256ToI256 = { name: "U256ToI256", code: 63 }, t2.U256ToByteVec = { name: "U256ToByteVec", code: 64 }, t2.ByteVecEq = { name: "ByteVecEq", code: 65 }, t2.ByteVecNeq = { name: "ByteVecNeq", code: 66 }, t2.ByteVecSize = { name: "ByteVecSize", code: 67 }, t2.ByteVecConcat = { name: "ByteVecConcat", code: 68 }, t2.AddressEq = { name: "AddressEq", code: 69 }, t2.AddressNeq = { name: "AddressNeq", code: 70 }, t2.AddressToByteVec = { name: "AddressToByteVec", code: 71 }, t2.IsAssetAddress = { name: "IsAssetAddress", code: 72 }, t2.IsContractAddress = { name: "IsContractAddress", code: 73 }, t2.Jump = (e3) => ({ name: "Jump", code: 74, offset: e3 }), t2.IfTrue = (e3) => ({ name: "IfTrue", code: 75, offset: e3 }), t2.IfFalse = (e3) => ({ name: "IfFalse", code: 76, offset: e3 }), t2.Assert = { name: "Assert", code: 77 }, t2.Blake2b = { name: "Blake2b", code: 78 }, t2.Keccak256 = { name: "Keccak256", code: 79 }, t2.Sha256 = { name: "Sha256", code: 80 }, t2.Sha3 = { name: "Sha3", code: 81 }, t2.VerifyTxSignature = { name: "VerifyTxSignature", code: 82 }, t2.VerifySecP256K1 = { name: "VerifySecP256K1", code: 83 }, t2.VerifyED25519 = { name: "VerifyED25519", code: 84 }, t2.NetworkId = { name: "NetworkId", code: 85 }, t2.BlockTimeStamp = { name: "BlockTimeStamp", code: 86 }, t2.BlockTarget = { name: "BlockTarget", code: 87 }, t2.TxId = { name: "TxId", code: 88 }, t2.TxInputAddressAt = { name: "TxInputAddressAt", code: 89 }, t2.TxInputsSize = { name: "TxInputsSize", code: 90 }, t2.VerifyAbsoluteLocktime = { name: "VerifyAbsoluteLocktime", code: 91 }, t2.VerifyRelativeLocktime = { name: "VerifyRelativeLocktime", code: 92 }, t2.Log1 = { name: "Log1", code: 93 }, t2.Log2 = { name: "Log2", code: 94 }, t2.Log3 = { name: "Log3", code: 95 }, t2.Log4 = { name: "Log4", code: 96 }, t2.Log5 = { name: "Log5", code: 97 }, t2.ByteVecSlice = { name: "ByteVecSlice", code: 98 }, t2.ByteVecToAddress = { name: "ByteVecToAddress", code: 99 }, t2.Encode = { name: "Encode", code: 100 }, t2.Zeros = { name: "Zeros", code: 101 }, t2.U256To1Byte = { name: "U256To1Byte", code: 102 }, t2.U256To2Byte = { name: "U256To2Byte", code: 103 }, t2.U256To4Byte = { name: "U256To4Byte", code: 104 }, t2.U256To8Byte = { name: "U256To8Byte", code: 105 }, t2.U256To16Byte = { name: "U256To16Byte", code: 106 }, t2.U256To32Byte = { name: "U256To32Byte", code: 107 }, t2.U256From1Byte = { name: "U256From1Byte", code: 108 }, t2.U256From2Byte = { name: "U256From2Byte", code: 109 }, t2.U256From4Byte = { name: "U256From4Byte", code: 110 }, t2.U256From8Byte = { name: "U256From8Byte", code: 111 }, t2.U256From16Byte = { name: "U256From16Byte", code: 112 }, t2.U256From32Byte = { name: "U256From32Byte", code: 113 }, t2.EthEcRecover = { name: "EthEcRecover", code: 114 }, t2.Log6 = { name: "Log6", code: 115 }, t2.Log7 = { name: "Log7", code: 116 }, t2.Log8 = { name: "Log8", code: 117 }, t2.Log9 = { name: "Log9", code: 118 }, t2.ContractIdToAddress = { name: "ContractIdToAddress", code: 119 }, t2.LoadLocalByIndex = { name: "LoadLocalByIndex", code: 120 }, t2.StoreLocalByIndex = { name: "StoreLocalByIndex", code: 121 }, t2.Dup = { name: "Dup", code: 122 }, t2.AssertWithErrorCode = { name: "AssertWithErrorCode", code: 123 }, t2.Swap = { name: "Swap", code: 124 }, t2.BlockHash = { name: "BlockHash", code: 125 }, t2.DEBUG = (e3) => ({ name: "DEBUG", code: 126, stringParts: e3 }), t2.TxGasPrice = { name: "TxGasPrice", code: 127 }, t2.TxGasAmount = { name: "TxGasAmount", code: 128 }, t2.TxGasFee = { name: "TxGasFee", code: 129 }, t2.I256Exp = { name: "I256Exp", code: 130 }, t2.U256Exp = { name: "U256Exp", code: 131 }, t2.U256ModExp = { name: "U256ModExp", code: 132 }, t2.VerifyBIP340Schnorr = { name: "VerifyBIP340Schnorr", code: 133 }, t2.GetSegregatedSignature = { name: "GetSegregatedSignature", code: 134 }, t2.MulModN = { name: "MulModN", code: 135 }, t2.AddModN = { name: "AddModN", code: 136 }, t2.U256ToString = { name: "U256ToString", code: 137 }, t2.I256ToString = { name: "I256ToString", code: 138 }, t2.BoolToString = { name: "BoolToString", code: 139 }, t2.GroupOfAddress = { name: "GroupOfAddress", code: 140 }, t2.VerifySignature = { name: "VerifySignature", code: 141 }, t2.GetSegregatedWebAuthnSignature = { name: "GetSegregatedWebAuthnSignature", code: 142 }, t2.DevInstr = (e3) => ({ name: "DevInstr", code: 143, instr: e3 }), t2.I256RoundInfinityDiv = { name: "I256RoundInfinityDiv", code: 144 }, t2.U256RoundInfinityDiv = { name: "U256RoundInfinityDiv", code: 145 }, t2.LoadMutField = (e3) => ({ name: "LoadMutField", code: 160, index: e3 }), t2.StoreMutField = (e3) => ({ name: "StoreMutField", code: 161, index: e3 }), t2.ApproveAlph = { name: "ApproveAlph", code: 162 }, t2.ApproveToken = { name: "ApproveToken", code: 163 }, t2.AlphRemaining = { name: "AlphRemaining", code: 164 }, t2.TokenRemaining = { name: "TokenRemaining", code: 165 }, t2.IsPaying = { name: "IsPaying", code: 166 }, t2.TransferAlph = { name: "TransferAlph", code: 167 }, t2.TransferAlphFromSelf = { name: "TransferAlphFromSelf", code: 168 }, t2.TransferAlphToSelf = { name: "TransferAlphToSelf", code: 169 }, t2.TransferToken = { name: "TransferToken", code: 170 }, t2.TransferTokenFromSelf = { name: "TransferTokenFromSelf", code: 171 }, t2.TransferTokenToSelf = { name: "TransferTokenToSelf", code: 172 }, t2.CreateContract = { name: "CreateContract", code: 173 }, t2.CreateContractWithToken = { name: "CreateContractWithToken", code: 174 }, t2.CopyCreateContract = { name: "CopyCreateContract", code: 175 }, t2.DestroySelf = { name: "DestroySelf", code: 176 }, t2.SelfContractId = { name: "SelfContractId", code: 177 }, t2.SelfAddress = { name: "SelfAddress", code: 178 }, t2.CallerContractId = { name: "CallerContractId", code: 179 }, t2.CallerAddress = { name: "CallerAddress", code: 180 }, t2.IsCalledFromTxScript = { name: "IsCalledFromTxScript", code: 181 }, t2.CallerInitialStateHash = { name: "CallerInitialStateHash", code: 182 }, t2.CallerCodeHash = { name: "CallerCodeHash", code: 183 }, t2.ContractInitialStateHash = { name: "ContractInitialStateHash", code: 184 }, t2.ContractCodeHash = { name: "ContractCodeHash", code: 185 }, t2.MigrateSimple = { name: "MigrateSimple", code: 186 }, t2.MigrateWithFields = { name: "MigrateWithFields", code: 187 }, t2.CopyCreateContractWithToken = { name: "CopyCreateContractWithToken", code: 188 }, t2.BurnToken = { name: "BurnToken", code: 189 }, t2.LockApprovedAssets = { name: "LockApprovedAssets", code: 190 }, t2.CreateSubContract = { name: "CreateSubContract", code: 191 }, t2.CreateSubContractWithToken = { name: "CreateSubContractWithToken", code: 192 }, t2.CopyCreateSubContract = { name: "CopyCreateSubContract", code: 193 }, t2.CopyCreateSubContractWithToken = { name: "CopyCreateSubContractWithToken", code: 194 }, t2.LoadMutFieldByIndex = { name: "LoadMutFieldByIndex", code: 195 }, t2.StoreMutFieldByIndex = { name: "StoreMutFieldByIndex", code: 196 }, t2.ContractExists = { name: "ContractExists", code: 197 }, t2.CreateContractAndTransferToken = { name: "CreateContractAndTransferToken", code: 198 }, t2.CopyCreateContractAndTransferToken = { name: "CopyCreateContractAndTransferToken", code: 199 }, t2.CreateSubContractAndTransferToken = { name: "CreateSubContractAndTransferToken", code: 200 }, t2.CopyCreateSubContractAndTransferToken = { name: "CopyCreateSubContractAndTransferToken", code: 201 }, t2.NullContractAddress = { name: "NullContractAddress", code: 202 }, t2.SubContractId = { name: "SubContractId", code: 203 }, t2.SubContractIdOf = { name: "SubContractIdOf", code: 204 }, t2.ALPHTokenId = { name: "ALPHTokenId", code: 205 }, t2.LoadImmField = (e3) => ({ name: "LoadImmField", code: 206, index: e3 }), t2.LoadImmFieldByIndex = { name: "LoadImmFieldByIndex", code: 207 }, t2.PayGasFee = { name: "PayGasFee", code: 208 }, t2.MinimalContractDeposit = { name: "MinimalContractDeposit", code: 209 }, t2.CreateMapEntry = (e3, t3) => ({ name: "CreateMapEntry", code: 210, immFieldsNum: e3, mutFieldsNum: t3 }), t2.MethodSelector = (e3) => ({ name: "MethodSelector", code: 211, selector: e3 }), t2.CallExternalBySelector = (e3) => ({ name: "CallExternalBySelector", code: 212, selector: e3 }), t2.ExternalCallerContractId = { name: "ExternalCallerContractId", code: 213 }, t2.ExternalCallerAddress = { name: "ExternalCallerAddress", code: 214 };
        class u extends a.Codec {
          encode(e3) {
            switch (e3.name) {
              case "CallLocal":
                return new Uint8Array([0, ...a.byteCodec.encode(e3.index)]);
              case "CallExternal":
                return new Uint8Array([1, ...a.byteCodec.encode(e3.index)]);
              case "Return":
                return new Uint8Array([2]);
              case "ConstTrue":
                return new Uint8Array([3]);
              case "ConstFalse":
                return new Uint8Array([4]);
              case "I256Const0":
                return new Uint8Array([5]);
              case "I256Const1":
                return new Uint8Array([6]);
              case "I256Const2":
                return new Uint8Array([7]);
              case "I256Const3":
                return new Uint8Array([8]);
              case "I256Const4":
                return new Uint8Array([9]);
              case "I256Const5":
                return new Uint8Array([10]);
              case "I256ConstN1":
                return new Uint8Array([11]);
              case "U256Const0":
                return new Uint8Array([12]);
              case "U256Const1":
                return new Uint8Array([13]);
              case "U256Const2":
                return new Uint8Array([14]);
              case "U256Const3":
                return new Uint8Array([15]);
              case "U256Const4":
                return new Uint8Array([16]);
              case "U256Const5":
                return new Uint8Array([17]);
              case "I256Const":
                return new Uint8Array([18, ...i.i256Codec.encode(e3.value)]);
              case "U256Const":
                return new Uint8Array([19, ...i.u256Codec.encode(e3.value)]);
              case "BytesConst":
                return new Uint8Array([20, ...o.byteStringCodec.encode(e3.value)]);
              case "AddressConst":
                return new Uint8Array([21, ...s.lockupScriptCodec.encode(e3.value)]);
              case "LoadLocal":
                return new Uint8Array([22, ...a.byteCodec.encode(e3.index)]);
              case "StoreLocal":
                return new Uint8Array([23, ...a.byteCodec.encode(e3.index)]);
              case "Pop":
                return new Uint8Array([24]);
              case "BoolNot":
                return new Uint8Array([25]);
              case "BoolAnd":
                return new Uint8Array([26]);
              case "BoolOr":
                return new Uint8Array([27]);
              case "BoolEq":
                return new Uint8Array([28]);
              case "BoolNeq":
                return new Uint8Array([29]);
              case "BoolToByteVec":
                return new Uint8Array([30]);
              case "I256Add":
                return new Uint8Array([31]);
              case "I256Sub":
                return new Uint8Array([32]);
              case "I256Mul":
                return new Uint8Array([33]);
              case "I256Div":
                return new Uint8Array([34]);
              case "I256Mod":
                return new Uint8Array([35]);
              case "I256Eq":
                return new Uint8Array([36]);
              case "I256Neq":
                return new Uint8Array([37]);
              case "I256Lt":
                return new Uint8Array([38]);
              case "I256Le":
                return new Uint8Array([39]);
              case "I256Gt":
                return new Uint8Array([40]);
              case "I256Ge":
                return new Uint8Array([41]);
              case "U256Add":
                return new Uint8Array([42]);
              case "U256Sub":
                return new Uint8Array([43]);
              case "U256Mul":
                return new Uint8Array([44]);
              case "U256Div":
                return new Uint8Array([45]);
              case "U256Mod":
                return new Uint8Array([46]);
              case "U256Eq":
                return new Uint8Array([47]);
              case "U256Neq":
                return new Uint8Array([48]);
              case "U256Lt":
                return new Uint8Array([49]);
              case "U256Le":
                return new Uint8Array([50]);
              case "U256Gt":
                return new Uint8Array([51]);
              case "U256Ge":
                return new Uint8Array([52]);
              case "U256ModAdd":
                return new Uint8Array([53]);
              case "U256ModSub":
                return new Uint8Array([54]);
              case "U256ModMul":
                return new Uint8Array([55]);
              case "NumericBitAnd":
                return new Uint8Array([56]);
              case "NumericBitOr":
                return new Uint8Array([57]);
              case "NumericXor":
                return new Uint8Array([58]);
              case "NumericSHL":
                return new Uint8Array([59]);
              case "NumericSHR":
                return new Uint8Array([60]);
              case "I256ToU256":
                return new Uint8Array([61]);
              case "I256ToByteVec":
                return new Uint8Array([62]);
              case "U256ToI256":
                return new Uint8Array([63]);
              case "U256ToByteVec":
                return new Uint8Array([64]);
              case "ByteVecEq":
                return new Uint8Array([65]);
              case "ByteVecNeq":
                return new Uint8Array([66]);
              case "ByteVecSize":
                return new Uint8Array([67]);
              case "ByteVecConcat":
                return new Uint8Array([68]);
              case "AddressEq":
                return new Uint8Array([69]);
              case "AddressNeq":
                return new Uint8Array([70]);
              case "AddressToByteVec":
                return new Uint8Array([71]);
              case "IsAssetAddress":
                return new Uint8Array([72]);
              case "IsContractAddress":
                return new Uint8Array([73]);
              case "Jump":
                return new Uint8Array([74, ...i.i32Codec.encode(e3.offset)]);
              case "IfTrue":
                return new Uint8Array([75, ...i.i32Codec.encode(e3.offset)]);
              case "IfFalse":
                return new Uint8Array([76, ...i.i32Codec.encode(e3.offset)]);
              case "Assert":
                return new Uint8Array([77]);
              case "Blake2b":
                return new Uint8Array([78]);
              case "Keccak256":
                return new Uint8Array([79]);
              case "Sha256":
                return new Uint8Array([80]);
              case "Sha3":
                return new Uint8Array([81]);
              case "VerifyTxSignature":
                return new Uint8Array([82]);
              case "VerifySecP256K1":
                return new Uint8Array([83]);
              case "VerifyED25519":
                return new Uint8Array([84]);
              case "NetworkId":
                return new Uint8Array([85]);
              case "BlockTimeStamp":
                return new Uint8Array([86]);
              case "BlockTarget":
                return new Uint8Array([87]);
              case "TxId":
                return new Uint8Array([88]);
              case "TxInputAddressAt":
                return new Uint8Array([89]);
              case "TxInputsSize":
                return new Uint8Array([90]);
              case "VerifyAbsoluteLocktime":
                return new Uint8Array([91]);
              case "VerifyRelativeLocktime":
                return new Uint8Array([92]);
              case "Log1":
                return new Uint8Array([93]);
              case "Log2":
                return new Uint8Array([94]);
              case "Log3":
                return new Uint8Array([95]);
              case "Log4":
                return new Uint8Array([96]);
              case "Log5":
                return new Uint8Array([97]);
              case "ByteVecSlice":
                return new Uint8Array([98]);
              case "ByteVecToAddress":
                return new Uint8Array([99]);
              case "Encode":
                return new Uint8Array([100]);
              case "Zeros":
                return new Uint8Array([101]);
              case "U256To1Byte":
                return new Uint8Array([102]);
              case "U256To2Byte":
                return new Uint8Array([103]);
              case "U256To4Byte":
                return new Uint8Array([104]);
              case "U256To8Byte":
                return new Uint8Array([105]);
              case "U256To16Byte":
                return new Uint8Array([106]);
              case "U256To32Byte":
                return new Uint8Array([107]);
              case "U256From1Byte":
                return new Uint8Array([108]);
              case "U256From2Byte":
                return new Uint8Array([109]);
              case "U256From4Byte":
                return new Uint8Array([110]);
              case "U256From8Byte":
                return new Uint8Array([111]);
              case "U256From16Byte":
                return new Uint8Array([112]);
              case "U256From32Byte":
                return new Uint8Array([113]);
              case "EthEcRecover":
                return new Uint8Array([114]);
              case "Log6":
                return new Uint8Array([115]);
              case "Log7":
                return new Uint8Array([116]);
              case "Log8":
                return new Uint8Array([117]);
              case "Log9":
                return new Uint8Array([118]);
              case "ContractIdToAddress":
                return new Uint8Array([119]);
              case "LoadLocalByIndex":
                return new Uint8Array([120]);
              case "StoreLocalByIndex":
                return new Uint8Array([121]);
              case "Dup":
                return new Uint8Array([122]);
              case "AssertWithErrorCode":
                return new Uint8Array([123]);
              case "Swap":
                return new Uint8Array([124]);
              case "BlockHash":
                return new Uint8Array([125]);
              case "DEBUG":
                return new Uint8Array([126, ...o.byteStringsCodec.encode(e3.stringParts)]);
              case "TxGasPrice":
                return new Uint8Array([127]);
              case "TxGasAmount":
                return new Uint8Array([128]);
              case "TxGasFee":
                return new Uint8Array([129]);
              case "I256Exp":
                return new Uint8Array([130]);
              case "U256Exp":
                return new Uint8Array([131]);
              case "U256ModExp":
                return new Uint8Array([132]);
              case "VerifyBIP340Schnorr":
                return new Uint8Array([133]);
              case "GetSegregatedSignature":
                return new Uint8Array([134]);
              case "MulModN":
                return new Uint8Array([135]);
              case "AddModN":
                return new Uint8Array([136]);
              case "U256ToString":
                return new Uint8Array([137]);
              case "I256ToString":
                return new Uint8Array([138]);
              case "BoolToString":
                return new Uint8Array([139]);
              case "GroupOfAddress":
                return new Uint8Array([140]);
              case "VerifySignature":
                return new Uint8Array([141]);
              case "GetSegregatedWebAuthnSignature":
                return new Uint8Array([142]);
              case "DevInstr":
                return new Uint8Array([143, ...a.byteCodec.encode(e3.instr)]);
              case "I256RoundInfinityDiv":
                return new Uint8Array([144]);
              case "U256RoundInfinityDiv":
                return new Uint8Array([145]);
              case "LoadMutField":
                return new Uint8Array([160, ...a.byteCodec.encode(e3.index)]);
              case "StoreMutField":
                return new Uint8Array([161, ...a.byteCodec.encode(e3.index)]);
              case "ApproveAlph":
                return new Uint8Array([162]);
              case "ApproveToken":
                return new Uint8Array([163]);
              case "AlphRemaining":
                return new Uint8Array([164]);
              case "TokenRemaining":
                return new Uint8Array([165]);
              case "IsPaying":
                return new Uint8Array([166]);
              case "TransferAlph":
                return new Uint8Array([167]);
              case "TransferAlphFromSelf":
                return new Uint8Array([168]);
              case "TransferAlphToSelf":
                return new Uint8Array([169]);
              case "TransferToken":
                return new Uint8Array([170]);
              case "TransferTokenFromSelf":
                return new Uint8Array([171]);
              case "TransferTokenToSelf":
                return new Uint8Array([172]);
              case "CreateContract":
                return new Uint8Array([173]);
              case "CreateContractWithToken":
                return new Uint8Array([174]);
              case "CopyCreateContract":
                return new Uint8Array([175]);
              case "DestroySelf":
                return new Uint8Array([176]);
              case "SelfContractId":
                return new Uint8Array([177]);
              case "SelfAddress":
                return new Uint8Array([178]);
              case "CallerContractId":
                return new Uint8Array([179]);
              case "CallerAddress":
                return new Uint8Array([180]);
              case "IsCalledFromTxScript":
                return new Uint8Array([181]);
              case "CallerInitialStateHash":
                return new Uint8Array([182]);
              case "CallerCodeHash":
                return new Uint8Array([183]);
              case "ContractInitialStateHash":
                return new Uint8Array([184]);
              case "ContractCodeHash":
                return new Uint8Array([185]);
              case "MigrateSimple":
                return new Uint8Array([186]);
              case "MigrateWithFields":
                return new Uint8Array([187]);
              case "CopyCreateContractWithToken":
                return new Uint8Array([188]);
              case "BurnToken":
                return new Uint8Array([189]);
              case "LockApprovedAssets":
                return new Uint8Array([190]);
              case "CreateSubContract":
                return new Uint8Array([191]);
              case "CreateSubContractWithToken":
                return new Uint8Array([192]);
              case "CopyCreateSubContract":
                return new Uint8Array([193]);
              case "CopyCreateSubContractWithToken":
                return new Uint8Array([194]);
              case "LoadMutFieldByIndex":
                return new Uint8Array([195]);
              case "StoreMutFieldByIndex":
                return new Uint8Array([196]);
              case "ContractExists":
                return new Uint8Array([197]);
              case "CreateContractAndTransferToken":
                return new Uint8Array([198]);
              case "CopyCreateContractAndTransferToken":
                return new Uint8Array([199]);
              case "CreateSubContractAndTransferToken":
                return new Uint8Array([200]);
              case "CopyCreateSubContractAndTransferToken":
                return new Uint8Array([201]);
              case "NullContractAddress":
                return new Uint8Array([202]);
              case "SubContractId":
                return new Uint8Array([203]);
              case "SubContractIdOf":
                return new Uint8Array([204]);
              case "ALPHTokenId":
                return new Uint8Array([205]);
              case "LoadImmField":
                return new Uint8Array([206, ...a.byteCodec.encode(e3.index)]);
              case "LoadImmFieldByIndex":
                return new Uint8Array([207]);
              case "PayGasFee":
                return new Uint8Array([208]);
              case "MinimalContractDeposit":
                return new Uint8Array([209]);
              case "CreateMapEntry":
                return new Uint8Array([210, ...a.byteCodec.encode(e3.immFieldsNum), ...a.byteCodec.encode(e3.mutFieldsNum)]);
              case "MethodSelector":
                return new Uint8Array([211, ...c.intAs4BytesCodec.encode(e3.selector)]);
              case "CallExternalBySelector":
                return new Uint8Array([212, ...c.intAs4BytesCodec.encode(e3.selector)]);
              case "ExternalCallerContractId":
                return new Uint8Array([213]);
              case "ExternalCallerAddress":
                return new Uint8Array([214]);
            }
          }
          _decode(e3) {
            const r3 = e3.consumeByte();
            switch (r3) {
              case 0:
                return (0, t2.CallLocal)(a.byteCodec._decode(e3));
              case 1:
                return (0, t2.CallExternal)(a.byteCodec._decode(e3));
              case 2:
                return t2.Return;
              case 3:
                return t2.ConstTrue;
              case 4:
                return t2.ConstFalse;
              case 5:
                return t2.I256Const0;
              case 6:
                return t2.I256Const1;
              case 7:
                return t2.I256Const2;
              case 8:
                return t2.I256Const3;
              case 9:
                return t2.I256Const4;
              case 10:
                return t2.I256Const5;
              case 11:
                return t2.I256ConstN1;
              case 12:
                return t2.U256Const0;
              case 13:
                return t2.U256Const1;
              case 14:
                return t2.U256Const2;
              case 15:
                return t2.U256Const3;
              case 16:
                return t2.U256Const4;
              case 17:
                return t2.U256Const5;
              case 18:
                return (0, t2.I256Const)(i.i256Codec._decode(e3));
              case 19:
                return (0, t2.U256Const)(i.u256Codec._decode(e3));
              case 20:
                return (0, t2.BytesConst)(o.byteStringCodec._decode(e3));
              case 21:
                return (0, t2.AddressConst)(s.lockupScriptCodec._decode(e3));
              case 22:
                return (0, t2.LoadLocal)(a.byteCodec._decode(e3));
              case 23:
                return (0, t2.StoreLocal)(a.byteCodec._decode(e3));
              case 24:
                return t2.Pop;
              case 25:
                return t2.BoolNot;
              case 26:
                return t2.BoolAnd;
              case 27:
                return t2.BoolOr;
              case 28:
                return t2.BoolEq;
              case 29:
                return t2.BoolNeq;
              case 30:
                return t2.BoolToByteVec;
              case 31:
                return t2.I256Add;
              case 32:
                return t2.I256Sub;
              case 33:
                return t2.I256Mul;
              case 34:
                return t2.I256Div;
              case 35:
                return t2.I256Mod;
              case 36:
                return t2.I256Eq;
              case 37:
                return t2.I256Neq;
              case 38:
                return t2.I256Lt;
              case 39:
                return t2.I256Le;
              case 40:
                return t2.I256Gt;
              case 41:
                return t2.I256Ge;
              case 42:
                return t2.U256Add;
              case 43:
                return t2.U256Sub;
              case 44:
                return t2.U256Mul;
              case 45:
                return t2.U256Div;
              case 46:
                return t2.U256Mod;
              case 47:
                return t2.U256Eq;
              case 48:
                return t2.U256Neq;
              case 49:
                return t2.U256Lt;
              case 50:
                return t2.U256Le;
              case 51:
                return t2.U256Gt;
              case 52:
                return t2.U256Ge;
              case 53:
                return t2.U256ModAdd;
              case 54:
                return t2.U256ModSub;
              case 55:
                return t2.U256ModMul;
              case 56:
                return t2.NumericBitAnd;
              case 57:
                return t2.NumericBitOr;
              case 58:
                return t2.NumericXor;
              case 59:
                return t2.NumericSHL;
              case 60:
                return t2.NumericSHR;
              case 61:
                return t2.I256ToU256;
              case 62:
                return t2.I256ToByteVec;
              case 63:
                return t2.U256ToI256;
              case 64:
                return t2.U256ToByteVec;
              case 65:
                return t2.ByteVecEq;
              case 66:
                return t2.ByteVecNeq;
              case 67:
                return t2.ByteVecSize;
              case 68:
                return t2.ByteVecConcat;
              case 69:
                return t2.AddressEq;
              case 70:
                return t2.AddressNeq;
              case 71:
                return t2.AddressToByteVec;
              case 72:
                return t2.IsAssetAddress;
              case 73:
                return t2.IsContractAddress;
              case 74:
                return (0, t2.Jump)(i.i32Codec._decode(e3));
              case 75:
                return (0, t2.IfTrue)(i.i32Codec._decode(e3));
              case 76:
                return (0, t2.IfFalse)(i.i32Codec._decode(e3));
              case 77:
                return t2.Assert;
              case 78:
                return t2.Blake2b;
              case 79:
                return t2.Keccak256;
              case 80:
                return t2.Sha256;
              case 81:
                return t2.Sha3;
              case 82:
                return t2.VerifyTxSignature;
              case 83:
                return t2.VerifySecP256K1;
              case 84:
                return t2.VerifyED25519;
              case 85:
                return t2.NetworkId;
              case 86:
                return t2.BlockTimeStamp;
              case 87:
                return t2.BlockTarget;
              case 88:
                return t2.TxId;
              case 89:
                return t2.TxInputAddressAt;
              case 90:
                return t2.TxInputsSize;
              case 91:
                return t2.VerifyAbsoluteLocktime;
              case 92:
                return t2.VerifyRelativeLocktime;
              case 93:
                return t2.Log1;
              case 94:
                return t2.Log2;
              case 95:
                return t2.Log3;
              case 96:
                return t2.Log4;
              case 97:
                return t2.Log5;
              case 98:
                return t2.ByteVecSlice;
              case 99:
                return t2.ByteVecToAddress;
              case 100:
                return t2.Encode;
              case 101:
                return t2.Zeros;
              case 102:
                return t2.U256To1Byte;
              case 103:
                return t2.U256To2Byte;
              case 104:
                return t2.U256To4Byte;
              case 105:
                return t2.U256To8Byte;
              case 106:
                return t2.U256To16Byte;
              case 107:
                return t2.U256To32Byte;
              case 108:
                return t2.U256From1Byte;
              case 109:
                return t2.U256From2Byte;
              case 110:
                return t2.U256From4Byte;
              case 111:
                return t2.U256From8Byte;
              case 112:
                return t2.U256From16Byte;
              case 113:
                return t2.U256From32Byte;
              case 114:
                return t2.EthEcRecover;
              case 115:
                return t2.Log6;
              case 116:
                return t2.Log7;
              case 117:
                return t2.Log8;
              case 118:
                return t2.Log9;
              case 119:
                return t2.ContractIdToAddress;
              case 120:
                return t2.LoadLocalByIndex;
              case 121:
                return t2.StoreLocalByIndex;
              case 122:
                return t2.Dup;
              case 123:
                return t2.AssertWithErrorCode;
              case 124:
                return t2.Swap;
              case 125:
                return t2.BlockHash;
              case 126:
                return (0, t2.DEBUG)(o.byteStringsCodec._decode(e3));
              case 127:
                return t2.TxGasPrice;
              case 128:
                return t2.TxGasAmount;
              case 129:
                return t2.TxGasFee;
              case 130:
                return t2.I256Exp;
              case 131:
                return t2.U256Exp;
              case 132:
                return t2.U256ModExp;
              case 133:
                return t2.VerifyBIP340Schnorr;
              case 134:
                return t2.GetSegregatedSignature;
              case 135:
                return t2.MulModN;
              case 136:
                return t2.AddModN;
              case 137:
                return t2.U256ToString;
              case 138:
                return t2.I256ToString;
              case 139:
                return t2.BoolToString;
              case 140:
                return t2.GroupOfAddress;
              case 141:
                return t2.VerifySignature;
              case 142:
                return t2.GetSegregatedWebAuthnSignature;
              case 143:
                return (0, t2.DevInstr)(a.byteCodec._decode(e3));
              case 144:
                return t2.I256RoundInfinityDiv;
              case 145:
                return t2.U256RoundInfinityDiv;
              case 160:
                return (0, t2.LoadMutField)(a.byteCodec._decode(e3));
              case 161:
                return (0, t2.StoreMutField)(a.byteCodec._decode(e3));
              case 162:
                return t2.ApproveAlph;
              case 163:
                return t2.ApproveToken;
              case 164:
                return t2.AlphRemaining;
              case 165:
                return t2.TokenRemaining;
              case 166:
                return t2.IsPaying;
              case 167:
                return t2.TransferAlph;
              case 168:
                return t2.TransferAlphFromSelf;
              case 169:
                return t2.TransferAlphToSelf;
              case 170:
                return t2.TransferToken;
              case 171:
                return t2.TransferTokenFromSelf;
              case 172:
                return t2.TransferTokenToSelf;
              case 173:
                return t2.CreateContract;
              case 174:
                return t2.CreateContractWithToken;
              case 175:
                return t2.CopyCreateContract;
              case 176:
                return t2.DestroySelf;
              case 177:
                return t2.SelfContractId;
              case 178:
                return t2.SelfAddress;
              case 179:
                return t2.CallerContractId;
              case 180:
                return t2.CallerAddress;
              case 181:
                return t2.IsCalledFromTxScript;
              case 182:
                return t2.CallerInitialStateHash;
              case 183:
                return t2.CallerCodeHash;
              case 184:
                return t2.ContractInitialStateHash;
              case 185:
                return t2.ContractCodeHash;
              case 186:
                return t2.MigrateSimple;
              case 187:
                return t2.MigrateWithFields;
              case 188:
                return t2.CopyCreateContractWithToken;
              case 189:
                return t2.BurnToken;
              case 190:
                return t2.LockApprovedAssets;
              case 191:
                return t2.CreateSubContract;
              case 192:
                return t2.CreateSubContractWithToken;
              case 193:
                return t2.CopyCreateSubContract;
              case 194:
                return t2.CopyCreateSubContractWithToken;
              case 195:
                return t2.LoadMutFieldByIndex;
              case 196:
                return t2.StoreMutFieldByIndex;
              case 197:
                return t2.ContractExists;
              case 198:
                return t2.CreateContractAndTransferToken;
              case 199:
                return t2.CopyCreateContractAndTransferToken;
              case 200:
                return t2.CreateSubContractAndTransferToken;
              case 201:
                return t2.CopyCreateSubContractAndTransferToken;
              case 202:
                return t2.NullContractAddress;
              case 203:
                return t2.SubContractId;
              case 204:
                return t2.SubContractIdOf;
              case 205:
                return t2.ALPHTokenId;
              case 206:
                return (0, t2.LoadImmField)(a.byteCodec._decode(e3));
              case 207:
                return t2.LoadImmFieldByIndex;
              case 208:
                return t2.PayGasFee;
              case 209:
                return t2.MinimalContractDeposit;
              case 210:
                return (0, t2.CreateMapEntry)(a.byteCodec._decode(e3), a.byteCodec._decode(e3));
              case 211:
                return (0, t2.MethodSelector)(c.intAs4BytesCodec._decode(e3));
              case 212:
                return (0, t2.CallExternalBySelector)(c.intAs4BytesCodec._decode(e3));
              case 213:
                return t2.ExternalCallerContractId;
              case 214:
                return t2.ExternalCallerAddress;
              default:
                throw new Error(`Unknown instr code: ${r3}`);
            }
          }
        }
        t2.InstrCodec = u, t2.instrCodec = new u(), t2.instrsCodec = new n.ArrayCodec(t2.instrCodec), t2.toU256 = function(e3) {
          switch ((function(e4) {
            if (e4 < 0n || e4 >= 2n ** 256n) throw new Error(`Invalid u256 number: ${e4}`);
          })(e3), e3) {
            case 0n:
              return t2.U256Const0;
            case 1n:
              return t2.U256Const1;
            case 2n:
              return t2.U256Const2;
            case 3n:
              return t2.U256Const3;
            case 4n:
              return t2.U256Const4;
            case 5n:
              return t2.U256Const5;
            default:
              return (0, t2.U256Const)(e3);
          }
        }, t2.toI256 = function(e3) {
          switch ((function(e4) {
            const t3 = 2n ** 255n;
            if (e4 < -t3 || e4 >= t3) throw new Error(`Invalid i256 number: ${e4}`);
          })(e3), e3) {
            case 0n:
              return t2.I256Const0;
            case 1n:
              return t2.I256Const1;
            case 2n:
              return t2.I256Const2;
            case 3n:
              return t2.I256Const3;
            case 4n:
              return t2.I256Const4;
            case 5n:
              return t2.I256Const5;
            case -1n:
              return t2.I256ConstN1;
            default:
              return (0, t2.I256Const)(e3);
          }
        };
      }, 2768: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.intAs4BytesCodec = t2.IntAs4BytesCodec = void 0;
        const n = r2(2709);
        class i extends n.Codec {
          encode(e3) {
            return new Uint8Array([e3 >> 24 & 255, e3 >> 16 & 255, e3 >> 8 & 255, 255 & e3]);
          }
          _decode(e3) {
            const t3 = e3.consumeBytes(4);
            return (255 & t3[0]) << 24 | (255 & t3[1]) << 16 | (255 & t3[2]) << 8 | 255 & t3[3];
          }
        }
        t2.IntAs4BytesCodec = i, t2.intAs4BytesCodec = new i();
      }, 1678: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.lockupScriptCodec = t2.safeP2HMPKHashCodec = t2.p2cCodec = void 0;
        const n = r2(5617), i = r2(2709), o = r2(2205), s = r2(5441), a = r2(4299);
        t2.p2cCodec = i.byte32Codec;
        const c = new i.ObjectCodec({ publicKeyHashes: new o.ArrayCodec(i.byte32Codec), m: n.i32Codec }), u = new i.ObjectCodec({ publicKeyLike: s.safePublicKeyLikeCodec, group: i.byteCodec });
        t2.safeP2HMPKHashCodec = new a.Checksum(i.byte32Codec);
        const d = new i.ObjectCodec({ hash: t2.safeP2HMPKHashCodec, group: i.byteCodec });
        t2.lockupScriptCodec = new i.EnumCodec("lockup script", { P2PKH: i.byte32Codec, P2MPKH: c, P2SH: i.byte32Codec, P2C: i.byte32Codec, P2PK: u, P2HMPK: d });
      }, 3049: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.methodsCodec = t2.methodCodec = t2.MethodCodec = void 0;
        const n = r2(2205), i = r2(5617), o = r2(2709), s = r2(6210), a = r2(664);
        class c extends o.Codec {
          encode(e3) {
            const t3 = [];
            var r3;
            return t3.push(o.boolCodec.encode(e3.isPublic)), t3.push(new Uint8Array([(r3 = e3, (r3.usePreapprovedAssets || r3.useContractAssets ? r3.usePreapprovedAssets && r3.useContractAssets ? 1 : !r3.usePreapprovedAssets && r3.useContractAssets ? 2 : 3 : 0) | (r3.usePayToContractOnly ? 4 : 0))])), t3.push(i.i32Codec.encode(e3.argsLength)), t3.push(i.i32Codec.encode(e3.localsLength)), t3.push(i.i32Codec.encode(e3.returnLength)), t3.push(s.instrsCodec.encode(e3.instrs)), (0, a.concatBytes)(t3);
          }
          _decode(e3) {
            const t3 = o.boolCodec._decode(e3);
            return { ...(function(e4) {
              const t4 = !!(4 & e4);
              switch (3 & e4) {
                case 0:
                  return { usePayToContractOnly: t4, usePreapprovedAssets: false, useContractAssets: false };
                case 1:
                  return { usePayToContractOnly: t4, usePreapprovedAssets: true, useContractAssets: true };
                case 2:
                  return { usePayToContractOnly: t4, usePreapprovedAssets: false, useContractAssets: true };
                case 3:
                  return { usePayToContractOnly: t4, usePreapprovedAssets: true, useContractAssets: false };
                default:
                  throw new Error(`Invalid asset modifier: ${e4}`);
              }
            })(o.byteCodec._decode(e3)), isPublic: t3, argsLength: i.i32Codec._decode(e3), localsLength: i.i32Codec._decode(e3), returnLength: i.i32Codec._decode(e3), instrs: s.instrsCodec._decode(e3) };
          }
        }
        t2.MethodCodec = c, t2.methodCodec = new c(), t2.methodsCodec = new n.ArrayCodec(t2.methodCodec);
      }, 6633: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.option = void 0;
        const n = r2(2709), i = new class extends n.Codec {
          encode() {
            return new Uint8Array([]);
          }
          _decode() {
          }
        }();
        t2.option = function(e3) {
          return new n.EnumCodec("option", { None: i, Some: e3 });
        };
      }, 7421: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.outputsCodec = t2.outputCodec = void 0;
        const n = r2(2205), i = r2(2577), o = r2(406), s = r2(1672);
        t2.outputCodec = (0, i.either)("output", o.assetOutputCodec, s.contractOutputCodec), t2.outputsCodec = new n.ArrayCodec(t2.outputCodec);
      }, 5441: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.safePublicKeyLikeCodec = t2.publicKeyLikeCodec = void 0;
        const n = r2(4299), i = r2(2709), o = new i.FixedSizeCodec(33);
        t2.publicKeyLikeCodec = new i.EnumCodec("public key like", { SecP256K1: o, SecP256R1: o, ED25519: i.byte32Codec, WebAuthn: o }), t2.safePublicKeyLikeCodec = new n.Checksum(t2.publicKeyLikeCodec);
      }, 7248: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.Reader = void 0, t2.Reader = class {
          constructor(e3) {
            this.index = 0, this.bytes = e3;
          }
          getIndex() {
            return this.index;
          }
          getBytes(e3, t3) {
            if (e3 > t3 || e3 < 0) throw new Error(`Invalid range [${e3}, ${t3})`);
            if (t3 > this.bytes.length) throw new Error(`Index out of range, data length: ${this.bytes.length}`);
            return this.bytes.slice(e3, t3);
          }
          consumeByte() {
            if (this.index >= this.bytes.length) throw new Error(`Index out of range: unable to consume byte at index ${this.index}, data length: ${this.bytes.length}`);
            const e3 = this.bytes[`${this.index}`];
            return this.index += 1, e3;
          }
          consumeBytes(e3) {
            const t3 = this.index, r2 = this.index + e3;
            if (t3 > r2 || r2 > this.bytes.length) throw new Error(`Index out of range: unable to consume bytes from index ${t3} to ${r2}, data length: ${this.bytes.length}`);
            const n = this.bytes.slice(t3, r2);
            return this.index = r2, n;
          }
          consumeAll() {
            return this.consumeBytes(this.bytes.length - this.index);
          }
        };
      }, 4459: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.statefulScriptCodecOpt = t2.scriptCodec = t2.ScriptCodec = void 0;
        const n = r2(2709), i = r2(3049), o = r2(6633);
        class s extends n.Codec {
          encode(e3) {
            return i.methodsCodec.encode(e3.methods);
          }
          _decode(e3) {
            return { methods: i.methodsCodec._decode(e3) };
          }
        }
        t2.ScriptCodec = s, t2.scriptCodec = new s(), t2.statefulScriptCodecOpt = (0, o.option)(t2.scriptCodec);
      }, 9510: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.signaturesCodec = t2.signatureCodec = void 0;
        const n = r2(2205), i = r2(2709);
        t2.signatureCodec = new i.FixedSizeCodec(64), t2.signaturesCodec = new n.ArrayCodec(t2.signatureCodec);
      }, 7500: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.timestampCodec = t2.TimestampCodec = void 0;
        const n = r2(664), i = r2(2709);
        class o extends i.Codec {
          encode(e3) {
            (0, i.assert)(e3 >= 0n && e3 < o.max, `Invalid timestamp: ${e3}`);
            const t3 = new Uint8Array(8);
            for (let r3 = 0; r3 < 8; r3 += 1) t3[`${r3}`] = Number(e3 >> BigInt(8 * (7 - r3)) & BigInt(255));
            return t3;
          }
          _decode(e3) {
            const t3 = e3.consumeBytes(8);
            return BigInt(`0x${(0, n.binToHex)(t3)}`);
          }
        }
        t2.TimestampCodec = o, o.max = 1n << 64n, t2.timestampCodec = new o();
      }, 6341: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.tokensCodec = t2.tokenCodec = void 0;
        const n = r2(5617), i = r2(2709), o = r2(2205);
        t2.tokenCodec = new i.ObjectCodec({ tokenId: i.byte32Codec, amount: n.u256Codec }), t2.tokensCodec = new o.ArrayCodec(t2.tokenCodec);
      }, 1092: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.transactionCodec = t2.TransactionCodec = void 0;
        const n = r2(2190), i = r2(9510), o = r2(4464), s = r2(406), a = r2(1672), c = r2(664), u = r2(2709), d = r2(7421);
        class f extends u.ObjectCodec {
          encodeApiTransaction(e3) {
            const t3 = f.fromApiTransaction(e3);
            return this.encode(t3);
          }
          decodeApiTransaction(e3) {
            const t3 = this.decode(e3);
            return f.toApiTransaction(t3);
          }
          static toApiTransaction(e3) {
            const t3 = n.UnsignedTxCodec.txId(e3.unsigned), r3 = n.UnsignedTxCodec.toApiUnsignedTx(e3.unsigned), i2 = !!e3.scriptExecutionOk, o2 = e3.contractInputs.map(((e4) => ({ hint: e4.hint, key: (0, c.binToHex)(e4.key) }))), u2 = (0, c.hexToBinUnsafe)(t3);
            return { unsigned: r3, scriptExecutionOk: i2, contractInputs: o2, generatedOutputs: e3.generatedOutputs.map(((e4, t4) => "Left" === e4.kind ? { ...s.AssetOutputCodec.toFixedAssetOutput(u2, e4.value, t4), type: "AssetOutput" } : a.ContractOutputCodec.convertToApiContractOutput(u2, e4.value, t4))), inputSignatures: e3.inputSignatures.map(((e4) => (0, c.binToHex)(e4))), scriptSignatures: e3.scriptSignatures.map(((e4) => (0, c.binToHex)(e4))) };
          }
          static fromApiTransaction(e3) {
            return { unsigned: n.UnsignedTxCodec.fromApiUnsignedTx(e3.unsigned), scriptExecutionOk: e3.scriptExecutionOk ? 1 : 0, contractInputs: e3.contractInputs.map(((e4) => ({ hint: e4.hint, key: (0, c.hexToBinUnsafe)(e4.key) }))), generatedOutputs: e3.generatedOutputs.map(((e4) => {
              if ("AssetOutput" === e4.type) return { kind: "Left", value: s.AssetOutputCodec.fromFixedAssetOutput(e4) };
              if ("ContractOutput" === e4.type) return { kind: "Right", value: a.ContractOutputCodec.convertToOutput(e4) };
              throw new Error("Invalid output type");
            })), inputSignatures: e3.inputSignatures.map(((e4) => (0, c.hexToBinUnsafe)(e4))), scriptSignatures: e3.scriptSignatures.map(((e4) => (0, c.hexToBinUnsafe)(e4))) };
          }
        }
        t2.TransactionCodec = f, t2.transactionCodec = new f({ unsigned: n.unsignedTxCodec, scriptExecutionOk: u.byteCodec, contractInputs: o.contractOutputRefsCodec, generatedOutputs: d.outputsCodec, inputSignatures: i.signaturesCodec, scriptSignatures: i.signaturesCodec });
      }, 2976: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.encodedSameAsPrevious = t2.unlockScriptCodec = void 0;
        const n = r2(2205), i = r2(5617), o = r2(2709), s = r2(4459), a = r2(1924), c = r2(5441), u = new o.FixedSizeCodec(33), d = new o.ObjectCodec({ publicKey: u, index: i.i32Codec }), f = new n.ArrayCodec(d), h = new o.ObjectCodec({ script: s.scriptCodec, params: a.valsCodec }), l = new class extends o.Codec {
          encode() {
            return new Uint8Array([]);
          }
          _decode() {
            return "SameAsPrevious";
          }
        }(), p = new class extends o.Codec {
          encode() {
            return new Uint8Array([]);
          }
          _decode() {
            return "P2PK";
          }
        }(), b = new n.ArrayCodec(c.publicKeyLikeCodec), y = new n.ArrayCodec(i.i32Codec), m = new o.ObjectCodec({ publicKeys: b, publicKeyIndexes: y });
        t2.unlockScriptCodec = new o.EnumCodec("unlock script", { P2PKH: u, P2MPKH: f, P2SH: h, SameAsPrevious: l, PoLW: u, P2PK: p, P2HMPK: m }), t2.encodedSameAsPrevious = t2.unlockScriptCodec.encode({ kind: "SameAsPrevious", value: "SameAsPrevious" });
      }, 2190: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.unsignedTxCodec = t2.UnsignedTxCodec = void 0;
        const n = r2(664), i = r2(4459), o = r2(5617), s = r2(7544), a = r2(406), c = r2(7007), u = r2(2709);
        class d extends u.ObjectCodec {
          encodeApiUnsignedTx(e3) {
            const t3 = d.fromApiUnsignedTx(e3);
            return this.encode(t3);
          }
          decodeApiUnsignedTx(e3) {
            const t3 = this.decode(e3);
            return d.toApiUnsignedTx(t3);
          }
          static txId(e3) {
            return (0, n.binToHex)((0, c.blakeHash)(t2.unsignedTxCodec.encode(e3)));
          }
          static toApiUnsignedTx(e3) {
            const t3 = d.txId(e3), r3 = (0, n.hexToBinUnsafe)(t3), o2 = e3.version, c2 = e3.networkId, u2 = e3.gasAmount, f = e3.gasPrice.toString(), h = s.InputCodec.toAssetInputs(e3.inputs), l = a.AssetOutputCodec.toFixedAssetOutputs(r3, e3.fixedOutputs);
            let p;
            return "Some" === e3.statefulScript.kind && (p = (0, n.binToHex)(i.scriptCodec.encode(e3.statefulScript.value))), { txId: t3, version: o2, networkId: c2, gasAmount: u2, scriptOpt: p, gasPrice: f, inputs: h, fixedOutputs: l };
          }
          static fromApiUnsignedTx(e3) {
            return { version: e3.version, networkId: e3.networkId, gasAmount: e3.gasAmount, gasPrice: BigInt(e3.gasPrice), inputs: s.InputCodec.fromAssetInputs(e3.inputs), fixedOutputs: a.AssetOutputCodec.fromFixedAssetOutputs(e3.fixedOutputs), statefulScript: void 0 !== e3.scriptOpt ? { kind: "Some", value: i.scriptCodec.decode((0, n.hexToBinUnsafe)(e3.scriptOpt)) } : { kind: "None", value: void 0 } };
          }
        }
        t2.UnsignedTxCodec = d, t2.unsignedTxCodec = new d({ version: u.byteCodec, networkId: u.byteCodec, statefulScript: i.statefulScriptCodecOpt, gasAmount: o.i32Codec, gasPrice: o.u256Codec, inputs: s.inputsCodec, fixedOutputs: a.assetOutputsCodec });
      }, 1924: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.valsCodec = t2.valCodec = void 0;
        const n = r2(5617), i = r2(5675), o = r2(2709), s = r2(1678), a = r2(2205);
        t2.valCodec = new o.EnumCodec("val", { Bool: o.boolCodec, I256: n.i256Codec, U256: n.u256Codec, ByteVec: i.byteStringCodec, Address: s.lockupScriptCodec }), t2.valsCodec = new a.ArrayCodec(t2.valCodec);
      }, 7695: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.MAP_ENTRY_DEPOSIT = t2.MINIMAL_CONTRACT_DEPOSIT = t2.DEFAULT_GAS_ALPH_AMOUNT = t2.DEFAULT_GAS_ATTOALPH_AMOUNT = t2.DEFAULT_GAS_PRICE = t2.DEFAULT_GAS_AMOUNT = t2.NULL_CONTRACT_ADDRESS = t2.ZERO_ADDRESS = t2.DUST_AMOUNT = t2.ONE_ALPH = t2.ALPH_TOKEN_ID = t2.MIN_UTXO_SET_AMOUNT = t2.TOTAL_NUMBER_OF_CHAINS = t2.TOTAL_NUMBER_OF_GROUPS = void 0, t2.TOTAL_NUMBER_OF_GROUPS = 4, t2.TOTAL_NUMBER_OF_CHAINS = t2.TOTAL_NUMBER_OF_GROUPS * t2.TOTAL_NUMBER_OF_GROUPS, t2.MIN_UTXO_SET_AMOUNT = BigInt(1e12), t2.ALPH_TOKEN_ID = "".padStart(64, "0"), t2.ONE_ALPH = 10n ** 18n, t2.DUST_AMOUNT = 10n ** 15n, t2.ZERO_ADDRESS = "tgx7VNFoP9DJiFMFgXXtafQZkUvyEdDHT9ryamHJYrjq", t2.NULL_CONTRACT_ADDRESS = "tgx7VNFoP9DJiFMFgXXtafQZkUvyEdDHT9ryamHJYrjq", t2.DEFAULT_GAS_AMOUNT = 2e4, t2.DEFAULT_GAS_PRICE = 10n ** 11n, t2.DEFAULT_GAS_ATTOALPH_AMOUNT = BigInt(t2.DEFAULT_GAS_AMOUNT) * t2.DEFAULT_GAS_PRICE, t2.DEFAULT_GAS_ALPH_AMOUNT = 2e-3, t2.MINIMAL_CONTRACT_DEPOSIT = t2.ONE_ALPH / 10n, t2.MAP_ENTRY_DEPOSIT = t2.ONE_ALPH / 10n;
      }, 5143: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.getContractCodeByCodeHash = t2.getTokenIdFromUnsignedTx = t2.getContractIdFromUnsignedTx = t2.getContractEventsCurrentCount = t2.multicallMethods = t2.signExecuteMethod = t2.callMethod = t2.subscribeContractEvents = t2.subscribeContractEvent = t2.decodeEvent = t2.subscribeContractDestroyedEvent = t2.subscribeContractCreatedEvent = t2.fetchContractState = t2.ContractInstance = t2.getMapItem = t2.RalphMap = t2.printDebugMessagesFromTx = t2.getDebugMessagesFromTx = t2.testMethod = t2.extractMapsFromApiResult = t2.addStdIdToFields = t2.subscribeEventsFromContract = t2.decodeContractDestroyedEvent = t2.decodeContractCreatedEvent = t2.DestroyContractEventAddresses = t2.CreateContractEventAddresses = t2.ExecutableScript = t2.ContractFactory = t2.randomTxId = t2.fromApiEventFields = t2.fromApiArray = t2.getDefaultValue = t2.fromApiFields = t2.Script = t2.Contract = t2.Artifact = t2.Struct = t2.DEFAULT_COMPILER_OPTIONS = t2.DEFAULT_NODE_COMPILER_OPTIONS = t2.StdIdFieldName = void 0;
        const s = r2(7077), a = r2(3749), c = o(r2(8486)), u = r2(664), d = r2(2581), f = r2(307), h = r2(4964), l = r2(7695), p = o(r2(1540)), b = r2(2505), y = r2(3651), m = r2(4652), g = new u.WebCrypto();
        t2.StdIdFieldName = "__stdInterfaceId", t2.DEFAULT_NODE_COMPILER_OPTIONS = { ignoreUnusedConstantsWarnings: false, ignoreUnusedVariablesWarnings: false, ignoreUnusedFieldsWarnings: false, ignoreUnusedPrivateFunctionsWarnings: false, ignoreUpdateFieldsCheckWarnings: false, ignoreCheckExternalCallerWarnings: false, ignoreUnusedFunctionReturnWarnings: false, skipAbstractContractCheck: false, skipTests: false }, t2.DEFAULT_COMPILER_OPTIONS = { errorOnWarnings: true, ...t2.DEFAULT_NODE_COMPILER_OPTIONS };
        class v {
          constructor(e3, t3, r3, n2) {
            this.name = e3, this.fieldNames = t3, this.fieldTypes = r3, this.isMutable = n2;
          }
          static fromJson(e3) {
            if (null === e3.name || null === e3.fieldNames || null === e3.fieldTypes || null === e3.isMutable) throw Error("The JSON for struct is incomplete");
            return new v(e3.name, e3.fieldNames, e3.fieldTypes, e3.isMutable);
          }
          static fromStructSig(e3) {
            return new v(e3.name, e3.fieldNames, e3.fieldTypes, e3.isMutable);
          }
          toJson() {
            return { name: this.name, fieldNames: this.fieldNames, fieldTypes: this.fieldTypes, isMutable: this.isMutable };
          }
        }
        t2.Struct = v;
        class w {
          constructor(e3, t3, r3) {
            this.version = e3, this.name = t3, this.functions = r3;
          }
          async isDevnet(e3) {
            if (!e3.nodeProvider) return false;
            const t3 = await e3.nodeProvider.infos.getInfosChainParams();
            return (0, u.isDevnet)(t3.networkId);
          }
        }
        function _(e3) {
          return { name: e3.name, paramNames: e3.paramNames, paramTypes: e3.paramTypes, paramIsMutable: e3.paramIsMutable, returnTypes: e3.returnTypes };
        }
        t2.Artifact = w;
        class A extends w {
          constructor(e3, t3, r3, n2, i2, o2, s2, a2, d2, f2, h2, l2, p2, b2) {
            super(e3, t3, d2), this.bytecode = r3, this.bytecodeDebugPatch = n2, this.codeHash = i2, this.fieldsSig = s2, this.eventsSig = a2, this.constants = f2, this.enums = h2, this.structs = l2, this.mapsSig = p2, this.stdInterfaceId = b2, this.bytecodeDebug = c.buildDebugBytecode(this.bytecode, this.bytecodeDebugPatch), this.codeHashDebug = o2, this.decodedContract = y.contract.contractCodec.decodeContract((0, u.hexToBinUnsafe)(this.bytecode)), this.bytecodeForTesting = void 0, this.decodedTestingContract = void 0, this.codeHashForTesting = void 0;
          }
          isInlineFunc(e3) {
            if (e3 >= this.functions.length) throw new Error(`Invalid function index ${e3}, function size: ${this.functions.length}`);
            return e3 >= this.decodedContract.methods.length;
          }
          getByteCodeForTesting() {
            if (void 0 !== this.bytecodeForTesting) return this.bytecodeForTesting;
            if (!(this.functions.length > this.decodedContract.methods.length) && this.publicFunctions().length == this.functions.length) return this.bytecodeForTesting = this.bytecodeDebug, this.codeHashForTesting = this.codeHashDebug, this.bytecodeForTesting;
            const e3 = y.contract.contractCodec.decodeContract((0, u.hexToBinUnsafe)(this.bytecodeDebug)), t3 = e3.methods.map(((e4) => ({ ...e4, isPublic: true }))), r3 = y.contract.contractCodec.encodeContract({ fieldLength: e3.fieldLength, methods: t3 }), n2 = p.blake2b(r3, void 0, 32);
            return this.bytecodeForTesting = (0, u.binToHex)(r3), this.codeHashForTesting = (0, u.binToHex)(n2), this.bytecodeForTesting;
          }
          getDecodedTestingContract() {
            if (void 0 !== this.decodedTestingContract) return this.decodedTestingContract;
            const e3 = (0, u.hexToBinUnsafe)(this.getByteCodeForTesting());
            return this.decodedTestingContract = y.contract.contractCodec.decodeContract(e3), this.decodedTestingContract;
          }
          hasCodeHash(e3) {
            return this.codeHash === e3 || this.codeHashDebug === e3 || this.codeHashForTesting === e3;
          }
          getDecodedMethod(e3) {
            return this.decodedContract.methods[`${e3}`];
          }
          publicFunctions() {
            return this.functions.filter(((e3, t3) => this.getDecodedMethod(t3).isPublic));
          }
          usingPreapprovedAssetsFunctions() {
            return this.functions.filter(((e3, t3) => this.getDecodedMethod(t3).usePreapprovedAssets));
          }
          usingAssetsInContractFunctions() {
            return this.functions.filter(((e3, t3) => this.getDecodedMethod(t3).useContractAssets));
          }
          isMethodUsePreapprovedAssets(e3, t3) {
            return e3 && this.isInlineFunc(t3) ? this.getDecodedTestingContract().methods[`${t3}`].usePreapprovedAssets : this.getDecodedMethod(t3).usePreapprovedAssets;
          }
          static fromJson(e3, t3 = "", r3 = "", n2 = []) {
            if (null == e3.version || null == e3.name || null == e3.bytecode || null == e3.codeHash || null == e3.fieldsSig || null == e3.eventsSig || null == e3.constants || null == e3.enums || null == e3.functions) throw Error("The artifact JSON for contract is incomplete");
            return new A(e3.version, e3.name, e3.bytecode, t3, e3.codeHash, r3 || e3.codeHash, e3.fieldsSig, e3.eventsSig, e3.functions, e3.constants, e3.enums, n2, null === e3.mapsSig ? void 0 : e3.mapsSig, null === e3.stdInterfaceId ? void 0 : e3.stdInterfaceId);
          }
          static fromCompileResult(e3, t3 = []) {
            return new A(e3.version, e3.name, e3.bytecode, e3.bytecodeDebugPatch, e3.codeHash, e3.codeHashDebug, e3.fields, e3.events, e3.functions.map(_), e3.constants, e3.enums, t3, e3.maps, e3.stdInterfaceId);
          }
          static async fromArtifactFile(e3, t3, r3, n2 = []) {
            const i2 = await s.promises.readFile(e3), o2 = JSON.parse(i2.toString());
            return A.fromJson(o2, t3, r3, n2);
          }
          toString() {
            const e3 = { version: this.version, name: this.name, bytecode: this.bytecode, codeHash: this.codeHash, fieldsSig: this.fieldsSig, eventsSig: this.eventsSig, functions: this.functions, constants: this.constants, enums: this.enums };
            return void 0 !== this.mapsSig && (e3.mapsSig = this.mapsSig), void 0 !== this.stdInterfaceId && (e3.stdInterfaceId = this.stdInterfaceId), JSON.stringify(e3, null, 2);
          }
          getInitialFieldsWithDefaultValues() {
            return E(void 0 === this.stdInterfaceId ? this.fieldsSig : { names: this.fieldsSig.names.slice(0, -1), types: this.fieldsSig.types.slice(0, -1), isMutable: this.fieldsSig.isMutable.slice(0, -1) }, this.structs);
          }
          toState(e3, t3, r3) {
            const n2 = void 0 !== r3 ? r3 : A.randomAddress();
            return { address: n2, contractId: (0, u.binToHex)((0, d.contractIdFromAddress)(n2)), bytecode: this.bytecode, codeHash: this.codeHash, fields: e3, fieldsSig: this.fieldsSig, asset: t3 };
          }
          static randomAddress() {
            const e3 = new Uint8Array(33);
            return g.getRandomValues(e3), e3[0] = 3, u.bs58.encode(e3);
          }
          printDebugMessages(e3, t3) {
            (0, b.isContractDebugMessageEnabled)() && 0 != t3.length && (console.log(`Testing ${this.name}.${e3}:`), t3.forEach(((e4) => W(e4))));
          }
          toApiFields(e3) {
            return void 0 === e3 ? [] : (function(e4, t3, r3) {
              return c.flattenFields(e4, t3.names, t3.types, t3.isMutable, r3).map(((e5) => (0, a.toApiVal)(e5.value, e5.type)));
            })(e3, this.fieldsSig, this.structs);
          }
          toApiArgs(e3, t3) {
            if (t3) {
              const r3 = this.functions.find(((t4) => t4.name == e3));
              if (null == r3) throw new Error(`Invalid function name: ${e3}`);
              return U(t3, r3, this.structs);
            }
            return [];
          }
          getMethodIndex(e3) {
            return this.functions.findIndex(((t3) => t3.name === e3));
          }
          toApiContractStates(e3) {
            return void 0 !== e3 ? e3.map(((e4) => (function(e5, t3) {
              const r3 = e5.fields ?? {}, n2 = e5.fieldsSig, i2 = c.flattenFields(r3, n2.names, n2.types, n2.isMutable, t3), o2 = i2.filter(((e6) => !e6.isMutable)).map(((e6) => (0, a.toApiVal)(e6.value, e6.type))), s2 = i2.filter(((e6) => e6.isMutable)).map(((e6) => (0, a.toApiVal)(e6.value, e6.type)));
              return { address: e5.address, bytecode: e5.bytecode, codeHash: e5.codeHash, initialStateHash: e5.initialStateHash, immFields: o2, mutFields: s2, asset: B(e5.asset) };
            })(e4, this.structs))) : void 0;
          }
          toApiTestContractParams(e3, t3) {
            const r3 = void 0 === t3.initialFields ? [] : c.flattenFields(t3.initialFields, this.fieldsSig.names, this.fieldsSig.types, this.fieldsSig.isMutable, this.structs), n2 = r3.filter(((e4) => !e4.isMutable)).map(((e4) => (0, a.toApiVal)(e4.value, e4.type))), i2 = r3.filter(((e4) => e4.isMutable)).map(((e4) => (0, a.toApiVal)(e4.value, e4.type))), o2 = this.getMethodIndex(e3);
            return { group: t3.group, blockHash: t3.blockHash, blockTimeStamp: t3.blockTimeStamp, txId: t3.txId, address: t3.contractAddress, callerContractAddress: t3.callerContractAddress, bytecode: this.isInlineFunc(o2) ? this.getByteCodeForTesting() : this.bytecodeDebug, initialImmFields: n2, initialMutFields: i2, initialAsset: void 0 !== t3.initialAsset ? B(t3.initialAsset) : void 0, methodIndex: o2, args: this.toApiArgs(e3, t3.args), existingContracts: this.toApiContractStates(t3.existingContracts), inputAssets: O(t3.inputAssets), dustAmount: t3.dustAmount?.toString() };
          }
          fromApiContractState(e3) {
            return { address: e3.address, contractId: (0, u.binToHex)((0, d.contractIdFromAddress)(e3.address)), bytecode: e3.bytecode, initialStateHash: e3.initialStateHash, codeHash: e3.codeHash, fields: T(e3.immFields, e3.mutFields, this.fieldsSig, this.structs), fieldsSig: this.fieldsSig, asset: (t3 = e3.asset, { alphAmount: (0, a.fromApiNumber256)(t3.attoAlphAmount), tokens: (0, a.fromApiTokens)(t3.tokens) }) };
            var t3;
          }
          static fromApiContractState(e3, t3) {
            return t3(e3.codeHash).fromApiContractState(e3);
          }
          static fromApiEvent(e3, t3, r3, n2) {
            let i2, o2;
            if (e3.eventIndex == A.ContractCreatedEventIndex) i2 = D(I(e3.fields, A.ContractCreatedEvent, true)), o2 = A.ContractCreatedEvent.name;
            else if (e3.eventIndex == A.ContractDestroyedEventIndex) i2 = I(e3.fields, A.ContractDestroyedEvent, true), o2 = A.ContractDestroyedEvent.name;
            else {
              const r4 = n2(t3).eventsSig[e3.eventIndex];
              i2 = I(e3.fields, r4), o2 = r4.name;
            }
            return { txId: r3, blockHash: e3.blockHash, contractAddress: e3.contractAddress, name: o2, eventIndex: e3.eventIndex, fields: i2 };
          }
          fromApiTestContractResult(e3, t3, r3, n2) {
            const i2 = this.functions.findIndex(((t4) => t4.name === e3)), o2 = this.functions[`${i2}`].returnTypes, s2 = x(t3.returns, o2, this.structs), a2 = 0 === s2.length ? null : 1 === s2.length ? s2[0] : s2, c2 = /* @__PURE__ */ new Map();
            return c2.set(t3.address, t3.codeHash), t3.contracts.forEach(((e4) => c2.set(e4.address, e4.codeHash))), { contractId: (0, u.binToHex)((0, d.contractIdFromAddress)(t3.address)), contractAddress: t3.address, returns: a2, gasUsed: t3.gasUsed, contracts: t3.contracts.map(((e4) => A.fromApiContractState(e4, n2))), txOutputs: t3.txOutputs.map(R), events: A.fromApiEvents(t3.events, c2, r3, n2), debugMessages: t3.debugMessages };
          }
          async txParamsForDeployment(e3, t3, r3) {
            const n2 = await this.isDevnet(e3), i2 = t3.initialFields ?? {}, o2 = this.buildByteCodeToDeploy($(this, i2), n2, t3.exposePrivateFunctions ?? false), s2 = await e3.getSelectedAccount();
            if ("gl-secp256k1" === s2.keyType && void 0 === r3) throw new Error("Groupless address requires explicit group number for contract deployment");
            return { signerAddress: s2.address, signerKeyType: s2.keyType, bytecode: o2, initialAttoAlphAmount: t3?.initialAttoAlphAmount, issueTokenAmount: t3?.issueTokenAmount, issueTokenTo: t3?.issueTokenTo, initialTokenAmounts: t3?.initialTokenAmounts, gasAmount: t3?.gasAmount, gasPrice: t3?.gasPrice, group: r3 };
          }
          buildByteCodeToDeploy(e3, t3, r3 = false) {
            if (r3 && !t3) throw new Error("Cannot expose private functions in non-devnet environment");
            try {
              const n2 = r3 && t3 ? this.getByteCodeForTesting() : t3 ? this.bytecodeDebug : this.bytecode;
              return c.buildContractByteCode(n2, e3, this.fieldsSig, this.structs);
            } catch (e4) {
              throw new m.TraceableError(`Failed to build bytecode for contract ${this.name}`, e4);
            }
          }
          static fromApiEvents(e3, t3, r3, n2) {
            return e3.map(((e4) => {
              const i2 = e4.contractAddress, o2 = t3.get(i2);
              if (void 0 !== o2 || e4.eventIndex < 0) return A.fromApiEvent(e4, o2, r3, n2);
              throw Error(`Cannot find codeHash for the contract address: ${i2}`);
            }));
          }
          toApiCallContract(e3, t3, r3, n2) {
            const i2 = this.functions[`${n2}`], o2 = U(e3.args ?? {}, i2, this.structs);
            return { ...e3, group: t3, address: r3, methodIndex: n2, args: o2, inputAssets: O(e3.inputAssets) };
          }
          fromApiCallContractResult(e3, t3, r3, n2) {
            const i2 = this.functions[`${r3}`].returnTypes;
            return S((0, a.tryGetCallResult)(e3), t3, i2, this.structs, n2);
          }
        }
        function S(e3, t3, r3, n2, i2) {
          const o2 = x(e3.returns, r3, n2), s2 = 0 === o2.length ? null : 1 === o2.length ? o2[0] : o2, a2 = /* @__PURE__ */ new Map();
          return e3.contracts.forEach(((e4) => a2.set(e4.address, e4.codeHash))), { returns: s2, gasUsed: e3.gasUsed, contracts: e3.contracts.map(((e4) => A.fromApiContractState(e4, i2))), txInputs: e3.txInputs, txOutputs: e3.txOutputs.map(((e4) => R(e4))), events: A.fromApiEvents(e3.events, a2, t3, i2), debugMessages: e3.debugMessages };
        }
        t2.Contract = A, A.ContractCreatedEventIndex = -1, A.ContractCreatedEvent = { name: "ContractCreated", fieldNames: ["address", "parentAddress", "stdInterfaceId"], fieldTypes: ["Address", "Address", "ByteVec"] }, A.ContractDestroyedEventIndex = -2, A.ContractDestroyedEvent = { name: "ContractDestroyed", fieldNames: ["address"], fieldTypes: ["Address"] }, A.DebugEventIndex = -3;
        class C extends w {
          constructor(e3, t3, r3, n2, i2, o2, s2) {
            super(e3, t3, o2), this.bytecodeTemplate = r3, this.bytecodeDebugPatch = n2, this.fieldsSig = i2, this.structs = s2;
          }
          static fromCompileResult(e3, t3 = []) {
            return new C(e3.version, e3.name, e3.bytecodeTemplate, e3.bytecodeDebugPatch, e3.fields, e3.functions.map(_), t3);
          }
          static fromJson(e3, t3 = "", r3 = []) {
            if (null == e3.version || null == e3.name || null == e3.bytecodeTemplate || null == e3.fieldsSig || null == e3.functions) throw Error("The artifact JSON for script is incomplete");
            return new C(e3.version, e3.name, e3.bytecodeTemplate, t3, e3.fieldsSig, e3.functions, r3);
          }
          static async fromArtifactFile(e3, t3, r3 = []) {
            const n2 = await s.promises.readFile(e3), i2 = JSON.parse(n2.toString());
            return this.fromJson(i2, t3, r3);
          }
          toString() {
            const e3 = { version: this.version, name: this.name, bytecodeTemplate: this.bytecodeTemplate, fieldsSig: this.fieldsSig, functions: this.functions };
            return JSON.stringify(e3, null, 2);
          }
          async txParamsForExecution(e3) {
            const t3 = await e3.signer.getSelectedAccount(), r3 = this.buildByteCodeToDeploy(e3.initialFields ?? {});
            return { signerAddress: t3.address, signerKeyType: t3.keyType, bytecode: r3, attoAlphAmount: e3.attoAlphAmount, tokens: e3.tokens, gasAmount: e3.gasAmount, gasPrice: e3.gasPrice, dustAmount: e3.dustAmount };
          }
          buildByteCodeToDeploy(e3) {
            try {
              return c.buildScriptByteCode(this.bytecodeTemplate, e3, this.fieldsSig, this.structs);
            } catch (e4) {
              throw new m.TraceableError(`Failed to build bytecode for script ${this.name}`, e4);
            }
          }
        }
        function T(e3, t3, r3, n2) {
          let [i2, o2] = [0, 0];
          const s2 = (r4, n3) => {
            const s3 = n3 ? t3[o2++] : e3[i2++];
            return (0, a.fromApiPrimitiveVal)(s3, r4);
          };
          return r3.names.reduce(((e4, t4, i3) => {
            const o3 = r3.types[`${i3}`], a2 = r3.isMutable[`${i3}`];
            return e4[`${t4}`] = M(a2, o3, n2, s2), e4;
          }), {});
        }
        function M(e3, t3, r3, n2) {
          if (t3.startsWith("[")) {
            const [i3, o3] = (0, a.decodeArrayType)(t3);
            return Array.from(Array(o3).keys()).map((() => M(e3, i3, r3, n2)));
          }
          if (t3.startsWith("(")) return (0, a.decodeTupleType)(t3).reduce(((t4, i3) => (t4.push(M(e3, i3, r3, n2)), t4)), []);
          const i2 = r3.find(((e4) => e4.name === t3));
          if (void 0 !== i2) return i2.fieldNames.reduce(((t4, o3, s2) => {
            const a2 = i2.fieldTypes[`${s2}`], c2 = e3 && i2.isMutable[`${s2}`];
            return t4[`${o3}`] = M(c2, a2, r3, n2), t4;
          }), {});
          const o2 = a.PrimitiveTypes.includes(t3) ? t3 : "ByteVec";
          return n2(o2, e3);
        }
        function E(e3, t3) {
          return e3.names.reduce(((r3, n2, i2) => {
            const o2 = e3.types[`${i2}`];
            return r3[`${n2}`] = M(false, o2, t3, a.getDefaultPrimitiveValue), r3;
          }), {});
        }
        function k(e3, t3, r3, n2 = false) {
          return M(false, t3, r3, ((t4) => {
            const r4 = e3.next();
            if (r4.done) throw Error("Not enough vals");
            return (0, a.fromApiPrimitiveVal)(r4.value, t4, n2);
          }));
        }
        function x(e3, t3, r3) {
          const n2 = e3.values();
          return t3.map(((e4) => k(n2, e4, r3)));
        }
        function I(e3, t3, r3 = false) {
          const n2 = e3.values();
          return t3.fieldNames.reduce(((e4, i2, o2) => {
            const s2 = t3.fieldTypes[`${o2}`];
            return e4[`${i2}`] = k(n2, s2, [], r3), e4;
          }), {});
        }
        function B(e3) {
          return { attoAlphAmount: (0, a.toApiNumber256)(e3.alphAmount), tokens: void 0 !== e3.tokens ? e3.tokens.map(a.toApiToken) : [] };
        }
        function U(e3, t3, r3) {
          return c.flattenFields(e3, t3.paramNames, t3.paramTypes, t3.paramIsMutable, r3).map(((e4) => (0, a.toApiVal)(e4.value, e4.type)));
        }
        function P(e3) {
          return { address: e3.address, asset: B(e3.asset) };
        }
        function O(e3) {
          return void 0 !== e3 ? e3.map(P) : void 0;
        }
        function R(e3) {
          if ("AssetOutput" === e3.type) {
            const t3 = e3;
            return { type: "AssetOutput", address: t3.address, alphAmount: (0, a.fromApiNumber256)(t3.attoAlphAmount), tokens: (0, a.fromApiTokens)(t3.tokens), lockTime: t3.lockTime, message: t3.message };
          }
          if ("ContractOutput" === e3.type) {
            const t3 = e3;
            return { type: "ContractOutput", address: t3.address, alphAmount: (0, a.fromApiNumber256)(t3.attoAlphAmount), tokens: (0, a.fromApiTokens)(t3.tokens) };
          }
          throw new Error(`Unknown output type: ${e3}`);
        }
        function N() {
          const e3 = new Uint8Array(32);
          return g.getRandomValues(e3), (0, u.binToHex)(e3);
        }
        function L(e3, t3) {
          const r3 = new Uint8Array(32).fill(0);
          return r3[30] = e3, r3[31] = t3, (0, d.addressFromContractId)((0, u.binToHex)(r3));
        }
        function j(e3, t3, r3) {
          if (e3.eventIndex !== r3) throw new Error(`Invalid event index: ${e3.eventIndex}, expected: ${r3}`);
          return I(e3.fields, t3, true);
        }
        function D(e3) {
          const t3 = e3.parentAddress, r3 = e3.stdInterfaceId;
          return { address: e3.address, parentAddress: "" === t3 ? void 0 : t3, stdInterfaceIdGuessed: "" === r3 ? void 0 : r3 };
        }
        function F(e3) {
          const t3 = j(e3, A.ContractCreatedEvent, A.ContractCreatedEventIndex);
          return { blockHash: e3.blockHash, txId: e3.txId, eventIndex: e3.eventIndex, name: A.ContractCreatedEvent.name, fields: D(t3) };
        }
        function H(e3) {
          const t3 = j(e3, A.ContractDestroyedEvent, A.ContractDestroyedEventIndex);
          return { blockHash: e3.blockHash, txId: e3.txId, eventIndex: e3.eventIndex, name: A.ContractDestroyedEvent.name, fields: { address: t3.address } };
        }
        function q(e3, t3, r3, n2, i2) {
          const o2 = { pollingInterval: e3.pollingInterval, messageCallback: (t4) => t4.eventIndex !== r3 ? Promise.resolve() : e3.messageCallback(n2(t4)), errorCallback: (t4, r4) => e3.errorCallback(t4, r4), onEventCountChanged: e3.onEventCountChanged, parallel: e3.parallel };
          return (0, h.subscribeToEvents)(o2, t3, i2);
        }
        function $(e3, t3) {
          return void 0 === e3.stdInterfaceId ? t3 : { ...t3, __stdInterfaceId: "414c5048" + e3.stdInterfaceId };
        }
        function V(e3, t3, r3, n2, i2) {
          const o2 = c.encodeMapPrefix(t3), s2 = c.encodeMapKey(r3, n2), a2 = (0, u.binToHex)(o2) + (0, u.binToHex)(s2);
          return (0, d.subContractId)(e3, a2, i2);
        }
        function G(e3) {
          return { names: ["value", "parentContractId"], types: [e3, "ByteVec"], isMutable: [true, false] };
        }
        function z(e3, t3, r3, n2) {
          const i2 = e3.mapsSig;
          if (void 0 === i2) return [];
          const o2 = [];
          return Object.keys(n2).forEach(((s2) => {
            const a2 = i2.names.findIndex(((e4) => e4 === s2));
            if (-1 === a2) throw new Error(`Map var ${s2} does not exist in contract ${e3.name}`);
            const f2 = i2.types[`${a2}`], h2 = (function(e4, t4, r4, n3, i3, o3) {
              const [s3, a3] = c.parseMapType(o3), f3 = (function(e5, t5) {
                const { immFields: r5, mutFields: n4 } = c.calcFieldSize(e5, true, t5), i4 = { isPublic: true, usePreapprovedAssets: false, useContractAssets: false, usePayToContractOnly: false, argsLength: 1, localsLength: 1, returnLength: 1, instrs: [(0, y.LoadLocal)(0), y.LoadImmFieldByIndex] }, o4 = r5, s4 = { fieldLength: r5 + n4 + 1, methods: [i4, { ...i4, instrs: [(0, y.LoadLocal)(0), y.LoadMutFieldByIndex] }, { ...i4, argsLength: 2, localsLength: 2, returnLength: 0, instrs: [y.CallerContractId, (0, y.LoadImmField)(o4), y.ByteVecEq, y.Assert, (0, y.LoadLocal)(0), (0, y.LoadLocal)(1), y.StoreMutFieldByIndex] }, { isPublic: true, usePreapprovedAssets: false, useContractAssets: true, usePayToContractOnly: false, argsLength: 1, localsLength: 1, returnLength: 0, instrs: [y.CallerContractId, (0, y.LoadImmField)(o4), y.ByteVecEq, y.Assert, (0, y.LoadLocal)(0), y.DestroySelf] }] }, a4 = y.contract.contractCodec.encodeContract(s4), d2 = p.blake2b(a4, void 0, 32);
                return { bytecode: (0, u.binToHex)(a4), codeHash: (0, u.binToHex)(d2) };
              })(a3, e4.structs);
              return Array.from(n3.entries()).map((([e5, n4]) => {
                const o4 = { value: n4, parentContractId: t4 }, c2 = V(t4, i3, e5, s3, r4);
                return { ...f3, address: (0, d.addressFromContractId)(c2), contractId: c2, fieldsSig: G(a3), fields: o4, asset: { alphAmount: l.ONE_ALPH } };
              }));
            })(e3, t3, r3, n2[`${s2}`], a2, f2);
            o2.push(...h2);
          })), o2;
        }
        function K(e3, t3, r3, n2, i2) {
          const o2 = t3.initialMaps ?? {}, s2 = t3.existingContracts ?? [], a2 = n2.contracts.filter(((t4) => t4.address === e3 || void 0 !== s2.find(((e4) => e4.address === t4.address)))), f2 = (function(e4, t4) {
            const r4 = [];
            return e4.events.forEach(((n3) => {
              if (n3.eventIndex === A.ContractCreatedEventIndex) {
                const i3 = n3.fields[0].value, o3 = e4.contracts.find(((e5) => e5.address === i3));
                void 0 === o3 || ((e5) => {
                  try {
                    return t4(e5), false;
                  } catch (e6) {
                    if (e6 instanceof Error && e6.message.includes("Unknown code with code hash")) return true;
                    throw e6;
                  }
                })(o3.codeHash) || r4.push(o3);
              }
            })), r4;
          })(n2, i2), h2 = [];
          return a2.concat(f2).forEach(((t4) => {
            const a3 = i2(t4.codeHash);
            if (void 0 !== a3.mapsSig) {
              const i3 = t4.address === e3 ? o2 : s2.find(((e4) => e4.address === t4.address))?.maps, f3 = (function(e4, t5, r4, n3, i4) {
                const o3 = (function(e5, t6) {
                  const r5 = e5.mapsSig;
                  return void 0 === r5 ? [] : r5.names.map(((e6, n4) => {
                    const i5 = r5.types[`${n4}`], o4 = t6[`${e6}`] ?? /* @__PURE__ */ new Map(), [s4, a5] = c.parseMapType(i5);
                    return { name: e6, value: o4, keyType: s4, valueType: a5, index: n4 };
                  }));
                })(e4, i4), s3 = (function(e5, t6, r5, n4, i5) {
                  const o4 = (0, u.binToHex)((0, d.contractIdFromAddress)(n4)), s4 = [];
                  return r5.forEach(((r6) => {
                    Array.from(r6.value.keys()).forEach(((n5) => {
                      const a5 = V(o4, r6.index, n5, r6.keyType, i5), c2 = t6.contracts.find(((e6) => e6.address === (0, d.addressFromContractId)(a5)));
                      if (void 0 === c2) return;
                      s4.push(c2.address);
                      const u2 = G(r6.valueType), f5 = T(c2.immFields, c2.mutFields, u2, e5.structs);
                      r6.value.set(n5, f5.value);
                    }));
                  })), s4;
                })(e4, n3, o3, t5, r4), a4 = (function(e5, t6, r5, n4, i5) {
                  const o4 = (0, u.binToHex)((0, d.contractIdFromAddress)(n4)), s4 = [];
                  return t6.debugMessages.forEach(((a5) => {
                    if (a5.contractAddress !== n4) return;
                    const u2 = c.tryDecodeMapDebugLog(a5.message);
                    if (void 0 === u2) return;
                    const f5 = r5[`${u2.mapIndex}`], h4 = c.decodePrimitive(u2.encodedKey, f5.keyType), l2 = (0, d.subContractId)(o4, u2.path, i5);
                    if (!u2.isInsert) return void f5.value.delete(h4);
                    const p2 = t6.contracts.find(((e6) => e6.address === (0, d.addressFromContractId)(l2)));
                    if (void 0 === p2) throw new Error(`Cannot find contract state for map value, map field: ${f5.name}, value type: ${f5.valueType}`);
                    s4.push(p2.address);
                    const b2 = G(f5.valueType), y2 = T(p2.immFields, p2.mutFields, b2, e5.structs);
                    f5.value.set(h4, y2.value);
                  })), s4;
                })(e4, n3, o3, t5, r4), f4 = s3.concat(a4), h3 = n3.contracts.filter(((e5) => void 0 === f4.find(((t6) => e5.address === t6))));
                return n3.contracts = h3, o3.reduce(((e5, t6) => (e5[`${t6.name}`] = t6.value, e5)), {});
              })(a3, t4.address, r3, n2, i3 ?? {});
              h2.push({ address: t4.address, maps: f3 });
            }
          })), h2;
        }
        function W(e3) {
          console.log(`> Contract @ ${e3.contractAddress} - ${e3.message}`);
        }
        async function J(e3, t3) {
          if ((0, u.isHexString)(e3) && 64 === e3.length) {
            const r3 = t3 ?? (0, f.getCurrentNodeProvider)();
            return (await r3.events.getEventsTxIdTxid(e3)).events.filter(((e4) => e4.eventIndex === A.DebugEventIndex)).map(((e4) => {
              if (1 === e4.fields.length && "ByteVec" === e4.fields[0].type) return { contractAddress: e4.contractAddress, message: (0, u.hexToString)(e4.fields[0].value) };
              throw new Error(`Invalid debug log: ${JSON.stringify(e4.fields)}`);
            }));
          }
          throw new Error(`Invalid tx id: ${e3}`);
        }
        async function Z(e3, t3) {
          const r3 = await J(e3, t3);
          r3.length > 0 && r3.forEach(((e4) => W(e4)));
        }
        async function X(e3, t3, r3, n2, i2) {
          const o2 = e3.mapsSig?.names.findIndex(((e4) => e4 === n2)), s2 = void 0 === o2 ? void 0 : e3.mapsSig?.types[`${o2}`];
          if (void 0 === s2) throw new Error(`Map ${n2} does not exist in contract ${e3.name}`);
          const [a2, u2] = c.parseMapType(s2), h2 = V(t3, o2, i2, a2, r3), l2 = (0, d.addressFromContractId)(h2);
          try {
            const t4 = await (0, f.getCurrentNodeProvider)().contracts.getContractsAddressState(l2), r4 = G(u2);
            return T(t4.immFields, t4.mutFields, r4, e3.structs).value;
          } catch (e4) {
            if (e4 instanceof Error && e4.message.includes("KeyNotFound")) return;
            throw new m.TraceableError(`Failed to get value from map ${n2}, key: ${i2}, parent contract id: ${t3}`, e4);
          }
        }
        function Y(e3) {
          if (e3 < 0 || e3 >= l.TOTAL_NUMBER_OF_GROUPS) throw new Error(`Invalid group index ${e3}, expected a value within the range [0, ${l.TOTAL_NUMBER_OF_GROUPS})`);
        }
        function Q(e3, t3, r3, n2) {
          if (r3.eventIndex !== n2 && !(n2 >= 0 && n2 < e3.eventsSig.length)) throw new Error("Invalid event index: " + r3.eventIndex + ", expected: " + n2);
          const i2 = e3.eventsSig[`${n2}`], o2 = I(r3.fields, i2);
          return { contractAddress: t3.address, blockHash: r3.blockHash, txId: r3.txId, eventIndex: r3.eventIndex, name: i2.name, fields: o2 };
        }
        function ee(e3) {
          if (e3 < 0 || e3 > 255) throw new Error(`StoreLocal index ${e3} must be between 0 and 255 inclusive`);
          return ie((0, y.StoreLocal)(e3));
        }
        function te(e3) {
          if (e3 < 0 || e3 > 255) throw new Error(`LoadLocal index ${e3} must be between 0 and 255 inclusive`);
          return ie((0, y.LoadLocal)(e3));
        }
        function re(e3) {
          return (0, u.binToHex)(y.i32Codec.encode(e3));
        }
        function ne(e3) {
          if (e3 < 0) throw new Error(`value ${e3} must be non-negative`);
          return e3 < 6 ? (BigInt(12) + e3).toString(16).padStart(2, "0") : ie((0, y.U256Const)(e3));
        }
        function ie(e3) {
          return (0, u.binToHex)(y.instrCodec.encode(e3));
        }
        t2.Script = C, t2.fromApiFields = T, t2.getDefaultValue = E, t2.fromApiArray = x, t2.fromApiEventFields = I, t2.randomTxId = N, u.assertType, t2.ContractFactory = class {
          constructor(e3) {
            this.contract = e3;
          }
          async deploy(e3, t3, r3) {
            const n2 = await this.contract.txParamsForDeployment(e3, { ...t3, initialFields: $(this.contract, t3.initialFields) }, r3), i2 = await e3.signAndSubmitDeployContractTx(n2);
            return { ...i2, contractInstance: this.at(i2.contractAddress) };
          }
          async deployTemplate(e3) {
            return this.deploy(e3, { initialFields: this.contract.getInitialFieldsWithDefaultValues() });
          }
          stateForTest_(e3, t3, r3, n2) {
            const i2 = { alphAmount: t3?.alphAmount ?? l.MINIMAL_CONTRACT_DEPOSIT, tokens: t3?.tokens };
            return { ...this.contract.toState($(this.contract, e3), i2, r3), bytecode: this.contract.bytecodeDebug, codeHash: this.contract.codeHash, maps: n2 };
          }
        }, t2.ExecutableScript = class {
          constructor(e3, t3) {
            this.script = e3, this.getContractByCodeHash = t3;
          }
          async execute(e3) {
            const t3 = await this.script.txParamsForExecution(e3);
            return await e3.signer.signAndSubmitExecuteScriptTx(t3);
          }
          async call(e3) {
            const t3 = this.script.functions.find(((e4) => "main" === e4.name));
            if (void 0 === t3) throw new Error(`There is no main function in script ${this.script.name}`);
            const r3 = this.script.buildByteCodeToDeploy(e3.initialFields), n2 = e3.txId ?? N(), i2 = (0, f.getCurrentNodeProvider)();
            return S(await i2.contracts.postContractsCallTxScript({ ...e3, group: e3.groupIndex ?? 0, bytecode: r3, inputAssets: O(e3.inputAssets) }), n2, t3.returnTypes, this.script.structs, this.getContractByCodeHash);
          }
        }, t2.CreateContractEventAddresses = Array.from(Array(l.TOTAL_NUMBER_OF_GROUPS).keys()).map(((e3) => L(A.ContractCreatedEventIndex, e3))), t2.DestroyContractEventAddresses = Array.from(Array(l.TOTAL_NUMBER_OF_GROUPS).keys()).map(((e3) => L(A.ContractDestroyedEventIndex, e3))), t2.decodeContractCreatedEvent = F, t2.decodeContractDestroyedEvent = H, t2.subscribeEventsFromContract = q, t2.addStdIdToFields = $, t2.extractMapsFromApiResult = K, t2.testMethod = async function(e3, t3, r3, n2) {
          const i2 = r3?.txId ?? N(), o2 = e3.contract, s2 = r3.contractAddress ?? (0, d.addressFromContractId)((0, u.binToHex)(g.getRandomValues(new Uint8Array(32)))), a2 = (0, u.binToHex)((0, d.contractIdFromAddress)(s2)), c2 = r3.group ?? 0, h2 = (function(e4, t4, r4, n3, i3) {
            const o3 = n3.initialMaps ?? {}, s3 = z(e4, t4, r4, o3), a3 = n3.existingContracts ?? [], c3 = a3.flatMap(((e5) => void 0 !== e5.maps ? z(i3(e5.codeHash), e5.contractId, r4, e5.maps ?? {}) : []));
            return a3.concat(s3, c3);
          })(o2, a2, c2, r3, n2), l2 = o2.toApiTestContractParams(t3, { ...r3, contractAddress: s2, txId: i2, initialFields: $(o2, r3.initialFields ?? {}), args: void 0 === r3.args ? {} : r3.args, existingContracts: h2 }), p2 = await (0, f.getCurrentNodeProvider)().contracts.postContractsTestContract(l2), b2 = K(s2, r3, c2, p2, n2), y2 = o2.fromApiTestContractResult(t3, p2, i2, n2);
          return y2.contracts.forEach(((e4) => {
            const t4 = b2.find(((t5) => t5.address === e4.address))?.maps;
            void 0 !== t4 && (e4.maps = t4);
          })), o2.printDebugMessages(t3, y2.debugMessages), { ...y2, maps: b2.find(((e4) => e4.address === s2))?.maps };
        }, t2.getDebugMessagesFromTx = J, t2.printDebugMessagesFromTx = Z, t2.RalphMap = class {
          constructor(e3, t3, r3) {
            this.parentContract = e3, this.parentContractId = t3, this.mapName = r3, this.groupIndex = (0, d.groupOfAddress)((0, d.addressFromContractId)(t3));
          }
          async get(e3) {
            return X(this.parentContract, this.parentContractId, this.groupIndex, this.mapName, e3);
          }
          async contains(e3) {
            return this.get(e3).then(((e4) => void 0 !== e4));
          }
          toJSON() {
            return { parentContractId: this.parentContractId, mapName: this.mapName, groupIndex: this.groupIndex };
          }
        }, t2.getMapItem = X, t2.ContractInstance = class {
          constructor(e3) {
            this.address = e3, this.contractId = (0, u.binToHex)((0, d.contractIdFromAddress)(e3)), this.groupIndex = (0, d.groupOfAddress)(e3);
          }
        }, t2.fetchContractState = async function(e3, t3) {
          const r3 = await (0, f.getCurrentNodeProvider)().contracts.getContractsAddressState(t3.address), n2 = e3.contract.fromApiContractState(r3);
          return { ...n2, fields: n2.fields };
        }, t2.subscribeContractCreatedEvent = function(e3, r3, n2) {
          Y(r3);
          const i2 = t2.CreateContractEventAddresses[`${r3}`];
          return q(e3, i2, A.ContractCreatedEventIndex, ((e4) => ({ ...F(e4), contractAddress: i2 })), n2);
        }, t2.subscribeContractDestroyedEvent = function(e3, r3, n2) {
          Y(r3);
          const i2 = t2.DestroyContractEventAddresses[`${r3}`];
          return q(e3, i2, A.ContractDestroyedEventIndex, ((e4) => ({ ...H(e4), contractAddress: i2 })), n2);
        }, t2.decodeEvent = Q, t2.subscribeContractEvent = function(e3, t3, r3, n2, i2) {
          const o2 = e3.eventsSig.findIndex(((e4) => e4.name === n2));
          return q(r3, t3.address, o2, ((r4) => Q(e3, t3, r4, o2)), i2);
        }, t2.subscribeContractEvents = function(e3, t3, r3, n2) {
          const i2 = { pollingInterval: r3.pollingInterval, messageCallback: (n3) => r3.messageCallback({ ...Q(e3, t3, n3, n3.eventIndex), contractAddress: t3.address }), errorCallback: (e4, t4) => r3.errorCallback(e4, t4), onEventCountChanged: r3.onEventCountChanged, parallel: r3.parallel };
          return (0, h.subscribeToEvents)(i2, t3.address, n2);
        }, t2.callMethod = async function(e3, t3, r3, n2, i2) {
          const o2 = e3.contract.getMethodIndex(r3), s2 = n2?.txId ?? N(), a2 = e3.contract.toApiCallContract({ ...n2, txId: s2, args: void 0 === n2.args ? {} : n2.args }, t3.groupIndex, t3.address, o2), c2 = await (0, f.getCurrentNodeProvider)().contracts.postContractsCallContract(a2), u2 = e3.contract.fromApiCallContractResult(c2, s2, o2, i2);
          return e3.contract.printDebugMessages(r3, u2.debugMessages), u2;
        }, t2.signExecuteMethod = async function(e3, t3, r3, n2) {
          const i2 = e3.contract.getMethodIndex(r3), o2 = e3.contract.functions[i2], s2 = await e3.contract.isDevnet(n2.signer), a2 = (function(e4, t4, r4, n3, i3, o3) {
            const s3 = void 0 !== i3 || void 0 !== o3, a3 = s3 ? "03" : "00";
            if (t4 && !s3) throw new Error("The contract call requires preapproved assets but none are provided");
            const [d3, f3] = (function(e5, t5) {
              let r5 = 1, n4 = 0;
              const i4 = [];
              return e5.paramTypes.forEach(((e6) => {
                const o4 = c.typeLength(e6, t5);
                if (o4 > 1) {
                  for (let e7 = 0; e7 < o4; e7++) i4.push(`{${r5 + e7}}`);
                  for (let e7 = 0; e7 < o4; e7++) i4.push(ee(n4 + (o4 - e7 - 1)));
                  n4 += o4;
                }
                r5 += o4;
              })), [i4, r5];
            })(r4, n3), h3 = (function(e5) {
              const t5 = [];
              if (e5) {
                const r5 = ne(BigInt(e5));
                t5.push(r5), t5.push(ie(y.ApproveAlph));
              }
              return t5;
            })(t4 ? i3 : void 0), l3 = (function(e5) {
              const t5 = [];
              return e5 && e5.forEach(((e6) => {
                const r5 = (0, u.hexToBinUnsafe)(e6.id);
                t5.push(ie((0, y.BytesConst)(r5))), t5.push(ne(BigInt(e6.amount))), t5.push(ie(y.ApproveToken));
              })), t5;
            })(t4 ? o3 : void 0), p3 = (function(e5) {
              const t5 = [];
              if (e5 > 0) {
                t5.push(ie(y.CallerAddress));
                const r5 = ie(y.Dup);
                e5 > 1 && t5.push(...new Array(e5 - 1).fill(r5));
              }
              return t5;
            })(h3.length / 2 + l3.length / 3), b2 = ne(BigInt(f3 - 1)), m3 = re(d3.length / 2), g2 = (function(e5, t5) {
              let r5 = 1, n4 = 0;
              const i4 = [];
              return e5.paramTypes.forEach(((e6) => {
                const o4 = c.typeLength(e6, t5);
                if (1 === o4 && i4.push(`{${r5}}`), o4 > 1) {
                  for (let e7 = 0; e7 < o4; e7++) i4.push(te(n4 + e7));
                  n4 += o4;
                }
                r5 += o4;
              })), i4;
            })(r4, n3), v2 = r4.returnTypes.reduce(((e5, t5) => e5 + c.typeLength(t5, n3)), 0), w2 = ie(y.Pop).repeat(v2), _2 = ne(BigInt(v2)), A2 = ie((0, y.CallExternal)(e4));
            return "0101" + a3 + "00" + m3 + "00" + re(p3.length + h3.length + l3.length + d3.length + g2.length + v2 + 4) + p3.join("") + h3.join("") + l3.join("") + d3.join("") + g2.join("") + b2 + _2 + "{0}" + A2 + w2;
          })(i2, e3.contract.isMethodUsePreapprovedAssets(s2, i2), o2, e3.contract.structs, n2.attoAlphAmount, n2.tokens), d2 = (function(e4, t4) {
            return { names: ["__contract__"].concat(t4.paramNames), types: [e4].concat(t4.paramTypes), isMutable: [false].concat(t4.paramIsMutable) };
          })(e3.contract.name, o2), f2 = c.buildScriptByteCode(a2, { __contract__: t3.contractId, ...n2.args }, d2, e3.contract.structs), h2 = n2.signer, l2 = await h2.getSelectedAccount(), p2 = { signerAddress: l2.address, signerKeyType: l2.keyType, bytecode: f2, attoAlphAmount: n2.attoAlphAmount, tokens: n2.tokens, gasAmount: n2.gasAmount, gasPrice: n2.gasPrice, group: t3.groupIndex, dustAmount: n2.dustAmount }, m2 = await h2.signAndSubmitExecuteScriptTx(p2);
          return (0, b.isContractDebugMessageEnabled)() && s2 && await Z(m2.txId, h2.nodeProvider), m2;
        }, t2.multicallMethods = async function(e3, t3, r3, n2) {
          const i2 = (Array.isArray(r3) ? r3 : [r3]).map(((e4) => Object.entries(e4))), o2 = i2.map(((r4) => r4.map(((r5) => {
            const [n3, i3] = r5, o3 = e3.contract.getMethodIndex(n3), s3 = i3?.txId ?? N();
            return e3.contract.toApiCallContract({ ...i3, txId: s3, args: void 0 === i3.args ? {} : i3.args }, t3.groupIndex, t3.address, o3);
          })))), s2 = await (0, f.getCurrentNodeProvider)().contracts.postContractsMulticallContract({ calls: o2.flat() });
          let a2 = 0;
          const c2 = o2.map(((t4, r4) => {
            const o3 = {}, c3 = i2[`${r4}`];
            return t4.forEach(((t5, r5) => {
              const i3 = t5.methodIndex, u2 = s2.results[`${a2}`], d2 = c3[`${r5}`][0];
              o3[`${d2}`] = e3.contract.fromApiCallContractResult(u2, t5.txId, i3, n2), a2 += 1;
            })), o3;
          }));
          return Array.isArray(r3) ? c2 : c2[0];
        }, t2.getContractEventsCurrentCount = async function(e3) {
          return (0, f.getCurrentNodeProvider)().events.getEventsContractContractaddressCurrentCount(e3).catch(((t3) => {
            if (t3 instanceof Error && t3.message.includes(`${e3} not found`)) return 0;
            throw new m.TraceableError(`Failed to get the event count for the contract ${e3}`, t3);
          }));
        }, t2.getContractIdFromUnsignedTx = async (e3, t3) => {
          const r3 = await e3.transactions.postTransactionsDecodeUnsignedTx({ unsignedTx: t3 }), n2 = r3.unsignedTx.fixedOutputs.length, i2 = r3.unsignedTx.txId + n2.toString(16).padStart(8, "0");
          return (0, u.binToHex)(p.blake2b((0, u.hexToBinUnsafe)(i2), void 0, 32)).slice(0, 62) + r3.fromGroup.toString(16).padStart(2, "0");
        }, t2.getTokenIdFromUnsignedTx = t2.getContractIdFromUnsignedTx, t2.getContractCodeByCodeHash = async function(e3, t3) {
          if ((0, u.isHexString)(t3) && 64 === t3.length) try {
            return await e3.contracts.getContractsCodehashCode(t3);
          } catch (e4) {
            if (e4 instanceof Error && e4.message.includes("not found")) return;
            throw new m.TraceableError(`Failed to get contract by code hash ${t3}`, e4);
          }
          throw new Error(`Invalid code hash: ${t3}`);
        };
      }, 2897: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.genArgs = t2.DappTransactionBuilder = void 0;
        const n = r2(2581), i = r2(3651), o = r2(1678), s = r2(4459), a = r2(7695), c = r2(4652), u = r2(664);
        function d(e3, t3) {
          if (0 === t3.length) return [];
          const r3 = t3.flatMap(((e4) => e4.id === a.ALPH_TOKEN_ID ? [(0, i.U256Const)(e4.amount), i.ApproveAlph] : [(0, i.BytesConst)((0, u.hexToBinUnsafe)(e4.id)), (0, i.U256Const)(e4.amount), i.ApproveToken]));
          return [(0, i.AddressConst)(e3), ...Array.from(Array(t3.length - 1).keys()).map((() => i.Dup)), ...r3];
        }
        function f(e3) {
          return e3 >= 0 ? (0, i.toU256)(e3) : (0, i.toI256)(e3);
        }
        function h(e3) {
          return e3.flatMap(((e4) => {
            if ("boolean" == typeof e4) return e4 ? [i.ConstTrue] : [i.ConstFalse];
            if ("bigint" == typeof e4) return f(e4);
            if ("string" == typeof e4) {
              if ((0, u.isHexString)(e4)) return [(0, i.BytesConst)((0, u.hexToBinUnsafe)(e4))];
              const t3 = (function(e5) {
                if ((0, u.isBase58)(e5)) try {
                  return o.lockupScriptCodec.decode((0, u.base58ToBytes)(e5));
                } catch (e6) {
                  return;
                }
              })(e4);
              return void 0 !== t3 ? (0, i.AddressConst)(t3) : (function(e5) {
                if (/^-?\d+[ui]?$/.test(e5)) return e5.endsWith("i") ? (0, i.toI256)(BigInt(e5.slice(0, e5.length - 1))) : e5.endsWith("u") ? (0, i.toU256)(BigInt(e5.slice(0, e5.length - 1))) : f(BigInt(e5));
                throw new Error(`Invalid number: ${e5}`);
              })(e4);
            }
            if (Array.isArray(e4)) return h(e4);
            if (e4 instanceof Map) throw new Error("Map cannot be used as a function argument");
            if ("object" == typeof e4) return h(Object.values(e4));
            throw new Error(`Unknown argument type: ${typeof e4}, arg: ${e4}`);
          }));
        }
        function l(e3, t3, r3, o2) {
          const s2 = h(r3);
          return [...s2, (0, i.toU256)(BigInt(s2.length)), (0, i.toU256)(BigInt(o2)), (0, i.BytesConst)((0, n.contractIdFromAddress)(e3)), (0, i.CallExternal)(t3), ...Array.from(Array(o2).keys()).map((() => i.Pop))];
        }
        t2.DappTransactionBuilder = class {
          constructor(e3) {
            this.callerAddress = e3;
            try {
              if (this.callerLockupScript = o.lockupScriptCodec.decode((0, u.base58ToBytes)(this.callerAddress)), "P2PKH" !== this.callerLockupScript.kind && "P2SH" !== this.callerLockupScript.kind) throw new Error("Expected a P2PKH address or P2SH address");
            } catch (t3) {
              throw new c.TraceableError(`Invalid caller address: ${e3}`, t3);
            }
            this.approvedAssets = /* @__PURE__ */ new Map(), this.instrs = [];
          }
          callContract(e3) {
            if (!(0, u.isBase58)(e3.contractAddress)) throw new Error(`Invalid contract address: ${e3.contractAddress}, expected a base58 string`);
            if (!(0, n.isContractAddress)(e3.contractAddress)) throw new Error(`Invalid contract address: ${e3.contractAddress}, expected a P2C address`);
            if (e3.methodIndex < 0) throw new Error(`Invalid method index: ${e3.methodIndex}`);
            const t3 = (e3.tokens ?? []).concat([{ id: a.ALPH_TOKEN_ID, amount: e3.attoAlphAmount ?? 0n }]), r3 = [...d(this.callerLockupScript, this.approveTokens(t3)), ...l(e3.contractAddress, e3.methodIndex, e3.args, e3.retLength ?? 0)];
            return this.instrs.push(...r3), this;
          }
          getResult() {
            const e3 = { methods: [{ isPublic: true, usePreapprovedAssets: this.approvedAssets.size > 0, useContractAssets: false, usePayToContractOnly: false, argsLength: 0, localsLength: 0, returnLength: 0, instrs: this.instrs }] }, t3 = s.scriptCodec.encode(e3), r3 = Array.from(this.approvedAssets.entries()).map((([e4, t4]) => ({ id: e4, amount: t4 })));
            return this.approvedAssets.clear(), this.instrs = [], { signerAddress: this.callerAddress, signerKeyType: "P2PKH" === this.callerLockupScript.kind ? "default" : "bip340-schnorr", bytecode: (0, u.binToHex)(t3), attoAlphAmount: r3.find(((e4) => e4.id === a.ALPH_TOKEN_ID))?.amount, tokens: r3.filter(((e4) => e4.id !== a.ALPH_TOKEN_ID)) };
          }
          addTokenToMap(e3, t3, r3) {
            const n2 = r3.get(e3);
            void 0 !== n2 ? r3.set(e3, n2 + t3) : t3 > 0n && r3.set(e3, t3);
          }
          approveTokens(e3) {
            const t3 = /* @__PURE__ */ new Map();
            return e3.forEach(((e4) => {
              if (!(0, u.isHexString)(e4.id) || 64 !== e4.id.length) throw new Error(`Invalid token id: ${e4.id}`);
              if (e4.amount < 0n) throw new Error(`Invalid token amount: ${e4.amount}`);
              this.addTokenToMap(e4.id, e4.amount, t3), this.addTokenToMap(e4.id, e4.amount, this.approvedAssets);
            })), Array.from(t3.entries()).map((([e4, t4]) => ({ id: e4, amount: t4 })));
          }
        }, t2.genArgs = h;
      }, 2282: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true });
      }, 4964: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.subscribeToEvents = t2.EventSubscription = void 0;
        const s = o(r2(307)), a = r2(664);
        class c extends a.Subscription {
          constructor(e3, t3, r3) {
            super(e3), this.parallel = false, this.contractAddress = t3, this.fromCount = void 0 === r3 ? 0 : r3, this.onEventCountChanged = e3.onEventCountChanged, this.parallel = e3.parallel ?? false;
          }
          currentEventCount() {
            return this.fromCount;
          }
          async getEvents(e3) {
            try {
              return await s.getCurrentNodeProvider().events.getEventsContractContractaddress(this.contractAddress, { start: e3 });
            } catch (t3) {
              if (t3 instanceof Error && t3.message.includes(`Contract events of ${this.contractAddress} not found`)) return { events: [], nextStart: e3 };
              throw t3;
            }
          }
          async polling() {
            try {
              const e3 = await this.getEvents(this.fromCount);
              if (this.fromCount === e3.nextStart) return;
              if (this.parallel) {
                const t3 = e3.events.map(((e4) => this.messageCallback(e4)));
                await Promise.all(t3);
              } else for (const t3 of e3.events) await this.messageCallback(t3);
              this.fromCount = e3.nextStart, void 0 !== this.onEventCountChanged && await this.onEventCountChanged(this.fromCount), await this.polling();
            } catch (e3) {
              await this.errorCallback(e3, this);
            }
          }
        }
        t2.EventSubscription = c, t2.subscribeToEvents = function(e3, t3, r3) {
          const n2 = new c(e3, t3, r3);
          return n2.subscribe(), n2;
        };
      }, 5033: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.DappTransactionBuilder = void 0, i(r2(8486), t2), i(r2(5143), t2), i(r2(4964), t2), i(r2(4529), t2), i(r2(2282), t2);
        var o = r2(2897);
        Object.defineProperty(t2, "DappTransactionBuilder", { enumerable: true, get: function() {
          return o.DappTransactionBuilder;
        } });
      }, 8486: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.buildDebugBytecode = t2.encodeContractField = t2.buildContractByteCode = t2.encodeContractFields = t2.buildScriptByteCode = t2.flattenFields = t2.typeLength = t2.encodeMapKey = t2.decodePrimitive = t2.tryDecodeMapDebugLog = t2.calcFieldSize = t2.encodeMapPrefix = t2.parseMapType = t2.splitFields = t2.encodeScriptField = t2.encodeScriptFieldAsString = t2.encodePrimitiveValues = t2.addressVal = t2.byteVecVal = t2.u256Val = t2.i256Val = t2.boolVal = t2.encodeVmAddress = t2.encodeVmByteVec = t2.encodeVmU256 = t2.encodeVmI256 = t2.encodeVmBool = t2.VmValType = t2.encodeAddress = t2.encodeByteVec = void 0;
        const n = r2(3749), i = r2(664), o = r2(3651), s = r2(2709), a = r2(4652), c = r2(2581);
        function u(e3) {
          if (!(0, i.isHexString)(e3)) throw Error(`Given value ${e3} is not a valid hex string`);
          const t3 = (0, i.hexToBinUnsafe)(e3);
          return o.byteStringCodec.encode(t3);
        }
        function d(e3) {
          return (0, c.addressToBytes)(e3);
        }
        var f;
        function h(e3) {
          return new Uint8Array([f.Bool, ...s.boolCodec.encode(e3)]);
        }
        function l(e3) {
          return new Uint8Array([f.I256, ...o.i256Codec.encode(e3)]);
        }
        function p(e3) {
          return new Uint8Array([f.U256, ...o.u256Codec.encode(e3)]);
        }
        function b(e3) {
          return new Uint8Array([f.ByteVec, ...u(e3)]);
        }
        function y(e3) {
          return new Uint8Array([f.Address, ...d(e3)]);
        }
        function m(e3, t3) {
          return (0, i.binToHex)(g(e3, t3));
        }
        function g(e3, t3) {
          switch (e3) {
            case "Bool":
              const e4 = (0, n.toApiBoolean)(t3) ? o.ConstTrue.code : o.ConstFalse.code;
              return new Uint8Array([e4]);
            case "I256":
              const r3 = (0, n.toApiNumber256)(t3);
              return (function(e5) {
                return o.instrCodec.encode((0, o.toI256)(e5));
              })(BigInt(r3));
            case "U256":
              const i2 = (0, n.toApiNumber256)(t3);
              return (function(e5) {
                return o.instrCodec.encode((0, o.toU256)(e5));
              })(BigInt(i2));
            case "Address":
              const s2 = (0, n.toApiAddress)(t3);
              return new Uint8Array([o.AddressConstCode, ...d(s2)]);
            default:
              const a2 = (0, n.toApiByteVec)(t3);
              return new Uint8Array([o.BytesConstCode, ...u(a2)]);
          }
          throw (function(e4, t4) {
            return Error(`Invalid script field ${t4} for type ${e4}`);
          })(e3, t3);
        }
        function v(e3, t3, r3, n2, i2) {
          return t3.flatMap(((t4, o2) => {
            if (!(t4 in e3)) throw new Error(`The value of field ${t4} is not provided`);
            return w(n2[`${o2}`], t4, r3[`${o2}`], e3[`${t4}`], i2);
          }));
        }
        function w(e3, t3, r3, i2, o2) {
          if (Array.isArray(i2) && r3.startsWith("[")) {
            const [s3, a3] = (0, n.decodeArrayType)(r3);
            if (i2.length !== a3) throw Error(`Invalid array length, expected ${a3}, got ${i2.length}`);
            return i2.flatMap(((r4, n2) => w(e3, `${t3}[${n2}]`, s3, r4, o2)));
          }
          if (Array.isArray(i2) && r3.startsWith("(")) {
            const s3 = (0, n.decodeTupleType)(r3);
            if (i2.length !== s3.length) throw Error(`Invalid tuple length, expected ${s3.length}, got ${i2.length}`);
            return s3.flatMap(((r4, n2) => w(e3, `${t3}._${n2}`, r4, i2[`${n2}`], o2)));
          }
          const s2 = o2.find(((e4) => e4.name === r3));
          if (void 0 !== s2) {
            if ("object" != typeof i2) throw Error("Expected an object, but got " + typeof i2);
            return s2.fieldNames.flatMap(((r4, n2) => {
              if (!(r4 in i2)) throw new Error(`The value of field ${r4} is not provided`);
              const a3 = s2.isMutable[`${n2}`], c2 = s2.fieldTypes[`${n2}`], u2 = i2[`${r4}`];
              return w(e3 && a3, `${t3}.${r4}`, c2, u2, o2);
            }));
          }
          const a2 = (function(e4, t4, r4) {
            const n2 = typeof r4;
            if ("Bool" === t4 && "boolean" === n2) return t4;
            if (!("U256" !== t4 && "I256" !== t4 || "string" !== n2 && "number" !== n2 && "bigint" !== n2)) return t4;
            if (("Address" === t4 || "ByteVec" === t4) && "string" === n2) return t4;
            if (!t4.startsWith("[") && "string" === n2) return "ByteVec";
            throw Error(`Invalid value ${r4} for ${e4}, expected a value of type ${t4}`);
          })(t3, r3, i2);
          return [{ name: t3, type: a2, value: i2, isMutable: e3 }];
        }
        t2.encodeByteVec = u, t2.encodeAddress = d, (function(e3) {
          e3[e3.Bool = 0] = "Bool", e3[e3.I256 = 1] = "I256", e3[e3.U256 = 2] = "U256", e3[e3.ByteVec = 3] = "ByteVec", e3[e3.Address = 4] = "Address";
        })(f = t2.VmValType || (t2.VmValType = {})), t2.encodeVmBool = h, t2.encodeVmI256 = l, t2.encodeVmU256 = p, t2.encodeVmByteVec = b, t2.encodeVmAddress = y, t2.boolVal = function(e3) {
          return { type: "Bool", value: e3 };
        }, t2.i256Val = function(e3) {
          return { type: "I256", value: BigInt(e3) };
        }, t2.u256Val = function(e3) {
          return { type: "U256", value: BigInt(e3) };
        }, t2.byteVecVal = function(e3) {
          return { type: "ByteVec", value: e3 };
        }, t2.addressVal = function(e3) {
          return { type: "Address", value: e3 };
        }, t2.encodePrimitiveValues = function(e3) {
          return S(e3.map((({ type: e4, value: t3 }) => ({ name: `${t3}`, type: e4, value: t3 }))));
        }, t2.encodeScriptFieldAsString = m, t2.encodeScriptField = g, t2.splitFields = function(e3) {
          return e3.types.reduce((([t3, r3], n2, i2) => {
            const o2 = n2.startsWith("Map[") ? t3 : r3;
            return o2.names.push(e3.names[`${i2}`]), o2.types.push(n2), o2.isMutable.push(e3.isMutable[`${i2}`]), [t3, r3];
          }), [{ names: [], types: [], isMutable: [] }, { names: [], types: [], isMutable: [] }]);
        }, t2.parseMapType = function(e3) {
          if (!e3.startsWith("Map[")) throw new Error(`Expected map type, got ${e3}`);
          const t3 = e3.indexOf("["), r3 = e3.indexOf(",");
          return [e3.slice(t3 + 1, r3), e3.slice(r3 + 1, e3.length - 1)];
        }, t2.encodeMapPrefix = function(e3) {
          const t3 = `__map__${e3}__`, r3 = new Uint8Array(t3.length);
          for (let e4 = 0; e4 < t3.length; e4 += 1) r3[e4] = t3.charCodeAt(e4);
          return r3;
        }, t2.calcFieldSize = function e3(t3, r3, i2) {
          const o2 = i2.find(((e4) => e4.name === t3));
          if (void 0 !== o2) return o2.fieldTypes.reduce(((t4, n2, s2) => {
            const a2 = e3(n2, r3 && o2.isMutable[`${s2}`], i2);
            return { immFields: t4.immFields + a2.immFields, mutFields: t4.mutFields + a2.mutFields };
          }), { immFields: 0, mutFields: 0 });
          if (t3.startsWith("[")) {
            const [o3, s2] = (0, n.decodeArrayType)(t3), a2 = e3(o3, r3, i2);
            return { immFields: a2.immFields * s2, mutFields: a2.mutFields * s2 };
          }
          return t3.startsWith("(") ? (0, n.decodeTupleType)(t3).reduce(((t4, n2) => {
            const o3 = e3(n2, r3, i2);
            return { immFields: t4.immFields + o3.immFields, mutFields: t4.mutFields + o3.mutFields };
          }), { immFields: 0, mutFields: 0 }) : r3 ? { immFields: 0, mutFields: 1 } : { immFields: 1, mutFields: 0 };
        }, t2.tryDecodeMapDebugLog = function(e3) {
          if (!e3.startsWith("insert at map path: ") && !e3.startsWith("remove at map path: ")) return;
          const t3 = e3.split(":");
          if (2 !== t3.length) return;
          const r3 = t3[1].slice(1);
          if (!(0, i.isHexString)(r3)) return;
          const n2 = r3.slice(14), o2 = n2.indexOf("5f5f");
          if (-1 === o2) return;
          const s2 = n2.slice(0, o2);
          return { path: r3, mapIndex: parseInt((function(e4) {
            let t4 = "";
            for (let r4 = 0; r4 < e4.length; r4 += 2) {
              const n3 = parseInt(e4.slice(r4, r4 + 2), 16);
              t4 += String.fromCharCode(n3);
            }
            return t4;
          })(s2)), encodedKey: (0, i.hexToBinUnsafe)(n2.slice(o2 + 4)), isInsert: e3.startsWith("insert") };
        }, t2.decodePrimitive = function(e3, t3) {
          switch (t3) {
            case "Bool":
              return s.boolCodec.decode(e3);
            case "I256":
              return o.i256Codec.decode(e3);
            case "U256":
              return o.u256Codec.decode(e3);
            case "ByteVec":
              return (0, i.binToHex)(e3);
            case "Address":
              return i.bs58.encode(e3);
            default:
              throw Error(`Expected primitive type, got ${t3}`);
          }
        }, t2.encodeMapKey = function(e3, t3) {
          switch (t3) {
            case "Bool":
              const r3 = (0, n.toApiBoolean)(e3) ? 1 : 0;
              return new Uint8Array([r3]);
            case "I256":
              const s2 = (0, n.toApiNumber256)(e3);
              return o.i256Codec.encode(BigInt(s2));
            case "U256":
              const a2 = (0, n.toApiNumber256)(e3);
              return o.u256Codec.encode(BigInt(a2));
            case "ByteVec":
              const c2 = (0, n.toApiByteVec)(e3);
              return (0, i.hexToBinUnsafe)(c2);
            case "Address":
              return d((0, n.toApiAddress)(e3));
            default:
              throw Error(`Expected primitive type, got ${t3}`);
          }
        }, t2.typeLength = function e3(t3, r3) {
          if (n.PrimitiveTypes.includes(t3)) return 1;
          if (t3.startsWith("[")) {
            const [i3, o2] = (0, n.decodeArrayType)(t3);
            return o2 * e3(i3, r3);
          }
          if (t3.startsWith("(")) return (0, n.decodeTupleType)(t3).reduce(((t4, n2) => t4 + e3(n2, r3)), 0);
          const i2 = r3.find(((e4) => e4.name === t3));
          return void 0 !== i2 ? i2.fieldTypes.reduce(((t4, n2) => t4 + e3(n2, r3)), 0) : 1;
        }, t2.flattenFields = v;
        const _ = /\{([0-9]*)\}/g;
        function A(e3, t3) {
          try {
            return t3();
          } catch (t4) {
            throw new a.TraceableError(`Failed to encode the field ${e3}`, t4);
          }
        }
        function S(e3) {
          const t3 = o.i32Codec.encode(e3.length);
          return e3.reduce(((e4, t4) => {
            const r3 = A(t4.name, (() => T(t4.type, t4.value))), n2 = new Uint8Array(e4.byteLength + r3.byteLength);
            return n2.set(e4, 0), n2.set(r3, e4.byteLength), n2;
          }), t3);
        }
        function C(e3, t3, r3) {
          const n2 = v(e3, t3.names, t3.types, t3.isMutable, r3);
          return { encodedImmFields: S(n2.filter(((e4) => !e4.isMutable))), encodedMutFields: S(n2.filter(((e4) => e4.isMutable))) };
        }
        function T(e3, t3) {
          switch (e3) {
            case "Bool":
              return h((0, n.toApiBoolean)(t3));
            case "I256":
              return l(BigInt((0, n.toApiNumber256)(t3)));
            case "U256":
              return p(BigInt((0, n.toApiNumber256)(t3)));
            case "ByteVec":
              return b((0, n.toApiByteVec)(t3));
            case "Address":
              return y((0, n.toApiAddress)(t3));
            default:
              throw Error(`Expected primitive type, got ${e3}`);
          }
        }
        t2.buildScriptByteCode = function(e3, t3, r3, n2) {
          const i2 = v(t3, r3.names, r3.types, r3.isMutable, n2);
          return e3.replace(_, ((e4, t4) => {
            const r4 = i2[`${t4}`];
            return A(r4.name, (() => m(r4.type, r4.value)));
          }));
        }, t2.encodeContractFields = C, t2.buildContractByteCode = function(e3, t3, r3, n2) {
          const { encodedImmFields: o2, encodedMutFields: s2 } = C(t3, r3, n2);
          return e3 + (0, i.binToHex)(o2) + (0, i.binToHex)(s2);
        }, t2.encodeContractField = T, t2.buildDebugBytecode = function(e3, t3) {
          if ("" === t3) return e3;
          const r3 = /[=+-][0-9a-f]*/g;
          let n2 = "", i2 = 0;
          for (const o2 of t3.matchAll(r3)) {
            const t4 = o2[0], r4 = t4[0];
            if ("=" === r4) {
              const r5 = parseInt(t4.substring(1));
              n2 += e3.slice(i2, i2 + r5), i2 += r5;
            } else "+" === r4 ? n2 += t4.substring(1) : i2 += parseInt(t4.substring(1));
          }
          return n2;
        };
      }, 4529: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.ScriptSimulator = void 0;
        const n = r2(2581), i = r2(3651), o = r2(1678), s = r2(7695), a = r2(664);
        function c(e3, t3, r3, n2) {
          n2(e3.kind.startsWith("Symbol") ? e3 : t3.kind.startsWith("Symbol") ? t3 : { kind: e3.kind, value: r3(e3.value, t3.value) });
        }
        function u(e3, t3, r3, n2) {
          n2(e3.kind.startsWith("Symbol") || t3.kind.startsWith("Symbol") ? { kind: "Symbol-Bool", value: void 0 } : { kind: "Bool", value: r3(e3.value, t3.value) });
        }
        function d(e3, t3) {
          return e3.length === t3.length && e3.every(((e4, r3) => e4 === t3[`${r3}`]));
        }
        function f() {
          const e3 = new Uint8Array(32);
          for (let t3 = 0; t3 < 32; t3++) e3[`${t3}`] = Math.floor(256 * Math.random());
          return e3;
        }
        t2.ScriptSimulator = class {
          static extractContractCalls(e3) {
            try {
              return this.extractContractCallsWithErrors(e3);
            } catch (e4) {
              return console.debug("Error extracting contract calls from script", e4), [];
            }
          }
          static extractContractCallsWithErrors(e3) {
            const t3 = (0, a.hexToBinUnsafe)(e3), r3 = i.unsignedTxCodec.decode(t3).statefulScript;
            switch (r3.kind) {
              case "Some":
                return this.extractContractCallsFromScript(r3.value);
              case "None":
                return [];
            }
          }
          static extractContractCallsFromScript(e3) {
            const t3 = e3.methods;
            if (0 === t3.length) return [];
            const r3 = t3[0];
            return this.extractContractCallsFromMainMethod(r3);
          }
          static extractContractCallsFromMainMethod(e3) {
            const t3 = new h(), r3 = new l(), s2 = [], m = { kind: "Address", value: { kind: "P2PKH", value: f() } }, g = new y();
            for (const f2 of e3.instrs) switch (f2.name) {
              case "ConstTrue":
                t3.push({ kind: "Bool", value: true });
                break;
              case "ConstFalse":
                t3.push({ kind: "Bool", value: false });
                break;
              case "I256Const0":
                t3.push({ kind: "I256", value: 0n });
                break;
              case "I256Const1":
                t3.push({ kind: "I256", value: 1n });
                break;
              case "I256Const2":
                t3.push({ kind: "I256", value: 2n });
                break;
              case "I256Const3":
                t3.push({ kind: "I256", value: 3n });
                break;
              case "I256Const4":
                t3.push({ kind: "I256", value: 4n });
                break;
              case "I256Const5":
                t3.push({ kind: "I256", value: 5n });
                break;
              case "I256ConstN1":
                t3.push({ kind: "I256", value: -1n });
                break;
              case "I256Const":
                t3.push({ kind: "I256", value: f2.value });
                break;
              case "U256Const0":
                t3.push({ kind: "U256", value: 0n });
                break;
              case "U256Const1":
                t3.push({ kind: "U256", value: 1n });
                break;
              case "U256Const2":
                t3.push({ kind: "U256", value: 2n });
                break;
              case "U256Const3":
                t3.push({ kind: "U256", value: 3n });
                break;
              case "U256Const4":
                t3.push({ kind: "U256", value: 4n });
                break;
              case "U256Const5":
                t3.push({ kind: "U256", value: 5n });
                break;
              case "U256Const":
                t3.push({ kind: "U256", value: f2.value });
                break;
              case "BytesConst":
                t3.push({ kind: "ByteVec", value: f2.value });
                break;
              case "AddressConst":
                t3.push({ kind: "Address", value: f2.value });
                break;
              case "LoadLocal":
                t3.push(r3.get(f2.index));
                break;
              case "StoreLocal":
                r3.set(f2.index, t3.pop());
                break;
              case "Pop":
                t3.pop();
                break;
              case "Dup":
                const e4 = t3.pop();
                t3.push(e4), t3.push(e4);
                break;
              case "Swap":
                const h2 = t3.pop(), l2 = t3.pop();
                t3.push(h2), t3.push(l2);
                break;
              case "BoolNot":
                const y2 = (v = t3.popBool(), w = (e5) => !e5, v.kind.startsWith("Symbol") ? v : { kind: v.kind, value: w(v.value) });
                t3.push(y2);
              case "BoolAnd":
                c(t3.popBool(), t3.popBool(), ((e5, t4) => e5 && t4), t3.push);
                break;
              case "BoolOr":
                c(t3.popBool(), t3.popBool(), ((e5, t4) => e5 || t4), t3.push);
                break;
              case "BoolEq":
                c(t3.popBool(), t3.popBool(), ((e5, t4) => e5 === t4), t3.push);
                break;
              case "BoolNeq":
                c(t3.popBool(), t3.popBool(), ((e5, t4) => e5 !== t4), t3.push);
                break;
              case "BoolToByteVec": {
                const e5 = t3.popBool();
                "Symbol-Bool" === e5.kind ? t3.push(e5) : t3.push({ kind: "ByteVec", value: i.boolCodec.encode(e5.value) });
                break;
              }
              case "I256Add": {
                const e5 = t3.popI256();
                c(t3.popI256(), e5, ((e6, t4) => e6 + t4), t3.push);
                break;
              }
              case "I256Sub": {
                const e5 = t3.popI256();
                c(t3.popI256(), e5, ((e6, t4) => e6 - t4), t3.push);
                break;
              }
              case "I256Mul": {
                const e5 = t3.popI256();
                c(t3.popI256(), e5, ((e6, t4) => e6 * t4), t3.push);
                break;
              }
              case "I256Div": {
                const e5 = t3.popI256();
                c(t3.popI256(), e5, ((e6, t4) => e6 / t4), t3.push);
                break;
              }
              case "I256Eq": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 === t4), t3.push);
                break;
              }
              case "I256Neq": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 !== t4), t3.push);
                break;
              }
              case "I256Lt": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 < t4), t3.push);
                break;
              }
              case "I256Le": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 <= t4), t3.push);
                break;
              }
              case "I256Gt": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 > t4), t3.push);
                break;
              }
              case "I256Ge": {
                const e5 = t3.popI256();
                u(t3.popI256(), e5, ((e6, t4) => e6 >= t4), t3.push);
                break;
              }
              case "U256Add": {
                const e5 = t3.popU256();
                c(t3.popU256(), e5, ((e6, t4) => e6 + t4), t3.push);
                break;
              }
              case "U256Sub": {
                const e5 = t3.popU256();
                c(t3.popU256(), e5, ((e6, t4) => e6 - t4), t3.push);
                break;
              }
              case "U256Mul": {
                const e5 = t3.popU256();
                c(t3.popU256(), e5, ((e6, t4) => e6 * t4), t3.push);
                break;
              }
              case "U256Div": {
                const e5 = t3.popU256();
                c(t3.popU256(), e5, ((e6, t4) => e6 / t4), t3.push);
                break;
              }
              case "U256Eq": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 === t4), t3.push);
                break;
              }
              case "U256Neq": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 !== t4), t3.push);
                break;
              }
              case "U256Lt": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 < t4), t3.push);
                break;
              }
              case "U256Le": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 <= t4), t3.push);
                break;
              }
              case "U256Gt": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 > t4), t3.push);
                break;
              }
              case "U256Ge": {
                const e5 = t3.popU256();
                u(t3.popU256(), e5, ((e6, t4) => e6 >= t4), t3.push);
                break;
              }
              case "ByteVecEq":
                u(t3.popByteVec(), t3.popByteVec(), ((e5, t4) => d(e5, t4)), t3.push);
                break;
              case "ByteVecNeq":
                u(t3.popByteVec(), t3.popByteVec(), ((e5, t4) => !d(e5, t4)), t3.push);
                break;
              case "ByteVecSize": {
                const e5 = t3.popByteVec();
                "Symbol-ByteVec" === e5.kind ? t3.push({ kind: "Symbol-U256", value: void 0 }) : t3.push({ kind: "U256", value: BigInt(e5.value.length) });
                break;
              }
              case "ByteVecConcat": {
                const e5 = t3.popByteVec();
                c(t3.popByteVec(), e5, ((e6, t4) => new Uint8Array([...e6, ...t4])), t3.push);
                break;
              }
              case "ByteVecSlice": {
                const e5 = t3.popU256(), r4 = t3.popU256(), n2 = t3.popByteVec();
                "Symbol-ByteVec" === n2.kind || "Symbol-U256" === r4.kind || "Symbol-U256" === e5.kind ? t3.push({ kind: "Symbol-ByteVec", value: void 0 }) : t3.push({ kind: "ByteVec", value: n2.value.slice(Number(r4.value), Number(e5.value)) });
                break;
              }
              case "AddressEq":
                u(t3.popAddress(), t3.popAddress(), ((e5, t4) => d(o.lockupScriptCodec.encode(e5), o.lockupScriptCodec.encode(t4))), t3.push);
                break;
              case "AddressNeq":
                u(t3.popAddress(), t3.popAddress(), ((e5, t4) => !d(o.lockupScriptCodec.encode(e5), o.lockupScriptCodec.encode(t4))), t3.push);
                break;
              case "AddressToByteVec": {
                const e5 = t3.popAddress();
                "Symbol-Address" === e5.kind ? t3.push({ kind: "Symbol-ByteVec", value: void 0 }) : t3.push({ kind: "ByteVec", value: o.lockupScriptCodec.encode(e5.value) });
                break;
              }
              case "Assert":
                if (!t3.popBool()) throw new Error("Assertion failed");
                break;
              case "Blake2b":
              case "Sha256":
              case "Sha3":
              case "Keccak256":
                b(f2.name), t3.popByteVec(), t3.push({ kind: "ByteVec", value: new Uint8Array(32) });
                break;
              case "ByteVecToAddress": {
                const e5 = t3.popByteVec();
                "Symbol-ByteVec" === e5.kind ? t3.push({ kind: "Symbol-Address", value: void 0 }) : t3.push({ kind: "Address", value: o.lockupScriptCodec.decode(e5.value) });
                break;
              }
              case "Zeros": {
                const e5 = t3.popU256();
                if ("Symbol-U256" === e5.kind) t3.push({ kind: "Symbol-ByteVec", value: void 0 });
                else {
                  if (e5.value > 4096) throw new Error("Zeros size is too large");
                  t3.push({ kind: "ByteVec", value: new Uint8Array(Number(e5.value)) });
                }
                break;
              }
              case "U256To1Byte":
              case "U256To2Byte":
              case "U256To4Byte":
              case "U256To8Byte":
              case "U256To16Byte":
              case "U256To32Byte":
                b(f2.name), t3.popU256(), t3.push({ kind: "Symbol-ByteVec", value: void 0 });
                break;
              case "U256From1Byte":
              case "U256From2Byte":
              case "U256From4Byte":
              case "U256From8Byte":
              case "U256From16Byte":
              case "U256From32Byte":
                b(f2.name), t3.popByteVec(), t3.push({ kind: "Symbol-U256", value: void 0 });
                break;
              case "CallExternal":
              case "CallExternalBySelector": {
                const e5 = t3.popByteVec(), r4 = t3.popU256();
                if (t3.popU256(), "Symbol-ByteVec" !== e5.kind && s2.push({ contractAddress: (0, n.addressFromContractId)((0, a.binToHex)(e5.value)), approvedAttoAlphAmount: g.getApprovedAttoAlph(), approvedTokens: g.getApprovedTokens() }), g.reset(), "Symbol-U256" !== r4.kind) for (let e6 = 0; e6 < r4.value; e6++) t3.push({ kind: "Symbol-Any", value: void 0 });
                break;
              }
              case "ContractIdToAddress": {
                const e5 = t3.popByteVec();
                "Symbol-ByteVec" === e5.kind ? t3.push({ kind: "Symbol-Address", value: void 0 }) : t3.push({ kind: "Address", value: { kind: "P2C", value: e5.value } });
                break;
              }
              case "LoadLocalByIndex": {
                const e5 = t3.popU256();
                if ("Symbol-U256" === e5.kind) throw new Error("LoadLocalByIndex index is a symbol");
                t3.push(r3.get(Number(e5.value)));
                break;
              }
              case "StoreLocalByIndex": {
                const e5 = t3.popU256();
                if ("Symbol-U256" === e5.kind) throw new Error("StoreLocalByIndex index is a symbol");
                r3.set(Number(e5.value), t3.pop());
                break;
              }
              case "CallerAddress":
                t3.push(m);
                break;
              case "ApproveAlph": {
                const e5 = t3.popU256(), r4 = t3.popAddress();
                r4.kind.startsWith("Symbol") ? g.setUnknown() : r4 === m && g.addApprovedAttoAlph(e5);
                break;
              }
              case "ApproveToken": {
                const e5 = t3.popU256(), r4 = t3.popByteVec(), n2 = t3.popAddress();
                n2.kind.startsWith("Symbol") ? g.setUnknown() : n2 === m && g.addApprovedToken(r4, e5);
                break;
              }
              case "CreateContractAndTransferToken":
                t3.popAddress();
              case "CreateContractWithToken":
                t3.popU256();
              case "CreateContract":
                t3.popByteVec(), t3.popByteVec(), t3.popByteVec(), t3.push({ kind: "Symbol-ByteVec", value: void 0 });
                break;
              case "TransferAlph":
                t3.popU256(), t3.popAddress(), t3.popAddress();
                break;
              case "TransferToken":
                t3.popU256(), t3.popByteVec(), t3.popAddress(), t3.popAddress();
                break;
              default:
                p(f2.name);
            }
            var v, w;
            return s2;
          }
        };
        class h {
          constructor() {
            this.stack = [], this.push = (e3) => {
              this.stack.push(e3);
            };
          }
          pop() {
            const e3 = this.stack.pop();
            if (void 0 === e3) throw new Error("Stack is empty");
            return e3;
          }
          size() {
            return this.stack.length;
          }
          checkedResult(e3, t3) {
            if (e3.kind.startsWith("Symbol")) {
              if (e3.kind !== `Symbol-${t3}`) throw new Error(`Expected a ${t3} value on the stack`);
              return e3;
            }
            if (e3.kind !== t3) throw new Error(`Expected a ${t3} value on the stack`);
            return e3;
          }
          popBool() {
            const e3 = this.pop();
            return this.checkedResult(e3, "Bool");
          }
          popI256() {
            const e3 = this.pop();
            return this.checkedResult(e3, "I256");
          }
          popU256() {
            const e3 = this.pop();
            return this.checkedResult(e3, "U256");
          }
          popByteVec() {
            const e3 = this.pop();
            return this.checkedResult(e3, "ByteVec");
          }
          popAddress() {
            const e3 = this.pop();
            return this.checkedResult(e3, "Address");
          }
        }
        class l {
          constructor() {
            this.locals = [];
          }
          get(e3) {
            const t3 = this.locals[`${e3}`];
            if (void 0 === t3) throw new Error(`Local variable at index ${e3} is not set`);
            return t3;
          }
          set(e3, t3) {
            this.locals[`${e3}`] = t3;
          }
          checkedResult(e3, t3, r3) {
            if (e3.kind.startsWith("Symbol")) {
              if (e3.kind !== `Symbol-${r3}`) throw new Error(`Local variable at index ${t3} is not a ${r3}`);
              return e3;
            }
            if (e3.kind !== r3) throw new Error(`Local variable at index ${t3} is not a ${r3}`);
            return e3;
          }
          getBool(e3) {
            const t3 = this.get(e3);
            return this.checkedResult(t3, e3, "Bool");
          }
          getI256(e3) {
            const t3 = this.get(e3);
            return this.checkedResult(t3, e3, "I256");
          }
          getU256(e3) {
            const t3 = this.get(e3);
            return this.checkedResult(t3, e3, "U256");
          }
          getByteVec(e3) {
            const t3 = this.get(e3);
            return this.checkedResult(t3, e3, "ByteVec");
          }
          getAddress(e3) {
            const t3 = this.get(e3);
            return this.checkedResult(t3, e3, "Address");
          }
        }
        function p(e3) {
          throw new Error(`Unimplemented instruction: ${e3}`);
        }
        function b(e3) {
          console.debug(`Dummy implementation for instruction: ${e3}`);
        }
        class y {
          constructor() {
            this.approvedTokens = [], this.reset();
          }
          reset() {
            this.approvedTokens = [{ id: s.ALPH_TOKEN_ID, amount: 0n }];
          }
          setUnknown() {
            this.approvedTokens = "unknown";
          }
          getApprovedAttoAlph() {
            if ("unknown" === this.approvedTokens) return "unknown";
            const e3 = this.approvedTokens[0].amount;
            return "unknown" === e3 ? "unknown" : 0n === e3 ? void 0 : e3;
          }
          getApprovedTokens() {
            if ("unknown" === this.approvedTokens) return "unknown";
            const e3 = this.approvedTokens.slice(1);
            return 0 === e3.length ? void 0 : e3;
          }
          addApprovedAttoAlph(e3) {
            this.addApprovedToken({ kind: "ByteVec", value: (0, a.hexToBinUnsafe)(s.ALPH_TOKEN_ID) }, e3);
          }
          addApprovedToken(e3, t3) {
            if ("unknown" === this.approvedTokens) return;
            if ("Symbol-ByteVec" === e3.kind) return void (this.approvedTokens = "unknown");
            const r3 = this.approvedTokens.findIndex(((t4) => d((0, a.hexToBinUnsafe)(t4.id), e3.value)));
            if (-1 === r3) this.approvedTokens.push({ id: (0, a.binToHex)(e3.value), amount: "Symbol-U256" === t3.kind ? "unknown" : t3.value });
            else {
              const e4 = this.approvedTokens[`${r3}`];
              if ("unknown" === e4.amount) return;
              "Symbol-U256" === t3.kind ? e4.amount = "unknown" : e4.amount += t3.value;
            }
          }
        }
      }, 2505: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.disableContractDebugMessage = t2.enableContractDebugMessage = t2.isContractDebugMessageEnabled = t2.disableDebugMode = t2.enableDebugMode = t2.isDebugModeEnabled = void 0;
        let r2 = false;
        t2.isDebugModeEnabled = function() {
          return r2;
        }, t2.enableDebugMode = function() {
          r2 = true;
        }, t2.disableDebugMode = function() {
          r2 = false;
        };
        let n = true;
        t2.isContractDebugMessageEnabled = function() {
          return n;
        }, t2.enableContractDebugMessage = function() {
          n = true;
        }, t2.disableContractDebugMessage = function() {
          n = false;
        };
      }, 4652: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.TraceableError = void 0;
        class r2 extends Error {
          constructor(e3, t3) {
            const r3 = void 0 === t3 ? void 0 : t3 instanceof Error ? t3.message : `${t3}`;
            super(r3 ? `${e3}, error: ${r3}` : e3), this.trace = t3;
            const n = new.target.prototype;
            Object.setPrototypeOf ? Object.setPrototypeOf(this, n) : this.__proto__ = n;
          }
        }
        t2.TraceableError = r2;
      }, 3869: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.isTransferTx = t2.getAddressFromUnlockScript = t2.getSenderAddress = t2.getDepositInfo = t2.getALPHDepositInfo = t2.isALPHTransferTx = t2.validateExchangeAddress = void 0;
        const n = r2(2581), i = r2(664), o = r2(2976), s = r2(4459), a = r2(4652);
        function c(e3) {
          return h(e3) && (function(e4) {
            return e4.unsigned.fixedOutputs.every(((e5) => 0 === e5.tokens.length));
          })(e3);
        }
        function u(e3) {
          const t3 = [];
          for (const r3 of e3.unsigned.inputs) try {
            if (r3.unlockScript === (0, i.binToHex)(o.encodedSameAsPrevious)) continue;
            const e4 = f(r3.unlockScript);
            t3.includes(e4) || t3.push(e4);
          } catch (e4) {
            throw new a.TraceableError("Failed to decode address from unlock script", e4);
          }
          return t3;
        }
        var d;
        function f(e3) {
          if (!(0, i.isHexString)(e3)) throw new Error(`Invalid unlock script ${e3}, expected a hex string`);
          const t3 = (0, i.hexToBinUnsafe)(e3);
          if (0 === t3.length) throw new Error("UnlockScript is empty");
          const r3 = t3[0], c2 = t3.slice(1);
          if (r3 === d.P2PKH) {
            if (33 !== c2.length) throw new Error(`Invalid p2pkh unlock script: ${e3}`);
            return (0, n.addressFromPublicKey)((0, i.binToHex)(c2));
          }
          if (r3 === d.P2MPKH) throw new Error("Naive multi-sig address is not supported for exchanges as it will be replaced by P2SH");
          if (r3 === d.P2SH) {
            let r4;
            try {
              r4 = o.unlockScriptCodec.decode(t3).value;
            } catch (t4) {
              throw new a.TraceableError(`Invalid p2sh unlock script: ${e3}`, t4);
            }
            return (0, n.addressFromScript)(s.scriptCodec.encode(r4.script));
          }
          throw new Error("Invalid unlock script type");
        }
        function h(e3) {
          return 0 === e3.contractInputs.length && 0 === e3.generatedOutputs.length && 0 !== e3.unsigned.inputs.length && void 0 === e3.unsigned.scriptOpt;
        }
        t2.validateExchangeAddress = function(e3) {
          const t3 = (0, i.base58ToBytes)(e3);
          if (0 === t3.length) throw new Error("Address is empty");
          const r3 = t3[0];
          if (r3 !== n.AddressType.P2PKH && r3 !== n.AddressType.P2SH) throw new Error("Invalid address type");
          if (33 !== t3.length) throw new Error("Invalid address length");
        }, t2.isALPHTransferTx = c, t2.getALPHDepositInfo = function(e3) {
          if (!c(e3)) return [];
          const t3 = u(e3), r3 = /* @__PURE__ */ new Map();
          return e3.unsigned.fixedOutputs.forEach(((e4) => {
            if (!t3.includes(e4.address)) {
              const t4 = r3.get(e4.address);
              void 0 === t4 ? r3.set(e4.address, BigInt(e4.attoAlphAmount)) : r3.set(e4.address, BigInt(e4.attoAlphAmount) + t4);
            }
          })), Array.from(r3.entries()).map((([e4, t4]) => ({ targetAddress: e4, depositAmount: t4 })));
        }, t2.getDepositInfo = function(e3) {
          if (!h(e3)) return { alph: [], tokens: [] };
          const t3 = u(e3), r3 = /* @__PURE__ */ new Map(), n2 = /* @__PURE__ */ new Map();
          return e3.unsigned.fixedOutputs.forEach(((e4) => {
            if (!t3.includes(e4.address)) {
              const t4 = r3.get(e4.address) ?? 0n;
              r3.set(e4.address, t4 + BigInt(e4.attoAlphAmount)), e4.tokens.forEach(((t5) => {
                const r4 = n2.get(t5.id) ?? /* @__PURE__ */ new Map(), i2 = r4.get(e4.address) ?? 0n;
                r4.set(e4.address, i2 + BigInt(t5.amount)), n2.set(t5.id, r4);
              }));
            }
          })), { alph: Array.from(r3.entries()).map((([e4, t4]) => ({ targetAddress: e4, depositAmount: t4 }))), tokens: Array.from(n2.entries()).flatMap((([e4, t4]) => Array.from(t4.entries()).map((([t5, r4]) => ({ tokenId: e4, targetAddress: t5, depositAmount: r4 }))))) };
        }, t2.getSenderAddress = function(e3) {
          return f(e3.unsigned.inputs[0].unlockScript);
        }, (function(e3) {
          e3[e3.P2PKH = 0] = "P2PKH", e3[e3.P2MPKH = 1] = "P2MPKH", e3[e3.P2SH = 2] = "P2SH";
        })(d || (d = {})), t2.getAddressFromUnlockScript = f, t2.isTransferTx = h;
      }, 3285: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.getDepositInfo = t2.getALPHDepositInfo = t2.isALPHTransferTx = t2.getSenderAddress = t2.validateExchangeAddress = void 0;
        var n = r2(3869);
        Object.defineProperty(t2, "validateExchangeAddress", { enumerable: true, get: function() {
          return n.validateExchangeAddress;
        } }), Object.defineProperty(t2, "getSenderAddress", { enumerable: true, get: function() {
          return n.getSenderAddress;
        } }), Object.defineProperty(t2, "isALPHTransferTx", { enumerable: true, get: function() {
          return n.isALPHTransferTx;
        } }), Object.defineProperty(t2, "getALPHDepositInfo", { enumerable: true, get: function() {
          return n.getALPHDepositInfo;
        } }), Object.defineProperty(t2, "getDepositInfo", { enumerable: true, get: function() {
          return n.getDepositInfo;
        } });
      }, 307: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.getDefaultExplorerProvider = t2.getDefaultNodeProvider = t2.getCurrentExplorerProvider = t2.setCurrentExplorerProvider = t2.getCurrentNodeProvider = t2.setCurrentNodeProvider = void 0;
        const n = r2(3749);
        let i, o;
        t2.setCurrentNodeProvider = function(e3, t3, r3) {
          i = "string" == typeof e3 ? new n.NodeProvider(e3, t3, r3) : e3;
        }, t2.getCurrentNodeProvider = function() {
          if (void 0 === i) throw Error("No node provider is set.");
          return i;
        }, t2.setCurrentExplorerProvider = function(e3, t3, r3) {
          o = "string" == typeof e3 ? new n.ExplorerProvider(e3, t3, r3) : e3;
        }, t2.getCurrentExplorerProvider = function() {
          return o;
        };
        const s = { mainnet: { nodeUrl: "https://node.mainnet.alephium.org", explorerUrl: "https://backend.mainnet.alephium.org" }, testnet: { nodeUrl: "https://node.testnet.alephium.org", explorerUrl: "https://backend.testnet.alephium.org" }, devnet: { nodeUrl: "http://127.0.0.1:22973", explorerUrl: "http://127.0.0.1:9090" } };
        t2.getDefaultNodeProvider = function(e3) {
          return new n.NodeProvider(s[e3].nodeUrl);
        }, t2.getDefaultExplorerProvider = function(e3) {
          return new n.ExplorerProvider(s[e3].explorerUrl);
        };
      }, 2126: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        }, s = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.utils = t2.codec = t2.web3 = void 0, BigInt.prototype.toJSON = function() {
          return this.toString();
        }, o(r2(3749), t2), o(r2(5033), t2), o(r2(3693), t2), o(r2(664), t2), o(r2(6705), t2), o(r2(3652), t2), o(r2(7695), t2), t2.web3 = s(r2(307)), t2.codec = s(r2(3651)), t2.utils = s(r2(664)), o(r2(2505), t2), o(r2(4648), t2), o(r2(2581), t2), o(r2(3285), t2), o(r2(4652), t2);
      }, 3693: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), i(r2(9191), t2), i(r2(2644), t2), i(r2(7375), t2);
      }, 9191: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        }, s = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.fromApiDestination = t2.toApiDestinations = t2.toApiDestination = t2.verifySignedMessage = t2.hashMessage = t2.extendMessage = t2.SignerProviderWithCachedAccounts = t2.SignerProviderWithMultipleAccounts = t2.SignerProviderSimple = t2.InteractiveSignerProvider = t2.SignerProvider = void 0;
        const a = r2(4062), c = r2(3749), u = o(r2(664)), d = s(r2(1540)), f = r2(2644), h = r2(7375), l = r2(2581);
        class p {
          async getSelectedAccount() {
            const e3 = await this.unsafeGetSelectedAccount();
            return p.validateAccount(e3), e3;
          }
          static validateAccount(e3) {
            const t3 = (0, l.addressFromPublicKey)(e3.publicKey, e3.keyType), r3 = (0, l.groupOfAddress)(t3);
            if (t3 !== e3.address || (0, f.isGroupedAccount)(e3) && r3 !== e3.group) throw Error(`Invalid accounot data: ${JSON.stringify(e3)}`);
          }
        }
        t2.SignerProvider = p, t2.InteractiveSignerProvider = class extends p {
          async enable(e3) {
            const t3 = await this.unsafeEnable(e3);
            return p.validateAccount(t3), t3;
          }
        };
        class b extends p {
          async submitTransaction(e3) {
            const t3 = { unsignedTx: e3.unsignedTx, signature: e3.signature };
            return this.nodeProvider.transactions.postTransactionsSubmit(t3);
          }
          async signAndSubmitTransferTx(e3) {
            const t3 = await this.signTransferTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              for (const e4 of t3.fundingTxs) await this.submitTransaction(e4);
              await this.submitTransaction(t3);
            } else await this.submitTransaction(t3);
            return t3;
          }
          async signAndSubmitDeployContractTx(e3) {
            const t3 = await this.signDeployContractTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              for (const e4 of t3.fundingTxs) await this.submitTransaction(e4);
              await this.submitTransaction(t3);
            } else await this.submitTransaction(t3);
            return t3;
          }
          async signAndSubmitExecuteScriptTx(e3) {
            const t3 = await this.signExecuteScriptTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              for (const e4 of t3.fundingTxs) await this.submitTransaction(e4);
              await this.submitTransaction(t3);
            } else await this.submitTransaction(t3);
            return t3;
          }
          async signAndSubmitUnsignedTx(e3) {
            const t3 = await this.signUnsignedTx(e3);
            return await this.submitTransaction(t3), t3;
          }
          async signAndSubmitChainedTx(e3) {
            const t3 = await this.signChainedTx(e3);
            for (const e4 of t3) await this.submitTransaction(e4);
            return t3;
          }
          async signTransferTx(e3) {
            const t3 = await this.buildTransferTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              const r3 = [];
              for (let n3 = 0; n3 < t3.fundingTxs.length; n3++) {
                const i2 = await this.signRaw(e3.signerAddress, t3.fundingTxs[n3].txId);
                r3.push({ ...t3.fundingTxs[n3], signature: i2 });
              }
              const n2 = await this.signRaw(e3.signerAddress, t3.txId);
              return { fromGroup: t3.fromGroup, toGroup: t3.toGroup, gasAmount: t3.gasAmount, gasPrice: t3.gasPrice, txId: t3.txId, unsignedTx: t3.unsignedTx, signature: n2, fundingTxs: r3 };
            }
            return { signature: await this.signRaw(e3.signerAddress, t3.txId), ...t3 };
          }
          async buildTransferTx(e3) {
            return h.TransactionBuilder.from(this.nodeProvider).buildTransferTx(e3, await this.getPublicKey(e3.signerAddress));
          }
          async signDeployContractTx(e3) {
            const t3 = await this.buildDeployContractTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              const r3 = [];
              for (let n3 = 0; n3 < t3.fundingTxs.length; n3++) {
                const i2 = await this.signRaw(e3.signerAddress, t3.fundingTxs[n3].txId);
                r3.push({ ...t3.fundingTxs[n3], signature: i2 });
              }
              const n2 = await this.signRaw(e3.signerAddress, t3.txId);
              return { contractAddress: t3.contractAddress, contractId: t3.contractId, gasAmount: t3.gasAmount, gasPrice: t3.gasPrice, groupIndex: t3.groupIndex, unsignedTx: t3.unsignedTx, txId: t3.txId, signature: n2, fundingTxs: r3 };
            }
            return { signature: await this.signRaw(e3.signerAddress, t3.txId), ...t3 };
          }
          async buildDeployContractTx(e3) {
            return h.TransactionBuilder.from(this.nodeProvider).buildDeployContractTx(e3, await this.getPublicKey(e3.signerAddress));
          }
          async signExecuteScriptTx(e3) {
            const t3 = await this.buildExecuteScriptTx(e3);
            if ("fundingTxs" in t3 && void 0 !== t3.fundingTxs) {
              const r3 = [];
              for (let n3 = 0; n3 < t3.fundingTxs.length; n3++) {
                const i2 = await this.signRaw(e3.signerAddress, t3.fundingTxs[n3].txId);
                r3.push({ ...t3.fundingTxs[n3], signature: i2 });
              }
              const n2 = await this.signRaw(e3.signerAddress, t3.txId);
              return { gasAmount: t3.gasAmount, gasPrice: t3.gasPrice, groupIndex: t3.groupIndex, unsignedTx: t3.unsignedTx, txId: t3.txId, simulationResult: t3.simulationResult, signature: n2, fundingTxs: r3 };
            }
            return { signature: await this.signRaw(e3.signerAddress, t3.txId), ...t3 };
          }
          async buildExecuteScriptTx(e3) {
            return h.TransactionBuilder.from(this.nodeProvider).buildExecuteScriptTx(e3, await this.getPublicKey(e3.signerAddress));
          }
          async signChainedTx(e3) {
            const t3 = await this.buildChainedTx(e3), r3 = await Promise.all(t3.map(((t4, r4) => this.signRaw(e3[`${r4}`].signerAddress, t4.txId))));
            return t3.map(((e4, t4) => ({ ...e4, signature: r3[`${t4}`] })));
          }
          async buildChainedTx(e3) {
            return h.TransactionBuilder.from(this.nodeProvider).buildChainedTx(e3, await Promise.all(e3.map(((e4) => this.getPublicKey(e4.signerAddress)))));
          }
          async signUnsignedTx(e3) {
            const t3 = h.TransactionBuilder.buildUnsignedTx(e3);
            return { signature: await this.signRaw(e3.signerAddress, t3.txId), ...t3 };
          }
          async signMessage(e3) {
            const t3 = g(e3.message, e3.messageHasher);
            return { signature: await this.signRaw(e3.signerAddress, t3) };
          }
        }
        t2.SignerProviderSimple = b;
        class y extends b {
          async getAccount(e3) {
            const t3 = (await this.getAccounts()).find(((t4) => t4.address === e3));
            if (void 0 === t3) throw new Error("Unmatched signerAddress");
            return t3;
          }
          async getPublicKey(e3) {
            return (await this.getAccount(e3)).publicKey;
          }
        }
        function m(e3) {
          return "Alephium Signed Message: " + e3;
        }
        function g(e3, t3) {
          switch (t3) {
            case "alephium":
              return u.binToHex(d.default.blake2b(m(e3), void 0, 32));
            case "sha256":
              const r3 = (0, a.createHash)("sha256");
              return r3.update(new TextEncoder().encode(e3)), u.binToHex(r3.digest());
            case "blake2b":
              return u.binToHex(d.default.blake2b(e3, void 0, 32));
            case "identity":
              return e3;
            default:
              throw Error(`Invalid message hasher: ${t3}`);
          }
        }
        function v(e3) {
          return { ...e3, attoAlphAmount: (0, c.toApiNumber256)(e3.attoAlphAmount), tokens: (0, c.toApiTokens)(e3.tokens) };
        }
        t2.SignerProviderWithMultipleAccounts = y, t2.SignerProviderWithCachedAccounts = class extends y {
          constructor() {
            super(...arguments), this._selectedAccount = void 0, this._accounts = /* @__PURE__ */ new Map();
          }
          unsafeGetSelectedAccount() {
            if (void 0 === this._selectedAccount) throw Error("No account is selected yet");
            return Promise.resolve(this._selectedAccount);
          }
          setSelectedAccount(e3) {
            const t3 = this._accounts.get(e3);
            if (void 0 === t3) throw Error("The address is not in the accounts");
            return this._selectedAccount = t3, Promise.resolve();
          }
          getAccounts() {
            return Promise.resolve(Array.from(this._accounts.values()));
          }
          async getAccount(e3) {
            const t3 = this._accounts.get(e3);
            if (void 0 === t3) throw Error("The address is not in the accounts");
            return Promise.resolve(t3);
          }
        }, t2.extendMessage = m, t2.hashMessage = g, t2.verifySignedMessage = function(e3, t3, r3, n2, i2) {
          const o2 = g(e3, t3);
          return u.verifySignature(o2, r3, n2, i2);
        }, t2.toApiDestination = v, t2.toApiDestinations = function(e3) {
          return e3.map(v);
        }, t2.fromApiDestination = function(e3) {
          return { ...e3, attoAlphAmount: (0, c.fromApiNumber256)(e3.attoAlphAmount ?? "0"), tokens: (0, c.fromApiTokens)(e3.tokens) };
        };
      }, 7375: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.updateBytecodeWithGroup = t2.getGroupFromTxScript = t2.TransactionBuilder = void 0;
        const n = r2(664), i = r2(3749), o = r2(2581), s = r2(9191), a = r2(2644), c = r2(3651), u = r2(6705), d = r2(7007), f = r2(7695), h = r2(4459);
        class l {
          static from(e3, t3, r3) {
            const n2 = "string" == typeof e3 ? new i.NodeProvider(e3, t3, r3) : e3;
            return new class extends l {
              get nodeProvider() {
                return n2;
              }
            }();
          }
          static validatePublicKey(e3, t3, r3) {
            if ((0, o.addressFromPublicKey)(t3, r3) !== e3.signerAddress) throw new Error("Unmatched public key");
          }
          async buildTransferTx(e3, t3) {
            const r3 = this.buildTransferTxParams(e3, t3), n2 = await this.nodeProvider.transactions.postTransactionsBuild(r3);
            return this.convertTransferTxResult(n2);
          }
          async buildDeployContractTx(e3, t3) {
            const r3 = this.buildDeployContractTxParams(e3, t3), n2 = await this.nodeProvider.contracts.postContractsUnsignedTxDeployContract(r3);
            return this.convertDeployContractTxResult(n2);
          }
          async buildExecuteScriptTx(e3, t3) {
            const r3 = this.buildExecuteScriptTxParams(e3, t3), n2 = await this.nodeProvider.contracts.postContractsUnsignedTxExecuteScript(r3);
            return this.convertExecuteScriptTxResult(n2);
          }
          async buildChainedTx(e3, t3) {
            if (e3.length !== t3.length) throw new Error("The number of build chained transaction parameters must match the number of public keys provided");
            const r3 = e3.map(((e4, r4) => {
              const n2 = e4.type;
              switch (n2) {
                case "Transfer":
                  return { type: n2, value: this.buildTransferTxParams(e4, t3[r4]) };
                case "DeployContract":
                  return { type: n2, value: this.buildDeployContractTxParams(e4, t3[r4]) };
                case "ExecuteScript":
                  return { type: n2, value: this.buildExecuteScriptTxParams(e4, t3[r4]) };
                default:
                  throw new Error(`Unsupported transaction type: ${n2}`);
              }
            }));
            return (await this.nodeProvider.transactions.postTransactionsBuildChained(r3)).map(((e4) => {
              const t4 = e4.type;
              switch (t4) {
                case "Transfer": {
                  const r4 = e4.value;
                  return { ...this.convertTransferTxResult(r4), type: t4 };
                }
                case "DeployContract": {
                  const r4 = e4.value;
                  return { ...this.convertDeployContractTxResult(r4), type: t4 };
                }
                case "ExecuteScript": {
                  const r4 = e4.value;
                  return { ...this.convertExecuteScriptTxResult(r4), type: t4 };
                }
                default:
                  throw new Error(`Unexpected transaction type: ${t4} for ${e4.value.txId}`);
              }
            }));
          }
          static buildUnsignedTx(e3) {
            const t3 = (0, n.hexToBinUnsafe)(e3.unsignedTx), r3 = c.unsignedTxCodec.decode(t3), i2 = (0, n.binToHex)((0, d.blakeHash)(t3)), [o2, s2] = (0, u.groupIndexOfTransaction)(r3);
            return { fromGroup: o2, toGroup: s2, unsignedTx: e3.unsignedTx, txId: i2, gasAmount: r3.gasAmount, gasPrice: r3.gasPrice };
          }
          buildTransferTxParams(e3, t3) {
            l.validatePublicKey(e3, t3, e3.signerKeyType);
            const { destinations: r3, gasPrice: n2, ...o2 } = e3;
            return { fromPublicKey: t3, fromPublicKeyType: e3.signerKeyType, destinations: (0, s.toApiDestinations)(r3), gasPrice: (0, i.toApiNumber256Optional)(n2), ...o2 };
          }
          buildDeployContractTxParams(e3, t3) {
            l.validatePublicKey(e3, t3, e3.signerKeyType);
            const { initialAttoAlphAmount: r3, initialTokenAmounts: n2, issueTokenAmount: o2, gasPrice: s2, ...a2 } = e3;
            return { fromPublicKey: t3, fromPublicKeyType: e3.signerKeyType, initialAttoAlphAmount: (0, i.toApiNumber256Optional)(r3), initialTokenAmounts: (0, i.toApiTokens)(n2), issueTokenAmount: (0, i.toApiNumber256Optional)(o2), gasPrice: (0, i.toApiNumber256Optional)(s2), ...a2 };
          }
          static checkAndGetParams(e3) {
            if ((0, a.isGroupedKeyType)(e3.signerKeyType ?? "default")) return e3;
            if (!(0, o.isGrouplessAddress)(e3.signerAddress)) throw new Error("Invalid signer key type for groupless address");
            const t3 = e3.group ?? p(e3.bytecode), r3 = (0, o.groupOfAddress)(e3.signerAddress);
            if (void 0 === t3 || t3 === r3) return { ...e3, group: r3 };
            const n2 = b(e3.bytecode, t3);
            return { ...{ ...e3, bytecode: n2 }, group: t3 };
          }
          buildExecuteScriptTxParams(e3, t3) {
            l.validatePublicKey(e3, t3, e3.signerKeyType);
            const r3 = l.checkAndGetParams(e3), { signerKeyType: n2, attoAlphAmount: o2, tokens: s2, gasPrice: a2, dustAmount: c2, ...u2 } = r3;
            return { fromPublicKey: t3, fromPublicKeyType: n2, attoAlphAmount: (0, i.toApiNumber256Optional)(o2), tokens: (0, i.toApiTokens)(s2), gasPrice: (0, i.toApiNumber256Optional)(a2), dustAmount: (0, i.toApiNumber256Optional)(c2), ...u2 };
          }
          convertTransferTxResult(e3) {
            return "fundingTxs" in e3 ? { unsignedTx: e3.unsignedTx, gasAmount: e3.gasAmount, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice), txId: e3.txId, fromGroup: e3.fromGroup, toGroup: e3.toGroup, fundingTxs: e3.fundingTxs?.map(((e4) => ({ ...e4, gasPrice: (0, i.fromApiNumber256)(e4.gasPrice) }))) } : { ...e3, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice) };
          }
          convertDeployContractTxResult(e3) {
            if ("fundingTxs" in e3) {
              const t4 = (0, n.binToHex)((0, o.contractIdFromAddress)(e3.contractAddress));
              return { groupIndex: e3.fromGroup, unsignedTx: e3.unsignedTx, gasAmount: e3.gasAmount, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice), txId: e3.txId, contractAddress: e3.contractAddress, contractId: t4, fundingTxs: e3.fundingTxs?.map(((e4) => ({ ...e4, gasPrice: (0, i.fromApiNumber256)(e4.gasPrice) }))) };
            }
            const t3 = (0, n.binToHex)((0, o.contractIdFromAddress)(e3.contractAddress));
            return { ...e3, groupIndex: e3.fromGroup, contractId: t3, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice) };
          }
          convertExecuteScriptTxResult(e3) {
            return "fundingTxs" in e3 ? { groupIndex: e3.fromGroup, unsignedTx: e3.unsignedTx, txId: e3.txId, gasAmount: e3.gasAmount, simulationResult: e3.simulationResult, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice), fundingTxs: e3.fundingTxs?.map(((e4) => ({ ...e4, gasPrice: (0, i.fromApiNumber256)(e4.gasPrice) }))) } : { ...e3, groupIndex: e3.fromGroup, gasPrice: (0, i.fromApiNumber256)(e3.gasPrice) };
          }
        }
        function p(e3) {
          const t3 = h.scriptCodec.decode((0, n.hexToBinUnsafe)(e3)).methods.flatMap(((e4) => e4.instrs));
          for (let e4 = 0; e4 < t3.length - 1; e4 += 1) {
            const r3 = t3[`${e4}`], n2 = t3[e4 + 1];
            if ("BytesConst" === r3.name && 32 === r3.value.length && ("CallExternal" === n2.name || "CallExternalBySelector" === n2.name)) {
              const e5 = r3.value[r3.value.length - 1];
              if (e5 >= 0 && e5 < f.TOTAL_NUMBER_OF_GROUPS) return e5;
            }
          }
          for (const e4 of t3) if ("BytesConst" === e4.name && 32 === e4.value.length) {
            const t4 = e4.value[e4.value.length - 1];
            if (t4 >= 0 && t4 < f.TOTAL_NUMBER_OF_GROUPS) return t4;
          }
        }
        function b(e3, t3) {
          const r3 = h.scriptCodec.decode((0, n.hexToBinUnsafe)(e3)).methods.map(((e4) => {
            const r4 = e4.instrs.map(((e5) => {
              if ("AddressConst" === e5.name && "P2PK" === e5.value.kind) {
                const r5 = { ...e5.value, value: { ...e5.value.value, group: t3 } };
                return { ...e5, value: r5 };
              }
              return e5;
            }));
            return { ...e4, instrs: r4 };
          })), i2 = h.scriptCodec.encode({ methods: r3 });
          return (0, n.binToHex)(i2);
        }
        t2.TransactionBuilder = l, t2.getGroupFromTxScript = p, t2.updateBytecodeWithGroup = b;
      }, 2644: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.isGrouplessAccount = t2.isGroupedAccount = t2.isGrouplessKeyType = t2.isGroupedKeyType = t2.keyTypes = t2.grouplessKeyTypes = t2.groupedKeyTypes = void 0;
        const n = r2(664);
        function i(e3) {
          return "default" === e3 || "bip340-schnorr" === e3;
        }
        function o(e3) {
          return "default" !== e3 && "bip340-schnorr" !== e3;
        }
        n.assertType, t2.groupedKeyTypes = ["default", "bip340-schnorr"], t2.grouplessKeyTypes = ["gl-secp256k1", "gl-secp256r1", "gl-ed25519", "gl-webauthn"], t2.keyTypes = [...t2.groupedKeyTypes, ...t2.grouplessKeyTypes], t2.isGroupedKeyType = i, t2.isGrouplessKeyType = o, t2.isGroupedAccount = function(e3) {
          return i(e3.keyType);
        }, t2.isGrouplessAccount = function(e3) {
          return o(e3.keyType);
        }, (0, n.assertType)(), (0, n.assertType)(), (0, n.assertType)(), (0, n.assertType)(), (0, n.assertType)(), (0, n.assertType)(), (0, n.assertType)(), n.assertType, (0, n.assertType)();
      }, 3652: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), i(r2(716), t2);
      }, 716: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.validateNFTBaseUri = t2.validateNFTCollectionUriMetaData = t2.validateNFTTokenUriMetaData = t2.validNFTCollectionUriMetaDataFields = t2.validNFTUriMetaDataAttributeTypes = t2.validNFTTokenUriMetaDataAttributesFields = t2.validNFTTokenUriMetaDataFields = void 0, r2(9114);
        const n = r2(4652);
        function i(e3) {
          return Object.keys(e3).forEach(((e4) => {
            if (!t2.validNFTTokenUriMetaDataFields.includes(e4)) throw new Error(`Invalid field ${e4}, only ${t2.validNFTTokenUriMetaDataFields} are allowed`);
          })), { name: o(e3, "name"), description: (function(e4, t3) {
            const r3 = e4[`${t3}`];
            if (void 0 !== r3 && ("string" != typeof r3 || "" === r3)) throw new Error(`JSON field '${t3}' is not a non empty string`);
            return r3;
          })(e3, "description"), image: o(e3, "image"), attributes: (function(e4) {
            if (e4) {
              if (!Array.isArray(e4)) throw new Error("Field 'attributes' should be an array");
              e4.forEach(((e5) => {
                if ("object" != typeof e5) throw new Error("Field 'attributes' should be an array of objects");
                Object.keys(e5).forEach(((e6) => {
                  if (!t2.validNFTTokenUriMetaDataAttributesFields.includes(e6)) throw new Error(`Invalid field ${e6} for attributes, only ${t2.validNFTTokenUriMetaDataAttributesFields} are allowed`);
                })), o(e5, "trait_type"), (function(e6) {
                  const t3 = e6.value;
                  if (("string" != typeof t3 || "" === t3) && "number" != typeof t3 && "boolean" != typeof t3) throw new Error("Attribute value should be a non empty string, number or boolean");
                })(e5);
              }));
            }
            return e4;
          })(e3.attributes) };
        }
        function o(e3, t3) {
          const r3 = e3[`${t3}`];
          if ("string" != typeof r3 || "" === r3) throw new Error(`JSON field '${t3}' is not a non empty string`);
          return r3;
        }
        async function s(e3, t3) {
          try {
            return await (await fetch(`${e3}${t3}`)).json();
          } catch (r3) {
            throw new n.TraceableError(`Error fetching NFT metadata from ${e3}${t3}`, r3);
          }
        }
        t2.validNFTTokenUriMetaDataFields = ["name", "description", "image", "attributes"], t2.validNFTTokenUriMetaDataAttributesFields = ["trait_type", "value"], t2.validNFTUriMetaDataAttributeTypes = ["string", "number", "boolean"], t2.validNFTCollectionUriMetaDataFields = ["name", "description", "image"], t2.validateNFTTokenUriMetaData = i, t2.validateNFTCollectionUriMetaData = function(e3) {
          return Object.keys(e3).forEach(((e4) => {
            if (!t2.validNFTCollectionUriMetaDataFields.includes(e4)) throw new Error(`Invalid field ${e4}, only ${t2.validNFTCollectionUriMetaDataFields} are allowed`);
          })), { name: o(e3, "name"), description: o(e3, "description"), image: o(e3, "image") };
        }, t2.validateNFTBaseUri = async function(e3, t3) {
          if ((r3 = t3) === parseInt(r3.toString(), 10) && t3 > 0) {
            const r4 = [];
            for (let n2 = 0; n2 < t3; n2++) {
              const t4 = i(await s(e3, n2));
              r4.push(t4);
            }
            return r4;
          }
          throw new Error("maxSupply should be a positive integer");
          var r3;
        };
      }, 6705: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), i(r2(8715), t2), i(r2(6284), t2), i(r2(8156), t2);
      }, 6284: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.transactionVerifySignature = t2.transactionSign = void 0;
        const s = o(r2(664));
        t2.transactionSign = function(e3, t3, r3) {
          return s.sign(e3, t3, r3);
        }, t2.transactionVerifySignature = function(e3, t3, r3, n2) {
          return s.verifySignature(e3, t3, r3, n2);
        };
      }, 8715: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.subscribeToTxStatus = t2.TxStatusSubscription = void 0;
        const s = o(r2(307)), a = r2(664);
        class c extends a.Subscription {
          constructor(e3, t3, r3, n2, i2) {
            super(e3), this.txId = t3, this.fromGroup = r3, this.toGroup = n2, this.confirmations = i2 ?? 1;
          }
          async polling() {
            try {
              const e3 = await s.getCurrentNodeProvider().transactions.getTransactionsStatus({ txId: this.txId, fromGroup: this.fromGroup, toGroup: this.toGroup });
              await this.messageCallback(e3), "Confirmed" === e3.type && e3.chainConfirmations >= this.confirmations && this.unsubscribe();
            } catch (e3) {
              await this.errorCallback(e3, this);
            }
          }
        }
        t2.TxStatusSubscription = c, t2.subscribeToTxStatus = function(e3, t3, r3, n2, i2) {
          const o2 = new c(e3, t3, r3, n2, i2);
          return o2.subscribe(), o2;
        };
      }, 8156: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.groupIndexOfTransaction = t2.waitForTxConfirmation = void 0;
        const n = r2(2581), i = r2(7695), o = r2(307), s = r2(664);
        t2.waitForTxConfirmation = async function e3(t3, r3, n2) {
          const i2 = (0, o.getCurrentNodeProvider)(), s2 = await i2.transactions.getTransactionsStatus({ txId: t3 });
          return "Confirmed" === s2.type && s2.chainConfirmations >= r3 ? s2 : (await new Promise(((e4) => setTimeout(e4, n2))), e3(t3, r3, n2));
        }, t2.groupIndexOfTransaction = function(e3) {
          if (0 === e3.inputs.length) throw new Error("Empty inputs for unsignedTx");
          const t3 = (r3 = e3.inputs[0].hint, (0, s.xorByte)(r3) % i.TOTAL_NUMBER_OF_GROUPS);
          var r3;
          let o2 = t3;
          for (const r4 of e3.fixedOutputs) {
            const e4 = (0, n.groupOfLockupScript)(r4.lockupScript);
            if (e4 !== t3) {
              o2 = e4;
              break;
            }
          }
          return [t3, o2];
        };
      }, 4468: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.base58ToBytes = t2.isBase58 = t2.bs58 = void 0;
        const i = n(r2(1219)), o = r2(4652);
        t2.bs58 = (0, i.default)("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"), t2.isBase58 = function(e3) {
          if ("" === e3 || "" === e3.trim()) return false;
          try {
            return t2.bs58.encode(t2.bs58.decode(e3)) === e3;
          } catch (e4) {
            return false;
          }
        }, t2.base58ToBytes = function(e3) {
          try {
            return t2.bs58.decode(e3);
          } catch (t3) {
            throw new o.TraceableError(`Invalid base58 string ${e3}`, t3);
          }
        }, t2.default = t2.bs58;
      }, 160: (e2, t2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.default = function(e3) {
          let t3 = 5381;
          for (let r2 = 0; r2 < e3.length; r2++) t3 = (t3 << 5) + t3 + (255 & e3[`${r2}`]) | 0;
          return t3;
        };
      }, 664: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__exportStar || function(e3, t3) {
          for (var r3 in e3) "default" === r3 || Object.prototype.hasOwnProperty.call(t3, r3) || n(t3, e3, r3);
        };
        Object.defineProperty(t2, "__esModule", { value: true }), i(r2(7219), t2), i(r2(4468), t2), i(r2(160), t2), i(r2(2737), t2), i(r2(531), t2), i(r2(1347), t2), i(r2(6999), t2);
      }, 6999: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.number256ToNumber = t2.number256ToBigint = t2.convertAlphAmountWithDecimals = t2.convertAmountWithDecimals = t2.prettifyNumber = t2.prettifyExactAmount = t2.prettifyTokenAmount = t2.prettifyAttoAlphAmount = t2.prettifyNumberConfig = t2.isNumeric = void 0;
        const i = n(r2(1594));
        function o(e3, r3, n2) {
          const o2 = u(f(e3), r3);
          if (!(0, t2.isNumeric)(o2)) return;
          const s2 = new i.default(o2);
          let a2;
          if (s2.gte(1)) a2 = s2.toFormat(n2.minDecimalPlaces);
          else {
            const e4 = s2.toFormat(n2.maxDecimalPlaces).split(".")[1], t3 = e4?.match(/^0+/), r4 = t3 && t3.length ? t3[0].length : 0, i2 = Math.max(r4 + n2.minDecimalSignificantDigits, n2.minDecimalPlaces);
            a2 = s2.toFormat(i2);
          }
          let c2 = a2.replace(/0+$/, "");
          const d2 = 1 + a2.indexOf(".") + n2.decimalPlacesWhenZero;
          return c2.length < d2 && (c2 = a2.substring(0, d2)), "." === c2[c2.length - 1] && (c2 = c2.slice(0, -1)), c2;
        }
        t2.isNumeric = (e3) => !isNaN(parseFloat(e3)) && isFinite(e3), t2.prettifyNumberConfig = { ALPH: { minDecimalPlaces: 2, maxDecimalPlaces: 10, minDecimalSignificantDigits: 2, decimalPlacesWhenZero: 2 }, TOKEN: { minDecimalPlaces: 4, maxDecimalPlaces: 16, minDecimalSignificantDigits: 2, decimalPlacesWhenZero: 1 }, Exact: { minDecimalPlaces: 18, maxDecimalPlaces: 18, minDecimalSignificantDigits: 0, decimalPlacesWhenZero: 0 } }, t2.prettifyAttoAlphAmount = function(e3) {
          return o(e3, 18, t2.prettifyNumberConfig.ALPH);
        }, t2.prettifyTokenAmount = function(e3, r3) {
          return o(e3, r3, t2.prettifyNumberConfig.TOKEN);
        }, t2.prettifyExactAmount = function(e3, r3) {
          return o(e3, r3, t2.prettifyNumberConfig.Exact);
        }, t2.prettifyNumber = o;
        const s = BigInt(-1), a = BigInt(0), c = "0000";
        function u(e3, t3) {
          let r3 = "";
          e3 < a && (r3 = "-", e3 *= s);
          let n2 = e3.toString();
          if (0 === t3) return r3 + n2;
          for (; n2.length <= t3; ) n2 = c + n2;
          const i2 = n2.length - t3;
          for (n2 = n2.substring(0, i2) + "." + n2.substring(i2); "0" === n2[0] && "." !== n2[1]; ) n2 = n2.substring(1);
          for (; "0" === n2[n2.length - 1] && "." !== n2[n2.length - 2]; ) n2 = n2.substring(0, n2.length - 1);
          return r3 + n2;
        }
        function d(e3, t3) {
          try {
            const r3 = new i.default(e3).multipliedBy(Math.pow(10, t3));
            return BigInt(r3.toFormat(0, { groupSeparator: "" }));
          } catch (e4) {
            return;
          }
        }
        function f(e3) {
          return "string" == typeof e3 ? BigInt(e3) : e3;
        }
        t2.convertAmountWithDecimals = d, t2.convertAlphAmountWithDecimals = function(e3) {
          return d(e3, 18);
        }, t2.number256ToBigint = f, t2.number256ToNumber = function(e3, t3) {
          return parseFloat(u(f(e3), t3));
        };
      }, 1347: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3);
          var i2 = Object.getOwnPropertyDescriptor(t3, r3);
          i2 && !("get" in i2 ? !t3.__esModule : i2.writable || i2.configurable) || (i2 = { enumerable: true, get: function() {
            return t3[r3];
          } }), Object.defineProperty(e3, n2, i2);
        } : function(e3, t3, r3, n2) {
          void 0 === n2 && (n2 = r3), e3[n2] = t3[r3];
        }), i = this && this.__setModuleDefault || (Object.create ? function(e3, t3) {
          Object.defineProperty(e3, "default", { enumerable: true, value: t3 });
        } : function(e3, t3) {
          e3.default = t3;
        }), o = this && this.__importStar || function(e3) {
          if (e3 && e3.__esModule) return e3;
          var t3 = {};
          if (null != e3) for (var r3 in e3) "default" !== r3 && Object.prototype.hasOwnProperty.call(e3, r3) && n(t3, e3, r3);
          return i(t3, e3), t3;
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.verifySignature = t2.sign = void 0;
        const s = r2(3071), a = r2(664), c = o(r2(9695)), u = r2(4062), d = new s.ec("secp256k1");
        function f(e3) {
          if ("default" !== e3 && "bip340-schnorr" !== e3 && "gl-secp256k1" !== e3) throw new Error(`Invalid key type ${e3}, only supports secp256k1 and schnorr for now`);
        }
        c.utils.sha256Sync = (...e3) => {
          const t3 = (0, u.createHash)("sha256");
          for (const r3 of e3) t3.update(r3);
          return t3.digest();
        }, c.utils.hmacSha256Sync = (e3, ...t3) => {
          const r3 = (0, u.createHmac)("sha256", e3);
          return t3.forEach(((e4) => r3.update(e4))), Uint8Array.from(r3.digest());
        }, t2.sign = function(e3, t3, r3) {
          const n2 = r3 ?? "default";
          if (f(n2), "default" === n2 || "gl-secp256k1" === n2) {
            const r4 = d.keyFromPrivate(t3).sign(e3);
            return (0, a.encodeSignature)(r4);
          }
          {
            const r4 = c.schnorr.signSync((0, a.hexToBinUnsafe)(e3), (0, a.hexToBinUnsafe)(t3));
            return (0, a.binToHex)(r4);
          }
        }, t2.verifySignature = function(e3, t3, r3, n2) {
          const i2 = n2 ?? "default";
          f(i2);
          try {
            return "default" === i2 || "gl-secp256k1" === i2 ? d.keyFromPublic(t3, "hex").verify(e3, (0, a.signatureDecode)(d, r3)) : c.schnorr.verifySync((0, a.hexToBinUnsafe)(r3), (0, a.hexToBinUnsafe)(e3), (0, a.hexToBinUnsafe)(t3));
          } catch (e4) {
            return false;
          }
        };
      }, 531: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.Subscription = void 0;
        const i = n(r2(2579));
        t2.Subscription = class {
          constructor(e3) {
            this.pollingInterval = e3.pollingInterval, this.messageCallback = e3.messageCallback, this.errorCallback = e3.errorCallback, this.task = void 0, this.cancelled = false, this.eventEmitter = new i.default();
          }
          subscribe() {
            this.eventEmitter.on("tick", (async () => {
              await this.polling(), this.cancelled || (this.task = setTimeout((() => this.eventEmitter.emit("tick")), this.pollingInterval));
            })), this.eventEmitter.emit("tick");
          }
          unsubscribe() {
            this.eventEmitter.removeAllListeners(), this.cancelled = true, void 0 !== this.task && clearTimeout(this.task);
          }
          isCancelled() {
            return this.cancelled;
          }
        };
      }, 2737: function(e2, t2, r2) {
        "use strict";
        var n = this && this.__importDefault || function(e3) {
          return e3 && e3.__esModule ? e3 : { default: e3 };
        };
        Object.defineProperty(t2, "__esModule", { value: true }), t2.assertType = t2.xorByte = t2.concatBytes = t2.difficultyToTarget = t2.targetToDifficulty = t2.isDevnet = t2.sleep = t2.hexToString = t2.stringToHex = t2.blockChainIndex = t2.binToHex = t2.hexToBinUnsafe = t2.toNonNegativeBigInt = t2.isHexString = t2.signatureDecode = t2.encodeHexSignature = t2.encodeSignature = t2.networkIds = void 0;
        const i = r2(3071), o = n(r2(3900)), s = r2(7695);
        t2.networkIds = ["mainnet", "testnet", "devnet"];
        const a = new i.ec("secp256k1");
        function c(e3) {
          let t3 = e3.s;
          return a.n && 1 === e3.s.cmp(a.nh) && (t3 = a.n.sub(e3.s)), e3.r.toString("hex", 66).slice(2) + t3.toString("hex", 66).slice(2);
        }
        function u(e3) {
          return e3.length % 2 == 0 && /^[0-9a-fA-F]*$/.test(e3);
        }
        function d(e3) {
          const t3 = [];
          for (let r3 = 0; r3 < e3.length; r3 += 2) t3.push(parseInt(e3.slice(r3, r3 + 2), 16));
          return new Uint8Array(t3);
        }
        function f(e3) {
          return Array.from(e3).map(((e4) => e4.toString(16).padStart(2, "0"))).join("");
        }
        t2.encodeSignature = c, t2.encodeHexSignature = function(e3, t3) {
          return c({ r: new o.default(e3, "hex"), s: new o.default(t3, "hex") });
        }, t2.signatureDecode = function(e3, t3) {
          if (128 !== t3.length) throw new Error("Invalid signature length");
          const r3 = t3.slice(64, 128), n2 = new o.default(r3, "hex");
          if (e3.n && n2.cmp(e3.nh) < 1) return { r: t3.slice(0, 64), s: r3 };
          throw new Error("The signature is not normalized");
        }, t2.isHexString = u, t2.toNonNegativeBigInt = function(e3) {
          try {
            const t3 = BigInt(e3);
            return t3 < 0n ? void 0 : t3;
          } catch {
            return;
          }
        }, t2.hexToBinUnsafe = d, t2.binToHex = f, t2.blockChainIndex = function(e3) {
          if (64 != e3.length) throw Error(`Invalid block hash: ${e3}`);
          const t3 = Number("0x" + e3.slice(-4)) % s.TOTAL_NUMBER_OF_CHAINS;
          return { fromGroup: Math.floor(t3 / s.TOTAL_NUMBER_OF_GROUPS), toGroup: t3 % s.TOTAL_NUMBER_OF_GROUPS };
        }, t2.stringToHex = function(e3) {
          let t3 = "";
          for (let r3 = 0; r3 < e3.length; r3++) t3 += "" + e3.charCodeAt(r3).toString(16);
          return t3;
        }, t2.hexToString = function(e3) {
          if (!u(e3)) throw new Error(`Invalid hex string: ${e3}`);
          const t3 = d(e3);
          return new TextDecoder().decode(t3);
        }, t2.sleep = function(e3) {
          return new Promise(((t3) => setTimeout(t3, e3)));
        }, t2.isDevnet = function(e3) {
          return 0 !== e3 && 1 !== e3;
        }, t2.targetToDifficulty = function(e3) {
          if (!u(e3) || 8 !== e3.length) throw Error(`Invalid target ${e3}, expected a hex string of length 8`);
          const t3 = d(e3.slice(0, 2))[0], r3 = BigInt("0x" + e3.slice(2));
          return (1n << 256n) / (t3 <= 3 ? r3 >> BigInt(8 * (3 - t3)) : r3 << BigInt(8 * (t3 - 3)));
        }, t2.difficultyToTarget = function(e3) {
          const t3 = 1n << 256n, r3 = 1n === e3 ? t3 - 1n : t3 / e3, n2 = Math.floor((r3.toString(2).length + 7) / 8), i2 = Number(n2 <= 3 ? BigInt.asIntN(32, r3) << BigInt(8 * (3 - n2)) : BigInt.asIntN(32, r3 >> BigInt(8 * (n2 - 3)))), o2 = new Uint8Array(4);
          return o2[0] = n2, o2[1] = i2 >> 16 & 255, o2[2] = i2 >> 8 & 255, o2[3] = 255 & i2, f(o2);
        }, t2.concatBytes = function(e3) {
          const t3 = e3.reduce(((e4, t4) => e4 + t4.length), 0), r3 = new Uint8Array(t3);
          let n2 = 0;
          for (const t4 of e3) r3.set(t4, n2), n2 += t4.length;
          return r3;
        }, t2.xorByte = function(e3) {
          return 255 & (e3 >> 24 & 255 ^ e3 >> 16 & 255 ^ e3 >> 8 & 255 ^ 255 & e3);
        }, t2.assertType = function() {
        };
      }, 7219: (e2, t2, r2) => {
        "use strict";
        Object.defineProperty(t2, "__esModule", { value: true }), t2.WebCrypto = void 0;
        const n = r2(4062), i = "undefined" != typeof window && void 0 !== window.document;
        t2.WebCrypto = class {
          constructor() {
            this.subtle = i ? globalThis.crypto.subtle : n.webcrypto ? n.webcrypto.subtle : crypto.subtle;
          }
          getRandomValues(e3) {
            if (!ArrayBuffer.isView(e3)) throw new TypeError("Failed to execute 'getRandomValues' on 'Crypto': parameter 1 is not of type 'ArrayBufferView'");
            const t3 = new Uint8Array(e3.buffer, e3.byteOffset, e3.byteLength);
            return i ? globalThis.crypto.getRandomValues(t3) : (0, n.randomFillSync)(t3), e3;
          }
        };
      }, 3349: (e2) => {
        "use strict";
        e2.exports = JSON.parse('{"aes-128-ecb":{"cipher":"AES","key":128,"iv":0,"mode":"ECB","type":"block"},"aes-192-ecb":{"cipher":"AES","key":192,"iv":0,"mode":"ECB","type":"block"},"aes-256-ecb":{"cipher":"AES","key":256,"iv":0,"mode":"ECB","type":"block"},"aes-128-cbc":{"cipher":"AES","key":128,"iv":16,"mode":"CBC","type":"block"},"aes-192-cbc":{"cipher":"AES","key":192,"iv":16,"mode":"CBC","type":"block"},"aes-256-cbc":{"cipher":"AES","key":256,"iv":16,"mode":"CBC","type":"block"},"aes128":{"cipher":"AES","key":128,"iv":16,"mode":"CBC","type":"block"},"aes192":{"cipher":"AES","key":192,"iv":16,"mode":"CBC","type":"block"},"aes256":{"cipher":"AES","key":256,"iv":16,"mode":"CBC","type":"block"},"aes-128-cfb":{"cipher":"AES","key":128,"iv":16,"mode":"CFB","type":"stream"},"aes-192-cfb":{"cipher":"AES","key":192,"iv":16,"mode":"CFB","type":"stream"},"aes-256-cfb":{"cipher":"AES","key":256,"iv":16,"mode":"CFB","type":"stream"},"aes-128-cfb8":{"cipher":"AES","key":128,"iv":16,"mode":"CFB8","type":"stream"},"aes-192-cfb8":{"cipher":"AES","key":192,"iv":16,"mode":"CFB8","type":"stream"},"aes-256-cfb8":{"cipher":"AES","key":256,"iv":16,"mode":"CFB8","type":"stream"},"aes-128-cfb1":{"cipher":"AES","key":128,"iv":16,"mode":"CFB1","type":"stream"},"aes-192-cfb1":{"cipher":"AES","key":192,"iv":16,"mode":"CFB1","type":"stream"},"aes-256-cfb1":{"cipher":"AES","key":256,"iv":16,"mode":"CFB1","type":"stream"},"aes-128-ofb":{"cipher":"AES","key":128,"iv":16,"mode":"OFB","type":"stream"},"aes-192-ofb":{"cipher":"AES","key":192,"iv":16,"mode":"OFB","type":"stream"},"aes-256-ofb":{"cipher":"AES","key":256,"iv":16,"mode":"OFB","type":"stream"},"aes-128-ctr":{"cipher":"AES","key":128,"iv":16,"mode":"CTR","type":"stream"},"aes-192-ctr":{"cipher":"AES","key":192,"iv":16,"mode":"CTR","type":"stream"},"aes-256-ctr":{"cipher":"AES","key":256,"iv":16,"mode":"CTR","type":"stream"},"aes-128-gcm":{"cipher":"AES","key":128,"iv":12,"mode":"GCM","type":"auth"},"aes-192-gcm":{"cipher":"AES","key":192,"iv":12,"mode":"GCM","type":"auth"},"aes-256-gcm":{"cipher":"AES","key":256,"iv":12,"mode":"GCM","type":"auth"}}');
      }, 6980: (e2) => {
        "use strict";
        e2.exports = JSON.parse('{"sha224WithRSAEncryption":{"sign":"rsa","hash":"sha224","id":"302d300d06096086480165030402040500041c"},"RSA-SHA224":{"sign":"ecdsa/rsa","hash":"sha224","id":"302d300d06096086480165030402040500041c"},"sha256WithRSAEncryption":{"sign":"rsa","hash":"sha256","id":"3031300d060960864801650304020105000420"},"RSA-SHA256":{"sign":"ecdsa/rsa","hash":"sha256","id":"3031300d060960864801650304020105000420"},"sha384WithRSAEncryption":{"sign":"rsa","hash":"sha384","id":"3041300d060960864801650304020205000430"},"RSA-SHA384":{"sign":"ecdsa/rsa","hash":"sha384","id":"3041300d060960864801650304020205000430"},"sha512WithRSAEncryption":{"sign":"rsa","hash":"sha512","id":"3051300d060960864801650304020305000440"},"RSA-SHA512":{"sign":"ecdsa/rsa","hash":"sha512","id":"3051300d060960864801650304020305000440"},"RSA-SHA1":{"sign":"rsa","hash":"sha1","id":"3021300906052b0e03021a05000414"},"ecdsa-with-SHA1":{"sign":"ecdsa","hash":"sha1","id":""},"sha256":{"sign":"ecdsa","hash":"sha256","id":""},"sha224":{"sign":"ecdsa","hash":"sha224","id":""},"sha384":{"sign":"ecdsa","hash":"sha384","id":""},"sha512":{"sign":"ecdsa","hash":"sha512","id":""},"DSA-SHA":{"sign":"dsa","hash":"sha1","id":""},"DSA-SHA1":{"sign":"dsa","hash":"sha1","id":""},"DSA":{"sign":"dsa","hash":"sha1","id":""},"DSA-WITH-SHA224":{"sign":"dsa","hash":"sha224","id":""},"DSA-SHA224":{"sign":"dsa","hash":"sha224","id":""},"DSA-WITH-SHA256":{"sign":"dsa","hash":"sha256","id":""},"DSA-SHA256":{"sign":"dsa","hash":"sha256","id":""},"DSA-WITH-SHA384":{"sign":"dsa","hash":"sha384","id":""},"DSA-SHA384":{"sign":"dsa","hash":"sha384","id":""},"DSA-WITH-SHA512":{"sign":"dsa","hash":"sha512","id":""},"DSA-SHA512":{"sign":"dsa","hash":"sha512","id":""},"DSA-RIPEMD160":{"sign":"dsa","hash":"rmd160","id":""},"ripemd160WithRSA":{"sign":"rsa","hash":"rmd160","id":"3021300906052b2403020105000414"},"RSA-RIPEMD160":{"sign":"rsa","hash":"rmd160","id":"3021300906052b2403020105000414"},"md5WithRSAEncryption":{"sign":"rsa","hash":"md5","id":"3020300c06082a864886f70d020505000410"},"RSA-MD5":{"sign":"rsa","hash":"md5","id":"3020300c06082a864886f70d020505000410"}}');
      }, 9262: (e2) => {
        "use strict";
        e2.exports = JSON.parse('{"1.3.132.0.10":"secp256k1","1.3.132.0.33":"p224","1.2.840.10045.3.1.1":"p192","1.2.840.10045.3.1.7":"p256","1.3.132.0.34":"p384","1.3.132.0.35":"p521"}');
      }, 7821: (e2) => {
        "use strict";
        e2.exports = JSON.parse('{"modp1":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff"},"modp2":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff"},"modp5":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"},"modp14":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff"},"modp15":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"},"modp16":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"},"modp17":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff"},"modp18":{"gen":"02","prime":"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff"}}');
      }, 3718: (e2) => {
        "use strict";
        e2.exports = { rE: "6.6.1" };
      }, 2853: (e2) => {
        "use strict";
        e2.exports = JSON.parse('{"2.16.840.1.101.3.4.1.1":"aes-128-ecb","2.16.840.1.101.3.4.1.2":"aes-128-cbc","2.16.840.1.101.3.4.1.3":"aes-128-ofb","2.16.840.1.101.3.4.1.4":"aes-128-cfb","2.16.840.1.101.3.4.1.21":"aes-192-ecb","2.16.840.1.101.3.4.1.22":"aes-192-cbc","2.16.840.1.101.3.4.1.23":"aes-192-ofb","2.16.840.1.101.3.4.1.24":"aes-192-cfb","2.16.840.1.101.3.4.1.41":"aes-256-ecb","2.16.840.1.101.3.4.1.42":"aes-256-cbc","2.16.840.1.101.3.4.1.43":"aes-256-ofb","2.16.840.1.101.3.4.1.44":"aes-256-cfb"}');
      } }, t = {};
      function r(n) {
        var i = t[n];
        if (void 0 !== i) return i.exports;
        var o = t[n] = { id: n, loaded: false, exports: {} };
        return e[n].call(o.exports, o, o.exports, r), o.loaded = true, o.exports;
      }
      return r.g = (function() {
        if ("object" == typeof globalThis) return globalThis;
        try {
          return this || new Function("return this")();
        } catch (e2) {
          if ("object" == typeof window) return window;
        }
      })(), r.nmd = (e2) => (e2.paths = [], e2.children || (e2.children = []), e2), r(2126);
    })()));
  }
});

// <stdin>
var ns = __toESM(require_alephium_web3_min());
var mod = ns.default ?? ns;
var stdin_default = mod;
var web3 = mod["web3"];
var codec = mod["codec"];
var utils = mod["utils"];
var node = mod["node"];
var explorer = mod["explorer"];
var NodeProvider = mod["NodeProvider"];
var tryGetCallResult = mod["tryGetCallResult"];
var ExplorerProvider = mod["ExplorerProvider"];
var PrimitiveTypes = mod["PrimitiveTypes"];
var toApiToken = mod["toApiToken"];
var toApiTokens = mod["toApiTokens"];
var fromApiToken = mod["fromApiToken"];
var fromApiTokens = mod["fromApiTokens"];
var toApiBoolean = mod["toApiBoolean"];
var toApiNumber256 = mod["toApiNumber256"];
var toApiNumber256Optional = mod["toApiNumber256Optional"];
var fromApiNumber256 = mod["fromApiNumber256"];
var toApiByteVec = mod["toApiByteVec"];
var toApiAddress = mod["toApiAddress"];
var toApiArray = mod["toApiArray"];
var toApiVal = mod["toApiVal"];
var fromApiPrimitiveVal = mod["fromApiPrimitiveVal"];
var decodeTupleType = mod["decodeTupleType"];
var decodeArrayType = mod["decodeArrayType"];
var getDefaultPrimitiveValue = mod["getDefaultPrimitiveValue"];
var forwardRequests = mod["forwardRequests"];
var requestWithLog = mod["requestWithLog"];
var request = mod["request"];
var StdInterfaceIds = mod["StdInterfaceIds"];
var convertHttpResponse = mod["convertHttpResponse"];
var isBalanceEqual = mod["isBalanceEqual"];
var DappTransactionBuilder = mod["DappTransactionBuilder"];
var encodeByteVec = mod["encodeByteVec"];
var encodeAddress = mod["encodeAddress"];
var VmValType = mod["VmValType"];
var encodeVmBool = mod["encodeVmBool"];
var encodeVmI256 = mod["encodeVmI256"];
var encodeVmU256 = mod["encodeVmU256"];
var encodeVmByteVec = mod["encodeVmByteVec"];
var encodeVmAddress = mod["encodeVmAddress"];
var boolVal = mod["boolVal"];
var i256Val = mod["i256Val"];
var u256Val = mod["u256Val"];
var byteVecVal = mod["byteVecVal"];
var addressVal = mod["addressVal"];
var encodePrimitiveValues = mod["encodePrimitiveValues"];
var encodeScriptFieldAsString = mod["encodeScriptFieldAsString"];
var encodeScriptField = mod["encodeScriptField"];
var splitFields = mod["splitFields"];
var parseMapType = mod["parseMapType"];
var encodeMapPrefix = mod["encodeMapPrefix"];
var calcFieldSize = mod["calcFieldSize"];
var tryDecodeMapDebugLog = mod["tryDecodeMapDebugLog"];
var decodePrimitive = mod["decodePrimitive"];
var encodeMapKey = mod["encodeMapKey"];
var typeLength = mod["typeLength"];
var flattenFields = mod["flattenFields"];
var buildScriptByteCode = mod["buildScriptByteCode"];
var encodeContractFields = mod["encodeContractFields"];
var buildContractByteCode = mod["buildContractByteCode"];
var encodeContractField = mod["encodeContractField"];
var buildDebugBytecode = mod["buildDebugBytecode"];
var StdIdFieldName = mod["StdIdFieldName"];
var DEFAULT_NODE_COMPILER_OPTIONS = mod["DEFAULT_NODE_COMPILER_OPTIONS"];
var DEFAULT_COMPILER_OPTIONS = mod["DEFAULT_COMPILER_OPTIONS"];
var Struct = mod["Struct"];
var Artifact = mod["Artifact"];
var Contract = mod["Contract"];
var Script = mod["Script"];
var fromApiFields = mod["fromApiFields"];
var getDefaultValue = mod["getDefaultValue"];
var fromApiArray = mod["fromApiArray"];
var fromApiEventFields = mod["fromApiEventFields"];
var randomTxId = mod["randomTxId"];
var ContractFactory = mod["ContractFactory"];
var ExecutableScript = mod["ExecutableScript"];
var CreateContractEventAddresses = mod["CreateContractEventAddresses"];
var DestroyContractEventAddresses = mod["DestroyContractEventAddresses"];
var decodeContractCreatedEvent = mod["decodeContractCreatedEvent"];
var decodeContractDestroyedEvent = mod["decodeContractDestroyedEvent"];
var subscribeEventsFromContract = mod["subscribeEventsFromContract"];
var addStdIdToFields = mod["addStdIdToFields"];
var extractMapsFromApiResult = mod["extractMapsFromApiResult"];
var testMethod = mod["testMethod"];
var getDebugMessagesFromTx = mod["getDebugMessagesFromTx"];
var printDebugMessagesFromTx = mod["printDebugMessagesFromTx"];
var RalphMap = mod["RalphMap"];
var getMapItem = mod["getMapItem"];
var ContractInstance = mod["ContractInstance"];
var fetchContractState = mod["fetchContractState"];
var subscribeContractCreatedEvent = mod["subscribeContractCreatedEvent"];
var subscribeContractDestroyedEvent = mod["subscribeContractDestroyedEvent"];
var decodeEvent = mod["decodeEvent"];
var subscribeContractEvent = mod["subscribeContractEvent"];
var subscribeContractEvents = mod["subscribeContractEvents"];
var callMethod = mod["callMethod"];
var signExecuteMethod = mod["signExecuteMethod"];
var multicallMethods = mod["multicallMethods"];
var getContractEventsCurrentCount = mod["getContractEventsCurrentCount"];
var getContractIdFromUnsignedTx = mod["getContractIdFromUnsignedTx"];
var getTokenIdFromUnsignedTx = mod["getTokenIdFromUnsignedTx"];
var getContractCodeByCodeHash = mod["getContractCodeByCodeHash"];
var EventSubscription = mod["EventSubscription"];
var subscribeToEvents = mod["subscribeToEvents"];
var ScriptSimulator = mod["ScriptSimulator"];
var SignerProvider = mod["SignerProvider"];
var InteractiveSignerProvider = mod["InteractiveSignerProvider"];
var SignerProviderSimple = mod["SignerProviderSimple"];
var SignerProviderWithMultipleAccounts = mod["SignerProviderWithMultipleAccounts"];
var SignerProviderWithCachedAccounts = mod["SignerProviderWithCachedAccounts"];
var extendMessage = mod["extendMessage"];
var hashMessage = mod["hashMessage"];
var verifySignedMessage = mod["verifySignedMessage"];
var toApiDestination = mod["toApiDestination"];
var toApiDestinations = mod["toApiDestinations"];
var fromApiDestination = mod["fromApiDestination"];
var groupedKeyTypes = mod["groupedKeyTypes"];
var grouplessKeyTypes = mod["grouplessKeyTypes"];
var keyTypes = mod["keyTypes"];
var isGroupedKeyType = mod["isGroupedKeyType"];
var isGrouplessKeyType = mod["isGrouplessKeyType"];
var isGroupedAccount = mod["isGroupedAccount"];
var isGrouplessAccount = mod["isGrouplessAccount"];
var TransactionBuilder = mod["TransactionBuilder"];
var getGroupFromTxScript = mod["getGroupFromTxScript"];
var updateBytecodeWithGroup = mod["updateBytecodeWithGroup"];
var WebCrypto = mod["WebCrypto"];
var bs58 = mod["bs58"];
var isBase58 = mod["isBase58"];
var base58ToBytes = mod["base58ToBytes"];
var networkIds = mod["networkIds"];
var encodeSignature = mod["encodeSignature"];
var encodeHexSignature = mod["encodeHexSignature"];
var signatureDecode = mod["signatureDecode"];
var isHexString = mod["isHexString"];
var toNonNegativeBigInt = mod["toNonNegativeBigInt"];
var hexToBinUnsafe = mod["hexToBinUnsafe"];
var binToHex = mod["binToHex"];
var blockChainIndex = mod["blockChainIndex"];
var stringToHex = mod["stringToHex"];
var hexToString = mod["hexToString"];
var sleep = mod["sleep"];
var isDevnet = mod["isDevnet"];
var targetToDifficulty = mod["targetToDifficulty"];
var difficultyToTarget = mod["difficultyToTarget"];
var concatBytes = mod["concatBytes"];
var xorByte = mod["xorByte"];
var assertType = mod["assertType"];
var Subscription = mod["Subscription"];
var sign = mod["sign"];
var verifySignature = mod["verifySignature"];
var isNumeric = mod["isNumeric"];
var prettifyNumberConfig = mod["prettifyNumberConfig"];
var prettifyAttoAlphAmount = mod["prettifyAttoAlphAmount"];
var prettifyTokenAmount = mod["prettifyTokenAmount"];
var prettifyExactAmount = mod["prettifyExactAmount"];
var prettifyNumber = mod["prettifyNumber"];
var convertAmountWithDecimals = mod["convertAmountWithDecimals"];
var convertAlphAmountWithDecimals = mod["convertAlphAmountWithDecimals"];
var number256ToBigint = mod["number256ToBigint"];
var number256ToNumber = mod["number256ToNumber"];
var TxStatusSubscription = mod["TxStatusSubscription"];
var subscribeToTxStatus = mod["subscribeToTxStatus"];
var transactionSign = mod["transactionSign"];
var transactionVerifySignature = mod["transactionVerifySignature"];
var waitForTxConfirmation = mod["waitForTxConfirmation"];
var groupIndexOfTransaction = mod["groupIndexOfTransaction"];
var validNFTTokenUriMetaDataFields = mod["validNFTTokenUriMetaDataFields"];
var validNFTTokenUriMetaDataAttributesFields = mod["validNFTTokenUriMetaDataAttributesFields"];
var validNFTUriMetaDataAttributeTypes = mod["validNFTUriMetaDataAttributeTypes"];
var validNFTCollectionUriMetaDataFields = mod["validNFTCollectionUriMetaDataFields"];
var validateNFTTokenUriMetaData = mod["validateNFTTokenUriMetaData"];
var validateNFTCollectionUriMetaData = mod["validateNFTCollectionUriMetaData"];
var validateNFTBaseUri = mod["validateNFTBaseUri"];
var TOTAL_NUMBER_OF_GROUPS = mod["TOTAL_NUMBER_OF_GROUPS"];
var TOTAL_NUMBER_OF_CHAINS = mod["TOTAL_NUMBER_OF_CHAINS"];
var MIN_UTXO_SET_AMOUNT = mod["MIN_UTXO_SET_AMOUNT"];
var ALPH_TOKEN_ID = mod["ALPH_TOKEN_ID"];
var ONE_ALPH = mod["ONE_ALPH"];
var DUST_AMOUNT = mod["DUST_AMOUNT"];
var ZERO_ADDRESS = mod["ZERO_ADDRESS"];
var NULL_CONTRACT_ADDRESS = mod["NULL_CONTRACT_ADDRESS"];
var DEFAULT_GAS_AMOUNT = mod["DEFAULT_GAS_AMOUNT"];
var DEFAULT_GAS_PRICE = mod["DEFAULT_GAS_PRICE"];
var DEFAULT_GAS_ATTOALPH_AMOUNT = mod["DEFAULT_GAS_ATTOALPH_AMOUNT"];
var DEFAULT_GAS_ALPH_AMOUNT = mod["DEFAULT_GAS_ALPH_AMOUNT"];
var MINIMAL_CONTRACT_DEPOSIT = mod["MINIMAL_CONTRACT_DEPOSIT"];
var MAP_ENTRY_DEPOSIT = mod["MAP_ENTRY_DEPOSIT"];
var isDebugModeEnabled = mod["isDebugModeEnabled"];
var enableDebugMode = mod["enableDebugMode"];
var disableDebugMode = mod["disableDebugMode"];
var isContractDebugMessageEnabled = mod["isContractDebugMessageEnabled"];
var enableContractDebugMessage = mod["enableContractDebugMessage"];
var disableContractDebugMessage = mod["disableContractDebugMessage"];
var BlockSubscription = mod["BlockSubscription"];
var AddressType = mod["AddressType"];
var validateAddress = mod["validateAddress"];
var isValidAddress = mod["isValidAddress"];
var addressToBytes = mod["addressToBytes"];
var isAssetAddress = mod["isAssetAddress"];
var isGrouplessAddress = mod["isGrouplessAddress"];
var isGrouplessAddressWithoutGroupIndex = mod["isGrouplessAddressWithoutGroupIndex"];
var isGrouplessAddressWithGroupIndex = mod["isGrouplessAddressWithGroupIndex"];
var defaultGroupOfGrouplessAddress = mod["defaultGroupOfGrouplessAddress"];
var isContractAddress = mod["isContractAddress"];
var groupOfAddress = mod["groupOfAddress"];
var contractIdFromAddress = mod["contractIdFromAddress"];
var tokenIdFromAddress = mod["tokenIdFromAddress"];
var groupOfPrivateKey = mod["groupOfPrivateKey"];
var publicKeyFromPrivateKey = mod["publicKeyFromPrivateKey"];
var addressFromPublicKey = mod["addressFromPublicKey"];
var addressFromScript = mod["addressFromScript"];
var addressFromContractId = mod["addressFromContractId"];
var addressFromTokenId = mod["addressFromTokenId"];
var contractIdFromTx = mod["contractIdFromTx"];
var subContractId = mod["subContractId"];
var groupOfLockupScript = mod["groupOfLockupScript"];
var groupFromBytes = mod["groupFromBytes"];
var groupFromHint = mod["groupFromHint"];
var hasExplicitGroupIndex = mod["hasExplicitGroupIndex"];
var addressWithoutExplicitGroupIndex = mod["addressWithoutExplicitGroupIndex"];
var addressFromLockupScript = mod["addressFromLockupScript"];
var validateExchangeAddress = mod["validateExchangeAddress"];
var getSenderAddress = mod["getSenderAddress"];
var isALPHTransferTx = mod["isALPHTransferTx"];
var getALPHDepositInfo = mod["getALPHDepositInfo"];
var getDepositInfo = mod["getDepositInfo"];
var TraceableError = mod["TraceableError"];
export {
  ALPH_TOKEN_ID,
  AddressType,
  Artifact,
  BlockSubscription,
  Contract,
  ContractFactory,
  ContractInstance,
  CreateContractEventAddresses,
  DEFAULT_COMPILER_OPTIONS,
  DEFAULT_GAS_ALPH_AMOUNT,
  DEFAULT_GAS_AMOUNT,
  DEFAULT_GAS_ATTOALPH_AMOUNT,
  DEFAULT_GAS_PRICE,
  DEFAULT_NODE_COMPILER_OPTIONS,
  DUST_AMOUNT,
  DappTransactionBuilder,
  DestroyContractEventAddresses,
  EventSubscription,
  ExecutableScript,
  ExplorerProvider,
  InteractiveSignerProvider,
  MAP_ENTRY_DEPOSIT,
  MINIMAL_CONTRACT_DEPOSIT,
  MIN_UTXO_SET_AMOUNT,
  NULL_CONTRACT_ADDRESS,
  NodeProvider,
  ONE_ALPH,
  PrimitiveTypes,
  RalphMap,
  Script,
  ScriptSimulator,
  SignerProvider,
  SignerProviderSimple,
  SignerProviderWithCachedAccounts,
  SignerProviderWithMultipleAccounts,
  StdIdFieldName,
  StdInterfaceIds,
  Struct,
  Subscription,
  TOTAL_NUMBER_OF_CHAINS,
  TOTAL_NUMBER_OF_GROUPS,
  TraceableError,
  TransactionBuilder,
  TxStatusSubscription,
  VmValType,
  WebCrypto,
  ZERO_ADDRESS,
  addStdIdToFields,
  addressFromContractId,
  addressFromLockupScript,
  addressFromPublicKey,
  addressFromScript,
  addressFromTokenId,
  addressToBytes,
  addressVal,
  addressWithoutExplicitGroupIndex,
  assertType,
  base58ToBytes,
  binToHex,
  blockChainIndex,
  boolVal,
  bs58,
  buildContractByteCode,
  buildDebugBytecode,
  buildScriptByteCode,
  byteVecVal,
  calcFieldSize,
  callMethod,
  codec,
  concatBytes,
  contractIdFromAddress,
  contractIdFromTx,
  convertAlphAmountWithDecimals,
  convertAmountWithDecimals,
  convertHttpResponse,
  decodeArrayType,
  decodeContractCreatedEvent,
  decodeContractDestroyedEvent,
  decodeEvent,
  decodePrimitive,
  decodeTupleType,
  stdin_default as default,
  defaultGroupOfGrouplessAddress,
  difficultyToTarget,
  disableContractDebugMessage,
  disableDebugMode,
  enableContractDebugMessage,
  enableDebugMode,
  encodeAddress,
  encodeByteVec,
  encodeContractField,
  encodeContractFields,
  encodeHexSignature,
  encodeMapKey,
  encodeMapPrefix,
  encodePrimitiveValues,
  encodeScriptField,
  encodeScriptFieldAsString,
  encodeSignature,
  encodeVmAddress,
  encodeVmBool,
  encodeVmByteVec,
  encodeVmI256,
  encodeVmU256,
  explorer,
  extendMessage,
  extractMapsFromApiResult,
  fetchContractState,
  flattenFields,
  forwardRequests,
  fromApiArray,
  fromApiDestination,
  fromApiEventFields,
  fromApiFields,
  fromApiNumber256,
  fromApiPrimitiveVal,
  fromApiToken,
  fromApiTokens,
  getALPHDepositInfo,
  getContractCodeByCodeHash,
  getContractEventsCurrentCount,
  getContractIdFromUnsignedTx,
  getDebugMessagesFromTx,
  getDefaultPrimitiveValue,
  getDefaultValue,
  getDepositInfo,
  getGroupFromTxScript,
  getMapItem,
  getSenderAddress,
  getTokenIdFromUnsignedTx,
  groupFromBytes,
  groupFromHint,
  groupIndexOfTransaction,
  groupOfAddress,
  groupOfLockupScript,
  groupOfPrivateKey,
  groupedKeyTypes,
  grouplessKeyTypes,
  hasExplicitGroupIndex,
  hashMessage,
  hexToBinUnsafe,
  hexToString,
  i256Val,
  isALPHTransferTx,
  isAssetAddress,
  isBalanceEqual,
  isBase58,
  isContractAddress,
  isContractDebugMessageEnabled,
  isDebugModeEnabled,
  isDevnet,
  isGroupedAccount,
  isGroupedKeyType,
  isGrouplessAccount,
  isGrouplessAddress,
  isGrouplessAddressWithGroupIndex,
  isGrouplessAddressWithoutGroupIndex,
  isGrouplessKeyType,
  isHexString,
  isNumeric,
  isValidAddress,
  keyTypes,
  multicallMethods,
  networkIds,
  node,
  number256ToBigint,
  number256ToNumber,
  parseMapType,
  prettifyAttoAlphAmount,
  prettifyExactAmount,
  prettifyNumber,
  prettifyNumberConfig,
  prettifyTokenAmount,
  printDebugMessagesFromTx,
  publicKeyFromPrivateKey,
  randomTxId,
  request,
  requestWithLog,
  sign,
  signExecuteMethod,
  signatureDecode,
  sleep,
  splitFields,
  stringToHex,
  subContractId,
  subscribeContractCreatedEvent,
  subscribeContractDestroyedEvent,
  subscribeContractEvent,
  subscribeContractEvents,
  subscribeEventsFromContract,
  subscribeToEvents,
  subscribeToTxStatus,
  targetToDifficulty,
  testMethod,
  toApiAddress,
  toApiArray,
  toApiBoolean,
  toApiByteVec,
  toApiDestination,
  toApiDestinations,
  toApiNumber256,
  toApiNumber256Optional,
  toApiToken,
  toApiTokens,
  toApiVal,
  toNonNegativeBigInt,
  tokenIdFromAddress,
  transactionSign,
  transactionVerifySignature,
  tryDecodeMapDebugLog,
  tryGetCallResult,
  typeLength,
  u256Val,
  updateBytecodeWithGroup,
  utils,
  validNFTCollectionUriMetaDataFields,
  validNFTTokenUriMetaDataAttributesFields,
  validNFTTokenUriMetaDataFields,
  validNFTUriMetaDataAttributeTypes,
  validateAddress,
  validateExchangeAddress,
  validateNFTBaseUri,
  validateNFTCollectionUriMetaData,
  validateNFTTokenUriMetaData,
  verifySignature,
  verifySignedMessage,
  waitForTxConfirmation,
  web3,
  xorByte
};
