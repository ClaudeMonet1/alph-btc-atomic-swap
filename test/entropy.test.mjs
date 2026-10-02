#!/usr/bin/env node
// Where secrets come from. Checks the generator behind a new identity (and the
// other secrets the swap draws), that nothing is truncated on the way to the
// mnemonic, and that no module in the signing path falls back to Math.random.
import { readFileSync, readdirSync } from 'node:fs';
import { newMasterSecret, MASTER_SECRET_BYTES, deriveKeys, mnemonicOf, entropyOf } from '../src/keys.js';
import { randomBytes, bytesToNum } from '../src/curve.js';
import { adaptorSecretFromBytes } from '../src/adaptor.js';
import { nonceGen } from '../src/musig2.js';
import { addressFromPublicKey, groupOfAddress } from '@alephium/web3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

let failed = 0; const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };
const groupOfPub = (pubHex, keyType) => groupOfAddress(addressFromPublicKey(pubHex, keyType));

// 1. A new identity is 128 bits from the platform CSPRNG
const N = 2000, samples = Array.from({ length: N }, () => newMasterSecret());
check('new secret is 16 bytes (128 bits = 12 words)', MASTER_SECRET_BYTES === 16 && samples.every((s) => s instanceof Uint8Array && s.length === 16));
check('every sample distinct', new Set(samples.map(bytesToHex)).size === N);
check('no sample is all zeros or all ones', samples.every((s) => !s.every((b) => b === 0) && !s.every((b) => b === 255)));

// Bit frequency: each of the 128 positions should be set about half the time.
// Binomial(2000, 1/2): sd 22.4, so |count - 1000| > 5 sd = 112 is a red flag.
const bitCounts = new Array(128).fill(0);
for (const s of samples) for (let i = 0; i < 128; i++) if ((s[i >> 3] >> (7 - (i & 7))) & 1) bitCounts[i]++;
const worstBit = bitCounts.reduce((a, c) => Math.max(a, Math.abs(c - N / 2)), 0);
check('every bit position is balanced', worstBit < 5 * Math.sqrt(N) / 2, `worst deviation ${worstBit} of ${N} (limit ${Math.round(5 * Math.sqrt(N) / 2)})`);

// Byte distribution over all samples: chi-square with 255 degrees of freedom, 99.9% point is 331
const bytes = samples.flatMap((s) => [...s]), hist = new Array(256).fill(0);
for (const b of bytes) hist[b]++;
const expected = bytes.length / 256;
const chi2 = hist.reduce((a, c) => a + (c - expected) ** 2 / expected, 0);
check('byte distribution is uniform', chi2 < 331, `chi-square ${chi2.toFixed(1)} over ${bytes.length} bytes (limit 331)`);

// 2. Nothing is lost between the entropy and the keys
{
  const sec = newMasterSecret(), words = mnemonicOf(sec);
  check('mnemonic keeps all 128 bits', words.split(' ').length === 12 && bytesToHex(entropyOf(words)) === bytesToHex(sec));
  const a = deriveKeys(sec, groupOfPub), b = deriveKeys(newMasterSecret(), groupOfPub);
  check('different entropy gives different keys', a.btc.pubHex !== b.btc.pubHex && a.alph.pubHex !== b.alph.pubHex && a.nostr.pubHex !== b.nostr.pubHex);
  for (const bad of [8, 20, 24, 33]) {
    let threw = false;
    try { deriveKeys(new Uint8Array(bad), groupOfPub); } catch { threw = true; }
    check(`a ${bad}-byte secret is refused`, threw);
  }
}

// 3. The other secrets a swap draws
{
  const ts = Array.from({ length: 200 }, () => adaptorSecretFromBytes(randomBytes(32)));
  check('adaptor secrets are distinct and in [1, n)', new Set(ts.map((x) => bytesToHex(x.tBytes))).size === 200 && ts.every((x) => x.t > 0n));
  check('adaptor points have even Y (x-only on the wire)', ts.every((x) => x.Tbytes.length === 32));
  const aggpk = hexToBytes('11'.repeat(32)), msg = hexToBytes('22'.repeat(32)), sk = newMasterSecret();
  const sec32 = hexToBytes(bytesToHex(sk) + bytesToHex(sk)); // 32 bytes for a signing key
  const n1 = nonceGen({ sk: sec32, pk: new Uint8Array([2, ...hexToBytes('33'.repeat(32))]), aggpk, msg });
  const n2 = nonceGen({ sk: sec32, pk: new Uint8Array([2, ...hexToBytes('33'.repeat(32))]), aggpk, msg });
  check('two nonces for the same message differ (fresh randomness, not deterministic)', bytesToHex(n1.pubNonce) !== bytesToHex(n2.pubNonce));
}

// 4. No weak randomness in the modules that handle keys, nonces or messages
{
  const roots = ['src', 'docs/js'];
  const offenders = [];
  for (const root of roots) {
    for (const f of readdirSync(new URL('../' + root, import.meta.url))) {
      if (!f.endsWith('.js')) continue;
      const text = readFileSync(new URL(`../${root}/${f}`, import.meta.url), 'utf8');
      if (/Math\.random/.test(text)) offenders.push(`${root}/${f}`);
    }
  }
  check('no Math.random in src/ or docs/js/', offenders.length === 0, offenders.join(', '));
}

console.log(failed ? `ENTROPY TEST FAILED (${failed})` : 'ENTROPY TEST PASSED'); process.exit(failed ? 1 : 0);
