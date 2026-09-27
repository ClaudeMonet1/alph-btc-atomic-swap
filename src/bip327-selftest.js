// Runs the BIP327 test vectors (docs/spec/bip327/*.json) against musig2.js and
// an adaptor round trip against adaptor.js. Same file in Node and the browser:
// the caller supplies loadJson(fileName) -> parsed vector file.
import * as m from './musig2.js';
import { xonlyKeyAgg, tapTweak, swapNonceGen, adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract, adaptorSecretFromBytes } from './adaptor.js';
import { hexToBytes, bytesToHex, schnorrVerify, randomBytes, randomSecretKey, schnorrGetPublicKey } from './curve.js';

const H = (h) => hexToBytes(h);
const eqHex = (bytes, hex) => bytesToHex(bytes).toLowerCase() === hex.toLowerCase();
const pick = (arr, idx) => idx.map((i) => H(arr[i]));

function expectError(fn, spec) {
  try { fn(); return `no error (expected ${JSON.stringify(spec)})`; } catch (e) {
    if (spec.type === 'invalid_contribution') {
      if (!(e instanceof m.InvalidContributionError)) return `wrong error class: ${e.message}`;
      if (e.contrib !== spec.contrib) return `wrong contrib ${e.contrib} (expected ${spec.contrib})`;
      if ((spec.signer ?? null) !== e.signer) return `wrong signer ${e.signer} (expected ${spec.signer})`;
      return null;
    }
    if (spec.type === 'value') {
      if (e instanceof m.InvalidContributionError) return `unexpected InvalidContributionError: ${e.message}`;
      if (spec.message && e.message !== spec.message) return `wrong message "${e.message}" (expected "${spec.message}")`;
      return null;
    }
    return `unknown spec type ${spec.type}`;
  }
}

export async function runVectors(loadJson) {
  const results = [];
  const check = (name, problem) => results.push({ name, ok: problem === null, problem });

  // key_agg
  { const v = await loadJson('key_agg_vectors.json');
    v.valid_test_cases.forEach((c, i) => check(`key_agg valid ${i}`, eqHex(m.getXonlyPk(m.keyAgg(pick(v.pubkeys, c.key_indices))), c.expected) ? null : 'mismatch'));
    v.error_test_cases.forEach((c, i) => check(`key_agg error ${i}: ${c.comment}`, expectError(() => m.keyAggAndTweak(pick(v.pubkeys, c.key_indices), pick(v.tweaks, c.tweak_indices), c.is_xonly), c.error)));
  }
  // nonce_gen
  { const v = await loadJson('nonce_gen_vectors.json');
    v.test_cases.forEach((c, i) => {
      const r = m.nonceGenInternal({ rand: H(c.rand_), sk: c.sk === null ? null : H(c.sk), pk: H(c.pk), aggpk: c.aggpk === null ? null : H(c.aggpk), msg: c.msg === null ? null : H(c.msg), extraIn: c.extra_in === null ? null : H(c.extra_in) });
      check(`nonce_gen ${i}`, eqHex(r.secNonce, c.expected_secnonce) && eqHex(r.pubNonce, c.expected_pubnonce) ? null : 'mismatch');
    });
  }
  // nonce_agg
  { const v = await loadJson('nonce_agg_vectors.json');
    v.valid_test_cases.forEach((c, i) => check(`nonce_agg valid ${i}`, eqHex(m.nonceAgg(pick(v.pnonces, c.pnonce_indices)), c.expected) ? null : 'mismatch'));
    v.error_test_cases.forEach((c, i) => check(`nonce_agg error ${i}: ${c.comment}`, expectError(() => m.nonceAgg(pick(v.pnonces, c.pnonce_indices)), c.error)));
  }
  // sign_verify
  { const v = await loadJson('sign_verify_vectors.json');
    const sk = H(v.sk);
    v.valid_test_cases.forEach((c, i) => {
      const pubkeys = pick(v.pubkeys, c.key_indices), pnonces = pick(v.pnonces, c.nonce_indices), msg = H(v.msgs[c.msg_index]);
      const session = m.sessionCtx(H(v.aggnonces[c.aggnonce_index]), pubkeys, [], [], msg);
      const psig = m.sign(Uint8Array.from(H(v.secnonces[0])), sk, session);
      const ok = eqHex(psig, c.expected) && m.partialSigVerify(psig, pnonces, pubkeys, [], [], msg, c.signer_index);
      check(`sign_verify valid ${i}`, ok ? null : 'mismatch or verify failed');
    });
    v.sign_error_test_cases.forEach((c, i) => check(`sign error ${i}: ${c.comment}`, expectError(() => {
      const session = m.sessionCtx(H(v.aggnonces[c.aggnonce_index]), pick(v.pubkeys, c.key_indices), [], [], H(v.msgs[c.msg_index]));
      m.sign(Uint8Array.from(H(v.secnonces[c.secnonce_index])), sk, session);
    }, c.error)));
    v.verify_fail_test_cases.forEach((c, i) => check(`verify fail ${i}: ${c.comment}`, m.partialSigVerify(H(c.sig), pick(v.pnonces, c.nonce_indices), pick(v.pubkeys, c.key_indices), [], [], H(v.msgs[c.msg_index]), c.signer_index) ? 'accepted' : null));
    v.verify_error_test_cases.forEach((c, i) => check(`verify error ${i}: ${c.comment}`, expectError(() => m.partialSigVerify(H(c.sig), pick(v.pnonces, c.nonce_indices), pick(v.pubkeys, c.key_indices), [], [], H(v.msgs[c.msg_index]), c.signer_index), c.error)));
  }
  // tweak
  { const v = await loadJson('tweak_vectors.json');
    const sk = H(v.sk), msg = H(v.msg);
    v.valid_test_cases.forEach((c, i) => {
      const pubkeys = pick(v.pubkeys, c.key_indices), pnonces = pick(v.pnonces, c.nonce_indices), tweaks = pick(v.tweaks, c.tweak_indices);
      const session = m.sessionCtx(H(v.aggnonce), pubkeys, tweaks, c.is_xonly, msg);
      const psig = m.sign(Uint8Array.from(H(v.secnonce)), sk, session);
      const ok = eqHex(psig, c.expected) && m.partialSigVerify(psig, pnonces, pubkeys, tweaks, c.is_xonly, msg, c.signer_index);
      check(`tweak valid ${i}: ${c.comment}`, ok ? null : 'mismatch or verify failed');
    });
    v.error_test_cases.forEach((c, i) => check(`tweak error ${i}: ${c.comment}`, expectError(() => {
      const session = m.sessionCtx(H(v.aggnonce), pick(v.pubkeys, c.key_indices), pick(v.tweaks, c.tweak_indices), c.is_xonly, msg);
      m.sign(Uint8Array.from(H(v.secnonce)), sk, session);
    }, c.error)));
  }
  // sig_agg
  { const v = await loadJson('sig_agg_vectors.json');
    const msg = H(v.msg);
    v.valid_test_cases.forEach((c, i) => {
      const pubkeys = pick(v.pubkeys, c.key_indices), tweaks = pick(v.tweaks, c.tweak_indices);
      const aggNonce = m.nonceAgg(pick(v.pnonces, c.nonce_indices));
      const session = m.sessionCtx(aggNonce, pubkeys, tweaks, c.is_xonly, msg);
      const sig = m.partialSigAgg(pick(v.psigs, c.psig_indices), session);
      const ok = eqHex(aggNonce, c.aggnonce) && eqHex(sig, c.expected) && schnorrVerify(sig, msg, m.getXonlyPk(session.keyCtx));
      check(`sig_agg valid ${i}`, ok ? null : 'mismatch or BIP340 verify failed');
    });
    v.error_test_cases.forEach((c, i) => check(`sig_agg error ${i}: ${c.comment}`, expectError(() => {
      const session = m.sessionCtx(H(c.aggnonce), pick(v.pubkeys, c.key_indices), pick(v.tweaks, c.tweak_indices), c.is_xonly, msg);
      m.partialSigAgg(pick(v.psigs, c.psig_indices), session);
    }, c.error)));
  }
  // det_sign
  { const v = await loadJson('det_sign_vectors.json');
    const sk = H(v.sk);
    v.valid_test_cases.forEach((c, i) => {
      const r = m.detSign(sk, H(c.aggothernonce), pick(v.pubkeys, c.key_indices), c.tweaks.map(H), c.is_xonly, H(v.msgs[c.msg_index]), c.rand === null ? null : H(c.rand));
      check(`det_sign valid ${i}`, eqHex(r.pubNonce, c.expected[0]) && eqHex(r.psig, c.expected[1]) ? null : 'mismatch');
    });
    v.error_test_cases.forEach((c, i) => check(`det_sign error ${i}: ${c.comment}`, expectError(() => m.detSign(sk, H(c.aggothernonce), pick(v.pubkeys, c.key_indices), c.tweaks.map(H), c.is_xonly, H(v.msgs[c.msg_index]), c.rand === null ? null : H(c.rand)), c.error)));
  }
  return results;
}

// Adaptor round trip on random keys: with and without a taproot tweak, both
// parities of R', tampering, and nonce reuse.
export function runAdaptorRoundTrip(rounds = 8) {
  const results = [];
  const check = (name, ok, detail = '') => results.push({ name, ok, problem: ok ? null : detail });
  for (let r = 0; r < rounds; r++) {
    const secA = randomSecretKey(), secB = randomSecretKey();
    const pubA = schnorrGetPublicKey(secA), pubB = schnorrGetPublicKey(secB);
    const { keyCtx: baseCtx, aggPubkey } = xonlyKeyAgg([pubA, pubB]);
    const tweaked = r % 2 === 0;
    const { keyCtx, Qbytes } = tweaked ? tapTweak(baseCtx, randomBytes(32)) : { keyCtx: baseCtx, Qbytes: aggPubkey };
    const msg = randomBytes(32);
    const { tBytes, T } = adaptorSecretFromBytes(randomBytes(32));
    const nA = swapNonceGen(secA, Qbytes, msg), nB = swapNonceGen(secB, Qbytes, msg);
    const aggNonce = m.nonceAgg([nA.pubNonce, nB.pubNonce]);
    const secNonceA = Uint8Array.from(nA.secNonce);
    const psA = adaptorSign(secA, nA.secNonce, aggNonce, keyCtx, msg, T);
    const psB = adaptorSign(secB, nB.secNonce, aggNonce, keyCtx, msg, T);
    check(`round ${r}: peer pre-signatures verify`, adaptorVerify(psA, nA.pubNonce, pubA, aggNonce, keyCtx, msg, T) && adaptorVerify(psB, nB.pubNonce, pubB, aggNonce, keyCtx, msg, T));
    const bad = Uint8Array.from(psB); bad[31] ^= 1;
    check(`round ${r}: tampered pre-signature refused`, !adaptorVerify(bad, nB.pubNonce, pubB, aggNonce, keyCtx, msg, T));
    check(`round ${r}: pre-signature under the wrong adaptor point refused`, !adaptorVerify(psB, nB.pubNonce, pubB, aggNonce, keyCtx, msg, T.double()));
    const agg = adaptorAggregate([psA, psB], aggNonce, keyCtx, msg, T);
    const sig = completeAdaptorSig(agg.R, agg.s, tBytes, agg.negR);
    check(`round ${r}: completed signature is BIP340-valid for ${tweaked ? 'tweaked Q' : 'P_swap'}`, schnorrVerify(sig, msg, Qbytes));
    check(`round ${r}: adaptor secret extracted`, bytesToHex(adaptorExtract(sig.slice(32, 64), agg.s, agg.negR)) === bytesToHex(tBytes));
    let reused = false; try { adaptorSign(secA, nA.secNonce, aggNonce, keyCtx, msg, T); } catch { reused = true; }
    check(`round ${r}: consumed nonce refused`, reused);
    let mismatch = false; try { adaptorSign(secB, secNonceA, aggNonce, keyCtx, msg, T); } catch { mismatch = true; }
    check(`round ${r}: nonce of another signer refused`, mismatch);
  }
  return results;
}
