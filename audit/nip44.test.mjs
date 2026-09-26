#!/usr/bin/env node
// Cross-check of src/nip44.js against nostr-tools' NIP-44 (vector-tested):
// each side encrypts, the other decrypts; tampered payloads are refused.
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import * as ref from 'nostr-tools/nip44';
import * as ours from '../src/nip44.js';
let failures = 0;
const check = (name, ok) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`); if (!ok) failures++; };
for (let i = 0; i < 20; i++) {
  const a = schnorr.utils.randomSecretKey(), b = schnorr.utils.randomSecretKey();
  const A = bytesToHex(schnorr.getPublicKey(a)), B = bytesToHex(schnorr.getPublicKey(b));
  const msg = i === 0 ? 'x' : i === 1 ? 'a'.repeat(65535) : JSON.stringify({ type: 'btc_locked', txid: bytesToHex(a), i, text: 'é中🚀'.repeat(i * 7) });
  const kOurs = ours.getConversationKey(a, B), kRef = ref.getConversationKey(a, B), kPeer = ref.getConversationKey(b, A);
  if (i < 3) check(`conversation key agrees (${i})`, bytesToHex(kOurs) === bytesToHex(kRef) && bytesToHex(kRef) === bytesToHex(kPeer));
  const c1 = ours.encrypt(msg, kOurs);
  const c2 = ref.encrypt(msg, kRef);
  const okA = ref.decrypt(c1, kPeer) === msg && ours.decrypt(c2, kOurs) === msg && ours.decrypt(c1, kPeer) === msg;
  if (i < 3 || !okA) check(`round trip both ways, length ${msg.length}`, okA);
  if (i === 2) {
    const bytes = Uint8Array.from(atob(c1), ch => ch.charCodeAt(0)); bytes[40] ^= 1;
    let refused = false; try { ours.decrypt(btoa(String.fromCharCode(...bytes)), kPeer); } catch { refused = true; }
    check('tampered ciphertext refused (MAC)', refused);
    let refused2 = false; try { ours.decrypt(c1, ours.getConversationKey(schnorr.utils.randomSecretKey(), B)); } catch { refused2 = true; }
    check('wrong key refused', refused2);
  }
}
for (const [len, padded] of [[1, 32], [32, 32], [33, 64], [37, 64], [45, 64], [49, 64], [64, 64], [65, 96], [100, 128], [111, 128], [200, 224], [250, 256], [320, 320], [383, 384], [384, 384], [400, 448], [500, 512], [512, 512], [515, 640], [700, 768], [800, 896], [900, 1024], [1020, 1024], [65536 - 1, 65536]]) {
  if (ours.calcPaddedLen(len) !== padded) check(`padded length of ${len}`, false);
}
check('padding schedule matches the NIP-44 table', failures === 0);
console.log(failures === 0 ? '\nNIP-44 CROSS-CHECK PASSED' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
