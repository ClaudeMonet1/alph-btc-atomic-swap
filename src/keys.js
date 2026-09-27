// One secret to back up, three keys to use (audit S12): the Nostr identity is
// the master secret itself (so existing identities keep their npub), and the
// Bitcoin and Alephium keys are derived from it with domain-separated tagged
// hashes. The Alephium key is ground into TARGET_ALPH_GROUP by a counter, so
// any imported Nostr key can trade (audit W9). A Bitcoin signature can never be
// replayed as an Alephium or Nostr signature and vice versa.
import { taggedHash, schnorrGetPublicKey, bytesToHex, bytesToNum, numTo32b, Fn, concatBytes } from './curve.js';

export const TARGET_ALPH_GROUP = 1;
export const KEY_DERIVATION = 'alph-btc-swap/v1';

function scalar(bytes) {
  const k = Fn.create(bytesToNum(bytes));
  if (k === 0n) throw new Error('derived key is zero');
  return numTo32b(k);
}
function u32(i) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, i); return b; }
function key(sec) { const pub = schnorrGetPublicKey(sec); return { sec, pub, pubHex: bytesToHex(pub) }; }

// groupOfPub(pubHex) -> Alephium group of the address of that x-only key.
export function deriveKeys(masterSec, groupOfPub) {
  if (!(masterSec instanceof Uint8Array) || masterSec.length !== 32) throw new Error('master secret must be 32 bytes');
  const nostr = key(masterSec);
  const btc = key(scalar(taggedHash(`${KEY_DERIVATION}/btc`, masterSec)));
  for (let i = 0; i < 100000; i++) {
    const alph = key(scalar(taggedHash(`${KEY_DERIVATION}/alph`, concatBytes(masterSec, u32(i)))));
    if (groupOfPub(alph.pubHex) === TARGET_ALPH_GROUP) return { nostr, btc, alph: { ...alph, index: i }, derivation: KEY_DERIVATION };
  }
  throw new Error('no Alephium key in the target group found');
}

// Before 2026-09-27 one key served all three roles; used to find and sweep funds left there.
export function legacyKeys(masterSec) {
  const k = key(masterSec);
  return { nostr: k, btc: k, alph: { ...k, index: -1 }, derivation: 'legacy-single-key' };
}
