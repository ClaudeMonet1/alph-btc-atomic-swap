// One secret to back up, standard keys to use (audit S12, HD rework of 2026-10-01).
//
// The stored 32-byte secret is the Nostr key (unchanged for existing identities)
// and, read as BIP39 entropy, a 24-word mnemonic. From that mnemonic's seed:
//   Bitcoin  m/86'/0'/0'/0/i   taproot key path (BIP86; i = 0 is the wallet address and the MuSig2 share)
//   Alephium m/44'/1234'/0'/0/i   the wallet library's path for the 'default' (ECDSA) key type;
//            the index advances until the address falls in TARGET_ALPH_GROUP, as Alephium wallets do
// so the Bitcoin descriptor and the Alephium account are importable elsewhere, and
// no signature is valid on more than one chain. The Nostr key is the raw entropy
// rather than NIP-06, so that identities created before this change keep their npub.
import { HDKey } from '@scure/bip32';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { taggedHash, schnorrGetPublicKey, ecdsaPublicKey, bytesToHex, bytesToNum, numTo32b, Fn, concatBytes } from './curve.js';

export const TARGET_ALPH_GROUP = 1;
export const KEY_DERIVATION = 'bip39/bip86/alph-bip44/v2';
export const BTC_PATH = (i) => `m/86'/0'/0'/0/${i}`;
export const ALPH_PATH = (i) => `m/44'/1234'/0'/0/${i}`;

export function mnemonicOf(masterSec) { return entropyToMnemonic(masterSec, wordlist); }
export function entropyOf(mnemonic) {
  const words = mnemonic.trim().toLowerCase().split(/\s+/).join(' ');
  if (!validateMnemonic(words, wordlist)) throw new Error('not a valid BIP39 mnemonic');
  const e = mnemonicToEntropy(words, wordlist);
  if (e.length !== 32) throw new Error('a 24-word mnemonic is needed (256 bits)');
  return e;
}

function key(sec, pub) { return { sec, pub, pubHex: bytesToHex(pub) }; }

// groupOfPub(pubHex, keyType) -> Alephium group of that key's address.
export function deriveKeys(masterSec, groupOfPub) {
  if (!(masterSec instanceof Uint8Array) || masterSec.length !== 32) throw new Error('master secret must be 32 bytes');
  const nostr = key(masterSec, schnorrGetPublicKey(masterSec));
  const root = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonicOf(masterSec)));
  const b = root.derive(BTC_PATH(0));
  const btc = { ...key(b.privateKey, b.publicKey.slice(1)), path: BTC_PATH(0) }; // x-only for taproot and MuSig2
  for (let i = 0; i < 1000; i++) {
    const a = root.derive(ALPH_PATH(i));
    const pub = a.publicKey; // 33-byte compressed, 'default' key type
    if (groupOfPub(bytesToHex(pub), 'default') === TARGET_ALPH_GROUP) {
      return { nostr, btc, alph: { ...key(a.privateKey, pub), keyType: 'default', path: ALPH_PATH(i), index: i }, derivation: KEY_DERIVATION };
    }
  }
  throw new Error('no Alephium key in the target group found');
}

// ---- Previous schemes, kept so that funds left on their addresses can be found and moved ----

// 2026-09-27 to 2026-10-01: tagged hashes of the secret, Schnorr key type on Alephium.
export function deriveKeysV1(masterSec, groupOfPub) {
  const scalar = (bytes) => { const k = Fn.create(bytesToNum(bytes)); if (k === 0n) throw new Error('zero'); return numTo32b(k); };
  const u32 = (i) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, i); return b; };
  const nostr = key(masterSec, schnorrGetPublicKey(masterSec));
  const bsec = scalar(taggedHash('alph-btc-swap/v1/btc', masterSec));
  const btc = key(bsec, schnorrGetPublicKey(bsec));
  for (let i = 0; i < 100000; i++) {
    const sec = scalar(taggedHash('alph-btc-swap/v1/alph', concatBytes(masterSec, u32(i))));
    const pub = schnorrGetPublicKey(sec);
    if (groupOfPub(bytesToHex(pub), 'bip340-schnorr') === TARGET_ALPH_GROUP) return { nostr, btc, alph: { ...key(sec, pub), keyType: 'bip340-schnorr', index: i }, derivation: 'alph-btc-swap/v1' };
  }
  throw new Error('no Alephium key in the target group found');
}

// Before 2026-09-27: one key for all three roles.
export function legacyKeys(masterSec) {
  const k = key(masterSec, schnorrGetPublicKey(masterSec));
  return { nostr: k, btc: k, alph: { ...k, keyType: 'bip340-schnorr', index: -1 }, derivation: 'legacy-single-key' };
}

// The Alephium key type of a public key as announced by a peer (33 bytes: ECDSA 'default', 32: Schnorr).
export function alphKeyTypeOf(pubHex) { return pubHex.length === 66 ? 'default' : 'bip340-schnorr'; }
export { ecdsaPublicKey };
