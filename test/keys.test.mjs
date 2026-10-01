#!/usr/bin/env node
// HD key derivation checks: BIP86 against the BIP's test vector, the Alephium
// path against the Alephium wallet library, ECDSA signatures against the SDK's
// verifier, the mnemonic round trip, and the invariants of the key set.
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { deriveKeys, deriveKeysV1, legacyKeys, mnemonicOf, entropyOf, TARGET_ALPH_GROUP, BTC_PATH, ALPH_PATH, alphKeyTypeOf } from '../src/keys.js';
import { ecdsaSign } from '../src/curve.js';
import { addressFromPublicKey, groupOfAddress, verifySignature } from '@alephium/web3';
import { deriveHDWalletPrivateKeyForGroup } from '@alephium/web3-wallet';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import * as bitcoin from 'bitcoinjs-lib'; import * as ecc from 'tiny-secp256k1'; bitcoin.initEccLib(ecc);
let failed = 0; const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };
const groupOfPub = (pubHex, keyType) => groupOfAddress(addressFromPublicKey(pubHex, keyType));

// BIP86 test vector (12-word mnemonic): first external address
{
  const seed = mnemonicToSeedSync('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const k = HDKey.fromMasterSeed(seed).derive(BTC_PATH(0));
  const addr = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(k.publicKey.slice(1)), network: bitcoin.networks.bitcoin }).address;
  check('BIP86 vector: internal key', bytesToHex(k.publicKey.slice(1)) === 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  check('BIP86 vector: address', addr === 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', addr);
}
const master = hexToBytes('11'.repeat(32));
const words = mnemonicOf(master);
check('24-word mnemonic round trip', words.split(' ').length === 24 && bytesToHex(entropyOf(words)) === bytesToHex(master));
const k = deriveKeys(master, groupOfPub);
// Alephium: same key and index as the wallet library for the target group
{
  const [privHex, index] = deriveHDWalletPrivateKeyForGroup(words, TARGET_ALPH_GROUP, 'default', 0);
  check('Alephium key equals the wallet library\'s derivation', bytesToHex(k.alph.sec) === privHex && k.alph.index === index, `index ${k.alph.index} vs ${index}`);
  check('Alephium key is ECDSA type in the target group', k.alph.keyType === 'default' && k.alph.pubHex.length === 66 && groupOfPub(k.alph.pubHex, 'default') === TARGET_ALPH_GROUP);
}
// ECDSA signature accepted by the SDK's verifier (what the node checks)
{
  const hash = '22'.repeat(32);
  const sig = bytesToHex(ecdsaSign(hexToBytes(hash), k.alph.sec));
  check('ECDSA signature verifies with the SDK (default key type)', sig.length === 128 && verifySignature(hash, k.alph.pubHex, sig, 'default'));
}
check('Nostr key is the master (npub unchanged)', k.nostr.pubHex === legacyKeys(master).nostr.pubHex);
check('Bitcoin key is x-only on the BIP86 path', k.btc.pubHex.length === 64 && k.btc.path === BTC_PATH(0));
check('deterministic', deriveKeys(master, groupOfPub).btc.pubHex === k.btc.pubHex && deriveKeys(master, groupOfPub).alph.index === k.alph.index);
check('three distinct keys', new Set([k.nostr.pubHex, k.btc.pubHex, k.alph.pubHex.slice(2)]).size === 3);
check('v1 scheme still derivable (for migration)', deriveKeysV1(master, groupOfPub).alph.keyType === 'bip340-schnorr');
check('key type inferred from announced key length', alphKeyTypeOf(k.alph.pubHex) === 'default' && alphKeyTypeOf(k.btc.pubHex) === 'bip340-schnorr');
console.log(`btc ${k.btc.pubHex.slice(0, 16)}... alph ${k.alph.pubHex.slice(0, 16)}... (${k.alph.path})`);
console.log(failed ? `KEYS TEST FAILED (${failed})` : 'KEYS TEST PASSED'); process.exit(failed ? 1 : 0);
