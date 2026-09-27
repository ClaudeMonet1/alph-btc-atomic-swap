#!/usr/bin/env node
import { deriveKeys, legacyKeys, TARGET_ALPH_GROUP } from '../src/keys.js';
import { addressFromPublicKey, groupOfAddress } from '@alephium/web3';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
const groupOfPub = (pubHex) => groupOfAddress(addressFromPublicKey(pubHex, 'bip340-schnorr'));
let failed = 0; const check = (n, ok) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}`); if (!ok) failed++; };
const master = hexToBytes('11'.repeat(32));
const a = deriveKeys(master, groupOfPub), b = deriveKeys(master, groupOfPub);
check('deterministic', a.btc.pubHex === b.btc.pubHex && a.alph.pubHex === b.alph.pubHex && a.alph.index === b.alph.index);
check('nostr key is the master', a.nostr.pubHex === legacyKeys(master).nostr.pubHex);
check('three distinct keys', new Set([a.nostr.pubHex, a.btc.pubHex, a.alph.pubHex]).size === 3);
check('alephium key in target group', groupOfPub(a.alph.pubHex) === TARGET_ALPH_GROUP);
const other = deriveKeys(hexToBytes('22'.repeat(32)), groupOfPub);
check('different master, different keys', other.btc.pubHex !== a.btc.pubHex);
check('vector btc', a.btc.pubHex.length === 64 && a.alph.pubHex.length === 64);
console.log(`btc ${a.btc.pubHex.slice(0, 16)}... alph ${a.alph.pubHex.slice(0, 16)}... index ${a.alph.index}`);
console.log(failed ? `KEYS TEST FAILED (${failed})` : 'KEYS TEST PASSED'); process.exit(failed ? 1 : 0);
