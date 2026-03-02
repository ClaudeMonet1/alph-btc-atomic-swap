#!/usr/bin/env node
// CLI wallet: derives BTC taproot, ALPH schnorr, and Nostr identity from a single nsec.
// Usage:
//   node src/wallet.js generate           - create new nsec, show all addresses
//   node src/wallet.js info <nsec|hex>    - derive and display addresses
//   node src/wallet.js balance <nsec|hex> - BTC (signet) + ALPH (testnet) balances
//   node src/wallet.js utxos <nsec|hex>   - list BTC UTXOs on signet

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { nip19 } from 'nostr-tools';
import { addressFromPublicKey } from '@alephium/web3';

bitcoin.initEccLib(ecc);

const SIGNET = bitcoin.networks.testnet; // signet uses "tb1" prefix
const ESPLORA_URL = 'https://mempool.space/signet/api';
const ALPH_TESTNET_URL = 'https://node.testnet.alephium.org';

function parseSecret(input) {
  if (input.startsWith('nsec')) {
    const decoded = nip19.decode(input);
    return decoded.data;
  }
  return hexToBytes(input);
}

function deriveAll(secBytes) {
  const pubKey = schnorr.getPublicKey(secBytes);
  const pubKeyHex = bytesToHex(pubKey);
  const nsec = nip19.nsecEncode(secBytes);
  const npub = nip19.npubEncode(pubKeyHex);
  const btcAddress = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(pubKey),
    network: SIGNET,
  }).address;
  const alphAddress = addressFromPublicKey(pubKeyHex, 'bip340-schnorr');

  return { secBytes, pubKey, pubKeyHex, nsec, npub, btcAddress, alphAddress };
}

async function esploraFetch(path) {
  const res = await fetch(`${ESPLORA_URL}${path}`);
  if (!res.ok) throw new Error(`Esplora ${path}: ${res.status}`);
  const ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

async function alphFetch(path) {
  const res = await fetch(`${ALPH_TESTNET_URL}${path}`);
  if (!res.ok) throw new Error(`ALPH API ${path}: ${res.status}`);
  return res.json();
}

function printInfo(info) {
  console.log('\n  Nostr');
  console.log(`    nsec:  ${info.nsec}`);
  console.log(`    npub:  ${info.npub}`);
  console.log(`    hex:   ${info.pubKeyHex}`);
  console.log('\n  Bitcoin (signet)');
  console.log(`    P2TR:  ${info.btcAddress}`);
  console.log('\n  Alephium (testnet)');
  console.log(`    addr:  ${info.alphAddress}`);
  console.log();
}

// ---- Commands ----

async function cmdGenerate() {
  const secBytes = schnorr.utils.randomSecretKey();
  const info = deriveAll(secBytes);
  console.log('\n  New identity generated:');
  printInfo(info);
  console.log('  Save your nsec securely. It controls all three chains.\n');
}

async function cmdInfo(input) {
  const secBytes = parseSecret(input);
  const info = deriveAll(secBytes);
  printInfo(info);
}

async function cmdBalance(input) {
  const secBytes = parseSecret(input);
  const info = deriveAll(secBytes);

  console.log(`\n  ${info.btcAddress} (BTC signet)`);
  try {
    const utxos = await esploraFetch(`/address/${info.btcAddress}/utxo`);
    const confirmed = utxos.filter(u => u.status?.confirmed);
    const total = confirmed.reduce((s, u) => s + u.value, 0);
    console.log(`    Balance: ${(total / 1e8).toFixed(8)} BTC (${confirmed.length} UTXOs)`);
  } catch (e) {
    console.log(`    Error: ${e.message}`);
  }

  console.log(`\n  ${info.alphAddress} (ALPH testnet)`);
  try {
    const bal = await alphFetch(`/addresses/${info.alphAddress}/balance`);
    const alph = Number(BigInt(bal.balance)) / 1e18;
    console.log(`    Balance: ${alph.toFixed(4)} ALPH`);
  } catch (e) {
    console.log(`    Error: ${e.message}`);
  }

  console.log('\n  Faucets:');
  console.log('    BTC:  https://signetfaucet.com/');
  console.log('    ALPH: https://faucet.testnet.alephium.org/');
  console.log();
}

async function cmdUtxos(input) {
  const secBytes = parseSecret(input);
  const info = deriveAll(secBytes);

  console.log(`\n  UTXOs for ${info.btcAddress} (signet)\n`);
  try {
    const utxos = await esploraFetch(`/address/${info.btcAddress}/utxo`);
    if (utxos.length === 0) {
      console.log('  No UTXOs found. Get signet BTC from https://signetfaucet.com/\n');
      return;
    }
    for (const u of utxos) {
      const conf = u.status?.confirmed ? 'confirmed' : 'unconfirmed';
      console.log(`  ${u.txid}:${u.vout}  ${(u.value / 1e8).toFixed(8)} BTC  [${conf}]`);
    }
    const total = utxos.filter(u => u.status?.confirmed).reduce((s, u) => s + u.value, 0);
    console.log(`\n  Total confirmed: ${(total / 1e8).toFixed(8)} BTC`);
  } catch (e) {
    console.log(`  Error: ${e.message}`);
  }
  console.log();
}

// ---- Main ----

const [,, cmd, arg] = process.argv;

if (!cmd || cmd === 'help') {
  console.log(`
  Usage: node src/wallet.js <command> [args]

  Commands:
    generate           Create new identity (nsec + addresses)
    info <nsec|hex>    Show derived addresses
    balance <nsec|hex> Show BTC (signet) + ALPH (testnet) balances
    utxos <nsec|hex>   List BTC UTXOs on signet
`);
} else if (cmd === 'generate') {
  await cmdGenerate();
} else if (cmd === 'info') {
  if (!arg) { console.error('Usage: wallet info <nsec|hex>'); process.exit(1); }
  await cmdInfo(arg);
} else if (cmd === 'balance') {
  if (!arg) { console.error('Usage: wallet balance <nsec|hex>'); process.exit(1); }
  await cmdBalance(arg);
} else if (cmd === 'utxos') {
  if (!arg) { console.error('Usage: wallet utxos <nsec|hex>'); process.exit(1); }
  await cmdUtxos(arg);
} else {
  console.error(`Unknown command: ${cmd}`);
  process.exit(1);
}
