#!/usr/bin/env node
// Two-browser swap against local chains: Bitcoin regtest through the Esplora
// shim (blocks every 15 s), the Alephium devnet, a local Nostr relay and the
// static page served from docs/. Needs the regtest node (BTC_RPC_URL, default
// http://127.0.0.1:18543) and the devnet node (http://127.0.0.1:22973) running,
// e.g. from the alph-btc-bridge nix shell. Usage: node scripts/e2e-local.mjs [seconds]
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import * as bitcoin from 'bitcoinjs-lib'; import * as ecc from 'tiny-secp256k1'; bitcoin.initEccLib(ecc);
import { addressFromPublicKey, groupOfAddress, ONE_ALPH } from '@alephium/web3';
import { deriveKeys } from '../src/keys.js';
import { setAlphNetwork, fundFromGenesis, waitForTx } from '../src/alph-swap.js';
import { schnorr } from '@noble/curves/secp256k1.js';

const seconds = Number(process.argv[2] || 900);
const RPC_URL = process.env.BTC_RPC_URL || 'http://127.0.0.1:18543';
const AUTH = 'Basic ' + Buffer.from(process.env.BTC_RPC_AUTH || 'nostralph:nostralph').toString('base64');
const rpc = async (method, params = []) => { const j = await fetch(RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: AUTH }, body: JSON.stringify({ method, params }) }).then((r) => r.json()); if (j.error) throw new Error(j.error.message); return j.result; };
const PAGE = 8765, SHIM = 18544, RELAY = 7777;
const here = new URL('..', import.meta.url).pathname;
const tmp = process.env.E2E_TMP || '/tmp/alph-swap-e2e-local';
rmSync(`${tmp}/profiles`, { recursive: true, force: true }); // fresh browsers every run
mkdirSync(tmp, { recursive: true });

// fresh keys for each local run (funded below)
const g = (p) => groupOfAddress(addressFromPublicKey(p, 'bip340-schnorr'));
const keys = {};
for (const n of ['A', 'B']) { const sec = schnorr.utils.randomSecretKey(); const d = deriveKeys(sec, g); keys[n] = { nsecHex: bytesToHex(sec), btc: bitcoin.payments.p2tr({ internalPubkey: Buffer.from(d.btc.pub), network: bitcoin.networks.regtest }).address, alph: addressFromPublicKey(d.alph.pubHex, 'bip340-schnorr') }; }
writeFileSync(`${tmp}/keys.json`, JSON.stringify(keys, null, 2));

const procs = [];
const start = (name, cmd, args, env = {}) => { const p = spawn(cmd, args, { cwd: here, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }); p.stdout.on('data', (d) => process.stdout.write(`[${name}] ${d}`)); p.stderr.on('data', (d) => process.stdout.write(`[${name}!] ${d}`)); procs.push(p); return p; };
const stop = () => { for (const p of procs) try { p.kill('SIGTERM'); } catch {} };
process.on('exit', stop); process.on('SIGINT', () => { stop(); process.exit(130); });

start('page', 'python3', ['-m', 'http.server', String(PAGE), '--bind', '127.0.0.1', '--directory', `${here}/docs`]);
start('shim', 'node', ['devnet/esplora-shim.mjs', String(SHIM)], { BTC_RPC_URL: RPC_URL, MINE_INTERVAL_MS: process.env.MINE_INTERVAL_MS || (process.env.E2E_MODE === 'refund' ? '40000' : '15000') });
start('relay', 'node', ['devnet/nostr-relay.mjs', String(RELAY)]);
await new Promise((r) => setTimeout(r, 1500));

// a refund drill leaves the regtest clock in the future: mining then fails with time-too-new
{ const tip = await rpc('getblock', [await rpc('getbestblockhash'), 1]); if (tip.time > Date.now() / 1000 + 7200) { console.error('regtest tip is in the future (after a refund drill): reset the chain first (stop-regtest; rm -rf devnet/bitcoin/regtest; start-regtest)'); stop(); process.exit(2); } }
// fund Bob (A) with a mature coinbase and both with devnet ALPH
console.log('funding', keys.A.btc, 'on regtest and both keys on devnet');
await rpc('generatetoaddress', [1, keys.A.btc]);
await rpc('generatetoaddress', [100, 'bcrt1prykz5vxt6lgr2tu56np35slhvlc77s7hlajr3qucsrkqwhvp48mqwel98k']);
setAlphNetwork('devnet');
for (const n of ['A', 'B']) await waitForTx((await fundFromGenesis(keys[n].alph, ONE_ALPH * 20n)).txId);

const url = `http://127.0.0.1:${PAGE}/index.html?btcNetwork=regtest&btcApi=http://127.0.0.1:${SHIM}&btcExplorer=http://127.0.0.1:${SHIM}&alphNetwork=devnet&alphNode=http://127.0.0.1:22973&alphExplorer=http://127.0.0.1:22973&relays=ws://127.0.0.1:${RELAY}`;
console.log('running the two-browser swap against', url);
const e2e = spawn('node', ['scripts/e2e-web.mjs', url, String(seconds), process.env.E2E_DIR || 'buy_alph'], { cwd: here, env: { ...process.env, BTC_RPC_URL: RPC_URL, E2E_KEYS: `${tmp}/keys.json`, E2E_PROFILE_DIR: `${tmp}/profiles`, E2E_SAT: process.env.E2E_SAT || '5000', E2E_ALPH: process.env.E2E_ALPH || '0.5' }, stdio: 'inherit' });
const code = await new Promise((r) => e2e.on('exit', r));
stop();
process.exit(code);
