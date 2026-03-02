#!/usr/bin/env node
// Nostr-Based Atomic Swap Protocol
//
// Alice (has ALPH, wants BTC) and Bob (has BTC, wants ALPH) communicate
// through a local Nostr relay using structured swap event kinds.
//
// Protocol phases:
//   1. Negotiation — Public offer (kind 1), acceptance (SWAP_SETUP)
//   2. Lock        — Bob locks BTC, Alice verifies + deploys ALPH, Bob verifies
//   3. Nonce       — Commit-then-reveal nonce exchange (prevents adaptive attacks)
//   4. Pre-sign    — Adaptor pre-signature exchange + verification
//   5. Claim       — Alice claims BTC (reveals t), Bob extracts t, claims ALPH
//
// Three test scenarios: happy path, both refund, crash recovery.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { nip19 } from 'nostr-tools';

import {
  keyAgg, nonceGen, nonceAgg,
  lift_x, hasEvenY, bytesToNum, numTo32b,
} from './musig2.js';
import {
  adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract,
  G, Fn, n, pointToBytes,
} from './adaptor.js';
import {
  bitcoinRpc, createSwapOutput, verifySwapOutput,
  buildClaimTx, buildP2TRKeyPathSpend, finalizeKeyPathSpend, broadcastTx,
  mineBlocks, extractSignatureFromTx, buildRefundTx, REGTEST, bitcoin,
} from './btc-swap.js';
import {
  compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState,
  fundFromGenesis, getBalance, waitForTx,
  web3, ONE_ALPH, PrivateKeyWallet, addressFromPublicKey, groupOfAddress,
} from './alph-swap.js';
import { computeTweakedKey, computeAdaptorChallenge, computeTweakedPrivateKey } from './taproot-utils.js';
import { startRelay } from './relay.js';
import {
  connectRelay, publish, waitForSwapEvent, waitForEvent,
  createPublicEvent, createSwapSetup, createSwapNonce, createSwapPresig, createSwapClaim,
  SWAP_SETUP_KIND, SWAP_NONCE_KIND, SWAP_PRESIG_KIND, SWAP_CLAIM_KIND,
} from './swap-events.js';

web3.setCurrentNodeProvider('http://127.0.0.1:22973');

const log = (phase, msg) => console.log(`[${phase}] ${msg}`);

// ============================================================
// Protocol Constants
// ============================================================

const RELAY_PORT = 7777;
const RELAY_URL = `ws://127.0.0.1:${RELAY_PORT}`;
const DM_TIMEOUT = 30000;
const BTC_AMOUNT = 0.5;
const BTC_SAT = Math.round(BTC_AMOUNT * 1e8);
const ALPH_AMOUNT = ONE_ALPH * 10n;
const CSV_TIMEOUT = 144;

// ============================================================
// Key Generation
// ============================================================

function generateSameGroupKeys() {
  const getGroup = (pub) => groupOfAddress(addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr'));
  const aliceSec = schnorr.utils.randomSecretKey();
  const alicePub = schnorr.getPublicKey(aliceSec);
  const targetGroup = getGroup(alicePub);
  let bobSec, bobPub;
  do {
    bobSec = schnorr.utils.randomSecretKey();
    bobPub = schnorr.getPublicKey(bobSec);
  } while (getGroup(bobPub) !== targetGroup);
  return { aliceSec, alicePub, bobSec, bobPub };
}

// ============================================================
// Shared Cryptographic Context
// ============================================================

// Both sides compute identical context from public inputs.
// Called after both locks are in place and verified.
function computeSharedContext({ alicePub, bobPub, btcLockTxid, btcLockVout, btcSat, contractId, csvTimeout }) {
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);

  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } =
    createSwapOutput(aggPubkey, bobPub, csvTimeout);  // Bob = refund path

  const aliceBtcAddress = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(alicePub), network: REGTEST,
  }).address;

  const { Qbytes, tweakScalar, negated: tweakNeg } = computeTweakedKey(aggPubkey, p2tr.hash);
  const gaccTweaked = tweakNeg ? Fn.create(n - gacc) : gacc;
  const tacc = tweakNeg ? Fn.neg(tweakScalar) : tweakScalar;

  const { sighash: btcSighash } = buildClaimTx(
    btcLockTxid, btcLockVout, btcSat, aliceBtcAddress, internalPubkey, scriptTree,
  );
  const alphMsg = hexToBytes(contractId);

  return {
    aggPubkey, keyCoeffs, gacc, gaccTweaked, tacc,
    Qbytes, btcSighash, alphMsg,
    swapBtcAddress, internalPubkey, scriptTree, p2tr,
    aliceBtcAddress,
  };
}

// ============================================================
// Alice's Protocol Flow
// ============================================================

async function aliceSideSwap(ws, aliceSec, bobPubHex, sessionId, {
  csvTimeout = CSV_TIMEOUT,
  alphTimeoutMs = Date.now() + 6 * 60 * 60 * 1000,
  skipClaim = false,
} = {}) {
  const alicePub = schnorr.getPublicKey(aliceSec);
  const alicePubHex = bytesToHex(alicePub);
  const bobPub = hexToBytes(bobPubHex);
  const aliceAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSec), keyType: 'bip340-schnorr' });
  const aliceBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;

  // ── Generate adaptor secret t, normalize T to even Y ──
  let tBytes = schnorr.utils.randomSecretKey();
  let t = bytesToNum(tBytes);
  let T = G.multiply(t);
  if (!hasEvenY(T)) {
    T = T.negate();
    t = Fn.neg(t);
    tBytes = numTo32b(t);
  }

  // ── SETUP: Send confirmation with adaptor point ──
  log('ALICE', 'Sending confirmation with adaptor point...');
  await publish(ws, createSwapSetup(aliceSec, {
    sessionId, recipientPubHex: bobPubHex, msgType: 'confirm',
    pubkey: alicePubHex,
    adaptorPoint: bytesToHex(pointToBytes(T)),
  }));

  // ── SETUP: Wait for Bob's BTC lock ──
  log('ALICE', 'Waiting for Bob to lock BTC...');
  const btcLockedEvent = await waitForSwapEvent(ws, SWAP_SETUP_KIND, sessionId, bobPubHex,
    (e) => JSON.parse(e.content).type === 'btc_locked', DM_TIMEOUT);
  const btcLocked = JSON.parse(btcLockedEvent.content);
  log('ALICE', `Bob locked BTC: txid=${btcLocked.txid.slice(0, 16)}... vout=${btcLocked.vout}`);

  // ── Verify BTC output ──
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey } = keyAgg(pubkeys);
  const { address: swapBtcAddress } = createSwapOutput(aggPubkey, bobPub, csvTimeout);
  await verifySwapOutput(btcLocked.txid, swapBtcAddress, BTC_AMOUNT);
  log('ALICE', 'BTC output verified');

  // ── Deploy ALPH contract ──
  log('ALICE', 'Deploying ALPH contract...');
  const compiled = await compileSwapContract();
  const bobAlphAddress = addressFromPublicKey(bobPubHex, 'bip340-schnorr');
  const bobGroup = groupOfAddress(bobAlphAddress);

  const deployResult = await deploySwapContract(
    aliceAlphWallet, bytesToHex(aggPubkey), bobAlphAddress, aliceAlphWallet.address,
    alphTimeoutMs, ALPH_AMOUNT, compiled, bobGroup,
  );
  await waitForTx(deployResult.txId);
  log('ALICE', `ALPH contract deployed: ${deployResult.contractAddress}`);

  // ── SETUP: Send contract info ──
  await publish(ws, createSwapSetup(aliceSec, {
    sessionId, recipientPubHex: bobPubHex, msgType: 'alph_deployed',
    contractId: deployResult.contractId,
    contractAddress: deployResult.contractAddress,
  }));

  // ── SETUP: Wait for Bob's verification ──
  log('ALICE', 'Waiting for Bob to verify ALPH contract...');
  await waitForSwapEvent(ws, SWAP_SETUP_KIND, sessionId, bobPubHex,
    (e) => JSON.parse(e.content).type === 'verified', DM_TIMEOUT);
  log('ALICE', 'Bob verified ALPH contract');

  // ── Compute shared context ──
  const ctx = computeSharedContext({
    alicePub, bobPub,
    btcLockTxid: btcLocked.txid, btcLockVout: btcLocked.vout,
    btcSat: BTC_SAT, contractId: deployResult.contractId, csvTimeout,
  });

  // ── NONCE: Commit ──
  const btcNonceA = nonceGen(aliceSec, ctx.Qbytes, ctx.btcSighash);
  const alphNonceA = nonceGen(aliceSec, ctx.aggPubkey, ctx.alphMsg);
  const btcNonceHashA = bytesToHex(sha256(btcNonceA.pubNonce));
  const alphNonceHashA = bytesToHex(sha256(alphNonceA.pubNonce));

  log('ALICE', 'Sending nonce commitments...');
  await publish(ws, createSwapNonce(aliceSec, {
    sessionId, recipientPubHex: bobPubHex, phase: 'commit',
    btcNonceHash: btcNonceHashA,
    alphNonceHash: alphNonceHashA,
  }));

  const bobCommitEvent = await waitForSwapEvent(ws, SWAP_NONCE_KIND, sessionId, bobPubHex,
    (e) => JSON.parse(e.content).phase === 'commit', DM_TIMEOUT);
  const bobCommit = JSON.parse(bobCommitEvent.content);
  log('ALICE', 'Got Bob\'s nonce commitments');

  // ── NONCE: Reveal ──
  log('ALICE', 'Revealing nonces...');
  await publish(ws, createSwapNonce(aliceSec, {
    sessionId, recipientPubHex: bobPubHex, phase: 'reveal',
    btcPubNonce: bytesToHex(btcNonceA.pubNonce),
    alphPubNonce: bytesToHex(alphNonceA.pubNonce),
  }));

  const bobRevealEvent = await waitForSwapEvent(ws, SWAP_NONCE_KIND, sessionId, bobPubHex,
    (e) => JSON.parse(e.content).phase === 'reveal', DM_TIMEOUT);
  const bobReveal = JSON.parse(bobRevealEvent.content);
  log('ALICE', 'Got Bob\'s nonce reveals');

  // Verify Bob's commitments match reveals
  const bobBtcNonce = hexToBytes(bobReveal.btcPubNonce);
  const bobAlphNonce = hexToBytes(bobReveal.alphPubNonce);
  if (bytesToHex(sha256(bobBtcNonce)) !== bobCommit.btcNonceHash) throw new Error('Bob BTC nonce commitment mismatch');
  if (bytesToHex(sha256(bobAlphNonce)) !== bobCommit.alphNonceHash) throw new Error('Bob ALPH nonce commitment mismatch');
  log('ALICE', 'Bob\'s nonce commitments verified');

  // Aggregate nonces
  const btcAggNonce = nonceAgg([btcNonceA.pubNonce, bobBtcNonce]);
  const alphAggNonce = nonceAgg([alphNonceA.pubNonce, bobAlphNonce]);

  // ── PRESIG: Create and exchange ──
  log('ALICE', 'Creating adaptor pre-signatures...');
  const btcAdaptorA = adaptorSign(aliceSec, btcNonceA.secNonce, btcAggNonce, ctx.keyCoeffs, ctx.Qbytes, ctx.btcSighash, T, 0, ctx.gaccTweaked);
  const alphAdaptorA = adaptorSign(aliceSec, alphNonceA.secNonce, alphAggNonce, ctx.keyCoeffs, ctx.aggPubkey, ctx.alphMsg, T, 0, ctx.gacc);

  await publish(ws, createSwapPresig(aliceSec, {
    sessionId, recipientPubHex: bobPubHex,
    btcPresig: bytesToHex(btcAdaptorA),
    alphPresig: bytesToHex(alphAdaptorA),
  }));

  const bobPresigEvent = await waitForSwapEvent(ws, SWAP_PRESIG_KIND, sessionId, bobPubHex, null, DM_TIMEOUT);
  const bobPresigs = JSON.parse(bobPresigEvent.content);
  log('ALICE', 'Got Bob\'s pre-signatures');

  // Verify Bob's pre-signatures
  const btcAdaptorB = hexToBytes(bobPresigs.btcPresig);
  const alphAdaptorB = hexToBytes(bobPresigs.alphPresig);

  if (!adaptorVerify(btcAdaptorB, bobBtcNonce, bobPub, btcAggNonce, ctx.keyCoeffs, ctx.Qbytes, ctx.btcSighash, T, 1, ctx.gaccTweaked))
    throw new Error('Bob BTC adaptor verification failed');
  if (!adaptorVerify(alphAdaptorB, bobAlphNonce, bobPub, alphAggNonce, ctx.keyCoeffs, ctx.aggPubkey, ctx.alphMsg, T, 1, ctx.gacc))
    throw new Error('Bob ALPH adaptor verification failed');
  log('ALICE', 'Bob\'s pre-signatures verified');

  // Aggregate
  const btcAdaptorAgg = adaptorAggregate([btcAdaptorA, btcAdaptorB], btcAggNonce, ctx.Qbytes, ctx.btcSighash, T);
  const alphAdaptorAgg = adaptorAggregate([alphAdaptorA, alphAdaptorB], alphAggNonce, ctx.aggPubkey, ctx.alphMsg, T);

  // Apply taproot tweak
  const btcE = computeAdaptorChallenge(btcAggNonce, ctx.Qbytes, ctx.btcSighash, T);
  const sTweaked = Fn.create(bytesToNum(btcAdaptorAgg.s) + Fn.create(ctx.tacc * btcE));
  const btcTweakedAgg = { R: btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: btcAdaptorAgg.negR };

  if (skipClaim) {
    log('ALICE', 'Skipping BTC claim (refund scenario)');
    return {
      tBytes, t, T, compiled,
      btcTweakedAgg, btcAdaptorAgg, alphAdaptorAgg,
      fundTxid: btcLocked.txid, fundVout: btcLocked.vout,
      internalPubkey: ctx.internalPubkey, scriptTree: ctx.scriptTree, p2tr: ctx.p2tr,
      deployResult, aliceAlphWallet, aliceBtcAddress,
    };
  }

  // ── CLAIM: Alice claims BTC ──
  log('ALICE', 'Completing BTC adaptor signature with secret t...');
  const btcFinalSig = completeAdaptorSig(btcTweakedAgg.R, btcTweakedAgg.s, tBytes, btcTweakedAgg.negR);

  if (!schnorr.verify(btcFinalSig, ctx.btcSighash, ctx.Qbytes))
    throw new Error('BTC completed signature invalid');

  const { psbt } = buildClaimTx(btcLocked.txid, btcLocked.vout, BTC_SAT, aliceBtcAddress, ctx.internalPubkey, ctx.scriptTree);
  const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
  const claimTxid = await broadcastTx(signedTxHex);
  await mineBlocks(1, aliceBtcAddress);
  log('ALICE', `BTC claimed! txid: ${claimTxid}`);

  await publish(ws, createSwapClaim(aliceSec, {
    sessionId, recipientPubHex: bobPubHex, claimType: 'btc_claimed',
    txid: claimTxid,
  }));

  // Wait for Bob's ALPH claim
  log('ALICE', 'Waiting for Bob to claim ALPH...');
  const alphClaimedEvent = await waitForSwapEvent(ws, SWAP_CLAIM_KIND, sessionId, bobPubHex,
    (e) => JSON.parse(e.content).type === 'alph_claimed', DM_TIMEOUT);
  const alphClaimed = JSON.parse(alphClaimedEvent.content);
  log('ALICE', `Bob claimed ALPH: txid=${alphClaimed.txid}`);

  return {
    claimTxid, compiled, deployResult,
    aliceAlphWallet, aliceBtcAddress,
    btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
    btcSighash: ctx.btcSighash, Qbytes: ctx.Qbytes,
    gaccTweaked: ctx.gaccTweaked, tacc: ctx.tacc, btcE,
    fundTxid: btcLocked.txid, fundVout: btcLocked.vout,
    internalPubkey: ctx.internalPubkey, scriptTree: ctx.scriptTree, p2tr: ctx.p2tr, alphMsg: ctx.alphMsg,
  };
}

// ============================================================
// Bob's Protocol Flow
// ============================================================

async function bobSideSwap(ws, bobSec, alicePubHex, sessionId, {
  csvTimeout = CSV_TIMEOUT,
  coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  stopAfterPresign = false,
} = {}) {
  const bobPub = schnorr.getPublicKey(bobSec);
  const bobPubHex = bytesToHex(bobPub);
  const alicePub = hexToBytes(alicePubHex);
  const bobAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(bobSec), keyType: 'bip340-schnorr' });
  const bobBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;

  // ── SETUP: Wait for Alice's confirmation ──
  log('BOB', 'Waiting for Alice\'s confirmation...');
  const confirmEvent = await waitForSwapEvent(ws, SWAP_SETUP_KIND, sessionId, alicePubHex,
    (e) => JSON.parse(e.content).type === 'confirm', DM_TIMEOUT);
  const confirm = JSON.parse(confirmEvent.content);
  log('BOB', `Alice confirmed. Adaptor point: ${confirm.adaptorPoint.slice(0, 16)}...`);

  const T = lift_x(bytesToNum(hexToBytes(confirm.adaptorPoint)));
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);

  // ── SETUP: Lock BTC ──
  log('BOB', 'Creating Bitcoin taproot output...');
  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } =
    createSwapOutput(aggPubkey, bobPub, csvTimeout);

  log('BOB', 'Funding swap from P2TR...');
  const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    swapBtcAddress, BTC_SAT, bobPub,
  );
  const bobTweakedKey = computeTweakedPrivateKey(bobSec, bobPub);
  const fundSig = schnorr.sign(fundSighash, bobTweakedKey);
  const fundTxHex = finalizeKeyPathSpend(fundPsbt, fundSig);
  const fundTxid = await broadcastTx(fundTxHex);
  await mineBlocks(1, bobBtcAddress);

  const fundRawTx = await bitcoinRpc('getrawtransaction', [fundTxid, true]);
  const fundVout = fundRawTx.vout.findIndex(o => o.scriptPubKey.address === swapBtcAddress);
  log('BOB', `BTC locked: txid=${fundTxid.slice(0, 16)}... vout=${fundVout}`);

  await publish(ws, createSwapSetup(bobSec, {
    sessionId, recipientPubHex: alicePubHex, msgType: 'btc_locked',
    txid: fundTxid, vout: fundVout, amountSat: BTC_SAT,
  }));

  // ── SETUP: Wait for Alice's ALPH contract ──
  log('BOB', 'Waiting for Alice to deploy ALPH contract...');
  const alphDeployedEvent = await waitForSwapEvent(ws, SWAP_SETUP_KIND, sessionId, alicePubHex,
    (e) => JSON.parse(e.content).type === 'alph_deployed', DM_TIMEOUT);
  const alphDeployed = JSON.parse(alphDeployedEvent.content);
  log('BOB', `ALPH contract: ${alphDeployed.contractAddress}`);

  // ── Verify ALPH contract ──
  const compiled = await compileSwapContract();
  const aliceAlphAddress = addressFromPublicKey(alicePubHex, 'bip340-schnorr');
  await verifyContractState(
    alphDeployed.contractAddress, bytesToHex(aggPubkey),
    bobAlphWallet.address, aliceAlphAddress,
    ALPH_AMOUNT, undefined, compiled,
  );
  log('BOB', 'ALPH contract verified');

  await publish(ws, createSwapSetup(bobSec, {
    sessionId, recipientPubHex: alicePubHex, msgType: 'verified',
  }));

  // ── Compute shared context ──
  const ctx = computeSharedContext({
    alicePub, bobPub,
    btcLockTxid: fundTxid, btcLockVout: fundVout,
    btcSat: BTC_SAT, contractId: alphDeployed.contractId, csvTimeout,
  });

  // ── NONCE: Wait for Alice's commit, then send ours ──
  log('BOB', 'Waiting for Alice\'s nonce commitments...');
  const aliceCommitEvent = await waitForSwapEvent(ws, SWAP_NONCE_KIND, sessionId, alicePubHex,
    (e) => JSON.parse(e.content).phase === 'commit', DM_TIMEOUT);
  const aliceCommit = JSON.parse(aliceCommitEvent.content);
  log('BOB', 'Got Alice\'s nonce commitments');

  const btcNonceB = nonceGen(bobSec, ctx.Qbytes, ctx.btcSighash);
  const alphNonceB = nonceGen(bobSec, ctx.aggPubkey, ctx.alphMsg);
  const btcNonceHashB = bytesToHex(sha256(btcNonceB.pubNonce));
  const alphNonceHashB = bytesToHex(sha256(alphNonceB.pubNonce));

  log('BOB', 'Sending nonce commitments...');
  await publish(ws, createSwapNonce(bobSec, {
    sessionId, recipientPubHex: alicePubHex, phase: 'commit',
    btcNonceHash: btcNonceHashB,
    alphNonceHash: alphNonceHashB,
  }));

  // ── NONCE: Wait for Alice's reveal, verify, send ours ──
  log('BOB', 'Waiting for Alice\'s nonce reveals...');
  const aliceRevealEvent = await waitForSwapEvent(ws, SWAP_NONCE_KIND, sessionId, alicePubHex,
    (e) => JSON.parse(e.content).phase === 'reveal', DM_TIMEOUT);
  const aliceReveal = JSON.parse(aliceRevealEvent.content);
  log('BOB', 'Got Alice\'s nonce reveals');

  // Verify Alice's commitments
  const aliceBtcNonce = hexToBytes(aliceReveal.btcPubNonce);
  const aliceAlphNonce = hexToBytes(aliceReveal.alphPubNonce);
  if (bytesToHex(sha256(aliceBtcNonce)) !== aliceCommit.btcNonceHash) throw new Error('Alice BTC nonce commitment mismatch');
  if (bytesToHex(sha256(aliceAlphNonce)) !== aliceCommit.alphNonceHash) throw new Error('Alice ALPH nonce commitment mismatch');
  log('BOB', 'Alice\'s nonce commitments verified');

  log('BOB', 'Revealing nonces...');
  await publish(ws, createSwapNonce(bobSec, {
    sessionId, recipientPubHex: alicePubHex, phase: 'reveal',
    btcPubNonce: bytesToHex(btcNonceB.pubNonce),
    alphPubNonce: bytesToHex(alphNonceB.pubNonce),
  }));

  // Aggregate nonces
  const btcAggNonce = nonceAgg([aliceBtcNonce, btcNonceB.pubNonce]);
  const alphAggNonce = nonceAgg([aliceAlphNonce, alphNonceB.pubNonce]);

  // ── PRESIG: Wait for Alice's, verify, send ours ──
  log('BOB', 'Waiting for Alice\'s pre-signatures...');
  const alicePresigEvent = await waitForSwapEvent(ws, SWAP_PRESIG_KIND, sessionId, alicePubHex, null, DM_TIMEOUT);
  const alicePresigs = JSON.parse(alicePresigEvent.content);
  log('BOB', 'Got Alice\'s pre-signatures');

  const btcAdaptorA = hexToBytes(alicePresigs.btcPresig);
  const alphAdaptorA = hexToBytes(alicePresigs.alphPresig);

  if (!adaptorVerify(btcAdaptorA, aliceBtcNonce, alicePub, btcAggNonce, ctx.keyCoeffs, ctx.Qbytes, ctx.btcSighash, T, 0, ctx.gaccTweaked))
    throw new Error('Alice BTC adaptor verification failed');
  if (!adaptorVerify(alphAdaptorA, aliceAlphNonce, alicePub, alphAggNonce, ctx.keyCoeffs, ctx.aggPubkey, ctx.alphMsg, T, 0, ctx.gacc))
    throw new Error('Alice ALPH adaptor verification failed');
  log('BOB', 'Alice\'s pre-signatures verified');

  log('BOB', 'Creating adaptor pre-signatures...');
  const btcAdaptorB = adaptorSign(bobSec, btcNonceB.secNonce, btcAggNonce, ctx.keyCoeffs, ctx.Qbytes, ctx.btcSighash, T, 1, ctx.gaccTweaked);
  const alphAdaptorB = adaptorSign(bobSec, alphNonceB.secNonce, alphAggNonce, ctx.keyCoeffs, ctx.aggPubkey, ctx.alphMsg, T, 1, ctx.gacc);

  await publish(ws, createSwapPresig(bobSec, {
    sessionId, recipientPubHex: alicePubHex,
    btcPresig: bytesToHex(btcAdaptorB),
    alphPresig: bytesToHex(alphAdaptorB),
  }));

  // Aggregate
  const btcAdaptorAgg = adaptorAggregate([btcAdaptorA, btcAdaptorB], btcAggNonce, ctx.Qbytes, ctx.btcSighash, T);
  const alphAdaptorAgg = adaptorAggregate([alphAdaptorA, alphAdaptorB], alphAggNonce, ctx.aggPubkey, ctx.alphMsg, T);

  // Apply taproot tweak
  const btcE = computeAdaptorChallenge(btcAggNonce, ctx.Qbytes, ctx.btcSighash, T);
  const sTweaked = Fn.create(bytesToNum(btcAdaptorAgg.s) + Fn.create(ctx.tacc * btcE));
  const btcTweakedAgg = { R: btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: btcAdaptorAgg.negR };

  if (stopAfterPresign) {
    log('BOB', '*** Stopping after pre-sign ***');
    return {
      aggPubkey, btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
      tacc: ctx.tacc, btcE, compiled,
      contractId: alphDeployed.contractId,
      groupIndex: bobAlphWallet.group,
      bobAlphWallet,
    };
  }

  // ── CLAIM: Wait for Alice's BTC claim ──
  log('BOB', 'Waiting for Alice to claim BTC...');
  const btcClaimedEvent = await waitForSwapEvent(ws, SWAP_CLAIM_KIND, sessionId, alicePubHex,
    (e) => JSON.parse(e.content).type === 'btc_claimed', DM_TIMEOUT);
  const btcClaimed = JSON.parse(btcClaimedEvent.content);
  log('BOB', `Alice claimed BTC: txid=${btcClaimed.txid}`);

  // ── Extract t from on-chain BTC signature using adaptorExtract ──
  log('BOB', 'Extracting adaptor secret t from on-chain signature...');
  const onChainSig = await extractSignatureFromTx(btcClaimed.txid);
  const extractedTBytes = adaptorExtract(onChainSig.slice(32, 64), btcTweakedAgg.s, btcTweakedAgg.negR);
  log('BOB', `Extracted t: ${bytesToHex(extractedTBytes).slice(0, 16)}...`);

  // Complete ALPH adaptor signature
  const alphFinalSig = completeAdaptorSig(alphAdaptorAgg.R, alphAdaptorAgg.s, extractedTBytes, alphAdaptorAgg.negR);

  if (!schnorr.verify(alphFinalSig, ctx.alphMsg, ctx.aggPubkey))
    throw new Error('ALPH completed signature invalid');

  // Claim ALPH
  await new Promise(r => setTimeout(r, 3000));
  log('BOB', 'Calling swap() on Alephium contract...');
  const alphClaimResult = await claimSwap(bobAlphWallet, alphDeployed.contractId, bytesToHex(alphFinalSig), compiled, bobAlphWallet.group);
  await waitForTx(alphClaimResult.txId);
  log('BOB', `ALPH claimed! txid: ${alphClaimResult.txId}`);

  await publish(ws, createSwapClaim(bobSec, {
    sessionId, recipientPubHex: alicePubHex, claimType: 'alph_claimed',
    txid: alphClaimResult.txId,
  }));

  return {
    extractedTBytes, alphClaimTxid: alphClaimResult.txId,
    aggPubkey, compiled, bobAlphWallet, bobBtcAddress,
    btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
    btcSighash: ctx.btcSighash, Qbytes: ctx.Qbytes,
    gaccTweaked: ctx.gaccTweaked, tacc: ctx.tacc, btcE,
    fundTxid, fundVout, internalPubkey, scriptTree,
  };
}

// ============================================================
// Shared Test Setup
// ============================================================

async function setupTest() {
  const { aliceSec, alicePub, bobSec, bobPub } = generateSameGroupKeys();
  const alicePubHex = bytesToHex(alicePub);
  const bobPubHex = bytesToHex(bobPub);

  const aliceAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSec), keyType: 'bip340-schnorr' });
  const bobAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(bobSec), keyType: 'bip340-schnorr' });
  const aliceBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;
  const bobBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;

  log('SETUP', `Alice npub: ${nip19.npubEncode(alicePubHex)}`);
  log('SETUP', `      ALPH: ${aliceAlphWallet.address} (group ${aliceAlphWallet.group})`);
  log('SETUP', `      BTC:  ${aliceBtcAddress}`);
  log('SETUP', `Bob   npub: ${nip19.npubEncode(bobPubHex)}`);
  log('SETUP', `      ALPH: ${bobAlphWallet.address} (group ${bobAlphWallet.group})`);
  log('SETUP', `      BTC:  ${bobBtcAddress}`);

  log('SETUP', 'Funding Alice with 100 ALPH...');
  await waitForTx((await fundFromGenesis(aliceAlphWallet.address, ONE_ALPH * 100n)).txId);
  log('SETUP', 'Funding Bob with 5 ALPH for gas...');
  await waitForTx((await fundFromGenesis(bobAlphWallet.address, ONE_ALPH * 5n)).txId);

  log('SETUP', 'Mining 101 blocks to Bob\'s BTC address...');
  const blockHashes = await bitcoinRpc('generatetoaddress', [101, bobBtcAddress]);
  const block = await bitcoinRpc('getblock', [blockHashes[0], 2]);
  const coinbaseTx = block.tx[0];
  const coinbaseVout = coinbaseTx.vout.findIndex(o => o.scriptPubKey.address === bobBtcAddress);
  const coinbaseAmountSat = Math.round(coinbaseTx.vout[coinbaseVout].value * 1e8);

  return {
    aliceSec, alicePub, bobSec, bobPub,
    alicePubHex, bobPubHex,
    aliceAlphWallet, bobAlphWallet,
    aliceBtcAddress, bobBtcAddress,
    coinbaseTxid: coinbaseTx.txid, coinbaseVout, coinbaseAmountSat,
  };
}

// ============================================================
// Scenario 1: Happy Path
// ============================================================

async function testHappyPath() {
  console.log('\n=== Scenario 1: Happy Path (Structured Nostr Events) ===\n');

  const {
    aliceSec, bobSec, alicePubHex, bobPubHex,
    aliceAlphWallet, bobAlphWallet, aliceBtcAddress,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  // Both connect to relay
  const aliceWs = await connectRelay(RELAY_URL);
  const bobWs = await connectRelay(RELAY_URL);

  // Alice posts offer, Bob discovers it → session established
  log('ALICE', 'Posting public swap offer...');
  const offerEvent = createPublicEvent(aliceSec,
    `Selling 10 ALPH for ${BTC_AMOUNT} BTC. DM me if interested.`,
    [['t', 'atomicswap']],
  );
  await publish(aliceWs, offerEvent);
  const sessionId = offerEvent.id;

  log('BOB', 'Watching for swap offers...');
  const offer = await waitForEvent(bobWs, 1, { '#t': ['atomicswap'], authors: [alicePubHex] }, DM_TIMEOUT);
  log('BOB', `Found offer: "${offer.content}"`);

  // Run both sides concurrently
  const [aliceResult] = await Promise.all([
    aliceSideSwap(aliceWs, aliceSec, bobPubHex, sessionId),
    bobSideSwap(bobWs, bobSec, alicePubHex, sessionId, {
      coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    }),
  ]);

  aliceWs.close();
  bobWs.close();

  // Verify final balances
  log('VERIFY', 'Checking final balances...');
  const aliceAlphBal = await getBalance(aliceAlphWallet.address);
  const bobAlphBal = await getBalance(bobAlphWallet.address);
  const claimRawTx = await bitcoinRpc('getrawtransaction', [aliceResult.claimTxid, true]);
  const aliceBtcReceived = claimRawTx.vout.find(o => o.scriptPubKey.address === aliceBtcAddress);

  log('VERIFY', `Alice ALPH: ${Number(aliceAlphBal.balance) / 1e18} ALPH`);
  log('VERIFY', `Bob   ALPH: ${Number(bobAlphBal.balance) / 1e18} ALPH`);
  log('VERIFY', `Alice BTC:  ${aliceBtcReceived.value} BTC`);

  if (Number(aliceAlphBal.balance) / 1e18 < 85) throw new Error('Alice ALPH balance too low');
  if (Number(bobAlphBal.balance) / 1e18 < 10) throw new Error('Bob ALPH balance too low');
  if (aliceBtcReceived.value < BTC_AMOUNT - 0.001) throw new Error('Alice BTC too low');

  console.log('\n=== SCENARIO 1: HAPPY PATH COMPLETE ===');
}

// ============================================================
// Scenario 2: Both Refund
// ============================================================

async function testBothRefund() {
  console.log('\n=== Scenario 2: Both Refund (Structured Nostr Events) ===\n');

  const {
    aliceSec, bobSec, bobPub, alicePubHex, bobPubHex,
    aliceAlphWallet, bobBtcAddress,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  const aliceWs = await connectRelay(RELAY_URL);
  const bobWs = await connectRelay(RELAY_URL);

  const REFUND_CSV_TIMEOUT = 10;

  // Session setup
  const offerEvent = createPublicEvent(aliceSec,
    `Selling 10 ALPH for ${BTC_AMOUNT} BTC.`,
    [['t', 'atomicswap']],
  );
  await publish(aliceWs, offerEvent);
  const sessionId = offerEvent.id;
  await waitForEvent(bobWs, 1, { '#t': ['atomicswap'], authors: [alicePubHex] }, DM_TIMEOUT);

  // Run with skipClaim=true and expired ALPH timeout
  const [aliceResult] = await Promise.all([
    aliceSideSwap(aliceWs, aliceSec, bobPubHex, sessionId, {
      csvTimeout: REFUND_CSV_TIMEOUT,
      alphTimeoutMs: Date.now() - 60000, // already expired
      skipClaim: true,
    }),
    bobSideSwap(bobWs, bobSec, alicePubHex, sessionId, {
      csvTimeout: REFUND_CSV_TIMEOUT,
      coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    }).catch(e => {
      if (e.message.includes('timeout')) {
        log('BOB', 'Timed out waiting for Alice\'s BTC claim (expected in refund scenario)');
        return null;
      }
      throw e;
    }),
  ]);

  aliceWs.close();
  bobWs.close();

  // Alice refunds ALPH
  log('REFUND', 'Alice calls ALPH refund()...');
  const aliceBalBefore = await getBalance(aliceAlphWallet.address);
  const refundAlph = await refundSwap(aliceAlphWallet, aliceResult.deployResult.contractId, aliceResult.compiled);
  await waitForTx(refundAlph.txId);
  const aliceBalAfter = await getBalance(aliceAlphWallet.address);
  const recovered = Number(aliceBalAfter.balance - aliceBalBefore.balance) / 1e18;
  log('REFUND', `Alice recovered ~${recovered.toFixed(2)} ALPH`);
  if (recovered < 9) throw new Error('ALPH refund recovery too low');

  // Bob refunds BTC
  log('REFUND', `Mining ${REFUND_CSV_TIMEOUT} blocks for CSV timeout...`);
  await mineBlocks(REFUND_CSV_TIMEOUT, bobBtcAddress);

  log('REFUND', 'Bob builds BTC refund tx (script-path spend)...');
  const { psbt: refundPsbt } = buildRefundTx(
    aliceResult.fundTxid, aliceResult.fundVout, BTC_SAT,
    bobBtcAddress, aliceResult.internalPubkey, aliceResult.scriptTree, REFUND_CSV_TIMEOUT,
  );

  refundPsbt.signInput(0, {
    publicKey: Buffer.concat([Buffer.from([0x02]), Buffer.from(bobPub)]),
    signSchnorr: (hash) => Buffer.from(schnorr.sign(hash, bobSec)),
  });
  refundPsbt.finalizeAllInputs();
  const refundTxHex = refundPsbt.extractTransaction().toHex();
  const refundTxid = await broadcastTx(refundTxHex);
  await mineBlocks(1, bobBtcAddress);

  const refundRawTx = await bitcoinRpc('getrawtransaction', [refundTxid, true]);
  const bobOutput = refundRawTx.vout.find(o => o.scriptPubKey.address === bobBtcAddress);
  log('REFUND', `Bob recovered ${bobOutput.value} BTC`);
  if (bobOutput.value < BTC_AMOUNT - 0.001) throw new Error('BTC refund amount too low');

  console.log('\n=== SCENARIO 2: BOTH REFUND COMPLETE ===');
}

// ============================================================
// Scenario 3: Crash Recovery
// ============================================================

async function testCrashRecovery() {
  console.log('\n=== Scenario 3: Crash Recovery (Structured Nostr Events) ===\n');

  const {
    aliceSec, bobSec, alicePubHex, bobPubHex,
    aliceBtcAddress, bobAlphWallet,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  const aliceWs = await connectRelay(RELAY_URL);
  const bobWs = await connectRelay(RELAY_URL);

  // Session setup
  const offerEvent = createPublicEvent(aliceSec,
    `Selling 10 ALPH for ${BTC_AMOUNT} BTC.`,
    [['t', 'atomicswap']],
  );
  await publish(aliceWs, offerEvent);
  const sessionId = offerEvent.id;
  await waitForEvent(bobWs, 1, { '#t': ['atomicswap'], authors: [alicePubHex] }, DM_TIMEOUT);

  // Alice will timeout waiting for alph_claimed — expected
  const alicePromise = aliceSideSwap(aliceWs, aliceSec, bobPubHex, sessionId).catch(e => {
    if (e.message.includes('timeout') && e.message.includes('alph_claimed')) {
      log('ALICE', 'Timed out waiting for Bob\'s ALPH claim (Bob crashed — expected)');
      return 'timeout';
    }
    throw e;
  });

  const bobResult = await bobSideSwap(bobWs, bobSec, alicePubHex, sessionId, {
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    stopAfterPresign: true,
  });
  log('BOB', '*** CRASH! Bob stops processing ***');

  const aliceResult = await alicePromise;

  aliceWs.close();
  bobWs.close();

  // Bob "restarts" and recovers
  log('RECOVER', 'Bob restarts and checks on-chain for Alice\'s BTC claim...');

  const claimTxid = aliceResult === 'timeout' ? null : aliceResult.claimTxid;
  const foundTxid = claimTxid || await findBtcClaimTxid(aliceBtcAddress);
  if (!foundTxid) throw new Error('Could not find Alice\'s BTC claim tx');
  log('RECOVER', `Found BTC claim tx: ${foundTxid}`);

  // Extract t from on-chain signature using adaptorExtract
  const onChainSig = await extractSignatureFromTx(foundTxid);
  const extractedTBytes = adaptorExtract(onChainSig.slice(32, 64), bobResult.btcTweakedAgg.s, bobResult.btcTweakedAgg.negR);
  log('RECOVER', `Extracted t: ${bytesToHex(extractedTBytes).slice(0, 16)}...`);

  // Complete ALPH adaptor signature
  const alphFinalSig = completeAdaptorSig(
    bobResult.alphAdaptorAgg.R,
    bobResult.alphAdaptorAgg.s,
    extractedTBytes,
    bobResult.alphAdaptorAgg.negR,
  );

  const alphSigValid = schnorr.verify(alphFinalSig, hexToBytes(bobResult.contractId), bobResult.aggPubkey);
  if (!alphSigValid) throw new Error('Recovery: ALPH completed signature invalid');
  log('RECOVER', 'ALPH signature valid');

  // Claim ALPH
  await new Promise(r => setTimeout(r, 3000));
  const compiled = await compileSwapContract();
  log('RECOVER', 'Bob claims ALPH after crash recovery...');
  const alphClaimResult = await claimSwap(bobAlphWallet, bobResult.contractId, bytesToHex(alphFinalSig), compiled, bobResult.groupIndex);
  await waitForTx(alphClaimResult.txId);
  log('RECOVER', `ALPH claimed! txid: ${alphClaimResult.txId}`);

  // Verify
  const bobAlphBal = await getBalance(bobAlphWallet.address);
  log('VERIFY', `Bob ALPH: ${Number(bobAlphBal.balance) / 1e18} ALPH`);
  if (Number(bobAlphBal.balance) / 1e18 < 10) throw new Error('Bob ALPH balance too low after recovery');

  console.log('\n=== SCENARIO 3: CRASH RECOVERY COMPLETE ===');
}

// Helper: find BTC claim txid by scanning recent blocks
async function findBtcClaimTxid(aliceBtcAddress) {
  const blockCount = await bitcoinRpc('getblockcount');
  for (let h = blockCount; h > blockCount - 10 && h > 0; h--) {
    const hash = await bitcoinRpc('getblockhash', [h]);
    const blk = await bitcoinRpc('getblock', [hash, 2]);
    for (const tx of blk.tx) {
      if (tx.vin[0].coinbase) continue;
      for (const out of tx.vout) {
        if (out.scriptPubKey.address === aliceBtcAddress && out.value > 0.1) {
          return tx.txid;
        }
      }
    }
  }
  return null;
}

// ============================================================
// Main
// ============================================================

(async () => {
  console.log('=== Nostr-Based Atomic Swap Protocol ===\n');

  log('RELAY', `Starting local Nostr relay on port ${RELAY_PORT}...`);
  const relay = startRelay(RELAY_PORT);
  log('RELAY', 'Relay running');

  try {
    await testHappyPath();
    await testBothRefund();
    await testCrashRecovery();

    console.log('\n=== ALL 3 SCENARIOS PASSED ===');
  } finally {
    await relay.close();
    log('RELAY', 'Relay stopped');
  }
})().catch(e => {
  console.error('\nFATAL:', e.message);
  console.error(e.stack);
  process.exit(1);
});
