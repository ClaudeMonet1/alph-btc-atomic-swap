#!/usr/bin/env node
// Nostr-Based Atomic Swap Workflow
//
// Alice and Bob communicate exclusively through a local Nostr relay.
// Public offers for discovery, NIP-44 encrypted DMs for negotiation
// and protocol execution. Tests the real message exchange pattern
// including nonce commitment round.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { finalizeEvent } from 'nostr-tools/pure';
import { Relay, useWebSocketImplementation } from 'nostr-tools/relay';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { nip19 } from 'nostr-tools';
import WebSocket from 'ws';

import {
  keyAgg, nonceGen, nonceAgg,
  lift_x, hasEvenY, bytesToNum, numTo32b,
} from './musig2.js';
import {
  adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig,
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

useWebSocketImplementation(WebSocket);
web3.setCurrentNodeProvider('http://127.0.0.1:22973');

const log = (phase, msg) => console.log(`[${phase}] ${msg}`);

// ============================================================
// Nostr Helpers
// ============================================================

async function publishEvent(relay, secKey, kind, content, tags = []) {
  const event = finalizeEvent({
    kind,
    content,
    tags,
    created_at: Math.floor(Date.now() / 1000),
  }, secKey);
  await relay.publish(event);
  return event;
}

function getConversationKey(secKey, recipientPubHex) {
  return nip44.utils.getConversationKey(secKey, recipientPubHex);
}

async function sendDM(relay, secKey, recipientPubHex, msg) {
  const convKey = getConversationKey(secKey, recipientPubHex);
  const ciphertext = nip44.encrypt(JSON.stringify(msg), convKey);
  return publishEvent(relay, secKey, 4, ciphertext, [['p', recipientPubHex]]);
}

function waitForDM(relay, secKey, fromPubHex, type, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      sub.close();
      reject(new Error(`Timeout waiting for DM type="${type}" from ${fromPubHex.slice(0, 8)}...`));
    }, timeoutMs);

    const myPubHex = bytesToHex(schnorr.getPublicKey(secKey));
    const convKey = getConversationKey(secKey, fromPubHex);

    const sub = relay.subscribe(
      [{ kinds: [4], authors: [fromPubHex], '#p': [myPubHex] }],
      {
        onevent(event) {
          try {
            const plaintext = nip44.decrypt(event.content, convKey);
            const msg = JSON.parse(plaintext);
            if (msg.type === type) {
              clearTimeout(timer);
              sub.close();
              resolve(msg);
            }
          } catch {}
        },
        oneose() {},
      },
    );
  });
}

function waitForPublic(relay, kind, filter, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      sub.close();
      reject(new Error(`Timeout waiting for public event kind=${kind}`));
    }, timeoutMs);

    const sub = relay.subscribe(
      [{ kinds: [kind], ...filter }],
      {
        onevent(event) {
          clearTimeout(timer);
          sub.close();
          resolve(event);
        },
        oneose() {},
      },
    );
  });
}

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
// Alice's Protocol Flow
// ============================================================

async function runAlice(relayUrl, aliceSec, bobPubHex, {
  csvTimeout = CSV_TIMEOUT,
  alphTimeoutMs = Date.now() + 6 * 60 * 60 * 1000,
  skipClaim = false,
} = {}) {
  const relay = await Relay.connect(relayUrl);
  const alicePub = schnorr.getPublicKey(aliceSec);
  const alicePubHex = bytesToHex(alicePub);

  const aliceAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSec), keyType: 'bip340-schnorr' });
  const aliceBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;

  // Round 1: Post public offer
  log('ALICE', 'Posting public swap offer...');
  await publishEvent(relay, aliceSec, 1,
    `Selling 10 ALPH for ${BTC_AMOUNT} BTC. DM me if interested.`,
    [['t', 'atomicswap']],
  );

  // Round 2: Wait for Bob's acceptance, then confirm
  log('ALICE', 'Waiting for Bob\'s acceptance...');
  const accept = await waitForDM(relay, aliceSec, bobPubHex, 'accept', DM_TIMEOUT);
  log('ALICE', `Bob accepted: "${accept.text}"`);

  // Generate adaptor secret t, share T = t*G
  // Normalize T to even Y so Bob's lift_x(x-only) produces the same point
  let tBytes = schnorr.utils.randomSecretKey();
  let t = bytesToNum(tBytes);
  let T = G.multiply(t);
  if (!hasEvenY(T)) {
    T = T.negate();
    t = Fn.neg(t);
    tBytes = numTo32b(t);
  }
  const TBytes = pointToBytes(T);

  // MuSig2 key aggregation
  const bobPub = hexToBytes(bobPubHex);
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);

  log('ALICE', 'Sending confirmation with pubkey and adaptor point...');
  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'confirm',
    text: 'Deal! Here are my details.',
    pubkey: alicePubHex,
    adaptorPoint: bytesToHex(TBytes),
  });

  // Round 3: Wait for Bob's BTC lock
  log('ALICE', 'Waiting for Bob to lock BTC...');
  const btcLocked = await waitForDM(relay, aliceSec, bobPubHex, 'btc_locked', DM_TIMEOUT);
  log('ALICE', `Bob locked BTC: txid=${btcLocked.txid.slice(0, 16)}... vout=${btcLocked.vout}`);

  // Verify BTC output
  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } = createSwapOutput(aggPubkey, bobPub, csvTimeout);
  await verifySwapOutput(btcLocked.txid, swapBtcAddress, BTC_AMOUNT);
  log('ALICE', 'BTC output verified');

  // Deploy ALPH contract
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

  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'alph_deployed',
    text: 'BTC looks good. ALPH contract is live.',
    contractId: deployResult.contractId,
    contractAddress: deployResult.contractAddress,
  });

  // Wait for Bob's verification
  log('ALICE', 'Waiting for Bob to verify ALPH contract...');
  await waitForDM(relay, aliceSec, bobPubHex, 'alph_verified', DM_TIMEOUT);
  log('ALICE', 'Bob verified ALPH contract');

  // Round 4: Nonce commitment
  // Build claim tx sighash first (needed for nonce generation)
  const { sighash: btcSighash } = buildClaimTx(
    btcLocked.txid, btcLocked.vout, BTC_SAT, aliceBtcAddress, internalPubkey, scriptTree,
  );
  const { Qbytes, tweakScalar, negated: tweakNeg } = computeTweakedKey(aggPubkey, p2tr.hash);
  const gaccTweaked = tweakNeg ? Fn.create(n - gacc) : gacc;
  const tacc = tweakNeg ? Fn.neg(tweakScalar) : tweakScalar;

  const alphMsg = hexToBytes(deployResult.contractId);

  // Generate nonces for both messages
  const btcNonceA = nonceGen(aliceSec, Qbytes, btcSighash);
  const alphNonceA = nonceGen(aliceSec, aggPubkey, alphMsg);

  // Commit: hash of pubnonces
  const btcNonceHashA = bytesToHex(sha256(btcNonceA.pubNonce));
  const alphNonceHashA = bytesToHex(sha256(alphNonceA.pubNonce));

  log('ALICE', 'Sending nonce commitments...');
  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'nonce_commit',
    text: 'Starting nonce exchange. Here\'s my commitment — no peeking!',
    btcNonceHash: btcNonceHashA,
    alphNonceHash: alphNonceHashA,
  });

  const bobCommit = await waitForDM(relay, aliceSec, bobPubHex, 'nonce_commit', DM_TIMEOUT);
  log('ALICE', 'Got Bob\'s nonce commitments');

  // Round 5: Nonce reveal
  log('ALICE', 'Revealing nonces...');
  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'nonce_reveal',
    text: 'Revealing my nonces.',
    btcPubNonce: bytesToHex(btcNonceA.pubNonce),
    alphPubNonce: bytesToHex(alphNonceA.pubNonce),
  });

  const bobReveal = await waitForDM(relay, aliceSec, bobPubHex, 'nonce_reveal', DM_TIMEOUT);
  log('ALICE', 'Got Bob\'s nonce reveals');

  // Verify Bob's commitments
  const bobBtcNonce = hexToBytes(bobReveal.btcPubNonce);
  const bobAlphNonce = hexToBytes(bobReveal.alphPubNonce);
  if (bytesToHex(sha256(bobBtcNonce)) !== bobCommit.btcNonceHash) throw new Error('Bob BTC nonce commitment mismatch');
  if (bytesToHex(sha256(bobAlphNonce)) !== bobCommit.alphNonceHash) throw new Error('Bob ALPH nonce commitment mismatch');
  log('ALICE', 'Bob\'s nonce commitments verified');

  // Aggregate nonces
  const btcAggNonce = nonceAgg([btcNonceA.pubNonce, bobBtcNonce]);
  const alphAggNonce = nonceAgg([alphNonceA.pubNonce, bobAlphNonce]);

  // Round 6: Pre-signing
  log('ALICE', 'Creating adaptor pre-signatures...');
  const btcAdaptorA = adaptorSign(aliceSec, btcNonceA.secNonce, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 0, gaccTweaked);
  const alphAdaptorA = adaptorSign(aliceSec, alphNonceA.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 0, gacc);

  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'presigs',
    text: 'Here are my adaptor pre-signatures.',
    btcPresig: bytesToHex(btcAdaptorA),
    alphPresig: bytesToHex(alphAdaptorA),
  });

  const bobPresigs = await waitForDM(relay, aliceSec, bobPubHex, 'presigs', DM_TIMEOUT);
  log('ALICE', 'Got Bob\'s pre-signatures');

  // Verify Bob's pre-signatures
  const btcAdaptorB = hexToBytes(bobPresigs.btcPresig);
  const alphAdaptorB = hexToBytes(bobPresigs.alphPresig);

  const btcV = adaptorVerify(btcAdaptorB, bobBtcNonce, bobPub, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccTweaked);
  const alphV = adaptorVerify(alphAdaptorB, bobAlphNonce, bobPub, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 1, gacc);
  if (!btcV) throw new Error('Bob BTC adaptor verification failed');
  if (!alphV) throw new Error('Bob ALPH adaptor verification failed');
  log('ALICE', 'Bob\'s pre-signatures verified');

  // Aggregate adaptor pre-signatures
  const btcAdaptorAgg = adaptorAggregate([btcAdaptorA, btcAdaptorB], btcAggNonce, Qbytes, btcSighash, T);
  const alphAdaptorAgg = adaptorAggregate([alphAdaptorA, alphAdaptorB], alphAggNonce, aggPubkey, alphMsg, T);

  // Apply taproot tweak to BTC adaptor
  const btcE = computeAdaptorChallenge(btcAggNonce, Qbytes, btcSighash, T);
  const sTweaked = Fn.create(bytesToNum(btcAdaptorAgg.s) + Fn.create(tacc * btcE));
  const btcTweakedAgg = { R: btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: btcAdaptorAgg.negR };

  if (skipClaim) {
    log('ALICE', 'Skipping BTC claim (refund scenario)');
    relay.close();
    return {
      tBytes, t, T, aggPubkey, keyCoeffs, gacc, compiled,
      btcTweakedAgg, btcAdaptorAgg, alphAdaptorAgg,
      btcSighash, Qbytes, gaccTweaked, tacc, btcE,
      fundTxid: btcLocked.txid, fundVout: btcLocked.vout,
      internalPubkey, scriptTree, p2tr,
      deployResult, alphMsg,
      aliceAlphWallet, aliceBtcAddress,
    };
  }

  // Round 7: Alice claims BTC
  log('ALICE', 'Completing BTC adaptor signature with secret t...');
  const btcFinalSig = completeAdaptorSig(btcTweakedAgg.R, btcTweakedAgg.s, tBytes, btcTweakedAgg.negR);

  const btcValid = schnorr.verify(btcFinalSig, btcSighash, Qbytes);
  if (!btcValid) throw new Error('BTC completed signature invalid');

  const { psbt } = buildClaimTx(btcLocked.txid, btcLocked.vout, BTC_SAT, aliceBtcAddress, internalPubkey, scriptTree);
  const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
  const claimTxid = await broadcastTx(signedTxHex);
  await mineBlocks(1, aliceBtcAddress);
  log('ALICE', `BTC claimed! txid: ${claimTxid}`);

  await sendDM(relay, aliceSec, bobPubHex, {
    type: 'btc_claimed',
    text: 'BTC claimed! The adaptor secret is on-chain now.',
    txid: claimTxid,
  });

  // Wait for Bob's ALPH claim confirmation
  log('ALICE', 'Waiting for Bob to claim ALPH...');
  const alphClaimed = await waitForDM(relay, aliceSec, bobPubHex, 'alph_claimed', DM_TIMEOUT);
  log('ALICE', `Bob claimed ALPH: txid=${alphClaimed.txid}`);

  relay.close();
  return {
    claimTxid, aggPubkey, deployResult, compiled,
    aliceAlphWallet, aliceBtcAddress,
    btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
    btcSighash, Qbytes, gaccTweaked, tacc, btcE,
    fundTxid: btcLocked.txid, fundVout: btcLocked.vout,
    internalPubkey, scriptTree, p2tr, alphMsg,
  };
}

// ============================================================
// Bob's Protocol Flow
// ============================================================

async function runBob(relayUrl, bobSec, alicePubHex, {
  csvTimeout = CSV_TIMEOUT,
  coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  stopAfterPresign = false,
} = {}) {
  const relay = await Relay.connect(relayUrl);
  const bobPub = schnorr.getPublicKey(bobSec);
  const bobPubHex = bytesToHex(bobPub);

  const bobAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(bobSec), keyType: 'bip340-schnorr' });
  const bobBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;

  // Round 1: Watch for public offer
  log('BOB', 'Watching for swap offers...');
  const offer = await waitForPublic(relay, 1, { '#t': ['atomicswap'], authors: [alicePubHex] }, DM_TIMEOUT);
  log('BOB', `Found offer: "${offer.content}"`);

  // Round 2: Accept offer
  log('BOB', 'Accepting offer...');
  await sendDM(relay, bobSec, alicePubHex, {
    type: 'accept',
    text: `Hey! 10 ALPH for ${BTC_AMOUNT} BTC works. Let's do this.`,
  });

  // Wait for Alice's confirmation
  log('BOB', 'Waiting for Alice\'s confirmation...');
  const confirm = await waitForDM(relay, bobSec, alicePubHex, 'confirm', DM_TIMEOUT);
  log('BOB', `Alice confirmed. Adaptor point: ${confirm.adaptorPoint.slice(0, 16)}...`);

  const alicePub = hexToBytes(alicePubHex);
  const T = lift_x(bytesToNum(hexToBytes(confirm.adaptorPoint)));

  // MuSig2 key aggregation (same order: alice, bob)
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);

  // Round 3: Lock BTC
  log('BOB', 'Creating Bitcoin taproot output...');
  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } = createSwapOutput(aggPubkey, bobPub, csvTimeout);

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

  await sendDM(relay, bobSec, alicePubHex, {
    type: 'btc_locked',
    text: 'BTC locked! Verify whenever you\'re ready.',
    txid: fundTxid,
    vout: fundVout,
    amountSat: BTC_SAT,
  });

  // Wait for Alice's ALPH deployment
  log('BOB', 'Waiting for Alice to deploy ALPH contract...');
  const alphDeployed = await waitForDM(relay, bobSec, alicePubHex, 'alph_deployed', DM_TIMEOUT);
  log('BOB', `ALPH contract: ${alphDeployed.contractAddress}`);

  // Verify ALPH contract
  const compiled = await compileSwapContract();
  const aliceAlphAddress = addressFromPublicKey(alicePubHex, 'bip340-schnorr');
  await verifyContractState(
    alphDeployed.contractAddress, bytesToHex(aggPubkey),
    bobAlphWallet.address, aliceAlphAddress,
    ALPH_AMOUNT, undefined, compiled,
  );
  log('BOB', 'ALPH contract verified');

  await sendDM(relay, bobSec, alicePubHex, {
    type: 'alph_verified',
    text: 'Contract checks out. Keys, balance, bytecode — all good.',
  });

  // Round 4: Nonce commitment
  const aliceBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;
  const { sighash: btcSighash } = buildClaimTx(
    fundTxid, fundVout, BTC_SAT, aliceBtcAddress, internalPubkey, scriptTree,
  );
  const { Qbytes, tweakScalar, negated: tweakNeg } = computeTweakedKey(aggPubkey, p2tr.hash);
  const gaccTweaked = tweakNeg ? Fn.create(n - gacc) : gacc;
  const tacc = tweakNeg ? Fn.neg(tweakScalar) : tweakScalar;

  const alphMsg = hexToBytes(alphDeployed.contractId);

  // Generate nonces
  const btcNonceB = nonceGen(bobSec, Qbytes, btcSighash);
  const alphNonceB = nonceGen(bobSec, aggPubkey, alphMsg);

  // Wait for Alice's commitment first, then send ours
  log('BOB', 'Waiting for Alice\'s nonce commitments...');
  const aliceCommit = await waitForDM(relay, bobSec, alicePubHex, 'nonce_commit', DM_TIMEOUT);
  log('BOB', 'Got Alice\'s nonce commitments');

  const btcNonceHashB = bytesToHex(sha256(btcNonceB.pubNonce));
  const alphNonceHashB = bytesToHex(sha256(alphNonceB.pubNonce));

  log('BOB', 'Sending nonce commitments...');
  await sendDM(relay, bobSec, alicePubHex, {
    type: 'nonce_commit',
    text: 'Here\'s mine.',
    btcNonceHash: btcNonceHashB,
    alphNonceHash: alphNonceHashB,
  });

  // Round 5: Nonce reveal — wait for Alice's first, then send ours
  log('BOB', 'Waiting for Alice\'s nonce reveals...');
  const aliceReveal = await waitForDM(relay, bobSec, alicePubHex, 'nonce_reveal', DM_TIMEOUT);
  log('BOB', 'Got Alice\'s nonce reveals');

  // Verify Alice's commitments
  const aliceBtcNonce = hexToBytes(aliceReveal.btcPubNonce);
  const aliceAlphNonce = hexToBytes(aliceReveal.alphPubNonce);
  if (bytesToHex(sha256(aliceBtcNonce)) !== aliceCommit.btcNonceHash) throw new Error('Alice BTC nonce commitment mismatch');
  if (bytesToHex(sha256(aliceAlphNonce)) !== aliceCommit.alphNonceHash) throw new Error('Alice ALPH nonce commitment mismatch');
  log('BOB', 'Alice\'s nonce commitments verified');

  log('BOB', 'Revealing nonces...');
  await sendDM(relay, bobSec, alicePubHex, {
    type: 'nonce_reveal',
    text: 'Commitment checks out. Here are mine.',
    btcPubNonce: bytesToHex(btcNonceB.pubNonce),
    alphPubNonce: bytesToHex(alphNonceB.pubNonce),
  });

  // Aggregate nonces
  const btcAggNonce = nonceAgg([aliceBtcNonce, btcNonceB.pubNonce]);
  const alphAggNonce = nonceAgg([aliceAlphNonce, alphNonceB.pubNonce]);

  // Round 6: Pre-signing — wait for Alice's first, then send ours
  log('BOB', 'Waiting for Alice\'s pre-signatures...');
  const alicePresigs = await waitForDM(relay, bobSec, alicePubHex, 'presigs', DM_TIMEOUT);
  log('BOB', 'Got Alice\'s pre-signatures');

  // Verify Alice's pre-signatures
  const btcAdaptorA = hexToBytes(alicePresigs.btcPresig);
  const alphAdaptorA = hexToBytes(alicePresigs.alphPresig);

  const btcVA = adaptorVerify(btcAdaptorA, aliceBtcNonce, alicePub, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 0, gaccTweaked);
  const alphVA = adaptorVerify(alphAdaptorA, aliceAlphNonce, alicePub, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 0, gacc);
  if (!btcVA) throw new Error('Alice BTC adaptor verification failed');
  if (!alphVA) throw new Error('Alice ALPH adaptor verification failed');
  log('BOB', 'Alice\'s pre-signatures verified');

  log('BOB', 'Creating adaptor pre-signatures...');
  const btcAdaptorB = adaptorSign(bobSec, btcNonceB.secNonce, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccTweaked);
  const alphAdaptorB = adaptorSign(bobSec, alphNonceB.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 1, gacc);

  await sendDM(relay, bobSec, alicePubHex, {
    type: 'presigs',
    text: 'Verified yours. Here are mine. Ready when you are!',
    btcPresig: bytesToHex(btcAdaptorB),
    alphPresig: bytesToHex(alphAdaptorB),
  });

  // Aggregate adaptor pre-signatures
  const btcAdaptorAgg = adaptorAggregate([btcAdaptorA, btcAdaptorB], btcAggNonce, Qbytes, btcSighash, T);
  const alphAdaptorAgg = adaptorAggregate([alphAdaptorA, alphAdaptorB], alphAggNonce, aggPubkey, alphMsg, T);

  // Apply taproot tweak
  const btcE = computeAdaptorChallenge(btcAggNonce, Qbytes, btcSighash, T);
  const sTweaked = Fn.create(bytesToNum(btcAdaptorAgg.s) + Fn.create(tacc * btcE));
  const btcTweakedAgg = { R: btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: btcAdaptorAgg.negR };

  // Early exit for crash recovery testing
  if (stopAfterPresign) {
    log('BOB', '*** Stopping after pre-sign ***');
    relay.close();
    return {
      aggPubkey, btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
      tacc, btcE, compiled,
      contractId: alphDeployed.contractId,
      groupIndex: bobAlphWallet.group,
      bobAlphWallet,
    };
  }

  // Round 7: Wait for Alice's BTC claim
  log('BOB', 'Waiting for Alice to claim BTC...');
  const btcClaimed = await waitForDM(relay, bobSec, alicePubHex, 'btc_claimed', DM_TIMEOUT);
  log('BOB', `Alice claimed BTC: txid=${btcClaimed.txid}`);

  // Extract t from on-chain BTC signature
  log('BOB', 'Extracting adaptor secret t from on-chain signature...');
  const onChainSig = await extractSignatureFromTx(btcClaimed.txid);
  const sOnChain = bytesToNum(onChainSig.slice(32, 64));
  const sPreTweaked = bytesToNum(btcAdaptorAgg.s);
  const tweakContrib = Fn.create(tacc * btcE);
  const tEffective = Fn.create(sOnChain - sPreTweaked - tweakContrib);
  const extractedT = btcTweakedAgg.negR ? Fn.neg(tEffective) : tEffective;
  log('BOB', `Extracted t: ${extractedT.toString(16).slice(0, 16)}...`);

  // Complete ALPH adaptor signature
  const alphFinalSig = completeAdaptorSig(alphAdaptorAgg.R, alphAdaptorAgg.s, numTo32b(extractedT), alphAdaptorAgg.negR);

  const alphSigValid = schnorr.verify(alphFinalSig, alphMsg, aggPubkey);
  if (!alphSigValid) throw new Error('ALPH completed signature invalid');

  // Claim ALPH
  await new Promise(r => setTimeout(r, 3000));
  log('BOB', 'Calling swap() on Alephium contract...');
  const alphClaimResult = await claimSwap(bobAlphWallet, alphDeployed.contractId, bytesToHex(alphFinalSig), compiled, bobAlphWallet.group);
  await waitForTx(alphClaimResult.txId);
  log('BOB', `ALPH claimed! txid: ${alphClaimResult.txId}`);

  await sendDM(relay, bobSec, alicePubHex, {
    type: 'alph_claimed',
    text: 'Extracted t, ALPH claimed. Pleasure doing business!',
    txid: alphClaimResult.txId,
  });

  relay.close();
  return {
    extractedT, alphClaimTxid: alphClaimResult.txId,
    aggPubkey, compiled, bobAlphWallet, bobBtcAddress,
    btcAdaptorAgg, alphAdaptorAgg, btcTweakedAgg,
    btcSighash, Qbytes, gaccTweaked, tacc, btcE,
    fundTxid, fundVout, internalPubkey, scriptTree,
  };
}

// ============================================================
// Scenario 1: Happy Path
// ============================================================

async function testHappyPath() {
  console.log('\n=== Scenario 1: Happy Path (Nostr Relay) ===\n');

  const {
    aliceSec, bobSec, alicePubHex, bobPubHex,
    aliceAlphWallet, bobAlphWallet, aliceBtcAddress,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  // Run Alice and Bob concurrently via relay
  const [aliceResult] = await Promise.all([
    runAlice(RELAY_URL, aliceSec, bobPubHex),
    runBob(RELAY_URL, bobSec, alicePubHex, {
      coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    }),
  ]);

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
  console.log('\n=== Scenario 2: Both Refund (Nostr Relay) ===\n');

  const {
    aliceSec, bobSec, bobPub, alicePubHex, bobPubHex,
    aliceAlphWallet, bobBtcAddress,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  const REFUND_CSV_TIMEOUT = 10;

  // Run through protocol with skipClaim=true and expired ALPH timeout
  const [aliceResult] = await Promise.all([
    runAlice(RELAY_URL, aliceSec, bobPubHex, {
      csvTimeout: REFUND_CSV_TIMEOUT,
      alphTimeoutMs: Date.now() - 60000, // already expired
      skipClaim: true,
    }),
    runBob(RELAY_URL, bobSec, alicePubHex, {
      csvTimeout: REFUND_CSV_TIMEOUT,
      coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    }).catch(e => {
      // Bob will timeout waiting for btc_claimed since Alice skips claim
      if (e.message.includes('Timeout')) {
        log('BOB', 'Timed out waiting for Alice\'s BTC claim (expected in refund scenario)');
        return null;
      }
      throw e;
    }),
  ]);

  // Alice refunds ALPH (timeout already expired)
  log('REFUND', 'Alice calls ALPH refund()...');
  const aliceBalBefore = await getBalance(aliceAlphWallet.address);
  const refundAlph = await refundSwap(aliceAlphWallet, aliceResult.deployResult.contractId, aliceResult.compiled);
  await waitForTx(refundAlph.txId);
  const aliceBalAfter = await getBalance(aliceAlphWallet.address);
  const recovered = Number(aliceBalAfter.balance - aliceBalBefore.balance) / 1e18;
  log('REFUND', `Alice recovered ~${recovered.toFixed(2)} ALPH`);
  if (recovered < 9) throw new Error('ALPH refund recovery too low');

  // Bob refunds BTC (mine past CSV timeout)
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
  console.log('\n=== Scenario 3: Crash Recovery (Nostr Relay) ===\n');

  const {
    aliceSec, bobSec, alicePubHex, bobPubHex,
    aliceBtcAddress, bobAlphWallet,
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
  } = await setupTest();

  // Run Alice (who will claim BTC) and Bob (who stops after presigning) concurrently
  // Alice will timeout waiting for alph_claimed — that's expected
  const alicePromise = runAlice(RELAY_URL, aliceSec, bobPubHex).catch(e => {
    if (e.message.includes('Timeout') && e.message.includes('alph_claimed')) {
      log('ALICE', 'Timed out waiting for Bob\'s ALPH claim (Bob crashed — expected)');
      return 'timeout';
    }
    throw e;
  });

  const bobResult = await runBob(RELAY_URL, bobSec, alicePubHex, {
    coinbaseTxid, coinbaseVout, coinbaseAmountSat,
    stopAfterPresign: true,
  });
  log('BOB', '*** CRASH! Bob stops processing ***');

  const aliceResult = await alicePromise;

  // Bob "restarts" and recovers
  log('RECOVER', 'Bob restarts and checks on-chain for Alice\'s BTC claim...');

  // Find the claim txid from on-chain data
  const claimTxid = aliceResult === 'timeout' ? null : aliceResult.claimTxid;
  const foundTxid = claimTxid || await findBtcClaimTxid(aliceBtcAddress);
  if (!foundTxid) throw new Error('Could not find Alice\'s BTC claim tx');
  log('RECOVER', `Found BTC claim tx: ${foundTxid}`);

  // Extract t from on-chain signature
  const onChainSig = await extractSignatureFromTx(foundTxid);
  const sOnChain = bytesToNum(onChainSig.slice(32, 64));
  const sPreTweaked = bytesToNum(bobResult.btcAdaptorAgg.s);
  const tweakContrib = Fn.create(bobResult.tacc * bobResult.btcE);
  const tEffective = Fn.create(sOnChain - sPreTweaked - tweakContrib);
  const extractedT = bobResult.btcTweakedAgg.negR ? Fn.neg(tEffective) : tEffective;
  log('RECOVER', `Extracted t: ${extractedT.toString(16).slice(0, 16)}...`);

  // Complete ALPH adaptor signature
  const alphFinalSig = completeAdaptorSig(
    bobResult.alphAdaptorAgg.R,
    bobResult.alphAdaptorAgg.s,
    numTo32b(extractedT),
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

// Helper: find BTC claim txid by scanning recent blocks for a non-coinbase tx to Alice
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
  console.log('=== Nostr-Based Atomic Swap Workflow ===\n');

  // Start local relay
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
