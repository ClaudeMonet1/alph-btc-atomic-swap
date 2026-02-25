#!/usr/bin/env node
// End-to-End Adaptor Signature Atomic Swap: BTC <-> ALPH
//
// Alice has ALPH, wants BTC. Bob has BTC, wants ALPH.
// No hash preimages. MuSig2 + adaptor signatures = scriptless scripts.
//
// On-chain footprint when swap succeeds:
//   Bitcoin: key path taproot spend (1 sig, looks like normal payment)
//   Alephium: contract call with 1 MuSig2 signature

import fs from 'fs';
import path from 'path';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { nip19 } from 'nostr-tools';

import {
  keyAgg, nonceGen, nonceAgg,
  taggedHash, lift_x, hasEvenY, getPlainPubkey,
} from './musig2.js';
import {
  adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig,
  G, Fn, n, numTo32b, bytesToNum, pointToBytes,
} from './adaptor.js';
import {
  bitcoinRpc, createSwapOutput, verifySwapOutput,
  buildClaimTx, buildP2TRKeyPathSpend, finalizeKeyPathSpend, broadcastTx,
  mineBlocks, extractSignatureFromTx, buildRefundTx, REGTEST, bitcoin,
} from './btc-swap.js';
import {
  compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState,
  fundFromGenesis, getBalance, waitForTx,
  web3, ONE_ALPH, PrivateKeyWallet,
} from './alph-swap.js';

const log = (phase, msg) => console.log(`[${phase}] ${msg}`);

// Compute the taproot-tweaked aggregate key Q = P + H_TapTweak(P || merkle_root) * G
function computeTweakedKey(aggPubkey, merkleRoot) {
  const tweakHash = taggedHash('TapTweak', aggPubkey, merkleRoot);
  const tweakScalar = bytesToNum(tweakHash);
  const P = lift_x(bytesToNum(aggPubkey));
  let Q = P.add(G.multiply(tweakScalar));
  const negated = !hasEvenY(Q);
  if (negated) Q = Q.negate();
  return { Q, Qbytes: getPlainPubkey(Q), tweakScalar, negated };
}

// Compute the adaptor challenge e for a given set of session parameters
function computeAdaptorChallenge(aggNonce, aggPubkey, msg, adaptorPoint) {
  const R1 = schnorr.Point.fromBytes(aggNonce.slice(0, 33));
  const R2 = schnorr.Point.fromBytes(aggNonce.slice(33, 66));
  const bHash = taggedHash('MuSig/noncecoef', aggNonce, aggPubkey, msg);
  const b = Fn.create(bytesToNum(bHash));
  const Ragg = R1.add(R2.multiply(b));
  const Reff = Ragg.add(adaptorPoint);
  const negR = !hasEvenY(Reff);
  const Rfinal = negR ? Reff.negate() : Reff;
  const e = Fn.create(bytesToNum(
    taggedHash('BIP0340/challenge', getPlainPubkey(Rfinal), aggPubkey, msg)
  ));
  return e;
}

// Compute taproot-tweaked private key for key-path-only P2TR spend
function computeTweakedPrivateKey(privateKeyBytes, pubkeyXOnly) {
  const d = bytesToNum(privateKeyBytes);
  const P = G.multiply(d);
  const dAdj = hasEvenY(P) ? d : Fn.create(n - d);
  const tweakHash = taggedHash('TapTweak', pubkeyXOnly);
  const tweak = bytesToNum(tweakHash);
  return numTo32b(Fn.create(dAdj + tweak));
}

// ---- Swap State Persistence ----

const SWAP_STATE_FILE = path.join(process.cwd(), '.swap-state.json');

function saveSwapState(data) {
  fs.writeFileSync(SWAP_STATE_FILE, JSON.stringify(data, null, 2));
  log('STATE', `Saved swap state (phase: ${data.phase})`);
}

function loadSwapState() {
  try {
    return JSON.parse(fs.readFileSync(SWAP_STATE_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function clearSwapState() {
  try {
    fs.unlinkSync(SWAP_STATE_FILE);
    log('STATE', 'Cleared swap state file');
  } catch {}
}

export async function recoverSwap(bobSecHex) {
  const state = loadSwapState();
  if (!state) return false;

  log('RECOVER', `Found swap state file (phase: ${state.phase})`);

  switch (state.phase) {
    case 'locked':
      log('RECOVER', 'Swap interrupted after locking funds but before pre-signing.');
      log('RECOVER', 'No adaptor pre-signatures were exchanged — cannot claim.');
      log('RECOVER', `BTC: wait for CSV timeout (${state.csvTimeout} blocks), then refund via script-path spend.`);
      log('RECOVER', `ALPH: wait until ${new Date(state.alphTimeoutMs).toISOString()}, then call refund().`);
      log('RECOVER', 'Manual intervention required. State file preserved.');
      return true;

    case 'presigned': {
      log('RECOVER', 'Swap interrupted after pre-signing. Completing BTC claim...');
      const btcFinalSig = completeAdaptorSig(
        hexToBytes(state.btcAdaptorAgg.R),
        hexToBytes(state.btcTweakedS),
        hexToBytes(state.adaptorSecret),
        state.btcAdaptorAgg.negR,
      );

      const btcSighash = hexToBytes(state.btcSighash);
      const Qbytes = hexToBytes(state.Qbytes);
      if (!schnorr.verify(btcFinalSig, btcSighash, Qbytes)) {
        throw new Error('Recovery: BTC completed signature invalid');
      }

      const internalPubkey = Buffer.from(hexToBytes(state.internalPubkey));
      const scriptTree = { output: Buffer.from(hexToBytes(state.scriptTreeOutput)) };
      const { psbt } = buildClaimTx(
        state.fundTxid, state.fundVout, state.btcSat,
        state.aliceBtcAddress, internalPubkey, scriptTree,
      );
      const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
      const claimTxid = await broadcastTx(signedTxHex);
      log('RECOVER', `BTC claimed! txid: ${claimTxid}`);

      saveSwapState({ ...state, phase: 'btc_claimed', btcClaimTxid: claimTxid });
      return recoverSwap(bobSecHex);
    }

    case 'btc_claimed': {
      log('RECOVER', 'BTC claimed. Extracting adaptor secret and claiming ALPH...');

      if (!bobSecHex) {
        log('RECOVER', 'Bob\'s private key required to claim ALPH. Pass bobSecHex to recoverSwap().');
        return true;
      }

      // Extract t from on-chain BTC signature
      const onChainSig = await extractSignatureFromTx(state.btcClaimTxid);
      const sOnChain = bytesToNum(onChainSig.slice(32, 64));
      const sPreTweaked = bytesToNum(hexToBytes(state.btcAdaptorAgg.s));
      const tacc = BigInt(state.tacc);
      const btcE = BigInt(state.btcE);
      const tweakContrib = Fn.create(tacc * btcE);
      const tEffective = Fn.create(sOnChain - sPreTweaked - tweakContrib);
      const extractedT = state.btcAdaptorAgg.negR ? Fn.neg(tEffective) : tEffective;
      log('RECOVER', `Extracted adaptor secret t: ${extractedT.toString(16).slice(0, 16)}...`);

      // Complete ALPH adaptor signature
      const alphFinalSig = completeAdaptorSig(
        hexToBytes(state.alphAdaptorAgg.R),
        hexToBytes(state.alphAdaptorAgg.s),
        numTo32b(extractedT),
        state.alphAdaptorAgg.negR,
      );

      const aggPubkey = hexToBytes(state.aggPubkey);
      const alphMsg = hexToBytes(state.contractId);
      if (!schnorr.verify(alphFinalSig, alphMsg, aggPubkey)) {
        throw new Error('Recovery: ALPH completed signature invalid');
      }

      // Claim ALPH
      web3.setCurrentNodeProvider('http://127.0.0.1:22973');
      const bobWallet = new PrivateKeyWallet({ privateKey: bobSecHex, keyType: 'bip340-schnorr' });
      const compiled = await compileSwapContract();
      await new Promise(r => setTimeout(r, 3000));
      const alphClaimResult = await claimSwap(
        bobWallet, state.contractId, bytesToHex(alphFinalSig),
        compiled, state.groupIndex,
      );
      await waitForTx(alphClaimResult.txId);
      log('RECOVER', `ALPH claimed! txid: ${alphClaimResult.txId}`);

      saveSwapState({ ...state, phase: 'complete' });
      return recoverSwap(bobSecHex);
    }

    case 'complete':
      log('RECOVER', 'Swap already completed. Cleaning up state file.');
      clearSwapState();
      return true;

    default:
      log('RECOVER', `Unknown phase: ${state.phase}`);
      return false;
  }
}

async function main() {
  console.log('=== BTC-ALPH Atomic Swap via Adaptor Signatures ===\n');

  // ============================================================
  // Phase 1: Setup -- keys, addresses, funding
  // ============================================================
  log('SETUP', 'Generating Alice and Bob keys from Nostr nsec...');

  // Generate keys, ensuring Alice and Bob end up in the same Alephium group
  // (required because Alephium's sharding requires contract caller = same group)
  let aliceSecBytes, bobSecBytes, alicePub, bobPub;
  {
    const { groupOfAddress, addressFromPublicKey } = await import('@alephium/web3');
    const getGroup = (pub) => groupOfAddress(addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr'));
    aliceSecBytes = schnorr.utils.randomSecretKey();
    alicePub = schnorr.getPublicKey(aliceSecBytes);
    const targetGroup = getGroup(alicePub);
    do {
      bobSecBytes = schnorr.utils.randomSecretKey();
      bobPub = schnorr.getPublicKey(bobSecBytes);
    } while (getGroup(bobPub) !== targetGroup);
  }

  // Derive Alephium wallets and BTC addresses from the same nsec keys
  web3.setCurrentNodeProvider('http://127.0.0.1:22973');
  const aliceAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSecBytes), keyType: 'bip340-schnorr' });
  const bobAlphWallet = new PrivateKeyWallet({ privateKey: bytesToHex(bobSecBytes), keyType: 'bip340-schnorr' });
  const aliceBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;
  const bobBtcAddress = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;

  // One nsec → three networks
  log('SETUP', `Alice npub: ${nip19.npubEncode(bytesToHex(alicePub))}`);
  log('SETUP', `      ALPH: ${aliceAlphWallet.address} (group ${aliceAlphWallet.group})`);
  log('SETUP', `      BTC:  ${aliceBtcAddress}`);
  log('SETUP', `Bob   npub: ${nip19.npubEncode(bytesToHex(bobPub))}`);
  log('SETUP', `      ALPH: ${bobAlphWallet.address} (group ${bobAlphWallet.group})`);
  log('SETUP', `      BTC:  ${bobBtcAddress}`);

  // Fund participants
  log('SETUP', 'Funding Alice with 100 ALPH...');
  await waitForTx((await fundFromGenesis(aliceAlphWallet.address, ONE_ALPH * 100n)).txId);

  log('SETUP', 'Funding Bob with 5 ALPH for gas...');
  await waitForTx((await fundFromGenesis(bobAlphWallet.address, ONE_ALPH * 5n)).txId);

  // Mine blocks to Bob's nsec-derived P2TR (coinbase matures after 100 confirmations)
  log('SETUP', 'Mining 101 blocks to Bob\'s BTC address...');
  const blockHashes = await bitcoinRpc('generatetoaddress', [101, bobBtcAddress]);
  const block = await bitcoinRpc('getblock', [blockHashes[0], 2]);
  const coinbaseTx = block.tx[0];
  const coinbaseVout = coinbaseTx.vout.findIndex(o => o.scriptPubKey.address === bobBtcAddress);
  const coinbaseAmountSat = Math.round(coinbaseTx.vout[coinbaseVout].value * 1e8);
  log('SETUP', `Bob BTC balance: ${coinbaseTx.vout[coinbaseVout].value} BTC (mature coinbase)`);

  const aliceAlphBal = await getBalance(aliceAlphWallet.address);
  log('SETUP', `Alice ALPH balance: ${Number(aliceAlphBal.balance) / 1e18} ALPH`);

  // ============================================================
  // Phase 2: Key Aggregation + Adaptor Setup
  // ============================================================
  log('KEYAGG', 'Computing MuSig2 key aggregation...');

  // Alice generates adaptor secret t, shares T = t*G
  const tBytes = schnorr.utils.randomSecretKey();
  const t = bytesToNum(tBytes);
  const T = G.multiply(t);
  log('KEYAGG', `Adaptor point T: ${bytesToHex(pointToBytes(T)).slice(0, 16)}...`);

  // P_swap = MuSig2_KeyAgg(P_alice, P_bob)
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);
  log('KEYAGG', `P_swap (aggregated key): ${bytesToHex(aggPubkey).slice(0, 16)}...`);

  // ============================================================
  // Phase 3: Lock funds on both chains
  // ============================================================
  // Timeout ordering: T_btc > T_alph + safety margin.
  // The first lock (BTC) must have a longer timeout so Bob can always
  // refund BTC after Alice's ALPH refund window has closed. This prevents
  // Alice from claiming BTC at the last moment before T_alph, leaving
  // Bob no time to extract t and claim ALPH.
  const CSV_TIMEOUT = 144; // ~1 day on mainnet; instant on regtest
  const BTC_AMOUNT = 0.5;
  const BTC_SAT = Math.round(BTC_AMOUNT * 1e8);

  log('LOCK', `Creating Bitcoin taproot output (key: P_swap, refund: Bob after ${CSV_TIMEOUT} blocks)...`);
  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } = createSwapOutput(aggPubkey, bobPub, CSV_TIMEOUT);
  log('LOCK', `BTC swap address: ${swapBtcAddress}`);

  // Bob funds swap from his nsec-derived P2TR (signed with his nsec)
  log('LOCK', 'Bob signs funding tx from his P2TR...');
  const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(
    coinbaseTx.txid, coinbaseVout, coinbaseAmountSat,
    swapBtcAddress, BTC_SAT, bobPub,
  );
  const bobTweakedKey = computeTweakedPrivateKey(bobSecBytes, bobPub);
  const fundSig = schnorr.sign(fundSighash, bobTweakedKey);
  const fundTxHex = finalizeKeyPathSpend(fundPsbt, fundSig);
  const fundTxid = await broadcastTx(fundTxHex);
  await mineBlocks(1, bobBtcAddress);

  // Find the swap output vout in the funding tx
  const fundRawTx = await bitcoinRpc('getrawtransaction', [fundTxid, true]);
  const fundVout = fundRawTx.vout.findIndex(o => o.scriptPubKey.address === swapBtcAddress);
  log('LOCK', `BTC funded from Bob's P2TR: txid=${fundTxid.slice(0, 16)}... vout=${fundVout}`);

  log('LOCK', 'Compiling and deploying Alephium AtomicSwap contract...');
  const compiled = await compileSwapContract();
  const ALPH_AMOUNT = ONE_ALPH * 10n;
  const ALPH_TIMEOUT_MS = Date.now() + 6 * 60 * 60 * 1000; // 6 hours < BTC's ~1 day

  // Deploy contract to Bob's group so Bob can claim from same group
  const deployResult = await deploySwapContract(
    aliceAlphWallet, bytesToHex(aggPubkey), bobAlphWallet.address, aliceAlphWallet.address,
    ALPH_TIMEOUT_MS, ALPH_AMOUNT, compiled, bobAlphWallet.group,
  );
  await waitForTx(deployResult.txId);
  log('LOCK', `ALPH contract deployed: ${deployResult.contractAddress}`);
  log('LOCK', `  contractId: ${deployResult.contractId}`);

  // ============================================================
  // Phase 3b: Verify counterparty locks before pre-signing
  // ============================================================

  // Alice verifies Bob's BTC lock: correct address, amount, confirmed
  log('VERIFY-LOCK', 'Alice verifies BTC taproot output...');
  await verifySwapOutput(fundTxid, swapBtcAddress, BTC_AMOUNT);
  log('VERIFY-LOCK', 'BTC output verified: correct address, amount, confirmed');

  // Bob verifies Alice's ALPH lock: correct swapKey, claimAddress, refundAddress, amount
  log('VERIFY-LOCK', 'Bob verifies Alephium contract state...');
  await verifyContractState(
    deployResult.contractAddress,
    bytesToHex(aggPubkey),     // expected swapKey
    bobAlphWallet.address,     // expected claimAddress (Bob)
    aliceAlphWallet.address,   // expected refundAddress (Alice)
    ALPH_AMOUNT,               // minimum ALPH deposited
    undefined,                 // maxTimeout
    compiled,                  // verify bytecode matches expected contract
  );
  log('VERIFY-LOCK', 'ALPH contract verified: correct keys, addresses, balance');

  // Checkpoint: locked — both chains funded and verified
  saveSwapState({
    phase: 'locked',
    alicePub: bytesToHex(alicePub),
    bobPub: bytesToHex(bobPub),
    aggPubkey: bytesToHex(aggPubkey),
    keyCoeffs: keyCoeffs.map(k => k.toString()),
    gacc: gacc.toString(),
    contractId: deployResult.contractId,
    contractAddress: deployResult.contractAddress,
    groupIndex: deployResult.groupIndex,
    fundTxid,
    fundVout,
    btcSat: BTC_SAT,
    csvTimeout: CSV_TIMEOUT,
    aliceBtcAddress,
    bobBtcAddress,
    aliceAlphAddress: aliceAlphWallet.address,
    bobAlphAddress: bobAlphWallet.address,
    internalPubkey: bytesToHex(internalPubkey),
    scriptTreeOutput: bytesToHex(scriptTree.output),
    p2trHash: bytesToHex(p2tr.hash),
    alphTimeoutMs: ALPH_TIMEOUT_MS,
    adaptorSecret: bytesToHex(tBytes),
  });

  // ============================================================
  // Phase 4: Pre-sign (off-chain adaptor exchange)
  // ============================================================

  // --- BTC claim: sign with taproot-tweaked key Q ---
  // Taproot key path requires signing against Q = P + H_TapTweak(P||m)*G
  const { sighash: btcSighash } = buildClaimTx(
    fundTxid, fundVout, BTC_SAT, aliceBtcAddress, internalPubkey, scriptTree,
  );
  log('PRESIGN', `BTC sighash: ${bytesToHex(btcSighash).slice(0, 16)}...`);

  const { Qbytes, tweakScalar, negated: tweakNeg } = computeTweakedKey(aggPubkey, p2tr.hash);
  log('PRESIGN', `Tweaked output key Q: ${bytesToHex(Qbytes).slice(0, 16)}...`);

  // BIP-327 apply_tweak: when Q has odd Y, negate gacc and tweak
  const gaccTweaked = tweakNeg ? Fn.create(n - gacc) : gacc;
  const tacc = tweakNeg ? Fn.neg(tweakScalar) : tweakScalar;

  // BTC adaptor presign: signers produce partials using Q as aggregate key,
  // with gaccTweaked, then tacc*e is added after aggregation.
  const btcNonceA = nonceGen(aliceSecBytes, Qbytes, btcSighash);
  const btcNonceB = nonceGen(bobSecBytes, Qbytes, btcSighash);
  const btcAggNonce = nonceAgg([btcNonceA.pubNonce, btcNonceB.pubNonce]);

  log('PRESIGN', 'Creating BTC adaptor pre-signatures (tweaked key)...');
  const btcAdaptorA = adaptorSign(aliceSecBytes, btcNonceA.secNonce, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 0, gaccTweaked);
  const btcAdaptorB = adaptorSign(bobSecBytes, btcNonceB.secNonce, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccTweaked);

  const btcV1 = adaptorVerify(btcAdaptorA, btcNonceA.pubNonce, alicePub, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 0, gaccTweaked);
  const btcV2 = adaptorVerify(btcAdaptorB, btcNonceB.pubNonce, bobPub, btcAggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccTweaked);
  log('PRESIGN', `BTC adaptor presig Alice valid: ${btcV1}`);
  log('PRESIGN', `BTC adaptor presig Bob   valid: ${btcV2}`);
  if (!btcV1 || !btcV2) throw new Error('BTC adaptor verification failed');

  const btcAdaptorAgg = adaptorAggregate([btcAdaptorA, btcAdaptorB], btcAggNonce, Qbytes, btcSighash, T);

  // Apply taproot tweak contribution: s_tweaked = s_agg + tacc * e (mod n)
  const btcE = computeAdaptorChallenge(btcAggNonce, Qbytes, btcSighash, T);
  const sTweaked = Fn.create(bytesToNum(btcAdaptorAgg.s) + Fn.create(tacc * btcE));
  const btcTweakedAgg = { R: btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: btcAdaptorAgg.negR };

  log('PRESIGN', 'BTC adaptor pre-sig aggregated + tweaked');

  // --- ALPH claim: sign with untweaked P_swap (no taproot tweak needed) ---
  const alphMsg = hexToBytes(deployResult.contractId);
  log('PRESIGN', `ALPH message (contractId): ${deployResult.contractId.slice(0, 16)}...`);

  const alphNonceA = nonceGen(aliceSecBytes, aggPubkey, alphMsg);
  const alphNonceB = nonceGen(bobSecBytes, aggPubkey, alphMsg);
  const alphAggNonce = nonceAgg([alphNonceA.pubNonce, alphNonceB.pubNonce]);

  log('PRESIGN', 'Creating ALPH adaptor pre-signatures...');
  const alphAdaptorA = adaptorSign(aliceSecBytes, alphNonceA.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 0, gacc);
  const alphAdaptorB = adaptorSign(bobSecBytes, alphNonceB.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 1, gacc);

  const alphV1 = adaptorVerify(alphAdaptorA, alphNonceA.pubNonce, alicePub, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 0, gacc);
  const alphV2 = adaptorVerify(alphAdaptorB, alphNonceB.pubNonce, bobPub, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 1, gacc);
  log('PRESIGN', `ALPH adaptor presig Alice valid: ${alphV1}`);
  log('PRESIGN', `ALPH adaptor presig Bob   valid: ${alphV2}`);
  if (!alphV1 || !alphV2) throw new Error('ALPH adaptor verification failed');

  const alphAdaptorAgg = adaptorAggregate([alphAdaptorA, alphAdaptorB], alphAggNonce, aggPubkey, alphMsg, T);
  log('PRESIGN', 'ALPH adaptor pre-sig aggregated');

  // Checkpoint: presigned — adaptor pre-sigs exchanged (critical for recovery)
  saveSwapState({
    ...loadSwapState(),
    phase: 'presigned',
    btcAdaptorAgg: {
      R: bytesToHex(btcAdaptorAgg.R),
      s: bytesToHex(btcAdaptorAgg.s),
      negR: btcAdaptorAgg.negR,
    },
    btcTweakedS: bytesToHex(btcTweakedAgg.s),
    alphAdaptorAgg: {
      R: bytesToHex(alphAdaptorAgg.R),
      s: bytesToHex(alphAdaptorAgg.s),
      negR: alphAdaptorAgg.negR,
    },
    tacc: tacc.toString(),
    btcE: btcE.toString(),
    gaccTweaked: gaccTweaked.toString(),
    Qbytes: bytesToHex(Qbytes),
    btcSighash: bytesToHex(btcSighash),
  });

  // ============================================================
  // Phase 5: Claim
  // ============================================================

  // --- Alice claims BTC (she knows t) ---
  log('CLAIM', 'Alice completes BTC adaptor signature with secret t...');
  const btcFinalSig = completeAdaptorSig(btcTweakedAgg.R, btcTweakedAgg.s, tBytes, btcTweakedAgg.negR);

  const btcFinalValid = schnorr.verify(btcFinalSig, btcSighash, Qbytes);
  log('CLAIM', `BTC completed signature valid: ${btcFinalValid}`);
  if (!btcFinalValid) throw new Error('BTC completed signature invalid!');

  log('CLAIM', 'Alice broadcasts BTC key-path spend...');
  const { psbt } = buildClaimTx(fundTxid, fundVout, BTC_SAT, aliceBtcAddress, internalPubkey, scriptTree);
  const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
  const claimTxid = await broadcastTx(signedTxHex);
  await mineBlocks(1, bobBtcAddress);
  log('CLAIM', `BTC claimed! txid: ${claimTxid}`);

  // Checkpoint: btc_claimed — Alice has BTC, Bob must extract t to claim ALPH
  saveSwapState({
    ...loadSwapState(),
    phase: 'btc_claimed',
    btcClaimTxid: claimTxid,
  });

  // --- Bob extracts t from on-chain BTC signature ---
  log('CLAIM', 'Bob extracts adaptor secret t from on-chain BTC signature...');
  const onChainSig = await extractSignatureFromTx(claimTxid);

  // s_onchain = s_pretweaked + tacc*e + t_eff  =>  t_eff = s_onchain - s_pretweaked - tacc*e
  const sOnChain = bytesToNum(onChainSig.slice(32, 64));
  const sPreTweaked = bytesToNum(btcAdaptorAgg.s); // before tweak
  const tweakContrib = Fn.create(tacc * btcE);
  const tEffective = Fn.create(sOnChain - sPreTweaked - tweakContrib);
  const extractedT = btcTweakedAgg.negR ? Fn.neg(tEffective) : tEffective;

  log('CLAIM', `Extracted t: ${extractedT.toString(16).slice(0, 16)}...`);
  log('CLAIM', `Original  t: ${t.toString(16).slice(0, 16)}...`);
  if (extractedT !== t) throw new Error('SECRET EXTRACTION FAILED');
  log('CLAIM', 'Secret t extracted successfully!');

  // --- Bob claims ALPH using extracted t ---
  log('CLAIM', 'Bob completes ALPH adaptor signature with extracted t...');
  const alphFinalSig = completeAdaptorSig(alphAdaptorAgg.R, alphAdaptorAgg.s, numTo32b(extractedT), alphAdaptorAgg.negR);

  const alphSigValid = schnorr.verify(alphFinalSig, alphMsg, aggPubkey);
  log('CLAIM', `ALPH completed signature valid: ${alphSigValid}`);
  if (!alphSigValid) throw new Error('ALPH completed signature invalid!');

  // Wait for cross-group contract propagation
  await new Promise(r => setTimeout(r, 3000));

  log('CLAIM', 'Bob calls swap() on Alephium contract...');
  const alphClaimResult = await claimSwap(bobAlphWallet, deployResult.contractId, bytesToHex(alphFinalSig), compiled, deployResult.groupIndex);
  await waitForTx(alphClaimResult.txId);
  log('CLAIM', `ALPH claimed! txid: ${alphClaimResult.txId}`);

  // Checkpoint: complete — swap finished, clean up state
  clearSwapState();

  // ============================================================
  // Phase 6: Verify
  // ============================================================
  log('VERIFY', 'Checking final balances...');

  const aliceAlphBalFinal = await getBalance(aliceAlphWallet.address);
  const bobAlphBalFinal = await getBalance(bobAlphWallet.address);
  const claimRawTx = await bitcoinRpc('getrawtransaction', [claimTxid, true]);
  const aliceBtcReceived = claimRawTx.vout.find(o => o.scriptPubKey.address === aliceBtcAddress);

  log('VERIFY', `Alice ALPH: ${Number(aliceAlphBalFinal.balance) / 1e18} ALPH`);
  log('VERIFY', `Bob   ALPH: ${Number(bobAlphBalFinal.balance) / 1e18} ALPH (received swap funds)`);
  log('VERIFY', `Alice BTC:  ${aliceBtcReceived.value} BTC (at nsec-derived P2TR)`);

  console.log('\n=== ATOMIC SWAP COMPLETE ===');
  console.log('Alice traded ALPH for BTC');
  console.log('Bob traded BTC for ALPH');
  console.log('One nsec per party → Nostr + Bitcoin + Alephium');
  console.log('No hash preimages were used');
  console.log('BTC spend was a key-path taproot (looks like normal payment)');
  console.log('ALPH claim verified MuSig2 signature on-chain');
}

// ============================================================
// Refund Path Tests
// ============================================================

async function generateSameGroupKeys() {
  const { groupOfAddress, addressFromPublicKey } = await import('@alephium/web3');
  const getGroup = (pub) => groupOfAddress(addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr'));
  const aliceSec = schnorr.utils.randomSecretKey();
  const alicePub = schnorr.getPublicKey(aliceSec);
  const targetGroup = getGroup(alicePub);
  let bobSec, bobPub;
  do { bobSec = schnorr.utils.randomSecretKey(); bobPub = schnorr.getPublicKey(bobSec); }
  while (getGroup(bobPub) !== targetGroup);
  return { aliceSec, alicePub, bobSec, bobPub };
}

async function testAlphRefund() {
  console.log('\n=== ALPH Refund Path Test ===\n');

  const { aliceSec, alicePub, bobSec, bobPub } = await generateSameGroupKeys();

  web3.setCurrentNodeProvider('http://127.0.0.1:22973');
  const aliceW = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSec), keyType: 'bip340-schnorr' });
  const bobW = new PrivateKeyWallet({ privateKey: bytesToHex(bobSec), keyType: 'bip340-schnorr' });
  log('REFUND-ALPH', `Alice: ${aliceW.address} (group ${aliceW.group})`);

  // Fund Alice
  await waitForTx((await fundFromGenesis(aliceW.address, ONE_ALPH * 100n)).txId);
  const balBefore = await getBalance(aliceW.address);
  log('REFUND-ALPH', `Alice balance before: ${Number(balBefore.balance) / 1e18} ALPH`);

  // Deploy contract with timeout already expired
  const compiled = await compileSwapContract();
  const { aggPubkey } = keyAgg([alicePub, bobPub]);
  const ALPH_AMOUNT = ONE_ALPH * 10n;

  const deploy = await deploySwapContract(
    aliceW, bytesToHex(aggPubkey), bobW.address, aliceW.address,
    Date.now() - 60000, // expired 1 minute ago
    ALPH_AMOUNT, compiled, bobW.group,
  );
  await waitForTx(deploy.txId);
  log('REFUND-ALPH', `Contract deployed with expired timeout: ${deploy.contractAddress}`);

  const balAfterDeploy = await getBalance(aliceW.address);
  log('REFUND-ALPH', `Alice after deploy: ${Number(balAfterDeploy.balance) / 1e18} ALPH`);

  // Alice calls refund
  log('REFUND-ALPH', 'Alice calls refund()...');
  const refund = await refundSwap(aliceW, deploy.contractId, compiled);
  await waitForTx(refund.txId);

  const balAfterRefund = await getBalance(aliceW.address);
  log('REFUND-ALPH', `Alice after refund: ${Number(balAfterRefund.balance) / 1e18} ALPH`);

  const recovered = Number(balAfterRefund.balance - balAfterDeploy.balance) / 1e18;
  log('REFUND-ALPH', `Recovered: ~${recovered.toFixed(2)} ALPH (10 minus gas)`);
  if (recovered < 9) throw new Error('ALPH refund did not recover expected funds');

  console.log('\n=== ALPH REFUND PATH: SUCCESS ===');
}

async function testBtcRefund() {
  console.log('\n=== BTC Refund Path Test ===\n');

  const { aliceSec, alicePub, bobSec, bobPub } = await generateSameGroupKeys();

  const bobBtcAddr = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;
  log('REFUND-BTC', `Bob BTC: ${bobBtcAddr}`);

  // MuSig2 key aggregation
  const { aggPubkey } = keyAgg([alicePub, bobPub]);

  // Create taproot swap output
  const CSV_TIMEOUT = 10; // short timeout for test (10 blocks)
  const BTC_AMOUNT = 0.5;
  const BTC_SAT = Math.round(BTC_AMOUNT * 1e8);

  const { address: swapAddr, internalPubkey, scriptTree } = createSwapOutput(aggPubkey, bobPub, CSV_TIMEOUT);
  log('REFUND-BTC', `Swap address: ${swapAddr}`);

  // Mine to Bob's P2TR and fund the swap
  log('REFUND-BTC', 'Mining 101 blocks to Bob...');
  const blockHashes = await bitcoinRpc('generatetoaddress', [101, bobBtcAddr]);
  const block = await bitcoinRpc('getblock', [blockHashes[0], 2]);
  const coinbaseTx = block.tx[0];
  const coinbaseVout = coinbaseTx.vout.findIndex(o => o.scriptPubKey.address === bobBtcAddr);
  const coinbaseAmountSat = Math.round(coinbaseTx.vout[coinbaseVout].value * 1e8);

  log('REFUND-BTC', 'Bob funds swap from his P2TR...');
  const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(
    coinbaseTx.txid, coinbaseVout, coinbaseAmountSat,
    swapAddr, BTC_SAT, bobPub,
  );
  const bobTweakedKey = computeTweakedPrivateKey(bobSec, bobPub);
  const fundSig = schnorr.sign(fundSighash, bobTweakedKey);
  const fundTxHex = finalizeKeyPathSpend(fundPsbt, fundSig);
  const fundTxid = await broadcastTx(fundTxHex);
  await mineBlocks(1, bobBtcAddr);

  const fundRawTx = await bitcoinRpc('getrawtransaction', [fundTxid, true]);
  const fundVout = fundRawTx.vout.findIndex(o => o.scriptPubKey.address === swapAddr);
  log('REFUND-BTC', `Swap funded: txid=${fundTxid.slice(0, 16)}... vout=${fundVout}`);

  // Mine past CSV timeout
  log('REFUND-BTC', `Mining ${CSV_TIMEOUT} blocks for CSV timeout...`);
  await mineBlocks(CSV_TIMEOUT, bobBtcAddr);

  // Build refund tx (script-path spend)
  log('REFUND-BTC', 'Bob builds refund tx (script-path spend)...');
  const { psbt: refundPsbt } = buildRefundTx(fundTxid, fundVout, BTC_SAT, bobBtcAddr, internalPubkey, scriptTree, CSV_TIMEOUT);

  // Sign with Bob's nsec (for OP_CHECKSIG in the refund script)
  // publicKey must be 33-byte compressed; signInput strips to x-only for matching
  refundPsbt.signInput(0, {
    publicKey: Buffer.concat([Buffer.from([0x02]), Buffer.from(bobPub)]),
    signSchnorr: (hash) => Buffer.from(schnorr.sign(hash, bobSec)),
  });
  refundPsbt.finalizeAllInputs();
  const refundTxHex = refundPsbt.extractTransaction().toHex();
  const refundTxid = await broadcastTx(refundTxHex);
  await mineBlocks(1, bobBtcAddr);

  log('REFUND-BTC', `BTC refunded! txid: ${refundTxid}`);

  // Verify Bob got BTC back
  const refundRawTx = await bitcoinRpc('getrawtransaction', [refundTxid, true]);
  const bobOutput = refundRawTx.vout.find(o => o.scriptPubKey.address === bobBtcAddr);
  log('REFUND-BTC', `Bob received: ${bobOutput.value} BTC`);
  if (bobOutput.value < BTC_AMOUNT - 0.001) throw new Error('BTC refund amount too low');

  console.log('\n=== BTC REFUND PATH: SUCCESS ===');
}

// Run all tests: happy path, then both refund paths
(async () => {
  const existingState = loadSwapState();
  if (existingState) {
    log('STARTUP', `Found interrupted swap (phase: ${existingState.phase}). Attempting recovery...`);
    await recoverSwap();
    return;
  }
  await main();
  await testAlphRefund();
  await testBtcRefund();
})().catch(e => {
  console.error('\nFATAL:', e.message);
  console.error(e.stack);
  process.exit(1);
});
