#!/usr/bin/env node
// Web server for BTC-ALPH Atomic Swap
// HTTP REST API + static files. Nostr messaging handled by public relays (browser-side).
// Supports devnet (local regtest + devnet) and testnet (signet + alph testnet) via SWAP_NETWORK env.

import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
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
  setBtcNetwork, getBtcNetwork, getP2TRAddress, getUtxos, selectUtxo,
  getBtcBalance, estimateFee, findVout, waitForConfirmation,
} from './btc-swap.js';
import {
  compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState,
  fundFromGenesis, getBalance, waitForTx,
  web3, ONE_ALPH, PrivateKeyWallet, addressFromPublicKey, groupOfAddress,
  setAlphNetwork,
} from './alph-swap.js';
import { computeTweakedKey, computeAdaptorChallenge, computeTweakedPrivateKey } from './taproot-utils.js';

// ============================================================
// Network Mode Detection
// ============================================================

const NETWORK_MODE = process.env.SWAP_NETWORK || 'devnet';
const isTestnet = NETWORK_MODE === 'testnet';

if (isTestnet) {
  setBtcNetwork('signet');
  setAlphNetwork('testnet');
} else {
  web3.setCurrentNodeProvider('http://127.0.0.1:22973');
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 7778;

// ============================================================
// Session Management
// ============================================================

const sessions = new Map(); // token -> SessionState

function createToken() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

function getSession(token) {
  const s = sessions.get(token);
  if (!s) throw new Error('Invalid session token');
  return s;
}

// ============================================================
// Shared context computation (same as nostr-swap.js)
// ============================================================

function computeSharedContext({ alicePub, bobPub, btcLockTxid, btcLockVout, btcSat, contractId, csvTimeout }) {
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCoeffs, gacc } = keyAgg(pubkeys);

  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } =
    createSwapOutput(aggPubkey, bobPub, csvTimeout);

  const aliceBtcAddress = getP2TRAddress(alicePub);

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
// HTTP Request Helpers
// ============================================================

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function json(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data));
}

function err(res, msg, status = 400) {
  json(res, { error: msg }, status);
}

// ============================================================
// findVout with retry (for testnet where tx may take a moment to appear)
// ============================================================

async function findVoutWithRetry(txid, address, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const vout = await findVout(txid, address);
      if (vout >= 0) return vout;
    } catch (_) {}
    if (i < maxRetries - 1) await new Promise(r => setTimeout(r, 2000));
  }
  // Fallback: destination is always first output
  return 0;
}

// ============================================================
// REST API Route Handler
// ============================================================

async function handleApi(req, res, urlPath) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }

  try {
    const body = req.method === 'POST' ? await readBody(req) : {};

    // ── Network info ──
    if (urlPath === '/api/network' && req.method === 'GET') {
      return json(res, { network: NETWORK_MODE, isTestnet });
    }

    // ── Identity ──
    if (urlPath === '/api/session' && req.method === 'POST') {
      const { nsec } = body;
      let secBytes;
      if (nsec.startsWith('nsec')) {
        const decoded = nip19.decode(nsec);
        secBytes = decoded.data;
      } else {
        secBytes = hexToBytes(nsec);
      }
      const pubKey = schnorr.getPublicKey(secBytes);
      const pubKeyHex = bytesToHex(pubKey);
      const npub = nip19.npubEncode(pubKeyHex);
      const btcAddress = getP2TRAddress(pubKey);
      const alphAddress = addressFromPublicKey(pubKeyHex, 'bip340-schnorr');
      const group = groupOfAddress(alphAddress);

      const token = createToken();
      sessions.set(token, {
        secBytes, pubKey, pubKeyHex, npub, btcAddress, alphAddress, group,
        role: null, peerPubHex: null,
        // Swap params
        btcAmount: 0.5, btcSat: 50000000, alphAmount: ONE_ALPH * 10n,
        csvTimeout: 144, alphTimeoutMs: Date.now() + 6 * 60 * 60 * 1000,
        // Swap state
        adaptorSecret: null, adaptorPoint: null, // Alice's t, T
        peerAdaptorPoint: null,
        btcLockTxid: null, btcLockVout: null,
        contractId: null, contractAddress: null,
        compiled: null, deployResult: null,
        ctx: null, // shared context
        btcNonce: null, alphNonce: null,
        peerBtcNonceHash: null, peerAlphNonceHash: null,
        peerBtcPubNonce: null, peerAlphPubNonce: null,
        btcAggNonce: null, alphAggNonce: null,
        myBtcPresig: null, myAlphPresig: null,
        peerBtcPresig: null, peerAlphPresig: null,
        btcAdaptorAgg: null, alphAdaptorAgg: null, btcTweakedAgg: null,
        // BTC funding (Bob)
        coinbaseTxid: null, coinbaseVout: null, coinbaseAmountSat: null,
      });

      return json(res, { token, pubKeyHex, npub, btcAddress, alphAddress, group, network: NETWORK_MODE });
    }

    // ── Devnet: Fund ──
    if (urlPath === '/api/fund' && req.method === 'POST') {
      if (isTestnet) return err(res, 'Funding not available on testnet. Use faucets: https://signetfaucet.com/ (BTC) and https://faucet.testnet.alephium.org/ (ALPH)');
      const s = getSession(body.token);

      // Fund ALPH from genesis
      const alphFundAmount = s.role === 'alice' ? ONE_ALPH * 100n : ONE_ALPH * 5n;
      const alphTx = await fundFromGenesis(s.alphAddress, alphFundAmount);
      await waitForTx(alphTx.txId);

      // Mine BTC blocks to user's address (creates coinbase UTXOs)
      const blockHashes = await bitcoinRpc('generatetoaddress', [101, s.btcAddress]);
      const block = await bitcoinRpc('getblock', [blockHashes[0], 2]);
      const coinbaseTx = block.tx[0];
      const coinbaseVout = coinbaseTx.vout.findIndex(o => o.scriptPubKey.address === s.btcAddress);
      const coinbaseAmountSat = Math.round(coinbaseTx.vout[coinbaseVout].value * 1e8);
      s.coinbaseTxid = coinbaseTx.txid;
      s.coinbaseVout = coinbaseVout;
      s.coinbaseAmountSat = coinbaseAmountSat;

      return json(res, {
        alphTxId: alphTx.txId,
        alphAmount: alphFundAmount.toString(),
        coinbaseTxid: coinbaseTx.txid,
        coinbaseVout,
        coinbaseAmountSat,
      });
    }

    // ── Devnet: Mine ──
    if (urlPath === '/api/mine' && req.method === 'POST') {
      if (isTestnet) return err(res, 'Mining not available on testnet. Wait for signet block confirmation (~5 min).');
      const s = getSession(body.token);
      const blocks = body.blocks || 1;
      const hashes = await mineBlocks(blocks, s.btcAddress);
      return json(res, { blocks: hashes.length });
    }

    // ── Balance ──
    if (urlPath.startsWith('/api/balance/') && req.method === 'GET') {
      const token = urlPath.split('/api/balance/')[1];
      const s = getSession(token);
      const alphBal = await getBalance(s.alphAddress);
      let btcSat = 0;
      try {
        btcSat = await getBtcBalance(s.btcAddress);
      } catch { /* balance query may fail */ }
      return json(res, {
        alph: (Number(alphBal.balance) / 1e18).toFixed(4),
        btc: (btcSat / 1e8).toFixed(8),
      });
    }

    // ── UTXOs ──
    if (urlPath.startsWith('/api/utxos/') && req.method === 'GET') {
      const token = urlPath.split('/api/utxos/')[1];
      const s = getSession(token);
      const utxos = await getUtxos(s.btcAddress);
      return json(res, utxos);
    }

    // ── Swap: Init ──
    if (urlPath === '/api/swap/init' && req.method === 'POST') {
      const s = getSession(body.token);
      s.role = body.role; // 'alice' or 'bob'
      s.peerPubHex = body.peerPubHex;
      if (body.btcAmount !== undefined) { s.btcAmount = body.btcAmount; s.btcSat = Math.round(body.btcAmount * 1e8); }
      if (body.alphAmount !== undefined) s.alphAmount = BigInt(body.alphAmount);
      if (body.csvTimeout !== undefined) s.csvTimeout = body.csvTimeout;
      if (body.sessionId !== undefined) s.sessionId = body.sessionId;

      const result = { role: s.role };

      if (s.role === 'alice') {
        // Generate adaptor secret t, normalize T to even Y
        let tBytes = schnorr.utils.randomSecretKey();
        let t = bytesToNum(tBytes);
        let T = G.multiply(t);
        if (!hasEvenY(T)) {
          T = T.negate();
          t = Fn.neg(t);
          tBytes = numTo32b(t);
        }
        s.adaptorSecret = tBytes;
        s.adaptorPoint = T;
        result.adaptorPoint = bytesToHex(pointToBytes(T));
      } else {
        // Bob stores peer's adaptor point
        if (body.adaptorPoint) {
          s.peerAdaptorPoint = lift_x(bytesToNum(hexToBytes(body.adaptorPoint)));
        }
      }

      return json(res, result);
    }

    // ── Swap: Lock BTC (Bob) ──
    if (urlPath === '/api/swap/lock-btc' && req.method === 'POST') {
      const s = getSession(body.token);
      const peerPub = hexToBytes(s.peerPubHex);
      const pubkeys = [peerPub, s.pubKey]; // [alice, bob]
      const { aggPubkey } = keyAgg(pubkeys);

      const { address: swapBtcAddress } = createSwapOutput(aggPubkey, s.pubKey, s.csvTimeout);

      // Determine UTXO to spend
      let utxoTxid, utxoVout, utxoValue;
      if (body.utxoTxid !== undefined) {
        // Frontend provided a specific UTXO (testnet mode)
        utxoTxid = body.utxoTxid;
        utxoVout = body.utxoVout;
        utxoValue = body.utxoValue;
      } else if (isTestnet) {
        // Auto-select UTXO on testnet
        const fee = await estimateFee(200);
        const utxo = await selectUtxo(s.btcAddress, s.btcSat + fee);
        utxoTxid = utxo.txid;
        utxoVout = utxo.vout;
        utxoValue = utxo.value;
      } else {
        // Devnet: use pre-funded coinbase
        utxoTxid = s.coinbaseTxid;
        utxoVout = s.coinbaseVout;
        utxoValue = s.coinbaseAmountSat;
      }

      const fee = await estimateFee(200);
      const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(
        utxoTxid, utxoVout, utxoValue,
        swapBtcAddress, s.btcSat, s.pubKey, fee,
      );
      const bobTweakedKey = computeTweakedPrivateKey(s.secBytes, s.pubKey);
      const fundSig = schnorr.sign(fundSighash, bobTweakedKey);
      const fundTxHex = finalizeKeyPathSpend(fundPsbt, fundSig);
      const fundTxid = await broadcastTx(fundTxHex);

      if (!isTestnet) {
        await mineBlocks(1, s.btcAddress);
      }

      // Find the vout for the swap address
      const fundVout = await findVoutWithRetry(fundTxid, swapBtcAddress);

      s.btcLockTxid = fundTxid;
      s.btcLockVout = fundVout;

      return json(res, { txid: fundTxid, vout: fundVout, amountSat: s.btcSat });
    }

    // ── Swap: Verify BTC (Alice) ──
    if (urlPath === '/api/swap/verify-btc' && req.method === 'POST') {
      const s = getSession(body.token);
      s.btcLockTxid = body.txid;
      s.btcLockVout = body.vout;

      const peerPub = hexToBytes(s.peerPubHex);
      const pubkeys = [s.pubKey, peerPub]; // [alice, bob]
      const { aggPubkey } = keyAgg(pubkeys);
      const { address: swapBtcAddress } = createSwapOutput(aggPubkey, peerPub, s.csvTimeout);
      await verifySwapOutput(body.txid, swapBtcAddress, s.btcAmount, { allowUnconfirmed: isTestnet });

      return json(res, { valid: true });
    }

    // ── Swap: Deploy ALPH (Alice) ──
    if (urlPath === '/api/swap/deploy-alph' && req.method === 'POST') {
      const s = getSession(body.token);
      const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(s.secBytes), keyType: 'bip340-schnorr' });
      const compiled = await compileSwapContract();
      s.compiled = compiled;

      const peerPub = hexToBytes(s.peerPubHex);
      const pubkeys = [s.pubKey, peerPub];
      const { aggPubkey } = keyAgg(pubkeys);

      const bobAlphAddress = addressFromPublicKey(s.peerPubHex, 'bip340-schnorr');
      const bobGroup = groupOfAddress(bobAlphAddress);

      const deployResult = await deploySwapContract(
        wallet, bytesToHex(aggPubkey), bobAlphAddress, wallet.address,
        s.alphTimeoutMs, s.alphAmount, compiled, bobGroup,
      );
      await waitForTx(deployResult.txId);

      s.contractId = deployResult.contractId;
      s.contractAddress = deployResult.contractAddress;
      s.deployResult = deployResult;

      return json(res, {
        contractId: deployResult.contractId,
        contractAddress: deployResult.contractAddress,
        txId: deployResult.txId,
      });
    }

    // ── Swap: Verify ALPH (Bob) ──
    if (urlPath === '/api/swap/verify-alph' && req.method === 'POST') {
      const s = getSession(body.token);
      s.contractId = body.contractId;
      s.contractAddress = body.contractAddress;

      const compiled = await compileSwapContract();
      s.compiled = compiled;

      const peerPub = hexToBytes(s.peerPubHex);
      const pubkeys = [peerPub, s.pubKey];
      const { aggPubkey } = keyAgg(pubkeys);

      const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(s.secBytes), keyType: 'bip340-schnorr' });
      const aliceAlphAddress = addressFromPublicKey(s.peerPubHex, 'bip340-schnorr');

      await verifyContractState(
        body.contractAddress, bytesToHex(aggPubkey),
        wallet.address, aliceAlphAddress,
        s.alphAmount, undefined, compiled,
      );

      return json(res, { valid: true });
    }

    // ── Swap: Compute context ──
    if (urlPath === '/api/swap/compute-context' && req.method === 'POST') {
      const s = getSession(body.token);
      const peerPub = hexToBytes(s.peerPubHex);

      // pubkeys always ordered [alice, bob]
      const alicePub = s.role === 'alice' ? s.pubKey : peerPub;
      const bobPub = s.role === 'bob' ? s.pubKey : peerPub;

      s.ctx = computeSharedContext({
        alicePub, bobPub,
        btcLockTxid: s.btcLockTxid, btcLockVout: s.btcLockVout,
        btcSat: s.btcSat, contractId: s.contractId, csvTimeout: s.csvTimeout,
      });

      return json(res, { swapBtcAddress: s.ctx.swapBtcAddress });
    }

    // ── Swap: Nonce commit ──
    if (urlPath === '/api/swap/nonce-commit' && req.method === 'POST') {
      const s = getSession(body.token);
      s.btcNonce = nonceGen(s.secBytes, s.ctx.Qbytes, s.ctx.btcSighash);
      s.alphNonce = nonceGen(s.secBytes, s.ctx.aggPubkey, s.ctx.alphMsg);

      const btcNonceHash = bytesToHex(sha256(s.btcNonce.pubNonce));
      const alphNonceHash = bytesToHex(sha256(s.alphNonce.pubNonce));

      return json(res, { btcNonceHash, alphNonceHash });
    }

    // ── Swap: Nonce reveal ──
    if (urlPath === '/api/swap/nonce-reveal' && req.method === 'POST') {
      const s = getSession(body.token);
      // Store peer's commitment hashes
      if (body.peerBtcNonceHash) s.peerBtcNonceHash = body.peerBtcNonceHash;
      if (body.peerAlphNonceHash) s.peerAlphNonceHash = body.peerAlphNonceHash;

      return json(res, {
        btcPubNonce: bytesToHex(s.btcNonce.pubNonce),
        alphPubNonce: bytesToHex(s.alphNonce.pubNonce),
      });
    }

    // ── Swap: Nonce verify ──
    if (urlPath === '/api/swap/nonce-verify' && req.method === 'POST') {
      const s = getSession(body.token);
      const peerBtcNonce = hexToBytes(body.peerBtcPubNonce);
      const peerAlphNonce = hexToBytes(body.peerAlphPubNonce);

      // Verify commits match reveals
      if (bytesToHex(sha256(peerBtcNonce)) !== s.peerBtcNonceHash)
        throw new Error('Peer BTC nonce commitment mismatch');
      if (bytesToHex(sha256(peerAlphNonce)) !== s.peerAlphNonceHash)
        throw new Error('Peer ALPH nonce commitment mismatch');

      s.peerBtcPubNonce = peerBtcNonce;
      s.peerAlphPubNonce = peerAlphNonce;

      // Aggregate nonces — order: [alice, bob]
      if (s.role === 'alice') {
        s.btcAggNonce = nonceAgg([s.btcNonce.pubNonce, peerBtcNonce]);
        s.alphAggNonce = nonceAgg([s.alphNonce.pubNonce, peerAlphNonce]);
      } else {
        s.btcAggNonce = nonceAgg([peerBtcNonce, s.btcNonce.pubNonce]);
        s.alphAggNonce = nonceAgg([peerAlphNonce, s.alphNonce.pubNonce]);
      }

      return json(res, { valid: true });
    }

    // ── Swap: Presign ──
    if (urlPath === '/api/swap/presign' && req.method === 'POST') {
      const s = getSession(body.token);
      const signerIndex = s.role === 'alice' ? 0 : 1;
      const T = s.role === 'alice' ? s.adaptorPoint : s.peerAdaptorPoint;

      const btcPresig = adaptorSign(s.secBytes, s.btcNonce.secNonce, s.btcAggNonce,
        s.ctx.keyCoeffs, s.ctx.Qbytes, s.ctx.btcSighash, T, signerIndex, s.ctx.gaccTweaked);
      const alphPresig = adaptorSign(s.secBytes, s.alphNonce.secNonce, s.alphAggNonce,
        s.ctx.keyCoeffs, s.ctx.aggPubkey, s.ctx.alphMsg, T, signerIndex, s.ctx.gacc);

      s.myBtcPresig = btcPresig;
      s.myAlphPresig = alphPresig;

      return json(res, {
        btcPresig: bytesToHex(btcPresig),
        alphPresig: bytesToHex(alphPresig),
      });
    }

    // ── Swap: Verify presig ──
    if (urlPath === '/api/swap/verify-presig' && req.method === 'POST') {
      const s = getSession(body.token);
      const peerPub = hexToBytes(s.peerPubHex);
      const peerIndex = s.role === 'alice' ? 1 : 0;
      const T = s.role === 'alice' ? s.adaptorPoint : s.peerAdaptorPoint;

      const peerBtcPresig = hexToBytes(body.peerBtcPresig);
      const peerAlphPresig = hexToBytes(body.peerAlphPresig);
      s.peerBtcPresig = peerBtcPresig;
      s.peerAlphPresig = peerAlphPresig;

      const peerBtcNonce = s.peerBtcPubNonce;
      const peerAlphNonce = s.peerAlphPubNonce;

      if (!adaptorVerify(peerBtcPresig, peerBtcNonce, peerPub, s.btcAggNonce,
        s.ctx.keyCoeffs, s.ctx.Qbytes, s.ctx.btcSighash, T, peerIndex, s.ctx.gaccTweaked))
        throw new Error('Peer BTC adaptor verification failed');
      if (!adaptorVerify(peerAlphPresig, peerAlphNonce, peerPub, s.alphAggNonce,
        s.ctx.keyCoeffs, s.ctx.aggPubkey, s.ctx.alphMsg, T, peerIndex, s.ctx.gacc))
        throw new Error('Peer ALPH adaptor verification failed');

      // Aggregate — order: [alice, bob]
      const presigs = s.role === 'alice'
        ? [s.myBtcPresig, peerBtcPresig]
        : [peerBtcPresig, s.myBtcPresig];
      const alphPresigs = s.role === 'alice'
        ? [s.myAlphPresig, peerAlphPresig]
        : [peerAlphPresig, s.myAlphPresig];

      s.btcAdaptorAgg = adaptorAggregate(presigs, s.btcAggNonce, s.ctx.Qbytes, s.ctx.btcSighash, T);
      s.alphAdaptorAgg = adaptorAggregate(alphPresigs, s.alphAggNonce, s.ctx.aggPubkey, s.ctx.alphMsg, T);

      // Taproot tweak
      const btcE = computeAdaptorChallenge(s.btcAggNonce, s.ctx.Qbytes, s.ctx.btcSighash, T);
      const sTweaked = Fn.create(bytesToNum(s.btcAdaptorAgg.s) + Fn.create(s.ctx.tacc * btcE));
      s.btcTweakedAgg = { R: s.btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: s.btcAdaptorAgg.negR };

      return json(res, { valid: true });
    }

    // ── Swap: Claim BTC (Alice) ──
    if (urlPath === '/api/swap/claim-btc' && req.method === 'POST') {
      const s = getSession(body.token);
      const btcFinalSig = completeAdaptorSig(
        s.btcTweakedAgg.R, s.btcTweakedAgg.s, s.adaptorSecret, s.btcTweakedAgg.negR,
      );

      if (!schnorr.verify(btcFinalSig, s.ctx.btcSighash, s.ctx.Qbytes))
        throw new Error('BTC completed signature invalid');

      const { psbt } = buildClaimTx(
        s.btcLockTxid, s.btcLockVout, s.btcSat,
        s.ctx.aliceBtcAddress, s.ctx.internalPubkey, s.ctx.scriptTree,
      );
      const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
      const claimTxid = await broadcastTx(signedTxHex);

      if (!isTestnet) {
        await mineBlocks(1, s.btcAddress);
      }

      return json(res, { txid: claimTxid });
    }

    // ── Swap: Claim ALPH (Bob) ──
    if (urlPath === '/api/swap/claim-alph' && req.method === 'POST') {
      const s = getSession(body.token);

      // Extract t from on-chain BTC claim tx
      const onChainSig = await extractSignatureFromTx(body.btcClaimTxid);
      const extractedTBytes = adaptorExtract(
        onChainSig.slice(32, 64), s.btcTweakedAgg.s, s.btcTweakedAgg.negR,
      );

      const alphFinalSig = completeAdaptorSig(
        s.alphAdaptorAgg.R, s.alphAdaptorAgg.s, extractedTBytes, s.alphAdaptorAgg.negR,
      );

      if (!schnorr.verify(alphFinalSig, s.ctx.alphMsg, s.ctx.aggPubkey))
        throw new Error('ALPH completed signature invalid');

      const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(s.secBytes), keyType: 'bip340-schnorr' });
      // Small delay for chain state to settle
      await new Promise(r => setTimeout(r, 2000));
      const alphClaimResult = await claimSwap(wallet, s.contractId, bytesToHex(alphFinalSig), s.compiled, wallet.group);
      await waitForTx(alphClaimResult.txId);

      return json(res, { txid: alphClaimResult.txId });
    }

    // ── Swap: Refund ALPH (Alice) ──
    if (urlPath === '/api/swap/refund-alph' && req.method === 'POST') {
      const s = getSession(body.token);
      const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(s.secBytes), keyType: 'bip340-schnorr' });
      const result = await refundSwap(wallet, s.contractId, s.compiled);
      await waitForTx(result.txId);
      return json(res, { txid: result.txId });
    }

    // ── Swap: Refund BTC (Bob) ──
    if (urlPath === '/api/swap/refund-btc' && req.method === 'POST') {
      const s = getSession(body.token);
      const peerPub = hexToBytes(s.peerPubHex);
      const pubkeys = [peerPub, s.pubKey]; // [alice, bob]
      const { aggPubkey } = keyAgg(pubkeys);
      const { internalPubkey, scriptTree } = createSwapOutput(aggPubkey, s.pubKey, s.csvTimeout);

      const { psbt: refundPsbt } = buildRefundTx(
        s.btcLockTxid, s.btcLockVout, s.btcSat,
        s.btcAddress, internalPubkey, scriptTree, s.csvTimeout,
      );

      refundPsbt.signInput(0, {
        publicKey: Buffer.concat([Buffer.from([0x02]), Buffer.from(s.pubKey)]),
        signSchnorr: (hash) => Buffer.from(schnorr.sign(hash, s.secBytes)),
      });
      refundPsbt.finalizeAllInputs();
      const refundTxHex = refundPsbt.extractTransaction().toHex();
      const refundTxid = await broadcastTx(refundTxHex);

      if (!isTestnet) {
        await mineBlocks(1, s.btcAddress);
      }

      return json(res, { txid: refundTxid });
    }

    // ── 404 ──
    err(res, 'Not found', 404);

  } catch (e) {
    console.error(`API error ${urlPath}:`, e.message);
    err(res, e.message, 500);
  }
}

// ============================================================
// HTTP Server
// ============================================================

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const urlPath = url.pathname;

  // API routes
  if (urlPath.startsWith('/api/')) {
    return handleApi(req, res, urlPath);
  }

  // Serve index.html for everything else
  const indexPath = path.join(__dirname, '..', 'index.html');
  try {
    const html = fs.readFileSync(indexPath, 'utf-8');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  } catch {
    res.writeHead(500);
    res.end('index.html not found');
  }
});

// ============================================================
// Start
// ============================================================

server.listen(PORT, () => {
  console.log(`BTC-ALPH Swap UI: http://localhost:${PORT}`);
  console.log(`Network mode:     ${NETWORK_MODE}${isTestnet ? ' (BTC signet + ALPH testnet)' : ' (BTC regtest + ALPH devnet)'}`);
});
