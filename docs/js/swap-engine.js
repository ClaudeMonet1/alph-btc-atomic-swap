// SwapEngine — client-side swap logic extracted from server.js
// All session state and swap protocol steps, no HTTP wrapper.

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import {
  keyAgg, nonceGen, nonceAgg,
  lift_x, hasEvenY, bytesToNum, numTo32b,
} from './musig2.js';
import {
  adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract,
  G, Fn, n, pointToBytes,
} from './adaptor.js';
import {
  createSwapOutput, verifySwapOutput,
  buildClaimTx, buildP2TRKeyPathSpend, finalizeKeyPathSpend, broadcastTx,
  extractSignatureFromTx, buildRefundTx, bitcoin, NETWORK,
  getP2TRAddress, getUtxos, selectUtxo,
  getBtcBalance, estimateFee, findVout, waitForConfirmation,
  sweepBtc as sweepBtcTx,
} from './btc.js';
import {
  compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState,
  getBalance, waitForTx, transferAlph,
  web3, ONE_ALPH, addressFromPublicKey, groupOfAddress,
} from './alph.js';
import { computeTweakedKey, computeAdaptorChallenge, computeTweakedPrivateKey } from './taproot-utils.js';

// ============================================================
// Shared context computation
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
// findVout with retry
// ============================================================

async function findVoutWithRetry(txid, address, maxRetries = 15) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const vout = await findVout(txid, address);
      if (vout >= 0) return vout;
    } catch (_) {}
    await new Promise(r => setTimeout(r, 3000));
  }
  throw new Error(`Tx ${txid} not found on Esplora after ${maxRetries * 3}s`);
}

// ============================================================
// SwapEngine
// ============================================================

export class SwapEngine {
  constructor(secBytes, pubKey) {
    this.secBytes = secBytes;
    this.pubKey = pubKey;
    this.pubKeyHex = bytesToHex(pubKey);
    this.btcAddress = getP2TRAddress(pubKey);
    this.alphAddress = addressFromPublicKey(this.pubKeyHex, 'bip340-schnorr');
    this.group = groupOfAddress(this.alphAddress);

    // Swap state
    this.role = null;
    this.peerPubHex = null;
    this.btcAmount = 0.00005;
    this.btcSat = 5000;
    this.alphAmount = ONE_ALPH;
    this.csvTimeout = 144;
    this.alphTimeoutMs = Date.now() + 6 * 60 * 60 * 1000;

    this.adaptorSecret = null;
    this.adaptorPoint = null;
    this.peerAdaptorPoint = null;
    this.btcLockTxid = null;
    this.btcLockVout = null;
    this.contractId = null;
    this.contractAddress = null;
    this.compiled = null;
    this.deployResult = null;
    this.ctx = null;

    this.btcClaimTxid = null;

    this.btcNonce = null;
    this.alphNonce = null;
    this.peerBtcNonceHash = null;
    this.peerAlphNonceHash = null;
    this.peerBtcPubNonce = null;
    this.peerAlphPubNonce = null;
    this.btcAggNonce = null;
    this.alphAggNonce = null;
    this.myBtcPresig = null;
    this.myAlphPresig = null;
    this.peerBtcPresig = null;
    this.peerAlphPresig = null;
    this.btcAdaptorAgg = null;
    this.alphAdaptorAgg = null;
    this.btcTweakedAgg = null;
  }

  // ── Identity ──

  get addresses() {
    return {
      pubKeyHex: this.pubKeyHex,
      btcAddress: this.btcAddress,
      alphAddress: this.alphAddress,
      group: this.group,
    };
  }

  // ── Balance / UTXOs ──

  async getBalances() {
    const alphBal = await getBalance(this.alphAddress);
    let btcConfirmedSat = 0, btcUnconfirmedSat = 0;
    try {
      const utxos = await getUtxos(this.btcAddress);
      for (const u of utxos) {
        if (u.status?.confirmed === false) btcUnconfirmedSat += u.value;
        else btcConfirmedSat += u.value;
      }
    } catch { /* balance query may fail */ }
    const btcTotalSat = btcConfirmedSat + btcUnconfirmedSat;
    return {
      alph: (Number(alphBal.balance) / 1e18).toFixed(4),
      btc: (btcTotalSat / 1e8).toFixed(8),
      btcConfirmedSat,
      btcUnconfirmedSat,
    };
  }

  async getUtxoList() {
    return getUtxos(this.btcAddress);
  }

  // ── Faucet ──

  async requestAlphFaucet() {
    const faucetRes = await fetch('https://faucet.testnet.alephium.org/send', {
      method: 'POST',
      body: this.alphAddress,
    });
    if (!faucetRes.ok) {
      const text = await faucetRes.text();
      throw new Error(`ALPH faucet error: ${faucetRes.status} ${text}`);
    }
    const message = await faucetRes.text();
    return { message: message.trim(), address: this.alphAddress };
  }

  // ── Swap: Init ──

  initSwap(role, peerPubHex, btcAmount, alphAmount, sessionId) {
    this.role = role;
    this.peerPubHex = peerPubHex;
    if (btcAmount !== undefined) { this.btcAmount = btcAmount; this.btcSat = Math.round(btcAmount * 1e8); }
    if (alphAmount !== undefined) this.alphAmount = BigInt(alphAmount);
    if (sessionId !== undefined) this.sessionId = sessionId;

    const result = { role: this.role };

    if (this.role === 'alice') {
      let tBytes = new Uint8Array(32);
      crypto.getRandomValues(tBytes);
      let t = bytesToNum(tBytes);
      let T = G.multiply(t);
      if (!hasEvenY(T)) {
        T = T.negate();
        t = Fn.neg(t);
        tBytes = numTo32b(t);
      }
      this.adaptorSecret = tBytes;
      this.adaptorPoint = T;
      result.adaptorPoint = bytesToHex(pointToBytes(T));
    }

    return result;
  }

  // Called by Bob after receiving Alice's adaptor point
  setAdaptorPoint(adaptorPointHex) {
    this.peerAdaptorPoint = lift_x(bytesToNum(hexToBytes(adaptorPointHex)));
  }

  // ── Swap: Lock BTC (Bob) ──

  async lockBtc(utxo) {
    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [peerPub, this.pubKey]; // [alice, bob]
    const { aggPubkey } = keyAgg(pubkeys);

    const { address: swapBtcAddress } = createSwapOutput(aggPubkey, this.pubKey, this.csvTimeout);

    let utxoTxid, utxoVout, utxoValue;
    if (utxo) {
      utxoTxid = utxo.txid;
      utxoVout = utxo.vout;
      utxoValue = utxo.value;
    } else {
      const fee = await estimateFee(200);
      const picked = await selectUtxo(this.btcAddress, this.btcSat + fee);
      utxoTxid = picked.txid;
      utxoVout = picked.vout;
      utxoValue = picked.value;
    }

    const fee = await estimateFee(200);
    const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(
      utxoTxid, utxoVout, utxoValue,
      swapBtcAddress, this.btcSat, this.pubKey, fee,
    );
    const bobTweakedKey = computeTweakedPrivateKey(this.secBytes, this.pubKey);
    const fundSig = schnorr.sign(fundSighash, bobTweakedKey);
    const fundTxHex = finalizeKeyPathSpend(fundPsbt, fundSig);
    const fundTxid = await broadcastTx(fundTxHex);

    const fundVout = await findVoutWithRetry(fundTxid, swapBtcAddress);

    this.btcLockTxid = fundTxid;
    this.btcLockVout = fundVout;

    return { txid: fundTxid, vout: fundVout, amountSat: this.btcSat };
  }

  // ── Swap: Verify BTC (Alice) ──

  async verifyBtc(txid, vout) {
    this.btcLockTxid = txid;
    this.btcLockVout = vout;

    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [this.pubKey, peerPub]; // [alice, bob]
    const { aggPubkey } = keyAgg(pubkeys);
    const { address: swapBtcAddress } = createSwapOutput(aggPubkey, peerPub, this.csvTimeout);
    await verifySwapOutput(txid, swapBtcAddress, this.btcAmount, { allowUnconfirmed: true });

    return { valid: true };
  }

  // ── Swap: Deploy ALPH (Alice) ──

  async deployAlph() {
    const compiled = await compileSwapContract();
    this.compiled = compiled;

    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [this.pubKey, peerPub];
    const { aggPubkey } = keyAgg(pubkeys);

    const bobAlphAddress = addressFromPublicKey(this.peerPubHex, 'bip340-schnorr');

    const deployResult = await deploySwapContract(
      this.pubKeyHex, this.secBytes, bytesToHex(aggPubkey), bobAlphAddress, this.alphAddress,
      this.alphTimeoutMs, this.alphAmount, compiled,
    );
    await waitForTx(deployResult.txId);

    this.contractId = deployResult.contractId;
    this.contractAddress = deployResult.contractAddress;
    this.deployResult = deployResult;

    return {
      contractId: deployResult.contractId,
      contractAddress: deployResult.contractAddress,
      txId: deployResult.txId,
    };
  }

  // ── Swap: Verify ALPH (Bob) ──

  async verifyAlph(contractId, contractAddress) {
    this.contractId = contractId;
    this.contractAddress = contractAddress;

    const compiled = await compileSwapContract();
    this.compiled = compiled;

    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [peerPub, this.pubKey];
    const { aggPubkey } = keyAgg(pubkeys);

    const aliceAlphAddress = addressFromPublicKey(this.peerPubHex, 'bip340-schnorr');

    await verifyContractState(
      contractAddress, bytesToHex(aggPubkey),
      this.alphAddress, aliceAlphAddress,
      this.alphAmount, undefined, compiled,
    );

    return { valid: true };
  }

  // ── Swap: Compute context ──

  computeContext() {
    const peerPub = hexToBytes(this.peerPubHex);
    const alicePub = this.role === 'alice' ? this.pubKey : peerPub;
    const bobPub = this.role === 'bob' ? this.pubKey : peerPub;

    this.ctx = computeSharedContext({
      alicePub, bobPub,
      btcLockTxid: this.btcLockTxid, btcLockVout: this.btcLockVout,
      btcSat: this.btcSat, contractId: this.contractId, csvTimeout: this.csvTimeout,
    });

    return { swapBtcAddress: this.ctx.swapBtcAddress };
  }

  // ── Swap: Nonce commit ──

  nonceCommit() {
    this.btcNonce = nonceGen(this.secBytes, this.ctx.Qbytes, this.ctx.btcSighash);
    this.alphNonce = nonceGen(this.secBytes, this.ctx.aggPubkey, this.ctx.alphMsg);

    const btcNonceHash = bytesToHex(sha256(this.btcNonce.pubNonce));
    const alphNonceHash = bytesToHex(sha256(this.alphNonce.pubNonce));

    return { btcNonceHash, alphNonceHash };
  }

  // ── Swap: Nonce reveal ──

  nonceReveal(peerBtcNonceHash, peerAlphNonceHash) {
    if (peerBtcNonceHash) this.peerBtcNonceHash = peerBtcNonceHash;
    if (peerAlphNonceHash) this.peerAlphNonceHash = peerAlphNonceHash;

    return {
      btcPubNonce: bytesToHex(this.btcNonce.pubNonce),
      alphPubNonce: bytesToHex(this.alphNonce.pubNonce),
    };
  }

  // ── Swap: Nonce verify ──

  nonceVerify(peerBtcPubNonce, peerAlphPubNonce) {
    const peerBtcNonce = hexToBytes(peerBtcPubNonce);
    const peerAlphNonce = hexToBytes(peerAlphPubNonce);

    if (bytesToHex(sha256(peerBtcNonce)) !== this.peerBtcNonceHash)
      throw new Error('Peer BTC nonce commitment mismatch');
    if (bytesToHex(sha256(peerAlphNonce)) !== this.peerAlphNonceHash)
      throw new Error('Peer ALPH nonce commitment mismatch');

    this.peerBtcPubNonce = peerBtcNonce;
    this.peerAlphPubNonce = peerAlphNonce;

    if (this.role === 'alice') {
      this.btcAggNonce = nonceAgg([this.btcNonce.pubNonce, peerBtcNonce]);
      this.alphAggNonce = nonceAgg([this.alphNonce.pubNonce, peerAlphNonce]);
    } else {
      this.btcAggNonce = nonceAgg([peerBtcNonce, this.btcNonce.pubNonce]);
      this.alphAggNonce = nonceAgg([peerAlphNonce, this.alphNonce.pubNonce]);
    }

    return { valid: true };
  }

  // ── Swap: Presign ──

  presign() {
    const signerIndex = this.role === 'alice' ? 0 : 1;
    const T = this.role === 'alice' ? this.adaptorPoint : this.peerAdaptorPoint;

    const btcPresig = adaptorSign(this.secBytes, this.btcNonce.secNonce, this.btcAggNonce,
      this.ctx.keyCoeffs, this.ctx.Qbytes, this.ctx.btcSighash, T, signerIndex, this.ctx.gaccTweaked);
    const alphPresig = adaptorSign(this.secBytes, this.alphNonce.secNonce, this.alphAggNonce,
      this.ctx.keyCoeffs, this.ctx.aggPubkey, this.ctx.alphMsg, T, signerIndex, this.ctx.gacc);

    this.myBtcPresig = btcPresig;
    this.myAlphPresig = alphPresig;

    return {
      btcPresig: bytesToHex(btcPresig),
      alphPresig: bytesToHex(alphPresig),
    };
  }

  // ── Swap: Verify presig ──

  verifyPresig(peerBtcPresig, peerAlphPresig) {
    const peerPub = hexToBytes(this.peerPubHex);
    const peerIndex = this.role === 'alice' ? 1 : 0;
    const T = this.role === 'alice' ? this.adaptorPoint : this.peerAdaptorPoint;

    const peerBtcPresigBytes = hexToBytes(peerBtcPresig);
    const peerAlphPresigBytes = hexToBytes(peerAlphPresig);
    this.peerBtcPresig = peerBtcPresigBytes;
    this.peerAlphPresig = peerAlphPresigBytes;

    const peerBtcNonce = this.peerBtcPubNonce;
    const peerAlphNonce = this.peerAlphPubNonce;

    if (!adaptorVerify(peerBtcPresigBytes, peerBtcNonce, peerPub, this.btcAggNonce,
      this.ctx.keyCoeffs, this.ctx.Qbytes, this.ctx.btcSighash, T, peerIndex, this.ctx.gaccTweaked))
      throw new Error('Peer BTC adaptor verification failed');
    if (!adaptorVerify(peerAlphPresigBytes, peerAlphNonce, peerPub, this.alphAggNonce,
      this.ctx.keyCoeffs, this.ctx.aggPubkey, this.ctx.alphMsg, T, peerIndex, this.ctx.gacc))
      throw new Error('Peer ALPH adaptor verification failed');

    // Aggregate — order: [alice, bob]
    const presigs = this.role === 'alice'
      ? [this.myBtcPresig, peerBtcPresigBytes]
      : [peerBtcPresigBytes, this.myBtcPresig];
    const alphPresigs = this.role === 'alice'
      ? [this.myAlphPresig, peerAlphPresigBytes]
      : [peerAlphPresigBytes, this.myAlphPresig];

    this.btcAdaptorAgg = adaptorAggregate(presigs, this.btcAggNonce, this.ctx.Qbytes, this.ctx.btcSighash, T);
    this.alphAdaptorAgg = adaptorAggregate(alphPresigs, this.alphAggNonce, this.ctx.aggPubkey, this.ctx.alphMsg, T);

    // Taproot tweak
    const btcE = computeAdaptorChallenge(this.btcAggNonce, this.ctx.Qbytes, this.ctx.btcSighash, T);
    const sTweaked = Fn.create(bytesToNum(this.btcAdaptorAgg.s) + Fn.create(this.ctx.tacc * btcE));
    this.btcTweakedAgg = { R: this.btcAdaptorAgg.R, s: numTo32b(sTweaked), negR: this.btcAdaptorAgg.negR };

    return { valid: true };
  }

  // ── Swap: Claim BTC (Alice) ──

  async claimBtc() {
    const btcFinalSig = completeAdaptorSig(
      this.btcTweakedAgg.R, this.btcTweakedAgg.s, this.adaptorSecret, this.btcTweakedAgg.negR,
    );

    if (!schnorr.verify(btcFinalSig, this.ctx.btcSighash, this.ctx.Qbytes))
      throw new Error('BTC completed signature invalid');

    const { psbt } = buildClaimTx(
      this.btcLockTxid, this.btcLockVout, this.btcSat,
      this.ctx.aliceBtcAddress, this.ctx.internalPubkey, this.ctx.scriptTree,
    );
    const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
    const claimTxid = await broadcastTx(signedTxHex);
    this.btcClaimTxid = claimTxid;

    return { txid: claimTxid };
  }

  // ── Swap: Claim ALPH (Bob) ──

  async claimAlph(btcClaimTxid) {
    // Retry extractSignatureFromTx — tx may still be propagating to Esplora mempool
    let onChainSig;
    for (let i = 0; i < 15; i++) {
      try {
        onChainSig = await extractSignatureFromTx(btcClaimTxid);
        break;
      } catch (e) {
        if (i === 14) throw new Error(`Cannot fetch BTC claim tx after 15 attempts: ${e.message}`);
        await new Promise(r => setTimeout(r, 2000));
      }
    }
    const extractedTBytes = adaptorExtract(
      onChainSig.slice(32, 64), this.btcTweakedAgg.s, this.btcTweakedAgg.negR,
    );

    const alphFinalSig = completeAdaptorSig(
      this.alphAdaptorAgg.R, this.alphAdaptorAgg.s, extractedTBytes, this.alphAdaptorAgg.negR,
    );

    if (!schnorr.verify(alphFinalSig, this.ctx.alphMsg, this.ctx.aggPubkey))
      throw new Error('ALPH completed signature invalid');

    const alphClaimResult = await claimSwap(this.pubKeyHex, this.secBytes, this.contractId, bytesToHex(alphFinalSig), this.compiled);
    await waitForTx(alphClaimResult.txId);

    return { txid: alphClaimResult.txId };
  }

  // ── Swap: Refund ALPH (Alice) ──

  async refundAlph() {
    const result = await refundSwap(this.pubKeyHex, this.secBytes, this.contractId, this.compiled);
    await waitForTx(result.txId);
    return { txid: result.txId };
  }

  // ── Sweep: Send all BTC ──

  async sweepBtc(destAddress) {
    const tweakedKey = computeTweakedPrivateKey(this.secBytes, this.pubKey);
    const txid = await sweepBtcTx(this.btcAddress, destAddress, this.pubKey, (sighash) => {
      return schnorr.sign(sighash, tweakedKey);
    });
    return txid;
  }

  // ── Sweep: Send all ALPH ──

  async sweepAlph(destAddress) {
    const bal = await getBalance(this.alphAddress);
    const available = bal.balance - bal.lockedBalance;
    // Reserve gas: 0.002 ALPH (20000 gas * 100 gwei)
    const gasReserve = ONE_ALPH / 500n;
    const sendAmount = available - gasReserve;
    if (sendAmount <= 0n) throw new Error('Insufficient ALPH balance to cover gas');
    const txId = await transferAlph(this.pubKeyHex, this.secBytes, destAddress, sendAmount);
    return txId;
  }

  // ── Address Validation ──

  static validateBtcAddress(addr) {
    try { bitcoin.address.toOutputScript(addr, NETWORK); return true; }
    catch { return false; }
  }

  static validateAlphAddress(addr) {
    try { groupOfAddress(addr); return true; }
    catch { return false; }
  }

  // ── Swap: Refund BTC (Bob) ──

  async refundBtc() {
    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [peerPub, this.pubKey]; // [alice, bob]
    const { aggPubkey } = keyAgg(pubkeys);
    const { internalPubkey, scriptTree } = createSwapOutput(aggPubkey, this.pubKey, this.csvTimeout);

    const { psbt: refundPsbt } = buildRefundTx(
      this.btcLockTxid, this.btcLockVout, this.btcSat,
      this.btcAddress, internalPubkey, scriptTree, this.csvTimeout,
    );

    refundPsbt.signInput(0, {
      publicKey: Buffer.concat([Buffer.from([0x02]), Buffer.from(this.pubKey)]),
      signSchnorr: (hash) => Buffer.from(schnorr.sign(hash, this.secBytes)),
    });
    refundPsbt.finalizeAllInputs();
    const refundTxHex = refundPsbt.extractTransaction().toHex();
    const refundTxid = await broadcastTx(refundTxHex);

    return { txid: refundTxid };
  }

  // ── Serialization: Checkpoint ──

  getCheckpoint() {
    if (this.btcClaimTxid) return 'btc_claimed';
    if (this.btcAdaptorAgg && this.alphAdaptorAgg) return 'presigned';
    if (this.btcLockTxid && this.contractId) return 'locked';
    return null;
  }

  toJSON() {
    const hex = (v) => v ? bytesToHex(v) : null;
    const aggToJSON = (agg) => agg ? { R: hex(agg.R), s: hex(agg.s), negR: agg.negR } : null;
    const nonceToJSON = (n) => n ? { secNonce: hex(n.secNonce), pubNonce: hex(n.pubNonce) } : null;

    // Save compiled bytecodes so we don't need recompilation on restore
    let compiledData = null;
    if (this.compiled) {
      compiledData = {
        contract: {
          bytecode: this.compiled.contract.bytecode,
          fields: this.compiled.contract.fields,
          name: this.compiled.contract.name,
        },
        claimScript: {
          bytecodeTemplate: this.compiled.claimScript.bytecodeTemplate,
          fields: this.compiled.claimScript.fields,
          name: this.compiled.claimScript.name,
        },
        refundScript: {
          bytecodeTemplate: this.compiled.refundScript.bytecodeTemplate,
          fields: this.compiled.refundScript.fields,
          name: this.compiled.refundScript.name,
        },
        structs: this.compiled.structs || [],
      };
    }

    return {
      version: 1,
      role: this.role,
      peerPubHex: this.peerPubHex,
      btcAmount: this.btcAmount,
      btcSat: this.btcSat,
      alphAmount: String(this.alphAmount),
      csvTimeout: this.csvTimeout,
      alphTimeoutMs: this.alphTimeoutMs,
      adaptorSecret: hex(this.adaptorSecret),
      adaptorPoint: this.adaptorPoint ? hex(pointToBytes(this.adaptorPoint)) : null,
      peerAdaptorPoint: this.peerAdaptorPoint ? hex(pointToBytes(this.peerAdaptorPoint)) : null,
      btcLockTxid: this.btcLockTxid,
      btcLockVout: this.btcLockVout,
      contractId: this.contractId,
      contractAddress: this.contractAddress,
      compiled: compiledData,
      btcNonce: nonceToJSON(this.btcNonce),
      alphNonce: nonceToJSON(this.alphNonce),
      peerBtcNonceHash: this.peerBtcNonceHash,
      peerAlphNonceHash: this.peerAlphNonceHash,
      peerBtcPubNonce: hex(this.peerBtcPubNonce),
      peerAlphPubNonce: hex(this.peerAlphPubNonce),
      btcAggNonce: hex(this.btcAggNonce),
      alphAggNonce: hex(this.alphAggNonce),
      myBtcPresig: hex(this.myBtcPresig),
      myAlphPresig: hex(this.myAlphPresig),
      peerBtcPresig: hex(this.peerBtcPresig),
      peerAlphPresig: hex(this.peerAlphPresig),
      btcAdaptorAgg: aggToJSON(this.btcAdaptorAgg),
      alphAdaptorAgg: aggToJSON(this.alphAdaptorAgg),
      btcTweakedAgg: aggToJSON(this.btcTweakedAgg),
      btcClaimTxid: this.btcClaimTxid,
    };
  }

  restoreFromJSON(data) {
    if (data.version !== 1) throw new Error(`Unknown swap state version: ${data.version}`);

    const bytes = (h) => h ? hexToBytes(h) : null;
    const point = (h) => h ? lift_x(bytesToNum(hexToBytes(h))) : null;
    const aggFromJSON = (a) => a ? { R: bytes(a.R), s: bytes(a.s), negR: a.negR } : null;
    const nonceFromJSON = (n) => n ? { secNonce: bytes(n.secNonce), pubNonce: bytes(n.pubNonce) } : null;

    this.role = data.role;
    this.peerPubHex = data.peerPubHex;
    this.btcAmount = data.btcAmount;
    this.btcSat = data.btcSat;
    this.alphAmount = BigInt(data.alphAmount);
    this.csvTimeout = data.csvTimeout;
    this.alphTimeoutMs = data.alphTimeoutMs;
    this.adaptorSecret = bytes(data.adaptorSecret);
    this.adaptorPoint = point(data.adaptorPoint);
    this.peerAdaptorPoint = point(data.peerAdaptorPoint);
    this.btcLockTxid = data.btcLockTxid;
    this.btcLockVout = data.btcLockVout;
    this.contractId = data.contractId;
    this.contractAddress = data.contractAddress;
    this.btcNonce = nonceFromJSON(data.btcNonce);
    this.alphNonce = nonceFromJSON(data.alphNonce);
    this.peerBtcNonceHash = data.peerBtcNonceHash;
    this.peerAlphNonceHash = data.peerAlphNonceHash;
    this.peerBtcPubNonce = bytes(data.peerBtcPubNonce);
    this.peerAlphPubNonce = bytes(data.peerAlphPubNonce);
    this.btcAggNonce = bytes(data.btcAggNonce);
    this.alphAggNonce = bytes(data.alphAggNonce);
    this.myBtcPresig = bytes(data.myBtcPresig);
    this.myAlphPresig = bytes(data.myAlphPresig);
    this.peerBtcPresig = bytes(data.peerBtcPresig);
    this.peerAlphPresig = bytes(data.peerAlphPresig);
    this.btcAdaptorAgg = aggFromJSON(data.btcAdaptorAgg);
    this.alphAdaptorAgg = aggFromJSON(data.alphAdaptorAgg);
    this.btcTweakedAgg = aggFromJSON(data.btcTweakedAgg);
    this.btcClaimTxid = data.btcClaimTxid;

    // Restore compiled from saved bytecodes
    if (data.compiled) {
      this.compiled = {
        contract: data.compiled.contract,
        claimScript: data.compiled.claimScript,
        refundScript: data.compiled.refundScript,
        structs: data.compiled.structs || [],
      };
    }
  }

  async rehydrate() {
    // Recompute shared context if we have enough state
    if (this.btcLockTxid && this.contractId && this.peerPubHex) {
      this.computeContext();
    }
    // If compiled wasn't saved, fetch from node
    if (!this.compiled && this.contractId) {
      this.compiled = await compileSwapContract();
    }
  }
}
