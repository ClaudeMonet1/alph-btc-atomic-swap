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
  web3, ONE_ALPH, PrivateKeyWallet, addressFromPublicKey, groupOfAddress,
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

async function findVoutWithRetry(txid, address, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const vout = await findVout(txid, address);
      if (vout >= 0) return vout;
    } catch (_) {}
    if (i < maxRetries - 1) await new Promise(r => setTimeout(r, 2000));
  }
  return 0;
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
    this.btcAmount = 0.5;
    this.btcSat = 50000000;
    this.alphAmount = ONE_ALPH * 10n;
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
    const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(this.secBytes), keyType: 'bip340-schnorr' });
    const compiled = await compileSwapContract();
    this.compiled = compiled;

    const peerPub = hexToBytes(this.peerPubHex);
    const pubkeys = [this.pubKey, peerPub];
    const { aggPubkey } = keyAgg(pubkeys);

    const bobAlphAddress = addressFromPublicKey(this.peerPubHex, 'bip340-schnorr');
    const bobGroup = groupOfAddress(bobAlphAddress);

    const deployResult = await deploySwapContract(
      wallet, bytesToHex(aggPubkey), bobAlphAddress, wallet.address,
      this.alphTimeoutMs, this.alphAmount, compiled, bobGroup,
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

    const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(this.secBytes), keyType: 'bip340-schnorr' });
    const aliceAlphAddress = addressFromPublicKey(this.peerPubHex, 'bip340-schnorr');

    await verifyContractState(
      contractAddress, bytesToHex(aggPubkey),
      wallet.address, aliceAlphAddress,
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

    return { txid: claimTxid };
  }

  // ── Swap: Claim ALPH (Bob) ──

  async claimAlph(btcClaimTxid) {
    const onChainSig = await extractSignatureFromTx(btcClaimTxid);
    const extractedTBytes = adaptorExtract(
      onChainSig.slice(32, 64), this.btcTweakedAgg.s, this.btcTweakedAgg.negR,
    );

    const alphFinalSig = completeAdaptorSig(
      this.alphAdaptorAgg.R, this.alphAdaptorAgg.s, extractedTBytes, this.alphAdaptorAgg.negR,
    );

    if (!schnorr.verify(alphFinalSig, this.ctx.alphMsg, this.ctx.aggPubkey))
      throw new Error('ALPH completed signature invalid');

    const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(this.secBytes), keyType: 'bip340-schnorr' });
    await new Promise(r => setTimeout(r, 2000));
    const alphClaimResult = await claimSwap(wallet, this.contractId, bytesToHex(alphFinalSig), this.compiled, wallet.group);
    await waitForTx(alphClaimResult.txId);

    return { txid: alphClaimResult.txId };
  }

  // ── Swap: Refund ALPH (Alice) ──

  async refundAlph() {
    const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(this.secBytes), keyType: 'bip340-schnorr' });
    const result = await refundSwap(wallet, this.contractId, this.compiled);
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
    const wallet = new PrivateKeyWallet({ privateKey: bytesToHex(this.secBytes), keyType: 'bip340-schnorr' });
    const bal = await getBalance(this.alphAddress);
    const available = bal.balance - bal.lockedBalance;
    // Reserve gas: 0.002 ALPH (20000 gas * 100 gwei)
    const gasReserve = ONE_ALPH / 500n;
    const sendAmount = available - gasReserve;
    if (sendAmount <= 0n) throw new Error('Insufficient ALPH balance to cover gas');
    const txId = await transferAlph(wallet, destAddress, sendAmount);
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
}
