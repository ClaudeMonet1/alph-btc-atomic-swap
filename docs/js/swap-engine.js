// SwapEngine — client-side swap logic extracted from server.js
// All session state and swap protocol steps, no HTTP wrapper.

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import { xonlyKeyAgg, tapTweak, swapNonceGen, nonceAgg, adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract, adaptorSecretFromBytes, G, Fn, n, lift_x, hasEvenY, bytesToNum, numTo32b, pointToBytes, Point } from './adaptor.js';
import {
  createSwapOutput, verifySwapOutput,
  buildClaimTx, buildP2TRKeyPathSpend, finalizeKeyPathSpend, broadcastTx,
  extractSignatureFromTx, buildRefundTx, bitcoin, NETWORK,
  getP2TRAddress, getUtxos, selectUtxo,
  getBtcBalance, estimateFee, estimateFeeRate, findVout, waitForConfirmation,
  buildCpfpChild, getConfirmations, BTC_NETWORK_NAME,
  sweepBtc as sweepBtcTx,
} from './btc.js';
import {
  compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState, verifyDeployment, ALPH_NETWORK,
  getBalance, waitForTx, transferAlph,
  web3, ONE_ALPH, addressFromPublicKey, groupOfAddress,
} from './alph.js';
import { computeTweakedPrivateKey } from './taproot-utils.js';
import { deriveKeys, legacyKeys, alphKeyTypeOf } from './keys.js';
import { btcLocktimeNow, alphTimeoutFor, alphTimeoutBounds, checkBtcLocktime, btcConfirmationsFor, alphConfirmationsFor, LOCK_CONFIRMATION_POLL_MS, LOCK_CONFIRMATION_TIMEOUT_MS, claimFeeFor, checkClaimFee, CLAIM_VBYTES, REFUND_VBYTES } from './timelocks.js';

// ============================================================
// Shared context computation
// ============================================================

function computeSharedContext({ alicePub, bobPub, btcLockTxid, btcLockVout, btcSat, contractId, btcLocktime, claimFeeSat }) {
  const pubkeys = [alicePub, bobPub];
  const { aggPubkey, keyCtx } = xonlyKeyAgg(pubkeys);

  const { address: swapBtcAddress, internalPubkey, scriptTree, p2tr } =
    createSwapOutput(aggPubkey, bobPub, btcLocktime);

  const aliceBtcAddress = getP2TRAddress(alicePub);

  const { Qbytes, keyCtx: btcKeyCtx } = tapTweak(keyCtx, p2tr.hash);

  const { sighash: btcSighash } = buildClaimTx(
    btcLockTxid, btcLockVout, btcSat, aliceBtcAddress, internalPubkey, scriptTree, claimFeeSat,
  );
  const alphMsg = hexToBytes(contractId);

  return {
    aggPubkey, keyCtx, btcKeyCtx,
    Qbytes, btcSighash, alphMsg,
    swapBtcAddress, internalPubkey, scriptTree, p2tr,
    aliceBtcAddress, claimFeeSat,
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
  // keys: { nostr, btc, alph } from keys.js (deriveKeys); a bare secret means the
  // legacy single key for all three roles (used to sweep old funds).
  constructor(keys, legacyPubKey) {
    if (keys instanceof Uint8Array) keys = legacyKeys(keys);
    this.keys = keys;
    // Nostr identity
    this.secBytes = keys.nostr.sec;
    this.pubKey = keys.nostr.pub;
    this.pubKeyHex = keys.nostr.pubHex;
    // Bitcoin: MuSig2 party key, own P2TR address, refund leaf key
    this.btcKey = keys.btc;
    this.btcAddress = getP2TRAddress(keys.btc.pub);
    // Alephium: account that deploys/claims/refunds the contract
    this.alphKey = keys.alph;
    this.alphAddress = addressFromPublicKey(keys.alph.pubHex, alphKeyTypeOf(keys.alph.pubHex));
    this.group = groupOfAddress(this.alphAddress);

    // Swap state
    this.role = null;
    this.peerPubHex = null; // peer's Nostr key (messaging)
    this.peer = null;       // { nostrPubHex, btcPubHex, alphPubHex, alphAddress }
    this.btcAmount = 0.00005;
    this.btcSat = 5000;
    this.alphAmount = ONE_ALPH;
    // Timelocks (timelocks.js): Bob chooses btcLocktime when he locks; Alice derives
    // alphTimeoutMs from it; Bob refuses a contract whose timeout opens too early.
    this.btcLocktime = null;
    this.alphTimeoutMs = null;
    // Fee of the pre-signed claim, proposed by Alice with the contract and accepted by Bob within bounds.
    this.claimFeeSat = null;

    this.adaptorSecret = null;
    this.adaptorPoint = null;
    this.peerAdaptorPoint = null;
    this.btcLockTxid = null;
    this.btcLockVout = null;
    this.btcLockPackage = null;
    this.btcLockChange = null;
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
      btcPubHex: this.btcKey.pubHex,
      alphPubHex: this.alphKey.pubHex,
    };
  }

  // The keys the peer announces in its offer/accept: { btc, alph } x-only hex.
  // A bare Nostr key means a legacy single-key peer (all three roles).
  static normalizePeer(peer) {
    if (typeof peer === 'string') return { nostrPubHex: peer, btcPubHex: peer, alphPubHex: peer, alphAddress: addressFromPublicKey(peer, 'bip340-schnorr') };
    // the Alephium key is 33 bytes (ECDSA, HD wallets) or 32 (Schnorr, earlier builds)
    if (!peer || !/^[0-9a-f]{64}$/i.test(peer.nostrPubHex || '') || !/^[0-9a-f]{64}$/i.test(peer.btcPubHex || '') || !/^(?:[0-9a-f]{64}|0[23][0-9a-f]{64})$/i.test(peer.alphPubHex || ''))
      throw new Error('peer keys missing or malformed (the peer may run an old build)');
    return { ...peer, alphAddress: addressFromPublicKey(peer.alphPubHex, alphKeyTypeOf(peer.alphPubHex)) };
  }
  get peerBtcPub() { return hexToBytes(this.peer.btcPubHex); }

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

  // Both parties need an Alephium address in the contract's group: only accounts
  // of that group can call swap()/refund(), and destroySelf! can only pay that
  // group (the node rejects anything else with InvalidOutputGroupIndex).
  checkPeerGroup(peer) {
    peer = SwapEngine.normalizePeer(peer);
    const peerGroup = groupOfAddress(peer.alphAddress);
    if (peerGroup !== this.group)
      throw new Error(`Counterparty's Alephium address is in group ${peerGroup}, yours is in group ${this.group}: the swap contract could not be claimed or refunded across groups. Refusing the swap.`);
  }

  initSwap(role, peer, btcAmount, alphAmount, sessionId) {
    peer = SwapEngine.normalizePeer(peer);
    this.checkPeerGroup(peer);
    // A retried setup for the same session keeps the adaptor secret: the peer may already hold T.
    if (sessionId !== undefined && this.sessionId === sessionId && this.role === role && this.peerPubHex === peer.nostrPubHex && (role !== 'alice' || this.adaptorPoint)) {
      return role === 'alice' ? { role, adaptorPoint: bytesToHex(pointToBytes(this.adaptorPoint)), reused: true } : { role, reused: true };
    }
    this.role = role;
    this.peer = peer;
    this.peerPubHex = peer.nostrPubHex;
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

  async lockBtc(utxo, onProgress = null) {
    const progress = (m) => { if (onProgress) onProgress(m); };
    // Never lock twice for one session: a retried lock step reuses the existing lock.
    if (this.btcLockTxid) return { txid: this.btcLockTxid, vout: this.btcLockVout, amountSat: this.btcSat, btcLocktime: this.btcLocktime, reused: true };
    const DUST_LIMIT = 546;
    const pubkeys = [this.peerBtcPub, this.btcKey.pub]; // [alice, bob]
    const { aggPubkey } = xonlyKeyAgg(pubkeys);

    this.btcLocktime = btcLocktimeNow();
    const { address: swapBtcAddress } = createSwapOutput(aggPubkey, this.btcKey.pub, this.btcLocktime);

    const p2tr = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(this.btcKey.pub), network: NETWORK });

    // Select UTXOs — single if specified, otherwise auto-select (possibly multiple)
    let inputs;
    if (utxo) {
      inputs = [utxo];
    } else {
      progress('Fetching your UTXOs from Esplora...');
      const utxos = await getUtxos(this.btcAddress);
      // Confirmed coins first (an unconfirmed coin at the end of a long chain is
      // refused by the network: "too many unconfirmed ancestors"), then largest first.
      utxos.sort((a, b) => (b.status?.confirmed === true) - (a.status?.confirmed === true) || b.value - a.value);
      progress(`${utxos.length} UTXO(s) found (${utxos.filter((u) => u.status?.confirmed).length} confirmed), estimating the fee...`);
      // Try single UTXO first
      const estFee1 = await estimateFee(154); // 1-in 2-out ~154 vB
      const single = utxos.find(u => {
        const change = u.value - this.btcSat - estFee1;
        return change >= DUST_LIMIT || (change >= 0 && change < DUST_LIMIT);
      });
      if (single) {
        inputs = [single];
      } else {
        // Accumulate UTXOs until we have enough
        inputs = [];
        let total = 0;
        for (const u of utxos) {
          inputs.push(u);
          total += u.value;
          const estFee = await estimateFee(43 + inputs.length * 58 + 43 * 2);
          if (total >= this.btcSat + estFee) break;
        }
        const finalFee = await estimateFee(43 + inputs.length * 58 + 43 * 2);
        if (total < this.btcSat + finalFee) {
          throw new Error(`Insufficient BTC: need ${this.btcSat + finalFee} sat, have ${total} sat across ${utxos.length} UTXOs`);
        }
      }
    }

    const totalInput = inputs.reduce((sum, u) => sum + u.value, 0);
    const fee = await estimateFee(43 + inputs.length * 58 + (inputs.length === 1 ? 43 : 43 * 2));
    progress(`Signing the lock: ${inputs.length} input(s), ${this.btcSat} sat to the swap output, fee ${fee} sat...`);

    // Build PSBT
    const psbt = new bitcoin.Psbt({ network: NETWORK });
    for (const inp of inputs) {
      psbt.addInput({
        hash: inp.txid,
        index: inp.vout,
        witnessUtxo: { script: p2tr.output, value: BigInt(inp.value) },
        tapInternalKey: Buffer.from(this.btcKey.pub),
      });
    }
    psbt.addOutput({ address: swapBtcAddress, value: BigInt(this.btcSat) });

    const change = totalInput - this.btcSat - fee;
    if (change >= DUST_LIMIT) {
      psbt.addOutput({ address: p2tr.address, value: BigInt(change) });
    } else if (change < 0) {
      throw new Error(`Insufficient UTXO: need ${this.btcSat + fee} sat, have ${totalInput} sat`);
    }
    // for a later child-pays-for-parent bump: the lock's fee, size and change output
    this.btcLockPackage = { vbytes: 43 + inputs.length * 58 + (change >= DUST_LIMIT ? 86 : 43), feeSat: fee };
    this.btcLockChange = change >= DUST_LIMIT ? { txid: null, vout: 1, value: change } : null; // txid filled after broadcast

    // Sign each input
    const bobTweakedKey = computeTweakedPrivateKey(this.btcKey.sec, this.btcKey.pub);
    const tx = psbt.__CACHE.__TX;
    const allScripts = inputs.map(() => p2tr.output);
    const allValues = inputs.map(u => BigInt(u.value));
    for (let i = 0; i < inputs.length; i++) {
      const sighash = tx.hashForWitnessV1(i, allScripts, allValues, bitcoin.Transaction.SIGHASH_DEFAULT);
      const sig = schnorr.sign(new Uint8Array(sighash), bobTweakedKey);
      psbt.updateInput(i, { tapKeySig: Buffer.from(sig) });
    }
    psbt.finalizeAllInputs();
    const fundTxHex = psbt.extractTransaction().toHex();
    progress('Broadcasting the lock transaction...');
    const fundTxid = await broadcastTx(fundTxHex);
    progress(`Broadcast ${fundTxid.slice(0, 16)}...; waiting for Esplora to index it...`);

    const fundVout = await findVoutWithRetry(fundTxid, swapBtcAddress);

    this.btcLockTxid = fundTxid;
    this.btcLockVout = fundVout;
    if (this.btcLockChange) this.btcLockChange.txid = fundTxid;

    return { txid: fundTxid, vout: fundVout, amountSat: this.btcSat, btcLocktime: this.btcLocktime };
  }

  // ── Swap: Verify BTC (Alice) ──
  // Bob's chosen refund locktime must lie within the accepted window; the ALPH
  // timeout is derived from it so that Alice's refund opens after Bob's. The
  // lock must be confirmed to the depth the amount calls for before Alice locks anything:
  // an unconfirmed lock is Bob's to replace. After the wait the window is
  // checked again, since confirmation may have eaten into it.

  async verifyBtc(txid, vout, btcLocktime, onProgress = null) {
    checkBtcLocktime(btcLocktime);
    this.btcLocktime = btcLocktime;
    this.alphTimeoutMs = alphTimeoutFor(btcLocktime);
    this.btcLockTxid = txid;
    this.btcLockVout = vout;

    const peerPub = this.peerBtcPub;
    const pubkeys = [this.btcKey.pub, peerPub]; // [alice, bob]
    const { aggPubkey } = xonlyKeyAgg(pubkeys);
    const { address: swapBtcAddress } = createSwapOutput(aggPubkey, peerPub, btcLocktime);
    const { confirmations } = await verifySwapOutput(txid, swapBtcAddress, this.btcAmount, {
      minConfirmations: btcConfirmationsFor(this.btcSat, BTC_NETWORK_NAME), pollMs: LOCK_CONFIRMATION_POLL_MS, timeoutMs: LOCK_CONFIRMATION_TIMEOUT_MS, onProgress,
    });
    checkBtcLocktime(btcLocktime);

    return { valid: true, confirmations };
  }

  // ── Swap: Deploy ALPH (Alice) ──
  // Alice also fixes the claim fee here (twice the current estimate, bounded), since
  // the pre-signed claim cannot change it later; Bob checks it against the same bounds.

  async deployAlph(onProgress = null) {
    const progress = (m) => { if (onProgress) onProgress(m); };
    // Never deploy twice for one session: a retried lock step reuses the existing contract.
    if (this.contractId && this.deployResult) {
      return { contractId: this.contractId, contractAddress: this.contractAddress, txId: this.deployResult.txId, claimFeeSat: this.claimFeeSat, reused: true };
    }
    progress('Compiling the swap contract on the Alephium node...');
    const compiled = await compileSwapContract();
    this.compiled = compiled;
    progress('Estimating the Bitcoin claim fee...');
    this.claimFeeSat = claimFeeFor(await estimateFeeRate(), this.btcSat);
    checkClaimFee(this.claimFeeSat, this.btcSat);

    const pubkeys = [this.btcKey.pub, this.peerBtcPub];
    const { aggPubkey } = xonlyKeyAgg(pubkeys);

    const bobAlphAddress = this.peer.alphAddress;
    this.checkPeerGroup(this.peer);

    progress('Deploying the contract (building, verifying and signing the transaction)...');
    const deployResult = await deploySwapContract(
      this.alphKey.pubHex, this.alphKey.sec, bytesToHex(aggPubkey), bobAlphAddress, this.alphAddress,
      this.alphTimeoutMs, this.alphAmount, compiled,
    );
    progress(`Deployed in ${deployResult.txId.slice(0, 16)}...; waiting for the node to confirm it...`);
    await waitForTx(deployResult.txId);

    this.contractId = deployResult.contractId;
    this.contractAddress = deployResult.contractAddress;
    this.deployResult = deployResult;

    return {
      contractId: deployResult.contractId,
      contractAddress: deployResult.contractAddress,
      txId: deployResult.txId,
      claimFeeSat: this.claimFeeSat,
    };
  }

  // ── Swap: Verify ALPH (Bob) ──

  async verifyAlph(contractId, contractAddress, claimFeeSat, deployTxId, onProgress = null) {
    checkClaimFee(claimFeeSat, this.btcSat);
    this.claimFeeSat = claimFeeSat;
    this.contractId = contractId;
    this.contractAddress = contractAddress;

    // The deployment must be the transaction that created this contract and be
    // deep enough that a reorganisation cannot remove what Bob pre-signs against.
    await verifyDeployment(deployTxId, contractAddress, alphConfirmationsFor(this.btcSat, ALPH_NETWORK), { onProgress });

    const compiled = await compileSwapContract();
    this.compiled = compiled;

    const pubkeys = [this.peerBtcPub, this.btcKey.pub];
    const { aggPubkey } = xonlyKeyAgg(pubkeys);

    const aliceAlphAddress = this.peer.alphAddress;

    // The contract's timeout must open after Bob's own BTC refund plus the margin,
    // otherwise Alice could refund her ALPH and then claim the BTC.
    const bounds = alphTimeoutBounds(this.btcLocktime);
    const verified = await verifyContractState(
      contractAddress, bytesToHex(aggPubkey),
      this.alphAddress, aliceAlphAddress,
      this.alphAmount, bounds.maxTimeout, compiled, bounds.minTimeout,
    );
    this.alphTimeoutMs = Number(verified.timeout); // Bob's deadline for the ALPH claim

    return { valid: true };
  }

  // ── Swap: Compute context ──

  computeContext() {
    const peerPub = this.peerBtcPub;
    const alicePub = this.role === 'alice' ? this.btcKey.pub : peerPub;
    const bobPub = this.role === 'bob' ? this.btcKey.pub : peerPub;

    this.ctx = computeSharedContext({
      alicePub, bobPub,
      btcLockTxid: this.btcLockTxid, btcLockVout: this.btcLockVout,
      btcSat: this.btcSat, contractId: this.contractId, btcLocktime: this.btcLocktime, claimFeeSat: this.claimFeeSat,
    });

    return { swapBtcAddress: this.ctx.swapBtcAddress };
  }

  // ── Swap: Nonce commit ──

  nonceCommit() {
    // fresh nonces: anything signed under the previous ones is void
    this.myBtcPresig = null; this.myAlphPresig = null;
    this.peerBtcPresig = null; this.peerAlphPresig = null;
    this.btcAdaptorAgg = null; this.alphAdaptorAgg = null; this.btcTweakedAgg = null;
    this.btcNonce = swapNonceGen(this.btcKey.sec, this.ctx.Qbytes, this.ctx.btcSighash);
    this.alphNonce = swapNonceGen(this.btcKey.sec, this.ctx.aggPubkey, this.ctx.alphMsg);

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
    // The secret nonces sign once (adaptorSign zeroes them). A retry returns the
    // pre-signatures already made; new nonces require the nonce step again.
    if (this.myBtcPresig && this.myAlphPresig) {
      return { btcPresig: bytesToHex(this.myBtcPresig), alphPresig: bytesToHex(this.myAlphPresig) };
    }
    const signerIndex = this.role === 'alice' ? 0 : 1;
    const T = this.role === 'alice' ? this.adaptorPoint : this.peerAdaptorPoint;

    const btcPresig = adaptorSign(this.btcKey.sec, this.btcNonce.secNonce, this.btcAggNonce, this.ctx.btcKeyCtx, this.ctx.btcSighash, T);
    const alphPresig = adaptorSign(this.btcKey.sec, this.alphNonce.secNonce, this.alphAggNonce, this.ctx.keyCtx, this.ctx.alphMsg, T);

    this.myBtcPresig = btcPresig;
    this.myAlphPresig = alphPresig;

    return {
      btcPresig: bytesToHex(btcPresig),
      alphPresig: bytesToHex(alphPresig),
    };
  }

  // ── Swap: Verify presig ──

  verifyPresig(peerBtcPresig, peerAlphPresig) {
    const peerPub = this.peerBtcPub;
    const peerIndex = this.role === 'alice' ? 1 : 0;
    const T = this.role === 'alice' ? this.adaptorPoint : this.peerAdaptorPoint;

    const peerBtcPresigBytes = hexToBytes(peerBtcPresig);
    const peerAlphPresigBytes = hexToBytes(peerAlphPresig);
    this.peerBtcPresig = peerBtcPresigBytes;
    this.peerAlphPresig = peerAlphPresigBytes;

    const peerBtcNonce = this.peerBtcPubNonce;
    const peerAlphNonce = this.peerAlphPubNonce;

    if (!adaptorVerify(peerBtcPresigBytes, peerBtcNonce, peerPub, this.btcAggNonce, this.ctx.btcKeyCtx, this.ctx.btcSighash, T))
      throw new Error('Peer BTC adaptor verification failed');
    if (!adaptorVerify(peerAlphPresigBytes, peerAlphNonce, peerPub, this.alphAggNonce, this.ctx.keyCtx, this.ctx.alphMsg, T))
      throw new Error('Peer ALPH adaptor verification failed');

    // Aggregate — order: [alice, bob]
    const presigs = this.role === 'alice'
      ? [this.myBtcPresig, peerBtcPresigBytes]
      : [peerBtcPresigBytes, this.myBtcPresig];
    const alphPresigs = this.role === 'alice'
      ? [this.myAlphPresig, peerAlphPresigBytes]
      : [peerAlphPresigBytes, this.myAlphPresig];

    this.btcAdaptorAgg = adaptorAggregate(presigs, this.btcAggNonce, this.ctx.btcKeyCtx, this.ctx.btcSighash, T);
    this.alphAdaptorAgg = adaptorAggregate(alphPresigs, this.alphAggNonce, this.ctx.keyCtx, this.ctx.alphMsg, T);

    // Taproot tweak
    this.btcTweakedAgg = this.btcAdaptorAgg; // the taproot tweak is part of the BIP327 key context

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
      this.ctx.aliceBtcAddress, this.ctx.internalPubkey, this.ctx.scriptTree, this.claimFeeSat,
    );
    const signedTxHex = finalizeKeyPathSpend(psbt, btcFinalSig);
    const claimTxid = await broadcastTx(signedTxHex);
    this.btcClaimTxid = claimTxid;

    return { txid: claimTxid };
  }

  // ── Swap: Bump the claim (Alice) ──
  // The claim's output is Alice's own P2TR: a child spending it pays for the parent.

  async getClaimConfirmations() { return this.btcClaimTxid ? getConfirmations(this.btcClaimTxid) : 0; }
  async getLockConfirmations() { return this.btcLockTxid ? getConfirmations(this.btcLockTxid) : 0; }
  lockBumpable() { return !!(this.btcLockTxid && this.btcLockChange && this.btcLockChange.value >= 330 + 111); }
  lockFeeRate() { return this.btcLockPackage ? this.btcLockPackage.feeSat / this.btcLockPackage.vbytes : 0; }

  // Child pays for parent from the lock's change output (or from the previous
  // child's output on a second bump); the package fee and size accumulate.
  async bumpLockFee() {
    if (!this.btcLockTxid) throw new Error('no lock to bump');
    if (!this.btcLockChange) throw new Error('the lock has no change output to spend (all coins went into it)');
    if (await getConfirmations(this.btcLockTxid) > 0) throw new Error('lock already confirmed');
    const feeRate = Math.ceil((await estimateFeeRate()) * 1.5);
    const { txid: parentTxid, vout, value } = this.btcLockChange;
    const { psbt, sighash, childFee } = buildCpfpChild(parentTxid, vout, value, this.btcKey.pub, feeRate, this.btcLockPackage.vbytes, this.btcLockPackage.feeSat);
    const sig = schnorr.sign(sighash, computeTweakedPrivateKey(this.btcKey.sec, this.btcKey.pub));
    const txid = await broadcastTx(finalizeKeyPathSpend(psbt, sig));
    this.btcLockPackage = { vbytes: this.btcLockPackage.vbytes + 111, feeSat: this.btcLockPackage.feeSat + childFee };
    this.btcLockChange = { txid, vout: 0, value: value - childFee };
    return { txid, childFee, feeRate };
  }

  async bumpClaimFee() {
    if (!this.btcClaimTxid) throw new Error('no claim to bump');
    if (await getConfirmations(this.btcClaimTxid) > 0) throw new Error('claim already confirmed');
    const feeRate = Math.ceil((await estimateFeeRate()) * 1.5);
    const outputSat = this.btcSat - this.claimFeeSat;
    const { psbt, sighash, childFee } = buildCpfpChild(this.btcClaimTxid, 0, outputSat, this.btcKey.pub, feeRate, CLAIM_VBYTES, this.claimFeeSat);
    const sig = schnorr.sign(sighash, computeTweakedPrivateKey(this.btcKey.sec, this.btcKey.pub));
    const txid = await broadcastTx(finalizeKeyPathSpend(psbt, sig));
    return { txid, childFee, feeRate };
  }

  // ── Swap: Claim ALPH (Bob) ──

  async claimAlph(btcClaimTxid, onProgress = null) {
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

    // Alice's claim must be confirmed before Bob spends the ALPH (a reorganised claim
    // would otherwise leave Alice with nothing); the 12 h margin leaves ample time.
    const claimDepth = btcConfirmationsFor(this.btcSat, BTC_NETWORK_NAME);
    for (;;) {
      const c = await getConfirmations(btcClaimTxid);
      if (onProgress) onProgress(c, claimDepth);
      if (c >= claimDepth) break;
      await new Promise(r => setTimeout(r, LOCK_CONFIRMATION_POLL_MS));
    }

    const alphClaimResult = await claimSwap(this.alphKey.pubHex, this.alphKey.sec, this.contractId, bytesToHex(alphFinalSig), this.compiled);
    await waitForTx(alphClaimResult.txId);

    return { txid: alphClaimResult.txId };
  }

  // ── Swap: Refund ALPH (Alice) ──

  async refundAlph() {
    const result = await refundSwap(this.alphKey.pubHex, this.alphKey.sec, this.contractId, this.compiled);
    await waitForTx(result.txId);
    return { txid: result.txId };
  }

  // ── Sweep: Send all BTC ──

  async sweepBtc(destAddress) {
    const tweakedKey = computeTweakedPrivateKey(this.btcKey.sec, this.btcKey.pub);
    const txid = await sweepBtcTx(this.btcAddress, destAddress, this.btcKey.pub, (sighash) => {
      return schnorr.sign(sighash, tweakedKey);
    });
    return txid;
  }

  // ── Sweep: Send all ALPH ──

  async sweepAlph(destAddress) {
    const bal = await getBalance(this.alphAddress);
    const available = bal.balance - bal.lockedBalance;
    // Reserve 0.01 ALPH: the transfer pays 0.002 ALPH of gas (20000 gas * 100 gwei) and
    // the node wants a little more than the exact amount (a sweep that left exactly the
    // gas was refused with "Not enough balance: expected +0.001 ALPH").
    const gasReserve = ONE_ALPH / 100n;
    const sendAmount = available - gasReserve;
    if (sendAmount <= 0n) throw new Error('Insufficient ALPH balance to cover gas');
    const txId = await transferAlph(this.alphKey.pubHex, this.alphKey.sec, destAddress, sendAmount);
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
    const pubkeys = [this.peerBtcPub, this.btcKey.pub]; // [alice, bob]
    const { aggPubkey } = xonlyKeyAgg(pubkeys);
    const { internalPubkey, scriptTree } = createSwapOutput(aggPubkey, this.btcKey.pub, this.btcLocktime);

    const refundFee = Math.max(Math.ceil((await estimateFeeRate()) * REFUND_VBYTES), 300);
    const { psbt: refundPsbt } = buildRefundTx(
      this.btcLockTxid, this.btcLockVout, this.btcSat,
      this.btcAddress, internalPubkey, scriptTree, this.btcLocktime, refundFee,
    );

    refundPsbt.signInput(0, {
      publicKey: Buffer.concat([Buffer.from([0x02]), Buffer.from(this.btcKey.pub)]),
      signSchnorr: (hash) => Buffer.from(schnorr.sign(hash, this.btcKey.sec)),
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
    if (this.btcLockTxid) return 'btc_locked'; // Bob has locked, Alice has not deployed yet
    if (this.sessionId && this.peerPubHex && this.role) return 'started'; // nothing on chain yet, but the session and Alice's adaptor secret must survive a reload
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
      version: 5,
      role: this.role,
      peerPubHex: this.peerPubHex,
      peer: this.peer,
      btcAmount: this.btcAmount,
      btcSat: this.btcSat,
      alphAmount: String(this.alphAmount),
      btcLocktime: this.btcLocktime,
      alphTimeoutMs: this.alphTimeoutMs,
      claimFeeSat: this.claimFeeSat,
      adaptorSecret: hex(this.adaptorSecret),
      adaptorPoint: this.adaptorPoint ? hex(pointToBytes(this.adaptorPoint)) : null,
      peerAdaptorPoint: this.peerAdaptorPoint ? hex(pointToBytes(this.peerAdaptorPoint)) : null,
      btcLockTxid: this.btcLockTxid,
      btcLockVout: this.btcLockVout,
      btcLockPackage: this.btcLockPackage || null,
      btcLockChange: this.btcLockChange || null,
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
    if (data.version !== 5) throw new Error(`Swap state version ${data.version} predates the per-domain keys (or earlier fixes) and cannot be resumed; recover manually`);

    const bytes = (h) => h ? hexToBytes(h) : null;
    const point = (h) => h ? lift_x(bytesToNum(hexToBytes(h))) : null;
    const aggFromJSON = (a) => a ? { R: bytes(a.R), s: bytes(a.s), negR: a.negR } : null;
    const nonceFromJSON = (n) => n ? { secNonce: bytes(n.secNonce), pubNonce: bytes(n.pubNonce) } : null;

    this.role = data.role;
    this.peerPubHex = data.peerPubHex;
    this.peer = data.peer ? SwapEngine.normalizePeer(data.peer) : (data.peerPubHex ? SwapEngine.normalizePeer(data.peerPubHex) : null);
    this.btcAmount = data.btcAmount;
    this.btcSat = data.btcSat;
    this.alphAmount = BigInt(data.alphAmount);
    this.btcLocktime = data.btcLocktime;
    this.alphTimeoutMs = data.alphTimeoutMs;
    this.claimFeeSat = data.claimFeeSat;
    this.adaptorSecret = bytes(data.adaptorSecret);
    this.adaptorPoint = point(data.adaptorPoint);
    this.peerAdaptorPoint = point(data.peerAdaptorPoint);
    this.btcLockTxid = data.btcLockTxid;
    this.btcLockVout = data.btcLockVout;
    this.btcLockPackage = data.btcLockPackage || null;
    this.btcLockChange = data.btcLockChange || null;
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
