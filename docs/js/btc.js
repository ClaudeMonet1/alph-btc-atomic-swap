// Bitcoin Taproot Operations for Atomic Swap — Browser/Static version
// Signet-only via Esplora (mempool.space). No RPC.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

bitcoin.initEccLib(ecc);

// ---- Hardcoded signet config ----

const NETWORK = bitcoin.networks.testnet;
const ESPLORA_URL = 'https://mempool.space/signet/api';
export const BTC_NETWORK_NAME = 'signet';

// ---- Esplora API client ----

async function esploraApi(path, method = 'GET', body = null) {
  const opts = { method };
  if (body !== null) {
    if (typeof body === 'string') {
      opts.headers = { 'Content-Type': 'text/plain' };
      opts.body = body;
    } else {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 30_000);
  let res;
  try { res = await fetch(`${ESPLORA_URL}${path}`, { ...opts, signal: ctl.signal }); }
  catch (e) { throw new Error(`Esplora ${method} ${path}: ${e.name === 'AbortError' ? 'no answer after 30 s' : e.message}`); }
  finally { clearTimeout(timer); }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Esplora ${method} ${path}: ${res.status} ${text}`);
  }
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return res.json();
  return res.text();
}

// ---- Utility functions ----

export async function estimateFee(vBytes = 150) {
  return Math.max(Math.ceil((await estimateFeeRate()) * vBytes), 300);
}

// Current fee rate in sat/vB from Esplora's half-hour estimate.
// Esplora's recommended fees lag the mempool on signet (a live run saw
// halfHourFee 1 while blocks cleared at 3 to 6 sat/vB), so take the larger of
// the fastest recommendation and the median of the next projected block.
// Signet blocks are small and the mempool.space projections assume full-size
// blocks, so /v1/fees/recommended said 1 sat/vB while miners only included
// 3 sat/vB and above (two live runs stalled on this). The rate is therefore the
// largest of the recommendation, the next-block projection and the 25th
// percentile fee rate of recent mined blocks (median over six: what miners actually took).
export async function estimateFeeRate() {
  const fees = await esploraApi('/v1/fees/recommended');
  let nextBlockMedian = 0, minedFloor = 0;
  try { const blocks = await esploraApi('/v1/fees/mempool-blocks'); nextBlockMedian = blocks?.[0]?.medianFee || 0; } catch {}
  try {
    const recent = await esploraApi('/v1/blocks');
    const p25s = (recent || []).slice(0, 6).map((b) => b.extras?.feeRange?.[2] || 0).sort((a, b) => a - b);
    minedFloor = p25s.length ? p25s[Math.floor(p25s.length / 2)] : 0; // median over the six blocks: one expensive block does not set the price
  } catch {}
  return Math.max(1, Math.ceil(Math.max(fees.fastestFee || 0, fees.halfHourFee || 0, nextBlockMedian, minedFloor)));
}

export async function getUtxos(address) {
  return esploraApi(`/address/${address}/utxo`);
}

export async function selectUtxo(address, minValue) {
  const utxos = await getUtxos(address);
  utxos.sort((a, b) => a.value - b.value);
  const pick = utxos.find(u => u.value >= minValue);
  if (!pick) throw new Error(`No UTXO >= ${minValue} sat for ${address} (have ${utxos.length} UTXOs)`);
  return pick;
}

export async function getBtcBalance(address) {
  const utxos = await getUtxos(address);
  const confirmed = utxos.filter(u => u.status?.confirmed !== false);
  return confirmed.reduce((sum, u) => sum + u.value, 0);
}

export function getP2TRAddress(pubkey) {
  return bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(pubkey),
    network: NETWORK,
  }).address;
}

export async function findVout(txid, address) {
  const tx = await esploraApi(`/tx/${txid}`);
  for (let i = 0; i < tx.vout.length; i++) {
    if (tx.vout[i].scriptpubkey_address === address) return i;
  }
  return -1;
}

export async function waitForConfirmation(txid, maxRetries = 60, intervalMs = 5000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const tx = await esploraApi(`/tx/${txid}`);
      if (tx.status?.confirmed) return { confirmations: 1, block_height: tx.status.block_height };
    } catch (_) {}
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error(`Tx ${txid} not confirmed after ${maxRetries} retries`);
}

// ---- Taproot swap output ----

// Refund leaf: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <bob> OP_CHECKSIG, with
// `locktime` an absolute Unix timestamp (compared against median time past).
export function createSwapOutput(aggPubkey, bobPubkey, locktime) {
  if (!Number.isInteger(locktime) || locktime < 500_000_000) throw new Error(`refund locktime must be a Unix timestamp, got ${locktime}`);
  const internalPubkey = Buffer.from(aggPubkey);

  const { OPS } = bitcoin.script;
  const refundScript = bitcoin.script.compile([
    bitcoin.script.number.encode(locktime),
    OPS.OP_CHECKLOCKTIMEVERIFY,
    OPS.OP_DROP,
    Buffer.from(bobPubkey),
    OPS.OP_CHECKSIG,
  ]);

  const scriptTree = { output: refundScript };

  const p2tr = bitcoin.payments.p2tr({
    internalPubkey,
    scriptTree,
    network: NETWORK,
  });

  return {
    address: p2tr.address,
    output: p2tr.output,
    internalPubkey,
    scriptTree,
    refundScript,
    p2tr,
  };
}

// ---- Verify funded swap output ----

// Confirmations of a transaction (0 while unconfirmed).
export async function getConfirmations(txid) {
  const status = await esploraApi(`/tx/${txid}/status`);
  if (!status.confirmed) return 0;
  const tip = parseInt(await esploraApi('/blocks/tip/height'), 10);
  return tip - status.block_height + 1;
}

// Verify that `txid` pays at least `minAmountBtc` to `expectedAddress` and has
// at least `minConfirmations` confirmations, waiting for them if necessary
// (`onProgress(confirmations, needed)` is called on every poll). The output is
// checked first, retrying while Esplora has not seen the transaction yet, so a
// wrong lock is refused at once and an unconfirmed one is never acted on.
export async function verifySwapOutput(txid, expectedAddress, minAmountBtc, { minConfirmations = 1, pollMs = 15_000, timeoutMs = 6 * 3600 * 1000, onProgress = null, maxRetries = 10, retryMs = 3000 } = {}) {
  let tx;
  for (let i = 0; i < maxRetries; i++) {
    try {
      tx = await esploraApi(`/tx/${txid}`);
      break;
    } catch (e) {
      if (i === maxRetries - 1) throw e;
      await new Promise(r => setTimeout(r, retryMs));
    }
  }
  const minSat = Math.round(minAmountBtc * 1e8);
  const found = tx.vout.some(out => out.scriptpubkey_address === expectedAddress && out.value >= minSat);
  if (!found) throw new Error(`No output to ${expectedAddress} with >= ${minAmountBtc} BTC in tx ${txid}`);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const confirmations = await getConfirmations(txid);
    if (onProgress) onProgress(confirmations, minConfirmations);
    if (confirmations >= minConfirmations) return { confirmations };
    if (Date.now() >= deadline) throw new Error(`Swap tx ${txid} has ${confirmations} of ${minConfirmations} confirmations after ${timeoutMs / 1000}s`);
    await new Promise(r => setTimeout(r, pollMs));
  }
}

// ---- Build claim transaction (key path spend) ----

export function buildClaimTx(fundingTxid, vout, amountSat, destAddress, internalPubkey, scriptTree, fee = 300) {
  // Ensure output stays above dust limit (330 sat for P2TR)
  const DUST_LIMIT = 330;
  if (amountSat - fee < DUST_LIMIT) {
    fee = Math.max(0, amountSat - DUST_LIMIT);
  }

  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    network: NETWORK,
  });

  const psbt = new bitcoin.Psbt({ network: NETWORK });

  psbt.addInput({
    hash: fundingTxid,
    index: vout,
    witnessUtxo: {
      script: p2tr.output,
      value: BigInt(amountSat),
    },
    tapInternalKey: Buffer.from(internalPubkey),
    tapMerkleRoot: p2tr.hash,
  });

  psbt.addOutput({
    address: destAddress,
    value: BigInt(amountSat - fee),
  });

  const tx = psbt.__CACHE.__TX;

  const sighash = tx.hashForWitnessV1(
    0,
    [p2tr.output],
    [BigInt(amountSat)],
    bitcoin.Transaction.SIGHASH_DEFAULT,
  );

  return { psbt, sighash: new Uint8Array(sighash), fee, tweakedKey: p2tr.pubkey };
}

// ---- Build simple P2TR key-path spend (single key, no script tree) ----

export function buildP2TRKeyPathSpend(fundingTxid, vout, inputAmountSat, destAddress, sendAmountSat, senderPubkey, fee = 300) {
  const DUST_LIMIT = 546;
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(senderPubkey),
    network: NETWORK,
  });

  const psbt = new bitcoin.Psbt({ network: NETWORK });

  psbt.addInput({
    hash: fundingTxid,
    index: vout,
    witnessUtxo: {
      script: p2tr.output,
      value: BigInt(inputAmountSat),
    },
    tapInternalKey: Buffer.from(senderPubkey),
  });

  psbt.addOutput({
    address: destAddress,
    value: BigInt(sendAmountSat),
  });

  const change = inputAmountSat - sendAmountSat - fee;
  if (change >= DUST_LIMIT) {
    psbt.addOutput({
      address: p2tr.address,
      value: BigInt(change),
    });
  } else if (change < 0) {
    // Fee exceeds available — cap fee to avoid negative balance
    // (no change output, full excess becomes fee)
    throw new Error(`Insufficient UTXO: need ${sendAmountSat + fee} sat, have ${inputAmountSat} sat`);
  }
  // else: 0 <= change < DUST_LIMIT — drop change, extra goes to fee

  const tx = psbt.__CACHE.__TX;
  const sighash = tx.hashForWitnessV1(
    0,
    [p2tr.output],
    [BigInt(inputAmountSat)],
    bitcoin.Transaction.SIGHASH_DEFAULT,
  );

  return { psbt, sighash: new Uint8Array(sighash), fee };
}

// ---- Child-pays-for-parent: spend an unconfirmed P2TR output we own to bump its parent ----
// `parentVbytes` and `parentFee` describe the stuck transaction; the child pays
// enough so that parent plus child reach `feeRate` sat/vB. Returns the child's
// PSBT and sighash for the owner to sign with the tweaked key.
export function buildCpfpChild(parentTxid, vout, outputSat, ownerPubkey, feeRate, parentVbytes, parentFee) {
  const CHILD_VBYTES = 111;
  const wanted = Math.ceil(feeRate * (parentVbytes + CHILD_VBYTES));
  const childFee = Math.max(wanted - parentFee, MIN_CHILD_FEE);
  if (outputSat - childFee < 330) throw new Error(`output too small to bump: ${outputSat} sat, child fee ${childFee} sat`);
  const p2tr = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(ownerPubkey), network: NETWORK });
  const psbt = new bitcoin.Psbt({ network: NETWORK });
  psbt.addInput({ hash: parentTxid, index: vout, witnessUtxo: { script: p2tr.output, value: BigInt(outputSat) }, tapInternalKey: Buffer.from(ownerPubkey) });
  psbt.addOutput({ address: p2tr.address, value: BigInt(outputSat - childFee) });
  const tx = psbt.__CACHE.__TX;
  const sighash = tx.hashForWitnessV1(0, [p2tr.output], [BigInt(outputSat)], bitcoin.Transaction.SIGHASH_DEFAULT);
  return { psbt, sighash: new Uint8Array(sighash), childFee };
}
const MIN_CHILD_FEE = 111;

// ---- Finalize and broadcast key-path spend ----

export function finalizeKeyPathSpend(psbt, signature) {
  psbt.updateInput(0, {
    tapKeySig: Buffer.from(signature),
  });
  psbt.finalizeAllInputs();
  return psbt.extractTransaction().toHex();
}

export async function broadcastTx(signedTxHex) {
  const txid = await esploraApi('/tx', 'POST', signedTxHex);
  return txid.trim();
}

// ---- Build refund transaction (script path spend) ----

export function buildRefundTx(fundingTxid, vout, amountSat, bobAddress, internalPubkey, scriptTree, locktime, fee = 300) {
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    network: NETWORK,
  });

  const redeemOutput = scriptTree.output;
  const p2trSpend = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    redeem: { output: redeemOutput },
    network: NETWORK,
  });

  const psbt = new bitcoin.Psbt({ network: NETWORK });

  psbt.addInput({
    hash: fundingTxid,
    index: vout,
    witnessUtxo: {
      script: p2tr.output,
      value: BigInt(amountSat),
    },
    tapInternalKey: Buffer.from(internalPubkey),
    tapLeafScript: [{
      controlBlock: p2trSpend.witness[p2trSpend.witness.length - 1],
      script: redeemOutput,
      leafVersion: 0xc0,
    }],
    sequence: 0xfffffffe, // nLockTime is enforced only when a sequence is not final
  });
  psbt.setLocktime(locktime);

  psbt.addOutput({
    address: bobAddress,
    value: BigInt(amountSat - fee),
  });

  return { psbt, p2trSpend };
}

// ---- Extract signature from witness ----

export async function extractSignatureFromTx(txid) {
  const tx = await esploraApi(`/tx/${txid}`);
  const witness = tx.vin[0].witness;
  if (!witness || witness.length === 0) throw new Error('No witness data');
  return hexToBytes(witness[0]);
}

// ---- Median time past: what OP_CHECKLOCKTIMEVERIFY compares a timestamp locktime against ----

export async function getMedianTimePast() {
  const tip = await esploraApi('/blocks');
  const older = await esploraApi(`/blocks/${tip[tip.length - 1].height - 1}`);
  const times = [...tip, ...older].map(b => b.timestamp).sort((a, b) => b - a).slice(0, 11).sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)];
}

// ---- Sweep all UTXOs to destination ----

export async function sweepBtc(address, destAddress, senderPubkey, signCallback) {
  const utxos = await getUtxos(address);
  if (utxos.length === 0) throw new Error('No UTXOs to sweep');

  const totalInput = utxos.reduce((sum, u) => sum + u.value, 0);

  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(senderPubkey),
    network: NETWORK,
  });

  const psbt = new bitcoin.Psbt({ network: NETWORK });

  for (const utxo of utxos) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        script: p2tr.output,
        value: BigInt(utxo.value),
      },
      tapInternalKey: Buffer.from(senderPubkey),
    });
  }

  // Estimate fee: ~58 vB per input + ~43 vB overhead + ~43 vB output
  const estVBytes = 43 + utxos.length * 58 + 43;
  const fee = await estimateFee(estVBytes);
  const sendAmount = totalInput - fee;
  if (sendAmount <= 546) throw new Error(`Balance too low to cover fee (${totalInput} sat, fee ${fee} sat)`);

  psbt.addOutput({ address: destAddress, value: BigInt(sendAmount) });

  // Sign each input
  const tx = psbt.__CACHE.__TX;
  for (let i = 0; i < utxos.length; i++) {
    const sighash = tx.hashForWitnessV1(
      i,
      utxos.map(() => p2tr.output),
      utxos.map(u => BigInt(u.value)),
      bitcoin.Transaction.SIGHASH_DEFAULT,
    );
    const sig = signCallback(new Uint8Array(sighash));
    psbt.updateInput(i, { tapKeySig: Buffer.from(sig) });
  }

  psbt.finalizeAllInputs();
  const txHex = psbt.extractTransaction().toHex();
  return await broadcastTx(txHex);
}

export { NETWORK, bitcoin, ecc };
