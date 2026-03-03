// Bitcoin Taproot Operations for Atomic Swap — Browser/Static version
// Signet-only via Esplora (mempool.space). No RPC.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

bitcoin.initEccLib(ecc);

// ---- Hardcoded signet config ----

const NETWORK = bitcoin.networks.testnet;
const ESPLORA_URL = 'https://mempool.space/signet/api';

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
  const res = await fetch(`${ESPLORA_URL}${path}`, opts);
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
  const fees = await esploraApi('/v1/fees/recommended');
  const feeRate = fees.halfHourFee || 2; // sat/vB
  return Math.max(feeRate * vBytes, 300);
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

export function createSwapOutput(aggPubkey, bobPubkey, timeoutBlocks) {
  const internalPubkey = Buffer.from(aggPubkey);

  const { OPS } = bitcoin.script;
  const refundScript = bitcoin.script.compile([
    bitcoin.script.number.encode(timeoutBlocks),
    OPS.OP_CHECKSEQUENCEVERIFY,
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

export async function verifySwapOutput(txid, expectedAddress, minAmountBtc, { allowUnconfirmed = false } = {}) {
  const tx = await esploraApi(`/tx/${txid}`);
  const confirmed = tx.status?.confirmed || false;
  if (!allowUnconfirmed && !confirmed) throw new Error(`Swap tx ${txid} not yet confirmed`);

  let found = false;
  for (const out of tx.vout) {
    if (out.scriptpubkey_address === expectedAddress && out.value >= Math.round(minAmountBtc * 1e8)) {
      found = true;
      break;
    }
  }
  if (!found) throw new Error(`No output to ${expectedAddress} with >= ${minAmountBtc} BTC in tx ${txid}`);
  return { confirmations: confirmed ? 1 : 0 };
}

// ---- Build claim transaction (key path spend) ----

export function buildClaimTx(fundingTxid, vout, amountSat, destAddress, internalPubkey, scriptTree, fee = 300) {
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
  if (change > 546) {
    psbt.addOutput({
      address: p2tr.address,
      value: BigInt(change),
    });
  }

  const tx = psbt.__CACHE.__TX;
  const sighash = tx.hashForWitnessV1(
    0,
    [p2tr.output],
    [BigInt(inputAmountSat)],
    bitcoin.Transaction.SIGHASH_DEFAULT,
  );

  return { psbt, sighash: new Uint8Array(sighash), fee };
}

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

export function buildRefundTx(fundingTxid, vout, amountSat, bobAddress, internalPubkey, scriptTree, csvTimeout, fee = 300) {
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
    sequence: csvTimeout,
  });

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
