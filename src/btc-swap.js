// Bitcoin Taproot Operations for Atomic Swap
// Requires Bitcoin Core regtest running at 127.0.0.1:18443

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

bitcoin.initEccLib(ecc);

const REGTEST = bitcoin.networks.regtest;
const RPC_URL = 'http://127.0.0.1:18443';
const RPC_AUTH = 'Basic ' + Buffer.from('nostralph:nostralph').toString('base64');

// ---- JSON-RPC helper ----

export async function bitcoinRpc(method, params = [], wallet = null) {
  const url = wallet ? `${RPC_URL}/wallet/${wallet}` : RPC_URL;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: RPC_AUTH },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`bitcoinRpc ${method}: ${json.error.message}`);
  return json.result;
}

// ---- Wallet setup ----

export async function setupRegtestWallet(walletName) {
  // Create or load wallet
  try {
    await bitcoinRpc('createwallet', [walletName]);
  } catch (e) {
    if (!e.message.includes('already exists')) throw e;
    try { await bitcoinRpc('loadwallet', [walletName]); } catch (_) {}
  }
  // Generate an address and mine blocks to fund it
  const addr = await bitcoinRpc('getnewaddress', [], walletName);
  await bitcoinRpc('generatetoaddress', [101, addr], walletName);
  return addr;
}

// ---- Taproot swap output ----

export function createSwapOutput(aggPubkey, bobPubkey, timeoutBlocks) {
  // aggPubkey: 32-byte x-only MuSig2 aggregated key (Buffer)
  // bobPubkey: 32-byte x-only key for refund script path
  // timeoutBlocks: CSV relative locktime

  const internalPubkey = Buffer.from(aggPubkey);

  // Refund script: <timeout> OP_CSV OP_DROP <bob_xonly> OP_CHECKSIG
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
    network: REGTEST,
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

// ---- Fund swap output ----

export async function fundSwapOutput(address, amountBtc, walletName) {
  const txid = await bitcoinRpc('sendtoaddress', [address, amountBtc], walletName);
  // Get the raw tx to find the vout
  const rawTx = await bitcoinRpc('getrawtransaction', [txid, true], walletName);
  let vout = -1;
  for (let i = 0; i < rawTx.vout.length; i++) {
    if (rawTx.vout[i].scriptPubKey.address === address) {
      vout = i;
      break;
    }
  }
  if (vout === -1) throw new Error('Could not find swap output in funded tx');
  return { txid, vout, rawTx };
}

// ---- Verify funded swap output ----

export async function verifySwapOutput(txid, expectedAddress, minAmountBtc) {
  const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
  const confirmations = rawTx.confirmations || 0;
  if (confirmations < 1) throw new Error(`Swap tx ${txid} not yet confirmed (${confirmations} confs)`);

  let found = false;
  for (const out of rawTx.vout) {
    if (out.scriptPubKey.address === expectedAddress && out.value >= minAmountBtc) {
      found = true;
      break;
    }
  }
  if (!found) throw new Error(`No output to ${expectedAddress} with >= ${minAmountBtc} BTC in tx ${txid}`);
  return { confirmations };
}

// ---- Build claim transaction (key path spend) ----

export function buildClaimTx(fundingTxid, vout, amountSat, destAddress, internalPubkey, scriptTree) {
  // Build an unsigned tx spending the taproot output via key path
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    network: REGTEST,
  });

  const fee = 300; // minimal fee for regtest
  const psbt = new bitcoin.Psbt({ network: REGTEST });

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

  // Extract sighash for MuSig2 signing.
  // bitcoinjs-lib has no public API for taproot sighash with external signers;
  // accessing __CACHE.__TX is the standard workaround (pinned to bitcoinjs-lib v7).
  const tx = psbt.__CACHE.__TX;

  const sighash = tx.hashForWitnessV1(
    0,                    // input index
    [p2tr.output],        // prevout scripts
    [BigInt(amountSat)],  // prevout values
    bitcoin.Transaction.SIGHASH_DEFAULT,
  );

  return { psbt, sighash: new Uint8Array(sighash), fee, tweakedKey: p2tr.pubkey };
}

// ---- Build simple P2TR key-path spend (single key, no script tree) ----

export function buildP2TRKeyPathSpend(fundingTxid, vout, inputAmountSat, destAddress, sendAmountSat, senderPubkey) {
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(senderPubkey),
    network: REGTEST,
  });

  const fee = 300;
  const psbt = new bitcoin.Psbt({ network: REGTEST });

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
  // For key path spend, witness is just [signature]
  // signature is 64-byte Schnorr sig (SIGHASH_DEFAULT means no suffix byte)
  psbt.updateInput(0, {
    tapKeySig: Buffer.from(signature),
  });
  psbt.finalizeAllInputs();
  return psbt.extractTransaction().toHex();
}

export async function broadcastTx(signedTxHex) {
  const txid = await bitcoinRpc('sendrawtransaction', [signedTxHex]);
  return txid;
}

// ---- Build refund transaction (script path spend) ----

export function buildRefundTx(fundingTxid, vout, amountSat, bobAddress, internalPubkey, scriptTree, csvTimeout) {
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    network: REGTEST,
  });

  // Get the redeem info for the script path
  const redeemOutput = scriptTree.output;
  const p2trSpend = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    redeem: { output: redeemOutput },
    network: REGTEST,
  });

  const fee = 300;
  const psbt = new bitcoin.Psbt({ network: REGTEST });

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
  const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
  // Key path witness: [signature]
  const witness = rawTx.vin[0].txinwitness;
  if (!witness || witness.length === 0) throw new Error('No witness data');
  // First element is the signature (64 or 65 bytes hex)
  const sigHex = witness[0];
  return hexToBytes(sigHex);
}

// ---- Mine blocks helper ----

export async function mineBlocks(n, address) {
  return bitcoinRpc('generatetoaddress', [n, address]);
}

export { REGTEST, bitcoin, ecc };
