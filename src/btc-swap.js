// Bitcoin Taproot Operations for Atomic Swap
// Supports dual-mode: RPC (regtest/devnet) and Esplora API (signet)

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

bitcoin.initEccLib(ecc);

// ---- Network configuration ----

const REGTEST = bitcoin.networks.regtest;
const RPC_URL = 'http://127.0.0.1:18443';
const RPC_AUTH = 'Basic ' + Buffer.from('nostralph:nostralph').toString('base64');

const NETWORKS = {
  regtest: { network: bitcoin.networks.regtest, esploraUrl: null, useRpc: true },
  signet:  { network: bitcoin.networks.testnet, esploraUrl: 'https://mempool.space/signet/api', useRpc: false },
};

let activeConfig = NETWORKS.regtest;

export function setBtcNetwork(name) {
  if (!NETWORKS[name]) throw new Error(`Unknown BTC network: ${name}`);
  activeConfig = NETWORKS[name];
}

export function getBtcNetwork() {
  return activeConfig;
}

// ---- Esplora API client ----

async function esploraApi(path, method = 'GET', body = null) {
  if (!activeConfig.esploraUrl) throw new Error('Esplora not available in RPC mode');
  const opts = { method };
  if (body !== null) {
    // POST /tx sends raw hex as plain text
    if (typeof body === 'string') {
      opts.headers = { 'Content-Type': 'text/plain' };
      opts.body = body;
    } else {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
  }
  const res = await fetch(`${activeConfig.esploraUrl}${path}`, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Esplora ${method} ${path}: ${res.status} ${text}`);
  }
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return res.json();
  return res.text();
}

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

// ---- New utility functions ----

export async function estimateFee(vBytes = 150) {
  if (activeConfig.useRpc) return 300; // flat fee for regtest
  const fees = await esploraApi('/v1/fees/recommended');
  const feeRate = fees.halfHourFee || 2; // sat/vB
  return Math.max(feeRate * vBytes, 300);
}

export async function getUtxos(address) {
  if (activeConfig.useRpc) {
    const result = await bitcoinRpc('scantxoutset', ['start', [`addr(${address})`]]);
    return (result.unspents || []).map(u => ({
      txid: u.txid, vout: u.vout, value: Math.round(u.amount * 1e8),
      status: { confirmed: true },
    }));
  }
  return esploraApi(`/address/${address}/utxo`);
}

export async function selectUtxo(address, minValue) {
  const utxos = await getUtxos(address);
  const confirmed = utxos.filter(u => u.status?.confirmed !== false);
  confirmed.sort((a, b) => a.value - b.value);
  const pick = confirmed.find(u => u.value >= minValue);
  if (!pick) throw new Error(`No UTXO >= ${minValue} sat for ${address} (have ${confirmed.length} UTXOs)`);
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
    network: activeConfig.network,
  }).address;
}

export async function findVout(txid, address) {
  if (activeConfig.useRpc) {
    const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
    for (let i = 0; i < rawTx.vout.length; i++) {
      if (rawTx.vout[i].scriptPubKey.address === address) return i;
    }
    return -1;
  }
  const tx = await esploraApi(`/tx/${txid}`);
  for (let i = 0; i < tx.vout.length; i++) {
    if (tx.vout[i].scriptpubkey_address === address) return i;
  }
  return -1;
}

export async function waitForConfirmation(txid, maxRetries = 60, intervalMs = 5000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      if (activeConfig.useRpc) {
        const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
        if (rawTx.confirmations >= 1) return { confirmations: rawTx.confirmations };
      } else {
        const tx = await esploraApi(`/tx/${txid}`);
        if (tx.status?.confirmed) return { confirmations: 1, block_height: tx.status.block_height };
      }
    } catch (_) {}
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error(`Tx ${txid} not confirmed after ${maxRetries} retries`);
}

// ---- Wallet setup ----

export async function setupRegtestWallet(walletName) {
  try {
    await bitcoinRpc('createwallet', [walletName]);
  } catch (e) {
    if (!e.message.includes('already exists')) throw e;
    try { await bitcoinRpc('loadwallet', [walletName]); } catch (_) {}
  }
  const addr = await bitcoinRpc('getnewaddress', [], walletName);
  await bitcoinRpc('generatetoaddress', [101, addr], walletName);
  return addr;
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
    network: activeConfig.network,
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

export async function verifySwapOutput(txid, expectedAddress, minAmountBtc, { allowUnconfirmed = false } = {}) {
  if (activeConfig.useRpc) {
    const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
    const confirmations = rawTx.confirmations || 0;
    if (!allowUnconfirmed && confirmations < 1) throw new Error(`Swap tx ${txid} not yet confirmed (${confirmations} confs)`);

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

  // Esplora mode
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
    network: activeConfig.network,
  });

  const psbt = new bitcoin.Psbt({ network: activeConfig.network });

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
    network: activeConfig.network,
  });

  const psbt = new bitcoin.Psbt({ network: activeConfig.network });

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
  if (activeConfig.useRpc) {
    return bitcoinRpc('sendrawtransaction', [signedTxHex]);
  }
  // Esplora: POST /tx with raw hex body, returns txid as plain text
  const txid = await esploraApi('/tx', 'POST', signedTxHex);
  return txid.trim();
}

// ---- Build refund transaction (script path spend) ----

export function buildRefundTx(fundingTxid, vout, amountSat, bobAddress, internalPubkey, scriptTree, csvTimeout, fee = 300) {
  const p2tr = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    network: activeConfig.network,
  });

  const redeemOutput = scriptTree.output;
  const p2trSpend = bitcoin.payments.p2tr({
    internalPubkey: Buffer.from(internalPubkey),
    scriptTree,
    redeem: { output: redeemOutput },
    network: activeConfig.network,
  });

  const psbt = new bitcoin.Psbt({ network: activeConfig.network });

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
  if (activeConfig.useRpc) {
    const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
    const witness = rawTx.vin[0].txinwitness;
    if (!witness || witness.length === 0) throw new Error('No witness data');
    return hexToBytes(witness[0]);
  }
  // Esplora: witness field is different
  const tx = await esploraApi(`/tx/${txid}`);
  const witness = tx.vin[0].witness;
  if (!witness || witness.length === 0) throw new Error('No witness data');
  return hexToBytes(witness[0]);
}

// ---- Mine blocks helper ----

export async function mineBlocks(n, address) {
  return bitcoinRpc('generatetoaddress', [n, address]);
}

export { REGTEST, bitcoin, ecc };
