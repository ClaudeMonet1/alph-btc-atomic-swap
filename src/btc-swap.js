// Bitcoin Taproot Operations for Atomic Swap
// Supports dual-mode: RPC (regtest/devnet) and Esplora API (signet)

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

bitcoin.initEccLib(ecc);

// ---- Network configuration ----

const REGTEST = bitcoin.networks.regtest;
const RPC_URL = process.env.BTC_RPC_URL || 'http://127.0.0.1:18443';
const RPC_AUTH = 'Basic ' + Buffer.from(process.env.BTC_RPC_AUTH || 'nostralph:nostralph').toString('base64');

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
  return Math.max(Math.ceil((await estimateFeeRate()) * vBytes), 300);
}

// Current fee rate in sat/vB (regtest: 2; otherwise Esplora's half-hour estimate).
export async function estimateFeeRate() {
  if (activeConfig.useRpc) return 2;
  const fees = await esploraApi('/v1/fees/recommended');
  return Math.max(1, fees.halfHourFee || 1);
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

// Confirmations of a transaction (0 while unconfirmed or unknown).
export async function getConfirmations(txid) {
  if (activeConfig.useRpc) {
    const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
    return rawTx.confirmations || 0;
  }
  const status = await esploraApi(`/tx/${txid}/status`);
  if (!status.confirmed) return 0;
  const tip = parseInt(await esploraApi('/blocks/tip/height'), 10);
  return tip - status.block_height + 1;
}

// Verify that `txid` pays at least `minAmountBtc` to `expectedAddress` and has
// at least `minConfirmations` confirmations, waiting for them if necessary
// (`onProgress(confirmations, needed)` is called on every poll). The output is
// checked before the wait, so a wrong lock is refused at once.
export async function verifySwapOutput(txid, expectedAddress, minAmountBtc, { minConfirmations = 1, pollMs = 15_000, timeoutMs = 6 * 3600 * 1000, onProgress = null } = {}) {
  const minSat = Math.round(minAmountBtc * 1e8);
  let found = false;
  if (activeConfig.useRpc) {
    const rawTx = await bitcoinRpc('getrawtransaction', [txid, true]);
    found = rawTx.vout.some(out => out.scriptPubKey.address === expectedAddress && Math.round(out.value * 1e8) >= minSat);
  } else {
    const tx = await esploraApi(`/tx/${txid}`);
    found = tx.vout.some(out => out.scriptpubkey_address === expectedAddress && out.value >= minSat);
  }
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

// ---- Child-pays-for-parent: spend an unconfirmed P2TR output we own to bump its parent ----
// `parentVbytes` and `parentFee` describe the stuck transaction; the child pays
// enough so that parent plus child reach `feeRate` sat/vB. Returns the child's
// PSBT and sighash for the owner to sign with the tweaked key.
export function buildCpfpChild(parentTxid, vout, outputSat, ownerPubkey, feeRate, parentVbytes, parentFee) {
  const CHILD_VBYTES = 111;
  const wanted = Math.ceil(feeRate * (parentVbytes + CHILD_VBYTES));
  const childFee = Math.max(wanted - parentFee, MIN_CHILD_FEE);
  if (outputSat - childFee < 330) throw new Error(`output too small to bump: ${outputSat} sat, child fee ${childFee} sat`);
  const p2tr = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(ownerPubkey), network: activeConfig.network });
  const psbt = new bitcoin.Psbt({ network: activeConfig.network });
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
  if (activeConfig.useRpc) {
    return bitcoinRpc('sendrawtransaction', [signedTxHex]);
  }
  // Esplora: POST /tx with raw hex body, returns txid as plain text
  const txid = await esploraApi('/tx', 'POST', signedTxHex);
  return txid.trim();
}

// ---- Build refund transaction (script path spend) ----

export function buildRefundTx(fundingTxid, vout, amountSat, bobAddress, internalPubkey, scriptTree, locktime, fee = 300) {
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

// ---- Median time past: what OP_CHECKLOCKTIMEVERIFY compares a timestamp locktime against ----

export async function getMedianTimePast() {
  if (activeConfig.useRpc) {
    const info = await bitcoinRpc('getblockchaininfo');
    return info.mediantime;
  }
  const tip = await esploraApi('/blocks');
  const older = await esploraApi(`/blocks/${tip[tip.length - 1].height - 1}`);
  const times = [...tip, ...older].map(b => b.timestamp).sort((a, b) => b - a).slice(0, 11).sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)];
}

// ---- Regtest: mine 101 blocks to `address` and return a mature coinbase worth at least `minSat` ----
// The regtest subsidy halves every 150 blocks, so a long-lived chain eventually
// pays less than a test needs; the error says so instead of failing later.
export async function mineMatureCoinbase(address, minSat) {
  const hashes = await bitcoinRpc('generatetoaddress', [101, address]);
  for (const hash of hashes.slice(0, hashes.length - 100)) {
    const block = await bitcoinRpc('getblock', [hash, 2]);
    const tx = block.tx[0];
    const vout = tx.vout.findIndex(o => o.scriptPubKey.address === address);
    const sat = Math.round(tx.vout[vout].value * 1e8);
    if (sat >= minSat) return { txid: tx.txid, vout, amountSat: sat };
  }
  const first = await bitcoinRpc('getblock', [hashes[0], 2]);
  throw new Error(`regtest coinbase is ${first.tx[0].vout[0].value} BTC, below the ${minSat / 1e8} BTC the test needs: reset the regtest chain`);
}

// ---- Mine blocks helper ----

export async function mineBlocks(n, address) {
  return bitcoinRpc('generatetoaddress', [n, address]);
}

export { REGTEST, bitcoin, ecc };
