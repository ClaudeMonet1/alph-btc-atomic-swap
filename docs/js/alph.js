// Alephium Contract Operations for Atomic Swap — Browser/Static version
// Testnet-only (public node)
// Uses direct node API calls for signing/submission to avoid esm.sh web3 singleton issues.

import alphWeb3 from '@alephium/web3';
const { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress, buildContractByteCode, buildScriptByteCode } = alphWeb3;
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { verifyUnsignedTx } from './alph-verify.js';

const ALPH_NODE_URL = 'https://node.testnet.alephium.org';
export const ALPH_NETWORK = 'testnet';
web3.setCurrentNodeProvider(ALPH_NODE_URL);

// Extract 32-byte contract ID hex from base58-encoded contract address
// Always use manual decode — SDK version may return Uint8Array instead of hex string
function contractIdFromAddress(address) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = 0n;
  for (const c of address) num = num * 58n + BigInt(A.indexOf(c));
  return num.toString(16).padStart(66, '0').slice(2); // strip 1-byte prefix
}

// ---- Node API helpers ----

async function nodeApi(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${ALPH_NODE_URL}${path}`, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Alephium API ${method} ${path}: ${res.status} ${text}`);
  }
  return res.json();
}

// ---- Sign and submit via direct API ----

// Build through the node, verify what came back against what was asked
// (alph-verify.js), and only then sign the transaction id.
async function signAndSubmit(buildPath, buildParams, secBytes, expect) {
  const result = await nodeApi(buildPath, 'POST', buildParams);
  verifyUnsignedTx(result.unsignedTx, result.txId, expect);
  const sig = schnorr.sign(hexToBytes(result.txId), secBytes);
  await nodeApi('/transactions/submit', 'POST', {
    unsignedTx: result.unsignedTx,
    signature: bytesToHex(sig),
  });
  return result;
}

// ---- Ralph contract source ----

const SWAP_CONTRACT_SOURCE = `
Contract AtomicSwap(
  swapKey: ByteVec,
  claimAddress: Address,
  refundAddress: Address,
  timeout: U256
) {
  @using(assetsInContract = true, checkExternalCaller = false)
  pub fn swap(sig: ByteVec) -> () {
    verifyBIP340Schnorr!(selfContractId!(), swapKey, sig)
    destroySelf!(claimAddress)
  }

  // Anyone in the contract's group may trigger the refund once the timeout has
  // passed; the funds always go to refundAddress.
  @using(assetsInContract = true, checkExternalCaller = false)
  pub fn refund() -> () {
    assert!(blockTimeStamp!() >= timeout, 0)
    destroySelf!(refundAddress)
  }
}

TxScript ClaimSwap(htlc: AtomicSwap, sig: ByteVec) {
  htlc.swap(sig)
}

TxScript RefundSwap(htlc: AtomicSwap) {
  htlc.refund()
}
`;

// ---- Compile ----

export async function compileSwapContract() {
  const result = await nodeApi('/contracts/compile-project', 'POST', {
    code: SWAP_CONTRACT_SOURCE,
  });
  const contract = result.contracts.find(c => c.name === 'AtomicSwap');
  const claimScript = result.scripts.find(s => s.name === 'ClaimSwap');
  const refundScript = result.scripts.find(s => s.name === 'RefundSwap');
  if (!contract || !claimScript || !refundScript) {
    throw new Error('Compilation failed: missing contract/script. Got: ' +
      JSON.stringify({ contracts: result.contracts.map(c => c.name), scripts: result.scripts.map(s => s.name) }));
  }
  return { contract, claimScript, refundScript, structs: result.structs || [] };
}

// ---- Deploy ----

export async function deploySwapContract(pubKeyHex, secBytes, swapKeyHex, claimAddress, refundAddress, timeoutMs, alphAmount, compiled) {
  const { contract, structs } = compiled;

  const bytecode = buildContractByteCode(
    contract.bytecode,
    {
      swapKey: swapKeyHex,
      claimAddress,
      refundAddress,
      timeout: BigInt(timeoutMs),
    },
    contract.fields,
    structs,
  );

  const result = await signAndSubmit('/contracts/unsigned-tx/deploy-contract', {
    fromPublicKey: pubKeyHex,
    fromPublicKeyType: 'bip340-schnorr',
    bytecode,
    initialAttoAlphAmount: alphAmount.toString(),
    gasAmount: 100000,
  }, secBytes, { kind: 'deploy', address: addressFromPublicKey(pubKeyHex, 'bip340-schnorr'), bytecode, initialAttoAlphAmount: alphAmount, gasAmount: 100000 });

  return {
    contractAddress: result.contractAddress,
    contractId: contractIdFromAddress(result.contractAddress),
    txId: result.txId,
    groupIndex: result.fromGroup,
  };
}

// ---- Claim (Bob calls swap with MuSig2 signature) ----

export async function claimSwap(pubKeyHex, secBytes, contractId, musig2SignatureHex, compiled) {
  const { claimScript, structs } = compiled;

  const bytecode = buildScriptByteCode(
    claimScript.bytecodeTemplate,
    {
      htlc: contractId,
      sig: musig2SignatureHex,
    },
    claimScript.fields,
    structs,
  );

  const result = await signAndSubmit('/contracts/unsigned-tx/execute-script', {
    fromPublicKey: pubKeyHex,
    fromPublicKeyType: 'bip340-schnorr',
    bytecode,
    attoAlphAmount: DUST_AMOUNT.toString(),
    gasAmount: 100000,
  }, secBytes, { kind: 'execute', address: addressFromPublicKey(pubKeyHex, 'bip340-schnorr'), bytecode, gasAmount: 100000 });

  return { txId: result.txId };
}

// ---- Refund (Alice calls refund after timeout) ----

export async function refundSwap(pubKeyHex, secBytes, contractId, compiled) {
  const { refundScript, structs } = compiled;

  const bytecode = buildScriptByteCode(
    refundScript.bytecodeTemplate,
    {
      htlc: contractId,
    },
    refundScript.fields,
    structs,
  );

  const result = await signAndSubmit('/contracts/unsigned-tx/execute-script', {
    fromPublicKey: pubKeyHex,
    fromPublicKeyType: 'bip340-schnorr',
    bytecode,
    attoAlphAmount: DUST_AMOUNT.toString(),
    gasAmount: 100000,
  }, secBytes, { kind: 'execute', address: addressFromPublicKey(pubKeyHex, 'bip340-schnorr'), bytecode, gasAmount: 100000 });

  return { txId: result.txId };
}

// ---- Verify contract state ----

export async function verifyContractState(contractAddress, expectedSwapKey, expectedClaimAddress, expectedRefundAddress, minAmount, maxTimeout, compiled, minTimeout) {
  const state = await nodeApi(`/contracts/${contractAddress}/state`);
  const fields = state.immFields;
  const swapKey = fields[0].value;
  const claimAddress = fields[1].value;
  const refundAddress = fields[2].value;
  const timeout = BigInt(fields[3].value);

  const errors = [];

  if (compiled) {
    if (state.bytecode !== compiled.contract.bytecode) {
      errors.push('bytecode mismatch: deployed contract does not match expected AtomicSwap bytecode');
    }
  }

  // A contract can only pay addresses of its own group (the node rejects the
  // transaction with InvalidOutputGroupIndex), and only accounts of that group
  // can call it. A claim address in another group could never be paid.
  const contractGroup = groupOfAddress(contractAddress);
  if (groupOfAddress(claimAddress) !== contractGroup) errors.push(`claimAddress ${claimAddress} is in group ${groupOfAddress(claimAddress)} but the contract is in group ${contractGroup}: swap() could never pay it`);
  if (groupOfAddress(refundAddress) !== contractGroup) errors.push(`refundAddress ${refundAddress} is in group ${groupOfAddress(refundAddress)} but the contract is in group ${contractGroup}`);
  if (swapKey !== expectedSwapKey) errors.push(`swapKey mismatch: ${swapKey} != ${expectedSwapKey}`);
  if (claimAddress !== expectedClaimAddress) errors.push(`claimAddress mismatch: ${claimAddress} != ${expectedClaimAddress}`);
  if (refundAddress !== expectedRefundAddress) errors.push(`refundAddress mismatch: ${refundAddress} != ${expectedRefundAddress}`);
  if (minTimeout !== undefined && timeout < BigInt(minTimeout)) errors.push(`timeout too early: ${timeout} < ${minTimeout} (the ALPH refund must open after the BTC refund plus the margin)`);
  if (maxTimeout !== undefined && timeout > BigInt(maxTimeout)) errors.push(`timeout too far: ${timeout} > ${maxTimeout}`);

  const balance = await nodeApi(`/addresses/${contractAddress}/balance`);
  const alphBalance = BigInt(balance.balance);
  if (alphBalance < minAmount) errors.push(`insufficient ALPH: ${alphBalance} < ${minAmount}`);

  if (errors.length > 0) throw new Error('Contract verification failed:\n  ' + errors.join('\n  '));
  return { swapKey, claimAddress, refundAddress, timeout, balance: alphBalance };
}

// ---- Balance check ----

export async function getBalance(address) {
  const result = await nodeApi(`/addresses/${address}/balance`);
  return {
    balance: BigInt(result.balance),
    lockedBalance: BigInt(result.lockedBalance),
  };
}

// ---- Deployment depth ----
// Bob relies on the contract existing with the state he verified. A deployment
// that is reorganised out after he pre-signed would leave him claiming nothing,
// so he waits until the deployment transaction has `minConfirmations` on its
// chain. The transaction must be the one that created `contractAddress` (a
// generated ContractOutput paying it), so a made-up txId cannot vouch for it.
export async function verifyDeployment(txId, contractAddress, minConfirmations, { pollMs = 4000, timeoutMs = 3600_000, onProgress = null } = {}) {
  if (!/^[0-9a-f]{64}$/i.test(txId || '')) throw new Error('deployment txId missing or malformed');
  const details = await nodeApi(`/transactions/details/${txId}`);
  const created = (details.generatedOutputs || []).some((o) => o.type === 'ContractOutput' && o.address === contractAddress);
  if (!created) throw new Error(`transaction ${txId} did not create contract ${contractAddress}`);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const status = await nodeApi(`/transactions/status?txId=${txId}`);
    const confirmations = status.type === 'Confirmed' ? status.chainConfirmations : 0;
    if (onProgress) onProgress(confirmations, minConfirmations);
    if (confirmations >= minConfirmations) return { confirmations };
    if (Date.now() >= deadline) throw new Error(`deployment ${txId} has ${confirmations} of ${minConfirmations} confirmations after ${timeoutMs / 1000}s`);
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

// ---- Wait for tx confirmation ----

export async function waitForTx(txId, maxRetries = 60, intervalMs = 2000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const status = await nodeApi(`/transactions/status?txId=${txId}`);
      if (status.type === 'Confirmed') return status;
    } catch (_) {}
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error(`Tx ${txId} not confirmed after ${maxRetries * intervalMs / 1000}s`);
}

// ---- Simple transfer ----

export async function transferAlph(pubKeyHex, secBytes, destAddress, attoAlphAmount) {
  const result = await signAndSubmit('/transactions/build', {
    fromPublicKey: pubKeyHex,
    fromPublicKeyType: 'bip340-schnorr',
    destinations: [{ address: destAddress, attoAlphAmount: attoAlphAmount.toString() }],
    gasAmount: 20000,
    gasPrice: '100000000000',
  }, secBytes, { kind: 'transfer', address: addressFromPublicKey(pubKeyHex, 'bip340-schnorr'), destinations: [{ address: destAddress, attoAlphAmount }], gasAmount: 20000 });
  return result.txId;
}

export { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress };
