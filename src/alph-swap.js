// Alephium Contract Operations for Atomic Swap
// Supports devnet (local) and testnet (public node)

import { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress, buildContractByteCode, buildScriptByteCode } from '@alephium/web3';
import { PrivateKeyWallet } from '@alephium/web3-wallet';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { verifyUnsignedTx } from './alph-verify.js';

const NODE_URL = 'http://127.0.0.1:22973'; // kept for backward compat
let alphNodeUrl = 'http://127.0.0.1:22973';
let alphNetworkName = 'devnet';

export function setAlphNetwork(name) {
  const urls = { devnet: 'http://127.0.0.1:22973', testnet: 'https://node.testnet.alephium.org' };
  if (!urls[name]) throw new Error(`Unknown ALPH network: ${name}`);
  alphNodeUrl = urls[name];
  alphNetworkName = name;
  web3.setCurrentNodeProvider(alphNodeUrl);
}

export function getAlphNetwork() {
  return { name: alphNetworkName, url: alphNodeUrl };
}

// Genesis private keys for devnet (one per group 0-3)
const GENESIS_KEYS = [
  'a642942e67258589cd2b1822c631506632db5a12aabcf413604e785300d762a5',
  'ec8c4e863e4027d5217c382bfc67bd2571f2a75c5e2c487a4c1508c4a7b34774',
  'bd7dd0c4abd3cf8ba2bab3b7a4312b4d5ce43008bf2fba52e05867c57b93f04e',
  '93ae1392670cf06fa35684ba95f4f6d850b7cf49e4cde5e69147e0e1df7b2434',
];

// ---- Node API helpers ----

async function nodeApi(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${alphNodeUrl}${path}`, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Alephium API ${method} ${path}: ${res.status} ${text}`);
  }
  return res.json();
}

// ---- Build through the node, verify, sign, submit ----
// The SDK's signAndSubmit* helpers sign the node's transaction id blindly; this
// path decodes the unsigned transaction first (alph-verify.js).
async function signAndSubmit(wallet, buildPath, buildParams, expect) {
  const result = await nodeApi(buildPath, 'POST', { fromPublicKey: wallet.publicKey, fromPublicKeyType: wallet.keyType || 'bip340-schnorr', ...buildParams });
  verifyUnsignedTx(result.unsignedTx, result.txId, { address: wallet.address, ...expect });
  const sig = schnorr.sign(hexToBytes(result.txId), hexToBytes(wallet.privateKey));
  await nodeApi('/transactions/submit', 'POST', { unsignedTx: result.unsignedTx, signature: bytesToHex(sig) });
  return result;
}

// ---- Ralph contract source ----

export const SWAP_CONTRACT_SOURCE = `
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

// 32-byte contract id from a base58 contract address (strip the type byte).
function contractIdFromAddress(address) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = 0n;
  for (const c of address) num = num * 58n + BigInt(A.indexOf(c));
  return num.toString(16).padStart(66, '0').slice(2);
}

// ---- Compile ----

export async function compileSwapContract() {
  const result = await nodeApi('/contracts/compile-project', 'POST', {
    code: SWAP_CONTRACT_SOURCE,
  });
  // result.contracts[0] = AtomicSwap, result.scripts[0] = ClaimSwap, result.scripts[1] = RefundSwap
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

export async function deploySwapContract(wallet, swapKeyHex, claimAddress, refundAddress, timeoutMs, alphAmount, compiled, targetGroup) {
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

  const params = { bytecode, initialAttoAlphAmount: alphAmount.toString() }; // the node estimates the gas; 100000 below is the ceiling we accept
  if (targetGroup !== undefined) params.group = targetGroup;

  const result = await signAndSubmit(wallet, '/contracts/unsigned-tx/deploy-contract', params, { kind: 'deploy', bytecode, initialAttoAlphAmount: alphAmount, gasAmount: 100000 });

  return {
    contractAddress: result.contractAddress,
    contractId: contractIdFromAddress(result.contractAddress),
    txId: result.txId,
    groupIndex: result.fromGroup,
  };
}

// ---- Claim (Bob calls swap with MuSig2 signature) ----

export async function claimSwap(wallet, contractId, musig2SignatureHex, compiled, targetGroup) {
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

  const params = { bytecode, attoAlphAmount: DUST_AMOUNT.toString() };
  if (targetGroup !== undefined) params.group = targetGroup;

  const result = await signAndSubmit(wallet, '/contracts/unsigned-tx/execute-script', params, { kind: 'execute', bytecode, gasAmount: 100000 });
  return { txId: result.txId };
}

// ---- Refund (Alice calls refund after timeout) ----

export async function refundSwap(wallet, contractId, compiled) {
  const { refundScript, structs } = compiled;

  const bytecode = buildScriptByteCode(
    refundScript.bytecodeTemplate,
    {
      htlc: contractId,
    },
    refundScript.fields,
    structs,
  );

  const result = await signAndSubmit(wallet, '/contracts/unsigned-tx/execute-script', { bytecode, attoAlphAmount: DUST_AMOUNT.toString() }, { kind: 'execute', bytecode, gasAmount: 100000 });

  return { txId: result.txId };
}

// ---- Fund from genesis ----

export async function fundFromGenesis(destAddress, amount) {
  if (alphNetworkName !== 'devnet') throw new Error('fundFromGenesis is only available on devnet. Use faucets on testnet.');
  const genesisKey = GENESIS_KEYS[0];

  web3.setCurrentNodeProvider(alphNodeUrl);
  const genesisWallet = new PrivateKeyWallet({
    privateKey: genesisKey,
    keyType: 'default',
  });

  const result = await genesisWallet.signAndSubmitTransferTx({
    signerAddress: genesisWallet.address,
    destinations: [{
      address: destAddress,
      attoAlphAmount: amount,
    }],
  });

  return { txId: result.txId };
}

// ---- Verify contract state ----

export async function verifyContractState(contractAddress, expectedSwapKey, expectedClaimAddress, expectedRefundAddress, minAmount, maxTimeout, compiled, minTimeout) {
  const state = await nodeApi(`/contracts/${contractAddress}/state`);
  const fields = state.immFields;
  // Fields order matches contract definition: swapKey, claimAddress, refundAddress, timeout
  const swapKey = fields[0].value;
  const claimAddress = fields[1].value;
  const refundAddress = fields[2].value;
  const timeout = BigInt(fields[3].value);

  const errors = [];

  // Verify bytecode matches the expected compiled contract code.
  // On-chain state.bytecode is the code template only (field values are in immFields).
  // Compare against the compiled template directly, not buildContractByteCode output
  // (which appends encoded field values for deployment tx construction).
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

export { NODE_URL, web3, ONE_ALPH, DUST_AMOUNT, PrivateKeyWallet, addressFromPublicKey, groupOfAddress };
