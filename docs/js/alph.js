// Alephium Contract Operations for Atomic Swap — Browser/Static version
// Testnet-only (public node)
// Uses direct node API calls for signing/submission to avoid esm.sh web3 singleton issues.

import alphWeb3 from '@alephium/web3';
const { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress, buildContractByteCode, buildScriptByteCode } = alphWeb3;
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const ALPH_NODE_URL = 'https://node.testnet.alephium.org';
web3.setCurrentNodeProvider(ALPH_NODE_URL);

// Extract 32-byte contract ID from base58-encoded contract address
const contractIdFromAddress = alphWeb3.contractIdFromAddress || ((address) => {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = 0n;
  for (const c of address) num = num * 58n + BigInt(A.indexOf(c));
  return num.toString(16).padStart(66, '0').slice(2); // strip 1-byte prefix
});

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

async function signAndSubmit(buildPath, buildParams, secBytes) {
  const result = await nodeApi(buildPath, 'POST', buildParams);
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

  @using(assetsInContract = true)
  pub fn refund() -> () {
    assert!(blockTimeStamp!() >= timeout, 0)
    checkCaller!(callerAddress!() == refundAddress, 1)
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
  }, secBytes);

  return {
    contractAddress: result.contractAddress,
    contractId: (typeof result.contractId === 'string' && result.contractId.length === 64)
      ? result.contractId
      : contractIdFromAddress(result.contractAddress),
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
  }, secBytes);

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
  }, secBytes);

  return { txId: result.txId };
}

// ---- Verify contract state ----

export async function verifyContractState(contractAddress, expectedSwapKey, expectedClaimAddress, expectedRefundAddress, minAmount, maxTimeout, compiled) {
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

  if (swapKey !== expectedSwapKey) errors.push(`swapKey mismatch: ${swapKey} != ${expectedSwapKey}`);
  if (claimAddress !== expectedClaimAddress) errors.push(`claimAddress mismatch: ${claimAddress} != ${expectedClaimAddress}`);
  if (refundAddress !== expectedRefundAddress) errors.push(`refundAddress mismatch: ${refundAddress} != ${expectedRefundAddress}`);
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
  }, secBytes);
  return result.txId;
}

export { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress };
