// Alephium Contract Operations for Atomic Swap — Browser/Static version
// Testnet-only (public node)

import alphWeb3 from '@alephium/web3';
const { web3, ONE_ALPH, DUST_AMOUNT, addressFromPublicKey, groupOfAddress, buildContractByteCode, buildScriptByteCode } = alphWeb3;
import alphWallet from '@alephium/web3-wallet';
const { PrivateKeyWallet } = alphWallet;

const ALPH_NODE_URL = 'https://node.testnet.alephium.org';
web3.setCurrentNodeProvider(ALPH_NODE_URL);

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

  const params = {
    signerAddress: wallet.address,
    signerKeyType: 'bip340-schnorr',
    bytecode,
    initialAttoAlphAmount: alphAmount,
    gasAmount: 100000,
  };
  if (targetGroup !== undefined) params.group = targetGroup;

  const result = await wallet.signAndSubmitDeployContractTx(params);

  return {
    contractAddress: result.contractAddress,
    contractId: result.contractId,
    txId: result.txId,
    groupIndex: result.groupIndex,
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

  const params = {
    signerAddress: wallet.address,
    signerKeyType: wallet.keyType || 'bip340-schnorr',
    bytecode,
    attoAlphAmount: DUST_AMOUNT,
    gasAmount: 100000,
  };
  if (targetGroup !== undefined) params.group = targetGroup;

  const result = await wallet.signAndSubmitExecuteScriptTx(params);
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

  const result = await wallet.signAndSubmitExecuteScriptTx({
    signerAddress: wallet.address,
    signerKeyType: wallet.keyType || 'bip340-schnorr',
    bytecode,
    attoAlphAmount: DUST_AMOUNT,
    gasAmount: 100000,
  });

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

export async function transferAlph(wallet, destAddress, attoAlphAmount) {
  const result = await wallet.signAndSubmitTransferTx({
    signerAddress: wallet.address,
    signerKeyType: 'bip340-schnorr',
    destinations: [{ address: destAddress, attoAlphAmount: attoAlphAmount.toString() }],
    gasAmount: 20000,
    gasPrice: '100000000000',
  });
  return result.txId;
}

export { web3, ONE_ALPH, DUST_AMOUNT, PrivateKeyWallet, addressFromPublicKey, groupOfAddress };
