// Verification of node-built Alephium transactions before signing.
//
// The wallet asks the node to build a transaction and receives an unsigned
// transaction plus its id. Signing the id blindly trusts the node: a hostile
// node could return a transaction that sends the wallet's funds anywhere. So
// the client decodes the unsigned transaction, recomputes the id, and checks
// that the transaction does exactly what was asked:
//   - every fixed output (change) pays the signer's own address, except the
//     destinations of an explicit transfer;
//   - a contract deployment is the canonical script
//       AddressConst(self) U256Const(amount) ApproveAlph
//       BytesConst(code) BytesConst(immFields) BytesConst(mutFields) CreateContract Pop
//     whose three byte constants concatenate to the submitted bytecode and whose
//     amount is the requested deposit;
//   - a script execution carries exactly the submitted script bytecode;
//   - gas does not exceed what was requested.
// Anything else is refused and never signed.
import { codec, addressToBytes, hexToBinUnsafe, binToHex } from '@alephium/web3';

export const MAX_GAS_PRICE = 100_000_000_000n * 10n; // ten times the default gas price

function lockupHex(lockupScript) {
  return binToHex(codec.lockupScript.lockupScriptCodec.encode(lockupScript));
}

function addressHex(address) {
  return binToHex(addressToBytes(address));
}

export function decodeUnsignedTx(unsignedTxHex) {
  return codec.unsignedTxCodec.decode(hexToBinUnsafe(unsignedTxHex));
}

function fail(what) {
  throw new Error(`refusing to sign: ${what}`);
}

// `expect`: { kind: 'deploy' | 'execute' | 'transfer', address, gasAmount,
//   bytecode (deploy: contract bytecode; execute: script bytecode),
//   initialAttoAlphAmount (deploy), destinations: [{ address, attoAlphAmount }] (transfer) }
export function verifyUnsignedTx(unsignedTxHex, txId, expect) {
  const u = decodeUnsignedTx(unsignedTxHex);
  if (codec.UnsignedTxCodec.txId(u) !== txId) fail('transaction id does not match the unsigned transaction');
  if (expect.gasAmount !== undefined && u.gasAmount > expect.gasAmount) fail(`gas ${u.gasAmount} exceeds the requested ${expect.gasAmount}`);
  if (u.gasPrice > MAX_GAS_PRICE) fail(`gas price ${u.gasPrice} exceeds ${MAX_GAS_PRICE}`);
  const self = addressHex(expect.address);

  // Outputs: everything that is not an explicit destination must come back to us.
  const destinations = (expect.destinations || []).map(d => ({ lockup: addressHex(d.address), amount: BigInt(d.attoAlphAmount), seen: false }));
  for (const out of u.fixedOutputs) {
    const lockup = lockupHex(out.lockupScript);
    if (lockup === self) continue;
    const d = destinations.find(x => !x.seen && x.lockup === lockup && x.amount === out.amount);
    if (!d) fail(`output of ${out.amount} to a foreign address ${lockup.slice(0, 16)}...`);
    d.seen = true;
    if (out.tokens.length > 0) fail('token output to a destination was not requested');
  }
  const missing = destinations.find(x => !x.seen);
  if (missing) fail(`requested destination ${missing.lockup.slice(0, 16)}... is not paid`);

  const script = u.statefulScript;
  if (expect.kind === 'transfer') {
    if (script.kind !== 'None') fail('a plain transfer must carry no script');
    return u;
  }
  if (script.kind !== 'Some') fail('missing script');
  const instrs = script.value.methods.flatMap(m => m.instrs);

  if (expect.kind === 'execute') {
    const encoded = binToHex(codec.script.scriptCodec.encode(script.value));
    if (encoded !== expect.bytecode) fail('script differs from the submitted bytecode');
    return u;
  }

  if (expect.kind === 'deploy') {
    const names = instrs.map(i => i.name);
    const shape = ['AddressConst', 'U256Const', 'ApproveAlph', 'BytesConst', 'BytesConst', 'BytesConst', 'CreateContract', 'Pop'];
    if (script.value.methods.length !== 1 || names.length !== shape.length || names.some((n, i) => n !== shape[i])) fail(`deploy script has an unexpected shape: ${names.join(' ')}`);
    if (lockupHex(instrs[0].value) !== self) fail('deploy script approves assets of another address');
    if (BigInt(instrs[1].value) !== BigInt(expect.initialAttoAlphAmount)) fail(`deploy script deposits ${instrs[1].value}, requested ${expect.initialAttoAlphAmount}`);
    const code = binToHex(instrs[3].value) + binToHex(instrs[4].value) + binToHex(instrs[5].value);
    if (code !== expect.bytecode) fail('deploy script creates a contract other than the submitted one');
    return u;
  }
  fail(`unknown expectation ${expect.kind}`);
}
