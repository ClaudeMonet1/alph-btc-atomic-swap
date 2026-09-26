#!/usr/bin/env node
// Regression test for audit finding W5 (blind signing of node-built Alephium
// transactions): builds real deploy, execute and transfer transactions on the
// devnet, checks that verifyUnsignedTx accepts them, then tampers with each in
// the ways a hostile node could and checks that every tampered transaction is
// refused before signing.
import { web3, codec, addressToBytes, buildContractByteCode, buildScriptByteCode, ONE_ALPH, DUST_AMOUNT, hexToBinUnsafe, binToHex, addressFromPublicKey } from '@alephium/web3';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { compileSwapContract, fundFromGenesis, waitForTx } from '../src/alph-swap.js';
import { verifyUnsignedTx } from '../src/alph-verify.js';

web3.setCurrentNodeProvider('http://127.0.0.1:22973');
const post = (p, b) => fetch('http://127.0.0.1:22973' + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());
const reencode = (u) => binToHex(codec.unsignedTxCodec.encode(u));
const idOf = (u) => codec.UnsignedTxCodec.txId(u);
let failures = 0;
const expectOk = (name, f) => { try { f(); console.log(`ok       ${name}`); } catch (e) { failures++; console.log(`FAIL     ${name}: unexpected refusal: ${e.message}`); } };
const expectRefused = (name, f) => { try { f(); failures++; console.log(`FAIL     ${name}: accepted`); } catch (e) { console.log(`refused  ${name}: ${e.message.slice(0, 90)}`); } };

const sec = schnorr.utils.randomSecretKey(); const pubHex = bytesToHex(schnorr.getPublicKey(sec));
const addr = addressFromPublicKey(pubHex, 'bip340-schnorr');
const otherSec = schnorr.utils.randomSecretKey(); const other = addressFromPublicKey(bytesToHex(schnorr.getPublicKey(otherSec)), 'bip340-schnorr');
await waitForTx((await fundFromGenesis(addr, ONE_ALPH * 30n)).txId);
const compiled = await compileSwapContract();
const bytecode = buildContractByteCode(compiled.contract.bytecode, { swapKey: '11'.repeat(32), claimAddress: other, refundAddress: addr, timeout: 1790000000000n }, compiled.contract.fields, compiled.structs);
const from = { fromPublicKey: pubHex, fromPublicKeyType: 'bip340-schnorr' };

// ---- deploy
const dep = await post('/contracts/unsigned-tx/deploy-contract', { ...from, bytecode, initialAttoAlphAmount: (ONE_ALPH * 10n).toString(), gasAmount: 100000 });
const depExpect = { kind: 'deploy', address: addr, bytecode, initialAttoAlphAmount: ONE_ALPH * 10n, gasAmount: 100000 };
expectOk('deploy as built', () => verifyUnsignedTx(dep.unsignedTx, dep.txId, depExpect));
expectRefused('deploy: forged id', () => verifyUnsignedTx(dep.unsignedTx, '00'.repeat(32), depExpect));
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(dep.unsignedTx)); u.fixedOutputs[0].lockupScript = codec.lockupScript.lockupScriptCodec.decode(addressToBytes(other)); expectRefused('deploy: change paid to another address', () => verifyUnsignedTx(reencode(u), idOf(u), depExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(dep.unsignedTx)); const i = u.statefulScript.value.methods[0].instrs; i[1].value = ONE_ALPH * 19n; expectRefused('deploy: larger deposit into the contract', () => verifyUnsignedTx(reencode(u), idOf(u), depExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(dep.unsignedTx)); const i = u.statefulScript.value.methods[0].instrs; const b = new Uint8Array(i[4].value); b[b.length - 1] ^= 1; i[4].value = b; expectRefused('deploy: contract fields altered', () => verifyUnsignedTx(reencode(u), idOf(u), depExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(dep.unsignedTx)); const i = u.statefulScript.value.methods[0].instrs; i[0].value = codec.lockupScript.lockupScriptCodec.decode(addressToBytes(other)); expectRefused('deploy: approval from another address', () => verifyUnsignedTx(reencode(u), idOf(u), depExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(dep.unsignedTx)); u.gasAmount = 500000; expectRefused('deploy: gas above the request', () => verifyUnsignedTx(reencode(u), idOf(u), depExpect)); }
// submit the honest one so that a script can target it
await post('/transactions/submit', { unsignedTx: dep.unsignedTx, signature: bytesToHex(schnorr.sign(hexToBytes(dep.txId), sec)) }); await waitForTx(dep.txId);
const contractId = binToHex(addressToBytes(dep.contractAddress).slice(1));

// ---- execute
const script = buildScriptByteCode(compiled.refundScript.bytecodeTemplate, { htlc: contractId }, compiled.refundScript.fields, compiled.structs);
const ex = await post('/contracts/unsigned-tx/execute-script', { ...from, bytecode: script, attoAlphAmount: DUST_AMOUNT.toString(), gasAmount: 100000 });
const exExpect = { kind: 'execute', address: addr, bytecode: script, gasAmount: 100000 };
expectOk('execute as built', () => verifyUnsignedTx(ex.unsignedTx, ex.txId, exExpect));
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(ex.unsignedTx)); const otherScript = buildScriptByteCode(compiled.claimScript.bytecodeTemplate, { htlc: contractId, sig: '00'.repeat(64) }, compiled.claimScript.fields, compiled.structs); u.statefulScript = { kind: 'Some', value: codec.script.scriptCodec.decode(hexToBinUnsafe(otherScript)) }; expectRefused('execute: another script substituted', () => verifyUnsignedTx(reencode(u), idOf(u), exExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(ex.unsignedTx)); u.fixedOutputs[0].lockupScript = codec.lockupScript.lockupScriptCodec.decode(addressToBytes(other)); expectRefused('execute: change paid to another address', () => verifyUnsignedTx(reencode(u), idOf(u), exExpect)); }

// ---- transfer
const tr = await post('/transactions/build', { ...from, destinations: [{ address: other, attoAlphAmount: ONE_ALPH.toString() }], gasAmount: 20000, gasPrice: '100000000000' });
const trExpect = { kind: 'transfer', address: addr, destinations: [{ address: other, attoAlphAmount: ONE_ALPH }], gasAmount: 20000 };
expectOk('transfer as built', () => verifyUnsignedTx(tr.unsignedTx, tr.txId, trExpect));
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(tr.unsignedTx)); const dest = u.fixedOutputs.find(o => binToHex(codec.lockupScript.lockupScriptCodec.encode(o.lockupScript)) === binToHex(addressToBytes(other))); dest.amount = ONE_ALPH * 5n; expectRefused('transfer: destination amount inflated', () => verifyUnsignedTx(reencode(u), idOf(u), trExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(tr.unsignedTx)); for (const o of u.fixedOutputs) o.lockupScript = codec.lockupScript.lockupScriptCodec.decode(addressToBytes(other)); expectRefused('transfer: change redirected', () => verifyUnsignedTx(reencode(u), idOf(u), trExpect)); }
{ const u = codec.unsignedTxCodec.decode(hexToBinUnsafe(tr.unsignedTx)); const ue = codec.unsignedTxCodec.decode(hexToBinUnsafe(ex.unsignedTx)); u.statefulScript = ue.statefulScript; expectRefused('transfer: script smuggled in', () => verifyUnsignedTx(reencode(u), idOf(u), trExpect)); }

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
