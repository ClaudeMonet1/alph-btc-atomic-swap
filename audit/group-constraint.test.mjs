#!/usr/bin/env node
// Regression test for audit finding S6 (Alephium group constraint). On the
// devnet: (1) the node refuses swap() when claimAddress is in another group
// (InvalidOutputGroupIndex), so such a contract could never pay Bob;
// (2) verifyContractState refuses that contract; (3) refund() is permissionless:
// a third party of the group triggers it after the timeout and Alice is paid.
import { web3, ONE_ALPH, addressFromPublicKey, groupOfAddress } from '@alephium/web3';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState, verifyDeployment, fundFromGenesis, waitForTx, getBalance } from '../src/alph-swap.js';

web3.setCurrentNodeProvider('http://127.0.0.1:22973');
let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`); if (!ok) failures++; };
const keyInGroup = (g) => { for (;;) { const s = schnorr.utils.randomSecretKey(); const p = bytesToHex(schnorr.getPublicKey(s)); const a = addressFromPublicKey(p, 'bip340-schnorr'); if (groupOfAddress(a) === g) return { privateKey: bytesToHex(s), publicKey: p, address: a, keyType: 'bip340-schnorr' }; } };
const alice = keyInGroup(1), relayer = keyInGroup(1), bob = keyInGroup(2), bobSameGroup = keyInGroup(1);
await waitForTx((await fundFromGenesis(alice.address, ONE_ALPH * 40n)).txId);
await waitForTx((await fundFromGenesis(relayer.address, ONE_ALPH * 5n)).txId);
const compiled = await compileSwapContract();
const swapSec = schnorr.utils.randomSecretKey(); const swapKey = bytesToHex(schnorr.getPublicKey(swapSec));

// (1) + (2): claimAddress in another group
{
  const d = await deploySwapContract(alice, swapKey, bob.address, alice.address, BigInt(Date.now() + 3600_000), ONE_ALPH * 10n, compiled);
  await waitForTx(d.txId);
  const sig = bytesToHex(schnorr.sign(hexToBytes(d.contractId), swapSec));
  let refused = null;
  try { await claimSwap(relayer, d.contractId, sig, compiled); } catch (e) { refused = e.message; }
  check('node refuses swap() paying a claimAddress of another group', refused !== null && refused.includes('InvalidOutputGroupIndex'), (refused || 'accepted').slice(0, 80));
  let verifyRefused = null;
  try { await verifyContractState(d.contractAddress, swapKey, bob.address, alice.address, ONE_ALPH * 10n, undefined, compiled); } catch (e) { verifyRefused = e.message; }
  check('verifyContractState refuses a cross-group claimAddress', verifyRefused !== null && verifyRefused.includes('group'), (verifyRefused || 'accepted').split('\n').slice(1, 2).join(''));
}
// (3): permissionless refund pays Alice
{
  const before = BigInt((await getBalance(alice.address)).balance);
  const d = await deploySwapContract(alice, swapKey, bobSameGroup.address, alice.address, BigInt(Date.now() - 1000), ONE_ALPH * 10n, compiled);
  await waitForTx(d.txId);
  const r = await refundSwap(relayer, d.contractId, compiled); await waitForTx(r.txId);
  const after = BigInt((await getBalance(alice.address)).balance);
  check('refund() by a third party pays refundAddress', after > before - ONE_ALPH / 10n, `alice ${before} -> ${after}`);
  const gone = await fetch(`http://127.0.0.1:22973/contracts/${d.contractAddress}/state`).then(r => r.status);
  check('contract destroyed after third-party refund', gone !== 200, `state HTTP ${gone}`);
}
// (4): deployment depth check is bound to the transaction that created the contract
{
  const d = await deploySwapContract(alice, swapKey, bobSameGroup.address, alice.address, BigInt(Date.now() + 3600_000), ONE_ALPH * 10n, compiled);
  await waitForTx(d.txId);
  const other = await fundFromGenesis(relayer.address, ONE_ALPH); await waitForTx(other.txId);
  let ok = false; try { ok = (await verifyDeployment(d.txId, d.contractAddress, 1)).confirmations >= 1; } catch (e) { ok = false; }
  check('verifyDeployment accepts the creating transaction', ok);
  let refused = null; try { await verifyDeployment(other.txId, d.contractAddress, 1); } catch (e) { refused = e.message; }
  check('verifyDeployment refuses a transaction that did not create the contract', refused !== null && refused.includes('did not create'), (refused || 'accepted').slice(0, 80));
  let malformed = null; try { await verifyDeployment(undefined, d.contractAddress, 1); } catch (e) { malformed = e.message; }
  check('verifyDeployment refuses a missing txId', malformed !== null);
}
console.log(failures === 0 ? 'GROUP CONSTRAINT TEST PASSED' : `GROUP CONSTRAINT TEST FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
