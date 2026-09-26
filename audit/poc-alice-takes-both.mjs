#!/usr/bin/env node
// Regression test for the timelock finding of the 2026-09-27 audit
// (alph-btc-bridge/docs/ATOMIC_SWAP_AUDIT.md, S1 and S2). Before the fix the
// ALPH refund opened at 6 h while the BTC refund needed 144 blocks and Bob never
// checked the contract's timeout, so Alice could refund her ALPH and then claim
// Bob's BTC with the completed adaptor signature. This script replays that
// attack with an ALPH timeout that is already reachable: Bob's verification
// must now refuse the contract, and the script fails loudly if it does not.
//
// Runs against the repository's regtest (port 18543) and devnet (22973), like
// src/atomic-swap.js.
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { keyAgg, nonceGen, nonceAgg, hasEvenY, bytesToNum, numTo32b } from '../src/musig2.js';
import { adaptorSign, adaptorVerify, adaptorAggregate, completeAdaptorSig, adaptorExtract, G, Fn, n, pointToBytes } from '../src/adaptor.js';
import { bitcoinRpc, createSwapOutput, buildClaimTx, buildP2TRKeyPathSpend, finalizeKeyPathSpend, broadcastTx, mineBlocks, extractSignatureFromTx, REGTEST, bitcoin } from '../src/btc-swap.js';
import { compileSwapContract, deploySwapContract, claimSwap, refundSwap, verifyContractState, fundFromGenesis, getBalance, waitForTx, web3, ONE_ALPH, PrivateKeyWallet, addressFromPublicKey, groupOfAddress } from '../src/alph-swap.js';
import { computeTweakedKey, computeAdaptorChallenge, computeTweakedPrivateKey } from '../src/taproot-utils.js';
import { btcLocktimeNow, alphTimeoutBounds } from '../src/timelocks.js';

const log = (who, m) => console.log(`[${who}] ${m}`);
web3.setCurrentNodeProvider('http://127.0.0.1:22973');

// same-group keys, as the swap requires
const getGroup = (pub) => groupOfAddress(addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr'));
const aliceSec = schnorr.utils.randomSecretKey();
const alicePub = schnorr.getPublicKey(aliceSec);
let bobSec, bobPub;
do { bobSec = schnorr.utils.randomSecretKey(); bobPub = schnorr.getPublicKey(bobSec); } while (getGroup(bobPub) !== getGroup(alicePub));
const aliceW = new PrivateKeyWallet({ privateKey: bytesToHex(aliceSec), keyType: 'bip340-schnorr' });
const bobW = new PrivateKeyWallet({ privateKey: bytesToHex(bobSec), keyType: 'bip340-schnorr' });
const aliceBtc = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(alicePub), network: REGTEST }).address;
const bobBtc = bitcoin.payments.p2tr({ internalPubkey: Buffer.from(bobPub), network: REGTEST }).address;

await waitForTx((await fundFromGenesis(aliceW.address, ONE_ALPH * 100n)).txId);
await waitForTx((await fundFromGenesis(bobW.address, ONE_ALPH * 5n)).txId);
const hashes = await bitcoinRpc('generatetoaddress', [101, bobBtc]);
const cb = (await bitcoinRpc('getblock', [hashes[0], 2])).tx[0];
const cbVout = cb.vout.findIndex(o => o.scriptPubKey.address === bobBtc);
const cbSat = Math.round(cb.vout[cbVout].value * 1e8);

// Alice's adaptor secret, normalised as the swap does
let tBytes = schnorr.utils.randomSecretKey();
let t = bytesToNum(tBytes);
let T = G.multiply(t);
if (!hasEvenY(T)) { T = T.negate(); t = Fn.neg(t); tBytes = numTo32b(t); }
const { aggPubkey, keyCoeffs, gacc } = keyAgg([alicePub, bobPub]);

// ---- Bob locks 0.5 BTC with the swap's default refund locktime (24 h)
const btcLocktime = btcLocktimeNow();
const BTC_SAT = 50_000_000;
const { address: swapAddr, internalPubkey, scriptTree, p2tr } = createSwapOutput(aggPubkey, bobPub, btcLocktime);
const { psbt: fundPsbt, sighash: fundSighash } = buildP2TRKeyPathSpend(cb.txid, cbVout, cbSat, swapAddr, BTC_SAT, bobPub);
const fundTxHex = finalizeKeyPathSpend(fundPsbt, schnorr.sign(fundSighash, computeTweakedPrivateKey(bobSec, bobPub)));
const fundTxid = await broadcastTx(fundTxHex);
await mineBlocks(1, bobBtc);
const fundVout = (await bitcoinRpc('getrawtransaction', [fundTxid, true])).vout.findIndex(o => o.scriptPubKey.address === swapAddr);
log('BOB', `locked ${BTC_SAT} sat in ${fundTxid}:${fundVout}, refundable at ${btcLocktime}`);

// ---- Alice locks 10 ALPH with a timeout that is already reachable
const compiled = await compileSwapContract();
const ALPH_AMOUNT = ONE_ALPH * 10n;
const deploy = await deploySwapContract(aliceW, bytesToHex(aggPubkey), bobW.address, aliceW.address, Date.now() - 60_000, ALPH_AMOUNT, compiled, bobW.group);
await waitForTx(deploy.txId);
// Bob's verification, as src/nostr-swap.js and src/server.js call it since the fix: with the timeout bounds
const bounds = alphTimeoutBounds(btcLocktime);
let refused = null;
try {
  await verifyContractState(deploy.contractAddress, bytesToHex(aggPubkey), bobW.address, aliceW.address, ALPH_AMOUNT, bounds.maxTimeout, compiled, bounds.minTimeout);
} catch (e) {
  refused = e.message;
}
if (!refused || !refused.includes('timeout too early')) {
  console.log('REGRESSION: Bob accepted a contract whose refund opens before his own');
  process.exit(1);
}
log('BOB', `refused the ALPH contract: ${refused.split('\n').pop().trim()}`);
console.log('\nRESULT: the attack of the audit is stopped at verification; nothing below is reachable in the protocol.');
console.log('The remainder replays the old attack with the check bypassed, to show what it protected against.\n');

// ---- Pre-signatures exchanged as in the swap
const { sighash: btcSighash } = buildClaimTx(fundTxid, fundVout, BTC_SAT, aliceBtc, internalPubkey, scriptTree);
const { Qbytes, tweakScalar, negated } = computeTweakedKey(aggPubkey, p2tr.hash);
const gaccT = negated ? Fn.create(n - gacc) : gacc;
const tacc = negated ? Fn.neg(tweakScalar) : tweakScalar;
const nA = nonceGen(aliceSec, Qbytes, btcSighash), nB = nonceGen(bobSec, Qbytes, btcSighash);
const aggNonce = nonceAgg([nA.pubNonce, nB.pubNonce]);
const psA = adaptorSign(aliceSec, nA.secNonce, aggNonce, keyCoeffs, Qbytes, btcSighash, T, 0, gaccT);
const psB = adaptorSign(bobSec, nB.secNonce, aggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccT);
if (!adaptorVerify(psB, nB.pubNonce, bobPub, aggNonce, keyCoeffs, Qbytes, btcSighash, T, 1, gaccT)) throw new Error('bob presig');
const agg = adaptorAggregate([psA, psB], aggNonce, Qbytes, btcSighash, T);
const e = computeAdaptorChallenge(aggNonce, Qbytes, btcSighash, T);
const sTweaked = numTo32b(Fn.create(bytesToNum(agg.s) + Fn.create(tacc * e)));
const alphMsg = hexToBytes(deploy.contractId);
const mA = nonceGen(aliceSec, aggPubkey, alphMsg), mB = nonceGen(bobSec, aggPubkey, alphMsg);
const alphAggNonce = nonceAgg([mA.pubNonce, mB.pubNonce]);
const alphAgg = adaptorAggregate([
  adaptorSign(aliceSec, mA.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 0, gacc),
  adaptorSign(bobSec, mB.secNonce, alphAggNonce, keyCoeffs, aggPubkey, alphMsg, T, 1, gacc),
], alphAggNonce, aggPubkey, alphMsg, T);
log('BOTH', 'adaptor pre-signatures exchanged and verified');

// ---- Alice refunds her ALPH first ...
const before = (await getBalance(aliceW.address)).balance;
await waitForTx((await refundSwap(aliceW, deploy.contractId, compiled)).txId);
const after = (await getBalance(aliceW.address)).balance;
log('ALICE', `refunded ALPH: +${Number(after - before) / 1e18} ALPH`);

// ---- ... then claims Bob's BTC with the completed adaptor signature (no timelock on the key path)
const sig = completeAdaptorSig(agg.R, sTweaked, tBytes, agg.negR);
if (!schnorr.verify(sig, btcSighash, Qbytes)) throw new Error('completed sig invalid');
const { psbt } = buildClaimTx(fundTxid, fundVout, BTC_SAT, aliceBtc, internalPubkey, scriptTree);
const claimTxid = await broadcastTx(finalizeKeyPathSpend(psbt, sig));
await mineBlocks(1, aliceBtc);
const claimed = (await bitcoinRpc('getrawtransaction', [claimTxid, true])).vout.find(o => o.scriptPubKey.address === aliceBtc);
log('ALICE', `claimed ${claimed.value} BTC in ${claimTxid} (Bob's CLTV refund opens at ${btcLocktime})`);

// ---- Bob extracts t and tries to claim ALPH: the contract no longer exists
const onChain = await extractSignatureFromTx(claimTxid);
const tExtracted = adaptorExtract(onChain.slice(32, 64), sTweaked, agg.negR);
log('BOB', `extracted t ${bytesToHex(tExtracted).slice(0, 16)}... (matches: ${bytesToHex(tExtracted) === bytesToHex(tBytes)})`);
const alphSig = completeAdaptorSig(alphAgg.R, alphAgg.s, tExtracted, alphAgg.negR);
if (!schnorr.verify(alphSig, alphMsg, aggPubkey)) throw new Error('alph sig invalid');
try {
  await waitForTx((await claimSwap(bobW, deploy.contractId, bytesToHex(alphSig), compiled, bobW.group)).txId);
  console.log('UNEXPECTED: Bob claimed ALPH');
} catch (err) {
  log('BOB', `ALPH claim failed: ${String(err.message).slice(0, 160)}`);
}
console.log(`\nRESULT: Alice holds ${claimed.value} BTC and her ${Number(after - before) / 1e18} ALPH back; Bob holds a valid t and nothing else.`);
