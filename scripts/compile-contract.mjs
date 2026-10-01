#!/usr/bin/env node
// Compile the Ralph source once and ship the result as a static artifact for
// the browser build (docs/contracts/atomic-swap.json). The public testnet node
// refuses the compile endpoint from browsers (its CORS preflight returns 403),
// and shipping one artifact also guarantees both parties use identical
// bytecode. Compiles through the devnet node by default (ALPH_NODE overrides).
import { writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { setAlphNetwork, compileSwapContract, SWAP_CONTRACT_SOURCE } from '../src/alph-swap.js';

const browserSource = readFileSync(new URL('../docs/js/alph.js', import.meta.url), 'utf8').match(/const SWAP_CONTRACT_SOURCE = `([\s\S]*?)`;/)[1];
if (browserSource !== SWAP_CONTRACT_SOURCE) throw new Error('docs/js/alph.js embeds a different contract source than src/alph-swap.js');
setAlphNetwork(process.env.ALPH_NODE || 'devnet');
const node = await fetch((process.env.ALPH_NODE === 'testnet' ? 'https://node.testnet.alephium.org' : 'http://127.0.0.1:22973') + '/infos/version').then((r) => r.json()).catch(() => ({}));
const compiled = await compileSwapContract();
const artifact = {
  sourceSha256: createHash('sha256').update(SWAP_CONTRACT_SOURCE).digest('hex'),
  compiledAt: new Date().toISOString(),
  nodeVersion: node.version || 'unknown',
  contract: { name: compiled.contract.name, bytecode: compiled.contract.bytecode, codeHash: compiled.contract.codeHash, fields: compiled.contract.fields },
  claimScript: { name: compiled.claimScript.name, bytecodeTemplate: compiled.claimScript.bytecodeTemplate, fields: compiled.claimScript.fields },
  refundScript: { name: compiled.refundScript.name, bytecodeTemplate: compiled.refundScript.bytecodeTemplate, fields: compiled.refundScript.fields },
  structs: compiled.structs || [],
};
const suffix = process.env.ARTIFACT_NETWORK ? `.${process.env.ARTIFACT_NETWORK}` : ''; // ARTIFACT_NETWORK=mainnet writes atomic-swap.mainnet.json
writeFileSync(new URL(`../docs/contracts/atomic-swap${suffix}.json`, import.meta.url), JSON.stringify(artifact, null, 2) + '\n');
console.log(`docs/contracts/atomic-swap.json written: codeHash ${artifact.contract.codeHash}, compiler ${artifact.nodeVersion}, source sha256 ${artifact.sourceSha256.slice(0, 16)}...`);
