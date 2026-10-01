#!/usr/bin/env node
// Bundle the browser dependencies into docs/vendor/ so that the page loads no
// code from a CDN at run time (audit W3): what runs is what the repository
// holds, reviewable and pinned by hash. Rewrites the import map in
// docs/index.html with local paths and an integrity block, and writes
// docs/vendor/SHA256SUMS. `--check` verifies the bundles against SHA256SUMS
// without rebuilding.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(root, 'docs/vendor');

// import-map specifier -> { entry (resolved from node_modules), file }
// The browser code targets @noble/curves 1.8 and @noble/hashes 1.7 (the Node
// code uses 2.x), installed under aliases noble-curves-1 and noble-hashes-1.
// `cjs: true` marks CommonJS packages: their entry is a generated ESM wrapper that
// re-exports every member by name (esbuild alone would expose only `default`, and
// the page uses named imports such as `import { bech32 } from 'bech32'`).
const BUNDLES = [
  { spec: '@noble/curves/secp256k1', entry: 'noble-curves-1/secp256k1', file: 'noble-curves-secp256k1.js' },
  { spec: '@noble/curves/utils', entry: 'noble-curves-1/abstract/utils', file: 'noble-curves-utils.js' },
  { spec: '@noble/hashes/sha256', entry: 'noble-hashes-1/sha256', file: 'noble-hashes-sha256.js' },
  { spec: '@noble/hashes/utils', entry: 'noble-hashes-1/utils', file: 'noble-hashes-utils.js' },
  { spec: '@noble/hashes/hkdf', entry: 'noble-hashes-1/hkdf', file: 'noble-hashes-hkdf.js' },
  { spec: '@noble/hashes/hmac', entry: 'noble-hashes-1/hmac', file: 'noble-hashes-hmac.js' },
  { spec: '@noble/ciphers/chacha', entry: '@noble/ciphers/chacha.js', file: 'noble-ciphers-chacha.js' },
  { spec: 'buffer', entry: 'buffer', file: 'buffer.js', cjs: true },
  { spec: 'bitcoinjs-lib', entry: 'bitcoinjs-lib', file: 'bitcoinjs-lib.js', cjs: true },
  { spec: 'tiny-secp256k1', entry: '@bitcoinerlab/secp256k1', file: 'tiny-secp256k1.js', cjs: true },
  { spec: '@alephium/web3', entry: '@alephium/web3', file: 'alephium-web3.js', cjs: true },
  { spec: 'bech32', entry: 'bech32', file: 'bech32.js', cjs: true },
  { spec: 'qrcode-generator', entry: 'qrcode-generator', file: 'qrcode-generator.js', cjs: true },
  { spec: 'jsqr', entry: 'jsqr', file: 'jsqr.js', cjs: true },
  { spec: '@scure/bip32', entry: '@scure/bip32', file: 'scure-bip32.js' },
  { spec: '@scure/bip39', entry: '@scure/bip39', file: 'scure-bip39.js' },
  { spec: '@scure/bip39/wordlists/english', entry: '@scure/bip39/wordlists/english', file: 'scure-bip39-english.js' },
];

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const RESERVED = new Set(['default', '__esModule']);
function cjsWrapper(entry) {
  const mod = require(entry);
  const names = Object.keys(mod).filter(k => !RESERVED.has(k) && /^[A-Za-z_$][\w$]*$/.test(k));
  return [
    `import * as ns from ${JSON.stringify(entry)};`,
    `const mod = ns.default ?? ns;`,
    `export default mod;`,
    ...names.map(k => `export const ${k} = mod[${JSON.stringify(k)}];`),
  ].join('\n');
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const sha384b64 = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64');

if (process.argv.includes('--check')) {
  const sums = readFileSync(resolve(out, 'SHA256SUMS'), 'utf8').trim().split('\n').map(l => l.split(/\s+/));
  let bad = 0;
  for (const [hash, file] of sums) {
    const actual = sha256(readFileSync(resolve(out, file)));
    if (actual !== hash) { bad++; console.log(`MISMATCH ${file}`); }
  }
  console.log(bad === 0 ? `vendor: ${sums.length} bundles match SHA256SUMS` : `vendor: ${bad} mismatch(es)`);
  process.exit(bad === 0 ? 0 : 1);
}

const banner = '// Bundled by scripts/vendor.mjs from the pinned package in node_modules. Do not edit; rebuild with `npm run vendor`.\n';
const integrity = {};
const sums = [];
for (const b of BUNDLES) {
  const pkgDir = b.entry.split('/').slice(0, b.entry.startsWith('@') ? 2 : 1).join('/');
  const version = JSON.parse(readFileSync(resolve(root, 'node_modules', pkgDir, 'package.json'), 'utf8')).version;
  await build({
    ...(b.cjs ? { stdin: { contents: cjsWrapper(b.entry), resolveDir: root, loader: 'js' } } : { entryPoints: [b.entry] }),
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    outfile: resolve(out, b.file),
    banner: { js: banner + `// ${b.spec} ${version}\n` },
    legalComments: 'inline',
    logLevel: 'error',
    // the browser bundles must use the 1.x noble libraries the page was written against
    alias: { '@noble/curves': 'noble-curves-1', '@noble/hashes': 'noble-hashes-1' },
    define: { 'process.env.NODE_ENV': '"production"' },
  });
  const bytes = readFileSync(resolve(out, b.file));
  integrity[`./vendor/${b.file}`] = sha384b64(bytes);
  sums.push(`${sha256(bytes)}  ${b.file}`);
  console.log(`${b.file.padEnd(28)} ${b.spec} ${version} ${(bytes.length / 1024).toFixed(0)} KB`);
}
writeFileSync(resolve(out, 'SHA256SUMS'), sums.join('\n') + '\n');

// rewrite the import map in docs/index.html
const html = readFileSync(resolve(root, 'docs/index.html'), 'utf8');
const map = { imports: Object.fromEntries(BUNDLES.map(b => [b.spec, `./vendor/${b.file}`])), integrity };
const rewritten = html.replace(/<script type="importmap">[\s\S]*?<\/script>/, `<script type="importmap">\n${JSON.stringify(map, null, 2)}\n</script>`);
if (rewritten === html) throw new Error('import map not found in docs/index.html');
writeFileSync(resolve(root, 'docs/index.html'), rewritten);
console.log('import map rewritten with local paths and integrity hashes');
