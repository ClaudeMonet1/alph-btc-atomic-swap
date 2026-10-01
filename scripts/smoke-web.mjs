#!/usr/bin/env node
// Load the static page in headless Chromium and report what it did: module
// loading (the vendored bundles and the import map with integrity hashes),
// identity derivation, relay connections, and any page error. Usage:
//   node scripts/smoke-web.mjs [url] [seconds]   (default: http://127.0.0.1:8765/index.html, 25)
// Serve docs/ first, e.g. `python3 -m http.server 8765 --bind 127.0.0.1` from docs/.
import puppeteer from 'puppeteer-core';
const url = process.argv[2] || 'http://127.0.0.1:8765/index.html';
const seconds = Number(process.argv[3] || 25);
const executablePath = process.env.CHROMIUM || '/run/current-system/sw/bin/chromium';
const browser = await puppeteer.launch({ executablePath, headless: true, args: ['--no-sandbox', '--disable-gpu'] });
const page = await browser.newPage();
await page.setCacheEnabled(false);
const console_ = [], errors = [], failed = [];
page.on('console', m => console_.push(`${m.type()}: ${m.text()}`));
page.on('pageerror', e => errors.push(String(e.message || e)));
page.on('requestfailed', r => failed.push(`${r.url()} ${r.failure()?.errorText}`));
await page.goto(url, { waitUntil: 'load' });
await new Promise(r => setTimeout(r, seconds * 1000));
const state = await page.evaluate(() => ({
  relayStatus: document.getElementById('relay-status')?.textContent ?? null,
  hasNsec: !!localStorage.getItem('btc-alph-swap-nsec'),
  text: document.body.innerText.slice(0, 4000),
}));
// BIP327 vectors and adaptor round trip, run by the browser build of musig2.js/adaptor.js
const selftest = await page.evaluate(async () => {
  try {
    const m = await import(new URL('./js/bip327-selftest.js', location.href).href);
    const load = (name) => fetch(new URL('./spec/bip327/' + name, location.href)).then((r) => r.json());
    const results = [...await m.runVectors(load), ...m.runAdaptorRoundTrip(4)];
    return { total: results.length, failed: results.filter((r) => !r.ok).map((r) => `${r.name}: ${r.problem}`) };
  } catch (e) { return { total: 0, failed: ['self-test did not run: ' + (e.message || e)] }; }
});
// QR decoding: a code generated in the page must decode back to the address
const qr = await page.evaluate(async () => {
  try {
    const [{ default: qrcode }, scan] = await Promise.all([import('qrcode-generator'), import(new URL('./js/qrscan.js', location.href).href)]);
    const addr = 'tb1pzz6dfhvdc7yvlerje4mxsqyln8llsxxvhjcf40xuemhefrd50r8ssj6kmv';
    const q = qrcode(0, 'M'); q.addData('bitcoin:' + addr + '?amount=0.001'); q.make();
    const n = q.getModuleCount(), scale = 6, pad = 4 * scale, size = n * scale + 2 * pad;
    const c = document.createElement('canvas'); c.width = size; c.height = size; const ctx = c.getContext('2d');
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, size, size); ctx.fillStyle = '#000';
    for (let r = 0; r < n; r++) for (let col = 0; col < n; col++) if (q.isDark(r, col)) ctx.fillRect(pad + col * scale, pad + r * scale, scale, scale);
    const text = scan.decodeImageData(ctx.getImageData(0, 0, size, size));
    const parsed = scan.addressFromQrText(text);
    return parsed === addr ? 'ok' : `mismatch: ${text}`;
  } catch (e) { return 'error: ' + (e.message || e); }
});
// Service worker registered (installable, offline load)
const sw = await page.evaluate(async () => { try { if (!navigator.serviceWorker) return 'unsupported'; const r = await Promise.race([navigator.serviceWorker.ready, new Promise((res) => setTimeout(() => res(null), 15000))]); return r ? `registered (${r.active?.state})` : 'not ready'; } catch (e) { return 'error: ' + e.message; } });
// The compiled contract artifact must load and match the embedded source
const artifact = await page.evaluate(async () => {
  try { const m = await import(new URL('./js/alph.js', location.href).href); const c = await m.compileSwapContract(); return { codeHash: c.contract.codeHash, bytecodeLen: c.contract.bytecode.length }; }
  catch (e) { return { error: e.message || String(e) }; }
});
// Offline reload: the service worker must serve the precached build (the app then
// runs and reports that the relays are unreachable, which is the expected offline state)
let offline = 'skipped';
const failedBeforeOffline = failed.length;
if (sw.startsWith('registered')) {
  try {
    await page.setOfflineMode(true);
    await page.reload({ waitUntil: 'load' });
    const ok = await page.waitForFunction(() => /npub1[a-z0-9]{20,}|Connection failed|Could not connect/.test(document.body.innerText), { timeout: 20000 }).then(() => true).catch(() => false);
    const text = await page.evaluate(() => document.body.innerText.slice(0, 200).replace(/\s+/g, ' '));
    offline = ok ? 'page loads offline (app ran: ' + (/npub1/.test(text) ? 'identity shown' : 'relays unreachable, as expected') + ')' : 'page did not load offline: ' + text.slice(0, 80);
    await page.setOfflineMode(false);
  } catch (e) { offline = 'error: ' + e.message; }
}
failed.length = failedBeforeOffline; // cross-origin requests fail offline by design
await browser.close();
const npub = (state.text.match(/npub1[a-z0-9]{20,}/) || [])[0];
const btc = (state.text.match(/(?:tb1p|bcrt1p|bc1p)[a-z0-9]{20,}/) || [])[0];
const alph = (state.text.match(/\b[1-9A-HJ-NP-Za-km-z]{44,46}\b/) || [])[0];
console.log('page errors      :', errors.length ? errors : 'none');
console.log('failed requests  :', failed.length ? failed : 'none');
console.log('relay status     :', state.relayStatus);
console.log('key in storage   :', state.hasNsec);
console.log('identity shown   :', { npub: npub?.slice(0, 16), btc: btc?.slice(0, 12), alph: alph?.slice(0, 12) });
console.log('bip327 self-test :', selftest.failed.length ? selftest.failed : `${selftest.total} checks passed`);
console.log('contract artifact:', artifact.error ? artifact.error : `codeHash ${artifact.codeHash.slice(0, 16)}..., ${artifact.bytecodeLen / 2} bytes`);
console.log('qr decode        :', qr);
console.log('service worker   :', sw);
console.log('offline reload   :', offline);
console.log('console (last 8) :'); for (const l of console_.slice(-8)) console.log('  ' + l.slice(0, 160));
const ok = errors.length === 0 && failed.length === 0 && npub && btc && state.hasNsec && selftest.total > 0 && selftest.failed.length === 0 && !artifact.error && !offline.startsWith('page did not load offline') && qr === 'ok';
console.log(ok ? '\nWEB SMOKE OK' : '\nWEB SMOKE FAILED');
process.exit(ok ? 0 : 1);
