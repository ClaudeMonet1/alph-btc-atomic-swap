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
await browser.close();
const npub = (state.text.match(/npub1[a-z0-9]{20,}/) || [])[0];
const btc = (state.text.match(/tb1p[a-z0-9]{20,}/) || [])[0];
const alph = (state.text.match(/\b[1-9A-HJ-NP-Za-km-z]{44,46}\b/) || [])[0];
console.log('page errors      :', errors.length ? errors : 'none');
console.log('failed requests  :', failed.length ? failed : 'none');
console.log('relay status     :', state.relayStatus);
console.log('key in storage   :', state.hasNsec);
console.log('identity shown   :', { npub: npub?.slice(0, 16), btc: btc?.slice(0, 12), alph: alph?.slice(0, 12) });
console.log('console (last 8) :'); for (const l of console_.slice(-8)) console.log('  ' + l.slice(0, 160));
const ok = errors.length === 0 && failed.length === 0 && npub && btc && state.hasNsec;
console.log(ok ? '\nWEB SMOKE OK' : '\nWEB SMOKE FAILED');
process.exit(ok ? 0 : 1);
