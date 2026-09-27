#!/usr/bin/env node
// Two headless browsers on the live (or local) page run a swap against each
// other: A publishes an offer, B accepts, both report their step boxes and
// console output. Usage: node scripts/e2e-web.mjs [url] [seconds] [dir]
// dir = buy_alph (A is Bob, the BTC side; default) or sell_alph (A is Alice).
// Profiles persist under E2E_PROFILE_DIR so funded test keys can be reused.
import puppeteer from 'puppeteer-core';
import { mkdirSync } from 'node:fs';
const url = process.argv[2] || 'https://claudemonet1.github.io/alph-btc-atomic-swap/index.html';
const seconds = Number(process.argv[3] || 90);
const dir = process.argv[4] || 'buy_alph';
const profileDir = process.env.E2E_PROFILE_DIR || '/tmp/e2e-profiles';
import { rmSync } from 'node:fs';
if (!process.env.E2E_KEEP) rmSync(profileDir, { recursive: true, force: true }); // fresh keys unless asked to keep funded ones
const executablePath = process.env.CHROMIUM || '/run/current-system/sw/bin/chromium';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function open(name) {
  mkdirSync(`${profileDir}/${name}`, { recursive: true });
  const browser = await puppeteer.launch({ executablePath, headless: true, userDataDir: `${profileDir}/${name}`, args: ['--no-sandbox', '--disable-gpu'] });
  const page = await browser.newPage();
  const logs = [];
  page.on('console', (m) => logs.push(`${m.type()}: ${m.text()}`));
  page.on('pageerror', (e) => logs.push(`PAGEERROR: ${e.message}`));
  page.on('dialog', async (d) => { logs.push(`DIALOG(${d.type()}): ${d.message().slice(0, 200)}`); await d.accept(); });
  await page.goto(url, { waitUntil: 'load' });
  await page.waitForFunction(() => /npub1[a-z0-9]{20,}/.test(document.body.innerText), { timeout: 60000 });
  const ident = await page.evaluate(() => ({
    npub: (document.body.innerText.match(/npub1[a-z0-9]{20,}/) || [])[0],
    btc: (document.body.innerText.match(/tb1p[a-z0-9]{20,}/) || [])[0],
    alph: (document.body.innerText.match(/\b[1-9A-HJ-NP-Za-km-z]{44,46}\b/) || [])[0],
  }));
  return { browser, page, logs, ident, name };
}
const steps = (page) => page.evaluate(() => document.getElementById('steps')?.textContent || '(no steps)');
const balances = (page) => page.evaluate(() => (document.body.innerText.match(/[\d.]+ (?:BTC|ALPH)/g) || []).slice(0, 4).join(' | '));

const A = await open('A'); const B = await open('B');
console.log('A', A.ident, '\nB', B.ident);
await sleep(8000); // relays
console.log('A balances:', await balances(A.page)); console.log('B balances:', await balances(B.page));

// A publishes an offer
await A.page.evaluate((dir) => { document.querySelector(`#direction-toggle button[data-dir="${dir}"]`).click(); document.getElementById('offer-alph').value = '0.5'; document.getElementById('offer-btc-sat').value = '5000'; }, dir);
await A.page.click('#publish-offer-btn');
console.log('A published a', dir, 'offer');
await sleep(4000);
console.log('A offer buttons:', await A.page.evaluate(() => [...document.querySelectorAll('#offers-list button')].map((b) => `${b.className}:${(b.dataset.offer || '').slice(0, 8)}`).join(' ')));
console.log('A identity row npub prefix vs offer author:', await A.page.evaluate(() => (document.body.innerText.match(/npub1[a-z0-9]{20,}/) || [])[0]?.slice(0, 16)));

// A's own offer id, from the Cancel button on its card
const offerId = await A.page.evaluate(async () => {
  for (let i = 0; i < 30; i++) { const b = document.querySelector('.cancel-offer-btn'); if (b) return b.dataset.offer; await new Promise((r) => setTimeout(r, 1000)); }
  return null;
});
console.log('A offer id:', offerId);
// B accepts exactly that offer (never a stranger's)
const accepted = await B.page.evaluate(async (id) => {
  for (let i = 0; i < 60; i++) {
    const btn = document.querySelector(`.accept-offer-btn[data-offer="${id}"]`);
    if (btn) { btn.click(); return id; }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
}, offerId);
console.log('B accepted offer', accepted);

for (let t = 15; t <= seconds; t += 15) {
  await sleep(15000);
  console.log(`\n===== t=${t}s\n--- A (${dir === 'buy_alph' ? 'Bob' : 'Alice'}) steps:\n${await steps(A.page)}\n--- B (${dir === 'buy_alph' ? 'Alice' : 'Bob'}) steps:\n${await steps(B.page)}`);
}
const pageLog = (page) => page.evaluate(() => document.getElementById('app-log')?.textContent || '(no log panel)');
console.log('\n--- A page log:\n' + (await pageLog(A.page)));
console.log('\n--- B page log:\n' + (await pageLog(B.page)));
const errs = (logs) => logs.filter((l) => /PAGEERROR|error:/.test(l) && !/Failed to load resource/.test(l));
console.log('\n--- A errors:', errs(A.logs)); console.log('--- B errors:', errs(B.logs));
console.log('\n--- A raw console:'); for (const l of A.logs) console.log('  ' + l.slice(0, 200));
await A.browser.close(); await B.browser.close();
