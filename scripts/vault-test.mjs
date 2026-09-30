#!/usr/bin/env node
// Headless check of the passphrase vault: set a passphrase, reload, a wrong
// passphrase is refused, the right one restores the same identity, remove it.
// Usage: node scripts/vault-test.mjs [url]
import puppeteer from 'puppeteer-core';
import { mkdtempSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
const url = process.argv[2] || 'http://127.0.0.1:8765/index.html';
const executablePath = process.env.CHROMIUM || '/run/current-system/sw/bin/chromium';
const profile = mkdtempSync(join(tmpdir(), 'vault-'));
const answers = []; const dialogs = [];
let failed = 0; const check = (n, ok, d = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) failed++; };
async function open() {
  const browser = await puppeteer.launch({ executablePath, headless: true, userDataDir: profile, args: ['--no-sandbox', '--disable-gpu'] });
  const page = await browser.newPage(); await page.setCacheEnabled(false);
  // The page uses in-page modals (modal.js): answer them from a queue injected before load.
  await page.evaluateOnNewDocument((queue) => {
    window.__modalAnswers = queue; window.__modalLog = [];
    new MutationObserver(() => {
      const m = document.getElementById('modal'); if (!m || m.dataset.answered) return;
      m.dataset.answered = '1';
      const msg = m.querySelector('#modal-msg')?.textContent || '';
      const input = m.querySelector('#modal-input');
      const kind = input ? 'prompt' : m.querySelector('#modal-cancel') ? 'confirm' : 'alert';
      window.__modalLog.push(`${kind}: ${msg.slice(0, 60)}`);
      setTimeout(() => {
        if (input) { const a = window.__modalAnswers.shift(); if (a === null || a === undefined) m.querySelector('#modal-cancel').click(); else { input.value = a; m.querySelector('#modal-ok').click(); } }
        else m.querySelector('#modal-ok').click();
      }, 50);
    }).observe(document, { childList: true, subtree: true });
  }, answers.splice(0));
  await page.goto(url, { waitUntil: 'load' });
  return { browser, page };
}
const npubOf = (page) => page.waitForFunction(() => /npub1[a-z0-9]{20,}/.test(document.body.innerText), { timeout: 60000 }).then(() => page.evaluate(() => (document.body.innerText.match(/npub1[a-z0-9]{20,}/) || [])[0]));
const stored = (page) => page.evaluate(() => ({ plain: !!localStorage.getItem('btc-alph-swap-nsec'), enc: !!localStorage.getItem('btc-alph-swap-nsec-enc') }));
const modalLog = (page) => page.evaluate(() => window.__modalLog || []);

answers.push('correct horse battery', 'correct horse battery');
let { browser, page } = await open();
const npub = await npubOf(page);
check('fresh identity stored in clear', (await stored(page)).plain);
await page.click('#passphrase-btn'); await new Promise((r) => setTimeout(r, 5000));
const s1 = await stored(page); check('passphrase set: vault record present, plaintext gone', s1.enc && !s1.plain, JSON.stringify(s1));
await browser.close();

answers.push('wrong passphrase', 'correct horse battery');
({ browser, page } = await open());
const npub2 = await npubOf(page);
const dl = await modalLog(page);
check('wrong passphrase refused then right one accepted', dl.some((d) => d.startsWith('alert: Wrong passphrase')), dl.slice(-3).join(' | '));
check('same identity after unlock', npub2 === npub, `${npub.slice(0, 16)} vs ${npub2?.slice(0, 16)}`);
await page.click('#passphrase-btn'); await new Promise((r) => setTimeout(r, 1500)); // confirm dialog auto-accepted: remove passphrase
const s2 = await stored(page); check('passphrase removed: plaintext back, vault gone', s2.plain && !s2.enc, JSON.stringify(s2));
await browser.close();
console.log(failed ? `VAULT TEST FAILED (${failed})` : 'VAULT TEST PASSED'); process.exit(failed ? 1 : 0);
