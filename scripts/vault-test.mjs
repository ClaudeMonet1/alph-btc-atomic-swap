#!/usr/bin/env node
// Headless check of the one-time unlock of a key sealed by an older build: a
// vault record and a sealed swap state are written as that build wrote them,
// then the page is loaded; a wrong passphrase is refused, the right one restores
// the same identity, stores the key unsealed and removes the record.
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

// Seal a known secret the way the removed feature did (PBKDF2-SHA256 600k, AES-256-GCM)
const SEC = '11'.repeat(16); // a 12-word identity
const seal = async (page, pass, plaintext) => page.evaluate(async (pass, plaintext) => {
  const enc = new TextEncoder();
  const b64 = (u8) => btoa(String.fromCharCode(...u8));
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext)));
  return JSON.stringify({ v: 1, kdf: 'pbkdf2-sha256', iterations: 600000, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
}, pass, plaintext);

// 1. a page whose key an older build sealed
let { browser, page } = await open();
const npub = await npubOf(page);
const record = await seal(page, 'correct horse battery', SEC);
await page.evaluate((rec) => { localStorage.setItem('btc-alph-swap-nsec-enc', rec); localStorage.removeItem('btc-alph-swap-nsec'); }, record);
check('sealed key in place', (await stored(page)).enc);
await browser.close();

// 2. reload: a wrong passphrase is refused, the right one unlocks and migrates
answers.push('wrong passphrase', 'correct horse battery');
({ browser, page } = await open());
const npub2 = await npubOf(page);
const dl = await modalLog(page);
check('wrong passphrase refused then right one accepted', dl.some((d) => d.startsWith('alert: Wrong passphrase')), dl.slice(-3).join(' | '));
const s1 = await page.evaluate(() => localStorage.getItem('btc-alph-swap-nsec'));
check('key migrated: stored unsealed and unchanged', s1 === SEC, String(s1).slice(0, 20));
const s2 = await stored(page);
check('record removed, plaintext present', s2.plain && !s2.enc, JSON.stringify(s2));
check('identity is the sealed key, not the one created before', npub2 !== npub && /^npub1/.test(npub2 || ''), `${npub2?.slice(0, 16)}`);
await browser.close();

// 3. the page no longer offers the feature
({ browser, page } = await open());
await npubOf(page);
check('no passphrase button', !(await page.evaluate(() => !!document.getElementById('passphrase-btn'))));
await browser.close();
console.log(failed ? `VAULT TEST FAILED (${failed})` : 'VAULT TEST PASSED'); process.exit(failed ? 1 : 0);
