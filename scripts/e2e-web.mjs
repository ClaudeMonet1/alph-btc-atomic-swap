#!/usr/bin/env node
// Two headless browsers on the live (or local) page run a swap against each
// other: A publishes an offer, B accepts, both report their step boxes and
// console output. Usage: node scripts/e2e-web.mjs [url] [seconds] [dir]
// dir = buy_alph (A is Bob, the BTC side; default) or sell_alph (A is Alice).
// E2E_MODE=swap (default) | counter (B counter-offers, A accepts the counter) |
// partial (A offers a range with E2E_MIN_ALPH, B fills E2E_FILL_ALPH of it) |
// refund (A aborts once both locks are done; with BTC_RPC_URL set, the harness
// moves the regtest clock past T_btc and expects Bob's page to refund itself).
// Profiles persist under E2E_PROFILE_DIR so funded test keys can be reused.
import puppeteer from 'puppeteer-core';
import { mkdirSync } from 'node:fs';
const url = process.argv[2] || 'https://claudemonet1.github.io/alph-btc-atomic-swap/index.html';
const seconds = Number(process.argv[3] || 90);
const dir = process.argv[4] || 'buy_alph';
const mode = process.env.E2E_MODE || 'swap';
const profileDir = process.env.E2E_PROFILE_DIR || '/tmp/e2e-profiles';
import { rmSync, readFileSync } from 'node:fs';
// E2E_KEYS=<json file with {A:{nsecHex},B:{nsecHex}}> seeds the pages with known keys (funded test keys
// live outside the browser profiles); otherwise fresh profiles and fresh keys every run.
const seededKeys = process.env.E2E_KEYS ? JSON.parse(readFileSync(process.env.E2E_KEYS, 'utf8')) : null;
if (!seededKeys && !process.env.E2E_KEEP) rmSync(profileDir, { recursive: true, force: true });
const executablePath = process.env.CHROMIUM || '/run/current-system/sw/bin/chromium';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function open(name) {
  mkdirSync(`${profileDir}/${name}`, { recursive: true });
  // E2E_DUMPIO=1 copies the browser's own stderr into this log (why a browser died)
  const browser = await puppeteer.launch({ executablePath, headless: true, userDataDir: `${profileDir}/${name}`, args: ['--no-sandbox', '--disable-gpu'], dumpio: !!process.env.E2E_DUMPIO });
  browser.on('disconnected', () => console.log(`${name}: BROWSER DISCONNECTED at ${new Date().toISOString()}`));
  const page = await browser.newPage();
  page.on('close', () => console.log(`${name}: PAGE CLOSED at ${new Date().toISOString()}`));
  await page.setCacheEnabled(false); // Pages sends max-age=600: a reused profile would run a stale build
  // in-page modals (modal.js): confirm and alert are accepted, prompts cancelled
  await page.evaluateOnNewDocument(() => {
    new MutationObserver(() => {
      const m = document.getElementById('modal'); if (!m || m.dataset.answered) return; m.dataset.answered = '1';
      console.log('MODAL: ' + (m.querySelector('#modal-msg')?.textContent || '').slice(0, 80));
      setTimeout(() => (m.querySelector('#modal-input') ? m.querySelector('#modal-cancel') : m.querySelector('#modal-ok')).click(), 50);
    }).observe(document, { childList: true, subtree: true });
  });
  if (seededKeys?.[name]?.nsecHex) await page.evaluateOnNewDocument((hex) => { try { if (!localStorage.getItem('btc-alph-swap-nsec')) localStorage.setItem('btc-alph-swap-nsec', hex); } catch {} }, seededKeys[name].nsecHex);
  const logs = [];
  page.on('console', (m) => logs.push(`${m.type()}: ${m.text()}`));
  page.on('pageerror', (e) => logs.push(`PAGEERROR: ${e.message}`));
  page.on('framenavigated', (f) => { if (f === page.mainFrame()) logs.push(`NAVIGATED: ${f.url().slice(0, 120)}`); });
  page.on('error', (e) => logs.push(`CRASH: ${e.message}`));
  page.on('dialog', async (d) => { logs.push(`DIALOG(${d.type()}): ${d.message().slice(0, 200)}`); await d.accept(); });
  await page.goto(url, { waitUntil: 'load' });
  await page.waitForFunction(() => /npub1[a-z0-9]{20,}/.test(document.body.innerText), { timeout: 60000 });
  const ident = await page.evaluate(() => ({
    npub: (document.body.innerText.match(/npub1[a-z0-9]{20,}/) || [])[0],
    btc: (document.body.innerText.match(/(?:tb1p|bcrt1p|bc1p)[a-z0-9]{20,}/) || [])[0],
    alph: (document.body.innerText.match(/\b[1-9A-HJ-NP-Za-km-z]{44,46}\b/) || [])[0],
  }));
  return { browser, page, logs, ident, name };
}
const steps = (page) => page.evaluate(() => document.getElementById('steps')?.textContent || '(no steps)');
const balances = (page) => page.evaluate(() => (document.body.innerText.match(/[\d.]+ (?:BTC|ALPH)/g) || []).slice(0, 4).join(' | '));

const A = await open('A'); const B = await open('B');
const aliceP = () => (dir === 'buy_alph' ? B : A), bobP = () => (dir === 'buy_alph' ? A : B); // dir is A's side
process.on('uncaughtException', (e) => { console.log('HARNESS ERROR:', e.message); console.log('--- A console:'); for (const l of A.logs.slice(-25)) console.log('  ' + l.slice(0, 200)); console.log('--- B console:'); for (const l of B.logs.slice(-25)) console.log('  ' + l.slice(0, 200)); process.exit(1); });
console.log('A', A.ident, '\nB', B.ident);
await sleep(8000); // relays
console.log('A balances:', await balances(A.page)); console.log('B balances:', await balances(B.page));
// Funds left on the pre-2026-09-27 single-key addresses: move them to the derived addresses first
for (const P of [A, B]) {
  const moved = await P.page.evaluate(async () => {
    const b = document.getElementById('legacy-sweep-btn'); if (!b) return false; b.click();
    for (let i = 0; i < 30; i++) { await new Promise((r) => setTimeout(r, 2000)); if (b.disabled === false || !document.body.contains(b) || b.textContent !== 'Moving...') break; }
    return document.getElementById('app-log')?.textContent.match(/Legacy [A-Z]+ \([a-z-]+\) (?:swept in [0-9a-f]+|failed: [^\n]*)/g) || ['clicked, no sweep line yet'];
  });
  if (moved) console.log(P.name, 'legacy funds:', moved);
}
await sleep(3000);
console.log('A balances after sweep:', await balances(A.page)); console.log('B balances after sweep:', await balances(B.page));
// E2E_SWEEP_ONLY=1 stops here (let the swept coins confirm before swapping)
if (process.env.E2E_SWEEP_ONLY) { await A.browser.close(); await B.browser.close(); process.exit(0); }

// A reloaded page recovers its swap but waits for a human to press Resume (it never
// re-locks or re-deploys on its own): the harness presses it.
const resumeIfOffered = async (P, tries = 20) => {
  const clicked = await P.page.evaluate(async (n) => {
    for (let i = 0; i < n; i++) {
      const b = document.getElementById('recovery-resume-btn');
      if (b) { b.click(); return true; }
      await new Promise((r) => setTimeout(r, 1000));
    }
    return false;
  }, tries).catch((e) => `error: ${e.message.slice(0, 60)}`);
  console.log(`${P.name}: resume button ${clicked === true ? 'clicked' : clicked || 'not offered'}`);
  return clicked === true;
};

// E2E_RESUME=1: the pages hold a swap in progress (saved checkpoints); watch it to the end without publishing anything
let offerId = null, accepted = null;
if (!process.env.E2E_RESUME) {
// A publishes an offer
await A.page.evaluate(({ dir, alph, sat, minAlph }) => { document.querySelector(`#direction-toggle button[data-dir="${dir}"]`).click(); document.getElementById('offer-alph').value = alph; document.getElementById('offer-btc-sat').value = sat; const mn = document.getElementById('offer-min-alph'); if (mn) mn.value = minAlph; }, { dir, alph: process.env.E2E_ALPH || '0.5', sat: process.env.E2E_SAT || '5000', minAlph: mode === 'partial' ? (process.env.E2E_MIN_ALPH || '0.1') : '' });
await A.page.click('#publish-offer-btn');
console.log('A published a', dir, 'offer');
await sleep(4000);
console.log('A offer buttons:', await A.page.evaluate(() => [...document.querySelectorAll('#offers-list button')].map((b) => `${b.className}:${(b.dataset.offer || '').slice(0, 8)}`).join(' ')));
console.log('A identity row npub prefix vs offer author:', await A.page.evaluate(() => (document.body.innerText.match(/npub1[a-z0-9]{20,}/) || [])[0]?.slice(0, 16)));

// A's own offer id, from the Cancel button on its card
offerId = await A.page.evaluate(async () => {
  for (let i = 0; i < 30; i++) { const b = document.querySelector('.cancel-offer-btn'); if (b) return b.dataset.offer; await new Promise((r) => setTimeout(r, 1000)); }
  return null;
});
console.log('A offer id:', offerId);

if (mode === 'counter') {
  // B counter-offers a smaller amount; A (the maker) accepts the counter
  const countered = await B.page.evaluate(async (id, alph, sat) => {
    for (let i = 0; i < 60; i++) {
      const btn = document.querySelector(`.counter-offer-btn[data-offer="${id}"]`);
      if (btn) {
        btn.click(); await new Promise((r) => setTimeout(r, 300));
        const form = btn.closest('.offer-card').querySelector('.counter-form'); if (!form) return 'no form';
        form.querySelector('.counter-alph').value = alph; form.querySelector('.counter-sat').value = sat;
        form.querySelector('.submit-counter-btn').click(); return id;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    return null;
  }, offerId, process.env.E2E_COUNTER_ALPH || '0.4', process.env.E2E_COUNTER_SAT || '4000');
  console.log('B countered offer', countered);
  accepted = await A.page.evaluate(async (id) => {
    for (let i = 0; i < 60; i++) {
      const btn = document.querySelector(`.accept-counter-btn[data-offer="${id}"]`);
      if (btn) { btn.click(); return id; }
      await new Promise((r) => setTimeout(r, 1000));
    }
    return null;
  }, offerId);
  console.log('A accepted the counter on', accepted);
} else if (mode === 'partial') {
  // first a hostile accept from a third key with amounts the offer never quoted: the maker must ignore it
  try {
    const { finalizeEvent, getPublicKey } = await import('nostr-tools/pure');
    const WebSocket = (await import('ws')).default;
    const relayUrl = new URL(url).searchParams.get('relays')?.split(',')[0];
    if (relayUrl) {
      // a hostile taker with properly derived keys (Alephium key in group 1), so that only the amounts are wrong
      const { deriveKeys } = await import('../src/keys.js');
      const { addressFromPublicKey, groupOfAddress } = await import('@alephium/web3');
      const sec = crypto.getRandomValues(new Uint8Array(32));
      const hk = deriveKeys(sec, (p, keyType) => groupOfAddress(addressFromPublicKey(p, keyType || 'default')));
      const content = { action: 'accept', offerId, alphAmount: (10n * 10n ** 18n).toString(), btcSat: 100, keys: { btc: hk.btc.pubHex, alph: hk.alph.pubHex } };
      const ev = finalizeEvent({ kind: 38389, created_at: Math.floor(Date.now() / 1000), tags: [['t', 'atomicswap'], ['t', 'accept'], ['p', A.ident.npub], ['d', `${offerId}:accept`]], content: JSON.stringify(content) }, sec);
      await new Promise((resolve) => { const ws = new WebSocket(relayUrl); ws.on('open', () => { ws.send(JSON.stringify(['EVENT', ev])); setTimeout(() => { ws.close(); resolve(); }, 500); }); ws.on('error', resolve); });
      await sleep(2500);
      const ignored = await A.page.evaluate(() => (document.getElementById('app-log')?.textContent || '').includes('Ignoring accept'));
      const started = await A.page.evaluate(() => (document.getElementById('app-log')?.textContent || '').includes('Swap started'));
      console.log('hostile accept (10 ALPH for 100 sat) ignored by the maker:', ignored && !started ? 'yes' : 'NO');
    }
  } catch (e) { console.log('hostile accept check skipped:', e.message); }
  // B fills part of A's range offer through the inline form
  accepted = await B.page.evaluate(async (id, fill) => {
    for (let i = 0; i < 60; i++) {
      const btn = document.querySelector(`.accept-offer-btn[data-offer="${id}"]`);
      if (btn) {
        btn.click(); await new Promise((r) => setTimeout(r, 300));
        const form = btn.closest('.offer-card').querySelector('.accept-form'); if (!form) return 'no fill form';
        form.querySelector('.fill-alph').value = fill; form.querySelector('.fill-alph').dispatchEvent(new Event('input'));
        form.querySelector('.submit-fill-btn').click(); return `${id} fill ${fill}`;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    return null;
  }, offerId, process.env.E2E_FILL_ALPH || '0.3');
} else {
  // B accepts exactly that offer (never a stranger's)
  accepted = await B.page.evaluate(async (id) => {
    for (let i = 0; i < 60; i++) {
      const btn = document.querySelector(`.accept-offer-btn[data-offer="${id}"]`);
      if (btn) { btn.click(); return id; }
      await new Promise((r) => setTimeout(r, 1000));
    }
    return null;
  }, offerId);
}
console.log('B accepted offer', accepted);
} else {
  console.log('resuming the swap held by the saved profiles');
  // Alice first: she must be waiting before Bob republishes his lock message, which a
  // subscription that is already open delivers but one opened afterwards would not replay to a waiter
  await resumeIfOffered(aliceP()); await sleep(5000); await resumeIfOffered(bobP());
}

// Poll both sides; stop early when both have claimed or either side shows an error.
let lastA = '', lastB = '', aborted = false;
const pollMs = mode === 'refund' || mode === 'resume' || mode === 'desync' ? 1000 : 15000; // these drills must catch a phase as it happens
let reloaded = false, desynced = false;
// The desync drill needs the exact moment both sides have committed their nonces: the
// page UI passes through it in under a second, so watch the relay for the two nonce
// events instead and reload Alice right then, while Bob waits for her reveal.
let desyncReady = false;
if (mode === 'desync') {
  const WebSocket = (await import('ws')).default;
  const relayUrl = process.env.E2E_RELAY || 'ws://127.0.0.1:7777';
  const authors = new Set();
  const ws = new WebSocket(relayUrl);
  ws.on('open', () => ws.send(JSON.stringify(['REQ', 'desync', { kinds: [38391], since: Math.floor(Date.now() / 1000) - 5 }])));
  ws.on('message', (raw) => {
    try {
      const m = JSON.parse(raw.toString());
      if (m[0] === 'EVENT' && m[2]?.kind === 38391) {
        authors.add(m[2].pubkey);
        if (authors.size >= 2) { desyncReady = true; try { ws.close(); } catch {} }
      }
    } catch {}
  });
  ws.on('error', (e) => console.log('desync relay watch failed:', e.message));
}
for (let t = pollMs / 1000; t <= seconds; t += pollMs / 1000) {
  await sleep(pollMs);
  // a page or browser that died is reopened on its profile: the app resumes the swap from its saved checkpoint
  const safeSteps = async (P) => {
    try { return await steps(P.page); } catch (e) {
      console.log(`\n===== ${P.name}: ${e.message.slice(0, 120)} (browser ${P.browser.connected ? 'connected' : 'gone'}); reopening the page on its profile`);
      try { if (P.browser.connected) await P.browser.close(); } catch {}
      const fresh = await open(P.name); const oldLogs = P.logs; Object.assign(P, fresh); P.logs = oldLogs.concat(['--- reopened ---'], fresh.logs);
      await resumeIfOffered(P, 25); // the reopened page recovers its swap but waits for Resume
      return await steps(P.page);
    }
  };
  const a = await safeSteps(A), b = await safeSteps(B);
  if (a !== lastA || b !== lastB) {
    console.log(`\n===== t=${t}s (${new Date().toISOString()})\n--- A (${dir === 'buy_alph' ? 'Bob' : 'Alice'}) steps:\n${a.replace(/\n\s*\n/g, '\n')}\n--- B (${dir === 'buy_alph' ? 'Alice' : 'Bob'}) steps:\n${b.replace(/\n\s*\n/g, '\n')}`);
    lastA = a; lastB = b;
  }
  const done = (x) => /5\. Claim\s*✓ Done/.test(x);
  // Desync drill: reload Alice alone once the nonce phase is under way, so her waiters
  // are gone while Bob is still waiting for her reveal. Resume on both sides must heal it.
  if (mode === 'desync' && !desynced && (desyncReady || /3\. Nonces\s*▶ Active/.test(b))) {
    desynced = true;
    const already = /BTC claimed|ALPH claimed/.test(a + b);
    console.log(`\n===== nonce phase reached: reloading Alice alone (Bob keeps waiting), then Resume on both${already ? ' [window missed: a claim is already out, the pair was faster than the drill]' : ''}`);
    await aliceP().page.reload({ waitUntil: 'load' });
    await sleep(6000);
    await resumeIfOffered(aliceP(), 25);
    await sleep(4000);
    await resumeIfOffered(bobP(), 10); // Bob may still be mid-step; Resume is only offered in recovery
    continue;
  }
  // reload both pages mid-protocol, then press Resume: the swap must finish from the saved checkpoints
  if (mode === 'resume' && !reloaded && /BTC locked: [0-9a-f]{16}/.test(dir === 'buy_alph' ? a : b)) {
    reloaded = true;
    console.log('\n===== Bob has locked: reloading both pages, then pressing Resume (Alice first)');
    await Promise.all([A.page.reload({ waitUntil: 'load' }), B.page.reload({ waitUntil: 'load' })]);
    await sleep(5000);
    await resumeIfOffered(aliceP()); await sleep(3000); await resumeIfOffered(bobP());
    continue;
  }
  if (mode === 'refund') {
    // abort as soon as Bob's lock is out and before Alice deploys: Bob's refund is the only way back
    const bobLocked = (x) => /BTC locked: [0-9a-f]{16}/.test(x);
    if (!aborted && bobLocked(dir === 'buy_alph' ? a : b)) {
      aborted = true;
      console.log('\n===== Bob has locked: A aborts (Bob goes to recovery, Alice resets)');
      await A.page.click('#abort-swap-btn'); await sleep(3000);
      if (process.env.BTC_RPC_URL) {
        // regtest: move the clock past T_btc so the shim's next blocks carry a median time past beyond the locktime
        const rpc = async (method, params = []) => { const j = await fetch(process.env.BTC_RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(process.env.BTC_RPC_AUTH || 'nostralph:nostralph').toString('base64') }, body: JSON.stringify({ method, params }) }).then((r) => r.json()); if (j.error) throw new Error(j.error.message); return j.result; };
        await rpc('setmocktime', [Math.floor(Date.now() / 1000) + 26 * 3600]);
        console.log('regtest clock moved 26 h ahead; waiting for the median time past to follow');
      }
    }
    const aLog = await A.page.evaluate(() => (document.getElementById('app-log')?.textContent || '') + (document.getElementById('recovery-status-msg')?.textContent || ''));
    const refunded = /BTC refunded/.test(aLog) || /BTC refunded/.test(a);
    if (refunded) { console.log('\n===== stop: Bob refunded after the abort'); break; }
    if (/✗ Error/.test(a + b) && !aborted) { console.log('\n===== stop: a side reported an error'); break; }
    continue;
  }
  if (mode === 'desync') {
    const logs = (await Promise.all([A.page, B.page].map((p) => p.evaluate(() => (document.getElementById('app-log')?.textContent || '') + (document.getElementById('recovery-status-msg')?.textContent || ''))))).join('\n');
    const btcClaimed = /BTC claimed|claimed the BTC|BTC claim/i.test(logs + a + b), alphClaimed = /ALPH claimed/i.test(logs + a + b);
    if (btcClaimed && alphClaimed) { console.log('\n===== stop: both claims are out (desync healed)'); break; }
    if (/✗ Error/.test(a + b)) console.log('   (a step shows an error; waiting to see whether the pair heals)');
    continue;
  }
  if ((done(a) && done(b)) || /✗ Error/.test(a + b)) { console.log('\n===== stop:', done(a) && done(b) ? 'both sides complete' : 'a side reported an error'); break; }
}
if (mode === 'refund' && process.env.BTC_RPC_URL) console.log('NOTE: the regtest chain now has blocks 26 h in the future; reset it (stop-regtest; rm -rf devnet/bitcoin/regtest; start-regtest) before other runs');
const pageLog = (page) => page.evaluate(() => document.getElementById('app-log')?.textContent || '(no log panel)');
console.log('\n--- A page log:\n' + (await pageLog(A.page)));
console.log('\n--- B page log:\n' + (await pageLog(B.page)));
const errs = (logs) => logs.filter((l) => /PAGEERROR|error:/.test(l) && !/Failed to load resource/.test(l));
console.log('\n--- A errors:', errs(A.logs)); console.log('--- B errors:', errs(B.logs));
console.log('\n--- A raw console:'); for (const l of A.logs) console.log('  ' + l.slice(0, 200));
await A.browser.close(); await B.browser.close();
