// BTC-ALPH Atomic Swap — Static/Browser App
// Replaces server API calls with direct SwapEngine usage.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { bech32 } from 'bech32';
import qrcode from 'qrcode-generator';
import { SwapEngine } from './swap-engine.js';
import { encryptTo as nip44EncryptTo, decryptFrom as nip44DecryptFrom } from './nip44.js';
import { getMedianTimePast, estimateFeeRate } from './btc.js';
import { CLAIM_VBYTES } from './timelocks.js';
import { groupOfAddress, addressFromPublicKey, getBalance } from './alph.js';
import { btcConfirmationsFor } from './timelocks.js';
import { BTC_NETWORK_NAME } from './btc.js';
import { getP2TRAddress } from './btc.js';
import { BUILD } from './build.js';
import { deriveKeys, deriveKeysV1, legacyKeys, mnemonicOf, entropyOf, alphKeyTypeOf, newMasterSecret, isMasterSecret } from './keys.js';
import { deriveVaultKey, newSalt, sealString, openString, saltOf } from './vault.js';
import { modalAlert, modalConfirm, modalPrompt } from './modal.js';
import { addressFromQrText, scanWithCamera } from './qrscan.js';
import { CONFIG, DEFAULTS as CONFIG_DEFAULTS, NETWORK_DEFAULTS, resetConfig, saveConfig } from './config.js';

// GitHub Pages caches every file for ten minutes: a tab opened before a deploy
// runs the old modules. Compare the module build id with version.json fetched
// uncached and say so; two peers on different builds cannot swap.
// ---- Installable page: service worker (offline load, network first) ----
async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.register('./sw.js');
    reg.addEventListener('updatefound', () => { if (reg.active) addLogMsg('system', 'A newer build is being fetched; reload when the banner says so', 'System'); }); // not on the first install
  } catch (e) { addLogMsg('system', `Offline support unavailable: ${e.message}`, 'System'); }
}

// ---- Notifications: only when this tab is not in front ----
function notificationsOn() { return 'Notification' in window && Notification.permission === 'granted' && localStorage.getItem('btc-alph-swap-notify') !== 'off'; }
function notify(title, body, tag = 'swap') {
  try {
    if (!notificationsOn()) return;
    if (document.visibilityState === 'visible' && document.hasFocus()) return;
    new Notification(title, { body, tag, icon: 'icons/icon-192.png' });
  } catch {}
}
function initNotifyButton() {
  const btn = document.getElementById('notify-btn');
  if (!btn) return;
  if (!('Notification' in window)) { btn.hidden = true; return; }
  const on = notificationsOn();
  btn.textContent = on ? '\u{1F514} Notifications on' : Notification.permission === 'denied' ? 'Notifications blocked' : 'Notifications';
  btn.disabled = Notification.permission === 'denied';
}
async function toggleNotifications() {
  if (!('Notification' in window)) return;
  if (notificationsOn()) { localStorage.setItem('btc-alph-swap-notify', 'off'); initNotifyButton(); return; }
  const perm = await Notification.requestPermission();
  if (perm === 'granted') { localStorage.setItem('btc-alph-swap-notify', 'on'); addLogMsg('system', 'Notifications on: you will be told when the peer acts or a wait ends while this tab is in the background', 'System'); }
  initNotifyButton();
}

// Settings: a form for the networks and endpoints (also settable by URL parameters, config.js).
const MAINNET_WARNING = 'MAINNET: real bitcoin and real ALPH.\n\n' +
  '- Bob\'s lock stays locked for 24 h if the swap does not complete; Alice\'s contract for 36 h.\n' +
  '- Confirmation depth scales with the amount (up to 6 Bitcoin blocks).\n' +
  '- This software has been exercised on signet, testnet, regtest and devnet; it has had no mainnet dry run yet.\n' +
  '- Keep amounts small and back up your recovery words first.';
function settingsForm() {
  const v = CONFIG;
  const opt = (sel, list) => list.map((n) => `<option value="${n}" ${sel === n ? 'selected' : ''}>${n}</option>`).join('');
  return `<div class="settings-form">
    <label>Bitcoin network</label><select id="cfg-btcNetwork">${opt(v.btcNetwork, ['signet', 'regtest', 'mainnet'])}</select>
    <label>Bitcoin API (Esplora shape)</label><input id="cfg-btcApi" value="${v.btcApi}">
    <label>Bitcoin explorer</label><input id="cfg-btcExplorer" value="${v.btcExplorer}">
    <label>Alephium network</label><select id="cfg-alphNetwork">${opt(v.alphNetwork, ['testnet', 'devnet', 'mainnet'])}</select>
    <label>Alephium node</label><input id="cfg-alphNode" value="${v.alphNode}">
    <label>Alephium explorer</label><input id="cfg-alphExplorer" value="${v.alphExplorer}">
    <label>Relays (comma separated)</label><input id="cfg-relays" value="${v.relays.join(', ')}">
    <div style="font-size:11px; color:#8b949e; margin-top:8px">Choosing a network fills its public services; edit them for a self-hosted stack. Saving reloads the page. The same values can be given as URL parameters (?btcNetwork=…&btcApi=…&relays=…; ?resetConfig restores the defaults).</div>
  </div>`;
}
async function showSettings() {
  const overlay = document.createElement('div'); overlay.className = 'modal-overlay'; overlay.id = 'modal';
  overlay.innerHTML = `<div class="modal-box"><div id="modal-msg" class="modal-msg"><strong>Settings</strong></div>${settingsForm()}
    <div class="modal-actions"><button class="sm" id="cfg-reset">Defaults</button><button class="sm" id="modal-cancel">Cancel</button><button class="sm primary" id="modal-ok">Save and reload</button></div></div>`;
  document.body.appendChild(overlay);
  const fill = (chain) => { const net = overlay.querySelector(chain === 'btc' ? '#cfg-btcNetwork' : '#cfg-alphNetwork').value; const d = NETWORK_DEFAULTS[chain][net]; if (!d) return; for (const [k, val] of Object.entries(d)) overlay.querySelector(`#cfg-${k}`).value = val; };
  overlay.querySelector('#cfg-btcNetwork').addEventListener('change', () => fill('btc'));
  overlay.querySelector('#cfg-alphNetwork').addEventListener('change', () => fill('alph'));
  overlay.querySelector('#modal-cancel').addEventListener('click', () => overlay.remove());
  overlay.querySelector('#cfg-reset').addEventListener('click', () => { overlay.remove(); resetConfig(); location.href = location.pathname; });
  overlay.querySelector('#modal-ok').addEventListener('click', async () => {
    const values = {};
    for (const k of ['btcNetwork', 'btcApi', 'btcExplorer', 'alphNetwork', 'alphNode', 'alphExplorer']) values[k] = overlay.querySelector(`#cfg-${k}`).value.trim().replace(/\/+$/, '');
    values.relays = overlay.querySelector('#cfg-relays').value.split(',').map((x) => x.trim()).filter(Boolean);
    if (!values.relays.length) { await modalAlert('At least one relay is needed.'); return; }
    if (values.btcNetwork === 'mainnet' || values.alphNetwork === 'mainnet') {
      overlay.remove();
      const typed = await modalPrompt(MAINNET_WARNING + '\n\nType MAINNET to switch:', { placeholder: 'MAINNET' });
      if (typed !== 'MAINNET') { addLogMsg('system', 'Mainnet not enabled', 'System'); return; }
    } else overlay.remove();
    saveConfig(values);
    location.href = location.pathname;
  });
}
// Mainnet: a persistent banner and a confirmation before any swap is published or taken.
async function confirmMainnet(action) {
  if (!CONFIG.isMainnet) return true;
  return modalConfirm(`${MAINNET_WARNING}\n\nProceed to ${action}?`, 'Proceed on mainnet');
}
function applyNetworkUi() {
  const label = document.querySelector('.network-badge');
  if (label) { label.textContent = `${CONFIG.btcNetwork.toUpperCase()} / ALPH ${CONFIG.alphNetwork.toUpperCase()}`; if (CONFIG.isMainnet) { label.classList.remove('testnet'); label.classList.add('mainnet'); } }
  if (CONFIG.btcNetwork !== 'signet' || CONFIG.alphNetwork !== 'testnet') document.body.classList.add('no-faucet');
  if (CONFIG.isMainnet) {
    const div = document.createElement('div'); div.className = 'mainnet-banner'; div.id = 'mainnet-banner';
    div.textContent = `MAINNET: real funds (BTC ${CONFIG.btcNetwork}, ALPH ${CONFIG.alphNetwork}). Locks last 24 h, confirmations scale with the amount, no mainnet dry run has been done yet. Keep amounts small.`;
    document.body.prepend(div);
    addLogMsg('system', 'MAINNET configuration active: real funds', 'Warning');
  }
  if (!CONFIG.isDefault) addLogMsg('system', `Custom endpoints: BTC ${CONFIG.btcNetwork} ${CONFIG.btcApi}; ALPH ${CONFIG.alphNetwork} ${CONFIG.alphNode}; relays ${CONFIG.relays.join(', ')}`, 'System');
}

async function checkBuild() {
  try {
    const res = await fetch(new URL('../version.json', import.meta.url), { cache: 'no-store' });
    const { build } = await res.json();
    addLogMsg('system', `Build ${BUILD}${build === BUILD ? '' : ` (a newer build ${build} is published: reload with Ctrl+Shift+R before swapping)`}`, 'System');
    if (build !== BUILD) {
      const el = document.getElementById('connect-status') || document.body;
      const div = document.createElement('div');
      div.style.cssText = 'background:#d29922;color:#000;padding:8px;font-size:13px;text-align:center';
      div.textContent = `This tab runs build ${BUILD}; the published build is ${build}. Reload with Ctrl+Shift+R (or clear the cache) before swapping: peers on different builds cannot swap.`;
      document.body.prepend(div);
    }
  } catch (e) { addLogMsg('system', `Build ${BUILD} (version check failed: ${e.message})`, 'System'); }
}
import { PetriNetViewer } from './petri-viewer.js';

// ============================================================
// State
// ============================================================

const state = {
  // Identity
  engine: null,
  secBytes: null,
  pubKeyHex: null,
  npub: null,
  btcAddress: null,
  alphAddress: null,
  nsecBech32: null,
  network: 'testnet',
  startedAt: Math.floor(Date.now() / 1000), // page load; older accepts are history, not a swap to start
  lastEventAt: 0, lastPeerEventAt: 0, lastSwapEvent: null,
  swapRun: null, // token of the step chain in progress; replaced on reset, abort or recovery
  offerFilter: { dir: 'all', sort: 'newest', hideMine: false },
  market: null, // { satPerAlph, at } reference rate from CoinGecko, when reachable
  history: new Map(), // pubkey -> { completed: Set(attester), started: Set(attester) } from public attestations
  // Relays
  relays: [],
  seenEvents: new Set(),
  subscriptions: new Map(),
  activeSubscriptions: new Map(),  // subId → { filters, onEvent } for reconnection
  // Offers
  offers: new Map(),
  myOffers: new Set(),
  // Active swap
  activeSwap: null,
  // Swap execution
  stepData: {},
  selectedUtxo: null,
};

// ============================================================
// Multi-Relay Nostr Client
// ============================================================

const DEFAULT_RELAYS = CONFIG.relays;

function connectRelay(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const timer = setTimeout(() => { ws.close(); reject(new Error(`timeout: ${url}`)); }, 8000);
    ws.onopen = () => { clearTimeout(timer); resolve(ws); };
    ws.onerror = () => { clearTimeout(timer); reject(new Error(`error: ${url}`)); };
  });
}

async function connectRelays(urls) {
  const statusEl = document.getElementById('connect-status');
  const results = await Promise.allSettled(urls.map(async (url) => {
    if (statusEl) statusEl.textContent = `Connecting to ${url.replace('wss://','')}...`;
    const ws = await connectRelay(url);
    return { ws, url, ready: true };
  }));
  const connected = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  const failed = results.filter(r => r.status === 'rejected').map((r, i) => urls[i]);
  if (failed.length > 0) console.warn('Failed relays:', failed);
  if (connected.length === 0) throw new Error('Could not connect to any relay. Check your network connection.');
  state.relays = connected;
  for (const relay of connected) setupRelayReconnect(relay);
  return connected;
}

function setupRelayReconnect(relay) {
  const reconnect = () => {
    relay.ready = false;
    updateRelayStatus();
    setTimeout(async () => {
      try {
        const ws = await connectRelay(relay.url);
        relay.ws = ws;
        relay.ready = true;
        setupRelayReconnect(relay);
        resubscribeRelay(relay);
        updateRelayStatus();
        addLogMsg('system', `Reconnected to ${relay.url.replace('wss://', '')}`, 'System');
        // the peer may have missed our last message while this relay was down
        if (state.activeSwap && state.lastSwapEvent) {
          try { relay.ws.send(JSON.stringify(['EVENT', state.lastSwapEvent])); addLogMsg('system', 'Republished the last swap message', 'System'); } catch {}
        }
      } catch {
        reconnect();  // retry on failure
      }
    }, 5000);
  };
  relay.ws.onclose = reconnect;
  relay.ws.onerror = () => {};  // onclose fires after onerror
}

function resubscribeRelay(relay) {
  for (const [subId, { filters, onEvent }] of state.activeSubscriptions) {
    const handler = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg[0] === 'EVENT' && msg[1] === subId) {
          const event = msg[2];
          if (state.seenEvents.has(event.id)) return;
          state.seenEvents.add(event.id);
          state.lastEventAt = Date.now();
          try { onEvent(event); }
          catch (err) { console.error('event handler failed', subId, event.kind, err); addLogMsg('error', `Handling a kind ${event.kind} event failed: ${err.message}`, 'Error'); }
        }
      } catch {}
    };
    relay.ws.addEventListener('message', handler);
    try { relay.ws.send(JSON.stringify(['REQ', subId, ...filters])); } catch {}
  }
}

function nostrSerialize(event) {
  return JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
}

async function signEvent(template) {
  const event = { ...template, pubkey: state.pubKeyHex };
  const serialized = new TextEncoder().encode(nostrSerialize(event));
  const id = bytesToHex(sha256(serialized));
  event.id = id;
  event.sig = bytesToHex(schnorr.sign(hexToBytes(id), state.keys.nostr.sec));
  return event;
}

// Publish with retries (2 s, 4 s, ... up to a minute): a relay hiccup must not
// abort a swap step. Swap messages are remembered so a reconnect can republish
// the last one (replaceable events make that idempotent).
async function nostrPublish(event) {
  if (event.kind >= SWAP_SETUP_KIND && event.kind <= SWAP_CLAIM_KIND) state.lastSwapEvent = event;
  let delay = 2000, lastErr;
  for (let attempt = 1; attempt <= 6; attempt++) {
    try { return await publishOnce(event); }
    catch (e) {
      lastErr = e;
      addLogMsg('system', `Publish failed (${e.message}); retry ${attempt}/6 in ${delay / 1000} s`, 'System');
      await new Promise((r) => setTimeout(r, delay)); delay = Math.min(delay * 2, 30000);
    }
  }
  throw lastErr;
}

function publishOnce(event) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    let errors = 0;
    const timer = setTimeout(() => { if (!resolved) reject(new Error('publish timeout')); }, 10000);

    for (const relay of state.relays) {
      if (!relay.ready || relay.ws.readyState !== WebSocket.OPEN) { errors++; continue; }
      const handler = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg[0] === 'OK' && msg[1] === event.id) {
            relay.ws.removeEventListener('message', handler);
            if (!resolved) { resolved = true; clearTimeout(timer); resolve(msg[2]); }
          }
        } catch {}
      };
      relay.ws.addEventListener('message', handler);
      try { relay.ws.send(JSON.stringify(['EVENT', event])); }
      catch { errors++; relay.ws.removeEventListener('message', handler); }
    }
    if (errors >= state.relays.length) {
      clearTimeout(timer);
      reject(new Error('No relays available'));
    }
  });
}

function subscribe(subId, filters, onEvent) {
  // Track for reconnection
  state.activeSubscriptions.set(subId, { filters, onEvent });

  const handlers = [];
  for (const relay of state.relays) {
    if (!relay.ready || relay.ws.readyState !== WebSocket.OPEN) continue;
    const handler = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg[0] === 'EVENT' && msg[1] === subId) {
          const event = msg[2];
          if (state.seenEvents.has(event.id)) return;
          state.seenEvents.add(event.id);
          state.lastEventAt = Date.now();
          onEvent(event);
        }
      } catch {}
    };
    relay.ws.addEventListener('message', handler);
    try { relay.ws.send(JSON.stringify(['REQ', subId, ...filters])); } catch {}
    handlers.push({ ws: relay.ws, handler });
  }
  const unsub = () => {
    state.activeSubscriptions.delete(subId);
    for (const { ws, handler } of handlers) {
      ws.removeEventListener('message', handler);
      try { ws.send(JSON.stringify(['CLOSE', subId])); } catch {}
    }
  };
  state.subscriptions.set(subId, unsub);
  return unsub;
}

const swapEventWaiters = [];

// Waits that span the peer's on-chain confirmation wait (lock and claim phases)
// get CHAIN_WAIT_MS; the timelocks are the real deadline, and the user can abort.
const CHAIN_WAIT_MS = 6 * 3600 * 1000;
const BTC_BLOCK_HINT = BTC_NETWORK_NAME === 'signet' ? 'a signet block takes 10 to 20 min' : 'about 10 min per block';
const ALPH_BLOCK_HINT = 'about 16 s per block';
const fmtRemaining = (ms) => { if (ms <= 0) return 'now'; const h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000); return h ? `${h} h ${m} min` : `${m} min`; };
function waitForSwapEvent(kind, sessionId, fromPub, predicate = null, timeoutMs = 3600_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const idx = swapEventWaiters.findIndex(w => w.resolve === resolve);
      if (idx >= 0) swapEventWaiters.splice(idx, 1);
      reject(new Error(`timeout waiting for kind ${kind}`));
    }, timeoutMs);
    swapEventWaiters.push({ kind, fromPub, predicate, resolve, reject, timer });
  });
}

// ============================================================
// Event Kinds & Builders
// ============================================================

const SWAP_OFFER_KIND = 38389;
const SWAP_SETUP_KIND = 38390;
const SWAP_NONCE_KIND = 38391;
const SWAP_PRESIG_KIND = 38392;
const SWAP_CLAIM_KIND = 38393;

// ============================================================
// NIP-44 v2 encryption of every swap message (nip44.js; NIP-04 until 2026-09-27)
// ============================================================

async function nip04Encrypt(plaintext, peerPubHex) {
  return nip44EncryptTo(state.keys.nostr.sec, peerPubHex, plaintext);
}

async function nip04Decrypt(ciphertext, peerPubHex) {
  return nip44DecryptFrom(state.keys.nostr.sec, peerPubHex, ciphertext);
}

function generateUUID() {
  return crypto.randomUUID ? crypto.randomUUID() : bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

async function createOfferEvent({ offerId, direction, alphAmount, btcSat, expiresAt, minAlph }) {
  return signEvent({
    kind: SWAP_OFFER_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', 'atomicswap'], ['t', 'offer'], ['d', offerId]],
    content: JSON.stringify({
      action: 'offer',
      offerId,
      direction,
      alphAmount: String(alphAmount),
      btcSat,
      network: state.network,
      expiresAt,
      keys: { btc: state.keys.btc.pubHex, alph: state.keys.alph.pubHex },
      ...(minAlph ? { minAlph: String(minAlph) } : {}), // partial fills allowed down to minAlph, at the same rate
    }),
  });
}

async function createOfferNote(offerEvent, { direction, alphAmount, btcSat }) {
  const alphVal = Number(BigInt(alphAmount)) / 1e18;
  const rate = Math.round(btcSat / alphVal);
  const verb = direction === 'sell_alph' ? 'Selling' : 'Buying';
  const text = [
    `${verb} ${alphVal} ALPH for ${btcSat.toLocaleString()} sats (${rate.toLocaleString()} sat/ALPH)`,
    `\u26a0 Testnet only \u2014 BTC signet + ALPH testnet coins, no real value`,
    `Peer-to-peer atomic swap \u2014 MuSig2 adaptor signatures, no custodian`,
    `https://claudemonet1.github.io/alph-btc-atomic-swap/`,
  ].join('\n');
  return signEvent({
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['e', offerEvent.id], ['t', 'atomicswap'], ['t', 'bitcoin'], ['t', 'alephium']],
    content: text,
  });
}

async function createCounterEvent({ offerId, offerEventId, offerCreator, index, alphAmount, btcSat, message }) {
  return signEvent({
    kind: SWAP_OFFER_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', 'atomicswap'], ['t', 'counter'], ['e', offerEventId], ['p', offerCreator], ['d', `${offerId}:counter:${index}`]],
    content: JSON.stringify({
      action: 'counter',
      offerId,
      alphAmount: String(alphAmount),
      btcSat,
      message: message || '',
      keys: { btc: state.keys.btc.pubHex, alph: state.keys.alph.pubHex },
    }),
  });
}

async function createAcceptEvent({ offerId, offerEventId, offerCreator, alphAmount, btcSat, counterparty }) {
  const payload = { action: 'accept', offerId, alphAmount: String(alphAmount), btcSat, keys: { btc: state.keys.btc.pubHex, alph: state.keys.alph.pubHex } };
  if (counterparty) payload.counterparty = counterparty;
  return signEvent({
    kind: SWAP_OFFER_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', 'atomicswap'], ['t', 'accept'], ['e', offerEventId], ['p', offerCreator], ['d', `${offerId}:accept`]],
    content: JSON.stringify(payload),
  });
}

async function createCancelEvent({ offerId, offerEventId, matchedPub }) {
  const payload = { action: 'cancel', offerId };
  if (matchedPub) payload.matchedPub = matchedPub;
  return signEvent({
    kind: SWAP_OFFER_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', 'atomicswap'], ['t', 'cancel'], ['e', offerEventId], ['d', `${offerId}:cancel`]],
    content: JSON.stringify(payload),
  });
}

async function createSwapSetup({ sessionId, recipientPubHex, msgType, ...data }) {
  const plaintext = JSON.stringify({ type: msgType, ...data });
  const content = await nip04Encrypt(plaintext, recipientPubHex);
  return signEvent({
    kind: SWAP_SETUP_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['e', sessionId], ['p', recipientPubHex], ['d', `${sessionId}:${msgType}`]],
    content,
  });
}

async function createSwapNonce({ sessionId, recipientPubHex, phase, ...data }) {
  const plaintext = JSON.stringify({ phase, ...data });
  const content = await nip04Encrypt(plaintext, recipientPubHex);
  return signEvent({
    kind: SWAP_NONCE_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['e', sessionId], ['p', recipientPubHex], ['d', `${sessionId}:${phase}`]],
    content,
  });
}

async function createSwapPresig({ sessionId, recipientPubHex, ...data }) {
  const plaintext = JSON.stringify(data);
  const content = await nip04Encrypt(plaintext, recipientPubHex);
  return signEvent({
    kind: SWAP_PRESIG_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['e', sessionId], ['p', recipientPubHex], ['d', sessionId]],
    content,
  });
}

async function createSwapClaim({ sessionId, recipientPubHex, claimType, ...data }) {
  const plaintext = JSON.stringify({ type: claimType, ...data });
  const content = await nip04Encrypt(plaintext, recipientPubHex);
  return signEvent({
    kind: SWAP_CLAIM_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['e', sessionId], ['p', recipientPubHex], ['d', `${sessionId}:${claimType}`]],
    content,
  });
}

// ============================================================
// Logging (no-op — protocol log removed)
// ============================================================

// Visible log (last 80 lines) under the swap panel, mirrored to the console.
const LOG_MAX = 80;
function addLogMsg(kind, text, who = '') {
  const line = `${new Date().toLocaleTimeString()} ${who ? who + ': ' : ''}${text}`;
  console.log(`[${kind}] ${line}`);
  const el = document.getElementById('app-log');
  if (!el) return;
  const div = document.createElement('div');
  div.textContent = line;
  if (who === 'Error' || kind === 'error') div.style.color = '#f85149';
  el.appendChild(div);
  while (el.children.length > LOG_MAX) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
function addProtocolMsg(kind, content, who) {
  let summary = '';
  try { const c = JSON.parse(content); summary = c.type || c.phase || (c.btcPresig ? 'presig' : ''); } catch { summary = '(unreadable)'; }
  addLogMsg('protocol', `kind ${kind} ${summary}`.trim(), who);
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ============================================================
// UI: Swap Steps
// ============================================================

const STEPS = [
  { id: 'setup', name: '1. Setup', desc: 'Init roles, exchange adaptor point' },
  { id: 'lock', name: '2. Lock', desc: 'Lock BTC + deploy ALPH contract' },
  { id: 'nonces', name: '3. Nonces', desc: 'Commit-then-reveal nonce exchange' },
  { id: 'presign', name: '4. Pre-sign', desc: 'Adaptor pre-signature exchange' },
  { id: 'claim', name: '5. Claim', desc: 'Claim assets on both chains' },
];

const stepsEl = document.getElementById('steps');

function renderSteps() {
  stepsEl.innerHTML = '';
  for (const step of STEPS) {
    const sd = state.stepData[step.id] || {};
    const status = sd.status || 'pending';
    const statusLabels = { pending: '\u25fb Pending', done: '\u2713 Done', active: '\u25b6 Active', error: '\u2717 Error' };
    const div = document.createElement('div');
    div.className = 'step';
    div.id = `step-${step.id}`;
    let bodyHtml = `<div>${step.desc}</div>`;
    if (sd.info) bodyHtml += `<div class="data">${escapeHtml(sd.info)}</div>`;
    if (sd.error) bodyHtml += `<div class="data" style="color:#f85149">${escapeHtml(sd.error)}</div>`;
    if (status === 'error') {
      bodyHtml += `<button class="sm orange step-retry" data-step="${step.id}" style="margin-top:6px">Retry</button>`;
    }
    div.innerHTML = `
      <div class="step-header">
        <span>${step.name}</span>
        <span class="status ${status}">${statusLabels[status]}</span>
      </div>
      <div class="step-body">${bodyHtml}</div>`;
    stepsEl.appendChild(div);
  }
  stepsEl.querySelectorAll('.step-retry').forEach(btn => {
    btn.addEventListener('click', () => retryStep(btn.dataset.step));
  });
  renderSwapActions();
}

function updateStep(id, updates) {
  const before = state.stepData[id]?.status;
  state.stepData[id] = { ...state.stepData[id], ...updates };
  renderSteps();
  if (updates.status === 'error' && before !== 'error') notify('Swap step failed', `${id}: ${updates.error || 'see the page'}`, 'error');
  if (updates.status === 'done' && before !== 'done' && (id === 'lock' || id === 'presign')) notify('Swap progress', `Step ${id} done`, 'step');
}

function renderSwapActions() {
  const actionsEl = document.getElementById('swap-actions');
  if (!state.activeSwap) { actionsEl.innerHTML = ''; return; }
  // Skip if recovery UI is active (it manages its own actions)
  if (document.getElementById('timeout-display')) return;

  let html = '';
  const lockDone = state.stepData.lock?.status === 'done';

  if (lockDone) {
    if (state.activeSwap.role === 'alice') {
      html += '<button class="danger sm" id="refund-alph-btn">Refund ALPH</button>';
    } else {
      html += '<button class="danger sm" id="refund-btc-btn">Refund BTC</button>';
    }
  }
  if (state.activeSwap.role === 'bob' && state.engine.btcLockTxid && !lockDone && state.engine.lockBumpable()) {
    html += '<button class="sm" id="bump-lock-btn" title="Child pays for parent: spend the lock\'s change at the current fee rate">Bump lock fee</button>';
  }

  // Always show abort button during an active swap
  html += '<button class="sm" id="abort-swap-btn" style="margin-left:auto">Abort Swap</button>';

  actionsEl.innerHTML = html;

  const refundAlphBtn = document.getElementById('refund-alph-btn');
  if (refundAlphBtn) refundAlphBtn.addEventListener('click', refundAlph);
  const refundBtcBtn = document.getElementById('refund-btc-btn');
  if (refundBtcBtn) refundBtcBtn.addEventListener('click', refundBtc);
  const bumpLockBtn = document.getElementById('bump-lock-btn');
  if (bumpLockBtn) bumpLockBtn.addEventListener('click', bumpLockNow);
  document.getElementById('abort-swap-btn').addEventListener('click', abortSwap);
}

// ============================================================
// Offer State Management
// ============================================================

const pendingOfferEvents = new Map();  // offerId → [{event, content}, ...]

function handleOfferEvent(event) {
  let content;
  try { content = JSON.parse(event.content); } catch { return; }

  if (content.network && content.network !== state.network) return;

  const action = content.action;
  if (action === 'completed' || action === 'started') return handleAttestationEvent(event, content);
  if (action === 'offer') {
    handleNewOffer(event, content);
  } else if (content.offerId && !state.offers.has(content.offerId)) {
    // Buffer events that arrive before their offer
    if (!pendingOfferEvents.has(content.offerId)) pendingOfferEvents.set(content.offerId, []);
    pendingOfferEvents.get(content.offerId).push({ event, content });
  } else if (action === 'counter') handleCounter(event, content);
  else if (action === 'accept') handleAcceptEvent(event, content);
  else if (action === 'cancel') handleCancelEvent(event, content);
}
function handleAttestationEvent(event, content) {
  if (content.action === 'completed' || content.action === 'started') { recordAttestation(event, content); renderOffersList(); }
}

function handleNewOffer(event, content) {
  const offerId = content.offerId;
  if (state.offers.has(offerId)) return;

  const offer = {
    id: offerId,
    eventId: event.id,
    pubkey: event.pubkey,
    direction: content.direction,
    alphAmount: content.alphAmount,
    btcSat: content.btcSat,
    network: content.network,
    expiresAt: content.expiresAt,
    createdAt: event.created_at,
    status: 'open',
    counters: [],
    acceptEvent: null,
    isMine: event.pubkey === state.pubKeyHex,
    keys: content.keys || null, // creator's { btc, alph } x-only keys; absent on an old build
    minAlph: content.minAlph && BigInt(content.minAlph) > 0n && BigInt(content.minAlph) < BigInt(content.alphAmount) ? content.minAlph : null, // partial fills
  };

  state.offers.set(offerId, offer);
  if (offer.isMine) state.myOffers.add(offerId);

  if (offer.expiresAt && offer.expiresAt < Math.floor(Date.now() / 1000)) {
    offer.status = 'expired';
  }

  addLogMsg('system', `New offer: ${offer.direction === 'sell_alph' ? 'Sell' : 'Buy'} ${formatAlph(offer.alphAmount)} ALPH for ${offer.btcSat} sat`, offer.isMine ? 'You' : event.pubkey.slice(0, 8) + '...');
  renderOffersList();

  // Replay any buffered events (accept/counter/cancel that arrived before the offer)
  const pending = pendingOfferEvents.get(offerId);
  if (pending) {
    pendingOfferEvents.delete(offerId);
    for (const { event: pe, content: pc } of pending) {
      if (pc.action === 'counter') handleCounter(pe, pc);
      else if (pc.action === 'accept') handleAcceptEvent(pe, pc);
      else if (pc.action === 'cancel') handleCancelEvent(pe, pc);
    }
  }
}

function handleCounter(event, content) {
  const offer = state.offers.get(content.offerId);
  if (!offer) return;
  if (offer.status === 'accepted' || offer.status === 'cancelled') return;

  const counter = {
    eventId: event.id,
    pubkey: event.pubkey,
    alphAmount: content.alphAmount,
    btcSat: content.btcSat,
    message: content.message || '',
    isMine: event.pubkey === state.pubKeyHex,
    keys: content.keys || null,
  };

  offer.counters.push(counter);
  offer.status = 'countered';

  addLogMsg('system', `Counter-offer on ${content.offerId.slice(0, 8)}...: ${formatAlph(content.alphAmount)} ALPH for ${content.btcSat} sat`, counter.isMine ? 'You' : event.pubkey.slice(0, 8) + '...');
  renderOffersList();
}

function handleAcceptEvent(event, content) {
  const offer = state.offers.get(content.offerId);
  if (!offer) return;
  if (offer.status === 'accepted' || offer.status === 'cancelled') return;

  const isMine = event.pubkey === state.pubKeyHex;
  const myCounterAccepted = content.counterparty && content.counterparty === state.pubKeyHex;
  const involvesUs = offer.isMine || isMine || myCounterAccepted;
  if (!involvesUs) {
    // Someone else's accept: for us the offer stays open until the creator's
    // taken signal (otherwise anyone could hide every offer by "accepting" it
    // with garbage amounts the maker will reject).
    offer.pendingAccepts = (offer.pendingAccepts || 0) + 1;
    renderOffersList();
    return;
  }

  if (offer.isMine) {
    const acceptor = content.counterparty || event.pubkey;
    const groupProblem = acceptor === state.pubKeyHex ? null : peerGroupProblem(peerKeysFor(offer, event, content));
    if (groupProblem) { addLogMsg('system', `Ignoring accept of ${content.offerId.slice(0, 8)}... : ${groupProblem}`, 'System'); return; }
    // The accept's amounts must be the offer's (or, for a partial fill, within the
    // range at the offer's rate): the taker chooses the fill, never the price.
    if (!content.counterparty) {
      const problem = acceptAmountsProblem(offer, content);
      if (problem) { addLogMsg('system', `Ignoring accept of ${content.offerId.slice(0, 8)}... from ${event.pubkey.slice(0, 8)}...: ${problem}`, 'Error'); return; }
    }
  }

  offer.status = 'accepted';
  offer.acceptEvent = event;
  addLogMsg('system', `Offer ${content.offerId.slice(0, 8)}... accepted!`, isMine ? 'You' : event.pubkey.slice(0, 8) + '...');
  renderOffersList();
  // Relays replay the last two days of events on every page load. An accept made
  // before this page was opened belongs to an earlier attempt: starting a swap
  // from it would put this side in a session the peer is no longer in (both then
  // wait for each other forever). Only a live accept starts a swap; an earlier
  // one is recovered through the saved swap state, or is over.
  const ageSeconds = state.startedAt - event.created_at;
  if (ageSeconds > 120) {
    addLogMsg('system', `Not starting a swap from the ${Math.round(ageSeconds / 60)} min old accept of offer ${offer.id.slice(0, 8)}... (earlier attempt). Publish or accept a fresh offer.`, 'System');
    markOfferProcessed(offer.id);
    return;
  }
  if (state.activeSwap) { addLogMsg('system', `Accept of ${offer.id.slice(0, 8)}... ignored: a swap is already active (session ${state.activeSwap.sessionId.slice(0, 8)}...)`, 'System'); return; }
  if (getProcessedOffers().has(offer.id)) { addLogMsg('system', `Accept of ${offer.id.slice(0, 8)}... ignored: offer already processed`, 'System'); return; }
  startSwapFromAccept(offer, event, content);
}

function handleCancelEvent(event, content) {
  const offer = state.offers.get(content.offerId);
  if (!offer) return;
  if (event.pubkey !== offer.pubkey) return; // only creator can cancel

  // Post-match cancel (has matchedPub): this is a "taken" signal, NOT a real cancel.
  // Only affects losing acceptors — never changes offer status to cancelled.
  if (content.matchedPub) {
    // the creator confirms a match: the offer is taken for everyone else
    if (offer.status !== 'accepted' && !offer.isMine && content.matchedPub !== state.pubKeyHex) {
      offer.status = 'accepted';
      renderOffersList();
      return;
    }
    if (offer.status === 'accepted') {
      const iAmMatchedAcceptor = content.matchedPub === state.pubKeyHex;
      if (state.activeSwap?.offerId === offer.id && !offer.isMine && !iAmMatchedAcceptor) {
        addLogMsg('system', 'Offer was taken by another user — aborting swap', 'System');
        markOfferProcessed(offer.id);
        offer.status = 'cancelled';
        resetSwap();
        renderOffersList();
      }
    }
    // If accept hasn't arrived yet (relay ordering), ignore — accept will process normally later.
    return;
  }

  // Regular cancel (user clicked Cancel button)
  if (offer.status === 'accepted') return;
  offer.status = 'cancelled';
  addLogMsg('system', `Offer ${content.offerId.slice(0, 8)}... cancelled`, event.pubkey === state.pubKeyHex ? 'You' : event.pubkey.slice(0, 8) + '...');
  renderOffersList();
}

setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  let changed = false;
  for (const [, offer] of state.offers) {
    if (offer.status === 'open' || offer.status === 'countered') {
      if (offer.expiresAt && offer.expiresAt < now) {
        offer.status = 'expired';
        changed = true;
      }
    }
  }
  if (changed) renderOffersList();
}, 30000);

// ============================================================
// UI: Offers List
// ============================================================

function formatAlph(attoAlph) {
  const n = Number(BigInt(attoAlph)) / 1e18;
  return n % 1 === 0 ? n.toFixed(0) : n.toFixed(4);
}

function formatSat(sat) {
  return Number(sat).toLocaleString();
}

function npubLink(pubkeyHex) {
  const npub = npubEncode(pubkeyHex);
  const short = npub.slice(0, 16) + '...';
  return `<a href="https://njump.me/${npub}" target="_blank" title="${npub}" class="npub-link">${short}</a>`;
}

function alphAddressFromPub(pubkeyHex) {
  try { return addressFromPublicKey(pubkeyHex, alphKeyTypeOf(pubkeyHex)); } catch { return null; }
}

function getP2TRAddressFromPub(pubkeyHex) {
  try { return getP2TRAddress(hexToBytes(pubkeyHex)); } catch { return null; }
}

// ---- Rates ----
// Offers quote btcSat for alphAmount (atto): the rate in sat per ALPH is btcSat * 1e18 / alphAmount.
function satPerAlph(alphAmount, btcSat) { const a = BigInt(alphAmount); return a > 0n ? Number(BigInt(btcSat) * 10n ** 18n * 1000n / a) / 1000 : 0; }
function btcSatFor(alphAmount, offer) { return Number(BigInt(alphAmount) * BigInt(offer.btcSat) / BigInt(offer.alphAmount)); }
function fmtRate(spa) { return `${spa.toLocaleString(undefined, { maximumFractionDigits: 2 })} sat/ALPH · ${Math.round(1e8 / spa).toLocaleString()} ALPH/BTC`; }
// deviation of an offer's rate from the market reference, from the point of view of the taker of `direction`
function rateDeviation(spa) {
  if (!state.market?.satPerAlph || !state.market.reliable) return null; // no comparison on a single or disputed quote
  return (spa - state.market.satPerAlph) / state.market.satPerAlph; // > 0: ALPH priced above market
}
function rateLine(spa, direction) {
  const dev = rateDeviation(spa);
  if (dev === null) return `<div class="rate-line">${fmtRate(spa)}</div>`;
  const pct = Math.round(Math.abs(dev) * 100);
  const cls = pct >= 30 ? 'far' : pct >= 10 ? 'off' : '';
  const side = dev > 0 ? 'above' : 'below';
  return `<div class="rate-line">${fmtRate(spa)} <span class="${cls}">(${pct}% ${side} market)</span></div>`;
}
// Three independent quotes of ALPH in BTC (all allow browser requests); the
// reference is their median and it counts as reliable only when at least two
// sources answered and they agree within 5 %.
const MARKET_SOURCES = [
  { name: 'CoinGecko', url: 'https://api.coingecko.com/api/v3/simple/price?ids=alephium&vs_currencies=btc', pick: (j) => j.alephium.btc * 1e8 },
  { name: 'CoinPaprika', url: 'https://api.coinpaprika.com/v1/tickers/alph-alephium?quotes=BTC', pick: (j) => j.quotes.BTC.price * 1e8 },
  { name: 'Gate.io', url: 'https://api.gateio.ws/api/v4/spot/tickers?currency_pair=ALPH_USDT', pick: null, usd: 'https://api.gateio.ws/api/v4/spot/tickers?currency_pair=BTC_USDT' },
];
async function fetchJson(url) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 8000);
  try { const r = await fetch(url, { cache: 'no-store', signal: ctl.signal }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return await r.json(); }
  finally { clearTimeout(t); }
}
async function refreshMarketRate() {
  const quotes = await Promise.all(MARKET_SOURCES.map(async (s) => {
    try {
      let spa;
      if (s.pick) spa = s.pick(await fetchJson(s.url));
      else { const [a, b] = await Promise.all([fetchJson(s.url), fetchJson(s.usd)]); spa = Number(a[0].last) / Number(b[0].last) * 1e8; }
      return Number.isFinite(spa) && spa > 0 ? { name: s.name, spa } : null;
    } catch { return null; }
  }));
  const sources = quotes.filter(Boolean).sort((a, b) => a.spa - b.spa);
  if (!sources.length) { state.market = null; updateRateDisplay(); return; }
  const median = sources[Math.floor(sources.length / 2)].spa;
  const spread = (sources[sources.length - 1].spa - sources[0].spa) / median;
  const reliable = sources.length >= 2 && spread <= 0.05;
  state.market = { satPerAlph: median, sources, spread, reliable, at: Date.now() };
  renderOffersList(); updateRateDisplay(); presetSatFromMarket();
}
function marketSummary() {
  const m = state.market; if (!m) return '';
  const names = m.sources.map((s) => s.name).join(', ');
  if (m.reliable) return `${fmtRate(m.satPerAlph)} (${names} agree within ${Math.max(1, Math.round(m.spread * 100))}%)`;
  if (m.sources.length === 1) return `${fmtRate(m.satPerAlph)} (${names} only: unconfirmed)`;
  return `sources disagree by ${Math.round(m.spread * 100)}%: ${m.sources.map((s) => `${s.name} ${s.spa.toFixed(1)}`).join(', ')} sat/ALPH`;
}
// The sat field follows the ALPH amount at the market rate until the user edits it by hand.
let satManual = false;
function presetSatFromMarket() {
  const m = state.market; if (!m?.reliable || satManual) return;
  const alphVal = parseFloat(document.getElementById('offer-alph').value) || 0;
  if (alphVal <= 0) return;
  document.getElementById('offer-btc-sat').value = String(Math.max(1, Math.round(alphVal * m.satPerAlph)));
  updateRateDisplay();
}

// ---- Counterparty history (public attestations, a hint and not a proof: anyone can publish them) ----
function historyOf(pubkey) {
  const h = state.history.get(pubkey);
  if (!h) return null;
  return { completed: h.completed.size, started: h.started.size };
}
function historyBadge(pubkey) {
  const h = historyOf(pubkey);
  if (!h) return '';
  return `<span class="peer-history" title="Attested by counterparties on the relays (anyone can publish such notes: a hint, not a proof)">${h.completed} completed · ${h.started} started</span>`;
}
function recordAttestation(event, content) {
  const subject = content.peer;
  if (!subject || !/^[0-9a-f]{64}$/.test(subject) || subject === event.pubkey) return;
  if (!state.history.has(subject)) state.history.set(subject, { completed: new Set(), started: new Set() });
  const h = state.history.get(subject);
  if (content.action === 'completed') h.completed.add(event.pubkey + ':' + content.offerId);
  if (content.action === 'started') h.started.add(event.pubkey + ':' + content.offerId);
}
async function publishAttestation(action) {
  if (!state.activeSwap) return;
  const { offerId, peerPubHex, sessionId } = state.activeSwap;
  try {
    const ev = await signEvent({
      kind: SWAP_OFFER_KIND, created_at: Math.floor(Date.now() / 1000),
      tags: [['t', 'atomicswap'], ['t', action], ['p', peerPubHex], ['d', `${offerId}:${action}:${state.pubKeyHex.slice(0, 16)}`]],
      content: JSON.stringify({ action, offerId, peer: peerPubHex, session: sessionId.slice(0, 16), network: state.network }),
    });
    await nostrPublish(ev);
  } catch (e) { addLogMsg('system', `Could not publish the ${action} note: ${e.message}`, 'System'); }
}

function explorerLink(chain, address, text) {
  if (chain === 'btc') {
    return `<a href="${CONFIG.btcExplorer}/address/${address}" target="_blank" title="${address}" class="amount-link">${text}</a>`;
  }
  return `<a href="${CONFIG.alphExplorer}/addresses/${address}" target="_blank" title="${address}" class="amount-link">${text}</a>`;
}

function renderOffersList() {
  const listEl = document.getElementById('offers-list');
  const countEl = document.getElementById('offers-count');

  const sorted = [...state.offers.values()].sort((a, b) => {
    const statusOrder = { open: 0, countered: 0, accepted: 1, aborted_locked: 2, completed: 3, aborted: 3, cancelled: 3, expired: 3 };
    const oa = statusOrder[a.status] ?? 3;
    const ob = statusOrder[b.status] ?? 3;
    if (oa !== ob) return oa - ob;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  const activeCount = sorted.filter(o => o.status === 'open' || o.status === 'countered').length;
  countEl.textContent = `(${activeCount})`;

  if (sorted.length === 0) {
    listEl.innerHTML = '<div style="color:#484f58; font-size:12px; text-align:center; padding:24px;">No offers yet. Create one or wait for offers to appear.</div>';
    return;
  }

  const f = state.offerFilter;
  let activeOffers = sorted.filter(o => (o.status === 'open' || o.status === 'countered') && (f.dir === 'all' || o.direction === f.dir) && !(f.hideMine && o.isMine));
  if (f.sort === 'rate') {
    // best for me: cheapest ALPH when I would buy (sell_alph offers), dearest when I would sell (buy_alph offers)
    activeOffers.sort((a, b) => { const ra = satPerAlph(a.alphAmount, a.btcSat), rb = satPerAlph(b.alphAmount, b.btcSat); return a.direction === 'sell_alph' ? ra - rb : rb - ra; });
  } else if (f.sort === 'size') {
    activeOffers.sort((a, b) => (BigInt(b.alphAmount) > BigInt(a.alphAmount) ? 1 : -1));
  }
  const inactiveOffers = sorted.filter(o => o.status !== 'open' && o.status !== 'countered');

  listEl.innerHTML = '';

  if (activeOffers.length === 0 && inactiveOffers.length === 0) {
    listEl.innerHTML = '<div style="color:#484f58; font-size:12px; text-align:center; padding:24px;">No offers yet. Create one or wait for offers to appear.</div>';
    return;
  }

  for (const offer of activeOffers) {
    listEl.appendChild(renderOfferCard(offer));
  }

  if (activeOffers.length === 0) {
    listEl.insertAdjacentHTML('beforeend', '<div style="color:#484f58; font-size:12px; text-align:center; padding:12px;">No open offers.</div>');
  }

  if (inactiveOffers.length > 0) {
    const historyToggle = document.createElement('button');
    historyToggle.className = 'history-toggle';
    historyToggle.innerHTML = `<span class="arrow">&#9654;</span> Recent History (${inactiveOffers.length})`;
    const historyContainer = document.createElement('div');
    historyContainer.className = 'history-container';
    historyContainer.style.display = 'none';
    for (const offer of inactiveOffers) {
      historyContainer.appendChild(renderOfferCard(offer));
    }
    historyToggle.addEventListener('click', () => {
      const open = historyContainer.style.display !== 'none';
      historyContainer.style.display = open ? 'none' : 'block';
      historyToggle.classList.toggle('open', !open);
    });
    listEl.appendChild(historyToggle);
    listEl.appendChild(historyContainer);
  }

  listEl.querySelectorAll('.accept-offer-btn').forEach(btn => {
    btn.addEventListener('click', () => acceptOffer(btn.dataset.offer));
  });
  listEl.querySelectorAll('.counter-offer-btn').forEach(btn => {
    btn.addEventListener('click', () => showCounterForm(btn.dataset.offer));
  });
  listEl.querySelectorAll('.cancel-offer-btn').forEach(btn => {
    btn.addEventListener('click', () => cancelOffer(btn.dataset.offer));
  });
  listEl.querySelectorAll('.accept-counter-btn').forEach(btn => {
    btn.addEventListener('click', () => acceptCounter(btn.dataset.offer, parseInt(btn.dataset.counter)));
  });
}

function renderOfferCard(offer) {
  const card = document.createElement('div');
  const isSell = offer.direction === 'sell_alph';
  let cardClass = 'offer-card';
  if (offer.isMine) cardClass += ' mine';
  else cardClass += isSell ? ' sell' : ' buy';
  if (offer.status === 'cancelled' || offer.status === 'expired' || offer.status === 'aborted') cardClass += ' cancelled';
  if (offer.status === 'aborted_locked') cardClass += ' aborted-locked';
  if (offer.status === 'accepted') cardClass += ' accepted';
  if (offer.status === 'completed') cardClass += ' completed';
  card.className = cardClass;

  const dirLabel = isSell ? 'SELL' : 'BUY';
  const dirClass = isSell ? 'sell' : 'buy';
  const preposition = isSell ? 'for' : 'with';
  const peerLabel = offer.isMine ? 'You' : npubLink(offer.pubkey);

  let statusBadge = '';
  if (offer.status === 'completed') statusBadge = '<span class="status-badge completed">Completed</span>';
  else if (offer.status === 'accepted') statusBadge = '<span class="status-badge accepted">Accepted</span>';
  else if (offer.status === 'aborted_locked') statusBadge = '<span class="status-badge aborted-locked">Aborted (funds locked)</span>';
  else if (offer.status === 'aborted') statusBadge = '<span class="status-badge aborted">Aborted</span>';
  else if (offer.status === 'cancelled') statusBadge = '<span class="status-badge cancelled">Cancelled</span>';
  else if (offer.status === 'expired') statusBadge = '<span class="status-badge expired">Expired</span>';

  let actionsHtml = '';
  const isActive = offer.status === 'open' || offer.status === 'countered';
  if (isActive) {
    if (offer.isMine) {
      actionsHtml = `<button class="sm danger cancel-offer-btn" data-offer="${offer.id}">Cancel</button>`;
    } else {
      actionsHtml = `<button class="sm primary accept-offer-btn" data-offer="${offer.id}">Accept</button>
                     <button class="sm counter-offer-btn" data-offer="${offer.id}">Counter</button>`;
    }
  }

  let alphAmountHtml = `<span class="alph">${offer.minAlph ? `${formatAlph(offer.minAlph)} to ` : ''}${formatAlph(offer.alphAmount)} ALPH</span>`;
  let btcAmountHtml = `<span class="btc">${offer.minAlph ? 'up to ' : ''}${formatSat(offer.btcSat)} sat</span>`;

  const hasAcceptData = (offer.status === 'accepted' || offer.status === 'completed' || offer.status === 'aborted_locked') && offer.acceptEvent;
  if (hasAcceptData) {
    const creatorPub = offer.pubkey;
    const acceptorPub = offer.acceptEvent.pubkey;
    let btcRecipientPub, alphRecipientPub;
    if (isSell) {
      btcRecipientPub = creatorPub;
      alphRecipientPub = acceptorPub;
    } else {
      btcRecipientPub = acceptorPub;
      alphRecipientPub = creatorPub;
    }
    const btcAddr = getP2TRAddressFromPub(btcRecipientPub);
    const alphAddr = alphAddressFromPub(alphRecipientPub);
    if (btcAddr) btcAmountHtml = `<span class="btc">${explorerLink('btc', btcAddr, `${formatSat(offer.btcSat)} sat`)}</span>`;
    if (alphAddr) alphAmountHtml = `<span class="alph">${explorerLink('alph', alphAddr, `${formatAlph(offer.alphAmount)} ALPH`)}</span>`;
  }

  const timeStr = offer.createdAt
    ? new Date(offer.createdAt * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '';

  let html = `
    <div class="card-header">
      <span class="amount">
        <span class="dir-badge ${dirClass}">${dirLabel}</span>
        ${alphAmountHtml}
        <span style="color:#8b949e"> ${preposition} </span>
        ${btcAmountHtml}
      </span>
      ${statusBadge}
    </div>
    ${rateLine(satPerAlph(offer.alphAmount, offer.btcSat), offer.direction)}
    <div class="card-body">
      <span class="peer">by ${peerLabel}${offer.isMine ? '' : historyBadge(offer.pubkey)}${offer.pendingAccepts && isActive ? ` <span class="peer-history" title="Someone sent an accept; the maker has not confirmed the match">${offer.pendingAccepts} accept pending</span>` : ''}</span>
      <span class="card-actions">${actionsHtml}</span>
    </div>`;

  if (offer.status === 'completed' && offer.acceptEvent) {
    const acceptorLabel = offer.acceptEvent.pubkey === state.pubKeyHex ? 'You' : npubLink(offer.acceptEvent.pubkey);
    html += `<div class="offer-details">Swapped with ${acceptorLabel}</div>`;
  } else if (offer.status === 'accepted' && offer.acceptEvent) {
    const acceptorLabel = offer.acceptEvent.pubkey === state.pubKeyHex ? 'You' : npubLink(offer.acceptEvent.pubkey);
    html += `<div class="offer-details">Accepted by ${acceptorLabel} — swap in progress</div>`;
  } else if (offer.status === 'aborted_locked') {
    html += `<div class="offer-details" style="color:#d29922">Funds still locked on-chain — use recovery to refund</div>`;
  } else if (offer.status === 'aborted') {
    html += `<div class="offer-details">Aborted before funds were locked</div>`;
  } else if (offer.status === 'expired') {
    html += `<div class="offer-details">Expired without acceptance</div>`;
  }

  if (offer.counters.length > 0) {
    html += '<div class="counters-list">';
    offer.counters.forEach((c, idx) => {
      const cPeer = c.isMine ? 'You' : npubLink(c.pubkey);
      let counterActions = '';
      if (isActive) {
        if (offer.isMine && !c.isMine) {
          counterActions = `<button class="sm primary accept-counter-btn" data-offer="${offer.id}" data-counter="${idx}">Accept</button>`;
        }
      }
      html += `<div class="counter-item">
        <span class="counter-info">Counter from ${cPeer}:</span>
        <span class="counter-amounts">${formatAlph(c.alphAmount)} ALPH / ${formatSat(c.btcSat)} sat</span>
        ${counterActions}
      </div>`;
    });
    html += '</div>';
  }

  if (!isActive && timeStr) {
    html += `<div class="offer-details">${timeStr}</div>`;
  }

  card.innerHTML = html;
  return card;
}

// ============================================================
// Offer Actions
// ============================================================

async function validateBalanceForSwap(role, alphAmountAtto, btcSat) {
  const warnings = [];
  try {
    const bal = await state.engine.getBalances();
    if (role === 'alice') {
      const alphNeeded = Number(BigInt(alphAmountAtto)) / 1e18;
      const alphHave = parseFloat(bal.alph);
      if (alphHave < alphNeeded) {
        warnings.push(`Insufficient ALPH: need ${alphNeeded.toFixed(4)}, have ${alphHave.toFixed(4)}`);
      }
    } else {
      const btcNeeded = btcSat + 500;
      const btcHave = bal.btcConfirmedSat + bal.btcUnconfirmedSat;
      if (btcHave < btcNeeded) {
        warnings.push(`Insufficient BTC: need ~${btcNeeded} sat, have ${btcHave} sat`);
      }
      const alphHave = parseFloat(bal.alph);
      if (alphHave < 0.01) {
        warnings.push(`Low ALPH balance (${alphHave.toFixed(4)} ALPH). You need ~0.01 ALPH for gas when claiming. Use the ALPH faucet.`);
      }
    }
  } catch (e) {
    console.warn('Balance check failed:', e);
  }
  return { ok: warnings.length === 0, warnings };
}

function showOfferWarning(text) {
  let el = document.getElementById('offer-warning');
  if (!el) {
    el = document.createElement('div');
    el.id = 'offer-warning';
    el.style.cssText = 'font-size:11px; color:#d29922; margin-top:6px; line-height:1.5;';
    document.querySelector('.offer-form .form-actions').appendChild(el);
  }
  el.textContent = text;
}

function clearOfferWarning() {
  const el = document.getElementById('offer-warning');
  if (el) el.textContent = '';
}

async function publishOffer() {
  const btn = document.getElementById('publish-offer-btn');
  if (!await confirmMainnet('publish this offer')) return;
  btn.disabled = true; btn.textContent = 'Publishing...';
  clearOfferWarning();

  try {
    const direction = document.querySelector('#direction-toggle button.active').dataset.dir;
    const alphVal = parseFloat(document.getElementById('offer-alph').value) || 1;
    const btcSat = parseInt(document.getElementById('offer-btc-sat').value) || 5000;
    const alphAmount = BigInt(Math.round(alphVal * 1e18));
    const minVal = parseFloat(document.getElementById('offer-min-alph').value) || 0;
    const minAlph = minVal > 0 && minVal < alphVal ? BigInt(Math.round(minVal * 1e18)) : null;
    if (minVal > 0 && minVal >= alphVal) { showOfferWarning('The minimum must be below the amount.'); btn.disabled = false; btn.textContent = 'Publish Offer'; return; }
    const dev = rateDeviation(satPerAlph(alphAmount, btcSat));
    if (dev !== null && Math.abs(dev) >= 0.3) {
      const ok = await modalConfirm(`Your rate is ${fmtRate(satPerAlph(alphAmount, btcSat))}, ${Math.round(Math.abs(dev) * 100)}% ${dev > 0 ? 'above' : 'below'} the market reference (${marketSummary()}). Publish anyway?`, 'Publish');
      if (!ok) { btn.disabled = false; btn.textContent = 'Publish Offer'; return; }
    }

    // Balance check (non-blocking warning)
    const role = direction === 'sell_alph' ? 'alice' : 'bob';
    const { warnings } = await validateBalanceForSwap(role, String(alphAmount), btcSat);
    if (warnings.length > 0) {
      showOfferWarning(warnings.join(' | '));
    }

    const offerId = generateUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + 86400;

    const event = await createOfferEvent({ offerId, direction, alphAmount, btcSat, expiresAt, minAlph });
    await nostrPublish(event);

    const note = await createOfferNote(event, { direction, alphAmount: String(alphAmount), btcSat });
    await nostrPublish(note).catch(() => {}); // best-effort

    addLogMsg('system', `Published offer: ${direction === 'sell_alph' ? 'Sell' : 'Buy'} ${alphVal} ALPH for ${btcSat} sat${minAlph ? ` (partial fills from ${minVal} ALPH)` : ''} (expires in 24h)`, 'You');
  } catch (e) {
    addLogMsg('system', `Publish error: ${e.message}`, 'Error');
  }

  btn.disabled = false; btn.textContent = 'Publish Offer';
}

// The swap contract lives in one Alephium group and can only be called by, and
// pay, addresses of that group; a peer in another group cannot trade with us.
function peerGroupProblem(peerKeys) {
  if (!peerKeys?.alph || !peerKeys?.btc) return 'peer did not announce its Bitcoin and Alephium keys (old build): it must reload';
  const mine = state.engine.group;
  let theirs;
  try { theirs = groupOfPub(peerKeys.alph); } catch { return "peer's Alephium key is malformed"; }
  return theirs === mine ? null : `peer's Alephium address is in group ${theirs}, yours in group ${mine}`;
}
// Returns why an accept's amounts do not match an offer, or null when they do.
function acceptAmountsProblem(offer, content) {
  let alph, sat;
  try { alph = BigInt(content.alphAmount); sat = BigInt(content.btcSat); } catch { return 'amounts are not numbers'; }
  if (alph <= 0n || sat <= 0n) return 'amounts must be positive';
  if (!offer.minAlph) {
    if (alph !== BigInt(offer.alphAmount) || sat !== BigInt(offer.btcSat)) return `amounts ${formatAlph(content.alphAmount)} ALPH / ${content.btcSat} sat differ from the offer (${formatAlph(offer.alphAmount)} ALPH / ${offer.btcSat} sat)`;
    return null;
  }
  if (alph < BigInt(offer.minAlph) || alph > BigInt(offer.alphAmount)) return `fill ${formatAlph(content.alphAmount)} ALPH is outside the offer's range`;
  const expected = BigInt(btcSatFor(content.alphAmount, offer));
  if (sat < expected - 1n || sat > expected + 1n) return `${content.btcSat} sat is not the offer's rate for ${formatAlph(content.alphAmount)} ALPH (expected ${expected} sat)`;
  if (sat < 1000n) return 'fill below 1000 sat';
  return null;
}

// The peer's keys for a swap: the creator's from the offer, the acceptor's from
// the accept (or from its counter-offer when the creator accepted a counter).
function peerKeysFor(offer, acceptEvent, acceptContent) {
  if (offer.isMine) {
    if (acceptContent.counterparty) return offer.counters.find((c) => c.pubkey === acceptContent.counterparty)?.keys || null;
    return acceptContent.keys || null;
  }
  return offer.keys || null;
}

// Inline amount form for an offer that allows partial fills.
function showAcceptForm(offerId) {
  const offer = state.offers.get(offerId);
  const btn = document.querySelector(`.accept-offer-btn[data-offer="${offerId}"]`);
  if (!offer || !btn) return;
  const card = btn.closest('.offer-card');
  if (card.querySelector('.accept-form')) return;
  const form = document.createElement('div');
  form.className = 'accept-form';
  form.innerHTML = `<label>ALPH</label><input type="text" class="fill-alph" value="${formatAlph(offer.alphAmount)}"> <span class="fill-sat">= ${formatSat(offer.btcSat)} sat</span> <button class="sm primary submit-fill-btn">Accept</button> <button class="sm cancel-fill-btn">X</button>
    <span style="color:#8b949e">range ${formatAlph(offer.minAlph)} to ${formatAlph(offer.alphAmount)} ALPH at ${fmtRate(satPerAlph(offer.alphAmount, offer.btcSat))}</span>`;
  card.appendChild(form);
  const input = form.querySelector('.fill-alph');
  const update = () => { const v = parseFloat(input.value) || 0; form.querySelector('.fill-sat').textContent = `= ${formatSat(btcSatFor(BigInt(Math.round(v * 1e18)).toString(), offer))} sat`; };
  input.addEventListener('input', update);
  form.querySelector('.cancel-fill-btn').addEventListener('click', () => form.remove());
  form.querySelector('.submit-fill-btn').addEventListener('click', () => { const v = parseFloat(input.value) || 0; acceptOffer(offerId, BigInt(Math.round(v * 1e18))); });
}

async function acceptOffer(offerId, fillAmount = null) {
  const offer = state.offers.get(offerId);
  if (!offer) return;
  if (!await confirmMainnet('take this offer')) return;
  const groupProblem = peerGroupProblem(offer.keys);
  if (groupProblem) { await modalAlert(`Cannot take this offer: ${groupProblem}.`); return; }

  // partial fill: the amount comes from the card's form, at the offer's rate
  let alphAmount = offer.alphAmount, btcSat = offer.btcSat;
  if (offer.minAlph) {
    if (fillAmount === null) return showAcceptForm(offerId);
    alphAmount = String(fillAmount);
    btcSat = btcSatFor(alphAmount, offer);
    const problem = acceptAmountsProblem(offer, { alphAmount, btcSat });
    if (problem) { await modalAlert(problem); return; }
  }
  const dev = rateDeviation(satPerAlph(alphAmount, btcSat));
  if (dev !== null && Math.abs(dev) >= 0.3) {
    const ok = await modalConfirm(`This offer's rate is ${fmtRate(satPerAlph(alphAmount, btcSat))}, ${Math.round(Math.abs(dev) * 100)}% ${dev > 0 ? 'above' : 'below'} the market reference (${marketSummary()}). Take it anyway?`, 'Take it');
    if (!ok) return;
  }

  // Acceptor role: sell_alph offer → acceptor is bob; buy_alph offer → acceptor is alice
  const role = offer.direction === 'sell_alph' ? 'bob' : 'alice';
  const { ok, warnings } = await validateBalanceForSwap(role, alphAmount, btcSat);
  if (!ok) {
    const proceed = await modalConfirm('Balance warnings:\n\n' + warnings.join('\n') + '\n\nProceed anyway?', 'Proceed');
    if (!proceed) return;
  }

  try {
    const event = await createAcceptEvent({
      offerId,
      offerEventId: offer.eventId,
      offerCreator: offer.pubkey,
      alphAmount,
      btcSat,
    });
    await nostrPublish(event);
  } catch (e) {
    addLogMsg('system', `Accept error: ${e.message}`, 'Error');
  }
}

async function acceptCounter(offerId, counterIndex) {
  const offer = state.offers.get(offerId);
  if (!offer || !offer.counters[counterIndex]) return;
  const counter = offer.counters[counterIndex];

  // Creator accepting a counter keeps their original role
  const role = offer.direction === 'sell_alph' ? 'alice' : 'bob';
  const { ok, warnings } = await validateBalanceForSwap(role, counter.alphAmount, counter.btcSat);
  if (!ok) {
    const proceed = await modalConfirm('Balance warnings:\n\n' + warnings.join('\n') + '\n\nProceed anyway?', 'Proceed');
    if (!proceed) return;
  }

  try {
    const event = await createAcceptEvent({
      offerId,
      offerEventId: offer.eventId,
      offerCreator: offer.pubkey,
      alphAmount: counter.alphAmount,
      btcSat: counter.btcSat,
      counterparty: counter.pubkey,
    });
    await nostrPublish(event);
  } catch (e) {
    addLogMsg('system', `Accept counter error: ${e.message}`, 'Error');
  }
}

function showCounterForm(offerId) {
  const offer = state.offers.get(offerId);
  if (!offer) return;

  const cards = document.querySelectorAll('.offer-card');
  for (const card of cards) {
    const btn = card.querySelector(`.counter-offer-btn[data-offer="${offerId}"]`);
    if (!btn) continue;
    if (card.querySelector('.counter-form')) return;

    const form = document.createElement('div');
    form.className = 'counter-form';
    form.innerHTML = `
      <label>ALPH</label>
      <input type="text" class="counter-alph" value="${formatAlph(offer.alphAmount)}">
      <label>sat</label>
      <input type="text" class="counter-sat" value="${offer.btcSat}">
      <button class="sm primary submit-counter-btn" data-offer="${offerId}">Send</button>
      <button class="sm cancel-counter-form-btn">X</button>
    `;
    card.appendChild(form);

    form.querySelector('.submit-counter-btn').addEventListener('click', async () => {
      const alphVal = parseFloat(form.querySelector('.counter-alph').value) || 0;
      const btcSat = parseInt(form.querySelector('.counter-sat').value) || 0;
      if (!alphVal || !btcSat) return;

      try {
        const event = await createCounterEvent({
          offerId,
          offerEventId: offer.eventId,
          offerCreator: offer.pubkey,
          index: offer.counters.length,
          alphAmount: BigInt(Math.round(alphVal * 1e18)),
          btcSat,
        });
        await nostrPublish(event);
        form.remove();
      } catch (e) {
        addLogMsg('system', `Counter error: ${e.message}`, 'Error');
      }
    });

    form.querySelector('.cancel-counter-form-btn').addEventListener('click', () => form.remove());
    break;
  }
}

async function cancelOffer(offerId) {
  const offer = state.offers.get(offerId);
  if (!offer) return;

  try {
    const event = await createCancelEvent({ offerId, offerEventId: offer.eventId });
    await nostrPublish(event);
  } catch (e) {
    addLogMsg('system', `Cancel error: ${e.message}`, 'Error');
  }
}

// ============================================================
// Accept -> Auto-Execute Swap
// ============================================================

function startSwapFromAccept(offer, acceptEvent, acceptContent) {
  const iAmCreator = offer.isMine;

  // Determine peer: for counter-accepts, the peer is the counter-proposer (counterparty),
  // not the accept event author (who is the offer creator in that case).
  const peerForCreator = acceptContent.counterparty || acceptEvent.pubkey;

  let role, peerPubHex;
  if (offer.direction === 'sell_alph') {
    role = iAmCreator ? 'alice' : 'bob';
    peerPubHex = iAmCreator ? peerForCreator : offer.pubkey;
  } else {
    role = iAmCreator ? 'bob' : 'alice';
    peerPubHex = iAmCreator ? peerForCreator : offer.pubkey;
  }

  const sessionId = acceptEvent.id;
  const alphAmount = acceptContent.alphAmount;
  const btcSat = acceptContent.btcSat;
  const peerKeys = peerKeysFor(offer, acceptEvent, acceptContent);
  if (!peerKeys?.btc || !peerKeys?.alph) {
    addLogMsg('system', `Not starting swap ${sessionId.slice(0, 8)}...: the peer did not announce its Bitcoin and Alephium keys (old build). Both sides must run the current build.`, 'Error');
    markOfferProcessed(offer.id);
    return;
  }
  const peer = { nostrPubHex: peerPubHex, btcPubHex: peerKeys.btc, alphPubHex: peerKeys.alph };

  state.activeSwap = {
    offerId: offer.id,
    role,
    peerPubHex,
    peer,
    sessionId,
    alphAmount,
    btcSat,
  };

  state.stepData = {};
  publishAttestation('started');
  addLogMsg('system', `Swap started: you are ${role === 'alice' ? 'Alice (ALPH side)' : 'Bob (BTC side)'}, session ${sessionId.slice(0, 12)}..., peer ${peerPubHex.slice(0, 12)}.... Both pages must show this same session.`, 'System');

  document.getElementById('swap-placeholder').classList.add('hidden');
  document.getElementById('swap-active').classList.remove('hidden');

  renderSwapInfo(state.activeSwap);
  renderSteps();

  // Show UTXO bar for Bob
  if (role === 'bob') {
    document.getElementById('utxo-bar').classList.remove('hidden');
    refreshUtxos();
  } else {
    document.getElementById('utxo-bar').classList.add('hidden');
  }

  subscribeToSwap(sessionId, peerPubHex);

  // On mobile, scroll to the swap panel (rendered above offers via column-reverse)
  document.getElementById('swap-active').scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Offer creator: publish cancel so other acceptors know the offer is taken
  if (iAmCreator) {
    createCancelEvent({ offerId: offer.id, offerEventId: offer.eventId, matchedPub: peerPubHex })
      .then(ev => nostrPublish(ev))
      .catch(() => {});
  }

  autoExecuteSwap();
}

function subscribeToSwap(sessionId, peerPubHex) {
  const existing = state.subscriptions.get('active_swap');
  if (existing) existing();

  swapEventWaiters.length = 0;

  subscribe('active_swap', [{
    kinds: [SWAP_SETUP_KIND, SWAP_NONCE_KIND, SWAP_PRESIG_KIND, SWAP_CLAIM_KIND],
    '#e': [sessionId],
    authors: [state.pubKeyHex, peerPubHex],
  }], async (event) => {
    const isMine = event.pubkey === state.pubKeyHex;
    const authorLabel = isMine ? 'You' : event.pubkey.slice(0, 8) + '...';
    if (!isMine) state.lastPeerEventAt = Date.now();

    // Decrypt the NIP-44 content; anything else from the peer is ignored (no plaintext fallback)
    let decryptedContent;
    try {
      decryptedContent = await nip04Decrypt(event.content, peerPubHex);
    } catch {
      addLogMsg('system', `Ignoring a swap message that is not NIP-44 encrypted to us (kind ${event.kind})`, 'System');
      return;
    }

    // Detect abort from peer
    if (!isMine && event.kind === SWAP_SETUP_KIND) {
      try {
        const parsed = JSON.parse(decryptedContent);
        if (parsed.type === 'abort') {
          addLogMsg('system', 'Peer aborted the swap', 'System');
          handlePeerAbort();
          return;
        }
      } catch {}
    }

    addProtocolMsg(event.kind, decryptedContent, authorLabel);
    if (!isMine) { let t = ''; try { const c = JSON.parse(decryptedContent); t = c.type || c.phase || (c.btcPresig ? 'pre-signatures' : ''); } catch {} notify('Swap: the peer acted', t ? `Received ${t}` : 'New message from the peer', 'peer'); }

    const decryptedEvent = { ...event, content: decryptedContent };
    for (let i = swapEventWaiters.length - 1; i >= 0; i--) {
      const w = swapEventWaiters[i];
      if (decryptedEvent.kind === w.kind && decryptedEvent.pubkey === w.fromPub) {
        if (!w.predicate || w.predicate(decryptedEvent)) {
          clearTimeout(w.timer);
          swapEventWaiters.splice(i, 1);
          w.resolve(decryptedEvent);
        }
      }
    }
  });
}

async function handlePeerAbort() {
  if (!state.activeSwap) return;

  // Reject all pending swap event waiters
  for (const w of swapEventWaiters) {
    clearTimeout(w.timer);
    w.reject(new Error('Peer aborted swap'));
  }
  swapEventWaiters.length = 0;

  markOfferProcessed(state.activeSwap.offerId);
  const lockDone = state.stepData.lock?.status === 'done' || ownFundsOnChain();
  const offer = state.offers.get(state.activeSwap.offerId);
  if (offer) offer.status = lockDone ? 'aborted_locked' : 'aborted';

  if (lockDone) {
    saveSwapState();
    renderOffersList();
    await transitionToRecovery();
  } else {
    resetSwap();
  }
}

// ============================================================
// Auto-Execute Swap
// ============================================================

// Every step checks that the swap it started for is still the active one: an
// abort, a peer abort or a reset ends the chain (a step that was awaiting a
// confirmation must not go on to deploy or lock).
function stepGuard(run) { return () => { if (state.swapRun !== run) throw new Error('Swap aborted'); }; }

async function autoExecuteSwap() {
  if (!state.activeSwap) return;
  const { role } = state.activeSwap;
  const run = state.swapRun = {}; const check = stepGuard(run);

  try {
    updateStep('setup', { status: 'active' });
    if (role === 'alice') {
      await executeSetupAlice();
    } else {
      await executeSetupBob();
    }
    check();
    updateStep('setup', { status: 'done' });

    if (state.stepData.lock?.status !== 'done') {
      updateStep('lock', { status: 'active' });
      if (role === 'alice') {
        await executeLockAlice();
      } else {
        await executeLockBob();
      }
      check();
      updateStep('lock', { status: 'done' });
      saveSwapState();
    }

    updateStep('nonces', { status: 'active' });
    await executeNonces(); check();
    updateStep('nonces', { status: 'done' });

    updateStep('presign', { status: 'active' });
    await executePresign(); check();
    updateStep('presign', { status: 'done' });
    saveSwapState();

    updateStep('claim', { status: 'active' });
    if (role === 'alice') {
      await executeClaimAlice();
    } else {
      await executeClaimBob();
    }
    check();
    updateStep('claim', { status: 'done' });

    showSwapComplete();

  } catch (e) {
    if (!state.activeSwap) { addLogMsg('system', 'Swap step ended after the swap was aborted', 'System'); return; }
    addLogMsg('system', `Swap error: ${e.message}`, 'Error');
  }
}

async function retryStep(stepId) {
  if (!state.activeSwap) return;
  const { role } = state.activeSwap;

  updateStep(stepId, { status: 'active', error: null });
  const run = state.swapRun = {}; const check = stepGuard(run);

  try {
    const stepFns = {
      alice: { setup: executeSetupAlice, lock: executeLockAlice, nonces: executeNonces, presign: executePresign, claim: executeClaimAlice },
      bob: { setup: executeSetupBob, lock: executeLockBob, nonces: executeNonces, presign: executePresign, claim: executeClaimBob },
    };
    await stepFns[role][stepId](); check();
    updateStep(stepId, { status: 'done' });
    saveSwapState();

    const stepOrder = ['setup', 'lock', 'nonces', 'presign', 'claim'];
    const idx = stepOrder.indexOf(stepId);
    for (let i = idx + 1; i < stepOrder.length; i++) {
      const nextStep = stepOrder[i];
      if (state.stepData[nextStep]?.status === 'done') continue;
      updateStep(nextStep, { status: 'active' });
      await stepFns[role][nextStep](); check();
      updateStep(nextStep, { status: 'done' });
      saveSwapState();
    }
    showSwapComplete();
  } catch (e) {
    addLogMsg('system', `Retry error: ${e.message}`, 'Error');
  }
}

// ============================================================
// Step Execution: Alice
// ============================================================

async function executeSetupAlice() {
  const { sessionId, peerPubHex, btcSat, alphAmount } = state.activeSwap;
  const btcAmount = btcSat / 1e8;

  try {
    const initResult = state.engine.initSwap('alice', state.activeSwap.peer || peerPubHex, btcAmount, String(alphAmount), sessionId);
    saveSwapState(); // the adaptor secret and the session survive a reload from here on

    state.stepData.setup = { ...state.stepData.setup, adaptorPoint: initResult.adaptorPoint };
    updateStep('setup', { info: `adaptorPoint: ${initResult.adaptorPoint?.slice(0, 24)}...\nSending to peer...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'confirm',
      pubkey: state.pubKeyHex, adaptorPoint: initResult.adaptorPoint,
    });
    await nostrPublish(event);

    updateStep('setup', { info: `adaptorPoint sent. Waiting for Bob's BTC lock...` });

    const btcLockedEvent = await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'btc_locked', CHAIN_WAIT_MS);
    const btcLocked = JSON.parse(btcLockedEvent.content);

    if (btcLocked.btcLocktime === undefined) throw new Error('Peer runs an old version without the BTC locktime: refusing to lock');
    const { confirmations } = await state.engine.verifyBtc(btcLocked.txid, btcLocked.vout, btcLocked.btcLocktime,
      (have, need) => updateStep('setup', { info: `BTC lock ${btcLocked.txid.slice(0, 16)}...: ${have}/${need} confirmations (not locking ALPH before that; ${BTC_BLOCK_HINT})` }));

    updateStep('setup', { info: `BTC locked: ${btcLocked.txid.slice(0, 16)}... verified with ${confirmations} confirmation(s)` });
  } catch (e) {
    updateStep('setup', { status: 'error', error: e.message });
    throw e;
  }
}

async function executeLockAlice() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    updateStep('lock', { info: 'Deploying the ALPH contract...' });
    const deployResult = await state.engine.deployAlph((m) => updateStep('lock', { info: m }));
    saveSwapState(); // the contract is on chain: remember it before anything else can go wrong
    updateStep('lock', { info: `ALPH deployed: ${deployResult.contractAddress.slice(0, 16)}...\nSending to peer...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'alph_deployed',
      contractId: deployResult.contractId, contractAddress: deployResult.contractAddress, claimFeeSat: deployResult.claimFeeSat, deployTxId: deployResult.txId,
    });
    await nostrPublish(event);

    updateStep('lock', { info: `ALPH: ${deployResult.contractAddress.slice(0, 16)}...\nWaiting for Bob to verify...` });
    await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'verified', CHAIN_WAIT_MS);

    state.engine.computeContext();
    updateStep('lock', { info: `ALPH: ${deployResult.contractAddress.slice(0, 16)}... | Bob verified | Context computed` });
  } catch (e) {
    updateStep('lock', { status: 'error', error: e.message });
    throw e;
  }
}

// While Alice's claim is unconfirmed, bump it (child pays for parent) if the
// fee floor has moved above its rate: Bob claims the ALPH only once the claim
// is confirmed, and the signet floor moved 1 -> 6 sat/vB during a live run.
function watchClaimFee(claimTxid) {
  let bumped = false;
  const started = Date.now();
  const timer = setInterval(async () => {
    try {
      if (bumped || Date.now() - started < 5 * 60_000) return;
      if (await state.engine.getClaimConfirmations() > 0) { clearInterval(timer); return; }
      const need = await estimateFeeRate();
      const have = state.engine.claimFeeSat / CLAIM_VBYTES;
      if (need <= have) return;
      bumped = true;
      const r = await state.engine.bumpClaimFee();
      addLogMsg('claim', `Claim ${claimTxid.slice(0, 12)}... paid ${have.toFixed(1)} sat/vB, the floor is ${need}: bumped with child ${r.txid.slice(0, 16)}... (${r.childFee} sat, ${r.feeRate} sat/vB)`, 'You');
      updateStep('claim', { info: `BTC claimed: ${claimTxid.slice(0, 16)}... (fee bumped: ${r.feeRate} sat/vB)\nWaiting for Bob to claim ALPH...` });
    } catch (e) { addLogMsg('claim', `Fee bump check failed: ${e.message}`, 'Error'); }
  }, 60_000);
  return () => clearInterval(timer);
}

// Bob's lock, like Alice's claim, is bumped (child pays for parent from the
// change output) when it sits unconfirmed under the fee floor.
function watchLockFee(lockTxid) {
  const started = Date.now();
  const timer = setInterval(async () => {
    try {
      if (Date.now() - started < 5 * 60_000) return;
      if (await state.engine.getLockConfirmations() > 0) { clearInterval(timer); return; }
      if (!state.engine.lockBumpable()) return;
      const need = await estimateFeeRate();
      const have = state.engine.lockFeeRate();
      if (need <= have) return;
      const r = await state.engine.bumpLockFee();
      addLogMsg('lock', `Lock ${lockTxid.slice(0, 12)}... paid ${have.toFixed(1)} sat/vB, the floor is ${need}: bumped with child ${r.txid.slice(0, 16)}... (${r.childFee} sat, ${r.feeRate} sat/vB)`, 'You');
      updateStep('lock', { info: `BTC locked: ${lockTxid.slice(0, 16)}... (fee bumped to ${r.feeRate} sat/vB)\nWaiting for Alice to deploy ALPH (${BTC_BLOCK_HINT}).` });
      saveSwapState();
    } catch (e) { addLogMsg('lock', `Lock fee bump check failed: ${e.message}`, 'Error'); }
  }, 60_000);
  return () => clearInterval(timer);
}

async function bumpLockNow() {
  try {
    const r = await state.engine.bumpLockFee();
    addLogMsg('lock', `Lock bumped with child ${r.txid.slice(0, 16)}... (${r.childFee} sat, ${r.feeRate} sat/vB)`, 'You');
    saveSwapState();
  } catch (e) { await modalAlert(`Cannot bump the lock: ${e.message}`); }
}

async function executeClaimAlice() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    const result = await state.engine.claimBtc();
    updateStep('claim', { info: `BTC claimed! txid: ${result.txid.slice(0, 24)}...`, btcClaimTxid: result.txid });
    saveSwapState();

    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'btc_claimed',
      txid: result.txid,
    });
    await nostrPublish(event);

    updateStep('claim', { info: `BTC claimed: ${result.txid.slice(0, 16)}...\nWaiting for Bob to claim ALPH...` });
    const stopWatch = watchClaimFee(result.txid);
    let alphClaimedEvent;
    try {
      alphClaimedEvent = await waitForSwapEvent(SWAP_CLAIM_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).type === 'alph_claimed', CHAIN_WAIT_MS);
    } finally { stopWatch(); }
    const alphClaimed = JSON.parse(alphClaimedEvent.content);
    updateStep('claim', { info: `BTC claimed: ${result.txid.slice(0, 16)}...\nBob claimed ALPH: ${alphClaimed.txid.slice(0, 16)}...`, alphClaimTxid: alphClaimed.txid });
    await refreshBalance();
  } catch (e) {
    updateStep('claim', { status: 'error', error: e.message });
    throw e;
  }
}

// ============================================================
// Step Execution: Bob
// ============================================================

async function executeSetupBob() {
  const { sessionId, peerPubHex, btcSat, alphAmount } = state.activeSwap;
  const btcAmount = btcSat / 1e8;

  try {
    updateStep('setup', { info: 'Waiting for Alice\'s confirmation...' });
    const confirmEvent = await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'confirm');
    const confirm = JSON.parse(confirmEvent.content);

    state.engine.initSwap('bob', state.activeSwap.peer || peerPubHex, btcAmount, String(alphAmount), sessionId);
    state.engine.setAdaptorPoint(confirm.adaptorPoint);
    saveSwapState();

    updateStep('setup', { info: `adaptorPoint: ${confirm.adaptorPoint.slice(0, 24)}...` });
  } catch (e) {
    updateStep('setup', { status: 'error', error: e.message });
    throw e;
  }
}

async function executeLockBob() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    const utxo = state.selectedUtxo || null;
    updateStep('lock', { info: 'Locking BTC...' });
    const lockResult = await state.engine.lockBtc(utxo, (m) => updateStep('lock', { info: m }));
    saveSwapState(); // the lock is on chain: remember it before anything else can go wrong
    updateStep('lock', { info: `BTC locked: ${lockResult.txid.slice(0, 16)}... vout=${lockResult.vout}\nPublishing...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'btc_locked',
      txid: lockResult.txid, vout: lockResult.vout, amountSat: lockResult.amountSat, btcLocktime: lockResult.btcLocktime,
    });
    await nostrPublish(event);

    const lockDepth = btcConfirmationsFor(state.activeSwap.btcSat, BTC_NETWORK_NAME);
    updateStep('lock', { info: `BTC locked: ${lockResult.txid.slice(0, 16)}...\nWaiting for Alice to deploy ALPH. She first waits for ${lockDepth} confirmation(s) of this lock (${BTC_BLOCK_HINT}), so this step takes a while.` });
    renderSwapActions(); // the bump button appears once a lock exists
    const stopLockWatch = watchLockFee(lockResult.txid);
    let alphDeployedEvent;
    try {
      alphDeployedEvent = await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).type === 'alph_deployed', CHAIN_WAIT_MS);
    } finally { stopLockWatch(); }
    const alphDeployed = JSON.parse(alphDeployedEvent.content);

    if (alphDeployed.claimFeeSat === undefined || !alphDeployed.deployTxId) throw new Error('Peer runs an old version without the claim fee or the deployment txid: refusing to continue');
    await state.engine.verifyAlph(alphDeployed.contractId, alphDeployed.contractAddress, alphDeployed.claimFeeSat, alphDeployed.deployTxId,
      (have, need) => updateStep('lock', { info: `ALPH contract ${alphDeployed.contractAddress.slice(0, 16)}...: deployment ${have}/${need} confirmations (${ALPH_BLOCK_HINT})` }));

    const verifiedEvent = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'verified',
    });
    await nostrPublish(verifiedEvent);

    state.engine.computeContext();
    updateStep('lock', { info: `BTC: ${lockResult.txid.slice(0, 16)}... | ALPH: ${alphDeployed.contractAddress.slice(0, 12)}... | Verified` });
  } catch (e) {
    updateStep('lock', { status: 'error', error: e.message });
    throw e;
  }
}

async function executeClaimBob() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    // Bob must claim before T_alph (12 h after his own refund opens): show the slack
    let base = 'Waiting for Alice to claim BTC...';
    const tAlphLine = () => state.engine.alphTimeoutMs ? `\nYour ALPH claim must be in before T_alph: ${fmtRemaining(state.engine.alphTimeoutMs - Date.now())} left` : '';
    const setInfo = (text) => { base = text; updateStep('claim', { info: base + tAlphLine() }); };
    setInfo(base);
    const countdown = setInterval(() => setInfo(base), 30000);
    let btcClaimed, result;
    try {
      const btcClaimedEvent = await waitForSwapEvent(SWAP_CLAIM_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).type === 'btc_claimed', CHAIN_WAIT_MS);
      btcClaimed = JSON.parse(btcClaimedEvent.content);

      state.engine.btcClaimTxid = btcClaimed.txid;
      saveSwapState();
      setInfo(`Alice claimed BTC: ${btcClaimed.txid.slice(0, 16)}...\nExtracting secret and claiming ALPH...`);
      updateStep('claim', { btcClaimTxid: btcClaimed.txid });

      result = await state.engine.claimAlph(btcClaimed.txid,
        (have, need) => setInfo(`Alice's BTC claim ${btcClaimed.txid.slice(0, 16)}...: ${have}/${need} confirmations before claiming ALPH (${BTC_BLOCK_HINT})`));
    } finally { clearInterval(countdown); }

    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'alph_claimed',
      txid: result.txid,
    });
    await nostrPublish(event);

    updateStep('claim', { info: `Alice BTC: ${btcClaimed.txid.slice(0, 16)}...\nALPH claimed: ${result.txid.slice(0, 16)}...`, alphClaimTxid: result.txid });
    await refreshBalance();
  } catch (e) {
    updateStep('claim', { status: 'error', error: e.message });
    throw e;
  }
}

// ============================================================
// Shared Steps: Nonces & Pre-sign
// ============================================================

async function executeNonces() {
  const { sessionId, peerPubHex, role } = state.activeSwap;
  const isAlice = role === 'alice';

  try {
    const commitResult = state.engine.nonceCommit();

    if (isAlice) {
      const commitEvent = await createSwapNonce({
        sessionId, recipientPubHex: peerPubHex, phase: 'commit',
        btcNonceHash: commitResult.btcNonceHash, alphNonceHash: commitResult.alphNonceHash,
      });
      await nostrPublish(commitEvent);
      updateStep('nonces', { info: 'Commitment sent. Waiting for peer...' });

      const peerCommitEvent = await waitForSwapEvent(SWAP_NONCE_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).phase === 'commit');
      const peerCommit = JSON.parse(peerCommitEvent.content);

      const revealResult = state.engine.nonceReveal(peerCommit.btcNonceHash, peerCommit.alphNonceHash);

      const revealEvent = await createSwapNonce({
        sessionId, recipientPubHex: peerPubHex, phase: 'reveal',
        btcPubNonce: revealResult.btcPubNonce, alphPubNonce: revealResult.alphPubNonce,
      });
      await nostrPublish(revealEvent);
      updateStep('nonces', { info: 'Nonces revealed. Waiting for peer reveal...' });

      const peerRevealEvent = await waitForSwapEvent(SWAP_NONCE_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).phase === 'reveal');
      const peerReveal = JSON.parse(peerRevealEvent.content);

      state.engine.nonceVerify(peerReveal.btcPubNonce, peerReveal.alphPubNonce);
    } else {
      updateStep('nonces', { info: 'Waiting for Alice\'s commitment...' });
      const peerCommitEvent = await waitForSwapEvent(SWAP_NONCE_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).phase === 'commit');
      const peerCommit = JSON.parse(peerCommitEvent.content);

      const commitEvent = await createSwapNonce({
        sessionId, recipientPubHex: peerPubHex, phase: 'commit',
        btcNonceHash: commitResult.btcNonceHash, alphNonceHash: commitResult.alphNonceHash,
      });
      await nostrPublish(commitEvent);

      updateStep('nonces', { info: 'Commitment exchanged. Waiting for peer reveal...' });
      const peerRevealEvent = await waitForSwapEvent(SWAP_NONCE_KIND, sessionId, peerPubHex,
        (e) => JSON.parse(e.content).phase === 'reveal');
      const peerReveal = JSON.parse(peerRevealEvent.content);

      const revealResult = state.engine.nonceReveal(peerCommit.btcNonceHash, peerCommit.alphNonceHash);

      const revealEvent = await createSwapNonce({
        sessionId, recipientPubHex: peerPubHex, phase: 'reveal',
        btcPubNonce: revealResult.btcPubNonce, alphPubNonce: revealResult.alphPubNonce,
      });
      await nostrPublish(revealEvent);

      state.engine.nonceVerify(peerReveal.btcPubNonce, peerReveal.alphPubNonce);
    }

    updateStep('nonces', { info: 'Nonces committed, revealed, verified, and aggregated' });
  } catch (e) {
    updateStep('nonces', { status: 'error', error: e.message });
    throw e;
  }
}

async function executePresign() {
  const { sessionId, peerPubHex, role } = state.activeSwap;
  const isAlice = role === 'alice';

  try {
    const presigResult = state.engine.presign();

    if (isAlice) {
      const presigEvent = await createSwapPresig({
        sessionId, recipientPubHex: peerPubHex,
        btcPresig: presigResult.btcPresig, alphPresig: presigResult.alphPresig,
      });
      await nostrPublish(presigEvent);
      updateStep('presign', { info: 'Pre-signatures sent. Waiting for peer...' });

      const peerPresigEvent = await waitForSwapEvent(SWAP_PRESIG_KIND, sessionId, peerPubHex);
      const peerPresigs = JSON.parse(peerPresigEvent.content);

      state.engine.verifyPresig(peerPresigs.btcPresig, peerPresigs.alphPresig);
    } else {
      updateStep('presign', { info: 'Waiting for Alice\'s pre-signatures...' });
      const peerPresigEvent = await waitForSwapEvent(SWAP_PRESIG_KIND, sessionId, peerPubHex);
      const peerPresigs = JSON.parse(peerPresigEvent.content);

      state.engine.verifyPresig(peerPresigs.btcPresig, peerPresigs.alphPresig);

      const presigEvent = await createSwapPresig({
        sessionId, recipientPubHex: peerPubHex,
        btcPresig: presigResult.btcPresig, alphPresig: presigResult.alphPresig,
      });
      await nostrPublish(presigEvent);
    }

    updateStep('presign', { info: 'Pre-signatures exchanged, verified, aggregated with taproot tweak' });
  } catch (e) {
    updateStep('presign', { status: 'error', error: e.message });
    throw e;
  }
}

// ============================================================
// Refund
// ============================================================

async function refundAlph() {
  const btn = document.getElementById('recovery-refund-alph-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Refunding...'; }
  try {
    const result = await state.engine.refundAlph();
    showRecoveryStatus(`ALPH refunded! txid: ${result.txid.slice(0, 16)}...`, 'ok');
    addLogMsg('recovery', `ALPH refunded in ${result.txid}`, 'You');
    await refreshBalance();
  } catch (e) {
    showRecoveryStatus(`ALPH refund error: ${e.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Refund ALPH'; }
  }
}

async function refundBtc() {
  const btn = document.getElementById('recovery-refund-btc-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Refunding...'; }
  try {
    const result = await state.engine.refundBtc();
    showRecoveryStatus(`BTC refunded! txid: ${result.txid.slice(0, 16)}...`, 'ok');
    addLogMsg('recovery', `BTC refunded in ${result.txid}`, 'You');
    await refreshBalance();
  } catch (e) {
    showRecoveryStatus(`BTC refund error: ${e.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Refund BTC'; }
  }
}

function showRecoveryStatus(msg, type) {
  let el = document.getElementById('recovery-status-msg');
  if (!el) {
    el = document.createElement('div');
    el.id = 'recovery-status-msg';
    el.style.cssText = 'font-size:11px; padding:6px 0; word-break:break-all;';
    const actions = document.getElementById('swap-actions');
    if (actions) actions.appendChild(el);
  }
  el.style.color = type === 'error' ? '#f85149' : '#2ea043';
  el.textContent = msg;
}

// ============================================================
// Swap Complete
// ============================================================

function showSwapComplete() {
  clearSwapState();
  stopTimeoutMonitor();
  notify('Swap complete', 'Both sides have claimed', 'done');
  if (state.activeSwap) {
    markOfferProcessed(state.activeSwap.offerId); // prevent auto-restart on refresh
    const offer = state.offers.get(state.activeSwap.offerId);
    if (offer) { offer.status = 'completed'; renderOffersList(); }
    publishAttestation('completed');
    // a partially filled offer of mine: republish the remainder at the same rate
    if (offer?.isMine && offer.minAlph) {
      const remaining = BigInt(offer.alphAmount) - BigInt(state.activeSwap.alphAmount);
      if (remaining >= BigInt(offer.minAlph)) {
        const btcSat = btcSatFor(remaining.toString(), offer);
        const offerId = generateUUID();
        createOfferEvent({ offerId, direction: offer.direction, alphAmount: remaining, btcSat, expiresAt: Math.floor(Date.now() / 1000) + 86400, minAlph: remaining > BigInt(offer.minAlph) ? BigInt(offer.minAlph) : null })
          .then((ev) => nostrPublish(ev)).then(() => addLogMsg('system', `Remainder republished: ${formatAlph(remaining.toString())} ALPH for ${btcSat} sat`, 'You'))
          .catch((e) => addLogMsg('system', `Could not republish the remainder: ${e.message}`, 'Error'));
      }
    }
  }
  const { alphAmount, btcSat, role } = state.activeSwap;
  const claimData = state.stepData.claim || {};
  const btcTxid = claimData.btcClaimTxid;
  const alphTxid = claimData.alphClaimTxid;
  const btcLabel = `${formatSat(btcSat)} sat`;
  const alphLabel = `${formatAlph(alphAmount)} ALPH`;
  const btcHtml = btcTxid
    ? `<a href="${CONFIG.btcExplorer}/tx/${btcTxid}" target="_blank" class="amount-link" style="color:#f7931a">${btcLabel}</a>`
    : `<span style="color:#f7931a">${btcLabel}</span>`;
  const alphHtml = alphTxid
    ? `<a href="${CONFIG.alphExplorer}/transactions/${alphTxid}" target="_blank" class="amount-link" style="color:#00d4aa">${alphLabel}</a>`
    : `<span style="color:#00d4aa">${alphLabel}</span>`;
  const actionsEl = document.getElementById('swap-actions');
  actionsEl.innerHTML = `
    <div class="swap-complete" style="width:100%">
      <h3>Swap Complete!</h3>
      <div style="font-size:12px; margin-top:4px">
        ${role === 'alice' ? 'Received' : 'Sent'} ${btcHtml} &harr;
        ${role === 'alice' ? 'Sent' : 'Received'} ${alphHtml}
      </div>
      <button class="sm" id="new-swap-btn" style="margin-top:12px">Clear Active Swap History</button>
    </div>
  `;
  document.getElementById('new-swap-btn').addEventListener('click', resetSwap);
}

async function sendAbortNotification() {
  if (!state.activeSwap) return;
  const { sessionId, peerPubHex } = state.activeSwap;
  try {
    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'abort',
      reason: 'User aborted swap',
    });
    await nostrPublish(event);
  } catch (e) {
    console.warn('Failed to send abort notification:', e);
  }
}

// Bob has coins on chain once his lock is broadcast; Alice once her contract is
// deployed (her engine also records Bob's lock txid, which is not her money).
function ownFundsOnChain() {
  if (!state.activeSwap || !state.engine) return false;
  return state.activeSwap.role === 'bob' ? !!state.engine.btcLockTxid : !!state.engine.contractId;
}

async function abortSwap() {
  if (!state.activeSwap) return;
  // Anything of ours on chain (Bob's lock, Alice's contract) means recovery, not
  // a reset: the lock step is not "done" until the peer has acted, but the coins
  // are already committed (found by the local refund drill on 2026-10-01).
  const lockDone = state.stepData.lock?.status === 'done' || ownFundsOnChain();
  let msg = 'Abort this swap?';
  if (lockDone) {
    msg += '\n\nFunds are already locked on-chain. After aborting, the recovery UI will appear with refund options.';
  } else {
    msg += '\n\nNo funds have been locked yet. Safe to abort.';
  }
  if (!await modalConfirm(msg, 'Abort')) return;

  markOfferProcessed(state.activeSwap.offerId);
  const offer = state.offers.get(state.activeSwap.offerId);
  if (offer) offer.status = lockDone ? 'aborted_locked' : 'aborted';
  await sendAbortNotification();

  if (lockDone) {
    saveSwapState();
    addLogMsg('system', 'Swap aborted — transitioning to recovery...', 'System');
    renderOffersList();
    await transitionToRecovery();
  } else {
    resetSwap();
    addLogMsg('system', 'Swap aborted', 'System');
  }
}

function resetSwap() {
  clearSwapState();
  stopTimeoutMonitor();
  stopBtcClaimPoller();
  const unsub = state.subscriptions.get('active_swap');
  if (unsub) unsub();
  swapEventWaiters.forEach(w => clearTimeout(w.timer));
  swapEventWaiters.length = 0;

  state.activeSwap = null;
  state.stepData = {};
  state.selectedUtxo = null;
  state.swapRun = null;

  // Re-create engine for fresh swap state (keeps same keys)
  state.engine = new SwapEngine(state.keys);

  document.getElementById('swap-placeholder').classList.remove('hidden');
  document.getElementById('swap-active').classList.add('hidden');
  document.getElementById('utxo-bar').classList.add('hidden');

  renderOffersList();
  refreshBalance();
}

// ============================================================
// Auto-Connect
// ============================================================

const STORAGE_KEY = 'btc-alph-swap-nsec';           // plaintext secret (no passphrase)
const STORAGE_KEY_ENC = 'btc-alph-swap-nsec-enc';   // vault record (passphrase set)
const BACKUP_CONFIRMED_KEY = 'btc-alph-swap-backup-confirmed';
// Session vault key (AES-GCM, derived from the passphrase); null when no passphrase is set.
let vaultKey = null, vaultSalt = null;
const hasPassphrase = () => !!localStorage.getItem(STORAGE_KEY_ENC);
const SWAP_STATE_KEY = 'btc-alph-swap-state';
const PROCESSED_OFFERS_KEY = 'btc-alph-swap-processed';

function getProcessedOffers() {
  // Migrate from old key if needed
  const legacy = localStorage.getItem('btc-alph-swap-aborted');
  if (legacy) {
    localStorage.setItem(PROCESSED_OFFERS_KEY, legacy);
    localStorage.removeItem('btc-alph-swap-aborted');
  }
  try { return new Set(JSON.parse(localStorage.getItem(PROCESSED_OFFERS_KEY) || '[]')); }
  catch { return new Set(); }
}

function markOfferProcessed(offerId) {
  const processed = getProcessedOffers();
  processed.add(offerId);
  // Keep only the last 50 to avoid unbounded growth
  const arr = [...processed].slice(-50);
  localStorage.setItem(PROCESSED_OFFERS_KEY, JSON.stringify(arr));
}

// A stored key is never replaced: it may hold funds. With a passphrase set, the
// secret is only available after the vault is opened; a cancelled prompt leaves
// the page locked (nothing is deleted).
async function loadOrCreateNsec(statusEl) {
  const encRaw = localStorage.getItem(STORAGE_KEY_ENC);
  if (encRaw) {
    const record = JSON.parse(encRaw);
    for (;;) {
      const pass = await modalPrompt('This wallet is protected by a passphrase. Enter it to unlock (Cancel keeps the page locked).', { password: true, placeholder: 'passphrase' });
      if (pass === null) throw new Error('Wallet locked: reload and enter the passphrase to use it.');
      if (statusEl) statusEl.textContent = 'Unlocking...';
      try {
        const salt = saltOf(record);
        const key = await deriveVaultKey(pass, salt);
        const hex = await openString(key, record);
        if (!isMasterSecret(hexToBytes(hex))) throw new Error('bad record');
        vaultKey = key; vaultSalt = salt;
        localStorage.removeItem(STORAGE_KEY); // a plaintext copy has no business next to the vault
        return hex;
      } catch { await modalAlert('Wrong passphrase.'); }
    }
  }
  const hex = localStorage.getItem(STORAGE_KEY);
  if (hex && (hex.length === 32 || hex.length === 64)) return hex; // 12-word (16 bytes) or 24-word / nsec (32 bytes)
  // A fresh identity is 16 bytes of entropy: 12 words, every key derived from them (keys.js).
  const fresh = bytesToHex(newMasterSecret());
  localStorage.setItem(STORAGE_KEY, fresh);
  return fresh;
}

// Set, change or remove the passphrase. The secret and the current swap state are re-sealed.
async function setPassphrase() {
  if (hasPassphrase()) {
    if (!await modalConfirm('A passphrase is set. Remove it and store the key in clear again?', 'Remove')) return;
    localStorage.setItem(STORAGE_KEY, bytesToHex(state.secBytes));
    localStorage.removeItem(STORAGE_KEY_ENC);
    vaultKey = null; vaultSalt = null;
    saveSwapState();
    addLogMsg('system', 'Passphrase removed: the key is stored in clear in this browser.', 'System');
  } else {
    const p1 = await modalPrompt('Choose a passphrase (at least 8 characters). It encrypts your key and swap state in this browser. Losing it means losing access unless you have backed up your recovery words.', { password: true, placeholder: 'passphrase' });
    if (p1 === null) return;
    if (p1.length < 8) { await modalAlert('At least 8 characters.'); return; }
    const p2 = await modalPrompt('Repeat the passphrase:', { password: true, placeholder: 'passphrase again' });
    if (p2 !== p1) { await modalAlert('The passphrases differ.'); return; }
    const salt = newSalt();
    const key = await deriveVaultKey(p1, salt);
    const record = await sealString(key, salt, bytesToHex(state.secBytes));
    localStorage.setItem(STORAGE_KEY_ENC, JSON.stringify(record));
    localStorage.removeItem(STORAGE_KEY);
    vaultKey = key; vaultSalt = salt;
    saveSwapState();
    addLogMsg('system', 'Passphrase set: the key and the swap state are now encrypted at rest (PBKDF2-SHA256, AES-256-GCM).', 'System');
  }
  initPassphraseButton();
}

function initPassphraseButton() {
  const btn = document.getElementById('passphrase-btn');
  if (btn) btn.textContent = hasPassphrase() ? '\u{1F512} Passphrase set' : 'Set passphrase';
}

const groupOfPub = (pubHex, keyType) => groupOfAddress(addressFromPublicKey(pubHex, keyType || alphKeyTypeOf(pubHex)));

// Until 2026-09-27 the Nostr key was also the Bitcoin and Alephium key. Funds
// left at those addresses are shown and can be moved to the derived addresses.
async function checkLegacyFunds() {
  if (state.secBytes.length !== 32) return; // 12-word identities never had earlier schemes
  try {
    // the single-key scheme (before 2026-09-27) and the tagged-hash scheme (until 2026-10-01);
    // every scheme holding more than dust is listed and swept
    const schemes = [
      { name: 'single-key', engine: new SwapEngine(legacyKeys(state.secBytes)) },
      { name: 'tagged-hash', engine: new SwapEngine(deriveKeysV1(state.secBytes, groupOfPub)) },
    ];
    const found = [];
    for (const s of schemes) {
      const b = await s.engine.getBalances();
      const btcSat = b.btcConfirmedSat + b.btcUnconfirmedSat, alph = Number(b.alph);
      if (btcSat >= 1000 || alph >= 0.02) found.push({ ...s, btcSat, alph });
    }
    if (!found.length) return;
    const summary = found.map((f) => `${f.btcSat} sat at ${f.engine.btcAddress.slice(0, 12)}… and ${f.alph} ALPH at ${f.engine.alphAddress.slice(0, 12)}… (${f.name} scheme)`).join('; ');
    addLogMsg('system', `Funds on previous addresses: ${summary}. Use "Move legacy funds" to bring them to the current addresses.`, 'System');
    const div = document.createElement('div');
    div.style.cssText = 'background:#1f6feb;color:#fff;padding:8px;font-size:13px;text-align:center';
    div.innerHTML = `Your keys changed (now standard HD wallet keys). Previous addresses still hold ${found.reduce((a, f) => a + f.btcSat, 0)} sat and ${found.reduce((a, f) => a + f.alph, 0).toFixed(3)} ALPH. <button id="legacy-sweep-btn" class="sm" style="margin-left:8px">Move legacy funds</button>`;
    document.body.prepend(div);
    document.getElementById('legacy-sweep-btn').addEventListener('click', async () => {
      const btn = document.getElementById('legacy-sweep-btn'); btn.disabled = true; btn.textContent = 'Moving...';
      let failures = 0;
      for (const f of found) {
        try {
          if (f.btcSat >= 1000) { const txid = await f.engine.sweepBtc(state.btcAddress); addLogMsg('system', `Legacy BTC (${f.name}) swept in ${txid}`, 'You'); }
          if (f.alph >= 0.02) { const txId = await f.engine.sweepAlph(state.alphAddress); addLogMsg('system', `Legacy ALPH (${f.name}) swept in ${txId}`, 'You'); }
        } catch (e) { failures++; addLogMsg('system', `Legacy sweep (${f.name}) failed: ${e.message}`, 'Error'); }
      }
      div.textContent = failures ? 'Some legacy funds could not be moved; see the log.' : 'Legacy funds moved; they appear at the current addresses once confirmed.';
      setTimeout(refreshBalance, 5000);
      if (!failures) setTimeout(() => div.remove(), 8000);
    });
  } catch (e) { addLogMsg('system', `Legacy funds check failed: ${e.message}`, 'System'); }
}

function npubEncode(pubKeyHex) {
  const pubKeyBytes = hexToBytes(pubKeyHex);
  const words = bech32.toWords(pubKeyBytes);
  return bech32.encode('npub', words, 90);
}

function nsecEncode(secHex) {
  const secBytes = hexToBytes(secHex);
  const words = bech32.toWords(secBytes);
  return bech32.encode('nsec', words, 90);
}

// ============================================================
// State Persistence
// ============================================================

function saveSwapState() {
  if (!state.engine || !state.activeSwap) return;
  const checkpoint = state.engine.getCheckpoint();
  if (!checkpoint) return;
  try {
    const data = {
      checkpoint,
      timestamp: Date.now(),
      engine: state.engine.toJSON(),
      activeSwap: state.activeSwap,
      stepData: state.stepData,
    };
    const json = JSON.stringify(data);
    if (vaultKey) {
      // sealed asynchronously; writes are serialised so the latest state wins
      saveQueue = saveQueue.then(async () => {
        const record = await sealString(vaultKey, vaultSalt, json);
        localStorage.setItem(SWAP_STATE_KEY, 'enc:' + JSON.stringify(record));
      }).catch((e) => console.warn('Failed to seal swap state:', e));
    } else {
      localStorage.setItem(SWAP_STATE_KEY, json);
    }
  } catch (e) {
    console.warn('Failed to save swap state:', e);
  }
}
let saveQueue = Promise.resolve();

async function loadSwapState() {
  try {
    const raw = localStorage.getItem(SWAP_STATE_KEY);
    if (!raw) return null;
    if (raw.startsWith('enc:')) {
      if (!vaultKey) throw new Error('sealed swap state but no vault key');
      return JSON.parse(await openString(vaultKey, JSON.parse(raw.slice(4))));
    }
    return JSON.parse(raw);
  } catch (e) {
    addLogMsg('system', `Saved swap state could not be read: ${e.message}`, 'Error');
    return null;
  }
}

function clearSwapState() {
  localStorage.removeItem(SWAP_STATE_KEY);
}

// ============================================================
// Recovery
// ============================================================

let timeoutMonitorInterval = null;
let btcClaimPollerInterval = null;

function stopTimeoutMonitor() {
  if (timeoutMonitorInterval) { clearInterval(timeoutMonitorInterval); timeoutMonitorInterval = null; }
}

function stopBtcClaimPoller() {
  if (btcClaimPollerInterval) { clearTimeout(btcClaimPollerInterval); btcClaimPollerInterval = null; }
}

function renderSwapInfo(activeSwap) {
  const infoEl = document.getElementById('swap-info');
  const alphDisplay = formatAlph(activeSwap.alphAmount);
  const peerNpub = npubEncode(activeSwap.peerPubHex);
  infoEl.innerHTML = `
    <div class="row"><span class="label">Role</span><span class="value">${activeSwap.role === 'alice' ? 'Alice (ALPH seller)' : 'Bob (BTC seller)'}</span></div>
    <div class="row"><span class="label">Amount</span><span class="value"><span class="alph">${alphDisplay} ALPH</span> &harr; <span class="btc">${formatSat(activeSwap.btcSat)} sat</span></span></div>
    <div class="row"><span class="label">Peer</span><span class="value" style="font-size:10px"><a href="https://njump.me/${peerNpub}" target="_blank" class="npub-link" title="${peerNpub}">${peerNpub.slice(0, 20)}...</a></span></div>
    <div class="row"><span class="label">Session</span><span class="value" style="font-size:10px" title="Nostr event ID used to route swap messages">${activeSwap.sessionId.slice(0, 16)}...</span></div>
  `;
}

async function recoverSwap(saved) {
  try {
    state.engine.restoreFromJSON(saved.engine);
    await state.engine.rehydrate();
  } catch (e) {
    addLogMsg('system', `Recovery failed: ${e.message}. Clearing state.`, 'Error');
    clearSwapState();
    return;
  }

  state.activeSwap = saved.activeSwap;
  state.stepData = saved.stepData || {};

  document.getElementById('swap-placeholder').classList.add('hidden');
  document.getElementById('swap-active').classList.remove('hidden');

  renderSwapInfo(state.activeSwap);
  renderSteps();

  // Subscribe to swap events in case peer comes back
  subscribeToSwap(state.activeSwap.sessionId, state.activeSwap.peerPubHex);

  addLogMsg('system', `Recovered swap from checkpoint: ${saved.checkpoint} (saved ${new Date(saved.timestamp).toLocaleString()})`, 'System');

  showRecoveryUI(saved.checkpoint);
}

function showRecoveryUI(checkpoint) {
  renderRecoveryActions(checkpoint);
  startTimeoutMonitor();
  if (checkpoint === 'presigned' && state.activeSwap.role === 'bob') {
    pollForBtcClaim();
  }
}

async function transitionToRecovery() {
  state.swapRun = null; // any step still running for this swap stops at its next check
  // Stop active pollers/monitors
  stopBtcClaimPoller();
  stopTimeoutMonitor();

  // Unsubscribe active swap subscription
  const unsub = state.subscriptions.get('active_swap');
  if (unsub) unsub();

  // Reject remaining waiters
  for (const w of swapEventWaiters) {
    clearTimeout(w.timer);
    w.reject(new Error('Swap aborted'));
  }
  swapEventWaiters.length = 0;

  // Re-subscribe for late-arriving claim events
  if (state.activeSwap) {
    subscribeToSwap(state.activeSwap.sessionId, state.activeSwap.peerPubHex);
  }

  // Mark active steps as errored
  for (const step of STEPS) {
    if (state.stepData[step.id]?.status === 'active') {
      updateStep(step.id, { status: 'error', error: 'Swap aborted' });
    }
  }

  // Check on-chain state for the true checkpoint
  let checkpoint = state.engine?.getCheckpoint() || 'locked';
  checkpoint = await checkOnChainState(checkpoint);

  showRecoveryUI(checkpoint);
}

async function checkOnChainState(checkpoint) {
  try {
    // Check BTC lock tx exists on-chain
    if (state.engine?.btcLockTxid) {
      const txResp = await fetch(`${CONFIG.btcApi}/tx/${state.engine.btcLockTxid}`);
      if (!txResp.ok) {
        addLogMsg('system', 'BTC lock tx not found on-chain', 'System');
      }

      // Check if BTC lock output is already spent (claimed)
      if (state.engine.btcLockVout != null) {
        const outspendResp = await fetch(`${CONFIG.btcApi}/tx/${state.engine.btcLockTxid}/outspend/${state.engine.btcLockVout}`);
        if (outspendResp.ok) {
          const outspend = await outspendResp.json();
          if (outspend.spent && outspend.txid) {
            addLogMsg('system', `BTC already claimed on-chain: ${outspend.txid.slice(0, 24)}...`, 'System');
            state.engine.btcClaimTxid = outspend.txid;
            checkpoint = 'btc_claimed';
            saveSwapState();
          }
        }
      }
    }

    // Check ALPH contract balance
    if (state.engine?.contractAddress) {
      try {
        const bal = await getBalance(state.engine.contractAddress);
        if (BigInt(bal.balance || 0n) === 0n) {
          state.stepData._alphContractEmpty = true;
          addLogMsg('system', 'ALPH contract is empty (already refunded or claimed)', 'System');
        }
      } catch {
        // 404 or 500 = contract destroyed (the node answers 500 for a destroyed contract)
        state.stepData._alphContractEmpty = true;
      }
    }
  } catch (e) {
    console.warn('On-chain state check error:', e);
  }
  return checkpoint;
}

function renderRecoveryActions(checkpoint) {
  const actionsEl = document.getElementById('swap-actions');
  const role = state.activeSwap?.role;
  if (!role) return;

  const alphEmpty = state.stepData._alphContractEmpty;
  let html = `<div id="timeout-display" style="width:100%; font-size:11px; color:#8b949e; margin-bottom:8px;"></div>`;

  if (checkpoint === 'started') {
    html += `<button class="sm primary" id="recovery-resume-btn">Resume Swap</button> `;
    html += `<span style="color:#8b949e; font-size:12px">Swap interrupted before anything was locked. Resume continues from the first unfinished step (peer must be online).</span> `;
  } else if (checkpoint === 'btc_locked') {
    html += `<button class="sm primary" id="recovery-resume-btn">Resume Swap</button> `;
    if (state.engine.lockBumpable()) html += `<button class="sm" id="recovery-bump-lock-btn">Bump lock fee</button> `;
    html += `<span style="color:#8b949e; font-size:12px">BTC locked; Alice had not deployed yet. Resume waits for her contract (peer must be online).</span> `;
    html += `<button class="sm danger" id="recovery-refund-btc-btn" disabled>Refund BTC</button> `;
  } else if (checkpoint === 'locked') {
    html += `<button class="sm primary" id="recovery-resume-btn">Resume Swap</button> `;
    if (role === 'alice') {
      if (alphEmpty) {
        html += `<span style="color:#8b949e; font-size:12px">ALPH already refunded/claimed</span> `;
      } else {
        html += `<button class="sm danger" id="recovery-refund-alph-btn" disabled>Refund ALPH</button> `;
      }
    } else {
      html += `<button class="sm danger" id="recovery-refund-btc-btn" disabled>Refund BTC</button> `;
    }
  } else if (checkpoint === 'presigned') {
    if (role === 'alice') {
      html += `<button class="sm primary" id="recovery-claim-btc-btn">Claim BTC Now</button> `;
      if (alphEmpty) {
        html += `<span style="color:#8b949e; font-size:12px">ALPH already refunded/claimed</span> `;
      } else {
        html += `<button class="sm danger" id="recovery-refund-alph-btn" disabled>Refund ALPH</button> `;
      }
    } else {
      html += `<span style="color:#d29922; font-size:12px">Watching for Alice's BTC claim...</span> `;
      html += `<button class="sm danger" id="recovery-refund-btc-btn" disabled>Refund BTC</button> `;
    }
  } else if (checkpoint === 'btc_claimed') {
    if (role === 'alice') {
      html += `<span style="color:#2ea043; font-size:12px">BTC claimed. Waiting for Bob to claim ALPH.</span> `;
      html += `<button class="sm" id="recovery-bump-btn" title="Child pays for parent: spend the claim output at the current fee rate">Bump claim fee</button> `;
    } else if (alphEmpty) {
      html += `<span style="color:#2ea043; font-size:12px">ALPH already claimed. Swap complete!</span> `;
    } else {
      html += `<button class="sm primary" id="recovery-claim-alph-btn">Claim ALPH</button> `;
    }
  }

  html += `<button class="sm" id="recovery-clear-btn" style="margin-left:auto">Clear State</button>`;
  actionsEl.innerHTML = html;

  // Bind handlers
  const resumeBtn = document.getElementById('recovery-resume-btn');
  if (resumeBtn) resumeBtn.addEventListener('click', resumeSwapFromLocked);
  const bumpLockBtn = document.getElementById('recovery-bump-lock-btn');
  if (bumpLockBtn) bumpLockBtn.addEventListener('click', bumpLockNow);

  const claimBtcBtn = document.getElementById('recovery-claim-btc-btn');
  if (claimBtcBtn) claimBtcBtn.addEventListener('click', recoveryClaimBtc);

  const claimAlphBtn = document.getElementById('recovery-claim-alph-btn');
  if (claimAlphBtn) claimAlphBtn.addEventListener('click', recoveryClaimAlph);

  const bumpBtn = document.getElementById('recovery-bump-btn');
  if (bumpBtn) bumpBtn.addEventListener('click', async () => {
    bumpBtn.disabled = true;
    try {
      const r = await state.engine.bumpClaimFee();
      addLogMsg('claim', `Claim bumped: child ${r.txid.slice(0, 24)}... pays ${r.childFee} sat (${r.feeRate} sat/vB)`, 'You');
    } catch (e) {
      showRecoveryStatus(`Bump error: ${e.message}`, 'error');
    } finally {
      bumpBtn.disabled = false;
    }
  });

  const refundAlphBtn = document.getElementById('recovery-refund-alph-btn');
  if (refundAlphBtn) refundAlphBtn.addEventListener('click', refundAlph);

  const refundBtcBtn = document.getElementById('recovery-refund-btc-btn');
  if (refundBtcBtn) refundBtcBtn.addEventListener('click', refundBtc);

  const clearBtn = document.getElementById('recovery-clear-btn');
  if (clearBtn) clearBtn.addEventListener('click', async () => {
    if (!await modalConfirm('Clear saved swap state?\n\nThis will NOT refund your locked funds. You will need to manually recover them if the swap is incomplete.', 'Clear')) return;
    clearSwapState();
    resetSwap();
  });
}

async function recoveryClaimBtc() {
  const btn = document.getElementById('recovery-claim-btc-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Claiming...'; }
  try {
    const result = await state.engine.claimBtc();
    addLogMsg('claim', `BTC claimed! txid: ${result.txid}`, 'You');
    saveSwapState();

    // Notify Bob via Nostr
    const { sessionId, peerPubHex } = state.activeSwap;
    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'btc_claimed',
      txid: result.txid,
    });
    await nostrPublish(event).catch(() => {});

    updateStep('claim', { status: 'done', info: `BTC claimed: ${result.txid.slice(0, 24)}...` });
    await refreshBalance();
    renderRecoveryActions('btc_claimed');
  } catch (e) {
    showRecoveryStatus(`Claim BTC error: ${e.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Claim BTC Now'; }
  }
}

async function recoveryClaimAlph() {
  const btn = document.getElementById('recovery-claim-alph-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Claiming...'; }
  try {
    let btcClaimTxid = state.engine.btcClaimTxid;
    if (!btcClaimTxid) {
      // Try to find it on-chain
      addLogMsg('system', 'Searching for BTC claim transaction...', 'System');
      btcClaimTxid = await findBtcClaimTx();
      if (!btcClaimTxid) throw new Error('BTC claim transaction not found on-chain. Cannot extract adaptor secret.');
      state.engine.btcClaimTxid = btcClaimTxid;
      saveSwapState();
    }
    addLogMsg('system', `Found BTC claim tx: ${btcClaimTxid.slice(0, 24)}...`, 'System');

    const result = await state.engine.claimAlph(btcClaimTxid);
    addLogMsg('claim', `ALPH claimed! txid: ${result.txid}`, 'You');

    // Notify Alice via Nostr
    const { sessionId, peerPubHex } = state.activeSwap;
    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'alph_claimed',
      txid: result.txid,
    });
    await nostrPublish(event).catch(() => {});

    updateStep('claim', { status: 'done', info: `ALPH claimed: ${result.txid.slice(0, 24)}...` });
    await refreshBalance();
    showSwapComplete();
  } catch (e) {
    showRecoveryStatus(`Claim ALPH error: ${e.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Claim ALPH'; }
  }
}

async function findBtcClaimTx() {
  if (!state.engine.btcLockTxid || state.engine.btcLockVout == null) return null;
  try {
    const resp = await fetch(`${CONFIG.btcApi}/tx/${state.engine.btcLockTxid}/outspend/${state.engine.btcLockVout}`);
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.spent && data.txid) return data.txid;
  } catch {}
  return null;
}

function onBtcClaimDetected(txid) {
  if (state.engine.btcClaimTxid) return; // already handled
  stopBtcClaimPoller();
  state.engine.btcClaimTxid = txid;
  saveSwapState();
  addLogMsg('claim', `Detected BTC claim: ${txid.slice(0, 24)}...`, 'System');
  renderRecoveryActions('btc_claimed');
}

function pollForBtcClaim() {
  stopBtcClaimPoller();
  addLogMsg('system', 'Watching for BTC claim (Esplora polling + Nostr)...', 'System');

  // Fast path: listen for Nostr btc_claimed event from peer
  if (state.activeSwap) {
    const { sessionId, peerPubHex } = state.activeSwap;
    waitForSwapEvent(SWAP_CLAIM_KIND, sessionId, peerPubHex,
      (e) => { try { return JSON.parse(e.content).type === 'btc_claimed'; } catch { return false; } },
      3600000, // 1h timeout
    ).then(event => {
      const { txid } = JSON.parse(event.content);
      onBtcClaimDetected(txid);
    }).catch(() => {}); // timeout or unsubscribed — ignore
  }

  // Slow path: poll Esplora outspend — 5s for first minute, then 15s
  let pollCount = 0;
  const poll = async () => {
    const txid = await findBtcClaimTx();
    if (txid) { onBtcClaimDetected(txid); return; }
    pollCount++;
    const nextInterval = pollCount < 12 ? 5000 : 15000;
    btcClaimPollerInterval = setTimeout(poll, nextInterval);
  };
  btcClaimPollerInterval = setTimeout(poll, 3000);
}

async function resumeSwapFromLocked() {
  const btn = document.getElementById('recovery-resume-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Resuming...'; }
  addLogMsg('system', 'Resuming swap from locked checkpoint (peer must be online)...', 'System');

  const { role } = state.activeSwap;
  try {
    // The lock step was interrupted (Bob waiting for Alice's contract, or Alice
    // waiting for Bob's verification): re-run it. lockBtc/deployAlph reuse what
    // is already on chain, and retryStep continues with the following steps.
    if (state.stepData.lock?.status !== 'done') {
      // setup and lock steps are idempotent (same adaptor point, same lock, same contract)
      await retryStep(state.stepData.setup?.status !== 'done' ? 'setup' : 'lock');
      return;
    }
    // Context should already be computed from rehydrate, but ensure it
    if (!state.engine.ctx) state.engine.computeContext();

    updateStep('nonces', { status: 'active' });
    await executeNonces();
    updateStep('nonces', { status: 'done' });
    saveSwapState();

    updateStep('presign', { status: 'active' });
    await executePresign();
    updateStep('presign', { status: 'done' });
    saveSwapState();

    updateStep('claim', { status: 'active' });
    if (role === 'alice') {
      await executeClaimAlice();
    } else {
      await executeClaimBob();
    }
    updateStep('claim', { status: 'done' });

    showSwapComplete();
  } catch (e) {
    addLogMsg('system', `Resume error: ${e.message}`, 'Error');
    if (btn) { btn.disabled = false; btn.textContent = 'Resume Swap'; }
  }
}

// ============================================================
// Timeout Monitoring
// ============================================================

function startTimeoutMonitor() {
  stopTimeoutMonitor();
  updateTimeoutDisplay();
  timeoutMonitorInterval = setInterval(updateTimeoutDisplay, 10000);
}

async function updateTimeoutDisplay() {
  const el = document.getElementById('timeout-display');
  if (!el || !state.engine) return;

  const lines = [];

  // ALPH timeout (T2)
  const alphTimeoutMs = state.engine.alphTimeoutMs;
  if (alphTimeoutMs) {
    const remaining = alphTimeoutMs - Date.now();
    if (remaining <= 0) {
      if (!state.stepData._alphRefundNotified) { state.stepData._alphRefundNotified = true; notify('ALPH refund available', 'The contract timeout has passed', 'refund'); }
      lines.push('ALPH refund: <span style="color:#2ea043">AVAILABLE NOW</span>');
      const refundBtn = document.getElementById('recovery-refund-alph-btn');
      if (refundBtn) refundBtn.disabled = false;
    } else {
      const hrs = Math.floor(remaining / 3600000);
      const mins = Math.floor((remaining % 3600000) / 60000);
      lines.push(`ALPH refund: ${hrs}h ${mins}m remaining`);
    }
  }

  // BTC timeout: the refund leaf's locktime against Bitcoin's median time past
  if (state.engine.btcLockTxid && state.engine.btcLocktime) {
    try {
      const mtp = await getMedianTimePast();
      const remaining = state.engine.btcLocktime - mtp;
      if (remaining <= 0) {
        if (!state.stepData._btcRefundNotified) { state.stepData._btcRefundNotified = true; notify('BTC refund available', 'Median time past reached the locktime', 'refund'); }
        lines.push('BTC refund: <span style="color:#2ea043">AVAILABLE NOW</span> (median time past reached the locktime)');
        const refundBtn = document.getElementById('recovery-refund-btc-btn');
        if (refundBtn) refundBtn.disabled = false;
        // Bob must not wait: while his BTC stays locked Alice can still claim it, and once
        // her refund opens she could keep both. Refund automatically as soon as possible.
        if (state.activeSwap?.role === 'bob' && state.engine.getCheckpoint() !== 'btc_claimed' && !state.stepData._btcRefundAttempted) {
          state.stepData._btcRefundAttempted = true;
          refundBtc().catch(() => { state.stepData._btcRefundAttempted = false; });
        }
      } else {
        const hrs = Math.floor(remaining / 3600);
        const mins = Math.floor((remaining % 3600) / 60);
        lines.push(`BTC refund: ${hrs}h ${mins}m remaining (median time past)`);
      }
    } catch (_) {
      lines.push('BTC refund: could not read the chain tip');
    }
  }
  el.innerHTML = lines.join('<br>');
}

async function autoConnect() {
  const statusEl = document.getElementById('connect-status');
  const errorEl = document.getElementById('connect-error');
  const errorMsgEl = document.getElementById('connect-error-msg');
  statusEl.textContent = 'Connecting...';
  errorEl.classList.add('hidden');

  try {
    const masterHex = await loadOrCreateNsec(statusEl);
    state.secBytes = hexToBytes(masterHex);
    initPassphraseButton();

    statusEl.textContent = 'Deriving identity...';
    // One secret (12 or 24 words), three keys: Nostr (NIP-06, or the secret itself for
    // 24-word identities), Bitcoin on BIP86 and Alephium on the wallet path in the target group.
    state.keys = deriveKeys(state.secBytes, groupOfPub);
    state.pubKeyHex = state.keys.nostr.pubHex;
    state.npub = npubEncode(state.pubKeyHex);

    // Create the swap engine
    state.engine = new SwapEngine(state.keys);
    state.btcAddress = state.engine.btcAddress;
    state.alphAddress = state.engine.alphAddress;
    state.network = 'testnet';

    statusEl.textContent = 'Connecting to Nostr relays...';
    const connected = await connectRelays(DEFAULT_RELAYS);

    // Update UI
    document.getElementById('connect-screen').style.display = 'none';
    document.getElementById('main-screen').classList.add('active');
    document.getElementById('info-npub').textContent = state.npub;
    document.getElementById('info-btc').textContent = state.btcAddress;
    document.getElementById('info-alph').textContent = state.alphAddress;

    // nsec in bech32 (stored in state, shown only when revealed)
    state.nsecBech32 = nsecEncode(bytesToHex(state.keys.nostr.sec));
    state.mnemonic = mnemonicOf(state.secBytes);
    state.wordCount = state.mnemonic.split(' ').length;

    const badge = document.getElementById('network-badge');
    badge.textContent = 'testnet';
    badge.className = 'network-badge testnet';

    // Backup state
    initBackupState();

    subscribeToOffers();
    refreshBalance();

    const relayNames = connected.map(r => r.url.replace('wss://', '')).join(', ');
    updateRelayStatus();
    addLogMsg('system', `Connected via ${connected.length} relays: ${relayNames}`, 'System');
    setInterval(updateRelayStatus, 10000);
    applyNetworkUi();
    checkBuild();
    registerServiceWorker();
    initNotifyButton();
    checkLegacyFunds();

    // Check for saved swap state to recover
    const savedSwap = await loadSwapState();
    if (savedSwap) {
      addLogMsg('system', 'Found saved swap state, recovering...', 'System');
      await recoverSwap(savedSwap);
    }
  } catch (e) {
    statusEl.textContent = '';
    errorMsgEl.textContent = 'Connection failed: ' + e.message;
    errorEl.classList.remove('hidden');
  }
}

// ============================================================
// Subscriptions
// ============================================================

function subscribeToOffers() {
  subscribe('offer_feed', [{
    kinds: [SWAP_OFFER_KIND],
    '#t': ['atomicswap'],
    since: Math.floor(Date.now() / 1000) - 172800,
  }], handleOfferEvent);
  // counterparty history: public 'started' and 'completed' notes over the last 60 days
  subscribe('history_feed', [{
    kinds: [SWAP_OFFER_KIND],
    '#t': ['completed', 'started'],
    since: Math.floor(Date.now() / 1000) - 60 * 86400,
  }], handleOfferEvent);
}

// ============================================================
// UTXOs
// ============================================================

async function refreshUtxos() {
  if (!state.engine) return;
  try {
    const utxos = await state.engine.getUtxoList();
    const sel = document.getElementById('utxo-select');
    sel.innerHTML = '<option value="">Auto-select best UTXO</option>';
    for (const u of utxos) {
      const conf = u.status?.confirmed ? 'conf' : 'unconf';
      const opt = document.createElement('option');
      opt.value = JSON.stringify({ txid: u.txid, vout: u.vout, value: u.value });
      opt.textContent = `${(u.value / 1e8).toFixed(8)} BTC  ${u.txid.slice(0, 12)}...:${u.vout} [${conf}]`;
      sel.appendChild(opt);
    }
  } catch {}
}

// ============================================================
// Relay Health
// ============================================================

function updateRelayStatus() {
  const el = document.getElementById('relay-status');
  const alive = state.relays.filter(r => r.ws.readyState === WebSocket.OPEN).length;
  const total = state.relays.length;
  const ago = (t) => { const s = Math.round((Date.now() - t) / 1000); return s < 60 ? `${s} s` : s < 3600 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`; };
  let text = alive < total ? `${alive}/${total} relays (reconnecting)` : `${alive}/${total} relays`;
  if (state.activeSwap && state.lastPeerEventAt) text += ` · peer ${ago(state.lastPeerEventAt)} ago`;
  el.textContent = text;
  el.title = state.lastEventAt ? `Last relay event ${ago(state.lastEventAt)} ago` : 'Connected Nostr relays';
  el.style.color = alive === 0 ? '#f85149' : alive < total ? '#d29922' : '#2ea043';

  // Fallback: trigger reconnect for relays that dropped without onclose firing
  for (const relay of state.relays) {
    if (relay.ready && relay.ws.readyState !== WebSocket.OPEN) {
      relay.ready = false;
      // Directly trigger reconnection since ws is already dead
      setTimeout(async () => {
        try {
          const ws = await connectRelay(relay.url);
          relay.ws = ws;
          relay.ready = true;
          setupRelayReconnect(relay);
          resubscribeRelay(relay);
          updateRelayStatus();
          addLogMsg('system', `Reconnected to ${relay.url.replace('wss://', '')}`, 'System');
        } catch {
          // Will retry on next updateRelayStatus cycle
        }
      }, 1000);
    }
  }
}

setInterval(() => {
  if (state.relays.length > 0) updateRelayStatus();
}, 10000);

// ============================================================
// Balance
// ============================================================

let balancePollTimer = null;

async function refreshBalance() {
  if (!state.engine) return;
  try {
    const bal = await state.engine.getBalances();

    const btcEl = document.getElementById('bal-btc');
    const alphEl = document.getElementById('bal-alph');

    btcEl.textContent = `${bal.btc} BTC`;
    alphEl.textContent = `${bal.alph} ALPH`;

    const hasPendingBtc = (bal.btcUnconfirmedSat || 0) > 0;
    btcEl.classList.toggle('pending', hasPendingBtc);
    if (hasPendingBtc) btcEl.title = `${(bal.btcConfirmedSat / 1e8).toFixed(8)} confirmed + ${(bal.btcUnconfirmedSat / 1e8).toFixed(8)} unconfirmed`;
    else btcEl.title = '';

    if (hasPendingBtc && !balancePollTimer) {
      balancePollTimer = setInterval(async () => {
        await refreshBalance();
      }, 10000);
    } else if (!hasPendingBtc && balancePollTimer) {
      clearInterval(balancePollTimer);
      balancePollTimer = null;
    }
  } catch {}
}

// ============================================================
// UI Event Handlers
// ============================================================

document.getElementById('refresh-bal-btn').addEventListener('click', refreshBalance);

// Reset key — strong confirmation
document.getElementById('reset-key-btn').addEventListener('click', async () => {
  const msg = 'WARNING: This replaces your current key.\n\n' +
    'All funds (BTC and ALPH) associated with this identity will be LOST ' +
    'unless you have backed up your recovery words (or, for a 24-word identity, the nsec).\n\n' +
    'Type RESET for a new 12-word identity, or paste 12 or 24 BIP39 words, or an nsec (nsec1... or 64 hex) to import one:';
  const input = (await modalPrompt(msg, { placeholder: 'RESET, 12 or 24 words, or nsec1...' }) || '').trim();
  if (!input) return;
  let importedHex = null;
  if (input !== 'RESET') {
    try {
      if (/^nsec1[a-z0-9]+$/i.test(input)) { const { words } = bech32.decode(input.toLowerCase(), 90); importedHex = bytesToHex(new Uint8Array(bech32.fromWords(words))); }
      else if (/^[0-9a-f]{64}$/i.test(input)) importedHex = input.toLowerCase();
      else if ([12, 24].includes(input.split(/\s+/).length)) importedHex = bytesToHex(entropyOf(input));
      else throw new Error('not 12 or 24 words, an nsec or 64 hex characters');
    } catch (e) { await modalAlert(`Cannot import: ${e.message}`); return; }
  }
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(STORAGE_KEY_ENC);
  localStorage.removeItem(BACKUP_CONFIRMED_KEY);
  if (importedHex) localStorage.setItem(STORAGE_KEY, importedHex);
  location.reload();
});

document.getElementById('retry-btn').addEventListener('click', () => autoConnect());

// Copy buttons (npub, btc, alph, nsec)
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const which = btn.dataset.copy;
    let text;
    if (which === 'btc') text = state.btcAddress;
    else if (which === 'alph') text = state.alphAddress;
    else if (which === 'npub') text = state.npub;
    else if (which === 'nsec') text = state.wordCount === 12 ? state.mnemonic : state.nsecBech32; // the backup that restores everything
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'ok!';
        setTimeout(() => { btn.textContent = 'copy'; }, 1200);
      });
    }
  });
});

// ---- Receive popup (QR + address, both copyable) ----

let receivePopupAddress = null;

function showReceivePopup(title, text) {
  receivePopupAddress = text;
  const popup = document.getElementById('receive-popup');
  const titleEl = document.getElementById('receive-popup-title');
  const qrEl = document.getElementById('receive-popup-qr');
  const addrEl = document.getElementById('receive-popup-addr');
  const statusEl = document.getElementById('receive-popup-status');

  titleEl.textContent = title;
  addrEl.textContent = text;
  statusEl.textContent = '';

  // Generate QR as canvas for copy-as-image support
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();

  const cellSize = 5;
  const margin = 8;
  const moduleCount = qr.getModuleCount();
  const size = moduleCount * cellSize + margin * 2;

  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = '#000000';
  for (let row = 0; row < moduleCount; row++) {
    for (let col = 0; col < moduleCount; col++) {
      if (qr.isDark(row, col)) {
        ctx.fillRect(col * cellSize + margin, row * cellSize + margin, cellSize, cellSize);
      }
    }
  }

  qrEl.innerHTML = '';
  qrEl.appendChild(canvas);
  popup.classList.remove('hidden');
}

// Click QR to copy as image
document.getElementById('receive-popup-qr').addEventListener('click', async () => {
  const statusEl = document.getElementById('receive-popup-status');
  const canvas = document.querySelector('#receive-popup-qr canvas');
  if (!canvas) return;
  try {
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
    statusEl.textContent = 'Copied QR image!';
    setTimeout(() => { statusEl.textContent = ''; }, 2000);
  } catch {
    statusEl.textContent = 'Copy image not supported in this browser';
    setTimeout(() => { statusEl.textContent = ''; }, 2000);
  }
});

// Click address to copy text
document.getElementById('receive-popup-addr').addEventListener('click', () => {
  const statusEl = document.getElementById('receive-popup-status');
  if (!receivePopupAddress) return;
  navigator.clipboard.writeText(receivePopupAddress).then(() => {
    statusEl.textContent = 'Copied address!';
    setTimeout(() => { statusEl.textContent = ''; }, 2000);
  });
});

// Close on click outside
document.getElementById('receive-popup').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    document.getElementById('receive-popup').classList.add('hidden');
  }
});

// npub QR button
document.querySelector('.qr-btn[data-qr="npub"]').addEventListener('click', () => {
  if (state.npub) showReceivePopup('npub', state.npub);
});

// Receive buttons (BTC, ALPH)
document.querySelectorAll('.recv-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const which = btn.dataset.recv;
    if (which === 'btc' && state.btcAddress) showReceivePopup('Receive BTC', state.btcAddress);
    else if (which === 'alph' && state.alphAddress) showReceivePopup('Receive ALPH', state.alphAddress);
  });
});

// ---- Send modal ----

let sendChain = null;

function showSendModal(chain) {
  sendChain = chain;
  const modal = document.getElementById('send-modal');
  const titleEl = document.getElementById('send-modal-title');
  const balEl = document.getElementById('send-modal-balance');
  const inputEl = document.getElementById('send-dest-addr');
  const errorEl = document.getElementById('send-modal-error');
  const statusEl = document.getElementById('send-modal-status');
  const confirmBtn = document.getElementById('send-confirm-btn');

  titleEl.textContent = chain === 'btc' ? 'Withdraw BTC' : 'Withdraw ALPH';
  balEl.textContent = chain === 'btc'
    ? `Balance: ${document.getElementById('bal-btc').textContent}`
    : `Balance: ${document.getElementById('bal-alph').textContent}`;
  inputEl.value = '';
  inputEl.placeholder = chain === 'btc' ? `${BTC_NETWORK_NAME} Bitcoin address` : 'Alephium address';
  errorEl.textContent = '';
  errorEl.classList.add('hidden');
  statusEl.textContent = '';
  statusEl.classList.add('hidden');
  confirmBtn.disabled = true;
  confirmBtn.textContent = 'Withdraw all';
  document.getElementById('send-addr-check').textContent = '';
  stopQrScan();
  modal.classList.remove('hidden');
  inputEl.focus();
}

// Validation of the destination as it is typed or scanned; the button stays off until it passes.
function checkDestination() {
  const input = document.getElementById('send-dest-addr');
  const checkEl = document.getElementById('send-addr-check');
  const confirmBtn = document.getElementById('send-confirm-btn');
  const addr = input.value.trim();
  const own = sendChain === 'btc' ? state.btcAddress : state.alphAddress;
  let ok = false, msg = '';
  if (!addr) msg = '';
  else if (addr === own) msg = 'That is this wallet\'s own address.';
  else if (sendChain === 'btc') {
    ok = SwapEngine.validateBtcAddress(addr);
    msg = ok ? `Valid ${BTC_NETWORK_NAME} Bitcoin address` : `Not a valid ${BTC_NETWORK_NAME} Bitcoin address${/^(bc1|1|3)/.test(addr) ? ' (this looks like a mainnet address)' : ''}`;
  } else {
    ok = SwapEngine.validateAlphAddress(addr);
    msg = ok ? `Valid Alephium address (group ${groupOfAddress(addr)})` : 'Not a valid Alephium address';
  }
  checkEl.textContent = msg;
  checkEl.style.color = ok ? '#2ea043' : addr ? '#f85149' : '#8b949e';
  confirmBtn.disabled = !ok || confirmBtn.textContent === 'Sending...';
  return ok;
}

let qrStop = null;
function stopQrScan() {
  if (qrStop) { try { qrStop(); } catch {} qrStop = null; }
  document.getElementById('send-scan-area').classList.add('hidden');
}
async function startQrScan() {
  const errorEl = document.getElementById('send-modal-error');
  errorEl.classList.add('hidden');
  if (!navigator.mediaDevices?.getUserMedia) { errorEl.textContent = 'This browser cannot open the camera here (a secure context is required).'; errorEl.classList.remove('hidden'); return; }
  document.getElementById('send-scan-area').classList.remove('hidden');
  const video = document.getElementById('send-qr-video');
  qrStop = await scanWithCamera(video, (text) => {
    qrStop = null; document.getElementById('send-scan-area').classList.add('hidden');
    const addr = addressFromQrText(text);
    document.getElementById('send-dest-addr').value = addr;
    if (!checkDestination()) { errorEl.textContent = `The QR code contains "${text.slice(0, 60)}", which is not a valid ${sendChain === 'btc' ? 'Bitcoin' : 'Alephium'} address for this network.`; errorEl.classList.remove('hidden'); }
  }, (message) => { errorEl.textContent = message; errorEl.classList.remove('hidden'); stopQrScan(); });
}

async function executeSend() {
  const destAddress = document.getElementById('send-dest-addr').value.trim();
  const errorEl = document.getElementById('send-modal-error');
  const statusEl = document.getElementById('send-modal-status');
  const confirmBtn = document.getElementById('send-confirm-btn');

  // Validated again right before signing, whatever the button state
  if (!checkDestination()) {
    errorEl.textContent = destAddress ? `Not a valid ${sendChain === 'btc' ? BTC_NETWORK_NAME + ' Bitcoin' : 'Alephium'} address` : 'Enter or scan a destination address';
    errorEl.classList.remove('hidden');
    return;
  }
  const chainName = sendChain === 'btc' ? 'BTC' : 'ALPH';
  if (!await modalConfirm(`Withdraw all ${chainName} to\n${destAddress}\n\nThis sends the whole balance; it cannot be undone.`, 'Withdraw')) return;

  errorEl.classList.add('hidden');
  confirmBtn.disabled = true;
  confirmBtn.textContent = 'Sending...';
  statusEl.textContent = 'Broadcasting transaction...';
  statusEl.classList.remove('hidden');

  try {
    let txid;
    if (sendChain === 'btc') {
      txid = await state.engine.sweepBtc(destAddress);
    } else {
      txid = await state.engine.sweepAlph(destAddress);
    }
    statusEl.textContent = `Withdrawn. txid: ${txid}`;
    confirmBtn.textContent = 'Done';
    addLogMsg('system', `${sendChain.toUpperCase()} withdrawn to ${destAddress.slice(0, 16)}...: ${txid}`, 'You');
    setTimeout(() => refreshBalance(), 3000);
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
    statusEl.classList.add('hidden');
    confirmBtn.textContent = 'Withdraw all';
    checkDestination();
  }
}

// Send buttons
document.querySelectorAll('.send-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    showSendModal(btn.dataset.send);
  });
});

document.getElementById('send-confirm-btn').addEventListener('click', executeSend);
document.getElementById('send-dest-addr').addEventListener('input', checkDestination);
document.getElementById('send-scan-btn').addEventListener('click', () => { startQrScan().catch((e) => addLogMsg('system', `QR scan failed: ${e.message}`, 'Error')); });
document.getElementById('send-scan-stop').addEventListener('click', stopQrScan);
document.getElementById('send-cancel-btn').addEventListener('click', () => {
  stopQrScan();
  document.getElementById('send-modal').classList.add('hidden');
});
document.getElementById('send-modal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    stopQrScan();
    document.getElementById('send-modal').classList.add('hidden');
  }
});

// nsec reveal/hide toggle
let nsecRevealed = false;
document.getElementById('nsec-reveal-btn').addEventListener('click', () => {
  const el = document.getElementById('key-info-nsec');
  const btn = document.getElementById('nsec-reveal-btn');
  nsecRevealed = !nsecRevealed;
  if (nsecRevealed) {
    el.textContent = state.wordCount === 12
      ? `${state.wordCount} words (your backup): ${state.mnemonic}\nnsec (Nostr key only, derived from the words): ${state.nsecBech32 || ''}`
      : `${state.nsecBech32 || ''}\n${state.wordCount} words: ${state.mnemonic}`;
    el.style.whiteSpace = 'pre-wrap';
    el.classList.remove('key-masked');
    btn.textContent = 'hide';
  } else {
    el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
    el.classList.add('key-masked');
    btn.textContent = 'show';
  }
});

// Backup confirmation
function initBackupState() {
  const confirmed = localStorage.getItem(BACKUP_CONFIRMED_KEY) === 'true';
  const keyRow = document.getElementById('key-row');
  const backupBtn = document.getElementById('backup-btn');
  const warning = document.getElementById('key-warning');

  if (confirmed) {
    keyRow.classList.remove('blink');
    backupBtn.textContent = '\u2713 Backed Up';
    backupBtn.classList.add('confirmed');
    warning.classList.add('hidden-warn');
  } else {
    keyRow.classList.add('blink');
    backupBtn.textContent = 'Backed Up';
    backupBtn.classList.remove('confirmed');
    warning.classList.remove('hidden-warn');
  }
}

document.getElementById('settings-btn').addEventListener('click', () => { showSettings().catch(() => {}); });
document.getElementById('notify-btn').addEventListener('click', () => { toggleNotifications().catch(() => {}); });
document.getElementById('passphrase-btn').addEventListener('click', () => { setPassphrase().catch((e) => addLogMsg('system', `Passphrase change failed: ${e.message}`, 'Error')); });

document.getElementById('backup-btn').addEventListener('click', async () => {
  const confirmed = await modalConfirm(
    'Have you saved your recovery words (or nsec) somewhere safe?\n\n' +
    'Without this key, all BTC and ALPH funds in this wallet will be permanently lost.\n\n' +
    'Click OK to confirm you have backed it up.', 'I backed it up'
  );
  if (!confirmed) return;
  localStorage.setItem(BACKUP_CONFIRMED_KEY, 'true');
  initBackupState();
});

document.getElementById('utxo-select').addEventListener('change', (e) => {
  state.selectedUtxo = e.target.value ? JSON.parse(e.target.value) : null;
});

document.querySelectorAll('#direction-toggle button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#direction-toggle button').forEach(b => {
      b.classList.remove('active', 'sell', 'buy');
    });
    btn.classList.add('active');
    btn.classList.add(btn.dataset.dir === 'sell_alph' ? 'sell' : 'buy');
    updateRateDisplay();
  });
});

function updateRateDisplay() {
  const alphVal = parseFloat(document.getElementById('offer-alph').value) || 0;
  const btcSat = parseInt(document.getElementById('offer-btc-sat').value) || 0;
  const el = document.getElementById('rate-display');
  if (alphVal > 0 && btcSat > 0) {
    const spa = satPerAlph(BigInt(Math.round(alphVal * 1e18)), btcSat);
    el.innerHTML = `Rate: ${rateLine(spa)}${state.market ? `<div class="rate-line">market ${marketSummary()}${state.market.reliable ? (satManual ? ' · <a href="#" id="use-market-rate">use market rate</a>' : ' · sat pre-set from it') : ''}</div>` : '<div class="rate-line">market reference unavailable</div>'}`;
    document.getElementById('use-market-rate')?.addEventListener('click', (e) => { e.preventDefault(); satManual = false; presetSatFromMarket(); });
  } else {
    el.textContent = 'Rate: --';
  }
}

document.getElementById('offer-alph').addEventListener('input', () => { presetSatFromMarket(); updateRateDisplay(); });
document.getElementById('offer-btc-sat').addEventListener('input', () => { satManual = true; updateRateDisplay(); });
updateRateDisplay();
refreshMarketRate(); setInterval(refreshMarketRate, 5 * 60_000);

// offer filters
document.querySelectorAll('#offer-filters [data-filter-dir]').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('#offer-filters [data-filter-dir]').forEach((x) => x.classList.remove('active')); b.classList.add('active');
  state.offerFilter.dir = b.dataset.filterDir; renderOffersList();
}));
document.getElementById('offer-sort').addEventListener('change', (e) => { state.offerFilter.sort = e.target.value; renderOffersList(); });
document.getElementById('offer-hide-mine').addEventListener('change', (e) => { state.offerFilter.hideMine = e.target.checked; renderOffersList(); });

document.getElementById('publish-offer-btn').addEventListener('click', publishOffer);

// Help modal
document.getElementById('help-btn').addEventListener('click', () => {
  document.getElementById('help-modal').classList.remove('hidden');
});
document.getElementById('help-close-btn').addEventListener('click', () => {
  document.getElementById('help-modal').classList.add('hidden');
});
document.getElementById('help-modal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    document.getElementById('help-modal').classList.add('hidden');
  }
});

// Petri net viewer (lazy init on first help open)
let petriViewer = null;
document.getElementById('help-btn').addEventListener('click', () => {
  if (!petriViewer) {
    petriViewer = new PetriNetViewer(document.getElementById('petri-viewer-container'));
  }
});

// Testnet: ALPH faucet
document.getElementById('alph-faucet-btn').addEventListener('click', async () => {
  if (!state.engine) return;
  const btn = document.getElementById('alph-faucet-btn');
  btn.disabled = true; btn.textContent = 'Wait...';
  try {
    const result = await state.engine.requestAlphFaucet();
    addLogMsg('system', `ALPH faucet: tokens on the way!`, 'System');
    setTimeout(() => refreshBalance(), 5000);
  } catch (e) {
    const msg = e.message || '';
    if (msg.includes('429') || msg.toLowerCase().includes('throttl') || msg.toLowerCase().includes('rate')) {
      addLogMsg('system', `ALPH faucet: throttled — you already requested tokens from this IP. Try again later.`, 'System');
    } else {
      addLogMsg('system', `ALPH faucet error: ${msg}`, 'Error');
    }
  }
  btn.disabled = false; btn.textContent = 'Faucet';
});

// ============================================================
// Init
// ============================================================

autoConnect().catch(e => {
  console.error('autoConnect fatal:', e);
  const s = document.getElementById('connect-status');
  const em = document.getElementById('connect-error-msg');
  const ee = document.getElementById('connect-error');
  if (s) s.textContent = '';
  if (em) em.textContent = 'Fatal: ' + e.message;
  if (ee) ee.classList.remove('hidden');
});
