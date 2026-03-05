// BTC-ALPH Atomic Swap — Static/Browser App
// Replaces server API calls with direct SwapEngine usage.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { bech32 } from 'bech32';
import qrcode from 'qrcode-generator';
import { SwapEngine } from './swap-engine.js';
import { groupOfAddress, addressFromPublicKey } from './alph.js';
import { getP2TRAddress } from './btc.js';

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
  logFilter: 'all',
};

// ============================================================
// Multi-Relay Nostr Client
// ============================================================

const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
];

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
          onEvent(event);
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
  event.sig = bytesToHex(schnorr.sign(hexToBytes(id), state.secBytes));
  return event;
}

function nostrPublish(event) {
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

function waitForSwapEvent(kind, sessionId, fromPub, predicate = null, timeoutMs = 600000) {
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
// NIP-04 Encryption (secp256k1 ECDH + AES-256-CBC)
// ============================================================

async function nip04Encrypt(plaintext, peerPubHex) {
  const sharedPoint = secp256k1.getSharedSecret(state.secBytes, '02' + peerPubHex);
  const sharedX = sharedPoint.slice(1, 33);
  const key = await crypto.subtle.importKey('raw', sharedX, { name: 'AES-CBC' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, encoded);
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext))) + '?iv=' + btoa(String.fromCharCode(...iv));
}

async function nip04Decrypt(ciphertext, peerPubHex) {
  const sharedPoint = secp256k1.getSharedSecret(state.secBytes, '02' + peerPubHex);
  const sharedX = sharedPoint.slice(1, 33);
  const key = await crypto.subtle.importKey('raw', sharedX, { name: 'AES-CBC' }, false, ['decrypt']);
  const [ctB64, ivB64] = ciphertext.split('?iv=');
  const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
  return new TextDecoder().decode(plainBuf);
}

function generateUUID() {
  return crypto.randomUUID ? crypto.randomUUID() : bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

async function createOfferEvent({ offerId, direction, alphAmount, btcSat, expiresAt }) {
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
    }),
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
    }),
  });
}

async function createAcceptEvent({ offerId, offerEventId, offerCreator, alphAmount, btcSat }) {
  return signEvent({
    kind: SWAP_OFFER_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', 'atomicswap'], ['t', 'accept'], ['e', offerEventId], ['p', offerCreator], ['d', `${offerId}:accept`]],
    content: JSON.stringify({
      action: 'accept',
      offerId,
      alphAmount: String(alphAmount),
      btcSat,
    }),
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
// UI: Protocol Log
// ============================================================

const logMessagesEl = document.getElementById('log-messages');

function addLogMsg(type, content, author = null) {
  const div = document.createElement('div');
  div.className = `msg ${type}`;
  div.dataset.type = type === 'system' ? 'system' : 'protocol';

  const tagNames = { system: 'SYS', setup: 'SETUP', nonce: 'NONCE', presig: 'PRESIG', claim: 'CLAIM' };
  let html = `<span class="tag">${tagNames[type] || type}</span>`;
  if (author) html += `<span style="color:#8b949e; font-size:10px">${author}</span> `;
  html += `<span>${escapeHtml(content)}</span>`;
  div.innerHTML = html;

  logMessagesEl.appendChild(div);
  applyLogFilter();
  logMessagesEl.scrollTop = logMessagesEl.scrollHeight;
}

function addProtocolMsg(kind, content, author) {
  const kindMap = {
    [SWAP_SETUP_KIND]: 'setup',
    [SWAP_NONCE_KIND]: 'nonce',
    [SWAP_PRESIG_KIND]: 'presig',
    [SWAP_CLAIM_KIND]: 'claim',
  };
  const type = kindMap[kind] || 'setup';
  let text = content;
  try {
    const parsed = JSON.parse(content);
    text = Object.entries(parsed).map(([k, v]) => {
      const vs = String(v);
      return `${k}: ${vs.length > 24 ? vs.slice(0, 24) + '...' : vs}`;
    }).join(' | ');
  } catch {}
  addLogMsg(type, text, author);
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function applyLogFilter() {
  const filter = state.logFilter;
  logMessagesEl.querySelectorAll('.msg').forEach(el => {
    if (filter === 'all') { el.style.display = ''; return; }
    el.style.display = el.dataset.type === filter ? '' : 'none';
  });
}

document.getElementById('log-toggle').addEventListener('click', () => {
  const btn = document.getElementById('log-toggle');
  const content = document.getElementById('log-content');
  btn.classList.toggle('open');
  content.classList.toggle('open');
});

document.querySelectorAll('.log-filter-bar button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.log-filter-bar button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.logFilter = btn.dataset.filter;
    applyLogFilter();
  });
});

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
  state.stepData[id] = { ...state.stepData[id], ...updates };
  renderSteps();
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

  // Always show abort button during an active swap
  html += '<button class="sm" id="abort-swap-btn" style="margin-left:auto">Abort Swap</button>';

  actionsEl.innerHTML = html;

  const refundAlphBtn = document.getElementById('refund-alph-btn');
  if (refundAlphBtn) refundAlphBtn.addEventListener('click', refundAlph);
  const refundBtcBtn = document.getElementById('refund-btc-btn');
  if (refundBtcBtn) refundBtcBtn.addEventListener('click', refundBtc);
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

  offer.status = 'accepted';
  offer.acceptEvent = event;

  const isMine = event.pubkey === state.pubKeyHex;
  addLogMsg('system', `Offer ${content.offerId.slice(0, 8)}... accepted!`, isMine ? 'You' : event.pubkey.slice(0, 8) + '...');
  renderOffersList();

  const involvesUs = offer.isMine || isMine;
  if (involvesUs && !state.activeSwap && !getProcessedOffers().has(offer.id)) {
    startSwapFromAccept(offer, event, content);
  }
}

function handleCancelEvent(event, content) {
  const offer = state.offers.get(content.offerId);
  if (!offer) return;
  if (event.pubkey !== offer.pubkey) return; // only creator can cancel

  // Post-accept cancel: offer creator matched with a specific acceptor.
  // If we're a DIFFERENT acceptor with an active swap on this offer, abort it.
  // The matched acceptor (content.matchedPub) should ignore the cancel.
  if (offer.status === 'accepted') {
    const iAmMatchedAcceptor = content.matchedPub && content.matchedPub === state.pubKeyHex;
    if (state.activeSwap?.offerId === offer.id && !offer.isMine && !iAmMatchedAcceptor) {
      addLogMsg('system', 'Offer was taken by another user — aborting swap', 'System');
      markOfferProcessed(offer.id);
      offer.status = 'cancelled';
      resetSwap();
      renderOffersList();
    }
    return;
  }

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
  try { return addressFromPublicKey(pubkeyHex, 'bip340-schnorr'); } catch { return null; }
}

function getP2TRAddressFromPub(pubkeyHex) {
  try { return getP2TRAddress(hexToBytes(pubkeyHex)); } catch { return null; }
}

function explorerLink(chain, address, text) {
  if (chain === 'btc') {
    return `<a href="https://mempool.space/signet/address/${address}" target="_blank" title="${address}" class="amount-link">${text}</a>`;
  }
  return `<a href="https://testnet.alephium.org/addresses/${address}" target="_blank" title="${address}" class="amount-link">${text}</a>`;
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

  const activeOffers = sorted.filter(o => o.status === 'open' || o.status === 'countered');
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
    historyToggle.innerHTML = `<span class="arrow">&#9654;</span> History (${inactiveOffers.length})`;
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

  let alphAmountHtml = `<span class="alph">${formatAlph(offer.alphAmount)} ALPH</span>`;
  let btcAmountHtml = `<span class="btc">${formatSat(offer.btcSat)} sat</span>`;

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
    <div class="card-body">
      <span class="peer">by ${peerLabel}</span>
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
  btn.disabled = true; btn.textContent = 'Publishing...';
  clearOfferWarning();

  try {
    const direction = document.querySelector('#direction-toggle button.active').dataset.dir;
    const alphVal = parseFloat(document.getElementById('offer-alph').value) || 1;
    const btcSat = parseInt(document.getElementById('offer-btc-sat').value) || 5000;
    const alphAmount = BigInt(Math.round(alphVal * 1e18));

    // Balance check (non-blocking warning)
    const role = direction === 'sell_alph' ? 'alice' : 'bob';
    const { warnings } = await validateBalanceForSwap(role, String(alphAmount), btcSat);
    if (warnings.length > 0) {
      showOfferWarning(warnings.join(' | '));
    }

    const offerId = generateUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    const event = await createOfferEvent({ offerId, direction, alphAmount, btcSat, expiresAt });
    await nostrPublish(event);

    addLogMsg('system', `Published offer: ${direction === 'sell_alph' ? 'Sell' : 'Buy'} ${alphVal} ALPH for ${btcSat} sat (expires in 1h)`, 'You');
  } catch (e) {
    addLogMsg('system', `Publish error: ${e.message}`, 'Error');
  }

  btn.disabled = false; btn.textContent = 'Publish Offer';
}

async function acceptOffer(offerId) {
  const offer = state.offers.get(offerId);
  if (!offer) return;

  // Acceptor role: sell_alph offer → acceptor is bob; buy_alph offer → acceptor is alice
  const role = offer.direction === 'sell_alph' ? 'bob' : 'alice';
  const { ok, warnings } = await validateBalanceForSwap(role, offer.alphAmount, offer.btcSat);
  if (!ok) {
    const proceed = confirm('Balance warnings:\n\n' + warnings.join('\n') + '\n\nProceed anyway?');
    if (!proceed) return;
  }

  try {
    const event = await createAcceptEvent({
      offerId,
      offerEventId: offer.eventId,
      offerCreator: offer.pubkey,
      alphAmount: offer.alphAmount,
      btcSat: offer.btcSat,
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
    const proceed = confirm('Balance warnings:\n\n' + warnings.join('\n') + '\n\nProceed anyway?');
    if (!proceed) return;
  }

  try {
    const event = await createAcceptEvent({
      offerId,
      offerEventId: offer.eventId,
      offerCreator: offer.pubkey,
      alphAmount: counter.alphAmount,
      btcSat: counter.btcSat,
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

  let role, peerPubHex;
  if (offer.direction === 'sell_alph') {
    role = iAmCreator ? 'alice' : 'bob';
    peerPubHex = iAmCreator ? acceptEvent.pubkey : offer.pubkey;
  } else {
    role = iAmCreator ? 'bob' : 'alice';
    peerPubHex = iAmCreator ? acceptEvent.pubkey : offer.pubkey;
  }

  const sessionId = acceptEvent.id;
  const alphAmount = acceptContent.alphAmount;
  const btcSat = acceptContent.btcSat;

  state.activeSwap = {
    offerId: offer.id,
    role,
    peerPubHex,
    sessionId,
    alphAmount,
    btcSat,
  };

  state.stepData = {};

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

  document.getElementById('log-toggle').classList.add('open');
  document.getElementById('log-content').classList.add('open');

  addLogMsg('system', `Swap started as ${role}: ${formatAlph(alphAmount)} ALPH <-> ${formatSat(btcSat)} sat`, 'System');

  // On mobile, scroll to the swap panel (rendered above offers via column-reverse)
  document.getElementById('swap-active').scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Offer creator: publish cancel so other acceptors know the offer is taken
  if (iAmCreator) {
    createCancelEvent({ offerId: offer.id, offerEventId: offer.eventId, matchedPub: acceptEvent.pubkey })
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

    // Decrypt NIP-04 encrypted content
    let decryptedContent = event.content;
    try {
      decryptedContent = await nip04Decrypt(event.content, peerPubHex);
    } catch {
      // Fallback: treat as plain JSON (backward compat with unencrypted events)
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
  const lockDone = state.stepData.lock?.status === 'done';
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

async function autoExecuteSwap() {
  if (!state.activeSwap) return;
  const { role } = state.activeSwap;

  try {
    updateStep('setup', { status: 'active' });
    if (role === 'alice') {
      await executeSetupAlice();
    } else {
      await executeSetupBob();
    }
    updateStep('setup', { status: 'done' });

    if (state.stepData.lock?.status !== 'done') {
      updateStep('lock', { status: 'active' });
      if (role === 'alice') {
        await executeLockAlice();
      } else {
        await executeLockBob();
      }
      updateStep('lock', { status: 'done' });
      saveSwapState();
    }

    updateStep('nonces', { status: 'active' });
    await executeNonces();
    updateStep('nonces', { status: 'done' });

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
    addLogMsg('system', `Swap error: ${e.message}`, 'Error');
  }
}

async function retryStep(stepId) {
  if (!state.activeSwap) return;
  const { role } = state.activeSwap;

  updateStep(stepId, { status: 'active', error: null });

  try {
    const stepFns = {
      alice: { setup: executeSetupAlice, lock: executeLockAlice, nonces: executeNonces, presign: executePresign, claim: executeClaimAlice },
      bob: { setup: executeSetupBob, lock: executeLockBob, nonces: executeNonces, presign: executePresign, claim: executeClaimBob },
    };
    await stepFns[role][stepId]();
    updateStep(stepId, { status: 'done' });
    saveSwapState();

    const stepOrder = ['setup', 'lock', 'nonces', 'presign', 'claim'];
    const idx = stepOrder.indexOf(stepId);
    for (let i = idx + 1; i < stepOrder.length; i++) {
      const nextStep = stepOrder[i];
      if (state.stepData[nextStep]?.status === 'done') continue;
      updateStep(nextStep, { status: 'active' });
      await stepFns[role][nextStep]();
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
    const initResult = state.engine.initSwap('alice', peerPubHex, btcAmount, String(alphAmount), sessionId);

    state.stepData.setup = { ...state.stepData.setup, adaptorPoint: initResult.adaptorPoint };
    updateStep('setup', { info: `adaptorPoint: ${initResult.adaptorPoint?.slice(0, 24)}...\nSending to peer...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'confirm',
      pubkey: state.pubKeyHex, adaptorPoint: initResult.adaptorPoint,
    });
    await nostrPublish(event);

    updateStep('setup', { info: `adaptorPoint sent. Waiting for Bob's BTC lock...` });

    const btcLockedEvent = await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'btc_locked');
    const btcLocked = JSON.parse(btcLockedEvent.content);

    await state.engine.verifyBtc(btcLocked.txid, btcLocked.vout);

    updateStep('setup', { info: `BTC locked: ${btcLocked.txid.slice(0, 16)}... verified` });
  } catch (e) {
    updateStep('setup', { status: 'error', error: e.message });
    throw e;
  }
}

async function executeLockAlice() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    const deployResult = await state.engine.deployAlph();
    updateStep('lock', { info: `ALPH deployed: ${deployResult.contractAddress.slice(0, 16)}...\nSending to peer...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'alph_deployed',
      contractId: deployResult.contractId, contractAddress: deployResult.contractAddress,
    });
    await nostrPublish(event);

    updateStep('lock', { info: `ALPH: ${deployResult.contractAddress.slice(0, 16)}...\nWaiting for Bob to verify...` });
    await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'verified');

    state.engine.computeContext();
    updateStep('lock', { info: `ALPH: ${deployResult.contractAddress.slice(0, 16)}... | Bob verified | Context computed` });
  } catch (e) {
    updateStep('lock', { status: 'error', error: e.message });
    throw e;
  }
}

async function executeClaimAlice() {
  const { sessionId, peerPubHex } = state.activeSwap;

  try {
    const result = await state.engine.claimBtc();
    updateStep('claim', { info: `BTC claimed! txid: ${result.txid.slice(0, 24)}...` });
    saveSwapState();

    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'btc_claimed',
      txid: result.txid,
    });
    await nostrPublish(event);

    updateStep('claim', { info: `BTC claimed: ${result.txid.slice(0, 16)}...\nWaiting for Bob to claim ALPH...` });
    const alphClaimedEvent = await waitForSwapEvent(SWAP_CLAIM_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'alph_claimed');
    const alphClaimed = JSON.parse(alphClaimedEvent.content);
    updateStep('claim', { info: `BTC claimed: ${result.txid.slice(0, 16)}...\nBob claimed ALPH: ${alphClaimed.txid.slice(0, 16)}...` });
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

    state.engine.initSwap('bob', peerPubHex, btcAmount, String(alphAmount), sessionId);
    state.engine.setAdaptorPoint(confirm.adaptorPoint);

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
    const lockResult = await state.engine.lockBtc(utxo);
    updateStep('lock', { info: `BTC locked: ${lockResult.txid.slice(0, 16)}... vout=${lockResult.vout}\nPublishing...` });

    const event = await createSwapSetup({
      sessionId, recipientPubHex: peerPubHex, msgType: 'btc_locked',
      txid: lockResult.txid, vout: lockResult.vout, amountSat: lockResult.amountSat,
    });
    await nostrPublish(event);

    updateStep('lock', { info: `BTC locked: ${lockResult.txid.slice(0, 16)}...\nWaiting for Alice to deploy ALPH...` });
    const alphDeployedEvent = await waitForSwapEvent(SWAP_SETUP_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'alph_deployed');
    const alphDeployed = JSON.parse(alphDeployedEvent.content);

    await state.engine.verifyAlph(alphDeployed.contractId, alphDeployed.contractAddress);

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
    updateStep('claim', { info: 'Waiting for Alice to claim BTC...' });
    const btcClaimedEvent = await waitForSwapEvent(SWAP_CLAIM_KIND, sessionId, peerPubHex,
      (e) => JSON.parse(e.content).type === 'btc_claimed');
    const btcClaimed = JSON.parse(btcClaimedEvent.content);

    state.engine.btcClaimTxid = btcClaimed.txid;
    saveSwapState();
    updateStep('claim', { info: `Alice claimed BTC: ${btcClaimed.txid.slice(0, 16)}...\nExtracting secret and claiming ALPH...` });

    const result = await state.engine.claimAlph(btcClaimed.txid);

    const event = await createSwapClaim({
      sessionId, recipientPubHex: peerPubHex, claimType: 'alph_claimed',
      txid: result.txid,
    });
    await nostrPublish(event);

    updateStep('claim', { info: `Alice BTC: ${btcClaimed.txid.slice(0, 16)}...\nALPH claimed: ${result.txid.slice(0, 16)}...` });
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
  try {
    addLogMsg('system', 'Refunding ALPH...', 'System');
    const result = await state.engine.refundAlph();
    addLogMsg('system', `ALPH refunded! txid: ${result.txid.slice(0, 24)}...`, 'System');
    await refreshBalance();
  } catch (e) {
    addLogMsg('system', `Refund error: ${e.message}`, 'Error');
  }
}

async function refundBtc() {
  try {
    addLogMsg('system', 'Refunding BTC (requires CSV timeout)...', 'System');
    const result = await state.engine.refundBtc();
    addLogMsg('system', `BTC refunded! txid: ${result.txid.slice(0, 24)}...`, 'System');
    await refreshBalance();
  } catch (e) {
    addLogMsg('system', `Refund error: ${e.message}`, 'Error');
  }
}

// ============================================================
// Swap Complete
// ============================================================

function showSwapComplete() {
  clearSwapState();
  stopTimeoutMonitor();
  if (state.activeSwap) {
    markOfferProcessed(state.activeSwap.offerId); // prevent auto-restart on refresh
    const offer = state.offers.get(state.activeSwap.offerId);
    if (offer) { offer.status = 'completed'; renderOffersList(); }
  }
  const { alphAmount, btcSat, role } = state.activeSwap;
  const actionsEl = document.getElementById('swap-actions');
  actionsEl.innerHTML = `
    <div class="swap-complete" style="width:100%">
      <h3>Swap Complete!</h3>
      <div style="color:#8b949e; font-size:12px; margin-top:4px">
        ${role === 'alice' ? 'Received' : 'Sent'} ${formatSat(btcSat)} sat &harr;
        ${role === 'alice' ? 'Sent' : 'Received'} ${formatAlph(alphAmount)} ALPH
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

async function abortSwap() {
  if (!state.activeSwap) return;
  const lockDone = state.stepData.lock?.status === 'done';
  let msg = 'Abort this swap?';
  if (lockDone) {
    msg += '\n\nFunds are already locked on-chain. After aborting, the recovery UI will appear with refund options.';
  } else {
    msg += '\n\nNo funds have been locked yet. Safe to abort.';
  }
  if (!confirm(msg)) return;

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

  // Re-create engine for fresh swap state (keeps same keys)
  state.engine = new SwapEngine(state.secBytes, hexToBytes(state.pubKeyHex));

  document.getElementById('swap-placeholder').classList.remove('hidden');
  document.getElementById('swap-active').classList.add('hidden');
  document.getElementById('utxo-bar').classList.add('hidden');

  renderOffersList();
  refreshBalance();
}

// ============================================================
// Auto-Connect
// ============================================================

const STORAGE_KEY = 'btc-alph-swap-nsec';
const BACKUP_CONFIRMED_KEY = 'btc-alph-swap-backup-confirmed';
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

const TARGET_ALPH_GROUP = 1;

function getOrCreateNsec() {
  let hex = localStorage.getItem(STORAGE_KEY);
  if (hex && hex.length === 64) {
    // Verify existing key is in the target group; if not, regenerate
    const pub = schnorr.getPublicKey(hexToBytes(hex));
    const addr = addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr');
    if (groupOfAddress(addr) === TARGET_ALPH_GROUP) return hex;
    // Wrong group — fall through to regenerate
  }
  // Grind until we find a key in the target ALPH group
  const sec = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(sec);
    const pub = schnorr.getPublicKey(sec);
    const addr = addressFromPublicKey(bytesToHex(pub), 'bip340-schnorr');
    if (groupOfAddress(addr) === TARGET_ALPH_GROUP) break;
  }
  hex = bytesToHex(sec);
  localStorage.setItem(STORAGE_KEY, hex);
  return hex;
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
    localStorage.setItem(SWAP_STATE_KEY, JSON.stringify(data));
  } catch (e) {
    console.warn('Failed to save swap state:', e);
  }
}

function loadSwapState() {
  try {
    const raw = localStorage.getItem(SWAP_STATE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
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
      const txResp = await fetch(`https://mempool.space/signet/api/tx/${state.engine.btcLockTxid}`);
      if (!txResp.ok) {
        addLogMsg('system', 'BTC lock tx not found on-chain', 'System');
      }

      // Check if BTC lock output is already spent (claimed)
      if (state.engine.btcLockVout != null) {
        const outspendResp = await fetch(`https://mempool.space/signet/api/tx/${state.engine.btcLockTxid}/outspend/${state.engine.btcLockVout}`);
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
        const balResp = await fetch(`https://node.testnet.alephium.org/addresses/${state.engine.contractAddress}/balance`);
        if (balResp.ok) {
          const bal = await balResp.json();
          const alphBalance = BigInt(bal.balance || '0');
          if (alphBalance === 0n) {
            state.stepData._alphContractEmpty = true;
            addLogMsg('system', 'ALPH contract is empty (already refunded or claimed)', 'System');
          }
        } else if (balResp.status === 404) {
          // Contract destroyed
          state.stepData._alphContractEmpty = true;
          addLogMsg('system', 'ALPH contract not found (destroyed/refunded)', 'System');
        }
      } catch {}
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

  if (checkpoint === 'locked') {
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

  const claimBtcBtn = document.getElementById('recovery-claim-btc-btn');
  if (claimBtcBtn) claimBtcBtn.addEventListener('click', recoveryClaimBtc);

  const claimAlphBtn = document.getElementById('recovery-claim-alph-btn');
  if (claimAlphBtn) claimAlphBtn.addEventListener('click', recoveryClaimAlph);

  const refundAlphBtn = document.getElementById('recovery-refund-alph-btn');
  if (refundAlphBtn) refundAlphBtn.addEventListener('click', refundAlph);

  const refundBtcBtn = document.getElementById('recovery-refund-btc-btn');
  if (refundBtcBtn) refundBtcBtn.addEventListener('click', refundBtc);

  const clearBtn = document.getElementById('recovery-clear-btn');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (!confirm('Clear saved swap state?\n\nThis will NOT refund your locked funds. You will need to manually recover them if the swap is incomplete.')) return;
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
    addLogMsg('system', `Claim BTC error: ${e.message}`, 'Error');
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
    addLogMsg('system', `Claim ALPH error: ${e.message}`, 'Error');
    if (btn) { btn.disabled = false; btn.textContent = 'Claim ALPH'; }
  }
}

async function findBtcClaimTx() {
  if (!state.engine.btcLockTxid || state.engine.btcLockVout == null) return null;
  try {
    const resp = await fetch(`https://mempool.space/signet/api/tx/${state.engine.btcLockTxid}/outspend/${state.engine.btcLockVout}`);
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
      lines.push('ALPH refund: <span style="color:#2ea043">AVAILABLE NOW</span>');
      const refundBtn = document.getElementById('recovery-refund-alph-btn');
      if (refundBtn) refundBtn.disabled = false;
    } else {
      const hrs = Math.floor(remaining / 3600000);
      const mins = Math.floor((remaining % 3600000) / 60000);
      lines.push(`ALPH refund: ${hrs}h ${mins}m remaining`);
    }
  }

  // BTC timeout (T1 = csvTimeout blocks)
  if (state.engine.btcLockTxid && state.engine.csvTimeout) {
    try {
      const txResp = await fetch(`https://mempool.space/signet/api/tx/${state.engine.btcLockTxid}`);
      if (txResp.ok) {
        const tx = await txResp.json();
        if (tx.status?.confirmed && tx.status.block_height) {
          const tipResp = await fetch('https://mempool.space/signet/api/blocks/tip/height');
          if (tipResp.ok) {
            const tipHeight = parseInt(await tipResp.text());
            const confirmations = tipHeight - tx.status.block_height + 1;
            const needed = state.engine.csvTimeout;
            if (confirmations >= needed) {
              lines.push(`BTC refund: <span style="color:#2ea043">AVAILABLE NOW</span> (${confirmations}/${needed} blocks)`);
              const refundBtn = document.getElementById('recovery-refund-btc-btn');
              if (refundBtn) refundBtn.disabled = false;
            } else {
              lines.push(`BTC refund: ${confirmations}/${needed} blocks`);
            }
          }
        } else {
          lines.push('BTC refund: lock tx unconfirmed');
        }
      }
    } catch {}
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
    const nsecHex = getOrCreateNsec();
    state.secBytes = hexToBytes(nsecHex);

    statusEl.textContent = 'Deriving identity...';
    const pubKey = schnorr.getPublicKey(state.secBytes);
    state.pubKeyHex = bytesToHex(pubKey);
    state.npub = npubEncode(state.pubKeyHex);

    // Create the swap engine
    state.engine = new SwapEngine(state.secBytes, pubKey);
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
    state.nsecBech32 = nsecEncode(nsecHex);

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

    // Check for saved swap state to recover
    const savedSwap = loadSwapState();
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
    since: Math.floor(Date.now() / 1000) - 86400,
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
  el.textContent = `${alive}/${total} relays`;
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
document.getElementById('reset-key-btn').addEventListener('click', () => {
  const msg = 'WARNING: This will permanently delete your current key.\n\n' +
    'All funds (BTC and ALPH) associated with this identity will be LOST ' +
    'unless you have backed up your nsec.\n\n' +
    'Type "RESET" to confirm:';
  const input = prompt(msg);
  if (input !== 'RESET') return;
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(BACKUP_CONFIRMED_KEY);
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
    else if (which === 'nsec') text = state.nsecBech32;
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

  titleEl.textContent = chain === 'btc' ? 'Send BTC' : 'Send ALPH';
  balEl.textContent = chain === 'btc'
    ? `Balance: ${document.getElementById('bal-btc').textContent}`
    : `Balance: ${document.getElementById('bal-alph').textContent}`;
  inputEl.value = '';
  inputEl.placeholder = chain === 'btc' ? 'tb1... destination address' : 'ALPH destination address';
  errorEl.textContent = '';
  errorEl.classList.add('hidden');
  statusEl.textContent = '';
  statusEl.classList.add('hidden');
  confirmBtn.disabled = false;
  confirmBtn.textContent = 'Sweep All';
  modal.classList.remove('hidden');
  inputEl.focus();
}

async function executeSend() {
  const destAddress = document.getElementById('send-dest-addr').value.trim();
  const errorEl = document.getElementById('send-modal-error');
  const statusEl = document.getElementById('send-modal-status');
  const confirmBtn = document.getElementById('send-confirm-btn');

  if (!destAddress) {
    errorEl.textContent = 'Please enter a destination address';
    errorEl.classList.remove('hidden');
    return;
  }

  // Validate address
  if (sendChain === 'btc') {
    if (!SwapEngine.validateBtcAddress(destAddress)) {
      errorEl.textContent = 'Invalid BTC address for signet/testnet';
      errorEl.classList.remove('hidden');
      return;
    }
  } else {
    if (!SwapEngine.validateAlphAddress(destAddress)) {
      errorEl.textContent = 'Invalid ALPH address';
      errorEl.classList.remove('hidden');
      return;
    }
  }

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
    statusEl.textContent = `Sent! txid: ${txid}`;
    confirmBtn.textContent = 'Done';
    addLogMsg('system', `${sendChain.toUpperCase()} sweep to ${destAddress.slice(0, 16)}...: ${txid}`, 'You');
    setTimeout(() => refreshBalance(), 3000);
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.classList.remove('hidden');
    statusEl.classList.add('hidden');
    confirmBtn.disabled = false;
    confirmBtn.textContent = 'Sweep All';
  }
}

// Send buttons
document.querySelectorAll('.send-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    showSendModal(btn.dataset.send);
  });
});

document.getElementById('send-confirm-btn').addEventListener('click', executeSend);
document.getElementById('send-cancel-btn').addEventListener('click', () => {
  document.getElementById('send-modal').classList.add('hidden');
});
document.getElementById('send-modal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
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
    el.textContent = state.nsecBech32 || '';
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

document.getElementById('backup-btn').addEventListener('click', () => {
  const confirmed = confirm(
    'Have you saved your nsec (private key) somewhere safe?\n\n' +
    'Without this key, all BTC and ALPH funds in this wallet will be permanently lost.\n\n' +
    'Click OK to confirm you have backed it up.'
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
    const rate = (alphVal / (btcSat / 1e8)).toLocaleString(undefined, { maximumFractionDigits: 0 });
    el.textContent = `Rate: ${rate} ALPH/BTC`;
  } else {
    el.textContent = 'Rate: --';
  }
}

document.getElementById('offer-alph').addEventListener('input', updateRateDisplay);
document.getElementById('offer-btc-sat').addEventListener('input', updateRateDisplay);
updateRateDisplay();

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
