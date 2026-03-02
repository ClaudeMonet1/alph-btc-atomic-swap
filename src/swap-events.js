// Atomic Swap Protocol — Nostr Event Kinds and Relay Helpers
//
// Structured event kinds for the MuSig2 adaptor signature exchange.
// Raw WebSocket relay helpers (no nostr-tools/relay dependency).
//
// Protocol phases:
//   SETUP  — Lock info, adaptor point, contract deployment, verification
//   NONCE  — Nonce commitment (hash) and reveal (actual nonces)
//   PRESIG — Adaptor pre-signature exchange
//   CLAIM  — Claim notifications (BTC claimed, ALPH claimed)
//
// All events tagged with #e = sessionId for session linking,
// #p = recipient for routing, d = unique dedup key.

import { getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import WebSocket from 'ws';

// ---- Event Kinds (parameterized replaceable, 30000-39999) ----

export const SWAP_SETUP_KIND  = 38390;
export const SWAP_NONCE_KIND  = 38391;
export const SWAP_PRESIG_KIND = 38392;
export const SWAP_CLAIM_KIND  = 38393;

// ---- Event Signing ----

function signEvent(template, secKeyBytes) {
  const event = { ...template, pubkey: getPublicKey(secKeyBytes) };
  return finalizeEvent(event, secKeyBytes);
}

// ---- Event Builders ----

// Generic kind-1 event (for public offers)
export function createPublicEvent(secKeyBytes, content, tags = []) {
  return signEvent({
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content,
  }, secKeyBytes);
}

// Setup phase: lock info, adaptor point, contract deployment, verification.
// Multiple SETUP messages per session, differentiated by content.type and d-tag.
export function createSwapSetup(secKeyBytes, { sessionId, recipientPubHex, msgType, ...data }) {
  return signEvent({
    kind: SWAP_SETUP_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['e', sessionId],
      ['p', recipientPubHex],
      ['d', `${sessionId}:${msgType}`],
    ],
    content: JSON.stringify({ type: msgType, ...data }),
  }, secKeyBytes);
}

// Nonce phase: commitment (hash) or reveal (actual nonces).
// phase = 'commit' or 'reveal', used in d-tag for dedup.
export function createSwapNonce(secKeyBytes, { sessionId, recipientPubHex, phase, ...data }) {
  return signEvent({
    kind: SWAP_NONCE_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['e', sessionId],
      ['p', recipientPubHex],
      ['d', `${sessionId}:${phase}`],
    ],
    content: JSON.stringify({ phase, ...data }),
  }, secKeyBytes);
}

// Pre-signature exchange.
export function createSwapPresig(secKeyBytes, { sessionId, recipientPubHex, ...data }) {
  return signEvent({
    kind: SWAP_PRESIG_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['e', sessionId],
      ['p', recipientPubHex],
      ['d', sessionId],
    ],
    content: JSON.stringify(data),
  }, secKeyBytes);
}

// Claim notification (btc_claimed / alph_claimed).
export function createSwapClaim(secKeyBytes, { sessionId, recipientPubHex, claimType, ...data }) {
  return signEvent({
    kind: SWAP_CLAIM_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['e', sessionId],
      ['p', recipientPubHex],
      ['d', `${sessionId}:${claimType}`],
    ],
    content: JSON.stringify({ type: claimType, ...data }),
  }, secKeyBytes);
}

// ---- Raw WebSocket Relay Helpers ----

export function connectRelay(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
    setTimeout(() => reject(new Error('relay connect timeout')), 5000);
  });
}

export function subscribe(ws, subId, filters, onEvent, onEose) {
  const handler = (raw) => {
    const msg = JSON.parse(raw.toString());
    if (msg[0] === 'EVENT' && msg[1] === subId) onEvent(msg[2]);
    if (msg[0] === 'EOSE' && msg[1] === subId && onEose) onEose();
  };
  ws.on('message', handler);
  ws.send(JSON.stringify(['REQ', subId, ...filters]));
  return () => {
    ws.off('message', handler);
    ws.send(JSON.stringify(['CLOSE', subId]));
  };
}

export function publish(ws, event) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('publish timeout')), 5000);
    const handler = (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg[0] === 'OK' && msg[1] === event.id) {
        ws.off('message', handler);
        clearTimeout(timeout);
        resolve(msg[2]);
      }
    };
    ws.on('message', handler);
    ws.send(JSON.stringify(['EVENT', event]));
  });
}

// Wait for a swap event from a specific party, with optional content predicate.
// Filters by kind + #e session tag + author pubkey.
export function waitForSwapEvent(ws, kind, sessionId, fromPubHex, predicate = null, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const subId = 'sw_' + Math.random().toString(36).slice(2, 10);
    const timeout = setTimeout(() => {
      unsub();
      reject(new Error(`timeout waiting for kind ${kind} from ${fromPubHex.slice(0, 8)}...`));
    }, timeoutMs);
    const unsub = subscribe(ws, subId,
      [{ kinds: [kind], '#e': [sessionId], authors: [fromPubHex] }],
      (event) => {
        if (predicate && !predicate(event)) return;
        unsub();
        clearTimeout(timeout);
        resolve(event);
      });
  });
}

// Wait for any event matching kind + filter (for public offer discovery).
export function waitForEvent(ws, kind, filter = {}, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const subId = 'w_' + Math.random().toString(36).slice(2, 10);
    const timeout = setTimeout(() => {
      unsub();
      reject(new Error(`timeout waiting for kind ${kind}`));
    }, timeoutMs);
    const unsub = subscribe(ws, subId, [{ kinds: [kind], ...filter }],
      (event) => {
        unsub();
        clearTimeout(timeout);
        resolve(event);
      });
  });
}
