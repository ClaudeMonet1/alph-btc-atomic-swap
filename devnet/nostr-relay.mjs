#!/usr/bin/env node
// Minimal NIP-01 relay for local runs: in-memory, replaceable events by
// (kind, pubkey, d-tag) for kinds 30000-39999, REQ filters on ids, kinds,
// authors, since, until and #-tags, EOSE and OK. No signature verification
// beyond shape (the page verifies nothing either; relays are untrusted).
// Usage: node devnet/nostr-relay.mjs [port]
import { WebSocketServer } from 'ws';
const PORT = Number(process.argv[2] || 7777);
const events = new Map(); // id -> event
const replaceKey = (e) => `${e.kind}:${e.pubkey}:${(e.tags.find((t) => t[0] === 'd') || [])[1] || ''}`;
const replaced = new Map(); // replaceKey -> id
const subs = new Map(); // ws -> Map(subId -> filters)

function matches(e, f) {
  if (f.ids && !f.ids.some((p) => e.id.startsWith(p))) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.authors && !f.authors.some((p) => e.pubkey.startsWith(p))) return false;
  if (f.since && e.created_at < f.since) return false;
  if (f.until && e.created_at > f.until) return false;
  for (const [k, v] of Object.entries(f)) {
    if (!k.startsWith('#')) continue;
    const tag = k.slice(1);
    if (!e.tags.some((t) => t[0] === tag && v.includes(t[1]))) return false;
  }
  return true;
}
const wss = new WebSocketServer({ port: PORT, host: '127.0.0.1' });
wss.on('connection', (ws) => {
  subs.set(ws, new Map());
  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg[0] === 'EVENT') {
      const e = msg[1];
      if (!e?.id || !e.pubkey || !e.sig || !Array.isArray(e.tags)) return ws.send(JSON.stringify(['OK', e?.id || '', false, 'invalid: shape']));
      if (e.kind >= 30000 && e.kind < 40000) { const k = replaceKey(e); const old = replaced.get(k); if (old) { const oe = events.get(old); if (oe && oe.created_at > e.created_at) return ws.send(JSON.stringify(['OK', e.id, true, 'duplicate: older'])); events.delete(old); } replaced.set(k, e.id); }
      events.set(e.id, e);
      ws.send(JSON.stringify(['OK', e.id, true, '']));
      for (const [client, m] of subs) for (const [subId, filters] of m) if (filters.some((f) => matches(e, f))) client.send(JSON.stringify(['EVENT', subId, e]));
    } else if (msg[0] === 'REQ') {
      const [, subId, ...filters] = msg;
      subs.get(ws).set(subId, filters);
      const hits = [...events.values()].filter((e) => filters.some((f) => matches(e, f))).sort((a, b) => a.created_at - b.created_at);
      for (const e of hits.slice(-500)) ws.send(JSON.stringify(['EVENT', subId, e]));
      ws.send(JSON.stringify(['EOSE', subId]));
    } else if (msg[0] === 'CLOSE') subs.get(ws)?.delete(msg[1]);
  });
  ws.on('close', () => subs.delete(ws));
});
console.log(`nostr relay on ws://127.0.0.1:${PORT}`);
