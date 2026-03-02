// Minimal NIP-01 Nostr relay using ws
// In-memory event store, filter matching, subscription forwarding

import { WebSocketServer } from 'ws';

function matchesFilter(event, filter) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since && event.created_at < filter.since) return false;
  if (filter.until && event.created_at > filter.until) return false;

  // NIP-01 tag filters: #<single-letter>
  for (const key of Object.keys(filter)) {
    if (key.startsWith('#') && key.length === 2) {
      const tagName = key[1];
      const wanted = filter[key];
      const tags = event.tags.filter(t => t[0] === tagName).map(t => t[1]);
      if (!wanted.some(v => tags.includes(v))) return false;
    }
  }
  return true;
}

export function attachRelay(wss) {
  const events = [];
  const subscriptions = new Map(); // ws -> Map<subId, filters[]>

  wss.on('connection', (ws) => {
    const subs = new Map();
    subscriptions.set(ws, subs);

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }
      if (!Array.isArray(msg) || msg.length < 2) return;

      const type = msg[0];

      if (type === 'EVENT') {
        const event = msg[1];
        if (!event || !event.id || event.kind === undefined) return;
        // Deduplicate
        if (events.some(e => e.id === event.id)) {
          ws.send(JSON.stringify(['OK', event.id, true, 'duplicate:']));
          return;
        }
        events.push(event);
        ws.send(JSON.stringify(['OK', event.id, true, '']));
        // Forward to matching subscriptions on all clients
        for (const [client, clientSubs] of subscriptions) {
          for (const [subId, filters] of clientSubs) {
            if (filters.some(f => matchesFilter(event, f))) {
              try { client.send(JSON.stringify(['EVENT', subId, event])); } catch {}
            }
          }
        }
      } else if (type === 'REQ') {
        const subId = msg[1];
        const filters = msg.slice(2);
        subs.set(subId, filters);
        // Send stored events matching filters
        let matches = events.filter(e => filters.some(f => matchesFilter(e, f)));
        // Apply limit (smallest limit across filters)
        const limits = filters.map(f => f.limit).filter(l => l !== undefined);
        if (limits.length > 0) {
          const limit = Math.min(...limits);
          matches = matches.slice(-limit);
        }
        for (const event of matches) {
          ws.send(JSON.stringify(['EVENT', subId, event]));
        }
        ws.send(JSON.stringify(['EOSE', subId]));
      } else if (type === 'CLOSE') {
        const subId = msg[1];
        subs.delete(subId);
      }
    });

    ws.on('close', () => {
      subscriptions.delete(ws);
    });
  });
}

export function startRelay(port) {
  const wss = new WebSocketServer({ port });
  attachRelay(wss);

  return {
    wss,
    close() {
      return new Promise((resolve) => {
        for (const client of wss.clients) {
          client.terminate();
        }
        wss.close(resolve);
      });
    },
  };
}
