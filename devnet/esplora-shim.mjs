#!/usr/bin/env node
// Esplora-shaped HTTP API over a Bitcoin Core regtest node, enough for the
// browser build (btc.js) to run a swap locally: tip height, blocks, tx and
// status, address UTXOs, broadcast, fee endpoints. Mines a block every
// MINE_INTERVAL_MS (default 15 s, 0 disables) so the chain behaves like a fast
// signet. CORS is open. Usage: node devnet/esplora-shim.mjs [port]
//   BTC_RPC_URL (default http://127.0.0.1:18543), BTC_RPC_AUTH (user:pass)
import http from 'node:http';
const PORT = Number(process.argv[2] || 18544);
const RPC_URL = process.env.BTC_RPC_URL || 'http://127.0.0.1:18543';
const AUTH = 'Basic ' + Buffer.from(process.env.BTC_RPC_AUTH || 'nostralph:nostralph').toString('base64');
const MINE_MS = Number(process.env.MINE_INTERVAL_MS ?? 15000);

async function rpc(method, params = []) {
  const res = await fetch(RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: AUTH }, body: JSON.stringify({ jsonrpc: '1.0', id: 'shim', method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}
const sat = (btc) => Math.round(btc * 1e8);

async function txToEsplora(txid) {
  const t = await rpc('getrawtransaction', [txid, 2]);
  const status = t.blockhash ? { confirmed: true, block_height: (await rpc('getblockheader', [t.blockhash])).height, block_hash: t.blockhash, block_time: t.blocktime } : { confirmed: false };
  return {
    txid: t.txid, version: t.version, locktime: t.locktime, size: t.size, weight: t.weight, fee: t.fee !== undefined ? sat(t.fee) : 0,
    vin: t.vin.map((i) => ({ txid: i.txid, vout: i.vout, witness: i.txinwitness || [], sequence: i.sequence, prevout: i.prevout ? { scriptpubkey_address: i.prevout.scriptPubKey?.address, value: sat(i.prevout.value) } : null })),
    vout: t.vout.map((o) => ({ scriptpubkey: o.scriptPubKey.hex, scriptpubkey_address: o.scriptPubKey.address, value: sat(o.value) })),
    status,
  };
}
async function blockSummary(hash) {
  const b = await rpc('getblock', [hash, 1]);
  return { id: b.hash, height: b.height, timestamp: b.time, tx_count: b.nTx, size: b.size, weight: b.weight, previousblockhash: b.previousblockhash, extras: { medianFee: 1, feeRange: [1, 1, 1, 1, 1, 1, 1] } };
}
async function blocksFrom(height, n = 10) {
  const out = [];
  for (let h = height; h > Math.max(-1, height - n); h--) out.push(await blockSummary(await rpc('getblockhash', [h])));
  return out;
}
async function addressUtxos(address) {
  const scan = await rpc('scantxoutset', ['start', [`addr(${address})`]]);
  const tip = await rpc('getblockcount');
  const utxos = scan.unspents.map((u) => ({ txid: u.txid, vout: u.vout, value: sat(u.amount), status: { confirmed: true, block_height: u.height } }));
  // unconfirmed outputs to the address, minus outputs spent in the mempool
  const mem = await rpc('getrawmempool', []);
  const spent = new Set();
  for (const id of mem) {
    const t = await rpc('getrawtransaction', [id, 1]).catch(() => null); if (!t) continue;
    for (const i of t.vin) spent.add(`${i.txid}:${i.vout}`);
    t.vout.forEach((o, vout) => { if (o.scriptPubKey.address === address) utxos.push({ txid: t.txid, vout, value: sat(o.value), status: { confirmed: false } }); });
  }
  return utxos.filter((u) => !spent.has(`${u.txid}:${u.vout}`));
}

const server = http.createServer(async (req, res) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': '*' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  const send = (code, body, type = 'application/json') => { res.writeHead(code, { ...cors, 'Content-Type': type }); res.end(type === 'application/json' ? JSON.stringify(body) : String(body)); };
  const path = req.url.split('?')[0];
  let m;
  try {
    if (path === '/blocks/tip/height') return send(200, await rpc('getblockcount'), 'text/plain');
    if (path === '/blocks' || path === '/v1/blocks') return send(200, await blocksFrom(await rpc('getblockcount')));
    if ((m = path.match(/^\/blocks\/(\d+)$/))) return send(200, await blocksFrom(Number(m[1])));
    if (path === '/v1/fees/recommended') return send(200, { fastestFee: 1, halfHourFee: 1, hourFee: 1, economyFee: 1, minimumFee: 1 });
    if (path === '/v1/fees/mempool-blocks') return send(200, [{ medianFee: 1, feeRange: [1, 1], nTx: (await rpc('getrawmempool', [])).length }]);
    if (path === '/mempool') { const ids = await rpc('getrawmempool', []); return send(200, { count: ids.length, vsize: 0, total_fee: 0, fee_histogram: [] }); }
    if ((m = path.match(/^\/tx\/([0-9a-f]{64})$/))) return send(200, await txToEsplora(m[1]));
    if ((m = path.match(/^\/tx\/([0-9a-f]{64})\/status$/))) return send(200, (await txToEsplora(m[1])).status);
    if ((m = path.match(/^\/tx\/([0-9a-f]{64})\/outspend\/(\d+)$/))) { const spends = await rpc('gettxspendingprevout', [[{ txid: m[1], vout: Number(m[2]) }]]).catch(() => [{}]); return send(200, { spent: !!spends[0]?.spendingtxid, txid: spends[0]?.spendingtxid }); }
    if ((m = path.match(/^\/address\/([a-zA-Z0-9]+)\/utxo$/))) return send(200, await addressUtxos(m[1]));
    if (path === '/tx' && req.method === 'POST') {
      let body = ''; for await (const c of req) body += c;
      try { return send(200, await rpc('sendrawtransaction', [body.trim()]), 'text/plain'); }
      catch (e) { return send(400, `sendrawtransaction RPC error: ${e.message}`, 'text/plain'); }
    }
    return send(404, { error: `no route for ${req.method} ${path}` });
  } catch (e) { return send(500, { error: e.message }); }
});

// Blocks go to an unspendable P2TR (the BIP341 NUMS point) unless MINE_ADDRESS is set.
const BURN = 'bcrt1prykz5vxt6lgr2tu56np35slhvlc77s7hlajr3qucsrkqwhvp48mqwel98k';
async function mine() {
  try { await rpc('generatetoaddress', [1, process.env.MINE_ADDRESS || BURN]); }
  catch (e) { console.error('mine failed:', e.message); }
}
server.listen(PORT, '127.0.0.1', () => {
  console.log(`esplora shim on http://127.0.0.1:${PORT} -> ${RPC_URL}; mining every ${MINE_MS} ms`);
  if (MINE_MS > 0) setInterval(mine, MINE_MS);
});
