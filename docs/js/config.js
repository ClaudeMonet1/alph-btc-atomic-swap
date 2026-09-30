// Endpoints and networks (audit item "own endpoints"): defaults are the public
// signet and Alephium testnet services; any can be overridden through URL query
// parameters, which are then remembered in this browser until ?resetConfig.
//   ?btcNetwork=signet|regtest|mainnet  ?btcApi=<esplora base>  ?btcExplorer=<base>
//   ?alphNetwork=testnet|devnet|mainnet ?alphNode=<node base>   ?alphExplorer=<base>
//   ?relays=wss://a,wss://b
// A self-hosted stack (Esplora, node, relay) needs nothing else; the local
// end-to-end run (scripts/e2e-local.mjs) uses this with regtest and devnet.
export const DEFAULTS = {
  btcNetwork: 'signet',
  btcApi: 'https://mempool.space/signet/api',
  btcExplorer: 'https://mempool.space/signet',
  alphNetwork: 'testnet',
  alphNode: 'https://node.testnet.alephium.org',
  alphExplorer: 'https://testnet.alephium.org',
  relays: ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'],
};
const KEY = 'btc-alph-swap-config';
const KEYS = Object.keys(DEFAULTS);

function load() {
  let stored = {};
  try { stored = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch {}
  const params = new URLSearchParams(location.search);
  if (params.has('resetConfig')) { stored = {}; try { localStorage.removeItem(KEY); } catch {} }
  let changed = false;
  for (const k of KEYS) {
    if (!params.has(k)) continue;
    const v = params.get(k);
    stored[k] = k === 'relays' ? v.split(',').map((s) => s.trim()).filter(Boolean) : v.replace(/\/+$/, '');
    changed = true;
  }
  if (changed) { try { localStorage.setItem(KEY, JSON.stringify(stored)); } catch {} }
  const cfg = { ...DEFAULTS, ...stored };
  for (const n of ['btcNetwork', 'alphNetwork']) if (!/^[a-z]+$/.test(cfg[n])) cfg[n] = DEFAULTS[n];
  cfg.isDefault = KEYS.every((k) => JSON.stringify(cfg[k]) === JSON.stringify(DEFAULTS[k]));
  return cfg;
}

export const CONFIG = load();
export function resetConfig() { try { localStorage.removeItem(KEY); } catch {} }
