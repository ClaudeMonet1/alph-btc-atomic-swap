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
// Public services per network: chosen automatically when a network is set without an endpoint.
export const NETWORK_DEFAULTS = {
  btc: {
    signet: { btcApi: 'https://mempool.space/signet/api', btcExplorer: 'https://mempool.space/signet' },
    mainnet: { btcApi: 'https://mempool.space/api', btcExplorer: 'https://mempool.space' },
    regtest: { btcApi: 'http://127.0.0.1:18544', btcExplorer: 'http://127.0.0.1:18544' },
  },
  alph: {
    testnet: { alphNode: 'https://node.testnet.alephium.org', alphExplorer: 'https://testnet.alephium.org' },
    mainnet: { alphNode: 'https://node.mainnet.alephium.org', alphExplorer: 'https://explorer.alephium.org' },
    devnet: { alphNode: 'http://127.0.0.1:22973', alphExplorer: 'http://127.0.0.1:22973' },
  },
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
  // a network named without its endpoints takes that network's public services
  if (params.has('btcNetwork') && !params.has('btcApi') && NETWORK_DEFAULTS.btc[params.get('btcNetwork')]) Object.assign(stored, NETWORK_DEFAULTS.btc[params.get('btcNetwork')]);
  if (params.has('alphNetwork') && !params.has('alphNode') && NETWORK_DEFAULTS.alph[params.get('alphNetwork')]) Object.assign(stored, NETWORK_DEFAULTS.alph[params.get('alphNetwork')]);
  if (changed) { try { localStorage.setItem(KEY, JSON.stringify(stored)); } catch {} }
  const cfg = { ...DEFAULTS, ...stored };
  for (const n of ['btcNetwork', 'alphNetwork']) if (!/^[a-z]+$/.test(cfg[n])) cfg[n] = DEFAULTS[n];
  cfg.isDefault = KEYS.every((k) => JSON.stringify(cfg[k]) === JSON.stringify(DEFAULTS[k]));
  cfg.isMainnet = cfg.btcNetwork === 'mainnet' || cfg.alphNetwork === 'mainnet';
  return cfg;
}

export const CONFIG = load();
export function resetConfig() { try { localStorage.removeItem(KEY); } catch {} }
// Stores a full configuration (the Settings form); takes effect after a reload.
export function saveConfig(values) {
  const stored = {};
  for (const k of KEYS) if (values[k] !== undefined && values[k] !== null && values[k] !== '') stored[k] = values[k];
  try { localStorage.setItem(KEY, JSON.stringify(stored)); } catch {}
}
