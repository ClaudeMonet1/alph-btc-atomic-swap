# BTC-ALPH Atomic Swaps

Trustless cross-chain swaps between Bitcoin and Alephium using MuSig2 adaptor signatures. No hash preimages, no bridge, no intermediary.

Each participant uses a **single Nostr nsec** as their identity across all three networks. The same secp256k1 private key derives their Nostr npub, Bitcoin P2TR address, and Alephium P2SH address.

```
nsec (secp256k1 scalar)
 ├── Nostr npub          (identity + coordination)
 ├── Bitcoin P2TR         (taproot, BIP-340 Schnorr)
 └── Alephium P2SH        (Schnorr, verifyBIP340Schnorr)
```

## Why This Works

Bitcoin (taproot) and Alephium both use **BIP-340 Schnorr signatures on secp256k1**. This shared signature scheme enables adaptor signatures to work natively on both sides without cross-curve proofs or hash preimage tricks.

Alephium provides the critical primitive: `verifyBIP340Schnorr!()` in the Ralph VM. That single builtin is all that's needed on the Alephium side.

## On-Chain Footprint

When the swap succeeds:

| Chain | What appears on-chain | Observer sees |
|-------|----------------------|---------------|
| Bitcoin | Key-path taproot spend | 1 signature. Looks like a normal payment. No scripts revealed. |
| Alephium | Contract call with `swap(sig)` | 1 signature verified against aggregated key. Contract destroyed. |

No hash preimages. No multisig. No script paths revealed on Bitcoin. The swap is indistinguishable from normal transactions to a chain observer.

## Try It

The static web app runs on GitHub Pages — no server, no install, no extensions. Open two browser tabs, publish an offer in one, accept in the other. The swap auto-executes through all 5 protocol steps.

**Networks**: Bitcoin signet + Alephium testnet. Get signet BTC from a [signet faucet](https://signet.bc-2.jp/) and testnet ALPH from the in-app faucet button.

To self-host:

```bash
# Any static HTTP server works
npx serve docs
# or
python3 -m http.server -d docs
```

### How the Web UI Works

1. The app generates a fresh Nostr nsec on load (or you paste your own)
2. It derives your npub, Bitcoin P2TR address (signet), and Alephium address (testnet) from that single key
3. You publish swap offers (e.g., "Sell 2 ALPH for 50000 sat") to public Nostr relays
4. Other users see your offer and can accept it
5. On accept, both sides auto-execute the 5-step adaptor signature protocol
6. All signing happens client-side — keys never leave the browser

## Dev Quick Start

Requires [Nix](https://nixos.org/) with flakes enabled.

```bash
# Enter the dev shell (provides Node.js, Bitcoin Core, Alephium, jq, etc.)
nix develop

# Install JS dependencies
npm install

# Start local chains
start-regtest && start-devnet

# Run the full test: happy path + both refund paths
npm run swap

# Run the Nostr relay-based swap (3 scenarios via structured events)
npm run nostr-swap

# Launch the web UI (devnet mode — local chains + Fund/Mine buttons)
npm run web

# Launch the web UI (testnet mode — signet + ALPH testnet)
npm run web:testnet

# Stop local chains
stop-regtest && stop-devnet
```

### Reset

If a previous run was interrupted or you want a clean slate, reset before running:

```bash
stop-regtest; stop-devnet
npm run reset
start-regtest && start-devnet
npm run swap
```

`npm run reset` removes `devnet/bitcoin/regtest/`, `devnet/alephium/.alephium/`, and `.swap-state.json`.

## Protocol

Alice has ALPH, wants BTC. Bob has BTC, wants ALPH.

```
1. Setup       Alice generates secret t, shares T = t*G
               Both compute P_swap = MuSig2(P_alice, P_bob)

2. Lock        Bob funds swap from his nsec-derived P2TR address
               Bob locks BTC in taproot   (key: P_swap, refund: Bob after T1)
               Alice deploys ALPH contract (key: P_swap, claim: Bob, refund: Alice after T2)
               T1 > T2 (BTC timeout must be longer)

3. Verify      Alice verifies BTC output on-chain
               Bob verifies ALPH contract state on-chain

4. Pre-sign    Both exchange adaptor pre-signatures for both claim transactions
               (off-chain, e.g. via Nostr NIP-44 encrypted DMs)

5. Claim       Alice completes BTC adaptor → claims BTC at her P2TR → reveals t
               Bob extracts t from Bitcoin → completes ALPH adaptor → claims ALPH

6. Refund      If Alice never claims: after T2, Alice refunds ALPH
               After T1 (> T2), Bob refunds BTC
```

### How Adaptor Signatures Work

Normal Schnorr: `e = H(R || P || m)`, `s = r + e*x`

Adaptor: the nonce point is shifted by an adaptor point `T = t*G`:
- Pre-signature: `e = H((R+T) || P || m)`, `s' = r + e*x` (not a valid sig)
- Complete: `s = s' + t` (now valid, but reveals `t`)
- Extract: `t = s - s'` (anyone with the pre-sig and completed sig recovers `t`)

The secret `t` is the atomic link. When Alice completes her adaptor to claim BTC, the completed signature on Bitcoin reveals `t`. Bob extracts `t` and completes his adaptor to claim ALPH.

### Atomicity

- If Alice claims BTC, she reveals `t`, and Bob can always claim ALPH.
- If Alice doesn't claim before `T2`, she can refund her ALPH. Bob can then refund his BTC after `T1`.
- `T2 < T1` ensures Alice's refund window comes first — if Alice refunds ALPH and then tries to claim BTC, Bob still has time to refund.
- Neither party can get both assets.

## The Alephium Contract

The entire Alephium-side smart contract is 17 lines of Ralph:

```ralph
Contract AtomicSwap(
  swapKey: ByteVec,       // MuSig2 aggregated key (32 bytes x-only)
  claimAddress: Address,  // Bob's address — receives funds on swap
  refundAddress: Address, // Alice's address — receives funds on refund
  timeout: U256           // millisecond timestamp
) {
  @using(assetsInContract = true, checkExternalCaller = false)
  pub fn swap(sig: ByteVec) -> () {
    verifyBIP340Schnorr!(selfContractId!(), swapKey, sig)
    destroySelf!(claimAddress)
  }

  @using(assetsInContract = true)
  pub fn refund() -> () {
    assert!(blockTimeStamp!() >= timeout, 0)
    checkCaller!(callerAddress!() == refundAddress, 1)
    destroySelf!(refundAddress)
  }
}
```

- `swap()` verifies a single 64-byte BIP-340 Schnorr signature against the MuSig2 aggregated key. No multisig opcodes, no hash preimages.
- The message being signed is `selfContractId!()` — a 32-byte value known at deploy time, avoiding the txId circular dependency.
- `destroySelf!()` sends all contract ALPH to the designated address and removes the contract.
- `refund()` is time-locked and caller-restricted — only Alice, and only after the timeout.
- No protocol changes to Alephium are needed. This uses existing VM builtins.

## Architecture

Two deployment modes share the same crypto core:

**Static web app** (`docs/`) — runs entirely in the browser via ES modules + import maps. No server, no build step. Testnet only (Bitcoin signet + ALPH testnet).

**Node.js server** (`src/server.js` + `index.html`) — HTTP backend for the web UI. Supports both devnet (local regtest/devnet chains) and testnet.

### Crypto Core

| File | What it does |
|------|-------------|
| `src/musig2.js` | BIP-327 MuSig2: key aggregation, nonce gen, partial sign/verify/agg |
| `src/adaptor.js` | Adaptor signatures: sign, verify, aggregate, complete, extract |
| `src/taproot-utils.js` | Taproot tweaked keys, adaptor challenge, tweaked private key |
| `src/btc-swap.js` | Bitcoin taproot: P2TR output, key-path spend, refund via script-path |
| `src/alph-swap.js` | Alephium contract: compile, deploy, claim, refund, verify state + bytecode |

### Static Web App (`docs/`)

| File | What it does |
|------|-------------|
| `docs/index.html` | HTML + CSS + import map + Buffer polyfill bootstrap |
| `docs/js/app.js` | UI, Nostr messaging, offer management, auto-execution |
| `docs/js/swap-engine.js` | All swap logic as a client-side class (replaces server.js API) |
| `docs/js/btc.js` | Bitcoin module (Esplora-only, signet-hardcoded) |
| `docs/js/alph.js` | Alephium module (testnet-hardcoded) |
| `docs/js/musig2.js` | BIP-327 MuSig2 (browser-compatible, uses `secp256k1.ProjectivePoint`) |
| `docs/js/adaptor.js` | Adaptor signatures (browser-compatible) |
| `docs/js/taproot-utils.js` | Taproot key tweaking (browser-compatible) |

All browser dependencies are loaded from esm.sh via import map — `@noble/curves`, `bitcoinjs-lib`, `@alephium/web3`, `bech32`. The Buffer polyfill is loaded before any modules via top-level `await`.

### CLI Tests

| File | What it does |
|------|-------------|
| `src/atomic-swap.js` | End-to-end orchestration, state persistence/recovery, refund tests |
| `src/nostr-swap.js` | Nostr relay-based swap: 3 scenarios (happy path, both refunds) |
| `src/relay.js` | Minimal NIP-01 Nostr relay (in-memory, for testing) |
| `src/swap-events.js` | Structured Nostr event builders (kinds 38390-38393) |
| `src/wallet.js` | CLI wallet utility |

No Bitcoin Core wallet is used anywhere. Bob signs the funding transaction with his nsec-tweaked private key. Alice receives BTC at her nsec-derived P2TR.

## Security Properties

| Property | How it holds |
|----------|-------------|
| **Atomicity** | Adaptor secret `t` links both chains — either both claims succeed or neither does |
| **No theft** | `swap()` always sends to `claimAddress` (Bob), regardless of caller |
| **No timeout race** | T_btc (144 blocks ~ 1 day) > T_alph (6 hours) |
| **Signature unforgeability** | MuSig2 2-of-2 — neither party can sign alone |
| **No replay** | Signature message is `selfContractId!()`, unique per contract |

## Crash Recovery

The swap orchestrator persists state to `.swap-state.json` at critical checkpoints:

| Phase | What's saved | Recovery action |
|-------|-------------|-----------------|
| `locked` | Funding txids, contract address, timeouts | Manual: wait for timeouts, then refund |
| `presigned` | Adaptor pre-signatures, tweak data | Auto: complete BTC claim, then ALPH claim |
| `btc_claimed` | BTC claim txid | Auto: extract `t` from Bitcoin, claim ALPH |
| `complete` | — | Cleanup state file |

On startup, `atomic-swap.js` checks for an existing state file and attempts automatic recovery.

## Ephemeral Keys

For production use, Alice and Bob can generate ephemeral per-swap keypairs instead of using their long-term nsec. The MuSig2 protocol only requires the keys for signing — funding can come from any wallet (an exchange, a hardware wallet, etc.), and withdrawal can go to any address.

## Nostr Coordination

Peers discover each other and exchange protocol messages over public Nostr relays. Five event kinds structure the swap lifecycle:

| Kind | Purpose |
|------|---------|
| 38389 | Offer lifecycle — publish, counter, accept, cancel |
| 38390 | Swap setup — role assignment, adaptor point, parameters |
| 38391 | Nonce exchange — MuSig2 nonce commit/reveal/verify |
| 38392 | Pre-signatures — adaptor pre-sig exchange and verification |
| 38393 | Claim notifications — BTC/ALPH claim txids |

All swap messages are encrypted (NIP-44) between the two parties. Offers are public.

## What's Left for Production

The cryptography and on-chain logic are complete. What remains:

- **Fee estimation**: Dynamic fees for both chains (currently hardcoded)
- **Mainnet deployment**: Safety limits, rate limiting, monitoring
- **Persistent state**: Browser version uses in-memory state only (refresh = lost swap)

## Dependencies

**Node.js** (server + CLI):
- `@alephium/web3` + `@alephium/web3-wallet` — Alephium SDK
- `bitcoinjs-lib` + `tiny-secp256k1` — Bitcoin taproot transactions
- `nostr-tools` — Nostr key encoding (npub/nsec)
- `@noble/curves` — secp256k1 primitives (used directly for MuSig2)
- `ws` — WebSocket (Nostr relay communication)

**Browser** (static app, via esm.sh CDN):
- `@noble/curves@1.8.1` — secp256k1, MuSig2, Schnorr
- `@noble/hashes@1.7.1` — SHA-256
- `bitcoinjs-lib@7.0.1` — Bitcoin transaction building
- `@bitcoinerlab/secp256k1@1.2.0` — ECC library for bitcoinjs-lib (pure JS, replaces WASM-based tiny-secp256k1)
- `@alephium/web3@2.0.8` + `@alephium/web3-wallet@2.0.8` — Alephium SDK
- `bech32@2.0.0` — npub encoding
- `buffer@6.0.3` — Buffer polyfill

## License

MIT
