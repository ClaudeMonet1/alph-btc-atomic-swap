# Design Notes

## Why Adaptor Signatures Instead of HTLCs

The classic approach to atomic swaps uses hash-time-locked contracts (HTLCs): Alice generates a secret, both sides lock funds behind the hash, Alice claims by revealing the preimage. This works but has drawbacks:

- **On-chain fingerprint**: Hash preimages are visible on-chain, linking the two legs of the swap
- **Larger transactions**: Each claim carries a 32-byte preimage in addition to a signature
- **Script path revealed on Bitcoin**: The HTLC script is exposed when spending

Adaptor signatures eliminate all three problems. The completed signature itself carries the secret — no preimage appears on-chain, no scripts are revealed on Bitcoin (key-path taproot spend), and the transaction is smaller.

| | Adaptor Signatures | HTLC |
|---|---|---|
| On-chain privacy | Looks like normal spends | Hash preimage visible |
| Bitcoin tx size | 1 signature (64 bytes) | 1 signature + 32-byte preimage |
| Script revealed | No (key-path spend) | Yes (script-path spend) |
| Implementation complexity | Higher (MuSig2 required) | Lower |

## MuSig2 Implementation

The MuSig2 implementation in `src/musig2.js` follows BIP-327:

- **Key aggregation** (section 4.3): Second-key optimization for efficient 2-of-2. The aggregated key Q is normalized to even-Y, tracked via `gacc`.
- **Nonce generation** (section 4.5): Two nonce pairs per signer, tagged hash derivation from secret key + aggregate pubkey + message.
- **Partial signing** (section 4.8): Each signer produces a partial signature using the nonce coefficient `b` and challenge `e`. Private key negation is handled correctly for x-only pubkeys and aggregate key parity.
- **Partial verification** (section 4.9): Verifies `s*G == R_eff + e*a*gacc*P` for each partial signature.
- **Aggregation** (section 4.10): Sums partial signatures, verifies the result with `schnorr.verify`.

The adaptor extension in `src/adaptor.js` modifies the challenge computation: `e = H((R_agg + T) || P || m)` instead of `e = H(R_agg || P || m)`. The partial signature formula is identical; only the effective R point differs.

## Bitcoin Side: Taproot

The swap output is a P2TR with:
- **Key path**: MuSig2 aggregated key P_swap (cooperative claim)
- **Script path**: `<timeout> OP_CSV OP_DROP <bob_pubkey> OP_CHECKSIG` (Bob's refund)

For the key-path claim, the signature must be against the **tweaked** output key Q = P + H_TapTweak(P || merkle_root) * G. The MuSig2 signing accounts for this by adjusting `gacc` and adding `tacc * e` to the aggregated scalar.

Bob funds the swap directly from his nsec-derived P2TR address. No Bitcoin Core wallet is involved — Bob signs the funding transaction with his nsec-tweaked private key using `schnorr.sign`.

## Alephium Side: Ralph Contract

The contract uses `verifyBIP340Schnorr!(selfContractId!(), swapKey, sig)` to verify the MuSig2 signature. The message is the contract's own ID (32 bytes), which is:

- Known at deploy time (deterministic from deployer + bytecode + fields)
- Unique per contract instance
- Not dependent on txId (avoids circular dependency)

The contract holds ALPH and is destroyed on claim/refund via `destroySelf!()`, which sends all assets to the specified address.

## Alephium Group Sharding

Alephium uses 4-group sharding. A contract caller must be in the same group as the contract. The implementation constrains key generation so Alice and Bob end up in the same group:

```js
const targetGroup = getGroup(alicePub);
do {
  bobSecBytes = schnorr.utils.randomSecretKey();
  bobPub = schnorr.getPublicKey(bobSecBytes);
} while (getGroup(bobPub) !== targetGroup);
```

In production with ephemeral per-swap keys, the initiator picks the target group and both parties generate keys until they land in it.

## Timelock Ordering

The BTC timelock (T1 = 144 blocks, ~1 day on mainnet) must be strictly longer than the ALPH timelock (T2 = 6 hours). This prevents the following attack:

1. Alice refunds ALPH (after T2)
2. Alice claims BTC (before T1)

With T1 > T2, if Alice refunds her ALPH, Bob still has time to refund his BTC before T1 expires. The margin between T1 and T2 must account for:
- Block confirmation times on both chains
- Time to detect Alice's ALPH refund
- Time to broadcast Bob's BTC refund

## State Persistence and Recovery

The swap orchestrator saves state at three checkpoints:

1. **`locked`**: Both chains funded, no pre-signatures yet. Recovery requires manual refund after timeouts.
2. **`presigned`**: Adaptor pre-signatures exchanged. Recovery can complete the BTC claim automatically, then the ALPH claim.
3. **`btc_claimed`**: BTC claimed, adaptor secret revealed on-chain. Recovery extracts `t` from Bitcoin and claims ALPH.

The state file (`.swap-state.json`) contains everything needed to resume: keys, nonces, adaptor data, transaction IDs, contract addresses.

## What Alephium Already Provides

Everything needed already exists in the Alephium VM:

| Feature | Used for |
|---------|----------|
| `verifyBIP340Schnorr!()` | Verify MuSig2 aggregated signature |
| `selfContractId!()` | Deterministic message for signing |
| `destroySelf!()` | Send contract funds to recipient |
| `blockTimeStamp!()` | Timeout-based refund |
| `checkCaller!()` | Restrict refund to deployer |
| `bip340-schnorr` key type | PrivateKeyWallet with Schnorr signing |
| Contract deployment | Fund and deploy in one transaction |

No protocol changes, no new opcodes, no forks required.

## Static Browser Deployment

The `docs/` directory contains a fully static version of the swap app that runs entirely in the browser. No server, no build step, no bundler — just ES modules loaded via import maps from esm.sh CDN.

### Why Static

The server (`src/server.js`) is an unnecessary trust boundary. It holds the user's private key and performs all signing server-side. The static version moves all logic to the browser: keys are generated and used client-side, signing happens in JavaScript, and chain interactions go directly to public APIs (Esplora for Bitcoin, REST API for Alephium). This eliminates the server as an attack surface.

### Browser Compatibility

The crypto modules (`musig2.js`, `adaptor.js`, `taproot-utils.js`) use `@noble/curves` which is designed for both Node.js and browsers. The main porting challenge was API surface differences in the esm.sh build:

- **`schnorr.Point`** does not exist in the browser build. Replaced with `secp256k1.ProjectivePoint` and manual scalar field arithmetic (`Fn` object).
- **`schnorr.Point.fromBytes()`** replaced with `ProjectivePoint.fromHex()` (accepts both hex strings and Uint8Array).
- **`point.toBytes(true)`** replaced with `point.toRawBytes(true)` (33-byte compressed) and `.slice(1)` for 32-byte x-only.
- **`tiny-secp256k1`** uses WASM which fails to initialize in the browser via esm.sh. Replaced with `@bitcoinerlab/secp256k1` which wraps `@noble/curves` in the interface that `bitcoinjs-lib` expects.
- **`@alephium/web3`** exports only a default export on esm.sh. Imported as `import alphWeb3 from '@alephium/web3'` then destructured.

### Import Map + Buffer Polyfill

The app uses an HTML import map to resolve bare specifiers (`'@noble/curves/secp256k1'` etc.) to esm.sh CDN URLs. A Buffer polyfill is loaded before any modules via top-level `await` in the bootstrap script, since `bitcoinjs-lib` uses `Buffer.from()` internally.

### CORS

All external APIs used by the static app have permissive CORS headers:
- `mempool.space/signet/api` — Bitcoin signet Esplora (`access-control-allow-origin: *`)
- `node.testnet.alephium.org` — Alephium testnet node (`access-control-allow-origin: *`)
- `faucet.testnet.alephium.org` — Alephium testnet faucet (`access-control-allow-origin: *`)

### SwapEngine

The `SwapEngine` class (`docs/js/swap-engine.js`) is a direct translation of all 18 API handlers from `server.js` into a single client-side class. Each method operates on `this.state` instead of a server-side session map. The swap protocol logic is identical — only the HTTP wrapper is removed.

### Testnet Only

The static version is hardcoded to Bitcoin signet + Alephium testnet. Devnet requires local blockchain nodes which can't be accessed from a browser. The Node.js server version supports both devnet and testnet.

### Identity Panel & Wallet Operations

The identity panel displays three address lines — npub, BTC (signet), and ALPH (testnet) — each with contextual action buttons:

- **npub**: `[copy] [QR]` — QR shows a receive popup with canvas-rendered QR code (click to copy as image) and address text (click to copy).
- **BTC**: `[Faucet] [copy] [Receive] [Send]` — Faucet links to signetfaucet.com. Receive shows QR popup. Send opens a sweep-all modal.
- **ALPH**: `[Faucet] [copy] [Receive] [Send]` — Faucet calls the Alephium testnet faucet API. Send sweeps all ALPH minus gas reserve.

The **private key** (nsec) is masked by default (`••••••••`) with a `[show]` toggle to reveal the bech32-encoded nsec. The key row blinks when backup has not been confirmed. The `[Backed Up]` button requires an explicit confirmation dialog before dismissing the warning.

**Send (sweep)** validates destination addresses before broadcasting:
- BTC: `bitcoin.address.toOutputScript(addr, NETWORK)` — covers tb1p, tb1q, 2-prefix, m/n on testnet/signet
- ALPH: `groupOfAddress(addr)` — throws on invalid format

The sweep functions (`sweepBtc`, `sweepAlph` in `swap-engine.js`) sign all confirmed UTXOs or transfer the full balance minus gas, using the same tweaked-key signing path as the swap protocol.
