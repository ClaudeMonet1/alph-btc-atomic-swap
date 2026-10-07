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

`src/musig2.js` implements BIP327 as specified and is checked against the BIP's test vectors (`docs/spec/bip327/*.json`: key aggregation, nonce generation, nonce aggregation, signing and verification, tweaking, signature aggregation and deterministic signing, including the error cases). The vectors run in Node (`npm run test:bip327`) and in the browser build (`npm run smoke:web` runs them in headless Chromium). Until 2026-09-27 the module was a self-consistent variant that hashed x-only keys, derived nonces its own way and kept the taproot tweak outside the signing context (CRYPTO_REVIEW F1 to F7); it produced valid signatures but could not be validated against anything.

- **Keys**: KeyAgg works on 33-byte plain keys. The parties' x-only keys are lifted to `02||x`, and a signer whose secret gives an odd-Y point negates it (`signerKey`), so the BIP340 identity key is also the MuSig2 key.
- **Tweaks**: the taproot output key is an x-only tweak of the key aggregation context (`tapTweak` = `ApplyTweak(ctx, H_TapTweak(P || merkle_root), true)`); `gacc` and `tacc` are carried in the context and the tweak's contribution `e·g·tacc` is added on aggregation, as in BIP327.
- **Nonces**: `NonceGen` with the secret key, the signer's public key, the aggregate key and the message as inputs; the 97-byte secret nonce carries the public key, is range-checked and zeroed on use, and signing refuses a nonce made for another key.
- **Curve shim**: `curve.js` exposes one small interface over `@noble/curves` 2.x (Node) or 1.x (browser, vendored), so that `musig2.js`, `adaptor.js`, `taproot-utils.js` and `bip327-selftest.js` are byte-identical in `src/` and `docs/js/`.

The adaptor extension in `src/adaptor.js` keeps BIP327's partial signature and changes only the challenge: `e = H((R + T) || Q || m)` with `R + T` normalised to even Y, which negates the nonces and the adaptor secret alike. `adaptorAggregate` includes the tweak term, so completing the aggregate pre-signature with `t` gives a BIP340 signature for the tweaked key directly, and `t` is extracted as the difference of the two `s` values. `bip327-selftest.js` also exercises the round trip on random keys, with and without a tweak, and checks that tampered pre-signatures, a wrong adaptor point, a consumed nonce and another signer's nonce are refused.

## Bitcoin Side: Taproot

The swap output is a P2TR with:
- **Key path**: MuSig2 aggregated key P_swap (cooperative claim)
- **Script path**: `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <bob_pubkey> OP_CHECKSIG` (Bob's refund, absolute Unix time)

For the key-path claim, the signature must be against the **tweaked** output key Q = P + H_TapTweak(P || merkle_root) * G. The MuSig2 signing accounts for this by adjusting `gacc` and adding `tacc * e` to the aggregated scalar.

Bob funds the swap directly from his nsec-derived P2TR address. No Bitcoin Core wallet is involved — Bob signs the funding transaction with his nsec-tweaked private key using `schnorr.sign`.

## Alephium Side: Ralph Contract

The contract uses `verifyBIP340Schnorr!(selfContractId!(), swapKey, sig)` to verify the MuSig2 signature. The message is the contract's own ID (32 bytes), which is:

- Known at deploy time (deterministic from deployer + bytecode + fields)
- Unique per contract instance
- Not dependent on txId (avoids circular dependency)

The contract holds ALPH and is destroyed on claim/refund via `destroySelf!()`, which sends all assets to the specified address.

Why a contract rather than a plain output (settled 2026-10-07, after measuring the alternative). A scriptless leg, where Alice funds a two-party address and both sign a refund in advance, is what the Bitcoin side does and it would cost a fifth as much. It cannot work here: an Alephium transaction has no lock time of its own, only outputs have one, and an output lock blocks every spender including the claimer. A pre-signed refund could therefore be broadcast at any moment, which reopens the claim-versus-refund race of audit findings S1 to S3. The asset permission system does not fill the gap either: it decides which assets a call may touch, holds nothing between transactions and has no clock. Script-hash outputs could carry the condition, but the node compiles only transaction scripts and contracts, so there is no supported path to spend one. The block timestamp the timeout needs is readable only from contract code, which is where this design already reads it. Measured on the devnet, the contract costs 0.01 ALPH to deploy and 0.01 to claim or refund, against 0.002 for a plain transfer, plus a 0.1 ALPH deposit returned when the contract is destroyed. The contract also buys a property the alternative lacks: the refund is permissionless, so anyone can trigger it after the timeout and the funds can only go back to Alice. Two chain features would change the conclusion, a transaction-level lock time or script-hash outputs exposed by the compiler with access to the block timestamp.

## Offers, fills, rates and history

An offer quotes `btcSat` for `alphAmount`; its rate is `btcSat / alphAmount` in sat per ALPH. With `minAlph` set, a taker may fill any amount between `minAlph` and `alphAmount` at that rate (the inline form on the card computes the sat side); the maker verifies every accept against the offer, exact amounts for an all-or-nothing offer, range and rate for a partial one, and ignores anything else, because the taker chooses the fill and never the price (until 2026-10-01 the maker took the accept's amounts on trust, so a taker could have started a swap at any amounts). After a partial fill the maker republishes the remainder at the same rate. For everyone except the maker and the acceptor, an accept does not take an offer off the list: the maker's taken signal (its cancel event naming the matched taker) does, otherwise anyone could hide every offer by accepting it with amounts the maker will reject; such pending accepts are shown on the card. The list has direction filters, "hide mine", and sorts by newest, size, or best rate for the viewer. Cards and the form show the rate both ways and the distance from a market reference: the median of three independent ALPH/BTC quotes (CoinGecko, CoinPaprika, Gate.io ALPH_USDT over BTC_USDT), counted as reliable only when at least two answered and agree within 5 %; a single or disputed quote is shown as such and not used for comparisons. With a reliable reference the sat field of the offer form is pre-set from the ALPH amount at the market rate until the user edits it by hand (a link restores it); publishing or taking an offer 30 % or more away from the reference asks for confirmation naming the sources.

Both parties publish public `started` and `completed` notes (kind 38389, tags `t=started|completed`, `p=<peer>`) about their counterparty; a card shows how many such notes others published about the maker over the last 60 days. Anyone can publish such notes, so this is a hint, not a proof.

## Keys

One secret, standard keys (audit S12 and W9; HD rework 2026-10-01). The stored secret is BIP39 entropy: 16 bytes, shown as 12 words, for identities created since 2026-10-01; 32 bytes, 24 words, for the ones before. From the mnemonic's seed, `keys.js` derives the Nostr key on the NIP-06 path `m/44'/1237'/0'/0/0` (12-word identities; a 32-byte secret stays the Nostr key itself so that earlier identities keep their npub, and an imported nsec is such a 32-byte secret), the Bitcoin key on the BIP86 path `m/86'/0'/0'/0/0` (taproot key path, so the descriptor `tr([…/86'/0'/0']xpub/0/*)` in Sparrow or Bitcoin Core finds the same coins) and the Alephium account on the wallet library's path `m/44'/1234'/0'/0/i` with the ECDSA key type, advancing `i` until the address falls in group 1 as Alephium wallets do, so the same words imported into the Alephium desktop or extension wallet give the same account. The page shows the words as the backup; for a 12-word identity the nsec is only the derived Nostr key and does not restore the wallet, which the reveal says. Index 0 of the Bitcoin branch is both the wallet address and the MuSig2 share. Peers announce `keys: { btc, alph }` in offers, counters and accepts (the Alephium key is 33 bytes for the HD scheme and 32 for the earlier Schnorr schemes, both accepted); the engine refuses a peer without them. Funds left on the addresses of the two earlier schemes (one key for everything until 2026-09-27, tagged hashes of the secret until 2026-10-01) are detected at load and moved with one click. `test/keys.test.mjs` checks the BIP86 and NIP-06 test vectors, agreement with the Alephium wallet library, the SDK's acceptance of the ECDSA signatures, and the mnemonic round trip; the smoke test repeats the derivation in the browser build.

## Alephium Group Sharding

Alephium uses 4-group sharding. A contract can only be called by accounts of its own group, and `destroySelf!` can only pay an address of its own group: the node rejects a payout to another group with `InvalidOutputGroupIndex` (checked on the devnet, `audit/group-constraint.test.mjs`). So Alice's refund address (the deployer, always in the contract's group) and Bob's claim address must be in the same group, otherwise Bob could never claim and Alice, who claims the BTC first, would end with both assets. This is enforced three times: the offer is refused when the peer's address is in another group, `initSwap` refuses such a peer, and Bob's contract verification checks that the claim address is in the contract's group. `refund()` may be called by anyone in the group once the timeout has passed and always pays `refundAddress`, so Alice does not need gas of her own to recover. The web app grinds every new key into `TARGET_ALPH_GROUP` (group 1) so that all its users can trade with each other. The Node demos constrain key generation so Alice and Bob end up in the same group:

```js
const targetGroup = getGroup(alicePub);
do {
  bobSecBytes = schnorr.utils.randomSecretKey();
  bobPub = schnorr.getPublicKey(bobSecBytes);
} while (getGroup(bobPub) !== targetGroup);
```

A key from another wallet that falls outside the target group is kept and reported; it cannot trade on the page.

## Timelock Ordering

Alice's BTC claim is what reveals the adaptor secret `t`; Bob claims ALPH only afterwards. So the leg that is claimed first (Bob's BTC) must become refundable **first**, and the leg claimed second (Alice's ALPH) only later, with a margin:

```
T_btc  = lock time + 24 h         Bob's refund leaf (OP_CHECKLOCKTIMEVERIFY, Unix time)
T_alph = T_btc + 12 h             Alice's contract timeout (blockTimeStamp, ms)
```

If it were the other way round (as in versions before 2026-09-27, which had ALPH at 6 h and BTC at 144 blocks), Alice could wait for her ALPH refund, take it, and then still claim the BTC with the completed adaptor signature, which has no timelock at all: she would end with both assets. That attack was demonstrated against the old code and is why both parties now enforce the ordering (`src/timelocks.js`, `docs/js/timelocks.js`):

- Bob chooses `T_btc` when he locks and sends it with the lock; Alice refuses a lock that expires in less than 1 h or more than 48 h, recomputes the swap address from it, and deploys her contract with `T_alph = T_btc + 12 h`.
- Bob reads the contract's `timeout` and refuses to pre-sign unless `T_btc + 6 h <= T_alph <= T_btc + 7 d`.
- Both timeouts are absolute timestamps. Bitcoin evaluates the leaf against median time past, which lags wall-clock time by one to two hours; the 12 h margin covers that lag, confirmation times on both chains, and Bob's reaction time.
- Confirmation depth scales with the amount (`btcConfirmationsFor`, `alphConfirmationsFor` in `timelocks.js`): below 0.001 BTC one Bitcoin block, below 0.01 two, below 0.1 three, else six; on Alephium two, four, eight or sixteen blocks of the contract's chain (devnet, which mines one block per transaction, stays at one). Both parties derive the depth from the agreed amount, so nothing is negotiated. The deepest rungs take about an hour on Bitcoin and a few minutes on Alephium, well inside the 24 h lock and the 12 h margin.
- Alice locks her ALPH only once Bob's funding transaction has that depth: an unconfirmed or shallow lock is Bob's to replace. She re-checks the locktime window after the wait.
- Bob pre-signs only once the deployment transaction, which Alice names in her `alph_deployed` message, has created the contract he verifies (a generated contract output paying its address) and has that depth on its chain (`verifyDeployment`): a deployment reorganised out after he pre-signed would leave him claiming nothing.
- Bob claims the ALPH only once Alice's BTC claim has that depth as well. The secret `t` is readable from the mempool, but a claim that is reorganised out after Bob has taken the ALPH would leave Alice with neither asset.
- Bob must refund promptly once `T_btc` has passed, or keep watching for Alice's claim until `T_alph`: Alice can claim the BTC until his refund confirms. The web app attempts the refund automatically as soon as median time past reaches the locktime.

## Fees

The claim is pre-signed, so its fee is fixed before either party signs: Alice proposes it when she deploys the contract (twice the current half-hour estimate for a 111 vB key-path spend, at least 1 sat/vB, at most 5% of the amount), Bob checks the same bounds before pre-signing, and both build the identical claim transaction from it. If the claim still gets stuck, Alice bumps it by spending its output, which is her own P2TR, with a child that pays for the parent (`bumpClaimFee`, "Bump claim fee" in the recovery panel). Bob's refund is built at refund time at the current rate and can be bumped the same way. Before 2026-09-27 both used a hard-coded 300 satoshis.

## Keys at rest, and where they come from

The secret and the swap state are kept unencrypted in this browser's `localStorage`, readable by anything that can read the browser profile (audit W3). The passphrase that used to seal them was removed on 2026-10-02, with the code that opened it: these are testnet amounts, and a wallet whose only protection is a forgotten passphrase loses more coins than it saves. A key left sealed by that option is therefore dropped at load, with one line in the log saying what was lost and that the recovery words bring it back. The help panel states that the key sits unencrypted in the profile.

A new identity is 128 bits from the platform CSPRNG (`crypto.getRandomValues`, which throws rather than falling back to anything weaker), read as a 12-word mnemonic with no truncation. The adaptor secret is 32 CSPRNG bytes reduced into [1, n) by `adaptorSecretFromBytes`, and every MuSig2 nonce mixes 32 fresh bytes as BIP327 prescribes. `npm run test:entropy` checks the distribution of 2000 fresh secrets bit by bit and byte by byte, the mnemonic round trip, the refusal of wrong-sized secrets, the range of adaptor secrets, that two nonces for one message differ, and that `Math.random` appears nowhere in `src/` or `docs/js/`; the browser smoke test repeats the generator check inside the page.

## Stuck transactions and lost relays

Recovery after a reload: the engine saves the session id, so a recovered Alice keeps the adaptor secret the peer already holds instead of minting a second one (found on 2026-10-02 by a live swap that was interrupted: her new adaptor point made every pre-signature unverifiable and the swap could only end in refunds). A peer that sends a different adaptor point is accepted only before pre-signatures exist, and refused with a clear error afterwards. `E2E_MODE=resume npm run e2e:local` reloads both pages right after Bob's lock, presses Resume on each and requires the swap to finish.

Messages that arrive early, and sides that fall out of step (2026-10-03). A swap message used to be dropped if the step waiting for it had not registered its wait yet, so a page that reloaded or retried a step left its peer waiting for ever: the sessions stalled in the nonce phase on the public relays were this. The page now keeps the peer's latest message per kind and phase, and a wait takes it from there before waiting for another; a long silence makes the page send its own last message again before giving up, so a peer that lost it can answer. If an unmatched nonce message arrives, meaning the peer restarted that exchange, this side restarts it too (at most twice, never once a pre-signature has been aggregated or a claim made), so the two state machines meet again instead of waiting on each other. A refund also settles the session now: it clears the saved state, which otherwise invited the next page load to resume a swap whose coins were already back.

Both parties' transactions can sit under the fee floor (signet's floor moves and the estimate lags): Alice's claim and Bob's lock are each watched by the page and bumped once with a child that spends their own output (the claim's output, the lock's change) when they are unconfirmed after five minutes with the floor above their rate; a "Bump" button does the same by hand, also from the recovery panel. A lock without a change output cannot be bumped, which the button says.

Relay publishes retry with backoff for up to a minute before a step fails, the last swap message is remembered and republished on a relay that reconnects (replaceable events make this idempotent), and the relay indicator shows reconnection and how long ago the peer last spoke. Every dialog is an in-page modal (`modal.js`): native dialogs blocked the page while a peer's message could arrive.

## Endpoints and a local end-to-end run

`config.js` holds the Bitcoin API (Esplora shape), the Alephium node, the explorer bases and the relays, with the public signet and testnet services as defaults. URL parameters override any of them and are remembered in the browser (`?btcNetwork=regtest&btcApi=…&alphNetwork=devnet&alphNode=…&relays=…`, `?resetConfig` restores the defaults); the Settings button shows what is in use. Faucet buttons hide off the test networks.

`npm run e2e:local` runs the complete two-browser swap against local chains in under a minute: `devnet/esplora-shim.mjs` serves the Esplora endpoints the page uses over a Bitcoin Core regtest node and mines a block every 15 s, `devnet/nostr-relay.mjs` is a minimal NIP-01 relay, the page is served from `docs/`, fresh keys are funded from a regtest coinbase and the devnet genesis, and `scripts/e2e-web.mjs` drives the maker and the taker through offer, accept, lock, deployment, nonces, pre-signatures and both claims. It needs the regtest node (`BTC_RPC_URL`, default port 18543) and the devnet node (port 22973) running, as the alph-btc-bridge nix shell provides them. `npm run e2e:live` is the same harness against the published page and real signet coins. `E2E_MODE=counter` takes the counter-offer path; `E2E_MODE=refund` aborts right after Bob's lock, moves the regtest clock 26 h ahead (`setmocktime`) so the shim's next blocks carry a median time past beyond T_btc, and expects Bob's recovery panel to refund by itself (the chain must be reset afterwards; the harness refuses to start on a future-dated chain). The first refund drill found two defects in the abort path: an abort between Bob's lock and Alice's deployment reset Bob's page instead of entering recovery, and a step chain awaiting a confirmation went on to deploy after a peer abort. Both are fixed: the abort rule looks at the party's own coins on chain (Bob's lock, Alice's contract), and every step chain carries a run token that an abort, reset or recovery invalidates.

## Mainnet switch

Settings offers signet, regtest or mainnet for Bitcoin and testnet, devnet or mainnet for Alephium; choosing a network fills that network's public services (`NETWORK_DEFAULTS` in `config.js`), which can then be edited for a self-hosted stack. Switching to mainnet requires typing MAINNET under a warning (24 h lock, 36 h contract timeout, amount-scaled confirmations, no dry run yet); on mainnet the badge turns red, a banner stays at the top, faucets are hidden, and every publish or accept asks for confirmation again. The confirmation ladders and fee logic already distinguish mainnet (`timelocks.js`). The contract artifact is looked up per network first (`atomic-swap.<network>.json`, written by `ARTIFACT_NETWORK=<network> npm run compile:contract`) with the common artifact as the fallback; the bytecode depends on the compiler version, not the network. A dry run with small real amounts has not been done and is the step that remains before mainnet use.

## Installable page and notifications

`manifest.webmanifest` and a generated service worker (`scripts/sw.template.js` through `stamp-build.mjs`, which lists the build's assets) make the page installable and let it open offline. The worker is network first for every same-origin request and never caches cross-origin ones, so a stale build is never served while the network is up; the cache name carries the build id and old caches are dropped on activation. Notifications are opt-in (a header button asks for permission) and fire only while the tab is not in front: a peer's message, a failed step, the lock and pre-sign steps done, a refund becoming available, and completion.

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
| `bip340-schnorr` key type | Direct API signing with `fromPublicKeyType` |
| Contract deployment | Fund and deploy in one transaction |

No protocol changes, no new opcodes, no forks required.

## Static Browser Deployment

The `docs/` directory contains a fully static version of the swap app that runs entirely in the browser. No server; ES modules resolved through an import map to bundles vendored in `docs/vendor/` (see below).

### Why Static

The server (`src/server.js`) is an unnecessary trust boundary. It holds the user's private key and performs all signing server-side. The static version moves all logic to the browser: keys are generated and used client-side, signing happens in JavaScript, and chain interactions go directly to public APIs (Esplora for Bitcoin, REST API for Alephium). This eliminates the server as an attack surface.

### Browser Compatibility

The browser build uses the vendored `@noble/curves` 1.8 while the Node build uses 2.x. The two point APIs differ (`ProjectivePoint.fromHex`/`toRawBytes` versus `Point.fromBytes`/`toBytes`, no `Point.Fn` in 1.x), so `docs/js/curve.js` and `src/curve.js` each wrap their library behind the same small interface and the crypto modules import only that. Other porting points: `tiny-secp256k1` uses WASM that does not initialise in the browser build and is replaced with `@bitcoinerlab/secp256k1`, which wraps `@noble/curves` in the interface `bitcoinjs-lib` expects; `@alephium/web3` is bundled as a CommonJS module and imported as a default export, then destructured.

### The contract is compiled once and shipped

The public testnet node answers the compile endpoint's CORS preflight with 403, so a browser cannot compile the Ralph source at run time (found on 2026-09-27 during the first two-browser swap on the live page: Alice failed at deployment). `npm run compile:contract` compiles the source through a node (devnet by default) into `docs/contracts/atomic-swap.json`; the browser loads that artifact and checks its SHA-256 of the source against the source embedded in `alph.js`, so both parties always use identical bytecode. The Node scripts still compile through their node.

### Dependencies are vendored, not fetched from a CDN

Until 2026-09-27 the import map pointed every bare specifier at esm.sh, so the code that handled the user's key was whatever the CDN served at load time (audit W3). `npm run vendor` (`scripts/vendor.mjs`) now bundles each dependency from the pinned package in `node_modules` into `docs/vendor/*.js` with esbuild, writes `docs/vendor/SHA256SUMS`, and rewrites the import map with local paths and an `integrity` block (subresource integrity for import maps, enforced by browsers that support it). The browser code targets `@noble/curves` 1.8 and `@noble/hashes` 1.7, installed under the aliases `noble-curves-1` and `noble-hashes-1` because the Node code uses the 2.x API. CommonJS packages get a generated wrapper so that named imports work. `npm run vendor:check` verifies the bundles against the checksums; `npm run smoke:web` loads the page in headless Chromium (serve `docs/` locally first) and reports page errors, failed requests, relay status and the derived identity. What runs in the browser is now what the repository holds; the remaining trust is in GitHub Pages serving the repository and in the browser itself.

A Buffer polyfill is still loaded before any module via top-level `await` in the bootstrap script, since `bitcoinjs-lib` uses `Buffer.from()` internally.

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
- **BTC**: `[Faucet] [copy] [Receive] [Withdraw]` — Faucet links to signetfaucet.com. Receive shows a QR popup. Withdraw opens a modal that sends the whole balance to a destination typed or scanned from a QR code (camera, `qrscan.js`: BarcodeDetector when the browser has it, otherwise jsQR on video frames; `bitcoin:`/`alephium:` URIs are reduced to the address), validated for the active network as it is typed and again before signing, with a confirmation naming the address.
- **ALPH**: `[Faucet] [copy] [Receive] [Withdraw]` — Faucet calls the Alephium testnet faucet API. Withdraw sends all ALPH minus a gas reserve, with the same scan and validation.

The **private key** (nsec) is masked by default (`••••••••`) with a `[show]` toggle to reveal the bech32-encoded nsec. The key row blinks when backup has not been confirmed. The `[Backed Up]` button requires an explicit confirmation dialog before dismissing the warning.

**Send (sweep)** validates destination addresses before broadcasting:
- BTC: `bitcoin.address.toOutputScript(addr, NETWORK)` — covers tb1p, tb1q, 2-prefix, m/n on testnet/signet
- ALPH: `groupOfAddress(addr)` — throws on invalid format

The sweep functions (`sweepBtc`, `sweepAlph` in `swap-engine.js`) sign all confirmed UTXOs or transfer the full balance minus gas, using the same tweaked-key signing path as the swap protocol.
