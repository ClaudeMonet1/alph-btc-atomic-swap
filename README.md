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

## Quick Start

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

# Stop local chains
stop-regtest && stop-devnet
```

### Reset

If a previous run was interrupted or you want a clean slate, reset before running:

```bash
# Stop services, wipe chain data + swap state, restart fresh
stop-regtest; stop-devnet
npm run reset
start-regtest && start-devnet
npm run swap
```

`npm run reset` removes `devnet/bitcoin/regtest/`, `devnet/alephium/.alephium/`, and `.swap-state.json`. The test generates fresh keys and mines new blocks each run, so stale chain state from a previous run will cause failures.

### What the Test Does

1. Generates fresh Nostr nsec keys for Alice and Bob
2. Derives addresses on all three networks from each nsec
3. Funds both parties (Alice with ALPH, Bob with BTC)
4. Executes the full atomic swap using only nsec-derived keys
5. Verifies final balances
6. Tests ALPH refund path (Alice reclaims after timeout)
7. Tests BTC refund path (Bob reclaims after CSV timeout)

### Expected Output

```
=== BTC-ALPH Atomic Swap via Adaptor Signatures ===

[SETUP] Alice npub: npub1ge08m5ep9fa9jk4jxsw68g07mvmh0mway2u6s8k598a6qnhamdxqnxusgh
[SETUP]       ALPH: pqaknjCEeaBPQ56x1N31G4ueEu51Mxa5CUcd2VPbTFZG (group 3)
[SETUP]       BTC:  bcrt1pql76lznu5dlm9sm3rg9y9w25sfsnhvjjrmhzs4x2ng4vvc2xkmkspanyxr
[SETUP] Bob   npub: npub10wfmvdmm29f8ahm7ngkr95pv0z6pw9lsjrlf0nkq79czkxcpvd7q3rv940
[SETUP]       ALPH: kNus9DiJrtAqqnkB7sTcRepYj4cQebFXK4tspvgsco4o (group 3)
[SETUP]       BTC:  bcrt1pxr3q46ypknaevu8ms3tsvza8hjdcmnlha7qp3c2xqgx5cfa8stnsd395n2
[LOCK]  BTC funded from Bob's P2TR: txid=1767a224c1b84482...
[LOCK]  ALPH contract deployed: 2B5aMK3mvBszS2nWduJGdAnwSGfWh9Rtimd3bNRbxUxDg
[CLAIM] BTC claimed! txid: 19a40e770406ffcbd9359dd39dc63f8aba488a...
[CLAIM] Secret t extracted successfully!
[CLAIM] ALPH claimed! txid: 44fd9b5bb6bac8651d6f260d1188724168cf0c...
[VERIFY] Alice ALPH: 89.99 ALPH  (started with 100, locked 10)
[VERIFY] Bob   ALPH: 14.99 ALPH  (started with 5, received 10)
[VERIFY] Alice BTC:  0.499997 BTC (at nsec-derived P2TR)

=== ALPH Refund Path Test ===
[REFUND-ALPH] Contract deployed with expired timeout
[REFUND-ALPH] Alice calls refund()...
[REFUND-ALPH] Recovered: ~9.99 ALPH (10 minus gas)

=== BTC Refund Path Test ===
[REFUND-BTC] Swap funded from Bob's P2TR
[REFUND-BTC] Mining 10 blocks for CSV timeout...
[REFUND-BTC] Bob builds refund tx (script-path spend)...
[REFUND-BTC] BTC refunded!
[REFUND-BTC] Bob received: 0.499997 BTC
```

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

| File | Lines | What it does |
|------|-------|-------------|
| `src/musig2.js` | 215 | BIP-327 MuSig2: key aggregation, nonce gen, partial sign/verify/agg |
| `src/adaptor.js` | 132 | Adaptor signatures: sign, verify, aggregate, complete, extract |
| `src/taproot-utils.js` | 44 | Taproot tweaked keys, adaptor challenge, tweaked private key |
| `src/btc-swap.js` | 285 | Bitcoin taproot: P2TR output, key-path spend, refund via script-path |
| `src/alph-swap.js` | 254 | Alephium contract: compile, deploy, claim, refund, verify state + bytecode |
| `src/atomic-swap.js` | 660 | End-to-end orchestration, state persistence/recovery, refund tests |
| `src/relay.js` | 98 | Minimal NIP-01 Nostr relay (in-memory, WebSocket) |
| `src/swap-events.js` | 178 | Structured Nostr event builders (kinds 38390-38393) for protocol phases |
| `src/nostr-swap.js` | 842 | Nostr relay-based swap: 3 scenarios (happy path, both refund, crash recovery) |

No Bitcoin Core wallet is used anywhere in the swap flow. Bob mines to his nsec-derived P2TR and signs the funding transaction with his nsec-tweaked private key. Alice receives BTC at her nsec-derived P2TR. All Bitcoin RPC calls go to the base node URL — no wallet context needed.

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

## What's Left for Production

The cryptography and on-chain logic are complete. What remains:

- **Fee estimation**: Dynamic fees for both chains (currently hardcoded for regtest/devnet)
- **Mainnet deployment**: Safety limits, rate limiting, monitoring

## Dependencies

- `@alephium/web3` + `@alephium/web3-wallet` — Alephium SDK
- `bitcoinjs-lib` + `tiny-secp256k1` — Bitcoin taproot transactions
- `nostr-tools` — Nostr key encoding (npub/nsec)
- `@noble/curves` — secp256k1 primitives (transitive dep, used directly for MuSig2)

## License

MIT
