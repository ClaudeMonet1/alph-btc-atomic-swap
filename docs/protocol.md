# BTC-ALPH Atomic Swap — Petri Net Protocol Model

Formal protocol model for the atomic swap. The protocol is modeled as an open Petri net that starts and ends with an empty net, with a single conflict point determining swap success or refund.

## Adaptor Signature Protocol

Alice has ALPH, wants BTC. Bob has BTC, wants ALPH.

```
;start () -> ready
```

Both parties agree on swap parameters. Each uses a single Nostr nsec — the same key derives their npub, Bitcoin P2TR address, and Alephium P2SH address. Alice generates adaptor secret t, shares T = t*G. MuSig2 key aggregation produces P_swap.

```
;negotiate ready -> swap_agreed
```

Bob funds from his nsec-derived P2TR address and locks BTC in a taproot output. Key path: P_swap (2-of-2). Script path: Bob can refund after timelock T1.

```
;lock_btc@Bob swap_agreed -> btc_locked
```

Alice verifies Bob's lock on Bitcoin, then locks ALPH in a Ralph Contract. `swap(sig)` verifies a MuSig2 signature against P_swap and sends funds to Bob's address. `refund()` lets Alice reclaim after timelock T2, where T2 < T1.

```
;lock_alph@Alice btc_locked -> both_locked
```

Both parties exchange adaptor pre-signatures via Nostr DMs (NIP-44 encrypted). Each side provides a partial MuSig2 signature tweaked by the adaptor point T. Both verify the other's adaptor is valid.

```
;exchange_presigs both_locked -> presigs_ready
```

**Conflict**: `alice_claims_btc` and `t2_timeout` both consume `presigs_ready`. Exactly one fires. This is the protocol's single decision point — everything before it is sequential, everything after is deterministic.

Alice completes her adaptor, producing a valid MuSig2 signature. She claims BTC to her nsec-derived P2TR address. The completed signature reveals the adaptor secret t (anyone can compute t = s_complete - s_pre). Bob extracts t from Alice's Bitcoin claim transaction, completes his own adaptor, and claims ALPH.

```
;alice_claims_btc@Alice presigs_ready -> t_revealed
;bob_claims_alph@Bob t_revealed -> ()
```

If Alice doesn't claim before T2, the timeout fires. Alice refunds her ALPH. After T1 (> T2) expires, Bob refunds his BTC. The T2 < T1 ordering prevents Alice from refunding ALPH and then racing to claim BTC — Bob always has time to refund.

```
;t2_timeout presigs_ready -> t2_expired
;alice_refunds_alph@Alice t2_expired -> btc_refundable
;t1_timeout btc_refundable -> t1_expired
;bob_refunds_btc@Bob t1_expired -> ()
```

## Properties

**Terminal states**: The net reaches empty via exactly one of two paths:
- Happy path: `alice_claims_btc` -> `bob_claims_alph` -> empty (swap complete)
- Cancel path: `t2_timeout` -> `alice_refunds_alph` -> `t1_timeout` -> `bob_refunds_btc` -> empty (full refund)

**Safety**: The net is 1-bounded. No place ever holds more than one token. The conflict on `presigs_ready` ensures mutual exclusion — either the swap path or the cancel path executes, never both.

**Atomicity**: If `alice_claims_btc` fires, `t_revealed` is produced, guaranteeing `bob_claims_alph` can fire. Bob can always claim after Alice claims. Neither party can get both assets.

**Liveness**: Under clock fairness, if Alice is unresponsive, `t2_timeout` eventually fires. Both parties always recover their assets on the cancel path.

## Abort Before Locking

Either party can abandon the swap before committing assets on-chain. These early aborts extend the setup phase:

```
;negotiate_timeout swap_agreed -> ()
;lock_timeout btc_locked -> ()
```

`negotiate_timeout` — Bob doesn't lock BTC. Alice loses nothing (she hasn't locked yet).

`lock_timeout` — Alice doesn't lock ALPH after seeing Bob's lock. Bob's BTC stays locked until T1, then he refunds. This is why T1 should be short relative to negotiation time.

## Composition

The open boundary (tokens entering via `start`, leaving via `-> ()`) enables composition with environment nets:

- **Nostr coordination net**: Order matching, DM exchange, reputation attestation
- **Bitcoin chain net**: Block production, taproot UTXO state, timelock progression
- **Alephium chain net**: Block production, P2SH state, Ralph script execution

Each environment net interfaces through shared places at the boundary.

## Nostr Event Mapping

The protocol phases map to structured Nostr events:

| Phase | Kind | Action | Content |
|-------|------|--------|---------|
| Discovery | 38389 | `offer` | Public offer: amounts, direction, npub |
| Discovery | 38389 | `accept` | Offer acceptance, triggers swap |
| `negotiate` | 38390 | `setup` | Role, adaptor point T, swap parameters |
| `lock_btc` / `lock_alph` | 38390 | `locked` | Funding txid, contract address |
| `exchange_presigs` | 38391 | `nonce-commit` | Hash of nonce (commit phase) |
| `exchange_presigs` | 38391 | `nonce-reveal` | MuSig2 public nonces |
| `exchange_presigs` | 38392 | `presig` | Adaptor pre-signatures |
| `alice_claims_btc` | 38393 | `claim-btc` | BTC claim txid (reveals t) |
| `bob_claims_alph` | 38393 | `claim-alph` | ALPH claim txid |

Offer events (38389) are public. All other events are NIP-44 encrypted between the two swap parties.
