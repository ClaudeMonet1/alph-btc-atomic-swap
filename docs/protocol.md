# BTC-ALPH Atomic Swap — Petri Net Protocol Model

Formal protocol model for the atomic swap. The protocol is modeled as an open Petri net that starts and ends with an empty net, with a single conflict point determining swap success or refund. Atomicity is guaranteed — either both parties swap or both refund.

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

Both parties exchange adaptor pre-signatures via Nostr DMs (NIP-44 encrypted). Each side provides a partial MuSig2 signature tweaked by the adaptor point T. Both verify the other's adaptor is valid. If the exchange stalls (party goes offline, Nostr fails), `exchange_timeout` fires when T2 passes, forking into the cancel path so both parties recover their assets.

```
;exchange_presigs both_locked -> presigs_ready
;exchange_timeout both_locked -> alph_refundable btc_cancel_wait
```

**Conflict**: `alice_claims_btc` and `t2_timeout` both consume `presigs_ready`. Exactly one fires. This is the protocol's decision point — everything after is deterministic.

### Happy path

Alice completes her adaptor, producing a valid MuSig2 signature. She claims BTC to her nsec-derived P2TR address. The completed signature reveals the adaptor secret t (anyone can compute t = s_complete - s_pre). Bob extracts t from Alice's Bitcoin claim transaction, completes his own adaptor, and claims ALPH. The T2 < T1 timelock ordering guarantees Bob sufficient time to extract t and claim.

```
;alice_claims_btc@Alice presigs_ready -> t_revealed
;bob_claims_alph@Bob t_revealed -> done
```

### Cancel path

If Alice doesn't claim BTC before T2, the timeout fires. This produces tokens in two independent places via a fork — ALPH and BTC refunds happen on different chains with different timelocks, so they proceed in parallel.

```
;t2_timeout presigs_ready -> alph_refundable btc_cancel_wait
```

Alice refunds ALPH immediately after T2. Bob waits for T1 (> T2) then refunds BTC. These are independent — neither blocks the other. Both must complete before the protocol terminates.

```
;alice_cancel_refund@Alice alph_refundable -> recovery_done
;t1_timeout btc_cancel_wait -> btc_cancel_refundable
;bob_cancel_refund@Bob btc_cancel_refundable -> recovery_done
;both_recovered recovery_done recovery_done -> done
```

### Termination

All paths produce a token in `done`. The `stop` transition closes the net.

```
;stop done -> ()
```

## Properties

**Terminal states**: Two paths to `done` (consumed by `stop`):
- Happy path: `alice_claims_btc` -> `bob_claims_alph` -> `done` (swap complete)
- Cancel path: fork -> `alice_cancel_refund` + `bob_cancel_refund` -> `both_recovered` -> `done` (full refund)

The cancel path is reachable from two places: `t2_timeout` at `presigs_ready` (Alice didn't claim) or `exchange_timeout` at `both_locked` (presig exchange stalled).

**Safety**: The net is 2-bounded. All places are 1-bounded except `recovery_done`, which holds 2 tokens on the cancel path (one per refund). The `both_recovered` join consumes both. Conflicts at `both_locked` and `presigs_ready` ensure mutual exclusion between the swap and cancel paths.

**Atomicity**: If `alice_claims_btc` fires, `t_revealed` is produced, guaranteeing `bob_claims_alph` fires. The T2 < T1 timelock ordering ensures Bob always has sufficient time to extract t and claim ALPH. Neither party can get both assets.

**Liveness**: Under clock fairness, if either party is unresponsive, a timeout eventually fires. `exchange_timeout` covers the presig exchange phase, `t2_timeout` covers the claim phase. The `both_recovered` join ensures the cancel path completes only after both parties have reclaimed their assets.

## Abort Before Locking

Either party can abandon the swap before committing assets on-chain. These early aborts extend the setup phase:

```
;negotiate_timeout swap_agreed -> done
;lock_timeout btc_locked -> btc_abort_wait
;t1_timeout_abort btc_abort_wait -> btc_abort_refundable
;bob_abort_refund@Bob btc_abort_refundable -> done
```

`negotiate_timeout` — Bob doesn't lock BTC. Alice loses nothing (she hasn't locked yet).

`lock_timeout` — Alice doesn't lock ALPH after seeing Bob's lock. Bob's BTC is already on-chain, so the token moves to `btc_abort_wait`. After T1 expires, Bob refunds via the script path.

## Composition

The open boundary (`start () ->` and `stop -> ()`) enables composition with environment nets:

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
