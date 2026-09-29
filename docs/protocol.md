# BTC-ALPH Atomic Swap — Petri Net Protocol Model

Formal protocol model for the atomic swap as implemented (rewritten 2026-09-29 after the audit). The protocol is an open Petri net that starts and ends with an empty net. Its safety property, checked exhaustively, is that Bob can never end with both assets; Alice can end with both only if Bob stays offline for the twelve hours after her claim, which is a liveness requirement on Bob, stated below rather than hidden.

## The net

Alice has ALPH and wants BTC; Bob has BTC and wants ALPH. The net below is generated from `docs/js/petri-net.js`, the same definition the page's simulator runs (`scripts/petri-doc.mjs --check` keeps them equal; `npm run test:petri` explores every reachable marking). Timers are tokens: `lock_btc` starts `btc_timer` (T_btc = lock time + 24 h, an absolute `OP_CHECKLOCKTIMEVERIFY` on Bob's refund leaf), `lock_alph` starts `alph_timer` (T_alph = T_btc + 12 h, the contract timeout; Bob refuses less than T_btc + 6 h). Actors: `@Alice`, `@Bob`, `@anyone`; timeouts and chain confirmations carry no actor.

<!-- net:start -->
```
;start () -> ready
;negotiate ready -> swap_agreed
;negotiate_timeout swap_agreed -> done
;lock_btc@Bob swap_agreed -> btc_locked btc_timer
;btc_confirms btc_locked -> btc_confirmed
;lock_alph@Alice btc_confirmed -> alph_locked alph_timer
;exchange_presigs alph_locked -> presigs_ready
;alice_claims_btc@Alice presigs_ready btc_timer -> t_revealed
;bob_claims_alph@Bob t_revealed alph_timer -> done
;stop done -> ()
;t_btc_timeout btc_timer -> btc_refund_open
;bob_abort_refund@Bob btc_confirmed btc_refund_open -> done
;bob_stall_refund@Bob alph_locked btc_refund_open -> btc_refunded
;bob_refund@Bob presigs_ready btc_refund_open -> btc_refunded
;alice_late_claim@Alice presigs_ready btc_refund_open -> t_revealed
;both_refunded btc_refunded alph_refunded -> done
;t_alph_timeout alph_timer -> alph_refundable
;alph_refund@anyone alph_refundable -> alph_refunded
;alice_has_both t_revealed alph_refunded -> done
```

- `start`: Someone accepts an offer; both pages start the same session
- `negotiate`: Alice draws t and sends T; both compute the MuSig2 key from the announced Bitcoin keys
- `negotiate_timeout` (timeout): Bob never locks (1 h): nothing is at stake, the session ends
- `lock_btc` (Bob): Bob locks BTC in the taproot output (key path: MuSig2 key; leaf: Bob after T_btc = now + 24 h) and starts T_btc
- `btc_confirms` (chain): Alice waits for the confirmation depth of the amount (one block on signet) and re-checks the locktime window
- `lock_alph` (Alice): Alice deploys the contract with T_alph = T_btc + 12 h; Bob checks the deployment depth, the state and T_alph >= T_btc + 6 h
- `exchange_presigs`: Nonce commit and reveal, then adaptor pre-signatures for the BTC claim and the ALPH claim, each verified
- `alice_claims_btc` (Alice): Alice completes the pre-signature with t and spends the key path before T_btc (bumping the fee if needed)
- `bob_claims_alph` (Bob): Bob reads t from the confirmed claim, completes the ALPH pre-signature and calls swap() before T_alph
- `stop`: The net is empty again
- `t_btc_timeout` (timeout): Median time past reaches T_btc: Bob's refund opens (the page refunds automatically)
- `bob_abort_refund` (Bob): Alice never deployed: Bob refunds through the leaf; nothing else to recover
- `bob_stall_refund` (Bob): The exchange stalled: Bob refunds through the leaf; Alice refunds at T_alph
- `bob_refund` (Bob): Alice has not claimed: Bob's refund confirms first and closes the key path
- `alice_late_claim` (Alice): Alice's claim confirms before Bob's refund: the race Bob avoids by refunding at once; Bob still has 12 h to claim the ALPH
- `both_refunded`: Cancel path complete: both parties recovered
- `t_alph_timeout` (timeout): Block time reaches T_alph: refund() opens
- `alph_refund` (anyone): refund() is permissionless and always pays Alice
- `alice_has_both`: Bob stayed offline for the 12 h after her claim: Alice holds the BTC and her ALPH. Liveness, not atomicity: Bob must claim within the window
<!-- net:end -->

### Happy path

`start`, `negotiate`, `lock_btc`, `btc_confirms`, `lock_alph`, `exchange_presigs`, `alice_claims_btc`, `bob_claims_alph`, `stop`. Alice's claim consumes `btc_timer`: once her claim is on chain, Bob's refund leaf can never be spent. Bob's claim consumes `alph_timer`: once the contract is claimed, Alice's refund can never open. Between the two, the implementation waits for confirmation depth on both chains (Alice on Bob's lock, Bob on Alice's deployment and on Alice's claim), and Alice bumps her claim's fee when it sits below the floor; those waits are inside `btc_confirms`, `lock_alph` and `bob_claims_alph`.

### Cancel path

`t_btc_timeout` fires when Bitcoin's median time past reaches T_btc and opens Bob's refund. Three cases:

- Alice never deployed (`btc_confirmed` still marked): `bob_abort_refund`, nothing else to recover.
- The exchange stalled after her deployment (`alph_locked`): `bob_stall_refund`, then `t_alph_timeout` and `alph_refund` twelve hours later, joined by `both_refunded`.
- Pre-signatures were exchanged (`presigs_ready`) and Alice has not claimed: `bob_refund` and `alice_late_claim` are both enabled and consume the same two tokens. This is the race the audit found: the key path has no timelock, so Alice can still claim until Bob's refund confirms. The page therefore refunds automatically the moment T_btc passes, and Alice's own refund opens only twelve hours later, so a late claim leaves Bob the whole window to take the ALPH.

### The liveness case

After `t_revealed`, `bob_claims_alph` and `t_alph_timeout` compete for `alph_timer`. If Bob is offline for the twelve hours after Alice's claim, `alph_refund` then `alice_has_both` fire: Alice holds the BTC and her ALPH. The construction cannot prevent this (a timeout must eventually free Alice's ALPH); it is a liveness requirement on Bob, whose page polls for Alice's claim and claims as soon as it is confirmed.

## Properties

Checked exhaustively by `test/petri.test.mjs` over every reachable marking:

- **Safety**: every place holds at most one token; the only dead marking is the empty net, so every run ends with `stop`.
- **Bob never ends with both assets**: no run fires both a Bob refund and `bob_claims_alph` (`bob_refund` and `alice_late_claim` are mutually exclusive; `alice_claims_btc` consumes the Bitcoin timer).
- **Alice ends with both assets only through `alice_has_both`**, i.e. only if Bob does not claim within T_alph − T_btc = 12 h of her claim.
- **Every transition is reachable.**

The net does not model the timelock *values*: with T_alph < T_btc the same net would admit a run where Alice refunds ALPH and then claims BTC (the defect found by the 2026-09-27 audit). Atomicity therefore rests on Bob's verification of the deployed contract (`alphTimeoutBounds`: T_btc + 6 h ≤ T_alph ≤ T_btc + 7 d), which is part of the protocol and not an optional check, and on Bob refunding promptly at T_btc.

## Abort Before Locking

`negotiate_timeout` (Bob never locks; the page waits one hour for a message before giving up) ends the session with nothing at stake. A reload at any point restores the saved session (`started`, `btc_locked`, `locked`, `presigned`, `btc_claimed` checkpoints) and resumes from the first unfinished step; the setup, lock and deployment steps are idempotent.

## Why a contract on ALPH instead of MuSig2?

Alephium supports Schnorr natively, so a symmetric MuSig2 construction is possible on both chains. The protocol uses a Ralph contract on the ALPH side instead for pragmatic reasons:

- **Inspectable state** — contract fields (swap key, claim/refund addresses, timeout) are readable on-chain, so the counterparty can verify the lock without trusting key aggregation.
- **Unilateral locking** — deploying a contract is a single tx from Alice. A MuSig2 funding output would require an interactive signing round just to lock.
- **Explicit timeouts** — the contract enforces `blockTimeStamp >= timeout` directly. MuSig2 would need Alephium script-path opcodes equivalent to Bitcoin's CLTV.
- **Atomic destruction** — after claim or refund, the contract self-destructs and returns all ALPH automatically.

The trade-off is asymmetry: BTC uses taproot MuSig2, ALPH uses a contract. A pure MuSig2 design on both chains would be more elegant but would add interactive rounds and verification complexity.

## Composition

The open boundary (`start () ->` and `stop -> ()`) enables composition with environment nets:

- **Nostr coordination net**: Order matching, DM exchange, reputation attestation
- **Bitcoin chain net**: Block production, taproot UTXO state, timelock progression
- **Alephium chain net**: Block production, P2SH state, Ralph script execution

Each environment net interfaces through shared places at the boundary.

## Nostr Event Mapping

| Phase | Kind | Content `type` / `phase` | Content |
|-------|------|--------------------------|---------|
| Discovery | 38389 | `offer`, `counter`, `accept`, `cancel` | Amounts, direction, expiry (24 h), the party's `keys: { btc, alph }` |
| `negotiate` | 38390 | `confirm` | Alice's adaptor point T |
| `lock_btc` | 38390 | `btc_locked` | Funding txid and vout, amount, T_btc, Bob's keys |
| `lock_alph` | 38390 | `alph_deployed`, then `verified` | Contract id and address, deployment txid, proposed claim fee; Bob's verification |
| `exchange_presigs` | 38391 | `commit`, `reveal` | Hashes of the public nonces, then the nonces |
| `exchange_presigs` | 38392 | (pre-signatures) | Adaptor pre-signatures for the BTC and ALPH claims |
| `alice_claims_btc` | 38393 | `btc_claimed` | BTC claim txid (reveals t once confirmed) |
| `bob_claims_alph` | 38393 | `alph_claimed` | ALPH claim txid |
| abort | 38390 | `abort` | The peer gave up before locking |

Offer events (38389) are public. All other events are NIP-44 v2 encrypted between the two swap parties (`nip44.js`, cross-checked against nostr-tools; NIP-04 in the browser and plaintext in the Node scripts until 2026-09-27). A message that does not decrypt is ignored; there is no plaintext fallback. An accept older than the page is not allowed to start a swap (relays replay two days of events on every load).
