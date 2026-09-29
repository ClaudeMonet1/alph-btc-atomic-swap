// The swap protocol as a Petri net: the single definition behind the in-page
// simulator (petri-viewer.js), docs/protocol.md (scripts/petri-doc.mjs) and
// test/petri.test.mjs (reachability checks). Rewritten on 2026-09-29 to match
// the protocol as implemented after the audit:
//
//   T_btc = lock time + 24 h (absolute, OP_CHECKLOCKTIMEVERIFY on Bob's refund leaf)
//   T_alph = T_btc + 12 h (contract timeout; Bob refuses less than T_btc + 6 h)
//
// Timers are tokens: lock_btc starts btc_timer, lock_alph starts alph_timer.
// Bob's refund opens when btc_timer expires; Alice's claim consumes the timer
// (before T_btc) or races Bob's refund transaction (after it). Bob's ALPH claim
// consumes alph_timer; if the timer expires first, Alice may refund the ALPH.
// Every place holds at most one token; the net starts and ends empty.

export const PLACES = [
  // happy path (column 1)
  { id: 'ready', col: 1, row: 1, desc: 'Offer accepted on Nostr; both sides in the same session' },
  { id: 'swap_agreed', col: 1, row: 3, desc: 'Keys and amounts known to both; Alice sent the adaptor point T' },
  { id: 'btc_locked', col: 1, row: 5, desc: "Bob's lock transaction is broadcast" },
  { id: 'btc_confirmed', col: 1, row: 7, desc: "Bob's lock has the confirmation depth the amount calls for" },
  { id: 'alph_locked', col: 1, row: 9, desc: 'Alice deployed the contract; Bob verified deployment depth, state and T_alph' },
  { id: 'presigs_ready', col: 1, row: 11, desc: 'Nonces (commit, reveal) and adaptor pre-signatures exchanged and verified' },
  { id: 't_revealed', col: 1, row: 13, desc: "Alice's BTC claim is on chain: the adaptor secret t is public" },
  { id: 'done', col: 1, row: 16, desc: 'Terminal' },
  // Bitcoin timer and refund (column 2)
  { id: 'btc_timer', col: 2, row: 5, desc: "Bob's refund locktime T_btc is running" },
  { id: 'btc_refund_open', col: 2, row: 8, desc: "T_btc passed: Bob's refund leaf is spendable; the key path still is too" },
  { id: 'btc_refunded', col: 2, row: 14, desc: "Bob's refund transaction confirmed" },
  // Alephium timer and refund (column 3)
  { id: 'alph_timer', col: 3, row: 9, desc: 'The contract timeout T_alph = T_btc + 12 h is running' },
  { id: 'alph_refundable', col: 3, row: 12, desc: 'T_alph passed: refund() is callable by anyone' },
  { id: 'alph_refunded', col: 3, row: 14, desc: 'The contract paid Alice back and destroyed itself' },
];

export const TRANSITIONS = [
  { id: 'start', label: 'start', actor: null, col: 1, row: 0, inputs: [], outputs: ['ready'], desc: 'Someone accepts an offer; both pages start the same session' },
  { id: 'negotiate', label: 'negotiate', actor: null, col: 1, row: 2, inputs: ['ready'], outputs: ['swap_agreed'], desc: 'Alice draws t and sends T; both compute the MuSig2 key from the announced Bitcoin keys' },
  { id: 'negotiate_timeout', label: 'no lock (1 h)', actor: 'timeout', col: 0, row: 3, inputs: ['swap_agreed'], outputs: ['done'], desc: 'Bob never locks (1 h): nothing is at stake, the session ends' },
  { id: 'lock_btc', label: 'lock BTC', actor: 'Bob', col: 1, row: 4, inputs: ['swap_agreed'], outputs: ['btc_locked', 'btc_timer'], desc: 'Bob locks BTC in the taproot output (key path: MuSig2 key; leaf: Bob after T_btc = now + 24 h) and starts T_btc' },
  { id: 'btc_confirms', label: 'confirms', actor: 'chain', col: 1, row: 6, inputs: ['btc_locked'], outputs: ['btc_confirmed'], desc: 'Alice waits for the confirmation depth of the amount (one block on signet) and re-checks the locktime window' },
  { id: 'lock_alph', label: 'lock ALPH', actor: 'Alice', col: 1, row: 8, inputs: ['btc_confirmed'], outputs: ['alph_locked', 'alph_timer'], desc: 'Alice deploys the contract with T_alph = T_btc + 12 h; Bob checks the deployment depth, the state and T_alph >= T_btc + 6 h' },
  { id: 'exchange_presigs', label: 'presigs', actor: null, col: 1, row: 10, inputs: ['alph_locked'], outputs: ['presigs_ready'], desc: 'Nonce commit and reveal, then adaptor pre-signatures for the BTC claim and the ALPH claim, each verified' },
  { id: 'alice_claims_btc', label: 'Alice claims', actor: 'Alice', col: 1, row: 12, inputs: ['presigs_ready', 'btc_timer'], outputs: ['t_revealed'], desc: 'Alice completes the pre-signature with t and spends the key path before T_btc (bumping the fee if needed)' },
  { id: 'bob_claims_alph', label: 'Bob claims', actor: 'Bob', col: 1, row: 14, inputs: ['t_revealed', 'alph_timer'], outputs: ['done'], desc: "Bob reads t from the confirmed claim, completes the ALPH pre-signature and calls swap() before T_alph" },
  { id: 'stop', label: 'stop', actor: null, col: 1, row: 17, inputs: ['done'], outputs: [], desc: 'The net is empty again' },
  // Bitcoin timer and refunds
  { id: 't_btc_timeout', label: 'T_btc', actor: 'timeout', col: 2, row: 7, inputs: ['btc_timer'], outputs: ['btc_refund_open'], desc: "Median time past reaches T_btc: Bob's refund opens (the page refunds automatically)" },
  { id: 'bob_abort_refund', label: 'Bob refunds', actor: 'Bob', col: 2, row: 9, inputs: ['btc_confirmed', 'btc_refund_open'], outputs: ['done'], desc: 'Alice never deployed: Bob refunds through the leaf; nothing else to recover' },
  { id: 'bob_stall_refund', label: 'Bob refunds', actor: 'Bob', col: 2, row: 10, inputs: ['alph_locked', 'btc_refund_open'], outputs: ['btc_refunded'], desc: 'The exchange stalled: Bob refunds through the leaf; Alice refunds at T_alph' },
  { id: 'bob_refund', label: 'Bob refunds', actor: 'Bob', col: 2, row: 12, inputs: ['presigs_ready', 'btc_refund_open'], outputs: ['btc_refunded'], desc: "Alice has not claimed: Bob's refund confirms first and closes the key path" },
  { id: 'alice_late_claim', label: 'late claim', actor: 'Alice', col: 2, row: 13, inputs: ['presigs_ready', 'btc_refund_open'], outputs: ['t_revealed'], desc: "Alice's claim confirms before Bob's refund: the race Bob avoids by refunding at once; Bob still has 12 h to claim the ALPH" },
  { id: 'both_refunded', label: 'both back', actor: null, col: 2, row: 16, inputs: ['btc_refunded', 'alph_refunded'], outputs: ['done'], desc: 'Cancel path complete: both parties recovered' },
  // Alephium timer and refunds
  { id: 't_alph_timeout', label: 'T_alph', actor: 'timeout', col: 3, row: 11, inputs: ['alph_timer'], outputs: ['alph_refundable'], desc: 'Block time reaches T_alph: refund() opens' },
  { id: 'alph_refund', label: 'refund()', actor: 'anyone', col: 3, row: 13, inputs: ['alph_refundable'], outputs: ['alph_refunded'], desc: 'refund() is permissionless and always pays Alice' },
  { id: 'alice_has_both', label: 'Alice has both', actor: null, col: 3, row: 15, inputs: ['t_revealed', 'alph_refunded'], outputs: ['done'], desc: 'Bob stayed offline for the 12 h after her claim: Alice holds the BTC and her ALPH. Liveness, not atomicity: Bob must claim within the window' },
];

export const NET = { places: PLACES, transitions: TRANSITIONS };

// The `;name inputs -> outputs` notation used in docs/protocol.md.
export function toNotation() {
  return TRANSITIONS.map((t) => `;${t.id}${t.actor && t.actor !== 'timeout' && t.actor !== 'chain' ? '@' + t.actor : ''} ${t.inputs.length ? t.inputs.join(' ') : '()'} -> ${t.outputs.length ? t.outputs.join(' ') : '()'}`).join('\n');
}
