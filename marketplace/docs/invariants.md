# Core Invariants (locked — spec §3, as amended)

Changes to this file require the owner's review (spec §22). Each invariant has
at least one locked test in `tests/security/`.

**Scope (owner decision Q4, 2026-10-21).** The amended invariants (7)–(10)
below govern **Hidden Trades**. Direct Payments v1 — which still runs on
this tree — keeps the pre-amendment (7)–(10) until v1's removal in build
stage H6: under v1, (7) every invoice destination is a Monero subaddress on
the configured network, parsed with a maintained Monero library in the
order decode/checksum → network → kind → torsion-free keys, with primary
and integrated addresses rejected; (8) no destination is ever assigned to
more than one invoice (unique constraint, one global `destinations`
table); (9) a destination is stored only after the core verifies a seller
signature binding it to the seller's pinned key and validates the address
with the in-process address parser — the wallet-RPC `validate_address`
cross-check named in the original v1 wording is not built (threat model
T2; the server runs no wallet and has no wallet-RPC client); (10) only
the core changes order/invoice state, through the §9 transition tables.
Invariant (11) belongs to that v1 scope:
it speaks of orders and Paid, which are v1 concepts — under Hidden Trades
there is no server-side order for a payment report to move. Read with this
scoping, the amended (9)/(10) and (11) do not contradict each other: they
govern different systems that coexist on the tree until H6.

**Funds.** The marketplace never: (1) generates, imports, or stores a spending
key; (2) receives purchase funds into an address it controls; (3) keeps customer
balances; (4) signs or relays payment transactions; (5) deducts fees from
purchase payments; (6) offers any control implying administrators can move or
recover funds.

**Destinations.** (7) Every assignment destination is a Monero subaddress on
the configured network, validated by the buyer's helper with a maintained
Monero library in the order decode/checksum → network → kind → torsion-free
keys; primary and integrated addresses are rejected. (8) No destination is
assigned to more than one trade: the seller helper's local ledger marks it
used on assignment and refuses reuse. (9) The server stores no destinations.
The buyer's helper accepts a destination only from an assignment whose
signature verifies against the seller's pinned key.

**State.** (10) The server holds no order or trade state. Trade state is
computed by the helpers from signed statements with the shared fold library.
(11) A buyer's payment report never moves an order to Paid.
(12) The word "verified" appears only for proof-verified or wallet-observed
payments — and nowhere at all until real stagenet tx-proof verification is
proven (decision log Q11 hard gate).

**Messaging.** (13) Only encrypted OpenPGP messages are accepted; there is no
plaintext composer. (14) The server never generates, receives, or stores
messaging private keys. (15) Message payloads, shipping details, session
tokens, destinations, assignments, tx proofs, txids and notary submissions
never appear in logs.

**Browser.** (16) No scripts, inline event handlers, third-party requests, or
user- or module-supplied HTML or CSS.

**Modules and keys.** (17) Modules receive only the data their interface
defines and return typed values; never spending keys, message payloads, session
tokens, or raw request bodies. (18) Swapping or disabling a module never
changes the terms, destinations, or evidence recorded on existing orders.
(19) Private view keys are stored only on seller opt-in to the view-only-wallet
module, encrypted with the external key file, never logged, deleted on opt-out.

**Amendment additions (2026-10-13).** (20) Envelope error responses never
distinguish a registered key from an unknown one, and `RecipientKeyRetired` is
returned only for keys the sender was already shown in that conversation.
(21) Input trimming happens exactly once, at the form layer; every layer below
is strict.

**Hidden Trades amendment (2026-10-20).** Enacted in build stage H1 under
the Alpha build spec's §17 (the owner-reviewed amendment, spec §0/§17):
(7), (8), (9), (10) and (15) amended as above. The remaining §17 amendments
and additions — (11), (12), (18) and (22)–(30) — lock in their named stages
(H2–H4) and are not enacted here. (Scope of the amended rows: see the
Scope paragraph at the top of this file — owner decision Q4, 2026-10-21.)
