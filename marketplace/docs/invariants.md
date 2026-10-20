# Core Invariants (locked — spec §3, as amended)

Changes to this file require the owner's review (spec §22). Each invariant has
at least one locked test in `tests/security/`.

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
(H2–H4) and are not enacted here.
