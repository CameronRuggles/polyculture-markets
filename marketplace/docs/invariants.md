# Core Invariants (locked — spec §3, as amended)

Changes to this file require the owner's review (spec §22). Each invariant has
at least one locked test in `tests/security/`.

**Funds.** The marketplace never: (1) generates, imports, or stores a spending
key; (2) receives purchase funds into an address it controls; (3) keeps customer
balances; (4) signs or relays payment transactions; (5) deducts fees from
purchase payments; (6) offers any control implying administrators can move or
recover funds.

**Destinations.** (7) Every invoice destination is a Monero subaddress on the
configured network, parsed with a maintained Monero library — validation order:
decode/checksum → network → kind → torsion-free keys; primary and integrated
addresses are rejected. (8) No destination is ever assigned to more than one
invoice (unique constraint, one global `destinations` table). (9) A destination
is stored only after the core verifies a seller signature binding it to the
seller's pinned key — and cross-checks it with the wallet-RPC `validate_address`
second parser; disagreement means reject + security event.

**State.** (10) Only the core changes order/invoice state, through the §9
transition tables. (11) A buyer's payment report never moves an order to Paid.
(12) The word "verified" appears only for proof-verified or wallet-observed
payments — and nowhere at all until real stagenet tx-proof verification is
proven (decision log Q11 hard gate).

**Messaging.** (13) Only encrypted OpenPGP messages are accepted; there is no
plaintext composer. (14) The server never generates, receives, or stores
messaging private keys. (15) Message payloads, shipping details, session tokens,
payment destinations, and tx proofs never appear in logs.

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
