# Stage 7 — Pre-flight brief (signed-address-pool, destinations table, auto-invoicing)

Prepared 2026-10-14 (background research, after Stage 6 CORE passed its
gate and Cameron parked payments). Nothing here is a decision, a
ratification, or a build start. Payments are PARKED (Cameron,
2026-10-14 21:13 UTC) — this brief exists so Stage 7 is not later built
on the pre-review pool design by accident, the same job the Stage 6
pre-flight did for invoices.

## Scope (spec §24 stage 7, §11)

1. `signed-address-pool` destination module: seller uploads up to 200
   self-generated subaddresses; core validates each (valid subaddress,
   correct network, not present anywhere in `destinations`); core
   returns the canonical pool statement; seller signs it locally and
   uploads the signature; core verifies against the seller's current
   key and activates the pool.
2. One global `destinations` table (spec invariant 8): an address is
   never assigned to more than one invoice, enforced by a unique
   constraint — not by application care.
3. Allocation + auto-invoicing: on each order the module proposes the
   lowest unassigned entry; the core assigns it in the same
   transaction, under a row lock and the unique constraint. Dashboard
   warns at 10 remaining entries; an exhausted pool falls back to
   `signed-invoice` if enabled, otherwise pauses new orders.
   Uncertified key rotation retires pools signed by the old key (§ on
   rotation), and open orders need buyer reconfirmation before a new
   invoice issues from a rotated key.

## What the earlier gates leave ready

- Stage 6 CORE (327 passed / 0 failed, blind 83/83) already built the
  library layer Stage 7 stands on: `PoolStatement` parse/serialize
  with byte-identity rules, address-count 1–200 with the count exactly
  matching the address lines, duplicate address lines within one pool
  rejected, and destinations carried only as the `Subaddress` newtype
  (Q17 — no success type carries kind/network as strings).
- Stage 2 already enforces the listing-side rule: a listing selects a
  destination module, and auto-invoice is selectable only with
  `signed-address-pool`.
- Stage 3 gives the key history and rotation records the pool
  signature must verify against (the seller's *current* key, pinned —
  the same pinning discipline Stage 4 uses for orders).
- Stage 4's order machine already has the transition Stage 7 feeds:
  Requested → AwaitingPayment, actor "Core (auto-invoice) or seller",
  guard "destination allocated and verified; invoice issued".

## Hard blocker before any Stage 7 migration

The duplicate-0006 defect (flagged in the Stage 6 report): two incompatible 0006
migrations create `conversation_key_sightings`, so a fresh install
breaks one live write path. A repair draft is already prepared and
awaiting Cameron's go-ahead (`MIGRATION-0006-REPAIR-DRAFT-2026-10-14.md`
— Option A: unify on the keys.rs schema pinned by the locked
blind_stage3 suite, patch the messages.rs write path to use it).
The `destinations` table must land as the migration AFTER that repair
is applied and re-verified on a fresh database. Writing it before, or
numbering around the defect, would bake the fresh-install break into
the one table whose whole job is a uniqueness guarantee.

## Safe to design now (no dependence on the parked payment decision)

- The `destinations` table shape from the spec's schema table
  (address, seller_id, source pool-or-invoice, pool_id, pool_index,
  invoice_id; address unique; invoice_id unique when set) and the
  allocation transaction (row lock + unique constraint, lowest
  unassigned entry, never reuse — including after expiry, supersede,
  or apparent abandonment).
- Pool-upload validation reusing the Stage 6 library exactly as built:
  no second address parser, no second normalization path.
- The low-pool warning (10 remaining), pool-exhaustion fallback, and
  old-key pool retirement on uncertified rotation — all core logic
  already specified, none of it touched by either external review.
- The fresh-install test obligation: Stage 7's gate must include a
  from-empty-database run, because the 0006 defect is exactly the
  class of bug the dev DB (a hand-built union of both shapes) hid.

## Hold — intersects the encrypted-orders ratification (do NOT lock the format yet)

Payments are parked and the encrypted-orders plan is reconciled but
NOT ratified (open lines R4–R11 in
`RATIFICATION-RECONCILIATION-2026-10-14.md`, review numbering).
Three Stage 7 pieces sit directly on that decision:

1. **Pool signing format — Merkle root (review A1).** The second
   review's server-payment-theft fix replaces "sign the whole pool
   statement as the buyer-facing proof" with: the seller signs a
   Merkle root over the pool, and each reservation certificate carries
   the assigned address's inclusion proof, so the buyer's helper
   verifies the address is the seller's without trusting the server.
   This also fixes a leak in the current spec design (§11's own
   caveat): today a buyer holding an invoice sees the seller's other
   unassigned pool entries. If A1 is ratified, the pool *activation*
   record and what is downloadable from an invoice page both change —
   do not lock either format in a Stage 7 build started before
   ratification.
2. **Reservation certificate replaces bare allocation.** Under the
   plan Cameron has ruled direction on (standing acceptance: signed
   listing + signed pool manifest + core reservation certificate ARE
   the acceptance for standard orders), allocation is no longer just
   "assign entry, issue invoice" — the core issues a signed
   reservation certificate binding the assigned address to the order,
   listing version, and both parties' fingerprints. That certificate
   needs a public-ID prefix the pinned pattern
   `^(mkt|inv|ord|pool|acct)_[0-9a-f]{32}$` does not have; adding the
   prefix is part of the same spec amendment, not a Stage 7 improvisation.
3. **Auto-invoicing's core-visible footprint.** Under the Step A
   correction already recorded in the Stage 6 pre-flight, if
   acknowledgements stay inside encrypted messages the core lifecycle
   shrinks to routing + disputes, and a core-issued, core-visible
   invoice page is exactly the kind of happy-path sales record the
   weaker exact privacy claim ("no verified happy-path sales ledger")
   excludes. Whether auto-invoicing survives as spec'd, becomes
   reservation-only, or moves into the encrypted channel is a
   ratification outcome — Stage 7 must not pre-answer it by wiring
   the Stage 4 Requested → AwaitingPayment transition to a pool
   allocation before Cameron unparks payments.

## Sequencing this brief recommends (for Cameron's call, not a start order)

1. Apply the 0006 migration repair (draft ready, awaiting go-ahead)
   and re-verify on a fresh database.
2. Ratification pass on the reconciled encrypted-orders sheet
   (R4–R11 plus the reservation-prefix and terminology items).
3. Representative-user workflow test of the manual order flow — the
   review and reconciliation both make this the gate before
   re-planning stages, with the helper as the primary path.
4. Only then: Stage 7 contract-first (§-style API contract section
   for pool upload/activation, destinations, allocation/reservation),
   written against whichever pool format step 2 ratified.

## Explicitly not in Stage 7, whenever it starts

- No invoice routes/pages (Stage 6 flow, still held with payments).
- No payment evidence work (Stage 8: seller-attestation / tx-proof).
- No completion tokens, fulfilment percentages, or "verified sales"
  counts fed by allocation data — the reconciliation records these
  as rejected for v2 reputation; destinations data must not become a
  back-door sales ledger.
