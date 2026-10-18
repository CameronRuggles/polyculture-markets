# Direct Payments v1 — mapping onto the spec v2 codebase

Owner handoff: `Direct_Monero_Payments_v1___Muse.AI_Handoff` (2026-10-15).
Status: payments UN-PARKED by the owner with this design (2026-10-15).
This plan follows the handoff's own kickoff: inspection + mapping first,
no code until the owner approves the plan.

## What the design is, in one paragraph

Buyers pay sellers directly, wallet to wallet. Sellers pre-generate
subaddresses in their own wallet with a helper tool; each subaddress
carries a one-line message signed by the seller's **primary address key**
(wallet `sign`), binding marketplace_id, network, seller_id, primary
address and the subaddress. The server stores signed subaddresses,
assigns exactly one per order at creation, and never touches keys,
funds, txids or amounts. The seller marks the order Paid after seeing
funds in their own wallet. No escrow, no tx-proof, no fees, no
server-side node/wallet in v1.

## How it maps onto what exists

| Handoff element | Existing seam | Verdict |
|---|---|---|
| Payment strategy behind plugin interface | `modules-api` traits (`DestinationProvider`, `PaymentEvidenceProvider`) — compiled-in modules per Q9 | Fits. New module `direct-v1` implements both traits |
| Signed subaddress pool | `destinations` table already in migration 0001 with a global uniqueness constraint; `DestinationEvidence::SignedPoolEntry` exists | Schema mostly exists; needs batch/entry metadata (message, signature) — migration 0008 |
| One subaddress per order, never reused | Domain + Stage 4 orders already pin seller terms/key at creation; allocation adds a row-locked take-oldest-unused step | Build in `app::orders` creation path |
| Seller marks Paid | `EvidenceClaim::SellerAttestation { amount_atomic: Option<u64> }` already exists; the state machine already accepts Core→Paid on evidence and forbids the Seller actor directly | Fits with **no state-machine change**: the seller's button submits an attestation claim (`amount_atomic: None` — the handoff forbids recording amounts); Core performs the transition |
| Amount display, QR, `monero:` URI | Stage 6 CORE (gated): `Atomic` formatting, QR/URI builder, `xmr-only` pricing | Reuse as-is |
| Address validation (primary = standard, entries = subaddresses, network match) | `modules-api` `Subaddress` newtype (parse → network → kind → torsion-free), Stage 6 destination typing | Reuse as-is |
| Low-pool alert, order notifications | Stage 4 inbox/notifications | Reuse |
| Pool-drain defences | Stage 4 has the <24h-account 3-order cap; add per-buyer 10/hour creation rate + max 3 open unpaid | Small addition at order creation |
| marketplace_id | App config already carries `marketplace_id` (env `MARKETPLACE_ID`) | Needs its real, permanent value from the owner before any batch is signed |
| Helper tool | Nothing exists | New crate + binary `seller-helper`; wallet RPC allowlist per handoff; pinned wallet 0.18.4.3 (the Stage 0 fixture version); `sign`/`verify` parameter shapes confirmed against that version before coding |

## Conflicts with spec v2, and dispositions

1. **Signature scheme (the big one).** Spec v2 §10 + the gated Stage 6
   CORE use **OpenPGP-signed** canonical invoice/pool statements. The
   handoff uses **Monero wallet signatures** per subaddress instead.
   Disposition: follow the handoff for payments — buyers verify inside
   their wallet, no GnuPG step at purchase time. PGP statements remain
   live for key rotation (Stage 3) and terms files (Stage 4). The
   Stage 6 invoice/pool statement parsers stay in the tree but leave
   the payment path; record in SPEC-V2-AMENDMENTS.
2. **Stage 8 shrinks.** tx-proof evidence is explicitly out of v1, and
   seller-attestation folds into this release. The old hard gate ("no
   *verified* label until tx-proof is proven") becomes moot — the UI
   must say "seller confirmed payment", never "verified". tx-proof
   module: deferred indefinitely, not scheduled.
3. **Assignment timing.** Handoff assigns at order **creation**; the
   v2 flow assigned at invoice issuance after seller accept, and Stage 4
   currently refuses accept-without-invoice. Under this design the
   payment page exists from creation; the accept gate goes away for
   the direct strategy. Follows the handoff.
4. **Address-change = identity reset.** The handoff asks for visible
   history reset + banner + retiring unused pool entries on a primary
   address change. Disposition with one softening, flagged for the
   owner: reuse the §8 continuity pattern (banner + "payment identity
   changed" marker for the configured 30 days, pool retired) but do
   **not** erase order/review history — counterparties' records and
   dispute evidence depend on it, and erasing history is exactly what a
   hijacked account would want. The reset applies to the payment
   identity's *presentation*, not to records.
5. **Unpaid-order expiry (48h)** has no domain state yet. Map expiry to
   a sweep that cancels unpaid orders past the deadline (subaddress
   stays retired either way). Lands with this release in minimal form;
   the general scheduler remains Stage 10.
6. **Escrow / encrypted-orders design stays dead.** Nothing in this
   plan revives it. The earlier "admin-selectable payment strategies"
   idea is superseded: one strategy, compiled in, per Q9.

## Build order (each step gated before the next)

1. Config/settings (handoff table; stagenet values) + seller primary
   address in the dashboard + change/reset flow.
2. Batch upload (all-or-nothing transaction, canonical message rebuild
   check, global duplicate rejection) + pool storage (migration 0008).
3. Allocation at order creation (row-locked, concurrency-tested) +
   pool-empty listing behaviour + drain defences.
4. Buyer payment page (amount, subaddress, primary + since-date,
   message + signature copy boxes, verification steps, disclosure;
   QR/URI from Stage 6 core).
5. Seller mark-paid (attestation claim) + 48h expiry sweep.
6. `seller-helper` crate (init/generate/check) + seller docs.
7. §22 gate: blind suite for the new surface, then stagenet acceptance
   with real wallets per the handoff's table (fixture wallet seed from
   Stage 0; versions and commands reported). Items that cannot run on
   real wallets get marked environment-deferred, never faked.

## Owner inputs needed

- **marketplace_id**: a short, stable string of his choosing. It is
  baked into every signed message; changing it later strands existing
  batches. (Dev default of zeros must not ship.)
- Confirmation of disposition 4 (history presentation reset, not
  erasure) — or his alternative.
- Everything else follows the handoff's suggested stagenet starts.
