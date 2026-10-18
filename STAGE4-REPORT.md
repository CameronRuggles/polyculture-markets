# Stage 4 — Completion Report (orders, terms, inbox)

Date: 2026-10-13 · Spec §24 Stage 4 (§9, §10 terms files, §15 inbox)

Process note: per Cameron's call, stages run in a hybrid gate mode —
the Stages 1–3 Opus review pack is written (`REVIEW-PACK-STAGES-1-3.md`),
blind-suite backfill is owed before Stage 8, and full §22 discipline
applies from Stage 5.

## What exists

- **Order creation** (`app::orders::create_order`): published-listing
  only, no self-orders, quantity bounds, total = unit × quantity in
  checked u64. The seller's current key fingerprint is **pinned** into
  the order; a seller without a key cannot be ordered from.
- **Terms files (§10):** built once at creation — canonical header
  (`marketplace-terms-v1`, pinned 128-bit IDs, quantity, total-atomic,
  pricing module, canonical timestamp), blank line, then Title /
  Description / Delivery terms / Refund terms sections, NFC-normalized
  with LF endings. The exact bytes and their SHA-256 are stored and
  **never regenerated**; participants can download the file and verify
  the digest themselves. Listings gained `delivery_terms` /
  `refund_terms` columns (migration 0005).
- **Idempotency:** `(buyer_id, idempotency_key)` unique; a resubmitted
  form returns the original order (proven live: two submissions, one
  order, same redirect).
- **New-account limit (§7):** accounts under 24 h old may hold at most
  3 orders.
- **Transitions:** every action (accept / decline / cancel / fulfil /
  complete / dispute) is checked against the domain transition table
  with the actor derived from the caller's relation to the order;
  `orders.state` is written only here. Accept additionally requires an
  issued invoice (§9 ordering) — until the payment stages, it is refused
  with an explanation. Dispute from AwaitingPayment enforces the
  72-hour buyer-report guard.
- **Order pages:** participant-only (everyone else gets 404), permitted
  actions rendered per state and role, evidence level shown with the
  plain labels ("Buyer reports payment (not verified)" etc.), the
  direct-payment/no-escrow warning, pinned seller fingerprint, terms
  digest + download.
- **Inbox (§15):** `notifications` on every order event (requested,
  declined, cancelled, fulfilled, completed, dispute) to the
  counterparty; inbox page with unread markers and mark-all-read;
  `unread_count` helper for the site header.

## Evidence

- Unit: terms builder is byte-exact and deterministic (CRLF input
  normalizes to the same bytes); workspace total 26/26 + integration.
- Live: order placed (2 × 0.35 XMR = 700,000,000,000 atomic), duplicate
  submission returned the same order, downloaded terms SHA-256 matched
  the stored digest, accept without invoice refused with the reason,
  decline landed and the buyer's inbox showed `order_declined`.

## Incident during this stage

A VM replacement wiped system packages and the dev database mid-stage.
Recovered by reprovisioning from scratch; `deploy/dev-setup.sh` now
rebuilds the whole dev environment in one command, migrations included.
No project files were lost (they live under the home directory).

## Honest gaps

- The site-wide layout with header attention counts (§15) is not yet
  unified across pages — pages are still standalone templates; the
  counts function exists. Layout unification is cosmetic debt, noted.
- Auto-completion 14 days after fulfilment is a retention/scheduler
  item (Stage 10); dispute handling beyond opening is Stage 9.
- Orders cannot progress past Requested until invoices exist
  (Stages 6–7) — by design (§9's accept rule).
