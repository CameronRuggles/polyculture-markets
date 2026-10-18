# Stage 2 — Completion Report (catalogue, listings, markup, media worker)

Date: 2026-10-13 · Spec §24 Stage 2 (§9 listings, §15 catalogue, §18 images)

## What exists

- **Markup renderer** (`domain::markup`): paragraphs, bullet lists, `**bold**`
  only. Everything is HTML-escaped before markup is applied, so no seller
  input can become a tag, attribute, or link; URLs stay plain text (§9).
- **Media worker** (`crates/media-worker`, separate binary): decodes by
  content (JPEG/PNG only), rejects >5 MiB, >4096 px any side, >24 MP —
  dimensions rejected from the header before full decode; re-encodes from
  pixels, stripping all metadata. The app invokes it with a cleared
  environment and a 10 s timeout; only worker output is stored/served.
- **Listings:** create (draft) / publish / pause / remove; validation for
  title (no angle brackets), description size, price (exact decimal → atomic,
  > 0), category (fixed set + migration 0003), destination module
  (`signed-address-pool` | `signed-invoice`), and §9's rule that auto-invoice
  requires the pool module. Pricing pinned to `xmr-only` until Stage 6.
- **Catalogue:** public browse with search (title/description), category
  filter, newest-first pagination (20/page). Listing page renders sanitized
  images + rendered markup; unpublished listings 404 for everyone but their
  seller (object-level check).
- **Seller admission (default `admin-approval` module):** apply →
  `admission_records` pending → moderator/admin queue at
  `/moderation/sellers` → approve flips role to seller in one transaction;
  re-applying while pending is idempotent.
- **Routes/authorize:** Stage 2 routes added to the single route table;
  parameterized routes enforce role + ownership in-handler (the §17
  resource-form `authorize()` generalization remains future work).

## §7 deviations from Stage 1 found and fixed during this stage

- Session idle/absolute lifetimes were 24 h / 14 d; §7 specifies **12 h / 7 d**
  — constants corrected, lifecycle test now derives from the constants.
- Cookies were `SameSite=Lax`; §7 specifies **Strict** — corrected.
- Passphrases now also checked against a bundled common-passphrase list
  (starter slice in code; the full list is a deployment data file) at
  registration and recovery.

## Evidence

- Unit: domain 7/7 (incl. markup paragraphs/lists/bold, script-injection and
  unmatched-marker cases), app 10/10, modules-api 4/4; Postgres integration
  1/1 — workspace 22/22.
- Media worker, direct: PNG carrying a `tEXt` "SECRET_METADATA" chunk →
  sanitized output, metadata gone; 5000×5000 header → rejected pre-decode;
  GIF → rejected.
- Live smoke: register → apply to sell → moderator approves → role = seller
  → create listing (pool + auto-invoice) → upload metadata-bearing PNG →
  publish → catalogue shows it → listing page renders `<strong>` and list
  items → the served image is the sanitized copy (no metadata).

## Honest gaps

- Worker sandboxing here is process separation + env clearing + timeout;
  seccomp / read-only-root wrapping is deployment work (Stage 10), as the
  spec's profile section intends.
- Seller profile page (§15) arrives with keys (Stage 3) and reputation
  (Stage 9); catalogue shows the seller pseudonym only for now.
- Categories are a fixed built-in set; operator-defined categories are a
  config question for Stage 10.
