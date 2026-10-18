# Stage 2 — Pre-flight brief (catalogue, listings, markup renderer, media worker)

Prepared 2026-10-13 from spec v2 §5, §7, §9, §16–§18, §22–§24, the Stage 0
schema (`marketplace/migrations/0001_initial.sql`), the Stage 1 `app` crate,
and `marketplace/docs/unverified.md`. This is groundwork for the implementing
session, not a spec change: nothing here relaxes a locked test or invariant.

## Scope (spec §24, stage 2 — verbatim)

Catalogue, listings, listing markup renderer, media worker.

## What already exists to build on

- Schema (`0001_initial.sql`): `listings` (public_id, seller_id, title,
  description, price_atomic BIGINT > 0, pricing_module, destination_module,
  auto_invoice, status draft|published|paused|removed) and `listing_media`
  (sanitized_ref, width, height — "media-worker output only").
- Stage 1 `authz::ROUTES` already declares `GET /sell` for Seller/Admin only;
  `/admin` and `/moderate` are declared but not yet routed.
- Accounts carry `role` (buyer|seller|moderator|admin, default buyer).

## Gaps and decisions the implementer must not silently invent

1. **No category storage.** The catalogue page must offer categories and
   filters (Required pages, § "Catalogue"), but `listings` has no category
   column and there is no categories table — the only `category` column in
   the schema is on `reports`. Stage 2 needs a new migration (0003) and a
   decision: single category per listing vs. a join table, and whether the
   category set is the operator's declarative list (§ "Declarative
   extensions": operators may add categories, no code) rather than free text.
2. **Route naming mismatch.** Spec §17 lists `GET /listings`,
   `GET /listings/{id}`, `GET /seller`, `POST /seller/listings`. Stage 1's
   route table uses `/sell`. Reconcile to the spec names in the route table
   before pages land, so the crawler/role-matrix tests (§23) test real paths.
3. **How does an account become a seller?** Default seller admission is
   `admin-approval` (§5/§7), but there is no admin surface yet and admin TOTP
   is an explicitly open Stage 1 gap. Stage 2 needs an explicit, minimal
   promotion path (and it must rotate the session on privilege change, §7) —
   or seller creation stays a dev-profile seed and "seller onboarding" is
   recorded in `unverified.md` as not yet shipped. Do not quietly make
   registration self-serve-seller; that contradicts the default module.
4. **Listing page wants a fingerprint that does not exist until Stage 3.**
   The Listing required page shows seller pseudonym *and fingerprint*, but
   identity keys are Stage 3. Stage 2 listing pages should ship without the
   fingerprint element (or with the seller-profile key section absent), and
   add it in Stage 3 — never render a placeholder fingerprint.
5. **Module selection precedes the modules.** A listing selects one enabled
   destination module and one pricing module (§9), but `xmr-only` pricing
   lands in Stage 6 and the destination modules in Stages 6–7. For Stage 2:
   store the module ids as the schema's TEXT fields, validate them against
   the enabled set in configuration, and enforce the one hard rule already
   in force — `auto_invoice` is allowed only with the address-pool module.
   No destination or price computation belongs in Stage 2.
6. **Search mechanism is unspecified.** Catalogue requires search (§ Required
   pages) and no search infrastructure exists in the schema. Pick the
   smallest thing that works at MVP scale (e.g. `ILIKE` on title/description
   or `pg_trgm`) and note the choice; do not add an external search service
   (no outbound network, §19 profiles).
7. **Upload body limit cannot wait for Stage 4.** Stage 1's report defers
   generalized per-route body limits to Stage 4, but the media upload route
   needs its own 5 MiB limit at Stage 2, enforced before parsing (§7 request
  limits; §18 image caps).

## Build checklist

### Catalogue & listings
- [ ] `GET /listings`: published listings only; search, category filter,
      pagination; counts server-side. Draft/paused/removed never leak into
      catalogue, search results, or counts.
- [ ] `GET /listings/{id}`: description rendered by the markup renderer,
      sanitized images only, seller pseudonym, price formatted from
      `price_atomic` with integer arithmetic (§9 Money: u64 atomic, decimal
      input parsed as string, max 12 decimal places, no floats anywhere).
      Order form itself is Stage 4 — do not stub a fake checkout.
- [ ] `POST /seller/listings` (Seller/Admin via the single `authorize()`
      table, CSRF on): create/edit own listings only; object-level check —
      a seller cannot edit another seller's listing (§17).
- [ ] Listing edits never touch existing orders' terms (§9 immutable terms —
      no orders exist yet, but do not build an edit path that could).

### Markup renderer
- [ ] Emits only `p`, `ul`, `li`, `strong` (§18). URLs render as plain text,
      never links. No raw HTML, seller CSS, scripts, external images, or
      tracking pixels (§9).
- [ ] Askama auto-escaping stays on everywhere; no user/module HTML, CSS, or
      URLs in attributes (§18).
- [ ] `cargo-fuzz` target for the listing markup renderer (§22.5), bounded
      CI run.

### Media worker
- [ ] Separate process: no network, read-only filesystem, seccomp filtering,
      memory and time limits (§18). The app stores only the worker's
      sanitized output (`listing_media.sanitized_ref`).
- [ ] Accept JPEG/PNG only; reject SVG, HTML, everything else. Caps:
      ≤ 5 MiB, ≤ 4096×4096, ≤ 24 megapixels decoded.
- [ ] Decode and re-encode; strip all metadata; store only sanitized output.
- [ ] Upload page carries the §18 warning verbatim in substance: photo
      backgrounds and reflections can identify a seller.
- [ ] `cargo-fuzz` target for the image worker (§22.5).

## Acceptance evidence for the stage gate (§22.4, §23)
- [ ] All Stage 0 + Stage 1 tests still green (workspace was 18/18 at the
      Stage 1 gate).
- [ ] Crawler pass (§23 Browser): every route as every role — no scripts,
      no event-handler attributes, no third-party URLs; seller content
      cannot inject markup, styles, or URLs.
- [ ] Route-by-role matrix (§23 Keys and accounts): cross-account listing
      access/edit denied for every non-owner role.
- [ ] Upload tests (§23 Retention and uploads): malformed and oversized
      uploads rejected; sanitized images carry no metadata.
- [ ] Monetary arithmetic stays exact in atomic units (§23) — price parse /
      format round-trip tests at the 12-decimal boundary.
- [ ] `docs/unverified.md` updated: anything Stage 2 claims but does not test
      (e.g. seccomp profile actually applied, seller onboarding if deferred
      per gap 3) is listed before the gate closes.

## Explicitly NOT Stage 2
Identity keys/fingerprints (3), orders/terms/state machine/inbox (4),
messaging (5), pricing and destination modules (6–7), moderation queue and
reports UI (9 — the `reports` table existing is not a Stage 2 surface).
