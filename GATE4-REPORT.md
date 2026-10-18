# Stage 4 Gate Report — orders, terms files, inbox (spec §§9, 10, 15, 17)

Date: 2026-10-14. Procedure: spec §22 stage gate, mirroring the
stages 1–3 retrofit (RETROFIT-REPORT.md). Stage 4 was built as a working
draft (STAGE4-REPORT.md) and is gated here before any Stage 5 work
starts, per the owner's gate-as-we-go ruling of 2026-10-13.

## Verdict: PASS

Stage 4 passes its §22 gate. A fresh blind suite, authored from the
spec + amendments + API contract only, passes in full (58 passed,
0 failed, 6 author-ignored as DERIVATION-UNCERTAIN). Four failures on
first run were all fixed in code; no blind assertion was edited. The
full workspace is green at **200 tests passed, 0 failed, 6 ignored**.
Two owner rulings landed during the gate (GET /orders amendment;
20,000-character description bound) and are recorded in §6 with their
timing. cargo-mutants evidence is in §5; the review pack is
REVIEW-PACK-STAGE4.md (the human/Opus review step itself remains the
owner's to run, as with stages 1–3).

## 1. Spec and contract currency (gate step 1)

Before the blind author was dispatched, the Stage 4-relevant rulings
were folded in and listed here:

- **Contract §11 added** (`marketplace/docs/api-contract.md`): the
  Stage 4 surface — `Order`/`OrderError`, `create_order`,
  `order_by_public_id`, `orders_for`, `terms_bytes`, `apply_action`,
  `build_terms`, and the inbox functions — with the §9/§10/§15
  semantics stated (checked totals, fingerprint pinning, idempotency,
  terms built once and never regenerated, the two app-layer guards
  above the pure table, notification content limits). The contract
  previously carried the state machines (§10) but no Stage 4 surface.
- **Contract §10 sketch corrected**: its `Actor` enum read
  `{ Buyer, Seller, System }` (a Stage 0 sketch); spec §9 and the
  domain crate distinguish **Core** and **Moderator**, so the sketch
  now reads `{ Buyer, Seller, Core, Moderator }`. (This correction
  mattered during integration — see §3, fix C2.)
- **Amendment — §17 `GET /orders`** (owner ruling, §6.1) and
  **amendment — description bound 20,000 chars** (owner ruling, §6.2),
  both appended to SPEC-V2-AMENDMENTS.md before dispatch.
- Q16's key-history requirement was already satisfied by the retrofit
  (migration 0006); nothing Stage 4 needed was missing from Stage 3's
  gated surface.

## 2. The blind suite

`marketplace/tests/security/blind_stage4.rs` — 64 tests, written by a
blind author in a separate session given ONLY the spec,
SPEC-V2-AMENDMENTS.md, and the API contract (post-amendment versions),
plus the Stage 4 scope statement. The author was expressly forbidden
the implementation, STAGE4-REPORT.md, and the other locked suites.

Coverage: the full domain transition table by actor × evidence
(including terminal-state exhaustiveness and non-table jumps); the
invoice table; app-layer actions by participant/stranger; accept's
InvoiceRequired; creation rules (published-only, self-order, seller
without key, quantity bounds, checked-total overflow); idempotency
(same key / different key / different buyer); fingerprint pinning
across key rotation; the §7 new-account limit; terms-file format,
normalization (CRLF, NFC), digest verification, and byte stability
across listing edits; `authorize()` for every order route in §17 as
amended (including `GET /orders`); object-level listing of orders;
inbox event/recipient/read semantics; ID and settlement pinning.

Result history: first full run **54 passed, 4 failed, 6 ignored**
(an earlier partial run's mass failures were an environment artefact
— PostgreSQL had died in a service restart; after re-provisioning
with `deploy/dev-setup.sh` the true failure set was four). After the
code fixes in §3: **58 passed, 0 failed, 6 ignored**. The 6 ignored
are the author's DERIVATION-UNCERTAIN marks (§7).

## 3. Code fixes (failures fixed in code, never in tests)

Four failures, four code fixes:

1. **Domain table dropped §9's dispute guard** (crates/domain).
   `order_can_transition(AwaitingPayment, Disputed)` accepted the
   buyer at ANY evidence level — the row ignored the `evidence`
   parameter that the Paid and Cancelled rows both use. Spec §9's
   guard for this transition is "buyer reported payment 72 hours ago
   with no seller response": the table now requires
   `actor == Buyer && evidence == BuyerReported` (the report's
   existence); the 72-hour timing stays at the app layer, which owns
   claim timestamps (orders.rs already enforced it there). Blind
   failure: `a_awaiting_payment_to_disputed_is_buyer_with_a_report_on_record`.
2. **`authorize()` denied the declared `GET /orders` route**
   (crates/app authz.rs). Route row added with the any-authenticated
   class per the §17 amendment (§6.1); the module-header deviation
   note was updated to record the resolution, and authz's own unit
   assertions for the route were updated from Deny to the amended
   behaviour (Allow for signed-in roles, LoginRequired anonymous).
   Blind failures: `h_get_orders_collection_is_a_declared_route`,
   `h_order_routes_anonymous_login_required_every_role_allowed`.
3. **Order `created_at` was not canonical** (crates/app orders.rs).
   `ORDER_COLS` rendered `to_char(created_at, 'YYYY-MM-DD HH24:MI')`
   (space separator, no seconds, no zone); it now renders the
   canonical RFC 3339 UTC form
   (`... AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'`) that the
   contract prints for the field. Blind failure:
   `k_created_orders_carry_ord_prefixed_ids_direct_settlement_requested_state`.

## 4. Construction fixes (locked-suite integration; assertions unchanged)

The blind file needed six construction adaptations to compile and run
against the real interfaces; each is marked in place with a
`CONSTRUCTION FIX (Stage 4 gate)` comment; no assertion text, expected
value, or test logic was altered:

- **C1. Imports re-pointed.** `authorize`, `route_requires_csrf`,
  `Decision`, `Role` were imported from the domain crate; they live in
  `app::authz`. `unread_count` was added to the `app::orders` import
  list (contract §11 names it in that module).
- **C2. `Actor::System` → the real enum.** The author worked from the
  contract §10 sketch's `System` variant (see §1 — the sketch was
  corrected under the implementer's step-1 duty, since the spec names
  Core and Moderator distinctly). All cells map to `Actor::Core`
  except the Disputed→Resolved positive assertion, which maps to
  `Actor::Moderator` — spec §9 names the Moderator for that
  transition, and mapping it to Core would have made the suite assert
  something the spec does not say. The author's asserted expectations
  are unchanged in every cell.
- **C3. Inbox-counts closure.** The author's `async move` closure
  moved the connection pool on first use; replaced by an equivalent
  `inbox_counts` helper function (same values, same call order).
- **C4. One `async` removed.** The DERIVATION-UNCERTAIN terms-label
  test is a plain `#[test]` whose body is a single `todo!()`; the
  stray `async` keyword was removed. The test remains ignored, as the
  author designed.
- **C5. Package scaffolding.** `[[test]] name = "blind_stage4"` added
  to tests/security/Cargo.toml (implementer-owned, as for stages 1–3).
- **C6. Stage 1 matrix updated under the owner amendment** — listed
  separately in §6.1 because it touches an earlier locked suite.

## 5. cargo-mutants

Two runs, scoped to the Stage 4 paths, outputs preserved under
`mutants-runs/stage4-domain/` and `mutants-runs/stage4-app/`. Because
the killing layer for this stage is the locked blind suite (a separate
package the mutants runner does not exercise), every mutant the unit
layer missed was additionally **hand-mutated in the real tree and run
against the full blind_stage4 suite**, following the retrofit's method
for the keys.rs DB family; both mutated files were restored and
verified byte-identical (md5) after each pass.

**Domain transition tables** (`crates/domain/src/lib.rs`,
`order_can_transition` + `invoice_can_transition`, 29 mutants):
9 caught by the domain crate's unit tests, 20 missed by the unit
layer — and **all 20 hand-verified KILLED by the blind suite** (each
arm deletion and operator flip fails 1–3 blind tests; log per mutant
in the preserved results file `handverify-blind-layer.txt`).
Ledger: **29 examined, 29 killed across layers, 0 survivors,
0 unviable.**

**App order paths** (`crates/app/src/orders.rs`, logic/operator
mutants in `create_order` and `apply_action`, 36 mutants): the app
crate's unit tests exercise orders.rs only lightly — 0 caught,
36 missed at the unit layer. Hand-verification against the blind
suite: **29 killed, 7 survived**, triaged below. (Whole-function
replacement mutants and the terms/inbox getter mutants were excluded
from this run by scope; the excluded class was spot-verified:
replacing `build_terms`' body with an empty vector fails 4 blind
tests, as expected — the suite asserts exact terms bytes.)

Survivors, honestly triaged:

1. **Notification event-string arms (6 mutants, orders.rs:377–382).**
   Deleting any one arm of the action→event match makes that action's
   notification fall through to the default `"order_updated"` string.
   The notification is still sent, to the same counterparty, with the
   same object reference — only its event-type label changes. The
   blind suite pins recipients, counts, references, and read state
   (all their mutants died), but no assertion pins the per-action
   event strings, because §15 names the events in prose without
   printing literal strings — the author could not assert them
   without inventing them (the same spec silence as the terms
   section labels, §7 item 1). **Accepted survivor, low severity.**
   Recommendation to the owner: pin the event-type strings in §15 or
   contract §11 so a future suite can assert them.
2. **Dispute-guard negation (1 mutant, orders.rs:363, `delete !`).**
   Inverting `if !old_enough` in the 72-hour dispute guard survives
   because the domain table's evidence requirement (gate fix 1)
   refuses every dispute state the blind suite can construct: the
   discriminating state — evidence already BuyerReported with a
   report younger than 72 hours — is exactly the one the author
   marked unreachable through the printed surface (§7 item 2). The
   shipped code is correct; the mutant is masked by defence in
   depth, not equivalent. **Accepted survivor with a Stage 6/7
   follow-up:** when buyer-report claims land, the suite must gain
   the young-report dispute test (the author's ignored 72-hour test
   already covers the satisfied side).

## 6. Owner rulings during the gate (timing documented)

Both rulings are the owner's (Cameron, 2026-10-14), logged in
DECISIONS-LOG-2026-10-13.md under "Owner rulings during the Stage 4
gate". Both landed BEFORE the blind author was dispatched, so the
suite was authored against the amended spec from the start; neither
was a response to a failing test.

### 6.1 GET /orders — resolved by owner amendment

The Stage 4 draft web layer served `GET /orders` while §17 declared no
such route, and the retrofit had made `authorize()` deny it (the safe
status quo). The owner approved amending §17 rather than moving the
page. Amendment text (SPEC-V2-AMENDMENTS.md, "§17 routes (owner
ruling, 2026-10-14)"):

> `GET /orders` is a declared route: the orders collection page (the
> §15 global header's "Orders" entry). Login-required — any
> authenticated account; anonymous actors get `LoginRequired`. The
> handler performs object-level filtering: a caller sees only orders
> where they are the buyer or the seller. `authorize()` gains this
> route with the any-authenticated class, alongside the
> already-declared `POST /orders`, `GET /orders/{id}`,
> `GET /orders/{id}/terms.txt`, and the order-action POSTs.

Consequences, all recorded: the blind Stage 4 suite asserts the
amended behaviour (declared-route tests in its §H); `authorize()`
gained the route (§3 fix 2); and the locked Stage 1 suite contained
one superseded cell — `("GET", "/orders")` in its undeclared-paths
list, correct when authored — which was updated under this ruling:
the row was removed from the undeclared list, a
`("GET", "/orders", Class::Authenticated)` row was added to its
declared-route matrix, and both edits plus the header prose carry an
"OWNER AMENDMENT 2026-10-14" comment in the file. This is the only
post-lock change to a Stage 1 assertion, it follows the owner's
ruling rather than a test failure (the suite passed as locked until
the route was amended), and the Stage 4 suite positively asserts the
new behaviour. Status: **deviation closed — resolved by owner
amendment.**

### 6.2 Description size bound — rider closed

The Stage 2 rider (implementation used 20,000 characters; the spec
said only "within the size bound"; the blind oversize test stayed
ignored) is closed: the owner ratified **20,000 characters**, pinned
in SPEC-V2-AMENDMENTS.md (§9 orders section). The Stage 2 blind test
`listing_oversized_description_fails` (1,000,000 characters) was
activated by removing only its `#[ignore]` attribute — the author's
designed activation path; its body is untouched. Stage 2 blind suite
re-run: **38 passed, 0 failed, 0 ignored** (media tests under the
MEDIA_WORKER/MEDIA_DIR harness, per RETROFIT-REPORT §4.8). The
closure is also noted in REVIEW-PACK-STAGE2.md.

## 7. Deviations, ambiguities, and owner-decision items

1. **Terms "selected options" section (owner decision).** Spec §10
   lists five terms sections (title, selected options, description,
   delivery terms, refund terms); the built terms file has four —
   v2 listings carry no selectable options, so there is nothing to
   snapshot. The blind author flagged the tension and left the exact
   labels unpinned rather than inventing them. Owner call: amend §10
   for option-less listings, or require an explicit (possibly empty)
   selected-options section for byte-level spec fidelity.
2. **Six DERIVATION-UNCERTAIN items** (author-ignored, §2): exact
   24-hour boundary of the §7 limit; whether orders held as *seller*
   count toward a young account's limit; the 72-hour dispute guard's
   satisfied path (claim aging is not expressible through the printed
   surface — the refused path is tested, and the app enforces the
   timing in SQL); core/moderator actions through `apply_action`
   (the surface derives only buyer/seller; the pure table's core and
   moderator cells are tested directly); non-participant
   indistinguishability for order detail/terms (the printed surface
   takes no actor — enforcement is the web layer's, listed as review
   invariant 7 in the review pack); exact terms section-label bytes
   (item 1). Each is a place one more spec sentence would pin the
   behaviour; none blocks Stage 5.
3. **Inbox timestamp format (noted, not changed).** `inbox()` renders
   notification times with the same `YYYY-MM-DD HH24:MI` pattern the
   gate fixed for order `created_at`. §15 does not pin the format and
   the blind suite accepts it, so it is recorded here rather than
   silently changed; a one-line fix if the owner wants uniformity.
4. **Pre-existing draft gaps carried forward** (from STAGE4-REPORT,
   out of gate scope): site-wide header attention counts not yet
   unified with `unread_count`; auto-complete and dispute resolution
   belong to Stages 10 and 9 respectively; orders cannot progress past
   Requested until Stages 6–7 — by design.

## 8. Environment notes

- PostgreSQL died mid-gate in a service restart, producing a partial
  run of mass PoolTimedOut failures; re-provisioned with
  `marketplace/deploy/dev-setup.sh` and the run repeated — the true
  failure set was four tests (§2). Standing lesson (AGENTS.md)
  reconfirmed: assume apt/DB state may vanish at session start.
- cargo-mutants' scratch copy overflows the 512 MB /tmp tmpfs on the
  app package (full dependency tree); runs must set TMPDIR to a
  home-disk directory.
- Crypto backend guard: PASS (Q8 — Sequoia resolves to Nettle
  everywhere, no RustCrypto features).

## 9. What the gate did not do

No Stage 5 work was started. The marketplace is not deployed anywhere;
nothing in this gate ran against a public instance. The human review
step (REVIEW-PACK-STAGE4.md to the owner's reviewer) remains the
owner's, as with stages 1–3.
