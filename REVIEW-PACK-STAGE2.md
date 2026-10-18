# Review Pack — Marketplace Spec v2, Stage 2 (listings, markup, media, seller admission)

**How to use:** paste whole into Claude Opus. This is the §22 stage-gate
review for Stage 2, produced in the 2026-10-13/14 retrofit (the stage was
first built as a working draft; this pack accompanies its gate).
Cameron (owner) makes final calls; your job is verdicts with file:line
evidence.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL, with
   the file and line you relied on. Abstract concern without a mechanism
   doesn't count; name who does what to whom.
2. The code is at `marketplace/crates/domain/src/` (`markup.rs`, money),
   `marketplace/crates/media-worker/`, and
   `marketplace/crates/app/src/` (`listings.rs`, `media.rs`, `web.rs`).
   The spec is "Privacy-First Noncustodial Marketplace — Spec v2" plus
   `SPEC-V2-AMENDMENTS.md` and the canonical contract
   `marketplace/docs/api-contract.md` (§8 is the Stage 2 surface). If
   you cannot see the files, say so and review against the claims and
   evidence summarized here instead — flag that limitation.
3. End with: (a) any test the locked suite must add for Stage 2, stated
   as plain-language assertions; (b) anything that must be fixed before
   Stage 6/7 (pools, invoices) builds on this code.

## What was built (claims to check)

Markup renderer (`domain::markup`): escapes ALL input first; the only
markup is paragraphs, `- ` bullet lists, and `**bold**`; the only tags
it can emit are `p`, `ul`, `li`, `strong`. URLs stay plain text;
unmatched `**` stays literal. Money (`domain::Atomic`): exact decimal
XMR ↔ atomic units, >12 decimal places rejected, canonical formatting,
u64 range-checked. Listing validation now follows contract §8 exactly:
`validate_listing(title, description, price_atomic: u64, category,
destination_module, auto_invoice) -> Result<(), ListingError>` with
variants `Title, Description, Price, Category, DestinationModule,
AutoInvoiceNeedsPool` (the draft took the price as a decimal string,
returned the parsed amount, and named the module variant `Module` —
all three deviations were corrected to the contract in the retrofit;
the web handler parses the form's decimal via `Atomic::parse_decimal`,
mapping unparseable input to the `Price` error). Title: non-empty, ≤120
chars, no angle brackets/newlines. Description: non-empty, ≤20 000 chars
(the bound is the implementation's; no text states one — see the
deferred item in the report). Category from the fixed operator set;
destination module one of `signed-address-pool` / `signed-invoice`;
auto-invoice only with the pool module. Catalogue `browse` returns
published listings only; unpublished/removed listings are
indistinguishable from nonexistent for non-owners. Media pipeline: the
app hands bytes to a separate worker process (cleared environment,
10 s timeout, no caller-chosen paths); only JPEG/PNG by content
sniffing; >5 MiB, any side >4096 px, or >24 MP rejected — dimension
limits enforced from the header before full decode; output is
re-encoded from decoded pixels so metadata (EXIF, PNG text chunks) is
stripped; the original upload is never stored or served. Seller
admission (default `admin-approval` module): `apply_for_seller` records
a pending application and re-applying while pending is idempotent (the
draft inserted duplicate pending rows — fixed in the retrofit, the
duplicates also broke the decision update). `decide_seller_application`
now takes the deciding actor's id and enforces the contract §8
invariant in the function itself, not only at the route layer: a
non-moderator/admin decider — including the applicant — fails with
`AdmissionError::Unauthorized` and changes nothing; a privileged
decision records the outcome and flips `accounts.role` to seller in
the same transaction (no partial grants). The recorded outcome string
for an approval is `approved`.

## Invariants to judge

1. Seller input cannot produce HTML, attributes, links, or images the
   renderer did not generate (escape-first; generated tags only).
2. The media worker cannot be reached with attacker-chosen paths, its
   dimension limits are enforced before full decode, and no failure
   mode serves or stores the original bytes.
3. Money never passes through floating point; parsing is exact and
   rejects >12 dp, negatives, and overflow.
4. Admission decisions are atomic: decision record + role flip in one
   transaction; no path grants seller without a privileged decider.
5. Unpublished listings leak nothing to non-owners (no oracle via
   browse, direct fetch, or error differences).
6. Listing validation cannot be bypassed by the web layer (the handler
   parses the price decimal exactly once; validation errors map to the
   contract variants).

## Evidence already in hand (retrofit, 2026-10-14)

- Locked blind suite `marketplace/tests/security/blind_stage2.rs`
  (author saw only the spec, amendments, and API contract): **37 pass,
  0 fail, 1 ignored** — the ignored test is the author's own, skipped
  by them because no text states a description size bound (recorded as
  an ambiguity for the owner, not silently dropped). Coverage: markup
  12, money 6, listing validation 9, media pipeline 7 (including a
  metadata-marker PNG whose tEXt chunk must not survive, header-crafted
  oversize dimensions rejected pre-decode, 5 MiB+1 rejected, GIF
  rejected), seller admission + catalogue DB tests 4.
- The suite initially failed 5 tests; all fixed in code or harness,
  none in assertions: contract alignment of `validate_listing`
  (signature + variant name), privileged-decider enforcement in
  `decide_seller_application`, apply idempotency, recorded outcome
  string, and the media tests' worker path (the run harness must set
  `MEDIA_WORKER` to the built binary — an environment gap, not a code
  defect; with it set, both media acceptance tests pass).
- Full workspace test suite green (see RETROFIT-REPORT.md for counts).
- Crypto backend guard PASS (Q8, Nettle everywhere).

---

**Rider closure (2026-10-14, during the Stage 4 gate):** the owner
ratified the listing-description bound at **20,000 characters** (pinned
in SPEC-V2-AMENDMENTS.md, §9). The blind suite's oversize test
(1,000,000 characters, previously `#[ignore]`d as DERIVATION-UNCERTAIN)
was activated unchanged — only the `#[ignore]` attribute was removed,
per the author's designed activation path — and the Stage 2 blind
suite re-ran green: **38 passed, 0 failed, 0 ignored** (media tests
under the MEDIA_WORKER/MEDIA_DIR harness, per the retrofit's §4.8
note). No Stage 2 item remains open.
