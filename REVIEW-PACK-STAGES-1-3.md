# Review Pack — Marketplace Spec v2, Stages 1–3 (for Claude Opus)

**How to use:** paste whole into Claude Opus. This is the §22 stage-gate
review for the first three implementation stages, run as one pack because
the stages were built consecutively. Cameron (owner) makes final calls;
your job is verdicts with file:line evidence.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL, with
   the file and line you relied on. Abstract concern without a mechanism
   doesn't count; name who does what to whom.
2. The code is at `marketplace/` (Rust workspace: crates/modules-api,
   crates/domain, crates/app, crates/media-worker). The spec is "Privacy-
   First Noncustodial Marketplace — Spec v2" plus amendments in
   `SPEC-V2-AMENDMENTS.md`; decisions in `DECISIONS-LOG-2026-10-13.md`.
   If you cannot see the files, say so and review against the claims and
   evidence summarized here instead — flag that limitation.
3. End with: (a) any test the locked suite must add for stages 1–3,
   stated as plain-language assertions; (b) anything that must be fixed
   before Stage 8 (payment evidence) builds on this code.

## What was built (claims to check)

**Stage 1 — accounts/sessions/auth (`crates/app/src/{passwords,usernames,sessions,recovery,authz,throttle,admission,db,web}.rs`)**
Argon2id (64 MiB, t3, p1) behind a global semaphore; saturation → 503
before hashing. Usernames case-folded, unique. Session tokens 256-bit,
only SHA-256 stored; idle 12 h / absolute 7 d (§7 values, corrected in
Stage 2); rotation on login; `__Host-` cookie name in the HTTPS profile,
SameSite=Strict. Per-session CSRF secret for authenticated POSTs,
double-submit cookie for public POSTs. Recovery codes: single-use,
hashed; consumption revokes all sessions + marks profile, in one
transaction; unknown user and bad code return identical errors.
`authorize()` over one route table, default-deny. Per-account token
bucket; per-username exponential login delay, never lockout. Default
admission = open registration behind flag + global cap, via the
modules-api trait.

**Stage 2 — catalogue/listings/media (`domain/src/markup.rs`,
`crates/media-worker/`, `app/src/{listings,media,web}.rs`)**
Markup subset: paragraphs, `- ` bullets, `**bold**`; everything escaped
before markup is applied; URLs never become links. Media worker is a
separate binary: content-sniffed JPEG/PNG only, ≤5 MiB, ≤4096 px/side,
≤24 MP (header pre-check), re-encode strips metadata; app invokes it
env-cleared with a 10 s timeout. Listings validate title/description/
price (exact decimal → atomic u64, > 0)/category/module; auto-invoice
only with `signed-address-pool`. Unpublished listings 404 for non-owners.
Seller admission default `admin-approval`: apply → pending record →
moderator decision flips role in one transaction.

**Stage 3 — identity keys (`app/src/keys.rs`)**
Cert validation via Sequoia (Nettle): standard policy, encryption subkey
+ signing key required; user IDs surfaced with real-name/email warnings.
Rotation: strict parse of `marketplace-key-rotation-v1` (field order,
Q15 ID patterns, canonical timestamp); certified path verifies detached
signatures from BOTH certs over the exact bytes and binds account +
old/new fingerprints + this instance's marketplace-id; uncertified path
explicit, recorded, drives a 90-day profile warning. Profiles show key
history, recovered marker (30 d), and serve `key.asc`.

## Invariants to judge

1. No code path lets a buyer's report (or any non-core actor) move an
   order to Paid. (Domain table, `crates/domain/src/lib.rs`.)
2. Session tokens, recovery codes, and passwords are never stored or
   logged in recoverable form.
3. Every state-changing route requires the session CSRF secret; public
   POSTs require the double-submit cookie; GET never changes state.
4. Unpublished/removed listings and other accounts' objects are
   indistinguishable from nonexistent ones (404, no oracle).
5. Seller input cannot produce HTML, attributes, links, or images the
   renderer/worker did not generate.
6. The media worker cannot be reached with attacker-chosen paths, and
   its failure modes never serve the original upload.
7. A rotation cannot be certified without control of both keys, and an
   uncertified rotation cannot be presented as certified anywhere.
8. Admission decisions (buyer registration, seller approval) are made
   by modules/core in one transaction — no partial role grants.
9. Envelope/oracle hygiene from the decision log (Q16 family): do any
   Stage 1–3 endpoints distinguish "exists but not yours" from "does
   not exist" for accounts, keys, listings, or sessions?
10. Anything in the Q1–Q17 decisions that the code contradicts.

## Evidence already in hand

Workspace tests: modules-api 4, domain 7, app 13, media-worker
(functional CLI checks), Postgres integration 1 — all green. Live
smokes: register→login→account; listing create→image sanitize→publish→
catalogue; key upload→dual-signed rotation→profile/`key.asc`. Stage
reports: `STAGE1-REPORT.md`, `STAGE2-REPORT.md`, `STAGE3-REPORT.md`
(they list known gaps: TOTP before any admin surface, seccomp wrapping
at deployment, statement library generalization at Stage 6).
