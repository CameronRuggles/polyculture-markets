# BM/BL Fix Batch — Completion Report (2026-10-19)

Source brief: *Polyculture Markets — Modules, Statements, Fuzzing and
Routes Audit* (audit 6), final section, tasks 1–5 (BM1, BM2, BL1,
BL2, BL3). Executed test-first under gate discipline on HEAD
`30041e1`. Baseline (from MEDIA-VERIFICATION-FIX-REPORT-2026-10-19.md):
workspace **574 passed / 0 failed / 9 ignored**, seller-helper 18/18.

Commits (local only, NOT pushed):

| Commit | Task |
| --- | --- |
| `1128786` | BM1 — registration gets its own hashing pool |
| `5b2a79b` | BM2 — recovery hashes first, one consuming transaction |
| `a10ee06` | BL1 — publish guard + form cleanup (partial, see §3 conflicts) |
| `aa9634d` | BL3 — category Cf rejected in seller text |
| `31df838` | BL2 — fuzzing reaches real messages |
| `ecaa073` | Test fixes caught by the full gate (see §8) |
| _this commit_ | This report |

All new tests live in `marketplace/crates/app/tests/modules_audit_fixes.rs`
(9 tests). No locked file was edited: `marketplace/tests/security/**`,
`docs/invariants.md` and the spec are byte-identical pre/post (SHA-256
manifests, §6).

---

## 1. BM1 — registration can no longer starve logins of hashing slots

**Done, with both brief tests.**

- `passwords.rs`: the shared `HashPool` gained a bounded-wait
  acquire (250 ms re-checks). `verify_guarded` (login / step-up
  path) now waits **up to 5 s** for a slot before answering
  `PasswordError::Busy` — the brief's "a few seconds". `hash_new`
  keeps the old fail-fast behaviour.
- `passwords::register_hash` runs on a **separate one-slot
  `REGISTRATION_POOL`**. Registration traffic — any number of
  in-flight requests — can never touch the four slots logins,
  step-up, passphrase change and recovery depend on.
- `web::register` reordered: shape checks → account-cap check →
  **username-taken check** → **registration budget** (the audit's
  per-instance budget, by source address: 10 per source per hour
  in the global `LoginThrottle` map, new `register_source_*`
  methods) → **CSRF** → hashing last. A taken username or a spent
  budget is refused with **no hash spent** and no account created.
- CSRF ordering note: the handler keeps the long-standing
  double-submit CSRF check. It runs *after* the two new cheap
  refusal checks and *before* hashing. This is deliberate: the
  Oct-17 tools pass recorded the pre-checks-before-CSRF order as
  the accepted pattern, and no token is needed to learn that a
  username is taken or a budget is spent — neither is secret.

**Tests** (`registrations_in_flight_do_not_block_login`,
`taken_username_registration_refused_without_hashing`,
`registration_budget_refuses_before_hashing`, plus two
`passwords.rs` unit tests):

- Four registration requests are held genuinely in flight (>200 B
  passphrases: measured fixed cost ≈5.6 s on this host; the test
  waits until the shared pool's waiters interface proves the
  logins were queuing). A correct login then **succeeds** — it
  queued briefly and got a slot when one freed. Under the old
  code this login got an instant `Busy`/503.
- Re-registering a taken username is refused (302 to
  `/register?msg=username_unavailable`) while the shared pool is
  saturated; the refusal returns in under half the measured
  single-hash cost, and a login attempted at the same moment
  still has to queue — positive proof the refusal spent no hash.
- Third test: logins against an artificially saturated shared
  pool (`PASSWORDS_TEST_HOOK_SATURATE`) fail `Busy` after
  ~5.0 s (asserted ≥4 s and <10 s), so the wait is bounded and
  the endpoint stays DoS-resistant.

## 2. BM2 — recovery can no longer burn the only code on a busy pool

**Done, with the brief test. The V3 behaviour landed 2026-10-19
(recovery also clears TOTP + notice + 72 h payment pause) is
preserved in full.**

`web::recover` rewritten, and `accounts::PasswordRecovery` replaced
by two functions:

1. `parse_recovery_code` — shape only (which account prefix, which
   16-char code), no database access.
2. The handler verifies the code against the stored hash (cheap
   SHA-256 compare, no pool slot) as a read-only pre-check, then
   **hashes the new passphrase first** (`passwords::hash_new`).
   If the pool is busy the handler errors here — **the code is
   untouched.**
3. `accounts::consume_recovery_code` then performs **one
   transaction**: re-reads the stored hash `FOR UPDATE` and
   re-compares (closing the race between pre-check and commit),
   consumes the code, sets the new passphrase hash, revokes every
   session, stamps `recovered_at`, clears the TOTP secret (the
   V3 decision), and stores the **new** code's hash — all or
   nothing.

Any failure before commit leaves the old code valid and the old
passphrase in place. The two V3 side effects that cannot live in
that transaction (the inbox notice and the seller payment-change
pause timestamp) run after commit, exactly as before, and the new
code page is rendered from the same `RecoverOutcome` data.

**Test** (`busy_pool_recovery_attempt_leaves_the_code_valid`):
with the pool saturated via the test hook, a recovery attempt
with a valid code fails (302 `msg=recovery_failed`), the account
row is **unchanged** (same code hash, same passphrase hash, no
`recovered_at`, TOTP secret still set); once the pool frees, the
**same code succeeds** — and the V3 effects are asserted:
TOTP cleared, payment pause visible, the new code issued.

## 3. BL1 — retiring invoices: DONE IN PART — two locked-test conflicts

### Done

- **Publish guard.** `POST /seller/listings/{id}/status` refuses
  to publish unless the seller has a payment identity **and** at
  least one unused pool address (new alert code
  `payment_setup_required`). Before this, a seller with neither
  could publish, and every order on such a listing sat in
  Requested forever: accepting needs an assigned address and
  there was nothing to assign. The guard sits at the only
  user-facing publish path; the library `set_status` primitive is
  unchanged (moderation-adjacent suites drive it directly).
  Test: `publish_requires_payment_identity_and_unused_pool`
  walks all three states (neither → refused; identity only →
  refused; identity + one unused entry → published).
- **Form cleanup.** The create-listing form no longer offers the
  destination-module select (which offered `signed-invoice`) or
  the auto-invoice checkbox. `ListingForm.destination_module` is
  now optional and defaults to `signed-address-pool`; the field
  stays accepted so older form copies keep working.
- **Rule-to-route test.** `every_authz_rule_names_a_served_route`
  probes every rule in `authz::ROUTES` against the running router
  anonymously (a served route answers with a page, redirect,
  refusal, or a handler 404 *with a body*; an unserved route
  answers axum's bare empty 404). The test passes — with the 13
  pinned exceptions below carried as an explicit list that fails
  the build if the dead set changes in either direction.

### CONFLICT 1 (documented, not resolved): the dead authz rules cannot be removed

The brief asks to remove "the 11 invoice and pool route rules".
Mechanical diff of `authz::ROUTES` against the router finds **13**
rules naming routes the router does not serve: the 6 `/invoices/*`
rules, `POST /orders/{id}/invoice` is *not* among them (it matches
the `/orders/{id}/{action}` route pattern), the 2
`/pools/{id}/statement.txt[.asc]` rules, the 3 `/seller/pools*`
rules (pool management moved to `/seller/payment-batches` in
Direct Payments), `GET /messages/{id}/download` (superseded by
`/conversations/{id}/messages/{mid}/download`), and `GET /security`.

**Every one of the 13 is pinned by the locked suite
`tests/security/blind_stage1.rs`**: its expected `authorize()`
table names each (invoice block at lines 84–104, order-invoice at
line 97, pool statements at 105–106, seller pools at 116–118 of
`crates/app/src/authz.rs` are mirrored in the suite, as are
`/security` at its line 304 and `/messages/{id}/download` at line
371), and it asserts the full table equals `authz::ROUTES` in
length and disposition. Removing any rule flips those assertions.
The suite's amendment budget for this batch is zero ("no
locked-suite amendments are authorized"), so the rules stay, and
the rule-to-route test carries them as the named exception set
`PINNED_DEAD_RULES`.

**Owner decision needed to finish this:** amend blind_stage1's
expected table (delete the 13 rows) in a future authorized pass;
the rule rows and the test's exception list then come out
together.

### CONFLICT 2 (documented, not resolved): the invoice guard in `apply_action` cannot be removed

The guard (an order whose `module_pins.destination` is
`signed-invoice` cannot be accepted without an issued invoice)
is pinned by the locked suite `tests/security/blind_direct_v1.rs`,
test `accept_on_legacy_order_still_requires_invoice` (line 601),
which builds exactly such an order and asserts the refusal.
`orders.rs` documents this in place ("Stage 4 suite's
invoice-gated fixtures and the Stage 9 suite's pinned-payload
flows pin this behaviour"). `blind_stage5.rs` likewise pins the
destination string and error text ("signed-invoice module is
disabled in this build"). Removing the guard breaks the locked
suite, so it stays. Same remedy as Conflict 1: a future
authorized amendment pass.

## 4. BL2 — fuzzing that reaches real messages

**Done, with the brief's criterion verified by execution.**

- **Envelope target rebuilt on the real fixtures.**
  `envelope_validate` used to validate against KeyRefs built from
  dummy fingerprints (`AAAA…`, `BBBB…`) that no real message can
  match, so it could only ever explore the parser's outermost
  layer. The context is now built once (via `OnceLock`) from the
  real GnuPG fixture certificates — Alice sends, Bob receives
  (`crates/app/tests/fixtures/gpg/cert-alice.asc` /
  `cert-bob.asc`, the same certs the messaging suites use) — and
  the corpus is seeded with the fixtures' real messages
  (300 B / 2 KB / 40 KB, signed and unsigned, plus the binary
  2 KB form).
- **Criterion check**: a new `fuzz/examples/check_corpus.rs`
  replays `validate_envelope` under the harness context over the
  whole corpus. Before seeding: **0 accepted** out of ~7,700
  corpus inputs. After seeding and the 60 s run: **3,146 corpus
  inputs, 7 accepted** — exactly the seven fixture seeds. The
  brief's test ("after a 60-second run, the corpus holds at
  least one input the validator accepts") passes.
- **New target `batch_parse`**: the payment-batch parser.
  `upload_batch`'s pure front end (JSON parse + format /
  marketplace / network header checks) was extracted verbatim
  into `app::payments::parse_batch_header` — upload_batch calls
  it, so the fuzzer exercises the real parser, not a copy — and
  the target then runs the per-entry pure checks (subaddress
  validation, canonical-message rebuild) for every entry of a
  batch whose header parses. Seeded with a valid batch file.
- **New target `unwrap_extract`**: `app::keys::extract_unwrapped_message`
  (the V4 disclosure parser) against both fixture certs, seeded
  with the real `--unwrap` fixtures.
- **Statements target**: the invoice and pool statement entry
  points were dropped (Direct Payments retired both kinds; the
  rotation-statement parser — live — stays, as do the address /
  atomic / timestamp field parsers). Note: the retired parsers
  themselves remain in `domain::statements`, because the locked
  Stage 5 suite pins their behaviour (696 assertions on the
  statement formats); removing the *fuzz entry points* is the
  change the brief's test measures, and it is complete.
- **Bounded runs** (this host, `--target x86_64-unknown-linux-gnu`;
  the default musl target's std component is absent from the
  installed nightly): envelope_validate **60 s, 142,453 execs,
  no crash**; batch_parse 30 s, 2,902,567 execs, no crash;
  unwrap_extract 30 s, 13,342 execs, no crash; statements 20 s,
  1,446,600 execs, no crash. Corpora updated in place (the two
  new corpora merge-minimized once: 1,982→1,692 and 396→315
  files, named seeds restored).

## 5. BL3 — no direction tricks in seller text

**Done, with the brief tests and more.**

- `crates/modules-api` gains the complete **Unicode 15.0 category
  Cf range table** (170 code points in 21 ranges: bidi controls
  U+202A–U+202E and U+2066–U+206F, zero-width U+200B–U+200F,
  U+2060, U+FEFF, soft hyphen U+00AD, tag characters
  U+E0001/U+E0020–U+E007F, Arabic marks, …) as
  `FORMAT_CHAR_RANGES`, with `is_format_char` /
  `contains_format_chars`.
- `normalize_form_lines` now rejects **all** of category Cf, as
  its comment always claimed (it previously named only four
  characters: U+200B/C/D and U+FEFF).
- Applications: listing **title** and **description**
  (`validate_listing` → `Title`/`Description` errors);
  **delivery and refund terms** (`validate_listing_terms`,
  enforced in `create_order` — the one place terms text is
  consumed into a terms file; the columns have no writer in the
  current UI, so this is the consumption-side guard);
  **review text** and the **seller reply** (new
  `ReviewError::FormatChars`); **profile text**
  (`update_profile` → HTTP 400, nothing stored).
- Ordinary non-ASCII text is unaffected: accented letters and
  combining marks (Café, U+0301) still validate — asserted in the
  tests, and the locked suites' Unicode cases (blind_stage4's
  NFC terms test uses U+0301/U+00E9, neither of which is Cf)
  still pass.

**Tests**: `format_chars_refused_in_listing_text_and_terms`
(title with U+200B refused; description with U+202E refused;
terms cases; clean accented text accepted),
`normalize_form_lines_rejects_all_of_category_cf` (seven Cf
exemplars across the ranges refused; plain text accepted),
`review_and_profile_text_refuse_format_chars` (review with
U+202E refused and unstored; seller reply with U+200B refused;
profile update with U+202E → HTTP 400 and unstored; clean text
accepted).

## 6. Locked-file integrity

Pre-manifest generated from git at HEAD `30041e1` over the 17
locked paths (`marketplace/tests/security/**` +
`marketplace/docs/invariants.md` — same set and method as
VERIFICATION-FIX-REPORT-2026-10-19.md); post-manifest taken from
the working tree at the end of the batch. **Result: all 17 files
byte-identical** (`diff` empty). Manifests saved beside this
report: `BM-BL-LOCKED-MANIFEST-PRE-2026-10-19.txt` /
`BM-BL-LOCKED-MANIFEST-POST-2026-10-19.txt`. The spec file lives
outside the repo (`~/workspace/user/files/…Spec_v2_0_4b7b.md`,
SHA-256 prefix `c840981d528d3b70`) and was never written to. No
locked-suite amendments were authorized in this batch and none
were made — the two BL1 subtasks that would have required them
are documented as conflicts in §3 instead.

## 7. Final gate

Environment: PostgreSQL re-provisioned for this run (the VM had
been replaced: Zonky binaries from `~/pgsys` to `/tmp/pgx`, data
`/tmp/pgdata`, port 5432, trust auth; `marketplace_dev` recreated,
migrations 0001–0015 applied, 38 tables verified — the server is
left running), `DATABASE_URL` as in prior gates, `MEDIA_WORKER`
pointing at the built media-worker, `MEDIA_DIR`/`BLOB_DIR` on
disk-backed storage, nettle shims per AGENTS.md, bwrap 0.9.0.
Executed as per-target complete runs; every target ran to
completion against the final tree.

| Suite | Result | Baseline |
| --- | --- | --- |
| app lib | 54 / 0 / 0 | 52 (+2 new BM1 unit tests) |
| app integration (13 files) | 95 / 0 / 0 | 86 (+9 new batch tests) |
| envelope + domain + modules-api + media-worker | 65 / 0 / 3 | 65 / 0 / 3 |
| blind_direct_v1 | 42 / 0 / 0 | 42 |
| blind_stage1 | 41 / 0 / 0 | 41 |
| blind_stage2 | 38 / 0 / 0 | 38 |
| blind_stage3 | 34 / 0 / 0 | 34 |
| blind_stage4 | 58 / 0 / 6 | 58 / 6 ignored |
| blind_stage6 | 83 / 0 / 0 | 83 |
| blind_stage9 (as amended 2026-10-19) | 43 / 0 / 0 | 43 |
| blind_stage10 | 32 / 0 / 0 | 32 |
| **Workspace total** | **585 / 0 / 9** | **574 / 0 / 9** |
| **seller-helper** | **18 / 0 / 0** | **18 / 0 / 0** |

The +11 over baseline is exactly the new coverage: 9 integration
tests in `modules_audit_fixes.rs` + 2 unit tests in
`passwords.rs`. No regressions anywhere; every blind suite is at
its baseline number, including the two suites that pin the BL1
conflicts (blind_stage1, blind_direct_v1) — they pass *because*
the pinned behaviour was left in place.

## 8. Honest notes

- **The full gate caught three defects in this batch's own new
  tests** (commit `ecaa073`): the BM2 test's helper used
  `/recover` instead of the real `/account/recover` route; the
  publish test used a fixed fixture subaddress that collides
  with the destinations table's global no-reuse constraint on
  re-runs; the profile test asserted 302 where axum issues 303.
  All three were in test code only — no production code changed
  after the per-task commits — and the corrected tests were
  re-run standalone and in the full gate above. The BM2 test's
  assertions discriminate the old behaviour by construction
  (old code answered a busy-pool recovery with a bare 500 and
  the code already spent; the test requires a
  `recovery_failed` redirect, a byte-identical account row, and
  a successful retry with the same code).
- **Environment incident (no results affected):** `/tmp` filled
  to 100% during a tooling build (512 MB tmpfs); the failed
  build was discarded and everything re-run with disk-backed
  `TMPDIR`/`CARGO_TARGET_DIR` under `~/tmp-build`.
- The one thing this batch deliberately leaves open is BL1's
  remainder (§3): the 13 dead authorization rules and the
  `apply_action` invoice guard stay until an owner-authorized
  locked-suite amendment removes their pins from blind_stage1
  and blind_direct_v1.
