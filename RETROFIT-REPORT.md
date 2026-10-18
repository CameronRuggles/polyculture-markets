# Retrofit Report — Spec v2 Stage-Gate Retrofit, Stages 1–3

**Date:** 2026-10-14 (work ordered by the owner 2026-10-13, 22:14 MDT)
**Scope:** retrofit stages 1–3 to their §22 gates, in the owner's order —
(1) spec amendments + API contract first, (2) blind suites, (3) fix
failures in code, never in tests, (4) cargo-mutants + one review pack per
stage. No Stage 4 feature work was started. **No stage starts until the
previous one passes its gate** — status per stage is in §2 below.

## 1. Step 1 — spec and contract brought current

- `SPEC-V2-AMENDMENTS.md` (project root) extended with the ratified
  Q13 form-layer normalization section, the Q17 clause (no `kind`/
  network strings on success types), Q11's SEIPD-v2 homework note, the
  Q16 key-history storage requirement, and the owner's gate-pace ruling
  recorded against §22.
- Canonical API contract: `marketplace/docs/api-contract.md` — §7
  (Stage 1 surface), §8 (Stage 2), §9 (Stage 3, incl. the Q16 taxonomy
  ordering and the conversation-scoped `RecipientKeyRetired` rule), §10
  state machines. The Stage 0 spike's `stage0-spike/API-CONTRACT.md` is
  banner-marked SUPERSEDED and kept as the spike record.
  `crates/modules-api` already conformed to the Q16/Q17 rulings
  (Subaddress newtype with torsion check, ordered `DestinationError`,
  `EnvelopeError` taxonomy, Q15 ID patterns, canonical u64).
- Q8 made explicit in the build: `crates/app/Cargo.toml` pins
  `sequoia-openpgp` with the `crypto-nettle` feature, and
  `marketplace/deploy/check-crypto-backend.sh` fails if experimental or
  variable-time crypto features ever resolve. Guard result: **PASS**
  (re-verified 2026-10-14 after the environment rebuild).

## 2. Gate verdicts

| Stage | Blind suite | Result | Verdict |
|---|---|---|---|
| 1 — accounts, sessions, authorization | `marketplace/tests/security/blind_stage1.rs`, 41 tests | **41 passed, 0 failed** | **PASS** |
| 2 — listings, markup, media, seller admission | `marketplace/tests/security/blind_stage2.rs`, 38 tests | **37 passed, 0 failed, 1 ignored** (author's own skip — no text states a description size bound) | **PASS** |
| 3 — identity keys, rotation, Q16 storage | `marketplace/tests/security/blind_stage3.rs`, 34 tests | **34 passed, 0 failed** | **PASS** |

Full workspace after all fixes: **141 tests passing, 0 failing** (app 14
unit + 1 PostgreSQL integration, domain 7, modules-api 7, the three
blind suites above; re-verified end-to-end on 2026-10-14 after a VM
replacement wiped the environment and it was re-provisioned).

Blind authorship: three separate author sessions; each was given ONLY
the spec file, `SPEC-V2-AMENDMENTS.md`, and
`marketplace/docs/api-contract.md`, plus its stage scope. Reading the
implementation, migrations, stage reports, and decision docs was
explicitly forbidden in their briefs. Each file header carries the
author's plain-language assertion list for the owner's review, and each
author reported ambiguities instead of inventing expectations (listed
in §7). The suite package `security-tests` is a workspace member at the
locked-test location `marketplace/tests/security/` (README + CODEOWNERS
lock in place).

## 3. Stage 3 key-history finding (owner-flagged Q16 check)

**Question:** does Stage 3's key storage record when each key was
current, and which conversations saw it?

**Finding:** half of it existed, half did not. Validity intervals were
recorded (`identity_keys.created_at` / `retired_at` / `status`, rotation
rows in `key_rotations`), but **which conversations saw a key was
recorded nowhere** — the Q16 conversation-scoped `RecipientKeyRetired`
decision would have been unanswerable for the leak-fixed form, and
adding it later would have meant a migration against live data.

**Fix (done now, as ordered):** migration
`marketplace/migrations/0006_conversation_key_sightings.sql` adds
`conversation_key_sightings` (conversation_id, account_id, fingerprint,
key_id, shown_to, shown_at; unique per tuple), with
`record_key_sighting` / `key_shown_in_conversation` in
`crates/app/src/keys.rs`. The gated semantics: a key counts as shown in
a conversation only if the account participates in it AND (a sighting
was recorded in THIS conversation OR the key was the account's current
key when the conversation was created). The blind suite probes the full
matrix across two conversations, including the leak-fix probe (a
sighting in C1 must not make the key count as shown in C2) — passing.

## 4. Code fixes (failures fixed in code; tests never edited to pass)

**Stage 1 (8 initial failures):**
1. `crates/app/src/authz.rs` — route table rewritten: the draft's
   22-route concrete-path subset (with draft-era names `/sell`,
   `/moderate`) replaced by spec §17's route list verbatim (52 routes)
   with contract §7 classes (public / any-authenticated / Seller+Admin /
   Moderator+Admin / Admin-only) and segment-wise pattern matching, so
   `authorize()` and `route_requires_csrf()` answer for §17's `{id}` /
   `{module}` path forms and for concrete paths. Served routes §17 does
   not enumerate are kept as marked EXTRA rows. §17 declares no
   `GET /orders` — `authorize` now denies it for every actor (the
   Stage 4 draft's orders page deviation is recorded in §7).
2. `crates/app/src/usernames.rs` — removed the draft's
   leading/trailing `-` ban from `validate_username`; contract §7
   states the complete rule (3–24 chars of `[a-z0-9_-]`).
3. `crates/app/src/passwords.rs` — common-password list gained the
   canonical top entries; `123456` (and peers) were missing.

**Stage 2 (5 initial failures):**
4. `crates/app/src/listings.rs` — `validate_listing` aligned to
   contract §8: price as `price_atomic: u64`, returns `Result<(),
   ListingError>`, variant `Module` renamed `DestinationModule`.
   `crates/app/src/web.rs` create-listing handler now parses the form
   decimal via `Atomic::parse_decimal` (unparseable → `Price`).
5. `listings.rs` — `decide_seller_application` takes the decider's id
   and enforces the contract §8 invariant itself: a non-moderator/admin
   decider (including the applicant) fails with the new
   `AdmissionError::Unauthorized` and changes nothing; privileged
   decisions record outcome + role flip in one transaction.
6. `listings.rs` — recorded approval outcome string is now `approved`.
7. `listings.rs` — `apply_for_seller` is idempotent while pending
   (the draft inserted duplicate pending rows, which also made the
   decision update fail its exactly-one-row check).
8. Harness, not code: the media tests require `MEDIA_WORKER` set to the
   built media-worker binary (and `MEDIA_DIR`); unset, the pipeline
   cannot spawn the worker and valid uploads are rejected. With the
   harness set, all media tests pass. Noted for CI wiring.

**Stage 3 (2 initial failures):**
9. `crates/app/src/keys.rs` — **expired certificates were accepted.**
   Sequoia's `with_policy` checks structure/bindings/revocation but not
   liveness; `validate_cert` now additionally requires
   `valid.alive()`. Independently reproduced outside the suite (a cert
   gpg reported `[expired: 2026-10-12]` validated OK before the fix,
   `PolicyInvalid` after).
10. `keys.rs` — `key_shown_in_conversation` semantics tightened to the
    gated reading in §3 (participant guard; interval branch = current
    at conversation creation; later keys count only via sightings).

**Implementation-crate test additions (not locked-suite edits):**
11. `crates/modules-api` — three unit tests added (network statement
    names round-trip, subaddress rendering round-trip, ModuleError
    Display) after the first mutants run showed those surfaces
    untested; see §6.
12. `crates/app/src/authz.rs` — unit test added for pattern-form caller
    paths (`/orders/{id}/{action}`), the arm the first authz mutants
    run found untested.

## 5. Construction fixes to blind test files (complete list)

Hard rule honored: no assertion was changed anywhere. The changes below
adapt only call/fixture CONSTRUCTION to the real interfaces where the
contract did not print a signature (authors guessed, per their briefs);
each is also marked with a `CONSTRUCTION FIX` comment at the site.

**blind_stage1.rs**
- C1. Import + construction: guessed type `app::admission::
  RateLimitedOpen::new()` → the real `app::admission::OpenAdmission
  { open: true }` (2 sites + import).
- C2. `admission_cx` helper: real `AdmissionCx` fields are
  `username / registrations_open / account_count / account_cap:
  Option<u64>`; the author's `(count, cap)` map onto them.
- C3. `FormInput::default()` (no `Default` exists) → `FormInput
  { fields: vec![] }` (2 sites).
- C4. `db::create_account` takes no `Role` argument (new accounts
  default to buyer): argument dropped (2 sites).
- C5. New `db_create_session` adapter: real signature is
  `create_session(pool, token, csrf_secret, &Session)`; the adapter
  builds `Session::fresh(account_id, now)` and a fixed fixture CSRF
  secret (3 call sites).
- C6. `session_by_token` returns `(Session, String)`: field accesses
  in the DB tests changed to tuple `.0` (7 sites).
- C7. `db::consume_recovery_code` is keyed by account id, not username:
  calls pass the account id; the "unknown username" no-oracle case uses
  a never-created account id (the name→id no-oracle property lives at
  the web layer). The equality assertion is unchanged (4 call sites +
  1 fixture binding).

**blind_stage2.rs**
- C8. `browse(&pool)` → `browse(&pool, None, None, 1)` (real signature
  takes query, category, page).
- C9. Catalogue fixture INSERT now supplies `listings.public_id`
  (NOT NULL, no DB default; the app generates it).

**blind_stage3.rs**
- C10. New `install` adapter: real `install_key` takes
  `(pool, account, cert_bytes, &CertInfo, Option<rotation>)`; the
  adapter validates the fixture cert for its `CertInfo` and, when the
  account already has a current key, records a rotation whose
  `certified` flag is exactly the author's boolean argument (statement
  bytes are a fixed fixture; they are not under test in the DB tests).
  12 call sites re-pointed at the adapter.
- C11. `current_key` / `key_history` return tuples: `.fingerprint`
  field accesses changed to `.0` (4 sites).
- C12. Expired-cert fixture rebuilt: the author's
  `--quick-set-expire <fpr> 1` + 2 s sleep never expired the key (gpg
  reads the bare number as DAYS — verified: expiration lands exactly
  86400 s after creation; gpg also refuses past dates). The fixture now
  generates the key under `--faked-system-time` three days in the past
  with a one-day expiry (plain epoch seconds; the `@epoch` spelling
  makes this gpg build silently use time 0 — also verified). The
  assertion (`PolicyInvalid`) is byte-for-byte the author's.

**Scaffolding (implementer's own files, not test content):**
- `marketplace/Cargo.toml`: `tests/security` added to workspace
  members once all three suites existed.
- `marketplace/tests/security/Cargo.toml`: dependency paths corrected
  (`../crates/` → `../../crates/`).

## 6. cargo-mutants

Tool: cargo-mutants 27.1.0. Runs (full outputs preserved under
`mutants-runs/` in this directory):

- **modules-api (whole crate)** — first run: 42 mutants, 25 caught,
  12 missed, 5 unviable. The 12 misses were untested surfaces
  (statement-name conversions, `From<Network>`, `Subaddress`
  rendering/Display, `ModuleError` Display, and the Q14 torsion
  `||`→`&&`). After the implementation-crate test additions in §4.11:
  **42 mutants, 36 caught, 1 missed, 5 unviable.** The sole survivor:
  `Subaddress::validate` torsion check `||` → `&&`
  (lib.rs:124) — killing it needs a valid-format Monero address whose
  public key is a non-identity small-order point; no such vetted vector
  exists in the tree (checked the Stage 0 spike fixtures) and none of
  the suites exercises one. **Deferred with reason:** the check itself
  is a direct port of the Q14 rule and its identity half is covered;
  add the vector when a trusted small-order address is sourced.
  `Network::statement_name` currently has no caller (kept API for the
  statement stages); it is covered by the new round-trip test.
- **app authz.rs** (tested by the app package's tests): **21 mutants,
  17 caught, 2 missed, 2 unviable** (the unviable pair are
  `Default::default()` return replacements for types that implement
  no `Default`). Both survivors are the same mutation in the two
  placeholder arms of `path_matches` (authz.rs:136:40 and 137:40):
  `&&` → `||`, so a segment counts as a placeholder if it starts with
  `{` OR ends with `}` instead of requiring both. They are
  **equivalent for every reachable input**: all patterns in the table
  are compile-time constants with well-formed `{…}` segments, and
  every caller presents either concrete segments or well-formed
  placeholders — the mutation could differ only on a hand-crafted
  malformed segment (`{id`, `id}`), which no caller generates and
  which would still have to match a declared route's overall shape to
  affect any decision. (Of the two misses observed in the first,
  pre-crash authz run, the 137:17 `||` → `&&` mutant was caught in
  this run — by the new pattern-form unit test in §4.12 — while
  136:40 survived both runs, joined here by its presented-path twin.)
- **app keys.rs** (tested by the app package's tests): **133 mutants,
  22 caught, 108 missed, 3 unviable.** The raw miss count needs its
  context: the app package's own unit tests barely touch keys.rs (3
  tests) — the coverage for this crate lives in the locked blind
  suite, which the mutants test phase does not run. The 108 misses
  triage as follows:
  - **99 return-value replacement variants of the six DB functions**
    (`current_key` 19, `key_history` 73, `install_key` 1,
    `record_key_sighting` 1, `key_shown_in_conversation` 2,
    `latest_uncertified_rotation` 3), plus the match-arm deletion in
    `latest_uncertified_rotation`: generated constants (`""`,
    `"xyzzy"`, 0, 1, empty vec, …) that the blind suite's DB tests
    reject by asserting exact fingerprints, version numbers, history
    contents, sighting scoping, and reported/unreported states.
    **Killed by the blind suite — verified by hand-mutation** (the
    mutant was applied to the real code, the blind Stage 3 suite run,
    and the code restored byte-identical): `key_shown_in_conversation
    → Ok(true)` fails the Q16 conversation-scoping probe;
    `current_key → Ok(None)` fails 3 DB tests; `key_history →
    Ok(vec![])` fails the rotation history assertions; deleting the
    `Some((false, date))` arm fails the uncertified-rotation test.
    `install_key → Ok(())` and `record_key_sighting → Ok(())` fall to
    the same assertions (a no-op install leaves no current key; a
    no-op sighting leaves the probe's post-sighting assertion false).
  - **`verify_detached → true` and `→ false`, `Helper::get_certs →
    Ok(vec![])`, `Helper::check → Ok(())`**: the signature-verification
    family. **Killed by the blind suite — `verify_detached → true`
    verified by hand-mutation** (tampered-message, wrong-cert,
    garbage-signature, and dual-signature rotation tests all fail);
    the other three fall to the same tests by construction (no certs
    or an ignored bad result both make valid signatures fail or
    invalid ones pass, each of which the suite asserts).
  - **`parse_rotation_statement` field-name `==` → `!=`** (keys.rs:163):
    **killed by the blind suite — verified by hand-mutation** (3
    statement tests fail). (The whole-function replacements of
    `parse_rotation_statement` were caught even by the app tests.)
  - **Surviving all suites (3), accepted with reasons:**
    `uid_warning` `&&` → `||` and `>=` → `<` (keys.rs:36–37) — the
    real-name warning heuristic would fire/miss on edge-shaped
    pseudonyms (single all-caps word; multi-word lowercase). The
    warning is advisory only — it never gates validation — and the
    blind author recorded the underlying warning semantics as
    spec-unspecified; tightening it needs an owner ruling on what
    counts as a "real name", not a test.
    `validate_cert` encryption-subkey `||` → `&&` (keys.rs:64) — a
    cert whose subkey is flagged for transport-only or storage-only
    encryption would be wrongly rejected (availability, not a
    security hole: the mutant only ever rejects more). Standard gpg
    cv25519 subkeys carry both flags, so no fixture in either suite
    distinguishes the forms; killing it needs a single-purpose-flag
    subkey fixture.

## 7. Ambiguities, deviations, deferred items

**From the blind authors (spec + contract genuinely silent; skipped or
flagged by the authors, never invented):**
- Stage 1: account-recovery POST path is named in contract §7's public
  set but has no §17 path (no matrix cell asserted); TOTP for
  Admin/Moderator has no contract interface (untestable at this layer);
  password length 12–256 has no named validation function; session
  boundary inclusivity at exactly 12 h/7 d untested (texts silent);
  `route_requires_csrf` for undeclared paths not asserted.
- Stage 2: description size bound stated NOWHERE (impl uses 20 000
  chars; the author's 1 000 000-char oversize test is present but
  `#[ignore]`d pending an owner ruling on the bound); no contract
  helper reaches stored media bytes from the returned reference (the
  metadata assertion runs only when the reference is a readable path);
  admission outcome strings are not spec-pinned (the gate records
  `approved`; see §4.6).
- Stage 3: revoked-cert error variant is asserted as `PolicyInvalid` by
  analogy with expiry (contract names no variant); warning strings are
  unspecified (only "some warning mentions email" is asserted);
  certify-only fixture self-skips if gpg won't construct it.

**Recorded deviations/forks for the owner:**
- **GET /orders**: §17 declares no orders collection route; the Stage 4
  draft web layer serves one. `authorize()` now follows §17 (Deny).
  Owner's call at the Stage 4 gate: amend §17 or move the page. Not
  fixed here — Stage 4 is a working draft and this retrofit does not
  touch it.
- **Q16 "conversation lifetime"**: the contract does not define the
  interval's end. The gate adopted: interval branch = key current at
  conversation creation; later presentations count only via recorded
  sightings (conservative, privacy-preserving, and the sighting path is
  the server's real presentation record). The open-ended-overlap
  alternative would make any later-installed key retroactively "shown".
- **DERIVATION-UNCERTAIN matrix cells** (author-flagged in the suite):
  POST /logout classified Authenticated; the seven order-action POSTs
  and invoice signature/evidence POSTs classified any-authenticated at
  route level (per contract §7; per-transition actors are state-machine
  checks); pool statement GETs any-authenticated at route level
  (§17's seller/invoice-holders rule read as object-level); anonymous ×
  GET /admin = LoginRequired per the general rule.

**Deferred:**
- Torsion-vector mutant (above): needs a vetted small-order address.
- Description size bound: owner to state it; the ignored blind test
  activates unchanged once ruled.
- Stage 4 remains an ungated working draft (STAGE4-REPORT.md) — its
  gate comes after this retrofit per the owner's order, and its known
  issue (built under the superseded "hybrid gate" note) plus the
  GET /orders deviation ride with it.

## 8. Review packs

One per stage, in the style of `REVIEW-PACK-STAGES-1-3.md`:
`REVIEW-PACK-STAGE1.md`, `REVIEW-PACK-STAGE2.md`,
`REVIEW-PACK-STAGE3.md` (this directory). Each carries the
post-retrofit claims, the invariants to judge, and the gate evidence
above. The human/Opus review itself is the owner's step — the packs are
ready to paste.

## 9. Environment note

Mid-retrofit, a VM replacement wiped system packages and PostgreSQL
(and /tmp, losing the first authz mutants run's output — its two
observed misses are triaged in §6). The environment was re-provisioned
(`marketplace/deploy/dev-setup.sh`; PostgreSQL and the dev packages
were restored from the local apt cache when the package-index refresh
hung), all six migrations re-applied, and the full workspace suite
re-verified green afterwards (§2).
