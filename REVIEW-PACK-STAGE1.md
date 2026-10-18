# Review Pack — Marketplace Spec v2, Stage 1 (accounts, sessions, authorization)

**How to use:** paste whole into Claude Opus. This is the §22 stage-gate
review for Stage 1, produced in the 2026-10-13/14 retrofit (the stage was
first built as a working draft; this pack accompanies its gate).
Cameron (owner) makes final calls; your job is verdicts with file:line
evidence.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL, with
   the file and line you relied on. Abstract concern without a mechanism
   doesn't count; name who does what to whom.
2. The code is at `marketplace/crates/app/src/` (`passwords.rs`,
   `usernames.rs`, `sessions.rs`, `recovery.rs`, `authz.rs`,
   `throttle.rs`, `admission.rs`, `db.rs`, `web.rs`). The spec is
   "Privacy-First Noncustodial Marketplace — Spec v2" plus
   `SPEC-V2-AMENDMENTS.md` and the canonical contract
   `marketplace/docs/api-contract.md` (§7 is the Stage 1 surface). If you
   cannot see the files, say so and review against the claims and
   evidence summarized here instead — flag that limitation.
3. End with: (a) any test the locked suite must add for Stage 1, stated
   as plain-language assertions; (b) anything that must be fixed before
   later stages build on this code.

## What was built (claims to check)

Argon2id (64 MiB, t3, p1) behind a global semaphore (`HashGuard`);
saturation returns Busy — never an unbounded queue. Passwords checked
against a bundled common-password list. Usernames: Unicode case-fold +
trim; validity is exactly the contract §7 rule — 3–24 chars of
`[a-z0-9_-]` after folding, no other restriction (a draft-era
leading/trailing `-` ban was removed in the retrofit when the blind
suite showed the contract states the complete rule). Sessions: 256-bit
tokens, only SHA-256 hashes stored; idle 12 h / absolute 7 d (spec §7
values); per-session CSRF secret, constant-time comparison. Recovery
codes: ≥100 bits, unambiguous alphabet, stored hashed only; consumption
is single-use and in one transaction revokes ALL sessions and marks the
account recovered; the DB layer is keyed by account id so a wrong code
and an unknown account produce the same outcome (no oracle — the
name→id resolution happens at the web layer). `authorize()` is the
single enforcement point over one route table that now matches spec
§17's route list verbatim (parameterized patterns, segment-wise
matching) classified per contract §7: public set / any-authenticated /
Seller+Admin / Moderator+Admin / Admin-only; anything undeclared is
Deny for every actor including Admin; every POST requires CSRF, no GET
does. Login throttle: per-folded-username exponential delay, capped,
never a lockout, shared across case spellings; per-account token bucket
for request admission. Buyer admission runs the modules-api
`AdmissionPolicy` trait; the default open policy admits only when
registration is open and the global account count is under the cap.

Stage 1's known extras beyond §17: the route table declares a handful
of served routes §17 does not enumerate (account home, recovery page,
seller-apply, moderation queue pages, sanitized-media serving, profile
and inbox actions), each marked EXTRA in `authz.rs` with the class of
its surface. One conflict is recorded, not hidden: §17 declares no
`GET /orders` collection route, so `authorize` denies it, while the
Stage 4 draft web layer serves an orders page behind its own session
check. That deviation belongs to Stage 4's gate.

## Invariants to judge

1. Session tokens, recovery codes, and passwords are never stored or
   logged in recoverable form.
2. `authorize()` is the only authorization entry point, denies by
   default, and its table matches spec §17 + contract §7 semantics —
   including LoginRequired (not Deny) for anonymous actors on declared
   authenticated routes, and Deny for undeclared routes even for Admin.
3. Recovery restores login only: it cannot touch keys, listings, or
   roles; it revokes all sessions atomically with the code burn.
4. The login throttle cannot be turned into an account lockout or an
   account-existence oracle.
5. Argon2 saturation degrades to Busy (503-class) without unbounded
   queueing and without ever verifying against a malformed stored hash.
6. CSRF: every state-changing route requires it; the comparison is
   constant-time and exact.

## Evidence already in hand (retrofit, 2026-10-14)

- Locked blind suite `marketplace/tests/security/blind_stage1.rs`
  (author saw only the spec, amendments, and API contract): **41/41
  pass**, including the full §17 route × role matrix — 52 declared
  routes × 5 actors = 260 `authorize()` assertions, 70 undeclared-route
  Deny assertions, 52 CSRF assertions — plus DB integration against
  PostgreSQL (hash-only storage, duplicate-username rejection,
  recovery single-use + total revocation + no-oracle).
- The suite initially failed 8 tests against the draft code; all 8 were
  fixed in code, none in tests: the route table was rewritten to §17
  (the draft had a 22-route concrete-path subset with draft-era names
  `/sell`, `/moderate`), username leading-character ban removed,
  common-password list gained the canonical top entries (`123456` was
  missing).
- cargo-mutants on `crates/modules-api` (the trait surface Stage 1
  builds on): 42 mutants, **36 caught, 1 missed, 5 unviable** after
  retrofit test additions; the one survivor is triaged in
  RETROFIT-REPORT.md.
- Crypto backend guard (`marketplace/deploy/check-crypto-backend.sh`):
  PASS — Sequoia resolves to Nettle; no experimental/variable-time
  features (Q8).
- Full workspace test suite green (see RETROFIT-REPORT.md for counts).
