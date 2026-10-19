# Account Security Audit — Fix Completion Report (2026-10-18)

**Scope built:** all 8 tasks of the Account Security Audit fix brief
(`Polyculture_Markets___Account_Security_Audit_2_rjst.md`, findings
AH1, AM1–AM3, AL1–AL4), implemented by the previous worker and
finished/verified here: full-suite verification, three test-fixture
corrections and two code fixes found during verification (below),
cleanup, and commits.

**Result: complete.** Workspace **533 passed / 0 failed / 9 ignored**
(baseline at HEAD `9943035`: 515/0/9; the +18 is the 14 new acceptance
tests plus 4 new unit tests), seller-helper **17/17**,
blind_direct_v1 **42/42**, blind_stage9 **43/43**, blind_stage10
**32/32**, blind_stage4 **58 passed / 6 ignored** — every locked
suite at its exact baseline count. **Locked-test conflicts: none**
(no locked suite was edited, and none failed on behaviour; see §10
for the one deliberate design accommodation).

Commits on `main` (not pushed): `b2229c3` (migration 0011 + password
list), `6e7aa88` (implementation), `8990fee` (acceptance suite).

---

## 1. Task 1 — TOTP at login; mandatory enrollment (AH1, AM1)

- The login form/handler takes an optional `totp` field; for any
  account with TOTP enrolled, a missing or wrong code is a login
  failure (generic error, failure recorded) — no session is issued.
  Codes pass through the one shared gate (§3), so login codes get
  counting, lockout and replay protection too.
- Enrollment is mandatory in effect for moderators: every moderator
  power — actions, disclosure reads (§3), seller decisions (§3) —
  refuses a non-enrolled moderator (TotpRequired), and once enrolled
  the code is demanded at login as well.
- Sellers are hard-gated: `seller_payment_gate` refuses payment
  identity changes and batch uploads until the account is enrolled.
- Acceptance: `login_requires_totp_once_enrolled`,
  `login_code_cannot_be_replayed`.

## 2. Task 2 — Step-up for identity changes (AM3; discharges payment-audit M1)

- `web::step_up`: current passphrase (verified through the
  per-account hash scope), plus a TOTP code through the shared gate
  when the account is enrolled. A session alone never suffices.
- Applied to: payment address change, batch upload, key upload, key
  rotation (including the uncertified "lost key" path), and TOTP
  enrollment start. Each success posts an inbox notice
  (`stepup_payment_identity`, `stepup_payment_batch`,
  `stepup_key_upload`, `stepup_key_rotation`,
  `stepup_totp_enrollment`) so a session thief's changes are visible
  to the owner.
- Acceptance: `stepup_required_for_payment_identity_batch_key_and_enrollment`
  (session-only attempts refused for all four; the key provably does
  not move; notices present).

## 3. Task 3 — Moderator gaps (AH1)

- **Disclosures:** a moderator session alone no longer decrypts or
  renders dispute disclosures. `POST /disputes/{id}/unlock` with a
  fresh code records a session-bound, purpose-bound grant
  (`totp_stepup_grants`, keyed by session-token hash) valid 10
  minutes; without it the dispute page renders the unlock form and
  the disclosures are not even decrypted.
- **Seller approvals:** `moderation_decide` requires a fresh code
  per decision; refusal re-renders the applications page with the
  reason.
- **Counting + lockout:** `moderation::verify_totp_gate` is the one
  verification path (moderator actions, disclosure unlock, login,
  step-up). A wrong code increments `totp_fail_count`; at 10 the
  account's code checking locks for 15 minutes — during the lock
  even a correct code is refused (`TotpLocked`) and attempts do not
  extend the lock. The account gets exactly one inbox notice per
  lockout episode (see the deviation note in §11 for one nuance
  fixed during verification).
- Acceptance: `moderator_disclosures_and_seller_approval_need_fresh_code`,
  `moderator_codes_lock_after_ten_failures` (the 11th attempt —
  correct code included — is refused inside the cool-down).

## 4. Task 4 — Login limits that hold (AM1, AM2)

- **Budget before hashing:** `Throttles::login_budget_exceeded` is
  checked before any Argon2 work; 10 failures inside a 1-hour window
  exhaust a folded username's budget and further attempts get the
  generic error with no hash performed. The pre-existing exponential
  sleep delay remains as a second layer.
- **One hash per username:** `HashGuard::verify_scoped` /
  `hash_scoped` serialize Argon2 per scope (folded username at
  login, `acct:{id}` at step-up) behind per-scope async mutexes;
  other usernames proceed against the unchanged global semaphore.
  Scope map is swept opportunistically past 8192 entries.
- **Failure map hygiene:** entries older than the window are swept
  on write; the map is hard-capped at 4096 with oldest-first
  eviction under flood.
- **Common-password list:** the 45-entry inline list is replaced by
  the bundled NCSC 100k corpus (§9). Checked at registration and at
  passphrase change.
- Acceptance: `login_budget_refuses_before_hashing`,
  `login_failure_budget_and_map_hygiene`,
  `hash_scoped_serializes_per_username_only`,
  `bundled_common_password_list_covers_the_full_corpus`.

## 5. Task 5 — Request throttle wired (AH1 follow-through)

- Chosen: **wired, not removed.** `Throttles::allow_request`
  (per-account token bucket, burst 60, refill 60/min) is invoked by
  every signed-in POST handler — directly per handler and centrally
  in `guard_post`, which the stage-9+ handlers route through; the
  account's bucket map is itself capped/aged. Over-budget requests
  get HTTP 429. (Anonymous POSTs — login, register, recovery — have
  no account to key on; login carries the task-4 budget instead.)
- Acceptance: `signed_in_posts_are_throttled_at_sixty` (the 61st
  rapid signed-in POST from one account returns 429).

## 6. Task 6 — Fail closed on missing secrets (AL1, AL2)

- Outside the Development profile: an unset *or empty*
  `DATABASE_URL` refuses startup (exit 2) — the `postgres:dev`
  fallback now exists only under Development. The key file must
  already exist (`KeyFile::load_existing`); a missing file is a
  configuration error (exit 2) and nothing is created.
- Ordering fix made during verification: the key file is loaded
  **before** the database pool is opened, so the refusal is
  deterministic. (First verification run flaked: with the pool
  opened first, a loaded box could die on a pool timeout — exit 1 —
  before reaching the key check.)
- New key files (Development only) are created with mode 0600 from
  creation via `OpenOptions::mode`, closing the create-then-chmod
  window.
- Acceptance: `production_profile_fails_closed` (both refusal cases
  exit 2 and create no file; the Development control starts and
  generates the file), `keyfile_load_existing_and_mode`.

## 7. Task 7 — TOTP tidy-ups (AL3)

- Replay: the gate records the accepted code's time step in
  `accounts.totp_last_step`; a code from that step or an older one
  is refused (`TotpReplayed`) at every gate. Replays do not count
  toward the lockout (an observed code is useless to an attacker,
  and the legitimate holder must not lock themselves out by racing
  their own code).
- `totp_confirm` refuses while TOTP is already active
  (`TotpAlreadyActive`) — a pending secret can no longer replace a
  live one; the only path off is `totp_disable`, which itself
  requires a current code and now also clears the replay/lockout
  bookkeeping.
- One deliberate accommodation, documented in the migration and in
  `moderation.rs`: enrollment confirmation does **not** record its
  step in `totp_last_step`. The locked Stage 9 suite confirms
  enrollment with the current code and then presents the *same*
  code at the step-up gate; consuming the step at confirmation
  would fail that suite. The gate is therefore the first consumer
  of a step, and everything from the first gated use onward is
  replay-protected. Flagged for an owner-decision amendment if
  stricter semantics are ever wanted; not a locked-test conflict
  (blind_stage9 passes 43/43 unmodified).
- Acceptance: `totp_gate_replay_and_confirm_while_active`,
  `login_code_cannot_be_replayed`.

## 8. Task 8 — Passphrase change + recovery-code issuance (AL4)

- `POST /account/passphrase`: requires the current passphrase
  (per-account scoped verify), enforces the usual new-passphrase
  policy (≥12 chars, not on the common list), updates the hash,
  revokes every OTHER session (`db::revoke_other_sessions`), keeps
  the current session, and posts an inbox notice.
- `POST /account/recovery-codes` — declared in the route table
  since §17 but never served until now — requires the current
  passphrase, burns every previous unconsumed code and issues a
  fresh one (`db::replace_recovery_code`, one transaction), shows
  it exactly once, and posts a notice.
- Acceptance: `passphrase_change_and_recovery_code_issue` (old
  passphrase fails afterwards, other sessions are revoked, the old
  recovery code is dead and the new one works).

## 9. Password-list provenance (task 4)

`marketplace/crates/app/data/common-passwords-ncsc-100k.txt`,
loaded via `include_str!` in `passwords.rs`:

- Source: `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`
  from the SecLists project (github.com/danielmiessler/SecLists,
  MIT-licensed), which mirrors the UK National Cyber Security
  Centre (NCSC) list of the 100,000 most common passwords, derived
  from the Have I Been Pwned breach corpus.
- Fetched 2026-10-18 via the GitHub API (the raw download had timed
  out in the sandbox; the API git-blob route worked): git blob
  `38eb37702244f55fda75cab281eb2145cd7685b6`; SHA-256 of the file as
  fetched: `c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0`
  (both recorded in the data file's own header).
- Line accounting, re-verified during this pass: 99,855 total
  lines = a 16-line comment header + **99,839 entries reproduced
  verbatim**, in published frequency order (the nominal "100k"
  includes trailing blanks in the source). The loader skips only
  the leading comment block — '#'-leading passwords further down
  survive (this was one of the pre-handoff fixes) — lowercases
  entries, and dedups: the runtime set holds **97,746 distinct**
  case-folded entries.

## 10. Locked-test conflicts

**None.** No file under `marketplace/tests/security/` was modified
(diff-verified), and every locked suite finished at its baseline
count (42/42, 43/43, 32/32, 58+6). The one place locked behaviour
shaped a design choice — enrollment confirmation not consuming the
TOTP step — is §7 above: an accommodation that leaves both the
brief's requirement (codes are single-use at every gate) and the
locked suite intact, documented in code and in migration 0011 for
an owner decision if stricter semantics are wanted.

During verification the locked suites failed *en masse* in one run
— every failure was `PoolTimedOut` on connect, zero assertion
failures: the sandbox service had restarted and wiped /tmp,
killing the user-space Postgres mid-run (§12). Re-provisioned and
re-run clean, they are all green.

## 11. Deviations from the brief (all deliberate, all documented in code)

1. **Lockout scope (task 3).** The brief says lock *moderator
   actions* after ~10 failures; the implementation locks *code
   checking* for the account (one shared gate serves moderator
   actions, disclosure unlock, login and step-up), for a fixed
   15-minute cool-down, refusing even correct codes during it.
   Stricter than the brief, and simpler to reason about.
   *Nuance found in verification and fixed in code:* the
   one-notice-per-episode bookkeeping originally only reset on a
   successful verification, so a second lockout episode with no
   success in between would have sent no notice; an expired lock
   now clears the episode state in the gate.
2. **Login form (task 1).** The handler accepted a `totp` field
   but `templates/login.html` rendered no input for it — an
   enrolled user could never have logged in through the real form.
   Fixed in the template (optional field, labelled as required
   when 2FA is on).
3. **Mandatory enrollment mechanics (task 1).** "Mandatory" is
   enforced functionally (no moderator power and no seller payment
   function is reachable without it) rather than by freezing
   unenrolled accounts outright.
4. **Budget parameters (task 4).** 10 failures / 1-hour window,
   generic error on refusal, no additional failure recorded while
   refused (the window ages out on its own). The failure map cap
   is 4096 entries (the brief says "cap and age out" without
   numbers).
5. **Notices beyond the brief (tasks 2, 8).** Passphrase changes
   and recovery-code issuance also post inbox notices; the brief
   requires notices for the task-2 actions only.
6. **Tor onion-service proof-of-work (AM2's fix line)** is an
   operator/deployment measure with no code surface in this repo;
   it is **not** implemented here and belongs in the operations
   documentation.

## 12. Verification record

- Runs: (a) acceptance suite alone on the inherited tree — 13/14,
  one failure (§13a); (b) a full-workspace run invalidated when
  the sandbox restarted and wiped /tmp (Postgres died mid-run;
  failures were connection errors only); (c) a clean full
  workspace run on a re-provisioned database — every suite green
  except the one acceptance test in §13b; (d) a confirmation run of
  the acceptance suite + the whole security-tests package on the
  final tree — **14/14** and all locked suites at baseline.
- Environment incidents (not product issues): the user-space
  Postgres (Zonky binaries + data under /tmp) was destroyed twice
  by sandbox restarts and re-provisioned from `~/pgsys` both times
  (fresh data directory, `marketplace_dev`, migrations 0001–0011
  applied in order, one file per transaction).
- Final counts (definitive runs c+d): workspace **533 passed /
  0 failed / 9 ignored**; seller-helper **17/17**; account-security
  acceptance **14/14**; blind_direct_v1 42/42; blind_stage9 43/43;
  blind_stage10 32/32; blind_stage4 58/6 ignored.
- Stray runtime artifacts removed: six untracked test-run PNGs
  under `marketplace/tests/security/media/` (the five tracked
  fixture PNGs in that directory are untouched).

## 13. Test-fixture corrections (new suite only — no locked suite touched)

The acceptance suite is new in this change; three of its own
fixtures were wrong and were corrected, each time leaving the
production behaviour and the substantive assertions intact:

a. **Stale order snapshot.** The task-3 test submitted a manual
   payment report and then called `apply_action("dispute")` with
   the pre-report `Order` snapshot (evidence `None`), which the
   domain table correctly denies. Fixed by re-fetching the order
   first — the exact pattern `tx_proof_flow.rs` uses.
b. **Wrong refusal shape.** The same test asserted the no-code
   seller decision returns a redirect (302/303); the handler
   deliberately re-renders the applications page with the refusal
   message (200), the same pattern as the security page's step-up
   refusals. The assertion now checks the 200 + the "Decision
   refused" message — stricter than before. (For the record: two
   earlier distressed-DB runs showed this test green because pool
   timeouts inside `current_session` turned the POST into a 302
   login redirect, accidentally satisfying the original assert;
   on a healthy database the render behaviour is deterministic.)
c. **Cleanup FK.** The suite's `cleanup()` helper enumerated 16
   child tables but not `admission_records`; deleting the approved
   applicant's account violated its FK. Added the missing delete.

## 14. Deliberately not done

- Fix-brief items from the *payment* audit (unrelated brief).
- Server-side signature/proof verification (unchanged, still off).
- Tor onion-service PoW configuration (deployment docs, §11.6).
- Commits are on `main` locally; **not pushed**.
