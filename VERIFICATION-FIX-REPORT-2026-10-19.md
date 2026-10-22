# Fix Verification — Fix Batch Report (2026-10-19)

**Brief:** `Polyculture_Markets___Fix_Verification_Accounts_and_Messaging` (auditor,
Oct 18 2026), final section — 11 tasks, executed in order 1–4, 5–10, 11.
**Base:** HEAD `0bdbdf6` (+2 CI-shakedown commits already in the tree).
**Result:** all 11 tasks complete. Final complete run: **568 passed /
0 failed / 9 ignored** (baseline 554/0/9; +14 new tests), seller-helper
**17/17** (see §12).

Commits (local only — push remains blocked on the `gh auth refresh` workflow
scope, handled outside this batch):

| Task | Commit | Finding |
|---|---|---|
| 1 | `8fe10c0` | V1 login budget |
| 2 | `fa95f41` | V2 step-up on passphrase change / recovery issue |
| 3 | `3c8be87` | V6 step-up failure counting + generic error |
| 4 | `3bfee32` | V5 atomic TOTP gate |
| 5 | `d15e9c1` | V3 recovery clears TOTP + 72 h payment pause |
| 6 | `66a6a86` | V4 disclosure tied to a named message |
| 7 | `701cc48` | V7 refresh stores a merge |
| 8 | `2de16f7` | V8 envelope prefix refused |
| 9 | `f6e3b3d` | V9 storage ceiling / new-account budget / ACCOUNT_CAP |
| 10 | `ea06ec7` | ML2 threat-model T7 corrected |
| 11 | `b763ef4` | Locked-suite amendment pass (TOTP seam + submit_disclosure) |

New acceptance suite: `marketplace/crates/app/tests/verification_fixes.rs`
(10 tests). New migrations: `0014_verification_fixes.sql` (stepup_fail_count),
`0015_disclosure_message_link.sql` (disclosures.message_id,
signature_created_at, message_received_at).

Environment note: the VM had been replaced again — Postgres was re-provisioned
from `~/pgsys` into `/tmp/pgx` (data `/tmp/pgdata`, port 5432, trust), the
`marketplace_dev` database recreated, and migrations 0001–0015 applied.

---

## 1. Task 1 (V1) — login budget rework

**What changed.** `throttle.rs`: failure-map eviction now removes the LOWEST
counts first (oldest within a count) and never evicts an entry at/over the
budget — the flood hole (5,000 fake-username failures pushing the victim out
of the old oldest-first map) is closed; `record_login_failure_counted` returns
the new count. `passwords.rs`: `HashGuard` gained a hash-op counter and a
per-scope guard (`scope_guard` / `verify_guarded`). `keyfile.rs`:
`device_cookie_mac` (HMAC subkey `device-cookie-v1`). `web.rs` login handler
rewritten: account lookup first; a non-authoritative budget pre-check
(skipped for a valid device cookie); the per-username hash lock is then held
across the AUTHORITATIVE budget re-check and the verify; failures are
recorded BEFORE the lock is released; the failure that lands exactly on the
budget posts a `login_budget_tripped` inbox notice. A successful login sets
a signed, HttpOnly, SameSite=Strict device cookie (1 year) alongside the
session cookie; `device_cookie_exempt` requires the cookie's public id to
match the account and the MAC to compare equal in constant time.

**Acceptance test** (`login_budget_burst_flood_and_device_cookie`, ~70 s):
a 150-way parallel wrong-password burst runs **≤ 10 hashes** (hash-op counter
delta; ≥ 1); a stranger with the right passphrase is then refused with **zero**
additional hashes; the `login_budget_tripped` notice exists; 5,000 failures on
non-existent usernames do not evict the victim (still refused); a forged
device cookie (one hex char flipped) exempts nobody; the genuine device-cookie
browser logs in while the budget is spent, and success clears the failures.

## 2. Task 2 (V2) — full step-up for passphrase change and recovery-code issue

Both handlers previously verified the current passphrase by hand and never
asked for a TOTP code. They now call the shared `step_up`; the security
page's two forms gained the TOTP field. **Test**
(`passphrase_change_and_recovery_issue_require_full_stepup`): on an enrolled
account, the right passphrase with NO code changes nothing (stored hash
byte-identical) and issues no code (0 unconsumed recovery codes); with a
code, the change succeeds (new passphrase verifies against the stored hash,
old one does not) and issuance leaves exactly one live code.

## 3. Task 3 (V6) — step-up failures counted; one generic error

Migration 0014 adds `accounts.stepup_fail_count`. `step_up` now takes the
session token; a wrong passphrase increments the counter atomically; at 5
the session in use is revoked (by token hash), the account is notified
(`stepup_session_revoked`), and the counter restarts; success resets it.
Every refusal returns the same `Step-up verification failed.` (the Busy case
excepted). **Test** (`stepup_failures_counted_session_revoked_generic_error`):
wrong-passphrase and wrong-code responses are byte-identical; only
passphrase failures move the counter (1 after one of each); the sixth
attempt after five wrong passphrases is a redirect to `/login`.

## 4. Task 4 (V5) — atomic TOTP counters

`verify_totp_gate` was rewritten: the failure increment is a single
`UPDATE … SET totp_fail_count = totp_fail_count + 1 … RETURNING` guarded
against a live lock; the lock trip is a conditional claim so exactly one
caller owns the episode and posts its single notice; a step is accepted
only through a conditional `UPDATE … WHERE totp_last_step IS NULL OR
totp_last_step < $step` — zero rows is a replay. **Test**
(`totp_gate_counters_and_replay_are_atomic`): 60 concurrent wrong codes
trip the lock (a correct code is then refused as locked), with exactly one
`totp_locked` notice and the counter reset; of two concurrent presentations
of the same valid code exactly one succeeds and one is `TotpReplayed`, and a
sequential third is also a replay.

## 5. Task 5 (V3) — recovery clears TOTP + 72-hour payment pause

**Owner decision 2026-10-19 (Cameron): a recovery code also clears TOTP.**
Implementation in the `recover` handler: after the passphrase reset, if
TOTP was enabled, the enrollment columns are wiped (exactly the
`totp_disable` set: secret, pending, enabled-at, last step, fail count,
lock, notified-at), the recovered page says TOTP was turned off, and an
inbox notice is posted (`security_recovery_totp_cleared`). Decision 4's
pause: the payment-identity handler refuses a CHANGE to an existing
identity while `recovered_at` is within 72 hours (new `pmsg=recovery_pause`
seller-page message). No pre-existing pause mechanism existed; the check
consults `recovered_at` (stamped by `consume_recovery_code`, which also
revokes all sessions) and lives in the web handler — the pinned library
function `payments::set_primary_address` is untouched. **Test**
(`recovery_clears_totp_and_pauses_payment_changes`): after recovery, login
needs no code, `totp_enrolled` is false, the notice exists, a change at
< 72 h is refused (address unchanged), and the same change succeeds after
`recovered_at` is backdated past 72 h.

## 6. Task 6 (V4) — disclosures tied to a chosen conversation message

`submit_disclosure_unwrapped` now takes `message_id`. The named message
must be in the disputed order's own conversation and sent by the other
party (else `BadInput`); `verified` additionally requires the signature —
whose creation time `keys::extract_unwrapped_message` now reports from its
creation subpacket — to have been created within the 24 hours before that
message arrived, and not after it. Migration 0015 stores `message_id`,
`signature_created_at`, `message_received_at`; the dispute page lists the
other party's messages as a select, and renders both times beside each
disclosure. **Test** (`disclosure_verified_only_for_fresh_signature_on_named_message`):
a message that arrived 1 h after its signature verifies; the brief's case —
the same correctly-signed text with the named message arriving **3 days**
after the signature — is stored as `unverified_claim`; a message from a
different conversation and one of the submitter's own messages are refused;
the dispute page shows both times. `messaging_audit`'s disclosure test was
updated to name its messages (arrival derived from the fixture signature
time, +1 h, so the pair never decays).

## 7. Task 7 (V7) — merge on key refresh

`keys::merged_refresh` merges the submission into the stored certificate
with Sequoia `Cert::merge_public`, validates the MERGED result under the
full upload policy, and the refresh handler stores the merge — never the
submission alone. **Test** (`refresh_merges_so_a_stale_copy_cannot_drop_a_revocation`):
carol's stored cert is v2 (subkey 1 revoked); refreshing with the v1 export
through the exact handler chain (validate → merge → store) leaves a message
to subkey 1 refused as `WrongRecipient`. (A message to it was refused
before the refresh too; the assertion that matters is that it still is
after.) `messaging_audit`'s refresh test assertions were updated in the
task-11 pass for merge semantics (stored cert = the validated merge, not
byte-equal to the submission; a refused refresh leaves it untouched).

## 8. Task 8 (V8) — text before the armor BEGIN line refused

`envelope::packet_bytes` now rejects non-whitespace before the BEGIN line
with `EnvelopeError::Malformed`, symmetric with the existing tail rule —
the raw submission is what gets stored as the blob, so a plaintext note
above the armor previously rode into storage. **Test**
(`text_above_the_armor_is_refused_and_nothing_is_stored`): the valid 300 B
fixture with one line of text above it is refused as Malformed, the blob
directory's file count is unchanged, no message row is stored; the clean
fixture still sends.

## 9. Task 9 (V9) — global ceiling, new-account budget, ACCOUNT_CAP

`messages::send_message` (signature unchanged) now also enforces, reading
limits from the environment at send time: a **global daily ceiling**
(default 256 MiB/24 h; `MSG_GLOBAL_DAILY_CEILING_BYTES`), a **free-disk
floor** on the blob volume via statvfs (default 1 GiB;
`MSG_DISK_FLOOR_BYTES`; both refusals are the new `SendError::StorageCeiling`,
rendered as a 503 at both web send sites), and a **1 MiB daily budget** for
accounts under a day old or without a completed order (either side, states
Completed/Resolved) instead of 16 MiB. `InstanceConfig` gained `account_cap`,
parsed strictly from `ACCOUNT_CAP` (junk fails closed with
`ConfigError::InvalidValue`); `main` wires `instance.account_cap` into the
web state, replacing the hard-wired `None`. Cargo.lock gains exactly one
edge (app → libc; libc 0.2 was already locked transitively). **Tests**
(`global_ceiling_new_account_budget_and_registration_cap` + config unit
tests): with the ceiling set low, a fresh account's message is refused at
the ceiling; with ~1.04 MiB of history planted, a further message is
refused at the smaller budget (the full budget would have allowed it);
with cap `Some(0)` registration is refused (403, admission); config tests
pin unset/number/junk/negative handling.

## 10. Task 10 (ML2) — threat model T7 corrected

T7 now describes what is actually built: the global daily storage ceiling,
the blob-volume disk floor, the smaller new-account budget, and the
`ACCOUNT_CAP` registration cap (built, operator-settable, ships unset as a
deliberate default). Tor proof-of-work remains listed as PLANNED. Document
review only, per the brief.

## 11. Task 11 — the locked-suite amendment pass

The batch's only exception to locked-file discipline, bundling two owner
decisions of **2026-10-18** (recorded in the account-security fix report's
outstanding items; both were decided *for* this pass).

### (a) TOTP enrollment-confirmation replay seam closed

- **Code** (`crates/app/src/moderation.rs`, not locked): `totp_confirm` now
  verifies step-exactly (`verify_step`) and records `totp_last_step` in the
  same conditional update that activates the secret; zero rows →
  `TotpReplayed`. The old "locked-suite constraint" doc note was replaced
  with the amendment record.
- **Locked file amended:** `marketplace/tests/security/blind_stage9.rs`,
  test `totp_enrollment_flow_require_totp_and_encrypted_storage`.
  *Before:* confirm with the current code, then present THE SAME code at
  `require_totp` and expect success ("the gate is the first consumer").
  *After:* the original flow is preserved in an amendment comment; the same
  code at the gate now asserts `ModError::TotpReplayed`, and the gate pass
  uses the next step's code (`now_secs() + 30`, always inside the ±1-step
  window). Test count unchanged (43).
- **Non-locked fallout:** `enroll()` helpers in
  `crates/app/tests/account_security.rs` (with its stale NOTE rewritten) and
  `crates/app/tests/media_disputes_audit.rs` now confirm with the previous
  step's code, leaving step 0 fresh. Acceptance (this batch's suite,
  `enrollment_confirm_consumes_its_step`): after confirmation, the same
  code at `verify_totp_gate` is `TotpReplayed`; the next step works.

### (b) Library detached-signature disclosure retired

- **Code** (`crates/app/src/disputes.rs`, not locked):
  `disputes::submit_disclosure` deleted (with its now-dead `normalize`
  helper); a retirement note sits where it was. `verify_detached` remains —
  key rotation still uses it. Nothing in the product called the retired
  function (the web layer has used the unwrap path since MM1).
- **Locked file amended:** `marketplace/tests/security/blind_stage9.rs` —
  `disclosure_fixture` gains the order conversation and a
  `plant_order_message` helper; `GpgHome` gains
  `sign_inline_armored`/`store_armored` (and loses the then-unused
  `sign_detached`). The three disclosure tests were rewritten through
  `submit_disclosure_unwrapped`, each carrying an amendment comment with
  the original text's substance:
  - `disclosure_signed_by_other_party_is_verified_and_stored_encrypted` —
    same scenario and assertions (verified status, decrypted display,
    ciphertext at rest), paste now a runtime inline-signed message
    naming a planted message (arrival = signature + 1 h).
  - `disclosure_self_signed_or_garbage_is_an_unverified_claim` —
    self-signed → claim (unchanged expectation); unsigned literal →
    claim (the garbage-signature position); **one expectation changed,
    asserted explicitly**: an unreadable paste is refused (`BadInput`)
    rather than stored — the unwrap form's semantics since MM1; the
    detached form's store-anything behavior has no counterpart.
  - `disclosure_nonparticipant_forbidden_and_resolved_dispute_bad_state` —
    same two refusals (`Forbidden`, `BadState`) through the new path.
- **Non-locked fallout:** `account_security.rs`'s moderator-unlock test
  planted its marker disclosure through the retired function; it now
  inserts the disclosures row directly with keyfile-encrypted
  `{"message": …, "signature": "unwrap"}` JSON — all it ever needed.
  `messaging_audit.rs`'s refresh assertions updated for V7 (see §7).

### Locked-path proof

SHA-256 manifests over `marketplace/tests/security/**` (recursive) +
`marketplace/docs/invariants.md` were taken before the batch and after.
**17 files; 16 identical; the only difference is
`tests/security/blind_stage9.rs`** (the task-11 amendments above):

- pre:  `1a791f8c10c473a2507582ffc48c4b57d3f9f5ac8974b5fffd3eb15e7cc6b7a5`
- post: `2a98fa392cef762b7bc5dbb86d480574d23fe8c936fc55dc9915cf067eceb400`

The spec was not touched. The untracked repo-root
`OWNER-DECISIONS-2026-10-18-EVENING.md` was left untracked and untouched.

## 12. Final verification

One complete run of the whole workspace plus seller-helper, standard
environment (`DATABASE_URL`, `MEDIA_WORKER`, `MEDIA_DIR`, `BLOB_DIR`,
disk-backed `TMPDIR`, nettle shims), nothing else running:

**Workspace: 568 passed / 0 failed / 9 ignored** (exit 0), against the
pre-batch baseline of 554 / 0 / 9 — the +14 are this batch's new tests
(10 in `verification_fixes`, 3 new app-lib unit tests in task 1, 1 config
unit test in task 9). Ignored unchanged at 9 (blind_stage4's 6 +
blind_stage5's 3). **Seller-helper: 17/17** (16 lib + 1 CLI), exit 0.

Per-suite, all blind suites exactly at baseline: blind_direct_v1 42,
blind_stage1 41, blind_stage2 38, blind_stage3 34, blind_stage4 58/6
ignored, blind_stage5 35/0/3, blind_stage6 83, **blind_stage9 43 (with
the task-11 amendments)**, blind_stage10 32. Acceptance suites:
account_security 14, messaging_audit 9, media_disputes_audit 9,
dispute_signature 1, verification_fixes 10; app lib 52 (48 baseline +
4 new units).

Notes on runs during the batch: the task-6 development cycle hit one
environmental failure class worth recording — the full-run environment
requires `MEDIA_WORKER`/`MEDIA_DIR` to be set, or two `blind_stage2` media
tests fail for environment reasons only (documented in AGENTS.md practice);
all final numbers here are from runs with the complete environment. The
cert-dave-short-expiry fixture (expiry 2026-10-20) did not expire during
the batch; no assertion was edited for it.

One tooling incident, recorded for honesty: an edit payload in task 2
containing a struct-field declaration for the recovery form was written
to disk with the field type replaced by the literal text `<redacted>`
(a redaction filter in the tooling). It was caught by the compiler,
verified to be the only occurrence in the tree, and repaired before
anything was committed on top of it.
