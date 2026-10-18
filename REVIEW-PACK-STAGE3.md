# Review Pack — Marketplace Spec v2, Stage 3 (identity keys, rotation, Q16 key history)

**How to use:** paste whole into Claude Opus. This is the §22 stage-gate
review for Stage 3, produced in the 2026-10-13/14 retrofit (the stage was
first built as a working draft; this pack accompanies its gate).
Cameron (owner) makes final calls; your job is verdicts with file:line
evidence.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL, with
   the file and line you relied on. Abstract concern without a mechanism
   doesn't count; name who does what to whom.
2. The code is at `marketplace/crates/app/src/keys.rs` plus migration
   `marketplace/migrations/0006_conversation_key_sightings.sql`. The
   spec is "Privacy-First Noncustodial Marketplace — Spec v2" plus
   `SPEC-V2-AMENDMENTS.md` and the canonical contract
   `marketplace/docs/api-contract.md` (§9 is the Stage 3 surface,
   including the Q16 storage contract). Decisions Q8, Q14, Q16, Q17 are
   in `DECISIONS-LOG-2026-10-13.md`. If you cannot see the files, say so
   and review against the claims and evidence summarized here instead —
   flag that limitation.
3. End with: (a) any test the locked suite must add for Stage 3, stated
   as plain-language assertions; (b) anything that must be fixed before
   Stage 5 (messaging) builds on these key records.

## What was built (claims to check)

Certificate validation via Sequoia on the Nettle backend (Q8 — same
backend in dev, CI, production; guard script enforces it): the cert
must parse (`Malformed`), be valid under the standard policy including
**not expired and not revoked** (`PolicyInvalid`), carry an
encryption-capable subkey (`NoEncryptionSubkey`) and a signing-capable
key (`NoSigningKey`). Two retrofit findings live here: (1) Sequoia's
`with_policy` validates structure/bindings/revocation but NOT liveness —
an expired primary still produced a ValidCert and was accepted until
the blind suite caught it; `validate_cert` now also requires
`valid.alive()`. (2) The suite's first expired-cert fixture never
actually expired its key (gpg reads `--quick-set-expire <fpr> 1` as
DAYS); the fixture was rebuilt under `--faked-system-time` so the cert
is genuinely expired at validation time — construction fix, assertion
unchanged, diff listed in RETROFIT-REPORT.md. The reported fingerprint
is the primary's, uppercase hex; every user ID is surfaced; user IDs
that look like an email address or a real name produce a warning (the
ID will be public). Detached-signature verification is over exact
bytes; any bad signature result fails the whole check. Rotation
statements parse strictly per the §4 canonical rules: fixed field
order `statement-format, marketplace-id, account-id, old-fingerprint,
new-fingerprint, rotated-at`; marketplace-id must equal this instance's
ID; account-id matches the §2/Q15 ID pattern; fingerprints uppercase
hex (40 or 64); canonical timestamp (leap seconds, month 13, CRLF,
tabs, field reorder, missing/double trailing LF all rejected — the
blind suite runs a 16-case mutation battery). Certified rotation
requires both certs' detached signatures over the exact statement
bytes; an uncertified (lost-key) rotation is a distinct recorded state,
reported by `latest_uncertified_rotation` for 90 days, and can never be
presented as certified.

Key storage (§16, Q16): installing a key retires the previous current
key in the same transaction — old row's `retired_at` set, rotation
recorded in `key_rotations` with `certified` true only for the
dual-signed path, new key becomes the single `current` row with the
next version number; full history (version, status, validity interval)
stays queryable. **Owner-flagged Q16 check, answered:** validity
intervals existed in the draft, but *which conversations saw a key* was
recorded nowhere. The retrofit added migration 0006
(`conversation_key_sightings`) plus `record_key_sighting` /
`key_shown_in_conversation`. The probe's semantics, as gated:
`key_shown_in_conversation` answers true only for a conversation the
account participates in, and only via (a) a sighting recorded in THIS
conversation, or (b) the key having been the account's current key at
the moment the conversation was created (validity interval covering
the conversation's start). A key installed after the conversation
began counts solely via a recorded sighting; key history from other
conversations never counts — that is the Q16 leak fix, and the blind
suite probes it directly across two conversations. One genuine
spec-reading fork is recorded for the owner: the contract says the
interval must overlap "the conversation's lifetime" without defining
its end; the gate adopted the conversation-start reading above (the
sighting mechanism covers genuine later presentations), and the
alternative open-ended reading is documented in RETROFIT-REPORT.md.

## Invariants to judge

1. A rotation cannot be certified without control of both keys; an
   uncertified rotation cannot be presented as certified anywhere.
2. At most one `current` key per account at any time; retirement and
   installation are one transaction; history is never rewritten.
3. Expired or revoked certs are rejected at install and at rotation —
   validation has no path that skips the standard policy or liveness.
4. `key_shown_in_conversation` reveals nothing about other
   conversations and nothing about non-participants' keys (Q16).
5. Statement parsing accepts exactly the canonical byte form — no
   normalization, no reordering tolerance, no second timestamp format.
6. The server never sees a private key; validation and verification
   run on the Nettle backend in every environment (Q8).

## Evidence already in hand (retrofit, 2026-10-14)

- Locked blind suite `marketplace/tests/security/blind_stage3.rs`
  (author saw only the spec, amendments, and API contract; all key
  fixtures are constructed with gpg in a temporary GNUPGHOME at test
  time): **34/34 pass** — cert validation 9, detached signatures 5,
  statement-parsing mutation battery 16, DB storage + Q16 sighting
  probes 4.
- The suite initially failed 2 tests, both fixed in code (expired-cert
  liveness; Q16 conversation-start semantics) plus one fixture
  construction fix (the never-expiring gpg fixture, diff in the
  report). No assertion was changed.
- Migration 0006 applied to the dev database; sighting functions
  covered by the suite's two-conversation leak probe.
- Crypto backend guard PASS (Q8). Full workspace suite green (see
  RETROFIT-REPORT.md).
