# Stage 5 — Completion Report (ciphertext messaging + envelope validation)

Date: 2026-10-14 · Spec §24 Stage 5 (§14 as amended: Q1, Q5, Q6, Q16)
First stage run under full §22 gate discipline (hybrid-mode decision).

## What exists

- **`crates/envelope`** — the amended §14 validator. The packet walk is a
  hand-rolled top-level header scanner that never descends into
  containers (Q6 by construction): 1–8 PKESKs, exactly one container,
  nothing after it; no SKESK/marker/compressed/literal/signature/padding
  at the top level; no trailing bytes after the armor footer. Containers:
  SEIPD v1, RFC 9580 SEIP v2, LibrePGP AED tag 20 with the Q1 fixed-header
  hand-check (version 1, AES 7/8/9, OCB/EAX, sane chunk octet, salt
  present). Pairing enforced (v3 → SEIPD v1/AED; v6 → SEIPD v2 only;
  mixed rejected). Errors follow the Q16 ordered taxonomy.
  *Design note:* the walk does not use a general OpenPGP parser for
  structure — general parsers fail whole messages on container contents
  they try to interpret (a compressed packet's deflate stream, an
  SEIPD's inner MDC). Sequoia is still used for certificate parsing in
  `KeyRef` (certificate-level subkey matching).
- **Messaging (`app::messages`)** — order-linked and direct
  conversations; ciphertext stored as blob files with minimal DB
  metadata (conversation, sender, recipient, recipient key ID, length,
  received, expiry per §20: 90 days at insert for inquiries; the
  order-terminal+60d refinement is the Stage 10 retention job's).
  Ciphertext is never rendered inline; downloads are participant-only
  `application/octet-stream` attachments with `nosniff` + `no-store`,
  byte-exact (proven live). Compose page has paste + file upload, shows
  the recipient's current fingerprint + key download, and a rotation
  banner when the other party rotated mid-conversation.
- **Key sightings (Q16 prerequisite)** — migration 0006 +
  `conversation_key_sightings` written whenever a participant's key is
  presented in a conversation. `RecipientKeyRetired` is decided from
  sightings plus validity-interval overlap with the conversation —
  never from key history alone.

## Gate results (§22)

- **Blind suite** (`crates/envelope/tests/blind_stage5.rs`, 38 tests,
  authored from the amended §14 + API contract only): **35 passed,
  0 failed, 3 ignored**. The ignored three are v6-PKESK constructions
  the author could not build verifiably with GnuPG 2.4.4 alone
  (documented in-test; v6 acceptance rests on the Stage 0 RFC 9580
  vectors, and item 2a — v6 hidden-recipient fixture — remains open
  in `docs/unverified.md`).
- **Failures found and fixed in the implementation (never the tests):**
  clearsigned messages are `NotEncrypted`, not `Malformed`; a top-level
  compressed packet is `UnsupportedPacket`; >8 PKESKs is
  `UnsupportedPacket` (packet-form violation). The author's recorded
  ambiguities (A1–A6) stand in the test file header; A3's variant
  choice was adopted.
- **One Q7a fixture-construction fix** (owner-visible, assertions
  untouched): the suite's PKESK splitter assumed GnuPG emits new-format
  packet headers; GnuPG actually emits the PKESK with an old-format
  header (0x85), which broke every spliced fixture before the validator
  ran. The splitter now parses both header formats. Diff is marked
  "Q7a CONSTRUCTION FIX" in the test file.
- **cargo-mutants** on `crates/envelope`: 46 mutants — 28 caught,
  14 missed, 4 unviable. Surviving diffs sat in `KeyRef` edge semantics
  and in bit operations inside the packet-header splitter (the blind
  fixtures exercise realistic GnuPG headers, so some mask arithmetic
  went undistinguished). Disposition: the suffix-alias fallback in
  `KeyRef::matches` was **removed** (exact handle membership only — no
  real packet form needs aliases, and containment matching is sloppier
  than the spec's model), and implementer unit tests now pin both the
  short-fingerprint guard and the header forms (old/new format, 1/2/4/
  5-byte lengths, partial + indeterminate + truncated rejection).
  Blind suite re-verified 35/35 after the changes. (Run detail: mutants
  needs `TMPDIR` on the home filesystem — /tmp is a 512 MB tmpfs that
  fills with the copied target dir and kills rustc.)
- **Workspace totals after the stage: 239 passed, 0 failed, 9 ignored**
  (verified 2026-10-14 on the standard port — see correction note).
  Media tests require `MEDIA_WORKER` set to an absolute path when
  invoked.

## Correction note (2026-10-14, later the same day)

The first completion message reported "143/143 green" from a partial
test-run delivery. The full run in fact surfaced 33 failures in the
locked Stage 4 blind suite — every one a database pool timeout: that
suite hardcodes the original dev-database address (localhost:5432,
from the apt-PostgreSQL era) while the replacement user-space server
had been started on port 5433. The server was moved back to the
standard port 5432 (data intact), after which the Stage 4 suite
passes 58/58 and the full workspace is 239 passed / 0 failed. No test
or implementation code was changed for this; it was an environment
address mismatch, and the interim numbers were wrong because a
truncated run output was trusted. The dev-database address is now
uniform: `postgres://postgres@localhost:5432/marketplace_dev`.
- Live smoke: valid dual-recipient GnuPG message accepted + byte-exact
  download; plaintext, wrong-recipient, extra-recipient (key ID shown),
  and hidden-recipient submissions each rejected with the right message
  and nothing stored; unread badge + mark-read working.

## Environment incident (resolved)

A VM replacement broke the system PostgreSQL (apt left unrecoverable:
held locks, uninstallable dependencies). Development now runs on a
user-space PostgreSQL 16.4 (Zonky binaries in `~/pgsys`, data in
`/tmp/pgdata`, user `pguser`) — recorded in AGENTS.md. It briefly ran
on port 5433 and was moved back to the standard 5432 the same day
(see the correction note below).
