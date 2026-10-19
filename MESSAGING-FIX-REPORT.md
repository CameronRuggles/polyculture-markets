# Messaging Audit Fix Report — 2026-10-19

Scope: the fix brief (tasks 0–8) of the *Polyculture Markets Messaging
Audit* (audited commit `9943035`; findings MH1, MH2, MM1–MM4, ML1–ML2),
executed on top of the account-security batch (HEAD `250b061`).
Discipline held throughout: test-first (every fix has failing evidence
recorded before the fix), failures fixed in code never in tests, **no
file under `marketplace/tests/security/` was modified**, commits grouped
on `main`, **not pushed** (the parent agent reviews and pushes).

## Final verification (fresh dev DB, `MEDIA_WORKER`/`MEDIA_DIR` set)

- Workspace: **544 passed / 0 failed / 9 ignored** (baseline 533/0/9 —
  the delta is exactly +9 new messaging acceptance tests and +2 new
  envelope unit tests).
- Locked blind suites, all at exact baseline: blind_direct_v1 **42/42**,
  blind_stage9 **43/43**, blind_stage10 **32/32**, blind_stage4 **58
  passed / 6 ignored**, blind_stage5 (envelope) **35 passed / 3
  ignored**; also blind_stage1 41, blind_stage2 38, blind_stage3 34,
  blind_stage6 83 — all green.
- Account-security suite: 14/14. Tx-proof suite: 20/20.
- seller-helper (separate workspace): **17/17**.
- **Locked-test conflicts: none.** No locked file was edited, and no
  locked suite required a behaviour exception (one deliberate
  accommodation to a locked suite's pinned API is documented under
  Task 3 — the library entry point it pins is unchanged; the *web form*
  changed, which is what the audit required).

## Task 0 — Real-client fixtures (brief task 0)

Fixtures live in `marketplace/crates/app/tests/fixtures/gpg/` with a
`README.md` recording provenance. All were produced by the sandbox's
real **GnuPG 2.4.4** in throwaway GNUPGHOMEs (`--pinentry-mode
loopback`, `%no-protection` test keys). **Private keys never entered
the repository** — the fixtures are public certificates and ciphertexts
only (verified by grep: zero files contain private key material), and
the scratch keyrings were discarded with `/tmp`.

Keys (RSA 2048 sign primary + RSA 2048 encryption subkey unless noted):

| Fixture | Fingerprint / notes |
| --- | --- |
| `cert-alice.asc` | `698C2CE6489C747F1458C2BF35C511FEAF38F328` — sender |
| `cert-bob.asc` | `54C8A581E49106123FB5CCBACED0A0143425A8E0` — recipient; disclosure signer |
| `cert-carol-v1.asc` | `346F063F…115BED30` — two encryption subkeys, both valid |
| `cert-carol-v2-revoked-subkey.asc` | same primary; first subkey revoked via `gpg --edit-key` → `revkey` |
| `cert-dave-short-expiry.asc` | whole cert expires **1 day after creation** (created 2026-10-19, expires 2026-10-20 — TIME-BOXED: tests installing it fail after that date; regenerate per the fixtures README) |
| `cert-dave-extended.asc` | same primary, expiry extended to 2028-10-18 (signatures only — see deviation note on `--quick-set-expire` below) |
| `cert-dave-added-subkey.asc` | same primary + an extra encryption subkey (new key material) |

Messages (alice → bob, also encrypted to alice), plaintexts
~300 B / ~2 KB / ~40 KB of seeded-random base64 text (seed 20261018 —
repetitive plaintext compresses away and would hide the packet framing
these fixtures exist to exercise):

- `msg-{300,2k,40k}-{signed,unsigned}.asc`, plus binary
  `msg-2k-signed.gpg` and `msg-300-signed.asc.gpg`.
- Verified with `gpg --list-packets`: the signed messages at every size
  and the 2 KB unsigned use **partial body lengths** on the
  encrypted-data packet (tag 20); the 300 B unsigned uses a definite
  length.

Disclosure fixtures: `msg-disclose-bob-to-alice.asc` (signed+encrypted,
plaintext "Bob here: your widget shipped today, tracking is in the next
message."), `unwrap-bob-signed.asc` (`gpg --unwrap --armor` output;
`gpg --verify` reports a good signature from bob),
`unwrap-bob-unsigned.asc` (literal data only). Key-matching fixture:
`msg-to-carol-subkey1.asc` (encrypted to carol's first subkey only,
made while it was valid).

**Baseline failure evidence** (acceptance suite run against unfixed
code, HEAD `250b061` + tests only): `gnupg_fixtures_accepted_through_http_forms`
failed at "300B unsigned with CRLF endings must be accepted; got 200"
— its LF twin passed first, isolating CRLF as the cause (MH1); the
large/partial-length fixtures failed behind it.

## Task 1 — CRLF normalisation (MH1)

*Failing evidence:* the fixtures test above; also
`crlf_rotation_statement_verifies_as_certified` — a browser-submitted
(CRLF) certified rotation statement was rejected, so only the
uncertified "lost key" path worked from a browser.

*Fix:* two layers. (a) `web::normalize_crlf` at the handler boundary for
every armored input — message paste and file upload, certificate
upload, rotation cert/statement/signatures, disclosure paste
(`"\r\n" → "\n"`, lone `'\r' → "\n"`). (b) The envelope armor parser
itself (`packet_bytes`) now finds the header/body blank line by walking
lines (LF or CRLF) instead of searching for `"\n\n"`, rejecting junk on
the BEGIN line or a non-header line before the separator. The
brief-locked `parse_rotation_statement` in keys.rs is untouched — the
normalisation happens before it is called.

*Files:* `crates/envelope/src/lib.rs`, `crates/app/src/web.rs`.

## Task 2 — Partial body lengths (MH2)

*Failing evidence:* real GnuPG fixtures over ~512 B refused by the
packet scanner, whose comment ("partial lengths are not for complete
messages") is false for GnuPG output; confirmed pre-fix via the
fixtures suite and a Sequoia probe.

*Fix:* `split_packets` rewritten around `read_new_length`. Partial
lengths are accepted **only on the final encrypted-data packet** (tag
18 SEIP / tag 20 AED), accumulated chunk-by-chunk under the existing
64 KiB cap; the packet must end the input; a partial length on a key
packet is still refused; the never-look-inside rule is preserved (the
scanner still reads headers only and hands the assembled body to
Sequoia for recipient matching).

*Correctness note (found during the fix):* the partial chunk size is
`1 << (octet − 224)` per RFC 9580 (worked example: 0xEA → 1024;
identical to Sequoia's `1 << (octet & 0x1F)` over 224..=254). The first
implementation used `−223` and its hand-built unit tests passed
anyway — the error was caught only by walking the real GnuPG fixtures
byte-by-byte (both fixture streams chain exactly to EOF under the
correct formula) and by a Sequoia `PacketParser` probe ([PKESK, PKESK,
AED] parsed cleanly). No EOF leniency was added; strict framing is
correct against real GnuPG output.

*Files:* `crates/envelope/src/lib.rs` (+2 unit tests:
`split_accepts_partial_on_final_data_packet`,
`split_refuses_partial_off_the_data_packet`; one pre-existing
*non-locked* envelope unit test had its stale comment/semantics updated
— its input still errors, now via truncation).

## Task 3 — Disclosure by unwrap (MM1)

*Failing evidence:* baseline disclosure POST with the new single-paste
form was not accepted — the old form demanded plaintext + a *detached*
signature, but marketplace messages are inline-signed, so no detached
signature exists for any real message; a disclosure could never verify.

*Fix:* the dispute page's disclosure form is now a single paste of
`gpg --unwrap --armor` output (the page shows the command). The server
(`keys::extract_unwrapped_message`) runs a streaming Sequoia verifier
against the other party's current certificate and extracts the
plaintext itself: stored bytes are exactly the verified bytes (CRLF
normalised before parsing). A good signature from the discloser's
counterparty → "verified"; unwrapped-but-unsigned, or a signature that
does not check out → stored as an unverified claim (never an error).

*Deviation — deliberate accommodation, flagged for owner decision:*
the library function `disputes::submit_disclosure` (plaintext +
detached signature) is **unchanged**, because the locked blind_stage9
suite pins its exact signature and semantics (detached → "verified",
garbage signature → "unverified_claim" stored, Forbidden, BadState).
The brief's requirement is met where users meet it — the **web form**
is unwrap-only (`disputes::submit_disclosure_unwrapped`) — and the
detached library entry point remains for the locked suite. This is not
a locked-test conflict; it is a scoping choice to surface: retire the
detached path and amend blind_stage9, or keep both.

*Files:* `crates/app/src/keys.rs`, `crates/app/src/disputes.rs`,
`crates/app/src/web.rs`, `templates/dispute.html`.

## Task 4 — Page/guide agreement (MM2)

*Failing evidence:* file-content test — the conversation page's example
command omitted `--sign` while the guide told users to sign and
claimed the page suggested it; the guide also promised 10 MiB
attachments against the code's 64 KiB cap.

*Fix:* page example is now
`gpg --armor --sign --encrypt --recipient THEIRS --recipient YOURS`.
The guide was corrected **down to the code** (the brief's default):
64 KiB per message, with an explicit line that the file-upload form
takes the same messages under the same cap — there is no separate,
larger attachment allowance.

*Files:* `templates/conversation.html`, `docs/encryption-guide.md`.

## Task 5 — Key matching + certificate refresh (MM3)

*Failing evidence:* (a) a message encrypted to carol's *revoked* subkey
was accepted (303) pre-fix — recipient matching collected every key in
the certificate; (b) POST `/account/keys/refresh` → 404 pre-fix —
certificates could never be refreshed (upload refused once a key
exists; rotation refuses the same fingerprint).

*Fix:* `KeyRef::from_cert` is now strict: the certificate is evaluated
under Sequoia's `StandardPolicy`; handles are collected only from
subkeys that are encryption-capable, alive, and not revoked. The old
collect-everything behaviour survives as `from_cert_unfiltered`, used
**only** by `messages::retired_shown` so retired-key detection keeps
working across expiry/refresh-revocation. New
`keys::validate_refresh` + `refresh_certificate`: a same-fingerprint
certificate is accepted only if the full set of key fingerprints and
the UID set are identical (new signatures — revocations, expiry
extensions — yes; new key material → refused in plain language and
pointed at rotation). The refresh form on the security page goes
through the account batch's step-up (passphrase + TOTP) and posts an
inbox notice.

*Files:* `crates/envelope/src/lib.rs`, `crates/app/src/keys.rs`,
`crates/app/src/messages.rs`, `crates/app/src/web.rs`,
`crates/app/src/authz.rs`, `templates/security.html`.

## Task 6 — Message limits + blocking (MM4)

*Failing evidence:* the limits acceptance test **did not compile**
pre-fix (`SendError::{RateLimited, BudgetExceeded, ConversationFull}`
and the `MSG_*` constants did not exist) — itself the baseline: any
account could open a direct conversation with any account and send
unlimited 64 KiB messages.

*Fix:* `messages::send_message` now enforces, in order: block check
(direct conversations only), per-account rate **60 messages/minute**,
per-account **daily byte budget 16 MiB**, per-conversation cap **1,000
messages / 16 MiB**. New `conversation_blocks` table (migration
**0012**): an account can block/unblock direct conversations per
account (block control on the conversation page, block list with
unblock forms on the conversations page); a block in either direction
closes the direct channel (403 on open, refusal on send). Order
conversations can never be blocked. Checks are aggregate-before-insert
(standard race tolerance for a disk-fill bound).

*Deviation:* the brief's testable core (rate + budget + cap + a block
control) is implemented as an explicit per-account block list. A
blanket "no direct conversations from accounts you haven't traded
with" toggle was **not** built — the block list covers the refusal
requirement without changing who may *start* a conversation.

*Files:* `crates/app/src/messages.rs`, `crates/app/src/web.rs`,
`crates/app/src/authz.rs`, `migrations/0012_conversation_blocks.sql`,
`templates/conversation.html`, `templates/conversations.html`.

## Task 7 — Pinned key on order conversations (ML1)

*Failing evidence:* pinned-key assertion in the acceptance suite —
order conversations showed the counterparty's *current* key, and the
change warning depended on a `key_rotations` row existing.

*Fix:* `messages::order_pinned_fingerprint` reads the order's own pin
(seller: `orders.seller_fpr_pinned`; buyer: the identity_keys validity
interval covering `order.created_at`). The conversation page shows
"For this order, X's key was pinned as … when the order was created"
and, whenever the current key differs — independent of any rotation
row — an alert: the pinned fingerprint, the current one, and a warning
that messages encrypted to a different key were not encrypted to the
recipient of this order. (The encryption guide §2 already carried the
"your own keyring is the real check" line ML1 asks for; noted, no doc
change needed there.)

*Files:* `crates/app/src/messages.rs`, `crates/app/src/web.rs`,
`templates/conversation.html`.

## Task 8 — Threat-model corrections (ML2)

`docs/threat-model.md` now tells the truth, post-fix: the wallet-RPC
`validate_address` cross-check is marked **not built** (the server runs
no wallet; an in-process parser validates addresses); TOTP-at-login
and per-action step-up are marked **built** (account-security batch),
while the separate admin/moderator listener is marked **planned, not
built**; per-account throttles are marked **built** (the wired request
throttle plus the messaging rate/budget/caps from Task 6); Tor
proof-of-work is marked a **planned operator-side** measure, not code.

*Files:* `docs/threat-model.md`.

## Acceptance suite

`marketplace/crates/app/tests/messaging_audit.rs` — 9 tests, all
passing: fixture acceptance through the HTTP forms (every fixture × LF
and CRLF, paste + binary/CRLF file upload, padded >64 KiB armor refused
with the cap named), CRLF certified rotation, unwrap disclosure
(verified vs claim), page/guide agreement, revoked-subkey refusal,
refresh (accept new signatures / refuse new key material), rate +
budget + conversation cap, direct-conversation blocking, pinned-key
display + change warning. Baselines for every test were observed
failing pre-fix (recorded above per task).

## Environment notes (stated plainly)

- Mid-verification, the sandbox VM was replaced and `/tmp` wiped,
  killing the user-space Postgres (binaries, datadir). Two background
  workspace runs straddling the wipe reported misleading failures
  (suites scheduled after the wipe had no database). Postgres was
  re-provisioned from `~/pgsys` (fresh cluster, `postgres` role
  recreated, migrations 0001–0012 applied in order — 38 tables) and
  **all final counts above come from foreground runs against that fresh
  database, read from logs on persistent storage**.
- The two `blind_stage2` media failures seen in one interim run were
  environmental (that run lacked `MEDIA_WORKER`/`MEDIA_DIR`); with
  them set, blind_stage2 is 38/38.
- `sq` (Sequoia CLI) is not installed in this sandbox, so the brief's
  optional "sq output" fixture cross-check was not performed; GnuPG
  2.4.4 output plus a Sequoia library probe covered the same ground.
- `gpg --quick-set-expire` silently did not extend expiry in this
  environment; the working method (recorded in the fixtures README) was
  `gpg --edit-key` driven over `--command-fd`.

## Deviations summary

1. Task 3: web form is unwrap-only; the locked-suite-pinned detached
   library function remains (owner decision: retire + amend
   blind_stage9, or keep both).
2. Task 6: block list implements the refusal core; no blanket
   trade-only toggle.
3. Task 4: guide corrected down to the code's 64 KiB (brief's default).
4. One pre-existing non-locked envelope unit test's comment/semantics
   updated (its input still errors).
5. Fixture plaintexts are seeded-random base64 rather than prose —
   required so compression cannot hide partial-length framing.

Nothing in the later media/content/disputes audit's scope was touched
(dispute *resolution* authority, CM3, is that audit's; only the
disclosure *form* changed here, per this brief).
