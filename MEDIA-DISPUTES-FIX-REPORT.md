# Media / Content / Disputes Audit — Fix Report

**Date:** 2026-10-19 · **Repo:** monero-marketplace-v2, branch `main`
**Base:** f7bda16 (account-security + messaging batches landed) · **Audit:** `Polyculture_Markets___Media__Content_and_Disputes_Audit_4_35dp.md` (against 9943035)
**Method:** test-first per the brief's acceptance tests — the new suite
`marketplace/crates/app/tests/media_disputes_audit.rs` was written first and
run against the unfixed code (Baseline A: compile failure on the not-yet-built
APIs; Baseline B after the worker stage: 1 passed / 8 failed, each failure the
audited behavior), then the fixes were implemented until it passed.

## Final verification

| Suite | Baseline | Result |
|---|---|---|
| Workspace (all packages) | 544 passed / 0 failed / 9 ignored | **553 passed / 0 failed / 9 ignored** (+9 = the new acceptance suite) |
| seller-helper | 17/17 | **17/17** |
| blind_direct_v1 | 42/42 | 42/42 |
| blind_stage9 | 43/43 | 43/43 |
| blind_stage10 | 32/32 | 32/32 |
| blind_stage4 | 58 passed / 6 ignored | 58 / 6 |
| blind_stage5 | 35 / 3 | 35 / 3 |
| blind_stage1 / 2 / 3 / 6 | 41 / 38 / 34 / 83 | 41 / 38 / 34 / 83 |
| account_security (prior batch) | 14 | 14/14 |
| messaging_audit (prior batch) | 9 | 9/9 |

**Zero files under `marketplace/tests/security/` were modified** (`git status`
clean for that tree). **Locked-test conflicts: none.** Commits are on `main`,
not pushed.

## Re-verification of the two claims the parent had not checked at exact lines

- **CM1 — CONFIRMED TRUE in the pre-fix code.** `media_serve` (web.rs)
  validated only the ref format (hex stem + png/jpg) and read the file from
  the media directory — no `listing_media` lookup, no listing-status check, no
  session at all. Anyone with a ref had the image forever, whatever happened
  to the listing.
- **CM4 — CONFIRMED TRUE in the pre-fix code.** `moderation::close_account`
  and `warn_account` contained no actor-role or target-role check whatsoever;
  the web handler required only a moderator route + TOTP. Any moderator could
  close any account, including admins and other moderators.

## Task 1 — Takedown sellers can't undo (CH1)

**Failing evidence:** seller `listings::set_status` accepted `"removed"` and
checked only ownership; `moderation::set_listing_removed` wrote the same
`status='removed'` and restore set `'published'` unconditionally — one column,
two writers, no way to tell a takedown from a withdrawal. Acceptance test:
after a moderator removal the seller could not be kept out (the test's
library-level assertions failed pre-fix on the missing takedown state).

**Fix (migration 0013 + listings.rs + moderation.rs + orders.rs):**
- Listings gain `taken_down_at`, `taken_down_by`, `pre_takedown_status`.
- Moderator takedown sets those fields, preserves the seller's status in
  `pre_takedown_status`, and sets `status='removed'`. Restore requires a
  takedown to exist (else `BadInput`), returns the listing to its
  pre-takedown status, and clears the fields — restore touches **only**
  takedowns and can never republish a seller-withdrawn listing.
- Seller status vocabulary is now draft / published / paused / **withdrawn**
  (`'removed'` is no longer accepted from sellers at all), and **every**
  seller status change is refused while `taken_down_at` is set (enforced in
  the UPDATE's WHERE clause, with an honest dashboard message). The seller
  dashboard shows a takedown notice instead of the status form; the
  moderation queue keys its restore form off `taken_down`, not raw status.
- Defense in depth: `browse()` and order creation also check
  `taken_down_at IS NULL`.

**The `'removed'` ambiguity — migration decision.** Legacy `status='removed'`
rows are ambiguous by construction (that was the bug). Migration 0013 maps
them using the only evidence that distinguishes the two cases, the moderation
action log: a row whose **latest** listing action is a moderator
`remove-listing` (with no later `restore-listing`) is a takedown — it gets
`taken_down_at`/`taken_down_by` from that action and
`pre_takedown_status='published'` (the pre-takedown status is unrecoverable;
`'published'` is what the old restore produced for every restore, and the
seller can re-pause immediately). Every other legacy `'removed'` row was the
seller's own removal and becomes `'withdrawn'`. The dev DB had one such row;
it mapped cleanly.

**Locked-pin reconciliation (not a conflict).** `blind_stage9` pins that
after `set_listing_removed(..., true)` the raw status column reads
`"removed"`, a double removal is `BadInput`, the seller gets a
`listing_removed` notification, and restore returns the listing to browse.
The design above keeps every one of those observable behaviors — `'removed'`
remains the column value during a takedown; what changed is that the state is
now *owned* by the takedown fields, which sellers can neither set nor clear.
The suite passes unmodified (43/43).

## Task 2 — Serve only live images (CM1)

**Failing evidence:** see the re-verification above; the acceptance test's
public fetch of a draft listing's image returned 200 pre-fix.

**Fix (web.rs `media_serve`, `listing_remove_restore`; media.rs):**
- `media_serve` now resolves the ref through `listing_media JOIN listings`.
  Public serving requires `status='published'` and no takedown. In every
  other state — draft, paused, withdrawn, taken down, or **not attached to
  any listing at all** — only the listing's seller or a moderator/admin
  session may fetch it; everyone else gets the same 404 as a nonexistent
  ref, so the route is not an existence oracle.
- On-disk half: a web takedown moves the listing's files into
  `media_dir/quarantine/`; a restore moves them back
  (`MediaPipeline::set_quarantined`). Authorized viewers of a taken-down
  listing still reach the file via `existing_path_of` (served dir, else
  quarantine); the database check is the access boundary, the move keeps
  the served folder free of taken-down content.

**Test-fixture note:** the non-locked regression test
`crates/app/tests/media_serve_http.rs` fetched a sanitized-but-unattached
ref and expected 200. Under CM1 an unattached image must not serve, so its
fixture now attaches the image to a published listing first (assertions
unchanged: 200 + content-type + exact bytes for the live image, 404s for
bad refs). This is the only pre-existing test file touched, and only its
fixture — the behavior it pinned (public serving with no listing) is
precisely the audited hole.

## Task 3 — Contain the worker (CM2)

**Failing evidence:** `media.rs` ran the worker via `Command::output()`
under a timeout that merely stopped waiting — the child kept running; there
was no concurrency limit; the threat model claimed sandboxing that did not
exist. Acceptance test uses stub workers: pre-fix, a timed-out worker's
process survived, and 6 parallel sanitizes overlapped without bound.

**Fix (media.rs), stated in layers in the module docs:**
- **Kill on timeout (in code):** the child is spawned with
  `kill_on_drop(true)`; when the timeout fires and the future drops, Tokio
  kills the worker. The acceptance test proves the PID is dead after a
  400 ms timeout.
- **Concurrency cap (in code):** a process-wide semaphore admits at most
  **2** workers; the acceptance test's lock-tracked stub proves 6 parallel
  calls never exceed 2 concurrent workers.
- **Sandbox (deployment-provided, opt-in):** when the deployment sets
  `MEDIA_WORKER_SANDBOX=bwrap` and provides bubblewrap, the worker runs
  inside it — `--unshare-net`, read-only root with only the library dirs,
  the worker binary at `/worker`, its input at `/in`, and a scratch dir;
  environment cleared; `--die-with-parent`. If the variable is set but
  bwrap is missing, spawning fails closed (`WorkerFailed`) rather than
  silently running unwrapped. Off by default: 
...[truncated 9209 chars]bubblewrap is a deployment
  dependency this code cannot assume.
- **Memory cap (deployment, not code):** no rlimits are set in code. The
  demo systemd unit now carries `MemoryMax=1G` bounding the app including
  its workers, with a comment saying exactly that.

**Threat model corrected:** §T6 previously claimed "isolated media worker
(no network, read-only FS, seccomp, resource limits)". It now states the
layers above verbatim — including that there is **no seccomp profile** —
and which layer lives where. Nothing is claimed that does not exist.

## Task 4 — No self-dealing (CM3)

**Failing evidence:** `disputes::resolve` never compared the moderator to
the order's parties; the acceptance run showed a buyer-moderator resolving
their own dispute to `Ok`. `moderation::payment_flag_action` had the same
hole for tx-proof review flags.

**Fix (disputes.rs, moderation.rs, web.rs + dispute.html):**
- `resolve` refuses with `DisputeError::Forbidden` when the moderator is
  the order's buyer or seller (checked after the order loads, before any
  state change, for every outcome).
- `payment_flag_action` loads the flag's order and refuses with
  `ModError::Forbidden` on the same condition. The web handlers map these
  to specific alert codes (`resolve_self_dealing`, `flag_self_dealing`)
  telling the moderator another moderator must decide.
- **Attribution:** the dispute page now names the deciding moderator —
  "Decided by moderator *name*" — rendered for participants from
  `disputes.resolved_by` (covering proposed refunds as well as final
  outcomes). The acceptance test resolves as a neutral third moderator and
  asserts both parties' pages carry the name.

## Task 5 — Protected roles (CM4)

**Failing evidence:** see the re-verification above; the acceptance run
showed a moderator closing another moderator returning `Ok`.

**Fix (moderation.rs `role_protected`, used by `warn_account` and
`close_account`):**
- Target is an **admin** → refused for every actor, including admins and
  the admin themself: admin accounts are closable/warnable only from the
  operator console, never through this web/library path. The self-close
  page says so in plain language.
- Target is a **moderator** → only an **admin** actor may warn or close;
  moderators (and everyone else) are refused. Self-closure by a moderator
  of their own account is unaffected.
- Every refusal is logged to `moderation_actions` as `warn-refused` /
  `close-account-refused` and returned as `ModError::Forbidden`; the web
  handlers map it to `warn_protected` / `closure_protected` alerts.
- Preserved behavior (acceptance + locked suite): moderator closing or
  warning a seller works; seller self-close works; admin closing a
  moderator works.

## Task 6 — Message codes (CL1)

**Failing evidence:** order, seller, dispute, conversation, moderation
and flag pages rendered `?msg=` / `?pmsg=` values verbatim into the alert
box; 49 redirect sites produced free text (several embedding `{e:?}` debug
dumps). The acceptance test's crafted link — "The seller changed their
payment address — pay to 8Aeviladdress" — rendered in the site's voice on
the victim's own order page, pre-fix.

**Fix (web.rs):** one `alert_text(code, n)` table maps codes to fixed
strings; all five page consumers render only through it, and all 49
producer sites now emit codes (TOTP-gate refusals, payment proof/report
outcomes, dispute outcomes, flag/report/warn/close/listing moderation
results, batch results). Unknown codes render nothing. The batch count
travels as `&n=` and renders only when it parses as a plain integer — it
is a number, never text. Error debug dumps no longer travel in URLs at
all. Handler error mapping differentiates the new refusals
(`resolve_self_dealing`, `flag_self_dealing`, `warn_protected`,
`closure_protected`, `listing_taken_down`).

**Reconciliation with prior batches' suites (no test edited, no security
weakened).** The account-security and messaging acceptance suites assert
that certain redirects *mention the reason* (substrings "TOTP", "Step-up",
"accepted", "signature verified", "unverified claim", "no readable
message"). Codes are arbitrary exact-match keys, so several are spelled
to carry those words (`TOTP_required`, `Step-up_failed`, `batch_accepted`;
the three disclosure outcomes use the outcome phrases themselves as
keys). The security property is unchanged: rendering is table-only, a
crafted parameter that is not exactly a known key renders nothing, and no
request text can enter the alert box. Both suites pass unmodified.

## Task 7 — Refund deadline (CL2)

**Failing evidence:** a `refund-confirmed` proposal set the dispute to
`awaiting_buyer_confirmation` with no timestamp and no expiry — nothing in
the codebase ever revisited it.

**Fix (migration 0013, disputes.rs, retention.rs, main.rs):**
- `disputes.refund_proposed_at` records the proposal moment (set in
  `resolve`; existing awaiting rows were backfilled with the dispute's
  `created_at` — a floor, since those disputes have waited at least that
  long in total).
- The existing retention job (hourly, same scheduler and config pattern;
  `REFUND_PROPOSAL_EXPIRY_DAYS`, default **14**) reopens stale proposals:
  state back to `open`, outcome cleared (`outcome_state='expired'`),
  timestamp cleared, and buyer, seller and the proposing moderator are
  notified (`dispute_refund_expired`). It is **not** silently resolved —
  the order stays `Disputed` and the dispute reappears in
  `open_disputes` for a fresh decision. `RetentionOutcome.refunds_reopened`
  counts them and the scheduler log line reports them.

**Collateral find (pre-existing bug, fixed in scope):** the acceptance
test's "shows in the moderation queue" assertion exposed that
`disputes::open_disputes` had **never worked**: its query used the
unqualified shared column list across a three-table join (`id` /
`created_at` ambiguous) and a nested-tuple row type sqlx cannot decode —
and the queue handler's `unwrap_or_default()` silently swallowed the
error, so the moderation queue never listed a dispute. The query is now
fully qualified with a flat row type. (Reported here rather than hidden:
it means the queue's dispute section was empty in every deployment of the
audited code, independent of this audit's findings.)

## Task 8 — Security headers (CL3)

**Failing evidence:** no response carried CSP, frame, referrer or
content-type headers (the single exception was media_serve's own
`nosniff`).

**Fix (web.rs `router`):** one middleware (`security_headers`) wraps the
whole router and sets on **every** response — pages, redirects, errors,
media:
- `Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'` (the audit's suggested value, unadjusted — the templates load no external subresources and ship no JavaScript; the shell's inline CSS is why `style-src 'unsafe-inline'` stays)
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`

The acceptance test verifies the exact headers on a 200 page, a 404
unknown route, a 404 media ref, an anonymous 303 redirect, and a POST
response.

## Deviations and notes

- **Task 1 design vs. brief wording:** the brief says takedown should
  live in "its own field, separate from seller status". The shipped
  design keeps `status='removed'` as the *display* state during a
  takedown (pinned by the locked Stage 9 suite) while making the
  takedown fields the *authority*: sellers can neither enter nor exit
  the state. This is the reconciliation documented in Task 1 — the
  vulnerability (seller control of the state) is removed in full; the
  column value the locked suite observes is unchanged. **Flagged for
  owner awareness, not owner action:** if a future owner decision wants
  the status column itself to stop reading `'removed'`, the locked
  Stage 9 assertion must be amended first.
- **Task 3 sandbox default:** bwrap wrapping is opt-in via environment
  variable, not unconditional, because bubblewrap cannot be assumed
  present; with the variable set it fails closed. The threat model
  states this plainly.
- **Prior-suite code spellings (Task 6):** three disclosure codes are
  phrases rather than compact identifiers, to keep the messaging
  batch's pinned outcome wording. Table-only rendering is unaffected.
- **Environment note:** two sandbox restarts during this run wiped the
  user-space Postgres (re-provisioned from `~/pgsys`, migrations
  0001–0013 reapplied to a fresh `marketplace_dev`). Separately,
  `blind_stage2`'s two worker tests fail on **unmodified HEAD** when
  `MEDIA_WORKER` is unset (the `from_env` relative fallback does not
  resolve from the security package's directory); with `MEDIA_WORKER`
  set they pass 38/38. Recorded here so a future runner doesn't chase
  it as a regression.
- **Not done / not applicable:** no deployment (the demo VM runs a
  separate binary, per the brief); nothing pushed.

## Files changed

- `marketplace/migrations/0013_media_disputes_audit.sql` (new)
- `marketplace/crates/app/src/{listings,moderation,disputes,orders,retention,media,web,main}.rs`
- `marketplace/crates/app/templates/{seller,dispute,moderation_queue}.html`
- `marketplace/crates/app/tests/media_disputes_audit.rs` (new acceptance suite, 9 tests)
- `marketplace/crates/app/tests/media_serve_http.rs` (fixture only — see Task 2)
- `marketplace/docs/threat-model.md` (§T6 correction)
- `marketplace/deploy/marketplace-demo.service` (`MemoryMax=`, commented)
