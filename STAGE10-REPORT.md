# Stage 10 report — deployment profiles, the §15 layout pass, retention, demo deploy

**Date:** 2026-10-16 · **Stage:** 10 of spec v2 §24 (deployment,
caching/proxy profile, operations) + the owner's demo decision of
2026-10-16 (a hosted live stagenet demo with the §15 HTML/CSS layout
pass landing in this stage, reviewed manually by the owner)
**Brief:** `STAGE10-BRIEF.md` · **Verdict: GATE PASSED** (see §3;
the cargo-mutants triage is §3.3)

Baselines, both re-established before changing code in this session:
full workspace at stage start **445 passed / 0 failed / 9 ignored**
(identical to the Stage 9 designated run); crypto guard **OK
(Nettle)**. Stage-start tree state was recorded in the brief §2,
including two harness facts the gate depends on: media tests need
`MEDIA_WORKER`/`MEDIA_DIR` set (documented since the retrofit
report), and the test invocation must not share the dev database
with another test driver (see §4).

No locked test was changed, weakened, or deleted. The one manifest
edit near the suites is implementer scaffolding in
`tests/security/Cargo.toml` (the tower/axum/http-body-util deps the
brief promised the author; versions taken from the workspace lock:
axum 0.8, tower 0.5.3, http-body-util 0.1.5). Migrations 0001–0009
are untouched; Stage 10 adds **no migration** — the retention
deletions run against existing columns.

---

## 1. What was built

### 1.1 Deployment profiles & instance configuration (§24 stage 10)

New module `crates/app/src/config.rs` (unit-tested, mutant-tested —
§3.3). The whole instance configuration resolves **once, at
startup, and fails closed**: unknown profile, unknown network, or
unconfirmed mainnet → the process prints the reason and exits 2.

- **Profiles**: `development` (default), `demo`, `production`.
  Sessions use the plain cookie only in development without
  `PRODUCTION_HTTPS`; demo/production get the `__Host-` Secure
  cookie — §19's two cache/session profiles.
- **Networks**: `stagenet` default; `testnet`; `mainnet` accepted
  **only** in the production profile **and** with the exact
  `MAINNET_CONFIRM` sentence (`I ACCEPT MAINNET REAL FUNDS`,
  case-sensitive, untrimmed). Mainnet in development/demo is
  refused even with the sentence; testnet is refused in
  production. Garbage values error — the previous code silently
  fell back to stagenet on an unrecognized `INSTANCE_NETWORK`;
  that fallback is deleted.
- `PaymentConfig::from_env` no longer reads `INSTANCE_NETWORK`
  itself; it takes the network from the resolved `InstanceConfig`
  (one resolver, one source of truth). Its numeric defaults are
  unchanged (locked suites construct it directly).
- Every other instance value resolves here too: marketplace ID
  (default `vespiary-market`), site name, bind address (default
  `127.0.0.1:8080` in every profile), registrations open/closed
  (strictly parsed), optional `SOURCE_URL`.
- The session-cookie flag now comes from the profile (the Stage 1
  `PRODUCTION_HTTPS` opt-in still forces Secure cookies in
  development; locked Stage 1 harness expectation preserved).

### 1.2 The §15 layout pass (the demo's review surface)

One shared page shell now frames **every** HTML page the server
renders (`shell()` in web.rs): doctype, charset, viewport, a single
inline `<style>` block (~90 lines: readable measure, system fonts,
one accent colour, visible focus, `role=alert`/`role=status`
treatment, card list, forms, tables, a small-screen media query),
a header with the site name, network label and navigation, and a
footer with **Policy · Limitations · Payment risks · Source ·
Help**, the software **Version**, and a "Network: stagenet · No
JavaScript, no trackers, no external requests" line.
**No JavaScript, no external assets, no web fonts, no CDN** —
pages make zero subresource requests. CSP unchanged
(`script-src 'none'` etc. from Stage 1).

- All 18 pre-existing templates became body fragments rendered
  inside the shell (variables, field names, and copy unchanged;
  titles preserved as page `<title>`s). The bare-HTML home page and
  the ad-hoc notice page went through the shell too.
- **Nav with counts (§15)**: Orders (n) counts open obligations for
  the signed-in account (seller: Requested/Paid awaiting action;
  buyer: Fulfilled awaiting completion), Messages (n) counts
  unread message notifications, Inbox (n) counts unread inbox
  notifications. Counts render only when > 0.
- **New public pages** (§15's checklist): `/` (real home page with
  the demo/stagenet banner), `/limitations`, `/policy`,
  `/payment-risks`, `/security-guide`, `/help`, `/source`.
  - *Limitations* shows the **instance's actual values**: profile,
    network, marketplace ID, version, registration state, and the
    retention periods the running configuration will apply
    (§15/§20: "actual values shown to users — not defaults"), plus
    the §2 does-not-protect list and an honest not-yet-implemented
    note for order purging.
  - *Payment risks* states plainly: direct wallet-to-wallet
    payments, **no escrow**, the marketplace cannot refund or
    reverse, "seller confirmed payment" is an attestation not a
    verification, and the verify-before-you-pay steps.
  - *Security guide* distils `docs/threat-model.md` and
    `docs/encryption-guide.md` (key pinning, sign-then-encrypt,
    invoice/pool verification walkthrough, disclosure rules).
  - *Policy* is the operator AUP template, labelled as the
    operator's to adopt, and states the closure-not-banning
    enforcement model honestly.
  - *Source* carries the AGPL source offer; it links `SOURCE_URL`
    when the operator configures one.
- **Stage 9 deferral closed (L6)**: the moderation queue gained a
  listing lookup (by public ID) with **remove/restore forms**
  posting to the Stage 9 TOTP-gated endpoints.
- Seller dashboard: persistent **pool low-water footer**
  (`role="alert"`) when unused pool entries are at/below
  `PAYMENTS_LOW_POOL_THRESHOLD`, complementing the one-shot inbox
  notification that fires when an assignment crosses the threshold.

### 1.3 Retention jobs (§20, the automatable subset)

New module `crates/app/src/retention.rs`: an in-process scheduler
(hourly default) runs four deletion passes with **database-computed
cutoffs** (single clock — the §20/`unverified.md` item 10 clock
question, now addressed):

| Data | Rule |
|---|---|
| Read notifications | deleted 30 d after being read (unread never deleted) |
| Sessions | deleted 7 d after expiry |
| Security events | deleted after 30 d |
| Dispute disclosures | deleted 180 d after the dispute resolves |

Periods are env-configurable; the disclosure period follows the
Stage 9 config — the exact value the dispute page states to users
(single source). The rest of §20 (order/invoice/message/report
windows) is **not** automated: it interacts with reputation facts
and counterparty history, and is recorded as open in
`docs/unverified.md` item 11 and disclosed on the Limitations
page rather than silently claimed.

### 1.4 Demo deploy tooling (`marketplace/deploy/`)

- `env.demo.template` — the demo instance env file: demo profile,
  stagenet, the owner-accepted Direct Payments defaults
  (batch 100, pool cap 100, low-pool alert 10, unpaid expiry 48 h,
  open-unpaid cap 3, order rate 10/h, reset warning 30 d, sweep
  900 s, server signature check off — v1 has no verifier), retention
  values, and **CHANGE-ME placeholders for every secret** (no real
  credential anywhere in the template).
- `marketplace-demo.service` — systemd unit: dedicated
  `marketplace` user, `EnvironmentFile`, restart-on-failure,
  hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`, state-dir-only writes).
- `deploy-demo.sh` — idempotent POSIX sh deploy: **refuses if the
  env file selects mainnet or the production profile**; builds the
  release binaries (`marketplace-app` — the app binary got an
  explicit `[[bin]]` name — and `media-worker`); creates user/dirs;
  installs binaries + unit; installs the env file **only if
  absent**; provisions the PostgreSQL role/db; applies migrations
  in glob order, each at most once (marker table); restarts and
  health-checks `http://127.0.0.1:8080/`; prints the deployed
  binary's SHA-256.
- `DEPLOY-DEMO-RUNBOOK.md` — the single-VM Google Cloud
  walkthrough (e2-small or better; e2-micro's 1 GB judged too
  small for app + Postgres), packages, deploy, SSH-tunnel access
  (TLS proxy optional), backup + restore procedure, cost parking,
  teardown. **The deploy itself was not run** — it is the parent
  task, per the stage's constraints.
- `marketplace/docs/operations.md` — **the operations manual Stage
  9 deferred**: profiles and the fail-closed config table, key-file
  custody and backup separation, database backup/restore procedure
  (drilled at this gate, §3.4), retention values and what is not
  automated, logging, upgrades, and the per-release checklist
  including the unsigned mainnet flip.

### 1.5 Files

New: `crates/app/src/config.rs`, `crates/app/src/retention.rs`,
templates `home/limitations/policy/payment_risks/security_guide/
help/source.html`, `deploy/{deploy-demo.sh, marketplace-demo.service,
env.demo.template, DEPLOY-DEMO-RUNBOOK.md}`, `docs/operations.md`.
Changed: `crates/app/src/{main,web,payments,lib}.rs`,
`crates/app/Cargo.toml` (binary name), all 18 existing templates
(fragment conversion; moderation_queue gained the listing section),
`docs/unverified.md` (items 10–12), `tests/security/Cargo.toml`
(scaffolding deps), `tests/security/blind_stage10.rs` (blind
author). Nothing else. No migration.

---

## 2. Owner decisions applied in this stage

- Demo staging + layout pass land in Stage 10 (owner, 2026-10-16):
  the pass covers every server-rendered page so the demo review is
  over the real interface.
- Handoff settings accepted with current defaults (owner-delegated,
  2026-10-16): the demo env template carries exactly those values.
- FCMP++ retest parked (owner, 2026-10-16): not a pre-mainnet
  blocker; nothing in Stage 10 depends on it.
- Mainnet flip NOT executed and not signable by this stage: section
  1 of the pre-mainnet sheet remains the owner's separate launch
  decision. Stage 10's production profile is shape + documentation;
  the demo tooling refuses mainnet independently of the binary's
  own refusal.

---

## 3. Gate evidence (§22)

### 3.1 Blind suite — `tests/security/blind_stage10.rs`

Authored by an independent subagent that never read `config.rs`,
`web.rs`, `retention.rs`, `main.rs`, the templates, or
`payments.rs` internals; it worked from `STAGE10-BRIEF.md`, the
spec text (§15/§19/§20/§22/§24), the amendments, the pre-mainnet
sheet, prior blind suites' fixture conventions, and the API
contract. The brief shipped before implementation and pinned the
contract the author tested against (config API + rules R1–R9,
layout invariants L1–L6, retention scope, deploy artifacts as
file-content contract surfaces).

**32 tests: profile truth table through an injected environment**
(defaults resolve to development/stagenet/`vespiary-market`;
mainnet accepted only in production + the exact confirmation —
near-miss confirmations `"yes"`, `"true"`, `"1"`, lowercased,
trailing space all fail; demo/development + mainnet refused even
with the exact sentence; testnet-in-production refused; bind stays
loopback in every profile; registration flag strictness; dev-cookie
rule preserved), **retention against a backdated database** (old
read notifications/sessions/security events/resolved-dispute
disclosures deleted; **unread notifications and unresolved-dispute
disclosures kept**), **anonymous HTTP through the real router**
(200s plus shell invariants on all ten public pages; the forbidden
set — script/link tags, external `src`/`href`, `@import`,
`javascript:`, inline handlers — absent from every response;
`/limitations` names the running network; `/payment-risks` states
no escrow), and **file-content scans of the deploy artifacts**
(stagenet/demo pinned in the template, sheet defaults present, no
mainnet line, password fields are placeholders, no 64-hex strings;
deploy script has `set -e` and a mainnet refusal; unit uses
`EnvironmentFile`; runbook covers backup and restore; templates
contain no script/link/external references).

**Coordinator's run: 32 passed, 0 failed** (inside the workspace
run, §3.2). The suite is locked as authored. One scaffolding note:
the workspace lock pins http-body-util **0.1.5**, not 0.2 — the
scaffolding dependency line in `tests/security/Cargo.toml` carries
that version, and the suite as authored compiles and passes
against it.

### 3.2 Workspace

**487 passed, 0 failed, 9 ignored** (23 suites; exit 0), against
the 445-passed stage-start baseline: +10 implementer unit tests
(config truth table, retention config), +32 blind Stage 10. All
prior locked suites green unchanged: blind_stage1–6, 9,
blind_direct_v1, api-contract, app integration (payments_db,
stage1_db), seller-helper, domain, envelope, modules-api.

### 3.3 Mutation testing (cargo-mutants, this stage's new code)

`cargo mutants -p app --file crates/app/src/config.rs --file
crates/app/src/retention.rs`, app-package tests as the test
command, output at `mutants-stage10/run1`: **45 mutants in 23 min —
31 caught, 10 missed, 4 unviable.**

Triage of the 10 missed — the pattern matters more than the count.
cargo-mutants' test command here is the **app package only**; the
blind suite lives in the separate `security-tests` package and is
not part of that command. Seven of the ten are missed *only*
relative to the app-package tests and are pinned by the blind
suite (green in the same gate run, §3.1–3.2):

- delete the `"stagenet"` match arm in `resolve` — the blind
  suite's explicit-stagenet case resolves it to Ok(Stagenet).
- The empty-string guard mutants (×3: `MARKETPLACE_ID`
  guard→false, `MARKETPLACE_ID` delete-`!`, `BIND_ADDR`
  guard→true) — the blind truth table sets a marketplace-ID
  override and asserts empty-string `MARKETPLACE_ID`/`BIND_ADDR`
  each yield `InvalidValue`.
- `InstanceConfig::network_name` → `""` / `"xyzzy"` (×2) — the
  blind HTTP tests assert `/limitations` names the running network
  ("stagenet"), a value rendered from this method.
- `run_retention` → `Ok(Default::default())` — the blind retention
  tests call `run_retention` against backdated fixtures and assert
  exact remaining row counts; a no-op body fails them.

The remaining three are **genuine survivors, cosmetic class**:
`Profile::as_str` → `""`/`"xyzzy"` (the profile's display label on
the Limitations page; the security-relevant enum value is fully
pinned, its label string is asserted nowhere) and the
`ConfigError` `Display` body (operator-facing message text; the
refusal behavior and exit code are pinned by the unit tests, the
blind suite, and the smoke's refusal matrix). Same accepted class
as prior stages' string survivors; recorded here rather than
silently absorbed. If the owner wants them dead, three one-line
assertions in the config unit tests suffice — a test addition to
my own (unlocked) tests, noted as an available follow-up, not a
gate blocker.

### 3.4 Live smoke (coordinator-run, dev server on loopback)

`/tmp/stage10-smoke.sh` against the debug binary, **24 checks
passed, 0 failed**: the startup refusal matrix (demo+mainnet with
the exact sentence, production+mainnet without/with-lowercased
confirmation, production+testnet, bogus network, bogus profile —
all exit 2 with the config error printed); all ten anonymous pages
return 200 carrying the shell (doctype, viewport, style block,
footer links, version) with no script/link markup; `/limitations`
names the running profile + stagenet; `/payment-risks` states no
escrow; home shows the stagenet demonstration banner; a real
register → session → account flow renders the shelled account page
with the counted nav. (Two early smoke failures were smoke-script
bugs — a wrong form field name and a wrong copy grep — fixed in
the script; the app was not at fault. The seller low-pool footer
is covered by compilation and the full suite (the handler field is
computed from the same threshold the order flow uses), but was not
separately exercised with a seeded low pool in this smoke — a
dedicated seeded-pool smoke is a reasonable future addition, not
a gate claim made here.)

### 3.5 Backup/restore drill (operations.md §3, executed)

`pg_dump` of the dev database (436 accounts of test data) →
restore into a scratch database → **32 tables and 436 accounts,
counts identical**; scratch database dropped. The runbook's
procedure is therefore drilled, not just written. (The Stage 10
brief pre-authorized naming this environment-deferred if no
pg_dump existed; `/usr/bin/pg_dump` is present in this VM
generation, so it was run for real.)

### 3.6 Crypto guard

`OK: sequoia-openpgp resolves to the Nettle backend; no RustCrypto
backend features enabled` (with the ~/pkgconfig + ~/pgsys shims,
§4). Re-run after the last code change.

---

## 4. Environment findings (this VM generation)

- **The gate invocation matters.** Two harness facts, both
  pre-existing and now recorded in the brief: media tests need
  `MEDIA_WORKER`/`MEDIA_DIR` (retrofit report item 8), and test
  drivers must not share `marketplace_dev` concurrently. My first
  two full runs violated one each (a grep pipeline also masked the
  first run's exit code — the counts in §3.2 come from a single
  clean run on a freshly reset database with the full harness env,
  and the suite list was reconciled arithmetically: 445 + 10 + 32
  = 487).
- **A leftover Stage 9 cargo-mutants chain** (started 19:00 by the
  Stage 9 session, on batches the Stage 9 report already records as
  restart-killed) was still running and sharing the dev database;
  it explained cross-run contamination (fixed test addresses
  colliding). I terminated the chain (PIDs in the session record)
  before the clean gate run. Stage 9's reported results are
  unaffected — its designated run predates this.
- Nettle has no system headers/.pc files in this generation: builds
  use `PKG_CONFIG_PATH=~/pkgconfig` (hand-written nettle.pc/
  hogweed.pc) and `NETTLE_PREGENERATED_BINDINGS=~/pgsys/
  nettle-bindings.rs` (the complete prior bindings file, containing
  `nettle_version_major`), the recipe recorded in AGENTS.md
  2026-10-16. Builds/tests used exactly that plus `DATABASE_URL`,
  `MEDIA_WORKER`, `MEDIA_DIR`.
- Rust builds need cargo from `~/.cargo/bin` (not on default PATH).

## 5. What is NOT done / honest deferrals

1. **The GCP demo deploy itself** — the parent's task, per the
   stage's constraints. The runbook + script are gate-tested as
   artifacts (file scans + shell review), not by execution against
   a VM.
2. **The rest of §20 retention** (order/invoice/terms purge with
   tombstones, message-payload and report windows, backup-copy
   completion) — open, `docs/unverified.md` item 11, disclosed on
   the Limitations page.
3. **Signed releases / reproducible builds** (§25) — the deploy
   script prints the binary SHA-256; no signing pipeline exists.
   `docs/unverified.md` item 12. Helper-binary checksums remain a
   release-time step for the same reason (computed on the final
   release build, never invented).
4. **Mainnet** — profile shape only. The flip needs the owner's
   section-1 sign-off, operator legal review, and a GPG usability
   test with a real user (all standing, from the missing-questions
   register); nothing here pre-empts them.
5. **Owner's manual demo review** — the point of the demo profile:
   Cameron clicks through the hosted instance and decides on
   issues. Visual polish beyond the §15 coherence pass (type,
   spacing, nav, mobile) is his feedback loop, not this gate's
   claim.

## 6. Recommendation

Stage 10 gate: **PASS**. Stages 0–10 (the spec's MVP) are now all
built and gated; what remains to a public instance is owner-side
(the demo deploy + review pass, the mainnet sign-off, legal
review, the GPG usability test) and the recorded extension scope
(stages 11–13) plus `docs/unverified.md` items 1, 5, 9, 11, 12.
