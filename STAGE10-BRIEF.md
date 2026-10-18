# Stage 10 Brief — Deployment profiles, §15 layout pass, retention jobs, operations

Prepared 2026-10-16 (coordinator), before any Stage 10 code. Governing texts:
spec v2 §15 (interface), §19 (deployment profiles), §20 (retention), §22
(gate discipline), §24 stage 10 ("Retention jobs, deployment profiles,
backups, operations docs — Minimum viable marketplace complete"),
SPEC-V2-AMENDMENTS.md, the PRE-MAINNET-CONFIRMATION-SHEET (owner decisions
2026-10-16), STAGE9-REPORT.md ("what the owner still owes" §3 + honest
deferrals), and Cameron's 2026-10-16 demo decision: once the build is
mostly finished, a hosted live demo (stagenet) with the §15 layout pass
landed, so the owner's manual review covers the real interface. Demo
host: a single small Google Cloud VM (parent runs the actual deploy;
this stage builds the profiles, tooling, and runbook only).

## Scope

### 1. Instance configuration & deployment profiles (`crates/app/src/config.rs`)

One strict resolver replaces the ad-hoc env reads in `main.rs`
(including the silent `INSTANCE_NETWORK` fallback in
`payments.rs::PaymentConfig::from_env`, which today maps *any*
unrecognised value to stagenet and accepts `mainnet` with zero
friction — exactly the accident this stage exists to prevent).

Profiles (spec §19): `development`, `demo`, `production`. The demo
profile is the hosted-stagenet-demo shape of the §19 HTTPS profile;
the production profile is documented shape only — nothing in this
stage flips, defaults, or points anything at mainnet.

Pinned public contract (the blind suite is authored against this):

```rust
// crates/app/src/config.rs
pub enum Profile { Development, Demo, Production }
pub struct InstanceConfig {
    pub profile: Profile,
    pub network: modules_api::Network,
    pub marketplace_id: String,      // default "vespiary-market"
    pub site_name: String,           // default "Vespiary Market"
    pub bind_addr: String,           // default "127.0.0.1:8080", all profiles
    pub dev_cookies: bool,           // true ONLY in Development (see rule R6)
    pub registrations_open: bool,    // default true
    pub source_url: Option<String>,  // SOURCE_URL
    pub version: &'static str,       // env!("CARGO_PKG_VERSION")
}
pub const MAINNET_CONFIRM_VALUE: &str = "I ACCEPT MAINNET REAL FUNDS";
pub enum ConfigError { UnknownProfile(String), UnknownNetwork(String),
    MainnetNotConfirmed, NetworkProfileMismatch, InvalidValue(&'static str) }
impl InstanceConfig {
    pub fn resolve(get: &dyn Fn(&str) -> Option<String>)
        -> Result<InstanceConfig, ConfigError>;
    pub fn from_env() -> Result<InstanceConfig, ConfigError>;
}
```

Rules:
- R1 `DEPLOY_PROFILE`: unset → Development. Exact `development` /
  `demo` / `production` only; anything else → `UnknownProfile`.
  No silent fallback, in either direction.
- R2 `INSTANCE_NETWORK`: unset → Stagenet. `stagenet` → Stagenet,
  `testnet` → Testnet, `mainnet` → Mainnet subject to R3/R4;
  anything else → `UnknownNetwork`. (The old silent mapping of
  garbage → stagenet is removed.)
- R3 Mainnet requires `MAINNET_CONFIRM` exactly equal to
  `MAINNET_CONFIRM_VALUE` — case-sensitive, no trimming. Absent,
  wrong, near-miss (`yes`, `true`, `mainnet`, lower-case variant)
  → `MainnetNotConfirmed`. Friction by design: hard to type by
  accident, impossible to set by a stray `=1`.
- R4 Mainnet is allowed ONLY in the Production profile (→
  `NetworkProfileMismatch` in Development/Demo, even with the
  confirm string). The demo is stagenet by owner decision; a dev
  instance on mainnet is precisely the accident being engineered
  out. Testnet is forbidden in Production (→ `NetworkProfileMismatch`);
  Production+stagenet is allowed (stagenet is the safe direction).
- R5 `BIND_ADDR`: any profile may override; the default is loopback
  in every profile (the app never binds a public interface by
  default; §19 puts a proxy or Tor in front).
- R6 `dev_cookies`: true only when profile = Development AND the
  legacy `PRODUCTION_HTTPS` env var is absent (back-compat with the
  Stage 1 cookie rule). Demo/Production → false (`__Host-` cookies).
- R7 `REGISTRATIONS_OPEN`: unset → true; `1`/`true` → true;
  `0`/`false` → false; anything else → `InvalidValue`.
- R8 `MARKETPLACE_ID` default `vespiary-market` (unchanged value;
  it is baked into signed payment messages and must never drift).
- R9 The network the payments layer runs on comes from
  `InstanceConfig`, never from a second env read:
  `PaymentConfig::from_env(marketplace_id, network)`.
  `PaymentConfig::defaults` is unchanged (locked suites use it).

### 2. §15 layout pass (all server-rendered pages)

Every HTML page is rendered inside ONE shared shell
(`app::web::page` / `shell`): doctype, `<head>` with charset +
viewport + page title + a single inline `<style>` block, a header
(site name; nav — Browse, Orders (n), Messages (n), Sell, Security,
account menu — per §15), `<main>`, and a footer (Policy, Limitations,
Payment risks, Source, Version, Help). §15 visual rules: neutral
background, high-contrast text, ONE accent colour, system font
stack, no animations, no carousels, visible keyboard focus,
responsive layout, semantic HTML, labelled controls.

Invariants:
- L1 No JavaScript anywhere: no `<script>`, no inline event
  handlers, no `javascript:` URLs. (Unchanged from Stages 1–9;
  the layout pass must not introduce any.)
- L2 No external requests: no `http://`/`https://` asset
  references, no CDN, no web fonts, no external stylesheets,
  no `@import`, no external `url(...)`. CSS is the one inline
  `<style>` block from the shell. User content is escaped as
  before, so an `https://` string typed by a user inside listing
  text is data, not an asset reference — the invariant is about
  tags/attributes the shell and templates emit.
- L3 Attention counts (§15: "counts are computed server-side on
  every request"): Messages (n) = unread inbox notifications;
  Orders (n) = orders where it is the viewer's move, matching
  `permitted_actions` obligation states (seller: Requested or
  Paid; buyer: Fulfilled). Counts render only when > 0.
  Anonymous pages render the anonymous nav (Browse, Log in,
  Register) with no counts.
- L4 New public pages required by the §15 footer / page list:
  `/limitations` (§2 limits + this instance's actual profile,
  network, retention values, enabled modules), `/policy`
  (operator acceptable-use template, plainly labelled as the
  operator's to adopt), `/payment-risks` (the honest v1 payment
  story: direct wallet-to-wallet, sellers confirm payment
  themselves, no escrow, no verification, no chargebacks),
  `/security-guide` (threat-model summary + encryption guide +
  verification walkthrough, from docs/), `/help`, `/source`
  (AGPL source availability; links SOURCE_URL when configured).
- L5 All 18 existing Askama templates become body fragments
  rendered through the shell; template variables and form field
  names do not change (locked suites and the smoke depend on
  them). The `/` home route renders through the shell too.
- L6 Stage 9 deferral closed: the moderation queue gains working
  no-JS remove/restore forms for listed listings (endpoints
  already exist and are TOTP-gated).

### 3. Retention jobs (`crates/app/src/retention.rs`)

A general in-process scheduler in `main.rs` (the payments sweep
pattern, generalised) runs `retention::run_retention(pool, cfg)`
on `RETENTION_INTERVAL_SECS` (default 3600). Only the unambiguous
§20 rows are automated in this stage:
- notifications read more than 30 days ago → deleted;
- sessions expired more than 7 days ago → deleted;
- security events older than 30 days → deleted;
- dispute disclosures whose dispute resolved more than 180 days
  ago → payload deleted (the Stage 9 deferral; row handling per
  the disclosures schema — delete the row, the dispute record
  itself is an order record and stays).

Everything else in §20 (order/invoice purge at terminal+180d with
tombstones, message payload windows, report windows, backup-copy
completion) is NOT automated here: it interacts with reputation
facts and counterparty history, and shipping it unreviewed would
be worse than naming it. It is recorded in `docs/unverified.md`
and `docs/operations.md` as not-yet-built. Retention periods are
config (`RetentionConfig`, env-overridable) and the Limitations
page shows the instance's actual values.

### 4. Deploy tooling (`marketplace/deploy/`)

- `deploy-demo.sh` — idempotent: builds the release binary,
  installs binary + systemd unit + env file (only if absent —
  never overwrites an existing env file), creates the app system
  user/dirs, provisions the PostgreSQL role/db, applies
  migrations in glob order, restarts the unit, and health-checks
  `http://127.0.0.1:8080/` until it answers. Re-running it is a
  no-op upgrade. It refuses to run if the env file selects
  mainnet (defense in depth behind R3/R4: the demo tooling is
  stagenet-only).
- `marketplace-demo.service` — systemd unit (dedicated user,
  `EnvironmentFile`, hardening flags, restart on failure).
- `env.demo.template` — every value a placeholder or a stagenet
  default from the PRE-MAINNET sheet (protected areas of the sheet:
  batch/pool 100, low-pool 10, expiry 48h, open-unpaid cap 3,
  rate 10/h, reset warning 30d, sweep 900s; server signature
  check OFF). NO secret-looking values anywhere: DB password and
  key-file path are `CHANGE-ME` placeholders; the file must pass
  the blind suite's secret scan.
- `DEPLOY-DEMO-RUNBOOK.md` — single Google Cloud VM walkthrough:
  sizing (e2-small or better; the always-free e2-micro's 1 GB is
  too small), OS packages, PostgreSQL, running deploy-demo.sh,
  reaching the demo (SSH tunnel primary; TLS reverse proxy
  optional), backup/restore procedure, stopping the VM to park
  cost. Written for copy-paste execution by the parent.
- `docs/operations.md` — the operations manual Stage 9 owed:
  profiles, key-file custody + separate backup, DB backup and
  TESTED restore procedure, log hygiene (no debug logging in
  production; security-event allow-list), retention values and
  what is/isn't automated, release checklist pointer.

### 5. Gate (§22)

- Blind suite `tests/security/blind_stage10.rs`, authored by an
  independent agent from this brief's contract + spec §15/§19/§20
  + amendments ONLY (never the implementation): config/profile
  rules R1–R9 (resolve() via injected env map — no process-env
  races), shell invariants L1/L2 via HTTP on the real router
  (anonymous pages), footer/static page presence, deploy-template
  secret scan, env-template stagenet defaults match the sheet.
- cargo-mutants on `config.rs` (+ shell/nav pure functions if
  separable), survivors triaged honestly.
- Crypto guard (`deploy/check-crypto-backend.sh`) green.
- Live smoke over HTTP incl. the layout (pages carry the shell;
  no script tags in any response body).
- Full workspace green; counts in STAGE10-REPORT.md.

## Out of scope (named, not silently dropped)

- The GCP deploy itself (parent runs it from the runbook).
- Any mainnet configuration, anywhere. Production profile is a
  documented shape; §1 of the pre-mainnet sheet stays unsigned.
- Signed releases / reproducible builds (Stage 9 carry list) —
  the deploy script prints the release binary's SHA-256, but
  the signed-release pipeline is NOT built in this stage and is
  recorded as such in the report and unverified.md.
- The rest of §20 retention (order purge/tombstones) — see §3.
- tx-proof / Stage 8 machinery — unchanged, not part of v1.
