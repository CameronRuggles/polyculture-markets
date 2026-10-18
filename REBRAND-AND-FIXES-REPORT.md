# Rebrand + demo-review fixes — report

**Date:** 2026-10-17
**Scope:** Apply the decided product name (**Polyculture Markets**,
owner decision 2026-10-17) to the marketplace, fix the three defects
the owner's demo review surfaced (dead image serving, orphaned
moderation surface, missing /admin), and redeploy the GCP demo.
**Status:** All four work items complete; full gate green; demo
redeployed and verified live from outside. Nothing mainnet; nothing
published anywhere else. `marketplace_id` (`vespiary-market`) was not
touched anywhere — it is baked into the signed statement format.

Surfaces and constraints were taken from
`~/workspace/onion-host-os/REBRAND-SCOPE-2026-10-17.md` (marketplace
class (a)/(c) items) and
`~/workspace/onion-host-os/RECIPE-MARKETPLACE-REPORT.md` (media
defect). The session cookie's `SameSite=Strict` was deliberately NOT
changed — that loosening is a separate owner decision still pending.

## 1. Brand default — "Vespiary Market" → "Polyculture Markets" (gated)

The compiled-in default `site_name` (`crates/app/src/config.rs:162`)
is pinned verbatim by the locked suite (`blind_stage10.rs` A8 +
assertion at :186), so the change went through the Q10 review-pack
gate:

- Pack: `NAME-PIN-REVIEW-PACK-2026-10-17.md` (spec context, the
  complete diff, rationale: owner-decided product name, display-only
  default, no behavior change).
- Independent fresh-context review: **APPROVE** (2026-10-17). The
  reviewer traced every `site_name` consumer (config resolution →
  `Nav` → shell `<title>`/brand, home template) and confirmed it is
  display-only — no comparison, signature, ID, persistence, or
  protocol-header use — and confirmed `marketplace_id`, its statement
  format (`payments.rs`), and its pins in `blind_stage10.rs` /
  `blind_direct_v1.rs` are untouched.
- Two reviewer notes, both honoured: (a) the pack's grep arithmetic
  said "exactly six hits"; the correct in-tree count was seven lines
  (the A8 note at `blind_stage10.rs:76` is the seventh — it was
  disclosed in the pack, miscounted in the summary line); a fresh
  grep was re-run immediately before the gated diff was applied, as
  the reviewer advised. (b) The A8 amendment was implemented per the
  approval condition: the original pin text `("Vespiary Market")`
  stays verbatim in the note, with the amendment dated and attributed
  to the owner decision; the assertion at :186 now reads
  `"brief default site name, as amended 2026-10-17"`.
- Applied diff: `config.rs:162` (default), `config.rs:225` (module
  unit test), `blind_stage10.rs:76` (A8 note), `blind_stage10.rs:186`
  (assertion). Deploy/doc display values adopted the name as ordinary
  class-(a) edits: `deploy/env.demo.template:20`,
  `deploy/marketplace-demo.service:2`, `docs/operations.md:23`.

## 2. Media serving fix (web.rs `media_serve`)

The stored-ref check ran its hex test over the whole ref **including
the extension**, whose letters are not hex digits, so
`GET /media/<ref>` 404'd every legitimately stored image on every
platform — while upload, sanitize, storage, and the listing `<img>`
all worked. Fix (minimal, per the recipe report): validate stem and
extension separately — extension must be `png`/`jpg`, stem non-empty
and all hex digits (`rsplit_once('.')`). `messages.rs:184` untouched
(it was already correct — extensionless refs).

**Regression test added:** `crates/app/tests/media_serve_http.rs` —
the first test in the tree that requests `/media/...`. It sanitizes a
real 1×1 PNG through the real media-worker into a temp dir, serves
the real router on an ephemeral port, and fetches the image back over
a real socket (200, `image/png`, byte-identical to the stored file),
plus the refusal cases (non-hex stem, absent ref, wrong extension).
Mutation-proven: with the fix temporarily reverted to the old check
the test **fails**; with the fix it passes. (Follows the
stage1_db.rs convention: requires `DATABASE_URL` + `MEDIA_WORKER`,
skips silently when unset.)

## 3. Moderation nav link (web.rs shell)

`Nav` now carries `role: Option<Role>` (new `session_role()` helper,
same Buyer-default rule the guards use; populated by both `nav_for`
and `nav_for_session`). `shell()` renders
`<a href="/moderation">Moderation</a>` in the main nav for **Admin
and Moderator** sessions only; buyers, sellers, and anonymous
visitors see no change.

## 4. /admin landing page (web.rs)

`GET /admin` was declared ADMIN_ONLY in the authz table (contract §7)
but had no route or handler, so it 404'd for everyone. Added the
route and `admin_page`: it authorizes through the existing table
(`authorize("GET", "/admin", …)`) and renders a small landing page in
the shared shell linking `/moderation`, `/moderation/sellers`, and
`/moderation/accounts`. Anyone who is not an admin — anonymous,
buyer, seller, moderator — gets the identical 404 (`404 "No"`, the
codebase's deliberate-404 convention), so the surface's existence is
not leaked, exactly as before this change.

## Gate

Environment: this sandbox is a fresh VM generation; the local
user-space PostgreSQL was re-provisioned from the Zonky binaries in
`~/pgsys` (data in `/tmp/pgdata`, migrations 0001–0009 applied in glob
order, 32 tables) and builds used the AGENTS.md shims
(`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=~/pkgconfig`). One environment adaptation: no psql
client exists on this generation, so migrations/admin SQL ran through
a scratch sqlx runner kept outside the project tree.

- **Full workspace: 489 passed / 0 failed / 9 ignored.**
- Locked suites named at the gate: `blind_stage10` **32/32** (with
  the amended A8 pin), `blind_stage9` **43/43**. All other blind
  suites also green (stage1 41, stage2 38, stage3 34, stage4 58 +
  6 ignored, stage5 35 + 3 ignored, stage6 83, direct_v1 42), plus
  the new media regression test (1) and the app unit/DB suites.
- **Crypto guard: OK** — sequoia-openpgp resolves to the Nettle
  backend; no RustCrypto backend features.
- The delta over the Stage 10 headline (487) is the new media test
  plus the QR decode-and-compare unit test that landed in the domain
  crate after that report's count.

## Redeploy (GCP demo)

- VM `marketplace-demo` (project `onion-rig`, 34.106.183.33), via
  `deploy/deploy-demo.sh` per DEPLOY-DEMO-RUNBOOK.md. Source copied
  fresh (target/, the dev `marketplace.key`, and dev media excluded —
  upload SHA-256 matched on both ends). Profile `demo`, network
  `stagenet`, loopback bind behind the existing nginx proxy.
- **Database preserved:** pre-deploy `pg_dump` backup on the VM at
  `~/backup-pre-rebrand-2026-10-17.sql` (85,155 B); the deploy applied
  no migrations (all already applied) and dropped nothing. Seeded
  state confirmed intact after deploy (11 accounts, 15 listings).
- Installed env updated: `SITE_NAME=Polyculture Markets` in
  `/etc/marketplace/marketplace.env`. The deploy's DB password was
  read from the installed env file on the VM and never left it.
- **Deployed binary SHA-256:
  `00bcf611f2fce50f19e2edd5ce127dbeb4de7937966ccae25da2af44c60cac41`**
  (`/usr/local/bin/marketplace-app`, printed by the deploy health
  check; service `active`, app answering on loopback).
- The nginx basic-auth gate stays **OFF** (owner removed it
  2026-10-16 for sharing; the gated config backup
  `marketplace-demo.bak-gated` was not touched).

## Live verification (from outside, no basic-auth)

Note: the 2026-10-16 credential files (`/tmp/demo-seed-users.json`,
`/tmp/probe_pw.txt`) did not survive this sandbox's VM replacement,
so verification used three throwaway accounts registered through the
live site (`verify*26`), promoted via the VM database where needed,
and **fully removed afterward** (accounts, sessions, recovery codes,
the listing, its media row, and the stored file) — the demo is back
to exactly its seeded 11 accounts / 15 listings.

- `GET /` → 200; homepage shows **Polyculture Markets**; zero
  occurrences of "Vespiary Market" on the page.
- `GET /listings` → 200 with all 15 seeded listings (data survived).
- **Media end-to-end:** as the throwaway seller — created a listing,
  uploaded a 1×1 PNG (sanitized by the media-worker, 303), published
  it; the public listing page rendered
  `<img src="/media/faf405be30dc074c7deac99d839775db.png">`; an
  unauthenticated `GET` of that URL returned **200, Content-Type
  image/png, `x-content-type-options: nosniff`, a valid 1×1 PNG
  body** (the worker's 71-byte re-encode of the 68-byte upload).
  Before this fix the same request 404'd.
- **Admin:** throwaway admin's homepage nav contains the Moderation
  link; `GET /admin` → **200** with links to `/moderation`,
  `/moderation/sellers`, `/moderation/accounts`.
- **Buyer:** `GET /admin` → **404** (identical-404 preserved); the
  buyer's nav contains no Moderation link.

## Left standing

- `SameSite=Strict` cookie behaviour is unchanged (owner decision
  pending) — link-arrival logins still bounce as documented in the
  demo review.
- The OS-side rebrand surfaces (vespiary.org/onionhost page, ISO
  filename, recipe catalogue names) are Manioc Server work, out of
  this report's scope.
