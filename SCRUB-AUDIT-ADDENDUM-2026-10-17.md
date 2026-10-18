# Scrub audit ADDENDUM — 2026-10-17 (post-Stage-10, post-rebrand)

Supplements `REVIEW-BUNDLE-SCRUB-AUDIT-2026-10-16.md`. That audit was
run ~2026-10-16 16:30 UTC, mid-Stage-9. Since then the tree gained the
Stage 10 deploy machinery, the demo deploy, and the 2026-10-17
rebrand/fix batch (489 tests green, demo redeployed). This addendum
re-scans what changed. **Nothing has been published; no git repo exists
yet; this is preparation for the GitHub push that still waits only on
Cameron's GitHub sign-in.**

## New MUST-EXCLUDE items (not in the Oct 16 list)

1. **`marketplace/marketplace.key`** — NEW since the audit. 64-byte
   ASCII key file, mode 600, created 2026-10-16 20:17 UTC in the
   marketplace tree root (the app's dev key file; `env.demo.template`
   points `KEY_FILE_PATH` at this name). The rebrand deploy already
   excluded it from the VM upload. It must never enter a repo or a
   review bundle. Add `*.key` and `marketplace.key` to `.gitignore`.
2. **`DEMO-DEPLOY-REPORT.md`** (project root) — contains the demo's
   basic-auth password **in plaintext** (line ~44: "this report is the
   only place this password is recorded") plus the demo VM's raw IP.
   The gate is currently OFF at Cameron's direction, but the gated
   nginx config is saved on the VM for one-step restoration — publishing
   this file would compromise that password permanently. Exclude the
   file, or redact the password line + IP before any push/bundle.
3. **`REBRAND-AND-FIXES-REPORT.md`** (project root) — no credentials,
   but names the demo VM, its raw IP, the on-VM backup path and the
   deployed binary hash. Infra detail, not code. Recommend exclude
   from the first public push (it can be published later, redacted);
   harmless in a private audit bundle if Cameron prefers reviewers see
   the full gate record.
4. **`marketplace/media/`** — runtime data, not source: contains a dev
   upload (`8aa49ad9….png`) and a `tmp/` dir. Exclude (`media/` +
   `tmp/`). Note `marketplace/tests/security/media/*.png` are test
   fixtures and stay IN.

## Re-verified clean (2026-10-17 scan)

- No `PRIVATE KEY-----` blocks anywhere outside `target/`.
- `marketplace/deploy/deploy-demo.sh` (new since audit) takes the DB
  password from the environment (`MARKETPLACE_DB_PASSWORD`) and dies
  if unset — no literal credential. `DEPLOY-DEMO-RUNBOOK.md` shows
  placeholder forms only. `env.demo.template` contains paths and a
  `CHANGE-ME` placeholder only. All three are safe to publish.
- `marketplace/deploy/dev-setup.sh` still carries the known hardcoded
  local-dev password from the Oct 16 audit (item 3 there) — still
  parameterise-or-exclude before push; unchanged.
- The Oct 16 MUST-EXCLUDE list stands in full: the stage0 fixture
  wallet seed (`stage0-spike/fixtures-wallet/FIXTURES.md`), the wallet
  files themselves, and the dev-setup password line.
- Still **no `.gitignore`** at project or `marketplace/` level (only
  `stage0-spike/.gitignore`). A ready-to-install one is saved beside
  this addendum as `GITIGNORE-PROPOSED-2026-10-17.txt`; install it as
  `.gitignore` at the repo root BEFORE `git init` — order still
  matters, history cannot be un-pushed cleanly.

## Size check (unchanged in shape)

`marketplace/target/` alone is ~14 GB on this VM generation; with
`downloads/` (~303 MB) and `stage0-spike/` (~1.7 GB) a naive
`git add .` still sweeps in many GB plus the wallet files and the key
above. The proposed `.gitignore` covers all of it.

## Open deliberate-disclosure decisions (Cameron's, unchanged)

- `marketplace/docs/unverified.md` (known-open security gaps) and
  `docs/threat-model.md`: recommended IN for the AI audit bundle;
  Cameron's explicit call for the public repo.
- The project-root stage reports and review packs are the project's
  working record. They are what make the multi-AI audit valuable
  (spec + amendments + gate reports), but several name GCP projects,
  the demo IP, and VM details. Suggested split: audit bundle = full
  record minus the MUST-EXCLUDE files above; first public repo =
  code + docs + spec/amendments, with infra-naming reports held back
  or redacted. Cameron decides; nothing above blocks the sign-in step.
