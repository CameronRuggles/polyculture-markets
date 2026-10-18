# External review / first GitHub push — scrub audit and bundle plan

Prepared 2026-10-16 (~16:30 UTC) while Cameron weighs: (a) a curated file
bundle for a Claude/ChatGPT review now, vs (b) GitHub. This audit is the
groundwork both routes need. No bundle was built and nothing was published;
the code tree is mid-Stage-9 (see Timing).

## Scan performed

Whole project tree (`~/workspace/monero-marketplace-v2/`), excluding
`target/` and `downloads/`, grepped for: PGP/OpenSSH/RSA private-key blocks,
mnemonic/seed-phrase mentions, `.env`/config files, wallet `.keys` files, and
hardcoded password/secret assignments in `.toml`/`.sh`/`.rs` sources.

## Clean results

- No private-key blocks anywhere in the text tree.
- Test fixture keys (`marketplace/crates/app/tests/fixtures/key-a.asc`,
  `key-b.asc`) are PUBLIC key blocks only.
- No `.env` files; the app reads `DATABASE_URL` from the environment
  (`crates/app/src/main.rs`).
- Session/CSRF values in `web.rs` are generated per session, not literals.

## MUST-EXCLUDE list (the only sensitive material found)

1. `stage0-spike/fixtures-wallet/FIXTURES.md` — contains the actual
   stagenet fixture wallet seed (German word list). The wallet is empty
   and fixture-only by design, but seeds never go in an upload or a repo.
2. `stage0-spike/fixtures-wallet/stage0-fixtures` and
   `stage0-spike/fixtures-wallet/stage0-fixtures.keys` — the fixture wallet
   files themselves.
3. `marketplace/deploy/dev-setup.sh` — contains a hardcoded LOCAL DEV
   database password (`PGPASSWORD`). Dev-only and already noted in
   workspace docs, but it should be parameterised or the file excluded
   before any public push; a public repo will be scanned by bots within
   minutes and the line will be flagged forever in history.

## Structural risk for a first GitHub push

- There is currently NO git repository and NO `.gitignore` at the project
  or `marketplace/` level (only `stage0-spike/.gitignore`, which ignores
  just `/target`).
- A naive `git init && git add .` would sweep in ~16 GB of
  `marketplace/target/`, ~303 MB of Monero binaries under `downloads/`,
  ~1.7 GB under `stage0-spike/` (its own target + the wallet files above),
  `mutants.out*`, and screenshots.
- First push therefore needs a prepared `.gitignore` BEFORE `git init`:
  `target/`, `downloads/`, `stage0-spike/fixtures-wallet/`, `mutants.out*`,
  plus the exclude list above. History cannot be un-pushed cleanly, so
  this order matters.

## Deliberate-disclosure decision (not a leak, a choice)

`marketplace/docs/unverified.md` (19 lines) is the known-open security
gaps list. Publishing it is normal for a mature project, but for a
pre-launch privacy tool Cameron should decide explicitly whether it goes
in the first public push / review bundle, and in what order. Same for
`docs/threat-model.md` — recommended IN for an AI review (reviewers need
it), Cameron's call for the public repo.

## Bundle structure (per crate, as recommended in chat)

- Root pack: spec v2
  (`~/workspace/user/files/Privacy-First_Noncustodial_Marketplace___Spec_v2_0_4b7b.md`)
  + `SPEC-V2-AMENDMENTS.md` (300 lines — REQUIRED; amendments override the
  spec, payments most of all) + `marketplace/docs/` (api-contract,
  invariants, threat-model, encryption-guide; unverified per above).
- Per crate: `crates/app`, `crates/envelope`, `crates/domain`,
  `crates/modules-api`, `crates/media-worker`, each with its gating blind
  suite from `marketplace/tests/security/`
  (blind_stage1/2/3/4/6, blind_direct_v1, blind_stage9 when gated).
- `seller-helper/` (~2,040 lines) as its own chunk + `SELLER-GUIDE.md`
  (mentions seed phrases instructionally; contains no actual seed).
- Migrations (`marketplace/migrations/`) with the app chunk.
- Measured 2026-10-16: ~14,100 lines of Rust across marketplace +
  seller-helper sources, ~10,800 lines in the security test tree —
  one or two chunks per crate in a current Claude/ChatGPT session.

## Timing

Stage 9 is actively being written in this tree right now
(`crates/app/src/reputation.rs`, `moderation.rs`, `disputes.rs`,
`reviews.rs`, `totp.rs` all modified 15:43–15:54 UTC today;
`tests/security/blind_stage9.rs`, 1,523 lines, already exists).
A bundle snapshotted this afternoon would be stale before the Stage 9
gate lands. Build the bundle AFTER the Stage 9 report, or snapshot now
only if the review is meant to cover stages 0–8 + Direct Payments v1
and say so on the bundle's cover note.

## Closure ruling — verified in the live Stage 9 code

Cameron's 2026-10-16 15:39 UTC ruling (no ban/suspension; account
closure only) is already in the build, not just in the brief:
`crates/app/src/moderation.rs` opens with "There is NO ban and NO
suspension" and implements `close_account` (status → closed, sessions
revoked, listings unpublished, pool retired, profile marked closed,
history retained); `templates/moderation_queue.html` states the same to
moderators. No action needed.
