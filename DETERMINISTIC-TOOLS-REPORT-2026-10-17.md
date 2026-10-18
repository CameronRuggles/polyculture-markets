# Deterministic tools report — Polyculture Markets

**Date:** 2026-10-17 (completed 2026-10-18 01:06 UTC / evening MDT)
**Authorized by:** Cameron, 2026-10-17 — "Do it for polyculture markets — do whatever is appropriate"
**Scope:** marketplace workspace (`marketplace/`, crates app / domain / envelope / media-worker / modules-api / tests/security) and the standalone `seller-helper/` crate.
**Spec basis:** Spec v2 §6 + operations section (cargo audit + cargo deny in CI), §22.5 (cargo-fuzz targets for envelope parser, statement parsers, terms file, listing markup, image worker), §24 Stage 12 (hardening), §25 (release gate).

## Headline verdicts

| Tool | Verdict |
|---|---|
| cargo audit | **Clean** after one documented ignore. 1 advisory found (rsa, lockfile-only, not compiled — see §2). seller-helper: 0. |
| cargo deny | **All four checks pass** for both workspaces (`advisories ok, bans ok, licenses ok, sources ok`). |
| clippy | Own-code warnings **35 → 11** (24 fixed; remaining 11 triaged, none security-relevant). seller-helper: 0 warnings. 14 warnings in locked tests untouched. |
| cargo geiger | **0 unsafe in every own crate**, verified independently of grep (all 100% safe on functions and expressions). Unsafe exists only in dependencies, as expected. |
| semgrep | 11 findings, **all 11 false positives** (each triaged below with its reason). 0 fixes. |
| cargo-fuzz | 6 targets created for the 5 §22.5 surfaces (+1 extra). **8,394,240 runs, no product-code crash.** One real panic found and **fixed** before fuzzing (envelope `from_fingerprint`); one crash in my own fuzz harness, root-caused and fixed. |
| Final test suite | **490 passed / 0 failed / 9 ignored** in one complete run against the restored Postgres (489 post-rebrand baseline + 1 new regression test). seller-helper: **13 passed / 0 failed**. |

One genuine bug was found and fixed in product code (§7.1). No locked test, invariant, or spec file was modified — the post-change manifest (§9) proves it: `tests/security/**`, `docs/invariants.md`, and `Cargo.lock` are byte-identical to the pre-change manifest.

## 1. Baseline and environment

* **No git repo exists** for this tree, so the pre-change state was recorded as a SHA-256 manifest (295 files): `DETERMINISTIC-TOOLS-PRE-MANIFEST-2026-10-17.txt`; the post-change manifest is beside it (`DETERMINISTIC-TOOLS-POST-MANIFEST-2026-10-17.txt`). Every change in §9 was computed from those two files.
* **Baseline compile:** `cargo check --workspace --all-targets` green before any change (warnings only, in locked test files).
* **PostgreSQL was restored** (it was absent on this VM generation, as AGENTS.md warns). Zonky binaries from `~/pgsys` were unpacked to `/tmp/pgsys2`, a fresh cluster was initialised in `/tmp/pgdata` as user `pguser`, started on port 5432, `postgres` password set to `dev`, database `marketplace_dev` created, and all 9 migrations applied (32 tables — matching the Stage 10 report). The server was left running; the final test suite used it.
* **Disk incident (mid-run):** `/tmp` is a 512 MB tmpfs and filled to 100%, which first looked like a C++ compiler failure in libfuzzer-sys (`No space left on device` writing compiler temporaries) and likely also caused the first two cargo-geiger install failures. Freed by removing dead install temp dirs and duplicate Postgres extracts; all later builds ran with `TMPDIR=~/tmp-build` (disk-backed, 77 GB free). No results were affected — every failed build was re-run to completion after the fix.
* **Advisory-database method note:** `cargo audit`'s git fetch of the RustSec advisory DB failed twice through this VM's proxy (IO error). The DB was instead fetched as a codeload.github.com tarball (integrity checked), unpacked, and git-initialised locally; audit ran with `--db /tmp/advisory-db --no-fetch` and loaded **1,338 advisories**. cargo-deny fetched its own DB successfully. Both results are from the same day's advisory data.

## 2. cargo audit — 0.22.2

Marketplace workspace: 316 lockfile dependencies scanned.

| Advisory | Crate | Severity | Disposition |
|---|---|---|---|
| RUSTSEC-2023-0071 "Marvin Attack: potential key recovery through timing sidechannels" (2023-11-22) | rsa 0.9.10 | 5.9 (medium) | **Accepted-with-reason; ignored in `.cargo/audit.toml` only.** No fixed release exists ("Solution: No fixed upgrade is available"). |

Why acceptance is sound, verified three independent ways:

1. rsa enters `Cargo.lock` only as an optional dependency of `sqlx-mysql`; the app builds sqlx 0.8.6 with the **postgres** backend only.
2. `cargo tree` (default features) contains **no rsa and no sqlx-mysql**; no rsa artefact exists under `target/debug/deps` — the crate is never compiled.
3. cargo-deny's feature-resolved advisory check reported the ignore as **"advisory not detected / no crate matched advisory criteria"** when one was initially present in deny.toml — its graph does not contain rsa at all.

The Marvin attack also requires RSA private-key decryption operations; this codebase performs none. The ignore therefore lives in `.cargo/audit.toml` (cargo-audit scans the raw lockfile), and was **deliberately removed from deny.toml** so that if the MySQL backend is ever enabled, deny fails loudly instead of suppressing a real exposure (comment in both files says so).

seller-helper: 45 dependencies scanned, **0 vulnerabilities, 0 warnings**.

Re-run after all changes: audit exits 0 for the marketplace (ignore applied) and for seller-helper.

*Not attempted (needs a decision, §11):* pruning rsa from the lockfile entirely by changing sqlx feature flags (`default-features = false`) — a feature change can alter sqlx behaviour, so per gate discipline it is dispositioned, not done silently.

## 3. cargo deny — 0.20.2

Two configs were authored: `marketplace/deny.toml` and `seller-helper/deny.toml`. Final result for both: **`advisories ok, bans ok, licenses ok, sources ok`**.

* **Advisories:** deny by default; no ignores (see §2 for the rsa reasoning).
* **Licences:** the allow list is exactly the licences present in the locked tree, each compatible with distribution under the project's AGPL-3.0-or-later:
  * Permissive (bulk of the tree): MIT, Apache-2.0 (165 + 41 + 26 + 13 + 3 packages across MIT/Apache expression variants), BSD-1/2/3-Clause, ISC, Zlib, BSL-1.0, CC0-1.0, 0BSD, Unlicense, Unicode-3.0, `bzip2-1.0.6`, `Apache-2.0 WITH LLVM-exception`.
  * Copyleft, reported accurately from crate metadata: **sequoia-openpgp 2.4.1 — LGPL-2.0-or-later**; **buffered-reader 1.4.1 — LGPL-2.0-or-later**; **nettle 7.5.0 and nettle-sys 2.3.2 — `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`** (the LGPL-3.0 branch is the one relied on; nettle-sys links the system Nettle library); r-efi offers LGPL-2.1 as one alternative beside MIT/Apache-2.0, which are the branches used. LGPL-2.0-or-later and LGPL-3.0 both combine with AGPL-3.0 distribution; **no GPL-only dependency exists in the tree.**
* **Own-crate licence metadata fixed:** `app`, `domain`, `media-worker`, and `modules-api` carried **no `license` field** and failed the licence check as "unlicensed". Each now declares `license = "AGPL-3.0-or-later"` (metadata-only change; `envelope` and `seller-helper` already declared it). The fifth unlicensed member, `security-tests`, is locked and was **not** touched — it already has `publish = false`, which `[licenses.private] ignore = true` covers.
* **Bans:** `multiple-versions = "warn"` — the tree currently carries two versions each of **getrandom, hashbrown, itertools, miniz_oxide, redox_syscall, shlex, syn, windows-sys** (seller-helper: syn). Collapsing them is dependency surgery, not a mechanical fix; they stay visible as warnings. `wildcards = "warn"` (not deny): cargo-deny counts every version-less workspace `path = "…"` dependency as a wildcard — all of ours are internal path deps, verified; every external requirement carries an explicit version.
* **Sources:** crates.io only; unknown registry/git denied. Passes.

## 4. clippy — Rust 1.99.0 (workspace toolchain)

`cargo clippy --workspace --all-targets` located warnings (file:line resolved):

| | Before | After |
|---|---|---|
| Own code | 35 | **11** |
| Locked `tests/security/**` | 14 | 14 (untouched, by rule) |
| seller-helper (`--all-targets`) | — | **0** |

**Fixed (24):**
* 18 × `format_in_format_args` in `crates/app/src/web.rs` — nested `format!` calls in redirect targets merged into single format strings (byte-identical output; pattern was uniform and script-verified, 18/18 replaced, none remaining).
* `crates/envelope/src/lib.rs` — unused import `sequoia_openpgp::packet::Packet` removed; AED cipher check `7 | 8 | 9` → `7..=9`; PKESK/container pairing match → `matches!`; (first two plus the `Fulfilled` match-guard collapse in web.rs were applied by `cargo clippy --fix` and then reviewed line by line).
* `crates/app/src/web.rs` — `"Fulfilled"` arm collapsed to a match guard (behaviour identical; covered by the locked Stage 4 order-action tests, which pass).
* `crates/envelope/src/lib.rs` unit test — `repeat(0u8).take(492)` → `repeat_n(0u8, 492)`.
* `crates/app/src/keys.rs` unit test — unnecessary `to_string()` removed.

**Remaining 11 own-code warnings — accepted with reasons, none security-relevant:**
* 4 × `type_complexity` (moderation.rs:237, reputation.rs:381, orders.rs:146, keys.rs:221) — fixing means introducing type aliases into handler/query signatures; refactor risk for zero behavioural gain. Burn down opportunistically.
* 2 × `result_large_err` (web.rs) — the Err variants are large because handlers return full responses; fixing means boxing response types across the web layer. Not mechanical.
* 2 × `too_many_arguments` — `orders::build_terms` (14 args) and a listings function (8 args). Both are deliberate, call-site-clear builders; a params-struct refactor is a design change.
* 2 × dead-field warnings (4 fields): `OrderTpl.is_buyer`, `DisputeTpl.{signed_signature, is_participant, is_moderator}` — populated template DTO fields that no template currently reads. **Flagged for Cameron (§11)** rather than deleted: fields are cheap, but `signed_signature` never being displayed might be a UI gap, not dead code.
* 1 × `items_after_test_module` (passwords.rs) — file-layout only.

Because 11 triaged warnings remain, the CI workflow (§8) runs clippy **without** `-D warnings` for now, with a comment saying to promote it once the backlog is burned down.

## 5. cargo geiger — 0.14.0

Own crates — **zero unsafe, on geiger's own count** (safe/total; "?" means the crate doesn't declare `#![forbid(unsafe_code)]`, not that unsafe was found):

| Crate | Functions | Expressions | Impls | Methods |
|---|---|---|---|---|
| app | 281/281 | 9716/9716 | 32/32 | 60/60 |
| domain | 22/22 | 587/587 | 3/3 | 4/4 |
| envelope | 29/29 | 919/919 | 1/1 | 4/4 |
| modules-api | 5/5 | 137/137 | 8/8 | 10/10 |
| media-worker | 2/2 | 102/102 | 0/0 | 0/0 |
| seller-helper | 27/27 | 1389/1389 | 9/9 | 24/24 |

Dependencies: unsafe is present, as expected — geiger's Ratio tree for the app root covers 191 unique packages, of which 135 contain some unsafe (aggregated from geiger output, deduplicated by crate+version: 648/13,269 unsafe functions, 50,615/802,429 unsafe expressions overall). The largest unsafe-expression carriers are the usual foundational crates: moxcms (10,097 — image colour management, via the `image` crate), tokio (2,990), nettle (2,633 of 4,077 — the FFI binding layer to the system Nettle; its own functions are 0/43 unsafe-declared), memchr (2,440), hashbrown (1,612 + 1,520 across two versions), pxfm (1,480), parking_lot_core (1,343), libbz2-rs-sys (1,154), libc (859). **Disposition: report only** — no dependency swaps on geiger grounds; these are the standard, heavily-audited Rust ecosystem crates, and the project's own code — the part Cameron's team controls — is unsafe-free.

Tool caveats, honestly: geiger 0.14 needed two attempts (a stale October `target/` artefact — a removed `repair_harness_0006.rs` test binary from the migration-repair session — broke its scan until the three stale target entries were deleted; `cargo metadata` itself was always clean), it emits "failed to match" warnings for the newest serde_core/js-sys packaging, and it could not parse one dependency file (signal-hook-registry 1.4.8) — so dependency totals are best-effort, while the own-crate zeroes are exact (and agree with the `grep -r unsafe` = 0 result from before the run).

## 6. semgrep — 1.136.0

Rulesets `p/rust` + `p/security-audit` (20 rules), 81 files scanned across both codebases: **11 findings, all false positives, 0 true positives, 0 fixes.**

| # | Rule | Location | Why it is a false positive |
|---|---|---|---|
| 1 | flask `template-unescaped-with-safe` | templates/listing.html:4 | Wrong framework (this is Askama, not Flask). The `\|safe` value is `description_html` — the output of `render_listing_markup`, which escapes all seller input first and emits only p/ul/li/strong. That is the §18 design, and the locked Stage 2 suite verifies seller content cannot inject markup. |
| 2 | `var-in-href` | templates/pay.html:10 | `payment_uri` is server-constructed by `payment_uri_for` from a `Subaddress::validate`-checked address and a u64 amount — a `monero:` URI, not user input. |
| 3 | `var-in-href` | templates/source.html:4 | `source_url` is the operator's own instance configuration (`SOURCE_URL`), displayed on the operator's own instance; Askama escapes it. Operator self-configuration is the trust boundary here. |
| 4 | `rust.args` | media-worker/src/main.rs:19 | argv is the worker's designed interface — the two file paths handed to it by its trusted parent process (§18 isolation). argv[0] is never used for a security decision. |
| 5 | `rust.args` | seller-helper/src/main.rs:229 | A local CLI tool parsing its own subcommands; by design. |
| 6–10 | `rust.temp-dir` ×5 | tests/security/blind_stage{3,9,10}.rs | Locked test code (not touchable regardless); temp dirs in tests are pid-scoped fixtures, not a production surface. |
| 11 | `rust.temp-dir` | seller-helper/src/lib.rs:651 | Inside a `#[cfg(test)]` helper (`test_out_dir`, pid-unique name). Test-only. |

Coverage limit, stated plainly: semgrep's Rust grammar failed to parse 3 files (`crates/app/src/keyfile.rs:47`, `seller-helper/src/config.rs:166`, `seller-helper/src/rpc.rs:249` — all choke on `raw` used as an identifier) — those files were only partially analysed. Overall parse rate reported by semgrep: ~99.9% of lines. Semgrep's Rust ruleset is thin (20 rules); it is a sweep, not an audit.

## 7. cargo-fuzz — cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, nightly 1.101.0

A new fuzz crate at `marketplace/fuzz/` (own workspace root, so the main workspace's lockfile/build are untouched) with **six targets covering the five §22.5 surfaces**, each calling the real entry points:

| Target (§22.5 surface) | Real entry points | Time | Runs | Result |
|---|---|---|---|---|
| `envelope_validate` (envelope parser) | `envelope::validate_envelope`, `extra_recipient_key_id`, `KeyRef::from_cert` | 301 s | 861,374 | clean |
| `image_worker` (image worker) | media-worker is binary-only (§18), so the target reproduces its `run()` pipeline call-for-call: same `image` 0.25 pin/features, format allowlist, dimension pre-check and limits, re-encode (divergence protocol documented in the target file) | 301 s | 3,103,630 | clean |
| `statements` (statement parsers) | `domain::statements::parse_invoice_statement`, `parse_pool_statement`, `app::keys::parse_rotation_statement`, `modules_api::Subaddress::validate`, `validate_standard_address`, `domain::Atomic::parse_decimal`, `validate_canonical_timestamp` | 121 s | 2,335,552 | clean |
| `markup` (listing markup) | `domain::markup::render_listing_markup` — plus an invariant assertion on every run: output may contain only the renderer's 8 allowlisted tags | 121 s | 1,137,475 | clean, invariant held on every run |
| `terms_file` (terms file) | **No terms-file parser exists** — §10 terms files are generated, never parsed back. Target fuzzes the real builder `app::orders::build_terms` (seller-controlled text fields), asserting determinism and the fixed format header | 121 s (after fix, §7.2) | 795,384 | clean |
| `envelope_keyref` (extra; envelope surface) | `envelope::KeyRef::from_fingerprint`, `from_cert` | 121 s | 160,825 | clean |

**Total: 8,394,240 runs. No crash in any product code.** Final corpora on disk: 7,691 files, 31 MB (envelope_validate 2,364; image_worker 1,981; envelope_keyref 1,326; statements 798; markup 706; terms_file 516), seeded from real fixtures (valid invoice/pool/rotation statements reconstructed from the crates' own test fixtures, the Stage 2 media PNGs, the app key fixtures key-a/key-b.asc, packet vectors from the envelope unit tests).

### 7.1 Real bug found and FIXED — envelope `KeyRef::from_fingerprint` panic

While designing the `envelope_keyref` target, the slicing in `KeyRef::from_fingerprint` was checked by hand and **panicked**: for any input of ≥ 16 bytes whose byte offset `len−16` falls inside a multi-byte UTF-8 character (minimal example: six `€` characters = 18 bytes), `fpr[fpr.len() - 16..]` throws "byte index N is not a char boundary". Reproduced standalone before any fix.

*Severity assessment:* **low as deployed, real as a library bug.** Production code (`app/messages.rs`, `app/web.rs`) builds KeyRefs only via `from_cert`, whose fingerprints are Sequoia-formatted ASCII hex; `from_fingerprint` currently has no production caller (only tests). But it is a public API of the security-critical envelope crate, one future caller away from being a remotely triggerable panic (message submission builds envelope contexts), and panics in a Tor-facing server are denial-of-service.

*Fix (in `crates/envelope/src/lib.rs`):* derive the key-ID suffix only when `len−16` is a char boundary; otherwise derive no suffix handle. Behaviour for every real fingerprint (ASCII hex) is byte-identical. A regression test, `from_fingerprint_non_ascii_never_panics`, was added to the envelope crate's own unit tests — not to any locked suite — and the € input is also a fuzz seed. The 160,825-run `envelope_keyref` fuzz run post-fix was clean.

### 7.2 Crash in the fuzz harness itself — root-caused, fixed, re-run

The first `terms_file` run crashed at run #28 (`artifacts/terms_file/crash-4c1ebba727bddd82fea4652466314c8f301860f8`, input `Ünïcödéé test`, panic "end byte index 4 is not a char boundary"). **The bug was in my fuzz target, not in product code:** the target quartered the input with `str::split_at(len/4)`, which panics on non-boundary offsets. `build_terms`/`terms_text` contain no slicing (verified by reading them). The target was fixed with a boundary-aware split helper, the crash artifact was copied into the corpus as a regression seed, the artifact was re-executed against the fixed target (exit 0), and the full 121 s re-run completed 795,384 runs clean. The artifact is retained under `fuzz/artifacts/terms_file/` as evidence.

## 8. CI scaffold

`.github/workflows/security-tools.yml` (new, in-repo only — **no push attempted; that needs Cameron's GitHub sign-in**): runs cargo audit + cargo deny for the marketplace (and seller-helper when present in the checkout), the Q8 crypto-backend guard, clippy (not yet `-D warnings`, see §4), a weekly scheduled run (so new advisories against the locked tree surface), and a separate fuzz-smoke job (nightly toolchain, 60 s per target). **It has never run on GitHub** — treat its first real run as a shakedown; it is written against prebuilt tool binaries (audit 0.22.2, deny 0.20.2, fuzz 0.13.2) and a stock runner's `nettle-dev`, so the local `NETTLE_PREGENERATED_BINDINGS` shim is not needed there.

## 9. Every file created or modified

Computed from the pre/post SHA-256 manifests. **Nothing deleted. `Cargo.lock` unchanged. Nothing under `tests/security/` or `docs/` changed.**

**Modified (7):**
* `marketplace/crates/app/src/web.rs` — 18 format merges + 1 match-guard collapse (clippy).
* `marketplace/crates/envelope/src/lib.rs` — clippy fixes (unused import, `7..=9`, `matches!`, `repeat_n`) + the `from_fingerprint` boundary fix + 1 regression test + explanatory comments.
* `marketplace/crates/app/src/keys.rs` — 1 unit-test `to_string()` removal.
* `marketplace/crates/{app,domain,media-worker,modules-api}/Cargo.toml` — `license = "AGPL-3.0-or-later"` added (4 files).

**Created (13, plus corpora/artifacts and this report):**
* `marketplace/deny.toml`, `seller-helper/deny.toml` — cargo-deny configs.
* `marketplace/.cargo/audit.toml` — cargo-audit ignore (rsa, §2).
* `marketplace/.github/workflows/security-tools.yml` — CI scaffold (§8).
* `marketplace/fuzz/Cargo.toml`, `marketplace/fuzz/Cargo.lock`, `marketplace/fuzz/.gitignore`, `marketplace/fuzz/src/bin/{envelope_validate,envelope_keyref,statements,markup,terms_file,image_worker}.rs` — the fuzz crate (§7).
* `marketplace/fuzz/corpus/**` (7,691 files / 31 MB grown corpora, from hand-written seeds) and `marketplace/fuzz/artifacts/terms_file/crash-4c1ebba7…` (the harness crash artifact, §7.2).
* `DETERMINISTIC-TOOLS-PRE-MANIFEST-2026-10-17.txt`, `DETERMINISTIC-TOOLS-POST-MANIFEST-2026-10-17.txt` (beside this report); this report itself.

No fixture-construction fixes were needed anywhere. No test was modified except the two unit tests inside our own crates noted above (one clippy tidy each) and the one regression test added.

## 10. Re-verification (final state, after all fixes)

* `cargo check --workspace --all-targets` — exit 0.
* **Full workspace test suite** — one complete run, fresh `marketplace_dev` (restored server, §1), full harness env (`DATABASE_URL`, `MEDIA_WORKER`, `MEDIA_DIR`, nettle shims): **490 passed / 0 failed / 9 ignored** across 24 test binaries. Reconciliation: 489 was the post-rebrand baseline; +1 is the new envelope regression test. No partial counts are reported anywhere in this document — this is a single complete run's total.
* seller-helper `cargo test` — **13 passed / 0 failed**.
* `cargo audit` — exit 0. `cargo deny check` — all four ok. `deploy/check-crypto-backend.sh` — OK (Sequoia resolves to Nettle, no RustCrypto features).
* clippy re-run — own-code warnings 11 (the accepted backlog in §4); locked-file warnings unchanged at 14.

**`docs/unverified.md` was NOT modified.** No result in this pass changes the status of any of its 12 items: the fuzz targets close a §22.5/§25 *deliverable* gap (they were never an unverified.md item), and the `from_fingerprint` fix is recorded here and in the code, not as an unverified-property closure. Stating this explicitly per instructions.

## 11. Needs a Cameron decision (not done, by design)

1. **Clippy backlog promotion:** after the 11 accepted warnings (§4) are burned down, flip CI clippy to `-D warnings`. The `DisputeTpl.signed_signature` never-displayed field (§4) may be a product/UI question, not just lint.
2. **rsa lockfile pruning:** optionally test `sqlx` with `default-features = false` to drop sqlx-mysql/rsa from `Cargo.lock` entirely and retire the audit ignore. Behaviour-risk is small but real (sqlx feature surface); needs a full gate run if adopted.
3. **Duplicate versions:** 8 crates at two versions (§3) — collapse only as a deliberate dependency pass.
4. **Type-complexity / large-Err refactors** (§4) — schedule only if wanted; they touch handler signatures.

## 12. What still stands between here and the §25 release gate (tooling side)

From §25's checklist, after this pass:

* ✅ `cargo audit` + `cargo deny` exist and pass; CI file written — but **the CI has never executed on GitHub** (needs the GitHub push, which needs Cameron's sign-in).
* ✅ Fuzz targets exist and have bounded runs (§22.5 satisfied at CI level). **Stage 12's "extended fuzzing" is still ahead**: longer campaigns (hours, not minutes), corpus minimisation into the repo, and ideally continuous fuzzing once the repo is public.
* ❌ **Independent security review** (§22.7 / §25) — not done; this pass is the deterministic pre-layer for it, not a substitute.
* ❌ **Signed releases / reproducible builds** — still open (unverified.md item 12, untouched).
* ❌ Tor Browser Safest verification (unverified.md item 5), Argon2 parameter benchmarking on target hardware (item 9), the rest of §20 retention automation (item 11), legal review, GPG usability test, mainnet section-1 sign-off — all unchanged by this pass.
* Environment note for whoever runs this next: Postgres on this VM generation is the user-space Zonky build (now running from `/tmp/pgsys2`, data `/tmp/pgdata` — it will **not** survive a VM replacement; re-provision per AGENTS.md), and builds on this VM need `TMPDIR` pointed off the 512 MB `/tmp` tmpfs for any heavy compilation.

## Appendix — tools and versions used

| Tool | Version | Install route |
|---|---|---|
| cargo / rustc (workspace toolchain) | 1.99.0 | rustup (pre-existing; clippy + rustfmt components already present for 1.99) |
| rustc nightly (fuzz) | 1.101.0-nightly (2026-10-16) | `rustup toolchain install nightly` |
| cargo-audit | 0.22.2 | prebuilt release binary |
| cargo-deny | 0.20.2 | prebuilt release binary |
| cargo-geiger | 0.14.0 | `cargo install --locked` (3 attempts; first two lost to network/disk, §1) |
| cargo-fuzz | 0.13.2 (libfuzzer-sys 0.4.13) | prebuilt release binary |
| semgrep | 1.136.0 | pip (`--break-system-packages`) |
| PostgreSQL | 16.4 (Zonky embedded) | from `~/pgsys` per AGENTS.md |
