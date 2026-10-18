# DRAFT — Stage 6 report completion (prepared 2026-10-14, background)

Status: draft completion for `STAGE6-REPORT.md`, **not applied**.
The report on disk is 158 lines / 8,129 bytes and ends mid-§6
("unit layer 72 caught / 19 missed / 3 unviable" — sentence
unfinished). Its §§7–8 never landed. That gap already caused one
real harm: a migration-repair brief was issued from a summary's
description of a §8 that does not exist in the file, and the
worker had to halt it (`MIGRATION-REPAIR-2026-10-14.md`, stopped
section). This draft reconstructs only what the preserved gate
artifacts verify, and marks the rest as not reconstructable —
per the standing lesson: never brief from a summary of a file
section that has not been grep-confirmed to exist.

## §6 remainder — reconstructable from preserved artifacts

Source: `mutants-runs/stage6-statements/` — `mutants.out/`
(caught/missed lists), `handverify-blind-layer.txt`,
`handverify-pricing.txt`. All counts below were re-read from
those files on 2026-10-14, not copied from any summary.

- Statement library (`statements.rs`, 94 mutants), unit layer:
  **72 caught / 19 missed / 3 unviable** (report's last line).
- Hand-verification of the 19 unit-layer misses against the
  locked blind_stage6 suite (apply diff in real tree, run blind
  suite, reverse, md5-verify restore — pristine md5
  `0a2476ad132c64f691d31219a2c1f03e`):
  - **5 KILLED by the blind layer:** fingerprint `==`→`!=`
    (93:31); `valid_terms_sha256` → true (100:5) and its
    `&&`→`||` (101:9); `parse_marketplace_id` `||`→`&&`
    (139:32); invoice `>`→`>=` (199:44).
  - **14 SURVIVED both layers:** 3 non-QR —
    `byte_gate` → true (88:5), `expect_end` → Some(()) (127:5),
    `expect_end` `&&`→`||` (127:33) — and **11 QR-geometry**
    mutants in `payment_qr_png` (315:23, 315:31, 319:25 ×2,
    319:38, 320:39 ×2, 321:39 ×2, 324:42, 324:51): scale,
    quiet-zone and module-offset changes no current test catches,
    because unit + blind tests check only PNG magic, byte
    determinism and amount sensitivity (blind author's note (d)
    in §3 of the report).
  - The 11 QR survivors are exactly the open item the
    paste-ready decode-and-compare test draft addresses
    (`QR-DECODE-TEST-DRAFT-2026-10-14.md`, not applied — it
    belongs in the implementer unit layer, not a locked suite).
  - The 3 non-QR survivors still need a triage sentence in the
    completed report: they were not closed by the QR draft.
    No triage prose for them survives in the tree — do not
    invent one; either triage them fresh or record them as
    accepted survivors with the reasoning written at that time.
- Pricing (`xmr_only_total`, hand-mutations in place of a
  cargo-mutants list for lib.rs): all 3 body replacements
  (→None, →Some(0), →Some(1)) **killed** by both the domain unit
  test and blind_stage6. Restore md5 verified
  (`handverify-pricing.txt`).

## §7 crypto guard — NOT reconstructable; needs a fresh check

The report header records only the verdict: "crypto guard green
(§7)". No §7 detail, guard script, or output file was found in
the project tree on 2026-10-14. The Gate 4 pattern (GATE4-REPORT
§8) is "PASS (Q8 — Sequoia resolves to Nettle everywhere, no
RustCrypto features)", but writing that sentence into Stage 6's
§7 from the Gate 4 precedent would be exactly the
summary-to-brief error that broke the first repair attempt.
**Completion path: re-run the guard check against the Stage 6
tree and write §7 from that output — do not backfill prose.**

## §8 environment / migration defect — superseded, cross-ref only

The report references §8 twice: §4 "Baseline (environment
recovered, §8): 239 passed / 0 failed" and §5 "No migration
files were changed (see §8 for why one needs an owner
decision)". The defect §8 described — the duplicate-0006 pair —
has since been **repaired and verified** (Option A; fresh
install 0001→0007, both write paths, full suite 327/0, Q16
probe green; `MIGRATION-REPAIR-2026-10-14.md`, executed
section). The completed report should carry a one-paragraph §8
that (a) records the environment recovery behind the 239
baseline only as far as the artifacts support, and (b) points
to the repair record as superseding the original defect
write-up, instead of restoring the old §8 text — a fresh
install no longer breaks, so the old text would mislead the
next reader the way the missing §8 misled the repair brief.

## What applying this draft means

Append the §6 remainder above to the report, add §7 only after
the fresh guard check, and add the §8 cross-reference
paragraph. No code, no locked test, and no other report is
touched by any of that.
