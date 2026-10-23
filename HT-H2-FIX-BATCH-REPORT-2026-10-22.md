# HT H2 — Fix Batch Report (2026-10-22)

Scope: findings E1–E11 of the re-verification of the H2 first
batch at `dcddf14` (the auditor's third pass over the HT work).
Branch `ht-h2-first-batch`, stacked on `dcddf14` — the first
batch's tip; nine commits, one per item (E1 and E5 are one item:
they are one fold rule). Three of the items carry owner rulings
given by Cameron on 2026-10-22 (§2). No `blind_*.rs` suite was
edited; the one deliberate consequence is recorded in §1 and
§3 (E1+E5).

Method, as before: the baseline gate was reproduced on the
stack point BEFORE any change (671/0/9, §1); each item was
implemented, test-run at target scope, and committed
separately; test changes were made only where an item orders
them (E2, E4, E6, E11, and E1+E5's domain tests). Failures were
fixed in code, never in tests.

Environment disclosure: the VM was replaced mid-batch. The
first baseline attempt was killed by the replacement and `/tmp`
was wiped with it; PostgreSQL was re-provisioned from the
kept-in-home Zonky tree (`/tmp/pgx`, `marketplace_dev`, port
5432) and the psql client is again the stdlib Python shim the
first batch's report discloses — control behaviour unchanged.
The reproduced baseline below is from the re-provisioned
environment, on the untouched `dcddf14` tree.

## 1. Gate record

| run | tree | passed | failed | ignored | log SHA-256 |
|---|---|---|---|---|---|
| baseline | `dcddf14` | 671 | 0 | 9 | `e8d0a321d751af3484efab2f6b07e5e204a25f0891a80abb91702ea2d61203ea` |
| final (verbatim `run-gate.sh`) | `53c8377` | — stops in phase 1 — | 1 | — | `65bea5e65f2c94110f79366e88529de49133a6bedda4181f6c4fc5371c5ae45f` |
| final (completion, all phases) | `53c8377` | 678 | 1 | 9 | `9d96d75a3fa7f7812457d8cebeb3b18622b5000739b0fedef22f916d8b607ca8` |

The baseline reproduces the re-verification's 671/0/9 exactly.

The final state is the EXPECTED intermediate state the batch
was commissioned into, stated plainly: **the only failure in
all 46 targets is `blind_ht1`'s
`fold_lapsed_and_terminals_ignore_later_statements`** — the
test carrying §6 rule 4's two pins (a `Closed` terminal ignores
a later settle; a `Settled` terminal ignores a later receipt).
Under owner ruling E1 (§2), a complete settle and a complete
receipt for one trade are a conflict by kind, so both pins'
premise is gone. Observed failure: `blind_ht1.rs:584`,
`left: Conflicted, right: Closed` — the receipt-first pin is
the one the harness reaches; the settle-first pin (asserting
`Settled` at :590) is masked by the abort and fails by the same
ruling (the new domain test covers both orders). `blind_ht1`
was NOT edited, per the brief; its re-authoring is the
separate Q3 work that follows this batch. Everything else is
green, including the other 23 `blind_ht1` tests.

Because cargo is fail-fast per phase, the verbatim
`run-gate.sh` run stops at that failure in phase 1 (its log's
head carries the new E8 binding: HEAD `53c8377`, tracked
changes 0, untracked files 285 — per-file count, see §3 E8 —
and the E7 line isolating runtime output to a scratch dir).
The completion row is the same three phases, same rebuilds,
same environment, run with `--no-fail-fast` so every target's
verdict is on record; it is an accounting run, not a second
gate, and it does not print `gate: PASS` either. Phase split
(completion): security 394 passed / 1 failed / 6 ignored,
workspace 242/0/3, seller-helper 42/0/0 (marketplace 636/1/9).

## 2. Owner rulings implemented (Cameron, 2026-10-22)

- **E1 — different complete terminals conflict.** Any two
  DIFFERENT complete terminal statements (settle or receipt)
  for one trade are `Conflicted`, order-independent. A settle
  and a receipt are different terminals by kind.
- **E5 — "different" settles = different terms.** Terms are
  `refund_atomic` + `return_required`. Identical terms
  re-signed, even in a different month, are ONE settle outcome,
  not a conflict. Receipts carry no terms and never conflict
  with each other.
- **E7 (PNGs) — remove on proof of no reader.** The five
  committed PNGs under `marketplace/tests/security/media/` are
  removed IF nothing in the tree reads them as input. Verified
  before removal: no code or test names any of the five files
  or reads that directory as input (the only references are
  old manifest listings); all five share one SHA-256 (the
  media suite's sanitizer output for a fixed test input) under
  random-hex names of the shape the suite writes per run.
  Removed in `3c37e10`; the locked-path manifest in §5 shows
  the removal as the batch's only locked-path change.

## 3. Per-item record

**E1+E5 — the fold's conflict rule, completed.** `bcfc2b4`.
`domain::ht_fold`'s pre-scan no longer dedupes settles by
whole-statement equality. It now surveys the complete
terminals: distinct settle TERMS (`refund_atomic`,
`return_required`) among settles passing `check_settle`, plus
whether a complete receipt (one naming the assignment's own
buyer and seller — the walk arm's existing condition) is held.
`Conflicted` = ≥2 distinct-term complete settles, or a
complete settle beside a complete receipt. Preserved, as
ordered: `Conflicted` is terminal with `refund_atomic: None`;
presence is over the full held set (`paid`, `shipped`, the
issue window describe all of it); one complete settle plus
proposals settles; an over-amount settle is not complete and
cannot conflict; two receipts close. New domain tests:
settle+receipt → `Conflicted` with identical `FoldedTrade` in
both orders; same-terms settles signed in different months →
`Settled` in both orders (the fixtures differ as statements —
month — and agree in terms); two receipts → `Closed`; a
receipt naming other parties is not complete and the settle
governs. The existing D3 tests rechecked against terms
dedupe: the distinct-terms pair still conflicts, the
identical duplicate still settles. Domain target 24 → 28.

**E2 — enumeration errors on an undeterminable entry.**
`f1d9edc`. `EvidenceStore::trade_ids` filtered entries with
`entry.path().is_dir()`, which follows symlinks and swallows
stat failures as "not a directory": a dangling symlink (or an
entry removed mid-listing) vanished from the enumeration, so
the store enumerated smaller than the disk (probes P3/P4:
17 entries read as 16, and the pool ledger seeded over the
shrunken set). `trade_ids` now decides from the entry's own
`file_type()`; a symlink's target is stat'd explicitly and
every failure propagates as an error in the F5 words. Only an
entry KNOWN to be a non-directory skips. Regression tests:
`dangling_symlink_trade_entry_fails_loud` (enumeration and the
assign-time ledger load both refuse) and
`symlinked_trade_entries_resolve_by_target` (a resolvable link
is judged by its target: dir enumerates, file skips).

**E3 — the demo id is never minted; the operator path is
documented.** `18e2e65`. `env.demo.template`'s "minted once on
first boot" claim was false for the demo profile (`main.rs`
only `load_existing`s; missing file exits 2 — the auditor
booted the shipped binary against a fresh state directory and
watched it create nothing). The template's HT section now
states the rule, the first-boot step, and
`HT_MARKETPLACE_ID`'s accurate role (a fresh instance may fix
a newly generated id there; a restore must use the EXISTING
id — the template no longer restricts it to restore-only).
The creation step — file content `mkt_` + 32 lowercase hex
chars, mode 0600, before first boot — is now in the template,
in `docs/operations.md` §2 ("The Hidden Trades id file"), and
in `DEPLOY-DEMO-RUNBOOK.md` §5, with commands. The key file
shares the gap (it too must already exist outside the
development profile); the runbook step creates both files
together (key: 32 bytes as 64 hex chars, mode 0600), and the
template's key section and §2 say so. Note the demo's real
first boot in October evidently ran the development profile
once; nothing in the shipped demo path creates either file.

**E4 — a foreign legacy signature refuses, complete or not.**
`b790ebd`. `joint_signature_state` seeded
`verifies_for_someone` with `seller_signed && buyer_signed`,
so a legacy `.sig` verifying for NEITHER party was waved
through whenever the per-party files already completed the
statement (probe P5) — contradicting the function's own doc
rule that a present-but-non-verifying signature file is an
error. The seed is now `false`; the neither-party refusal is
unconditional. D2's duplicate-acceptance is untouched (a
legacy file duplicating a per-party signature verifies FOR
that party and still loads — its regression test still
passes). New regression test:
`foreign_legacy_sig_beside_a_complete_statement_refuses_the_load`
— a third party's signature planted at the legacy path beside
a complete settle refuses the load.

**E6 — the fail-closed test no longer reads the caller's
shell.** `4c45a1b`. `production_profile_fails_closed`'s
development control took `HT_ID_FILE_PATH` from the ambient
environment when one was provided; the auditor's run had one
exported globally, so the test's verdict rested on the
caller's shell. The path is the per-test temp dir
unconditionally. Verified: the test passes with a hostile
ambient `HT_ID_FILE_PATH` exported, and that path is never
written.

**E7 — gate runs stop writing into the tree.** `3c37e10` (and
the PNG determination in §2). `run-gate.sh` exports
`MEDIA_DIR` and `BLOB_DIR` to a fresh `mktemp` scratch
directory for the run, replacing any caller exports. Verified
at gate scale: across the final gate + completion runs, the
tree's `marketplace/tests/security/media/` count did not move
(21 pre-existing untracked debris files before and after),
while the scratch dir collected the runs' output (3 media
files, 36 blob files); no `marketplace.htid` exists anywhere
in the tree after the runs, and tracked changes were 0
throughout.

**E8 — the tree binding can't bury a tracked change.**
`f078faf`. `run-gate.sh` prints the tracked-modified count
(`git status --porcelain --untracked-files=no`) and the
untracked count (`git ls-files --others --exclude-standard`)
as separate lines. The untracked figure is a per-file count,
so it is not comparable to the old lumped line (27 at
`dcddf14`, which counted untracked directories as one entry
each): the final run binds as tracked 0 / untracked 285 —
the 285 are the known working papers and runtime debris
directories at per-file granularity.

**E9 — corrections to this batch's predecessor report.**
`53c8377`. "Corrections (audit 3)" appended to
`HT-H2-FIRST-BATCH-REPORT-2026-10-21.md`, append-only
(70 insertions, 0 deletions), covering the six record errors:
the phantom `ht_ordering` target (the second stored-status
coverage is `ht_publish_gate` lines 136 and 349); the role-map
attribution (the private `parse_held_statement` in
`seller-helper/helper-core/src/store.rs`, not an
`ht_statements` symbol); the git-status/htid method claim
(`.gitignore` line 15 hides the file — the claim re-proved by
filename search, the method restated); D3's "nothing depends
on held order" (`issue_window_ends` follows the FIRST held
outbound shipped statement); the §4 "media fixtures" misnomer
plus the manifest-scope note (`crates/envelope/tests/
blind_stage5.rs`, pinned by the close-out manifest, unchanged
in both batches); and item 5's stale doc, which is also fixed
at its source: `admit_joint_statement`'s comment no longer
says held order decides which completed settle the fold
reaches first.

**E10 — no code; H2-intake note.** The auditor's
spec-conformance note stands: §4.1's intake checks do not
reject an assignment naming the same key as buyer and seller
(the batch-1 D1 change reordered the role map to
buyer-first-precedence, so such a statement loads with one
party's signature unaccounted). **Recorded for H2 intake:**
when statement intake is built, refuse an assignment whose
buyer and seller fingerprints are equal, at intake, before
role precedence applies. No helper change is made now — the
helper only stores and folds assignments that arrive over the
conversation, and there is no intake surface to refuse at yet.
(Related, carried from the first batch: widen the `{seq:02}`
sidecar/file padding before intake admits arbitrary
counterparty statements.)

**E11 — status exit code matches its output.** `0998102`.
**Exit-code change, recorded as ordered:** `seller status`
and `buyer status` (one shared command) now exit NON-ZERO
(1, via the existing fail path) when the store-level
`(evidence store) ERROR:` row is printed — previously the row
printed and the process exited 0, so a script checking the
exit code was told the status succeeded over a broken store.
Per-trade F10 ERROR rows keep exit 0: that trade is reported
and the rest of the status is real. New CLI test
(`status_over_an_unreadable_store_prints_the_error_row_and_fails`,
through the real binary): healthy store exits 0; a
dangling-symlink entry in `trades/` prints the ERROR row and
exits non-zero; buyer status over its own healthy store still
exits 0.

## 4. Test-delta reconciliation (671 → 678 passed, 680 → 688 total)

Every target whose count changed between the two gate logs;
all other targets are identical in count.

| target | baseline | final | delta | why |
|---|---|---|---|---|
| `domain` lib | 24 | 28 | +4 | E1+E5: settle+receipt conflict both orders; same-terms/different-month settles; two receipts close; foreign receipt not complete |
| `helper_core` lib | 18 | 21 | +3 | E2: dangling-symlink enumeration + resolvable-link companion; E4: foreign legacy sig beside a complete statement |
| `cli_ht` | 2 | 3 | +1 | E11: status ERROR row + non-zero exit |
| `blind_ht1` | 24 passed | 23 passed, 1 failed | 1 flip | E1 by design (§1): `fold_lapsed_and_terminals_ignore_later_statements` — NOT edited; re-authoring is Q3's |

Net: +8 new tests, one pass→fail flip (the designed one),
no test deleted, no `#[ignore]` changed, no locked suite's
count moved except `blind_ht1`'s verdict flip above.

## 5. Locked-path manifest (standing N4 item)

SHA-256 of every file under `marketplace/tests/security/**`
plus `marketplace/docs/invariants.md`, before the batch (at
`dcddf14`) and after it (at `53c8377`). Exactly ONE declared
difference: the five runtime-output PNGs are gone (E7, §2).
Every `blind_*.rs` suite — including `blind_ht1.rs`, whose
failure is a verdict change, not a byte change — the README,
`src/lib.rs`, `Cargo.toml`, and `docs/invariants.md` are
byte-identical across the batch.

Before:

```
89b314949616c7af874267a03dfea2af655354edb9fc43cdf7f02b0919dcb90c  marketplace/docs/invariants.md
4426731ddf3877ed1191f54270b1e1fd2368eee3d05ad47132e8f6b369fe1d16  marketplace/tests/security/Cargo.toml
77b35f84f3b9dc3c109917851c8628f5b2dca98f7d081fa2267490b81e7bbe8a  marketplace/tests/security/README.md
154fe7d092e3239ee92ed554a6177b6cf7b26752165d7548cc5831fbf177a76a  marketplace/tests/security/blind_direct_v1.rs
c20fbe00c49a3e64e1a1580c146f72d49c58d7951617ccefdd0acdafe679af87  marketplace/tests/security/blind_ht1.rs
702a23b531fdab59bf75b24fd3f8830c3fc2461ecef69bea072ee0a2b92e933e  marketplace/tests/security/blind_stage1.rs
0555d5d4d9cb8517962ced46f9f68a1029765efc82e0e700e3c8388e359a2b93  marketplace/tests/security/blind_stage10.rs
347bf65d90d6215b35b939f7711e6f651ce86ba5818087901cf748e4c0b8ca02  marketplace/tests/security/blind_stage2.rs
e3cee166a880ab95bd0cb827f2b2dcb80a905bfcf6a6860931abe3e7c14b6c71  marketplace/tests/security/blind_stage3.rs
0fea6f68bbc7ae627b89a4521cc413043a51e870b14ed03d5804b854dfbf8e47  marketplace/tests/security/blind_stage4.rs
5de41f8e44399fed1544c96473ec700e9839c80a4e5e28510208587dda0b2e12  marketplace/tests/security/blind_stage6.rs
7ba8dcb6684fa605333deab9b060a3865a0f2f1cb62b820e2c6cbd98ec8f11aa  marketplace/tests/security/blind_stage9.rs
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/2c07c9de955f2f0a575670550ebcfb56.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/396fe560ca3e1c02816d324bc2ad269a.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/580bbbf97480414748721220a58bcd01.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/aa6786f9219555e539f105e05ac63ff8.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/f4c7d313ed23c09211a0a25a124169dc.png
5eae21ee8c9ad3866f34da62aa894f9659df4318609032188ead58f855cd8942  marketplace/tests/security/src/lib.rs
```

After:

```
89b314949616c7af874267a03dfea2af655354edb9fc43cdf7f02b0919dcb90c  marketplace/docs/invariants.md
4426731ddf3877ed1191f54270b1e1fd2368eee3d05ad47132e8f6b369fe1d16  marketplace/tests/security/Cargo.toml
77b35f84f3b9dc3c109917851c8628f5b2dca98f7d081fa2267490b81e7bbe8a  marketplace/tests/security/README.md
154fe7d092e3239ee92ed554a6177b6cf7b26752165d7548cc5831fbf177a76a  marketplace/tests/security/blind_direct_v1.rs
c20fbe00c49a3e64e1a1580c146f72d49c58d7951617ccefdd0acdafe679af87  marketplace/tests/security/blind_ht1.rs
702a23b531fdab59bf75b24fd3f8830c3fc2461ecef69bea072ee0a2b92e933e  marketplace/tests/security/blind_stage1.rs
0555d5d4d9cb8517962ced46f9f68a1029765efc82e0e700e3c8388e359a2b93  marketplace/tests/security/blind_stage10.rs
347bf65d90d6215b35b939f7711e6f651ce86ba5818087901cf748e4c0b8ca02  marketplace/tests/security/blind_stage2.rs
e3cee166a880ab95bd0cb827f2b2dcb80a905bfcf6a6860931abe3e7c14b6c71  marketplace/tests/security/blind_stage3.rs
0fea6f68bbc7ae627b89a4521cc413043a51e870b14ed03d5804b854dfbf8e47  marketplace/tests/security/blind_stage4.rs
5de41f8e44399fed1544c96473ec700e9839c80a4e5e28510208587dda0b2e12  marketplace/tests/security/blind_stage6.rs
7ba8dcb6684fa605333deab9b060a3865a0f2f1cb62b820e2c6cbd98ec8f11aa  marketplace/tests/security/blind_stage9.rs
5eae21ee8c9ad3866f34da62aa894f9659df4318609032188ead58f855cd8942  marketplace/tests/security/src/lib.rs
```

## 6. Deviations and notes, stated plainly

(a) **The final gate is two logs, not one.** Cargo's per-phase
fail-fast plus the one designed failure make a single green
`run-gate.sh` log impossible for this batch by construction;
§1 records both logs and their hashes rather than presenting
the completion run as the gate. Once Q3 re-authors the two
pins, a verbatim run should print `gate: PASS` again.

(b) **The phase split in §1 is from the completion run's
target accounting** (security = the `security-tests` package
targets; seller-helper counted separately as the gate does).

(c) **E3's docs are written from the code's actual behaviour**
(`main.rs` profile match, `htid.rs` validation, keyfile
format), and the demo's October first boot is noted as it
must have happened — via a development-profile run — since
nothing in the shipped demo path creates either identity file.
If the owner remembers it differently, the docs are the part
to correct; the template's false sentence is gone either way.

## 7. Commits (branch `ht-h2-first-batch`, on `dcddf14`)

- `f1d9edc` E2 (audit 3): trade enumeration errors on an entry whose type cannot be determined
- `b790ebd` E4 (audit 3): a legacy signature verifying for neither party refuses, complete statement or not
- `bcfc2b4` E1+E5 (owner rules, Cameron 2026-10-22): different complete terminals conflict; settles differ by terms
- `4c45a1b` E6 (audit 3): production_profile_fails_closed uses its per-test temp dir unconditionally
- `0998102` E11 (audit 3): seller/buyer status exits non-zero when the store itself cannot be read
- `18e2e65` E3 (audit 3): the demo profile never mints the HT id — document the first-boot creation step
- `f078faf` E8 (audit 3): gate tree binding reports tracked changes and untracked files separately
- `3c37e10` E7 (audit 3): gate runs isolate runtime output; the five committed media PNGs were runtime output and are removed
- `53c8377` E9 (audit 3): Corrections (audit 3) appended to the first-batch report; the stale admission rule fixed at its source
- this report (E10's record is §3).

## 8. Carried forward (unchanged by this batch)

- The Q3 blind re-authoring now has a concrete second job:
  re-author `blind_ht1`'s two rule-4 pins
  (`fold_lapsed_and_terminals_ignore_later_statements`) to the
  E1 rule — a complete settle and a complete receipt held for
  one trade are a dispute, not a race either way.
- F6's live proof still waits on H2's receipt intake (its
  fold half closed in H1); the OutProofV2 stagenet
  binary-acceptance run remains the hard entry gate for proof
  intake; E10's same-key refusal and the `{seq:02}` padding
  widening belong to H2 intake.
- Dave fixture renewal due before 2027-10-20 (auditor note
  N12).
