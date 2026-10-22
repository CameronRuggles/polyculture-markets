# HT H2 — First Batch Report (2026-10-21)

Scope: the second-batch items from the re-verification of the fix
stack (`869c954`) — its Fix Brief tasks 4–10 (findings N3–N9) —
plus the two fold/store defects and the owner's conflict rule
from the close-out delta re-verification of `e4e899c` (findings
D2 and D3). Commissioned by the owner 2026-10-21 after H1 was
formally closed. Branch `ht-h2-first-batch` off `main` at
`4d9db82` (the merged H1 closure); `main` itself is untouched by
this batch.

Method, as before: the baseline gate was reproduced on the
branch point BEFORE any change (662/0/9, below); each task was
implemented and committed separately; test changes were made
only where a task orders them (tasks 4, 5, 9, 10 and the D2/D3
test additions). No `blind_*.rs` suite was edited — the one
locked-path change is the task-5 move, witnessed by the
SHA-256 manifest in §4. Failures were fixed in code, never in
tests; the D2 regression test was verified failing against the
pre-fix logic before the fix was accepted.

## 1. Gate record

| run | tree | passed | failed | ignored | log SHA-256 |
|---|---|---|---|---|---|
| baseline | `4d9db82` (branch point) | 662 | 0 | 9 | `b6343d86159cad5d6468d798da73fbe6fc7ae5b0a2ad89efe75e733ed6ec16b9` |
| final | `c94a540` (last code commit) | 671 | 0 | 9 | `52a557c38d99f8c6369b0a37a7e865e0e11ff1d891ff642f637e64b119287a4a` |

Both runs end `gate: PASS`. The baseline log predates task 8's
tree-binding lines; its HEAD was verified as `4d9db82` at run
start. The final log carries the new binding at its head:
`gate tree: HEAD c94a54088ea3e7a91fe848175e95821913c9360e`,
`gate tree: dirty files: 27` (the count is the untracked
working papers at the repo root and runtime artifact dirs; every
tracked file in the batch was committed before the run).

Phase split: baseline security 397/0/6, workspace 231/0/3,
seller-helper 34/0/0 (marketplace 628/0/9). Final: security
395/0/6, workspace 238/0/3, seller-helper 38/0/0 (marketplace
633/0/9).

Skip-as-pass labels (N7): the two known environment-limited
passes — `media_serve_http`'s HTTP cases without `MEDIA_WORKER`,
and one `messaging_audit` case without `gpg` — **did not occur
in either run of this batch**: the media worker was built and
pointed to, and gpg is present, so both suites ran their full
cases. This is recorded because the labels belong to the runs
where they occur; neither log contains a skip line.

Environment disclosure: this batch's gate runs executed in a VM
whose apt `postgresql-client` had been wiped and whose
user-space PostgreSQL tree ships no `psql`. The gate's database
rebuild therefore ran through a small Python (stdlib-only) psql
shim speaking the simple-query protocol, control-tested before
use (SELECT, DROP/CREATE DATABASE, ON_ERROR_STOP exiting
non-zero on bad SQL, and migration 0001 applied cleanly to a
scratch database). All other gate behaviour — compilation, the
suites, the seller-helper runs — is native. The shim is a local
environment prosthesis only; no repository file depends on it.

## 2. Test-delta reconciliation (662 → 671, +9 net)

Every target whose count changed, per the two gate logs; all
other targets are byte-identical in count.

| target | baseline | final | delta | why |
|---|---|---|---|---|
| `ht_invariants_scope` | 2 (security phase) | 2 (workspace phase) | 0 | task 5: moved out of the locked package into the app crate; same 2 tests |
| `ht_publish_gate` | 3 | 5 | +2 | task 4: `takedown_notifies_the_seller`, `second_takedown_is_refused_and_pre_takedown_status_survives` |
| `domain` lib | 21 | 24 | +3 | D3: `two_distinct_complete_settles_conflict_in_either_order`, `a_duplicated_settle_still_settles`, `one_complete_settle_and_one_over_amount_settle_settles` |
| `helper_core` lib | 14 | 18 | +4 | task 9: `trade_ids_match_the_open_store`, `unreadable_trades_directory_fails_loud`; D2: `legacy_sig_duplicating_a_per_party_sig_still_loads`; D3: `two_distinct_complete_settles_conflict_whichever_was_admitted_first` |

Marketplace 628 → 633 (+2 task 4, +3 D3 domain; the move is
phase-only). Seller-helper 34 → 38 (+4 helper-core). No test
was deleted; no `#[ignore]` changed; no locked suite's count
moved.

## 3. Per-task record

**Task 4 (N3) — dropped takedown coverage restored, non-locked.**
`508b891`. The blind_stage9 case swap (H1 F14 disposition) left
the notification and double-remove assertions of the original
case with no coverage anywhere. Both now have cases in
`crates/app/tests/ht_publish_gate.rs` (section 3, header-noted
as implementer-written pending H2's Q3 blind re-authoring):
a takedown writes exactly one `listing_removed` notification
for the seller (the `orders::notify` call moderation has made
all along), and a second `set_listing_removed(…, true)` returns
`ModError::BadInput`, leaves `pre_takedown_status = 'published'`
intact, and the subsequent restore still lands on `paused`
through the F14 gate — proving the restore read the preserved
value, not a clobbered `'removed'`. The third dropped assertion
(stored status reads `removed` while taken down) was already
covered twice (`media_disputes_audit`, `ht_ordering`); not
duplicated. The stale comment is corrected: that case's
assertion message no longer calls itself a "locked-suite pin".

**Task 5 (N4) — `ht_invariants_scope` out of the locked
package.** `22558e5`. `marketplace/tests/security/ht_invariants_scope.rs`
→ `marketplace/crates/app/tests/ht/ht_invariants_scope.rs`,
registered as an explicit `[[test]]` target of the app crate
(the `ht/` subdir keeps it out of cargo's autodiscovery, same
as before); the security package's manifest loses only that
target's entry. The suite's assertions are unchanged — the
invariants doc resolves identically (`../../docs/invariants.md`
from the app manifest dir). Its header note now tells the
truth: implementer-written under the owner's reviewed fix
brief, NOT blind-authored, moved because the locked package is
reserved for blind-authored suites. No blind/owner exemption
exists or is claimed. Its 2 tests now count in the gate's
workspace phase (security phase 397 → 395). The standing N4
manifest requirement is discharged in §4.

**Task 6 (N5) — Corrections (audit 2) appended to the H1 fix
report.** `21041bf`. Append-only (70 insertions, 0 deletions):
the seven misstatements the re-verification catalogued, each
beside the true statement, every one verified against the tree
or record before writing — the `--received-at` value and the
sidecar's timestamp are the canonical `YYYY-MM-DDTHH:MM:SSZ`
form, not integer unix seconds; a well-formed re-dated sidecar
LOADS SILENTLY (only a malformed one is refused — there is no
integrity check); the assignment's early/late field is
`expires_at` (`payment_due` exists nowhere); task 11's test is
`terms_version_rule_bites` in `ht_statements.rs`; there is no
`ExpectedSigners::for_kind` symbol (the role map is returned by
`ht_statements::parse_held_statement`); the restore test pins
the library `app::listings::submit_terms`, not the HTTP submit
route; and the pack's "no other test exercises listing removal
at all" was false when written (`media_disputes_audit` and
`ht_publish_gate` both exercise removal). See deviation (a)
for how the seven were identified.

**Task 7 (N6) — the htid file gets an operator path.**
`208d7ed`. `deploy/env.demo.template` gains an
`HT_ID_FILE_PATH` entry and a commented `HT_MARKETPLACE_ID`
alternative, with the permanence warning in the template
itself. `docs/operations.md` §2 gains "The Hidden Trades id
file" (per-instance, permanent, never rotates; backed up with
the deployment; losing it when the id is recorded nowhere else
strands the instance's HT history) and §3's backup script and
restore drill now carry the file; the demo runbook's §8 backup
block copies it beside the key file. The
`production_profile_fails_closed` development control now takes
`HT_ID_FILE_PATH` from the environment with a per-test tempdir
fallback, and asserts the id file landed there. Acceptance
verified at gate scale: `git status` for `crates/app/` is
byte-identical before and after the full final gate run, and no
`marketplace.htid` was minted (the baseline run had minted
one). See deviation (b) for the DEV_CONTROL item.

**Task 8 (N7) — gate runs bind themselves to a tree.**
`28005a9`. `run-gate.sh` prints `gate tree: HEAD <sha>` and
`gate tree: dirty files: <n>` before the preflight; both of
this batch's log hashes are recorded in §1 (raw logs stay
off-tree, as before).

**Task 9 (N8) — evidence-store reads fail loud.** `f86c930`.
`EvidenceStore::trade_ids` and `has_trades` now return
`Result`: a trades directory that exists but cannot be read is
an error in the F5 words ("an unreadable store is never an
empty one"); only a MISSING trades directory reads as an empty
store (a store never opened). `load_assignment` distinguishes
absent (no trade directory, or a readable directory with no
assignment file → `Ok(None)`) from present-but-unreadable
(→ `Err`). The failure propagates through
`collect_assignment_destinations` and
`PoolLedger::load_for_assign`, so **seller assign refuses over
an unreadable store** instead of seeding fresh over spent
destinations; `verify::trade_status` returns the store-level
`Err` and the CLI's status prints an `(evidence store) ERROR:`
row instead of "No trades in the evidence store". Per-trade
fold failures keep their F10 rows — only the enumeration
failure is store-level. Tests: `trade_ids_match_the_open_store`
and `unreadable_trades_directory_fails_loud` (the `trades/`
directory replaced by a regular file — a chmod would not stop
a root-running suite), the latter asserting the refusal at
enumeration, assignment load, ledger load-for-assign, and
status; the one existing `trade_ids()` call site in `cli_ht`
was updated mechanically.

**Task 10 (N9) — migration baseline by name, not count.**
`06d5265`. The pre-H1-schema restore test in `ht_publish_gate`
applied "everything except 0017" behind an exact count
assertion (17 files). It now applies migration files named
strictly below 0017 and the count assertion is gone, so the
next migration cannot be silently applied to the "pre-0017"
baseline or break the pin. 0017 itself is unchanged (still
applied via `include_str!` after the baseline).

**D2 — the legacy-signature duplicate no longer refuses the
load.** `d0390fd`. `joint_signature_state`'s legacy loop
skipped any party whose slot a per-party file had filled, then
reported the signature as verifying for NEITHER party and
refused the whole load — the delta auditor's probe (a
pre-rename store holding the seller's settle signature under
both the legacy and per-party names) made such a trade
unloadable. The legacy signature is now checked against BOTH
parties, taken slots included: it fills an unset slot, a
duplicate is accepted as the same evidence, and the refusal
remains only for a signature that verifies for neither party
while the statement is incomplete (an unresolvable certificate
for an unfilled slot lands on that same refusal, as before).
Regression test `legacy_sig_duplicating_a_per_party_sig_still_loads`
is the probe made permanent — legacy seller sig + seller
per-party countersig loads as a proposal; the buyer's
countersignature then settles with refund 1000 — and was run
against the pre-fix loop first, where it fails with the
auditor's exact error.

**D3 — two different complete settles are a conflict (owner
rule).** `c94a540`. **Owner decision, Cameron, 2026-10-21:**
two DIFFERENT complete settles for one trade are a conflict
(a dispute), never an order-dependent pick — a settle is a
jointly signed statement of final terms, not a payment, and
renegotiation (sign settle A, then settle B) is the realistic
path to holding two; arrival order must not decide which
agreement governs. Implemented in `domain::ht_fold`:
`TradeState` gains `Conflicted` (terminal). The fold pre-scans
the held set, deduplicates identical settles (a re-sent
statement is one settle), counts distinct settles passing
`check_settle`; two or more make the outcome `Conflicted`
with `refund_atomic: None`, presence-based — `paid`,
`shipped` and the issue window are computed over the FULL held
set (a conflict suppresses positional terminals, including a
receipt's, so nothing about the outcome depends on held
order), and terminal states supersede the overdue flag as
before. One complete settle plus one-signature proposals
still folds to the complete settle; an over-amount settle is
not complete and cannot conflict. Tests: three domain cases
(both held orders → the identical `FoldedTrade`; a duplicated
identical settle settles; one valid + one over-amount settle
settles, both orders) plus the auditor's store-level probe
made permanent (`two_distinct_complete_settles_conflict_whichever_was_admitted_first`:
two stores, opposite admission orders, identical Conflicted
folds). `blind_ht1` re-verified 24/24 against the changed fold
before the commit, and the final gate confirms it.

Receipts, examined as instructed: two complete RECEIPTS held
for one trade fold to the same `Closed` state in either order
— a receipt carries no outcome fields (no amount, no terms),
so there is no second outcome for order to pick between, and
no ambiguity of the D3 kind arises. The rule was therefore
NOT extended to receipts. See noted item (e) for the one
interaction the implementation does decide.

## 4. Locked-path manifest (standing N4 item)

SHA-256 of every file under `marketplace/tests/security/**`
plus `marketplace/docs/invariants.md`, before the batch
(at `4d9db82`) and after it (at `c94a540`). All `blind_*.rs`
suites, the README, `src/lib.rs`, and the media fixtures are
byte-identical across the batch. Exactly two entries change:
`ht_invariants_scope.rs` leaves the locked package (task 5),
and `tests/security/Cargo.toml` loses its `[[test]]` entry.
`docs/invariants.md` is unchanged.

Before:

```
106c45f9ff4fe1bbaf317a657e3ab2f0e94d8ee465e55dab8579020359825e68  marketplace/tests/security/Cargo.toml
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
7f635ca43b1660ebc24ce980a2500e4574af66e55358283352153d2cf69d6f64  marketplace/tests/security/ht_invariants_scope.rs
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/2c07c9de955f2f0a575670550ebcfb56.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/396fe560ca3e1c02816d324bc2ad269a.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/580bbbf97480414748721220a58bcd01.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/aa6786f9219555e539f105e05ac63ff8.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/f4c7d313ed23c09211a0a25a124169dc.png
5eae21ee8c9ad3866f34da62aa894f9659df4318609032188ead58f855cd8942  marketplace/tests/security/src/lib.rs
89b314949616c7af874267a03dfea2af655354edb9fc43cdf7f02b0919dcb90c  marketplace/docs/invariants.md
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
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/2c07c9de955f2f0a575670550ebcfb56.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/396fe560ca3e1c02816d324bc2ad269a.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/580bbbf97480414748721220a58bcd01.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/aa6786f9219555e539f105e05ac63ff8.png
eacb1a012fc0820bb358ea06380857fd97d62a420932142014ac89bcc4afbbc3  marketplace/tests/security/media/f4c7d313ed23c09211a0a25a124169dc.png
5eae21ee8c9ad3866f34da62aa894f9659df4318609032188ead58f855cd8942  marketplace/tests/security/src/lib.rs
```

The moved suite at its new home (content differs from the old
locked copy only in the header authorship note):
`0b8088aedbc108c77da7c5d13eddd0f83b33335316adb52dfe01b4ecbbd6e430  marketplace/crates/app/tests/ht/ht_invariants_scope.rs`

## 5. Deviations and noted items, stated plainly

(a) **Task 6's item list.** The commissioning brief's
parenthetical list for this task ("task 8's form, STORE_README
root, pool.json.md naming, fold/AppState unreachable arm")
matches nothing locatable in the tree or the records. The
batch instead corrected the seven misstatements the
re-verification report's own N5 section enumerates — each one
located verbatim in the H1 fix report (or, for the seventh, in
the re-verification pack) and verified against the tree before
the correction was written. The seven are listed in §3 task 6.

(b) **Task 7's DEV_CONTROL item.** No variable named
`DEV_CONTROL` (or any dev-control secret) exists anywhere in
the tree, the deploy material, or the reports — the
development control is a profile behaviour of the binary, not
an env-gated secret. Nothing was added for it. The template
carries the two identity variables the binary actually reads
(`HT_ID_FILE_PATH`, `HT_MARKETPLACE_ID`).

(c) **Task 8's scope.** As commissioned, this batch added the
HEAD + dirty-count binding only — not the auditor brief's
refuse-on-dirty behaviour or toolchain-version lines.

(d) **Skip-as-pass labels.** Neither known environment-limited
case occurred in this batch's baseline or final runs; §1
records them as checked and absent rather than omitting the
topic.

(e) **Noted for the owner (D3 receipts interaction).** Two
complete receipts present no ambiguity and the rule was not
extended (§3, D3). One interaction the implementation DOES
decide, by the rule's presence-based shape: if a trade holds
BOTH a complete receipt AND two distinct complete settles,
the fold reports `Conflicted`, not `Closed` — the money terms
are disputed even though receipt was acknowledged, and a
conflict is the outcome a moderator should see first. This
follows from the owner's rule as stated; if the owner wants a
receipt to outrank a settle conflict, that is a one-line
precedence change with its own test, and it is flagged here
rather than buried.

(f) **D2's residual strictness, unchanged.** A legacy signature
that verifies for neither party still refuses the load when
the statement is incomplete — including the case where a
certificate for an unfilled slot cannot be resolved, which
lands on the same neither-party refusal, as before. D2
widened only the duplicate case, as the finding specified.

## 6. Commits (branch `ht-h2-first-batch`, off `4d9db82`)

- `508b891` task 4 (N3): restore dropped takedown coverage in a non-locked suite
- `22558e5` task 5 (N4): move ht_invariants_scope out of the locked package
- `21041bf` task 6 (N5): Corrections (audit 2) appended to the H1 fix report
- `208d7ed` task 7 (N6): give the htid file an operator path
- `28005a9` task 8 (N7): print tree binding at the top of every gate run
- `f86c930` task 9 (N8): evidence-store reads fail loud
- `06d5265` task 10 (N9): migration baseline by name, not by count
- `d0390fd` D2: a legacy sig duplicating a per-party sig no longer refuses the load
- `c94a540` D3 (owner rule, Cameron 2026-10-21): two different complete settles are a conflict, never first-complete-wins
- this report.

## 7. Carried into H2 (unchanged by this batch)

- F6's live proof still waits on H2's receipt intake (its
  fold half closed in H1).
- The OutProofV2 stagenet binary-acceptance run remains the
  hard entry gate for proof intake.
- The Q3 blind re-authoring — re-locking the takedown coverage
  (task 4) and replacing the moved scope guards with
  blind-authored equivalents if the owner wants them locked
  (task 5) — is H2 work, as is the parked decision on whether
  `blind_ht1` gets a blind re-authoring.

## Corrections (audit 3)

Appended 2026-10-22 by the HT H2 fix batch (append-only, like
audit 2's corrections to the H1 report). The dcddf14
re-verification found no code defect behind any of these, but
six statements in this report are wrong or imprecise as
records; each is corrected beside the true statement, verified
against the tree before writing.

1. **§3 task 4's "covered twice".** The report said the stored-
   status assertion was "already covered twice
   (`media_disputes_audit`, `ht_ordering`)". No target named
   `ht_ordering` exists. The two places are
   `media_disputes_audit` and `ht_publish_gate` — the latter
   asserts the stored `'removed'` status at lines 136 and 349.
   The conclusion (the assertion was not duplicated) stands.

2. **§3 task 6's role-map attribution.** The correction to the
   H1 fix report said "there is no `ExpectedSigners::for_kind`
   symbol (the role map is returned by
   `ht_statements::parse_held_statement`)". No symbol named
   `parse_held_statement` exists in `ht_statements`; the
   function is the private `parse_held_statement` in
   `seller-helper/helper-core/src/store.rs`.

3. **§3 task 7's verification method.** The report said
   acceptance was verified by "`git status` for `crates/app/`
   byte-identical before and after the gate run". `git status`
   can show no such thing for `marketplace.htid`: `.gitignore`
   line 15 lists the filename, so the file is invisible to git
   status wherever it lands. The claim itself was re-proved by
   the re-verification's method — a filename search of the tree
   after a full gate run finds no `marketplace.htid` anywhere —
   but the method named in this report could not have shown it.

4. **§3 D3's "nothing depends on held order".** The report said
   "`paid`, `shipped` and the issue window are computed over
   the FULL held set", so that "nothing about the outcome
   depends on held order". State and refund do not depend on
   order; the issue window can. `shipped_effective` is set by
   the FIRST held outbound shipped statement only, so where
   two held shipped statements disagree on the ship date,
   `issue_window_ends` follows whichever was held first. The
   sentence holds for `paid` and `shipped` (set-valued over the
   full set) and not for the window.

5. **The stale rule in the code's own docs.** §3's D3 entry
   superseded first-complete-wins in the fold, but the doc
   comment on `admit_joint_statement` in
   `seller-helper/helper-core/src/store.rs` still said "held
   order decides which completed one the fold reaches first".
   Corrected at its source by the fix batch (E9): the comment
   now restates the conflict rule.

6. **§4's "media fixtures" and manifest scope.** §4 called the
   five tracked files under `marketplace/tests/security/media/`
   "media fixtures". They are not fixtures: they are runtime
   output (one shared SHA-256, the media suite's sanitizer
   output for a fixed input, under random-hex names) committed
   in the initial import, and nothing in the tree reads them as
   input. The fix batch removes them under the owner's ruling
   (E7), with its own pre/post manifest. Separately, §4's
   manifest scope was narrower than the close-out manifest's
   without saying so: the close-out manifest also pinned
   `marketplace/crates/envelope/tests/blind_stage5.rs`
   (`390e13a75f8e64de1939f25c5eda8d0e78fa5f009640d1deafe443567031511b`),
   which is outside §4's "every file under
   `marketplace/tests/security/**` plus invariants" scope and
   is unchanged by this batch and the fix batch alike.
