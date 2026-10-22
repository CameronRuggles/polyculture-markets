# HT Stage H1 — Close-Out Report (re-verification fix brief, tasks 1–3) — 2026-10-21

This report records the close-out batch that answers the external
re-verification of the H1 fix stack (`869c954`, verdict: H1 does not
close yet — F12/F19 unaccounted, N1, N2). It executes tasks 1–3 of
that re-verification's fix brief. Tasks 4–10 of the same brief
(N3–N9 and the standing hygiene items) are NOT in this batch; the
brief assigns them to H2's first batch, and they are untouched here.

Commits on `deployment-fix-batch`, above the audited `869c954`:

| Commit | Task |
|---|---|
| `233f3ea` | Task 1 — closure mapping for all of F1–F19 (record only) |
| `aa27d50` | Task 2 — N1: settle and receipt require BOTH parties' signatures |
| `43fc734` | Task 3 — N2: restate v1 (9) in `docs/invariants.md` as built |
| (this report's commit) | This report |

## Environment note (read first)

The builder VM was replaced mid-batch: `/tmp` (the user-space
PostgreSQL and its data) was wiped after the baseline gate and
before the final gate. PostgreSQL was re-provisioned from the
persisted binaries per `AGENTS.md` (fresh `initdb`, trust auth,
port 5432, database `marketplace_dev`); no repository state was
affected (all commits and both gate logs live under `~`). The
baseline gate below ran on the previous VM generation, the final
gate on the new one — same tree lineage, same recorded gate
environment (`run-gate.sh` preflight: `DATABASE_URL`,
`MEDIA_WORKER`, `NETTLE_PREGENERATED_BINDINGS`,
`PKG_CONFIG_PATH`, disk-backed `TMPDIR`). Both log files are kept
with this record's working papers; their SHA-256s:

- baseline (`869c954`, before any close-out change):
  `31781aca6cb771d1ebd514f83c70d6539f96e519f0ba44aef18d52c106a23aa4`
- final (this stack's tip, code at `43fc734`):
  `6d08c6bb5f142b588d1785377670594243fa8315ad51ce1d0c38d9032635d2e6`

## Baseline

Before any close-out change, the full `run-gate.sh` was re-run at
`869c954` and reproduced the fix stack's recorded gate **exactly**:
marketplace **628 passed / 0 failed / 9 ignored**, seller-helper
**31 / 0 / 0** (combined 659/0/9), `gate: PASS`. The starting
point of this batch is therefore the state the re-verification
audited, not a drifted tree.

## Task 1 — F12 and F19 mapped (record only) · `233f3ea`

The fix report named no F12 or F19 anywhere. Audit 1's actual text
was recovered from the uploaded report
(`Polyculture_Markets___HT_Stage_H1_Audit_1`) and both findings
were read there; the re-verification auditor's guesses about their
identity were wrong in both cases (it guessed F12 ≈ the task-9
spike-evidence ruling and F19 ≈ blind-authorship custody — F19's
real subject is adjacent to custody, but it is not that).

**F12** (Process · Verified) — "The blind suite was authored after
the implementation it tests." At `d21c523`, `crates/domain` and
`helper-core` landed at 19:16:23Z and the statements fold at
19:28:47Z (2026-10-20); `tests/security/blind_ht1.rs` landed at
19:52:59Z and was extended at 20:19:53Z — after the code it
tests, against `tests/security/README.md` rule 1, and without the
plain-language assertion list README Q10 asks for. Git-verified
again in this batch (commit times and the single later touch of
`blind_ht1.rs`, by fix task 2's CRLF case, `664cf63`). **Disposition:**
the H1 report's "authored before the implementation" claim is
withdrawn as not borne out by git history; the standing answer is
owner decision Q3 (a separate blind author for locked HT suites
from H2 on) plus the `92f76d7` re-authoring demonstration (17
assertions mapping 1:1 onto the implementer's case list). The
underlying fact cannot be undone retroactively; nothing in this
batch pretends otherwise.

**F19** (Info · Verified) — "The H1 report overstates blind_ht1's
mutation coverage." `blind_ht1.rs:267-289` at `d21c523` runs the
same six mutations (LF, blank line, extra field, marketplace,
spacing, CRLF) plus indentation; key-order mutation is exercised
only on the receipt; a bad signature digest is fed to two
statements, not all eleven. The parsers do enforce field order,
so the exposure was report accuracy, not enforcement.
**Disposition:** correction of record, made in the appendix
itself; no code or test change follows from F19.

The appendix (append-only; no pre-existing line of the fix report
was edited) maps all nineteen findings to their closing
task/commit and status, with Audit 1's severity for each.
## Task 2 — N1: both signatures for settle and receipt · `aa27d50`

**Defect (verified in the pre-batch tree).**
`seller-helper/helper-core/src/store.rs` `parse_held_statement`
mapped `settle` and `receipt` to `ExpectedSigner::Either`, so the
store verified ONE signature from either party and
`load_events` emitted the fold event; `ht_fold.rs` then treated
the trade as terminal (Settled / Closed). The format contract
says otherwise: `crates/domain/src/ht_statements.rs` — settle
"signed by both parties", receipt "both parties sign the same
bytes". The re-verification also showed the earlier pack's
proposed fix could not work: there is no
`ExpectedSigners::for_kind`, and a one-line fixed-signer change
would still have left the fold consuming a one-signature
statement.

**Fix (store only; `ht_fold.rs` unchanged — it only ever sees
completed statements).**

- A joint statement is held as one statement file plus one
  signature file per party: `NN-<kind>.seller.sig` and
  `NN-<kind>.buyer.sig` beside `NN-<kind>.txt`.
- `admit_statement` runs all existing checks for the presented
  signature (parse, trade-id, party, verify, received-at format),
  then `admit_joint_statement` files the signature under the
  signer's party slot. Admitting the SAME bytes from the other
  party adds their slot (a countersignature); re-admitting a held
  signature is a no-op; DIFFERENT bytes under the same kind are a
  separate proposal with its own sequence number — held order
  decides which completed proposal the fold reaches first.
- `load_events` re-verifies per party (`joint_signature_state`):
  both parties' signatures held and verifying → the event is
  emitted; exactly one → the statement is a non-terminal
  proposal and yields NO event and no error; no signature file
  at all, any present signature failing verification, or an
  unresolvable signer certificate → the usual held-set error.
  A legacy unsuffixed `NN-<kind>.sig` (pre-joint on-disk shape)
  counts as the evidence of whichever party it verifies
  against, so an old one-signature hold loads as exactly what
  it is — a proposal, never a terminal state.
- All other kinds, the pool ledger, and every CLI behaviour are
  unchanged. No production command admits a settle or receipt in
  H1 (verified: the only `admit_statement` callers admit
  `assignment` and `open`), so no caller changes were needed.

**Test replacement — the batch's single ordered exception.** The
re-verification brief orders this replacement; it is declared
here and in the commit message, per the batch's instructions.
Removed: `admit_accepts_a_settle_from_either_party`, which pinned
the one-signature behaviour as correct. Added (helper-core unit
tests, `store.rs`):

- `settle_completes_only_with_both_parties_signatures` — a
  buyer-only settle is held, loads with NO settle event, and the
  fold is not terminal; after the seller countersigns the same
  bytes, the settle event reaches the fold and the trade folds
  to Settled with the statement's refund.
- `receipt_completes_only_with_both_parties_signatures` — the
  mirror image: seller-only receipt → no receipt event, fold not
  Closed; buyer countersignature → Closed.
- `joint_statement_from_a_third_party_is_refused_in_either_slot`
  — a third party is refused as a settle's FIRST signer and as
  the COUNTERSIGNER of a held one-party settle.
- `load_reads_a_legacy_one_signature_settle_as_a_proposal` — a
  hand-placed pre-joint hold (`NN-settle.txt` + unsuffixed
  `.sig`) loads without error and yields no settle event; a
  per-party signature file that does not verify is refused at
  load.

Fixture fallout in the same (non-locked) test module, assertion
intent unchanged in both: `held_trade`'s receipt gains the
buyer's countersignature (a one-signature receipt no longer
folds to Closed, which the round-trip test asserts), and
`load_refuses_unsigned_tampered_and_foreign_files` case (a) now
removes BOTH receipt signature files before asserting the
"without its signature" refusal.

Negative-control note: the baseline gate ran the OLD test green
(it asserted the one-signature behaviour); the new tests assert
the converse and pass on the fixed tree. Both cannot pass on the
same code — the pair is the flip's evidence.

## Task 3 — N2: v1 (9) restated as built · `43fc734`

`marketplace/docs/invariants.md` is a locked-path file ("Changes
to this file require the owner's review", spec §22). Its Q4
Scope paragraph quoted v1's old (9) as operative, including a
wallet-RPC `validate_address` cross-check with "disagreement
meaning reject + security event". No wallet-RPC client exists in
the tree; `docs/threat-model.md` T2 already records the
cross-check as NOT built (corrected once before, messaging audit
ML2).

The Scope paragraph's (9) now reads as built, mirroring T2: the
core verifies the seller signature against the key pinned on the
order and validates the address with the in-process address
parser; the `validate_address` cross-check is marked not built
(threat model T2). `validate_address` now appears in
`invariants.md` exactly once, as not built.

Before editing, every string `tests/security/ht_invariants_scope.rs`
asserts was read from the test source; all seven (the Q4 scope
header, `govern **Hidden Trades**`, ``one global `destinations` ``,
`Invariant (11) belongs to that v1 scope`, the squashed
keeps-the-pre-amendment sentence, `The server stores no
destinations.`, `The server holds no order or trade state.`) are
unchanged by the edit, and the suite passes 2/2 on the final
tree (and in the full gate below).

## Locked-path manifest (pre / post SHA-256)

Scope: `marketplace/tests/security/**` +
`marketplace/crates/envelope/tests/blind_stage5.rs` +
`marketplace/docs/invariants.md`. Pre-hashes were taken at
`869c954` before any close-out edit; post-hashes at `43fc734`.
**Exactly one locked-path file changed — the deliberate task-3
edit:**

- `marketplace/docs/invariants.md`:
  pre `b9e568268e8b3b10ab260b858695dbfb0a5d8b2ace8f7bc47090f6695fdb1b71`
  → post `89b314949616c7af874267a03dfea2af655354edb9fc43cdf7f02b0919dcb90c`

Every other file in scope is byte-identical pre/post, including
all of `tests/security/` (blind suites, `ht_invariants_scope.rs`,
`Cargo.toml`, `README.md`, `src/lib.rs`) and `blind_stage5.rs`
(pre/post `390e13a75f8e64de1939f25c5eda8d0e78fa5f009640d1deafe443567031511b`).
Unlike the fix stack (re-verification N4), this batch ships its
manifest with the record.

## Final gate

Full `./run-gate.sh` on the final tree (code at `43fc734`):
**`gate: PASS`** — **662 passed / 0 failed / 9 ignored**.

Delta against the recorded fix-stack gate and this batch's own
baseline re-run (identical numbers):

| Suite | Before | After | Δ |
|---|---|---|---|
| marketplace (security phase + workspace) | 628/0/9 | 628/0/9 | 0 |
| seller-helper | 31/0/0 | 34/0/0 | **+3** |
| combined | 659/0/9 | 662/0/9 | **+3** |

The +3 is exactly helper-core's lib target (11 → 14: −1 replaced
test, +4 new tests, named under Task 2 above). No test was
removed or ignored anywhere else; the ignored count is unchanged
at 9; no locked test was edited (manifest above). Marketplace
totals did not move: task 3 changed only documentation prose
outside every string the scope suite asserts.

## What this batch does NOT close (owner calls, stated plainly)

1. **N2's wording still awaits the owner's formal sign-off** —
   `invariants.md` requires it by its own rule; the edit is
   built and gated, but the file is not "reviewed" until the
   owner says so.
2. **F6's partial state** stands as the fix report recorded it.
   Accepting it as a formal H2 hand-off is an owner call; this
   batch takes no position.
3. **The OutProofV2 spike gate** (binary acceptance of a
   constructed proof by a real stagenet node) remains an
   owner-side rig item; accepting its move from an H1-close item
   to gating H2's proof intake is an owner call.

Fix brief tasks 4–10 (N3's lost removal-coverage assertions,
N4's locked-package hygiene, N5's record corrections, N6's htid
operator path, N7's gate-log tree binding, N8's fail-loud store
reads, N9's migration-count test) ride with H2's first batch, as
the brief assigns them. H1 closes when the re-verification
auditor confirms tasks 1–3 and the owner makes the three calls
above.

---

## Correction (2026-10-21) — F12 evidence paragraph, two false specifics

Found by the external auditor's close-out delta re-verification
at `e4e899c` (finding **D1**). The F12 evidence paragraph above
(the "Task 1" section) contains two specifics that are false:

> "`tests/security/blind_ht1.rs` landed at 19:52:59Z and **was
> extended at 20:19:53Z**"

> "Git-verified again in this batch (commit times and **the
> single later touch of `blind_ht1.rs`, by fix task 2's CRLF
> case, `664cf63`**)"

The git-verified facts (re-checked with `git log` on the file
and `git show --stat 664cf63` when this correction was written):

- Exactly **one** commit has ever touched
  `marketplace/tests/security/blind_ht1.rs` in the whole
  history: `096add5` (2026-10-20T19:52:59Z, "HT H1 (gate):
  blind_ht1 locked suite — 24/24"). The file was created in
  that commit and never extended or otherwise modified
  afterwards; no commit at 20:19:53Z touched it.
- `664cf63` (2026-10-21T19:49:10Z) is "HT H1 fix task 2: a
  real mkt_ marketplace id per instance (audit F1)". It changed
  `marketplace/crates/app/src/config.rs`, `htid.rs`, `lib.rs`,
  `main.rs` and `web.rs`, `marketplace/crates/app/templates/seller.html`,
  and two app test files. It is not a CRLF case and did not
  touch `blind_ht1.rs`.

The balance of the F12 paragraph stands: the implementation
commits (19:16:23Z, 19:28:47Z, 2026-10-20) precede the suite's
single landing at 19:52:59Z, which is the fact F12 rests on.

The F12 closure itself is unaffected: it stands on the
appendix in `HT-H1-FIX-REPORT-2026-10-21.md`, which states the
F12 evidence correctly. That file is not touched by this
correction. This section is append-only; the original
paragraph above is left as written, errors included, so the
record shows both.
