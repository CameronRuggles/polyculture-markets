# Review pack — amend the pinned default site name (Q10 gate)

**Date:** 2026-10-17
**Change under review:** one display string — the compiled-in default
`site_name` — plus the two test expectations that pin it.
**Gate:** DECISIONS-LOG Q10. Review packs are allowed for stage gates
only under conditions: fresh context, spec + diff only, file:line
evidence required. This pack is the whole input.

## Decision being implemented

On 2026-10-17 the owner decided the marketplace software's product
name: **Polyculture Markets** (the OS sibling is Manioc Server; both
names from James C. Scott). Recorded in
`~/workspace/onion-host-os/NAMING-DECISION-SHEET-2026-10-16.md`
(DECIDED section) and `~/workspace/onion-host-os/REBRAND-SCOPE-2026-10-17.md`
class (c) item 1, which classifies this exact string as "a code change
through the marketplace's own gate process."

## Spec context

- Stage 10 brief (STAGE10-BRIEF.md) pinned the then-current default
  site name as part of the §15 instance-identity surface. The locked
  suite records the pin and its basis: `tests/security/blind_stage10.rs`
  assumption A8 (line 76) — "The brief pins the site_name default
  ("Vespiary Market")…; only the default is asserted."
- `site_name` is display-only: it is the header/brand string an
  instance shows when the operator has not set the `SITE_NAME` env
  var. It does not enter any signed statement, any ID pattern, any
  state machine, or any authorization decision.
- The protocol constant `marketplace_id` (default `vespiary-market`,
  `crates/app/src/config.rs:156`) is **not** part of this change. It is
  baked into the signed statement format
  (`xmr-direct-v1|vespiary-market|…`, `crates/app/src/payments.rs`)
  and stays permanently.

## The diff (complete)

1. `crates/app/src/config.rs:162`
   - `_ => "Vespiary Market".to_string(),`
   - → `_ => "Polyculture Markets".to_string(),`
2. `crates/app/src/config.rs:225` (the module's own unit test)
   - `assert_eq!(c.site_name, "Vespiary Market");`
   - → `assert_eq!(c.site_name, "Polyculture Markets");`
3. `tests/security/blind_stage10.rs:186` (locked suite — the amendment
   this review gates)
   - `assert_eq!(c.site_name, "Vespiary Market", "brief default site name");`
   - → `assert_eq!(c.site_name, "Polyculture Markets", "brief default site name, as amended 2026-10-17");`
   - and assumption A8 (`tests/security/blind_stage10.rs:76`) updated
     to record the amendment and its basis (owner decision 2026-10-17),
     keeping the original pin text visible in the note.

Nothing else. `grep -rn "Vespiary Market"` over the tree (excluding
`target/`) returns exactly six hits: the three above, plus three
deploy/doc display values that are operator-facing text, not tests —
`deploy/env.demo.template:20`, `deploy/marketplace-demo.service:2`,
`docs/operations.md:23` — which adopt the new name as ordinary
documentation edits (REBRAND-SCOPE class (a)) and are not part of this
gate question.

## Rationale

- The pinned value is a brand string whose entire content is the
  product's name; the owner has renamed the product. The pin's purpose
  (the default must be deliberate, asserted, and not drift silently)
  is preserved: the default remains explicit, asserted at both the
  unit and locked-suite layers, and the amendment is documented at
  the pin site.
- No behavior changes: resolution order (env override wins), failure
  modes, and every other default in `InstanceConfig::resolve` are
  untouched. An instance that sets `SITE_NAME` sees no difference.
- The change is one string literal in one match arm; there is no
  plausible coupling to payments, crypto, authorization, or state
  machines. Reviewer is asked to verify that claim against the tree
  (all uses of `site_name` / `instance.site_name`).

## What the reviewer is asked

Verdict (approve / reject) with file:line evidence on:

1. The diff above is complete — no other code or locked test depends
   on the literal `"Vespiary Market"` or on the old default's value.
2. `site_name` has no consumer where a value change alters behavior
   beyond display (check every `site_name` use, incl. templates).
3. `marketplace_id` and its pins (incl. `blind_stage10.rs` R8
   assertion and `blind_direct_v1.rs`) are untouched by this change.
4. The A8 assumption-note amendment preserves the audit trail
   (original pin still visible, amendment dated and attributed).
