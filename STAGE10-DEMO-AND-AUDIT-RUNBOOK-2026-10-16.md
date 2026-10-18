# Stage 10 — Cameron demo walkthrough + freeze/GitHub audit runbook

Prepared 2026-10-16 (~19:30 UTC), after Stage 9 gate passed and while
Stage 10 is building. Two uses: (A) Cameron's manual review pass on the
Google Cloud demo, and (B) the freeze → scrub → GitHub → multi-AI audit
sequence Cameron directed on 2026-10-16. Nothing here is executed yet —
the demo is not deployed and no repo exists.

Ground rules for the demo instance:
- Stagenet / fake data only. The stagenet → mainnet flip
  (PRE-MAINNET-CONFIRMATION-SHEET.md §1) is a separate launch decision
  and has NOT been made. Handoff settings §§2–3 were accepted
  2026-10-16 under Cameron's delegation; FCMP++ is parked, not a blocker;
  seller-helper checksums are a release-time step on the final binaries,
  not a demo blocker.
- The automated live smoke already proved the logic end-to-end
  (STAGE9-REPORT.md: 33/33 HTTP checks, workspace 445 passed). Cameron's
  pass is therefore NOT re-proving logic — it is the §15 layout pass and
  human judgment: does the real interface read clearly, in the right
  order, with honest wording, for a non-technical user?

## A. Demo walkthrough (in order; ~one sitting)

Test cast needed: one buyer account, one seller account, one moderator
account. Seller flow needs moderator admission approval first, and every
moderator action needs a TOTP code (enroll the moderator early or the
moderation steps will refuse — there is no bypass by design).

1. First impression (logged out): home `/`, catalogue `/listings`.
   Flag: anything that looks unfinished, misaligned, or that promises
   more than v1 does. This is the §15 surface.
2. Register + log in (`/register`, `/login`). Flag: any step where the
   next action isn't obvious.
3. Seller journey: apply (`/seller/apply`) → moderator approves
   (`/moderation/sellers`) → register GnuPG key (`/account/keys`) →
   create listing (`/seller/listings`) → set payment identity and upload
   a subaddress batch (`/seller/payment-identity`,
   `/seller/payment-batches`).
4. Buyer journey: order from the catalogue → pay page (`/orders/{id}/pay`,
   QR at `/orders/{id}/pay/qr.png`) → check the honesty wording: payment
   is seller-confirmed, NOT verified on-chain, and no page should imply
   otherwise. Download the terms file (`/orders/{id}/terms.txt`) and
   confirm it matches what was agreed.
5. Order lifecycle: seller accepts, marks paid, fulfils; buyer completes.
   Then leave a review (`/orders/{id}/review`), seller replies once, and
   check the seller profile (`/sellers/{id}`): raw-facts panel should
   show seller-confirmed payments and 0 verified on-chain, plus the
   sock-puppet honesty line.
6. Messaging: order conversation (`/conversations/for-order/{oid}`) —
   messages are PGP ciphertext; moderators have no conversation access.
   Flag any copy that suggests otherwise.
7. Dispute: open a dispute on a second order, submit disclosed evidence
   (genuinely signed → "evidence"; anything else → "unverified claim"),
   moderator resolves with TOTP. If testing refund-confirmed, note it is
   two-step: moderator proposes, only the buyer's confirmation
   (`/disputes/{id}/confirm-refund`) resolves it.
8. Moderation: file a report (`/reports`), work the queue
   (`/moderation`): warn, remove/restore a listing, then — last, because
   it ends the identity — close the seller account. Expected: listings
   paused, pool retired, login refused with the closure message, profile
   shows "Account closed", order/review history retained for
   counterparties. There is no ban/suspension anywhere; flag any copy
   that implies a person (not an identity) can be excluded.
9. Self-service closure LAST, on a throwaway account only
   (`/account/security`, passphrase + typed CLOSE): it runs the same
   closure path and is not reversible in the demo.
10. Layout sweep on every page visited: heading order, table overflow,
    button labels matching the action taken, timestamps readable,
    no raw/unstyled page left in the flow.

How to flag issues so they are actionable in one pass: page URL, what
you expected, what you saw, and whether it blocks your sign-off or is
polish. One list, sent once at the end of the walkthrough, beats
piecemeal notes — Stage 10 fixes land before the freeze.

## B. Freeze → scrub → GitHub → multi-AI audit sequence

Order is load-bearing; do not parallelise steps 1–3.

1. FREEZE: Stage 10 gate passed, Cameron's demo issues fixed, tree
   declared the audit candidate. No code changes after this point except
   through a new freeze.
2. RE-SCRUB (do not rely on the 2026-10-16 audit alone):
   REVIEW-BUNDLE-SCRUB-AUDIT-2026-10-16.md was written mid-Stage-9.
   Stage 10 adds exactly the file class most likely to carry secrets —
   deployment profiles, ops docs, config templates. Re-run its scan
   (private-key blocks, seed phrases, .env/config, wallet files,
   hardcoded passwords) over the frozen tree before anything is staged.
   Known must-excludes from the first audit, still binding:
   - `stage0-spike/fixtures-wallet/FIXTURES.md` (stagenet seed phrase)
   - `stage0-spike/fixtures-wallet/stage0-fixtures` + `.keys`
   - `marketplace/deploy/dev-setup.sh` (hardcoded local dev DB
     password — parameterise or exclude)
   Also keep out by size/history hygiene: `target/` (~16 GB),
   `downloads/` (~303 MB), `stage0-spike/` build output (~1.7 GB),
   `mutants.out*`, screenshots.
3. `.gitignore` BEFORE `git init`, per the audit's list. History cannot
   be un-pushed cleanly; a secret committed once is flagged forever.
4. GitHub sign-in (Cameron's, via takeover — same pattern as the Google
   sign-in) and first push of the frozen, scrubbed tree.
5. Multi-AI audit against the FROZEN tree, using the audit's bundle
   structure even on GitHub: spec v2 +
   SPEC-V2-AMENDMENTS.md are REQUIRED reading for every auditor —
   without the amendments, reviewers will flag deliberately amended
   decisions (Direct Payments v1, closure-not-ban) as bugs. Per-crate
   chunks with their blind suites; seller-helper as its own chunk;
   threat-model.md IN for reviewers.
6. Collect audit findings against the frozen commit hash only; triage
   into fix-before-public-instance vs note-and-defer. Any fix restarts
   at step 1 for the changed surface.

One open decision for Cameron (his call, not a blocker for the demo):
whether `marketplace/docs/unverified.md` — the known-open security
gaps list — goes in the first PUBLIC GitHub push, and in what form.
Recommended IN for the AI audit round regardless; the public-repo
question can be decided at freeze time.
