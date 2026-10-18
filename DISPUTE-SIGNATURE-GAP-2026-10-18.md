# Dispute page signed-signature gap — investigation
Date: 2026-10-18 (checked 01:25–01:40 UTC)
Question left open in DETERMINISTIC-TOOLS-REPORT-2026-10-17.md §4/§11:
is `DisputeTpl.signed_signature` dead code, or a UI gap?

## Verdict: real UI gap, not dead code

Moderators and dispute participants cannot verify the seller's payment-address
ownership from the dispute page, even though the server already fetches the
data needed to do so.

## Evidence (all read 2026-10-18)

1. Template struct — `marketplace/crates/app/src/web.rs:2456-2470`
   `DisputeTpl` has `signed_message: Option<String>` and
   `signed_signature: Option<String>`.

2. Population — `web.rs:2520-2534` (`dispute_page`)
   Both are populated from the same payment assignment:
   - `signed_message: assignment.as_ref().map(|a| a.message.clone())`
   - `signed_signature: assignment.as_ref().map(|a| a.signature.clone())`
   So the signature is fetched on every dispute-page load and then discarded
   by the template layer.

3. Template — `marketplace/crates/app/templates/dispute.html:8-13`
   The "What moderators can see" list renders:
   - `assigned_address` (line 11)
   - `signed_message` (line 12)
   It renders **no** `signed_signature` anywhere in the file (full-file read).

4. Contrast — the payment page does it correctly
   `templates/pay.html:20-24` renders BOTH the signed message and the
   signature in copyable `<textarea readonly>` blocks, plus the seller's
   primary address (`a.primary_address`), with instructions to verify all
   three in the buyer's own wallet. Verification is impossible with message
   alone: a wallet verify needs message + primary address + signature.

5. Assignment type — `marketplace/crates/app/src/payments.rs:540-545, 562-603`
   `Assignment { address, message, signature, primary_address, .. }`.
   `primary_address` is the address bound in field 5 of the signed message
   (`xmr-direct-v1|...|<primary>|<subaddress>`), deliberately the address
   whose key made the signature, not the seller's current identity.
   `DisputeTpl` does not carry `primary_address` at all — so even adding the
   signature alone leaves the moderator to parse the primary out of the
   signed message by hand. Pay.html shows it explicitly for that reason.

6. The other three "dead" fields are different
   Report §4 groups `OrderTpl.is_buyer` and `DisputeTpl.{is_participant,
   is_moderator}` with `signed_signature`. Those three are genuinely
   redundant template fields: their values are already consumed in Rust to
   compute `can_disclose` / `show_resolve` / review permissions
   (`web.rs:2503-2540`, `1888-1913`), and `DisputeTpl.is_buyer` IS used in
   the template (`dispute.html:41`). `signed_signature` is the only one
   whose value reaches neither Rust logic nor the template.

## Why it matters
The dispute page's stated purpose is to show moderators the public order
record. The assigned subaddress + signed message are presented as payment
evidence, but without the signature they are an unverifiable claim by the
server — exactly what Direct Payments v1 is designed to let anyone check
independently (see `security_guide.html:21`, `payment_risks.html:10`:
"Copy the signed message and signature exactly and verify them with your
wallet"). A moderator resolving a "paid / not paid, wrong address" dispute
currently has to leave the dispute page and open the order's pay page to
get the signature — if they know to do that at all.

## Minimal gated fix (prepared, NOT applied — gate discipline applies)
1. `web.rs` — add `signed_primary_address: Option<String>` to `DisputeTpl`,
   populated as `assignment.as_ref().map(|a| a.primary_address.clone())`.
   (One field, one line — mirrors the existing two.)
2. `templates/dispute.html` — in "What moderators can see", after the
   signed_message line, add the primary address and the signature, ideally
   as copyable readonly textareas matching pay.html's presentation rather
   than inline `<code>`.
3. Add a template/render regression test requesting a dispute page for an
   order with a payment assignment and asserting the signature (and primary)
   appear — the same pattern that caught the image-serving bug in the
   rebrand batch ("first-ever image-request test").
4. Run through the normal gate: review pack, locked tests untouched, full
   workspace suite re-run (baseline 490 passed / 0 failed / 9 ignored).

No spec change is needed: no locked test pins the dispute template's
field list, and displaying data the handler already fetches does not change
any format, crypto, or payment behaviour.

## Remaining choice for Cameron
Apply this as a small standalone fix batch, or fold it into the next
marketplace batch (e.g. alongside any multisig-exploration follow-on or
the sqlx/rsa lockfile decision from report §11). It does not block the
GitHub push, the demo, or any release gate item.
