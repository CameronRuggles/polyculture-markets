# Review — payment, order and trust design pack

Oct 14, 2026 · @Cameron

## Summary

**Adopt, with changes.** This is the simplest version of the design so far. Of 25 items, 7 adopt as written, 18 adopt with changes, and none are rejected. Most of what remains wrong is in what the design *claims*, not in what it does.

The five changes that matter most:

1. **Make the helper check every payment address against the seller's own signature.** The server picks the address. If nothing checks it, a compromised server or an exiting operator redirects payments, and "noncustodial" becomes false (A1).
2. **Move the listing digest inside the terms commitment.** As written in P7, the platform can recover which listing every order is for by trying each public listing digest (A3).
3. **Stop saying the platform can't tell a sale happened.** A reservation followed shortly by seller activity in that thread is a probable sale. Acknowledge every order on arrival, pad ciphertext sizes, and fix the copy (A2).
4. **Use the tx key as payment evidence, with one order per transaction.** Any wallet that exposes a tx key can produce it. Also warn *before* payment when the buyer is about to pay from a swap service or exchange, which silently removes their evidence (UX-1).
5. **Cap reservations for new sellers, and drop endorsements.** A platform-set reservation cap is the one pre-purchase protection that needs no positive signal. Endorsements are a submitted positive signal and break G2.

## Verdicts

One row per item; the Decision column is yours. "Adopt" means as written.

| Item | Verdict | Change required | Decision |
| --- | --- | --- | --- |
| P1 Identity | Adopt | None beyond the key rotation already in §8. |  |
| P2 Listing is the contract | Adopt with changes | Price rules in a declarative schema the helper and operator evaluate identically, no free text. Withdrawal stops new reservations only; issued ones stay binding to expiry. Late payment: seller's choice of fulfil or full refund. Replace the per-order-acceptance fallback with an unlisted single-buyer listing version, so there is one protocol path. |  |
| P3 Pools | Adopt with changes | Sign the pool as a Merkle root; each reservation certificate carries the address's inclusion proof, so the helper checks the address is the seller's without trusting the server (A1). Sellers use a wallet dedicated to the marketplace (A5). |  |
| P4 Reservation | Adopt with changes | Add a platform-set weekly reservation cap for new sellers, rising with continuity. State the consequence of omitting the listing: capacity is enforceable per seller, not per listing (Q2). |  |
| P5 Reservation hygiene | Adopt | Fold the late-payment rule into the P2 standing-offer text so the two can't disagree. |  |
| P6 Local composition | Adopt with changes | Render the summary from the exact object being committed. The helper checks shipping eligibility locally, since the platform cannot. |  |
| P7 Commitments | Adopt with changes | Move the listing digest inside the terms, under secret₁, out of C\_order (A3). Specify length-prefixed canonical encoding for every ‖. |  |
| P8 Refund address in the open | Adopt with changes | Reject refund addresses reused across orders or matching any pool address. Amendments only before a dispute opens, signed by the identity key, seller notified, after a delay. Delete at window close. |  |
| P9 Submission | Adopt with changes | Pad ciphertexts to size buckets. The seller's helper acknowledges every submission on arrival, not on payment (A2). |  |
| Payment and proof rehearsal | Adopt with changes | Evidence is txid + tx key + reserved address, one order per transaction; drop the fresh challenge (corrections). The rehearsal checks the amount received. Ask "paying from your own wallet?" before showing the address. |  |
| P10 Settlement by agreement | Adopt with changes | Authorization irrevocable until its deadline; amount is what the buyer receives, fee on top; deadline 72 hours or less. Settling closes the money claim only; the buyer may still reveal for deception. Settlements feed T3 triage. |  |
| P11 Mismatch defense | Adopt with changes | Encrypt the commercial and shipping parts as separate messages, so a reveal exposes one. A buyer-signed ciphertext that decrypts validly two ways is a buyer-side finding. Mismatch ends in refund; no resubmission path. |  |
| P12 Layer 2 | Adopt with changes | Accept amount ≥ total; underpayment is "resolved mistake". Conformity checks run mechanically on the P2 schema. |  |
| P13 Proof qualification | Adopt with changes | Duplicate-output checks need a chain-wide lookup; custom unlock times are already blocked at relay (corrections). Name the chain-data source under the no-outbound rule: own node, or two that must agree. |  |
| P14 Paid activation | Adopt with changes | Re-activation fees after a ban are donated publicly with proof, so banning never earns the operator money. Describe the fee as pricing griefing and re-entry, not as deterring scams. |  |
| T1 Findings-only enforcement | Adopt | — |  |
| T2 Deception vs breach | Adopt | — |  |
| T3 Ratio demoted | Adopt with changes | One-way in triage too: the ratio may raise a seller's priority, never lower it below what findings and open disputes alone imply. |  |
| T4 Seller dossier | Adopt with changes | Drop endorsements; they are a submitted positive signal. Add the buyer's own history with this seller, computed in the helper from local bundles. |  |
| T5 Re-entry | Adopt | Reword only: blocklists stop careless re-entry; the real costs are fee, probation and time. |  |
| T6 Noncooperation | Adopt | — |  |
| U1 Helper | Adopt with changes | One download and one upload per order instead of pasted fragments. Verify Merkle inclusion. Pin an offline root that certifies seller keys. |  |
| U2 Effort budget | Adopt with changes | Count the missing steps: a fresh refund subaddress from the wallet, and copying txid and tx key. About six actions per order is realistic. |  |
| U3 Errors before payment | Adopt with changes | The title overstates: a mismatch surfaces after payment. Checking on arrival helps only when the seller is online. |  |
| U4 Structured disputes | Adopt | — |  |

## Attacks not modelled

The strongest attack makes the system claim two false things at once: that it is noncustodial, and that an innocent seller failed to perform.

**A1 — The server substitutes payment addresses.** The server chooses each address and signs the certificate. Whoever controls it (a breach, a seizure run as a honeypot, an operator about to exit) can issue certificates for its own addresses. Pinning the operator key does not help: that key signs the bad certificates. Buyers pay the attacker. Worse, a later dispute shows "paid to the reserved address", so the platform's own evidence convicts honest sellers who never saw a coin.

Fix: sellers sign a Merkle root over their pool, and each certificate carries the address's inclusion proof. The helper verifies it against the seller's key, and seller keys are certified by an offline root. Layer 2 checks inclusion too, not just the certificate. A compromised server then also needs the seller's signing key.

**A2 — A probable sales ledger from metadata.** The platform sees reservation (who, whom, when), then submission. Payment prompts the seller to open the order and reply "received" or "shipped" within hours. A seized database turns that timing into a list of likely sales with dates; ciphertext sizes hint at item counts. Fix: the seller's helper sends a fixed-size acknowledgement on *arrival* for every submission; pad all envelopes to size buckets; purge reservation rows and thread metadata at window close; reword §2 and §7.

**A3 — Listing recovery from C\_order.** If C\_terms and C\_shipping are submitted alongside C\_order, the only unknown left in C\_order is the listing digest, and every listing digest is public. The platform hashes each candidate and learns the listing. This undoes P4's deliberate omission. Fix: put the listing digest inside the terms under secret₁, or submit C\_order alone.

**A4 — Clipboard address swap.** Common malware replaces a copied address with the attacker's. The rehearsal catches it, but only after the money is gone. Fix: the helper shows the address in short chunks to compare against the wallet's confirmation screen, and the rehearsal flags a wrong destination immediately.

**A5 — Janus linking of seller wallets.** Someone who suspects that a seller's pool address and another subaddress (another market, a donation address) share a wallet can send a crafted payment to one that looks as if it went to the other. If the recipient confirms receipt, the link is confirmed ([Cook, 2025](https://www.johndcook.com/blog/2025/11/28/monero-subaddresses/)). In this design, shipping *is* confirmation. Fix: sellers use a wallet dedicated to this marketplace. Carrot is designed to close the Janus attack ([jeffro256 CCS proposal](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/504)).

**A6 — Settlement as an escape hatch.** A seller who ships nothing and settles every dispute never reaches Layer 2, so never accrues a finding; only T3 triage sees them. Fix: settling closes the money claim only, the buyer may still reveal for deception, and settlement counts feed triage (P10).

**A7 — Ban-farming.** Each ban earns the operator a re-activation fee. Even if never abused, the incentive is visible and corrodes trust in rulings. Fix: post-ban re-activation fees are donated publicly with proof (P14).

## Usability

**The step most likely to cost an ordinary user their protection is payment, not PGP.** It fails silently: the order completes, the goods may even arrive, and the buyer only learns they had no evidence when they need it.

**UX-1 — Paying from something that isn't their wallet.** Buyers holding other coins often use an instant swap service that pays the merchant address directly, or withdraw from an exchange straight to it. The order works, but the tx key belongs to the service, so the buyer can never produce Layer 2 evidence. Some wallet setups don't keep tx keys either (the CLI only does with `store-tx-info` set; the GUI shows the key on its history page, per [getmonero.org](https://getmonero.org/resources/user-guides/prove-payment.html)).

Least-complex fix: before showing the address, the helper asks one question, "Will you pay from your own wallet, one that shows a transaction key?", and says plainly that otherwise only Layer 1 protects them. The rehearsal then confirms or turns red. Layer 1 still works without the bundle because the refund address sits outside the order; that choice earns its keep here.

**UX-2 — Paste shuttling.** As written, each order moves six fragments between three programs: certificate into the helper, refund subaddress from the wallet, submission to the web form, receipt back, address into the wallet, txid and tx key back. Each is a chance to paste the wrong thing or give up. Fix: file in, file out. The page offers one order-kit file (listing snapshot plus certificate); the helper emits one submission file to upload; the receipt comes back as a file. No JavaScript needed. Two copies remain: the refund subaddress in, txid and tx key out.

**UX-3 — Silent underpayment.** "Subtract fee from amount" options and swap services that deliver approximately both produce short payments. The seller doesn't ship, and the buyer just waits. The rehearsal already reads the amount received; have it compare against the total and say "short by X" at once.

**UX-4 — Identity key loss.** Everything else recovers from the identity key; the key itself does not. Setup should make a backup feel mandatory and test one restore.

**UX-5 — Disputes months later.** A Layer 2 reveal may happen on a new computer. The helper must restore the bundle from the server backup with the identity key alone.

With these fixes, a buyer's order is about six actions: download the kit, open it and paste a refund subaddress, review, upload, pay, paste txid and tx key. That is close to the U2 budget.

## Wording that overstates

Ten places promise more than the mechanism delivers; four are privacy claims that copy must not repeat.

| Where | Current wording | Problem | Say instead |
| --- | --- | --- | --- |
| §2 | Learns "no confirmation that a sale occurred" | No confirmation, but timing still marks probable sales (A2) | "No confirmation of sale; timing can still suggest which orders were paid." |
| §7 | Never knows "whether payment occurred" | Same | Move it to "Can infer": which reservations probably became sales. |
| P4, §7 | The platform does not know which listing | As specified, it can compute it from C\_order (A3) | True once P7 is fixed. |
| §1 | Never holds trade funds | True of funds, but the server chooses destinations; unchecked, that is custody of routing (A1) | "Never holds funds. It assigns payment addresses, which the helper checks against the seller's signature." |
| §8 | Substitution "mitigated by helper key-pinning" | Pinning the operator key does not stop whoever controls the operator's server | "Mitigated by seller-signed address proofs checked in the helper, and seller keys certified by an offline root." |
| U3 | "Errors surface before payment" | The seller opens the order after payment | "Most errors are prevented by construction; a mismatch surfaces after payment and ends in refund." |
| P11 | Reveal establishes "buyer-side mismatch" | Only if the ciphertext decrypts one way (corrections) | Add the two-decryptions rule. |
| P13 | "Per Monero's own documentation" | The official source is the 2018 burning-bug post-mortem, about burnt outputs generally, not tx proofs | Cite it and name the mechanism: duplicate one-time output keys. |
| T4 | Endorsements are "assertions, never a computed score" | Still a submitted positive signal, against G2 | Drop endorsements, or stop calling the record purely subtractive. |
| T5, P14 | Blocklists; bans "cost the banned something real" | Fingerprints and pool addresses are free to replace; the real cost is one small fee | "Bans cost one activation fee plus probation time." |

## Factual corrections

**Most mechanics in the pack are right; four need correcting and one changes a design choice.**

**Payment evidence can be simpler.** Monero's own guide proves a payment with three things: txid, destination address and the tx key; the checker gets the amount and confirmations ([getmonero.org](https://getmonero.org/resources/user-guides/prove-payment.html)). Any GUI user can copy the tx key from the history page. A fresh challenge adds little here: the reserved address is single-use and txids are deduplicated, so the evidence is already bound to the case, and P13 already admits the challenge proves nothing about timing. I preferred the challenge in the last round; with single-use addresses I no longer do.

One trade-off: a revealed tx key lets the verifier test that transaction against any address it knows. Require one order per transaction, so the only other output is the buyer's change, at an address the platform doesn't know. Keep signed proofs as an option for buyers who want them.

| Topic | Pack says | Correction |
| --- | --- | --- |
| Burnt outputs (P13) | Check for "duplicated one-time outputs" | Burning means several outputs share one one-time address; only one is spendable, and the wallet spends the largest ([post-mortem](https://getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html)). Spotting a duplicate needs every output on chain with that key, not one transaction lookup. A buyer can only burn the seller's payment by sending a *larger* duplicate, so the realistic case is a seller falsely claiming a burn. Rule: a burn claim is Inconclusive unless the seller identifies the duplicate. |
| Timelocks (P13) | Check "timelocked" outputs | Nodes already refuse to relay custom unlock-time transactions; only a miner can include one. The feature is deprecated at the FCMP++ fork ([getmonero.org](https://www.getmonero.org/2026/05/10/deprecating-unlock-time.html)). Keep the check; expect it almost never to fire. |
| FCMP++/Carrot (Q9) | Open question | No mainnet fork date as of July 2026, and the code for proving facts about funds was still being adjusted ([CriptoNoticias](https://www.criptonoticias.com/tecnologia/monero-mayor-salto-privacidad-fcmp/)). Carrot supports existing addresses and is designed to tackle the burning bug and Janus attacks ([CCS proposal](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/504)). Re-test every proof path on the stressnet before relying on it. |
| Subaddress derivation (§1, P3) | Needs the private view key | True for today's wallets. Carrot code I saw derives subaddresses from a separate address-generation secret; if the spec confirms it, new-style wallets could let the platform generate addresses without viewing funds, retiring pools. Verify against the Carrot spec before planning on it. |
| Session-key reveal (P11, Q4) | Establishes buyer-side mismatch | Sound: the key is per message, reveals only that message, and never exposes the private key. But AEAD modes such as GCM and OCB are not key-committing, so a crafted ciphertext can decrypt validly under two session keys. The buyer signed the ciphertext, so two valid decryptions are proof of buyer manipulation; write that rule down. |
| Tx keys and seed restore | A restored wallet loses tx keys | Correct, and the CLI keeps them only with `store-tx-info` set. |
| Refund address (P8) | An address reveals nothing on-chain | Correct for chain observers. Pre-Carrot, Janus linking (A5) needs the owner to confirm receipt, which refund addresses rarely do. Low risk. |

## Your ten questions

1. **Standing offer.** Yes for terms and price: the signed listing plus the signed pool bind the seller as firmly as an acceptance would. It still fails on eligibility (shipping region is sealed, so only the helper can enforce it), capacity (per seller only), withdrawal mid-flight, late payment, and free-text price rules. Fixes are in the P2, P4 and P6 rows.
2. **Inventory trilemma.** Right pick for a small market, with one carve-out: unique items. A one-off item oversells whenever two buyers reserve inside the expiry window, and each oversell becomes a refund in T3 triage. Offer an opt-in "unique item" mode: the certificate names the listing and only one reservation can be open. The seller accepts that the platform learns the listing for those orders, and the listing discloses it.
3. **Settlement gaming.** Covered by the P10 row. Partial settlements must state what claim remains, or default to closing the whole money claim. An authorization that lapses is re-signed by the buyer, never re-priced by the operator.
4. **Session-key defense.** Sound, but it exposes the whole message, and it needs the two-decryptions rule (corrections, P11 row).
5. **Refund address in the open.** The correlation cost is modest; the platform already links a buyer's orders through their account. The amendment path is the real attack surface, so restrict it as in the P8 row. The understated cost is retention: a seized database lists buyer refund addresses by account, so delete them at window close.
6. **Paid activation.** It changes the economics of griefing (reservation exhaustion, fake disputes, smears), which need many identities. It barely touches scams: one scam identity's take dwarfs any fee honest users would accept. A small fee is enough; raising it taxes honest users more than scammers. Remove the ban-farming incentive as in the P14 row.
7. **Smuggled denominators.** Two: T3 triage ordering (make it one-way) and T4 endorsements (drop them). Continuity is fine as shown. As the sole buyer-facing story, subtractive-only is honest but thin; it cannot tell a two-year seller from a two-year sleeper. Add two things that don't break G2: the new-seller reservation cap, which bounds exposure instead of predicting honesty, and the buyer's own history in the helper, which no seller can submit.
8. **Most likely place to lose the user.** Payment from something other than their own wallet (UX-1). Least-complex fix: one question before the address is shown, and a rehearsal that turns red.
9. **Proof checklist.** See corrections: tx-key evidence with one order per transaction, burn claims Inconclusive unless shown, timelocks nearly extinct, and a named chain-data source. Re-validate every proof path on the FCMP++/Carrot stressnet.
10. **Strongest unnamed attack.** Server-side address substitution (A1). It makes the platform both a thief and a false witness against honest sellers, and the fix is a seller signature checked in the helper.

## Sources

- [How to prove a payment was made](https://getmonero.org/resources/user-guides/prove-payment.html) — getmonero.org user guide
- [A Post Mortem of The Burning Bug](https://getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html) — getmonero.org, Sep 25 2018
- [Deprecating Monero's Custom Transaction Unlock Time](https://www.getmonero.org/2026/05/10/deprecating-unlock-time.html) — getmonero.org, May 10 2026
- [Monero se alista para tener mayor privacidad: FCMP++ en la recta final](https://www.criptonoticias.com/tecnologia/monero-mayor-salto-privacidad-fcmp/) — CriptoNoticias, Jul 21 2026
- [jeffro256 full-time dev work 2024Q4](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/504) — Monero CCS proposal describing Carrot
- [Monero subaddresses](https://www.johndcook.com/blog/2025/11/28/monero-subaddresses/) — John D. Cook, Nov 28 2025 (subaddress derivation and the Janus attack)
