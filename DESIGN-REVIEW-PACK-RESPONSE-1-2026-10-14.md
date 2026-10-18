<!-- REVIEW OF THE CONSOLIDATED PACK, received 2026-10-14 via Cameron's
paste (verbatim). Answers DESIGN-PACK-PAYMENT-AND-TRUST-2026-10-14.md.
Verdict: adopt the architecture with changes; do not ratify yet.
Author unattributed in text. -->

Review verdict

Adopt the architecture with changes; do not ratify this draft as an implementable protocol yet.

The central choices are defensible: direct payments, encrypted orders, no manufactured positive-sales score, and disputes that distinguish evidence from judgement. The design also correctly treats usability as part of the security model.

However, several unresolved details affect what the platform can truthfully claim, not merely implementation quality:

1. A signed listing proves its contents, not that it was an applicable, active offer when this reservation was issued. P2/P4 need an authenticated offer-lifecycle rule.
2. P11 does not cover all decryption failures. A successful, authenticated session-key opening can establish the stored plaintext. A failed opening cannot establish buyer fault.
3. Reservation inflation can suppress review even if the ratio is "only triage." T3 retains an attacker-controlled denominator with operational consequences.
4. "Errors surface before payment" is false as written. Your seller-side checks occur after payment, and the platform cannot validate encrypted conformity.
5. P13 needs a defined implementation and evidence semantics, not just a checklist. A valid proof is not proof of current spendability, payer identity, or exact payment time.
6. The ordinary-user workflow is substantially longer than U2 describes. Manual handoffs between website, helper, wallet, and backup are the principal abandonment risk.

There are also two internal contradictions worth fixing immediately:

- §8 contemplates a payment-denial finding being "auto-sustained," while T1 prohibits algorithm-produced findings.
- G2 excludes submitted positive trust inputs, while T4 places endorsements in the buyer-facing trust dossier. Calling them assertions does not prevent buyers from treating them as reassurance.

1. Verdicts per numbered decision

Protocol: setup

| Item | Verdict | Reason and required change |
|---|---|---|
| P1 — Identity | Adopt with changes | Specify a constrained OpenPGP profile, primary-key versus signing/encryption-subkey identity, historical key validation, revocation, rotation, and recovery. A valid signature establishes control of a signing key—not a unique person or trustworthy account. Avoid requiring real-name/email OpenPGP user IDs. |
| P2 — Listing contract | Adopt with changes | The standing offer can replace per-order acceptance for objectively conforming orders, but applicability must be provable. Define active intervals, withdrawal, reservation survival, payment deadlines, and eligibility. A signed old listing must not become binding merely because the buyer possesses it. See §2 below. |
| P3 — Pools | Adopt with changes | Receiving-address authorization without spend-key ownership is reasonable. But "diverts only their own income" is too strong: address selection also affects buyers' recourse, order attribution, and address-based enforcement. Require canonical address validation, manifest membership verification, network binding, and duplicate/reuse rules. |
| P4 — Reservation | Adopt with changes | Omitting the listing is compatible with privacy, provided P2's applicability gap is closed separately. The helper must verify the seller-signed pool authorization, not merely the operator certificate. Bind marketplace identity, protocol version, exact policy version, and pool-manifest identity. |
| P5 — Hygiene | Adopt with changes | "Unpaid reservations" are unknowable in the happy path. Cap outstanding/unexpired reservations and reservation issuance rates instead. Recovery must preserve wallet identity, major/minor indices, and scan-start information—not merely a scalar "highest index." Late payment must preserve a claim to fulfilment or refund, but not necessarily the original delivery/price obligations. |

Protocol: ordering and disputes

| Item | Verdict | Reason and required change |
|---|---|---|
| P6 — Local composition | Adopt with changes | Define one canonical, machine-readable pricing/terms format and one interpretation shared by buyer helper, seller helper, and moderator. No arbitrary executable pricing rules. The reviewed summary must be rendered from the exact bytes committed and signed. Specify how commercial deadlines depend on shipping facts without leaking them unnecessarily. |
| P7 — Commitments | Adopt with changes | The construction is sensible under standard hash assumptions. Specify hash, distinct domains, canonical encoding, length framing, randomness source, schema version, and context binding. The seller needs the openings—or sufficient equivalent material—to perform the promised commitment check. The encrypted payload must explicitly include them. |
| P8 — Open refund address | Adopt with changes | The designation mechanism is sound; the privacy cost is real but manageable. "An address reveals nothing on-chain" needs qualification. For v1, the simplest safe amendment policy is no unilateral refund-address amendment: use a buyer-signed replacement explicitly acknowledged by the seller, with settlements naming the exact address revision. |
| P9 — Submission | Adopt with changes | Define an idempotent, one-submission-per-reservation state machine. The buyer must obtain and locally verify the receipt before the helper presents the payment instruction. Retries must return the same receipt rather than create another order. A submission receipt proves operator attestation to stored bytes—not seller receipt, readability, conformity, or acceptance. |
| P10 — Agreed settlement | Adopt with changes | Good separation from adjudication. Scope must be enumerated, not free-form: full monetary claim, named partial claim, remaining balance, and whether any conduct allegation remains open. Bind authorization revision, address revision, network, seller, reservation, and marketplace. Freeze supersession rules before the seller pays. |
| P11 — Mismatch defense | Adopt with changes | Sound for a successful, authenticated opening of the exact receipted ciphertext. Not sufficient for wrong-recipient encryption, malformed key wrapping, missing keys, or failed integrity checks. An arbitrary wrong session key must never become "proof of buyer garbage." Commercial and shipping components need independent encryption keys if disclosure is to remain selective. |
| P12 — Selective disclosure | Adopt with changes | Establish admission criteria and burdens of proof for each allegation. Separate cryptographic facts, external evidence, factual conclusions, and intent conclusions. Preserve buyer access after account suspension/banning. Define "Resolved mistake," "Inconclusive," and "Procedural noncooperation" so they cannot silently become sustained seller misconduct. |
| P13 — Proof qualification | Adopt with changes | The caveat is correct, but the procedure is not yet complete enough to support findings. Pin exact wallet/proof implementations; define inclusion, unlocking, output attribution, cross-case credit allocation, timing semantics, and failure classification. "Already spent" is not a reason to reject a genuine historical payment. |
| P14 — Paid activation | Adopt with changes; pilot only | It creates a per-account acquisition/re-entry cost, not a meaningful general Sybil guarantee. Rate limits remain necessary. Existing orders, evidence retrieval, disputes, and appeals must survive a ban without another payment. Remove "forfeit" unless the fee is actually refundable before a ban; revenue already earned is not newly forfeited. |

Trust and enforcement

| Item | Verdict | Reason and required change |
|---|---|---|
| T1 — Findings-only enforcement | Adopt with changes | Good principle. Deduplicate incidents and distinguish findings from sanctions. One outage affecting twenty buyers is twenty affected transactions but may be one root incident. Separately authorize temporary, precautionary restrictions during investigation; label them as precautions, not sustained findings. |
| T2 — Deception versus breach | Adopt with changes | One strongly established deceptive act can justify removal. But falsity does not by itself establish knowledge or intent. Honest volume is not reliably observable here; manufactured estimates must not become systematic mitigation. Review should emphasize severity, duration, common cause, remediation, and recurrence. |
| T3 — Ratio demotion | Reject the ratio-based queue ordering | Queue position determines whether and when misconduct is reviewed. Inflating reservations can manufacture delayed scrutiny. Keep counterparty patterns as investigative context, but prioritize admitted complaints by severity, evidence sufficiency, age, and urgency—not an attacker-controlled denominator. |
| T4 — Seller dossier | Adopt with changes | Show "No sustained findings recorded," not "clean." First-seen age is not trading continuity. Remove endorsements from the v1 trust dossier: they undermine G2 and add revocation, issuer-authentication, and comprehension burdens. State explicitly that no findings may mean no reviewed complaints. |
| T5 — Re-entry | Adopt with changes | Fingerprint blocks are useful against exact reuse, not identity continuity. Address matches are weak attribution evidence and can be poisoned. Authenticated key rotation must carry findings forward; unauthenticated new identities start unestablished. Clarify that paying again does not entitle a banned identity to return. |
| T6 — Noncooperation | Adopt with changes | Correct distinction. Require a properly admitted case, demonstrable notice under the platform's participation rules, accessible response tools, and outage/recovery allowances. Ignoring an unsupported Layer-1 demand must not automatically create noncooperation. |

Usability

| Item | Verdict | Reason and required change |
|---|---|---|
| U1 — Helper | Adopt with changes | CLI-first is reasonable for development, not evidence of suitability for ordinary users. Permit an explicit user-initiated "Submit" action from the helper; forbidding all network submission adds manual failure opportunities without inherently improving confidentiality. Test backup restoration, not merely backup creation. |
| U2 — Effort budget | Adopt with changes | Keep the budget as a testable goal, but count reservation acquisition, importing signed artifacts, receipt retrieval/verification, fresh refund-address creation, uploads, and backup. Test mobile-wallet/desktop-helper and hardware-wallet workflows separately. |
| U3 — Errors before payment | Reject as written | Seller checks happen after payment. Buyer-built conformity is only as good as the helper, listing semantics, offer applicability, and wallet handoff. Replace with a bounded claim identifying which checks happen before payment and which remain seller-side or dispute-time. |
| U4 — Structured disputes | Adopt with changes | Structure is useful. Friction is not reliably anti-abuse: attackers automate it, while distressed honest users abandon it. Use evidence admission, quotas, and deduplication rather than deliberate tedium. Layer 1 ending most disputes is a hypothesis to measure, not an established property. |

2. Standing offers and inventory — questions 1 and 2

The standing-offer clause can supply agreement evidence

It supplies the seller's advance agreement if all prerequisites are objectively established:

- This exact version applied to this reservation.
- The buyer met the stated eligibility conditions.
- The order conformed.
- Submission and payment satisfied the defined deadlines.
- The seller's capacity promise covered the order.

The current missing link is the first condition.

Unmodelled attack: offer-lifecycle ambiguity

A buyer retains a cheap signed listing version. The seller supersedes or withdraws it. The buyer later obtains a seller-level reservation and submits an order citing the old version.

The buyer can prove:

- genuine seller signature;
- genuine reservation;
- genuine submission;
- qualifying payment.

None of those proves the old offer was applicable to that reservation.

Conversely, a dishonest seller can describe a previously active version as withdrawn before a genuine reservation.

This can cause the moderator to sustain a false contractual-breach finding.

Least-complex fix

For standing-offer listings, use seller-signed fixed validity intervals with no retroactive withdrawal of the interval's commitment:

- State when reservations may qualify.
- State the submission/payment grace periods.
- Bound those periods explicitly.
- Edits affect later qualifying intervals; they do not erase existing commitments.

This avoids a per-order acceptance round trip and avoids making the reservation listing-visible.

If you require immediate withdrawal, you need authenticated applicability history—potentially a seller-wide catalog epoch whose applicable listing set can be demonstrated later. That is more complex. I would not add it before testing whether short, fixed offer intervals suffice.

Eligibility must also be objective. "Seller may refuse unsuitable buyers" is not a precise standing offer. Ambiguous/custom eligibility should use your explicit-acceptance fallback.

Inventory choice

Your tradeoff is reasonable for a small marketplace, provided the product says plainly:

Availability is seller-managed. The platform does not reserve exact item inventory.

Seller-wide reservation-rate/capacity limits can constrain worst-case exposure without revealing quantities. Exact SKU inventory cannot be guaranteed under your chosen privacy/noninteractivity constraints.

Also define oversell handling. It should ordinarily be a service problem requiring refund, not automatically deception. Repeated knowingly impossible availability claims may support deception, but the intent evidence must be separate.

Late payment

"Expiry ends routing privileges, not obligations" is directionally good but imprecise.

After expiry, the seller should owe fulfilment if still mutually feasible, otherwise return of the qualifying received amount under a defined process. An expired FX quote should not automatically bind the original merchandise price forever.

3. Settlement authorizations — question 3

The mechanism is workable. Its main hazards are state ambiguity, not atomic-unit arithmetic.

Required rules

1. One identified claim allocation.  
   A settlement specifies which monetary claim it closes and what remains outstanding.

2. One effective authorization revision.  
   A new authorization must not retroactively invalidate a payment made under a previously accepted one.

3. One effective address revision.  
   Do not verify against "the currently recorded address." Verify against the address explicitly bound in the operative authorization.

4. Credit allocation, not blanket txid deduplication.  
   One transaction can legitimately pay multiple recipients. Prevent re-crediting the same destination payment/output allocation, while allowing distinct allocations within the same transaction.

5. No unsolicited closure.  
   A transfer without the applicable buyer authorization is evidence of a transfer, not authority to close the complaint.

6. No automatic conduct settlement.  
   Monetary settlement does not establish innocence or eliminate already established misconduct.

Atomic XMR units eliminate ambiguity once the amount is agreed. Fiat drift before agreement remains a commercial negotiation; drift after agreement is governed by the signed fixed amount and expiry.

A proof does not establish who economically funded the transfer. Therefore prefer:

"The authorized settlement amount was evidenced at the designated destination."

over:

"The seller demonstrably returned the buyer's original money."

Likewise, "refund" should not imply that you established an original purchase if Layer 1 never disclosed one.

4. OpenPGP session-key defense — question 4

What works

GnuPG explicitly supports disclosing a session key to demonstrate what a particular ciphertext contains, without disclosing the recipient's long-term private key. Its documentation specifically mentions reporting abusive encrypted messages this way. Source: GnuPG session-key options

For your defense, require:

- exact ciphertext bytes authenticated by the buyer's submission and receipt;
- an approved encryption profile;
- successful integrity/authentication verification;
- bounded parsing;
- exact canonical comparison against the committed contents and openings.

That can establish a mismatch in the submitted material.

What does not work

A seller who provides an incorrect session key will obtain a failed decryption or meaningless unauthenticated output.

That establishes nothing about buyer fault.

Also, if encryption went to the wrong key, the seller may have no session key to disclose. An outer recipient key identifier is not proof that key wrapping was correctly performed.

Classify such cases as unresolved technical/readability failures unless separate evidence establishes responsibility.

Disclosure scope

A session key reveals everything encrypted under that key—not an abstract "one message" boundary enforced by the marketplace.

RFC 9580 supports session-key reuse in its v2 encrypted format. Your profile should forbid reuse across orders, commercial/shipping compartments, attachments requiring separate disclosure, and subsequent messages. Source: RFC 9580, §13.8

Thus:

- Commercial and shipping components need separate encryption keys.
- Revealing a commercial key may still expose everything inside that commercial packet.
- If the shipping ciphertext is nested inside it, the shipping plaintext can remain sealed, but its ciphertext and metadata become visible.
- Never ask users to paste session keys into a public case thread or expose them in diagnostic logs.

For simplicity, use one well-tested OpenPGP profile rather than "anything the libraries can decrypt." Reject legacy unauthenticated encryption and disable unnecessary compression.

5. Monero mechanics and proof qualification — question 9

Claims that are correct, with qualifications

Subaddress derivation

For the legacy key hierarchy, subaddress generation requires the private view key and the relevant public spend-key/index information; the public view key alone is insufficient.

Your signed-pool approach avoids giving the platform the seller's viewing capability.

Seed restoration and transaction keys

For conventional wallet paths, outgoing transaction keys are locally retained metadata, not recovered merely from the seed and chain. The official payment-proof guide also conditions key retrieval on transaction-information storage. Cake Wallet documents loss of these values after restoration/rescanning. Official guide · Cake Wallet guide

Correct the bundle wording to:

"Transaction key material required by the supported wallet/proof path."

Do not assume every transaction has exactly one scalar key; supported paths must preserve any additional transaction keys required.

Proof versus spendability

Your warning is explicitly supported by Monero's wallet RPC documentation and issue #8819. Wallet RPC documentation · Issue #8819

But distinguish:

- Never usable because of construction/burning/locking: potentially relevant to payment qualification.
- Received and subsequently spent by the recipient: still a valid historical payment.
- Not presently unlocked: may be a temporary pending state.
- Not independently established as spendable: a limit on the finding.

Do not require the recipient to prove they still hold the money.

Additions to P13

Specify and test:

- An operator-controlled, independently validated chain source. A proof checked against an attacker-controlled daemon is not adequate chain evidence.
- Chain/network identity, block hash/height, confirmation threshold, and reorg transitions.
- Ordinary unlock delay separately from abnormal transaction locking.
- Primary/additional transaction-public-key handling, subaddress proofs, supported proof versions, and strict parsing.
- Amount decoding and output attribution for the exact supported implementation.
- Duplicate one-time-output checks across relevant chain history, not just within the submitted transaction.
- Partial payments, overpayments, split transactions, and multiple outputs to the same destination.
- Destination-specific credit allocation across original payments, settlements, activation fees, and any other proof-accepting subsystem.
- A distinction between invalid evidence, unsupported evidence, temporarily unavailable evidence, and evidence of an adverse fact.

The current documentation notes that nonzero transaction unlock_time has been restricted by a relay rule since v0.18.3.4. A relay policy is not, by itself, a universal historical or consensus-level spendability guarantee. Wallet RPC documentation

Timing

A blockchain transaction does not provide an authoritative exact broadcast time.

Define the contractual deadline using something the system can actually evaluate—such as qualifying inclusion with a grace period—and acknowledge the resulting confirmation/clock semantics. A block timestamp is not proof that the buyer pressed "send" at a precise wall-clock time.

Fresh challenges

Your caveat is correct: a fresh proof challenge binds presentation, not transaction creation.

For simplicity, I would consider dropping mandatory new wallet-generated proofs at dispute time:

- Save a durable order-context payment proof during rehearsal.
- Bind its presentation to the case using the party's signed case submission.
- Continue enforcing transaction/destination credit deduplication.

This preserves case association without forcing a restored wallet to regenerate a proof for a new challenge. Validate the alternative against your attribution requirements; do not assume tx-key possession establishes payer identity.

FCMP++/Carrot

The official download page retrieved for this review lists 0.18.5.3 as the current release. The Carrot specification describes the FCMP++ upgrade as upcoming. I would therefore keep deployed legacy behavior and proposed Carrot behavior explicitly separate rather than assume migration has occurred. Downloads · Carrot specification

Material changes in the Carrot design include:

- Existing address compatibility.
- A new-wallet generate-address secret that can generate addresses without payment-viewing access.
- Janus-attack mitigation.
- Stateless burning-bug mitigation.
- Changed output/key/scanning mechanics and expanded viewing capabilities.

Therefore, the statement "address generation requires the private view key" is legacy-specific, not a permanent Monero invariant.

Carrot's specification also explicitly says a successful scan does not universally guarantee spendability. Its address-conditional forward-secrecy claims make retention of plaintext addresses relevant to future exposure as well.

Do not assume existing proof formats or transaction-key backup rules remain sufficient. Introduce a separately tested migration profile tied to the actual activated protocol and supported wallets.

6. Refund-address privacy and amendment attacks — question 5

The privacy cost is understated in one sentence:

"A Monero address reveals nothing on-chain."

A better version is:

"A destination address alone does not ordinarily let a passive observer identify its corresponding on-chain outputs. It remains identifying off-chain data, and additional proof/key material can reveal particular payments."

Relevant consequences:

- The platform associates a buyer account with a wallet destination.
- Reuse elsewhere creates direct off-chain linkage.
- Current legacy subaddresses have active-linkage limitations, including the Janus attack.
- Refund acknowledgements or observable settlement events can supply an attacker with the response needed for an active test.
- Dispute proofs connect destination, transaction, amount, and case inside restricted evidence.

Monero's own advisory describes the active subaddress-linking conditions and distinguishes subaddresses from separate-wallet isolation. Monero subaddress advisory

Fresh addresses remain a good default. Do not tell users they create perfect wallet unlinkability.

Amendment attack surface

"Latest authenticated amendment wins" is unsafe unless "latest" has precise, shared semantics.

A buyer can issue one revision while the seller is preparing another; the platform can deliver them in different orders; a replay can show one party an older effective address.

Least-complex v1 rule:

- Initial refund address is fixed.
- Exceptional replacement requires buyer signature and seller acknowledgement.
- A settlement authorization names the exact acknowledged address revision.
- A new revision never invalidates an already qualifying settlement transfer.

Loss of the refund wallet should not be confused with loss of the OpenPGP identity key. Those are independent recovery problems.

7. Attacker economics and trust — questions 6 and 7

Paid activation

The relevant economics are approximately:

Attack return − acquired-account cost − transaction costs − operating/delay costs − expected losses.

A small activation fee affects the account-cost term. It does not necessarily make that term important relative to scam proceeds.

For illustration, a hypothetical $5-equivalent fee is negligible against a $500 scam, but material against $0.20-value account spam. Neither conclusion requires knowing actual fee tiers.

Also:

- Paying once permits repeated reservation/dispute abuse unless separately limited.
- Already-aged parallel accounts reduce the marginal effect of banning one account.
- Account sale transfers continuity without creating a new fee.
- Reusing pre-existing paid accounts defeats any claim that each ban immediately generates fresh expenditure.

Use:

"Each activated account has a acquisition cost; bans can impose additional replacement cost."

Not:

"A person pays once ever."

You cannot establish personhood, and honest people may lose keys or need separate identities.

Operator incentives

Use simple structural checks:

- Publish fee/refund policy independently of misconduct outcomes.
- No ban quotas or moderator compensation tied to replacement fees.
- Provide signed reasons and an appeal route.
- Remedy erroneous bans without another activation charge.
- Report aggregate enforcement statistics without transaction-level disclosure.

If the service fee is nonrefundable from the outset, remove "forfeit on a fraud ban."

Denominators have re-entered in two places

T3 queue ordering

This is a real suppression attack:

1. Seller inflates reservations.
2. Refund/reservation ratio decreases.
3. Review priority falls.
4. Genuine complaints wait longer.
5. Buyers continue seeing no sustained findings.

Human review at the end does not neutralize adversarial control over access to that review.

Remove the ratio.

G3 volume mitigation

Allowing unverified volume estimates to routinely soften sanctions is also an exonerating denominator. It conflicts with your own warning that such safety can be manufactured.

Allow a moderator to consider uncertainty and incident context, but do not implement "many reservations → more tolerated failures."

Subtractive-only trust is workable—with honest limits

It is workable as a negative-information record, not as the sole basis for deciding a seller is safe.

The dossier should say:

"No sustained findings recorded. Sales volume and successful fulfilment are not verified. Absence of findings is not evidence of successful trading."

Show first-seen and last-observed listing availability separately. Do not collapse them into "active for two years."

Endorsements should be omitted from v1. Even properly signed endorsements authenticate the assertion's issuer, not its truth; displaying them prominently reintroduces positive reassurance by another route.

8. Strongest additional attacks — question 10

Beyond the offer-lifecycle and queue-suppression attacks above:

A. Noncooperation manufactured from unsupported complaints

An attacker opens many Layer-1 demands against a seller. The seller cannot economically answer all of them. Silence becomes a sustained procedural finding.

This makes the platform accurately record silence but misleadingly imply failed commercial participation.

Fix: Layer 1 is an optional settlement invitation. Mandatory response duties begin only after a case meets defined admission requirements. Notice and deadline rules must tolerate service outages.

B. Address-based blocklist poisoning

A banned seller uploads another merchant's public receiving address. Later, the innocent merchant uploads the same address and is treated as linked to the banned identity.

Fix: An address match is a routing/uniqueness conflict or investigative lead—not proof of common account control. Never make it an automatic identity-based fraud attribution.

C. Operator signatures mistaken for independent truth

A compromised or malicious operator can sign substituted key mappings, backdated receipts, or conflicting histories. Pinning its root proves you are talking to that operator; it does not prove the operator is honest.

The draft's substitution mitigation overstates what root pinning achieves.

Fix: Verify seller-signed artifacts and independently established seller fingerprints where available. Preserve client-held receipts and authenticated key transitions. Describe first-contact trust in the operator as a trust assumption, not merely a bootstrap inconvenience.

A receipt timestamp is an operator's signed assertion unless you add an independent timestamp mechanism—which may not be worth the complexity.

D. Parser disagreement produces false conformity

The buyer helper, seller helper, and moderator disagree about duplicate fields, Unicode, quantity units, omitted defaults, price rounding, or whether prose overrides structured terms.

Each verifies signatures correctly; they disagree about the contract.

Fix: One canonical grammar, no duplicate fields, explicit defaults, bounded arithmetic, and a defined precedence rule. Unsupported contract forms require explicit acceptance.

E. Evidence absence converted into intent

The seller signs "I have not received payment." The buyer later produces a valid proof. The platform calls this deliberate deception.

Possible alternatives include missed restored subaddresses, an unsynchronized wallet, abnormal output behavior, or a statement about unlocked availability rather than chain inclusion.

Fix: Define exactly which factual proposition a statement asserts. Contradiction establishes falsity only to that proposition's scope; deliberate deception needs additional knowledge/intent evidence.

Similarly, authentic tracking does not prove correct goods arrived; a delivery scan does not necessarily establish delivery to the committed destination.

F. Quiet complainants create manufactured cleanliness

A seller discourages disputes, offers off-platform settlements only if complaints are withdrawn, or selectively exploits buyers who skipped evidence backup.

The account ages with no sustained findings.

This cannot be eliminated by a findings-only model, but it must be reflected in the dossier language. The record measures established complaints, not underlying failure prevalence.

G. Restricted evidence mistaken for publicly checkable proof

A signed, redacted moderation outcome authenticates what the operator decided. Without the underlying evidence, buyers cannot independently verify its substantive correctness.

Fix: Distinguish:

- cryptographic facts checked by the reviewer;
- external evidence assessed by the reviewer;
- moderation judgement;
- publicly verifiable signature on the published outcome.

Do not market a redacted outcome as a publicly cryptographically proven seller failure.

9. Ordinary-user failure and least-complex fix — question 8

Most likely failure: the post-payment handoff

The moment after paying is when the buyer feels finished.

They must instead locate transaction data in a different application, return to the helper, rehearse verification, save evidence, and potentially upload a backup. Failure gives no immediate symptom. The harm appears months later.

Cake Wallet's documentation illustrates the dependence on locally saved transaction metadata and wallet settings. A universal "30-second rehearsal" is not yet credible.

Least-complex fix

Make the user-facing task:

"Save payment evidence"

—not "generate and verify a transaction proof."

The helper should:

1. Before payment, verify that the selected wallet path can export usable evidence.
2. Present the payment instruction only after the submission receipt is verified.
3. Accept a single supported evidence export or assisted wallet handoff.
4. Validate and store a durable proof automatically.
5. Confirm local storage and, if enabled, backup.
6. Show a persistent, recoverable "Payment evidence not saved" state if the step was skipped.

A user may still continue without the guarantee, but the loss must be explicit and visible. Do not silently classify an untested wallet path as protected.

Also allow explicit user-initiated helper submission. "It submits nothing by itself" can remain true without requiring manual copying: the user clicks Submit, sees the destination and payload class, and authorizes the upload.

No-JS web UI does not require no-network client tooling.

Hidden seller burden

The seller path is not merely "see payment → open order → ship." It includes:

- correlate payment and reservation;
- verify signed submission;
- check commitments/openings;
- check listing applicability and conformity;
- check amount and payment qualification;
- interpret shipping and deadlines.

These checks should produce one seller summary with clear exceptions, not multiple cryptographic tasks.

The representative-user gate should include retry, lost-key, wallet-restore, malformed-order, late-payment, and refund-address-recovery scenarios—not just a successful demonstration.

10. Retention and ratification gates

Retention recommendation

Use a platform-wide maximum supported dispute horizon, with listings choosing within it. Otherwise ciphertext retention can become indefinite.

| Data class | Recommended rule |
|---|---|
| Order ciphertext and linked routing metadata | Retain through the applicable claim-opening window; extend only for an active case/appeal. |
| Detailed dispute evidence | Restricted access; retain through final resolution and a published bounded post-appeal period, subject to legal requirements. |
| Encrypted evidence backups | User-controlled retention with clear deletion semantics and an independent export option. |
| Submission receipts | Buyers retain full copies. Platform retention need not mean permanent storage of every buyer/address association. |
| Burn/reuse prevention | Preserve the minimum address-uniqueness record needed to prevent reuse; remove expired buyer linkage where feasible. |
| Redacted enforcement history | Retain for continuity and appeals, with corrections linked to prior outcomes rather than silently overwriting them. |

Backups do not reduce loss modes to "lost identity key." Other modes include missing historical encryption subkeys, incomplete bundles, inaccessible wallet recovery material, corrupt backups, omitted uploads, and server deletion. Test restoration from a clean device.

Gates before ratification

I would require these six gates:

1. Authenticated offer applicability and deadline semantics.
2. Canonical order/pricing format and explicit protocol state machine.
3. Successful versus failed P11 opening tests, including compartment leakage.
4. Pinned Monero proof-verification implementation with adversarial qualification tests.
5. Removal of ratio-based review suppression and definition of dispute admission.
6. Unaided user tests covering evidence export and actual backup recovery.

Also fix the activation references: §3/P1 point to P12, but activation is P14.

Bottom line: keep the privacy architecture and the subtractive record. Remove mechanisms that manufacture reassurance or make human attention attacker-controlled. Most importantly, make every published conclusion name the precise proposition established—and leave everything else explicitly unresolved.
