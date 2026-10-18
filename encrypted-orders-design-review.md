Encrypted Orders and Seller-Trust Signals
External Design Review

Project: Noncustodial Monero marketplace
Architecture: Rust / Axum / PostgreSQL, AGPL-3.0, server-rendered HTML, no JavaScript
Specification: v2
Review date: 2026-10-14
Status: Recommendations pending ratification

Executive Verdict

Step A — dispute-triggered payment verification: adopt with changes.

Step B — encrypted orders: adopt with changes, but reject the proposed dispute logic as sufficient evidence of a scam.

The privacy direction is sound. The proposed trust inference is not:

A committed order plus a valid payment proof establishes neither seller acceptance nor seller fraud.

With authenticated seller acceptance added, the evidence can establish an agreed obligation and evidence of payment. Fulfilment, breach, and intent remain separate questions.

Under the stated constraints, no protocol can provide a hard-to-fake completed-sales denominator or a generally reliable positive seller-trust score. Useful negative findings, authenticated continuity, attributable endorsements, and limited re-entry friction are achievable. A defensible “this seller fulfils 99% of orders” claim is not.

This direction should be ratified only if the product accepts that distinction.

Immediate implementation finding

Do not build the proposed Monero timelocked-to-self bond. Monero officially announced deprecation of custom transaction unlock times. Ordinary relay already rejects them, and the announced consensus change would invalidate the intended locking assumptions for new transactions.[1]

1. Verdict on Step A and Step B

1.1 Step A: Dispute-Triggered Verification

Verdict: adopt with changes.

Routine platform verification is unnecessary for direct settlement when the seller’s wallet is authoritative for the seller’s own decision to fulfil.

However, distinguish:

- Seller acknowledges receipt: a signed assertion by the seller.
- Platform verified payment evidence: a dispute-time technical result.
- Buyer’s obligation discharged: an adjudicative conclusion considering the agreed payment terms.

Do not call the first one “platform-confirmed paid.”

If the seller sends a core-visible paid transition, the platform learns an assertion that a sale occurred. Step A alone therefore does not mean:

“The marketplace does not know whether sales happen.”

It means:

“The marketplace does not independently verify those assertions.”

If no happy-path sales visibility is genuinely a requirement, payment acknowledgements and completion states must stay inside encrypted messages. The core’s lifecycle should concern routing and disputes, not settlement.

Strongest counterargument

Removing routine verification eliminates early detection of payment mistakes and pushes technical support into the most adversarial part of the transaction.

Buyers may discover only during a dispute that:

- their wallet cannot reproduce a proof;
- they paid the wrong address;
- the purported payment is not adequate settlement evidence.

Required mitigation

Provide a locally executed pre-payment checklist and an exportable evidence bundle.

These are load-bearing requirements, not optional documentation.

1.2 Step B: Encrypted Orders

Verdict: adopt with changes.

Encrypted orders substantially reduce the ordinary server’s plaintext exposure. The original proposal is nevertheless missing several essentials:

1. Seller acceptance before payment.
2. Authenticated, immutable listing versions.
3. An authenticated address assignment.
4. A precisely defined, randomized commitment.
5. A separate privacy policy and storage boundary for disputes.

A buyer’s commitment proves what the buyer committed. It does not prove the seller agreed to it.

For example, a buyer can commit an impossible deadline or a price copied incorrectly, pay the assigned address, and complain. Without seller acceptance, the operator has no cryptographic basis for treating that document as the seller’s obligation.

Strongest counterargument

The design removes the server’s ability to validate the order while making the buyer responsible for constructing the exact document on which future protection depends.

Ambiguous terms, arithmetic mistakes, stale listings, incorrect recipients, and missing signatures become expensive failures.

No JavaScript does not prevent a solution, but it means either:

- an audited local helper does the deterministic work; or
- users perform a demanding manual file-and-signature workflow.

Do not re-plan around Step B without testing that complete workflow with representative users.

“They already use GPG” is not sufficient evidence that users can reliably create and preserve a dispute-ready order.

1.3 Correct the Privacy Promise

Replace:

“The marketplace never knows order contents, sales, totals, revenue.”

With:

“Ordinary orders remain encrypted. The platform has no verified happy-path sales ledger. Disputes can disclose selected order terms and payment information. Communication, address-assignment, and public-listing metadata remain visible.”

Disputes necessarily disclose some sales. Optional positive receipts disclose purported completions. A server seizure can capture retained dispute evidence.

Do not claim a liability reduction from this architecture without jurisdiction-specific legal advice. Data minimization is a technical benefit, not a demonstrated exemption from operator obligations.

2. The Seller-Trust Impossibility Result

2.1 Indistinguishable Honest and Fabricated Activity

Consider two worlds:

- Honest world: many independent buyers exchange ciphertext with a seller and submit completion receipts.
- Fabricated world: the seller controls the buyer keys, exchanges equivalent ciphertext, and submits equivalent receipts.

If the platform receives the same permitted observations in both worlds, it cannot distinguish them.

Adding blind signatures changes linkability. It does not change whether the underlying buyer or completion is genuine.

Even adding payment evidence would not establish independent trade: a seller can transfer money between wallets they control. The principal is not necessarily lost. The recurring cost is mainly fees and any temporary capital constraint.

This is consistent with the broader Sybil problem: multiple keys do not establish multiple independent entities.[2]

The result is specifically about a reliable sales or fulfilment signal. It is not an impossibility of all useful reputation. Identity continuity and attributable misconduct remain useful.

2.2 The Problem Is Larger Than the Denominator

Even a genuine sales count would not make complaints a clean failure rate:

- reporting is voluntary;
- dissatisfied buyers may not preserve evidence;
- buyers differ in willingness to reveal sensitive orders;
- disputed deliveries have uncertain outcomes;
- positive reports are selectively submitted.

A completion-receipt count is not a complete denominator even before Sybil inflation.

Do not publish a percentage, Bayesian reliability estimate, or “verified sales” label based on these mechanisms.

3. Recommended Seller-Trust Mechanism Stack

Ratings concern resistance to fabricating the claimed meaning, not merely resistance to forging signatures.

| Mechanism | Fake resistance | Privacy cost | Implementation cost | Recommendation |
|---|---|---|---|---|
| Seller-signed acceptance plus dispute payment evidence | High for authenticated agreement/payment predicates; insufficient for fulfilment | Medium–high in disputes | Medium | Required |
| Reasoned findings of specific misconduct | Depends on evidence; high only for narrowly established facts | Medium | High operational cost | Primary negative signal |
| Platform-observed key/listing continuity | High for continuity; low for honesty | Low incremental cost | Low–medium | Display separately |
| Seller activation delay and promotion probation | Low–medium; parallel identity farming remains | Low | Low–medium | Limited re-entry friction |
| Explicit, scoped endorsements | Low–medium; stronger with credible external relationships | Medium: reveals endorsement graph | Medium | Optional, not a numerical score |
| Countersigned completion receipts | Low for independent fulfilled sales | Medium: links a purported completion to an order | Medium | Omit from v2, or label as attestations |
| Blind completion tokens | Low for genuine completions | Lower cryptographic linkability; metadata still matters | High, including local tooling | Reject for v2 reputation |
| Monero timelocked-to-self “bond” | Not a dependable current design | Reveals capital-related evidence | High | Reject |
| Buyer-age-weighted complaints | Weak; keys can be farmed or transferred | Medium | Medium | Do not use as an evidence multiplier |

3.1 Sustained Findings

The proposed formulation assumes:

“Honest sellers should essentially never accrue proven scams because a complainant must really pay.”

That does not hold.

A malicious buyer can actually pay, receive the goods, and falsely allege non-delivery. The incremental attack cost is not necessarily the whole payment: the buyer received something of value.

A competitor may also accept a real expense to damage a seller.

An honest seller can suffer delivery failures or business collapse without deliberate fraud.

Recommended enforcement policy

- One high-confidence finding of deliberate, material deception can justify removal. A denominator is not needed to tolerate zero intentional fraud.
- One finding of service breach should not automatically mean fraud.
- Repeated adjudicated breaches can justify warnings, promotion restrictions, or suspension as service-risk enforcement, without claiming a measured failure rate.
- Require human review and an appeal route before permanent removal, except for urgent temporary containment.

There is no defensible universal threshold N.

Counting ambiguous cases does not make them certain. Free keys do not prove independent complainants.

A scammer staying below a threshold is precisely why a secret “three strikes” counter is inferior to severity-based enforcement and visible, reasoned findings.

Do not offer a budget of unpunished intentional scams.

3.2 Countersigned Completion Receipts

These authenticate:

“These two keys jointly attested to completion.”

They do not authenticate:

“An independent customer received the promised goods.”

Aged accounts increase preparation time, but an attacker can age a portfolio in parallel. Bulk receipts can be manufactured in bulk.

They also contradict strict no-completion-visibility if the core receives them tied to order commitments.

Recommendation

Preserve the ability for users to retain private completion acknowledgements, but do not build the platform’s denominator around them.

If public attestations are offered later:

- label their limited meaning explicitly;
- do not present them as independently verified sales;
- never let them cancel adverse findings.

3.3 Blind-Signed Completion Tokens

Reject as a trust solution.

A token issued at commitment time proves eligibility at commitment time, not completion.

A Sybil buyer can redeem it without purchasing or receiving anything.

Requiring seller approval does not help against seller-controlled buyers. Moving issuance to completion simply moves the unsupported attestation.

There is also an attribution problem:

- If the token is freely creditable to any seller, tokens can be redirected, traded, or harvested elsewhere.
- If issuance is seller-bound, the issuer learns seller-related issuance metadata or needs additional cryptographic machinery to enforce the binding.
- Revealing the seller at redemption reveals an aggregate purported completion signal.
- Redeeming through the original logged-in account or thread can undo the intended unlinkability.

Blind-signature unforgeability prevents obtaining extra signatures without issuance interactions. It does not make issuance eligibility meaningful.

RFC 9474 describes those cryptographic guarantees. Privacy Pass explicitly separates token issuance from the attestation of the qualifying property.3

Decoy issuance can obscure demand but does not authenticate completions. Per-thread issuance changes the counted object from orders to threads.

Neither fixes farming.

3.4 Costly Identity and Vouching

Use platform-observed first-seen dates, not PGP key creation dates.

Display:

- identity first observed;
- uninterrupted listing availability;
- signing-key continuity and rotations;
- current and historical enforcement status.

Call this continuity, not “years of successful trading.”

A seller activation delay and restrictions on promotion during probation impose some waiting cost. Attackers can nevertheless prepare many identities concurrently, so these mechanisms must not be described as preventing re-entry.

Vouching

Vouching is useful only as an explicit social assertion:

“Seller A endorses seller B for this stated scope, until this date.”

Make endorsements:

- signed;
- expiring;
- revocable;
- limited in number.

Preserve their history. Specify in advance what an adjudicated failure does to the sponsor’s endorsement privileges.

Do not recursively compute a trust score over an unconstrained vouch graph. A colluding cluster can endorse itself.

An established seller is not necessarily a credible judge of another seller’s fulfilment.

These mechanisms do not demonstrably cost scammers more than honest newcomers. Their usefulness depends on accumulated relationships and scarce promotional privileges, not the mere existence of signatures.

3.5 Buyer Standing

Weight evidence, not account age.

A first-time buyer can provide decisive evidence. An old buyer can lie.

Do not penalize an unproven complaint merely because it fails. That discourages precisely the buyers who already bear the financial risk.

Sanction separately established misconduct:

- fabricated evidence;
- knowingly false material statements;
- duplicate or abusive filings.

Use age and history for modest queue or rate-limit decisions where appropriate, not as substitutes for proof.

3.6 Best Achievable Pre-Purchase Posture

Offer a risk dossier, not a safety score.

Include:

- authenticated identity and listing continuity;
- scoped endorsements and who made them;
- adjudicated misconduct and remediation history;
- explicit “new/unestablished seller” status;
- clear seller-specific fulfilment and refund terms;
- a prominent warning that direct payments have no platform-enforced recovery.

Advise small initial exposure and incremental purchasing.

This is genuine protection through limiting loss, not through pretending to know reliability.

Important limitation

Because the platform cannot see amounts, it cannot enforce a financial exposure cap.

Limits on listing visibility or new address reservations can slow activity, but cannot bound victims’ monetary losses.

4. Order and Dispute Protocol

The following protocol is feasible without custody, JavaScript, or routine payment verification.

4.1 Phase 1: Establish Authenticated Inputs

Seller responsibilities

1. Publish a signed, versioned listing and terms snapshot.
2. Upload a signed address-pool manifest binding:
   - seller identity;
   - Monero network;
   - exact address bytes;
   - pool and version identifiers.

A signature establishes seller authorization to receive at those addresses.

It does not prove the seller owns their spend keys. Do not infer ownership from a pool signature.

Core responsibilities

3. Reserve one address atomically.
4. Return a signed reservation certificate binding:
   - protocol version and marketplace identifier;
   - random order/reservation identifier;
   - buyer and seller fingerprints;
   - listing-version digest;
   - assigned address and network;
   - issuance time and reservation policy.

Never recycle an exposed address for another order, including after apparent abandonment.

A late payment otherwise becomes ambiguous.

Reservation expiry must not destroy the historical evidence binding.

4.2 Phase 2: Commit the Proposal

The buyer constructs the order locally.

Commercial document contents

Include:

- identities and reservation certificate;
- exact listing snapshot or its authenticated reference;
- items, quantities and options;
- total in integer Monero atomic units;
- any exchange-rate agreement and its expiry;
- shipping service and charges;
- payment deadline and settlement conditions;
- fulfilment deadlines;
- refund and dispute terms.

Avoid external links whose contents can change.

Commitment structure

For privacy-preserving disclosure, separate:

- commercial terms;
- shipping and personal data.

One concrete structure is:

    C_terms = H(domain_terms || random_secret_1 || encoded_terms)

    C_shipping = H(domain_shipping || random_secret_2 || encoded_shipping)

    C_order = H(domain_order || C_terms || C_shipping)

Use:

- an unambiguous, versioned, length-delimited encoding;
- independent cryptographically random secrets, for example 256-bit values;
- an explicitly specified hash algorithm;
- precisely defined input bytes.

A bare hash of predictable terms is not reliably hiding. Shipping commitments need independent randomness too.

Buyer responsibilities

1. Sign the proposal and its commitment.
2. Encrypt the package to the seller.
3. Submit ciphertext and a signed outer commitment/reservation binding.

Core responsibilities

4. Store the commitment immutably with its receipt time and ciphertext digest.
5. Return a signed submission receipt.

The core cannot verify that the hidden proposal matches the public commitment at this stage.

It also cannot guarantee that the ciphertext contains a valid order. That check belongs to the seller.

OpenPGP encryption and signatures serve distinct confidentiality and authentication functions. Encryption alone is not a signed agreement.[5]

4.3 Phase 3: Seller Acceptance Before Payment

Seller responsibilities

1. Decrypt and validate the buyer’s proposal.
2. Recompute the commitments.
3. Check:
   - address;
   - listing version;
   - amount;
   - deadlines;
   - shipping requirements.
4. Sign an explicit acceptance binding:
   - C_order;
   - the reservation;
   - both identities.

Return the signed acceptance encrypted to the buyer.

The core routes it without receiving a visible “accepted sale” transition.

If terms change, produce a new committed version and explicit acceptance. Do not rely on informal amendments whose precedence is unclear.

Buyer responsibility

Pay only after verifying seller acceptance.

This is the principal missing protection in the original proposal.

4.4 Phase 4: Payment and Fulfilment

The buyer pays the accepted address.

The seller checks their own wallet and fulfils under the accepted terms.

Payment acknowledgements, shipping information, and completion messages remain encrypted.

Both parties retain a local evidence bundle.

Buyer evidence bundle

Retain:

- exact committed files and random secrets;
- submission and reservation receipts;
- seller acceptance;
- relevant signed messages;
- transaction identifiers;
- wallet records needed to produce a payment proof.

Encrypting a recoverable archive to the buyer as well as the seller avoids dependence on one plaintext file.

It does not remove the need for key backups.

4.5 Phase 5: Dispute Intake

Initial buyer submission

Submit to a restricted dispute service:

- allegation and requested resolution;
- signed submission and reservation receipts;
- commercial terms and their commitment secret;
- C_shipping, initially without shipping plaintext;
- seller’s signed acceptance;
- relevant signed communications.

Operator verification order

1. Identity and signature validity under the applicable historical keys.
2. Reservation and submission receipt authenticity.
3. Commitment opening and protocol encoding.
4. Seller acceptance of that same commitment.
5. Address and network consistency.
6. Deadlines and the specific obligation allegedly breached.

Only then request or process payment evidence.

This avoids unnecessary disclosure and expensive proof work for structurally invalid cases.

Reveal shipping data only if necessary to decide the allegation.

A shipping-address disagreement may require disclosure. A payment-denial case may not.

4.6 Phase 6: Payment Evidence

Give the buyer a fresh case challenge containing:

- case identifier;
- accepted commitment.

Use it as the Monero proof message.

Verifier checks

Check:

- supported proof format and cryptographic validity;
- exact accepted destination;
- received amount against the agreed obligation;
- distinct transaction evidence for split payments;
- chain inclusion;
- sufficient confirmations;
- reorg handling;
- timing under the accepted terms;
- abnormal locking or output conditions relevant to adequate payment.

check_tx_proof exposes good, received, in_pool, and confirmations, and accepts the message used to generate the proof.[6]

A proof message binds the proof presentation to a case.

It does not retroactively put the order commitment into the blockchain transaction.

The fresh, authenticated address assignment and accepted terms provide that association.

Deduplicate payment evidence and findings. One payment or incident must not generate several strikes through repeated case filings.

4.7 Phase 7: Response, Decision and Appeal

Provide the seller:

- the relevant allegations;
- the relevant evidence;
- a bounded response period.

Permit relevant signed replies, fulfilment evidence, and refund evidence.

A refund should be assessed against an authenticated buyer-designated refund address, with equivalent payment-evidence checks.

The platform cannot compel a refund.

Outcomes

| Outcome | Meaning | Seller signal |
|---|---|---|
| Dismissed | Evidence defeats the allegation or shows no applicable breach | No adverse finding; not a “successful sale” |
| Inconclusive / not established | Evidence cannot decide the material issue | No fraud finding; retain the distinction from dismissal |
| Resolved mistake | Established error, corrected or credibly resolved | Record remediation if warranted; no automatic fraud strike |
| Sustained service breach | An agreed obligation was breached under the published evidentiary policy | Service-risk warning or restrictions; do not label intentional fraud |
| Sustained deliberate deception | Evidence supports material intentional deception | Removal may follow a single serious finding |
| Procedural noncooperation | Seller failed the published dispute-response obligation | Separate warning or restriction; not proof of non-delivery |

“Sustained” must state what was sustained.

A panel can sustain a breach without establishing criminal or moral intent.

Nonresponse is grounds for enforcing a participation rule, not automatically proof that goods never arrived.

Refunds resolve loss but do not erase independently established intentional deception.

Issue a signed, reasoned decision and allow appeal.

Publish only a minimal redacted outcome, not:

- transaction identifiers;
- amounts;
- addresses;
- buyer identities;
- evidence bundles.

5. Payment-Proof Assumptions Requiring Reconsideration

This is the settled-ground assumption that should be reopened before ratification.

Monero’s current RPC documentation explicitly warns that transaction proofs do not guarantee spendability.

Funds can be timelocked or affected by duplicated one-time output addresses. The corresponding project issue also recommends care around fresh subaddresses.6

Consequently:

good = true plus sufficient received is not universally equivalent to “the buyer made adequate, usable payment.”

Already-spent funds are not themselves a problem. A seller spending a legitimate receipt must not invalidate payment.

The relevant question is whether the evidence demonstrates valid settlement under the accepted conditions, not whether the money remains unspent today.

Fresh, never-reused subaddresses are an important mitigation.

Do not treat address allocation as a complete spendability proof. Validate the exact supported wallet and proof path against known adversarial cases before automatically sustaining payment-denial findings.

Unresolved technical anomalies should result in technical review or an inconclusive outcome.

5.1 Cryptographic Verification Versus Chain Observations

Distinguish:

- Proof verification: local cryptographic checks using transaction data.
- Chain inclusion and confirmations: observations of the chain supplied by nodes.

No full local chain sync is inherently required for the proposed workflow.

A single remote node is nevertheless not a trustless finality oracle.

Independent node observations reduce reliance on one endpoint. They do not become equivalent to independently validating consensus.

Node outages or disagreements must postpone decisions, not count against a party.

The verification service needs no seller private view key.

Describe it as a proof-verification service rather than implying it operates a seller view-only wallet.

6. Delivery, Quality and Adjudication

The warning about delivery is correct, but “delivery is unprovable” is too absolute.

Delivery may have useful noncryptographic evidence:

- carrier records;
- signed acknowledgements;
- admissions;
- contemporaneous correspondence;
- other independently checkable facts.

A tracking number returned inside an encrypted message can be revealed during a dispute and checked if the carrier supports it.

Encryption does not inherently prevent dispute-time verification.

However:

- a delivery scan is not proof of package contents;
- testimony about wrong goods is not made decisive by a hash;
- quality disputes remain dependent on evidence and judgment.

Do not restrict the system solely to cryptographically decidable disputes. That would leave the principal buyer risk substantially unaddressed.

Instead publish:

1. What cryptography establishes.
2. What external evidence can support.
3. The burden and standard for an administrative finding.
4. What remains inconclusive.

This makes the operator an evidence-based moderator, not an oracle.

7. Metadata, Griefing, Retention and Build Implications

7.1 Metadata

The retained graph remains sensitive.

Ciphertext threads, address reservations, timestamps, lengths, and seller-associated address pools reveal activity and intent.

Priority order

1. Remove listing IDs from routing where unnecessary.
2. Keep payment and completion transitions inside ciphertext.
3. Minimize access logs and retention.
4. Support coarse ciphertext-size padding in local tooling.
5. Evaluate cover traffic only against a defined observer.

Occasional user-generated decoys are not equivalent to a systematic traffic-analysis defence.

In a no-JavaScript product, convincing cover traffic is especially burdensome.

Thread/order decoupling reduces one inference but does not eliminate the buyer–seller graph.

7.2 Buyer Griefing and Address Exhaustion

Start with:

- bounded reservation quotas;
- expiry of routing privileges, not address reuse;
- seller-controlled intake.

Proof-of-work is possible through local tools, but adds accessibility and support costs.

Add it only in response to measured abuse.

Pool restoration and lookahead

Address pools must remain known to the seller’s wallet and recoverable after restoration.

Large gaps of unused subaddresses can interact with wallet lookahead and cause payments not to appear as expected.

Preserve pool index information locally and test restoration beyond default lookahead.[8]

7.3 Retention

Separate:

- short-lived ordinary ciphertext;
- minimal immutable reservation and commitment receipts;
- sensitive dispute evidence;
- redacted enforcement history.

A seller ban must not delete buyers’ outstanding evidence or prevent already-issued orders from being disputed.

Specify evidence deletion across:

- backups;
- write-ahead logs;
- application logs;
- crash reporting;
- search indexes.

A separate dispute database is useful only if plaintext does not leak back into ordinary infrastructure.

7.4 Functions the Core Can No Longer Authoritatively Perform

The following cannot remain authoritative core functions:

- order arithmetic and total validation;
- quantity-dependent inventory reservation;
- paid, shipped and completed transitions;
- verified completion rankings;
- amount-based exposure controls;
- transaction-based commissions;
- revenue analytics.

Seller-local inventory becomes necessary.

Public stock updates may themselves disclose sales-related activity, so the privacy claim must account for them.

7.5 Surviving Stage 4 Machinery

The terms-digest work survives as:

- versioned local encoding;
- commitment machinery;
- authenticated listing snapshots.

It does not survive as a server-generated authoritative plaintext order.

The core state machine becomes approximately:

    reserved
        → ciphertext submitted/routed
        → retained/expired

With separate:

- dispute lifecycle;
- enforcement lifecycle.

The buyer/seller commercial state machine exists locally and inside signed encrypted exchanges.

Existing plaintext order records remain exposed until deliberately migrated or deleted according to policy.

Encrypting future orders does not retroactively erase Stage 4’s data.

8. Three Additional Real-World Failure Modes

8.1 Active Key or Address Substitution

A compromised platform can:

- present a substituted seller key to a new buyer;
- impersonate a seller;
- redirect payment instructions.

Encryption to the attacker’s key works perfectly.

Mitigations

- pinned fingerprints;
- seller-signed listing and pool artifacts;
- authenticated key transitions;
- externally verifiable identity where available;
- local verification.

Residual limitation

A first-time buyer whose only identity source is the compromised platform has a bootstrap trust problem.

This architecture protects stored plaintext better than it protects against an actively malicious server.

8.2 Mature Identities Are Sold, Compromised or Used for an Exit Scam

A seller can behave well for a long time, build continuity and endorsements, and then scam during one concentrated interval.

Alternatively, someone can buy or steal the identity.

Past continuity says little about present willingness to honour a much larger exposure.

Mitigations

- do not turn age into a safety guarantee;
- flag key and business changes;
- retain recent adverse findings;
- constrain promotional privileges during review;
- encourage limited buyer exposure.

Residual limitation

With no visible amounts or outstanding obligations, the platform cannot bound an exit scam.

8.3 Disputes Become a Privacy-Extraction and Operational Attack Surface

A hostile participant can force adjudication around sensitive details.

Filings can also overwhelm the human review process.

If review becomes slow, real victims get little protection. If review becomes automatic, evidence ambiguity causes wrongful bans.

Mitigations

- structured allegations;
- staged disclosure;
- no default shipping-data reveal;
- restricted reviewer access;
- bounded technical work;
- duplicate detection;
- staffing targets;
- explicit inconclusive outcomes.

Ordinary OpenPGP encryption to long-lived keys does not provide automatic forward secrecy.

Later compromise of those decryption keys can expose retained old orders.

9. Ratification Recommendations

Ratify or reject each recommendation separately.

| ID | Recommendation | Proposed decision |
|---|---|---|
| R1 | Dispute-only payment verification, with private happy-path states and a tested local evidence workflow | Adopt with changes |
| R2 | Encrypted orders, with authenticated listings, reservation certificates and seller acceptance before payment | Adopt with changes |
| R3 | Randomized, versioned, precisely encoded commitments supporting limited disclosure | Adopt |
| R4 | Treat committed order plus transaction proof as sufficient proof of a scam | Reject |
| R5 | Multidimensional seller risk dossier | Adopt |
| R6 | Completion percentages and verified-sales claims based on the proposed receipts or tokens | Reject |
| R7 | Severity- and evidence-based enforcement; one serious intentional-deception finding may justify removal | Adopt |
| R8 | Limited probation and continuity-based privileges, acknowledging parallel identity farming | Adopt with limitations |
| R9 | Blind completion tokens for v2 reputation | Reject |
| R10 | Monero timelocked-to-self bond | Reject |
| R11 | Add proof-spendability, active key substitution, pool restoration/lookahead, dispute-data isolation and post-ban evidence-preservation security gates | Adopt |

10. Final Conclusion

Adopt the privacy architecture, but abandon the idea that commitments and payment proofs make seller fraud straightforward to prove.

The best achievable product is:

An encrypted direct-payment marketplace with authenticated agreements, qualified pre-purchase signals, bounded user exposure, and fallible but accountable post-hoc enforcement.

It is not:

A marketplace with cryptographically established seller reliability.

That distinction should be explicit in the specification, interface, dispute policy, and public claims before stages are re-planned.

References

1. Monero — Deprecating Monero’s Custom Transaction Unlock Time
   https://www.getmonero.org/2026/05/10/deprecating-unlock-time.html

2. John Douceur — The Sybil Attack
   https://www.microsoft.com/en-us/research/publication/the-sybil-attack/

3. RFC 9474 — RSA Blind Signatures
   https://www.rfc-editor.org/rfc/rfc9474.html

4. RFC 9576 — The Privacy Pass Architecture
   Includes attestation and metadata/side-channel considerations.
   https://www.rfc-editor.org/rfc/rfc9576.html

5. RFC 9580 — OpenPGP
   https://www.rfc-editor.org/rfc/rfc9580.html

6. Monero — Wallet RPC Documentation: check_tx_proof
   https://docs.getmonero.org/rpc-library/wallet-rpc/#check_tx_proof

7. Monero Project — Transaction-Proof Spendability Caveats, Issue #8819
   https://github.com/monero-project/monero/issues/8819

8. Monero — Wallet CLI Reference and Pool/Lookahead Issue #9213
   https://docs.getmonero.org/interacting/monero-wallet-cli-reference/
   https://github.com/monero-project/monero/issues/9213
