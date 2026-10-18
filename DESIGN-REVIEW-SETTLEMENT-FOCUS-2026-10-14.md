<!-- SECOND REVIEW TEXT received 2026-10-14 (verbatim, Cameron's paste;
the companion walkthrough critique is in
DESIGN-REVIEW-WALKTHROUGH-CRITIQUE-2026-10-14.md). Focus: standing-offer
explicitness and the refund-first settlement-amount hole. Author
unattributed in text. -->

This is a coherent design, and the refund-first layer is a meaningful improvement: many disputes can end without opening the order.

But I would not ratify this exact wording yet. Two substantive gaps remain: when a signed listing becomes a binding standing offer, and how an unopened dispute's refund amount is established. Neither requires abandoning your architecture.

1. A signed listing can replace individual acceptance—but only explicitly

Your step 7 can work. My earlier acceptance recommendation was addressing the missing evidence of seller agreement; a sufficiently precise, seller-authorized standing offer can supply that agreement instead.

A signature alone does not establish that every future order is accepted. The listing must explicitly say something like:

While this listing version is active, the seller authorizes the marketplace to issue address reservations under its stated limits. A conforming order submitted and paid within the specified deadlines binds the seller without further acceptance.

You then need to define:

- Eligibility: destinations, shipping methods, quantity limits, options, and exclusions.
- Price calculation: integer atomic units, rounding, shipping calculations, and any exchange-rate expiry.
- Capacity: whether availability is unlimited, seller-managed, or subject to reservation quotas.
- Binding event: reservation, submission, or timely payment.
- Expiry and withdrawal: what happens to outstanding reservations when the seller edits or withdraws the listing.
- Payment deadlines: including late payments and delayed confirmation.
- Conformance: exactly what makes an order eligible for the standing offer.

The seller must also authorize the reservation mechanism—not merely sign an address pool.

The inventory constraint still bites

If quantity is encrypted, the core cannot decrement stock by quantity.

You therefore cannot simultaneously promise:

1. arbitrary hidden quantities;
2. exact core-enforced inventory;
3. immediate acceptance without seller involvement.

Within your proposed flow, use bounded orders, reservation-slot limits, or seller-managed availability, and acknowledge the remaining overselling risk.

Verdict on removing acceptance: acceptable for listings that support a precise standing-offer model. Not a safe universal rule for every listing.

Also, step 5 should say the helper reduces accidental nonconformance, not that the buyer "can't invent terms." A malicious buyer can submit arbitrary plaintext and commitments. The protection is that nonconforming terms do not bind the seller, as assessed during a contested dispute.

2. Refund-first needs a buyer-agreed settlement amount

This is the main protocol hole:

"The operator checks the proof against that address and the claimed amount. If it verifies, the case closes."

Whose claimed amount?

Without opening the order or verifying the original payment, the operator does not know the loss. A seller could refund a tiny amount, prove it, and claim closure.

You can preserve unopened settlement by distinguishing settlement by agreement from adjudicated full refund.

Recommended replacement for step 12

1. The seller proposes a refund amount and settlement scope.
2. The buyer signs a settlement authorization binding:
   - case ID;
   - order commitment;
   - recorded refund address;
   - exact amount in atomic units;
   - deadline;
   - whether this settles the monetary claim.
3. The seller pays that address.
4. The operator verifies the refund evidence against the signed authorization.
5. The monetary claim closes as settled without adjudication.

The buyer can initiate this by signing the requested settlement amount when opening the dispute.

If the buyer does not agree, a payment proof alone cannot establish full compensation without further evidence. The case proceeds to selective disclosure.

This gives you the privacy benefit you want without pretending the operator knows an unopened order's correct refund amount.

Closure is not exoneration

Your two statements—

- "If it verifies, the case closes."
- "Refunds don't erase either way."

—need separation.

Use:

An agreed refund can close the monetary claim without a merits finding. It does not erase an existing finding or automatically terminate review of independently supported deliberate deception.

A seller who settles before any evidence is revealed should receive neither a positive reliability credit nor an invented adverse finding. But refunding should not purchase immunity from evidence already establishing misconduct.

3. Recording a public refund address is defensible, with explicit limits

I agree with the rationale: it lets the seller route a refund without decrypting the order, including when the buyer has lost the evidence bundle.

However:

- The buyer's PGP signature proves designation of the address, not ownership of its wallet keys.
- The helper must generate or select a fresh address and preserve its wallet recovery information.
- Use a unique refund address per order.
- Bind it to the reservation ID, commitment, network, and ciphertext digest in the signed submission.
- Have the marketplace receipt cover that complete binding.

If the address later needs changing, require a separately authenticated amendment with a defined precedence rule. Do not allow the operator or seller to silently substitute it.

Losing the order bundle does not necessarily prevent receiving a refund; losing the refund wallet's keys does. Keep those failure modes separate.

The privacy cost is also real: the core now retains a buyer-associated Monero destination. That does not, by itself, expose its incoming transactions, but it is additional sensitive metadata and should have a retention policy.

4. Keep the Monero proof qualification in the guarantees

Do not reduce the refund guarantee to:

"The seller can't fake a refund."

A valid proof authenticates specific payment evidence. It is not universally sufficient to establish usable settlement. Monero's documentation explicitly warns that transaction proofs do not guarantee spendability.[1]

For original payments and refunds alike, the protocol still needs:

- exact destination and agreed amount;
- confirmed inclusion and reorg handling;
- supported proof formats;
- relevant abnormal-output or locking checks;
- deduplication against prior settlement claims.

A fresh case challenge binds the proof presentation to the case; it does not prove that the transaction occurred after the challenge. Check transaction timing and prior use separately where that matters.

The accurate guarantee is:

A seller cannot satisfy the settlement protocol merely by asserting that a refund was sent; the operator verifies qualifying payment evidence against the authenticated settlement instruction.

5. Three wording changes to avoid overstating privacy and enforcement

Step 6

Instead of:

"It now knows two accounts are transacting."

Use:

"It knows that one account submitted an encrypted order proposal to another under a specific listing version."

A submission is not a completed sale.

Step 9

Instead of:

"The marketplace never even learns a sale happened."

Use:

"The happy path produces no core-visible payment or completion confirmation."

The core can still infer activity from metadata, public stock changes, and later disputes.

Step 13

Add:

If the seller declines refund, fails to respond, or contests the claim, the buyer may proceed to selective disclosure.

Otherwise a silent seller can leave the case stuck before the contested phase.

Revised guarantees

I would ratify these:

- The seller's signed standing offer and authorized reservation rules establish the applicable terms for a conforming, timely order.
- The buyer cannot change the committed order after submission without detection.
- Buyer-authored terms outside the standing offer do not bind the seller.
- A refund can settle an unopened monetary claim when its amount and destination are authenticated and agreed, and qualifying payment evidence is verified.
- Happy-path commercial contents and settlement acknowledgements remain encrypted.
- The marketplace holds neither payment funds nor users' wallet keys.
- Disputes can reveal selected commercial facts; fulfilment and intent remain matters of evidence and judgment.

Bottom line: this is close. I would accept standing-offer listings instead of per-order acceptance, provided their authorization, eligibility, capacity, and expiry rules are explicit. I would accept refund-first without opening the order, provided closure follows a buyer-authenticated settlement amount—not the seller's unilateral claim.

Those are protocol requirements, not cosmetic wording changes.

[1] Monero Wallet RPC documentation — transaction-proof methods and spendability caveats
