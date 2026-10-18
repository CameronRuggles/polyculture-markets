# Addendum to DECISIONS-FOR-OPUS-REVIEW.md — ambiguities not in Q1–Q12

Paste-ready supplement. Append this to the decision pack before sending
it to Claude Opus, as a new section after Q12 and before Part 4.
It covers recorded blind-test ambiguities that Q1–Q12 do not ask about.
Source: stage0-spike/tests-blind/README-BLIND.md, "Contract ambiguities
found" — A2, A3, A4, S2, E1, E2. Q1–Q12 already cover A1, S1, S3, S4,
S5, E3, E4 (via Q7a) and E5.

---

### Additional questions — please answer in the same template, as Q13–Q17

**Q13 — Address input normalization (blind A2).**
Nothing in the spec or the API contract says whether surrounding
whitespace or a trailing newline on a Monero address is trimmed or
rejected. The blind author deliberately left it untested.
Options: **A (implementer lean) reject any address that is not exactly
the bare address string** — strictness matches the canonical-statement
philosophy elsewhere in the spec, and a trimmed-accept path is a place
for two code paths to disagree about the same destination;
**B** trim ASCII whitespace at the user-input boundary only, never in
stored/statement parsing. If you pick B, say exactly which layers trim
and which must not.

**Q14 — Curve-point validity for destinations (blind A4).**
Neither spec nor contract says whether address validation must check
that the embedded public spend/view keys are valid curve points, beyond
prefix + checksum parsing via a maintained Monero library (§3 #7).
All spike fixtures carry real keys, so the tests pass under either
reading. Options: **A (implementer lean) require whatever validity the
`monero` crate's parser already enforces, and write that into the spec
as the requirement** — no extra hand-rolled curve check;
**B** require an explicit point-validity check in addition to parsing,
and name what it must reject. If you pick B, name a concrete bad
destination that A accepts and B stops.

**Q15 — Statement ID patterns (blind S2).**
§10 exemplifies but does not formally pattern `marketplace-id`,
`invoice-id`, and `order-id` values (e.g. `mkt_…`, `inv_8d1e5b0c3a7f`,
`ord_…`). The blind tests therefore do not assert rejection of
malformed IDs beyond the non-ASCII rule. Options:
**A (implementer lean) pin the patterns in §10 now** — prefix, allowed
characters, and length range for each ID type — before the locked
suite is finalized, so malformed IDs are rejected at parse;
**B** leave IDs as opaque printable-ASCII strings at parse time and
enforce shape only where IDs are generated/looked up in the core.
If you pick A, propose the actual patterns.

**Q16 — Envelope error-variant classification (blind E1 + E2).**
Two classification gaps the blind tests worked around by asserting
"any of the plausible variants":
- E1: raw plaintext and empty input could map to `Plaintext`,
  `Malformed`, or `NotArmoredOrBinary` — no rule orders them.
- E2: a PKESK belonging to neither the recipient's nor the sender's
  cert could be `WrongRecipient` or `UnknownRecipient`.
Options: **A (implementer lean) pin both classifications in the
contract now** (suggest: empty/plaintext-shaped input → `Plaintext`
if it is not an OpenPGP message at all; a PKESK for a parseable but
unregistered key → `UnknownRecipient`, reserving `WrongRecipient`
for a key that belongs to a different registered user);
**B** formally leave variants unspecified for these cases and keep
the locked tests asserting rejection only — accepting that two
conforming implementations can return different errors.
This matters only if anything downstream (UI messages, logs, other
tests) will ever branch on the variant; say whether you think it will.

**Q17 — The `kind` field in the address API (blind A3).**
The API contract's `DestinationInfo.kind` is a free `String` with
exactly one documented value, `"subaddress"`. Options:
**A (implementer lean) replace the free string with a closed enum in
the Stage 0 `modules-api`/statements work**, so an undocumented kind
is unrepresentable; **B** keep the string and treat `"subaddress"` as
the only value other code may ever compare against. Minor, but it is
cheaper to close now than after Stage 6/7 code depends on it.

Response additions — please add:
```
Q13: <option> — <reasoning>
Q14: ...
Q15: ...
Q16: ...
Q17: ...
```

---

## Why this addendum exists (not part of the paste)

- Q1–Q12 in DECISIONS-FOR-OPUS-REVIEW.md are complete on the three
  spike findings (F1 AED, F2 backend, fixture failures) and on
  Q9/Q10 owner strategy. Nothing in Q1–Q12 needs changing.
- These five questions are the remainder of the blind author's own
  recorded list. Left unasked, they do not block the spike verdict —
  they resurface when the locked `tests/security/` suite is finalized
  in Stage 0 proper, which the spike report puts at 1–2 focused days
  of remaining work.
- No decision has been made on any of Q13–Q17; the "implementer lean"
  labels above are recommendations for Opus to challenge, in the same
  style as the main pack, not Cameron rulings.
