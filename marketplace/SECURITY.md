# Security Policy

This software handles payment destinations and private communications
metadata. It never holds customer funds.

## Reporting

Report vulnerabilities privately to the instance operator or the project
maintainer through the contact on the instance's Security page. Do not open
public issues for vulnerabilities that affect fund safety, destination
integrity, message confidentiality, or account security until a fix has been
released.

## Scope notes

- The core invariants are in `docs/invariants.md`; the threat model is in
  `docs/threat-model.md`; known unverified properties are listed in
  `docs/unverified.md` and disclosed on every instance's Limitations page.
- No instance should handle real payments before the independent security
  review required by the spec's release gate (§25) has been completed.
