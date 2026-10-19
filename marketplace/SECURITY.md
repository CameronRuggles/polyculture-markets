# Security Policy

This software handles payment destinations and private communications
metadata. It never holds customer funds.

## Reporting

Report vulnerabilities in this software privately through GitHub's
private vulnerability reporting for the project repository:

- **https://github.com/CameronRuggles/polyculture-markets/security/advisories/new**

That form goes to the project maintainer only. (Private vulnerability
reporting was enabled on the repository on 2026-10-18.) Vulnerabilities
in one operator's *deployment* — their host, their configuration, their
key custody — belong to that instance's operator; the instance's own
Security page carries their contact.

Do not open a public issue for a vulnerability that affects fund safety,
destination integrity, message confidentiality, or account security until
a fix has been released.

## Scope notes

- The core invariants are in `docs/invariants.md`; the threat model is in
  `docs/threat-model.md`; known unverified properties are listed in
  `docs/unverified.md` and disclosed on every instance's Limitations page.
- No instance should handle real payments before the independent security
  review required by the spec's release gate (§25) has been completed.
