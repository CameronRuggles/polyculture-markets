# ARCHIVED — Stage 0 feasibility spike (archived 2026-10-18)

This directory is the Stage 0 feasibility spike of 2026-10-13: a
throwaway prototype that proved the four make-or-break assumptions
before the real build (see `SPIKE-REPORT.md`). **It is history, not
a component.** Nothing in production descends from this code by
copy; the shipping implementation is the workspace under
`marketplace/` (and `seller-helper/`).

## Status

- **Not built, not tested, not deployed.** CI (`.github/workflows/ci.yml`)
  never touches it; it belongs to no Cargo workspace (its own
  `Cargo.toml` is standalone and referenced by nothing); dependency
  scanners should target the two shipping lockfiles
  (`marketplace/Cargo.lock`, `seller-helper/Cargo.lock`).
- **Kept byte-stable on purpose.** Early reports cite this tree and
  its pinned `Cargo.lock` as evidence of what was actually tested.
  Its lockfile is therefore deliberately *not* updated.

## Known advisory exposure — why archiving is safe here

The pinned lockfile includes `rustls 0.23.45`, against which four
advisories were published on 2026-10-14 (RUSTSEC-2026-0346 through
RUSTSEC-2026-0349). That is acceptable for exactly one reason: this
code has never run outside the author's sandbox, serves no traffic,
holds no keys, and per this notice must not be built or run against
untrusted input. If that ever changes — if anyone wants to revive
the prototype — updating the lockfile (or, better, deleting this
directory) comes first.

## How to read it

`SPIKE-REPORT.md` is the narrative; `API-CONTRACT.md` is the sketch
the production API grew from; `fixtures-rfc9580/` are the RFC 9580
test vectors it validated against. `fixtures-wallet/` (not in git)
held a stagenet throwaway wallet — never a real one.
