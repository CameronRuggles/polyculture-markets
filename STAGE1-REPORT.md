# Stage 1 — Completion Report (accounts, sessions, authorization)

Date: 2026-10-13 · Spec §24 Stage 1 · Built after Cameron lifted the Q10 park.

## What exists

New `app` crate in `marketplace/crates/app/` (Axum 0.8, SQLx/PostgreSQL 16
local, Askama templates, no JavaScript anywhere):

- **Passwords:** Argon2id (64 MiB, t=3, p=1 — starting point, hardware tuning
  still unverified #9) behind a global semaphore; saturation returns
  `HashError::Busy` → HTTP 503 instead of queueing.
- **Usernames:** case-folded at input, 3–24 chars `[a-z0-9_-]`, unique
  case-insensitively (DB constraint + fold).
- **Sessions:** 256-bit tokens, SHA-256 hashes only at rest; idle 24 h /
  absolute 14 d; fresh token on login and after registration (rotation);
  `__Host-session` in the HTTPS profile, plain `session` cookie in dev.
- **CSRF:** per-session synchronizer secret for authenticated POSTs;
  double-submit cookie for public POSTs; SameSite=Lax cookies throughout.
- **Recovery:** 20-char unambiguous codes, hashed at rest, single-use;
  consuming one revokes **all** sessions and marks the profile recovered in
  a single transaction; a fresh code is issued; unknown username and bad
  code return the same error (no account oracle).
- **Authorization:** one route table (`authz::ROUTES`) + a single
  `authorize()`; default-deny for anything undeclared. `/admin` etc. are
  declared but not yet routed (404 = denied) until their stages build them.
- **Throttles:** per-account token bucket (burst 60, 60/min refill);
  per-username exponential login delay (2s → capped 300s), **never** a
  lockout (a lockout is a stranger-freezing weapon).
- **Admission:** default `open-registration` module implements the
  modules-api trait — feature flag + global account cap, core supplies the
  count, module decides.
- **Pages:** register / login / logout / account / recover as plain HTML
  forms; registration displays the recovery code exactly once.

## Evidence

- Unit tests: app **9/9** (hash round-trip, username rules, session
  lifecycle incl. idle/absolute/revocation, recovery-code hashing, the full
  authorize matrix, bucket limits + refill, login-delay growth, admission
  flag/cap).
- Integration (real PostgreSQL): **1/1** — create account, duplicate
  rejected, session round-trip, recovery burns the code, revokes sessions,
  second use fails.
- Workspace: modules-api 4/4, domain 4/4 (from Stage 0) still green.
- Live smoke test: register → recovery code shown once → session cookie →
  `/account` renders with folded username; anonymous `/account` → redirect
  to login.

## Notes / honest gaps

- Applied login delay is capped at 5 s of actual sleep in the handler (the
  recorded delay schedule itself goes to 300 s; full-strength delays are a
  deployment-profile decision — revisit at Stage 10 hardening).
- TOTP for admin/moderator accounts (amendment, Stage 1 missing-question)
  is NOT yet implemented — admin routes aren't live; it lands before any
  admin surface ships.
- Per-route body limits, security headers, and the `authorize()` middleware
  form (currently enforced in-handler for `/account`) generalize in Stage 4
  when real pages land.
