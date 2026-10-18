// ============================================================================
// BLIND STAGE 1 SECURITY SUITE — accounts, sessions, authorization (spec §7, §17)
// ============================================================================
// Authored from the specification alone (Spec v2 + SPEC-V2-AMENDMENTS.md +
// marketplace/docs/api-contract.md), without seeing the implementation, per
// spec §22. Failures are to be fixed in the code, never by editing these
// tests (fixture constructions only, with the owner's sight of the diff).
//
// Conventions used below:
//   * `// DERIVATION-UNCERTAIN:` marks a cell/assertion whose derivation from
//     the texts is genuinely ambiguous; the comment states the ambiguity and
//     the reading that was encoded.
//   * `// INTERFACE-GUESS:` marks a call whose exact Rust shape (type name,
//     constructor, argument list) is not pinned by the contract; the call is
//     written as the contract dictates as closely as the texts allow.
//   * Boundary instants (exactly 12h idle / exactly 7d absolute) are never
//     asserted: the texts do not say whether the endpoints are inclusive, so
//     session tests probe strictly inside and strictly outside the limits.
// ============================================================================
//
// PLAIN-LANGUAGE ASSERTION LIST (for the owner)
// ----------------------------------------------------------------------------
// A. Route-by-role authorization matrix (authorize())
//   A1. Public pages/actions allow absolutely everyone, including a visitor
//       who is not logged in: the catalogue list and detail pages, seller
//       profile pages, the seller's public key download, the register and
//       login pages and their form submissions, and the Security,
//       Limitations and Policy pages.
//   A2. Signed-in-only pages/actions refuse a visitor who is not logged in
//       with "log in first" (LoginRequired) — which is a different answer
//       from "forbidden" (Deny) — and allow every signed-in role (Buyer,
//       Seller, Moderator, Admin). This covers: logging out, the inbox, the
//       account security page, adding/rotating identity keys, revoking a
//       session, generating recovery codes, creating an order, viewing an
//       order and its terms file, every order action button (accept,
//       decline, cancel, fulfil, complete, dispute, issue invoice), viewing
//       an invoice, its QR image and its statement files, submitting an
//       invoice signature, submitting payment evidence, viewing a pool
//       statement (the stricter "only this pool's seller and its buyers"
//       rule is an object-level check on top of this), conversations,
//       sending a message, downloading a message, viewing a dispute, adding
//       dispute disclosures, and filing a report.
//   A3. Seller surfaces allow only Seller and Admin; Buyer and Moderator are
//       refused with "forbidden", and a logged-out visitor gets "log in
//       first". This covers: the seller dashboard, creating a listing,
//       viewing and creating address pools, and signing a pool.
//   A4. Moderation surfaces allow only Moderator and Admin; Buyer and
//       Seller are refused with "forbidden", and a logged-out visitor gets
//       "log in first". This covers the moderation queue and resolving a
//       dispute.
//   A5. The admin surface allows only Admin; Buyer, Seller and Moderator
//       are refused with "forbidden", and a logged-out visitor gets "log
//       in first".
//   A6. Anything not in the route table is refused with "forbidden" for
//       everyone — including Admin, and including a logged-out visitor
//       (who gets "forbidden", not "log in first", for a route that does
//       not exist). This covers made-up paths and using the
//       wrong method on a real path (e.g. POST on the catalogue, GET on
//       logout, GET on an order's accept action, DELETE anywhere).
//
// B. CSRF
//   B1. Every POST route in the table requires a CSRF token.
//   B2. No GET route requires a CSRF token.
//
// C. Usernames
//   C1. Folding a username lowercases it, so different capitalisations of
//       the same name fold to the exact same string ("Alice", "ALICE" and
//       "aLiCe" are one account name).
//   C2. Folding trims whitespace from the ends of the name.
//   C3. Folding performs Unicode case folding, not just ASCII: accented
//       capitals fold to their lowercase forms, so "ÉMILE" and "émile"
//       are the same name.
//   C4. Folding is stable: folding an already-folded name changes nothing.
//   C5. Folding does not remove spaces inside a name (only the ends are
//       trimmed), so a name with an inner space stays invalid.
//   C6. A folded name of 3 to 24 characters drawn only from lowercase
//       letters, digits, underscore and hyphen is accepted — including the
//       exact boundary lengths 3 and 24, names that are all digits, and
//       names starting with a hyphen or underscore (the rules name no
//       other restriction).
//   C7. Names that are too short (0, 1 or 2 characters) or too long
//       (25 characters) are rejected.
//   C8. Names containing uppercase letters (i.e. not folded first), spaces,
//       punctuation or symbols ( ! . @ / + ), or non-ASCII letters are
//       rejected by validation.
//
// D. Passwords and the Argon2 guard
//   D1. A passphrase hashes and then verifies as correct.
//   D2. A wrong passphrase does not verify against that hash.
//   D3. Hashing the same passphrase twice gives two different stored
//       strings (salting), and both verify.
//   D4. The stored hash is not the passphrase and does not contain the
//       passphrase as text.
//   D5. Verification against a garbage stored string never succeeds.
//   D6. Very common passwords are recognised as common ("password" and
//       "123456" are asserted — see the uncertainty note in the test), and
//       a long nonsense passphrase is not flagged as common.
//   D7. A guard configured with zero hashing permits refuses work
//       immediately with "busy" instead of hanging or queueing forever.
//   D8. Under a flood of simultaneous hashing requests on a one-permit
//       guard, at least one request succeeds and at least one is refused
//       with "busy" — work is never queued without bound (see the
//       uncertainty note in the test about the unspecified queue size).
//
// E. Sessions and CSRF token comparison
//   E1. The idle timeout constant is 12 hours and the absolute timeout
//       constant is 7 days.
//   E2. A freshly created session belongs to its account, is not revoked,
//       and has its creation and last-seen times set to the creation
//       moment.
//   E3. A fresh session is valid at creation and still valid just before
//       12 hours of inactivity.
//   E4. A session is invalid after more than 12 hours without activity.
//   E5. Touching a session updates its last-seen time, and validity is
//       then measured from the touch: a session touched at 11 hours is
//       still valid at 22 hours 59 minutes but invalid at 23 hours
//       1 minute.
//   E6. Touching never extends the absolute limit: a session kept busy
//       with regular touches right up to the 7-day mark is valid just
//       before 7 days and invalid just after 7 days, even though its
//       last touch was about an hour earlier.
//   E7. A revoked session is invalid immediately, at its creation moment.
//   E8. A new session token is exactly 64 hexadecimal characters (256
//       bits written in hex), and two tokens are never alike.
//   E9. Hashing a token gives 32 bytes, always the same 32 bytes for the
//       same token, a different result for a different token, and never
//       the token itself.
//   E10. CSRF comparison accepts the exact stored secret and rejects a
//       different secret, a secret with an extra suffix, and an empty
//       presented value.
//
// F. Recovery codes (shape and hashing)
//   F1. Each generated recovery code carries at least 100 bits of entropy
//       worth of symbols: at least 17 characters from any alphabet of at
//       most 64 symbols (the weakest reading of the contract's "at least
//       100 bits").
//   F2. Recovery codes are plain ASCII, and never contain both members of
//       a visually confusable pair (0 with O, or 1 with l/I) — the
//       "unambiguous alphabet" requirement.
//   F3. Two generated recovery codes are different from each other.
//   F4. Hashing a code gives 32 bytes, is deterministic, differs between
//       codes, and is never the code itself.
//
// G. Login throttle
//   G1. Repeated login failures for one name produce delays that never
//       go down (non-decreasing).
//   G2. The throttle is keyed by the folded name: failures recorded under
//       "Alice", "ALICE" and "aLiCe" (folded before recording, as the API
//       requires) all feed one shared, still-growing delay sequence.
//   G3. A different name is unaffected: its first delay equals the first
//       delay a brand-new throttle gives any name (the delay depends only
//       on that name's own failure count — the recording function takes
//       no timestamp, so it cannot depend on the clock).
//   G4. Clearing a name's failures resets it: the next delay equals the
//       first-delay again.
//   G5. The delay is capped, so it can never grow into a lockout: after
//       well over a hundred failures the delay has stopped growing —
//       each further failure returns exactly the same delay.
//   G6. A fresh request throttle allows an account's first request (the
//       request limiter is advisory and starts open).
//
// H. Token bucket (per-account request limiter mechanics)
//   H1. A bucket with capacity 3 and no refill allows exactly 3 requests
//       and then refuses, and still refuses an hour later.
//   H2. A bucket refills with time: after draining a 2-token bucket that
//       refills at 60 tokens per minute, waiting 30 seconds restores
//       service.
//   H3. Refilling never exceeds capacity: after that long wait the bucket
//       allows exactly its capacity (2), not the 30 tokens that elapsed.
//   H4. Refill is proportional: a 5-token bucket refilling at 60 per
//       minute, fully drained, allows exactly 3 requests after 3 seconds
//       and refuses the fourth.
//
// I. Admission (default open policy, through the AdmissionPolicy trait)
//   I1. When registrations are open and the account count is under the
//       cap, a registration is Admitted (checked at an empty instance and
//       one below the cap).
//   I2. When registrations are closed, a registration is not Admitted.
//   I3. When the account count is exactly at the cap, a registration is
//       not Admitted; the same holds above the cap.
//
// J. Database integration (PostgreSQL; skipped silently when DATABASE_URL
//    is not set — returning early is the harness contract, not a pass
//    claim the owner should read as coverage)
//   J1. An account can be created, and creating a second account with the
//       exact same (folded) username fails.
//   J2. A session created for an account can be found again by its raw
//       token, belongs to that account, is not revoked, and is valid now.
//   J3. Looking up a session by an unknown token finds nothing.
//   J4. What is stored in the sessions table is exactly the token's hash
//       (the same 32 bytes hash_token produces) and never the raw token.
//   J5. What is stored in the recovery codes table is exactly the code's
//       hash and never the raw code.
//   J6. Consuming a recovery code with a wrong code fails, does not
//       revoke the account's sessions, and gives exactly the same outcome
//       as consuming a code for a username that does not exist (no way to
//       probe whether an account exists).
//   J7. Consuming a recovery code with the correct code succeeds exactly
//       once: the same code cannot be consumed a second time.
//   J8. A successful recovery revokes ALL of the account's sessions (both
//       sessions created before recovery stop being usable).
//   J9. A successful recovery marks the account as recovered (the
//       recovered-at timestamp is set).
//   (Every database test deletes the rows it created.)
// ============================================================================

use app::admission::OpenAdmission; // CONSTRUCTION FIX (2026-10-14): real type name (was guessed RateLimitedOpen)
use app::authz::{authorize, route_requires_csrf, Decision, Role};
use app::passwords::{is_common_password, HashError, HashGuard};
use app::recovery::{hash_code, new_recovery_code};
use app::sessions::{
    csrf_matches, hash_token, new_token, Session, ABSOLUTE_TIMEOUT, IDLE_TIMEOUT,
};
use app::throttle::{Throttles, TokenBucket};
use app::usernames::{fold_username, validate_username};
use modules_api::{Admission, AdmissionCx, AdmissionPolicy, FormInput};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Fixed synthetic "now" for every time-based unit test (determinism: no
/// test in this file sleeps or reads the wall clock, except the DB tests,
/// which must compare against real stored timestamps).
fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp is valid")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Want {
    Allow,
    Deny,
    LoginRequired,
}

fn decision_name(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
        Decision::LoginRequired => "LoginRequired",
    }
}

fn assert_decision(method: &str, path: &str, actor_name: &str, got: Decision, want: Want) {
    let ok = matches!(
        (want, &got),
        (Want::Allow, Decision::Allow)
            | (Want::Deny, Decision::Deny)
            | (Want::LoginRequired, Decision::LoginRequired)
    );
    assert!(
        ok,
        "authorize({method} {path}) for {actor_name}: expected {want:?}, got {}",
        decision_name(&got)
    );
}

/// Actor indices used across the matrix: 0 anonymous, 1 Buyer, 2 Seller,
/// 3 Moderator, 4 Admin. A fresh `Option<Role>` is built per call because
/// the contract does not promise `Role: Copy`.
fn actor(index: usize) -> (&'static str, Option<Role>) {
    match index {
        0 => ("anonymous", None),
        1 => ("Buyer", Some(Role::Buyer)),
        2 => ("Seller", Some(Role::Seller)),
        3 => ("Moderator", Some(Role::Moderator)),
        _ => ("Admin", Some(Role::Admin)),
    }
}

// ---------------------------------------------------------------------------
// A. Route-by-role authorization matrix
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Spec §17 unauthenticated set (contract §7): allows every actor.
    Public,
    /// Authenticated, no role restriction: anonymous -> LoginRequired,
    /// every signed-in role -> Allow (object-level rules apply on top).
    Authenticated,
    /// Seller surfaces: Seller and Admin only.
    Seller,
    /// Moderation surfaces: Moderator and Admin only.
    Moderation,
    /// /admin: Admin only.
    AdminOnly,
}

/// The route table, derived from spec §17's route list (path forms as
/// written there) and classified by contract §7's authorization semantics.
const ROUTES: &[(&str, &str, Class)] = &[
    // --- Public (spec §17 unauthenticated set; contract §7) ---
    ("GET", "/listings", Class::Public),
    ("GET", "/listings/{id}", Class::Public),
    ("GET", "/sellers/{id}", Class::Public),
    ("GET", "/sellers/{id}/key.asc", Class::Public),
    ("GET", "/register", Class::Public),
    ("POST", "/register", Class::Public),
    ("GET", "/login", Class::Public),
    ("POST", "/login", Class::Public),
    ("GET", "/security", Class::Public),
    ("GET", "/limitations", Class::Public),
    ("GET", "/policy", Class::Public),
    // --- Authenticated, any role (contract §7: account, security/keys,
    //     orders and inbox surfaces; messaging/disputes/reports are
    //     signed-in surfaces with participant/object checks on top) ---
    // DERIVATION-UNCERTAIN: POST /logout is listed next to the login
    // routes in spec §17, and contract §7's public set names "register/
    // login pages and their POSTs". Logout is meaningless without a
    // session, so it is encoded as authenticated (anonymous ->
    // LoginRequired); if "their POSTs" was meant to include logout, this
    // one cell (anonymous x POST /logout) would be Allow instead.
    ("POST", "/logout", Class::Authenticated),
    ("GET", "/inbox", Class::Authenticated),
    ("GET", "/account/security", Class::Authenticated),
    ("POST", "/account/keys", Class::Authenticated),
    ("POST", "/account/keys/rotate", Class::Authenticated),
    ("POST", "/account/sessions/{id}/revoke", Class::Authenticated),
    ("POST", "/account/recovery-codes", Class::Authenticated),
    ("POST", "/orders", Class::Authenticated),
    // OWNER AMENDMENT 2026-10-14 (SPEC-V2-AMENDMENTS.md, §17): the
    // orders collection route GET /orders is declared (any
    // authenticated account) effective this date. This row and the
    // removal of ("GET", "/orders") from the undeclared list below
    // were applied by the implementer under that ruling during the
    // Stage 4 gate — the suite's only post-lock changes, recorded in
    // GATE4-REPORT.md.
    ("GET", "/orders", Class::Authenticated),
    ("GET", "/orders/{id}", Class::Authenticated),
    ("GET", "/orders/{id}/terms.txt", Class::Authenticated),
    // DERIVATION-UNCERTAIN (applies to all seven order-action POSTs
    // below): the §9 state machine restricts each transition to a
    // specific actor (seller accepts, buyer cancels, ...). Contract §7
    // nevertheless classifies "orders" surfaces as any-authenticated
    // with object-level rules applying on top, so authorize() — the
    // route-level function — is asserted to Allow every signed-in role
    // here; the per-transition actor guard is a state-machine check,
    // not a route decision. If authorize() is intended to encode the
    // transition actors as well, these rows are the ones that change.
    ("POST", "/orders/{id}/accept", Class::Authenticated),
    ("POST", "/orders/{id}/decline", Class::Authenticated),
    ("POST", "/orders/{id}/cancel", Class::Authenticated),
    ("POST", "/orders/{id}/fulfil", Class::Authenticated),
    ("POST", "/orders/{id}/complete", Class::Authenticated),
    ("POST", "/orders/{id}/dispute", Class::Authenticated),
    ("POST", "/orders/{id}/invoice", Class::Authenticated),
    ("GET", "/invoices/{id}", Class::Authenticated),
    ("GET", "/invoices/{id}/qr.png", Class::Authenticated),
    ("GET", "/invoices/{id}/statement.txt", Class::Authenticated),
    ("GET", "/invoices/{id}/statement.txt.asc", Class::Authenticated),
    // DERIVATION-UNCERTAIN: POST /invoices/{id}/signature is performed by
    // the order's seller in the §11 flow, and evidence submission by the
    // buyer; contract §7 names only the seller dashboard and listing
    // creation as seller-only surfaces, so both are encoded as
    // any-authenticated at route level with the party check at object
    // level.
    ("POST", "/invoices/{id}/signature", Class::Authenticated),
    ("POST", "/invoices/{id}/evidence/{module}", Class::Authenticated),
    // DERIVATION-UNCERTAIN: spec §17 adds "a pool statement is visible
    // only to its seller and to buyers holding an invoice from that
    // pool". That is an object-level visibility rule; at route level the
    // statement is not public, so anonymous -> LoginRequired and every
    // signed-in role -> Allow, with the pool-specific rule on top.
    ("GET", "/pools/{id}/statement.txt", Class::Authenticated),
    ("GET", "/pools/{id}/statement.txt.asc", Class::Authenticated),
    ("GET", "/conversations/{id}", Class::Authenticated),
    ("POST", "/conversations/{id}/messages", Class::Authenticated),
    ("GET", "/messages/{id}/download", Class::Authenticated),
    ("GET", "/disputes/{id}", Class::Authenticated),
    ("POST", "/disputes/{id}/disclosures", Class::Authenticated),
    ("POST", "/reports", Class::Authenticated),
    // --- Seller surfaces (Seller or Admin; contract §7) ---
    ("GET", "/seller", Class::Seller),
    ("POST", "/seller/listings", Class::Seller),
    ("GET", "/seller/pools", Class::Seller),
    ("POST", "/seller/pools", Class::Seller),
    ("POST", "/seller/pools/{id}/signature", Class::Seller),
    // --- Moderation surfaces (Moderator or Admin; contract §7) ---
    ("GET", "/moderation", Class::Moderation),
    ("POST", "/disputes/{id}/resolve", Class::Moderation),
    // --- Admin only (contract §7: "/admin: Admin only") ---
    // DERIVATION-UNCERTAIN: spec §17's route list contains no literal
    // /admin route; contract §7 and the amendments (admin routes on a
    // separate listener) establish the surface. Only the exact path
    // "/admin" is asserted; whether /admin/* subpaths are declared
    // routes is not decided by the texts and is not asserted.
    // For the anonymous cell: the general rule "authenticated routes
    // return LoginRequired for anonymous" is applied; an implementation
    // that Denies anonymous on /admin to hide the surface would differ
    // on this one cell.
    ("GET", "/admin", Class::AdminOnly),
];

fn expected(class: Class, actor_index: usize) -> Want {
    match class {
        Class::Public => Want::Allow,
        Class::Authenticated => {
            if actor_index == 0 {
                Want::LoginRequired
            } else {
                Want::Allow
            }
        }
        Class::Seller => match actor_index {
            0 => Want::LoginRequired,
            2 | 4 => Want::Allow, // Seller, Admin
            _ => Want::Deny,      // Buyer, Moderator
        },
        Class::Moderation => match actor_index {
            0 => Want::LoginRequired,
            3 | 4 => Want::Allow, // Moderator, Admin
            _ => Want::Deny,      // Buyer, Seller
        },
        Class::AdminOnly => match actor_index {
            0 => Want::LoginRequired,
            4 => Want::Allow, // Admin
            _ => Want::Deny,  // Buyer, Seller, Moderator
        },
    }
}

/// A1–A5: the full route-by-role matrix — every declared route, every
/// actor, every method in the table.
#[test]
fn matrix_every_declared_route_every_actor() {
    for (method, path, class) in ROUTES {
        for index in 0..5 {
            let (name, role) = actor(index);
            let got = authorize(method, path, role);
            assert_decision(method, path, name, got, expected(*class, index));
        }
    }
}

/// A1 spot check: the catalogue is reachable with no account at all.
#[test]
fn matrix_public_catalogue_allows_anonymous() {
    assert_decision("GET", "/listings", "anonymous", authorize("GET", "/listings", None), Want::Allow);
    assert_decision(
        "GET",
        "/sellers/{id}/key.asc",
        "anonymous",
        authorize("GET", "/sellers/{id}/key.asc", None),
        Want::Allow,
    );
}

/// A2 spot check: anonymous on an authenticated route is LoginRequired,
/// which must NOT collapse into Deny (the two are distinguishable by
/// design at this layer, contract §7).
#[test]
fn matrix_anonymous_gets_login_required_not_deny() {
    assert_decision("GET", "/inbox", "anonymous", authorize("GET", "/inbox", None), Want::LoginRequired);
    assert_decision(
        "POST",
        "/orders",
        "anonymous",
        authorize("POST", "/orders", None),
        Want::LoginRequired,
    );
}

/// A3 spot check: a Buyer is forbidden from seller surfaces — Deny, even
/// though the Buyer is signed in.
#[test]
fn matrix_seller_surface_denies_buyer_and_moderator() {
    assert_decision(
        "GET",
        "/seller",
        "Buyer",
        authorize("GET", "/seller", Some(Role::Buyer)),
        Want::Deny,
    );
    assert_decision(
        "POST",
        "/seller/listings",
        "Moderator",
        authorize("POST", "/seller/listings", Some(Role::Moderator)),
        Want::Deny,
    );
}

/// A4/A5 spot check: moderation is not an Admin-only surface, and admin
/// is not open to moderators.
#[test]
fn matrix_moderation_and_admin_boundaries() {
    assert_decision(
        "GET",
        "/moderation",
        "Moderator",
        authorize("GET", "/moderation", Some(Role::Moderator)),
        Want::Allow,
    );
    assert_decision(
        "GET",
        "/moderation",
        "Seller",
        authorize("GET", "/moderation", Some(Role::Seller)),
        Want::Deny,
    );
    assert_decision(
        "GET",
        "/admin",
        "Moderator",
        authorize("GET", "/admin", Some(Role::Moderator)),
        Want::Deny,
    );
    assert_decision(
        "POST",
        "/disputes/{id}/resolve",
        "Buyer",
        authorize("POST", "/disputes/{id}/resolve", Some(Role::Buyer)),
        Want::Deny,
    );
}

/// A6: undeclared paths and wrong methods on known paths are Deny for
/// every actor — including Admin, and including anonymous (an unknown
/// route must not leak a LoginRequired that implies it exists).
#[test]
fn matrix_undeclared_paths_and_wrong_methods_deny_everyone() {
    const UNDECLARED: &[(&str, &str)] = &[
        ("GET", "/no-such-route"),
        ("POST", "/listings"),
        ("POST", "/listings/{id}"),
        ("GET", "/logout"), // logout is POST-only
        ("PUT", "/login"),
        ("DELETE", "/listings/{id}"),
        ("POST", "/inbox"), // inbox is GET-only
        ("GET", "/account/keys"), // keys are POST-only
        ("POST", "/security"), // static info pages are GET-only
        ("GET", "/orders/{id}/accept"), // order actions are POST-only; GET never changes state
        ("GET", "/seller/listings"),     // listing creation is POST-only
        ("DELETE", "/account/security"),
        ("PATCH", "/seller"),
    ];
    for (method, path) in UNDECLARED {
        for index in 0..5 {
            let (name, role) = actor(index);
            let got = authorize(method, path, role);
            assert_decision(method, path, name, got, Want::Deny);
        }
    }
}

// ---------------------------------------------------------------------------
// B. CSRF
// ---------------------------------------------------------------------------

/// B1 + B2: every POST route in the table requires CSRF; no GET route
/// does (contract §7: "Every state-changing route (all POSTs) requires
/// CSRF; no GET route requires CSRF, and GET never changes state").
/// route_requires_csrf is deliberately NOT asserted for undeclared
/// paths: the texts do not decide whether the function answers about the
/// method in the abstract or only about declared routes.
#[test]
fn csrf_every_post_route_requires_it_no_get_route_does() {
    for (method, path, _) in ROUTES {
        let required = route_requires_csrf(method, path);
        if *method == "POST" {
            assert!(required, "POST {path} must require CSRF");
        } else {
            assert!(!required, "GET {path} must not require CSRF");
        }
    }
}

// ---------------------------------------------------------------------------
// C. Usernames
// ---------------------------------------------------------------------------

/// C1: case variants of the same name are the same account name.
#[test]
fn username_case_variants_fold_identically() {
    assert_eq!(fold_username("Alice"), "alice");
    assert_eq!(fold_username("ALICE"), fold_username("alice"));
    assert_eq!(fold_username("aLiCe"), fold_username("Alice"));
}

/// C2: folding trims surrounding whitespace.
#[test]
fn username_folding_trims_ends() {
    assert_eq!(fold_username("  alice  "), "alice");
    assert_eq!(fold_username("\talice\n"), "alice");
}

/// C3: folding is Unicode case folding (contract §7: "Unicode case-fold
/// + trim"), not ASCII-only lowercasing.
#[test]
fn username_folding_is_unicode_case_fold() {
    assert_eq!(fold_username("ÉMILE"), "émile");
    assert_eq!(fold_username("ÉMILE"), fold_username("émile"));
}

/// C4: folding is idempotent.
#[test]
fn username_folding_is_idempotent() {
    let once = fold_username("  Alice_42  ");
    assert_eq!(fold_username(&once), once);
}

/// C5 + C8 (part): an inner space survives folding and fails validation.
#[test]
fn username_inner_space_survives_folding_and_is_invalid() {
    assert_eq!(fold_username("a b"), "a b");
    assert!(!validate_username("a b"));
}

/// C6: valid folded names, including both length boundaries.
#[test]
fn username_validate_accepts_contract_charset_and_lengths() {
    assert!(validate_username("abc")); // minimum length 3
    assert!(validate_username(&"a".repeat(24))); // maximum length 24
    assert!(validate_username("alice_42-x")); // letters, digits, '_' and '-'
    assert!(validate_username("123")); // all digits
    // The contract states the complete rule — 3–24 chars of [a-z0-9_-]
    // after folding — and names no leading-character restriction.
    assert!(validate_username("-ab"));
    assert!(validate_username("_ab"));
    // A name becomes valid exactly by folding it (C1 + C6 together).
    assert!(validate_username(&fold_username("Alice")));
}

/// C7: length boundaries are enforced.
#[test]
fn username_validate_rejects_bad_lengths() {
    assert!(!validate_username(""));
    assert!(!validate_username("a"));
    assert!(!validate_username("ab"));
    assert!(!validate_username(&"a".repeat(25)));
}

/// C8: anything outside [a-z0-9_-] is rejected — including unfolded
/// (uppercase) input, which proves validate does not fold on its own.
#[test]
fn username_validate_rejects_out_of_charset() {
    assert!(!validate_username("Alice")); // not folded first
    assert!(!validate_username("a!b"));
    assert!(!validate_username("a.b"));
    assert!(!validate_username("a@b"));
    assert!(!validate_username("a/b"));
    assert!(!validate_username("a+b"));
    assert!(!validate_username("émile")); // non-ASCII letter
}

// ---------------------------------------------------------------------------
// D. Passwords and the Argon2 guard
// ---------------------------------------------------------------------------

/// D1–D5: hash/verify round-trip, wrong passphrase, salting, and stored
/// form. (A short real Argon2 hash is expected and allowed.)
#[tokio::test]
async fn password_hash_verify_roundtrip_and_salting() {
    let guard = HashGuard::new(4);
    let passphrase = "my correct passphrase 123";

    let hash1 = guard.hash(passphrase).await.expect("hash must succeed");
    // D4: the stored form is not, and does not contain, the passphrase.
    assert_ne!(hash1, passphrase);
    assert!(!hash1.contains(passphrase));

    // D1 / D2.
    assert!(
        guard.verify(passphrase, &hash1).await.expect("verify must run"),
        "the right passphrase must verify"
    );
    assert!(
        !guard.verify("my wrong passphrase 456", &hash1).await.expect("verify must run"),
        "a wrong passphrase must not verify"
    );

    // D3: salting — a second hash of the same passphrase differs and
    // still verifies.
    let hash2 = guard.hash(passphrase).await.expect("second hash must succeed");
    assert_ne!(hash1, hash2, "two hashes of one passphrase must differ (salted)");
    assert!(guard.verify(passphrase, &hash2).await.expect("verify must run"));

    // D5: a malformed stored hash must never authenticate anyone,
    // whether the implementation reports that as Ok(false) or
    // Err(HashError::Invalid).
    let garbage = guard.verify(passphrase, "not-an-argon2-hash").await;
    assert!(
        !matches!(garbage, Ok(true)),
        "verification against a garbage stored hash must never succeed"
    );
}

/// D6: common-password list.
/// DERIVATION-UNCERTAIN: the spec (§7) requires passphrases to be
/// "checked against a bundled offline list of common passwords" but no
/// text enumerates the list's contents. "password" and "123456" appear
/// in every standard common-password corpus (they are the canonical top
/// entries), so they are asserted; the task brief's example
/// "password123456" is NOT asserted, because a top-N bundled list might
/// legitimately stop short of it. The negative case is a long nonsense
/// string that no common-password list plausibly contains.
#[test]
fn common_passwords_are_flagged() {
    assert!(is_common_password("password"), "\"password\" is on every common-password list");
    assert!(is_common_password("123456"), "\"123456\" is on every common-password list");
    assert!(
        !is_common_password("zqxjkvb-uncommon-passphrase-987654"),
        "a long nonsense passphrase must not be flagged as common"
    );
}

/// D7: a zero-permit guard must refuse with Busy, deterministically —
/// never hang waiting for a permit that cannot exist and never queue
/// without bound (contract §7: "Busy on saturation — never queues
/// unboundedly"). The timeout turns a hypothetical hang into a failure
/// instead of a stuck suite.
#[tokio::test]
async fn argon2_guard_with_zero_permits_reports_busy() {
    // INTERFACE-GUESS: HashGuard::new(0) is constructible (a semaphore
    // with zero permits). If the constructor forbids 0, this test's
    // construction is the part to re-check — the Busy-not-hang property
    // itself is contractual.
    let guard = HashGuard::new(0);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        guard.hash("some-passphrase-123"),
    )
    .await;
    match outcome {
        Ok(Err(e)) => assert!(
            matches!(e, HashError::Busy),
            "zero-permit guard must report Busy, got a different error"
        ),
        Ok(Ok(_)) => panic!("zero-permit guard must not produce a hash"),
        Err(_) => panic!("zero-permit guard hung: saturation must return Busy, never block forever"),
    }
}

/// D8: saturation under concurrency (spec §7 Argon2 guard, §23 "a login
/// flood gets 503s from the Argon2 guard").
/// DERIVATION-UNCERTAIN: the contract fixes the behaviour (bounded queue,
/// Busy on overflow) but not the queue's length. This test fires 24
/// simultaneous hashes at a 1-permit guard; Argon2id at OWASP parameters
/// takes long enough that the requests genuinely overlap, so any queue
/// that deserves the name "short bounded queue" (contract §7) overflows.
/// If the implementation's queue legitimately holds all 24, this is the
/// assertion to bring to the owner rather than silently relax.
#[tokio::test]
async fn argon2_guard_saturation_reports_busy_for_some() {
    let guard = std::sync::Arc::new(HashGuard::new(1));
    let mut handles = Vec::new();
    for _ in 0..24 {
        let g = guard.clone();
        handles.push(tokio::spawn(
            async move { g.hash("saturation-test-passphrase").await },
        ));
    }
    let mut ok_count = 0usize;
    let mut busy_count = 0usize;
    for handle in handles {
        match handle.await.expect("hash task must not panic") {
            Ok(_) => ok_count += 1,
            Err(HashError::Busy) => busy_count += 1,
            Err(_) => panic!("hashing a valid passphrase may only fail with Busy"),
        }
    }
    assert!(ok_count >= 1, "at least the permit holder's hash must succeed");
    assert!(
        busy_count >= 1,
        "a flood beyond the bounded queue must refuse some work with Busy (ok={ok_count}, busy={busy_count})"
    );
}

// ---------------------------------------------------------------------------
// E. Sessions and CSRF token comparison
// ---------------------------------------------------------------------------

/// E1: the timeout constants are exactly the spec §7 values.
#[test]
fn session_timeout_constants_match_spec() {
    assert_eq!(IDLE_TIMEOUT, Duration::hours(12));
    assert_eq!(ABSOLUTE_TIMEOUT, Duration::days(7));
}

/// E2 + E3: a fresh session's fields and immediate validity.
#[test]
fn fresh_session_fields_and_validity() {
    let s = Session::fresh(42, t0());
    assert_eq!(s.account_id, 42);
    assert!(!s.revoked);
    assert_eq!(s.created_at, t0());
    assert_eq!(s.last_seen_at, t0());
    assert!(s.is_valid(t0()), "a fresh session is valid at creation");
    assert!(
        s.is_valid(t0() + Duration::hours(11) + Duration::minutes(59)),
        "a session is still valid just inside the 12h idle limit"
    );
}

/// E4: idle expiry.
#[test]
fn session_expires_after_idle_timeout() {
    let s = Session::fresh(42, t0());
    assert!(
        !s.is_valid(t0() + Duration::hours(12) + Duration::minutes(1)),
        "12h+ of inactivity must invalidate the session"
    );
}

/// E5: touch refreshes the idle deadline (and updates last_seen_at).
#[test]
fn session_touch_refreshes_idle_deadline() {
    let mut s = Session::fresh(42, t0());
    s.touch(t0() + Duration::hours(11));
    assert_eq!(s.last_seen_at, t0() + Duration::hours(11));
    assert!(
        s.is_valid(t0() + Duration::hours(22) + Duration::minutes(59)),
        "validity is measured from the last touch, not from creation"
    );
    assert!(
        !s.is_valid(t0() + Duration::hours(23) + Duration::minutes(1)),
        "12h+ after the last touch the session is invalid"
    );
}

/// E6: touch never refreshes the absolute deadline.
#[test]
fn session_touch_does_not_extend_absolute_deadline() {
    let mut s = Session::fresh(42, t0());
    // Keep the session busy: touch daily, then again an hour before the
    // 7-day mark, so the idle deadline is nowhere near when it dies.
    for day in 1..7 {
        s.touch(t0() + Duration::days(day));
    }
    s.touch(t0() + Duration::days(6) + Duration::hours(23));
    assert!(
        s.is_valid(t0() + Duration::days(7) - Duration::minutes(30)),
        "an active session is valid just inside the 7d absolute limit"
    );
    assert!(
        !s.is_valid(t0() + Duration::days(7) + Duration::minutes(1)),
        "past 7d the session is invalid regardless of activity (last touch ~2h earlier)"
    );
}

/// E7: revocation is immediate.
#[test]
fn revoked_session_is_invalid() {
    let mut s = Session::fresh(42, t0());
    s.revoked = true;
    assert!(!s.is_valid(t0()), "a revoked session is invalid at once");
}

/// E8 + E9: token generation and hashing (spec §7: 256 random bits, hex;
/// only the SHA-256 hash is ever stored).
#[test]
fn session_tokens_are_long_distinct_and_hash_deterministically() {
    let a = new_token();
    let b = new_token();
    assert_eq!(a.len(), 64, "256 random bits in hex is 64 characters");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "token must be hex");
    assert_ne!(a, b, "two generated tokens must differ");

    let ha = hash_token(&a);
    assert_eq!(ha.len(), 32, "the stored hash is 32 bytes (SHA-256)");
    assert_eq!(ha, hash_token(&a), "hash_token is deterministic");
    assert_ne!(ha, hash_token(&b), "different tokens hash differently");
    assert_ne!(
        ha.to_vec(),
        a.as_bytes().to_vec(),
        "the stored hash is never the token itself"
    );
}

/// E10: CSRF secret comparison (contract §7: csrf_matches, constant
/// time — timing itself is not observable from a unit test; equality
/// semantics are).
/// INTERFACE-GUESS: csrf_matches is grouped with the session surface in
/// contract §7 and is imported from app::sessions; if it lives in
/// another app module, only this import moves — the semantics asserted
/// here are the contract's.
#[test]
fn csrf_matches_only_the_exact_secret() {
    assert!(csrf_matches("secret-token-value", "secret-token-value"));
    assert!(!csrf_matches("secret-token-value", "secret-token-valuf"));
    assert!(!csrf_matches("secret-token-value", "secret-token-value-extra"));
    assert!(!csrf_matches("secret-token-value", ""));
}

// ---------------------------------------------------------------------------
// F. Recovery codes (shape and hashing)
// ---------------------------------------------------------------------------

/// F1–F4 (spec §7: 10 codes of at least 100 bits each; contract §7:
/// "≥100 bits, unambiguous alphabet", stored as SHA-256 hashes).
/// DERIVATION-UNCERTAIN: no text pins the code's exact length or
/// alphabet, and grouped formats with separators are conceivable, so
/// the length assertion uses the weakest sound reading: even the most
/// compact plausible alphabet (64 symbols, 6 bits each) needs 17
/// characters to reach 100 bits, and separators only add length. The
/// unambiguity assertion is pair-based (never both members of a
/// confusable pair), which hex/base32/base58-style alphabets all
/// satisfy.
#[test]
fn recovery_code_shape_and_hashing() {
    let c1 = new_recovery_code();
    let c2 = new_recovery_code();
    assert_ne!(c1, c2, "two generated recovery codes must differ");
    assert!(
        c1.chars().count() >= 17,
        "a code of at least 100 bits needs at least 17 symbols: got {c1:?}"
    );
    assert!(c1.is_ascii(), "recovery codes are ASCII");
    let has = |ch: char| c1.contains(ch);
    assert!(!(has('0') && has('O')), "alphabet must not contain both 0 and O");
    assert!(
        !(has('1') && (has('l') || has('I'))),
        "alphabet must not contain both 1 and l/I"
    );

    let h1 = hash_code(&c1);
    assert_eq!(h1.len(), 32, "the stored code hash is 32 bytes (SHA-256)");
    assert_eq!(h1, hash_code(&c1), "hash_code is deterministic");
    assert_ne!(h1, hash_code(&c2), "different codes hash differently");
    assert_ne!(h1.to_vec(), c1.as_bytes().to_vec(), "the stored hash is never the code itself");
}

// ---------------------------------------------------------------------------
// G. Login throttle
// ---------------------------------------------------------------------------

/// G1: delays never decrease as failures accumulate.
/// INTERFACE-GUESS: the contract's Throttles sketch names its methods
/// but no constructor; `Throttles::new()` with no arguments is used.
/// If construction takes configuration, only these constructions
/// change — the delay properties asserted are the contract's.
#[test]
fn login_throttle_delays_are_non_decreasing() {
    let th = Throttles::new();
    let mut delays = Vec::new();
    for _ in 0..8 {
        delays.push(th.record_login_failure("alice"));
    }
    for pair in delays.windows(2) {
        assert!(
            pair[1] >= pair[0],
            "login delays must be non-decreasing, got {delays:?}"
        );
    }
}

/// G2: the throttle is keyed by the folded name (contract §7:
/// record_login_failure takes username_folded and is "keyed by
/// submitted name, account or not"; spec §7: "keyed by the submitted
/// username whether or not it exists"). Callers fold first — exactly as
/// the API directs — so every capitalisation feeds one sequence.
#[test]
fn login_throttle_is_shared_across_case_spellings() {
    let th = Throttles::new();
    let d1 = th.record_login_failure(&fold_username("Alice"));
    let d2 = th.record_login_failure(&fold_username("ALICE"));
    let d3 = th.record_login_failure(&fold_username("aLiCe"));
    assert!(
        d2 >= d1 && d3 >= d2,
        "case spellings of one name share one growing throttle ({d1:?}, {d2:?}, {d3:?})"
    );
}

/// G3 + G4: per-name independence and reset on clear. The recording
/// function takes no timestamp, so for a fixed failure count the delay
/// is fully determined — a fresh name on a used throttle must get
/// exactly the delay a fresh throttle gives a fresh name.
#[test]
fn login_throttle_is_per_name_and_clear_resets() {
    let reference_first = Throttles::new().record_login_failure("carol");

    let th = Throttles::new();
    for _ in 0..5 {
        th.record_login_failure("alice");
    }
    assert_eq!(
        th.record_login_failure("bob"),
        reference_first,
        "failures for one name must not raise another name's delay"
    );

    th.clear_login_failures("alice");
    assert_eq!(
        th.record_login_failure("alice"),
        reference_first,
        "clearing a name's failures resets its delay to the first-failure delay"
    );
}

/// G5: the throttle delays, never locks out (spec §7: "Delay, never
/// lockout, so attackers cannot lock users out"; contract §7: "grows
/// exponentially, capped"). A capped exponential must have stopped
/// growing long before 130 failures — any base delay and any finite cap
/// consistent with a login delay saturate many doublings earlier — so
/// the last two delays must be exactly equal. The return type is a
/// finite Duration by construction; there is no lockout state to reach.
#[test]
fn login_throttle_delay_is_capped_never_a_lockout() {
    let th = Throttles::new();
    let mut last = th.record_login_failure("mallory");
    for _ in 0..128 {
        let d = th.record_login_failure("mallory");
        assert!(d >= last, "delays stay non-decreasing even near the cap");
        last = d;
    }
    assert_eq!(
        th.record_login_failure("mallory"),
        last,
        "after 130 failures the delay must have reached its cap and stopped growing"
    );
}

/// G6: a fresh request throttle starts open. (Exhaustion behaviour of
/// allow_request depends on constructor configuration the contract does
/// not pin for Throttles, so only the starts-open property — which any
/// advisory limiter must have — is asserted.)
#[test]
fn request_throttle_allows_first_request() {
    let th = Throttles::new();
    assert!(th.allow_request(123, t0()), "a fresh throttle allows a first request");
}

// ---------------------------------------------------------------------------
// H. Token bucket
// ---------------------------------------------------------------------------

/// H1: capacity is enforced, and with zero refill it stays enforced.
#[test]
fn token_bucket_enforces_capacity_without_refill() {
    let mut bucket = TokenBucket::new(3.0, 0.0, t0());
    assert!(bucket.allow(t0()));
    assert!(bucket.allow(t0()));
    assert!(bucket.allow(t0()));
    assert!(!bucket.allow(t0()), "the 4th request exceeds capacity 3");
    assert!(
        !bucket.allow(t0() + Duration::hours(1)),
        "with refill 0, time alone restores nothing"
    );
}

/// H2 + H3: refill over time, capped at capacity.
#[test]
fn token_bucket_refills_over_time_and_caps_at_capacity() {
    let mut bucket = TokenBucket::new(2.0, 60.0, t0());
    assert!(bucket.allow(t0()));
    assert!(bucket.allow(t0()));
    assert!(!bucket.allow(t0()), "bucket drained at t0");
    let later = t0() + Duration::seconds(30); // 30 tokens' worth of refill
    assert!(bucket.allow(later), "refill restores service");
    assert!(bucket.allow(later));
    assert!(
        !bucket.allow(later),
        "refill is capped at capacity 2, not the 30 tokens that elapsed"
    );
}

/// H4: refill is proportional to elapsed time (60/min = 1/second:
/// exactly 3 tokens after 3 seconds from empty).
#[test]
fn token_bucket_partial_refill_is_proportional() {
    let mut bucket = TokenBucket::new(5.0, 60.0, t0());
    for _ in 0..5 {
        assert!(bucket.allow(t0()));
    }
    assert!(!bucket.allow(t0()));
    let t = t0() + Duration::seconds(3);
    assert!(bucket.allow(t));
    assert!(bucket.allow(t));
    assert!(bucket.allow(t));
    assert!(!bucket.allow(t), "only 3 tokens refilled in 3 seconds");
}

// ---------------------------------------------------------------------------
// I. Admission — default open policy through the AdmissionPolicy trait
// ---------------------------------------------------------------------------

/// INTERFACE-GUESS (whole section): contract §6/§7 pin the trait, the
/// Admission enum, and the rule — default open policy: `!registrations_open`
/// or count >= cap ⇒ not Admitted — but they do not print AdmissionCx's
/// field list, the open policy's Rust type name, or FormInput's
/// construction. The guesses below follow the contract's own words:
/// fields named `registrations_open`, `count`, `cap` (the identifiers
/// the contract itself uses in §7), the policy type named after the
/// spec's module id `rate-limited-open`, and an empty FormInput via
/// Default. If any guess differs from the real interface, these
/// constructions are what changes — the admit/not-admit expectations
/// are the contract's rule verbatim.
fn admission_cx(registrations_open: bool, count: u64, cap: u64) -> AdmissionCx {
    // CONSTRUCTION FIX (implementer, 2026-10-14; expectations unchanged —
    // listed in RETROFIT-REPORT.md): the real AdmissionCx fields are
    // username / registrations_open / account_count / account_cap, with
    // the cap an Option<u64>. The author's (count, cap) pair maps onto
    // account_count / Some(cap).
    AdmissionCx {
        username: "blind-suite-user".to_string(),
        registrations_open,
        account_count: count,
        account_cap: Some(cap),
    }
}

/// I1: open + under cap ⇒ Admitted.
#[test]
fn admission_open_policy_admits_when_open_and_under_cap() {
    let policy = OpenAdmission { open: true }; // CONSTRUCTION FIX (2026-10-14): real policy type; open=true is the guessed ::new() default
    let input = FormInput { fields: vec![] }; // CONSTRUCTION FIX (2026-10-14): FormInput has no Default; empty field list is the empty form
    let empty = policy
        .admit(&admission_cx(true, 0, 100), &input)
        .expect("admit must not error for the open policy");
    assert!(matches!(empty, Admission::Admitted), "open and empty must admit");
    let one_below = policy
        .admit(&admission_cx(true, 99, 100), &input)
        .expect("admit must not error for the open policy");
    assert!(
        matches!(one_below, Admission::Admitted),
        "open and one below the cap must admit"
    );
}

/// I2 + I3: closed, at cap, or over cap ⇒ not Admitted. (The contract's
/// rule is stated as "not Admitted"; whether the outcome is Rejected or
/// PendingApproval is not pinned for the open policy, so only
/// not-Admitted is asserted.)
#[test]
fn admission_open_policy_does_not_admit_when_closed_or_at_cap() {
    let policy = OpenAdmission { open: true }; // CONSTRUCTION FIX (2026-10-14): real policy type; open=true is the guessed ::new() default
    let input = FormInput { fields: vec![] }; // CONSTRUCTION FIX (2026-10-14): FormInput has no Default; empty field list is the empty form
    for (open, count, cap, why) in [
        (false, 0, 100, "registrations closed"),
        (true, 100, 100, "count exactly at cap"),
        (true, 150, 100, "count over cap"),
    ] {
        let outcome = policy
            .admit(&admission_cx(open, count, cap), &input)
            .expect("admit must not error for the open policy");
        assert!(
            !matches!(outcome, Admission::Admitted),
            "must not admit when {why}"
        );
    }
}

// ---------------------------------------------------------------------------
// J. Database integration (PostgreSQL)
// ---------------------------------------------------------------------------
// INTERFACE-GUESS (whole section): the task brief and contract §7 name
// app::db as the persistence surface whose function names follow the
// operations (create_account, create_session, session_by_token,
// store_recovery_code, consume_recovery_code), storing only hashes
// (§16). Exact signatures are not printed in the contract, so the calls
// below use the most direct reading:
//   create_account(pool, username_folded, password_hash, role)
//       -> Result<account_id (i64), sqlx::Error>
//   create_session(pool, account_id, raw_token) -> Result<_, sqlx::Error>
//       (the DB layer hashes; J4 verifies only the hash is stored)
//   session_by_token(pool, raw_token) -> Result<Option<Session>, sqlx::Error>
//   store_recovery_code(pool, account_id, raw_code) -> Result<_, sqlx::Error>
//       (the DB layer hashes; J5 verifies only the hash is stored)
//   consume_recovery_code(pool, username_folded, raw_code)
//       -> Result<bool, sqlx::Error>   (true = consumed)
// and Role is app::authz::Role. Where a real signature differs, these
// call sites are what changes — the storage and outcome properties
// asserted (hash-only storage, exactly-once consumption, total session
// revocation, recovery marking, no account oracle) are spec §7/§16.

/// Returns None (test returns early) when DATABASE_URL is unset, per
/// the harness contract.
async fn db_pool() -> Option<PgPool> {
    match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(
            PgPool::connect(&url)
                .await
                .expect("DATABASE_URL is set: connecting to PostgreSQL must succeed"),
        ),
        _ => None,
    }
}

fn unique_username(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("bt{}_{}_{}", std::process::id() % 100_000, n, tag);
    assert!(
        validate_username(&name),
        "test-generated username {name:?} must itself satisfy the username rules"
    );
    name
}

/// Deletes every row a DB test created, children before the account.
/// (The account primary-key column is read as `id` — cleanup only; no
/// assertion depends on it.)
async fn cleanup_account(pool: &PgPool, username: &str) {
    let _ = sqlx::query(
        "DELETE FROM sessions WHERE account_id IN (SELECT id FROM accounts WHERE username = $1)",
    )
    .bind(username)
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "DELETE FROM recovery_codes WHERE account_id IN (SELECT id FROM accounts WHERE username = $1)",
    )
    .bind(username)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM accounts WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await;
}

// CONSTRUCTION FIX (implementer, 2026-10-14; assertions unchanged —
// listed in RETROFIT-REPORT.md): the real signature is
// create_session(pool, token, csrf_secret, &Session). This adapter builds
// the Session value the author's (account_id, token) shape implied; the
// CSRF secret is a fixed fixture string (CSRF behavior is unit-tested in
// section E, not here).
async fn db_create_session(
    pool: &PgPool,
    account_id: i64,
    token: &str,
) -> Result<(), sqlx::Error> {
    let session = Session::fresh(account_id, OffsetDateTime::now_utc());
    app::db::create_session(pool, token, "blind-suite-csrf-fixture", &session).await
}

async fn make_account(pool: &PgPool, username: &str) -> i64 {
    let guard = HashGuard::new(2);
    let hash = guard
        .hash("db-test-passphrase-123")
        .await
        .expect("hashing for account creation must succeed");
    app::db::create_account(pool, username, &hash) // CONSTRUCTION FIX (2026-10-14): real create_account takes no role; new accounts default to buyer
        .await
        .expect("account creation must succeed")
}

/// J1: creation works; the exact same folded username cannot register
/// twice (§16: username unique, case-folded).
#[tokio::test]
async fn db_account_creation_and_duplicate_username_rejected() {
    let Some(pool) = db_pool().await else { return };
    let username = unique_username("dup");

    let id = make_account(&pool, &username).await;
    assert!(id > 0, "a created account gets a positive internal id");

    let guard = HashGuard::new(2);
    let hash = guard.hash("other-passphrase-456").await.expect("hash");
    let duplicate = app::db::create_account(&pool, &username, &hash).await; // CONSTRUCTION FIX (2026-10-14): see make_account
    assert!(
        duplicate.is_err(),
        "a duplicate folded username must be rejected"
    );

    cleanup_account(&pool, &username).await;
}

/// J2 + J3 + J4: session round-trip, hash-only storage.
#[tokio::test]
async fn db_session_roundtrip_stores_only_the_hash() {
    let Some(pool) = db_pool().await else { return };
    let username = unique_username("ses");
    let account_id = make_account(&pool, &username).await;

    let token = new_token();
    db_create_session(&pool, account_id, &token)
        .await
        .expect("session creation must succeed");

    // J2: the raw token finds the session again.
    let found = app::db::session_by_token(&pool, &token)
        .await
        .expect("session lookup must run")
        .expect("a session must be findable by its raw token");
    assert_eq!(found.0.account_id, account_id); // CONSTRUCTION FIX (2026-10-14): session_by_token returns (Session, csrf)
    assert!(!found.0.revoked); // CONSTRUCTION FIX (2026-10-14): tuple .0
    assert!(
        found.0.is_valid(OffsetDateTime::now_utc()), // CONSTRUCTION FIX (2026-10-14): tuple .0
        "a just-created stored session is valid now"
    );

    // J3: an unknown token finds nothing.
    let missing = app::db::session_by_token(&pool, &new_token())
        .await
        .expect("session lookup must run");
    assert!(missing.is_none(), "an unknown token must find no session");

    // J4: the stored bytes are exactly hash_token(token), never the
    // raw token (§16: sessions store token_hash only).
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM sessions WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("the session row must be readable");
    assert_eq!(stored, hash_token(&token).to_vec(), "stored token_hash must equal hash_token(token)");
    assert_ne!(stored, token.as_bytes().to_vec(), "the raw token must never be stored");

    cleanup_account(&pool, &username).await;
}

async fn assert_session_usable(pool: &PgPool, token: &str, account_id: i64) {
    match app::db::session_by_token(pool, token).await {
        Ok(Some(s)) => {
            assert_eq!(s.0.account_id, account_id); // CONSTRUCTION FIX (2026-10-14): tuple .0
            assert!(!s.0.revoked, "session must not be revoked");
            assert!(
                s.0.is_valid(OffsetDateTime::now_utc()), // CONSTRUCTION FIX (2026-10-14): tuple .0
                "session must be valid before recovery"
            );
        }
        Ok(None) => panic!("session must be findable before recovery"),
        Err(e) => panic!("session lookup failed: {e}"),
    }
}

async fn assert_session_unusable(pool: &PgPool, token: &str) {
    match app::db::session_by_token(pool, token).await {
        Ok(None) => {} // revoked sessions no longer resolve: correct
        Ok(Some(s)) => assert!(
            s.0.revoked || !s.0.is_valid(OffsetDateTime::now_utc()), // CONSTRUCTION FIX (2026-10-14): tuple .0
            "after recovery the session must be revoked or invalid"
        ),
        Err(e) => panic!("session lookup failed: {e}"),
    }
}

/// J5–J9: recovery codes — hash-only storage, exactly-once consumption,
/// total session revocation, recovery marking, and no account oracle
/// (spec §7: "Recovery restores login only, revokes all sessions, ...
/// shows 'account recovered' with the date"; contract §7: consuming
/// succeeds exactly once, revokes ALL sessions and marks the profile
/// recovered in one transaction; unknown username and wrong code give
/// the same outcome).
#[tokio::test]
async fn db_recovery_code_single_use_revokes_all_sessions_no_oracle() {
    let Some(pool) = db_pool().await else { return };
    let username = unique_username("rec");
    let account_id = make_account(&pool, &username).await;
    // CONSTRUCTION FIX (implementer, 2026-10-14; assertion unchanged):
    // db::consume_recovery_code is keyed by account id, not username —
    // the unknown-username no-oracle property is realized at the web
    // layer, which resolves the name to an id first. The ghost case
    // therefore uses an account id that was never created.
    let ghost_account_id = account_id + 1_000_000_000; // never created

    // Two live sessions for the account.
    let token1 = new_token();
    let token2 = new_token();
    db_create_session(&pool, account_id, &token1).await.expect("session 1");
    db_create_session(&pool, account_id, &token2).await.expect("session 2");
    assert_session_usable(&pool, &token1, account_id).await;
    assert_session_usable(&pool, &token2, account_id).await;

    // Store one recovery code.
    let code = new_recovery_code();
    app::db::store_recovery_code(&pool, account_id, &code)
        .await
        .expect("storing a recovery code must succeed");

    // J5: only the hash is stored.
    let stored_code_hash: Vec<u8> =
        sqlx::query_scalar("SELECT code_hash FROM recovery_codes WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("the recovery code row must be readable");
    assert_eq!(
        stored_code_hash,
        hash_code(&code).to_vec(),
        "stored code_hash must equal hash_code(code)"
    );
    assert_ne!(
        stored_code_hash,
        code.as_bytes().to_vec(),
        "the raw recovery code must never be stored"
    );

    // J6: a wrong code fails — and gives exactly the same outcome as a
    // code presented for a username that does not exist (no oracle).
    let wrong_outcome = app::db::consume_recovery_code(&pool, account_id, "wrong-code-value") // CONSTRUCTION FIX (2026-10-14): keyed by account id
        .await
        .expect("consumption attempt must run");
    assert!(!wrong_outcome, "a wrong code must not be consumed");
    let ghost_outcome = app::db::consume_recovery_code(&pool, ghost_account_id, &code) // CONSTRUCTION FIX (2026-10-14): ghost account id
        .await
        .expect("consumption attempt must run");
    assert_eq!(
        wrong_outcome, ghost_outcome,
        "wrong code and unknown username must produce the same outcome (no account oracle)"
    );
    // A failed attempt is not a recovery: sessions stay alive.
    assert_session_usable(&pool, &token1, account_id).await;
    assert_session_usable(&pool, &token2, account_id).await;

    // J7: the correct code succeeds exactly once.
    let first = app::db::consume_recovery_code(&pool, account_id, &code) // CONSTRUCTION FIX (2026-10-14): keyed by account id
        .await
        .expect("consumption must run");
    assert!(first, "the correct code must be consumed");
    let second = app::db::consume_recovery_code(&pool, account_id, &code) // CONSTRUCTION FIX (2026-10-14): keyed by account id
        .await
        .expect("consumption must run");
    assert!(!second, "the same code must not be consumable twice");

    // J8: recovery revoked ALL sessions.
    assert_session_unusable(&pool, &token1).await;
    assert_session_unusable(&pool, &token2).await;

    // J9: the account is marked recovered (§16: accounts.recovered_at).
    let recovered: Option<Option<OffsetDateTime>> =
        sqlx::query_scalar("SELECT recovered_at FROM accounts WHERE username = $1")
            .bind(&username)
            .fetch_optional(&pool)
            .await
            .expect("the account row must be readable");
    assert!(
        matches!(recovered, Some(Some(_))),
        "a successful recovery must set recovered_at"
    );

    cleanup_account(&pool, &username).await;
}
