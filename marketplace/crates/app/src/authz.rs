//! Route authorization (spec §17): every route declares its roles in ONE
//! table; a single `authorize()` enforces it; anything undeclared is denied.
//!
//! The table below is spec §17's route list verbatim (path forms as written
//! there, `{…}` segments match exactly one path segment), classified by the
//! API contract §7 semantics:
//!   Public        — spec §17's unauthenticated set: every actor allowed.
//!   Authenticated — any signed-in account; anonymous gets LoginRequired.
//!   Seller        — Seller and Admin.
//!   Moderation    — Moderator and Admin.
//!   AdminOnly     — Admin.
//! Every POST route requires CSRF; no GET route does (contract §7).
//!
//! Rows marked EXTRA are routes the web layer serves that §17's list does
//! not enumerate (account home, the seller-application flow, the
//! moderation queue pages, sanitized-media serving, profile and inbox
//! actions). They are declared here with the class of their surface so
//! the table stays complete for the running app; §17 remains the
//! authority for the routes it does list. (History: §17 originally
//! declared no GET /orders collection route, so `authorize` denied it
//! while the Stage 4 draft web layer served the page — deviation
//! recorded in RETROFIT-REPORT.md. Resolved by owner amendment
//! 2026-10-14: §17 now declares the route; see SPEC-V2-AMENDMENTS.md.)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Buyer,
    Seller,
    Moderator,
    Admin,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteRule {
    pub method: &'static str,
    pub path: &'static str,
    /// None = public route. Some(&[]) = any authenticated account.
    pub roles: Option<&'static [Role]>,
    /// State-changing routes require a CSRF token.
    pub csrf: bool,
}

const PUBLIC: Option<&[Role]> = None;
const AUTHENTICATED: Option<&[Role]> = Some(&[]);
const SELLER: Option<&[Role]> = Some(&[Role::Seller, Role::Admin]);
const MODERATION: Option<&[Role]> = Some(&[Role::Moderator, Role::Admin]);
const ADMIN_ONLY: Option<&[Role]> = Some(&[Role::Admin]);

pub const ROUTES: &[RouteRule] = &[
    // -- Public (spec §17 unauthenticated set) --
    RouteRule { method: "GET", path: "/listings", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/listings/{id}", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/sellers/{id}", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/sellers/{id}/key.asc", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/register", roles: PUBLIC, csrf: false },
    RouteRule { method: "POST", path: "/register", roles: PUBLIC, csrf: true },
    RouteRule { method: "GET", path: "/login", roles: PUBLIC, csrf: false },
    RouteRule { method: "POST", path: "/login", roles: PUBLIC, csrf: true },
    RouteRule { method: "GET", path: "/security", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/limitations", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/policy", roles: PUBLIC, csrf: false },
    // -- Authenticated, any role (§17 signed-in surfaces; contract §7) --
    RouteRule { method: "POST", path: "/logout", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "GET", path: "/inbox", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/account/security", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/account/keys", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/keys/rotate", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/sessions/{id}/revoke", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/recovery-codes", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders", roles: AUTHENTICATED, csrf: true },
    // §17 as amended by owner ruling 2026-10-14 (SPEC-V2-AMENDMENTS.md):
    // the orders collection route is declared — any authenticated
    // account; the handler filters to the caller's own orders.
    RouteRule { method: "GET", path: "/orders", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/orders/{id}", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/orders/{id}/terms.txt", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/orders/{id}/accept", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/decline", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/cancel", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/fulfil", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/complete", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/dispute", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/invoice", roles: AUTHENTICATED, csrf: true },
    // Direct Payments v1 (2026-10-15): buyer payment page + QR are
    // participant-only at the object level (non-participants get 404);
    // mark-paid is seller-only at the object level.
    RouteRule { method: "GET", path: "/orders/{id}/pay", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/orders/{id}/pay/qr.png", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/orders/{id}/mark-paid", roles: AUTHENTICATED, csrf: true },
    // Tx-proof flow (2026-10-18): buyer proof submission + manual
    // report; seller per-order confirmation + not-received declaration.
    RouteRule { method: "POST", path: "/orders/{id}/submit-proof", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/manual-report", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/confirm-payment", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/declare-not-received", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "GET", path: "/invoices/{id}", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/invoices/{id}/qr.png", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/invoices/{id}/statement.txt", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/invoices/{id}/statement.txt.asc", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/invoices/{id}/signature", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/invoices/{id}/evidence/{module}", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "GET", path: "/pools/{id}/statement.txt", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/pools/{id}/statement.txt.asc", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/conversations/{id}", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/conversations/{id}/messages", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "GET", path: "/messages/{id}/download", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/disputes/{id}", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "POST", path: "/disputes/{id}/disclosures", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/reports", roles: AUTHENTICATED, csrf: true },
    // -- Seller surfaces --
    RouteRule { method: "GET", path: "/seller", roles: SELLER, csrf: false },
    RouteRule { method: "POST", path: "/seller/listings", roles: SELLER, csrf: true },
    RouteRule { method: "GET", path: "/seller/pools", roles: SELLER, csrf: false },
    RouteRule { method: "POST", path: "/seller/pools", roles: SELLER, csrf: true },
    RouteRule { method: "POST", path: "/seller/pools/{id}/signature", roles: SELLER, csrf: true },
    // Direct Payments v1 (2026-10-15): payment identity + batch upload
    // live on the seller dashboard surface.
    RouteRule { method: "POST", path: "/seller/payment-identity", roles: SELLER, csrf: true },
    RouteRule { method: "POST", path: "/seller/payment-batches", roles: SELLER, csrf: true },
    // -- Moderation surfaces --
    RouteRule { method: "GET", path: "/moderation", roles: MODERATION, csrf: false },
    RouteRule { method: "POST", path: "/disputes/{id}/resolve", roles: MODERATION, csrf: true },
    // -- Admin only (contract §7; amendments: admin on a separate listener) --
    RouteRule { method: "GET", path: "/admin", roles: ADMIN_ONLY, csrf: false },
    // -- EXTRA rows: served by the web layer, not enumerated in §17 --
    RouteRule { method: "GET", path: "/", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/account", roles: AUTHENTICATED, csrf: false },
    RouteRule { method: "GET", path: "/account/recover", roles: PUBLIC, csrf: false },
    RouteRule { method: "POST", path: "/account/recover", roles: PUBLIC, csrf: true },
    RouteRule { method: "POST", path: "/account/profile", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/seller/apply", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/seller/listings/{id}/status", roles: SELLER, csrf: true },
    RouteRule { method: "POST", path: "/seller/listings/{id}/media", roles: SELLER, csrf: true },
    RouteRule { method: "GET", path: "/media/{ref}", roles: PUBLIC, csrf: false },
    RouteRule { method: "GET", path: "/moderation/sellers", roles: MODERATION, csrf: false },
    RouteRule { method: "POST", path: "/moderation/sellers/{id}", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/inbox/read-all", roles: AUTHENTICATED, csrf: true },
    // -- Stage 9: reviews, disputes, moderation, closure --
    RouteRule { method: "POST", path: "/orders/{id}/review", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/orders/{id}/review/reply", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/disputes/{id}/confirm-refund", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "GET", path: "/moderation/accounts", roles: MODERATION, csrf: false },
    RouteRule { method: "POST", path: "/moderation/reports/{id}", roles: MODERATION, csrf: true },
    RouteRule { method: "GET", path: "/moderation/flags/{id}", roles: MODERATION, csrf: false },
    RouteRule { method: "POST", path: "/moderation/flags/{id}", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/moderation/accounts/{id}/warn", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/moderation/accounts/{id}/close", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/moderation/listings/{id}/remove", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/moderation/listings/{id}/restore", roles: MODERATION, csrf: true },
    RouteRule { method: "POST", path: "/account/totp/begin", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/totp/confirm", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/totp/disable", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/account/close", roles: AUTHENTICATED, csrf: true },
    // Account Security Audit (2026-10-18): passphrase change (task 8;
    // POST /account/recovery-codes above was declared by §17 all
    // along and is now actually served) and the moderator disclosure
    // unlock (task 3; Moderation, like the other dispute actions).
    RouteRule { method: "POST", path: "/account/passphrase", roles: AUTHENTICATED, csrf: true },
    RouteRule { method: "POST", path: "/disputes/{id}/unlock", roles: MODERATION, csrf: true },
];

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Authenticated route hit without a session.
    LoginRequired,
}

/// Segment-wise path match: a `{…}` segment in either the declared
/// pattern or the presented path matches any single non-empty segment,
/// so callers may pass §17's path forms verbatim or concrete paths.
fn path_matches(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let a: Vec<&str> = path.split('/').collect();
    p.len() == a.len()
        && p.iter().zip(a.iter()).all(|(x, y)| {
            x == y
                || (x.starts_with('{') && x.ends_with('}') && !y.is_empty())
                || (y.starts_with('{') && y.ends_with('}') && !x.is_empty())
        })
}

fn find_rule(method: &str, path: &str) -> Option<&'static RouteRule> {
    ROUTES
        .iter()
        .find(|r| r.method == method && path_matches(r.path, path))
}

pub fn authorize(method: &str, path: &str, role: Option<Role>) -> Decision {
    let Some(rule) = find_rule(method, path) else {
        return Decision::Deny; // default-deny: undeclared route
    };
    match rule.roles {
        None => Decision::Allow,
        Some(allowed) => match role {
            None => Decision::LoginRequired,
            Some(r) => {
                if allowed.is_empty() || allowed.contains(&r) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        },
    }
}

pub fn route_requires_csrf(method: &str, path: &str) -> bool {
    find_rule(method, path).map(|r| r.csrf).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix() {
        assert_eq!(authorize("GET", "/", None), Decision::Allow);
        assert_eq!(authorize("GET", "/listings/{id}", None), Decision::Allow);
        assert_eq!(authorize("GET", "/account", None), Decision::LoginRequired);
        assert_eq!(authorize("GET", "/account", Some(Role::Buyer)), Decision::Allow);
        assert_eq!(authorize("GET", "/seller", Some(Role::Buyer)), Decision::Deny);
        assert_eq!(authorize("GET", "/seller", Some(Role::Seller)), Decision::Allow);
        assert_eq!(authorize("GET", "/moderation", Some(Role::Seller)), Decision::Deny);
        assert_eq!(authorize("GET", "/moderation", Some(Role::Moderator)), Decision::Allow);
        assert_eq!(authorize("GET", "/admin", Some(Role::Moderator)), Decision::Deny);
        assert_eq!(authorize("GET", "/admin", Some(Role::Admin)), Decision::Allow);
        // §17 as amended 2026-10-14 declares GET /orders (any
        // authenticated account; anonymous gets LoginRequired).
        assert_eq!(authorize("GET", "/orders", Some(Role::Admin)), Decision::Allow);
        assert_eq!(authorize("GET", "/orders", Some(Role::Buyer)), Decision::Allow);
        assert_eq!(authorize("GET", "/orders", None), Decision::LoginRequired);
        assert_eq!(authorize("GET", "/orders/{id}", Some(Role::Buyer)), Decision::Allow);
        // Concrete paths match parameterized declarations.
        assert_eq!(authorize("GET", "/orders/ord_0123456789abcdef0123456789abcdef", Some(Role::Buyer)), Decision::Allow);
        // A caller may also present the parameterized form itself (the
        // web layer's router pattern "/orders/{id}/{action}"): the
        // path-side placeholder must match a literal action segment in
        // the table. (Retrofit addition, 2026-10-14: a cargo-mutants run
        // found this arm of path_matches untested.)
        assert_eq!(authorize("POST", "/orders/{id}/{action}", Some(Role::Buyer)), Decision::Allow);
        assert_eq!(authorize("POST", "/orders/{id}/{action}", None), Decision::LoginRequired);
        assert_eq!(authorize("POST", "/orders/{id}/{action}", Some(Role::Admin)), Decision::Allow);
        assert_eq!(authorize("DELETE", "/account", Some(Role::Admin)), Decision::Deny);
        assert_eq!(authorize("GET", "/nope", Some(Role::Admin)), Decision::Deny);
        assert!(route_requires_csrf("POST", "/login"));
        assert!(route_requires_csrf("POST", "/account/sessions/{id}/revoke"));
        assert!(!route_requires_csrf("GET", "/login"));
    }
}
