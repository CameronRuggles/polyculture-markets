//! HTTP layer (Stage 1): register / login / logout / account / recover.
//! No JavaScript anywhere; forms are plain POSTs. Public POSTs use a
//! double-submit CSRF cookie; authenticated POSTs use the per-session
//! CSRF secret (§3.14 family: synchronizer tokens + SameSite cookies).

use crate::admission::OpenAdmission;
use crate::authz::{authorize, Decision, Role};
use crate::passwords::{HashError, HashGuard};
use crate::{db, recovery, sessions, usernames};
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use modules_api::{Admission, AdmissionPolicy};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hash_guard: HashGuard,
    pub throttles: Arc<crate::throttle::Throttles>,
    pub registrations_open: bool,
    pub account_cap: Option<u64>,
    /// true in the onion/plain-HTTP dev profile (cookie name `session`),
    /// false in production HTTPS (`__Host-session`, Secure attribute).
    pub dev_cookies: bool,
    pub media: crate::media::MediaPipeline,
    pub marketplace_id: String,
    /// Direct Payments v1 settings (config, not constants).
    pub payments: crate::payments::PaymentConfig,
    /// Stage 9: the marketplace key file (buyer tokens; encryption of
    /// TOTP secrets and disclosed evidence at rest).
    pub keyfile: std::sync::Arc<crate::keyfile::KeyFile>,
    /// Stage 9: reputation / reviews / disputes configuration.
    pub stage9: crate::reputation::Stage9Config,
    /// Stage 10: resolved instance configuration (profile, network,
    /// site identity) — the single source every page and the shell
    /// read from (config.rs).
    pub instance: crate::config::InstanceConfig,
    /// Stage 10: retention periods (shown on the Limitations page).
    pub retention: crate::retention::RetentionConfig,
}

impl AppState {
    fn cookie_name(&self) -> &'static str {
        if self.dev_cookies { "session" } else { "__Host-session" }
    }
    fn set_cookie(&self, token: &str) -> String {
        let secure = if self.dev_cookies { "" } else { "; Secure" };
        format!(
            "{}={token}; Path=/; HttpOnly; SameSite=Strict{secure}",
            self.cookie_name()
        )
    }
    fn anon_csrf_cookie(&self, value: &str) -> String {
        let secure = if self.dev_cookies { "" } else { "; Secure" };
        format!("csrf={value}; Path=/; SameSite=Strict{secure}")
    }

    /// Account Security Audit task 5 (AM2 follow-through): the
    /// per-account request throttle (`Throttles::allow_request`,
    /// previously dead code) is wired into every signed-in POST.
    /// Returns the 429 response when this account's burst budget is
    /// spent; handlers call this immediately after the session is
    /// established, before any other work.
    fn throttle_or_429(&self, account_id: i64) -> Option<Response> {
        if self.throttles.allow_request(account_id, OffsetDateTime::now_utc()) {
            None
        } else {
            Some((StatusCode::TOO_MANY_REQUESTS, "Too many requests — slow down and retry shortly.").into_response())
        }
    }
}

/// Account Security Audit task 2 (AM3; also discharges payment-audit
/// M1): the step-up for identity-changing actions. A session alone is
/// never enough: the caller must re-prove the CURRENT PASSPHRASE,
/// plus a current TOTP code when the account is enrolled. Hashing
/// goes through the per-account scope so step-up attempts cannot
/// starve the login gate. On success the caller performs the action
/// and records an inbox notice (see `stepup_notice`).
async fn step_up(
    st: &AppState,
    sess: &sessions::Session,
    password: &str,
    totp_code: Option<&str>,
) -> Result<(), String> {
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    let Some(stored) = stored else {
        return Err("Step-up verification failed.".into());
    };
    let scope = format!("acct:{}", sess.account_id);
    match st.hash_guard.verify_scoped(&scope, password, &stored).await {
        Ok(true) => {}
        Ok(false) => return Err("Step-up verification failed: the passphrase did not verify.".into()),
        Err(HashError::Busy) => return Err("Step-up verification failed: busy, retry shortly.".into()),
        Err(_) => return Err("Step-up verification failed.".into()),
    }
    if crate::moderation::totp_enrolled(&st.pool, sess.account_id).await.unwrap_or(false) {
        let Some(code) = totp_code.filter(|c| !c.trim().is_empty()) else {
            return Err("Step-up verification failed: a TOTP code is required for this account.".into());
        };
        if let Err(e) = crate::moderation::verify_totp_gate(&st.pool, &st.keyfile, sess.account_id, code).await {
            return Err(format!("Step-up verification failed: TOTP code refused ({e:?})."));
        }
    }
    Ok(())
}

/// The inbox notice an identity-changing action leaves behind (task
/// 2): if a session was stolen, the owner sees exactly what changed.
async fn stepup_notice(st: &AppState, account_id: i64, event_type: &str, what: &str) {
    let _ = crate::orders::notify(&st.pool, account_id, event_type, what).await;
}

// -- Stage 10: the shared page shell (§15) ----------------------------------
//
// Every HTML page this server renders goes through `shell`: one
// doctype, one <head>, ONE inline <style> block, the §15 header
// (site name; Browse, Orders (n), Messages (n), Sell, Security;
// account menu), <main>, and the §15 footer (Policy, Limitations,
// Payment risks, Source, Version, Help). No JavaScript, no external
// assets, no web fonts — the CSS below is the only styling, and it
// follows §15: neutral background, high-contrast text, one accent
// colour, system fonts, no animations, visible keyboard focus,
// responsive layout.

/// Escape a value interpolated into the hand-built shell (template
/// bodies are already escaped by Askama at the variable level; the
/// shell's own values — title, site name, username — are not).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// What the header needs. Built per request by `nav_for` (counts are
/// computed server-side on every request, §15); `Nav::anonymous` is
/// for pages rendered without a session or a request context.
#[derive(Clone)]
pub struct Nav {
    pub site_name: String,
    pub version: &'static str,
    pub network_name: &'static str,
    pub source_url: Option<String>,
    pub username: Option<String>,
    /// The viewer's role, when a session resolved one. The shell uses
    /// it for role-gated nav entries (Moderation); counts and identity
    /// above stay role-blind.
    pub role: Option<Role>,
    pub csrf: Option<String>,
    /// Orders where it is the viewer's move (permitted_actions
    /// obligation states: seller — Requested/Paid; buyer — Fulfilled).
    pub orders_attention: i64,
    /// Unread inbox notifications (all types).
    pub inbox_unread: i64,
    /// Unread message notifications (event_type = message_received).
    pub messages_unread: i64,
}

impl Nav {
    pub fn anonymous(cfg: &crate::config::InstanceConfig) -> Nav {
        Nav {
            site_name: cfg.site_name.clone(),
            version: cfg.version,
            network_name: cfg.network_name(),
            source_url: cfg.source_url.clone(),
            username: None,
            role: None,
            csrf: None,
            orders_attention: 0,
            inbox_unread: 0,
            messages_unread: 0,
        }
    }
}

const SHELL_CSS: &str = "\
:root{color-scheme:light}\
*{box-sizing:border-box}\
body{margin:0;background:#f5f2ec;color:#1c1a17;font-family:system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;line-height:1.5}\
.wrap{max-width:62rem;margin:0 auto;padding:0 1rem 2rem}\
header.site{border-bottom:2px solid #8a5a00;margin-bottom:1.25rem;padding:.75rem 0 .5rem}\
header.site .brand{font-size:1.35rem;font-weight:700;color:#1c1a17;text-decoration:none}\
header.site .net{color:#5c564c;font-size:.85rem;margin-left:.5rem}\
nav.main{display:flex;flex-wrap:wrap;gap:.25rem 1rem;margin-top:.4rem;align-items:center}\
nav.main a{color:#7a5200;text-decoration:none;font-weight:600}\
nav.main a:hover{text-decoration:underline}\
nav.main .acct{margin-left:auto;display:flex;gap:.25rem 1rem;align-items:center;flex-wrap:wrap}\
nav.main form{display:inline;margin:0}\
main{display:block}\
h1{font-size:1.6rem;line-height:1.25;margin:.4rem 0 .8rem}\
h2{font-size:1.2rem;margin:1.4rem 0 .5rem;border-bottom:1px solid #d8d2c4;padding-bottom:.2rem}\
h3{font-size:1.05rem;margin:1.1rem 0 .4rem}\
a{color:#7a5200}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em;overflow-wrap:anywhere}\
pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#fffdf8;border:1px solid #d8d2c4;padding:.6rem;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}\
article{background:#fffdf8;border:1px solid #d8d2c4;border-radius:.4rem;padding:.8rem 1rem;margin:.8rem 0}\
label{display:block;margin:.55rem 0;font-weight:600}\
label input,label select,label textarea{margin-top:.2rem}\
input,select,textarea{font:inherit;color:inherit;background:#fffdf8;border:1px solid #8d8574;border-radius:.3rem;padding:.45rem .55rem;max-width:100%}\
input[type=text],input[type=password],input[type=number],select,textarea{width:34rem;max-width:100%}\
textarea{width:40rem;max-width:100%}\
input[type=checkbox]{width:auto}\
button{font:inherit;font-weight:700;background:#7a5200;color:#fff;border:1px solid #7a5200;border-radius:.3rem;padding:.45rem .9rem;cursor:pointer;margin:.3rem .3rem .3rem 0}\
button:hover{background:#66450a}\
:focus{outline:3px solid #b36b00;outline-offset:2px}\
[role=alert]{border:1px solid #a33327;background:#fbeeec;border-radius:.4rem;padding:.6rem .8rem}\
[role=status]{border:1px solid #8a5a00;background:#fdf6e0;border-radius:.4rem;padding:.6rem .8rem}\
.badge{font-weight:700}\
footer.site{border-top:1px solid #d8d2c4;margin-top:2rem;padding-top:.7rem;color:#5c564c;font-size:.9rem}\
footer.site nav{display:flex;flex-wrap:wrap;gap:.25rem 1rem}\
footer.site a{color:#7a5200}\
img{max-width:100%;height:auto}\
table{border-collapse:collapse}td,th{border:1px solid #d8d2c4;padding:.3rem .6rem;text-align:left}\
@media (max-width:40rem){nav.main .acct{margin-left:0}h1{font-size:1.35rem}}";

fn count_badge(n: i64) -> String {
    if n > 0 {
        format!(" <span class=\"badge\">({n})</span>")
    } else {
        String::new()
    }
}

/// Render the full HTML document for a page body fragment. `title`
/// is plain text (escaped here); `body` is template output whose own
/// variables Askama already escaped.
pub fn shell(nav: &Nav, title: &str, body: &str) -> String {
    let mut nav_html = String::new();
    nav_html.push_str("<a href=\"/listings\">Browse</a>");
    if nav.username.is_some() {
        nav_html.push_str(&format!(
            "<a href=\"/orders\">Orders{}</a>",
            count_badge(nav.orders_attention)
        ));
        nav_html.push_str(&format!(
            "<a href=\"/conversations\">Messages{}</a>",
            count_badge(nav.messages_unread)
        ));
        nav_html.push_str("<a href=\"/seller\">Sell</a>");
        nav_html.push_str("<a href=\"/account/security\">Security</a>");
        if matches!(nav.role, Some(Role::Admin) | Some(Role::Moderator)) {
            nav_html.push_str("<a href=\"/moderation\">Moderation</a>");
        }
        nav_html.push_str("<span class=\"acct\">");
        nav_html.push_str(&format!(
            "<a href=\"/inbox\">Inbox{}</a>",
            count_badge(nav.inbox_unread)
        ));
        nav_html.push_str(&format!(
            "<a href=\"/account\">{}</a>",
            esc(nav.username.as_deref().unwrap_or_default())
        ));
        if let Some(csrf) = &nav.csrf {
            nav_html.push_str(&format!(
                "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">Log out</button></form>",
                esc(csrf)
            ));
        }
        nav_html.push_str("</span>");
    } else {
        nav_html.push_str("<span class=\"acct\"><a href=\"/login\">Log in</a><a href=\"/register\">Register</a></span>");
    }
    let source_link = match &nav.source_url {
        Some(u) => format!("<a href=\"{}\">Source</a>", esc(u)),
        None => "<a href=\"/source\">Source</a>".to_string(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title} · {site}</title><style>{css}</style></head>\
<body><div class=\"wrap\">\
<header class=\"site\"><a class=\"brand\" href=\"/\">{site}</a><span class=\"net\">{network}</span>\
<nav class=\"main\">{nav}</nav></header>\
<main>{body}</main>\
<footer class=\"site\"><nav>\
<a href=\"/policy\">Policy</a><a href=\"/limitations\">Limitations</a>\
<a href=\"/payment-risks\">Payment risks</a>{source_link}\
<a href=\"/help\">Help</a></nav>\
<p>Version {version} · Network: {network} · No JavaScript, no trackers, no external requests — every page is rendered by this server.</p>\
</footer></div></body></html>",
        title = esc(title),
        site = esc(&nav.site_name),
        network = esc(nav.network_name),
        css = SHELL_CSS,
        nav = nav_html,
        source_link = source_link,
        version = nav.version,
        body = body,
    )
}

/// Compute the §15 attention counts into a nav for account `me`.
async fn fill_counts(st: &AppState, nav: &mut Nav, me: i64) {
    nav.inbox_unread = sqlx::query_scalar(
        "SELECT count(*) FROM notifications WHERE account_id = $1 AND read_at IS NULL",
    )
    .bind(me)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);
    nav.messages_unread = sqlx::query_scalar(
        "SELECT count(*) FROM notifications WHERE account_id = $1 AND read_at IS NULL \
         AND event_type = 'message_received'",
    )
    .bind(me)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);
    nav.orders_attention = sqlx::query_scalar(
        "SELECT count(*) FROM orders WHERE \
         (seller_id = $1 AND state IN ('Requested', 'Paid')) \
         OR (buyer_id = $1 AND state = 'Fulfilled')",
    )
    .bind(me)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);
}

/// Build the nav for the current request: resolves the session and,
/// when logged in, computes the §15 attention counts.
async fn nav_for(st: &AppState, headers: &HeaderMap) -> Nav {
    let mut nav = Nav::anonymous(&st.instance);
    if let Some((_token, sess, csrf)) = current_session(st, headers).await {
        nav.username = Some(db::username_of_id(&st.pool, sess.account_id).await);
        nav.role = Some(session_role(st, sess.account_id).await);
        nav.csrf = Some(csrf);
        fill_counts(st, &mut nav, sess.account_id).await;
    }
    nav
}

/// The account's role as the authz enum, defaulting to Buyer when the
/// row carries nothing the table knows (same rule the guards use).
async fn session_role(st: &AppState, account_id: i64) -> Role {
    let role_s = db::role_of(&st.pool, account_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "buyer".into());
    role_from_str(&role_s)
}

/// Nav for handlers that already hold a resolved session (render
/// helpers below the handler layer).
async fn nav_for_session(st: &AppState, sess: &sessions::Session, csrf: &str) -> Nav {
    let mut nav = Nav::anonymous(&st.instance);
    nav.username = Some(db::username_of_id(&st.pool, sess.account_id).await);
    nav.role = Some(session_role(st, sess.account_id).await);
    nav.csrf = Some(csrf.to_string());
    fill_counts(st, &mut nav, sess.account_id).await;
    nav
}

/// Render a template fragment into a full shelled page response.
async fn page(st: &AppState, headers: &HeaderMap, title: &str, body: String) -> Response {
    let nav = nav_for(st, headers).await;
    Html(shell(&nav, title, &body)).into_response()
}

/// Shelled page with an explicit nav (handlers that already hold a
/// session-derived context, and notice pages).
fn page_with(nav: &Nav, title: &str, body: String) -> Response {
    Html(shell(nav, title, &body)).into_response()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home_page))
        .route("/limitations", get(limitations_page))
        .route("/policy", get(policy_page))
        .route("/payment-risks", get(payment_risks_page))
        .route("/security-guide", get(security_guide_page))
        .route("/help", get(help_page))
        .route("/source", get(source_page))
        .route("/register", get(register_form).post(register))
        .route("/login", get(login_form).post(login))
        .route("/logout", post(logout))
        .route("/account", get(account_page))
        .route("/account/recover", get(recover_form).post(recover))
        .route("/listings", get(catalogue))
        .route("/listings/{id}", get(listing_page))
        .route("/seller", get(seller_page))
        .route("/seller/apply", post(seller_apply))
        .route("/seller/listings", post(create_listing))
        .route("/seller/listings/{id}/status", post(listing_status))
        .route("/seller/listings/{id}/media", post(listing_media))
        .route("/media/{r#ref}", get(media_serve))
        .route("/moderation/sellers", get(moderation_sellers))
        .route("/moderation/sellers/{id}", post(moderation_decide))
        .route("/account/security", get(security_page))
        .route("/account/keys", post(upload_key))
        .route("/account/keys/rotate", post(rotate_key))
        .route("/account/profile", post(update_profile))
        .route("/account/sessions/{id}/revoke", post(revoke_session))
        .route("/sellers/{id}", get(seller_profile))
        .route("/sellers/{id}/key.asc", get(seller_key_download))
        .route("/orders", get(orders_page).post(create_order_handler))
        .route("/orders/{id}", get(order_page))
        .route("/orders/{id}/terms.txt", get(terms_download))
        .route("/orders/{id}/pay", get(pay_page))
        .route("/orders/{id}/pay/qr.png", get(pay_qr))
        .route("/orders/{id}/{action}", post(order_action))
        .route("/seller/payment-identity", post(payment_identity_post))
        .route("/seller/payment-batches", post(payment_batch_post))
        .route("/inbox", get(inbox_page))
        .route("/inbox/read-all", post(inbox_read_all))
        .route("/conversations", get(conversations_page))
        .route("/conversations/{id}", get(conversation_page))
        .route("/conversations/{id}/messages", post(send_message_handler))
        .route("/conversations/{id}/messages/file", post(send_message_file_handler))
        .route("/conversations/{id}/messages/{mid}/download", get(message_download))
        .route("/conversations/for-order/{oid}", post(conversation_for_order))
        .route("/conversations/direct/{aid}", post(conversation_direct))
        // Stage 9: reviews, disputes, reports, moderation, TOTP, closure.
        .route("/orders/{id}/review", post(review_submit))
        .route("/orders/{id}/review/reply", post(review_reply))
        .route("/disputes/{id}", get(dispute_page))
        .route("/disputes/{id}/unlock", post(dispute_unlock))
        .route("/disputes/{id}/disclosures", post(disclosure_submit))
        .route("/disputes/{id}/resolve", post(dispute_resolve))
        .route("/disputes/{id}/confirm-refund", post(dispute_confirm_refund))
        .route("/reports", post(report_create))
        .route("/moderation", get(moderation_queue))
        .route("/moderation/accounts", get(moderation_queue))
        .route("/moderation/reports/{id}", post(report_decide))
        .route("/moderation/flags/{id}", get(flag_page).post(flag_decide))
        .route("/moderation/accounts/{id}/warn", post(account_warn))
        .route("/moderation/accounts/{id}/close", post(account_close_mod))
        .route("/moderation/listings/{id}/remove", post(listing_remove))
        .route("/moderation/listings/{id}/restore", post(listing_restore))
        .route("/account/totp/begin", post(totp_begin_h))
        .route("/account/totp/confirm", post(totp_confirm_h))
        .route("/account/totp/disable", post(totp_disable_h))
        .route("/account/passphrase", post(passphrase_change))
        .route("/account/recovery-codes", post(recovery_code_issue))
        .route("/account/close", post(account_close_self))
        // Admin landing (contract §7 declares GET /admin ADMIN_ONLY;
        // the handler enforces the table and keeps the identical 404
        // for everyone else).
        .route("/admin", get(admin_page))
        .with_state(state)
}

// -- helpers -----------------------------------------------------------------

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

async fn current_session(
    st: &AppState,
    headers: &HeaderMap,
) -> Option<(String, sessions::Session, String)> {
    let token = cookie_value(headers, st.cookie_name())?;
    let (sess, csrf) = db::session_by_token(&st.pool, &token).await.ok()??;
    let now = OffsetDateTime::now_utc();
    if !sess.is_valid(now) {
        return None;
    }
    let _ = db::touch_session(&st.pool, &token, now).await;
    Some((token, sess, csrf))
}

fn role_from_str(s: &str) -> Role {
    match s {
        "seller" => Role::Seller,
        "moderator" => Role::Moderator,
        "admin" => Role::Admin,
        _ => Role::Buyer,
    }
}

// -- Stage 10: home + the §15 public pages -----------------------------------

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTpl {
    site_name: String,
    network_name: String,
    registrations_open: bool,
}

async fn home_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let tpl = HomeTpl {
        site_name: st.instance.site_name.clone(),
        network_name: st.instance.network_name().to_string(),
        registrations_open: st.instance.registrations_open,
    };
    let title = st.instance.site_name.clone();
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "limitations.html")]
struct LimitationsTpl {
    profile: String,
    network_name: String,
    marketplace_id: String,
    version: String,
    registrations_open: bool,
    notifications_read_days: i64,
    sessions_expired_days: i64,
    security_events_days: i64,
    disclosures_resolved_days: i64,
}

async fn limitations_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // §15/§20: the Limitations page shows THIS instance's actual
    // values — profile, network, and the retention periods the
    // running configuration will really apply.
    let tpl = LimitationsTpl {
        profile: st.instance.profile.as_str().to_string(),
        network_name: st.instance.network_name().to_string(),
        marketplace_id: st.instance.marketplace_id.clone(),
        version: st.instance.version.to_string(),
        registrations_open: st.instance.registrations_open,
        notifications_read_days: st.retention.notifications_read_days,
        sessions_expired_days: st.retention.sessions_expired_days,
        security_events_days: st.retention.security_events_days,
        disclosures_resolved_days: st.retention.disclosures_resolved_days,
    };
    page(&st, &headers, "Limitations", tpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "policy.html")]
struct PolicyTpl;

async fn policy_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    page(&st, &headers, "Policy", PolicyTpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "payment_risks.html")]
struct PaymentRisksTpl;

async fn payment_risks_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    page(&st, &headers, "Payment risks", PaymentRisksTpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "security_guide.html")]
struct SecurityGuideTpl;

async fn security_guide_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    page(&st, &headers, "Security guide", SecurityGuideTpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "help.html")]
struct HelpTpl;

async fn help_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    page(&st, &headers, "Help", HelpTpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "source.html")]
struct SourceTpl {
    source_url: Option<String>,
    version: String,
    marketplace_id: String,
}

async fn source_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let tpl = SourceTpl {
        source_url: st.instance.source_url.clone(),
        version: st.instance.version.to_string(),
        marketplace_id: st.instance.marketplace_id.clone(),
    };
    page(&st, &headers, "Source code", tpl.render().unwrap()).await
}

// -- templates ---------------------------------------------------------------

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTpl {
    error: Option<String>,
    csrf: String,
}
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl {
    error: Option<String>,
    csrf: String,
}
#[derive(Template)]
#[template(path = "account.html")]
struct AccountTpl {
    username: String,
    role: String,
    recovery_code: Option<String>,
    csrf: String,
    /// Stage 9: moderator warning visibility + closure state.
    warned_date: Option<String>,
    account_closed: bool,
}
#[derive(Template)]
#[template(path = "recover.html")]
struct RecoverTpl {
    error: Option<String>,
    csrf: String,
}

// -- handlers ----------------------------------------------------------------

async fn register_form(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let csrf = sessions::new_csrf_secret();
    let tpl = RegisterTpl { error: None, csrf: csrf.clone() };
    let nav = nav_for(&st, &headers).await;
    (
        [(header::SET_COOKIE, st.anon_csrf_cookie(&csrf))],
        Html(shell(&nav, "Register", &tpl.render().unwrap())),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    csrf: String,
}

async fn register(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RegisterForm>,
) -> Response {
    if cookie_value(&headers, "csrf").as_deref() != Some(f.csrf.as_str()) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let folded = usernames::fold_username(&f.username);
    if !usernames::validate_username(&folded) || f.password.len() < 12 || crate::passwords::is_common_password(&f.password) {
        let tpl = RegisterTpl {
            error: Some("Username must be 3–24 chars (a–z, 0–9, _ or -); passphrase at least 12 chars and not a common one.".into()),
            csrf: f.csrf.clone(),
        };
        return page(&st, &headers, "Register", tpl.render().unwrap()).await;
    }
    // Admission (default module): flag + global cap, decided by the module.
    let count = db::count_accounts(&st.pool).await.unwrap_or(0);
    let module = OpenAdmission { open: st.registrations_open };
    let cx = modules_api::AdmissionCx {
        username: folded.clone(),
        registrations_open: st.registrations_open,
        account_count: count as u64,
        account_cap: st.account_cap,
    };
    match module.admit(&cx, &modules_api::FormInput { fields: vec![] }) {
        Ok(Admission::Admitted) => {}
        _ => return (StatusCode::FORBIDDEN, "Registration is not open").into_response(),
    }
    let hash = match st.hash_guard.hash(&f.password).await {
        Ok(h) => h,
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy, retry shortly").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    };
    let id = match db::create_account(&st.pool, &folded, &hash).await {
        Ok(id) => id,
        Err(_) => {
            let tpl = RegisterTpl {
                error: Some("That username is taken.".into()),
                csrf: f.csrf.clone(),
            };
            return page(&st, &headers, "Register", tpl.render().unwrap()).await;
        }
    };
    let code = recovery::new_recovery_code();
    let _ = db::store_recovery_code(&st.pool, id, &code).await;
    // Log the new account in (session rotation on privilege change = fresh token).
    let token = sessions::new_token();
    let csrf_secret = sessions::new_csrf_secret();
    let sess = sessions::Session::fresh(id, OffsetDateTime::now_utc());
    if db::create_session(&st.pool, &token, &csrf_secret, &sess).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    }
    let role = db::role_of(&st.pool, id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    let mut nav = Nav::anonymous(&st.instance);
    nav.username = Some(folded.clone());
    nav.csrf = Some(csrf_secret.clone());
    let tpl = AccountTpl {
        username: folded,
        role,
        recovery_code: Some(code),
        csrf: csrf_secret,
        warned_date: None,
        account_closed: false,
    };
    (
        [(header::SET_COOKIE, st.set_cookie(&token))],
        Html(shell(&nav, "Account", &tpl.render().unwrap())),
    )
        .into_response()
}

async fn login_form(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let csrf = sessions::new_csrf_secret();
    let tpl = LoginTpl { error: None, csrf: csrf.clone() };
    let nav = nav_for(&st, &headers).await;
    (
        [(header::SET_COOKIE, st.anon_csrf_cookie(&csrf))],
        Html(shell(&nav, "Log in", &tpl.render().unwrap())),
    )
        .into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    /// Account Security Audit task 1 (AH1/AM1): the TOTP code,
    /// required at login for any account with TOTP enrolled.
    totp: Option<String>,
    csrf: String,
}

async fn login(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<LoginForm>) -> Response {
    if cookie_value(&headers, "csrf").as_deref() != Some(f.csrf.as_str()) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let folded = usernames::fold_username(&f.username);
    let fail = |st: &AppState| {
        let d = st.throttles.record_login_failure(&folded);
        (d, LoginTpl {
            error: Some("Invalid username or passphrase.".into()),
            csrf: f.csrf.clone(),
        })
    };
    // AM1: the per-username attempt budget is checked BEFORE any
    // hashing. A budget-exhausted name gets the generic error with no
    // hash work and no extra delay recorded (the window ages out on
    // its own); other usernames are unaffected.
    if st.throttles.login_budget_exceeded(&folded) {
        let tpl = LoginTpl {
            error: Some("Invalid username or passphrase.".into()),
            csrf: f.csrf.clone(),
        };
        return page(&st, &headers, "Log in", tpl.render().unwrap()).await;
    }
    let row = db::account_by_username(&st.pool, &folded).await.ok().flatten();
    let Some((id, stored, _role)) = row else {
        let (d, tpl) = fail(&st);
        tokio::time::sleep(std::time::Duration::from_secs(d.whole_seconds().min(5) as u64)).await;
        return page(&st, &headers, "Log in", tpl.render().unwrap()).await;
    };
    // AM2: verification is serialized per username — parallel guesses
    // against one account queue behind a single Argon2 run instead of
    // filling the shared hashing pool.
    match st.hash_guard.verify_scoped(&folded, &f.password, &stored).await {
        Ok(true) => {}
        Ok(false) => {
            let (d, tpl) = fail(&st);
            tokio::time::sleep(std::time::Duration::from_secs(d.whole_seconds().min(5) as u64)).await;
            return page(&st, &headers, "Log in", tpl.render().unwrap()).await;
        }
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy, retry shortly").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    }
    // Task 1 (AH1): an enrolled account needs its TOTP code at login
    // too — the passphrase alone no longer opens a full session. The
    // code goes through the same gate as every step-up (counting,
    // lockout, replay protection). A missing/wrong code is a login
    // failure like any other: generic error, failure recorded (which
    // also feeds the budget above).
    if crate::moderation::totp_enrolled(&st.pool, id).await.unwrap_or(false) {
        let code_ok = match f.totp.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            Some(code) => crate::moderation::verify_totp_gate(&st.pool, &st.keyfile, id, code)
                .await
                .is_ok(),
            None => false,
        };
        if !code_ok {
            let (d, tpl) = fail(&st);
            tokio::time::sleep(std::time::Duration::from_secs(d.whole_seconds().min(5) as u64)).await;
            return page(&st, &headers, "Log in", tpl.render().unwrap()).await;
        }
    }
    st.throttles.clear_login_failures(&folded);
    // Stage 9 (owner ruling 2026-10-16): a closed account cannot log
    // in — closure ended the identity. The password was verified first,
    // so this message leaks nothing to anyone who does not hold the
    // passphrase. Nothing here claims the person cannot return under
    // a new identity; closure is not an exclusion tool.
    if crate::moderation::account_status(&st.pool, id)
        .await
        .map(|(s, _, _)| s == "closed")
        .unwrap_or(false)
    {
        let tpl = LoginTpl {
            error: Some("This account has been closed.".into()),
            csrf: f.csrf.clone(),
        };
        return page(&st, &headers, "Log in", tpl.render().unwrap()).await;
    }
    let token = sessions::new_token();
    let csrf_secret = sessions::new_csrf_secret();
    let sess = sessions::Session::fresh(id, OffsetDateTime::now_utc());
    if db::create_session(&st.pool, &token, &csrf_secret, &sess).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    }
    (
        [(header::SET_COOKIE, st.set_cookie(&token))],
        Redirect::to("/account"),
    )
        .into_response()
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf: String,
}

async fn logout(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<LogoutForm>) -> Response {
    let Some((token, sess, csrf_secret)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf_secret, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let _ = db::revoke_all_sessions(&st.pool, sess.account_id).await;
    let _ = token;
    (
        [(header::SET_COOKIE, st.set_cookie(""))],
        Redirect::to("/"),
    )
        .into_response()
}

async fn account_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // Route-table enforcement (§3.14): /account requires any account.
    let Some((_t, sess, csrf_secret)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    let role = role_from_str(&role_s);
    if authorize("GET", "/account", Some(role)) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Denied").into_response();
    }
    let (username,): (String,) = sqlx::query_as("SELECT username FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_one(&st.pool)
        .await
        .unwrap_or_else(|_| ("?".into(),));
    let (acct_status, _closed_at, warned_at) =
        crate::moderation::account_status(&st.pool, sess.account_id)
            .await
            .unwrap_or(("active".into(), None, None));
    let tpl = AccountTpl {
        username,
        role: role_s,
        recovery_code: None,
        csrf: csrf_secret,
        warned_date: warned_at.map(|t| t.date().to_string()),
        account_closed: acct_status == "closed",
    };
    page(&st, &headers, "Account", tpl.render().unwrap()).await
}

async fn recover_form(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let csrf = sessions::new_csrf_secret();
    let tpl = RecoverTpl { error: None, csrf: csrf.clone() };
    let nav = nav_for(&st, &headers).await;
    (
        [(header::SET_COOKIE, st.anon_csrf_cookie(&csrf))],
        Html(shell(&nav, "Recover account", &tpl.render().unwrap())),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RecoverForm {
    username: String,
    code: String,
    password: String,
    csrf: String,
}

async fn recover(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<RecoverForm>) -> Response {
    if cookie_value(&headers, "csrf").as_deref() != Some(f.csrf.as_str()) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let folded = usernames::fold_username(&f.username);
    // Stage 10: error re-renders go through the shell like every page.
    async fn err(st: &AppState, headers: &HeaderMap, csrf: &str, msg: &str) -> Response {
        let tpl = RecoverTpl { error: Some(msg.into()), csrf: csrf.into() };
        page(st, headers, "Recover account", tpl.render().unwrap()).await
    }
    if f.password.len() < 12 || crate::passwords::is_common_password(&f.password) {
        return err(&st, &headers, &f.csrf, "Passphrase at least 12 chars and not a common one.").await;
    }
    let Some((id, _stored, _role)) = db::account_by_username(&st.pool, &folded).await.ok().flatten() else {
        return err(&st, &headers, &f.csrf, "Recovery failed.").await; // same message as a bad code: no account oracle
    };
    match db::consume_recovery_code(&st.pool, id, &f.code).await {
        Ok(true) => {}
        _ => return err(&st, &headers, &f.csrf, "Recovery failed.").await,
    }
    let hash = match st.hash_guard.hash(&f.password).await {
        Ok(h) => h,
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy").into_response(),
        Err(_) => return err(&st, &headers, &f.csrf, "Recovery failed.").await,
    };
    let _ = sqlx::query("UPDATE accounts SET password_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(&hash)
        .execute(&st.pool)
        .await;
    // Fresh recovery code for next time; sessions already revoked by consume.
    let code = recovery::new_recovery_code();
    let _ = db::store_recovery_code(&st.pool, id, &code).await;
    page(
        &st,
        &headers,
        "Recovered",
        format!(
            "<h1>Passphrase reset</h1><p>All sessions were signed out.</p><p><strong>New recovery code (shown once): {}</strong></p><p><a href=\"/login\">Log in</a></p>",
            esc(&code)
        ),
    )
    .await
}

// -- Stage 2: catalogue, listings, seller admission, media -------------------

use crate::listings as lst;
use axum::extract::{Multipart, Path, Query};
use std::collections::HashMap;

pub struct ListingView {
    pub public_id: String,
    pub seller_public_id: String,
    pub title: String,
    pub price_xmr: String,
    pub category: String,
    pub seller_name: String,
    pub status: String,
}

fn view_of(l: &lst::Listing) -> ListingView {
    ListingView {
        public_id: l.public_id.clone(),
        seller_public_id: l.seller_public_id.clone(),
        title: l.title.clone(),
        price_xmr: domain::Atomic(l.price_atomic as u64).format_decimal(),
        category: l.category.clone(),
        seller_name: l.seller_name.clone(),
        status: l.status.clone(),
    }
}

#[derive(Template)]
#[template(path = "catalogue.html")]
struct CatalogueTpl {
    listings: Vec<ListingView>,
    q: String,
    category: String,
    categories: Vec<String>,
    page: i64,
}

async fn catalogue(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let q = p.get("q").cloned().unwrap_or_default();
    let category = p.get("category").cloned().unwrap_or_default();
    let page: i64 = p.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let items = lst::browse(
        &st.pool,
        if q.is_empty() { None } else { Some(&q) },
        if category.is_empty() { None } else { Some(&category) },
        page,
    )
    .await
    .unwrap_or_default();
    let tpl = CatalogueTpl {
        listings: items.iter().map(view_of).collect(),
        q,
        category,
        categories: lst::CATEGORIES.iter().map(|s| s.to_string()).collect(),
        page,
    };
    let nav = nav_for(&st, &headers).await;
    // (The local `page` is the catalogue page number; the shell call
    // goes through page_with for that reason.)
    page_with(&nav, "Browse listings", tpl.render().unwrap())
}

#[derive(Template)]
#[template(path = "listing.html")]
struct ListingTpl {
    listing: lst::Listing,
    price_xmr: String,
    description_html: String,
    media: Vec<(String, i32, i32)>,
    can_order: bool,
    /// Direct Payments v1: set when the seller has a payment identity
    /// but an empty pool — the listing cannot take orders right now.
    payment_notice: Option<String>,
    csrf: String,
    idem: String,
    /// Stage 9: the report form renders for logged-in viewers.
    viewer_logged_in: bool,
}

async fn listing_page(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(l) = lst::listing_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such listing").into_response();
    };
    // Object-level check: unpublished listings are visible only to their seller.
    if l.status != "published" {
        let owner = current_session(&st, &headers)
            .await
            .map(|(_, s, _)| s.account_id == l.seller_id)
            .unwrap_or(false);
        if !owner {
            return (StatusCode::NOT_FOUND, "No such listing").into_response();
        }
    }
    let media = lst::media_of(&st.pool, l.id).await.unwrap_or_default();
    let viewer = current_session(&st, &headers).await;
    // Direct Payments v1: a seller WITH a payment identity but an
    // empty pool cannot take orders — the listing says so. A seller
    // with no payment identity keeps the pre-payment behaviour.
    let mut payment_notice: Option<String> = None;
    if crate::payments::get_identity(&st.pool, l.seller_id).await.ok().flatten().is_some() {
        let unused = crate::payments::unused_count(&st.pool, l.seller_id).await.unwrap_or(0);
        if unused == 0 {
            payment_notice = Some(
                "This seller needs to add payment addresses before new orders can be taken.".into(),
            );
        }
    }
    let pool_blocked = payment_notice.is_some();
    let can_order = l.status == "published"
        && !pool_blocked
        && viewer
            .as_ref()
            .map(|(_, s, _)| s.account_id != l.seller_id)
            .unwrap_or(false);
    let viewer_logged_in = viewer.is_some();
    let title = l.title.clone();
    let tpl = ListingTpl {
        price_xmr: domain::Atomic(l.price_atomic as u64).format_decimal(),
        description_html: domain::markup::render_listing_markup(&l.description),
        media,
        can_order,
        payment_notice,
        csrf: viewer.map(|(_, _, c)| c).unwrap_or_default(),
        idem: sessions::new_token(),
        viewer_logged_in,
        listing: l,
    };
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

#[derive(Template)]
#[template(path = "seller.html")]
struct SellerTpl {
    is_seller: bool,
    listings: Vec<ListingView>,
    categories: Vec<String>,
    application_state: Option<String>,
    // Direct Payments v1 dashboard state.
    payment_seller_id: String,
    payment_marketplace_id: String,
    payment_network: String,
    payment_primary: Option<String>,
    payment_unused: i64,
    /// Stage 10: pool at/below the configured low-water mark
    /// (PAYMENTS_LOW_POOL_THRESHOLD) — the dashboard footer warns
    /// persistently, beside the one-shot inbox notification that
    /// fires when an assignment crosses the threshold (orders.rs).
    payment_low: bool,
    payment_changed: Option<String>,
    payment_message: Option<String>,
    csrf: String,
}

async fn seller_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    let is_seller = matches!(role_from_str(&role_s), Role::Seller | Role::Admin);
    let listings = if is_seller {
        lst::listings_of_seller(&st.pool, sess.account_id)
            .await
            .unwrap_or_default()
            .iter()
            .map(view_of)
            .collect()
    } else {
        vec![]
    };
    let application_state = if is_seller {
        None
    } else {
        lst::seller_application_state(&st.pool, sess.account_id).await.ok().flatten()
    };
    // Direct Payments v1: the seller_id shown here is the value the
    // helper tool's `init` copies — derived in exactly one place
    // (payments::payment_seller_id).
    let public_id = db::public_id_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_default();
    let payment_seller_id = crate::payments::payment_seller_id(&public_id).unwrap_or_default();
    let identity = if is_seller {
        crate::payments::get_identity(&st.pool, sess.account_id).await.ok().flatten()
    } else {
        None
    };
    let payment_primary = identity.as_ref().map(|i| i.primary_address.clone());
    let payment_unused = if identity.is_some() {
        crate::payments::unused_count(&st.pool, sess.account_id).await.unwrap_or(0)
    } else {
        0
    };
    let payment_changed = if is_seller {
        crate::payments::identity_changed_recently(&st.pool, sess.account_id, &st.payments)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let tpl = SellerTpl {
        is_seller,
        listings,
        categories: lst::CATEGORIES.iter().map(|s| s.to_string()).collect(),
        application_state,
        payment_seller_id,
        payment_marketplace_id: st.payments.marketplace_id.clone(),
        payment_network: crate::payments::network_name(st.payments.network).to_string(),
        payment_primary,
        payment_unused,
        payment_low: identity.is_some() && payment_unused <= st.payments.low_pool_threshold,
        payment_changed,
        payment_message: p.get("pmsg").cloned(),
        csrf,
    };
    page(&st, &headers, "Sell", tpl.render().unwrap()).await
}

// -- Direct Payments v1: identity + batch upload ----------------------------

#[derive(Deserialize)]
struct PaymentIdentityForm {
    primary_address: String,
    /// Step-up (task 2): current passphrase, plus a TOTP code when
    /// the account is enrolled.
    password: Option<String>,
    totp: Option<String>,
    csrf: String,
}

/// The seller payment gate shared by the identity and batch handlers
/// (tasks 1+2): TOTP enrollment is MANDATORY before a seller can set
/// a payment identity, and every change needs the step-up. Returns
/// the refusal redirect when the gate fails.
async fn seller_payment_gate(
    st: &AppState,
    sess: &sessions::Session,
    password: Option<&str>,
    totp: Option<&str>,
) -> Option<Response> {
    if !crate::moderation::totp_enrolled(&st.pool, sess.account_id).await.unwrap_or(false) {
        return Some(
            Redirect::to("/seller?pmsg=Enroll in TOTP on your security page first: a payment identity cannot be set or changed without two-factor authentication.")
                .into_response(),
        );
    }
    let Some(pw) = password.filter(|p| !p.is_empty()) else {
        return Some(
            Redirect::to("/seller?pmsg=Step-up verification failed: enter your current passphrase.").into_response(),
        );
    };
    match step_up(st, sess, pw, totp).await {
        Ok(()) => None,
        Err(msg) => Some(Redirect::to(&format!("/seller?pmsg={msg}")).into_response()),
    }
}

async fn payment_identity_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<PaymentIdentityForm>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    if authorize("POST", "/seller/payment-identity", Some(role_from_str(&role_s))) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Sellers only").into_response();
    }
    if let Some(r) = seller_payment_gate(&st, &sess, f.password.as_deref(), f.totp.as_deref()).await {
        return r;
    }
    // The form field arrives through the form layer; the address value
    // itself is validated untrimmed by modules-api (whitespace-wrapped
    // input is rejected there, never silently stripped below).
    let lines = match modules_api::normalize_form_lines(&f.primary_address) {
        Ok(v) if v.len() == 1 => v,
        _ => {
            return Redirect::to("/seller?pmsg=Primary address rejected: paste exactly one address.").into_response()
        }
    };
    match crate::payments::set_primary_address(&st.pool, sess.account_id, &lines[0], &st.payments).await {
        Ok(_) => {
            stepup_notice(&st, sess.account_id, "stepup_payment_identity", "your primary payment address was set or changed").await;
            Redirect::to("/seller?pmsg=Payment identity saved.").into_response()
        }
        Err(e) => Redirect::to(&format!("/seller?pmsg=Primary address rejected: {e:?}")).into_response(),
    }
}

async fn payment_batch_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut mp: Multipart,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    if authorize("POST", "/seller/payment-batches", Some(role_from_str(&role_s))) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Sellers only").into_response();
    }
    let mut csrf_ok = false;
    let mut pasted: Option<String> = None;
    let mut file_text: Option<String> = None;
    // Step-up fields (task 2): the batch form carries the current
    // passphrase and, when enrolled, a TOTP code.
    let mut stepup_password: Option<String> = None;
    let mut stepup_totp: Option<String> = None;
    while let Ok(Some(field)) = mp.next_field().await {
        match field.name() {
            Some("csrf") => {
                if let Ok(v) = field.text().await {
                    csrf_ok = sessions::csrf_matches(&csrf, &v);
                }
            }
            Some("password") => {
                if let Ok(v) = field.text().await {
                    stepup_password = Some(v);
                }
            }
            Some("totp") => {
                if let Ok(v) = field.text().await {
                    stepup_totp = Some(v);
                }
            }
            Some("batch_json") => {
                if let Ok(v) = field.text().await {
                    if !v.trim().is_empty() {
                        pasted = Some(v);
                    }
                }
            }
            Some("batch_file") => {
                if let Ok(b) = field.bytes().await {
                    if !b.is_empty() {
                        file_text = String::from_utf8(b.to_vec()).ok();
                    }
                }
            }
            _ => {}
        }
    }
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    if let Some(r) = seller_payment_gate(&st, &sess, stepup_password.as_deref(), stepup_totp.as_deref()).await {
        return r;
    }
    // The batch text is parsed as JSON and its string values are stored
    // byte-exact as parsed — nothing here trims or re-encodes them.
    let Some(text) = file_text.or(pasted) else {
        return Redirect::to("/seller?pmsg=No batch received: paste the batch JSON or choose the batch file.").into_response();
    };
    match crate::payments::upload_batch(&st.pool, sess.account_id, &text, &st.payments).await {
        Ok(n) => {
            stepup_notice(&st, sess.account_id, "stepup_payment_batch", "a signed subaddress batch was uploaded to your pool").await;
            Redirect::to(&format!("/seller?pmsg=Batch accepted: {n} payment address(es) added to your pool.")).into_response()
        }
        Err(e) => Redirect::to(&format!("/seller?pmsg=Batch rejected (nothing was stored): {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct CsrfOnly {
    csrf: String,
}

async fn seller_apply(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<CsrfOnly>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    if lst::seller_application_state(&st.pool, sess.account_id).await.ok().flatten().as_deref() == Some("pending") {
        return Redirect::to("/seller").into_response(); // idempotent re-apply
    }
    let _ = lst::apply_for_seller(&st.pool, sess.account_id).await;
    Redirect::to("/seller").into_response()
}

#[derive(Deserialize)]
struct ListingForm {
    title: String,
    description: String,
    price: String,
    category: String,
    destination_module: String,
    auto_invoice: Option<String>,
    csrf: String,
}

async fn create_listing(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<ListingForm>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    if authorize("POST", "/seller/listings", Some(role_from_str(&role_s))) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Sellers only").into_response();
    }
    let auto = f.auto_invoice.as_deref() == Some("true");
    // Contract §8: validate_listing takes the price in atomic units; the
    // decimal form field is parsed here (unparseable ⇒ Price error).
    let validated = match domain::Atomic::parse_decimal(f.price.trim()) {
        Some(p) => lst::validate_listing(&f.title, &f.description, p.0, &f.category, &f.destination_module, auto)
            .map(|()| p.0 as i64),
        None => Err(lst::ListingError::Price),
    };
    match validated {
        Ok(price_atomic) => {
            match lst::create_listing(&st.pool, sess.account_id, &f.title, &f.description, price_atomic, &f.category, &f.destination_module, auto).await {
                Ok(_) => Redirect::to("/seller").into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("Invalid listing: {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct StatusForm {
    status: String,
    csrf: String,
}

async fn listing_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<StatusForm>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some(l) = lst::listing_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such listing").into_response();
    };
    match lst::set_status(&st.pool, l.id, sess.account_id, &f.status).await {
        Ok(true) => Redirect::to("/seller").into_response(),
        _ => (StatusCode::FORBIDDEN, "Not your listing").into_response(),
    }
}

async fn listing_media(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    mut mp: Multipart,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    let Some(l) = lst::listing_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such listing").into_response();
    };
    if l.seller_id != sess.account_id {
        return (StatusCode::FORBIDDEN, "Not your listing").into_response();
    }
    let mut csrf_ok = false;
    let mut bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = mp.next_field().await {
        match field.name() {
            Some("csrf") => {
                if let Ok(v) = field.text().await {
                    csrf_ok = sessions::csrf_matches(&csrf, &v);
                }
            }
            Some("image") => {
                if let Ok(b) = field.bytes().await {
                    bytes = Some(b.to_vec());
                }
            }
            _ => {}
        }
    }
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some(bytes) = bytes else {
        return (StatusCode::BAD_REQUEST, "No image").into_response();
    };
    match st.media.sanitize(&bytes).await {
        Ok((r#ref, w, h)) => {
            let _ = lst::add_media(&st.pool, l.id, &r#ref, w, h).await;
            Redirect::to("/seller").into_response()
        }
        Err(crate::media::MediaError::TooLarge) => (StatusCode::BAD_REQUEST, "Image over 5 MiB").into_response(),
        Err(crate::media::MediaError::Rejected) => {
            (StatusCode::BAD_REQUEST, "Image rejected (JPEG/PNG, max 4096x4096)").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Media worker error").into_response(),
    }
}

async fn media_serve(State(st): State<AppState>, Path(r#ref): Path<String>) -> Response {
    // Refs are server-generated as `<32 hex>.<png|jpg>` (media.rs
    // sanitize); validate the stem as hex and the extension separately.
    // The earlier check ran the hex test over the WHOLE ref including
    // the extension, whose letters are not hex digits, so it could
    // never pass and every stored image 404'd — defect found
    // 2026-10-17 by the OS recipe's full-stack drive; regression test
    // in crates/app/tests/media_serve_http.rs.
    let ok = match r#ref.rsplit_once('.') {
        Some((stem, ext)) => {
            (ext == "png" || ext == "jpg")
                && !stem.is_empty()
                && stem.chars().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    };
    if !ok {
        return (StatusCode::NOT_FOUND, "No").into_response();
    }
    match tokio::fs::read(st.media.path_of(&r#ref)).await {
        Ok(bytes) => {
            let ct = if r#ref.ends_with(".png") { "image/png" } else { "image/jpeg" };
            (
                [
                    (header::CONTENT_TYPE, ct),
                    (header::HeaderName::from_static("x-content-type-options"), "nosniff"),
                ],
                bytes,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "No").into_response(),
    }
}

#[derive(Template)]
#[template(path = "moderation.html")]
struct ModerationTpl {
    applications: Vec<(i64, String)>,
    csrf: String,
    /// Account Security Audit task 3: shown when a decision was
    /// refused for want of a fresh TOTP code.
    message: Option<String>,
    totp_enrolled: bool,
}

async fn moderation_sellers_render(st: &AppState, headers: &HeaderMap, sess: &sessions::Session, csrf: &str, message: Option<String>) -> Response {
    let applications = lst::pending_seller_applications(&st.pool).await.unwrap_or_default();
    let totp_enrolled = crate::moderation::totp_enrolled(&st.pool, sess.account_id)
        .await
        .unwrap_or(false);
    let tpl = ModerationTpl { applications, csrf: csrf.to_string(), message, totp_enrolled };
    let _ = sess;
    page(st, headers, "Seller applications", tpl.render().unwrap()).await
}

async fn moderation_sellers(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    if authorize("GET", "/moderation/sellers", Some(role_from_str(&role_s))) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Moderators only").into_response();
    }
    moderation_sellers_render(&st, &headers, &sess, &csrf, None).await
}

#[derive(Deserialize)]
struct DecideForm {
    decision: String,
    /// Task 3 (AH1): approving or declining a seller is a moderator
    /// action — it needs a fresh TOTP code like every other one.
    totp: Option<String>,
    csrf: String,
}

async fn moderation_decide(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<DecideForm>,
) -> Response {
    let Some((_t, _sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(_sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let role_s = db::role_of(&st.pool, _sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    if !matches!(role_from_str(&role_s), Role::Moderator | Role::Admin) {
        return (StatusCode::FORBIDDEN, "Moderators only").into_response();
    }
    // Task 3 (AH1): a fresh TOTP code gates seller decisions — a
    // moderator session alone must not be able to approve sellers.
    let code = f.totp.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let totp_ok = match code {
        Some(c) => crate::moderation::require_totp(&st.pool, &st.keyfile, _sess.account_id, c)
            .await
            .is_ok(),
        None => false,
    };
    if !totp_ok {
        return moderation_sellers_render(
            &st,
            &headers,
            &_sess,
            &csrf,
            Some("Decision refused: a fresh TOTP code is required to approve or decline a seller. Enroll on your security page if you have not.".into()),
        )
        .await;
    }
    let _ = lst::decide_seller_application(&st.pool, _sess.account_id, id, f.decision == "approve").await;
    Redirect::to("/moderation/sellers").into_response()
}

// -- Stage 3: identity keys, rotation, profiles, security page ----------------

use crate::keys as kmod;

#[derive(Template)]
#[template(path = "security.html")]
struct SecurityTpl {
    message: Option<String>,
    warnings: Vec<String>,
    current_fingerprint: Option<String>,
    sessions: Vec<(i64, String, String, bool)>,
    profile_text: String,
    csrf: String,
    // Stage 9: TOTP enrollment + self-service closure.
    totp_enabled: bool,
    totp_pending_secret: Option<String>,
    totp_pending_uri: Option<String>,
}

async fn security_page_render(st: &AppState, sess: &sessions::Session, csrf: &str, message: Option<String>, warnings: Vec<String>) -> Response {
    let current = kmod::current_key(&st.pool, sess.account_id).await.ok().flatten();
    let sessions = db::list_sessions(&st.pool, sess.account_id).await.unwrap_or_default();
    let (_, _, _, _, profile_text) = db::account_by_public_id(
        &st.pool,
        &db::public_id_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_default(),
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let totp_enabled = crate::moderation::totp_enrolled(&st.pool, sess.account_id)
        .await
        .unwrap_or(false);
    let totp_pending_secret = crate::moderation::totp_pending(&st.pool, &st.keyfile, sess.account_id)
        .await
        .ok()
        .flatten();
    let username: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_one(&st.pool)
        .await
        .unwrap_or_default();
    let totp_pending_uri = totp_pending_secret
        .as_ref()
        .map(|s| crate::totp::otpauth_uri(&st.marketplace_id, &username, s));
    let tpl = SecurityTpl {
        message,
        warnings,
        current_fingerprint: current.map(|(f, _, _)| f),
        sessions,
        profile_text,
        csrf: csrf.to_string(),
        totp_enabled,
        totp_pending_secret,
        totp_pending_uri,
    };
    let nav = nav_for_session(st, sess, csrf).await;
    page_with(&nav, "Account security", tpl.render().unwrap())
}

async fn security_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    security_page_render(&st, &sess, &csrf, None, vec![]).await
}

#[derive(Deserialize)]
struct KeyUploadForm {
    cert: String,
    /// Step-up (task 2, AM3): current passphrase, plus a TOTP code
    /// when enrolled. A stolen session must not be able to plant the
    /// key buyers will encrypt shipping details to.
    password: Option<String>,
    totp: Option<String>,
    csrf: String,
}

async fn upload_key(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<KeyUploadForm>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    // Step-up BEFORE anything else moves (task 2).
    let Some(pw) = f.password.as_deref().filter(|p| !p.is_empty()) else {
        return security_page_render(&st, &sess, &csrf, Some("Step-up verification failed: enter your current passphrase.".into()), vec![]).await;
    };
    if let Err(msg) = step_up(&st, &sess, pw, f.totp.as_deref()).await {
        return security_page_render(&st, &sess, &csrf, Some(msg), vec![]).await;
    }
    if kmod::current_key(&st.pool, sess.account_id).await.ok().flatten().is_some() {
        return security_page_render(&st, &sess, &csrf, Some("A key is already registered. Use rotation to replace it.".into()), vec![]).await;
    }
    match kmod::validate_cert(f.cert.as_bytes()) {
        Ok(info) => {
            let warnings = info.warnings.clone();
            match kmod::install_key(&st.pool, sess.account_id, f.cert.as_bytes(), &info, None).await {
                Ok(()) => {
                    stepup_notice(&st, sess.account_id, "stepup_key_upload", "an identity key was registered on your account").await;
                    security_page_render(&st, &sess, &csrf, Some(format!("Key registered: {}", info.fingerprint)), warnings).await
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not store key (fingerprint already registered?)").into_response(),
            }
        }
        Err(e) => security_page_render(&st, &sess, &csrf, Some(format!("Key rejected: {e:?}")), vec![]).await,
    }
}

#[derive(Deserialize)]
struct RotateForm {
    new_cert: String,
    statement: String,
    sig_old: String,
    sig_new: String,
    lost: Option<String>,
    /// Step-up (task 2, AM3): current passphrase, plus a TOTP code
    /// when enrolled — including for the uncertified ("lost key")
    /// path, which is exactly the path a session thief would take.
    password: Option<String>,
    totp: Option<String>,
    csrf: String,
}

async fn rotate_key(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<RotateForm>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    // Step-up BEFORE anything else moves (task 2).
    let Some(pw) = f.password.as_deref().filter(|p| !p.is_empty()) else {
        return security_page_render(&st, &sess, &csrf, Some("Step-up verification failed: enter your current passphrase.".into()), vec![]).await;
    };
    if let Err(msg) = step_up(&st, &sess, pw, f.totp.as_deref()).await {
        return security_page_render(&st, &sess, &csrf, Some(msg), vec![]).await;
    }
    let Some((cur_fpr, cur_cert, _v)) = kmod::current_key(&st.pool, sess.account_id).await.ok().flatten() else {
        return security_page_render(&st, &sess, &csrf, Some("No current key to rotate.".into()), vec![]).await;
    };
    let info = match kmod::validate_cert(f.new_cert.as_bytes()) {
        Ok(i) => i,
        Err(e) => return security_page_render(&st, &sess, &csrf, Some(format!("New key rejected: {e:?}")), vec![]).await,
    };
    if info.fingerprint == cur_fpr {
        return security_page_render(&st, &sess, &csrf, Some("New key is the current key.".into()), vec![]).await;
    }
    if f.lost.as_deref() == Some("true") {
        // Uncertified rotation: no statement, warning shows for 90 days (§8).
        return match kmod::install_key(&st.pool, sess.account_id, f.new_cert.as_bytes(), &info, Some((b"", None, None, false))).await {
            Ok(()) => {
                stepup_notice(&st, sess.account_id, "stepup_key_rotation", "your identity key was rotated (uncertified)").await;
                security_page_render(&st, &sess, &csrf, Some("Key rotated without certification. A warning will show on your profile for 90 days.".into()), info.warnings.clone()).await
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rotation failed").into_response(),
        };
    }
    // Certified rotation: statement must bind account, both fingerprints, this instance.
    let public_id = db::public_id_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_default();
    let stmt = match kmod::parse_rotation_statement(&f.statement, &st.marketplace_id) {
        Some(s) => s,
        None => return security_page_render(&st, &sess, &csrf, Some("Rotation statement is malformed.".into()), vec![]).await,
    };
    if stmt.account_id != public_id || stmt.old_fingerprint != cur_fpr || stmt.new_fingerprint != info.fingerprint {
        return security_page_render(&st, &sess, &csrf, Some("Rotation statement does not match this account and these keys.".into()), vec![]).await;
    }
    let ok_old = kmod::verify_detached(&cur_cert, f.statement.as_bytes(), f.sig_old.as_bytes());
    let ok_new = kmod::verify_detached(f.new_cert.as_bytes(), f.statement.as_bytes(), f.sig_new.as_bytes());
    if !ok_old || !ok_new {
        return security_page_render(&st, &sess, &csrf, Some("Both signatures must verify (old key and new key).".into()), vec![]).await;
    }
    match kmod::install_key(
        &st.pool,
        sess.account_id,
        f.new_cert.as_bytes(),
        &info,
        Some((f.statement.as_bytes(), Some(f.sig_old.as_bytes()), Some(f.sig_new.as_bytes()), true)),
    )
    .await
    {
        Ok(()) => {
            stepup_notice(&st, sess.account_id, "stepup_key_rotation", "your identity key was rotated (certified)").await;
            security_page_render(&st, &sess, &csrf, Some(format!("Key rotated (certified): {}", info.fingerprint)), info.warnings.clone()).await
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rotation failed").into_response(),
    }
}

#[derive(Deserialize)]
struct ProfileForm {
    profile_text: String,
    csrf: String,
}

async fn update_profile(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<ProfileForm>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) || f.profile_text.chars().count() > 1000 {
        return (StatusCode::FORBIDDEN, "Rejected").into_response();
    }
    let _ = db::set_profile_text(&st.pool, sess.account_id, f.profile_text.trim()).await;
    Redirect::to("/account/security").into_response()
}

async fn revoke_session(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let _ = db::revoke_session_by_id(&st.pool, id, sess.account_id).await;
    Redirect::to("/account/security").into_response()
}

#[derive(Template)]
#[template(path = "seller_profile.html")]
struct ProfileTpl {
    csrf: String,
    username: String,
    public_id: String,
    role: String,
    recovered_date: Option<String>,
    uncertified_rotation_date: Option<String>,
    current_fingerprint: Option<String>,
    profile_text: String,
    history: Vec<(String, i32, String, String, Option<String>)>,
    listings: Vec<ListingView>,
    // Direct Payments v1: payment identity presentation (the primary
    // address is public by design — buyers verify against it).
    payment_primary: Option<String>,
    payment_changed: Option<String>,
    // Stage 9: reputation, reviews, closure (owner ruling 2026-10-16).
    account_closed: bool,
    closed_date: Option<String>,
    rep_model: String,
    rep_score: Option<String>,
    rep_review_count: i32,
    rep_established: i64,
    raw: RepRawView,
    reviews: Vec<crate::reviews::ReviewView>,
    viewer_logged_in: bool,
}

/// Preformatted raw-facts panel values (core-rendered under every model).
struct RepRawView {
    member_since: String,
    age_days: i64,
    first_sale: String,
    completed: i64,
    buyers: i64,
    confirmed: i64,
    verified: i64,
    disputes_opened: i64,
    disputes_against: i64,
    rot_certified: i64,
    rot_uncertified: i64,
}

async fn seller_profile(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let csrf = current_session(&st, &headers).await.map(|(_, _, c)| c).unwrap_or_default();
    let Some((account_id, username, role, recovered_at, profile_text)) =
        db::account_by_public_id(&st.pool, &id).await.ok().flatten()
    else {
        return (StatusCode::NOT_FOUND, "No such account").into_response();
    };
    let now = OffsetDateTime::now_utc();
    let recovered_date = recovered_at.and_then(|t| {
        if now - t < time::Duration::days(30) {
            Some(t.date().to_string())
        } else {
            None
        }
    });
    // Uncertified-rotation warning shows for 90 days from the rotation (§8).
    let uncert = kmod::latest_uncertified_rotation(&st.pool, account_id).await.ok().flatten();
    let uncertified_rotation_date = uncert.filter(|_d| true);
    let current = kmod::current_key(&st.pool, account_id).await.ok().flatten();
    let history = kmod::key_history(&st.pool, account_id).await.unwrap_or_default();
    let listings = lst::listings_of_seller(&st.pool, account_id)
        .await
        .unwrap_or_default()
        .iter()
        .filter(|l| l.status == "published")
        .map(view_of)
        .collect();
    let payment_identity = crate::payments::get_identity(&st.pool, account_id).await.ok().flatten();
    let payment_primary = payment_identity.map(|i| i.primary_address);
    let payment_changed = crate::payments::identity_changed_recently(&st.pool, account_id, &st.payments)
        .await
        .ok()
        .flatten();
    // Stage 9: sync this seller's facts (any terminal order gets its
    // fact whichever path terminated it), then read the stored summary
    // and the core raw-facts panel.
    let _ = crate::reputation::sync_facts_for_seller(&st.pool, &st.keyfile, &st.stage9, account_id).await;
    let summary = crate::reputation::summary_row(&st.pool, account_id).await.ok().flatten();
    let rawf = crate::reputation::raw_facts(&st.pool, account_id).await.unwrap_or_default();
    let reviews = crate::reviews::reviews_for_seller(&st.pool, &st.stage9, account_id)
        .await
        .unwrap_or_default();
    let (acct_status, closed_at, _warned) = crate::moderation::account_status(&st.pool, account_id)
        .await
        .unwrap_or(("active".into(), None, None));
    let viewer_logged_in = !csrf.is_empty();
    let title = username.clone();
    let raw = RepRawView {
        member_since: rawf.member_since_month,
        age_days: rawf.account_age_days,
        first_sale: rawf.first_sale_month.unwrap_or_else(|| "—".into()),
        completed: rawf.completed_orders,
        buyers: rawf.distinct_buyers,
        confirmed: rawf.seller_confirmed_payments,
        verified: rawf.verified_payments,
        disputes_opened: rawf.disputes_opened,
        disputes_against: rawf.disputes_against_seller,
        rot_certified: rawf.rotations_certified,
        rot_uncertified: rawf.rotations_uncertified,
    };
    let tpl = ProfileTpl {
        csrf,
        username,
        public_id: id.clone(),
        role,
        recovered_date,
        uncertified_rotation_date,
        current_fingerprint: current.map(|(f, _, _)| f),
        profile_text,
        history,
        listings,
        payment_primary,
        payment_changed,
        account_closed: acct_status == "closed",
        closed_date: closed_at.map(|t| t.date().to_string()),
        rep_model: summary.as_ref().map(|s| s.model_id.clone()).unwrap_or_default(),
        rep_score: summary.as_ref().and_then(|s| s.weighted_score).map(|v| format!("{v:.2}")),
        rep_review_count: summary.as_ref().map(|s| s.review_count).unwrap_or(0),
        rep_established: summary.as_ref().map(|s| s.established_buyers).unwrap_or(0),
        raw,
        reviews,
        viewer_logged_in,
    };
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

async fn seller_key_download(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let Some((account_id, ..)) = db::account_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such account").into_response();
    };
    match kmod::current_key(&st.pool, account_id).await.ok().flatten() {
        Some((_f, cert, _v)) => (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"key.asc\"",
                ),
            ],
            cert,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "No key").into_response(),
    }
}

// -- Stage 4: orders + inbox ---------------------------------------------------

use crate::orders as ord;

pub struct OrderView {
    pub public_id: String,
    pub listing_title: String,
    pub state: String,
    pub total_xmr: String,
    pub buyer_id: i64,
    pub created_at: String,
}

fn order_view(o: &ord::Order) -> OrderView {
    OrderView {
        public_id: o.public_id.clone(),
        listing_title: o.listing_title.clone(),
        state: o.state.clone(),
        total_xmr: domain::Atomic(o.total_atomic as u64).format_decimal(),
        buyer_id: o.buyer_id,
        created_at: o.created_at.clone(),
    }
}

#[derive(Template)]
#[template(path = "orders.html")]
struct OrdersTpl {
    orders: Vec<OrderView>,
    me: i64,
}

async fn orders_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let orders = ord::orders_for(&st.pool, sess.account_id)
        .await
        .iter()
        .map(order_view)
        .collect();
    let tpl = OrdersTpl {
        orders,
        me: sess.account_id,
    };
    page(&st, &headers, "Orders", tpl.render().unwrap()).await
}

#[derive(Deserialize)]
struct OrderForm {
    listing_id: String,
    quantity: u32,
    idem: String,
    csrf: String,
}

async fn create_order_handler(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<OrderForm>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    match ord::create_order_with_config(&st.pool, &st.marketplace_id, sess.account_id, &f.listing_id, f.quantity, &f.idem, &st.payments).await {
        Ok((order, _created)) => Redirect::to(&format!("/orders/{}", order.public_id)).into_response(),
        Err(ord::OrderError::PoolEmpty) => (StatusCode::BAD_REQUEST, "This seller needs to add payment addresses before new orders can be taken.").into_response(),
        Err(ord::OrderError::TooManyOpenUnpaid) => (StatusCode::BAD_REQUEST, "You already have the maximum number of open unpaid orders. Pay or cancel one first.").into_response(),
        Err(ord::OrderError::OrderRateLimited) => (StatusCode::BAD_REQUEST, "Too many orders created in the last hour. Please wait before ordering again.").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("Order failed: {e:?}")).into_response(),
    }
}

#[derive(Template)]
#[template(path = "order.html")]
struct OrderTpl {
    order: ord::Order,
    total_xmr: String,
    evidence_label: String,
    actions: Vec<String>,
    /// Direct Payments v1: the order carries a payment assignment.
    has_payment: bool,
    /// Tx-proof flow (2026-10-18): the viewing seller may confirm
    /// payment for this order (per-order, bound to the subaddress;
    /// design update #2.1). Rendered identically whatever the source
    /// of the order's Paid state.
    can_confirm: bool,
    /// The order's assigned subaddress (the seller's own), named by
    /// the confirmation form.
    assigned_address: Option<String>,
    /// The viewing buyer's own submitted proof — buyer only; the
    /// seller's render never receives this data (visibility rule).
    my_proof: Option<crate::payments::PaymentProof>,
    /// The buyer may submit (or revise) a proof in this state.
    proof_open: bool,
    /// The buyer has a manual "I paid" report on file.
    manual_reported: bool,
    /// The viewing seller may declare not-received (past the
    /// unpaid-expiry horizon; design update #2.4).
    can_declare: bool,
    message: Option<String>,
    csrf: String,
    // Stage 9: review + dispute presentation.
    review: Option<crate::reviews::ReviewView>,
    can_review: bool,
    can_reply: bool,
    is_buyer: bool,
    dispute: Option<(i64, String)>,
}

fn permitted_actions(o: &ord::Order, me: i64) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    let is_buyer = o.buyer_id == me;
    let is_seller = o.seller_id == me;
    match o.state.as_str() {
        "Requested" => {
            if is_seller {
                v.push("accept".into());
                v.push("decline".into());
            }
            if is_buyer {
                v.push("cancel".into());
            }
        }
        "AwaitingPayment" => {
            if is_buyer || is_seller {
                v.push("cancel".into());
            }
            if is_buyer {
                v.push("dispute".into());
            }
        }
        "Paid" => {
            if is_seller {
                v.push("fulfil".into());
            }
            if is_buyer || is_seller {
                v.push("dispute".into());
            }
        }
        "Fulfilled"
            if is_buyer => {
                v.push("complete".into());
                v.push("dispute".into());
            }
        _ => {}
    }
    v
}

fn evidence_label(level: &str) -> String {
    match level {
        "BuyerReported" => "Buyer reports payment (not confirmed by the seller)".into(),
        // Tx-proof flow (2026-10-18): the truthful label for the buyer
        // and for moderators. The seller never sees this string (see
        // seller_evidence_label).
        "BuyerProofSubmitted" => "Buyer-submitted payment proof (unverified)".into(),
        // Direct Payments v1 copy rule: "seller confirmed payment" —
        // never "verified" as a payment claim.
        "SellerAttested" => "Seller confirmed payment".into(),
        "ProofVerified" => "Payment proof recorded".into(),
        "WalletObserved" => "Payment observed by wallet".into(),
        _ => "No payment evidence recorded".into(),
    }
}

/// The seller-facing evidence label (owner-directed visibility rule,
/// 2026-10-18): a proof-driven Paid must be indistinguishable from an
/// attestation-driven Paid, so the seller sees the same line either
/// way. The proof's existence is never displayed to the seller.
fn seller_evidence_label(level: &str) -> String {
    match level {
        "BuyerProofSubmitted" => "Seller confirmed payment".into(),
        other => evidence_label(other),
    }
}

async fn order_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let Some(o) = ord::order_by_public_id(&st.pool, &id).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    let has_payment = crate::payments::has_assignment(&st.pool, o.id).await.unwrap_or(false);
    // Tx-proof flow (2026-10-18): per-viewer payment presentation.
    // The seller's render is built WITHOUT any proof data: only the
    // buyer branch below ever fetches the proof row.
    let is_buyer = o.buyer_id == sess.account_id;
    let viewer_is_seller = o.seller_id == sess.account_id;
    let assignment = if has_payment {
        crate::payments::assignment_for_order(&st.pool, o.id, &st.payments)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let assigned_address = assignment.as_ref().map(|a| a.address.clone());
    let can_confirm = has_payment
        && viewer_is_seller
        && matches!(
            o.state.as_str(),
            "AwaitingPayment" | "Paid" | "Fulfilled" | "Disputed"
        );
    let proof_open = is_buyer
        && has_payment
        && matches!(
            o.state.as_str(),
            "Requested" | "AwaitingPayment" | "Paid" | "Fulfilled"
        );
    let my_proof = if is_buyer {
        crate::payments::payment_proof_for_order(&st.pool, o.id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let manual_reported = if is_buyer {
        crate::payments::payment_report_for_order(&st.pool, o.id)
            .await
            .ok()
            .flatten()
            .map(|r| r.kind == "manual")
            .unwrap_or(false)
    } else {
        false
    };
    let can_declare = viewer_is_seller
        && has_payment
        && crate::payments::declaration_available(&st.pool, &o, &st.payments)
            .await
            .unwrap_or(false);
    let evidence = if viewer_is_seller {
        seller_evidence_label(&o.evidence_level)
    } else {
        evidence_label(&o.evidence_level)
    };
    let review = crate::reviews::review_for_order(&st.pool, &st.stage9, o.id)
        .await
        .ok()
        .flatten();
    let can_review = is_buyer && matches!(o.state.as_str(), "Completed" | "Resolved");
    let can_reply = o.seller_id == sess.account_id
        && review.as_ref().map(|r| r.seller_reply.is_none()).unwrap_or(false);
    let dispute = crate::disputes::dispute_for_order(&st.pool, o.id)
        .await
        .ok()
        .flatten()
        .map(|d| (d.id, d.state));
    let title = format!("Order {}", o.public_id);
    let tpl = OrderTpl {
        total_xmr: domain::Atomic(o.total_atomic as u64).format_decimal(),
        evidence_label: evidence,
        actions: permitted_actions(&o, sess.account_id),
        has_payment,
        can_confirm,
        assigned_address,
        my_proof,
        proof_open,
        manual_reported,
        can_declare,
        message: p.get("msg").cloned(),
        csrf,
        review,
        can_review,
        can_reply,
        is_buyer,
        dispute,
        order: o,
    };
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

#[derive(Deserialize)]
struct OrderActionForm {
    csrf: String,
    txid: Option<String>,
    proof: Option<String>,
}

async fn order_action(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
    Form(f): Form<OrderActionForm>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some(o) = ord::order_by_public_id(&st.pool, &id).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    if action == "submit-proof" {
        // Tx-proof flow (2026-10-18): the buyer's evidence submission.
        // Buyer-facing copy only — the seller is never notified.
        return match crate::payments::submit_payment_proof(
            &st.pool,
            &o,
            sess.account_id,
            f.txid.as_deref().unwrap_or(""),
            f.proof.as_deref().unwrap_or(""),
            &st.payments,
        )
        .await
        {
            Ok(_) => Redirect::to(&format!(
                "/orders/{id}?msg={}",
                "Payment proof recorded. It is carried unverified: the seller and moderators check it in their own wallets."
            ))
            .into_response(),
            Err(e) => Redirect::to(&format!("/orders/{id}?msg=Proof not accepted: {e:?}")).into_response(),
        };
    }
    if action == "manual-report" {
        // The buyer's manual "I paid" fallback (BuyerReported).
        return match crate::payments::submit_manual_report(&st.pool, &o, sess.account_id).await {
            Ok(_) => Redirect::to(&format!(
                "/orders/{id}?msg={}",
                "Your payment report is recorded on your word alone — weaker protection than a transaction proof."
            ))
            .into_response(),
            Err(e) => Redirect::to(&format!("/orders/{id}?msg=Report not accepted: {e:?}")).into_response(),
        };
    }
    if action == "confirm-payment" {
        // Per-order seller confirmation bound to the subaddress
        // (design update #2.1); identical wording for every Paid path.
        return match crate::payments::confirm_payment(&st.pool, &o, sess.account_id, &st.payments).await {
            Ok(_) => Redirect::to(&format!("/orders/{id}?msg={}", "Payment confirmed for this order.")).into_response(),
            Err(e) => Redirect::to(&format!("/orders/{id}?msg=Confirmation not allowed: {e:?}")).into_response(),
        };
    }
    if action == "declare-not-received" {
        // Seller not-received declaration (design update #2.4). The
        // confirmation wording is identical whether or not a proof
        // is on file — the seller learns nothing from it.
        return match crate::payments::declare_not_received(&st.pool, &o, sess.account_id, &st.payments).await {
            Ok(_) => Redirect::to(&format!("/orders/{id}?msg={}", "Declaration recorded.")).into_response(),
            Err(e) => Redirect::to(&format!("/orders/{id}?msg=Declaration not allowed: {e:?}")).into_response(),
        };
    }
    if action == "mark-paid" {
        // Direct Payments v1: the seller's mark-paid submits a
        // SellerAttestation claim through the DirectV1 module; the
        // core performs the Paid transition (payments::mark_paid).
        return match crate::payments::mark_paid(&st.pool, &o, sess.account_id, &st.payments).await {
            Ok(_) => Redirect::to(&format!("/orders/{id}?msg={}", "Payment marked: seller confirmed payment.")).into_response(),
            Err(e) => Redirect::to(&format!("/orders/{id}?msg=Mark-paid not allowed: {e:?}")).into_response(),
        };
    }
    match ord::apply_action(&st.pool, &o, &action, sess.account_id).await {
        Ok(_) => Redirect::to(&format!("/orders/{id}")).into_response(),
        Err(ord::OrderError::InvoiceRequired) => Redirect::to(&format!(
            "/orders/{id}?msg={}",
            "Accepting requires an issued invoice. Invoices arrive with the payment stages."
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!("/orders/{id}?msg=Action not allowed: {e:?}")).into_response(),
    }
}

// -- Direct Payments v1: buyer payment page ----------------------------------

#[derive(Template)]
#[template(path = "pay.html")]
struct PayTpl {
    order: ord::Order,
    total_xmr: String,
    payment_uri: String,
    assignment: Option<crate::payments::Assignment>,
    is_paid: bool,
    /// Closed states (audit task 4, 2026-10-18): no payable address
    /// is presented; the page says the order is closed instead.
    closed: bool,
}

/// Terminal order states for payment purposes (fix-brief task 4):
/// the pay page must not present a payable address in any of these.
/// There is no separate Expired state — expiry lands in Cancelled.
fn payment_closed(state: &str) -> bool {
    matches!(state, "Cancelled" | "Declined" | "Completed" | "Resolved")
}

async fn pay_page(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let Some(o) = ord::order_by_public_id(&st.pool, &id).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    // Participants only — everyone else gets the same 404 as a
    // nonexistent order (no oracle).
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    let closed = payment_closed(&o.state);
    // Closed orders render with NO assignment at all: the address,
    // the payment URI and the QR are withheld, not just hidden.
    let assignment = if closed {
        None
    } else {
        crate::payments::assignment_for_order(&st.pool, o.id, &st.payments)
            .await
            .ok()
            .flatten()
    };
    let payment_uri = match &assignment {
        Some(a) => domain::statements::payment_uri_for(&a.address, o.total_atomic as u64),
        None => String::new(),
    };
    let title = format!("Pay for order {}", o.public_id);
    let tpl = PayTpl {
        total_xmr: domain::Atomic(o.total_atomic as u64).format_decimal(),
        payment_uri,
        assignment,
        is_paid: o.state == "Paid",
        closed,
        order: o,
    };
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

async fn pay_qr(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let Some(o) = ord::order_by_public_id(&st.pool, &id).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    if payment_closed(&o.state) {
        // Task 4: the QR route 404s on closed orders.
        return (StatusCode::NOT_FOUND, "No payment assignment").into_response();
    }
    let Some(a) = crate::payments::assignment_for_order(&st.pool, o.id, &st.payments)
        .await
        .ok()
        .flatten()
    else {
        return (StatusCode::NOT_FOUND, "No payment assignment").into_response();
    };
    let png = domain::statements::payment_qr_png_for(&a.address, o.total_atomic as u64);
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::HeaderName::from_static("x-content-type-options"), "nosniff"),
        ],
        png,
    )
        .into_response()
}

async fn terms_download(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let Some(o) = ord::order_by_public_id(&st.pool, &id).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    match ord::terms_bytes(&st.pool, o.id).await {
        Some(bytes) => (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"terms.txt\""),
            ],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "No terms").into_response(),
    }
}

#[derive(Template)]
#[template(path = "inbox.html")]
struct InboxTpl {
    items: Vec<(i64, String, String, String, bool)>,
    csrf: String,
}

async fn inbox_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let items = ord::inbox(&st.pool, sess.account_id).await;
    let tpl = InboxTpl { items, csrf };
    page(&st, &headers, "Inbox", tpl.render().unwrap()).await
}

async fn inbox_read_all(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<CsrfOnly>) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let _ = ord::mark_all_read(&st.pool, sess.account_id).await;
    Redirect::to("/inbox").into_response()
}

// -- Stage 5: conversations & ciphertext messaging -----------------------------

use crate::messages as msg;

#[derive(Template)]
#[template(path = "conversations.html")]
struct ConversationsTpl {
    conversations: Vec<msg::Conversation>,
}

async fn conversations_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let conversations = msg::list_for(&st.pool, sess.account_id).await.unwrap_or_default();
    let tpl = ConversationsTpl { conversations };
    page(&st, &headers, "Conversations", tpl.render().unwrap()).await
}

pub struct MsgView {
    pub id: i64,
    pub sender_id: i64,
    pub ciphertext_text: String,
    pub at: String,
}

#[derive(Template)]
#[template(path = "conversation.html")]
struct ConversationTpl {
    conv_id: i64,
    rotation_warning: bool,
    other_public_id: String,
    other_name: String,
    other_fingerprint: String,
    messages: Vec<(i64, i64, i32, String)>,
    message: Option<String>,
    me: i64,
    csrf: String,
}

async fn conversation_render(
    st: &AppState,
    sess: &sessions::Session,
    csrf: &str,
    conv_id: i64,
    message: Option<String>,
) -> Response {
    let Some((other_id, other_name)) = msg::other_participant(&st.pool, conv_id, sess.account_id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such conversation").into_response();
    };
    let _ = msg::record_sightings(&st.pool, conv_id).await;
    let _ = msg::mark_read(&st.pool, conv_id, sess.account_id).await;
    let other_fingerprint = crate::keys::current_key(&st.pool, other_id)
        .await
        .ok()
        .flatten()
        .map(|(f, _, _)| f)
        .unwrap_or_else(|| "(no key registered)".into());
    let messages = msg::messages_of(&st.pool, conv_id).await.unwrap_or_default();
    let other_public_id = db::public_id_of(&st.pool, other_id).await.ok().flatten().unwrap_or_default();
    let rotation_warning: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM key_rotations kr
          WHERE kr.account_id = $1
            AND kr.created_at > (SELECT created_at FROM conversations WHERE id = $2))",
    )
    .bind(other_id)
    .bind(conv_id)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(false);
    let title = format!("Conversation with {other_name}");
    let tpl = ConversationTpl {
        conv_id,
        rotation_warning,
        other_public_id,
        other_name,
        other_fingerprint,
        messages,
        message,
        me: sess.account_id,
        csrf: csrf.to_string(),
    };
    let nav = nav_for_session(st, sess, csrf).await;
    page_with(&nav, &title, tpl.render().unwrap())
}

async fn conversation_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !msg::is_participant(&st.pool, id, sess.account_id).await.unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "No such conversation").into_response();
    }
    conversation_render(&st, &sess, &csrf, id, p.get("msg").cloned()).await
}

#[derive(Deserialize)]
struct SendForm {
    ciphertext: String,
    csrf: String,
}

async fn send_message_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<SendForm>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    if !msg::is_participant(&st.pool, id, sess.account_id).await.unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "No such conversation").into_response();
    }
    // The ciphertext is never re-rendered into the form on failure (§14:
    // rejected plaintext is never echoed). Only the error text returns.
    match msg::send_message(&st.pool, id, sess.account_id, f.ciphertext.as_bytes()).await {
        Ok(()) => Redirect::to(&format!("/conversations/{id}")).into_response(),
        Err(msg::SendError::NoKey) => conversation_render(&st, &sess, &csrf, id, Some("Both parties need a registered identity key before messaging.".into())).await,
        Err(msg::SendError::TooLarge) => conversation_render(&st, &sess, &csrf, id, Some("Message exceeds the 64 KiB limit.".into())).await,
        Err(msg::SendError::Envelope(e)) => {
            let kid = if e == modules_api::EnvelopeError::ExtraRecipient {
                extra_key_id(&st, id, sess.account_id, f.ciphertext.as_bytes()).await
            } else {
                None
            };
            conversation_render(&st, &sess, &csrf, id, Some(msg::envelope_message(&e, kid))).await
        }
        Err(msg::SendError::Db) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not send").into_response(),
    }
}

async fn extra_key_id(st: &AppState, conv_id: i64, sender_id: i64, bytes: &[u8]) -> Option<String> {
    let (recipient_id, _n) = msg::other_participant(&st.pool, conv_id, sender_id).await.ok()??;
    let s = crate::keys::current_key(&st.pool, sender_id).await.ok()??;
    let r = crate::keys::current_key(&st.pool, recipient_id).await.ok()??;
    let ctx = envelope::EnvelopeContext {
        sender: envelope::KeyRef::from_cert(&s.1)?,
        recipient: envelope::KeyRef::from_cert(&r.1)?,
        recipient_retired_shown: vec![],
    };
    envelope::extra_recipient_key_id(bytes, &ctx)
}

async fn message_download(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, mid)): Path<(i64, i64)>,
) -> Response {
    let Some((_t, sess, _c)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !msg::is_participant(&st.pool, id, sess.account_id).await.unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "No such conversation").into_response();
    }
    match msg::message_blob(&st.pool, id, mid).await {
        Some(bytes) => (
            [
                ("content-type", "application/octet-stream"),
                ("content-disposition", "attachment; filename=\"message.asc\""),
                ("x-content-type-options", "nosniff"),
                ("cache-control", "no-store"),
            ],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "No such message").into_response(),
    }
}

async fn conversation_for_order(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(oid): Path<String>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some(o) = ord::order_by_public_id(&st.pool, &oid).await else {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    };
    if o.buyer_id != sess.account_id && o.seller_id != sess.account_id {
        return (StatusCode::NOT_FOUND, "No such order").into_response();
    }
    match msg::find_or_create_for_order(&st.pool, o.id, o.buyer_id, o.seller_id).await {
        Ok(cid) => Redirect::to(&format!("/conversations/{cid}")).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not open conversation").into_response(),
    }
}

async fn conversation_direct(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(aid): Path<String>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some((other_id, ..)) = db::account_by_public_id(&st.pool, &aid).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such account").into_response();
    };
    if other_id == sess.account_id {
        return (StatusCode::BAD_REQUEST, "Cannot message yourself").into_response();
    }
    match msg::find_or_create_direct(&st.pool, sess.account_id, other_id).await {
        Ok(cid) => Redirect::to(&format!("/conversations/{cid}")).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not open conversation").into_response(),
    }
}

async fn send_message_file_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    mut mp: Multipart,
) -> Response {
    let Some((_t, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    if !msg::is_participant(&st.pool, id, sess.account_id).await.unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "No such conversation").into_response();
    }
    let mut csrf_ok = false;
    let mut bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = mp.next_field().await {
        match field.name() {
            Some("csrf") => {
                if let Ok(v) = field.text().await {
                    csrf_ok = sessions::csrf_matches(&csrf, &v);
                }
            }
            Some("ciphertext_file") => {
                if let Ok(b) = field.bytes().await {
                    bytes = Some(b.to_vec());
                }
            }
            _ => {}
        }
    }
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    let Some(bytes) = bytes else {
        return conversation_render(&st, &sess, &csrf, id, Some("No file received.".into())).await;
    };
    match msg::send_message(&st.pool, id, sess.account_id, &bytes).await {
        Ok(()) => Redirect::to(&format!("/conversations/{id}")).into_response(),
        Err(msg::SendError::TooLarge) => conversation_render(&st, &sess, &csrf, id, Some("Message exceeds the 64 KiB limit.".into())).await,
        Err(msg::SendError::NoKey) => conversation_render(&st, &sess, &csrf, id, Some("Both parties need a registered identity key before messaging.".into())).await,
        Err(msg::SendError::Envelope(e)) => {
            let kid = if e == modules_api::EnvelopeError::ExtraRecipient {
                extra_key_id(&st, id, sess.account_id, &bytes).await
            } else {
                None
            };
            conversation_render(&st, &sess, &csrf, id, Some(msg::envelope_message(&e, kid))).await
        }
        Err(msg::SendError::Db) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not send").into_response(),
    }
}

// =====================================================================
// Stage 9: reviews, disputes, reports, moderation, TOTP, closure.
// Guard discipline matches the rest of the file: session + CSRF check,
// then the library call; the route table (authz.rs) declares access.
// =====================================================================

async fn notice_page(st: &AppState, headers: &HeaderMap, title: &str, body: &str) -> Response {
    let body = format!(
        "<h1>{}</h1><p>{}</p><p><a href=\"/\">Home</a> · <a href=\"/account\">Account</a></p>",
        esc(title),
        esc(body)
    );
    page(st, headers, title, body).await
}

async fn guard_post(
    st: &AppState,
    headers: &HeaderMap,
    pattern: &str,
    csrf_given: &str,
) -> Result<(sessions::Session, String), Response> {
    let Some((_t, sess, csrf)) = current_session(st, headers).await else {
        return Err(Redirect::to("/login").into_response());
    };
    // Task 5: every signed-in POST passes the per-account throttle.
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return Err(r);
    }
    let role = role_from_str(&db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into()));
    if authorize("POST", pattern, Some(role)) != Decision::Allow {
        return Err((StatusCode::FORBIDDEN, "Denied").into_response());
    }
    if !sessions::csrf_matches(&csrf, csrf_given) {
        return Err((StatusCode::FORBIDDEN, "CSRF check failed").into_response());
    }
    Ok((sess, csrf))
}

async fn guard_moderator(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<(sessions::Session, String), Response> {
    let Some((_t, sess, csrf)) = current_session(st, headers).await else {
        return Err(Redirect::to("/login").into_response());
    };
    let role = role_from_str(&db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into()));
    if !matches!(role, Role::Moderator | Role::Admin) {
        return Err((StatusCode::FORBIDDEN, "Denied").into_response());
    }
    Ok((sess, csrf))
}

// -- reviews ----------------------------------------------------------------

#[derive(Deserialize)]
struct ReviewForm {
    csrf: String,
    score: String,
    text: String,
}

async fn review_submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ReviewForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/orders/{id}/review", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let score: i32 = f.score.parse().unwrap_or(0);
    match crate::reviews::submit_review(&st.pool, &st.keyfile, &st.stage9, &id, sess.account_id, score, &f.text).await {
        Ok(()) => Redirect::to(&format!("/orders/{id}?msg={}", "Review saved.")).into_response(),
        Err(e) => Redirect::to(&format!("/orders/{id}?msg=Review not saved: {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct ReplyForm {
    csrf: String,
    text: String,
}

async fn review_reply(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ReplyForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/orders/{id}/review/reply", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::reviews::seller_reply(&st.pool, &st.stage9, &id, sess.account_id, &f.text).await {
        Ok(()) => Redirect::to(&format!("/orders/{id}?msg={}", "Reply posted.")).into_response(),
        Err(e) => Redirect::to(&format!("/orders/{id}?msg=Reply not posted: {e:?}")).into_response(),
    }
}

// -- disputes -----------------------------------------------------------------

#[derive(Template)]
#[template(path = "dispute.html")]
struct DisputeTpl {
    csrf: String,
    dispute_id: i64,
    dispute_state: String,
    outcome: Option<String>,
    order_public_id: String,
    listing_title: String,
    buyer_username: String,
    seller_username: String,
    total_xmr: String,
    evidence_label: String,
    terms_hash: String,
    assigned_address: Option<String>,
    signed_message: Option<String>,
    signed_signature: Option<String>,
    disclosures: Vec<crate::disputes::DisclosureView>,
    /// Account Security Audit task 3 (AH1): for a moderator viewer
    /// without a live step-up grant, disclosures are not decrypted
    /// or rendered at all — the page shows the unlock form instead.
    disclosures_locked: bool,
    /// The buyer's submitted tx proof — populated ONLY when the
    /// viewer is a moderator or the buyer party (owner-directed
    /// visibility rule, 2026-10-18). A seller's render never carries
    /// this data.
    buyer_proof: Option<crate::payments::PaymentProof>,
    is_participant: bool,
    is_moderator: bool,
    is_buyer: bool,
    can_disclose: bool,
    show_resolve: bool,
    awaiting_buyer: bool,
    retention_days: i64,
    message: Option<String>,
    totp_enrolled: bool,
}

async fn dispute_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let Some((token, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let role = role_from_str(&db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into()));
    if authorize("GET", "/disputes/{id}", Some(role)) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Denied").into_response();
    }
    let is_moderator = matches!(role, Role::Moderator | Role::Admin);
    let Some(d) = crate::disputes::get_dispute(&st.pool, id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such dispute").into_response();
    };
    let Some(o) = ord::order_by_internal_id(&st.pool, d.order_id).await else {
        return (StatusCode::NOT_FOUND, "No such dispute").into_response();
    };
    let is_participant = o.buyer_id == sess.account_id || o.seller_id == sess.account_id;
    if !is_participant && !is_moderator {
        // Same 404 as a nonexistent dispute (no oracle).
        return (StatusCode::NOT_FOUND, "No such dispute").into_response();
    }
    let buyer_username = db::username_of_id(&st.pool, o.buyer_id).await;
    let seller_username = db::username_of_id(&st.pool, o.seller_id).await;
    let assignment = crate::payments::assignment_for_order(&st.pool, o.id, &st.payments)
        .await
        .ok()
        .flatten();
    // Task 3 (AH1): moderator READS of disclosures need a fresh code.
    // Without a live step-up grant for this session, the disclosures
    // are not even decrypted, let alone rendered. Parties to the
    // dispute keep their existing view (the audit's finding is about
    // moderator sessions specifically).
    let disclosures_locked = is_moderator
        && !crate::moderation::stepup_granted(
            &st.pool,
            &crate::sessions::hash_token(&token),
            sess.account_id,
            "disclosures",
        )
        .await;
    let disclosures = if disclosures_locked {
        Vec::new()
    } else {
        crate::disputes::disclosures_for(&st.pool, &st.keyfile, d.id)
            .await
            .unwrap_or_default()
    };
    let totp_enrolled = crate::moderation::totp_enrolled(&st.pool, sess.account_id)
        .await
        .unwrap_or(false);
    // Visibility rule: moderators and the buyer party see the real
    // evidence label and the submitted proof; the seller party sees
    // the indistinguishable label and no proof data at all.
    let viewer_is_seller_party = is_participant && o.seller_id == sess.account_id;
    let evidence = if viewer_is_seller_party {
        seller_evidence_label(&o.evidence_level)
    } else {
        evidence_label(&o.evidence_level)
    };
    let buyer_proof = if is_moderator || o.buyer_id == sess.account_id {
        crate::payments::payment_proof_for_order(&st.pool, o.id)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let tpl = DisputeTpl {
        csrf,
        dispute_id: d.id,
        dispute_state: d.state.clone(),
        outcome: d.outcome.clone(),
        order_public_id: o.public_id.clone(),
        listing_title: o.listing_title.clone(),
        buyer_username,
        seller_username,
        total_xmr: domain::Atomic(o.total_atomic as u64).format_decimal(),
        evidence_label: evidence,
        buyer_proof,
        terms_hash: o.terms_sha256.clone(),
        assigned_address: assignment.as_ref().map(|a| a.address.clone()),
        signed_message: assignment.as_ref().map(|a| a.message.clone()),
        signed_signature: assignment.as_ref().map(|a| a.signature.clone()),
        disclosures,
        disclosures_locked,
        is_participant,
        is_moderator,
        is_buyer: o.buyer_id == sess.account_id,
        can_disclose: is_participant && d.state == "open",
        show_resolve: is_moderator && d.state == "open",
        awaiting_buyer: d.state == "awaiting_buyer_confirmation",
        retention_days: st.stage9.disclosure_retention_days,
        message: p.get("msg").cloned(),
        totp_enrolled,
    };
    let title = format!("Dispute {}", d.id);
    page(&st, &headers, &title, tpl.render().unwrap()).await
}

#[derive(Deserialize)]
struct UnlockForm {
    csrf: String,
    totp: String,
}

/// Task 3 (AH1): the moderator presents a FRESH TOTP code to unlock
/// disclosure viewing for this session (10 minutes, session-bound —
/// see moderation::grant_stepup). Failed attempts go through the
/// shared gate, so they count toward the lockout.
async fn dispute_unlock(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<UnlockForm>,
) -> Response {
    let Some((token, sess, csrf)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if let Some(r) = st.throttle_or_429(sess.account_id) {
        return r;
    }
    let role = role_from_str(&db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into()));
    if authorize("POST", "/disputes/{id}/unlock", Some(role)) != Decision::Allow {
        return (StatusCode::FORBIDDEN, "Denied").into_response();
    }
    if !sessions::csrf_matches(&csrf, &f.csrf) {
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    match crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        Ok(()) => {
            let _ = crate::moderation::grant_stepup(
                &st.pool,
                &crate::sessions::hash_token(&token),
                sess.account_id,
                "disclosures",
            )
            .await;
            Redirect::to(&format!("/disputes/{id}")).into_response()
        }
        Err(e) => Redirect::to(&format!(
            "/disputes/{id}?msg=Unlock refused: {e:?}. Disclosures stay locked."
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct DisclosureForm {
    csrf: String,
    message: String,
    signature: String,
}

async fn disclosure_submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<DisclosureForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/disputes/{id}/disclosures", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::disputes::submit_disclosure(&st.pool, &st.keyfile, id, sess.account_id, &f.message, &f.signature).await {
        Ok(status) => {
            let note = if status == "verified" {
                "Disclosure recorded: signature verified against the other party's pinned key."
            } else {
                "Disclosure recorded as an unverified claim (signature did not verify against the other party's pinned key)."
            };
            Redirect::to(&format!("/disputes/{id}?msg={note}")).into_response()
        }
        Err(e) => Redirect::to(&format!("/disputes/{id}?msg=Disclosure not accepted: {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct ResolveForm {
    csrf: String,
    outcome: String,
    totp: String,
}

async fn dispute_resolve(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<ResolveForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/disputes/{id}/resolve", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/disputes/{id}?msg=Moderator action refused: {e:?}. Enroll in TOTP on your security page first.")).into_response();
    }
    match crate::disputes::resolve(&st.pool, &st.keyfile, &st.stage9, id, sess.account_id, &f.outcome).await {
        Ok(()) => Redirect::to(&format!("/disputes/{id}?msg={}", "Outcome recorded.")).into_response(),
        Err(e) => Redirect::to(&format!("/disputes/{id}?msg=Resolve failed: {e:?}")).into_response(),
    }
}

async fn dispute_confirm_refund(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/disputes/{id}/confirm-refund", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::disputes::confirm_refund(&st.pool, &st.keyfile, &st.stage9, id, sess.account_id).await {
        Ok(()) => Redirect::to(&format!("/disputes/{id}?msg={}", "Refund confirmed; the dispute is resolved.")).into_response(),
        Err(e) => Redirect::to(&format!("/disputes/{id}?msg=Confirmation failed: {e:?}")).into_response(),
    }
}

// -- reports --------------------------------------------------------------------

#[derive(Deserialize)]
struct ReportForm {
    csrf: String,
    target_kind: String,
    target_id: String,
    category: String,
    reason: String,
}

async fn report_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ReportForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/reports", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::moderation::create_report(&st.pool, sess.account_id, &f.target_kind, &f.target_id, &f.category, &f.reason).await {
        Ok(_) => notice_page(&st, &headers, "Report received", "Thank you — a moderator will review it in the queue. Reports are read by moderators together with the public order and listing record.").await,
        Err(e) => notice_page(&st, &headers, "Report not filed", &format!("The report could not be filed ({e:?}). Check the category and reason and try again.")).await,
    }
}

// -- admin landing ------------------------------------------------------------------
//
// GET /admin is declared ADMIN_ONLY in the authz table (contract §7),
// but no handler existed until 2026-10-17, so the route 404'd for
// everyone — the demo review found admins locked out of a declared
// surface. The landing page links the existing moderation surfaces.
// Anyone who is not an admin gets the identical 404 the missing route
// used to produce: the surface's existence is not leaked by a
// distinguishable response (same convention as media_serve's "No").

async fn admin_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some((_t, sess, _csrf)) = current_session(&st, &headers).await else {
        return (StatusCode::NOT_FOUND, "No").into_response();
    };
    if authorize("GET", "/admin", Some(session_role(&st, sess.account_id).await)) != Decision::Allow {
        return (StatusCode::NOT_FOUND, "No").into_response();
    }
    let body = "<h1>Admin</h1>\
        <p>Instance administration lives on the moderation surfaces:</p><ul>\
        <li><a href=\"/moderation\">Moderation queue</a> — open disputes and reports, account search, listing removal and restore.</li>\
        <li><a href=\"/moderation/sellers\">Seller applications</a> — approve or decline pending seller applications.</li>\
        <li><a href=\"/moderation/accounts\">Accounts</a> — the moderation queue's account view.</li></ul>"
        .to_string();
    page(&st, &headers, "Admin", body).await
}

// -- moderation queue + actions ---------------------------------------------------

/// Stage 10 (L6): a listing looked up from the queue page, carrying
/// exactly what the remove/restore form needs.
struct ListingHitView {
    public_id: String,
    title: String,
    status: String,
    seller_name: String,
}

#[derive(Template)]
#[template(path = "moderation_queue.html")]
struct ModerationQueueTpl {
    csrf: String,
    disputes: Vec<(crate::disputes::Dispute, String, String, String)>,
    reports: Vec<crate::moderation::Report>,
    /// Open auto-review payment flags (tx-proof flow, 2026-10-18).
    payment_flags: Vec<crate::payments::PaymentFlag>,
    accounts: Vec<crate::moderation::AccountHit>,
    query: String,
    listing_query: String,
    listing_hit: Option<ListingHitView>,
    message: Option<String>,
    totp_enrolled: bool,
}

async fn moderation_queue(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let (sess, csrf) = match guard_moderator(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let q = p.get("q").cloned().unwrap_or_default();
    let accounts = if q.trim().is_empty() {
        vec![]
    } else {
        crate::moderation::search_accounts(&st.pool, &q).await.unwrap_or_default()
    };
    // Stage 10 (L6): listing lookup for the remove/restore forms —
    // Stage 9 routed and TOTP-gated the endpoints but the queue page
    // had no form that could reach them.
    let listing_query = p.get("listing").cloned().unwrap_or_default();
    let mut listing_hit = None;
    if !listing_query.trim().is_empty() {
        if let Some(l) = crate::listings::listing_by_public_id(&st.pool, listing_query.trim())
            .await
            .ok()
            .flatten()
        {
            listing_hit = Some(ListingHitView {
                public_id: l.public_id.clone(),
                title: l.title.clone(),
                status: l.status.clone(),
                seller_name: db::username_of_id(&st.pool, l.seller_id).await,
            });
        }
    }
    let tpl = ModerationQueueTpl {
        csrf,
        disputes: crate::disputes::open_disputes(&st.pool).await.unwrap_or_default(),
        reports: crate::moderation::open_reports(&st.pool).await.unwrap_or_default(),
        payment_flags: crate::payments::open_payment_flags(&st.pool).await.unwrap_or_default(),
        accounts,
        query: q,
        listing_query,
        listing_hit,
        message: p.get("msg").cloned(),
        totp_enrolled: crate::moderation::totp_enrolled(&st.pool, sess.account_id).await.unwrap_or(false),
    };
    page(&st, &headers, "Moderation queue", tpl.render().unwrap()).await
}

#[derive(Deserialize)]
struct ModReportForm {
    csrf: String,
    action: String,
    totp: String,
}

async fn report_decide(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<ModReportForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/moderation/reports/{id}", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/moderation?msg=Action refused: {e:?}")).into_response();
    }
    match crate::moderation::report_action(&st.pool, id, sess.account_id, &f.action).await {
        Ok(()) => Redirect::to("/moderation?msg=Report updated.").into_response(),
        Err(e) => Redirect::to(&format!("/moderation?msg=Report action failed: {e:?}")).into_response(),
    }
}

// -- payment review flags (tx-proof flow, 2026-10-18) -------------------------

#[derive(Template)]
#[template(path = "moderation_flag.html")]
struct FlagTpl {
    csrf: String,
    flag: crate::payments::PaymentFlag,
    order_state: String,
    buyer_username: String,
    seller_username: String,
    /// The proof the flag is about — moderators only; this page is
    /// behind guard_moderator, so the data never reaches a seller.
    proof: Option<crate::payments::PaymentProof>,
    dispute_id: Option<i64>,
    totp_enrolled: bool,
    message: Option<String>,
}

async fn flag_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(p): Query<HashMap<String, String>>,
) -> Response {
    let (sess, csrf) = match guard_moderator(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(flag) = crate::payments::payment_flag_by_id(&st.pool, id)
        .await
        .ok()
        .flatten()
    else {
        return (StatusCode::NOT_FOUND, "No such flag").into_response();
    };
    let Some(o) = ord::order_by_internal_id(&st.pool, flag.order_id).await else {
        return (StatusCode::NOT_FOUND, "No such flag").into_response();
    };
    let proof = crate::payments::payment_proof_for_order(&st.pool, o.id)
        .await
        .ok()
        .flatten();
    let dispute_id = crate::disputes::dispute_for_order(&st.pool, o.id)
        .await
        .ok()
        .flatten()
        .map(|d| d.id);
    let tpl = FlagTpl {
        csrf,
        flag,
        order_state: o.state.clone(),
        buyer_username: db::username_of_id(&st.pool, o.buyer_id).await,
        seller_username: db::username_of_id(&st.pool, o.seller_id).await,
        proof,
        dispute_id,
        totp_enrolled: crate::moderation::totp_enrolled(&st.pool, sess.account_id)
            .await
            .unwrap_or(false),
        message: p.get("msg").cloned(),
    };
    page(&st, &headers, "Payment review flag", tpl.render().unwrap()).await
}

async fn flag_decide(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<ModReportForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/moderation/flags/{id}", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/moderation?msg=Action refused: {e:?}")).into_response();
    }
    match crate::moderation::payment_flag_action(&st.pool, id, sess.account_id, &f.action).await {
        Ok(()) => Redirect::to("/moderation?msg=Flag updated.").into_response(),
        Err(e) => Redirect::to(&format!("/moderation?msg=Flag action failed: {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct WarnForm {
    csrf: String,
    reason: String,
    totp: String,
}

async fn account_warn(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<WarnForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/moderation/accounts/{id}/warn", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/moderation?msg=Action refused: {e:?}")).into_response();
    }
    let Some((target_id, ..)) = db::account_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such account").into_response();
    };
    match crate::moderation::warn_account(&st.pool, target_id, sess.account_id, &f.reason).await {
        Ok(()) => Redirect::to("/moderation?msg=Warning recorded.").into_response(),
        Err(e) => Redirect::to(&format!("/moderation?msg=Warn failed: {e:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct TotpOnlyForm {
    csrf: String,
    totp: String,
}

async fn account_close_mod(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<TotpOnlyForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/moderation/accounts/{id}/close", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/moderation?msg=Action refused: {e:?}")).into_response();
    }
    let Some((target_id, ..)) = db::account_by_public_id(&st.pool, &id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "No such account").into_response();
    };
    match crate::moderation::close_account(&st.pool, target_id, sess.account_id, "moderator closure").await {
        Ok(()) => Redirect::to("/moderation?msg=Account closed. Its listings are unpublished and its history remains for counterparties.").into_response(),
        Err(e) => Redirect::to(&format!("/moderation?msg=Closure failed: {e:?}")).into_response(),
    }
}

async fn listing_remove_restore(st: &AppState, headers: &HeaderMap, id: &str, f: &TotpOnlyForm, remove: bool) -> Response {
    let pattern = if remove { "/moderation/listings/{id}/remove" } else { "/moderation/listings/{id}/restore" };
    let (sess, _c) = match guard_post(st, headers, pattern, &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::moderation::require_totp(&st.pool, &st.keyfile, sess.account_id, &f.totp).await {
        return Redirect::to(&format!("/moderation?msg=Action refused: {e:?}")).into_response();
    }
    match crate::moderation::set_listing_removed(&st.pool, id, sess.account_id, remove).await {
        Ok(()) => Redirect::to("/moderation?msg=Listing updated.").into_response(),
        Err(e) => Redirect::to(&format!("/moderation?msg=Listing action failed: {e:?}")).into_response(),
    }
}

async fn listing_remove(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<TotpOnlyForm>,
) -> Response {
    listing_remove_restore(&st, &headers, &id, &f, true).await
}

async fn listing_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<TotpOnlyForm>,
) -> Response {
    listing_remove_restore(&st, &headers, &id, &f, false).await
}

// -- TOTP enrollment + self-service closure ----------------------------------------

#[derive(Deserialize)]
struct TotpBeginForm {
    csrf: String,
    /// Step-up (task 2, AM3): enrollment changes the account's
    /// second factor, so it needs the current passphrase — plus a
    /// current code when TOTP is already on.
    password: Option<String>,
    totp: Option<String>,
}

async fn totp_begin_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TotpBeginForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/account/totp/begin", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(pw) = f.password.as_deref().filter(|p| !p.is_empty()) else {
        return security_page_render(&st, &sess, &f.csrf, Some("Step-up verification failed: enter your current passphrase to start TOTP enrollment.".into()), vec![]).await;
    };
    if let Err(msg) = step_up(&st, &sess, pw, f.totp.as_deref()).await {
        return security_page_render(&st, &sess, &f.csrf, Some(msg), vec![]).await;
    }
    match crate::moderation::totp_begin(&st.pool, &st.keyfile, sess.account_id).await {
        Ok(_) => {
            stepup_notice(&st, sess.account_id, "stepup_totp_enrollment", "TOTP enrollment was started on your account").await;
            security_page_render(&st, &sess, &f.csrf, Some("Enrollment started: enter the code from your authenticator to activate.".into()), vec![]).await
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Could not start enrollment").into_response(),
    }
}

#[derive(Deserialize)]
struct TotpCodeForm {
    csrf: String,
    code: String,
}

async fn totp_confirm_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TotpCodeForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/account/totp/confirm", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::moderation::totp_confirm(&st.pool, &st.keyfile, sess.account_id, &f.code).await {
        Ok(()) => security_page_render(&st, &sess, &f.csrf, Some("Two-factor authentication is on.".into()), vec![]).await,
        Err(_) => security_page_render(&st, &sess, &f.csrf, Some("That code did not verify — enrollment not activated.".into()), vec![]).await,
    }
}

async fn totp_disable_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TotpCodeForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/account/totp/disable", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::moderation::totp_disable(&st.pool, &st.keyfile, sess.account_id, &f.code).await {
        Ok(()) => security_page_render(&st, &sess, &f.csrf, Some("Two-factor authentication is off. Moderator actions are unavailable until you re-enroll.".into()), vec![]).await,
        Err(_) => security_page_render(&st, &sess, &f.csrf, Some("That code did not verify — TOTP unchanged.".into()), vec![]).await,
    }
}

#[derive(Deserialize)]
struct CloseSelfForm {
    csrf: String,
    password: String,
    confirm: String,
}

async fn account_close_self(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CloseSelfForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/account/close", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if f.confirm.trim() != "CLOSE" {
        return security_page_render(&st, &sess, &f.csrf, Some("Type CLOSE to confirm account closure.".into()), vec![]).await;
    }
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    let Some(stored) = stored else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    };
    match st.hash_guard.verify(&f.password, &stored).await {
        Ok(true) => {}
        _ => {
            return security_page_render(&st, &sess, &f.csrf, Some("Passphrase did not verify — account not closed.".into()), vec![]).await;
        }
    }
    match crate::moderation::close_account(&st.pool, sess.account_id, sess.account_id, "self-service closure").await {
        Ok(()) => notice_page(
            &st,
            &headers,
            "Account closed",
            "This account is closed: it can no longer log in, its listings are unpublished, and its reputation history stays visible to past counterparties. Closing an account ends this identity — it does not erase order history, and it cannot be undone from here.",
        )
        .await,
        Err(e) => notice_page(&st, &headers, "Closure failed", &format!("The account could not be closed ({e:?}).")).await,
    }
}

// -- Task 8 (AL4): passphrase change + recovery-code issuance --------------
//
// Before this fix, the ONLY way to change a passphrase was to burn
// the single recovery code through /account/recover — a user who
// merely suspected a leak had to spend their one recovery path.

#[derive(Deserialize)]
struct PassphraseChangeForm {
    csrf: String,
    current_password: String,
    new_password: String,
}

async fn passphrase_change(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<PassphraseChangeForm>,
) -> Response {
    let (sess, _c) = match guard_post(&st, &headers, "/account/passphrase", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // The current session's token: it survives the change; every
    // OTHER session is revoked.
    let Some((token, _, _)) = current_session(&st, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if f.new_password.len() < 12 || crate::passwords::is_common_password(&f.new_password) {
        return security_page_render(&st, &sess, &f.csrf, Some("New passphrase must be at least 12 characters and not a common one.".into()), vec![]).await;
    }
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    let Some(stored) = stored else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    };
    let scope = format!("acct:{}", sess.account_id);
    match st.hash_guard.verify_scoped(&scope, &f.current_password, &stored).await {
        Ok(true) => {}
        Ok(false) => {
            return security_page_render(&st, &sess, &f.csrf, Some("Current passphrase did not verify — passphrase unchanged.".into()), vec![]).await;
        }
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy, retry shortly").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    }
    let hash = match st.hash_guard.hash_scoped(&scope, &f.new_password).await {
        Ok(h) => h,
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy, retry shortly").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    };
    if sqlx::query("UPDATE accounts SET password_hash = $2 WHERE id = $1")
        .bind(sess.account_id)
        .bind(&hash)
        .execute(&st.pool)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    }
    let _ = db::revoke_other_sessions(&st.pool, sess.account_id, &token).await;
    stepup_notice(&st, sess.account_id, "security_passphrase_changed", "your passphrase was changed and all other sessions were signed out").await;
    security_page_render(&st, &sess, &f.csrf, Some("Passphrase changed. All other sessions were signed out.".into()), vec![]).await
}

#[derive(Deserialize)]
struct RecoveryIssueForm {
    csrf: String,
    password: String,
}

/// POST /account/recovery-codes — declared in the route table since
/// §17 but never served until now (AL4). Issuing a code requires the
/// current passphrase, burns every previous unconsumed code, and
/// shows the new code exactly once.
async fn recovery_code_issue(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RecoveryIssueForm>,
) -> Response {
    let (sess, csrf) = match guard_post(&st, &headers, "/account/recovery-codes", &f.csrf).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    let Some(stored) = stored else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    };
    let scope = format!("acct:{}", sess.account_id);
    match st.hash_guard.verify_scoped(&scope, &f.password, &stored).await {
        Ok(true) => {}
        Ok(false) => {
            return security_page_render(&st, &sess, &f.csrf, Some("Passphrase did not verify — no recovery code was issued.".into()), vec![]).await;
        }
        Err(HashError::Busy) => return (StatusCode::SERVICE_UNAVAILABLE, "Busy, retry shortly").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    }
    let code = recovery::new_recovery_code();
    if db::replace_recovery_code(&st.pool, sess.account_id, &code).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response();
    }
    stepup_notice(&st, sess.account_id, "security_recovery_code_issued", "a new recovery code was issued; previous codes no longer work").await;
    // Render the account page with the code shown once (the register
    // flow's presentation).
    let (username,): (String,) = sqlx::query_as("SELECT username FROM accounts WHERE id = $1")
        .bind(sess.account_id)
        .fetch_one(&st.pool)
        .await
        .unwrap_or_else(|_| ("?".into(),));
    let role_s = db::role_of(&st.pool, sess.account_id).await.ok().flatten().unwrap_or_else(|| "buyer".into());
    let (acct_status, _closed_at, warned_at) =
        crate::moderation::account_status(&st.pool, sess.account_id)
            .await
            .unwrap_or(("active".into(), None, None));
    let tpl = AccountTpl {
        username,
        role: role_s,
        recovery_code: Some(code),
        csrf,
        warned_date: warned_at.map(|t| t.date().to_string()),
        account_closed: acct_status == "closed",
    };
    page(&st, &headers, "Account", tpl.render().unwrap()).await
}
