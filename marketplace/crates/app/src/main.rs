use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Stage 10: instance configuration resolves FIRST and fails
    // closed. A bad profile, an unknown network, or an unconfirmed
    // mainnet selection stops startup with the reason — the process
    // never runs under a configuration nobody chose (config.rs).
    let mut instance = match app::config::InstanceConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    // Account Security Audit AL2 (task 6): outside the Development
    // profile there is NO database fallback. The old silent default
    // (postgres:dev@localhost) meant a mistyped deployment connected
    // to a development database — or failed later in confusing ways.
    // Refuse to start instead.
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            if instance.profile != app::config::Profile::Development {
                eprintln!(
                    "configuration error: DATABASE_URL is not set; refusing to start outside the development profile"
                );
                std::process::exit(2);
            }
            "postgres://postgres:dev@localhost/marketplace_dev".into()
        }
    };
    // Stage 9: the marketplace key file lives OUTSIDE the database
    // (KEY_FILE_PATH, default ./marketplace.key, mode 0600). It keys
    // buyer tokens and encrypts TOTP secrets + disclosed evidence;
    // back it up separately from the database (docs/operations.md).
    //
    // Account Security Audit AL1 (task 6): outside the Development
    // profile the key file must ALREADY exist. Silently minting a
    // replacement (the old behaviour) makes every stored TOTP secret
    // and disclosure undecryptable and changes every buyer token —
    // an operator who notices only that "logins broke" has already
    // lost the data. Refuse to start.
    //
    // The key file is loaded BEFORE the database pool is opened: a
    // refused start must be deterministic (exit 2 on the missing
    // secret itself), never a race against pool connection timing.
    let key_path = std::env::var("KEY_FILE_PATH").unwrap_or_else(|_| "marketplace.key".into());
    let keyfile = if instance.profile != app::config::Profile::Development {
        match app::keyfile::KeyFile::load_existing(std::path::Path::new(&key_path)) {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "configuration error: cannot load marketplace key file at {key_path}: {e}; \
                     refusing to start outside the development profile (a fresh key would \
                     orphan every stored TOTP secret and disclosure)"
                );
                std::process::exit(2);
            }
        }
    } else {
        app::keyfile::KeyFile::load_or_generate(std::path::Path::new(&key_path))
            .expect("marketplace key file must be readable or creatable")
    };
    // HT H1 audit fix task 2 (F1): the Hidden Trades statement
    // identity gets the key file's lifecycle. Unless the operator
    // fixed it via HT_MARKETPLACE_ID, the value `resolve` produced
    // is a fresh generation; it is replaced here by the persisted
    // one — generated and stored on first boot in Development,
    // required to already exist outside it. Minting a replacement
    // silently would orphan every pinned terms statement and every
    // configured helper on the instance: the AL1 failure class,
    // one level up. Loaded before the pool opens, like the key
    // file, so a refused start is deterministic.
    if std::env::var_os("HT_MARKETPLACE_ID").is_none() {
        let id_path = std::env::var("HT_ID_FILE_PATH").unwrap_or_else(|_| "marketplace.htid".into());
        if instance.profile != app::config::Profile::Development {
            match app::htid::load_existing(std::path::Path::new(&id_path)) {
                Ok(id) => instance.ht_marketplace_id = id,
                Err(e) => {
                    eprintln!(
                        "configuration error: cannot load HT marketplace id file at {id_path}: {e}; \
                         refusing to start outside the development profile (a fresh id would \
                         orphan every pinned terms statement)"
                    );
                    std::process::exit(2);
                }
            }
        } else {
            instance.ht_marketplace_id =
                app::htid::load_or_generate(std::path::Path::new(&id_path))
                    .expect("HT marketplace id file must be readable or creatable");
        }
    }
    let pool = PgPoolOptions::new().max_connections(8).connect(&url).await?;
    // Direct Payments v1: the marketplace_id is baked into every signed
    // payment message, so it must be short, stable, and permanent —
    // "vespiary-market" (owner-approved 2026-10-15). It now comes from
    // the instance config (MARKETPLACE_ID remains the override); the
    // network beside it is the profile-resolved one, never a second
    // env read.
    let marketplace_id = instance.marketplace_id.clone();
    let payments = app::payments::PaymentConfig::from_env(&marketplace_id, instance.network);
    // Direct Payments v1 network guard (audit L2): assignment has no
    // network filter, so if this database already holds payment
    // identities or unused pool entries for a DIFFERENT network (the
    // instance was flipped stagenet <-> mainnet on the same database),
    // refuse to start rather than hand out addresses buyers' wallets
    // would reject.
    match app::payments::ensure_network_consistency(&pool, &payments).await {
        Ok(()) => {}
        Err(app::payments::PaymentError::NetworkMismatch {
            identities,
            unused_entries,
        }) => {
            eprintln!(
                "configuration error: stored payment state does not match the instance network ({}): \
                 {identities} payment identit(y/ies) and {unused_entries} unused pool entr(y/ies) \
                 belong to another network. Refusing to start — align the instance network with \
                 the database, or clear the stored payment state deliberately.",
                app::payments::network_name(payments.network)
            );
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("configuration error: payment network guard failed: {e:?}");
            std::process::exit(2);
        }
    }
    let stage9 = app::reputation::Stage9Config::from_env();
    let mut retention = app::retention::RetentionConfig::from_env();
    // The disclosure retention period has ONE source of truth: the
    // Stage 9 config (it is the value the dispute page states to
    // users before they disclose). The retention job follows it.
    retention.disclosures_resolved_days = stage9.disclosure_retention_days;
    {
        // Stage 9: backfill reputation facts for terminal orders that
        // predate the facts pipeline.
        let bp = pool.clone();
        let bk = keyfile.clone();
        let bc = stage9.clone();
        tokio::spawn(async move {
            match app::reputation::backfill_all(&bp, &bk, &bc).await {
                Ok(n) if n > 0 => println!("stage 9: backfilled {n} reputation fact(s)"),
                Ok(_) => {}
                Err(_) => println!("stage 9: fact backfill error"),
            }
        });
    }
    let state = app::web::AppState {
        pool: pool.clone(),
        hash_guard: app::passwords::HashGuard::new(4),
        throttles: Arc::new(app::throttle::Throttles::new()),
        registrations_open: instance.registrations_open,
        // Verification-fix V9: the cap is an operator setting
        // (ACCOUNT_CAP), no longer hard-wired off.
        account_cap: instance.account_cap,
        dev_cookies: instance.dev_cookies,
        media: app::media::MediaPipeline::from_env(),
        marketplace_id,
        payments: payments.clone(),
        keyfile: std::sync::Arc::new(keyfile),
        stage9,
        instance,
        retention: retention.clone(),
    };
    // Direct Payments v1 expiry sweep: minimal in-process interval
    // task. Cancels unpaid direct orders past the configured expiry;
    // their subaddresses retire.
    {
        let sweep_pool = pool.clone();
        let sweep_cfg = payments.clone();
        let sweep_kf = state.keyfile.clone();
        let sweep_rep = state.stage9.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                sweep_cfg.sweep_interval_secs.max(60),
            ));
            loop {
                tick.tick().await;
                match app::payments::expire_unpaid_orders_with_facts(&sweep_pool, &sweep_cfg, &sweep_kf, &sweep_rep).await {
                    Ok(n) if n > 0 => println!("payment expiry sweep: cancelled {n} unpaid order(s)"),
                    Ok(_) => {}
                    Err(_) => println!("payment expiry sweep: error"),
                }
            }
        });
    }
    // Stage 10 retention scheduler (spec §20): the generalised form
    // of the sweep pattern above. Deletes only the categories whose
    // semantics are unambiguous (retention.rs); the rest of §20 is
    // documented as not-yet-built in docs/unverified.md.
    {
        let ret_pool = pool.clone();
        let ret_cfg = retention.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                ret_cfg.interval_secs.max(60),
            ));
            loop {
                tick.tick().await;
                match app::retention::run_retention(&ret_pool, &ret_cfg).await {
                    Ok(out) if out.total() > 0 || out.refunds_reopened > 0 => println!(
                        "retention: deleted {} notification(s), {} session(s), {} security event(s), {} disclosure(s); reopened {} stale refund proposal(s)",
                        out.notifications, out.sessions, out.security_events, out.disclosures, out.refunds_reopened
                    ),
                    Ok(_) => {}
                    Err(_) => println!("retention: error"),
                }
            }
        });
    }
    let bind = state.instance.bind_addr.clone();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!(
        "listening on http://{bind} (profile: {}, network: {})",
        state.instance.profile.as_str(),
        state.instance.network_name()
    );
    axum::serve(listener, app::web::router(state)).await?;
    Ok(())
}
