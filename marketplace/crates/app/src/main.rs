use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Stage 10: instance configuration resolves FIRST and fails
    // closed. A bad profile, an unknown network, or an unconfirmed
    // mainnet selection stops startup with the reason — the process
    // never runs under a configuration nobody chose (config.rs).
    let instance = match app::config::InstanceConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:dev@localhost/marketplace_dev".into());
    let pool = PgPoolOptions::new().max_connections(8).connect(&url).await?;
    // Direct Payments v1: the marketplace_id is baked into every signed
    // payment message, so it must be short, stable, and permanent —
    // "vespiary-market" (owner-approved 2026-10-15). It now comes from
    // the instance config (MARKETPLACE_ID remains the override); the
    // network beside it is the profile-resolved one, never a second
    // env read.
    let marketplace_id = instance.marketplace_id.clone();
    let payments = app::payments::PaymentConfig::from_env(&marketplace_id, instance.network);
    // Stage 9: the marketplace key file lives OUTSIDE the database
    // (KEY_FILE_PATH, default ./marketplace.key, mode 0600). It keys
    // buyer tokens and encrypts TOTP secrets + disclosed evidence;
    // back it up separately from the database (docs/operations.md).
    let key_path = std::env::var("KEY_FILE_PATH").unwrap_or_else(|_| "marketplace.key".into());
    let keyfile = app::keyfile::KeyFile::load_or_generate(std::path::Path::new(&key_path))
        .expect("marketplace key file must be readable or creatable");
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
        account_cap: None,
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
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                sweep_cfg.sweep_interval_secs.max(60),
            ));
            loop {
                tick.tick().await;
                match app::payments::expire_unpaid_orders(&sweep_pool, &sweep_cfg).await {
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
                    Ok(out) if out.total() > 0 => println!(
                        "retention: deleted {} notification(s), {} session(s), {} security event(s), {} disclosure(s)",
                        out.notifications, out.sessions, out.security_events, out.disclosures
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
