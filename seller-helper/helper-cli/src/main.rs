//! `helper` — the Hidden Trades helper (Alpha spec §14), one
//! program with seller and buyer modes. The v1 seller commands are
//! preserved under seller mode (`helper seller init|generate|check`,
//! see legacy.rs); the Hidden Trades commands run on helper-core:
//!
//!   seller terms    sign a listing's terms statement
//!   seller assign   draw a pool address, sign an assignment + open token
//!   buyer  pin      pin a counterparty's certificate
//!   buyer  verify   run the §14 checks on an assignment before paying
//!   buyer  status   fold every trade in the evidence store
//!   seller status   the same fold, from the seller's store
//!
//! The core commands read the helper config (default
//! ~/.config/xmr-direct-helper/helper.json): marketplace, network,
//! the user's key files, and the evidence store's location. The key
//! passphrase comes from PCM_HELPER_PASSPHRASE or an interactive
//! prompt — never a command-line flag (audit L4's rule, kept).

mod legacy;

use helper_core::seller::{AssignInputs, TermsInputs};
use helper_core::store::{EvidenceStore, PoolLedger};
use helper_core::verify::VerifyInputs;
use helper_core::CoreConfig;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
helper — Hidden Trades helper (Polyculture Markets Alpha)

USAGE:
  helper init --marketplace-id ID --key-file F --cert-file F
                      [--network monero-stagenet] [--store-dir DIR]
                      [--core-config PATH] [--force true]
  helper seller init|generate|check ...   Direct Payments v1 commands
  helper seller terms --listing ID --transit-risk seller|buyer
                      --remedy-cap-pct N --payment-timing prepay|on_ship|on_receipt
                      --title T --description D --delivery-terms X
                      --refund-terms Y --price XMR [--version N]
  helper seller assign --listing ID --buyer FINGERPRINT
                      [--amount-atomic N] [--payment-timing T]
                      [--expires-at TS] [--destination ADDR] [--batch FILE]
  helper seller status
  helper buyer pin <certificate-file>
  helper buyer verify --assignment FILE --terms FILE --terms-text FILE
                      [--seller-cert FILE] [--ceiling N --open-exposure N]
                      [--received-at TS]
  helper buyer status

Core commands take --core-config PATH (default
~/.config/xmr-direct-helper/helper.json). The key passphrase is read
from PCM_HELPER_PASSPHRASE or prompted for — never a flag.

EXIT CODES:
  0  the command succeeded. For the status commands, every trade
     in the evidence store folded clean.
  1  the command itself failed: bad arguments, an unreadable file
     or config, an unreadable evidence store, a refused verify.
  2  status commands only: the status WAS produced, but at least
     one trade's row is an ERROR (for example a held statement
     whose signature does not verify against its signer's pinned
     certificate). The run completed; one or more trades did not.
";

/// Exit code for a run that failed as a run (owner ruling
/// 2026-10-24, E11): every run-level failure — usage errors
/// included — is 1, so that 2 means exactly one thing.
const EXIT_RUN_FAILED: u8 = 1;
/// Exit code for a status run that completed with at least one
/// per-trade ERROR row (owner ruling 2026-10-24, E11).
const EXIT_ROWS_WITH_ERRORS: u8 = 2;

fn fail(e: String) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::from(EXIT_RUN_FAILED)
}

fn core_config(args: &legacy::Args) -> Result<CoreConfig, String> {
    let path = match args.flags.get("core-config") {
        Some(p) => PathBuf::from(p),
        None => helper_core::default_core_config_path(),
    };
    CoreConfig::load(&path)
}

fn passphrase() -> Result<Option<String>, String> {
    if let Ok(p) = std::env::var("PCM_HELPER_PASSPHRASE") {
        return Ok(Some(p));
    }
    if std::io::stdin().is_terminal() {
        let p = legacy::prompt_password("Key passphrase (blank if none)")?;
        return Ok(if p.is_empty() { None } else { Some(p) });
    }
    Ok(None)
}

fn read_file(flag: &str, args: &legacy::Args) -> Result<Vec<u8>, String> {
    let p = args
        .flags
        .get(flag)
        .ok_or_else(|| format!("--{flag} FILE is required"))?;
    std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))
}

fn flag_u64(args: &legacy::Args, flag: &str) -> Result<Option<u64>, String> {
    match args.flags.get(flag) {
        Some(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("--{flag} must be a whole number")),
        None => Ok(None),
    }
}

// -- seller core commands ----------------------------------------------------

fn cmd_seller_terms(args: &legacy::Args) -> Result<(), String> {
    let cfg = core_config(args)?;
    let listing = args
        .flags
        .get("listing")
        .ok_or("terms needs --listing ID")?
        .clone();
    let store = EvidenceStore::open(cfg.store_dir.clone())?;
    let version = match flag_u64(args, "version")? {
        Some(v) => v,
        None => match helper_core::store::load_terms(&store, &listing) {
            Some(saved) => {
                let prev = domain::ht_statements::parse_terms_statement(
                    &saved.statement,
                    &cfg.marketplace_id,
                )
                .ok_or("the saved terms statement no longer parses")?;
                prev.listing_version + 1
            }
            None => 1,
        },
    };
    let price_atomic = match (args.flags.get("price"), flag_u64(args, "price-atomic")?) {
        (Some(decimal), _) => domain::Atomic::parse_decimal(decimal)
            .ok_or("--price is not a valid XMR amount")?
            .0,
        (_, Some(n)) => n,
        _ => return Err("terms needs --price XMR (or --price-atomic N)".to_string()),
    };
    let req = |flag: &str| -> Result<String, String> {
        args.flags
            .get(flag)
            .cloned()
            .ok_or_else(|| format!("terms needs --{flag}"))
    };
    let inputs = TermsInputs {
        marketplace_id: cfg.marketplace_id.clone(),
        listing_id: listing.clone(),
        listing_version: version,
        seller_fingerprint: cfg.own_fingerprint()?,
        title: req("title")?,
        description: req("description")?,
        delivery_terms: req("delivery-terms")?,
        refund_terms: req("refund-terms")?,
        price_atomic,
        transit_risk: domain::ht_statements::TransitRisk::from_statement(&req("transit-risk")?)
            .ok_or("--transit-risk must be seller or buyer")?,
        remedy_cap_pct: flag_u64(args, "remedy-cap-pct")?
            .ok_or("terms needs --remedy-cap-pct N")?,
        payment_timing: domain::ht_statements::PaymentTiming::from_statement(
            &req("payment-timing")?,
        )
        .ok_or("--payment-timing must be prepay, on_ship or on_receipt")?,
    };
    let secret = std::fs::read(&cfg.key_file)
        .map_err(|e| format!("cannot read key file {}: {e}", cfg.key_file.display()))?;
    let signed = helper_core::seller::create_terms(&inputs, &secret, passphrase()?.as_deref())?;
    helper_core::store::save_terms(&store, &listing, &helper_core::seller::saved_terms(&signed))?;
    println!("Terms statement (version {version}) for {listing}:");
    println!();
    print!("{}", signed.statement_text);
    println!();
    println!("Detached signature:");
    println!();
    print!("{}", signed.signature);
    println!();
    println!("Paste both into the listing's terms form on your seller page to pin them.");
    println!("The canonical terms text this statement signs is saved in the evidence store;");
    println!("the listing's fields must match it exactly or the marketplace will refuse the pin.");
    Ok(())
}

fn cmd_seller_assign(args: &legacy::Args) -> Result<(), String> {
    let cfg = core_config(args)?;
    let network = cfg.network_enum().ok_or("helper config network is not a statement network name")?;
    let store = EvidenceStore::open(cfg.store_dir.clone())?;
    let listing = args
        .flags
        .get("listing")
        .ok_or("assign needs --listing ID")?
        .clone();
    let saved = helper_core::store::load_terms(&store, &listing)
        .ok_or("no saved terms for that listing: run `helper seller terms` first")?;
    let terms_stmt = domain::ht_statements::parse_terms_statement(&saved.statement, &cfg.marketplace_id)
        .ok_or("the saved terms statement no longer parses")?;
    let pool_path = cfg.store_dir.join("pool.json");
    // Ledger durability (audit F5): the lock spans load → seed →
    // create_assignment (which marks the address used and saves);
    // load_for_assign refuses a missing ledger over a store that
    // already holds trades, and an unreadable ledger is a hard
    // error — never an empty one.
    let _ledger_lock = helper_core::store::LedgerLock::acquire(&pool_path)?;
    let mut pool = PoolLedger::load_for_assign(&pool_path, &store)?;
    if let Some(batch) = args.flags.get("batch") {
        let raw = std::fs::read(batch).map_err(|e| format!("cannot read batch {batch}: {e}"))?;
        let added = pool.seed_from_batch_json(&raw, &store, &cfg.marketplace_id, network)?;
        println!("Seeded {added} new pool address(es) from the batch file.");
        pool.save(&pool_path)?;
    }
    let amount_atomic = match flag_u64(args, "amount-atomic")? {
        Some(n) => n,
        None => domain::ht_statements::listing_terms_price(&saved.terms_text)
            .ok_or("the saved terms text carries no price")?,
    };
    let expires_at = match args.flags.get("expires-at") {
        Some(ts) => ts.clone(),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            helper_core::canonical_timestamp(now + 30 * 24 * 3600)
                .ok_or("cannot compute a default expiry")?
        }
    };
    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let inputs = AssignInputs {
        marketplace_id: cfg.marketplace_id.clone(),
        network,
        seller_fingerprint: cfg.own_fingerprint()?,
        buyer_fingerprint: args
            .flags
            .get("buyer")
            .ok_or("assign needs --buyer FINGERPRINT")?
            .clone(),
        terms_statement_text: saved.statement.clone(),
        payment_timing: match args.flags.get("payment-timing") {
            Some(t) => Some(
                domain::ht_statements::PaymentTiming::from_statement(t)
                    .ok_or("--payment-timing must be prepay, on_ship or on_receipt")?,
            ),
            None => None,
        },
        amount_atomic,
        expires_at,
        nonce,
    };
    let _ = terms_stmt;
    let secret = std::fs::read(&cfg.key_file)
        .map_err(|e| format!("cannot read key file {}: {e}", cfg.key_file.display()))?;
    let out = helper_core::seller::create_assignment(
        &inputs,
        &secret,
        passphrase()?.as_deref(),
        &store,
        &mut pool,
        &pool_path,
        args.flags.get("destination").map(String::as_str),
    )?;
    println!("Assignment for trade {} ({}):", out.trade_id, out.destination);
    println!();
    print!("{}", out.assignment_text);
    println!();
    println!("Assignment signature:");
    println!();
    print!("{}", out.assignment_sig);
    println!();
    println!("Open token (trade {}):", out.trade_id);
    println!();
    print!("{}", out.open_text);
    println!();
    print!("{}", out.open_sig);
    println!();
    println!("Send the assignment and its signature to the buyer inside your encrypted");
    println!("conversation, and keep the open token for when the trade opens (§8.2).");
    println!("Both are saved in the evidence store under the trade-id.");
    Ok(())
}

/// Run a status command. Returns `Ok(true)` when the status was
/// produced but at least one per-trade row is an ERROR, so the
/// caller can exit with [`EXIT_ROWS_WITH_ERRORS`].
fn cmd_status(args: &legacy::Args) -> Result<bool, String> {
    let cfg = core_config(args)?;
    let network = cfg.network_enum().ok_or("helper config network is not a statement network name")?;
    let store = EvidenceStore::open(cfg.store_dir.clone())?;
    let now = helper_core::now_canonical();
    // N8: a store whose trades directory cannot be read prints an
    // ERROR row for the store — never "No trades in the evidence
    // store", which would report a broken store as an empty one.
    let rows = match helper_core::verify::trade_status(
        &store,
        &cfg.marketplace_id,
        network,
        &now,
        Some(cfg.cert_file.as_path()),
    ) {
        Ok(rows) => rows,
        Err(e) => {
            println!("(evidence store)  ERROR: {e}");
            // E11 (audit 3): a store-level failure is a FAILED
            // command — the row printed but the process exited 0,
            // so a script checking the exit code was told the
            // status succeeded while looking at a broken store.
            // When the store itself cannot be read there is no
            // status to succeed at, so this stays a run failure
            // (exit 1) under the owner ruling below.
            return Err("the evidence store could not be read; no status was produced".into());
        }
    };
    if rows.is_empty() {
        println!("No trades in the evidence store.");
        return Ok(false);
    }
    // E11 (owner ruling 2026-10-24): a per-trade ERROR row (F10)
    // makes the run exit 2. The earlier shape kept exit 0 for
    // these rows on the reasoning that the trade is reported and
    // the rest of the status is real; the owner reversed that —
    // an ERROR row is tamper evidence (a held statement whose
    // signature does not verify is the sharp case) and a script
    // driving the helper must not see success on a tainted run.
    // The status still prints in full; only the code changes.
    let mut saw_error_row = false;
    for (trade_id, row) in rows {
        match row {
            Ok(Some(f)) => {
                println!(
                    "{trade_id}  state={:?}  paid={} shipped={} terminal={}",
                    f.state, f.paid, f.shipped, f.terminal
                );
                if let Some(end) = &f.issue_window_ends {
                    println!("    issue window ends {end}");
                }
                if f.payment_overdue {
                    println!(
                        "    PAYMENT OVERDUE: pay-on-receipt terms, goods shipped, still unpaid past the assignment's payment date"
                    );
                }
                if let Some(r) = f.refund_atomic {
                    println!("    settled refund: {r} atomic");
                }
            }
            Ok(None) => {
                println!("{trade_id}  (no assignment held for this trade)");
            }
            Err(e) => {
                // An unreadable trade is printed as an error, never
                // silently skipped (audit F10).
                println!("{trade_id}  ERROR: {e}");
                saw_error_row = true;
            }
        }
    }
    Ok(saw_error_row)
}

// -- buyer commands ------------------------------------------------------------

fn cmd_buyer_pin(args: &legacy::Args) -> Result<(), String> {
    let cfg = core_config(args)?;
    let store = EvidenceStore::open(cfg.store_dir.clone())?;
    let file = args
        .positional
        .first()
        .ok_or("pin needs a <certificate-file> argument")?;
    let cert = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let fpr = store.pin_cert(&cert)?;
    println!("Pinned {fpr} from {file}.");
    println!("Verify this fingerprint against one the seller published somewhere you trust");
    println!("before relying on it: pinning is the moment trust is decided.");
    Ok(())
}

fn cmd_buyer_verify(args: &legacy::Args) -> Result<(), String> {
    let cfg = core_config(args)?;
    let network = cfg.network_enum().ok_or("helper config network is not a statement network name")?;
    let store = EvidenceStore::open(cfg.store_dir.clone())?;
    let assignment = read_file("assignment", args)?;
    let assignment_sig = match args.flags.get("assignment-sig") {
        Some(p) => String::from_utf8(std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?)
            .map_err(|_| "assignment signature is not text".to_string())?,
        None => {
            let p = format!("{}.sig", args.flags.get("assignment").cloned().unwrap_or_default());
            String::from_utf8(std::fs::read(&p).map_err(|e| format!("cannot read {p}: {e}"))?)
                .map_err(|_| "assignment signature is not text".to_string())?
        }
    };
    let terms_statement = read_file("terms", args)?;
    let terms_sig = match args.flags.get("terms-sig") {
        Some(p) => String::from_utf8(std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?)
            .map_err(|_| "terms signature is not text".to_string())?,
        None => {
            let p = format!("{}.sig", args.flags.get("terms").cloned().unwrap_or_default());
            String::from_utf8(std::fs::read(&p).map_err(|e| format!("cannot read {p}: {e}"))?)
                .map_err(|_| "terms signature is not text".to_string())?
        }
    };
    let terms_text = String::from_utf8(read_file("terms-text", args)?)
        .map_err(|_| "terms text is not text".to_string())?;

    // The seller's certificate: the pin, or an explicitly supplied
    // certificate pinned on first use (TOFU, §14) — pinned ONLY
    // after its fingerprint is computed and matches the one the
    // assignment names (audit F9: the pin write used to happen
    // before the comparison, so a refused verify still left the
    // wrong key pinned while the message claimed "not pinned").
    let fields = helper_core::verify::assignment_fields(
        std::str::from_utf8(&assignment).map_err(|_| "assignment is not text".to_string())?,
    )
    .ok_or("the assignment does not parse")?;
    let seller_cert = match store.pinned_cert(&fields.seller_key_fingerprint) {
        Some(c) => c,
        None => match args.flags.get("seller-cert") {
            Some(p) => {
                let cert = std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
                let fpr = helper_core::keys::fingerprint_of(&cert)
                    .map_err(|e| format!("the supplied certificate is unusable: {e}"))?;
                if fpr != fields.seller_key_fingerprint {
                    return Err(format!(
                        "the supplied certificate is {fpr}, but the assignment names {}: not pinned",
                        fields.seller_key_fingerprint
                    ));
                }
                let pinned = store.pin_cert(&cert)?;
                debug_assert_eq!(pinned, fpr);
                println!("Pinned the seller's key {fpr} on first use. Check it against a");
                println!("fingerprint the seller published somewhere you trust before paying.");
                cert
            }
            None => {
                return Err(format!(
                    "no pinned key for seller {}: pin it first (`helper buyer pin <cert>`), \
                     or pass --seller-cert to pin on first use",
                    fields.seller_key_fingerprint
                ))
            }
        },
    };

    let ceiling = match (flag_u64(args, "ceiling")?, flag_u64(args, "open-exposure")?) {
        (Some(c), Some(e)) => Some((c, e)),
        _ => None,
    };
    let inputs = VerifyInputs {
        assignment: assignment.clone(),
        assignment_sig: assignment_sig.clone(),
        seller_cert,
        own_fingerprint: cfg.own_fingerprint()?,
        marketplace_id: cfg.marketplace_id.clone(),
        network,
        terms_statement,
        terms_sig,
        terms_text,
        now: helper_core::now_canonical(),
        ceiling,
    };
    match helper_core::verify::verify_assignment(&inputs) {
        Ok(v) => {
            // Admission (audit F4): the verified assignment enters
            // the held set through the store's verified door, with
            // the receipt time the buyer recorded (owner decision
            // Q2) when they pass one.
            let expected = helper_core::store::ExpectedSigners {
                seller_fpr: fields.seller_key_fingerprint.clone(),
                buyer_fpr: inputs.own_fingerprint.clone(),
            };
            store.admit_statement(
                &v.trade_id,
                "assignment",
                &assignment,
                &assignment_sig,
                &inputs.seller_cert,
                &expected,
                &cfg.marketplace_id,
                network,
                args.flags.get("received-at").map(String::as_str),
            )?;
            for w in &v.warnings {
                println!("WARNING: {w}");
            }
            let a = &v.assignment;
            println!(
                "Assignment checks passed (signature, terms, destination, amount, expiry). Trade {}",
                v.trade_id
            );
            println!("Pay {} XMR to {}", domain::Atomic(a.amount_atomic).format_decimal(), a.destination.as_str());
            println!("Payment proof message (exact): {}", domain::ht_statements::payment_proof_message(&v.trade_id));
            println!("The assignment is saved in your evidence store. Nothing has been paid yet:");
            println!("pay from your wallet, then keep the transaction proof with this trade-id.");
            Ok(())
        }
        Err(e) => Err(format!(
            "verify REFUSED ({e:?}): do not pay. The refusal names the first failed check of §14."
        )),
    }
}

// -- dispatch ------------------------------------------------------------------

/// Dispatch a core command. The `bool` is the status commands'
/// "at least one per-trade ERROR row" signal (E11); every other
/// command reports `false`.
fn run_core(mode: &str, cmd: &str, args: &legacy::Args) -> Result<bool, String> {
    match (mode, cmd) {
        ("seller", "terms") => cmd_seller_terms(args).map(|()| false),
        ("seller", "assign") => cmd_seller_assign(args).map(|()| false),
        ("seller", "status") => cmd_status(args),
        ("buyer", "pin") => cmd_buyer_pin(args).map(|()| false),
        ("buyer", "verify") => cmd_buyer_verify(args).map(|()| false),
        ("buyer", "status") => cmd_status(args),
        _ => Err(format!("unknown command: {mode} {cmd}")),
    }
}

/// `helper init` (§14, both modes): write the core config the other
/// commands read. The seller-mode `init` of Direct Payments v1 is a
/// different command (`helper seller init`) and is untouched.
fn cmd_init_core(args: &legacy::Args) -> Result<(), String> {
    let path = match args.flags.get("core-config") {
        Some(p) => PathBuf::from(p),
        None => helper_core::default_core_config_path(),
    };
    if path.exists() && args.flags.get("force").map(String::as_str) != Some("true") {
        return Err(format!(
            "a helper config already exists at {}: pass --force to replace it",
            path.display()
        ));
    }
    let req = |flag: &str| -> Result<String, String> {
        args.flags
            .get(flag)
            .cloned()
            .ok_or_else(|| format!("init needs --{flag}"))
    };
    let cfg = helper_core::CoreConfig {
        marketplace_id: req("marketplace-id")?,
        network: args
            .flags
            .get("network")
            .cloned()
            .unwrap_or_else(|| "monero-stagenet".to_string()),
        key_file: PathBuf::from(req("key-file")?),
        cert_file: PathBuf::from(req("cert-file")?),
        store_dir: match args.flags.get("store-dir") {
            Some(p) => PathBuf::from(p),
            None => helper_core::seller_config_dir().join("ht-store"),
        },
    };
    if cfg.network_enum().is_none() {
        return Err(format!(
            "unknown network {:?}: use a statement network name (monero-mainnet, monero-stagenet, monero-testnet)",
            cfg.network
        ));
    }
    let fpr = cfg.own_fingerprint()?;
    cfg.save(&path)?;
    println!("Wrote helper config to {}", path.display());
    println!("Marketplace: {}  Network: {}", cfg.marketplace_id, cfg.network);
    println!("Your key fingerprint (from {}): {fpr}", cfg.cert_file.display());
    println!("Evidence store: {}", cfg.store_dir.display());
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // Exit-code allocation (owner ruling 2026-10-24, E11; see
    // EXIT CODES in the usage text): usage errors are run-level
    // failures and exit 1 — they used to exit 2, which is now
    // reserved for status runs with per-trade ERROR rows.
    if argv.first().map(String::as_str) == Some("init") {
        return match legacy::parse_args(&argv[1..]) {
            Ok(a) => match cmd_init_core(&a) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            },
            Err(e) => {
                eprintln!("error: {e}\n\n{USAGE}");
                ExitCode::from(EXIT_RUN_FAILED)
            }
        };
    }
    let (mode, rest) = match argv.split_first() {
        Some((m, r)) => (m.as_str(), r),
        None => {
            eprint!("{USAGE}");
            return ExitCode::from(EXIT_RUN_FAILED);
        }
    };
    if mode == "--help" || mode == "-h" || mode == "help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if mode != "seller" && mode != "buyer" {
        eprintln!("error: unknown mode {mode:?} (want seller or buyer)\n\n{USAGE}");
        return ExitCode::from(EXIT_RUN_FAILED);
    }
    let (cmd, rest) = match rest.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            eprint!("{USAGE}");
            return ExitCode::from(EXIT_RUN_FAILED);
        }
    };
    let args = match legacy::parse_args(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(EXIT_RUN_FAILED);
        }
    };
    // Legacy v1 seller commands first.
    if mode == "seller" {
        match cmd {
            "init" => {
                return match legacy::cmd_init(&args) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(e),
                }
            }
            "generate" => {
                return match legacy::cmd_generate(&args) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(e),
                }
            }
            "check" => {
                return match legacy::cmd_check(&args) {
                    Ok(code) => ExitCode::from(code as u8),
                    Err(e) => fail(e),
                }
            }
            _ => {}
        }
    }
    match run_core(mode, cmd, &args) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(EXIT_ROWS_WITH_ERRORS),
        Err(e) => fail(e),
    }
}
