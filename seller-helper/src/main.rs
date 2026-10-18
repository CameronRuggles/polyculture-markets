//! seller-helper CLI: `init`, `generate --count N`, `check <address>`.
//!
//! The tool talks only to the seller's local monero-wallet-rpc on
//! 127.0.0.1 (see the `rpc` module's allowlist) and writes a batch
//! file the seller uploads to the marketplace by hand. It never asks
//! for, sees, or stores seeds, wallet passwords or keys.

use seller_helper::config::{self, Config};
use seller_helper::rpc::{RpcClient, RpcError};
use seller_helper::{run_generate, Error};
use std::collections::HashMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
seller-helper — Direct Monero Payments v1 seller tool

USAGE:
  seller-helper init [--marketplace-id ID] [--network mainnet|stagenet]
                     [--seller-id ID] [--rpc-url URL]
                     [--rpc-user USER] [--config PATH]
  seller-helper generate --count N [--out FILE] [--config PATH]
  seller-helper check <address> [--config PATH]

init prompts for the wallet RPC password interactively. It is never
accepted as a command-line flag: command lines leak through shell
history and process listings.

The config file (default ~/.config/xmr-direct-helper/config.json) holds
the marketplace values copied from your seller dashboard plus the login
for YOUR local monero-wallet-rpc. It never holds seeds or wallet keys.
";

struct Args {
    flags: HashMap<String, String>,
    positional: Vec<String>,
}

fn parse_args(rest: &[String]) -> Result<Args, String> {
    let mut flags = HashMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let arg = &rest[i];
        if let Some(flag) = arg.strip_prefix("--") {
            if let Some((name, value)) = flag.split_once('=') {
                flags.insert(name.to_string(), value.to_string());
            } else {
                let value = rest
                    .get(i + 1)
                    .ok_or_else(|| format!("flag --{flag} needs a value"))?;
                flags.insert(flag.to_string(), value.clone());
                i += 1;
            }
        } else {
            positional.push(arg.clone());
        }
        i += 1;
    }
    Ok(Args { flags, positional })
}

fn config_path(args: &Args) -> PathBuf {
    match args.flags.get("config") {
        Some(p) => PathBuf::from(p),
        None => config::default_config_path(),
    }
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}: ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("prompt failed: {e}"))?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading input failed: {e}"))?;
    Ok(line.trim().to_string())
}

/// A value comes from the flag if given, else an interactive prompt,
/// else (non-interactive stdin) a clear error naming the missing flag.
fn value_or_prompt(
    args: &Args,
    flag: &str,
    label: &str,
    interactive: bool,
) -> Result<String, String> {
    if let Some(v) = args.flags.get(flag) {
        if !v.is_empty() {
            return Ok(v.clone());
        }
    }
    if interactive {
        let v = prompt(label)?;
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(format!(
        "missing --{flag} (no value given and no interactive terminal to prompt on)"
    ))
}

/// Turns terminal echo off while a password is read (best effort via
/// `stty`; if that is unavailable the prompt still works, just with
/// echo) and restores it on drop — including on read errors.
#[cfg(unix)]
struct EchoOff;

#[cfg(unix)]
impl EchoOff {
    fn engage() -> Self {
        let _ = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status();
        EchoOff
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
    }
}

/// Prompt for a secret: like `prompt`, but with terminal echo off.
fn prompt_password(label: &str) -> Result<String, String> {
    print!("{label}: ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("prompt failed: {e}"))?;
    let read = {
        #[cfg(unix)]
        let _echo = EchoOff::engage();
        let stdin = std::io::stdin();
        let mut line = String::new();
        let r = stdin.lock().read_line(&mut line);
        r.map(|_| line.trim().to_string())
    };
    println!();
    read.map_err(|e| format!("reading input failed: {e}"))
}

/// The RPC password comes from an interactive prompt ONLY (audit L4).
/// The old `--rpc-password` flag put the password into shell history
/// and process listings, so the flag is refused outright — scripts
/// that still pass it get a clear error, not a silent prompt.
fn rpc_password_value(args: &Args, interactive: bool) -> Result<String, String> {
    if args.flags.contains_key("rpc-password") {
        return Err(
            "--rpc-password is not accepted: a password on the command line leaks \
             through shell history and process listings. Run `seller-helper init` \
             in a terminal and it will prompt for the password instead."
                .to_string(),
        );
    }
    if interactive {
        let v = prompt_password("Wallet RPC login password (your --rpc-login password)")?;
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(
        "missing wallet RPC password: it is only ever read from an interactive \
         prompt, so run init in a terminal"
            .to_string(),
    )
}

fn cmd_init(args: &Args) -> Result<(), String> {
    let interactive = std::io::stdin().is_terminal();
    let cfg = Config {
        marketplace_id: value_or_prompt(args, "marketplace-id", "Marketplace ID (from your seller dashboard)", interactive)?,
        network: value_or_prompt(args, "network", "Network (mainnet or stagenet)", interactive)?,
        seller_id: value_or_prompt(args, "seller-id", "Seller ID (from your seller dashboard)", interactive)?,
        rpc_url: value_or_prompt(args, "rpc-url", "Wallet RPC URL (e.g. http://127.0.0.1:28088/json_rpc)", interactive)?,
        rpc_user: value_or_prompt(args, "rpc-user", "Wallet RPC login user (your --rpc-login user)", interactive)?,
        rpc_password: rpc_password_value(args, interactive)?,
        marketplace_account_index: None,
    };
    cfg.validate()?;
    let path = config_path(args);
    config::save_config(&path, &cfg)?;
    println!("Saved helper config to {}", path.display());
    println!();
    println!("Notes:");
    println!("- The config stores your LOCAL wallet RPC login so the tool can");
    println!("  talk to your wallet. It is written with owner-only permissions");
    println!("  (0600). It contains no seed, no wallet password and no keys —");
    println!("  this tool never asks for those.");
    println!("- The RPC login stays on this machine. The marketplace never");
    println!("  sees it.");
    println!();
    println!("Next: start monero-wallet-rpc on 127.0.0.1 with --rpc-login, open");
    println!("your wallet in it, then run: seller-helper generate --count 20");
    Ok(())
}

fn load_and_client(args: &Args) -> Result<(Config, PathBuf, RpcClient), String> {
    let path = config_path(args);
    let cfg = config::load_config(&path)?;
    let client = RpcClient::from_config(&cfg).map_err(|e| e.to_string())?;
    Ok((cfg, path, client))
}

fn cmd_generate(args: &Args) -> Result<(), String> {
    let count_raw = args
        .flags
        .get("count")
        .ok_or_else(|| "generate needs --count N".to_string())?;
    let count: u32 = count_raw
        .parse()
        .map_err(|_| format!("--count {count_raw:?} is not a number"))?;
    let (mut cfg, path, client) = load_and_client(args)?;
    let out = match args.flags.get("out") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(format!("xmr-direct-batch-{}.json", cfg.seller_id)),
    };
    let outcome = run_generate(&client, &cfg, count, &out).map_err(|e| match e {
        Error::Validation(m) => m,
        other => other.to_string(),
    })?;
    // Remember the dedicated account index for the next run.
    if cfg.marketplace_account_index != Some(outcome.account_index) {
        cfg.marketplace_account_index = Some(outcome.account_index);
        config::save_config(&path, &cfg)?;
    }
    println!(
        "Wallet RPC OK (monero-wallet version {}, config network {}).",
        outcome.wallet_version, cfg.network
    );
    println!("Primary address: {}", outcome.primary_address);
    println!(
        "Marketplace account: index {} ({})",
        outcome.account_index,
        if outcome.account_created {
            "created and labelled \"xmr-direct-marketplace\""
        } else {
            "existing dedicated account"
        }
    );
    println!(
        "Wrote {} signed subaddresses to {}",
        outcome.count,
        outcome.batch_path.display()
    );
    println!(
        "Every signature was self-verified against your primary address before writing."
    );
    println!();
    println!(
        "RESTORE WARNING: the highest subaddress index used in the marketplace \
         account is {}. Wallets only scan a limited number of subaddresses ahead \
         after a restore from seed (monero-wallet v0.18 scans 200 subaddresses \
         ahead per account by default). If you ever restore this wallet from its \
         seed, raise the wallet's subaddress lookahead (--subaddress-lookahead / \
         wallet setting) to at least {} BEFORE restoring, so no marketplace \
         subaddress is missed.",
        outcome.highest_subaddress_index, outcome.highest_subaddress_index
    );
    println!();
    println!("Next: upload the batch file in your seller dashboard.");
    Ok(())
}

fn cmd_check(args: &Args) -> Result<i32, String> {
    let address = args
        .positional
        .first()
        .ok_or_else(|| "check needs an <address> argument".to_string())?;
    let (_cfg, _path, client) = load_and_client(args)?;
    match client.get_address_index(address) {
        Ok((major, minor)) => {
            println!("{address}");
            println!(
                "belongs to this wallet: account {major}, subaddress index {minor}"
            );
            Ok(0)
        }
        Err(RpcError::Rpc { code, message }) => {
            println!("{address}");
            println!("not in this wallet (wallet RPC: {code} {message})");
            Ok(1)
        }
        Err(e) => {
            eprintln!("check failed: {e}");
            Ok(1)
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match argv.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if cmd == "--help" || cmd == "-h" || cmd == "help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match parse_args(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match cmd {
        "init" => match cmd_init(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        "generate" => match cmd_generate(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        "check" => match cmd_check(&args) {
            Ok(code) => ExitCode::from(code as u8),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        other => {
            eprintln!("error: unknown command {other:?}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
