//! Helper configuration: where it lives, how it is validated.
//!
//! The config file is the ONLY place the RPC login is stored, it lives
//! on the seller's own machine, and it never contains seeds, wallet
//! passwords or keys — the tool never sees those. It is written with
//! 0600 permissions on Unix.
//!
//! Default location: `~/.config/xmr-direct-helper/config.json`
//! (or `$XDG_CONFIG_HOME/xmr-direct-helper/config.json`). Override with
//! the `--config <path>` flag on any command.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Stable marketplace identifier baked into every signed message.
    pub marketplace_id: String,
    /// `mainnet` or `stagenet`.
    pub network: String,
    /// Seller's stable marketplace ID, `[a-z0-9-]` only.
    pub seller_id: String,
    /// Local wallet RPC URL, e.g. `http://127.0.0.1:28088/json_rpc`.
    /// The host MUST be 127.0.0.1 or localhost; anything else is refused.
    pub rpc_url: String,
    /// RPC login user for the seller's LOCAL monero-wallet-rpc.
    pub rpc_user: String,
    /// RPC login password for the seller's LOCAL monero-wallet-rpc.
    /// Stored only in this local file; never sent anywhere except the
    /// loopback RPC as an HTTP Digest response hash.
    pub rpc_password: String,
    /// Index of the dedicated marketplace account inside the wallet.
    /// Set by `generate` on first run (after it creates and labels the
    /// account) so later runs reuse the same account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marketplace_account_index: Option<u32>,
}

/// A parsed, validated RPC URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        validate_marketplace_id(&self.marketplace_id)?;
        validate_network(&self.network)?;
        validate_seller_id(&self.seller_id)?;
        parse_rpc_url(&self.rpc_url)?;
        if self.rpc_user.is_empty() {
            return Err(
                "rpc_user is empty: the tool requires an RPC login \
                 (start monero-wallet-rpc with --rpc-login user:pass)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub fn validate_marketplace_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("marketplace_id must not be empty".to_string());
    }
    // One field of a `|` joined ASCII message: printable ASCII only,
    // no `|`, no whitespace (whitespace invites copy/paste corruption).
    if !id
        .chars()
        .all(|c| ('!'..='~').contains(&c) && c != '|')
    {
        return Err(format!(
            "marketplace_id {id:?} is invalid: use printable ASCII without spaces or '|'"
        ));
    }
    Ok(())
}

pub fn validate_network(network: &str) -> Result<(), String> {
    match network {
        "mainnet" | "stagenet" => Ok(()),
        other => Err(format!(
            "network {other:?} is invalid: expected \"mainnet\" or \"stagenet\""
        )),
    }
}

pub fn validate_seller_id(seller_id: &str) -> Result<(), String> {
    if seller_id.is_empty() {
        return Err("seller_id must not be empty".to_string());
    }
    if !seller_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "seller_id {seller_id:?} is invalid: only [a-z0-9-] is allowed"
        ));
    }
    Ok(())
}

/// Parse an RPC URL, refusing anything that is not plain HTTP to
/// 127.0.0.1 or localhost. This is a hard rule of the tool: the wallet
/// RPC is local-only, and the HTTP transport here has no TLS, so
/// loopback HTTP is the only supported (and only safe) shape.
pub fn parse_rpc_url(url: &str) -> Result<RpcUrl, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("rpc_url {url:?} is invalid: must start with http:// (loopback RPC only)")
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/json_rpc"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| format!("rpc_url {url:?} has an invalid port"))?;
            (&authority[..i], port)
        }
        None => (authority, 18082),
    };
    let host_lc = host.to_ascii_lowercase();
    if host_lc != "127.0.0.1" && host_lc != "localhost" {
        return Err(format!(
            "rpc_url host {host:?} refused: the wallet RPC must be on 127.0.0.1 or localhost"
        ));
    }
    if path.is_empty() || !path.starts_with('/') || path.contains(|c: char| c.is_whitespace()) {
        return Err(format!("rpc_url {url:?} has an invalid path"));
    }
    Ok(RpcUrl {
        host: host_lc,
        port,
        path: path.to_string(),
    })
}

/// Default config path: `$XDG_CONFIG_HOME/xmr-direct-helper/config.json`
/// or `~/.config/xmr-direct-helper/config.json`.
pub fn default_config_path() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x)
                .join("xmr-direct-helper")
                .join("config.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("xmr-direct-helper")
        .join("config.json")
}

pub fn load_config(path: &std::path::Path) -> Result<Config, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read config {} ({e}); run `seller-helper init` first",
            path.display()
        )
    })?;
    let cfg: Config = serde_json::from_str(&raw)
        .map_err(|e| format!("config {} is not valid: {e}", path.display()))?;
    cfg.validate()?;
    Ok(cfg)
}

pub fn save_config(path: &std::path::Path, cfg: &Config) -> Result<(), String> {
    cfg.validate()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create config directory {}: {e}", parent.display()))?;
    }
    let mut body = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    body.push('\n');
    crate::write_atomic(path, body.as_bytes()).map_err(|e| e.to_string())?;
    // The config holds the local RPC login: restrict it to the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_url(url: &str) -> Config {
        Config {
            marketplace_id: "testmarket".into(),
            network: "stagenet".into(),
            seller_id: "seller-1".into(),
            rpc_url: url.into(),
            rpc_user: "user".into(),
            rpc_password: "pass".into(),
            marketplace_account_index: None,
        }
    }

    #[test]
    fn accepts_loopback_urls() {
        for url in [
            "http://127.0.0.1:18082/json_rpc",
            "http://127.0.0.1:28088/json_rpc",
            "http://localhost:18082/json_rpc",
            "http://LOCALHOST:28088/json_rpc",
            "http://127.0.0.1:18082",
        ] {
            assert!(cfg_with_url(url).validate().is_ok(), "{url}");
        }
        let parsed = parse_rpc_url("http://127.0.0.1:28088/json_rpc").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 28088);
        assert_eq!(parsed.path, "/json_rpc");
    }

    #[test]
    fn refuses_non_localhost_urls() {
        for url in [
            "http://192.168.1.5:18082/json_rpc",
            "http://10.0.0.2:18082/json_rpc",
            "http://example.com:18082/json_rpc",
            "http://127.0.0.2:18082/json_rpc",
            "http://0.0.0.0:18082/json_rpc",
            "https://127.0.0.1:18082/json_rpc",
            "127.0.0.1:18082/json_rpc",
            "http://127.0.0.1.evil.example:18082/json_rpc",
        ] {
            assert!(cfg_with_url(url).validate().is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn validates_ids() {
        assert!(validate_seller_id("seller-1").is_ok());
        assert!(validate_seller_id("abc123").is_ok());
        assert!(validate_seller_id("Seller_1").is_err());
        assert!(validate_seller_id("has space").is_err());
        assert!(validate_seller_id("").is_err());
        assert!(validate_marketplace_id("testmarket").is_ok());
        assert!(validate_marketplace_id("has space").is_err());
        assert!(validate_marketplace_id("has|pipe").is_err());
        assert!(validate_marketplace_id("").is_err());
        assert!(validate_network("mainnet").is_ok());
        assert!(validate_network("stagenet").is_ok());
        assert!(validate_network("testnet").is_err());
        assert!(validate_network("Mainnet").is_err());
    }
}
