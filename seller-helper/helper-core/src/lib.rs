//! helper-core: the library half of the Hidden Trades helper
//! (Alpha build spec §14). It holds everything both modes share —
//! OpenPGP key handling, the evidence store, the buyer's `verify`
//! pipeline, the seller's statement builders, the §6 trade fold
//! (re-exported from the domain crate, the one implementation), and
//! Monero transaction-proof construction and form checks.
//!
//! The core never talks to the marketplace and never touches a
//! node: the only network-shaped thing here is proof FORM (§14:
//! "the helper has no node, so it checks a proof's form only").

pub mod keys;
pub mod proof;
pub mod seller;
pub mod store;
pub mod verify;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The helper's own configuration (§8.3 settings block, helper
/// side): which marketplace and network its statements name, whose
/// key signs, and where the evidence store lives. Distinct from the
/// v1 seller config (wallet RPC login), which stays with the legacy
/// seller commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub marketplace_id: String,
    /// Statement network name: `monero-mainnet` / `monero-stagenet`
    /// / `monero-testnet`.
    pub network: String,
    /// This user's secret key (armored), for signing statements.
    pub key_file: PathBuf,
    /// This user's public certificate (armored).
    pub cert_file: PathBuf,
    /// Evidence store root.
    pub store_dir: PathBuf,
}

impl CoreConfig {
    pub fn network_enum(&self) -> Option<modules_api::Network> {
        modules_api::Network::from_statement_name(&self.network)
    }

    pub fn load(path: &std::path::Path) -> Result<CoreConfig, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read helper config {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("helper config {} is not valid: {e}", path.display()))
    }

    /// The user's own key fingerprint, from their certificate file.
    pub fn own_fingerprint(&self) -> Result<String, String> {
        let cert = std::fs::read(&self.cert_file).map_err(|e| {
            format!("cannot read own certificate {}: {e}", self.cert_file.display())
        })?;
        keys::fingerprint_of(&cert)
    }
}

/// Default location of the core config, beside the v1 config.
pub fn default_core_config_path() -> PathBuf {
    seller_config_dir().join("helper.json")
}

pub fn seller_config_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("xmr-direct-helper");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("xmr-direct-helper")
}

/// Canonical `YYYY-MM-DDTHH:MM:SSZ` for a unix timestamp — the only
/// timestamp shape §5 accepts.
pub fn canonical_timestamp(unix_seconds: i64) -> Option<String> {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix_seconds).ok()?;
    let format = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    dt.format(&format).ok()
}

/// "Now" in the canonical timestamp shape.
pub fn now_canonical() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    canonical_timestamp(secs).unwrap_or_default()
}
