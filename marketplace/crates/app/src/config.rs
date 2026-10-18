//! Instance configuration and deployment profiles (spec §19; Stage 10).
//!
//! One strict resolver replaces every ad-hoc env read that decides how
//! an instance runs. The rules that matter are all fail-closed:
//!
//! - The default network is **stagenet**, in every profile.
//! - An unrecognised profile or network value is a startup **error**,
//!   never a silent fallback. (Before Stage 10, `INSTANCE_NETWORK`
//!   silently mapped any garbage to stagenet and accepted `mainnet`
//!   with no friction at all; both behaviours are gone.)
//! - **Mainnet** requires two independent deliberate acts: the
//!   Production profile AND `MAINNET_CONFIRM` set to exactly
//!   [`MAINNET_CONFIRM_VALUE`] — case-sensitive, untrimmed. It is
//!   refused in the Development and Demo profiles even with the
//!   confirm string: the hosted demo is stagenet by owner decision
//!   (2026-10-16), and a dev instance holding real-funds addresses
//!   is precisely the accident this module exists to prevent.
//! - Testnet is refused in the Production profile (a production
//!   instance is mainnet-with-confirmation or stagenet, nothing else).
//! - The bind address defaults to loopback in every profile; §19
//!   puts a TLS proxy or Tor in front, never the app itself.
//!
//! Resolution takes an injected getter (`resolve`) so tests and the
//! locked blind suite can exercise the full truth table without
//! touching process env.

use modules_api::Network;

/// The exact `MAINNET_CONFIRM` value. Deliberately a sentence, not a
/// boolean: it cannot be produced by a stray `=1`, a copied dev env
/// file, or an autocomplete.
pub const MAINNET_CONFIRM_VALUE: &str = "I ACCEPT MAINNET REAL FUNDS";

/// Deployment profiles (spec §19). `Demo` is the hosted stagenet demo
/// shape of the §19 HTTPS profile, per the owner's 2026-10-16 demo
/// decision; `Production` is a documented shape in this stage —
/// nothing here flips an instance to mainnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Development,
    Demo,
    Production,
}

impl Profile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Development => "development",
            Profile::Demo => "demo",
            Profile::Production => "production",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// DEPLOY_PROFILE held a value that is not a profile name.
    UnknownProfile(String),
    /// INSTANCE_NETWORK held a value that is not a network name.
    UnknownNetwork(String),
    /// INSTANCE_NETWORK=mainnet without the exact MAINNET_CONFIRM.
    MainnetNotConfirmed,
    /// A network that the selected profile may not run (mainnet
    /// outside Production; testnet inside Production).
    NetworkProfileMismatch,
    /// A recognised variable held an unusable value.
    InvalidValue(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::UnknownProfile(v) => {
                write!(f, "unknown DEPLOY_PROFILE value: {v:?} (expected development, demo, or production)")
            }
            ConfigError::UnknownNetwork(v) => {
                write!(f, "unknown INSTANCE_NETWORK value: {v:?} (expected stagenet, testnet, or mainnet)")
            }
            ConfigError::MainnetNotConfirmed => {
                write!(f, "INSTANCE_NETWORK=mainnet requires MAINNET_CONFIRM to be set to the exact confirmation sentence (see config.rs); refusing to start")
            }
            ConfigError::NetworkProfileMismatch => {
                write!(f, "this network is not permitted in the selected DEPLOY_PROFILE (mainnet requires production; testnet is forbidden in production)")
            }
            ConfigError::InvalidValue(name) => {
                write!(f, "invalid value for {name}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceConfig {
    pub profile: Profile,
    pub network: Network,
    /// MARKETPLACE_ID. Baked into every signed payment message; the
    /// default must never drift ("vespiary-market", owner-approved
    /// 2026-10-15).
    pub marketplace_id: String,
    /// SITE_NAME — shown in the header of every page.
    pub site_name: String,
    /// BIND_ADDR. Loopback by default in every profile.
    pub bind_addr: String,
    /// Plain-HTTP cookie shape (`session`, no Secure attribute).
    /// True ONLY in the Development profile without PRODUCTION_HTTPS;
    /// Demo/Production use `__Host-` Secure cookies.
    pub dev_cookies: bool,
    /// REGISTRATIONS_OPEN.
    pub registrations_open: bool,
    /// SOURCE_URL — where this instance's source code lives (AGPL).
    /// Shown on the /source page and in the footer when set.
    pub source_url: Option<String>,
    /// Build version, reported in the footer and on /limitations.
    pub version: &'static str,
}

impl InstanceConfig {
    /// Resolve from an injected environment getter. `get` returns
    /// the raw value of a variable, or None when unset. No trimming
    /// or case-folding is applied to safety-relevant values.
    pub fn resolve(get: &dyn Fn(&str) -> Option<String>) -> Result<InstanceConfig, ConfigError> {
        let profile = match get("DEPLOY_PROFILE") {
            None => Profile::Development,
            Some(v) => match v.as_str() {
                "development" => Profile::Development,
                "demo" => Profile::Demo,
                "production" => Profile::Production,
                _ => return Err(ConfigError::UnknownProfile(v)),
            },
        };

        let network = match get("INSTANCE_NETWORK") {
            None => Network::Stagenet,
            Some(v) => match v.as_str() {
                "stagenet" => Network::Stagenet,
                "testnet" => Network::Testnet,
                "mainnet" => {
                    if get("MAINNET_CONFIRM").as_deref() != Some(MAINNET_CONFIRM_VALUE) {
                        return Err(ConfigError::MainnetNotConfirmed);
                    }
                    if profile != Profile::Production {
                        return Err(ConfigError::NetworkProfileMismatch);
                    }
                    Network::Mainnet
                }
                _ => return Err(ConfigError::UnknownNetwork(v)),
            },
        };
        if network == Network::Testnet && profile == Profile::Production {
            return Err(ConfigError::NetworkProfileMismatch);
        }

        let marketplace_id = match get("MARKETPLACE_ID") {
            None => "vespiary-market".to_string(),
            Some(v) if !v.is_empty() => v,
            Some(_) => return Err(ConfigError::InvalidValue("MARKETPLACE_ID")),
        };
        let site_name = match get("SITE_NAME") {
            Some(v) if !v.is_empty() => v,
            _ => "Polyculture Markets".to_string(),
        };
        let bind_addr = match get("BIND_ADDR") {
            None => "127.0.0.1:8080".to_string(),
            Some(v) if !v.is_empty() => v,
            Some(_) => return Err(ConfigError::InvalidValue("BIND_ADDR")),
        };
        let dev_cookies =
            profile == Profile::Development && get("PRODUCTION_HTTPS").is_none();
        let registrations_open = match get("REGISTRATIONS_OPEN") {
            None => true,
            Some(v) => match v.as_str() {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => return Err(ConfigError::InvalidValue("REGISTRATIONS_OPEN")),
            },
        };
        let source_url = match get("SOURCE_URL") {
            Some(v) if !v.is_empty() => Some(v),
            _ => None,
        };

        Ok(InstanceConfig {
            profile,
            network,
            marketplace_id,
            site_name,
            bind_addr,
            dev_cookies,
            registrations_open,
            source_url,
            version: env!("CARGO_PKG_VERSION"),
        })
    }

    pub fn from_env() -> Result<InstanceConfig, ConfigError> {
        Self::resolve(&|k| std::env::var(k).ok())
    }

    /// The network name as used in signed statements and on the
    /// Limitations page ("stagenet" / "testnet" / "mainnet").
    pub fn network_name(&self) -> &'static str {
        crate::payments::network_name(self.network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resolve(pairs: &[(&str, &str)]) -> Result<InstanceConfig, ConfigError> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        InstanceConfig::resolve(&|k| map.get(k).cloned())
    }

    #[test]
    fn empty_env_is_dev_stagenet() {
        let c = resolve(&[]).unwrap();
        assert_eq!(c.profile, Profile::Development);
        assert_eq!(c.network, Network::Stagenet);
        assert_eq!(c.marketplace_id, "vespiary-market");
        assert_eq!(c.site_name, "Polyculture Markets");
        assert_eq!(c.bind_addr, "127.0.0.1:8080");
        assert!(c.dev_cookies);
        assert!(c.registrations_open);
        assert_eq!(c.source_url, None);
    }

    #[test]
    fn profiles_parse_exactly() {
        assert_eq!(resolve(&[("DEPLOY_PROFILE", "demo")]).unwrap().profile, Profile::Demo);
        assert_eq!(
            resolve(&[("DEPLOY_PROFILE", "production")]).unwrap().profile,
            Profile::Production
        );
        for bad in ["Demo", "prod", "staging", "", "DEMO", "demo "] {
            assert_eq!(
                resolve(&[("DEPLOY_PROFILE", bad)]),
                Err(ConfigError::UnknownProfile(bad.to_string())),
                "profile {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn network_defaults_and_garbage() {
        assert_eq!(resolve(&[]).unwrap().network, Network::Stagenet);
        assert_eq!(
            resolve(&[("INSTANCE_NETWORK", "testnet")]).unwrap().network,
            Network::Testnet
        );
        for bad in ["main", "MAINNET", "stage", "", "stagenet "] {
            assert_eq!(
                resolve(&[("INSTANCE_NETWORK", bad)]),
                Err(ConfigError::UnknownNetwork(bad.to_string())),
                "network {bad:?} must be refused, not silently mapped"
            );
        }
    }

    #[test]
    fn mainnet_needs_exact_confirm_and_production() {
        // No confirm at all.
        assert_eq!(
            resolve(&[("DEPLOY_PROFILE", "production"), ("INSTANCE_NETWORK", "mainnet")]),
            Err(ConfigError::MainnetNotConfirmed)
        );
        // Near-miss confirms all fail.
        for miss in [
            "yes",
            "true",
            "1",
            "mainnet",
            "i accept mainnet real funds",
            "I ACCEPT MAINNET REAL FUNDS ",
            "I ACCEPT MAINNET REAL FUNDS\n",
        ] {
            assert_eq!(
                resolve(&[
                    ("DEPLOY_PROFILE", "production"),
                    ("INSTANCE_NETWORK", "mainnet"),
                    ("MAINNET_CONFIRM", miss),
                ]),
                Err(ConfigError::MainnetNotConfirmed),
                "confirm {miss:?} must not open mainnet"
            );
        }
        // Exact confirm in the wrong profiles still fails.
        for prof in ["development", "demo"] {
            assert_eq!(
                resolve(&[
                    ("DEPLOY_PROFILE", prof),
                    ("INSTANCE_NETWORK", "mainnet"),
                    ("MAINNET_CONFIRM", MAINNET_CONFIRM_VALUE),
                ]),
                Err(ConfigError::NetworkProfileMismatch),
                "mainnet in {prof} must be refused"
            );
        }
        // The one accepting combination.
        let c = resolve(&[
            ("DEPLOY_PROFILE", "production"),
            ("INSTANCE_NETWORK", "mainnet"),
            ("MAINNET_CONFIRM", MAINNET_CONFIRM_VALUE),
        ])
        .unwrap();
        assert_eq!(c.network, Network::Mainnet);
        assert!(!c.dev_cookies);
    }

    #[test]
    fn testnet_forbidden_in_production_only() {
        assert_eq!(
            resolve(&[("DEPLOY_PROFILE", "production"), ("INSTANCE_NETWORK", "testnet")]),
            Err(ConfigError::NetworkProfileMismatch)
        );
        assert!(resolve(&[("DEPLOY_PROFILE", "demo"), ("INSTANCE_NETWORK", "testnet")]).is_ok());
        // Production stagenet is allowed (the safe direction).
        assert_eq!(
            resolve(&[("DEPLOY_PROFILE", "production")]).unwrap().network,
            Network::Stagenet
        );
    }

    #[test]
    fn cookies_follow_profile_and_legacy_override() {
        assert!(resolve(&[]).unwrap().dev_cookies);
        assert!(!resolve(&[("PRODUCTION_HTTPS", "1")]).unwrap().dev_cookies);
        assert!(!resolve(&[("DEPLOY_PROFILE", "demo")]).unwrap().dev_cookies);
        assert!(!resolve(&[("DEPLOY_PROFILE", "production")]).unwrap().dev_cookies);
    }

    #[test]
    fn registrations_open_strict_parse() {
        assert!(resolve(&[("REGISTRATIONS_OPEN", "1")]).unwrap().registrations_open);
        assert!(resolve(&[("REGISTRATIONS_OPEN", "true")]).unwrap().registrations_open);
        assert!(!resolve(&[("REGISTRATIONS_OPEN", "0")]).unwrap().registrations_open);
        assert!(!resolve(&[("REGISTRATIONS_OPEN", "false")]).unwrap().registrations_open);
        assert_eq!(
            resolve(&[("REGISTRATIONS_OPEN", "yes")]),
            Err(ConfigError::InvalidValue("REGISTRATIONS_OPEN"))
        );
    }

    #[test]
    fn bind_and_ids() {
        let c = resolve(&[("BIND_ADDR", "127.0.0.1:9999"), ("MARKETPLACE_ID", "other-market")])
            .unwrap();
        assert_eq!(c.bind_addr, "127.0.0.1:9999");
        assert_eq!(c.marketplace_id, "other-market");
        assert_eq!(
            resolve(&[("BIND_ADDR", "")]),
            Err(ConfigError::InvalidValue("BIND_ADDR"))
        );
        assert_eq!(
            resolve(&[("MARKETPLACE_ID", "")]),
            Err(ConfigError::InvalidValue("MARKETPLACE_ID"))
        );
        let c = resolve(&[("SOURCE_URL", "https://example.org/src")]).unwrap();
        assert_eq!(c.source_url.as_deref(), Some("https://example.org/src"));
    }
}
