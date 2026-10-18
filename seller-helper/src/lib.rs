//! seller-helper — library core for the Direct Monero Payments v1
//! seller tool.
//!
//! The tool talks ONLY to the seller's local monero-wallet-rpc (see
//! [`rpc`], which enforces a strict method allowlist and loopback-only
//! URLs), pre-generates subaddresses in a dedicated wallet account,
//! signs a one-line binding message for each with the wallet's `sign`
//! method (spend-key signature by the primary address), self-verifies
//! every signature with `verify`, and only then writes the batch file
//! — atomically, byte-exact, all-or-nothing.

pub mod config;
pub mod rpc;

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Label of the dedicated wallet account that holds marketplace
/// subaddresses. Also the account's label as shown in wallet software
/// (the label of an account is the label of its index-0 address).
pub const DEDICATED_ACCOUNT_LABEL: &str = "xmr-direct-marketplace";

/// Format identifier of the batch file, per the v1 handoff.
pub const BATCH_FORMAT: &str = "xmr-direct-batch-v1";

/// Message prefix, per the v1 handoff.
pub const MESSAGE_PREFIX: &str = "xmr-direct-v1";

#[derive(Debug)]
pub enum Error {
    Rpc(rpc::RpcError),
    Validation(String),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rpc(e) => write!(f, "{e}"),
            Error::Validation(m) => write!(f, "{m}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rpc::RpcError> for Error {
    fn from(e: rpc::RpcError) -> Self {
        Error::Rpc(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Build the canonical signed message, byte-exact per the handoff:
/// `xmr-direct-v1|<marketplace_id>|<network>|<seller_id>|<primary_address>|<subaddress>`
/// One line, ASCII only, no trailing newline. Fields are passed
/// through exactly as given — never trimmed or re-encoded.
pub fn build_message(
    marketplace_id: &str,
    network: &str,
    seller_id: &str,
    primary_address: &str,
    subaddress: &str,
) -> String {
    format!(
        "{MESSAGE_PREFIX}|{marketplace_id}|{network}|{seller_id}|{primary_address}|{subaddress}"
    )
}

/// Parse an address with the vetted `monero` crate and return
/// (network name, kind) where network is "mainnet" | "stagenet" |
/// "testnet" and kind is "standard" | "subaddress" | "integrated".
pub fn classify_address(address: &str) -> Result<(&'static str, &'static str), Error> {
    let parsed = monero::Address::from_str(address)
        .map_err(|_| Error::Validation(format!("address {address:?} does not parse")))?;
    let network = match parsed.network {
        monero::Network::Mainnet => "mainnet",
        monero::Network::Stagenet => "stagenet",
        monero::Network::Testnet => "testnet",
    };
    let kind = match parsed.addr_type {
        monero::AddressType::Standard => "standard",
        monero::AddressType::SubAddress => "subaddress",
        monero::AddressType::Integrated(_) => "integrated",
    };
    Ok((network, kind))
}

/// Hard gate used by `generate` before anything is created: the
/// wallet's primary address must be a STANDARD address on the
/// configured network (stagenet addresses start with 5/7, mainnet
/// with 4/8 — the `monero` crate's parse is authoritative here, the
/// prefixes are just the human-visible consequence).
pub fn check_primary_address(primary: &str, expected_network: &str) -> Result<(), Error> {
    let (network, kind) = classify_address(primary)?;
    if kind != "standard" {
        return Err(Error::Validation(format!(
            "wallet primary address is a {kind} address, not a standard address; aborting"
        )));
    }
    if network != expected_network {
        return Err(Error::Validation(format!(
            "wallet is on {network} but the helper is configured for {expected_network}; \
             aborting before creating any subaddress"
        )));
    }
    Ok(())
}

/// Local sanity check applied to every subaddress the wallet returns
/// before it is signed and written: it must parse as a subaddress on
/// the configured network.
pub fn check_subaddress(subaddress: &str, expected_network: &str) -> Result<(), Error> {
    let (network, kind) = classify_address(subaddress)?;
    if kind != "subaddress" {
        return Err(Error::Validation(format!(
            "wallet returned a {kind} address where a subaddress was expected; aborting batch"
        )));
    }
    if network != expected_network {
        return Err(Error::Validation(format!(
            "wallet returned a {network} subaddress but {expected_network} is configured; aborting batch"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchEntry {
    pub subaddress: String,
    pub message: String,
    pub signature: String,
}

/// The batch file the seller uploads to the marketplace. Field order
/// matches the handoff exactly; values are stored byte-for-byte as
/// the wallet returned them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchFile {
    pub format: String,
    pub marketplace_id: String,
    pub network: String,
    pub seller_id: String,
    pub primary_address: String,
    pub entries: Vec<BatchEntry>,
}

/// Write `bytes` to `path` atomically: write to a temp file in the
/// SAME directory, fsync, then rename over the target. A crash never
/// leaves a partial file at `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("out");
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        // Files written through here include the helper config, which
        // carries the wallet RPC login. The temp file is owner-only
        // (0600) from the moment it exists (audit L4): the previous
        // order — write with default permissions, rename, chmod the
        // final path afterwards — left a window in which the secret
        // sat on disk readable by other local users.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug)]
pub struct GenerateOutcome {
    pub primary_address: String,
    pub wallet_version: u32,
    pub account_index: u32,
    pub account_created: bool,
    pub highest_subaddress_index: u32,
    pub batch_path: PathBuf,
    pub count: usize,
}

/// Find the dedicated marketplace account, or create and label it.
///
/// Order: (1) the account index stored in the config after a previous
/// run, if that account still exists in the open wallet AND still
/// carries the dedicated label on its index-0 address (audit L3: the
/// stored index is only a hint from a previous run — a config reused
/// against a different wallet could name a personal account, and
/// marketplace addresses must never be written into an account that
/// is not labelled as the dedicated one); (2) a scan of accounts via
/// `get_address` (the only listing method on the allowlist) looking
/// for the dedicated label on the account's index-0 address;
/// (3) `create_account` with the dedicated label.
fn find_or_create_marketplace_account(
    client: &rpc::RpcClient,
    stored: Option<u32>,
) -> Result<(u32, bool), Error> {
    if let Some(idx) = stored {
        if let Ok(acct) = client.get_address(idx) {
            let label = acct
                .entries
                .iter()
                .find(|e| e.address_index == 0)
                .map(|e| e.label.as_str())
                .unwrap_or("");
            if label == DEDICATED_ACCOUNT_LABEL {
                return Ok((idx, false));
            }
            // Stored index names some other account: do not use it.
            // Fall through to the label scan below.
        }
    }
    // Scan accounts until get_address reports the index out of bound
    // (RPC error code -14 on v0.18.4.3).
    for idx in 0..10_000u32 {
        match client.get_address(idx) {
            Ok(acct) => {
                let label = acct
                    .entries
                    .iter()
                    .find(|e| e.address_index == 0)
                    .map(|e| e.label.as_str())
                    .unwrap_or("");
                if label == DEDICATED_ACCOUNT_LABEL {
                    return Ok((idx, false));
                }
            }
            Err(rpc::RpcError::Rpc { .. }) => break,
            Err(e) => return Err(Error::Rpc(e)),
        }
    }
    let (idx, _addr) = client.create_account(DEDICATED_ACCOUNT_LABEL)?;
    Ok((idx, true))
}

/// The `generate` flow. Aborts the WHOLE batch — writing no file — if
/// anything fails: version sanity, primary-network check, address
/// creation, labelling, signing, or the self-verify of any entry.
pub fn run_generate(
    client: &rpc::RpcClient,
    cfg: &config::Config,
    count: u32,
    out_path: &Path,
) -> Result<GenerateOutcome, Error> {
    if count == 0 {
        return Err(Error::Validation("--count must be at least 1".into()));
    }
    if count > 1000 {
        return Err(Error::Validation("--count must be at most 1000".into()));
    }

    // 1. Sanity: the RPC answers and reports a version.
    let (wallet_version, _release) = client.get_version()?;

    // 2. Primary address (account 0, index 0) and the network gate.
    //    This runs BEFORE any account/subaddress is created.
    let primary = client.get_address(0)?.primary;
    check_primary_address(&primary, &cfg.network)?;

    // 3. Dedicated marketplace account: find or create + label.
    let (account_index, account_created) =
        find_or_create_marketplace_account(client, cfg.marketplace_account_index)?;

    // 4. Create the subaddresses in that account.
    let created = client.create_address(account_index, count)?;
    if created.addresses.len() != count as usize {
        return Err(Error::Validation(format!(
            "wallet created {} subaddresses, expected {count}; aborting batch",
            created.addresses.len()
        )));
    }
    let highest = created.indices.iter().max().copied().unwrap_or(0);

    // 5. Label each new subaddress, validate it locally, build the
    //    message, sign it, and self-verify the signature. Any failure
    //    aborts here, before the batch file exists.
    let label = format!("{MESSAGE_PREFIX}|{}|{}", cfg.marketplace_id, cfg.seller_id);
    let mut entries = Vec::with_capacity(count as usize);
    for (subaddress, minor) in created.addresses.iter().zip(created.indices.iter()) {
        client.label_address(account_index, *minor, &label)?;
        check_subaddress(subaddress, &cfg.network)?;
        let message = build_message(
            &cfg.marketplace_id,
            &cfg.network,
            &cfg.seller_id,
            &primary,
            subaddress,
        );
        if !message.is_ascii() || message.contains('\n') {
            return Err(Error::Validation(
                "internal error: built message is not one ASCII line".into(),
            ));
        }
        let signature = client.sign(&message)?;
        // Byte-exact passthrough, with only a shape sanity check:
        // wallet `sign` on v0.18 returns a 93-char "SigV2…" string.
        if signature.len() != 93 || !signature.starts_with("SigV2") {
            return Err(Error::Validation(format!(
                "wallet returned an unexpected signature shape for {subaddress}; aborting batch"
            )));
        }
        let good = client.verify(&message, &primary, &signature)?;
        if !good {
            return Err(Error::Validation(format!(
                "self-verify FAILED for subaddress {subaddress}; aborting batch, no file written"
            )));
        }
        entries.push(BatchEntry {
            subaddress: subaddress.clone(),
            message,
            signature,
        });
    }

    // 6. Write the batch file atomically (temp file in the target
    //    directory + rename). Values go in exactly as returned.
    let batch = BatchFile {
        format: BATCH_FORMAT.to_string(),
        marketplace_id: cfg.marketplace_id.clone(),
        network: cfg.network.clone(),
        seller_id: cfg.seller_id.clone(),
        primary_address: primary.clone(),
        entries,
    };
    let mut body = serde_json::to_string_pretty(&batch)
        .map_err(|e| Error::Validation(format!("serializing batch failed: {e}")))?;
    body.push('\n');
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_atomic(out_path, body.as_bytes())?;

    Ok(GenerateOutcome {
        primary_address: primary,
        wallet_version,
        account_index,
        account_created,
        highest_subaddress_index: highest,
        batch_path: out_path.to_path_buf(),
        count: batch.entries.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Fixture addresses from stage0-spike/fixtures-wallet/FIXTURES.md
    // (valueless fixture wallets generated with monero-wallet-cli
    // v0.18.4.3 --offline).
    const STAGENET_PRIMARY: &str =
        "58kAS8eiH5R6bjTTgVfsCvVEXKrA6PhJkaCsPsGidQtfQZ98sMKgJXe48TC49BwsofTkG1sWBL3jwJBK7XiZkofKE1AtgdA";
    const STAGENET_SUB1: &str =
        "75r1jA2VfCadHkdZcFGg711xJ9nNXFwV4CEcbiFEvUCXai8tZZ4yQq4Jpfo1iQFwLbhca2hjCh8D5ZtXC8pBpzSvS4KuQmi";
    const STAGENET_SUB2: &str =
        "7A2Mse7F5Jy3FELkdiJNz6Qs2sUYhhR9e7DTxBH5kcApdwAJkGTu97A3S3wSqFQAj9TAzxzbnGer13S9LeSvEMKr7S76sTL";
    const TESTNET_PRIMARY: &str =
        "9swuSAxW2WsVyr6H4uc4hCQ77kQv6pb34RLkp8wtuKQoK3kHYGwtomd6cK5Zj2KyxxHK6jHz4N8EuJT1fwRYUqh64R3wxyf";
    const TESTNET_SUB1: &str =
        "BaQm3viv6hsMjQSbzGEXdZbzNV9bx8tcrAHbtNkF3YgLf6xbeL81KNUUsTeTdLMbkKRPq8YbYo4oLfLM9Ycf2jnH9we3m7h";
    const MAINNET_PRIMARY: &str =
        "41mvUKc5wWo47E9xAaJbMGZZ8hVR35HPWaJ2Jb11rAXMHYPM5MhQPdyjYv6krK3VP5XJp3jiE47JKRFiC2YQ9XjJ46sXs9y";
    const MAINNET_SUB1: &str =
        "87hanmtwEvw3NwpLrLgr3vcZFHc88yQJqSzGx4MPNssLC36ku3zh7fuS67riw1iBP88N7P2gTWvYr81VBLqmyECu99fXNfk";

    #[test]
    fn message_is_byte_exact() {
        let msg = build_message(
            "testmarket",
            "stagenet",
            "seller-1",
            STAGENET_PRIMARY,
            STAGENET_SUB1,
        );
        assert_eq!(
            msg,
            "xmr-direct-v1|testmarket|stagenet|seller-1|\
             58kAS8eiH5R6bjTTgVfsCvVEXKrA6PhJkaCsPsGidQtfQZ98sMKgJXe48TC49BwsofTkG1sWBL3jwJBK7XiZkofKE1AtgdA|\
             75r1jA2VfCadHkdZcFGg711xJ9nNXFwV4CEcbiFEvUCXai8tZZ4yQq4Jpfo1iQFwLbhca2hjCh8D5ZtXC8pBpzSvS4KuQmi"
        );
        assert!(msg.is_ascii());
        assert!(!msg.contains('\n'));
        assert!(!msg.ends_with('\n'));
        assert_eq!(msg.matches('|').count(), 5);
    }

    #[test]
    fn network_and_kind_checks_use_the_monero_crate() {
        assert_eq!(
            classify_address(STAGENET_PRIMARY).unwrap(),
            ("stagenet", "standard")
        );
        assert_eq!(
            classify_address(STAGENET_SUB1).unwrap(),
            ("stagenet", "subaddress")
        );
        assert_eq!(
            classify_address(MAINNET_PRIMARY).unwrap(),
            ("mainnet", "standard")
        );
        assert_eq!(
            classify_address(MAINNET_SUB1).unwrap(),
            ("mainnet", "subaddress")
        );
        assert_eq!(
            classify_address(TESTNET_PRIMARY).unwrap(),
            ("testnet", "standard")
        );
        assert_eq!(
            classify_address(TESTNET_SUB1).unwrap(),
            ("testnet", "subaddress")
        );
        assert!(classify_address("not-an-address").is_err());
        assert!(classify_address("").is_err());

        // The generate gate: right network passes, wrong network aborts.
        assert!(check_primary_address(STAGENET_PRIMARY, "stagenet").is_ok());
        assert!(check_primary_address(MAINNET_PRIMARY, "mainnet").is_ok());
        assert!(check_primary_address(STAGENET_PRIMARY, "mainnet").is_err());
        assert!(check_primary_address(MAINNET_PRIMARY, "stagenet").is_err());
        assert!(check_primary_address(TESTNET_PRIMARY, "stagenet").is_err());
        // A subaddress is not a primary.
        assert!(check_primary_address(STAGENET_SUB1, "stagenet").is_err());
        // Subaddress checks.
        assert!(check_subaddress(STAGENET_SUB1, "stagenet").is_ok());
        assert!(check_subaddress(MAINNET_SUB1, "mainnet").is_ok());
        assert!(check_subaddress(STAGENET_SUB1, "mainnet").is_err());
        assert!(check_subaddress(STAGENET_PRIMARY, "stagenet").is_err());
    }

    #[test]
    fn batch_json_shape_and_field_order() {
        let batch = BatchFile {
            format: BATCH_FORMAT.to_string(),
            marketplace_id: "testmarket".into(),
            network: "stagenet".into(),
            seller_id: "seller-1".into(),
            primary_address: STAGENET_PRIMARY.into(),
            entries: vec![BatchEntry {
                subaddress: STAGENET_SUB1.into(),
                message: build_message(
                    "testmarket",
                    "stagenet",
                    "seller-1",
                    STAGENET_PRIMARY,
                    STAGENET_SUB1,
                ),
                signature: format!("SigV2{}", "a".repeat(88)),
            }],
        };
        let text = serde_json::to_string_pretty(&batch).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["format"], "xmr-direct-batch-v1");
        assert_eq!(v["marketplace_id"], "testmarket");
        assert_eq!(v["network"], "stagenet");
        assert_eq!(v["seller_id"], "seller-1");
        assert_eq!(v["primary_address"], STAGENET_PRIMARY);
        assert_eq!(v["entries"][0]["subaddress"], STAGENET_SUB1);
        assert_eq!(v["entries"][0]["signature"].as_str().unwrap().len(), 93);
        // No extra top-level keys, in the handoff's order. (Checked on
        // the serialized text: serde_json::Value sorts map keys, but
        // struct serialization emits fields in declaration order.)
        assert_eq!(v.as_object().unwrap().len(), 6);
        let order = [
            "\"format\"",
            "\"marketplace_id\"",
            "\"network\"",
            "\"seller_id\"",
            "\"primary_address\"",
            "\"entries\"",
        ];
        let positions: Vec<usize> = order.iter().map(|k| text.find(k).unwrap()).collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "top-level keys out of order in: {text}"
        );
        assert_eq!(v["entries"][0].as_object().unwrap().len(), 3);
        let entry_text = &text[text.find("\"entries\"").unwrap()..];
        let entry_order = ["\"subaddress\"", "\"message\"", "\"signature\""];
        let entry_positions: Vec<usize> = entry_order
            .iter()
            .map(|k| entry_text.find(k).unwrap())
            .collect();
        assert!(entry_positions.windows(2).all(|w| w[0] < w[1]));
        // Round-trips.
        let back: BatchFile = serde_json::from_str(&text).unwrap();
        assert_eq!(back, batch);
    }

    // ---------- Fake wallet RPC server for generate-flow tests. -----
    // Speaks just enough HTTP + JSON-RPC for the allowlisted methods,
    // returning the fixture addresses. NOT a mock of record for real
    // wallet behaviour — the live smoke test covers the real binary.

    struct FakeWallet {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for FakeWallet {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn fake_response_body(method: &str, request: &str, verify_good: bool) -> String {
        let result = match method {
            "get_version" => {
                r#"{"release":true,"version":65565}"#.to_string()
            }
            "get_address" => {
                let account = extract_number(request, "\"account_index\":").unwrap_or(0);
                if account == 0 {
                    format!(
                        r#"{{"address":"{STAGENET_PRIMARY}","addresses":[{{"address":"{STAGENET_PRIMARY}","address_index":0,"label":"Primary account","used":false}}]}}"#
                    )
                } else {
                    return r#"{"jsonrpc":"2.0","id":"0","error":{"code":-14,"message":"account index is out of bound"}}"#
                        .to_string();
                }
            }
            "create_account" => {
                format!(r#"{{"account_index":1,"address":"{STAGENET_SUB1}"}}"#)
            }
            "create_address" => {
                format!(
                    r#"{{"address":"{STAGENET_SUB1}","address_index":1,"address_indices":[1,2],"addresses":["{STAGENET_SUB1}","{STAGENET_SUB2}"]}}"#
                )
            }
            "label_address" => "{}".to_string(),
            "sign" => {
                format!(r#"{{"signature":"SigV2{}"}}"#, "a".repeat(88))
            }
            "verify" => {
                format!(
                    r#"{{"good":{verify_good},"old":false,"signature_type":"spend","version":2}}"#
                )
            }
            _ => {
                return r#"{"jsonrpc":"2.0","id":"0","error":{"code":-32601,"message":"method not found"}}"#
                    .to_string()
            }
        };
        format!(r#"{{"jsonrpc":"2.0","id":"0","result":{result}}}"#)
    }

    fn extract_number(text: &str, key: &str) -> Option<u32> {
        let start = text.find(key)? + key.len();
        let digits: String = text[start..]
            .chars()
            .skip_while(|c| *c == ' ')
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }

    fn start_fake_wallet(verify_good: bool) -> (u16, FakeWallet) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let mut buf: Vec<u8> = Vec::new();
                        let mut chunk = [0u8; 4096];
                        // Read headers, then the Content-Length body.
                        let body_start = loop {
                            match stream.read(&mut chunk) {
                                Ok(0) => break None,
                                Ok(n) => {
                                    buf.extend_from_slice(&chunk[..n]);
                                    if let Some(pos) = buf
                                        .windows(4)
                                        .position(|w| w == b"\r\n\r\n")
                                    {
                                        break Some(pos + 4);
                                    }
                                }
                                Err(_) => break None,
                            }
                        };
                        if let Some(bs) = body_start {
                            let head = String::from_utf8_lossy(&buf[..bs]).to_string();
                            let content_len: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (n, v) = l.split_once(':')?;
                                    if n.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            while buf.len() < bs + content_len {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                    Err(_) => break,
                                }
                            }
                            let request =
                                String::from_utf8_lossy(&buf[bs..]).to_string();
                            let method = request
                                .split("\"method\":\"")
                                .nth(1)
                                .and_then(|s| s.split('"').next())
                                .unwrap_or("")
                                .to_string();
                            let body = fake_response_body(&method, &request, verify_good);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (
            port,
            FakeWallet {
                stop,
                handle: Some(handle),
            },
        )
    }

    fn test_config() -> config::Config {
        config::Config {
            marketplace_id: "testmarket".into(),
            network: "stagenet".into(),
            seller_id: "seller-1".into(),
            rpc_url: "http://127.0.0.1:1/json_rpc".into(),
            rpc_user: "user".into(),
            rpc_password: "pass".into(),
            marketplace_account_index: None,
        }
    }

    fn test_out_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "seller-helper-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_against_fake_wallet_writes_batch() {
        let (port, _fake) = start_fake_wallet(true);
        let client = rpc::RpcClient::new("127.0.0.1", port, "/json_rpc", "", "");
        let dir = test_out_dir("happy");
        let out = dir.join("batch.json");
        let outcome = run_generate(&client, &test_config(), 2, &out).unwrap();
        assert_eq!(outcome.primary_address, STAGENET_PRIMARY);
        assert_eq!(outcome.account_index, 1);
        assert!(outcome.account_created);
        assert_eq!(outcome.highest_subaddress_index, 2);
        assert_eq!(outcome.count, 2);
        let text = std::fs::read_to_string(&out).unwrap();
        let batch: BatchFile = serde_json::from_str(&text).unwrap();
        assert_eq!(batch.format, "xmr-direct-batch-v1");
        assert_eq!(batch.entries.len(), 2);
        assert_eq!(batch.entries[0].subaddress, STAGENET_SUB1);
        assert_eq!(batch.entries[1].subaddress, STAGENET_SUB2);
        assert_eq!(
            batch.entries[0].message,
            build_message(
                "testmarket",
                "stagenet",
                "seller-1",
                STAGENET_PRIMARY,
                STAGENET_SUB1
            )
        );
        assert_eq!(batch.entries[0].signature.len(), 93);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_aborts_without_file_when_verify_fails() {
        let (port, _fake) = start_fake_wallet(false);
        let client = rpc::RpcClient::new("127.0.0.1", port, "/json_rpc", "", "");
        let dir = test_out_dir("verifyfail");
        let out = dir.join("batch.json");
        let result = run_generate(&client, &test_config(), 2, &out);
        assert!(result.is_err(), "self-verify failure must abort the batch");
        assert!(
            !out.exists(),
            "no batch file may be written when self-verify fails"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- Parameterised fake wallet (audit fix-brief tests). --
    // Like the fake above, but the `verify` result's signature_type and
    // account 0's index-0 label are configurable, so the M2/L3 cases can
    // be driven: a wallet reporting a VIEW-key signature, and a stored
    // account index whose label is not the dedicated one.

    struct FakeSpec {
        verify_good: bool,
        verify_sig_type: &'static str,
        acct0_label: &'static str,
    }

    fn fake_response_body_v2(method: &str, request: &str, spec: &FakeSpec) -> String {
        let result = match method {
            "get_version" => {
                r#"{"release":true,"version":65565}"#.to_string()
            }
            "get_address" => {
                let account = extract_number(request, "\"account_index\":").unwrap_or(0);
                if account == 0 {
                    format!(
                        r#"{{"address":"{STAGENET_PRIMARY}","addresses":[{{"address":"{STAGENET_PRIMARY}","address_index":0,"label":"{}","used":false}}]}}"#,
                        spec.acct0_label
                    )
                } else {
                    return r#"{"jsonrpc":"2.0","id":"0","error":{"code":-14,"message":"account index is out of bound"}}"#
                        .to_string();
                }
            }
            "create_account" => {
                format!(r#"{{"account_index":1,"address":"{STAGENET_SUB1}"}}"#)
            }
            "create_address" => {
                format!(
                    r#"{{"address":"{STAGENET_SUB1}","address_index":1,"address_indices":[1,2],"addresses":["{STAGENET_SUB1}","{STAGENET_SUB2}"]}}"#
                )
            }
            "label_address" => "{}".to_string(),
            "sign" => {
                format!(r#"{{"signature":"SigV2{}"}}"#, "a".repeat(88))
            }
            "verify" => {
                format!(
                    r#"{{"good":{},"old":false,"signature_type":"{}","version":2}}"#,
                    spec.verify_good, spec.verify_sig_type
                )
            }
            _ => {
                return r#"{"jsonrpc":"2.0","id":"0","error":{"code":-32601,"message":"method not found"}}"#
                    .to_string()
            }
        };
        format!(r#"{{"jsonrpc":"2.0","id":"0","result":{result}}}"#)
    }

    fn start_fake_wallet_v2(spec: FakeSpec) -> (u16, FakeWallet) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let mut buf: Vec<u8> = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let body_start = loop {
                            match stream.read(&mut chunk) {
                                Ok(0) => break None,
                                Ok(n) => {
                                    buf.extend_from_slice(&chunk[..n]);
                                    if let Some(pos) =
                                        buf.windows(4).position(|w| w == b"\r\n\r\n")
                                    {
                                        break Some(pos + 4);
                                    }
                                }
                                Err(_) => break None,
                            }
                        };
                        if let Some(bs) = body_start {
                            let head = String::from_utf8_lossy(&buf[..bs]).to_string();
                            let content_len: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (n, v) = l.split_once(':')?;
                                    if n.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            while buf.len() < bs + content_len {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                    Err(_) => break,
                                }
                            }
                            let request = String::from_utf8_lossy(&buf[bs..]).to_string();
                            let method = request
                                .split("\"method\":\"")
                                .nth(1)
                                .and_then(|s| s.split('"').next())
                                .unwrap_or("")
                                .to_string();
                            let body = fake_response_body_v2(&method, &request, &spec);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (
            port,
            FakeWallet {
                stop,
                handle: Some(handle),
            },
        )
    }

    /// Audit task 5 (M2): Monero accepts view-key signatures as "good",
    /// but a view key is routinely copied to watch-only wallets and
    /// bookkeeping tools, so a signature the wallet reports as made
    /// with the VIEW key must fail the helper's self-verify and abort
    /// the batch — even when `good` is true.
    #[test]
    fn generate_aborts_without_file_when_verify_reports_view_key() {
        let spec = FakeSpec {
            verify_good: true,
            verify_sig_type: "view",
            acct0_label: "Primary account",
        };
        let (port, _fake) = start_fake_wallet_v2(spec);
        let client = rpc::RpcClient::new("127.0.0.1", port, "/json_rpc", "", "");
        let dir = test_out_dir("viewkey");
        let out = dir.join("batch.json");
        let result = run_generate(&client, &test_config(), 2, &out);
        assert!(
            result.is_err(),
            "a view-key signature must fail self-verify and abort the batch, got {result:?}"
        );
        assert!(
            !out.exists(),
            "no batch file may be written when self-verify rejects the key type"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit task 9 (L3): the account index stored in the config is
    /// only a hint from a previous run. If that account's label is not
    /// the dedicated marketplace label (config reused against another
    /// wallet, account relabelled, ...), the helper must NOT write
    /// marketplace subaddresses into it: it falls back to the label
    /// scan (and, finding no dedicated account here, creates one).
    #[test]
    fn stored_account_index_with_wrong_label_falls_back_to_scan() {
        let spec = FakeSpec {
            verify_good: true,
            verify_sig_type: "spend",
            acct0_label: "Primary account",
        };
        let (port, _fake) = start_fake_wallet_v2(spec);
        let client = rpc::RpcClient::new("127.0.0.1", port, "/json_rpc", "", "");
        let mut cfg = test_config();
        // Stored index 0 exists in this wallet, but it is the primary
        // account — its label is not the dedicated one.
        cfg.marketplace_account_index = Some(0);
        let dir = test_out_dir("wronglabel");
        let out = dir.join("batch.json");
        let outcome = run_generate(&client, &cfg, 2, &out).unwrap();
        assert_eq!(
            outcome.account_index, 1,
            "the unlabelled stored account must not be used; the scan/create path decides"
        );
        assert!(
            outcome.account_created,
            "with no dedicated account found by the scan, a new one is created and labelled"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit task 9 (L4): files written by this tool include the helper
    /// config, which carries the wallet RPC login. They must be
    /// owner-only (0600) from the moment they exist — not written with
    /// default permissions and chmod'ed after the rename, which left
    /// a window with the secret readable on disk.
    #[cfg(unix)]
    #[test]
    fn write_atomic_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_out_dir("atomic-perms");
        let path = dir.join("config.json");
        write_atomic(&path, b"{\"rpc_password\":\"fixture\"}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "helper-written files must be owner-only from creation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
