//! The evidence store (§14): each party keeps every statement of
//! every trade, the pins for counterparties' keys, and (seller side)
//! the local address-pool ledger. Plain files under one directory —
//! statements as the exact bytes held (plus their detached
//! signatures), a payment record as JSON — so the store is
//! inspectable and backable-up with ordinary tools, and so the fold
//! can be recomputed by hand.
//!
//! Layout:
//! ```text
//! <root>/pins/<FINGERPRINT>.asc        pinned certificates
//! <root>/pool.json                     seller pool ledger
//! <root>/trades/<trade-id>/00-assignment.txt (+ .sig)
//! <root>/trades/<trade-id>/01-shipped.txt    (+ .sig)  ...
//! <root>/trades/<trade-id>/NN-payment.json
//! ```
//! Event files carry a sequence prefix: the fold replays them in
//! held order (§6), which is the order statements arrived or were
//! made.

use domain::ht_fold::{PaymentRecord, TradeEvent};
use domain::ht_statements;
use modules_api::Network;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct EvidenceStore {
    root: PathBuf,
}

/// The on-disk shape of a payment record (the domain type carries
/// no serde derives; this is the store's own serialisation).
#[derive(Debug, Serialize, Deserialize)]
struct PaymentJson {
    txid: String,
    proof: String,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("path has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), path.file_name().and_then(|n| n.to_str()).unwrap_or("f")));
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot store {}: {e}", path.display()))?;
    Ok(())
}

impl EvidenceStore {
    pub fn open(root: PathBuf) -> Result<EvidenceStore, String> {
        std::fs::create_dir_all(root.join("pins"))
            .and_then(|_| std::fs::create_dir_all(root.join("trades")))
            .map_err(|e| format!("cannot create evidence store: {e}"))?;
        Ok(EvidenceStore { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // -- pins ------------------------------------------------------

    /// Pin a certificate under its own fingerprint; returns the
    /// fingerprint. Pinning is explicit (§14): a key change is a
    /// decision, not an accident of a later verify.
    pub fn pin_cert(&self, cert_bytes: &[u8]) -> Result<String, String> {
        let fpr = crate::keys::fingerprint_of(cert_bytes)?;
        write_atomic(&self.root.join("pins").join(format!("{fpr}.asc")), cert_bytes)?;
        Ok(fpr)
    }

    pub fn pinned_cert(&self, fingerprint: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join("pins").join(format!("{fingerprint}.asc"))).ok()
    }

    // -- trade events ----------------------------------------------

    pub fn trade_dir(&self, trade_id: &str) -> PathBuf {
        self.root.join("trades").join(trade_id)
    }

    fn next_seq(&self, trade_id: &str) -> Result<usize, String> {
        let dir = self.trade_dir(trade_id);
        let mut n = 0;
        if dir.exists() {
            for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some((seq, _)) = name.split_once('-') {
                    if let Ok(v) = seq.parse::<usize>() {
                        n = n.max(v + 1);
                    }
                }
            }
        }
        Ok(n)
    }

    /// Save a signed statement as the trade's next held event.
    pub fn save_statement(
        &self,
        trade_id: &str,
        kind: &str,
        statement: &[u8],
        signature: Option<&str>,
    ) -> Result<(), String> {
        let seq = self.next_seq(trade_id)?;
        let base = self.trade_dir(trade_id).join(format!("{seq:02}-{kind}"));
        write_atomic(&base.with_extension("txt"), statement)?;
        if let Some(sig) = signature {
            write_atomic(&base.with_extension("sig"), sig.as_bytes())?;
        }
        Ok(())
    }

    /// Save the buyer's payment record as the trade's next held
    /// event (§6 rule 1: the fold's payment leg).
    pub fn save_payment(&self, trade_id: &str, record: &PaymentRecord) -> Result<(), String> {
        let seq = self.next_seq(trade_id)?;
        let path = self
            .trade_dir(trade_id)
            .join(format!("{seq:02}-payment.json"));
        let json = serde_json::to_string_pretty(&PaymentJson {
            txid: record.txid.clone(),
            proof: record.proof.clone(),
        })
        .map_err(|e| e.to_string())?;
        write_atomic(&path, json.as_bytes())
    }

    /// All trade ids with a store directory, sorted.
    pub fn trade_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.root.join("trades")) {
            for entry in rd.flatten() {
                if entry.path().is_dir() {
                    ids.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        ids.sort();
        ids
    }

    /// Load a trade's held events in held order, parsed with the
    /// domain parsers. A stored file that no longer parses is
    /// corruption the caller must hear about — never a silent skip.
    pub fn load_events(
        &self,
        trade_id: &str,
        marketplace_id: &str,
        network: Network,
    ) -> Result<Vec<TradeEvent>, String> {
        let dir = self.trade_dir(trade_id);
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("cannot read trade store: {e}"))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".txt") || name.ends_with("-payment.json") {
                files.push(entry.path());
            }
        }
        files.sort();
        let mut events = Vec::new();
        for path in files {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let kind = name
                .split_once('-')
                .map(|(_, k)| k.to_string())
                .unwrap_or_default();
            let raw = std::fs::read(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
            let bad = |what: &str| format!("stored {what} in {name} no longer parses");
            let event = match kind.as_str() {
                "assignment.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("assignment"))?;
                    let a = ht_statements::parse_assignment_statement(&text, marketplace_id, network)
                        .ok_or_else(|| bad("assignment"))?;
                    TradeEvent::Assignment(a)
                }
                "ack.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("ack"))?;
                    TradeEvent::Ack(
                        ht_statements::parse_ack_statement(&text, marketplace_id)
                            .ok_or_else(|| bad("ack"))?,
                    )
                }
                "shipped.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("shipped"))?;
                    TradeEvent::Shipped(
                        ht_statements::parse_shipped_statement(&text, marketplace_id)
                            .ok_or_else(|| bad("shipped"))?,
                    )
                }
                "issue.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("issue"))?;
                    TradeEvent::Issue(
                        ht_statements::parse_issue_statement(&text, marketplace_id)
                            .ok_or_else(|| bad("issue"))?,
                    )
                }
                "settle.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("settle"))?;
                    TradeEvent::Settle(
                        ht_statements::parse_settle_statement(&text, marketplace_id)
                            .ok_or_else(|| bad("settle"))?,
                    )
                }
                "receipt.txt" => {
                    let text = String::from_utf8(raw).map_err(|_| bad("receipt"))?;
                    TradeEvent::Receipt(
                        ht_statements::parse_receipt_statement(&text, marketplace_id)
                            .ok_or_else(|| bad("receipt"))?,
                    )
                }
                "payment.json" => {
                    let record: PaymentJson =
                        serde_json::from_slice(&raw).map_err(|_| bad("payment record"))?;
                    TradeEvent::Payment(PaymentRecord {
                        txid: record.txid,
                        proof: record.proof,
                    })
                }
                _ => continue,
            };
            events.push(event);
        }
        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// The seller's local pool ledger (§17 invariant (8), H1 text): the
// helper tracks which subaddresses it has handed out — an address is
// marked used at assignment time, with the trade it went to, and is
// never handed out again.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolEntry {
    pub address: String,
    pub trade_id: Option<String>,
    /// The batch entry's wallet message + signature, kept verbatim
    /// (§19: the ledger keeps the existing `xmr-direct-v1` wallet
    /// signature for every pool entry, so a later wallet-signed
    /// destination attestation stays possible).
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolLedger {
    pub entries: Vec<PoolEntry>,
}

#[derive(Debug, Deserialize)]
struct BatchFileIn {
    entries: Vec<BatchEntryIn>,
}

#[derive(Debug, Deserialize)]
struct BatchEntryIn {
    subaddress: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

impl PoolLedger {
    pub fn load(path: &Path) -> PoolLedger {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => PoolLedger::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(path, json.as_bytes())
    }

    /// Seed unused addresses from a v1 signed-batch file (the
    /// seller's `generate` output): every subaddress in the batch
    /// that the ledger does not already know is added unused.
    /// Returns how many were added.
    pub fn seed_from_batch_json(&mut self, batch_json: &[u8]) -> Result<usize, String> {
        let batch: BatchFileIn =
            serde_json::from_slice(batch_json).map_err(|e| format!("batch file does not parse: {e}"))?;
        let mut added = 0;
        for entry in batch.entries {
            if !self.entries.iter().any(|e| e.address == entry.subaddress) {
                self.entries.push(PoolEntry {
                    address: entry.subaddress,
                    trade_id: None,
                    message: entry.message,
                    signature: entry.signature,
                });
                added += 1;
            }
        }
        Ok(added)
    }

    pub fn is_used(&self, address: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.address == address && e.trade_id.is_some())
    }

    pub fn unused_count(&self) -> usize {
        self.entries.iter().filter(|e| e.trade_id.is_none()).count()
    }

    /// The next unused address, unmarked — marking happens only
    /// once the assignment holding it exists (mark at signing).
    pub fn peek_unused(&self) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.trade_id.is_none())
            .map(|e| e.address.as_str())
    }

    /// Mark an address used for a trade. Refuses an address the
    /// ledger does not hold, and any address already used — the
    /// one-assignment-per-address rule is enforced here, at the
    /// only place assignments draw addresses from.
    pub fn mark_used(&mut self, address: &str, trade_id: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.address == address)
            .ok_or_else(|| "address is not in the local pool ledger".to_string())?;
        if entry.trade_id.is_some() {
            return Err(format!(
                "address already used for trade {}",
                entry.trade_id.as_deref().unwrap_or_default()
            ));
        }
        entry.trade_id = Some(trade_id.to_string());
        Ok(())
    }

    /// Add a single address (the one-off path, §14 `assign
    /// --destination`); refuses a duplicate.
    pub fn add(&mut self, address: &str) -> Result<(), String> {
        if self.entries.iter().any(|e| e.address == address) {
            return Err("address is already in the local pool ledger".to_string());
        }
        self.entries.push(PoolEntry {
            address: address.to_string(),
            trade_id: None,
            message: None,
            signature: None,
        });
        Ok(())
    }
}

/// Saved terms statements, per listing (seller side): the helper
/// remembers the last terms it signed for a listing so the next
/// version number and the assignment's defaults come from the
/// seller's own record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedTerms {
    pub statement: String,
    pub signature: String,
    pub terms_text: String,
}

pub fn save_terms(store: &EvidenceStore, listing_id: &str, saved: &SavedTerms) -> Result<(), String> {
    let path = store.root().join("terms").join(format!("{listing_id}.json"));
    let json = serde_json::to_string_pretty(saved).map_err(|e| e.to_string())?;
    write_atomic(&path, json.as_bytes())
}

pub fn load_terms(store: &EvidenceStore, listing_id: &str) -> Option<SavedTerms> {
    let path = store.root().join("terms").join(format!("{listing_id}.json"));
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// All `account -> trades` bookkeeping the fold needs is derived;
/// this map type is only for callers grouping events by trade.
pub type TradeEvents = BTreeMap<String, Vec<TradeEvent>>;
