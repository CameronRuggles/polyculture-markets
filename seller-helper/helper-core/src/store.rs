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
//!
//! Admission (audit F4): nothing enters the held set on trust. A
//! statement is admitted only with its detached signature and the
//! signer's certificate, and only after the store has parsed it,
//! checked its trade-id against the folder it will sit in, resolved
//! the certificate's fingerprint against the party the statement
//! kind expects, and verified the signature. Loading re-verifies
//! the whole set the same way: a held file that lost its signature,
//! names another trade, or no longer verifies is an error the
//! caller hears about, never a silent skip.

use domain::ht_fold::{PaymentRecord, TimedEvent, TradeEvent};
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

/// Which of the trade's parties a statement kind must come from
/// (Alpha spec §6/§13). The fold is symmetric — statements travel
/// both ways over the same conversation — so the signer check is
/// what binds a held statement to its claimed author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedSigner {
    Seller,
    Buyer,
    /// Settle and receipt may be signed by either party: settle is
    /// "signed by whoever proposes it" (§6) and the receipt names
    /// both parties, superseding the v1 "whoever closes" ambiguity
    /// for the held set. Both are still checked to be ONE of the
    /// two parties.
    Either,
}

/// The trade's two parties by key fingerprint. Admission and load
/// resolve every statement's signer against these (taken from the
/// trade's own assignment, which both parties hold).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSigners {
    pub seller_fpr: String,
    pub buyer_fpr: String,
}

/// Parse one held statement of `kind`, returning the trade-id it
/// carries (the assignment carries none — its digest IS the id and
/// is checked separately), the party it must come from, and the
/// fold event for the kinds the fold consumes. `open` and
/// `refund-to` are held and verified like everything else but are
/// not fold events in H1 (the open token is dispute evidence,
/// §8.2; refund-to intake is H2), so they yield no event.
fn parse_held_statement(
    kind: &str,
    text: &str,
    marketplace_id: &str,
    network: Network,
) -> Result<(Option<String>, ExpectedSigner, Option<TradeEvent>), String> {
    let bad = || format!("the {kind} statement does not parse");
    match kind {
        "assignment" => {
            let a = ht_statements::parse_assignment_statement(text, marketplace_id, network)
                .ok_or_else(bad)?;
            Ok((None, ExpectedSigner::Seller, Some(TradeEvent::Assignment(a))))
        }
        "open" => {
            let o = ht_statements::parse_open_token(text, marketplace_id).ok_or_else(bad)?;
            Ok((Some(o.trade_id.clone()), ExpectedSigner::Seller, None))
        }
        "ack" => {
            let a = ht_statements::parse_ack_statement(text, marketplace_id).ok_or_else(bad)?;
            Ok((Some(a.trade_id.clone()), ExpectedSigner::Seller, Some(TradeEvent::Ack(a))))
        }
        "shipped" => {
            let s = ht_statements::parse_shipped_statement(text, marketplace_id).ok_or_else(bad)?;
            let role = match s.direction {
                ht_statements::ShippedDirection::Out => ExpectedSigner::Seller,
                ht_statements::ShippedDirection::Return => ExpectedSigner::Buyer,
            };
            Ok((Some(s.trade_id.clone()), role, Some(TradeEvent::Shipped(s))))
        }
        "issue" => {
            let i = ht_statements::parse_issue_statement(text, marketplace_id).ok_or_else(bad)?;
            Ok((Some(i.trade_id.clone()), ExpectedSigner::Buyer, Some(TradeEvent::Issue(i))))
        }
        "settle" => {
            let s = ht_statements::parse_settle_statement(text, marketplace_id).ok_or_else(bad)?;
            Ok((Some(s.trade_id.clone()), ExpectedSigner::Either, Some(TradeEvent::Settle(s))))
        }
        "receipt" => {
            let r = ht_statements::parse_receipt_statement(text, marketplace_id).ok_or_else(bad)?;
            Ok((Some(r.trade_id.clone()), ExpectedSigner::Either, Some(TradeEvent::Receipt(r))))
        }
        "refund-to" => {
            let _r = ht_statements::parse_refund_to_statement(text, marketplace_id, network)
                .ok_or_else(bad)?;
            Ok((Some(_r.trade_id.clone()), ExpectedSigner::Buyer, None))
        }
        _ => Err(format!("unknown statement kind {kind}")),
    }
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

    /// Admit a signed statement into the held set as the trade's
    /// next event (audit F4). Every check runs BEFORE anything is
    /// written:
    ///
    /// - the statement parses for its `kind` under this instance;
    /// - a kind that carries a trade-id names THIS trade (the
    ///   assignment is checked by digest: its bytes must hash to
    ///   the folder's id);
    /// - `signer_cert`'s fingerprint is the party `expected` names
    ///   for this kind (shipped is direction-dependent: `out` is the
    ///   seller's, `return` the buyer's; settle and receipt may
    ///   come from either party);
    /// - the detached signature verifies against that certificate.
    ///
    /// `received_at`, when the holder recorded one, is the
    /// witnessed time the statement arrived in the conversation
    /// (owner decision Q2); it is stored as a `<stem>.received`
    /// sidecar next to the statement — evidence, never signed
    /// bytes — and handed to the fold at load.
    pub fn admit_statement(
        &self,
        trade_id: &str,
        kind: &str,
        statement: &[u8],
        signature: &str,
        signer_cert: &[u8],
        expected: &ExpectedSigners,
        marketplace_id: &str,
        network: Network,
        received_at: Option<&str>,
    ) -> Result<(), String> {
        let text = std::str::from_utf8(statement)
            .map_err(|_| format!("the {kind} statement is not UTF-8"))?;
        let (carried_id, role, _event) =
            parse_held_statement(kind, text, marketplace_id, network)?;
        if let Some(id) = &carried_id {
            if id != trade_id {
                return Err(format!(
                    "the {kind} statement names trade {id}, not this trade ({trade_id}): not held"
                ));
            }
        }
        if kind == "assignment" && ht_statements::trade_id(statement) != trade_id {
            return Err(format!(
                "the assignment statement's digest is not this trade's id ({trade_id}): not held"
            ));
        }
        let signer_fpr = crate::keys::fingerprint_of(signer_cert)
            .map_err(|e| format!("the signer's certificate is unusable: {e}"))?;
        let role_matches = match role {
            ExpectedSigner::Seller => signer_fpr == expected.seller_fpr,
            ExpectedSigner::Buyer => signer_fpr == expected.buyer_fpr,
            ExpectedSigner::Either => {
                signer_fpr == expected.seller_fpr || signer_fpr == expected.buyer_fpr
            }
        };
        if !role_matches {
            return Err(format!(
                "the {kind} statement was signed by {signer_fpr}, not the {} of this trade: not held",
                match role {
                    ExpectedSigner::Seller => "seller",
                    ExpectedSigner::Buyer => "buyer",
                    ExpectedSigner::Either => "seller or buyer",
                }
            ));
        }
        if !crate::keys::verify_detached(signer_cert, statement, signature.as_bytes()) {
            return Err(format!(
                "the {kind} statement's signature does not verify against its signer's certificate: not held"
            ));
        }
        if let Some(ts) = received_at {
            if !domain::validate_canonical_timestamp(ts) {
                return Err(format!(
                    "received-at {ts:?} is not a canonical timestamp (YYYY-MM-DDTHH:MM:SSZ)"
                ));
            }
        }
        let seq = self.next_seq(trade_id)?;
        let base = self.trade_dir(trade_id).join(format!("{seq:02}-{kind}"));
        write_atomic(&base.with_extension("txt"), statement)?;
        write_atomic(&base.with_extension("sig"), signature.as_bytes())?;
        if let Some(ts) = received_at {
            let received_path = self
                .trade_dir(trade_id)
                .join(format!("{seq:02}-{kind}.received"));
            write_atomic(&received_path, ts.as_bytes())?;
        }
        Ok(())
    }

    /// Resolve the certificate for a fingerprint: the holder's own
    /// certificate when it is that key, else the pin file.
    fn resolve_cert(&self, fingerprint: &str, own_cert: Option<&Path>) -> Result<Vec<u8>, String> {
        if let Some(path) = own_cert {
            if let Ok(bytes) = std::fs::read(path) {
                if crate::keys::fingerprint_of(&bytes).ok().as_deref() == Some(fingerprint) {
                    return Ok(bytes);
                }
            }
        }
        self.pinned_cert(fingerprint).ok_or_else(|| {
            format!(
                "no certificate held for signer {fingerprint} (not the own key and no pin): the held set cannot be verified"
            )
        })
    }

    /// Parse just the trade's assignment statement, if one is held.
    /// This is how a caller learns the trade's two parties (the
    /// fingerprints admission and load check against). A held
    /// assignment that no longer parses is an error, not an absence.
    pub fn load_assignment(
        &self,
        trade_id: &str,
        marketplace_id: &str,
        network: Network,
    ) -> Result<Option<ht_statements::AssignmentStatement>, String> {
        let dir = self.trade_dir(trade_id);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with("-assignment.txt") {
                    let raw = std::fs::read(entry.path())
                        .map_err(|e| format!("cannot read {name}: {e}"))?;
                    let text = String::from_utf8(raw)
                        .map_err(|_| format!("stored assignment in {name} is not UTF-8"))?;
                    return ht_statements::parse_assignment_statement(&text, marketplace_id, network)
                        .map(Some)
                        .ok_or_else(|| format!("stored assignment in {name} no longer parses"));
                }
            }
        }
        Ok(None)
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

    /// Whether the store holds any trade directory at all.
    pub fn has_trades(&self) -> bool {
        !self.trade_ids().is_empty()
    }

    /// Load a trade's held events in held order, RE-VERIFYING the
    /// whole held set (audit F4): every statement file must still
    /// parse, name this trade, carry its `.sig`, and verify against
    /// the certificate of the party its kind expects — resolved
    /// from `own_cert` when that is the signer's key, else from
    /// the pins. Any failure is an error the caller hears about;
    /// an unverifiable held set never folds. Returns the events as
    /// [`TimedEvent`]s carrying each statement's recorded receipt
    /// time for the fold (owner decision Q2).
    pub fn load_events(
        &self,
        trade_id: &str,
        expected: &ExpectedSigners,
        marketplace_id: &str,
        network: Network,
        own_cert: Option<&Path>,
    ) -> Result<Vec<TimedEvent>, String> {
        let dir = self.trade_dir(trade_id);
        let mut files: Vec<PathBuf> = Vec::new();
        if dir.is_dir() {
            for entry in
                std::fs::read_dir(&dir).map_err(|e| format!("cannot read trade store: {e}"))?
            {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue; // write_atomic temp files
                }
                if name.ends_with(".txt") || name.ends_with("-payment.json") {
                    files.push(entry.path());
                }
            }
        }
        files.sort();
        let mut events = Vec::new();
        for path in files {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let kind_ext = name
                .split_once('-')
                .map(|(_, k)| k.to_string())
                .unwrap_or_default();
            let raw = std::fs::read(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
            if kind_ext == "payment.json" {
                let record: PaymentJson = serde_json::from_slice(&raw)
                    .map_err(|_| format!("stored payment record in {name} no longer parses"))?;
                events.push(TimedEvent {
                    event: TradeEvent::Payment(PaymentRecord {
                        txid: record.txid,
                        proof: record.proof,
                    }),
                    received_at: None,
                });
                continue;
            }
            let Some(kind) = kind_ext.strip_suffix(".txt") else {
                continue; // not a statement file (e.g. user notes)
            };
            if !matches!(
                kind,
                "assignment" | "open" | "ack" | "shipped" | "issue" | "settle" | "receipt"
                    | "refund-to"
            ) {
                continue; // not a statement kind this build knows
            }
            let stem = name.strip_suffix(".txt").unwrap_or_default();
            let sig = std::fs::read_to_string(dir.join(format!("{stem}.sig"))).map_err(|_| {
                format!(
                    "{name} is held without its signature ({stem}.sig is missing): the held set is not trusted"
                )
            })?;
            let text = String::from_utf8(raw)
                .map_err(|_| format!("stored {kind} in {name} is not UTF-8"))?;
            let (carried_id, role, event) =
                parse_held_statement(kind, &text, marketplace_id, network)
                    .map_err(|e| format!("stored statement {name}: {e}"))?;
            if let Some(id) = &carried_id {
                if id != trade_id {
                    return Err(format!(
                        "{name} names trade {id} but sits in trade {trade_id}'s folder: the held set is not trusted"
                    ));
                }
            }
            if kind == "assignment" && ht_statements::trade_id(text.as_bytes()) != trade_id {
                return Err(format!(
                    "{name}'s digest is not this trade's id ({trade_id}): the held set is not trusted"
                ));
            }
            let candidates: Vec<&str> = match role {
                ExpectedSigner::Seller => vec![expected.seller_fpr.as_str()],
                ExpectedSigner::Buyer => vec![expected.buyer_fpr.as_str()],
                ExpectedSigner::Either => {
                    vec![expected.seller_fpr.as_str(), expected.buyer_fpr.as_str()]
                }
            };
            let mut verified = false;
            let mut resolve_error: Option<String> = None;
            for fpr in candidates {
                match self.resolve_cert(fpr, own_cert) {
                    Ok(cert) => {
                        if crate::keys::verify_detached(&cert, text.as_bytes(), sig.as_bytes()) {
                            verified = true;
                            break;
                        }
                    }
                    Err(e) => resolve_error = Some(e),
                }
            }
            if !verified {
                let detail = resolve_error
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default();
                return Err(format!(
                    "{name}'s signature does not verify against the pinned certificate of its expected signer{detail}: the held set is not trusted"
                ));
            }
            let received_at = match std::fs::read_to_string(dir.join(format!("{stem}.received"))) {
                Ok(raw) => {
                    let ts = raw.trim_end().to_string();
                    if !domain::validate_canonical_timestamp(&ts) {
                        return Err(format!(
                            "{stem}.received is not a canonical timestamp: the held set is not trusted"
                        ));
                    }
                    Some(ts)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("cannot read {stem}.received: {e}")),
            };
            if let Some(event) = event {
                events.push(TimedEvent { event, received_at });
            }
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

/// An exclusive lock on the pool ledger, held across
/// load → allocate → mark → save during assignment (audit F5):
/// two helper processes assigning at once must never draw the
/// same address from the same on-disk ledger. The lock is a
/// `<ledger>.lock` file created exclusively; a contender waits
/// briefly, then errors rather than proceeding unlocked. The file
/// is removed on drop; a crashed holder leaves it behind and the
/// error message says exactly how to clear it.
pub struct LedgerLock {
    path: PathBuf,
}

impl LedgerLock {
    pub fn acquire(ledger_path: &Path) -> Result<LedgerLock, String> {
        let mut lock_os = ledger_path.as_os_str().to_owned();
        lock_os.push(".lock");
        let lock_path = PathBuf::from(lock_os);
        for _ in 0..200 {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&lock_path) {
                Ok(_file) => return Ok(LedgerLock { path: lock_path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => {
                    return Err(format!(
                        "cannot create the pool lock {}: {e}",
                        lock_path.display()
                    ));
                }
            }
        }
        Err(format!(
            "the pool ledger is locked by another helper process ({} exists): if no helper is running, remove that file and retry",
            lock_path.display()
        ))
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Every destination any stored assignment names, mapped to the
/// trade that spent it — read from the evidence store, which is
/// the durable record when the ledger is not (audit F5).
fn collect_assignment_destinations(
    store: &EvidenceStore,
    marketplace_id: &str,
    network: Network,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut spent = std::collections::BTreeMap::new();
    for trade_id in store.trade_ids() {
        if let Some(assignment) = store.load_assignment(&trade_id, marketplace_id, network)? {
            spent.insert(assignment.destination.to_string(), trade_id);
        }
    }
    Ok(spent)
}

impl PoolLedger {
    /// Load the ledger. A MISSING file is a fresh, empty ledger;
    /// a present-but-unreadable one is a hard error (audit F5):
    /// silently treating corruption as an empty ledger would hand
    /// out destinations that are already spent.
    pub fn load(path: &Path) -> Result<PoolLedger, String> {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).map_err(|e| {
                format!(
                    "the pool ledger at {} is unreadable ({e}): refusing to continue — an unreadable ledger is never an empty one",
                    path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PoolLedger::default()),
            Err(e) => Err(format!("cannot read the pool ledger at {}: {e}", path.display())),
        }
    }

    /// Load for ASSIGNMENT (audit F5): when the evidence store
    /// already holds trades but the ledger file is gone, the fresh
    /// ledger would not know which destinations those trades spent
    /// — that is an error with a remedy, never a fresh start.
    pub fn load_for_assign(
        path: &Path,
        store: &EvidenceStore,
    ) -> Result<PoolLedger, String> {
        if !path.exists() && store.has_trades() {
            return Err(format!(
                "the pool ledger at {} is missing but the evidence store holds trades: the ledger is the only record of which destinations are spent — restore it (the batch file re-seeds safely: seeding never resurrects a spent address) before assigning",
                path.display()
            ));
        }
        Self::load(path)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(path, json.as_bytes())
    }

    /// Seed unused addresses from a v1 signed-batch file (the
    /// seller's `generate` output): every subaddress in the batch
    /// that the ledger does not already know is added — EXCEPT one
    /// a stored assignment proves spent (audit F5): seeding never
    /// resurrects a spent address, so re-seeding from the batch is
    /// a safe recovery for a lost ledger. Entries the ledger
    /// already holds as unused that a stored assignment proves
    /// spent are healed to used. Returns how many were added.
    pub fn seed_from_batch_json(
        &mut self,
        batch_json: &[u8],
        store: &EvidenceStore,
        marketplace_id: &str,
        network: Network,
    ) -> Result<usize, String> {
        let spent = collect_assignment_destinations(store, marketplace_id, network)?;
        for entry in self.entries.iter_mut() {
            if entry.trade_id.is_none() {
                if let Some(trade_id) = spent.get(&entry.address) {
                    entry.trade_id = Some(trade_id.clone());
                }
            }
        }
        let batch: BatchFileIn =
            serde_json::from_slice(batch_json).map_err(|e| format!("batch file does not parse: {e}"))?;
        let mut added = 0;
        for entry in batch.entries {
            if !self.entries.iter().any(|e| e.address == entry.subaddress) {
                let trade_id = spent.get(&entry.subaddress).cloned();
                self.entries.push(PoolEntry {
                    address: entry.subaddress,
                    trade_id,
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

// ---------------------------------------------------------------------------
// Tests (audit fix batch 2026-10-21 — F4 admission/load, F5 ledger).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{fingerprint_of, generate_test_cert, sign_detached};
    use domain::ht_fold::{fold_trade_timed, TradeState};
    use domain::ht_statements::{
        AckStatement, AssignmentStatement, IssueKind, IssueStatement, PaymentTiming,
        ReceiptStatement, SettleStatement, ShippedDirection, ShippedStatement,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
    const SUB_A: &str =
        "75VjEqDg5fp7hyErNLsyRK59sHRJjLX3fTvARvKvGodj5PPajrWjmyQ2mvuPWWMWi4HNS5jg4jvyYLREvx63KZe4HK7sbH8";
    const SUB_B: &str =
        "72GeiPtUwSSSsbBtk7SgYGebrQYiDZZYvGa7Y5Z5AAi2M5Cpp38sCU8DjQtcCVJPTxUjua8ekmSuRhzNSz6gFcfFErM7Jqm";
    const SUB_C: &str =
        "72HKxCdo45R5NSYiv1iag63a62dNHoAe7dbEVhJKfkKQ1wnrMdnZyFy8jCmuMgjT7K9Ap9zjRwjDi9uU3Ab3ygWn1p8Jj3g";
    const SUB_D: &str =
        "72HmXLDN1khcDL5cB1Mdp8Nb2zDm9pkjpMbygn959Ky8hQJzNfJU7hvVQBt8jye5GeB91TEZqzg3NDmpxxEZfczpUD2FHxc";

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "pcm-store-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    struct Parties {
        seller_sec: Vec<u8>,
        seller_pub: Vec<u8>,
        buyer_sec: Vec<u8>,
        buyer_pub: Vec<u8>,
        expected: ExpectedSigners,
    }

    fn parties() -> Parties {
        let (seller_sec, seller_pub) =
            generate_test_cert("Seller <seller@example.com>").expect("seller key");
        let (buyer_sec, buyer_pub) =
            generate_test_cert("Buyer <buyer@example.com>").expect("buyer key");
        let expected = ExpectedSigners {
            seller_fpr: fingerprint_of(&seller_pub).expect("seller fpr"),
            buyer_fpr: fingerprint_of(&buyer_pub).expect("buyer fpr"),
        };
        Parties { seller_sec, seller_pub, buyer_sec, buyer_pub, expected }
    }

    fn assignment_bytes(p: &Parties, destination: &str) -> Vec<u8> {
        AssignmentStatement {
            marketplace_id: MKT.into(),
            network: Network::Stagenet,
            seller_key_fingerprint: p.expected.seller_fpr.clone(),
            buyer_key_fingerprint: p.expected.buyer_fpr.clone(),
            terms_statement_sha256: "ab".repeat(32),
            destination: modules_api::Subaddress::validate(destination, Network::Stagenet)
                .expect("fixture subaddress"),
            amount_atomic: 250_000_000_000,
            payment_timing: PaymentTiming::Prepay,
            expires_at: "2027-01-01T00:00:00Z".into(),
            nonce: "0123456789abcdef0123456789abcdef".into(),
        }
        .to_bytes()
    }

    fn ack_bytes(trade_id: &str, date: &str) -> Vec<u8> {
        AckStatement { marketplace_id: MKT.into(), trade_id: trade_id.into(), date: date.into() }
            .to_bytes()
    }

    fn sign(secret: &[u8], bytes: &[u8]) -> String {
        sign_detached(secret, None, bytes).expect("sign")
    }

    /// A store holding one fully-admitted trade (assignment, ack,
    /// shipped, issue, receipt, payment), with the buyer's cert
    /// pinned and the seller's cert written next to the store as
    /// the "own cert". Returns (root, store, parties, trade_id,
    /// own_cert_path).
    fn held_trade(tag: &str) -> (PathBuf, EvidenceStore, Parties, String, PathBuf) {
        let root = temp_root(tag);
        let store = EvidenceStore::open(root.clone()).expect("store");
        let p = parties();
        let assignment = assignment_bytes(&p, SUB_A);
        let trade_id = ht_statements::trade_id(&assignment);
        let admit = |kind: &str, bytes: &[u8], secret: &[u8], cert: &[u8], received: Option<&str>| {
            let sig = sign(secret, bytes);
            store
                .admit_statement(
                    &trade_id, kind, bytes, &sig, cert, &p.expected, MKT, Network::Stagenet,
                    received,
                )
                .expect("admit");
        };
        admit("assignment", &assignment, &p.seller_sec, &p.seller_pub, None);
        admit("ack", &ack_bytes(&trade_id, "2026-10-21"), &p.seller_sec, &p.seller_pub, None);
        let shipped = ShippedStatement {
            marketplace_id: MKT.into(),
            trade_id: trade_id.clone(),
            direction: ShippedDirection::Out,
            date: "2026-10-22".into(),
            carrier_commit: "ef".repeat(32),
        }
        .to_bytes();
        admit("shipped", &shipped, &p.seller_sec, &p.seller_pub, Some("2026-10-25T09:00:00Z"));
        let issue = IssueStatement {
            marketplace_id: MKT.into(),
            trade_id: trade_id.clone(),
            kind: IssueKind::MissingPart,
            requested_refund_pct: 40,
            date: "2026-11-01".into(),
        }
        .to_bytes();
        admit("issue", &issue, &p.buyer_sec, &p.buyer_pub, Some("2026-11-05T10:00:00Z"));
        let receipt = ReceiptStatement {
            marketplace_id: MKT.into(),
            trade_id: trade_id.clone(),
            seller_key_fingerprint: p.expected.seller_fpr.clone(),
            buyer_key_fingerprint: p.expected.buyer_fpr.clone(),
            month: "2026-11".into(),
        }
        .to_bytes();
        admit("receipt", &receipt, &p.seller_sec, &p.seller_pub, None);
        store
            .save_payment(&trade_id, &PaymentRecord { txid: "aa".repeat(32), proof: "OutProofV2:x".into() })
            .expect("payment");
        store.pin_cert(&p.buyer_pub).expect("pin buyer");
        let own_cert = root.join("own.asc");
        std::fs::write(&own_cert, &p.seller_pub).expect("own cert");
        (root, store, p, trade_id, own_cert)
    }

    #[test]
    fn admit_and_load_round_trip_with_receipt_times() {
        let (_root, store, p, trade_id, own_cert) = held_trade("round-trip");
        let events = store
            .load_events(&trade_id, &p.expected, MKT, Network::Stagenet, Some(&own_cert))
            .expect("load");
        assert_eq!(events.len(), 6, "assignment, ack, shipped, issue, receipt, payment");
        let shipped = events
            .iter()
            .find(|t| matches!(t.event, TradeEvent::Shipped(_)))
            .expect("shipped event");
        assert_eq!(shipped.received_at.as_deref(), Some("2026-10-25T09:00:00Z"));
        let issue = events
            .iter()
            .find(|t| matches!(t.event, TradeEvent::Issue(_)))
            .expect("issue event");
        assert_eq!(issue.received_at.as_deref(), Some("2026-11-05T10:00:00Z"));
        let folded = fold_trade_timed(&events, "2026-11-15T00:00:00Z").expect("fold");
        assert_eq!(folded.state, TradeState::Closed);
        assert!(folded.paid && folded.shipped);
    }

    #[test]
    fn admit_refuses_unsigned_wrong_party_and_wrong_trade() {
        let root = temp_root("admit-refusals");
        let store = EvidenceStore::open(root).expect("store");
        let p = parties();
        let assignment = assignment_bytes(&p, SUB_A);
        let trade_id = ht_statements::trade_id(&assignment);
        let sig = sign(&p.seller_sec, &assignment);
        store
            .admit_statement(&trade_id, "assignment", &assignment, &sig, &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect("assignment admits");
        let ack = ack_bytes(&trade_id, "2026-10-21");

        // Unsigned / garbage signature: refused.
        let err = store
            .admit_statement(&trade_id, "ack", &ack, "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n", &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect_err("garbage signature must refuse");
        assert!(err.contains("does not verify"), "{err}");

        // Ack signed by the BUYER (wrong party): refused.
        let buyer_sig = sign(&p.buyer_sec, &ack);
        let err = store
            .admit_statement(&trade_id, "ack", &ack, &buyer_sig, &p.buyer_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect_err("buyer-signed ack must refuse");
        assert!(err.contains("not the seller"), "{err}");

        // Ack carrying ANOTHER trade's id, properly seller-signed:
        // refused on the trade-id check.
        let foreign = ack_bytes(&"ff".repeat(32), "2026-10-21");
        let foreign_sig = sign(&p.seller_sec, &foreign);
        let err = store
            .admit_statement(&trade_id, "ack", &foreign, &foreign_sig, &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect_err("foreign ack must refuse");
        assert!(err.contains("names trade"), "{err}");
    }

    #[test]
    fn admit_accepts_a_settle_from_either_party() {
        let root = temp_root("settle-either");
        let store = EvidenceStore::open(root).expect("store");
        let p = parties();
        let assignment = assignment_bytes(&p, SUB_A);
        let trade_id = ht_statements::trade_id(&assignment);
        let sig = sign(&p.seller_sec, &assignment);
        store
            .admit_statement(&trade_id, "assignment", &assignment, &sig, &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect("assignment admits");
        let settle = SettleStatement {
            marketplace_id: MKT.into(),
            trade_id: trade_id.clone(),
            refund_atomic: 1_000,
            return_required: false,
            month: "2026-11".into(),
        }
        .to_bytes();
        let buyer_sig = sign(&p.buyer_sec, &settle);
        store
            .admit_statement(&trade_id, "settle", &settle, &buyer_sig, &p.buyer_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect("buyer-signed settle admits (either party)");
        // A settle from a THIRD party still refuses.
        let (third_sec, third_pub) = generate_test_cert("Third <t@example.com>").expect("third key");
        let third_sig = sign(&third_sec, &settle);
        let err = store
            .admit_statement(&trade_id, "settle", &settle, &third_sig, &third_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect_err("third-party settle must refuse");
        assert!(err.contains("not the seller or buyer"), "{err}");
    }

    #[test]
    fn load_refuses_unsigned_tampered_and_foreign_files() {
        // (a) A statement file with NO signature file: refused.
        {
            let (_root, store, p, trade_id, own_cert) = held_trade("load-unsigned");
            let dir = store.trade_dir(&trade_id);
            // Remove the receipt's signature (the set is admitted
            // and complete apart from this) and reload.
            let sig = dir.join("04-receipt.sig");
            assert!(sig.exists());
            std::fs::remove_file(&sig).expect("remove sig");
            let err = store
                .load_events(&trade_id, &p.expected, MKT, Network::Stagenet, Some(&own_cert))
                .expect_err("missing signature must refuse the load");
            assert!(err.contains("without its signature"), "{err}");
        }
        // (b) A tampered statement (date changed after signing):
        // refused at load — the signature no longer verifies.
        {
            let (_root, store, p, trade_id, own_cert) = held_trade("load-tampered");
            let dir = store.trade_dir(&trade_id);
            std::fs::write(dir.join("01-ack.txt"), ack_bytes(&trade_id, "2026-10-23"))
                .expect("tamper");
            let err = store
                .load_events(&trade_id, &p.expected, MKT, Network::Stagenet, Some(&own_cert))
                .expect_err("tampered statement must refuse the load");
            assert!(err.contains("does not verify"), "{err}");
        }
        // (c) Another trade's ack (properly signed, for its own
        // trade) sitting in this folder: refused at load.
        {
            let (_root, store, p, trade_id, own_cert) = held_trade("load-foreign");
            let dir = store.trade_dir(&trade_id);
            let other = parts_setup_other_trade(&store, &p);
            let other_dir = store.trade_dir(&other);
            std::fs::copy(other_dir.join("01-ack.txt"), dir.join("06-ack.txt")).expect("copy txt");
            std::fs::copy(other_dir.join("01-ack.sig"), dir.join("06-ack.sig")).expect("copy sig");
            // Renumber: held order is by filename; the foreign ack
            // must sort as a later event — its content is what bites.
            let err = store
                .load_events(&trade_id, &p.expected, MKT, Network::Stagenet, Some(&own_cert))
                .expect_err("foreign ack must refuse the load");
            assert!(err.contains("names trade"), "{err}");
        }
    }

    /// Admit a second trade (different destination/nonce → a
    /// different trade id) and return its id.
    fn parts_setup_other_trade(store: &EvidenceStore, p: &Parties) -> String {
        let stmt = AssignmentStatement {
            marketplace_id: MKT.into(),
            network: Network::Stagenet,
            seller_key_fingerprint: p.expected.seller_fpr.clone(),
            buyer_key_fingerprint: p.expected.buyer_fpr.clone(),
            terms_statement_sha256: "ab".repeat(32),
            destination: modules_api::Subaddress::validate(SUB_B, Network::Stagenet)
                .expect("fixture subaddress"),
            amount_atomic: 100,
            payment_timing: PaymentTiming::Prepay,
            expires_at: "2027-01-01T00:00:00Z".into(),
            nonce: "fedcba9876543210fedcba9876543210".into(),
        };
        let bytes = stmt.to_bytes();
        let other_id = ht_statements::trade_id(&bytes);
        let sig = sign(&p.seller_sec, &bytes);
        store
            .admit_statement(&other_id, "assignment", &bytes, &sig, &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect("other assignment");
        let ack = ack_bytes(&other_id, "2026-10-21");
        let ack_sig = sign(&p.seller_sec, &ack);
        store
            .admit_statement(&other_id, "ack", &ack, &ack_sig, &p.seller_pub, &p.expected, MKT, Network::Stagenet, None)
            .expect("other ack");
        let _ = &stmt;
        other_id
    }

    #[test]
    fn ledger_unreadable_is_a_hard_error_never_an_empty_ledger() {
        let root = temp_root("ledger-corrupt");
        let path = root.join("pool.json");
        std::fs::write(&path, "{ not json").expect("write corrupt");
        let err = PoolLedger::load(&path).expect_err("corrupt ledger must error");
        assert!(err.contains("unreadable"), "{err}");
        std::fs::write(&path, "{\"entries\": 42}").expect("write wrong shape");
        assert!(PoolLedger::load(&path).is_err(), "wrong-shape ledger must error");
        // Missing file: a fresh ledger, no error.
        let missing = root.join("absent.json");
        let ledger = PoolLedger::load(&missing).expect("missing ledger is fresh");
        assert_eq!(ledger.unused_count(), 0);
    }

    #[test]
    fn load_for_assign_refuses_a_missing_ledger_over_existing_trades() {
        let (_root, store, _p, _tid, _own) = held_trade("ledger-missing");
        let missing = _root.join("pool.json");
        assert!(!missing.exists());
        let err = PoolLedger::load_for_assign(&missing, &store)
            .expect_err("missing ledger over existing trades must error");
        assert!(err.contains("missing but the evidence store holds trades"), "{err}");
        // Same call over an EMPTY store is a fresh start.
        let empty_root = temp_root("ledger-missing-empty");
        let empty_store = EvidenceStore::open(empty_root.clone()).expect("store");
        PoolLedger::load_for_assign(&empty_root.join("pool.json"), &empty_store)
            .expect("missing ledger over an empty store is fine");
    }

    #[test]
    fn seeding_never_resurrects_a_spent_address_and_heals() {
        let (_root, store, p, trade_id, _own) = held_trade("seed");
        let batch = format!(
            "{{\"entries\":[{{\"subaddress\":\"{SUB_A}\"}},{{\"subaddress\":\"{SUB_B}\"}}]}}"
        );
        // Fresh ledger + batch containing the address the stored
        // assignment already spent (SUB_A): it seeds as USED.
        let mut ledger = PoolLedger::default();
        ledger
            .seed_from_batch_json(batch.as_bytes(), &store, MKT, Network::Stagenet)
            .expect("seed");
        assert!(ledger.is_used(SUB_A), "spent address must seed as used");
        assert_eq!(ledger.peek_unused(), Some(SUB_B));
        let spent_entry = ledger.entries.iter().find(|e| e.address == SUB_A).expect("entry");
        assert_eq!(spent_entry.trade_id.as_deref(), Some(trade_id.as_str()));
        // Healing: a ledger that (wrongly) holds SUB_A unused is
        // corrected by the same seed.
        let mut ledger2 = PoolLedger::default();
        ledger2.add(SUB_A).expect("add");
        ledger2
            .seed_from_batch_json(batch.as_bytes(), &store, MKT, Network::Stagenet)
            .expect("seed 2");
        assert!(ledger2.is_used(SUB_A), "seed must heal a wrongly-unused spent address");
    }

    #[test]
    fn concurrent_assigns_under_the_lock_never_reuse_an_address() {
        let root = temp_root("ledger-concurrent");
        let store = std::sync::Arc::new(EvidenceStore::open(root.clone()).expect("store"));
        let pool_path = std::sync::Arc::new(root.join("pool.json"));
        let mut ledger = PoolLedger::default();
        for addr in [SUB_A, SUB_B, SUB_C, SUB_D] {
            ledger.add(addr).expect("add");
        }
        ledger.save(&pool_path).expect("save seed ledger");

        let mut handles = Vec::new();
        for i in 0..4 {
            let store = store.clone();
            let pool_path = pool_path.clone();
            handles.push(std::thread::spawn(move || -> Result<String, String> {
                let _lock = LedgerLock::acquire(&pool_path)?;
                let mut ledger = PoolLedger::load_for_assign(&pool_path, &store)?;
                let addr = ledger
                    .peek_unused()
                    .map(str::to_string)
                    .ok_or("pool exhausted")?;
                ledger.mark_used(&addr, &format!("trade-{i}"))?;
                ledger.save(&pool_path)?;
                Ok(addr)
            }));
        }
        let mut drawn: Vec<String> = Vec::new();
        for h in handles {
            drawn.push(h.join().expect("thread").expect("assign"));
        }
        drawn.sort();
        drawn.dedup();
        assert_eq!(drawn.len(), 4, "four concurrent assigns must draw four distinct addresses");
        let final_ledger = PoolLedger::load(&pool_path).expect("final load");
        assert_eq!(final_ledger.unused_count(), 0);
    }
}
