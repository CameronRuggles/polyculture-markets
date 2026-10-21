//! The instance's Hidden Trades marketplace id file (HT H1 audit
//! fix task 2, finding F1).
//!
//! HT statements pin the instance's `mkt_` id byte-exact, so the id
//! must be generated exactly once and then be permanent — the same
//! lifecycle problem the marketplace key file solves for the master
//! secret (keyfile.rs), and the same solution: a small file beside
//! the deployment (env `HT_ID_FILE_PATH`, default `marketplace.htid`
//! in the working directory).
//!
//! The id is NOT a secret — it is printed on the seller page for
//! the helper's `init`. Its INTEGRITY is load-bearing instead:
//! silently minting a replacement (the failure audit AL1 removed
//! for the key file) would orphan every pinned terms statement and
//! every configured helper on the instance. Non-development
//! profiles therefore start only through `load_existing` (main.rs).
//!
//! An operator who must fix the id themselves sets
//! `HT_MARKETPLACE_ID` in the environment instead (validated in
//! config.rs); the file is then neither read nor written.

use std::path::Path;

/// Load an EXISTING id file, refusing when it is absent or its
/// contents are not a valid `mkt_` id (audit AL1's rule, one level
/// up): a missing file must never be silently replaced.
pub fn load_existing(path: &Path) -> std::io::Result<String> {
    let raw = std::fs::read(path)?;
    parse_id_file(&raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HT id file must contain a single mkt_ marketplace id",
        )
    })
}

/// Load the id file, generating and persisting a fresh id if it
/// does not exist. New files are created with mode 0600 FROM
/// CREATION (the key file's discipline: no create-then-chmod
/// window), even though the id itself is public — the file's
/// integrity, not its secrecy, is what matters.
pub fn load_or_generate(path: &Path) -> std::io::Result<String> {
    if path.exists() {
        return load_existing(path);
    }
    let id = crate::config::generate_ht_marketplace_id();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    use std::io::Write;
    file.write_all(id.as_bytes())?;
    Ok(id)
}

fn parse_id_file(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    if modules_api::validate_public_id(text, "mkt_") {
        Some(text.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "htid-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_existing_refuses_missing_and_generated_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("instance.htid");
        // Missing: refused, and nothing is created (AL1).
        assert!(load_existing(&path).is_err());
        assert!(!path.exists());
        // Generated: 0600 in the final state, valid, and stable
        // across loads — the second call reads the file back.
        let id = load_or_generate(&path).unwrap();
        assert!(modules_api::validate_public_id(&id, "mkt_"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new id file must be 0600, got {mode:o}");
        assert_eq!(load_existing(&path).unwrap(), id);
        assert_eq!(load_or_generate(&path).unwrap(), id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn id_file_parsing_is_strict() {
        assert_eq!(
            parse_id_file(b"mkt_0123456789abcdef0123456789abcdef"),
            Some("mkt_0123456789abcdef0123456789abcdef".to_string())
        );
        // A trailing newline (an editor's doing) is tolerated.
        assert_eq!(
            parse_id_file(b"mkt_0123456789abcdef0123456789abcdef\n"),
            Some("mkt_0123456789abcdef0123456789abcdef".to_string())
        );
        assert!(parse_id_file(b"vespiary-market").is_none());
        assert!(parse_id_file(b"").is_none());
        assert!(parse_id_file(b"mkt_0123").is_none());
    }
}
