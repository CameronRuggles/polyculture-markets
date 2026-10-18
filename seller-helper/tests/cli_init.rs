//! CLI-level tests for `seller-helper init` (audit fix-brief task 9,
//! finding L4). The wallet RPC password must never be accepted as a
//! command-line flag: command lines leak through shell history and
//! process listings. `init` prompts for it instead.

use std::process::{Command, Stdio};

#[test]
fn init_refuses_rpc_password_flag() {
    let bin = env!("CARGO_BIN_EXE_seller-helper");
    let dir = std::env::temp_dir().join(format!(
        "seller-helper-cli-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    let out = Command::new(bin)
        .args([
            "init",
            "--config",
            cfg.to_str().unwrap(),
            "--marketplace-id",
            "testmarket",
            "--network",
            "stagenet",
            "--seller-id",
            "seller-1",
            "--rpc-url",
            "http://127.0.0.1:28088/json_rpc",
            "--rpc-user",
            "user",
            "--rpc-password",
            "fixture-password",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "init must refuse --rpc-password; stdout/stderr: {} / {stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("rpc-password"),
        "the refusal must name the removed flag, got: {stderr}"
    );
    assert!(
        !cfg.exists(),
        "no config may be written when the password flag is refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
