//! Spike 4: tx-proof verification client (spec §12 `tx-proof` module).
//! Talks JSON-RPC to a local monero-wallet-rpc verify-only wallet.
//! The method, parameters, and result fields below are per the official
//! Monero wallet RPC documentation for `check_tx_proof`:
//!   inputs:  txid, address, message, signature
//!   outputs: good (bool), received (atomic u64), confirmations (u64),
//!            in_pool (bool), untrusted (bool)

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckTxProof {
    pub good: bool,
    pub received_atomic: u64,
    pub confirmations: u64,
    pub in_pool: bool,
}

/// Build the exact JSON-RPC request body (factored out so the spike can
/// assert the wire format without a node).
pub fn build_request(txid_hex: &str, address: &str, message: &str, signature: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": "check_tx_proof",
        "params": {
            "txid": txid_hex,
            "address": address,
            "message": message,
            "signature": signature
        }
    })
}

pub fn parse_response(v: &Value) -> Result<CheckTxProof, String> {
    if let Some(err) = v.get("error") {
        return Err(format!("wallet rpc error: {err}"));
    }
    let r = v.get("result").ok_or("missing result")?;
    Ok(CheckTxProof {
        good: r.get("good").and_then(Value::as_bool).ok_or("missing good")?,
        received_atomic: r.get("received").and_then(Value::as_u64).ok_or("missing received")?,
        confirmations: r.get("confirmations").and_then(Value::as_u64).ok_or("missing confirmations")?,
        in_pool: r.get("in_pool").and_then(Value::as_bool).ok_or("missing in_pool")?,
    })
}

pub fn check_tx_proof(
    endpoint: &str,
    txid_hex: &str,
    address: &str,
    message: &str,
    signature: &str,
) -> Result<CheckTxProof, String> {
    if txid_hex.len() != 64 || !txid_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("txid must be 64 hex chars".into());
    }
    let body = build_request(txid_hex, address, message, signature);
    let resp = ureq::post(endpoint)
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|e| format!("rpc transport: {e}"))?;
    let mut resp = resp;
    let v: Value = resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("rpc response parse: {e}"))?;
    parse_response(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn request_shape_matches_wallet_rpc_docs() {
        let req = build_request("ab".repeat(32).as_str(), "5ADDR", "inv_123", "OutProofV2sig");
        assert_eq!(req["method"], "check_tx_proof");
        assert_eq!(req["params"]["txid"], "ab".repeat(32));
        assert_eq!(req["params"]["address"], "5ADDR");
        assert_eq!(req["params"]["message"], "inv_123");
        assert_eq!(req["params"]["signature"], "OutProofV2sig");
    }

    #[test]
    fn parses_documented_result_fields() {
        // Shape per official wallet RPC docs for check_tx_proof.
        let v = serde_json::json!({"jsonrpc":"2.0","id":"0","result":{
            "confirmations": 12, "good": true, "in_pool": false,
            "received": 1250000000000u64, "untrusted": false }});
        let parsed = parse_response(&v).expect("parses");
        assert!(parsed.good);
        assert_eq!(parsed.received_atomic, 1_250_000_000_000);
        assert_eq!(parsed.confirmations, 12);
        assert!(!parsed.in_pool);
    }

    /// End-to-end against a mock wallet-rpc server on localhost: proves the
    /// HTTP transport + JSON handling work. The cryptographic verification
    /// itself happens inside the real wallet — testing THAT needs a synced
    /// stagenet monerod + wallet (recorded as environment-deferred).
    #[test]
    fn end_to_end_against_mock_wallet_rpc() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read headers, then exactly Content-Length body bytes (TCP may segment them).
            let mut data: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            let header_end;
            loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "eof before headers complete");
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    break;
                }
            }
            let head = String::from_utf8_lossy(&data[..header_end]).to_string();
            let content_len: usize = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                .unwrap_or(0);
            while data.len() < header_end + content_len {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "eof before body complete");
                data.extend_from_slice(&buf[..n]);
            }
            let req = String::from_utf8_lossy(&data).to_string();
            assert!(req.contains("check_tx_proof"), "server saw: {req}");
            let body = r#"{"jsonrpc":"2.0","id":"0","result":{"confirmations":42,"good":true,"in_pool":false,"received":500000000000,"untrusted":false}}"#;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let out = check_tx_proof(
            &format!("http://127.0.0.1:{port}/json_rpc"),
            &"cd".repeat(32),
            "5SomeAddress",
            "inv_8d1e5b0c3a7f",
            "OutProofV2fakesig",
        )
        .expect("mock rpc call succeeds");
        assert!(out.good);
        assert_eq!(out.confirmations, 42);
        assert_eq!(out.received_atomic, 500_000_000_000);
        server.join().unwrap();
    }

    #[test]
    fn rejects_malformed_txid_before_any_network_call() {
        let r = check_tx_proof("http://127.0.0.1:1/json_rpc", "xyz", "a", "m", "s");
        assert!(r.is_err());
    }
}
