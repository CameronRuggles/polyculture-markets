//! Wallet RPC client for the seller's LOCAL monero-wallet-rpc.
//!
//! Every RPC call in this tool passes through the single choke point
//! [`RpcClient::call`], which matches the method name against
//! [`ALLOWED_METHODS`] and refuses anything else BEFORE any network
//! I/O happens. The transport is a hand-rolled minimal HTTP/1.1 POST
//! over `std::net::TcpStream` to 127.0.0.1/localhost only, with HTTP
//! Digest authentication (MD5, qop=auth) as required by Monero's epee
//! server when the wallet RPC is started with `--rpc-login`.
//!
//! No other network access exists in this binary: no telemetry, no
//! update checks, no uploads. The only socket it ever opens is to the
//! configured loopback RPC URL.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The complete allowlist of wallet RPC methods this tool may call.
/// Anything else — notably `transfer`, `sweep_all`, `query_key`,
/// `get_balance`, wallet open/create/close methods — is refused in
/// [`RpcClient::call`] before any network I/O.
pub const ALLOWED_METHODS: &[&str] = &[
    "get_version",
    "get_address",
    "create_account",
    "create_address",
    "label_address",
    "get_address_index",
    "sign",
    "verify",
];

pub fn ensure_allowed(method: &str) -> Result<(), RpcError> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(RpcError::NotAllowed(method.to_string()))
    }
}

#[derive(Debug)]
pub enum RpcError {
    /// Method is not on the allowlist. Returned before any network I/O.
    NotAllowed(String),
    /// TCP/HTTP level failure (connect, read, unexpected status, ...).
    Transport(String),
    /// The wallet RPC returned a JSON-RPC error object.
    Rpc { code: i64, message: String },
    /// Digest authentication failed / was demanded but not configured.
    Auth(String),
    /// The response did not have the expected shape.
    Parse(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::NotAllowed(m) => {
                write!(f, "RPC method {m:?} is not on the helper allowlist; refused")
            }
            RpcError::Transport(m) => write!(f, "wallet RPC transport error: {m}"),
            RpcError::Rpc { code, message } => {
                write!(f, "wallet RPC error {code}: {message}")
            }
            RpcError::Auth(m) => write!(f, "wallet RPC authentication failed: {m}"),
            RpcError::Parse(m) => write!(f, "unexpected wallet RPC response shape: {m}"),
        }
    }
}

impl std::error::Error for RpcError {}

pub struct RpcClient {
    host: String,
    port: u16,
    path: String,
    user: String,
    password: String,
}

struct HttpResponse {
    status: u16,
    /// Header names lowercased; duplicates preserved (the epee server
    /// sends two WWW-Authenticate headers: MD5 and MD5-sess).
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RpcClient {
    pub fn new(host: &str, port: u16, path: &str, user: &str, password: &str) -> RpcClient {
        RpcClient {
            host: host.to_string(),
            port,
            path: path.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        }
    }

    pub fn from_config(cfg: &crate::config::Config) -> Result<RpcClient, RpcError> {
        let url = crate::config::parse_rpc_url(&cfg.rpc_url).map_err(RpcError::Transport)?;
        Ok(RpcClient::new(
            &url.host,
            url.port,
            &url.path,
            &cfg.rpc_user,
            &cfg.rpc_password,
        ))
    }

    /// THE choke point. Every wallet RPC call in this crate goes
    /// through here; the allowlist check runs before any socket is
    /// opened, so a refused method provably causes no network I/O.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        ensure_allowed(method)?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        })
        .to_string();
        let resp = self.http_post_json_rpc(&body)?;
        let text = String::from_utf8_lossy(&resp.body);
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| RpcError::Parse(format!("response is not JSON ({e}): {text:.120}")))?;
        if let Some(err) = parsed.get("error") {
            if !err.is_null() {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string();
                return Err(RpcError::Rpc { code, message });
            }
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Parse("response has no \"result\" field".to_string()))
    }

    /// One JSON-RPC POST, with the Digest handshake when demanded.
    ///
    /// IMPORTANT (confirmed against monero-wallet-rpc v0.18.4.3): the
    /// epee server binds the Digest nonce to the TCP CONNECTION. The
    /// authenticated retry must be sent on the same connection that
    /// received the 401 challenge — a retry on a fresh connection is
    /// rejected with another 401 even when the Digest response hash is
    /// correct. Both attempts therefore share one connection here, and
    /// responses are read by Content-Length (not by waiting for the
    /// server to close, which it won't on a kept-alive connection).
    fn http_post_json_rpc(&self, body: &str) -> Result<HttpResponse, RpcError> {
        let stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|e| {
            RpcError::Transport(format!(
                "cannot connect to {}:{} ({e}); is monero-wallet-rpc running there?",
                self.host, self.port
            ))
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let mut conn = HttpConn {
            stream,
            buf: Vec::new(),
        };
        let first = self.send_and_read(&mut conn, body, None)?;
        if first.status != 401 {
            if first.status != 200 {
                return Err(RpcError::Transport(format!(
                    "wallet RPC returned HTTP {}",
                    first.status
                )));
            }
            return Ok(first);
        }
        // 401: the server demands Digest auth. Answer on THIS
        // connection (see the note above), with nc starting at 1 for
        // this connection's challenge.
        if self.user.is_empty() {
            return Err(RpcError::Auth(
                "server requires an RPC login but none is configured".to_string(),
            ));
        }
        let auth = self.digest_authorization(&first, 1)?;
        let second = self.send_and_read(&mut conn, body, Some(&auth))?;
        if second.status == 401 {
            return Err(RpcError::Auth(
                "login rejected (check the --rpc-login user/password in your config)".to_string(),
            ));
        }
        if second.status != 200 {
            return Err(RpcError::Transport(format!(
                "wallet RPC returned HTTP {}",
                second.status
            )));
        }
        Ok(second)
    }

    fn send_and_read(
        &self,
        conn: &mut HttpConn,
        body: &str,
        authorization: Option<&str>,
    ) -> Result<HttpResponse, RpcError> {
        let mut req = String::new();
        req.push_str(&format!("POST {} HTTP/1.1\r\n", self.path));
        req.push_str(&format!("Host: {}:{}\r\n", self.host, self.port));
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        if let Some(auth) = authorization {
            req.push_str(&format!("Authorization: {auth}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        conn.stream
            .write_all(req.as_bytes())
            .map_err(|e| RpcError::Transport(format!("writing request failed: {e}")))?;
        conn.read_response()
    }

    /// Build the Digest Authorization header for a 401 challenge.
    /// The epee server offers two challenges (algorithm=MD5 and
    /// algorithm=MD5-sess) with the same nonce; this tool implements
    /// plain MD5 with qop=auth and picks that challenge.
    fn digest_authorization(&self, resp: &HttpResponse, nc_value: u32) -> Result<String, RpcError> {
        let challenges: Vec<&str> = resp
            .headers
            .iter()
            .filter(|(name, _)| name == "www-authenticate")
            .map(|(_, value)| value.as_str())
            .filter(|v| v.trim_start().to_ascii_lowercase().starts_with("digest"))
            .collect();
        if challenges.is_empty() {
            return Err(RpcError::Auth(
                "401 response carried no Digest challenge".to_string(),
            ));
        }
        let mut chosen: Option<HashMap<String, String>> = None;
        for raw in &challenges {
            let params = parse_digest_params(&raw["digest".len()..]);
            match params.get("algorithm").map(|a| a.to_ascii_uppercase()) {
                None => {
                    chosen = Some(params);
                    break;
                }
                Some(ref a) if a == "MD5" => {
                    chosen = Some(params);
                    break;
                }
                _ => {
                    if chosen.is_none() {
                        chosen = Some(params);
                    }
                }
            }
        }
        let params = chosen.ok_or_else(|| RpcError::Auth("no usable Digest challenge".into()))?;
        let algorithm = params
            .get("algorithm")
            .cloned()
            .unwrap_or_else(|| "MD5".to_string());
        if !algorithm.eq_ignore_ascii_case("MD5") {
            return Err(RpcError::Auth(format!(
                "unsupported Digest algorithm {algorithm:?} (this tool implements MD5)"
            )));
        }
        let realm = params.get("realm").cloned().unwrap_or_default();
        let nonce = params
            .get("nonce")
            .cloned()
            .ok_or_else(|| RpcError::Auth("Digest challenge has no nonce".to_string()))?;
        let qop = params.get("qop").cloned();
        let opaque = params.get("opaque").cloned();

        let nc = format!("{nc_value:08x}");
        let cnonce = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let digest = format!("{:x}", md5::compute(format!("{}-{nanos}", std::process::id()).as_bytes()));
            digest[..16].to_string()
        };
        let ha1 = md5_hex(&format!("{}:{}:{}", self.user, realm, self.password));
        let ha2 = md5_hex(&format!("POST:{}", self.path));
        let response = match &qop {
            Some(q) => md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{q}:{ha2}")),
            None => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
        };
        let mut auth = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5",
            self.user, realm, nonce, self.path, response
        );
        if let Some(q) = &qop {
            auth.push_str(&format!(", qop={q}, nc={nc}, cnonce=\"{cnonce}\""));
        }
        if let Some(o) = &opaque {
            auth.push_str(&format!(", opaque=\"{o}\""));
        }
        Ok(auth)
    }

    // ---- Typed wrappers over `call`. Response shapes below were
    // ---- confirmed against monero-wallet-rpc v0.18.4.3 (stagenet).

    /// get_version → `{release: bool, version: u32}` (65565 on 0.18.4.3).
    pub fn get_version(&self) -> Result<(u32, bool), RpcError> {
        let r = self.call("get_version", json!({}))?;
        let version = r
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Parse("get_version: no numeric \"version\"".into()))?
            as u32;
        let release = r.get("release").and_then(Value::as_bool).unwrap_or(false);
        Ok((version, release))
    }

    /// get_address {account_index} →
    /// `{address: String, addresses: [{address, address_index, label, used}, ...]}`
    /// where `address` is the account's primary (index 0) address and the
    /// `addresses` entries are OBJECTS. Unknown account → RPC error
    /// code -14, message "account index is out of bound".
    pub fn get_address(&self, account_index: u32) -> Result<AccountAddresses, RpcError> {
        let r = self.call("get_address", json!({ "account_index": account_index }))?;
        let primary = r
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::Parse("get_address: no string \"address\"".into()))?
            .to_string();
        let mut entries = Vec::new();
        if let Some(arr) = r.get("addresses").and_then(Value::as_array) {
            for e in arr {
                entries.push(AddressEntry {
                    address: e
                        .get("address")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    address_index: e
                        .get("address_index")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32,
                    label: e
                        .get("label")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    used: e.get("used").and_then(Value::as_bool).unwrap_or(false),
                });
            }
        }
        Ok(AccountAddresses { primary, entries })
    }

    /// create_account {label} → `{account_index, address}`.
    pub fn create_account(&self, label: &str) -> Result<(u32, String), RpcError> {
        let r = self.call("create_account", json!({ "label": label }))?;
        let idx = r
            .get("account_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Parse("create_account: no \"account_index\"".into()))?
            as u32;
        let addr = r
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok((idx, addr))
    }

    /// create_address {account_index, count} →
    /// `{address, address_index, address_indices: [u32], addresses: [String]}`
    /// NOTE: unlike get_address, `addresses` here is an array of PLAIN
    /// STRINGS (confirmed on v0.18.4.3).
    pub fn create_address(
        &self,
        account_index: u32,
        count: u32,
    ) -> Result<CreatedAddresses, RpcError> {
        let r = self.call(
            "create_address",
            json!({ "account_index": account_index, "count": count }),
        )?;
        let addresses: Vec<String> = r
            .get("addresses")
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::Parse("create_address: no \"addresses\" array".into()))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| RpcError::Parse("create_address: address not a string".into()))
            })
            .collect::<Result<_, _>>()?;
        let indices: Vec<u32> = r
            .get("address_indices")
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::Parse("create_address: no \"address_indices\"".into()))?
            .iter()
            .map(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .ok_or_else(|| RpcError::Parse("create_address: index not a number".into()))
            })
            .collect::<Result<_, _>>()?;
        if addresses.len() != indices.len() {
            return Err(RpcError::Parse(
                "create_address: addresses/address_indices length mismatch".into(),
            ));
        }
        Ok(CreatedAddresses { addresses, indices })
    }

    /// label_address {index: {major, minor}, label} → `{}`.
    pub fn label_address(&self, major: u32, minor: u32, label: &str) -> Result<(), RpcError> {
        self.call(
            "label_address",
            json!({ "index": { "major": major, "minor": minor }, "label": label }),
        )?;
        Ok(())
    }

    /// get_address_index {address} → on v0.18.4.3 the result is
    /// `{index: {major, minor}}` — there are NO top-level
    /// account_index/address_index fields in the response.
    /// An address the wallet does not own → RPC error code -2,
    /// message "Address doesn't belong to the wallet".
    pub fn get_address_index(&self, address: &str) -> Result<(u32, u32), RpcError> {
        let r = self.call("get_address_index", json!({ "address": address }))?;
        let index = r
            .get("index")
            .ok_or_else(|| RpcError::Parse("get_address_index: no \"index\" object".into()))?;
        let major = index
            .get("major")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Parse("get_address_index: no \"major\"".into()))? as u32;
        let minor = index
            .get("minor")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Parse("get_address_index: no \"minor\"".into()))? as u32;
        Ok((major, minor))
    }

    /// sign {data} → `{signature}`: 93 chars, starts with "SigV2"
    /// (spend-key signature from account 0's primary key).
    pub fn sign(&self, data: &str) -> Result<String, RpcError> {
        let r = self.call("sign", json!({ "data": data }))?;
        r.get("signature")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::Parse("sign: no string \"signature\"".into()))
    }

    /// verify {data, address, signature} →
    /// `{good: bool, old: bool, signature_type: "spend", version: 2}`.
    /// Works for addresses the wallet does not own. Returns `good`.
    pub fn verify(&self, data: &str, address: &str, signature: &str) -> Result<bool, RpcError> {
        let r = self.call(
            "verify",
            json!({ "data": data, "address": address, "signature": signature }),
        )?;
        r.get("good")
            .and_then(Value::as_bool)
            .ok_or_else(|| RpcError::Parse("verify: no bool \"good\"".into()))
    }
}

#[derive(Debug, Clone)]
pub struct AddressEntry {
    pub address: String,
    pub address_index: u32,
    pub label: String,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub struct AccountAddresses {
    pub primary: String,
    pub entries: Vec<AddressEntry>,
}

#[derive(Debug, Clone)]
pub struct CreatedAddresses {
    pub addresses: Vec<String>,
    pub indices: Vec<u32>,
}

fn md5_hex(data: &str) -> String {
    format!("{:x}", md5::compute(data.as_bytes()))
}

/// Parse the parameter list of a Digest challenge (the part after
/// "Digest "), honouring quoted strings (which may contain commas).
pub fn parse_digest_params(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = s[key_start..i].trim().to_ascii_lowercase();
        i += 1; // skip '='
        let value;
        if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let val_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            value = s[val_start..i].to_string();
            i += 1; // skip closing quote
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            value = s[val_start..i].trim().to_string();
        }
        map.insert(key, value);
    }
    map
}

/// A single HTTP connection with a small read buffer. Responses are
/// framed by Content-Length (or chunked encoding), never by waiting
/// for close: the Digest handshake needs the connection kept alive.
struct HttpConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl HttpConn {
    fn fill_some(&mut self) -> Result<usize, RpcError> {
        let mut chunk = [0u8; 8192];
        let n = self
            .stream
            .read(&mut chunk)
            .map_err(|e| RpcError::Transport(format!("reading response failed: {e}")))?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// Consume and return the next `n` bytes, reading as needed.
    fn take(&mut self, n: usize) -> Result<Vec<u8>, RpcError> {
        while self.buf.len() < n {
            if self.fill_some()? == 0 {
                return Err(RpcError::Transport(
                    "connection closed mid-response".into(),
                ));
            }
        }
        let out = self.buf[..n].to_vec();
        self.buf.drain(..n);
        Ok(out)
    }

    /// Consume and return one CRLF-terminated line (without the CRLF).
    fn take_line(&mut self) -> Result<Vec<u8>, RpcError> {
        loop {
            if let Some(pos) = find_subslice(&self.buf, b"\r\n") {
                let line = self.buf[..pos].to_vec();
                self.buf.drain(..pos + 2);
                return Ok(line);
            }
            if self.fill_some()? == 0 {
                return Err(RpcError::Transport(
                    "connection closed mid-response".into(),
                ));
            }
        }
    }

    fn read_response(&mut self) -> Result<HttpResponse, RpcError> {
        // Header block: lines until an empty line.
        let mut status: Option<u16> = None;
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let line = self.take_line()?;
            if line.is_empty() {
                break;
            }
            let text = String::from_utf8_lossy(&line).to_string();
            if status.is_none() {
                status = Some(
                    text.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| {
                            RpcError::Transport(format!("bad HTTP status line: {text}"))
                        })?,
                );
            } else if let Some(colon) = text.find(':') {
                headers.push((
                    text[..colon].trim().to_ascii_lowercase(),
                    text[colon + 1..].trim().to_string(),
                ));
            }
        }
        let status = status.ok_or_else(|| RpcError::Transport("empty HTTP response".into()))?;
        let chunked = headers.iter().any(|(n, v)| {
            n == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked")
        });
        let body = if chunked {
            self.read_chunked_body()?
        } else {
            match headers
                .iter()
                .find(|(n, _)| n == "content-length")
                .and_then(|(_, v)| v.parse::<usize>().ok())
            {
                Some(len) => self.take(len)?,
                // No framing information: read until close.
                None => {
                    let mut body = std::mem::take(&mut self.buf);
                    let mut chunk = [0u8; 8192];
                    loop {
                        let n = self
                            .stream
                            .read(&mut chunk)
                            .map_err(|e| RpcError::Transport(format!("reading response failed: {e}")))?;
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    body
                }
            }
        };
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    fn read_chunked_body(&mut self) -> Result<Vec<u8>, RpcError> {
        let mut out = Vec::new();
        loop {
            let line = self.take_line()?;
            let size_str = String::from_utf8_lossy(&line).to_string();
            let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| RpcError::Transport("bad chunk size".into()))?;
            if size == 0 {
                // Trailer headers end with an empty line.
                loop {
                    if self.take_line()?.is_empty() {
                        break;
                    }
                }
                break;
            }
            out.extend_from_slice(&self.take(size)?);
            let crlf = self.take(2)?;
            if crlf != b"\r\n" {
                return Err(RpcError::Transport("bad chunk framing".into()));
            }
        }
        Ok(out)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_client() -> RpcClient {
        // Nothing listens on 127.0.0.1:1; if the allowlist check did
        // not run first, calls would fail with a Transport error
        // instead of NotAllowed — which is exactly what these tests
        // distinguish. They pass with no server running.
        RpcClient::new("127.0.0.1", 1, "/json_rpc", "user", "pass")
    }

    #[test]
    fn allowlist_refuses_dangerous_methods_without_network() {
        let client = dead_client();
        for method in [
            "transfer",
            "query_key",
            "sweep_all",
            "get_balance",
            "get_accounts",
            "open_wallet",
            "create_wallet",
            "close_wallet",
            "restore_deterministic_wallet",
            "get_transfers",
            "",
        ] {
            match client.call(method, json!({})) {
                Err(RpcError::NotAllowed(m)) => assert_eq!(m, method),
                other => panic!("method {method:?} must be refused by the allowlist, got {other:?}"),
            }
        }
    }

    #[test]
    fn allowlist_contains_exactly_the_spec_methods() {
        let mut sorted: Vec<&str> = ALLOWED_METHODS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![
                "create_account",
                "create_address",
                "get_address",
                "get_address_index",
                "get_version",
                "label_address",
                "sign",
                "verify",
            ]
        );
    }

    #[test]
    fn allowlisted_method_reaches_the_network_layer() {
        // Sanity: an allowlisted method is NOT refused; against a dead
        // port it fails as a transport error instead.
        let client = dead_client();
        match client.call("get_version", json!({})) {
            Err(RpcError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn digest_challenge_parsing_prefers_md5_over_md5_sess() {
        // The exact challenge pair captured from monero-wallet-rpc
        // v0.18.4.3 (two WWW-Authenticate headers, same nonce).
        let resp = HttpResponse {
            status: 401,
            headers: vec![
                (
                    "www-authenticate".to_string(),
                    "Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"CNs6N9a/lf9gBMk5pXv+Pg==\",stale=false".to_string(),
                ),
                (
                    "www-authenticate".to_string(),
                    "Digest qop=\"auth\",algorithm=MD5-sess,realm=\"monero-rpc\",nonce=\"CNs6N9a/lf9gBMk5pXv+Pg==\",stale=false".to_string(),
                ),
            ],
            body: Vec::new(),
        };
        let client = RpcClient::new("127.0.0.1", 28088, "/json_rpc", "user", "pass");
        let auth = client.digest_authorization(&resp, 1).unwrap();
        assert!(auth.starts_with("Digest username=\"user\""), "{auth}");
        assert!(auth.contains("algorithm=MD5"), "{auth}");
        assert!(!auth.contains("MD5-sess"), "{auth}");
        assert!(auth.contains("qop=auth"), "{auth}");
        assert!(auth.contains("nonce=\"CNs6N9a/lf9gBMk5pXv+Pg==\""), "{auth}");
        // response hash is 32 lowercase hex chars
        let resp_hash = auth
            .split("response=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap();
        assert_eq!(resp_hash.len(), 32);
        assert!(resp_hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn digest_params_parse_quoted_values_with_special_chars() {
        let params = parse_digest_params(
            " qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"CNs6N9a/lf9gBMk5pXv+Pg==\",stale=false",
        );
        assert_eq!(params["realm"], "monero-rpc");
        assert_eq!(params["nonce"], "CNs6N9a/lf9gBMk5pXv+Pg==");
        assert_eq!(params["qop"], "auth");
        assert_eq!(params["algorithm"], "MD5");
    }
}
