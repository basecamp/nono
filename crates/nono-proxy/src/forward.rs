//! Shared L7 upstream-forwarding pipeline.
//!
//! Used by both the reverse-proxy path ([`crate::reverse`]) and the
//! TLS-intercept CONNECT path ([`crate::tls_intercept`]). The two callers
//! differ in how they parse the inbound request, look up the route, and
//! transform/inject credentials, but converge on the same wire-level
//! upstream operation:
//!
//! 1. Establish an upstream byte stream — direct TCP (with optional TLS)
//!    or chained CONNECT through an enterprise proxy (then TLS).
//! 2. Write the pre-built HTTP/1.1 request bytes + body.
//! 3. Stream the response back into the inbound sink.
//! 4. Emit one L7 audit event with the response status.
//!
//! ## Why pre-built request bytes
//!
//! Each caller has its own rules for header filtering, credential
//! injection, and path transformation. Asking this module to handle that
//! would mean smuggling all of that policy through a parameter struct.
//! Instead, the caller hands in finished bytes: a clean separation
//! between "build the request" and "speak it on the wire".

use crate::audit;
use crate::error::{ProxyError, Result};
use crate::scrub::{ChunkedDecoder, CredentialScrubber, encode_chunk};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

/// Timeout for upstream TCP connect (matches the historical reverse-proxy value).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_REWRITE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Scheme of the upstream connection. `Http` is only legal for loopback
/// targets; the caller is responsible for enforcing that invariant
/// (`reverse.rs` does so via `validate_http_upstream_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

/// How the upstream byte stream is established.
pub enum UpstreamStrategy<'a> {
    /// Connect directly to one of `resolved_addrs` (DNS rebinding-safe:
    /// the addresses must already have been validated by the host filter).
    Direct { resolved_addrs: &'a [SocketAddr] },
    /// Chain a CONNECT through an enterprise proxy. `proxy_addr` is the
    /// `host:port` of the corporate proxy; `proxy_auth_header` is the literal
    /// value to send in `Proxy-Authorization` (e.g. `"Basic …"`), or `None`
    /// for unauthenticated proxies.
    ExternalProxy {
        proxy_addr: &'a str,
        proxy_auth_header: Option<&'a str>,
    },
}

/// Description of the upstream the caller wants to reach.
pub struct UpstreamSpec<'a> {
    pub scheme: UpstreamScheme,
    pub host: &'a str,
    pub port: u16,
    pub strategy: UpstreamStrategy<'a>,
    /// TLS connector to use for an `Https` scheme. Reverse-proxy callers
    /// pass either the route's per-route connector (custom CA / mTLS) or
    /// the shared default; intercept callers do the same.
    pub tls_connector: &'a TlsConnector,
}

/// Audit-emission context.
pub struct AuditCtx<'a> {
    pub log: Option<&'a audit::SharedAuditLog>,
    pub mode: audit::ProxyMode,
    pub event_ctx: audit::EventContext<'a>,
    /// Logical target string (route prefix for reverse, hostname for intercept).
    pub target: &'a str,
    pub method: &'a str,
    /// Path as it should appear in the audit log (the *inbound* path before
    /// any rewriting — e.g. `/v1/chat/completions`, not the upstream URL).
    pub path: &'a str,
}

/// Optional HTTP/1.1 response body rewrite hook.
///
/// Used for OAuth token capture, where the proxy must buffer a token endpoint
/// response, replace real token fields with phantoms, and only then release the
/// response to the sandboxed client.
pub type ResponseRewrite<'a> =
    &'a (dyn Fn(u16, &[(String, String)], &[u8]) -> Result<Vec<u8>> + Send + Sync);

/// Connect to the upstream, write `request_bytes + body`, stream the
/// response back into `inbound`, and emit the L7 audit event.
///
/// Returns the response status code (or 502 if the upstream sent something
/// unparseable).
pub async fn forward_request<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    forward_request_with_response_rewrite(inbound, request_bytes, body, upstream, audit, None, None)
        .await
}

/// Like [`forward_request`], with an optional response rewrite (OAuth token
/// capture) and an optional [`CredentialScrubber`] for a request that carries
/// an injected credential: the response's head and body are scrubbed of it
/// before they reach `inbound` (see [`crate::scrub`]).
pub async fn forward_request_with_response_rewrite<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
    response_rewrite: Option<ResponseRewrite<'_>>,
    scrub: Option<&CredentialScrubber>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let status = match upstream.scheme {
        UpstreamScheme::Https => {
            let mut tls_stream = open_https_upstream(&upstream).await?;
            write_request(&mut tls_stream, request_bytes, body).await?;
            stream_or_rewrite_response(
                &mut tls_stream,
                inbound,
                response_rewrite,
                scrub,
                audit.method,
            )
            .await?
        }
        UpstreamScheme::Http => {
            let mut tcp_stream = open_http_upstream(&upstream).await?;
            write_request(&mut tcp_stream, request_bytes, body).await?;
            stream_or_rewrite_response(
                &mut tcp_stream,
                inbound,
                response_rewrite,
                scrub,
                audit.method,
            )
            .await?
        }
    };

    audit::log_l7_request(
        audit.log,
        audit.mode,
        &audit.event_ctx,
        audit.target,
        audit.method,
        audit.path,
        status,
    );
    Ok(status)
}

async fn stream_or_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    response_rewrite: Option<ResponseRewrite<'_>>,
    scrub: Option<&CredentialScrubber>,
    method: &str,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    match (response_rewrite, scrub) {
        (Some(rewrite), scrub) => buffer_rewrite_response(upstream, inbound, rewrite, scrub).await,
        (None, Some(scrub)) => stream_scrubbed_response(upstream, inbound, scrub, method).await,
        (None, None) => stream_response(upstream, inbound).await,
    }
}

/// Open an upstream HTTPS connection (Direct TLS or ExternalProxy + TLS).
pub(crate) async fn open_https_upstream(
    upstream: &UpstreamSpec<'_>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = open_tcp_upstream(upstream).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(upstream.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    upstream
        .tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: upstream.host.to_string(),
            reason: format!("TLS handshake failed: {}", e),
        })
}

/// Open an upstream HTTP (plain) connection. Caller has already validated
/// that this is a loopback target.
async fn open_http_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    open_tcp_upstream(upstream).await
}

/// Establish the TCP layer of the upstream connection (without TLS).
pub(crate) async fn open_tcp_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    match upstream.strategy {
        UpstreamStrategy::Direct { resolved_addrs } => {
            if resolved_addrs.is_empty() {
                // Same fail-closed contract as CONNECT (`connect.rs`): never
                // re-resolve the hostname. An empty slice means DNS failed or
                // was skipped, so a second lookup would bypass the link-local
                // metadata check already applied to `resolved_addrs`.
                Err(ProxyError::UpstreamConnect {
                    host: upstream.host.to_string(),
                    reason: "DNS resolution returned no addresses".to_string(),
                })
            } else {
                connect_to_resolved(resolved_addrs, upstream.host).await
            }
        }
        UpstreamStrategy::ExternalProxy {
            proxy_addr,
            proxy_auth_header,
        } => crate::external::connect_via_proxy(
            proxy_addr,
            upstream.host,
            upstream.port,
            proxy_auth_header,
        )
        .await
        .map_err(|e| match e {
            ProxyError::ExternalProxy(reason) => ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason,
            },
            other => other,
        }),
    }
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. Connecting to the IP
/// directly (not re-resolving the hostname) prevents DNS rebinding TOCTOU.
async fn connect_to_resolved(addrs: &[SocketAddr], host: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                debug!("Connect to {} failed: {}", addr, e);
                last_err = Some(e.to_string());
            }
            Err(_) => {
                debug!("Connect to {} timed out", addr);
                last_err = Some("connection timed out".to_string());
            }
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_string(),
        reason: last_err.unwrap_or_else(|| "no addresses to connect to".to_string()),
    })
}

async fn write_request<S>(stream: &mut S, request: &[u8], body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Stream the upstream response back to the inbound sink.
///
/// Returns the HTTP status code parsed from the first chunk. Streams
/// chunked / SSE / HTTP-streaming bodies transparently because we never
/// buffer the body — each upstream read is mirrored to the inbound write.
async fn stream_response<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut status_code: u16 = 502;
    let mut first_chunk = true;

    loop {
        let n = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };

        if first_chunk {
            status_code = parse_response_status(&buf[..n]);
            first_chunk = false;
        }

        inbound.write_all(&buf[..n]).await?;
        inbound.flush().await?;
    }

    Ok(status_code)
}

/// Parse HTTP status code from the first response chunk.
///
/// Returns 502 when the response doesn't contain a valid status line.
fn parse_response_status(data: &[u8]) -> u16 {
    let line_end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    let first_line = &data[..line_end.min(64)];

    if let Ok(line) = std::str::from_utf8(first_line) {
        let mut parts = line.split_whitespace();
        if let Some(version) = parts.next()
            && version.starts_with("HTTP/")
            && let Some(code_str) = parts.next()
            && code_str.len() == 3
        {
            return code_str.parse().unwrap_or(502);
        }
    }
    502
}

/// Largest response head (status line and headers) the scrubbing path reads
/// before it gives up on the response.
const MAX_SCRUB_RESPONSE_HEAD: usize = 64 * 1024;

/// The framing and coding a response head declares.
struct ResponseHead {
    status: u16,
    chunked: bool,
    content_encoding: Option<String>,
    content_length: Option<String>,
}

fn parse_response_head(head: &[u8]) -> ResponseHead {
    let text = String::from_utf8_lossy(head);
    let mut parsed = ResponseHead {
        status: parse_response_status(head),
        chunked: false,
        content_encoding: None,
        content_length: None,
    };
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            parsed.chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding") {
            parsed.content_encoding = Some(match parsed.content_encoding.take() {
                Some(earlier) => format!("{earlier}, {value}"),
                None => value.to_string(),
            });
        } else if name.eq_ignore_ascii_case("content-length") {
            parsed.content_length = Some(value.to_string());
        }
    }
    parsed
}

/// Stream the upstream response to `inbound` with the injected credential
/// masked in its head and body.
///
/// Masking keeps every length, so a `Content-Length` body (and a body that
/// ends at close) streams through as it arrives. A chunked body is decoded
/// first, because a chunk boundary can fall inside a secret, and re-framed
/// one chunk per release. Interim (1xx) heads pass through, scrubbed. A
/// content-encoded response that may carry a body is refused before any of
/// its bytes are written: the scrub cannot read it.
async fn stream_scrubbed_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    scrub: &CredentialScrubber,
    method: &str,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    let mut masked = false;
    let head = loop {
        let head_end = loop {
            if let Some(end) = find_header_end(&pending) {
                break end.saturating_add(4);
            }
            if pending.len() > MAX_SCRUB_RESPONSE_HEAD {
                return Err(ProxyError::HttpParse(
                    "upstream response head too large".to_string(),
                ));
            }
            let n = upstream.read(&mut buf).await?;
            if n == 0 {
                return Err(ProxyError::HttpParse(
                    "upstream closed before the response head".to_string(),
                ));
            }
            pending.extend_from_slice(&buf[..n]);
        };
        let mut head_bytes: Vec<u8> = pending.drain(..head_end).collect();
        let head = parse_response_head(&head_bytes);
        if crate::scrub::refuses_content_encoding(
            head.content_encoding.as_deref(),
            method,
            head.status,
            head.content_length.as_deref(),
        ) {
            return Err(ProxyError::HttpParse(
                crate::scrub::content_encoding_refusal(
                    head.content_encoding.as_deref().unwrap_or_default(),
                ),
            ));
        }
        masked |= scrub.mask_in_place(&mut head_bytes);
        inbound.write_all(&head_bytes).await?;
        if !(100..200).contains(&head.status) || head.status == 101 {
            break head;
        }
    };

    let mut stream = scrub.stream();
    let mut decoder = head.chunked.then(ChunkedDecoder::default);
    let mut input = pending;
    loop {
        if !input.is_empty() {
            let out = match decoder.as_mut() {
                Some(decoder) => {
                    let mut plain = Vec::new();
                    decoder.feed(&input, &mut plain)?;
                    encode_chunk(&stream.push(&plain))
                }
                None => stream.push(&input),
            };
            if !out.is_empty() {
                inbound.write_all(&out).await?;
                inbound.flush().await?;
            }
        }
        if decoder.as_ref().is_some_and(ChunkedDecoder::is_done) {
            break;
        }
        input = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => buf[..n].to_vec(),
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };
    }
    let tail = stream.finish();
    match decoder {
        Some(decoder) => {
            inbound.write_all(&encode_chunk(&tail)).await?;
            // A body the upstream cut short stays short: no last chunk.
            if decoder.is_done() {
                inbound.write_all(b"0\r\n\r\n").await?;
            }
        }
        None => inbound.write_all(&tail).await?,
    }
    inbound.flush().await?;
    if masked || stream.masked() {
        warn!("credential scrub: masked the injected credential in an upstream response");
    }
    Ok(head.status)
}

const MAX_REWRITE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

async fn buffer_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    rewrite: ResponseRewrite<'_>,
    scrub: Option<&CredentialScrubber>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(UPSTREAM_REWRITE_READ_TIMEOUT, upstream.read(&mut buf))
            .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Upstream read error: {}", e);
                break;
            }
            Err(_) => {
                return Err(ProxyError::HttpParse(
                    "timed out reading response for OAuth capture rewrite".to_string(),
                ));
            }
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_REWRITE_RESPONSE_BYTES {
            return Err(ProxyError::HttpParse(
                "response too large for OAuth capture rewrite".to_string(),
            ));
        }
    }

    let mut rewritten = rewrite_http1_response(&raw, rewrite)?;
    // Same-length mask: the Content-Length the rewrite set stays right.
    if scrub.is_some_and(|scrub| scrub.mask_in_place(&mut rewritten)) {
        warn!("credential scrub: masked the injected credential in an upstream response");
    }
    let status = parse_response_status(&rewritten);
    inbound.write_all(&rewritten).await?;
    inbound.flush().await?;
    Ok(status)
}

fn rewrite_http1_response(raw: &[u8], rewrite: ResponseRewrite<'_>) -> Result<Vec<u8>> {
    let Some(header_end) = find_header_end(raw) else {
        return Err(ProxyError::HttpParse(
            "upstream response missing header terminator".to_string(),
        ));
    };
    let head = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let head_str = std::str::from_utf8(head).map_err(|_| {
        ProxyError::HttpParse("upstream response headers are not UTF-8".to_string())
    })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::HttpParse("upstream response missing status".to_string()))?;
    let status = parse_response_status(raw);
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_encoded = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim().to_string();
        let value_trimmed = value.trim().to_string();
        if name_trimmed.eq_ignore_ascii_case("transfer-encoding")
            && value_trimmed
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name_trimmed.eq_ignore_ascii_case("content-encoding") && !value_trimmed.is_empty() {
            content_encoded = true;
        }
        headers.push((name_trimmed, value_trimmed));
    }

    if chunked {
        body = decode_chunked_body(&body)?;
    }
    if content_encoded {
        return Err(ProxyError::HttpParse(
            "cannot safely rewrite or inspect content-encoded OAuth capture response".to_string(),
        ));
    }

    let rewritten_body = rewrite(status, &headers, &body)?;
    let mut out = Vec::new();
    out.extend_from_slice(status_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", rewritten_body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rewritten_body);
    Ok(out)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let Some(line_end_rel) = body[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        };
        let line_end = pos + line_end_rel;
        let size_line = std::str::from_utf8(&body[pos..line_end])
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| ProxyError::HttpParse("chunk size overflow".to_string()))?;
        if end + 2 > body.len() || &body[end..end + 2] != b"\r\n" {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        }
        out.extend_from_slice(&body[pos..end]);
        pos = end + 2;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_status_extracts_code() {
        assert_eq!(parse_response_status(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_response_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(parse_response_status(b"HTTP/1.1 502 Bad Gateway\r\n"), 502);
    }

    #[test]
    fn parse_response_status_handles_garbage() {
        assert_eq!(parse_response_status(b""), 502);
        assert_eq!(parse_response_status(b"garbage"), 502);
        assert_eq!(parse_response_status(b"NOT-HTTP 200 OK"), 502);
    }

    #[test]
    fn rewrite_http1_response_decodes_chunked_body_before_rewrite() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let rewritten = rewrite_http1_response(raw, &|_, _, body| {
            assert_eq!(body, br#"{"a":1}"#);
            Ok(br#"{"b":2}"#.to_vec())
        })
        .unwrap();

        let text = std::str::from_utf8(&rewritten).unwrap();
        assert!(text.contains("Content-Length: 7"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(text.ends_with(r#"{"b":2}"#));
    }

    #[tokio::test]
    async fn open_tcp_upstream_fails_closed_when_resolved_addrs_empty() {
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(config));
        let spec = UpstreamSpec {
            scheme: UpstreamScheme::Http,
            host: "does-not-resolve.invalid",
            port: 80,
            strategy: UpstreamStrategy::Direct {
                resolved_addrs: &[],
            },
            tls_connector: &connector,
        };
        let err = open_tcp_upstream(&spec).await.expect_err("empty addrs");
        match err {
            ProxyError::UpstreamConnect { host, reason } => {
                assert_eq!(host, "does-not-resolve.invalid");
                assert!(
                    reason.contains("DNS resolution returned no addresses"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected UpstreamConnect, got {other}"),
        }
    }

    const SECRET: &str = "ghs_scrubTestSecret0123456789";

    /// Feed `pieces` from a fake upstream (each its own write, then EOF) to
    /// `stream_scrubbed_response` and return its result and what the client got.
    async fn scrubbed(pieces: &[&[u8]], method: &str) -> (Result<u16>, Vec<u8>) {
        use tokio::io::AsyncWriteExt;
        let scrub = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let (mut proxy_side, mut origin) = tokio::io::duplex(64);
        let pieces: Vec<Vec<u8>> = pieces.iter().map(|p| p.to_vec()).collect();
        let writer = tokio::spawn(async move {
            for piece in pieces {
                origin.write_all(&piece).await.unwrap();
                origin.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            origin.shutdown().await.unwrap();
        });
        let mut inbound: Vec<u8> = Vec::new();
        let result = stream_scrubbed_response(&mut proxy_side, &mut inbound, &scrub, method).await;
        drop(proxy_side);
        let _ = writer.await;
        (result, inbound)
    }

    fn split_at_secret(text: &str, offset: usize) -> (Vec<u8>, Vec<u8>) {
        let at = text.find(SECRET).unwrap() + offset;
        (
            text.as_bytes()[..at].to_vec(),
            text.as_bytes()[at..].to_vec(),
        )
    }

    #[tokio::test]
    async fn scrubbed_response_masks_content_length_body_split_mid_secret() {
        let body = format!("{{\"authorization\":\"Bearer {SECRET}\"}}");
        let raw = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (a, b) = split_at_secret(&raw, 7);
        let (result, out) = scrubbed(&[&a, &b], "GET").await;
        assert_eq!(result.unwrap(), 400);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.len(), raw.len(), "{out}");
        assert!(!out.contains(SECRET), "{out}");
        assert!(out.contains(&format!("Content-Length: {}", body.len())));
        assert!(out.contains(&"*".repeat(SECRET.len())));
    }

    #[tokio::test]
    async fn scrubbed_response_masks_header_echo() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nX-Echo-Authorization: Bearer {SECRET}\r\nContent-Length: 2\r\n\r\nok"
        );
        let (result, out) = scrubbed(&[raw.as_bytes()], "GET").await;
        assert_eq!(result.unwrap(), 200);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains(SECRET), "{out}");
        assert!(out.ends_with("\r\n\r\nok"), "{out}");
    }

    /// A chunk boundary inside the secret: the body is decoded before the
    /// scrub and re-framed, so the client still gets valid chunked framing.
    #[tokio::test]
    async fn scrubbed_response_masks_secret_split_across_chunks() {
        let (left, right) = SECRET.split_at(10);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\ntoken={left}\r\n{:x}\r\n{right};\r\n0\r\n\r\n",
            6 + left.len(),
            right.len() + 1
        );
        let (result, out) = scrubbed(&[raw.as_bytes()], "GET").await;
        assert_eq!(result.unwrap(), 200);
        let out = String::from_utf8(out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("Transfer-Encoding: chunked"), "{out}");
        assert!(body.ends_with("0\r\n\r\n"), "{out}");
        let decoded = decode_chunked_body(body.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            format!("token={};", "*".repeat(SECRET.len()))
        );
    }

    #[tokio::test]
    async fn scrubbed_response_truncated_chunked_body_gets_no_last_chunk() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nonly-six";
        let (result, out) = scrubbed(&[raw.as_bytes()], "GET").await;
        assert_eq!(result.unwrap(), 200);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.ends_with("0\r\n\r\n"), "{out}");
    }

    #[tokio::test]
    async fn scrubbed_response_passes_interim_head() {
        let raw = format!(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n{SECRET}",
            SECRET.len()
        );
        let (result, out) = scrubbed(&[raw.as_bytes()], "POST").await;
        assert_eq!(result.unwrap(), 201);
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201"),
            "{out}"
        );
        assert!(!out.contains(SECRET), "{out}");
    }

    #[tokio::test]
    async fn scrubbed_response_refuses_content_encoded_body_before_writing() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nxxxx";
        let (result, out) = scrubbed(&[raw.as_bytes()], "GET").await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Content-Encoding gzip"), "{err}");
        assert!(out.is_empty(), "nothing may reach the client: {out:?}");
    }

    #[tokio::test]
    async fn scrubbed_response_allows_content_encoding_without_a_body() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 20\r\n\r\n";
        let (result, out) = scrubbed(&[raw.as_bytes()], "HEAD").await;
        assert_eq!(result.unwrap(), 200);
        assert_eq!(out, raw.as_bytes());
    }

    #[test]
    fn buffered_rewrite_output_is_scrubbed_too() {
        let scrub = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut rewritten = rewrite_http1_response(raw, &|_, _, _| {
            Ok(format!("{{\"t\":\"{SECRET}\"}}").into_bytes())
        })
        .unwrap();
        let before = rewritten.len();
        assert!(scrub.mask_in_place(&mut rewritten));
        assert_eq!(rewritten.len(), before);
        assert!(!String::from_utf8(rewritten).unwrap().contains(SECRET));
    }

    #[test]
    fn rewrite_http1_response_rejects_content_encoded_body_for_all_statuses() {
        let raw =
            b"HTTP/1.1 400 Bad Request\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nxxxx";
        let err = rewrite_http1_response(raw, &|_, _, body| Ok(body.to_vec())).unwrap_err();

        assert!(
            err.to_string()
                .contains("content-encoded OAuth capture response"),
            "unexpected error: {err}"
        );
    }
}
