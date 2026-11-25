//! The words a 502 Bad Gateway says about the upstream it could not use.
//!
//! When the proxy cannot reach an upstream, or refuses one, the agent sees a
//! `502 Bad Gateway`. Many agents read any 5xx as a server outage and retry
//! for minutes, so the body names the host the client asked for and the
//! cause in plain words:
//!
//! ```text
//! {"error":"Bad Gateway","message":"nono proxy could not reach api.example.com:443: connection refused"}
//! ```
//!
//! The `error` field is unchanged. The message is built only from the host
//! and port the client asked for and a phrase from a fixed set, never from
//! an error's text: those carry resolved addresses, an upstream proxy's
//! address, and TLS and HTTP library text, none of which belong in a
//! response the sandboxed client reads.

use crate::error::ProxyError;

/// Why an upstream could not be used, in the words a 502 body gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamFailure {
    /// The name resolved to no address.
    DnsLookupFailed,
    /// The upstream refused the TCP connection.
    ConnectionRefused,
    /// No network route: this computer looks offline.
    NetworkUnreachable,
    /// The network is up but the host can't be reached.
    HostUnreachable,
    /// The connection, or the wait for the upstream's answer, timed out.
    TimedOut,
    /// TCP connected but the TLS handshake with the upstream failed.
    TlsHandshakeFailed,
    /// The configured upstream proxy could not be reached.
    UpstreamProxyUnreachable,
    /// The configured upstream proxy answered the CONNECT with a refusal.
    UpstreamProxyRefused,
    /// The intercepted host has no route for this host and port.
    NoRoute,
    /// Anything else.
    Other,
}

impl UpstreamFailure {
    /// Classify a proxy error. Only the variant, the `io::ErrorKind` and the
    /// crate's own reason strings decide; nothing of the error is kept.
    pub(crate) fn of(err: &ProxyError) -> Self {
        match err {
            ProxyError::UpstreamConnect { reason, .. } => Self::of_reason(reason),
            ProxyError::ExternalProxy(reason) => Self::of_reason(reason),
            ProxyError::Io(e) => Self::of_io(e),
            _ => Self::Other,
        }
    }

    /// Classify the reason string of a [`ProxyError::UpstreamConnect`] (or an
    /// external-proxy failure), as the CONNECT path holds it.
    pub(crate) fn of_reason(reason: &str) -> Self {
        let r = reason.to_ascii_lowercase();
        // The upstream proxy first: its connect error embeds an OS error
        // ("cannot connect to external proxy …: Connection refused") that is
        // about the proxy, not the host the client asked for.
        if r.contains("rejected connect") {
            Self::UpstreamProxyRefused
        } else if r.contains("external proxy") {
            Self::UpstreamProxyUnreachable
        } else if r.starts_with("tls handshake failed") || r.contains("server name for tls") {
            Self::TlsHandshakeFailed
        } else if r.starts_with("dns resolution") {
            Self::DnsLookupFailed
        } else if r.contains("timed out") {
            // "connection timed out" (connect_to_resolved), "timed out waiting
            // for upstream upgrade response", and the OS's ETIMEDOUT text
            // ("Connection timed out" on Linux, "Operation timed out" on macOS).
            Self::TimedOut
        } else if r.contains("connection refused") {
            Self::ConnectionRefused
        } else if r.contains("network is unreachable") || r.contains("network unreachable") {
            Self::NetworkUnreachable
        } else if r.contains("no route to host") || r.contains("host is unreachable") {
            Self::HostUnreachable
        } else {
            Self::Other
        }
    }

    fn of_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            ErrorKind::HostUnreachable => Self::HostUnreachable,
            ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Other,
        }
    }

    fn phrase(self) -> &'static str {
        match self {
            Self::DnsLookupFailed => "DNS lookup failed",
            Self::ConnectionRefused => "connection refused",
            Self::NetworkUnreachable => "the network is unreachable",
            Self::HostUnreachable => "no route to host",
            Self::TimedOut => "timed out",
            Self::TlsHandshakeFailed => "TLS handshake failed",
            Self::UpstreamProxyUnreachable => "the upstream proxy could not be reached",
            Self::UpstreamProxyRefused => "the upstream proxy refused the connection",
            Self::NoRoute => "no route is configured for this host and port",
            Self::Other => "the connection failed",
        }
    }

    /// The one-line message: the host and port the client asked for, and why.
    pub(crate) fn message(self, host: &str, port: u16) -> String {
        let target = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        match self {
            Self::NoRoute => format!("nono proxy refused {target}: {}", self.phrase()),
            _ => format!("nono proxy could not reach {target}: {}", self.phrase()),
        }
    }

    /// The JSON body of a 502 for this failure: `error` as before, plus
    /// `message`. Built with serde_json, so no host can break out of it.
    pub(crate) fn bad_gateway_body(self, host: &str, port: u16) -> String {
        serde_json::json!({
            "error": "Bad Gateway",
            "message": self.message(host, port),
        })
        .to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // OS error numbers, so the tests see the platform's own strerror text.
    #[cfg(target_os = "linux")]
    mod errno {
        pub const ECONNREFUSED: i32 = 111;
        pub const ENETUNREACH: i32 = 101;
        pub const EHOSTUNREACH: i32 = 113;
        pub const ETIMEDOUT: i32 = 110;
    }
    #[cfg(target_os = "macos")]
    mod errno {
        pub const ECONNREFUSED: i32 = 61;
        pub const ENETUNREACH: i32 = 51;
        pub const EHOSTUNREACH: i32 = 65;
        pub const ETIMEDOUT: i32 = 60;
    }

    fn connect_error(reason: String) -> ProxyError {
        ProxyError::UpstreamConnect {
            host: "api.example.com".to_string(),
            reason,
        }
    }

    fn test_connector() -> tokio_rustls::TlsConnector {
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    }

    fn os_reason(code: i32) -> String {
        // What connect_to_resolved stores: the io::Error's Display.
        std::io::Error::from_raw_os_error(code).to_string()
    }

    fn body_message(body: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["error"], "Bad Gateway", "error field must stay as it was");
        assert_eq!(v.as_object().unwrap().len(), 2, "only error and message");
        v["message"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn dns_lookup_failed_from_the_real_empty_resolution() {
        let connector = test_connector();
        let spec = crate::forward::UpstreamSpec {
            scheme: crate::forward::UpstreamScheme::Https,
            host: "api.example.com",
            port: 443,
            strategy: crate::forward::UpstreamStrategy::Direct {
                resolved_addrs: &[],
            },
            tls_connector: &connector,
        };
        let err = crate::forward::open_tcp_upstream(&spec).await.unwrap_err();
        assert_eq!(UpstreamFailure::of(&err), UpstreamFailure::DnsLookupFailed);
        assert_eq!(
            body_message(&UpstreamFailure::of(&err).bad_gateway_body("api.example.com", 443)),
            "nono proxy could not reach api.example.com:443: DNS lookup failed"
        );
    }

    #[tokio::test]
    async fn connection_refused_from_a_real_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);
        let connector = test_connector();
        let addrs = [addr];
        let spec = crate::forward::UpstreamSpec {
            scheme: crate::forward::UpstreamScheme::Https,
            host: "localhost",
            port: addr.port(),
            strategy: crate::forward::UpstreamStrategy::Direct {
                resolved_addrs: &addrs,
            },
            tls_connector: &connector,
        };
        let err = crate::forward::open_tcp_upstream(&spec).await.unwrap_err();
        assert_eq!(
            UpstreamFailure::of(&err),
            UpstreamFailure::ConnectionRefused
        );
    }

    #[tokio::test]
    async fn tls_handshake_failed_from_a_real_plaintext_upstream() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        });
        let connector = test_connector();
        let addrs = [addr];
        let spec = crate::forward::UpstreamSpec {
            scheme: crate::forward::UpstreamScheme::Https,
            host: "localhost",
            port: addr.port(),
            strategy: crate::forward::UpstreamStrategy::Direct {
                resolved_addrs: &addrs,
            },
            tls_connector: &connector,
        };
        let err = crate::forward::open_https_upstream(&spec)
            .await
            .unwrap_err();
        assert_eq!(
            UpstreamFailure::of(&err),
            UpstreamFailure::TlsHandshakeFailed
        );
    }

    #[tokio::test]
    async fn upstream_proxy_unreachable_from_a_real_closed_proxy_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let connector = test_connector();
        let spec = crate::forward::UpstreamSpec {
            scheme: crate::forward::UpstreamScheme::Https,
            host: "api.example.com",
            port: 443,
            strategy: crate::forward::UpstreamStrategy::ExternalProxy {
                proxy_addr: &addr,
                proxy_auth_header: None,
            },
            tls_connector: &connector,
        };
        let err = crate::forward::open_tcp_upstream(&spec).await.unwrap_err();
        // The OS error inside is "Connection refused", but it is the proxy's.
        assert_eq!(
            UpstreamFailure::of(&err),
            UpstreamFailure::UpstreamProxyUnreachable
        );
        let body = UpstreamFailure::of(&err).bad_gateway_body("api.example.com", 443);
        assert!(
            !body.contains(&addr),
            "the proxy's address stays out: {body}"
        );
    }

    #[test]
    fn os_errors_in_the_platforms_own_words() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use errno::*;
            for (code, want) in [
                (ECONNREFUSED, UpstreamFailure::ConnectionRefused),
                (ENETUNREACH, UpstreamFailure::NetworkUnreachable),
                (EHOSTUNREACH, UpstreamFailure::HostUnreachable),
                (ETIMEDOUT, UpstreamFailure::TimedOut),
            ] {
                let reason = os_reason(code);
                assert_eq!(UpstreamFailure::of_reason(&reason), want, "{reason}");
                assert_eq!(
                    UpstreamFailure::of(&ProxyError::Io(std::io::Error::from_raw_os_error(code))),
                    want,
                    "io kind of {reason}"
                );
            }
        }
        // musl's wording.
        assert_eq!(
            UpstreamFailure::of_reason("Network unreachable (os error 101)"),
            UpstreamFailure::NetworkUnreachable
        );
        assert_eq!(
            UpstreamFailure::of_reason("Host is unreachable (os error 113)"),
            UpstreamFailure::HostUnreachable
        );
    }

    #[test]
    fn the_crates_own_reasons() {
        for (reason, want) in [
            ("connection timed out", UpstreamFailure::TimedOut),
            (
                "timed out waiting for upstream upgrade response",
                UpstreamFailure::TimedOut,
            ),
            (
                "invalid server name for TLS",
                UpstreamFailure::TlsHandshakeFailed,
            ),
            (
                "enterprise proxy rejected CONNECT to api.example.com:443 with status 403",
                UpstreamFailure::UpstreamProxyRefused,
            ),
            (
                "failed to read response from external proxy: early eof",
                UpstreamFailure::UpstreamProxyUnreachable,
            ),
            (
                "upstream closed before sending an upgrade response",
                UpstreamFailure::Other,
            ),
            (
                "pool request failed: client error (Connect)",
                UpstreamFailure::Other,
            ),
        ] {
            assert_eq!(
                UpstreamFailure::of(&connect_error(reason.into())),
                want,
                "{reason}"
            );
        }
        assert_eq!(
            UpstreamFailure::of(&ProxyError::HttpParse("x".into())),
            UpstreamFailure::Other
        );
    }

    #[test]
    fn every_message() {
        let cases = [
            (
                UpstreamFailure::DnsLookupFailed,
                "could not reach h:443: DNS lookup failed",
            ),
            (
                UpstreamFailure::ConnectionRefused,
                "could not reach h:443: connection refused",
            ),
            (
                UpstreamFailure::NetworkUnreachable,
                "could not reach h:443: the network is unreachable",
            ),
            (
                UpstreamFailure::HostUnreachable,
                "could not reach h:443: no route to host",
            ),
            (
                UpstreamFailure::TimedOut,
                "could not reach h:443: timed out",
            ),
            (
                UpstreamFailure::TlsHandshakeFailed,
                "could not reach h:443: TLS handshake failed",
            ),
            (
                UpstreamFailure::UpstreamProxyUnreachable,
                "could not reach h:443: the upstream proxy could not be reached",
            ),
            (
                UpstreamFailure::UpstreamProxyRefused,
                "could not reach h:443: the upstream proxy refused the connection",
            ),
            (
                UpstreamFailure::NoRoute,
                "refused h:443: no route is configured for this host and port",
            ),
            (
                UpstreamFailure::Other,
                "could not reach h:443: the connection failed",
            ),
        ];
        for (failure, want) in cases {
            assert_eq!(failure.message("h", 443), format!("nono proxy {want}"));
        }
    }

    #[test]
    fn an_ipv6_host_is_bracketed_once() {
        let f = UpstreamFailure::ConnectionRefused;
        assert_eq!(
            f.message("::1", 8443),
            "nono proxy could not reach [::1]:8443: connection refused"
        );
        assert_eq!(
            f.message("[::1]", 8443),
            "nono proxy could not reach [::1]:8443: connection refused"
        );
    }

    #[test]
    fn a_hostile_host_cannot_break_the_json() {
        let host = "evil\"}\r\nX-Injected: 1\r\n\r\n{\"a";
        let body = UpstreamFailure::ConnectionRefused.bad_gateway_body(host, 443);
        assert!(!body.contains('\r') && !body.contains('\n'), "{body:?}");
        assert!(body_message(&body).contains(host));
    }

    #[test]
    fn nothing_but_host_port_and_phrase_reaches_the_body() {
        let secret_reason = "TLS handshake failed: invalid peer certificate for 10.1.2.3 token=abc";
        let err = connect_error(secret_reason.to_string());
        let body = UpstreamFailure::of(&err).bad_gateway_body("api.example.com", 443);
        assert_eq!(
            body,
            r#"{"error":"Bad Gateway","message":"nono proxy could not reach api.example.com:443: TLS handshake failed"}"#
        );
    }
}
