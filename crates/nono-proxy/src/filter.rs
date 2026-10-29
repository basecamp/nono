//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Checks the hostname against the allowlist/deny list before resolving DNS,
//! then resolves and checks the resulting IPs against the link-local range
//! (cloud metadata SSRF protection) and, under a public-only
//! [`ResolvedAddressPolicy`], against the other non-public address classes.

use crate::config::{ResolvedAddressPolicy, is_proxy_denied_metadata_ip, parse_host_ip_literal};
use crate::error::Result;
use nono::net_filter::{
    AddressClass, FilterResult, HostFilter, address_class, host_pattern_matches,
};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::debug;

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: FilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
    /// IP addresses the allowlist names as exact entries (`10.1.2.3`,
    /// `[fd00::1]:8443`): an address named outright is permitted by a
    /// public-only address policy.
    named_ips: Arc<Vec<IpAddr>>,
    /// The public-only address gate, when the policy sets `public_only`.
    address_gate: Option<Arc<AddressGate>>,
}

/// A public-only [`ResolvedAddressPolicy`], normalized for matching.
#[derive(Debug)]
struct AddressGate {
    /// (normalized host pattern, classes it may resolve to)
    exceptions: Vec<(String, Vec<AddressClass>)>,
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
            named_ips: Arc::new(named_ips(allowed_hosts)),
            address_gate: None,
        }
    }

    /// Create a strict proxy filter: an empty allowlist denies every host.
    #[must_use]
    pub fn new_strict(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new_strict(allowed_hosts),
            named_ips: Arc::new(named_ips(allowed_hosts)),
            address_gate: None,
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
            named_ips: Arc::new(Vec::new()),
            address_gate: None,
        }
    }

    /// Apply a resolved-address policy. Without `public_only` this changes
    /// nothing; with it, every address a host resolves to must be public, or
    /// in a class the policy's exceptions permit for that host, or the
    /// host's own IP literal named by the allowlist. The policy must already
    /// be valid ([`ResolvedAddressPolicy::validate`]).
    #[must_use]
    pub fn with_resolved_address_policy(self, policy: &ResolvedAddressPolicy) -> Self {
        if !policy.public_only {
            return self;
        }
        let exceptions = policy
            .exceptions
            .iter()
            .map(|(pattern, classes)| {
                (
                    HostFilter::normalize_authority_host(pattern),
                    classes.clone(),
                )
            })
            .collect();
        Self {
            address_gate: Some(Arc::new(AddressGate { exceptions })),
            ..self
        }
    }

    /// Append user-configured deny entries. Evaluated before the allowlist.
    ///
    /// Supports the same wildcard syntax as the allowlist (`*.example.com`).
    #[must_use]
    pub fn with_denied_hosts(self, denied: &[String]) -> Self {
        if denied.is_empty() {
            return self;
        }
        Self {
            inner: self.inner.with_denied_hosts(denied),
            ..self
        }
    }

    /// Check a host against the filter with async DNS resolution.
    ///
    /// The allowlist/deny check runs on the hostname alone before any DNS
    /// lookup, since resolution itself sends a query to the domain's
    /// nameserver and would leak the hostname even for a denied host.
    ///
    /// Once resolved, all resolved IPs are checked against the link-local
    /// deny range (cloud metadata SSRF / DNS rebinding protection).
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        let pre_check = proxy_metadata_filter_result(host, &[])
            .unwrap_or_else(|| self.check_host_result(host, port, &[]));

        if !pre_check.is_allowed() {
            return Ok(CheckResult {
                result: pre_check,
                resolved_addrs: Vec::new(),
            });
        }

        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let result = proxy_metadata_filter_result(host, &resolved_ips)
            .unwrap_or_else(|| self.check_host_result(host, port, &resolved_ips));
        let result = self.gate_addresses(host, &resolved_ips, result);

        // Only return resolved addrs on allow to prevent misuse
        let addrs = if result.is_allowed() {
            resolved
        } else {
            Vec::new()
        };

        Ok(CheckResult {
            result,
            resolved_addrs: addrs,
        })
    }

    /// Check a host with pre-resolved IPs (no DNS lookup).
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        let result = proxy_metadata_filter_result(host, resolved_ips)
            .unwrap_or_else(|| self.inner.check_host(host, resolved_ips));
        self.gate_addresses(host, resolved_ips, result)
    }

    /// Under a public-only policy, turn an allow into a deny when any of
    /// `resolved_ips` is in a non-public class the policy does not permit for
    /// `host`. Any one such address denies the host, as a link-local one
    /// does: the caller connects to whichever resolved address answers.
    fn gate_addresses(
        &self,
        host: &str,
        resolved_ips: &[IpAddr],
        result: FilterResult,
    ) -> FilterResult {
        let Some(gate) = self.address_gate.as_deref() else {
            return result;
        };
        if !result.is_allowed() {
            return result;
        }
        let normalized = HostFilter::normalize_authority_host(host);
        let literal = parse_host_ip_literal(host);
        for ip in resolved_ips {
            let Some(class) = address_class(ip) else {
                continue;
            };
            let named = literal == Some(*ip) && self.named_ips.contains(ip);
            let excepted = gate.exceptions.iter().any(|(pattern, classes)| {
                classes.contains(&class) && host_pattern_matches(pattern, &normalized)
            });
            let permittable = !matches!(class, AddressClass::LinkLocal | AddressClass::Unspecified);
            if !(permittable && (named || excepted)) {
                return FilterResult::DenyAddressClass {
                    host: host.to_string(),
                    ip: *ip,
                    class,
                };
            }
        }
        result
    }

    /// Checks deny (incl. `host:port`) before the allowlist, so a wildcard
    /// `allow_domain: ["*"]` can't shadow a port-scoped deny entry.
    fn check_host_result(&self, host: &str, port: u16, resolved_ips: &[IpAddr]) -> FilterResult {
        // Normalize before appending the port: a raw trailing dot would land
        // mid-string (e.g. "evil.com.:443"), past where normalization looks.
        let normalized_host = HostFilter::normalize_authority_host(host);
        // Bracket IPv6 literals so their embedded colons can't be mistaken
        // for the port separator (e.g. "[::1]:8975", not "::1:8975").
        let host_port = if normalized_host.parse::<Ipv6Addr>().is_ok() {
            format!("[{normalized_host}]:{port}")
        } else {
            format!("{normalized_host}:{port}")
        };

        if let Some(deny) = self.inner.check_deny(&host_port) {
            return deny;
        }
        if let Some(deny) = self.inner.check_deny(host) {
            return deny;
        }

        let result = self.inner.check_host(host, resolved_ips);
        if !matches!(result, FilterResult::DenyNotAllowed { .. }) {
            return result;
        }

        self.inner.check_host(&host_port, resolved_ips)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
}

/// The IP addresses among `allowed_hosts` written as exact entries: a bare
/// literal (`10.1.2.3`, `fd00::1`, `[fd00::1]`) or one with a port
/// (`10.1.2.3:8080`, `[fd00::1]:8443`). Wildcard entries name no address.
fn named_ips(allowed_hosts: &[String]) -> Vec<IpAddr> {
    allowed_hosts
        .iter()
        .filter(|entry| !entry.contains('*'))
        .filter_map(|entry| {
            let entry = entry.trim();
            parse_host_ip_literal(entry).or_else(|| {
                let (host, port) = entry.rsplit_once(':')?;
                port.parse::<u16>().ok()?;
                if host.contains(':') && !host.starts_with('[') {
                    // An unbracketed IPv6 literal: its last group is not a port.
                    return None;
                }
                parse_host_ip_literal(host)
            })
        })
        .collect()
}

fn proxy_metadata_filter_result(host: &str, resolved_ips: &[IpAddr]) -> Option<FilterResult> {
    if parse_host_ip_literal(host).is_some_and(|ip| is_proxy_denied_metadata_ip(&ip))
        || resolved_ips.iter().any(is_proxy_denied_metadata_ip)
    {
        return Some(FilterResult::DenyHost {
            host: host.to_string(),
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_proxy_filter_delegates_to_host_filter() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_host_port_entries() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(160, 79, 104, 10))];

        let result = filter.check_host_result("platform.claude.com", 443, &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_host_port_entries_do_not_override_metadata_deny() {
        let filter = ProxyFilter::new(&["metadata.google.internal:443".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_result("metadata.google.internal", 443, &public_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["evil.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());

        let result = filter.check_host_with_ips("good.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_with_denied_hosts_wildcard() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["*.ads.example.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("tracker.ads.example.com", &public_ip);
        assert!(!result.is_allowed());

        // bare domain must NOT match wildcard
        let result = filter.check_host_with_ips("ads.example.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_under_wildcard_allow() {
        // A port-scoped deny must hold under a wildcard allow, without
        // affecting other ports on the same host.
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["127.0.0.1:8975".to_string()]);
        let loopback = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];

        let result = filter.check_host_result("127.0.0.1", 8975, &loopback);
        assert!(!result.is_allowed(), "denied port must not be allowed");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("127.0.0.1", 8787, &loopback);
        assert!(
            result.is_allowed(),
            "unrelated port on the same host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_trailing_dot_fqdn() {
        // A trailing-dot FQDN must not bypass a port-scoped deny via
        // unnormalized host:port construction (see check_host_result).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["evil.com:443".to_string()]);

        let result = filter.check_host_result("evil.com.", 443, &[]);
        assert!(
            !result.is_allowed(),
            "trailing-dot form must still be denied"
        );
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denied_host_port_honored_for_ipv6_literal() {
        // An IPv6 host:port deny must match the bracketed authority form,
        // not "::1:8975" (ambiguous with the port separator).
        let filter =
            ProxyFilter::new(&["*".to_string()]).with_denied_hosts(&["[::1]:8975".to_string()]);

        let result = filter.check_host_result("::1", 8975, &[]);
        assert!(!result.is_allowed(), "IPv6 host:port form must be denied");
        assert!(matches!(result, FilterResult::DenyHost { .. }));

        let result = filter.check_host_result("::1", 8787, &[]);
        assert!(
            result.is_allowed(),
            "unrelated port on the same IPv6 host must remain allowed"
        );
    }

    #[test]
    fn test_proxy_filter_allow_all() {
        let filter = ProxyFilter::allow_all();
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let result = filter.check_host_with_ips("anything.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_private_networks() {
        let filter = ProxyFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host_with_ips("corp.internal", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_link_local() {
        let filter = ProxyFilter::allow_all();
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host_with_ips("evil.com", &link_local);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_aws_ipv6_metadata_literals() {
        let filter = ProxyFilter::allow_all();
        for host in [
            "fd00:ec2::254",
            "fd00:0ec2::254",
            "fd00:ec2:0:0:0:0:0:254",
            "[fd00:ec2::254]",
        ] {
            let result = filter.check_host_with_ips(host, &[]);
            assert!(
                !result.is_allowed(),
                "AWS IPv6 metadata literal {host:?} must be denied"
            );
        }
    }

    #[test]
    fn test_pre_resolution_check_denies_disallowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("evil.com", 443, &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_pre_resolution_check_allows_allowed_host_without_ips() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host_result("api.openai.com", 443, &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_pre_resolution_check_host_port_fallback_without_ips() {
        let filter = ProxyFilter::new(&["platform.claude.com:443".to_string()]);
        let result = filter.check_host_result("platform.claude.com", 443, &[]);
        assert!(result.is_allowed());

        let result = filter.check_host_result("platform.claude.com", 8443, &[]);
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_check_host_denies_disallowed_host_without_dns_resolution() {
        // .invalid (RFC 2606) never resolves, so a hang/error here would mean
        // DNS was attempted before the allowlist check.
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let result = filter
            .check_host("data-exfiltration-secret.example.invalid", 443)
            .await
            .unwrap();
        assert!(!result.result.is_allowed());
        assert!(matches!(result.result, FilterResult::DenyNotAllowed { .. }));
        assert!(result.resolved_addrs.is_empty());
    }

    #[test]
    fn test_proxy_filter_denies_trailing_dot_metadata_hostname() {
        // CONNECT-path callers pass the raw wire hostname straight through
        // with no normalization; the filter itself must catch this.
        let filter = ProxyFilter::allow_all();
        let result = filter.check_host_with_ips("metadata.google.internal.", &[]);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_proxy_filter_denies_unicode_form_of_punycode_deny_entry() {
        let filter = ProxyFilter::allow_all().with_denied_hosts(&["xn--mnchen-3ya.de".to_string()]);
        let result = filter.check_host_with_ips("münchen.de", &[]);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_resolved_aws_ipv6_metadata_ip() {
        let filter = ProxyFilter::allow_all();
        let resolved = vec![IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
        ))];
        let result = filter.check_host_with_ips("allowed.example", &resolved);
        assert!(!result.is_allowed());
    }

    fn public_only(exceptions: &[(&str, &[AddressClass])]) -> ResolvedAddressPolicy {
        ResolvedAddressPolicy {
            public_only: true,
            exceptions: exceptions
                .iter()
                .map(|(pattern, classes)| ((*pattern).to_string(), classes.to_vec()))
                .collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_default_policy_keeps_private_answers_allowed() {
        // Without public_only nothing changes: nono allows RFC 1918 by design.
        let filter = ProxyFilter::new(&["corp.example".to_string()])
            .with_resolved_address_policy(&ResolvedAddressPolicy::default());
        for addr in ["10.0.0.1", "127.0.0.1", "100.64.0.1", "fd00::1"] {
            assert!(
                filter
                    .check_host_with_ips("corp.example", &[ip(addr)])
                    .is_allowed(),
                "{addr}"
            );
        }
    }

    #[test]
    fn test_public_only_refuses_allowlisted_name_at_each_non_public_class() {
        let filter = ProxyFilter::new(&["api.example.com".to_string()])
            .with_resolved_address_policy(&public_only(&[]));
        for (addr, class) in [
            ("10.0.0.1", AddressClass::Private),
            ("172.16.0.1", AddressClass::Private),
            ("192.168.1.1", AddressClass::Private),
            ("fd7a:115c:a1e0::53", AddressClass::Private),
            ("127.0.0.1", AddressClass::Loopback),
            ("::1", AddressClass::Loopback),
            ("100.100.100.100", AddressClass::Cgnat),
            ("0.0.0.0", AddressClass::Unspecified),
            ("::ffff:10.0.0.1", AddressClass::Private),
        ] {
            let result = filter.check_host_with_ips("api.example.com", &[ip(addr)]);
            assert_eq!(
                result,
                FilterResult::DenyAddressClass {
                    host: "api.example.com".to_string(),
                    ip: ip(addr),
                    class,
                },
                "{addr}"
            );
        }
        // Link-local stays the library's own refusal.
        let result = filter.check_host_with_ips("api.example.com", &[ip("169.254.1.1")]);
        assert!(matches!(result, FilterResult::DenyLinkLocal { .. }));
        // Public answers pass.
        let result = filter.check_host_with_ips("api.example.com", &[ip("104.18.7.96")]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_public_only_one_non_public_answer_refuses_the_host() {
        let filter = ProxyFilter::new(&["api.example.com".to_string()])
            .with_resolved_address_policy(&public_only(&[]));
        let result =
            filter.check_host_with_ips("api.example.com", &[ip("104.18.7.96"), ip("10.0.0.1")]);
        assert!(matches!(result, FilterResult::DenyAddressClass { .. }));
    }

    #[test]
    fn test_public_only_exception_permits_only_its_classes() {
        let filter = ProxyFilter::new(&[
            "console.int.example".to_string(),
            "*.corp.example".to_string(),
        ])
        .with_resolved_address_policy(&public_only(&[
            ("console.int.example", &[AddressClass::Private]),
            (
                "*.corp.example",
                &[AddressClass::Private, AddressClass::Cgnat],
            ),
        ]));
        assert!(
            filter
                .check_host_with_ips("console.int.example", &[ip("10.1.2.3")])
                .is_allowed()
        );
        // Case and a trailing dot do not change the match.
        assert!(
            filter
                .check_host_with_ips("Console.Int.Example.", &[ip("10.1.2.3")])
                .is_allowed()
        );
        // The same name at a loopback or CGNAT address is still refused.
        for addr in ["127.0.0.1", "100.64.0.1", "0.0.0.0"] {
            assert!(
                matches!(
                    filter.check_host_with_ips("console.int.example", &[ip(addr)]),
                    FilterResult::DenyAddressClass { .. }
                ),
                "{addr}"
            );
        }
        // Link-local can never be excepted.
        assert!(
            !filter
                .check_host_with_ips("console.int.example", &[ip("169.254.0.1")])
                .is_allowed()
        );
        assert!(
            filter
                .check_host_with_ips("db.corp.example", &[ip("100.80.0.1")])
                .is_allowed()
        );
        // A wildcard exception does not cover the bare suffix, which the
        // allowlist does not allow either.
        assert!(
            !filter
                .check_host_with_ips("corp.example", &[ip("10.0.0.1")])
                .is_allowed()
        );
    }

    #[test]
    fn test_public_only_exception_does_not_allow_a_host() {
        let filter =
            ProxyFilter::new(&["api.example.com".to_string()]).with_resolved_address_policy(
                &public_only(&[("console.int.example", &[AddressClass::Private])]),
            );
        let result = filter.check_host_with_ips("console.int.example", &[ip("10.1.2.3")]);
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_public_only_permits_an_ip_literal_the_allowlist_names() {
        let filter = ProxyFilter::new(&["10.1.2.3".to_string(), "[fd00::5]:8443".to_string()])
            .with_resolved_address_policy(&public_only(&[]));
        assert!(
            filter
                .check_host_with_ips("10.1.2.3", &[ip("10.1.2.3")])
                .is_allowed()
        );
        assert_eq!(*filter.named_ips, vec![ip("10.1.2.3"), ip("fd00::5")]);

        // A wildcard names no address: a literal it matches is still gated.
        let wildcard =
            ProxyFilter::new(&["*".to_string()]).with_resolved_address_policy(&public_only(&[]));
        assert!(matches!(
            wildcard.check_host_with_ips("10.1.2.3", &[ip("10.1.2.3")]),
            FilterResult::DenyAddressClass { .. }
        ));
        // So does allow-all.
        let all = ProxyFilter::allow_all().with_resolved_address_policy(&public_only(&[]));
        assert!(matches!(
            all.check_host_with_ips("127.0.0.1", &[ip("127.0.0.1")]),
            FilterResult::DenyAddressClass { .. }
        ));
    }

    #[test]
    fn test_named_ips_reads_literals_with_and_without_ports() {
        let entries: Vec<String> = [
            "10.1.2.3",
            "127.0.0.1:8080",
            "fd00::1",
            "[fd00::2]",
            "[fd00::3]:443",
            "*.example.com",
            "example.com:443",
            "10.9.9.9:notaport",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            named_ips(&entries),
            vec![
                ip("10.1.2.3"),
                ip("127.0.0.1"),
                ip("fd00::1"),
                ip("fd00::2"),
                ip("fd00::3")
            ]
        );
    }

    #[test]
    fn test_denied_hosts_keep_the_address_policy() {
        let filter = ProxyFilter::new(&["api.example.com".to_string()])
            .with_resolved_address_policy(&public_only(&[]))
            .with_denied_hosts(&["evil.example.com".to_string()]);
        assert!(matches!(
            filter.check_host_with_ips("api.example.com", &[ip("10.0.0.1")]),
            FilterResult::DenyAddressClass { .. }
        ));
    }

    #[tokio::test]
    async fn test_check_host_resolves_then_gates_the_answer() {
        // localhost resolves to loopback on every host this runs on.
        let filter = ProxyFilter::new(&["localhost".to_string()])
            .with_resolved_address_policy(&public_only(&[]));
        let check = filter.check_host("localhost", 80).await.unwrap();
        assert!(matches!(
            check.result,
            FilterResult::DenyAddressClass {
                class: AddressClass::Loopback,
                ..
            }
        ));
        assert!(check.resolved_addrs.is_empty());

        let excepted = ProxyFilter::new(&["localhost".to_string()]).with_resolved_address_policy(
            &public_only(&[("localhost", &[AddressClass::Loopback])]),
        );
        let check = excepted.check_host("localhost", 80).await.unwrap();
        assert!(check.result.is_allowed());
        assert!(!check.resolved_addrs.is_empty());
        assert!(check.resolved_addrs.iter().all(|a| a.ip().is_loopback()));
    }
}
