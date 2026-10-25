//! The `403` the proxy answers a host-filter denial with.
//!
//! By default a denial is answered `HTTP/1.1 403 Forbidden: <reason>`, with
//! no headers and no body. A profile can set
//! [`crate::config::ProxyConfig::allowlist_denial_message`] to say something
//! more useful to whoever reads the refusal — often an agent — when a host is
//! refused for not being in the allowlist. The message replaces the reason
//! phrase (CONNECT clients usually surface only the status line) and is also
//! sent as a plain-text body (forward-HTTP clients such as curl print it). An
//! `X-Nono-Denied-By` header names the rule.
//!
//! Only the wording changes: what is denied, the audit event, and the
//! connection's fate are the same with or without a message. Denials other
//! than "not in the allowlist" (the deny list, link-local and other refused
//! addresses) keep the default response, because the advice a message gives
//! for the allowlist ("ask for it to be allowed") is wrong for them.

use nono::net_filter::FilterResult;

/// Rule label for a host refused because it is not in the allowlist. Appended
/// to the message as `[rule: net.allowlist]` and sent as `X-Nono-Denied-By`.
pub const ALLOWLIST_RULE: &str = "net.allowlist";

/// The placeholder a message may use for the refused host.
pub const HOST_PLACEHOLDER: &str = "{host}";

/// Longest message a profile may configure, before substitution.
pub const MAX_MESSAGE_LEN: usize = 512;

/// Longest host substituted for `{host}`: a DNS name's limit.
const MAX_HOST_LEN: usize = 253;

/// Longest message after substitution, before the rule tag: a message made of
/// `{host}` placeholders must not grow a reason phrase without bound.
const MAX_RENDERED_LEN: usize = 1024;

/// Check a configured message: one line of printable ASCII, at most
/// [`MAX_MESSAGE_LEN`] bytes, whose only placeholder is `{host}`.
///
/// # Errors
///
/// Returns a description of the first problem found.
pub fn validate_message(message: &str) -> Result<(), String> {
    if message.trim().is_empty() {
        return Err("must not be empty".to_string());
    }
    if message.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "is {} bytes; the limit is {MAX_MESSAGE_LEN}",
            message.len()
        ));
    }
    if let Some(c) = message.chars().find(|c| !is_printable_ascii(*c)) {
        return Err(format!(
            "contains {c:?}; only printable ASCII on one line is allowed"
        ));
    }
    if message.replace(HOST_PLACEHOLDER, "").contains(['{', '}']) {
        return Err(format!(
            "contains a brace outside the {HOST_PLACEHOLDER} placeholder, the only one supported"
        ));
    }
    Ok(())
}

/// The full `403` response for a host denial: the configured message for an
/// allowlist refusal, otherwise exactly the default response.
#[must_use]
pub fn host_denial_response(message: Option<&str>, host: &str, result: &FilterResult) -> String {
    match message {
        Some(message) if matches!(result, FilterResult::DenyNotAllowed { .. }) => {
            let text = render(message, host);
            format!(
                "HTTP/1.1 403 Forbidden: {text}\r\n\
                 X-Nono-Denied-By: {ALLOWLIST_RULE}\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {text}\n",
                text.len() + 1
            )
        }
        _ => format!(
            "HTTP/1.1 403 Forbidden: {}\r\n\r\n",
            result.reason().replace(['\r', '\n'], " ")
        ),
    }
}

/// Substitute `{host}` and append the rule tag. The result is one line of
/// printable ASCII however the message or host arrived: either may reach the
/// proxy without the profile's validation, and the host is the client's.
fn render(message: &str, host: &str) -> String {
    let host: String = host
        .chars()
        .take(MAX_HOST_LEN)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect();
    let message: String = message
        .chars()
        .take(MAX_MESSAGE_LEN)
        .map(|c| if is_printable_ascii(c) { c } else { '?' })
        .collect();
    let mut text = message.replace(HOST_PLACEHOLDER, &host);
    text.truncate(MAX_RENDERED_LEN);
    format!("{} [rule: {ALLOWLIST_RULE}]", text.trim_end())
}

fn is_printable_ascii(c: char) -> bool {
    c == ' ' || c.is_ascii_graphic()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const MESSAGE: &str = "refused: {host} is not reachable from the sandbox. Instead: say what \
                           you needed it for, and ask your person to allow it. Don't retry or \
                           work around it.";

    fn not_allowed(host: &str) -> FilterResult {
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    #[test]
    fn without_a_message_the_response_is_the_default() {
        let result = not_allowed("example.com");
        assert_eq!(
            host_denial_response(None, "example.com", &result),
            "HTTP/1.1 403 Forbidden: host example.com is not in the allowlist\r\n\r\n"
        );
    }

    #[test]
    fn an_allowlist_refusal_carries_the_message_header_and_body() {
        let response =
            host_denial_response(Some(MESSAGE), "example.com", &not_allowed("example.com"));
        let text = "refused: example.com is not reachable from the sandbox. Instead: say what \
                    you needed it for, and ask your person to allow it. Don't retry or work \
                    around it. [rule: net.allowlist]";
        assert_eq!(
            response,
            format!(
                "HTTP/1.1 403 Forbidden: {text}\r\n\
                 X-Nono-Denied-By: net.allowlist\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {text}\n",
                text.len() + 1
            )
        );
    }

    #[test]
    fn other_denials_keep_the_default_response() {
        let deny_host = FilterResult::DenyHost {
            host: "blocked.example".to_string(),
        };
        assert_eq!(
            host_denial_response(Some(MESSAGE), "blocked.example", &deny_host),
            host_denial_response(None, "blocked.example", &deny_host)
        );
        let link_local = FilterResult::DenyLinkLocal {
            ip: "169.254.169.254".parse::<IpAddr>().unwrap(),
        };
        assert_eq!(
            host_denial_response(Some(MESSAGE), "metadata", &link_local),
            host_denial_response(None, "metadata", &link_local)
        );
    }

    #[test]
    fn the_host_is_reduced_to_printable_ascii_and_bounded() {
        let hostile = "evil.example\r\nX-Injected: 1\u{1b}[31m";
        let text = render("{host}", hostile);
        assert_eq!(
            text,
            "evil.example??X-Injected:?1?[31m [rule: net.allowlist]"
        );

        let long = "a".repeat(1000);
        let text = render("{host}", &long);
        assert_eq!(text.len(), MAX_HOST_LEN + " [rule: net.allowlist]".len());
    }

    #[test]
    fn an_unvalidated_message_still_renders_as_one_bounded_line() {
        let text = render(&format!("bad\r\nline{}", "x".repeat(2000)), "h");
        assert!(text.chars().all(is_printable_ascii));
        assert!(text.len() <= MAX_MESSAGE_LEN + " [rule: net.allowlist]".len());
    }

    #[test]
    fn substitution_cannot_grow_the_message_without_bound() {
        let message = HOST_PLACEHOLDER.repeat(MAX_MESSAGE_LEN / HOST_PLACEHOLDER.len());
        assert!(validate_message(&message).is_ok());
        let text = render(&message, &"a".repeat(MAX_HOST_LEN));
        assert_eq!(
            text.len(),
            MAX_RENDERED_LEN + " [rule: net.allowlist]".len()
        );
    }

    #[test]
    fn every_placeholder_is_substituted() {
        assert_eq!(
            render("{host} and {host}", "a.example"),
            "a.example and a.example [rule: net.allowlist]"
        );
    }

    #[test]
    fn validation_accepts_the_intended_message() {
        assert_eq!(validate_message(MESSAGE), Ok(()));
        assert_eq!(validate_message("no placeholder at all"), Ok(()));
    }

    #[test]
    fn validation_rejects_bad_messages() {
        for bad in [
            "",
            "   ",
            "two\nlines",
            "tab\there",
            "caf\u{e9}",
            "{port} is closed",
            "{host",
            "stray } brace",
        ] {
            assert!(validate_message(bad).is_err(), "accepted {bad:?}");
        }
        assert!(validate_message(&"x".repeat(MAX_MESSAGE_LEN)).is_ok());
        assert!(validate_message(&"x".repeat(MAX_MESSAGE_LEN + 1)).is_err());
    }
}
