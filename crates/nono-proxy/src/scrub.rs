//! Keep an injected credential out of the responses the sandbox reads.
//!
//! The proxy swaps a phantom for the real credential on the upstream leg, so
//! the sandboxed client never holds the secret. An upstream can still hand it
//! back: an error page that quotes the request's `Authorization` header, a
//! debug or echo endpoint, a token-introspection response, a redirect whose
//! `Location` carries a query-parameter credential. [`CredentialScrubber`]
//! masks every form of the injected credential the proxy knows in the
//! response's headers and body before the client sees them.
//!
//! The mask is the same length as what it replaces (`*` bytes), so
//! `Content-Length` and HTTP/1.1 chunk sizes stay valid and the body can be
//! scrubbed as it streams. A match that spans two reads is caught by holding
//! back the shortest tail that could still begin one ([`StreamScrub`]); only
//! a tail that is a prefix of a needle is held, so ordinary streaming (SSE,
//! chunked JSON) is not delayed.
//!
//! The scrub reads plain bytes, so a credentialed request is sent with
//! `Accept-Encoding: identity`, and a response that arrives content-encoded
//! anyway is refused rather than delivered unscanned
//! ([`refuses_content_encoding`]).

use base64::Engine;
use zeroize::Zeroizing;

use crate::credential::LoadedCredential;

/// Shortest value scrubbed. A shorter one would mask unrelated bytes too
/// often (and a credential that short is not one the scrub can protect).
pub const MIN_SCRUB_LEN: usize = 8;

/// The byte every masked byte becomes.
pub const MASK_BYTE: u8 = b'*';

/// The forms of one injected credential to mask in a response.
pub struct CredentialScrubber {
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for CredentialScrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialScrubber")
            .field("needles", &self.needles.len())
            .finish()
    }
}

impl CredentialScrubber {
    /// The scrubber for `cred`: its raw value, the injected header value and
    /// every extra injected header's value, each whole and, after its first
    /// word (the scheme, `Bearer`), word by word (`Bearer X` → `X`), the
    /// decoded `user:password` (and the password) of a Basic value, and the
    /// percent-encoded raw value when that differs. The first word of a value
    /// of several words is left alone: it is the format's literal, not the
    /// secret. `None` when none of them is at least [`MIN_SCRUB_LEN`] bytes.
    #[must_use]
    pub fn for_credential(cred: &LoadedCredential) -> Option<Self> {
        let mut values: Vec<Zeroizing<String>> = Vec::new();
        values.push(cred.raw_credential.clone());
        let encoded = urlencoding::encode(cred.raw_credential.as_str()).into_owned();
        values.push(Zeroizing::new(encoded));
        let header_values = std::iter::once(&cred.header_value)
            .chain(cred.extra_headers.iter().map(|(_, value)| value));
        for value in header_values {
            values.push(value.clone());
            let words: Vec<&str> = value.split_ascii_whitespace().collect();
            let secret_words = if words.len() > 1 {
                &words[1..]
            } else {
                &words[..]
            };
            for &word in secret_words {
                values.push(Zeroizing::new(word.to_string()));
                if let Some(userpass) = decode_basic(word) {
                    if let Some((_, password)) = userpass.split_once(':') {
                        values.push(Zeroizing::new(password.to_string()));
                    }
                    values.push(userpass);
                }
            }
        }
        // A raw credential that is itself a Basic token (base64 of user:pass),
        // as a command-backed helper may print it.
        if let Some(userpass) = decode_basic(cred.raw_credential.as_str()) {
            if let Some((_, password)) = userpass.split_once(':') {
                values.push(Zeroizing::new(password.to_string()));
            }
            values.push(userpass);
        }
        Self::from_values(values.iter().map(|v| v.as_bytes()))
    }

    /// A scrubber for these values, keeping those at least [`MIN_SCRUB_LEN`]
    /// bytes long that are not made of the mask byte alone.
    #[must_use]
    pub fn from_values<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Option<Self> {
        let mut needles: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for value in values {
            if value.len() < MIN_SCRUB_LEN
                || value.iter().all(|&b| b == MASK_BYTE)
                || needles.iter().any(|n| n.as_slice() == value)
            {
                continue;
            }
            needles.push(Zeroizing::new(value.to_vec()));
        }
        // Longest first, so a longer form is masked whole before a shorter
        // one inside it (the result is the same; this keeps it obvious).
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        (!needles.is_empty()).then_some(Self { needles })
    }

    /// Mask every occurrence of every needle in `data` in place. Returns
    /// whether anything was masked.
    pub fn mask_in_place(&self, data: &mut [u8]) -> bool {
        let mut masked = false;
        for needle in &self.needles {
            let mut start = 0;
            while let Some(found) = find(&data[start..], needle) {
                let at = start.saturating_add(found);
                let end = at.saturating_add(needle.len());
                data[at..end].fill(MASK_BYTE);
                masked = true;
                start = end;
            }
        }
        masked
    }

    /// `value` with every needle masked, or `None` when it holds none.
    #[must_use]
    pub fn scrub_value(&self, value: &[u8]) -> Option<Vec<u8>> {
        let mut out = value.to_vec();
        self.mask_in_place(&mut out).then_some(out)
    }

    /// Start scrubbing one response body as it streams.
    #[must_use]
    pub fn stream(&self) -> StreamScrub<'_> {
        StreamScrub {
            scrubber: self,
            held: Vec::new(),
            masked: false,
        }
    }

    /// Length of the longest suffix of `data` that is a proper prefix of some
    /// needle: the bytes that could still begin a match the next read ends.
    fn partial_tail(&self, data: &[u8]) -> usize {
        let mut longest: usize = 0;
        for needle in &self.needles {
            let max = needle.len().saturating_sub(1).min(data.len());
            for len in (longest.saturating_add(1)..=max).rev() {
                if data[data.len() - len..] == needle[..len] {
                    longest = len;
                    break;
                }
            }
        }
        longest
    }
}

/// Scrubs one body across reads. Feed each read to [`StreamScrub::push`] and
/// write what it returns; at the end of the body write [`StreamScrub::finish`].
pub struct StreamScrub<'a> {
    scrubber: &'a CredentialScrubber,
    held: Vec<u8>,
    masked: bool,
}

impl StreamScrub<'_> {
    /// Scrub the next read. Returns the bytes that are safe to release now;
    /// a tail that could begin a match is kept for the next call.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(chunk);
        self.masked |= self.scrubber.mask_in_place(&mut data);
        let keep = self.scrubber.partial_tail(&data);
        self.held = data.split_off(data.len() - keep);
        data
    }

    /// The end of the body: release what was held (it began no match).
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    /// Whether anything in this body was masked so far.
    #[must_use]
    pub fn masked(&self) -> bool {
        self.masked
    }
}

/// Whether a response whose `Content-Encoding` is `encoding` must be refused:
/// it names a coding other than `identity` and the response may carry a body
/// (not `HEAD`, not 1xx/204/304, not `Content-Length: 0`).
#[must_use]
pub fn refuses_content_encoding(
    encoding: Option<&str>,
    method: &str,
    status: u16,
    content_length: Option<&str>,
) -> bool {
    let encoded = encoding.is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
    });
    let bodiless = method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
        || content_length.is_some_and(|len| len.trim() == "0");
    encoded && !bodiless
}

/// The audit and error text for a refused content-encoded response.
#[must_use]
pub fn content_encoding_refusal(encoding: &str) -> String {
    format!(
        "the response to a credentialed request arrived with Content-Encoding {}, which the \
         credential scrub cannot read; refused rather than delivered unscanned",
        encoding.trim()
    )
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut at = 0;
    while at <= last_start {
        let rel = haystack[at..=last_start].iter().position(|&b| b == first)?;
        let candidate = at + rel;
        if &haystack[candidate..candidate + needle.len()] == needle {
            return Some(candidate);
        }
        at = candidate + 1;
    }
    None
}

/// `word` decoded as standard base64 to UTF-8 `user:password`, if it is one.
fn decode_basic(word: &str) -> Option<Zeroizing<String>> {
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(word)
            .ok()?,
    );
    let text = std::str::from_utf8(&decoded).ok()?;
    (text.contains(':') && !text.chars().any(char::is_control))
        .then(|| Zeroizing::new(text.to_string()))
}

/// Decodes an HTTP/1.1 chunked body as it streams, so the scrub sees the
/// payload and not the framing (a chunk boundary can fall inside a secret).
#[derive(Debug, Default)]
pub struct ChunkedDecoder {
    state: ChunkState,
    line: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ChunkState {
    #[default]
    Size,
    Data(usize),
    DataCr,
    DataLf,
    Trailer,
    Done,
}

/// Longest chunk-size or trailer line accepted.
const MAX_CHUNK_LINE: usize = 4096;

impl ChunkedDecoder {
    /// Feed the next bytes of the body; payload bytes are appended to `out`.
    /// Bytes after the last chunk and its trailers are ignored.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> crate::error::Result<()> {
        use crate::error::ProxyError;
        while !input.is_empty() {
            match self.state {
                ChunkState::Size | ChunkState::Trailer => {
                    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
                        self.line.extend_from_slice(input);
                        if self.line.len() > MAX_CHUNK_LINE {
                            return Err(ProxyError::HttpParse("chunk line too long".to_string()));
                        }
                        return Ok(());
                    };
                    self.line.extend_from_slice(&input[..nl]);
                    input = &input[nl + 1..];
                    if self.line.len() > MAX_CHUNK_LINE {
                        return Err(ProxyError::HttpParse("chunk line too long".to_string()));
                    }
                    let line = std::mem::take(&mut self.line);
                    let line = line.strip_suffix(b"\r").unwrap_or(&line);
                    if self.state == ChunkState::Trailer {
                        if line.is_empty() {
                            self.state = ChunkState::Done;
                        }
                        continue;
                    }
                    let text = std::str::from_utf8(line)
                        .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
                    let hex = text.split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(hex, 16)
                        .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
                    self.state = if size == 0 {
                        ChunkState::Trailer
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(remaining) => {
                    let take = remaining.min(input.len());
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    self.state = if take == remaining {
                        ChunkState::DataCr
                    } else {
                        ChunkState::Data(remaining - take)
                    };
                }
                ChunkState::DataCr | ChunkState::DataLf => {
                    let expected = if self.state == ChunkState::DataCr {
                        b'\r'
                    } else {
                        b'\n'
                    };
                    if input[0] != expected {
                        return Err(ProxyError::HttpParse(
                            "malformed chunked response".to_string(),
                        ));
                    }
                    input = &input[1..];
                    self.state = if self.state == ChunkState::DataCr {
                        ChunkState::DataLf
                    } else {
                        ChunkState::Size
                    };
                }
                ChunkState::Done => return Ok(()),
            }
        }
        Ok(())
    }

    /// Whether the last chunk and its trailers have been read.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }
}

/// Frame `data` as one HTTP/1.1 chunk (nothing for empty data).
#[must_use]
pub fn encode_chunk(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::InjectMode;

    const SECRET: &str = "ghs_0123456789abcdefSECRET";

    fn cred(raw: &str, header_value: &str) -> LoadedCredential {
        LoadedCredential {
            inject_mode: InjectMode::Header,
            proxy_inject_mode: InjectMode::Header,
            raw_credential: Zeroizing::new(raw.to_string()),
            header_name: "Authorization".to_string(),
            proxy_header_name: "Authorization".to_string(),
            header_value: Zeroizing::new(header_value.to_string()),
            extra_headers: Vec::new(),
            path_pattern: None,
            proxy_path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy_query_param_name: None,
        }
    }

    fn masked(len: usize) -> String {
        "*".repeat(len)
    }

    #[test]
    fn masks_raw_and_header_forms_same_length() {
        let s =
            CredentialScrubber::for_credential(&cred(SECRET, &format!("Bearer {SECRET}"))).unwrap();
        let body = format!("{{\"echo\":\"Bearer {SECRET}\",\"again\":\"{SECRET}\"}}");
        let out = s.scrub_value(body.as_bytes()).unwrap();
        assert_eq!(out.len(), body.len());
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains(SECRET), "{out}");
        assert_eq!(
            out,
            format!(
                "{{\"echo\":\"{}\",\"again\":\"{}\"}}",
                masked(7 + SECRET.len()),
                masked(SECRET.len())
            )
        );
    }

    #[test]
    fn nothing_to_mask_is_none() {
        let s =
            CredentialScrubber::for_credential(&cred(SECRET, &format!("Bearer {SECRET}"))).unwrap();
        assert!(s.scrub_value(b"{\"ok\":true}").is_none());
    }

    #[test]
    fn basic_value_masks_encoded_userpass_and_password() {
        use base64::engine::general_purpose::STANDARD;
        // A helper that prints base64("x-access-token:TOKEN") for `Basic {}`.
        let encoded = STANDARD.encode(format!("x-access-token:{SECRET}"));
        let s = CredentialScrubber::for_credential(&cred(&encoded, &format!("Basic {encoded}")))
            .unwrap();
        for leaked in [
            encoded.clone(),
            format!("x-access-token:{SECRET}"),
            SECRET.to_string(),
        ] {
            let body = format!("token={leaked};");
            let out = String::from_utf8(s.scrub_value(body.as_bytes()).unwrap()).unwrap();
            assert!(!out.contains(SECRET) && !out.contains(&encoded), "{out}");
        }
    }

    #[test]
    fn percent_encoded_form_is_masked() {
        let raw = "abc+def/ghi=jkl&mno";
        let s = CredentialScrubber::for_credential(&cred(raw, "")).unwrap();
        let body = b"Location: https://x.example/cb?key=abc%2Bdef%2Fghi%3Djkl%26mno";
        let out = String::from_utf8(s.scrub_value(body).unwrap()).unwrap();
        assert!(!out.contains("abc%2Bdef"), "{out}");
    }

    #[test]
    fn short_values_are_not_needles() {
        assert!(CredentialScrubber::for_credential(&cred("short", "short")).is_none());
        // The whole header value is long enough even when its credential is not.
        let s = CredentialScrubber::for_credential(&cred("short", "Bearer short")).unwrap();
        assert_eq!(s.scrub_value(b"Bearer short").unwrap(), b"************");
        assert!(s.scrub_value(b"short").is_none());
        assert!(CredentialScrubber::from_values([b"********".as_slice()]).is_none());
    }

    #[test]
    fn the_scheme_word_is_not_a_needle() {
        let s = CredentialScrubber::for_credential(&cred(
            SECRET,
            &format!("Authorization-Token {SECRET}"),
        ))
        .unwrap();
        assert!(
            s.scrub_value(b"see the Authorization-Token header docs")
                .is_none()
        );
        assert!(s.scrub_value(SECRET.as_bytes()).is_some());
    }

    #[test]
    fn extra_header_values_are_masked() {
        let mut c = cred(SECRET, &format!("Bearer {SECRET}"));
        c.extra_headers = vec![(
            "X-Org-Key".to_string(),
            Zeroizing::new("org-key-9876543210".to_string()),
        )];
        let s = CredentialScrubber::for_credential(&c).unwrap();
        let out = s.scrub_value(b"X-Org-Key: org-key-9876543210").unwrap();
        assert_eq!(out, format!("X-Org-Key: {}", masked(18)).into_bytes());
    }

    /// Every way to cut the body into two reads masks the secret.
    #[test]
    fn stream_masks_across_every_split() {
        let s = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let body = format!("data: {{\"k\":\"{SECRET}\"}}\n\n");
        for cut in 0..=body.len() {
            let mut st = s.stream();
            let mut out = st.push(&body.as_bytes()[..cut]);
            out.extend(st.push(&body.as_bytes()[cut..]));
            out.extend(st.finish());
            assert_eq!(out.len(), body.len(), "cut {cut}");
            let out = String::from_utf8(out).unwrap();
            assert!(!out.contains(SECRET), "cut {cut}: {out}");
            assert!(st.masked());
        }
    }

    #[test]
    fn stream_byte_at_a_time() {
        let s = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let body = format!("x{SECRET}y{SECRET}z");
        let mut st = s.stream();
        let mut out = Vec::new();
        for b in body.as_bytes() {
            out.extend(st.push(std::slice::from_ref(b)));
        }
        out.extend(st.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("x{}y{}z", masked(SECRET.len()), masked(SECRET.len()))
        );
    }

    /// Bytes that cannot begin a match are released at once (SSE is not held).
    #[test]
    fn stream_holds_only_a_possible_prefix() {
        let s = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let mut st = s.stream();
        assert_eq!(st.push(b"data: hello\n\n"), b"data: hello\n\n");
        assert_eq!(st.push(b"tail gh"), b"tail ");
        assert_eq!(st.push(b"x"), b"ghx");
        assert!(st.finish().is_empty());
        assert!(!st.masked());
    }

    #[test]
    fn stream_releases_held_prefix_at_finish() {
        let s = CredentialScrubber::from_values([SECRET.as_bytes()]).unwrap();
        let mut st = s.stream();
        assert_eq!(st.push(b"end ghs_0123"), b"end ");
        assert_eq!(st.finish(), b"ghs_0123");
    }

    #[test]
    fn content_encoding_refusal_rules() {
        assert!(refuses_content_encoding(Some("gzip"), "GET", 200, None));
        assert!(refuses_content_encoding(
            Some("identity, br"),
            "POST",
            400,
            Some("12")
        ));
        assert!(!refuses_content_encoding(
            Some("identity"),
            "GET",
            200,
            None
        ));
        assert!(!refuses_content_encoding(None, "GET", 200, None));
        assert!(!refuses_content_encoding(Some("gzip"), "HEAD", 200, None));
        assert!(!refuses_content_encoding(Some("gzip"), "GET", 304, None));
        assert!(!refuses_content_encoding(Some("gzip"), "GET", 204, None));
        assert!(!refuses_content_encoding(
            Some("gzip"),
            "GET",
            200,
            Some("0")
        ));
    }

    #[test]
    fn chunked_decoder_reassembles_split_chunks() {
        let raw = b"4\r\nghs_\r\n6;ext=1\r\n012345\r\n0\r\nX-Trailer: a\r\n\r\nignored";
        for cut in 0..=raw.len() {
            let mut d = ChunkedDecoder::default();
            let mut out = Vec::new();
            d.feed(&raw[..cut], &mut out).unwrap();
            d.feed(&raw[cut..], &mut out).unwrap();
            assert_eq!(out, b"ghs_012345", "cut {cut}");
            assert!(d.is_done(), "cut {cut}");
        }
    }

    #[test]
    fn chunked_decoder_rejects_bad_framing() {
        let mut out = Vec::new();
        assert!(ChunkedDecoder::default().feed(b"zz\r\n", &mut out).is_err());
        assert!(
            ChunkedDecoder::default()
                .feed(b"2\r\nabX\r\n", &mut out)
                .is_err()
        );
        let long = vec![b'1'; MAX_CHUNK_LINE + 1];
        assert!(ChunkedDecoder::default().feed(&long, &mut out).is_err());
    }

    #[test]
    fn encode_chunk_frames_data() {
        assert_eq!(encode_chunk(b"hello"), b"5\r\nhello\r\n");
        assert!(encode_chunk(b"").is_empty());
    }
}
