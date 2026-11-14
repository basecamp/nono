//! Size of a generated Seatbelt profile, by rule kind.
//!
//! `sandbox_init` takes time roughly in proportion to the profile it compiles,
//! and a profile with many grants runs to hundreds of kilobytes. This breaks a
//! profile down so its size can be attributed: each top-level form is counted
//! under its kind, the action, its operations and its first filter's name
//! (`allow file-read* subpath`, `allow file-read-metadata literal`,
//! `deny mach-lookup global-name`), with the bytes it takes.
//!
//! It reads the profile text only. It never changes, validates or applies a
//! profile, so it is safe to run on any profile and on any platform (the
//! tests run everywhere; macOS uses it for its debug log).

use std::collections::HashMap;

/// A profile's size, by rule kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltProfileStats {
    /// The whole profile, in bytes.
    pub(crate) total_bytes: usize,
    /// How many top-level forms it has.
    pub(crate) rules: usize,
    /// One entry per kind, largest first (ties by kind, for a stable order).
    pub(crate) kinds: Vec<SeatbeltRuleKindStats>,
}

/// The rules of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltRuleKindStats {
    /// The action, its operations and the name of its first filter, if any:
    /// `allow file-read* subpath`, `allow process-fork`.
    pub(crate) kind: String,
    /// How many forms of this kind the profile has.
    pub(crate) count: usize,
    /// The bytes they take, each from its opening paren through its closing
    /// one and the newline after it, if any.
    pub(crate) bytes: usize,
}

/// Break `profile` down by rule kind.
///
/// Bytes outside any form (blank lines, `;` and `#| |#` comments, a newline
/// not directly after a form) are counted in `total_bytes` only; a comment
/// inside a form counts in its bytes and never in its kind. An unbalanced form runs to
/// the end of the profile.
pub(crate) fn seatbelt_profile_stats(profile: &str) -> SeatbeltProfileStats {
    let mut by_kind: HashMap<String, (usize, usize)> = HashMap::new();
    let mut rules = 0usize;
    for (start, end) in top_level_forms(profile) {
        let form = &profile[start..end];
        let bytes = if profile[end..].starts_with('\n') {
            form.len().saturating_add(1)
        } else {
            form.len()
        };
        let entry = by_kind.entry(form_kind(form)).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(bytes);
        rules = rules.saturating_add(1);
    }
    let mut kinds: Vec<SeatbeltRuleKindStats> = by_kind
        .into_iter()
        .map(|(kind, (count, bytes))| SeatbeltRuleKindStats { kind, count, bytes })
        .collect();
    kinds.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.kind.cmp(&b.kind)));
    SeatbeltProfileStats {
        total_bytes: profile.len(),
        rules,
        kinds,
    }
}

/// Byte spans of the top-level forms, each from its `(` through its `)`.
fn top_level_forms(profile: &str) -> Vec<(usize, usize)> {
    let bytes = profile.as_bytes();
    let mut forms = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i),
            b';' | b'#' if comment_end(bytes, i) > i => {
                i = comment_end(bytes, i);
                continue;
            }
            b'(' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            b')' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    forms.push((start, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    if depth > 0 {
        forms.push((start, bytes.len()));
    }
    forms
}

/// Index just past the comment starting at `at`: a `;` comment through the
/// end of its line, a `#|` comment through its `|#` (or the end of the
/// profile, when it is unterminated). `at` itself when no comment starts
/// there.
fn comment_end(bytes: &[u8], at: usize) -> usize {
    match (bytes.get(at), bytes.get(at + 1)) {
        (Some(b';'), _) => bytes[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |n| at + n),
        (Some(b'#'), Some(b'|')) => bytes[at + 2..]
            .windows(2)
            .position(|w| w == b"|#")
            .map_or(bytes.len(), |n| at + 2 + n + 2),
        _ => at,
    }
}

/// `s` from its first byte that is neither whitespace nor in a comment.
fn skip_blank(s: &str) -> &str {
    let mut rest = s.trim_start();
    loop {
        let end = comment_end(rest.as_bytes(), 0);
        if end == 0 {
            return rest;
        }
        rest = rest[end..].trim_start();
    }
}

/// Index of the closing quote of the string opening at `open`, or the last
/// index when it is unterminated. Backslash escapes the next byte.
fn skip_string(bytes: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i,
            _ => i += 1,
        }
    }
    bytes.len().saturating_sub(1)
}

/// `allow file-read* subpath` for `(allow file-read* (subpath "/x"))`: the
/// symbols before the first nested form or string, then that form's head.
fn form_kind(form: &str) -> String {
    let inner = form.strip_prefix('(').unwrap_or(form);
    let mut words: Vec<&str> = Vec::new();
    let mut rest = skip_blank(inner);
    loop {
        if rest.is_empty() || rest.starts_with(')') || rest.starts_with('"') {
            break;
        }
        if let Some(nested) = rest.strip_prefix('(') {
            let head = symbol(skip_blank(nested));
            if !head.is_empty() {
                words.push(head);
            }
            break;
        }
        let word = symbol(rest);
        if word.is_empty() {
            break;
        }
        words.push(word);
        rest = skip_blank(&rest[word.len()..]);
    }
    if words.is_empty() {
        "(empty)".to_string()
    } else {
        words.join(" ")
    }
}

/// The symbol at the start of `s`: up to whitespace, a paren, a quote or a
/// `;` comment.
fn symbol(s: &str) -> &str {
    let end = s
        .find(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '"' || c == ';')
        .unwrap_or(s.len());
    &s[..end]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn kind<'a>(stats: &'a SeatbeltProfileStats, kind: &str) -> &'a SeatbeltRuleKindStats {
        stats
            .kinds
            .iter()
            .find(|k| k.kind == kind)
            .unwrap_or_else(|| panic!("no kind {kind:?} in {:?}", stats.kinds))
    }

    #[test]
    fn counts_each_form_under_its_kind() {
        let profile = "\
(version 1)
(deny default)
(allow process-fork)
(allow file-read* (subpath \"/usr\"))
(allow file-read* (subpath \"/opt/homebrew\"))
(allow file-read* (literal \"/\"))
(allow file-read-metadata (literal \"/Users\"))
(deny mach-lookup (global-name \"com.apple.secd\"))
(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))
";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.total_bytes, profile.len());
        assert_eq!(stats.rules, 9);
        let subpath = kind(&stats, "allow file-read* subpath");
        assert_eq!(subpath.count, 2);
        assert_eq!(
            subpath.bytes,
            "(allow file-read* (subpath \"/usr\"))\n".len()
                + "(allow file-read* (subpath \"/opt/homebrew\"))\n".len()
        );
        assert_eq!(kind(&stats, "allow file-read* literal").count, 1);
        assert_eq!(kind(&stats, "allow file-read-metadata literal").count, 1);
        assert_eq!(kind(&stats, "deny mach-lookup global-name").count, 1);
        assert_eq!(kind(&stats, "allow system-socket socket-domain").count, 1);
        assert_eq!(kind(&stats, "allow process-fork").count, 1);
        assert_eq!(kind(&stats, "deny default").count, 1);
        assert_eq!(kind(&stats, "version 1").count, 1);
        // Every byte of this profile is in a form or the newline after one.
        let sum: usize = stats.kinds.iter().map(|k| k.bytes).sum();
        assert_eq!(sum, profile.len());
    }

    #[test]
    fn largest_kind_comes_first() {
        let profile = "\
(allow process-fork)
(allow file-ioctl (literal \"/a\"))
(allow file-ioctl (literal \"/b\"))
(allow file-read* (subpath \"/a-much-longer-path-than-the-others\"))
";
        let stats = seatbelt_profile_stats(profile);
        let order: Vec<&str> = stats.kinds.iter().map(|k| k.kind.as_str()).collect();
        assert_eq!(
            order,
            [
                "allow file-ioctl literal",
                "allow file-read* subpath",
                "allow process-fork"
            ]
        );
    }

    #[test]
    fn parens_and_semicolons_in_strings_are_not_structure() {
        let profile = "\
(allow file-read* (literal \"/odd (dir); name\"))
(allow file-read* (literal \"/quote\\\" ) here\"))
(allow file-read-metadata (regex \"^/usr/bin/[^/]+$\"))
(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))
";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 4);
        assert_eq!(kind(&stats, "allow file-read* literal").count, 2);
        assert_eq!(kind(&stats, "allow file-read-metadata regex").count, 1);
        assert_eq!(kind(&stats, "allow file-ioctl regex").count, 1);
        let sum: usize = stats.kinds.iter().map(|k| k.bytes).sum();
        assert_eq!(sum, profile.len());
    }

    #[test]
    fn several_forms_on_a_line_and_across_lines() {
        // A platform rule can hold more than one form, or one form over
        // several lines.
        let profile = "(allow network-outbound) (allow file-write-unlink (subpath \"/r\"))\n\
(allow file-read*\n    (require-any (literal \"/a\") (literal \"/b\")))\n";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 3);
        assert_eq!(kind(&stats, "allow network-outbound").count, 1);
        assert_eq!(kind(&stats, "allow file-write-unlink subpath").count, 1);
        assert_eq!(kind(&stats, "allow file-read* require-any").count, 1);
        // The space between the first two forms belongs to neither.
        let sum: usize = stats.kinds.iter().map(|k| k.bytes).sum();
        assert_eq!(sum, profile.len() - 1);
    }

    #[test]
    fn comments_and_blank_lines_count_only_in_the_total() {
        let profile = "; a comment with (parens)\n\n(allow process-fork)\n";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 1);
        assert_eq!(stats.total_bytes, profile.len());
        assert_eq!(
            kind(&stats, "allow process-fork").bytes,
            "(allow process-fork)\n".len()
        );
    }

    #[test]
    fn block_comments_are_not_structure() {
        // Outside a form, and inside one, parens in a `#| |#` comment are
        // neither a form nor a kind.
        let profile = "#| (allow phantom) |#\n(allow process-fork) #| (deny x) |#\n(allow #| ) (phantom) |# process-exec)\n";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 2);
        assert_eq!(kind(&stats, "allow process-fork").count, 1);
        assert_eq!(kind(&stats, "allow process-exec").count, 1);
        assert_eq!(
            kind(&stats, "allow process-exec").bytes,
            "(allow #| ) (phantom) |# process-exec)\n".len()
        );
        assert!(stats.kinds.iter().all(|k| !k.kind.contains("phantom")));
        // An unterminated one runs to the end, and hides what follows.
        assert_eq!(
            seatbelt_profile_stats("(allow process-fork)\n#| (allow x)").rules,
            1
        );
        // A `#` that opens no comment is an ordinary byte.
        let hash = seatbelt_profile_stats("(allow mach-lookup (global-name \"a#b\")) (allow #t)\n");
        assert_eq!(hash.rules, 2);
        assert_eq!(kind(&hash, "allow #t").count, 1);
    }

    #[test]
    fn comments_inside_a_form_are_not_in_its_kind() {
        let profile = "\
(allow file-read* ; why\n (subpath \"/usr\"))
(allow file-read* #| why |# (subpath \"/opt\"))
(allow file-read*;why\n (subpath \"/a\"))
(allow file-read* ( ; first\n subpath \"/b\"))
(allow file-read* (subpath \"/c\"))
";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 5);
        assert_eq!(stats.kinds.len(), 1, "{:?}", stats.kinds);
        assert_eq!(kind(&stats, "allow file-read* subpath").count, 5);
    }

    #[test]
    fn unbalanced_form_runs_to_the_end() {
        let profile = "(allow process-fork)\n(allow file-read* (subpath \"/x\"";
        let stats = seatbelt_profile_stats(profile);
        assert_eq!(stats.rules, 2);
        assert_eq!(
            kind(&stats, "allow file-read* subpath").bytes,
            "(allow file-read* (subpath \"/x\"".len()
        );
        assert_eq!(seatbelt_profile_stats("").rules, 0);
        assert_eq!(seatbelt_profile_stats("(").kinds[0].kind, "(empty)");
    }
}
