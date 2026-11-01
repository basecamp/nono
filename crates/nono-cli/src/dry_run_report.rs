//! `nono run --dry-run --json`: what a run would apply, as data.
//!
//! The text dry run is written for people. A program that needs to decide on
//! the same answer (a launcher checking that a sandbox keeps away from some
//! directory, say) would otherwise have to parse it, and a path can hold any
//! byte the text framing uses.
//!
//! The report is read from the launch's own plan, never from a resolver of its
//! own: the run's capability set as `prepare_run_launch_plan` builds it (the
//! code `nono run` uses: globs expanded, variables filled, symlinks followed,
//! policy groups and user flags included), its network decision and resource
//! limits, and each brokered command's sandbox as `build_child_launch_spec`
//! builds it, read back from the launch spec the child applies.
//!
//! Its contract is that capability set. What else a run does is out of it and
//! named in `out_of_scope`. What would widen filesystem access beyond the set
//! is either listed as a path grant (a generated Seatbelt allow rule of a shape
//! read back exactly, in `seatbelt_grants`) or named in `incomplete` (capability
//! elevation, any other Seatbelt allow rule), so a program that decides on the
//! report fails closed when `incomplete` is non-empty.

use std::path::Path;

use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, Result, UnixSocketCapability,
};
use serde_json::{Value, json};

use crate::launch_runtime::{LaunchPlan, NetworkIntent};
use crate::tool_sandbox::DryRunChild;

/// The report's format version: a new field is added without a change; a
/// field changed or removed gets a new version, and so does a new field a
/// reader must read to keep the contract.
///
/// - 2: `seatbelt_grants`, which took the generated Seatbelt allow rules it
///   lists out of `incomplete`, so a reader of 1 would pass what it never read.
/// - 3: `seatbelt_grants` now reads back **every** file rule of the Seatbelt
///   profile the launch applies (parsed from the profile itself, not rebuilt
///   from the capability list), each with its real scope — `literal` (that
///   path), `subpath` (its subtree), `children` (its direct children) or
///   `atomic_temp`. A rule not shown bounded goes to `incomplete`. The
///   `metadata_paths` and `metadata_children` fields are gone: their reads are
///   `metadata` grants here now, with the scope each rule actually has.
pub(crate) const DRY_RUN_REPORT_VERSION: u32 = 3;

/// What a run does that the report does not cover: out of its contract.
pub(crate) const OUT_OF_SCOPE: &[&str] = &[
    "brokered commands' network policy (each command's proxy, ports and domains)",
    "how the network mode is enforced: left to the deployment (linux.sandbox_policy = external), Landlock alone (linux.sandbox_policy = landlock), or an unenforced proxy on WSL2 (wsl2_proxy_policy = insecure_proxy)",
    "resolution of the program through PATH (program is as given)",
    "session hooks, which run on the host outside the sandbox",
    "environment credentials injected into the session or a command",
    "URL opening delegated to the host browser (open_urls)",
    "signal, process-information and IPC scope",
    "a brokered command allowed to run directly (allow_direct_exec_bypass), which then runs under the session's own sandbox, as filesystem lists it",
    "what the supervisor runs or sends on the host for the run (credential source commands, a daemon_pid_source helper, an approval webhook)",
    "the execute allowlist: not computed in a dry run (the session's execute gate, an ELF closure over the executables on PATH; on macOS its process-exec rule)",
    "how Unix-socket grants are enforced (with linux.af_unix_mediation off, the default, AF_UNIX is not mediated; abstract and unnamed sockets are never path grants)",
    "nono's own per-launch files (its capability state file, command-mediation shims and sockets, the proxy's CA bundle)",
];

/// The report of `plan`, a run of `program` from `workdir`, with `children`
/// (each brokered sandbox, as the launch builds it) and the profile's raw
/// Seatbelt rules (`raw_rules`), which the capability list cannot show.
pub(crate) fn dry_run_report(
    plan: &LaunchPlan,
    mediation: &crate::execution_runtime::DryRunMediation,
    undecided: &[String],
    raw_rules: &[String],
    workdir: &Path,
) -> Result<Value> {
    let workdir =
        workdir
            .canonicalize()
            .map_err(|source| nono::NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source,
            })?;
    // The child's own view: the exec widens a read grant of `/proc/self` to
    // `/proc` (every descendant reads its own entries), the call it makes.
    #[cfg(target_os = "linux")]
    let caps = {
        let mut caps = plan.caps.clone();
        caps.widen_procfs_self_to_proc();
        caps
    };
    #[cfg(not(target_os = "linux"))]
    let caps = plan.caps.clone();
    // Where the program starts, as `execute_sandboxed` decides it: the
    // working directory with command mediation, else that directory when the
    // capability set covers it, else `/`.
    let mediated = plan
        .flags
        .command_policies
        .as_ref()
        .is_some_and(crate::command_policy::CommandPoliciesConfig::is_active);
    let start_dir = if mediated {
        workdir.clone()
    } else {
        crate::execution_runtime::execution_start_dir(&workdir, &plan.caps)?
    };
    let mut incomplete: Vec<String> = undecided.to_vec();
    incomplete.extend(mediation.unresolved.iter().map(|(name, reason)| {
        format!("credential '{name}' doesn't resolve as declared: {reason}")
    }));
    // (Resource limits are applied on Linux only: a macOS run refuses them.)
    #[cfg(not(target_os = "linux"))]
    if caps.resource_limits().is_some() {
        incomplete.push(
            "resource limits, which this platform's run refuses rather than apply".to_string(),
        );
    }
    #[cfg(target_os = "linux")]
    if plan.flags.capability_elevation || caps.extensions_enabled() {
        incomplete.push(
            "capability elevation: the supervisor can grant paths beyond this list at runtime"
                .to_string(),
        );
    }
    // Every file grant read back from the profile the launch applies, from
    // the session's augmented set (`grant_outer_caps`), or the plan's own set
    // when no mediation runs — the same choice the launch makes. On Linux
    // there is no Seatbelt profile, so this is empty and Landlock grants no
    // metadata-only reads.
    #[cfg(target_os = "macos")]
    let profile_caps = mediation.session_caps.as_ref().unwrap_or(&caps);
    #[cfg(not(target_os = "macos"))]
    let profile_caps = &caps;
    let (seatbelt_grants, grant_incomplete) = profile_grants(profile_caps, raw_rules)?;
    incomplete.extend(grant_incomplete);
    let limits = caps.resource_limits();
    let commands = mediation
        .children
        .iter()
        .map(|child| child_value(child, &workdir, &caps))
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "version": DRY_RUN_REPORT_VERSION,
        "program": path_value(Path::new(&plan.program)),
        "workdir": path_value(&start_dir),
        "incomplete": incomplete,
        "out_of_scope": OUT_OF_SCOPE,
        "filesystem": caps.fs_capabilities().iter().map(session_fs_value).collect::<Vec<_>>(),
        "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
        "seatbelt_grants": seatbelt_grants,
        // (Each as declared: a dry run reads no credential source.)
        "credentials": {
            "env": plan.loaded_secrets.iter().map(|secret| secret.env_var.clone()).collect::<Vec<_>>(),
            "proxy": proxy_credential_names(&plan.flags.network),
            "commands": mediation.credentials.iter().map(|c| json!({
                "name": c.name,
                "type": c.kind,
                "path": c.declared,
                "resolved": c.resolved.as_deref().map(path_value),
                "unresolved": c.unresolved,
            })).collect::<Vec<_>>(),
        },
        "network": network_value(&plan.flags.network, &caps),
        "resources": {
            "memory_bytes": limits.and_then(|l| l.memory_bytes),
            "max_processes": limits.and_then(|l| l.max_processes),
        },
        "commands": commands,
    }))
}

/// The credential routes the session's proxy would carry, by name (a
/// `--credential` service, a profile's custom credential, a provider route),
/// as declared.
fn proxy_credential_names(intent: &NetworkIntent) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Some(proxy) = intent.proxy_options() {
        if let Some(credentials) = proxy.credentials.as_ref() {
            names.extend(credentials.credentials.iter().cloned());
            names.extend(credentials.custom_credentials.keys().cloned());
        }
        names.extend(
            proxy
                .credential_routes
                .iter()
                .map(|route| route.name.clone()),
        );
    }
    names.sort();
    names.dedup();
    names
}

/// Whether the launch remaps `cap` to the process it applies to
/// (`remap_procfs_self_references` rewrites it).
fn process_relative(cap: &FsCapability) -> bool {
    let mut probe = CapabilitySet::new();
    probe.add_fs(cap.clone());
    probe.remap_procfs_self_references(0, None);
    probe
        .fs_capabilities()
        .first()
        .is_some_and(|after| after.resolved != cap.resolved)
}

/// A session grant as the child gets it. One the launch remaps to the child's
/// own process after it forks (`remap_procfs_self_references`: `/proc/self/...`,
/// `/proc/thread-self/...`, `/dev/fd`, `/dev/std*`) is reported in that
/// self-relative spelling, marked `process_relative`, not as the dry run's own
/// process.
fn session_fs_value(cap: &FsCapability) -> Value {
    let mut value = fs_value(cap);
    if process_relative(cap)
        && cap.resolved != Path::new("/proc")
        && let Some(object) = value.as_object_mut()
    {
        object.insert("path".to_string(), path_value(&cap.original));
        object.insert("process_relative".to_string(), json!(true));
    }
    value
}

/// The plan's network: its mode, and the port exceptions the capability set
/// carries beside it (a connect or bind port, a localhost port or range, the
/// ports the proxy lets the run bind), which a restricted mode still allows.
fn network_value(intent: &NetworkIntent, caps: &CapabilitySet) -> Value {
    let mut bind_ports: Vec<u16> = caps.tcp_bind_ports().to_vec();
    if let Some(proxy) = intent.proxy_options().filter(|proxy| proxy.is_active()) {
        bind_ports.extend(proxy.allow_bind_ports.iter().copied());
    }
    bind_ports.sort_unstable();
    bind_ports.dedup();
    json!({
        "mode": network_mode(intent, caps),
        "connect_ports": caps.tcp_connect_ports(),
        "bind_ports": bind_ports,
        "localhost_ports": caps.localhost_ports(),
        // (macOS: a restricted mode still lets the sandbox reach the host's
        // resolver, unless the profile blocks it. Linux grants nothing by it.)
        "resolver": cfg!(target_os = "macos") && caps.dns_enabled() && network_mode(intent, caps) != "allowed",
        "localhost_port_ranges": caps
            .localhost_port_ranges()
            .iter()
            .map(|(low, high)| json!([low, high]))
            .collect::<Vec<_>>(),
    })
}

/// The network mode the plan decided: blocked, through the proxy, or open
/// (with no proxy or block decided, the capability set's own mode).
fn network_mode(intent: &NetworkIntent, caps: &CapabilitySet) -> &'static str {
    match intent {
        NetworkIntent::BlockAll => "blocked",
        intent if intent.is_proxy_active() => "proxy",
        _ => match caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked",
            nono::NetworkMode::ProxyOnly { .. } => "proxy",
            nono::NetworkMode::AllowAll => "allowed",
        },
    }
}

/// A generated Seatbelt allow rule read back as a path grant: what it lets the
/// sandbox do there (`access`) and how its filter reaches from `path`
/// (`filter`). The record is at least as wide as the rule, never narrower:
///
/// - `access`: `metadata` (`file-read-metadata` alone), `read` (`file-read*`,
///   `file-read-data`), `write` (`file-write*`, `file-write-data`, with
///   `file-read-metadata` beside them or not) or `readwrite` (a read op and a
///   write op); `read` and `write` each also stand for the entries' metadata.
/// - `filter`: `literal` (that path itself), `subpath` (it and everything
///   beneath it), or `atomic_temp` (the entries beside `path` named
///   `<path>.tmp.<digits>.<hex>`, the atomic-write siblings of a write grant;
///   the regex's `$` also matches before one final line terminator).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "macos", test))]
struct SeatbeltGrant {
    access: &'static str,
    filter: &'static str,
    path: String,
}

#[cfg(any(target_os = "macos", test))]
impl SeatbeltGrant {
    fn value(&self) -> Value {
        json!({ "access": self.access, "filter": self.filter, "path": self.path })
    }
}

/// The ops a path grant may hold: each `(read, write, metadata)`.
///
/// `file-map-executable` (mapping a file as executable memory) and
/// `file-ioctl` count as `read`: both reach the file, conservatively more than
/// metadata, and the generator only ever emits them on a path a read grant
/// already covers or on a device node, so this never narrows and never widens
/// past a read grant.
#[cfg(any(target_os = "macos", test))]
const SEATBELT_FILE_OPS: &[(&str, (bool, bool, bool))] = &[
    ("file-read-metadata", (false, false, true)),
    ("file-read*", (true, false, false)),
    ("file-read-data", (true, false, false)),
    ("file-map-executable", (true, false, false)),
    ("file-ioctl", (true, false, false)),
    ("file-write*", (false, true, false)),
    ("file-write-data", (false, true, false)),
];

/// The regex `add_atomic_write_rule` puts after a write grant's escaped path.
#[cfg(any(target_os = "macos", test))]
const ATOMIC_TEMP_SUFFIX: &str = r"\.tmp\.[0-9]+\.[0-9a-f]+$";

/// `rule` read back as a path grant, when it is one of the shapes the
/// preparation generates and nothing else:
///
/// - `(allow OP... (literal "PATH"))` or `(allow OP... (subpath "PATH"))`, each
///   OP one of `SEATBELT_FILE_OPS`, PATH absolute and unescaped as the exact
///   inverse of `escape_seatbelt_path` (the deny groups' `file-read-metadata`,
///   the symlink pairs' `file-read*`, keychain database grants);
/// - `(allow file-write* file-read-metadata (regex #"^PATH\.tmp\.[0-9]+\.[0-9a-f]+$"))`,
///   PATH unescaped as the exact inverse of `regex_escape_path`
///   (`add_atomic_write_rule`).
///
/// Anything else is none, and stays in `incomplete`: another op, filter or
/// regex, a second filter or rule, a comment, other spacing, an escape the
/// escaper never writes. And a rule is read back only when the generator's own
/// code renders the record it reads to that rule byte for byte, so no rule
/// stands for a path other than the one it was generated from.
#[cfg(any(target_os = "macos", test))]
fn seatbelt_grant(rule: &str) -> Option<SeatbeltGrant> {
    let body = rule.strip_prefix("(allow ")?.strip_suffix("\"))")?;
    // (No op holds a space or a parenthesis, so the first " (" ends the ops.)
    let (ops, filter) = body.split_once(" (")?;
    if let Some(regex) = filter.strip_prefix("regex #\"") {
        let path = regex
            .strip_prefix('^')?
            .strip_suffix(ATOMIC_TEMP_SUFFIX)
            .and_then(regex_unescape)?;
        if ops != "file-write* file-read-metadata"
            || !path.starts_with('/')
            || crate::capability_ext::atomic_write_rule(&path) != rule
        {
            return None;
        }
        return Some(SeatbeltGrant {
            access: "write",
            filter: "atomic_temp",
            path,
        });
    }
    let (filter, quoted) = if let Some(quoted) = filter.strip_prefix("literal \"") {
        ("literal", quoted)
    } else {
        ("subpath", filter.strip_prefix("subpath \"")?)
    };
    let path = seatbelt_unescape(quoted).filter(|path| path.starts_with('/'))?;
    let (mut read, mut write, mut metadata) = (false, false, false);
    for op in ops.split(' ') {
        let (_, (r, w, m)) = SEATBELT_FILE_OPS.iter().find(|(name, _)| *name == op)?;
        read |= r;
        write |= w;
        metadata |= m;
    }
    let access = match (read, write, metadata) {
        (true, true, _) => "readwrite",
        (true, false, _) => "read",
        (false, true, _) => "write",
        (false, false, true) => "metadata",
        (false, false, false) => return None,
    };
    let escaped = crate::policy::escape_seatbelt_path(&path).ok()?;
    if format!("(allow {ops} ({filter} \"{escaped}\"))") != rule {
        return None;
    }
    Some(SeatbeltGrant {
        access,
        filter,
        path,
    })
}

/// The exact inverse of `escape_seatbelt_path`: `\\` and `\"` are the only
/// escapes it writes, a bare `"` would end the string, and it refuses every
/// control character. Any of those otherwise is none.
#[cfg(any(target_os = "macos", test))]
fn seatbelt_unescape(quoted: &str) -> Option<String> {
    let mut out = String::with_capacity(quoted.len());
    let mut chars = quoted.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                c @ ('\\' | '"') => out.push(c),
                _ => return None,
            },
            '"' => return None,
            c if c.is_control() => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The characters `regex_escape_path` writes with a backslash before them:
/// every ICU metacharacter outside a set, and the `"` that would end the
/// Seatbelt string.
#[cfg(any(target_os = "macos", test))]
const REGEX_ESCAPED: &[char] = &[
    '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\', '"',
];

/// The exact inverse of `regex_escape_path`: each of `REGEX_ESCAPED` only
/// after a backslash, and a backslash only before one of them, so the regex
/// matches the path's characters themselves and nothing else. (In a `#"…"`
/// string the backslashes reach the regex engine as written, which is what
/// the generated `\.tmp\.` relies on.) A control character, which ICU reads
/// as itself but the escaper never had to consider, is none.
#[cfg(any(target_os = "macos", test))]
fn regex_unescape(escaped: &str) -> Option<String> {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                c if REGEX_ESCAPED.contains(&c) => out.push(c),
                _ => return None,
            },
            c if REGEX_ESCAPED.contains(&c) || c.is_control() => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The allow ops the profile emits that grant no filesystem path: a rule with
/// one of these can be consumed without a file grant. Matched exactly, so a
/// new op the generator adds falls through to `incomplete` rather than being
/// waved past. (File ops are in `SEATBELT_FILE_OPS`; `deny`, `version` and
/// `debug` forms are handled by shape.)
#[cfg(any(target_os = "macos", test))]
const NON_FILE_ALLOW_OPS: &[&str] = &[
    "iokit-get-properties",
    "iokit-open",
    "lsopen",
    "user-preference-read",
    "ipc-posix-sem*",
    "ipc-posix-shm-read-data",
    "ipc-posix-shm-write-create",
    "ipc-posix-shm-write-data",
    "mach-lookup",
    "mach-per-user-lookup",
    "mach-task-name",
    "network-bind",
    "network-inbound",
    "network-outbound",
    "process-exec*",
    "process-fork",
    "process-info*",
    "pseudo-tty",
    "signal",
    "sysctl-read",
    "system-fsctl",
    "system-info",
    "system-socket",
];

/// The two static `file-ioctl` device regexes the profile always emits
/// (byte for byte). They match terminal device nodes, which no tier root can
/// be, so they grant nothing a path check must see.
#[cfg(any(target_os = "macos", test))]
const DEVICE_IOCTL_RULES: &[&str] = &[
    r#"(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))"#,
    r#"(allow file-ioctl (regex #"^/dev/pty[a-z][0-9a-f]+$"))"#,
];

/// Whether a profile line grants no filesystem path and so can be consumed
/// without a grant record: a `deny` (which only narrows), the `(version …)`
/// and `(debug …)` headers, a non-file allow op, or a static device-ioctl
/// rule. Anything else — an unknown or wildcard op, a file op not read back as
/// a grant, a construct that is not an allow/deny s-expression — is not
/// bounded and must go to `incomplete`.
///
/// A line is bounded only when it is a **single** top-level S-expression form
/// (nothing but whitespace after its first balanced close) that is a `deny`, a
/// `(version …)`/`(debug …)` header, or an `allow` whose ops are **all**
/// non-file. So a line that carries a second form or a file op anywhere —
/// `(deny X) (allow file-read* (subpath "/R"))`, `(allow process-fork
/// file-read* (subpath "/opt/private"))`, neither of which a current generator
/// emits — is not bounded and falls to `incomplete`, never waved past on its
/// first form or op.
#[cfg(any(target_os = "macos", test))]
fn rule_is_bounded(line: &str) -> bool {
    if DEVICE_IOCTL_RULES.contains(&line) {
        return true;
    }
    if !is_single_form(line) {
        return false;
    }
    let Some(body) = line.strip_prefix('(') else {
        return false;
    };
    let (kind, rest) = body
        .split_once(' ')
        .unwrap_or((body.trim_end_matches(')'), ""));
    match kind {
        "deny" | "version" | "debug" => true,
        "allow" => {
            // The ops are everything up to the first filter `(`.
            let ops = rest.split_once(" (").map_or(rest, |(ops, _)| ops);
            let first = ops.split([' ', ')']).next().unwrap_or("");
            NON_FILE_ALLOW_OPS.contains(&first)
                && !ops.split([' ', ')']).any(|op| op.starts_with("file-"))
        }
        _ => false,
    }
}

/// Whether `line` is one balanced parenthesised form with nothing but
/// whitespace after it: the generator writes one form per line, so a line
/// holding a second form is not generator output and is not bounded. (A quote
/// or escape inside a string can't open or close a group here; a `"` toggles
/// a string span so parens inside it don't count.)
#[cfg(any(target_os = "macos", test))]
fn is_single_form(line: &str) -> bool {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut closed_at = None;
    for (i, c) in line.char_indices() {
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    closed_at = Some(i);
                    break;
                }
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    match closed_at {
        Some(i) => line[i + 1..].trim().is_empty(),
        None => false,
    }
}

/// Every file grant the Seatbelt profile for `caps` gives, read back from the
/// profile the launch applies (not rebuilt from the capability list), and an
/// `incomplete` note for each rule not shown bounded.
///
/// Each line of the profile is one of: a raw rule
/// (`unsafe_macos_seatbelt_rules`, named for `incomplete` — the profile wrote
/// it and it is never read back as a grant); a direct-children metadata rule,
/// rendered from the generator's own producer so a line is matched to its
/// directory and no other line is mistaken for it; a rule `seatbelt_grant`
/// reads back (`literal`, `subpath` or `atomic_temp`); a bounded non-file or
/// device rule; or anything else, which goes to `incomplete` so a reader fails
/// closed. macOS only; Linux generates no profile and grants no path here.
#[cfg(target_os = "macos")]
fn profile_grants(caps: &CapabilitySet, raw_rules: &[String]) -> Result<(Vec<Value>, Vec<String>)> {
    let profile = nono::sandbox::seatbelt_profile(caps)?;
    // The direct-children rules, rendered from the generator's own producer
    // and escaper: a line equal to one is that directory's children grant.
    let mut children: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for read in nono::path::path_metadata_reads(caps.path_metadata_dirs())? {
        if let nono::path::PathMetadataRead::Children(dir) = read {
            let rule = format!(
                "(allow file-read-metadata (regex \"^{}/[^/]+$\"))",
                nono::sandbox::seatbelt_path_regex(&dir)?
            );
            children.insert(rule, dir);
        }
    }
    // The lines of each raw rule: skip them while parsing (they are named for
    // `incomplete` below), so a raw rule's line is never read back as a grant.
    let raw_applied: Vec<&String> = raw_rules
        .iter()
        .filter(|rule| caps.platform_rules().contains(rule))
        .collect();
    let raw_lines: std::collections::HashSet<&str> =
        raw_applied.iter().flat_map(|rule| rule.lines()).collect();
    let mut grants = Vec::new();
    let mut incomplete = Vec::new();
    for rule in &raw_applied {
        incomplete.push(format!(
            "a raw Seatbelt rule (unsafe_macos_seatbelt_rules) the capability list cannot show: {rule}"
        ));
    }
    for line in profile.lines() {
        if line.is_empty() || raw_lines.contains(line) {
            continue;
        }
        if let Some(dir) = children.get(line) {
            grants.push(
                SeatbeltGrant {
                    access: "metadata",
                    filter: "children",
                    path: dir.clone(),
                }
                .value(),
            );
        } else if let Some(grant) = seatbelt_grant(line) {
            grants.push(grant.value());
        } else if !rule_is_bounded(line) {
            incomplete.push(format!(
                "a generated Seatbelt rule not read back as a path grant: {line}"
            ));
        }
    }
    Ok((grants, incomplete))
}

#[cfg(not(target_os = "macos"))]
fn profile_grants(
    _caps: &CapabilitySet,
    _raw_rules: &[String],
) -> Result<(Vec<Value>, Vec<String>)> {
    Ok((Vec::new(), Vec::new()))
}

/// One brokered sandbox: what its launch builds (filesystem, sockets, the
/// binary it runs, its execute allowlist), what would widen it, and every path
/// its policy declares, which a later run resolves again.
fn child_value(child: &DryRunChild, workdir: &Path, outer_caps: &CapabilitySet) -> Result<Value> {
    // (A declared path the launch expands only when the command runs: an
    // expansion that fails here is named on this entry, not the whole report.)
    let (declared, declared_error) = match crate::tool_sandbox::declared_policy_paths(
        &child.sandbox,
        workdir,
        workdir,
        outer_caps,
    ) {
        Ok(declared) => (declared, None),
        Err(err) => (
            Vec::new(),
            Some(format!("its declared paths do not expand: {err}")),
        ),
    };
    let mut cwd_dependent: Vec<&String> = Vec::new();
    for d in declared.iter().filter(|d| d.cwd_dependent) {
        if !cwd_dependent.contains(&&d.entry) {
            cwd_dependent.push(&d.entry);
        }
    }
    let declared: Vec<Value> = declared
        .iter()
        .map(|d| {
            json!({
                "field": d.field,
                "entry": d.entry,
                "expanded": d.expanded.as_deref().map(path_value),
            })
        })
        .collect();
    let mut value = json!({
        "command": child.command,
        "caller": child.caller,
        "intercept": child.intercept,
        "declared": declared,
        "cwd_dependent": cwd_dependent,
    });
    let launch = match &child.launch {
        Ok(launch) => {
            let raw = &child.sandbox.unsafe_macos_seatbelt_rules;
            let (seatbelt_grants, mut incomplete) = profile_grants(&launch.caps, raw)?;
            // (A grant the launch spec carries resolved for the supervisor's own
            // process: the child, a different process, can't apply it, and its
            // launch stops. Reported in its self-relative spelling.)
            let mut filesystem = Vec::new();
            for cap in launch.caps.fs_capabilities() {
                let mut entry = without_source(fs_value(cap));
                if process_relative(cap)
                    && let Some(object) = entry.as_object_mut()
                {
                    incomplete.push(format!(
                        "{} is process-relative, which its launch can't carry to the command",
                        cap.original.display()
                    ));
                    object.insert("path".to_string(), path_value(&cap.original));
                    object.insert("process_relative".to_string(), json!(true));
                }
                filesystem.push(entry);
            }
            json!({
                "executable": path_value(&launch.executable),
                "incomplete": incomplete,
                // (No `source`: the launch spec a child applies carries none.)
                "filesystem": filesystem,
                "unix_sockets": launch.caps.unix_socket_capabilities().iter().map(|c| without_source(socket_value(c))).collect::<Vec<_>>(),
                "exec_paths": launch.exec_paths.iter().map(|p| path_value(p)).collect::<Vec<_>>(),
                "seatbelt_grants": seatbelt_grants,
            })
        }
        Err(reason) => json!({
            "executable": null,
            "incomplete": [format!("its launch from the working directory is not built: {reason}")],
            "filesystem": [],
            "unix_sockets": [],
            "exec_paths": [],
            "seatbelt_grants": [],
        }),
    };
    if let (Some(object), Some(launch)) = (value.as_object_mut(), launch.as_object()) {
        object.extend(launch.clone());
    }
    if let (Some(reason), Some(list)) = (
        declared_error,
        value.get_mut("incomplete").and_then(Value::as_array_mut),
    ) {
        list.push(json!(reason));
    }
    Ok(value)
}

fn fs_value(cap: &FsCapability) -> Value {
    let mut value = json!({
        "path": path_value(&cap.resolved),
        "original": path_value(&cap.original),
        "access": access_name(cap.access),
        "kind": if cap.is_file { "file" } else { "directory" },
    });
    add_source(&mut value, &cap.source);
    value
}

fn socket_value(cap: &UnixSocketCapability) -> Value {
    let mut value = json!({
        "path": path_value(&cap.resolved),
        "original": path_value(&cap.original),
        "scope": match cap.scope {
            nono::SocketScope::File => "file",
            nono::SocketScope::DirChildren => "dir_children",
            nono::SocketScope::DirSubtree => "dir_subtree",
        },
        "mode": match cap.mode {
            nono::UnixSocketMode::Connect => "connect",
            nono::UnixSocketMode::ConnectBind => "connect_bind",
        },
    });
    add_source(&mut value, &cap.source);
    value
}

fn without_source(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("source");
        object.remove("group");
    }
    value
}

fn add_source(value: &mut Value, source: &CapabilitySource) {
    let (name, group) = match source {
        CapabilitySource::User => ("user", None),
        CapabilitySource::Profile => ("profile", None),
        CapabilitySource::Group(group) => ("group", Some(group.clone())),
        CapabilitySource::System => ("system", None),
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("source".to_string(), json!(name));
        if let Some(group) = group {
            object.insert("group".to_string(), json!(group));
        }
    }
}

fn access_name(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::ReadWrite => "readwrite",
    }
}

/// A path as a JSON string when it is UTF-8; otherwise an object holding its
/// bytes in hex, so no path is ever reported as some other path.
fn path_value(path: &Path) -> Value {
    match path.to_str() {
        Some(text) => json!(text),
        None => json!({ "hex": path_hex(path) }),
    }
}

#[cfg(unix)]
fn path_hex(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(not(unix))]
fn path_hex(path: &Path) -> String {
    path.to_string_lossy()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_utf8_path_is_a_string() {
        assert_eq!(path_value(Path::new("/a/b (c) [d]")), json!("/a/b (c) [d]"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_its_bytes_in_hex() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/a/\xff\nb"));
        assert_eq!(path_value(path), json!({ "hex": "2f612fff0a62" }));
    }

    #[test]
    fn a_non_file_or_device_rule_is_bounded_and_a_file_rule_is_not() {
        // Bounded: a deny (narrows only), the headers, the fixed non-file
        // allow ops, and the two static device-ioctl rules.
        for line in [
            r#"(deny file-read* (subpath "/a"))"#,
            r#"(deny default)"#,
            "(version 1)",
            "(debug deny)",
            "(allow process-exec*)",
            "(allow process-info* (target self))",
            "(allow mach-lookup)",
            "(allow signal (target same-sandbox))",
            "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))",
            "(allow network-outbound (remote tcp \"*:443\"))",
            "(allow network-outbound (path \"/var/run/mDNSResponder\"))",
            "(allow iokit-open (iokit-user-client-class \"x\"))",
            "(allow lsopen)",
            "(allow user-preference-read)",
            r#"(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))"#,
            r#"(allow file-ioctl (regex #"^/dev/pty[a-z][0-9a-f]+$"))"#,
        ] {
            assert!(rule_is_bounded(line), "{line}");
        }
        // Not bounded: a file rule (read back as a grant instead, or named for
        // `incomplete`), an unknown or wildcard op, and a non-s-expression.
        for line in [
            r#"(allow file-read* (literal "/"))"#,
            r#"(allow file-read-metadata (literal "/a"))"#,
            r#"(allow file-read-xattr (literal "/a"))"#,
            "(allow file*)",
            "(allow some-new-op)",
            "(allow default)",
            "(allow)",
            "not a rule",
            // A non-file op paired with a file op: bounded on the first op
            // would wave the file grant past, so it must not be bounded.
            r#"(allow process-exec* file-read* (subpath "/R"))"#,
            r#"(allow signal file-write* (literal "/R"))"#,
            // A second form on the line, after a bounded first form: a deny or
            // a bounded allow must not shield a trailing file allow.
            r#"(deny default) (allow file-read* (subpath "/R"))"#,
            r#"(allow process-fork) (allow file-read* (subpath "/opt/private"))"#,
            r#"(allow process-fork)(allow file-write* (literal "/R"))"#,
        ] {
            assert!(!rule_is_bounded(line), "{line}");
        }
        // A lone deny that mentions a file op is still just a deny: bounded.
        assert!(rule_is_bounded(r#"(deny file-read-data (subpath "/a"))"#));
    }

    #[test]
    fn map_executable_and_ioctl_read_back_as_read_grants() {
        // Both reach the file, so they read back as `read` (never narrower
        // than metadata); their paths are a subset of the read grants.
        for (rule, want) in [
            (
                r#"(allow file-map-executable (subpath "/a"))"#,
                grant("read", "subpath", "/a"),
            ),
            (
                r#"(allow file-ioctl (literal "/dev/tty"))"#,
                grant("read", "literal", "/dev/tty"),
            ),
            (
                r#"(allow file-read* file-ioctl (literal "/a"))"#,
                grant("read", "literal", "/a"),
            ),
        ] {
            assert_eq!(seatbelt_grant(rule), want, "{rule}");
        }
    }

    /// Paths that hold every character an escaper treats specially.
    const AWKWARD_PATHS: &[&str] = &[
        "/a",
        "/",
        "/Users/luke/Library/Application Support/x",
        r#"/a/b "c""#,
        r"/a\b",
        r#"/a\"b"#,
        r"/a\\",
        "/x.y+z*w?(v)[u]{t}|s^r$q",
        "/a/.tmp.1.f",
        "/a/allow (literal \"/\")",
        "/a/é/日本",
    ];

    fn grant(access: &'static str, filter: &'static str, path: &str) -> Option<SeatbeltGrant> {
        Some(SeatbeltGrant {
            access,
            filter,
            path: path.to_string(),
        })
    }

    #[test]
    fn generated_rules_read_back_as_the_paths_they_were_generated_from() -> Result<()> {
        for path in AWKWARD_PATHS {
            let escaped = crate::policy::escape_seatbelt_path(path)?;
            // (The deny groups' stat-only read, as `emit_macos_deny_rules_for_path`
            // writes it for a directory or a path that isn't there, and for a file.)
            let absent = format!("/nonexistent-dry-run-report{path}");
            let mut caps = CapabilitySet::new();
            crate::policy::emit_macos_deny_rules_for_path(Path::new(&absent), &mut caps)?;
            let mut grants = Vec::new();
            for rule in caps.platform_rules() {
                match seatbelt_grant(rule) {
                    Some(g) => grants.push(g.value()),
                    // Everything else the deny group emits is a deny, bounded
                    // whatever its path says (keyed on the `deny` form, not a
                    // substring), so none of it reaches `incomplete`.
                    None => assert!(rule_is_bounded(rule), "{path}: {rule}"),
                }
            }
            assert_eq!(
                grants,
                vec![json!({ "access": "metadata", "filter": "subpath", "path": absent })],
                "{path}"
            );
            for (rule, want) in [
                (
                    format!("(allow file-read-metadata (literal \"{escaped}\"))"),
                    grant("metadata", "literal", path),
                ),
                // (The symlink pairs.)
                (
                    format!("(allow file-read* (subpath \"{escaped}\"))"),
                    grant("read", "subpath", path),
                ),
                // (Keychain database grants: specific and wildcard ops, apart.)
                (
                    format!("(allow file-read-data (literal \"{escaped}\"))"),
                    grant("read", "literal", path),
                ),
                (
                    format!("(allow file-write-data (literal \"{escaped}\"))"),
                    grant("write", "literal", path),
                ),
                (
                    format!("(allow file-write* (literal \"{escaped}\"))"),
                    grant("write", "literal", path),
                ),
                (
                    format!("(allow file-read* file-write* (subpath \"{escaped}\"))"),
                    grant("readwrite", "subpath", path),
                ),
                (
                    format!("(allow file-write* file-read-metadata (literal \"{escaped}\"))"),
                    grant("write", "literal", path),
                ),
                (
                    crate::capability_ext::atomic_write_rule(path),
                    grant("write", "atomic_temp", path),
                ),
            ] {
                assert_eq!(seatbelt_grant(&rule), want, "{rule}");
            }
        }
        // (A file the deny group finds: a literal.)
        let file =
            std::env::current_exe().map_err(|e| nono::NonoError::SandboxInit(e.to_string()))?;
        let mut caps = CapabilitySet::new();
        crate::policy::emit_macos_deny_rules_for_path(&file, &mut caps)?;
        let grants: Vec<Value> = caps
            .platform_rules()
            .iter()
            .filter_map(|rule| seatbelt_grant(rule).map(|g| g.value()))
            .collect();
        assert_eq!(
            grants,
            vec![json!({ "access": "metadata", "filter": "literal", "path": file.to_str() })]
        );
        Ok(())
    }

    #[test]
    fn a_rule_of_any_other_shape_is_not_read_back() {
        let atomic = crate::capability_ext::atomic_write_rule("/a");
        assert_eq!(
            atomic,
            r#"(allow file-write* file-read-metadata (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            "the shape the cases below vary"
        );
        for rule in [
            // Not a path.
            r#"(allow file-read* (literal "a"))"#,
            r#"(allow file-read* (literal ""))"#,
            r#"(allow file-read* (subpath "~/a"))"#,
            // Another op, beside one that is read back or alone.
            r#"(allow file-read-xattr (literal "/a"))"#,
            r#"(allow file* (literal "/a"))"#,
            r#"(allow process-exec* (literal "/a"))"#,
            r#"(allow network-outbound (literal "/a"))"#,
            r#"(allow mach-lookup (global-name "/a"))"#,
            r#"(allow file-read*)"#,
            r#"(allow default)"#,
            // Another filter, or more than one.
            r#"(allow file-read* (path "/a"))"#,
            r#"(allow file-read* (prefix "/a"))"#,
            r#"(allow file-read* (vnode-type REGULAR-FILE))"#,
            r#"(allow file-read* (literal "/a") (literal "/b"))"#,
            r#"(allow file-read* (require-any (literal "/a")))"#,
            r#"(allow file-read* (require-all (literal "/a") (vnode-type REGULAR-FILE)))"#,
            r#"(allow file-read* (literal "/a"))(allow file-read* (subpath "/"))"#,
            r#"(allow file-read* (literal "/a")) (allow file-read* (subpath "/b"))"#,
            // Any regex but the one, on any op but its own.
            r#"(allow file-read* (regex #"^/a$"))"#,
            r#"(allow file-read-metadata (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-read-metadata file-write* (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\.tmp\.[0-9]*\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\.tmp\.[0-9]+\.[0-9a-z]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a.b\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a/.*\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a/[^/]+\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a|/b\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\d\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\/b\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex "^/a\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\.tmp\.[0-9]+\.[0-9a-f]+$") (literal "/b"))"#,
            // An escape the escaper never writes, or a quote it always escapes.
            r#"(allow file-read* (literal "/a\n"))"#,
            r#"(allow file-read* (literal "/a\x41;"))"#,
            r#"(allow file-read* (literal "/a"b"))"#,
            r#"(allow file-read* (literal "/a\"))"#,
            "(allow file-read* (literal \"/a\u{7}\"))",
            "(allow file-read* (literal \"/a\nb\"))",
            // Other spacing, a comment, a deny.
            r#"(allow  file-read* (literal "/a"))"#,
            r#"(allow file-read*  (literal "/a"))"#,
            r#"(allow file-read* (literal  "/a"))"#,
            r#"(allow file-read* (literal "/a") )"#,
            r#"( allow file-read* (literal "/a"))"#,
            r#" (allow file-read* (literal "/a"))"#,
            r#"(allow file-read* (literal "/a")) "#,
            "(allow\tfile-read* (literal \"/a\"))",
            r#"(allow file-read* #| c |# (literal "/a"))"#,
            "(allow file-read*; c\n (literal \"/a\"))",
            r#"(deny file-read* (literal "/a"))"#,
            r#"(allow (literal "/a"))"#,
        ] {
            assert_eq!(seatbelt_grant(rule), None, "{rule}");
        }
    }

    #[test]
    fn a_rule_is_read_back_only_as_the_escaper_writes_it() {
        // (Each decodes to a path some other spelling of which the escaper
        // writes, or to none: the record never names a path the rule doesn't.)
        for rule in [
            r#"(allow file-read* (literal "/a\\\\"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\\\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
            r#"(allow file-write* file-read-metadata (regex #"^/a\"\.tmp\.[0-9]+\.[0-9a-f]+$"))"#,
        ] {
            let read = seatbelt_grant(rule);
            if let Some(grant) = &read {
                let again = if grant.filter == "atomic_temp" {
                    crate::capability_ext::atomic_write_rule(&grant.path)
                } else {
                    format!(
                        "(allow file-read* ({} \"{}\"))",
                        grant.filter,
                        crate::policy::escape_seatbelt_path(&grant.path).unwrap_or_default()
                    )
                };
                assert_eq!(again, rule, "{rule} read back as {grant:?}");
            }
        }
        assert_eq!(
            seatbelt_grant(r#"(allow file-read* (literal "/a\\\\"))"#),
            grant("read", "literal", r"/a\\")
        );
        assert_eq!(
            seatbelt_grant(
                r#"(allow file-write* file-read-metadata (regex #"^/a\"\.tmp\.[0-9]+\.[0-9a-f]+$"))"#
            ),
            grant("write", "atomic_temp", "/a\"")
        );
    }

    /// Coverage (a): over profiles from the real generator, across capability
    /// shapes (a read grant, a write grant with its atomic-temp rule, a `$PATH`
    /// symlink chain, extensions, a raw rule), **every** line of the profile is
    /// accounted for — a raw rule named for `incomplete`, a direct-children
    /// rule, a grant `seatbelt_grant` reads back, a bounded rule, or a line
    /// named in `incomplete`. No rule is silently dropped, so a new emitter
    /// can't widen access unseen. It also checks the full `{access, filter,
    /// path}` of the grants a known fixture must produce, not only their paths.
    #[cfg(target_os = "macos")]
    #[test]
    fn every_rule_the_generator_emits_is_accounted_for() -> Result<()> {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().canonicalize().expect("canon");
        std::fs::create_dir(base.join("readdir")).expect("readdir");
        std::fs::write(base.join("write.json"), b"{}").expect("writefile");
        // A $PATH directory reached through a symlink chain (hops + ancestors).
        std::fs::create_dir_all(base.join("real/bin")).expect("real/bin");
        std::fs::create_dir(base.join("R")).expect("R");
        symlink(base.join("real/bin"), base.join("R/hop")).expect("hop");
        symlink(base.join("R/hop"), base.join("pathdir")).expect("pathdir");

        for (label, build) in [
            ("read + write + atomic", {
                fn b(c: &mut CapabilitySet, base: &Path) {
                    c.add_fs(
                        nono::FsCapability::new_dir(base.join("readdir"), AccessMode::Read)
                            .expect("read cap"),
                    );
                    c.add_fs(
                        nono::FsCapability::new_file(
                            base.join("write.json"),
                            AccessMode::ReadWrite,
                        )
                        .expect("write cap"),
                    );
                    // `add_fs` records the capability but doesn't emit the
                    // atomic-temp platform rule a run's preparation would, so
                    // add it as the generator does, to exercise that filter.
                    c.add_platform_rule(crate::capability_ext::atomic_write_rule(
                        base.join("write.json").to_str().expect("utf-8"),
                    ))
                    .expect("atomic rule");
                }
                b as fn(&mut CapabilitySet, &Path)
            }),
            ("path metadata via a symlink chain", {
                fn b(c: &mut CapabilitySet, base: &Path) {
                    c.add_path_metadata_dir(base.join("pathdir"));
                }
                b
            }),
            ("extensions + a raw rule", {
                fn b(c: &mut CapabilitySet, _base: &Path) {
                    c.set_extensions_enabled(true);
                    c.add_platform_rule(r#"(allow file-read* (subpath "/opt/x"))"#.to_string())
                        .expect("raw rule");
                }
                b
            }),
        ] {
            let mut caps = CapabilitySet::new();
            build(&mut caps, &base);
            let raw: Vec<String> = caps
                .platform_rules()
                .iter()
                .filter(|r| r.contains("/opt/x"))
                .cloned()
                .collect();
            let (_grants, incomplete) = profile_grants(&caps, &raw)?;
            // The direct-children rules, as profile_grants renders them.
            let mut children = std::collections::HashSet::new();
            for read in nono::path::path_metadata_reads(caps.path_metadata_dirs())? {
                if let nono::path::PathMetadataRead::Children(dir) = read {
                    children.insert(format!(
                        "(allow file-read-metadata (regex \"^{}/[^/]+$\"))",
                        nono::sandbox::seatbelt_path_regex(&dir)?
                    ));
                }
            }
            let raw_lines: std::collections::HashSet<&str> =
                raw.iter().flat_map(|r| r.lines()).collect();
            // Every line is accounted for, not only `(allow file-…)` lines:
            // each hits exactly the branch profile_grants takes for it.
            let profile = nono::sandbox::seatbelt_profile(&caps)?;
            for line in profile.lines() {
                if line.is_empty() {
                    continue;
                }
                let accounted = raw_lines.contains(line)
                    || children.contains(line)
                    || seatbelt_grant(line).is_some()
                    || rule_is_bounded(line)
                    || incomplete.iter().any(|m| m.ends_with(line));
                assert!(accounted, "{label}: unaccounted rule: {line}");
            }
        }

        // The full records a known fixture must produce (not only paths): a
        // read dir grant (both ops' shapes collapse to one), its atomic-temp.
        let mut caps = CapabilitySet::new();
        caps.add_fs(
            nono::FsCapability::new_dir(base.join("readdir"), AccessMode::Read).expect("read cap"),
        );
        caps.add_platform_rule(crate::capability_ext::atomic_write_rule(
            base.join("write.json").to_str().expect("utf-8"),
        ))
        .expect("atomic");
        let (grants, _) = profile_grants(&caps, &[])?;
        let readdir = base.join("readdir").to_str().expect("utf-8").to_string();
        let writefile = base.join("write.json").to_str().expect("utf-8").to_string();
        assert!(
            grants.contains(&json!({ "access": "read", "filter": "subpath", "path": readdir })),
            "read subpath grant for the read dir: {grants:?}"
        );
        assert!(
            grants.contains(
                &json!({ "access": "write", "filter": "atomic_temp", "path": writefile })
            ),
            "atomic_temp grant for the writable file: {grants:?}"
        );
        assert!(
            grants.contains(&json!({ "access": "read", "filter": "literal", "path": "/" })),
            "the static root read is reported: {grants:?}"
        );
        Ok(())
    }

    #[test]
    fn access_and_source_names() {
        assert_eq!(access_name(AccessMode::Read), "read");
        assert_eq!(access_name(AccessMode::Write), "write");
        assert_eq!(access_name(AccessMode::ReadWrite), "readwrite");
        let mut value = json!({});
        add_source(&mut value, &CapabilitySource::Group("g".to_string()));
        assert_eq!(value, json!({ "source": "group", "group": "g" }));
    }
}
