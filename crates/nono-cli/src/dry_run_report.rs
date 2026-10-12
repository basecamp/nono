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
//! (capability elevation, a Seatbelt allow rule) is named in `incomplete`, so a
//! program that decides on the report fails closed when it is non-empty.

use std::path::Path;

use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, Result, UnixSocketCapability,
};
use serde_json::{Value, json};

use crate::launch_runtime::{LaunchPlan, NetworkIntent};
use crate::tool_sandbox::DryRunChild;

/// The report's format version: a new field is added without a change; a
/// field changed or removed gets a new version.
pub(crate) const DRY_RUN_REPORT_VERSION: u32 = 1;

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
    #[cfg(target_os = "linux")]
    if plan.flags.capability_elevation || caps.extensions_enabled() {
        incomplete.push(
            "capability elevation: the supervisor can grant paths beyond this list at runtime"
                .to_string(),
        );
    }
    incomplete.extend(seatbelt_widenings(&caps, raw_rules));
    // (The rules command mediation's runtime adds to the session's set at
    // launch: an allow among them widens it too.)
    let runtime_allows = mediation
        .session_rules
        .iter()
        .filter(|rule| seatbelt_allows(rule))
        .count();
    if runtime_allows > 0 {
        incomplete.push(format!(
            "{runtime_allows} Seatbelt allow rule(s) command mediation adds to the session at launch"
        ));
    }
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
        "metadata_paths": metadata_paths(&caps),
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

/// The directories whose metadata the run lets the sandbox read beyond the
/// list (macOS: each `$PATH` directory, its children, ancestors and symlink
/// hops, as `file-read-metadata` only). Linux grants none.
#[cfg(target_os = "macos")]
fn metadata_paths(caps: &CapabilitySet) -> Vec<Value> {
    caps.path_metadata_dirs()
        .iter()
        .map(|p| path_value(p))
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn metadata_paths(_caps: &CapabilitySet) -> Vec<Value> {
    Vec::new()
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

/// Whether a Seatbelt rule holds an `allow` form anywhere, however it is
/// spaced: `(allow`, `( allow`, `(\tallow`.
fn seatbelt_allows(rule: &str) -> bool {
    rule.match_indices('(')
        .any(|(at, _)| rule[at + 1..].trim_start().starts_with("allow"))
}

/// The Seatbelt rules that can grant beyond the capability list: the
/// profile's raw rules the set applies, whatever they say, and every other
/// `allow` rule the preparation generated (a keychain grant, say). Deny rules
/// only narrow.
fn seatbelt_widenings(caps: &CapabilitySet, raw_rules: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    // (Only the raw rules the prepared set still applies: none on Linux, and
    // none a trust policy stripped.)
    let applied_raw = raw_rules
        .iter()
        .filter(|rule| caps.platform_rules().contains(rule))
        .count();
    if applied_raw > 0 {
        out.push(format!(
            "{applied_raw} raw Seatbelt rule(s) (unsafe_macos_seatbelt_rules) the capability list cannot show"
        ));
    }
    let generated = caps
        .platform_rules()
        .iter()
        .filter(|rule| !raw_rules.contains(rule) && seatbelt_allows(rule))
        .count();
    if generated > 0 {
        out.push(format!(
            "{generated} generated Seatbelt allow rule(s) that grant beyond the capability list"
        ));
    }
    out
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
            let mut incomplete = seatbelt_widenings(&launch.caps, raw);
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
            })
        }
        Err(reason) => json!({
            "executable": null,
            "incomplete": [format!("its launch from the working directory is not built: {reason}")],
            "filesystem": [],
            "unix_sockets": [],
            "exec_paths": [],
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
    fn seatbelt_allows_beyond_the_list_are_named() -> Result<()> {
        let mut caps = CapabilitySet::new();
        caps.add_platform_rule("(deny file-read* (subpath \"/a\"))".to_string())?;
        assert!(
            seatbelt_widenings(&caps, &[]).is_empty(),
            "a deny only narrows"
        );
        caps.add_platform_rule(
            "(deny file-read* (subpath \"/b\")) (allow file-read* (subpath \"/c\"))".to_string(),
        )?;
        assert_eq!(
            seatbelt_widenings(&caps, &[]).len(),
            1,
            "an allow anywhere in a rule widens"
        );
        let unapplied = vec!["(allow file-read* (subpath \"/d\"))".to_string()];
        assert_eq!(
            seatbelt_widenings(&caps, &unapplied).len(),
            1,
            "a raw rule the set doesn't apply counts for nothing"
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
