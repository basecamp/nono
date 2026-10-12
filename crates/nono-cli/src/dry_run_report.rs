//! `nono run --dry-run --json`: what a run would apply, as data.
//!
//! The text dry run is written for people. A program that needs to decide on
//! the same answer (a launcher checking that a sandbox keeps away from some
//! directory, say) would otherwise have to parse it, and a path can hold any
//! byte the text framing uses. This report carries the same resolution as
//! JSON on stdout: every filesystem and Unix-socket capability the run would
//! apply (globs expanded, variables filled, symlinks followed, policy groups
//! and user flags included), the resource limits, and each brokered command's
//! sandbox, resolved by the code that builds it at launch.
//!
//! Not listed: what nono adds for itself once it runs (its capability state
//! file, the command-mediation shims and sockets under its runtime directory,
//! trust-verified instruction files when trust scanning is on).

use std::path::{Path, PathBuf};

use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, Result, UnixSocketCapability,
};
use serde_json::{Value, json};

use crate::command_policy::{CommandPoliciesConfig, CommandSandboxConfig};
use crate::sandbox_prepare::PreparedSandbox;

/// The report's format version: a new field is added without a change; a
/// field changed or removed gets a new version.
pub(crate) const DRY_RUN_REPORT_VERSION: u32 = 1;

/// The report for `prepared`, as `nono run` would apply it from `workdir`.
pub(crate) fn dry_run_report(
    prepared: &PreparedSandbox,
    program: &std::ffi::OsStr,
    workdir: &Path,
) -> Result<Value> {
    let workdir =
        workdir
            .canonicalize()
            .map_err(|source| nono::NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source,
            })?;
    let caps = &prepared.caps;
    let limits = caps.resource_limits();
    let commands = match prepared.command_policies.as_ref() {
        Some(config) if config.is_active() => {
            command_reports(config, &workdir, caps, &prepared.deny_paths)?
        }
        _ => Vec::new(),
    };
    Ok(json!({
        "version": DRY_RUN_REPORT_VERSION,
        "program": path_value(Path::new(program)),
        "workdir": path_value(&workdir),
        "filesystem": caps.fs_capabilities().iter().map(fs_value).collect::<Vec<_>>(),
        "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
        "network": { "blocked": caps.is_network_blocked() },
        "resources": {
            "memory_bytes": limits.and_then(|l| l.memory_bytes),
            "max_processes": limits.and_then(|l| l.max_processes),
        },
        "commands": commands,
    }))
}

/// Each sandbox a brokered command can run under: its session sandbox
/// (`from.session`, else the top-level `sandbox`), each other caller's
/// `from` edge, and each intercept rule's override. An explicit deny runs
/// nothing and is not listed.
fn command_reports(
    config: &CommandPoliciesConfig,
    workdir: &Path,
    outer_caps: &CapabilitySet,
    deny_paths: &[PathBuf],
) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (name, command) in &config.commands {
        let session = match command.from.get("session") {
            Some(from) => from.sandbox(),
            None => command.sandbox.as_ref(),
        };
        if let Some(sandbox) = session {
            out.push(command_value(
                name,
                Some("session"),
                None,
                sandbox,
                workdir,
                outer_caps,
                deny_paths,
            )?);
        }
        for (caller, from) in &command.from {
            if caller == "session" {
                continue;
            }
            if let Some(sandbox) = from.sandbox() {
                out.push(command_value(
                    name,
                    Some(caller),
                    None,
                    sandbox,
                    workdir,
                    outer_caps,
                    deny_paths,
                )?);
            }
        }
        for (index, rule) in command.intercept.iter().enumerate() {
            if let Some(sandbox) = rule.sandbox.as_ref() {
                out.push(command_value(
                    name,
                    None,
                    Some(index),
                    sandbox,
                    workdir,
                    outer_caps,
                    deny_paths,
                )?);
            }
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn command_value(
    name: &str,
    caller: Option<&str>,
    intercept: Option<usize>,
    sandbox: &CommandSandboxConfig,
    workdir: &Path,
    outer_caps: &CapabilitySet,
    deny_paths: &[PathBuf],
) -> Result<Value> {
    // Resolved as a run of the command from the working directory would be.
    let (caps, exec_paths) = crate::tool_sandbox::resolve_policy_grants(
        sandbox, workdir, workdir, outer_caps, deny_paths,
    )?;
    // The entries whose meaning depends on where the command runs: a relative
    // path, or a dynamic `@` token, resolve against its live working directory.
    let cwd_dependent: Vec<&String> = sandbox
        .fs_read
        .iter()
        .chain(&sandbox.fs_read_file)
        .chain(&sandbox.fs_write)
        .chain(&sandbox.fs_write_file)
        .chain(&sandbox.unix_socket_bind)
        .chain(&sandbox.exec_paths)
        .filter(|entry| {
            !(entry.starts_with('/') || entry.starts_with('$') || entry.starts_with('~'))
        })
        .collect();
    Ok(json!({
        "command": name,
        "caller": caller,
        "intercept": intercept,
        "filesystem": caps.fs_capabilities().iter().map(fs_value).collect::<Vec<_>>(),
        "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
        "exec_paths": exec_paths.iter().map(|p| path_value(p)).collect::<Vec<_>>(),
        "cwd_dependent": cwd_dependent,
    }))
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
    fn access_and_source_names() {
        assert_eq!(access_name(AccessMode::Read), "read");
        assert_eq!(access_name(AccessMode::Write), "write");
        assert_eq!(access_name(AccessMode::ReadWrite), "readwrite");
        let mut value = json!({});
        add_source(&mut value, &CapabilitySource::Group("g".to_string()));
        assert_eq!(value, json!({ "source": "group", "group": "g" }));
    }
}
