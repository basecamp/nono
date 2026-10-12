//! `nono run --dry-run --json`: what a run would apply, as data.
//!
//! The text dry run is written for people. A program that needs to decide on
//! the same answer (a launcher checking that a sandbox keeps away from some
//! directory, say) would otherwise have to parse it, and a path can hold any
//! byte the text framing uses. This report carries the same resolution as
//! JSON on stdout: every filesystem and Unix-socket capability the run would
//! apply (globs expanded, variables filled, symlinks followed, policy groups
//! and user flags included), the effective network mode, the resource limits,
//! and each brokered command's sandbox, resolved by the code that builds it at
//! launch.
//!
//! What it cannot model is named in `incomplete` (raw macOS Seatbelt rules,
//! a credential it cannot resolve): a program that decides on the report
//! treats a nonempty `incomplete` as "cannot be shown". Not listed at all: what
//! nono adds for itself once it runs (its capability state file, the
//! command-mediation shims and sockets under its runtime directory, a brokered
//! command's runtime baseline of system libraries), and instruction files the
//! trust scan verifies.

use std::path::{Path, PathBuf};

use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, NetworkMode, Result,
    UnixSocketCapability,
};
use serde_json::{Value, json};

use crate::cli::SandboxArgs;
use crate::command_policy::{
    CommandCredentialGrantConfig, CommandCredentialType, CommandPoliciesConfig,
    CommandSandboxConfig,
};
use crate::sandbox_prepare::PreparedSandbox;

/// The report's format version: a new field is added without a change; a
/// field changed or removed gets a new version.
pub(crate) const DRY_RUN_REPORT_VERSION: u32 = 1;

/// The report for `prepared`, as `nono run` would apply it from `workdir`.
pub(crate) fn dry_run_report(
    args: &SandboxArgs,
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
    // The child's own view: on Linux the launch widens a read grant of
    // `/proc/self` to `/proc` (every descendant reads its own entries).
    #[cfg(target_os = "linux")]
    let caps = {
        let mut caps = prepared.caps.clone();
        caps.widen_procfs_self_to_proc();
        caps
    };
    #[cfg(not(target_os = "linux"))]
    let caps = prepared.caps.clone();
    let mut incomplete: Vec<String> = Vec::new();
    if !caps.platform_rules().is_empty() {
        incomplete.push(format!(
            "{} raw platform rule(s) (unsafe_macos_seatbelt_rules) the report cannot model",
            caps.platform_rules().len()
        ));
    }
    let limits = caps.resource_limits();
    let commands = match prepared.command_policies.as_ref() {
        Some(config) if config.is_active() => command_reports(
            config,
            prepared.resolved_command_binaries.as_ref(),
            &workdir,
            &caps,
            &prepared.deny_paths,
        )?,
        _ => Vec::new(),
    };
    Ok(json!({
        "version": DRY_RUN_REPORT_VERSION,
        "program": path_value(Path::new(program)),
        "workdir": path_value(&workdir),
        "incomplete": incomplete,
        "filesystem": caps.fs_capabilities().iter().map(fs_value).collect::<Vec<_>>(),
        "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
        "network": network_value(args, prepared, &caps),
        "resources": {
            "memory_bytes": limits.and_then(|l| l.memory_bytes),
            "max_processes": limits.and_then(|l| l.max_processes),
        },
        "commands": commands,
    }))
}

/// The network mode the run applies: the proxy, when the run starts one, is
/// decided after preparation (`proxy_runtime`), as the text summary decides it.
fn network_value(args: &SandboxArgs, prepared: &PreparedSandbox, caps: &CapabilitySet) -> Value {
    let mode = match caps.network_mode() {
        NetworkMode::Blocked => "blocked",
        NetworkMode::ProxyOnly { .. } => "proxy",
        NetworkMode::AllowAll => {
            if crate::sandbox_prepare::proxy_pending(args, prepared) {
                "proxy"
            } else {
                "allowed"
            }
        }
    };
    json!({ "mode": mode, "blocked": mode != "allowed" })
}

/// Each sandbox a brokered command can run under, as the runtime selects it:
/// its session sandbox (`from.session`, else the top-level `sandbox`), each
/// `from.<caller>` edge whose caller is a command that lists it in `can_use`,
/// and each intercept rule's override when the command can run at all. An
/// explicit deny runs nothing and is not listed.
fn command_reports(
    config: &CommandPoliciesConfig,
    binaries: Option<&crate::command_policy::ResolvedCommandBinaries>,
    workdir: &Path,
    outer_caps: &CapabilitySet,
    deny_paths: &[PathBuf],
) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (name, command) in &config.commands {
        let ctx = CommandContext {
            config,
            name,
            executable: binaries
                .and_then(|b| b.commands.get(name))
                .map(|b| b.canonical_path.clone()),
            workdir,
            outer_caps,
            deny_paths,
        };
        let session = match command.from.get("session") {
            Some(from) => from.sandbox(),
            None => command.sandbox.as_ref(),
        };
        let mut reachable = false;
        if let Some(sandbox) = session {
            reachable = true;
            out.push(ctx.value(Some("session"), None, sandbox)?);
        }
        for (caller, from) in &command.from {
            if caller == "session" {
                continue;
            }
            let admitted = config
                .commands
                .get(caller)
                .is_some_and(|c| c.can_use.iter().any(|n| n == name));
            if let (true, Some(sandbox)) = (admitted, from.sandbox()) {
                reachable = true;
                out.push(ctx.value(Some(caller), None, sandbox)?);
            }
        }
        if reachable {
            for (index, rule) in command.intercept.iter().enumerate() {
                if let Some(sandbox) = rule.sandbox.as_ref() {
                    out.push(ctx.value(None, Some(index), sandbox)?);
                }
            }
        }
    }
    Ok(out)
}

struct CommandContext<'a> {
    config: &'a CommandPoliciesConfig,
    name: &'a str,
    executable: Option<PathBuf>,
    workdir: &'a Path,
    outer_caps: &'a CapabilitySet,
    deny_paths: &'a [PathBuf],
}

impl CommandContext<'_> {
    fn value(
        &self,
        caller: Option<&str>,
        intercept: Option<usize>,
        sandbox: &CommandSandboxConfig,
    ) -> Result<Value> {
        // Resolved as a run of the command from the working directory would be.
        let grants = crate::tool_sandbox::resolve_policy_grants(
            sandbox,
            self.workdir,
            self.workdir,
            self.outer_caps,
            self.deny_paths,
        )?;
        let mut caps = grants.caps;
        let mut incomplete: Vec<String> = Vec::new();
        if !sandbox.unsafe_macos_seatbelt_rules.is_empty() {
            incomplete.push(format!(
                "{} raw Seatbelt rule(s) (unsafe_macos_seatbelt_rules) the report cannot model",
                sandbox.unsafe_macos_seatbelt_rules.len()
            ));
        }
        // The credentials its launch hands it as paths: a raw file to read, a
        // local socket to connect to.
        for handle in credential_names(sandbox) {
            let Some(credential) = self.config.credentials.get(handle) else {
                incomplete.push(format!("credential '{handle}' is not defined"));
                continue;
            };
            match credential_path(credential) {
                Ok(Some((path, CommandCredentialType::LocalSocket))) => {
                    caps.add_unix_socket(UnixSocketCapability::new_file(
                        &path,
                        nono::UnixSocketMode::Connect,
                    )?);
                    caps.add_fs(FsCapability::new_file(&path, AccessMode::Read)?);
                }
                Ok(Some((path, _))) => {
                    caps.add_fs(FsCapability::new_file(&path, AccessMode::Read)?)
                }
                Ok(None) => {}
                Err(reason) => incomplete.push(format!("credential '{handle}': {reason}")),
            }
        }
        // The entries whose meaning depends on where the command runs: a
        // relative path, or a dynamic `@` token, resolve against its live
        // working directory.
        let cwd_dependent: Vec<&String> = grants
            .declared
            .iter()
            .map(|d| &d.entry)
            .filter(|entry| {
                !(entry.starts_with('/') || entry.starts_with('$') || entry.starts_with('~'))
            })
            .collect();
        Ok(json!({
            "command": self.name,
            "caller": caller,
            "intercept": intercept,
            "executable": self.executable.as_deref().map(path_value),
            "incomplete": incomplete,
            "filesystem": caps.fs_capabilities().iter().map(fs_value).collect::<Vec<_>>(),
            "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
            "exec_paths": grants.exec_paths.iter().map(|p| path_value(p)).collect::<Vec<_>>(),
            "declared": grants.declared.iter().map(|d| json!({
                "field": d.field,
                "entry": d.entry,
                "expanded": path_value(&d.expanded),
            })).collect::<Vec<_>>(),
            "cwd_dependent": cwd_dependent,
        }))
    }
}

/// The credential handles a command sandbox uses (`use_credentials`, then
/// `credentials`), as the launch reads them.
fn credential_names(sandbox: &CommandSandboxConfig) -> Vec<&str> {
    let mut names: Vec<&str> = sandbox.use_credentials.iter().map(String::as_str).collect();
    names.extend(
        sandbox
            .credentials
            .iter()
            .map(|credential| match credential {
                CommandCredentialGrantConfig::Name(name) => name.as_str(),
                CommandCredentialGrantConfig::Policy(policy) => policy.name.as_str(),
            }),
    );
    names
}

/// A raw-file or local-socket credential's canonical path, as the launch
/// resolves it; none for a proxied or ambient one, which hands the command no
/// path. An error when the launch could not resolve it either.
fn credential_path(
    credential: &crate::command_policy::CommandCredentialConfig,
) -> std::result::Result<Option<(PathBuf, CommandCredentialType)>, String> {
    let kind = credential.credential_type;
    let template = match kind {
        CommandCredentialType::RawFile | CommandCredentialType::LocalSocket => {
            credential.path.as_deref().ok_or("no path")?
        }
        CommandCredentialType::Proxy | CommandCredentialType::Ambient => return Ok(None),
    };
    let expanded = match kind {
        CommandCredentialType::LocalSocket => {
            crate::policy::expand_env_vars_strict(template).map_err(|e| e.to_string())?
        }
        _ => template.to_string(),
    };
    let path = PathBuf::from(expanded)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    Ok(Some((path, kind)))
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
