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
//! command-mediation shims and sockets under its runtime directory), what a
//! brokered command's launch derives from the binary it runs rather than from
//! its policy (the interpreter, the ELF dependency closure, an `exec`
//! intercept's helper), and instruction files the trust scan verifies.

use std::path::{Path, PathBuf};

use nono::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, Result, UnixSocketCapability,
};
use serde_json::{Value, json};

use crate::cli::SandboxArgs;
use crate::command_policy::{
    CommandCredentialGrantConfig, CommandCredentialType, CommandPoliciesConfig,
    CommandSandboxConfig, InterceptActionConfig,
};
use crate::sandbox_prepare::PreparedSandbox;

/// The report's format version: a new field is added without a change; a
/// field changed or removed gets a new version.
pub(crate) const DRY_RUN_REPORT_VERSION: u32 = 1;

/// The report for `prepared`, as `nono run` would apply it from `workdir`.
/// `raw_platform_rules`: how many raw Seatbelt rules the profile adds
/// (`unsafe_macos_seatbelt_rules`), which the report cannot model.
pub(crate) fn dry_run_report(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    program: &std::ffi::OsStr,
    workdir: &Path,
    raw_platform_rules: usize,
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
    // (Only the profile's raw rules: the rules nono generates itself, its
    // protected-root denies among them, are part of the resolution reported.)
    if raw_platform_rules > 0 {
        incomplete.push(format!(
            "{raw_platform_rules} raw Seatbelt rule(s) (unsafe_macos_seatbelt_rules) the report cannot model"
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
        "network": network_value(args, prepared)?,
        "resources": {
            "memory_bytes": limits.and_then(|l| l.memory_bytes),
            "max_processes": limits.and_then(|l| l.max_processes),
        },
        "commands": commands,
    }))
}

/// The network mode the run applies, decided as the launch decides it
/// (`prepare_proxy_launch_options`, which builds the proxy's settings without
/// starting it): blocked, filtered through the proxy, or allowed.
fn network_value(args: &SandboxArgs, prepared: &PreparedSandbox) -> Result<Value> {
    let intent = crate::proxy_runtime::prepare_proxy_launch_options(
        args,
        prepared,
        true,
        "dry-run".to_string(),
    )?;
    // With no proxy and no block decided, the launch keeps the prepared
    // capability set's own mode (a manifest's `"mode": "blocked"`, say).
    let mode = match intent {
        crate::launch_runtime::NetworkIntent::BlockAll => "blocked",
        ref intent if intent.is_proxy_active() => "proxy",
        _ => match prepared.caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked",
            nono::NetworkMode::ProxyOnly { .. } => "proxy",
            nono::NetworkMode::AllowAll => "allowed",
        },
    };
    Ok(json!({ "mode": mode, "blocked": mode != "allowed" }))
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
        // Each sandbox a run of the command selects, with the caller that
        // selects it.
        let mut selected: Vec<(&str, &CommandSandboxConfig)> = Vec::new();
        if let Some(sandbox) = session {
            selected.push(("session", sandbox));
            out.push(ctx.value(Some("session"), None, sandbox, None)?);
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
                selected.push((caller.as_str(), sandbox));
                out.push(ctx.value(Some(caller), None, sandbox, None)?);
            }
        }
        // (An intercept rule applies to a run of the command, which only a
        // session or admitted caller makes.) A `respond` rule launches nothing.
        // A rule with a sandbox of its own runs under it, whoever called; an
        // `exec` rule without one runs its helper under each sandbox the
        // callers select; any other rule without one runs the command as
        // already listed.
        if !selected.is_empty() {
            for (index, rule) in command.intercept.iter().enumerate() {
                let helper = match &rule.action {
                    InterceptActionConfig::Respond { .. } => continue,
                    InterceptActionConfig::Exec { command: argv } => {
                        argv.first().map(String::as_str)
                    }
                    _ => None,
                };
                match (rule.sandbox.as_ref(), helper) {
                    (Some(sandbox), _) => {
                        out.push(ctx.value(None, Some(index), sandbox, helper)?)
                    }
                    (None, Some(_)) => {
                        for (caller, sandbox) in &selected {
                            out.push(ctx.value(Some(caller), Some(index), sandbox, helper)?);
                        }
                    }
                    (None, None) => {}
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
    /// `helper`: an `exec` intercept's helper, as written, which the launch runs
    /// in place of the command's own executable.
    fn value(
        &self,
        caller: Option<&str>,
        intercept: Option<usize>,
        sandbox: &CommandSandboxConfig,
        helper: Option<&str>,
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
        let executable = match helper {
            None => self.executable.clone(),
            Some(raw) => match crate::policy::expand_env_vars_strict(raw)
                .map_err(|e| e.to_string())
                .and_then(|p| PathBuf::from(p).canonicalize().map_err(|e| e.to_string()))
            {
                Ok(path) => Some(path),
                Err(reason) => {
                    incomplete.push(format!("exec helper '{raw}': {reason}"));
                    None
                }
            },
        };
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
                // A path that isn't the kind the credential says (a regular
                // file named as a socket) leaves the credential unavailable
                // at launch; it is named here rather than failing the report.
                Ok(Some((path, CommandCredentialType::LocalSocket))) => {
                    match UnixSocketCapability::new_file(&path, nono::UnixSocketMode::Connect)
                        .and_then(|socket| {
                            FsCapability::new_file(&path, AccessMode::Read).map(|f| (socket, f))
                        }) {
                        Ok((socket, file)) => {
                            caps.add_unix_socket(socket);
                            caps.add_fs(file);
                        }
                        Err(e) => incomplete.push(format!("credential '{handle}': {e}")),
                    }
                }
                // (The launch reads a raw-file credential only from a regular
                // file: a device, a FIFO or a socket leaves it unavailable.)
                Ok(Some((path, _))) if !path.is_file() => incomplete.push(format!(
                    "credential '{handle}': {} is not a regular file",
                    path.display()
                )),
                Ok(Some((path, _))) => match FsCapability::new_file(&path, AccessMode::Read) {
                    Ok(file) => caps.add_fs(file),
                    Err(e) => incomplete.push(format!("credential '{handle}': {e}")),
                },
                Ok(None) => {}
                Err(reason) => incomplete.push(format!("credential '{handle}': {reason}")),
            }
        }
        // The entries whose meaning depends on where the command runs: a
        // dynamic `@` token, or an entry still relative once its variables are
        // filled, resolve against its live working directory.
        let mut cwd_dependent: Vec<&String> = Vec::new();
        for d in grants.declared.iter().filter(|d| d.cwd_dependent) {
            if !cwd_dependent.contains(&&d.entry) {
                cwd_dependent.push(&d.entry);
            }
        }
        Ok(json!({
            "command": self.name,
            "caller": caller,
            "intercept": intercept,
            "executable": executable.as_deref().map(path_value),
            "incomplete": incomplete,
            "filesystem": caps.fs_capabilities().iter().map(fs_value).collect::<Vec<_>>(),
            "unix_sockets": caps.unix_socket_capabilities().iter().map(socket_value).collect::<Vec<_>>(),
            "exec_paths": grants.exec_paths.iter().map(|p| path_value(p)).collect::<Vec<_>>(),
            "declared": grants.declared.iter().map(|d| json!({
                "field": d.field,
                "entry": d.entry,
                "expanded": d.expanded.as_deref().map(path_value),
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
