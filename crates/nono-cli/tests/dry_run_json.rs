//! `nono run --dry-run --json`: the resolved capability set as data.
//!
//! Each case checks the report against what the run resolves: globs expanded,
//! variables filled, symlinks followed, user flags included, resource limits as
//! fields, and each brokered command's sandbox resolved by the launch code.

use nono_test_support::{Argv, NonoTest, nono_test};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

type Run<'t> = nono_test_support::cli::Sandboxed<'t, nono_test_support::cli::RunMode>;

fn report(t: &NonoTest, json: &str, extra: impl FnOnce(Run<'_>) -> Run<'_>) -> Value {
    let profile = t.write_profile("dry-run-json", json);
    let completed = extra(t.run().profile(&profile).workdir(t.workspace()))
        .dry_run_json()
        .exec(Argv::new("/bin/true"))
        .assert_success("--dry-run --json exits 0");
    serde_json::from_str(&completed.stdout())
        .unwrap_or_else(|e| panic!("stdout is one JSON document ({e}): {}", completed.stdout()))
}

fn canon(path: &Path) -> String {
    fs::canonicalize(path)
        .expect("the test made this path")
        .to_str()
        .expect("test paths are UTF-8")
        .to_string()
}

fn fs_entry<'a>(report: &'a Value, path: &str) -> Option<&'a Value> {
    report["filesystem"]
        .as_array()
        .expect("filesystem is an array")
        .iter()
        .find(|entry| entry["path"] == path)
}

#[test]
fn reports_resolved_session_grants_and_resources() {
    let t = nono_test!("dry-run-json-session");
    let ws = t.workspace().to_path_buf();
    // A glob, a symlink, a variable, and a name the text summary's framing uses.
    for dir in ["cache-a", "cache-b", "target", "odd (Capabilities:) [x]"] {
        fs::create_dir_all(ws.join(dir)).expect("create dir");
    }
    symlink(ws.join("target"), ws.join("link")).expect("symlink");
    fs::create_dir_all(t.home().join("docs")).expect("create docs");
    let json = format!(
        r#"{{"meta":{{"name":"t"}},"filesystem":{{"read":["{ws}/cache-*","{ws}/link","$HOME/docs","{ws}/odd (Capabilities:) [x]"]}}}}"#,
        ws = ws.display()
    );
    let flag_dir = ws.join("flag");
    fs::create_dir_all(&flag_dir).expect("create flag dir");
    let report = report(&t, &json, |run| run.read(&flag_dir).memory("64M"));

    assert_eq!(report["version"], 1);
    for dir in ["cache-a", "cache-b"] {
        let entry = fs_entry(&report, &canon(&ws.join(dir)))
            .unwrap_or_else(|| panic!("glob match {dir} listed: {report}"));
        assert_eq!(entry["access"], "read");
        assert_eq!(entry["kind"], "directory");
        assert_eq!(entry["source"], "profile");
    }
    let target =
        fs_entry(&report, &canon(&ws.join("target"))).expect("the symlink's target is listed");
    assert_eq!(target["original"], ws.join("link").to_str().expect("utf-8"));
    assert!(
        fs_entry(&report, &canon(&t.home().join("docs"))).is_some(),
        "$HOME filled: {report}"
    );
    assert!(
        fs_entry(&report, &canon(&ws.join("odd (Capabilities:) [x]"))).is_some(),
        "a path holding the text summary's framing is reported whole: {report}"
    );
    assert_eq!(
        fs_entry(&report, &canon(&flag_dir)).expect("--read listed")["source"],
        "user"
    );
    assert_eq!(report["resources"]["memory_bytes"], 64 * 1024 * 1024);
    assert!(report["resources"]["max_processes"].is_null());
    assert_eq!(report["commands"], serde_json::json!([]));
}

#[test]
fn reports_each_brokered_command_sandbox_resolved() {
    let t = nono_test!("dry-run-json-commands");
    let ws = t.workspace().to_path_buf();
    for dir in ["data", "helpers", "intercepted", "other", "from-caller"] {
        fs::create_dir_all(ws.join(dir)).expect("create dir");
    }
    symlink(ws.join("data"), ws.join("data-link")).expect("symlink");
    fs::write(ws.join("token"), "t").expect("write token");
    let json = format!(
        r#"{{
          "meta": {{"name": "t"}},
          "workdir": {{"access": "readwrite"}},
          "command_policies": {{
            "credentials": {{"tok": {{"type": "raw-file", "path": "{ws}/token"}}}},
            "commands": {{
              "probe": {{
                "executable": "/bin/true",
                "from": {{
                  "session": {{"sandbox": {{"fs_read": ["{ws}/data-link", ".", "{ws}/not-yet", "$UID/rel"], "exec_paths": ["{ws}/helpers"], "use_credentials": ["tok"]}}}},
                  "caller": {{"sandbox": {{"fs_read": ["{ws}/from-caller"]}}}},
                  "stranger": {{"sandbox": {{"fs_read": ["{ws}/other"]}}}},
                  "nocan": {{"sandbox": {{"fs_read": ["{ws}/other"]}}}}
                }},
                "intercept": [
                  {{"args": ["x"], "sandbox": {{"fs_read": ["{ws}/intercepted"]}}}},
                  {{"args": ["r"], "action": {{"type": "respond", "stdout": "hi"}}}},
                  {{"args": ["e"], "action": {{"type": "exec", "command": ["/bin/echo"]}}}}
                ]
              }},
              "caller": {{
                "executable": "/bin/echo",
                "can_use": ["probe"],
                "sandbox": {{"fs_write": ["{ws}/other"]}}
              }},
              "nocan": {{
                "executable": "/bin/echo",
                "sandbox": {{"fs_read": ["{ws}/other"], "use_credentials": []}}
              }},
              "denied": {{
                "executable": "/bin/echo",
                "from": {{"session": "deny"}},
                "intercept": [{{"args": ["y"], "sandbox": {{"fs_read": ["{ws}/intercepted"]}}}}]
              }}
            }}
          }}
        }}"#,
        ws = ws.display()
    );
    let report = report(&t, &json, |run| run.allow_cwd());
    let commands = report["commands"].as_array().expect("commands is an array");
    let find = |command: &str, caller: &str| {
        commands
            .iter()
            .find(|c| c["command"] == command && c["caller"] == caller)
    };
    let has_path = |entry: &Value, path: &Path| {
        entry["filesystem"]
            .as_array()
            .expect("filesystem")
            .iter()
            .any(|e| e["path"] == canon(path).as_str())
    };
    let probe = find("probe", "session")
        .unwrap_or_else(|| panic!("probe's session sandbox listed: {report}"));
    let data = probe["filesystem"]
        .as_array()
        .expect("filesystem")
        .iter()
        .find(|e| e["path"] == canon(&ws.join("data")).as_str())
        .unwrap_or_else(|| panic!("the symlinked grant resolves to its target: {probe}"));
    assert_eq!(
        data["original"],
        ws.join("data-link").to_str().expect("utf-8")
    );
    assert!(
        has_path(probe, &ws),
        "'.' resolves against the working directory: {probe}"
    );
    assert!(
        has_path(probe, &ws.join("token")),
        "the raw-file credential is a read grant: {probe}"
    );
    assert_eq!(probe["executable"], canon(Path::new("/bin/true")).as_str());
    #[cfg(target_os = "linux")]
    assert!(
        probe["exec_paths"]
            .as_array()
            .expect("exec_paths")
            .iter()
            .any(|p| p == ws.join("helpers").to_str().expect("utf-8")),
        "the launch's execute allowlist holds the policy's exec_paths: {probe}"
    );
    assert_eq!(
        probe["cwd_dependent"],
        serde_json::json!([".", "$UID/rel"]),
        "an entry its variables leave relative depends on the working directory too"
    );
    assert!(
        probe["declared"]
            .as_array()
            .expect("declared")
            .iter()
            .any(|d| d["field"] == "fs_read"
                && d["expanded"] == ws.join("not-yet").to_str().expect("utf-8")),
        "a declared path that is not there yet is still reported: {probe}"
    );
    assert_eq!(probe["incomplete"], serde_json::json!([]));
    assert!(
        find("nocan", "session").is_some(),
        "nocan's top-level sandbox is the session's: {report}"
    );
    let from_caller = find("probe", "caller")
        .unwrap_or_else(|| panic!("an admitted caller's edge is listed: {report}"));
    assert!(
        has_path(from_caller, &ws.join("from-caller")),
        "{from_caller}"
    );
    assert!(
        find("probe", "nocan").is_none(),
        "an edge from a command that does not list probe in can_use never runs, and is not listed: {report}"
    );
    assert!(
        find("probe", "stranger").is_none(),
        "an edge from a caller that is no command listing probe in can_use never runs, and is not listed: {report}"
    );
    assert!(
        !commands.iter().any(|c| c["command"] == "denied"),
        "an explicit session deny, with no admitted caller, runs nothing, its intercept override neither, and is not listed: {report}"
    );
    let intercept = commands
        .iter()
        .find(|c| c["command"] == "probe" && c["intercept"] == 0 && c["caller"] == "session")
        .unwrap_or_else(|| panic!("the intercept rule's sandbox listed: {report}"));
    assert!(
        commands
            .iter()
            .any(|c| c["command"] == "probe" && c["intercept"] == 0 && c["caller"] == "caller"),
        "for each caller whose run it intercepts: {report}"
    );
    assert!(
        !commands
            .iter()
            .any(|c| c["command"] == "probe" && c["intercept"] == 1),
        "a respond rule launches nothing, and its sandbox is not listed: {report}"
    );
    let exec = commands
        .iter()
        .find(|c| c["command"] == "probe" && c["intercept"] == 2 && c["caller"] == "session")
        .unwrap_or_else(|| panic!("an exec rule is listed, under the session's sandbox: {report}"));
    let exec_caller = commands
        .iter()
        .find(|c| c["command"] == "probe" && c["intercept"] == 2 && c["caller"] == "caller")
        .unwrap_or_else(|| panic!("and under each admitted caller's: {report}"));
    assert!(
        has_path(exec_caller, &ws.join("from-caller")),
        "{exec_caller}"
    );
    assert_eq!(
        exec_caller["executable"],
        canon(Path::new("/bin/echo")).as_str()
    );
    assert_eq!(
        exec["executable"],
        canon(Path::new("/bin/echo")).as_str(),
        "its helper is what runs: {exec}"
    );
    assert!(
        has_path(exec, &ws.join("data")),
        "the session's sandbox: {exec}"
    );
    assert!(has_path(intercept, &ws.join("intercepted")), "{intercept}");
    let caller = find("caller", "session")
        .unwrap_or_else(|| panic!("a top-level sandbox is the session's: {report}"));
    assert!(
        caller["filesystem"]
            .as_array()
            .expect("fs")
            .iter()
            .any(|e| e["path"] == canon(&ws.join("other")).as_str() && e["access"] == "readwrite"),
        "{caller}"
    );
}

#[test]
fn reports_the_network_mode_the_run_applies() {
    let t = nono_test!("dry-run-json-network");
    let proxied = report(
        &t,
        r#"{"meta":{"name":"t"},"network":{"allow_domain":["example.com"]}}"#,
        |run| run,
    );
    assert_eq!(proxied["network"], serde_json::json!({"mode": "proxy"}));
    let blocked = report(&t, r#"{"meta":{"name":"t"}}"#, |run| run.block_net());
    assert_eq!(blocked["network"], serde_json::json!({"mode": "blocked"}));
    let open = report(&t, r#"{"meta":{"name":"t"}}"#, |run| run);
    assert_eq!(open["network"], serde_json::json!({"mode": "allowed"}));
    // A credential route defined but not enabled starts no proxy.
    let defined_only = report(
        &t,
        r#"{"meta":{"name":"t"},"network":{"custom_credentials":{"x":{"upstream":"https://example.com","credential_key":"env://ASN_UNSET_TOKEN"}}}}"#,
        |run| run,
    );
    assert_eq!(
        defined_only["network"],
        serde_json::json!({"mode": "allowed"})
    );
}

#[test]
fn reports_a_manifest_blocked_network_as_blocked() {
    let t = nono_test!("dry-run-json-manifest-network");
    let manifest = t.root().join("manifest.json");
    fs::write(
        &manifest,
        r#"{"version": "0.1.0", "filesystem": {"grants": []}, "network": {"mode": "blocked"}}"#,
    )
    .expect("write manifest");
    let completed = t
        .run()
        .config(&manifest)
        .workdir(t.workspace())
        .dry_run_json()
        .exec(Argv::new("/bin/true"))
        .assert_success("--dry-run --json exits 0");
    let report: Value = serde_json::from_str(&completed.stdout()).expect("one JSON document");
    assert_eq!(
        report["network"],
        serde_json::json!({"mode": "blocked"}),
        "the launch keeps the manifest's block: {report}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn reports_proc_self_as_the_launch_widens_it() {
    let t = nono_test!("dry-run-json-proc");
    let report = report(
        &t,
        r#"{"meta":{"name":"t"},"filesystem":{"read":["/proc/self"]}}"#,
        |run| run,
    );
    assert!(
        fs_entry(&report, "/proc").is_some(),
        "a read grant of /proc/self is /proc in the child: {report}"
    );
}

#[test]
fn json_requires_dry_run() {
    // (--json alone, without --dry-run, is refused by the argument parser.)
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nono"))
        .args(["run", "--json", "--", "/bin/true"])
        .output()
        .expect("run nono");
    assert!(!out.status.success(), "--json without --dry-run is refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--dry-run"));
    // Nor with --detached, whose launch discards stdout.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nono"))
        .args([
            "run",
            "--dry-run",
            "--json",
            "--detached",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run nono");
    assert!(!out.status.success(), "--json with --detached is refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--detached"));
}

/// The report is the run's own capability set: the same profile (a glob, a
/// variable, a symlink, a brokered command) reported by the dry run and run for
/// real, where the sandboxed process reads the capability state nono writes
/// for it (`$NONO_CAP_FILE`, the set the run applies) and runs the brokered
/// command on a path its sandbox reaches through a symlink.
#[cfg(target_os = "linux")]
#[test]
fn the_report_is_the_capability_set_the_run_applies() {
    let t = nono_test!("dry-run-json-equals-run");
    let ws = t.workspace().to_path_buf();
    for dir in ["logs-a", "logs-b", "target", "data"] {
        fs::create_dir_all(ws.join(dir)).expect("create dir");
    }
    symlink(ws.join("target"), ws.join("link")).expect("symlink");
    symlink(ws.join("data"), ws.join("data-link")).expect("symlink");
    fs::write(ws.join("data").join("secret"), "secret-7096\n").expect("write secret");
    fs::create_dir_all(t.home().join("docs")).expect("create docs");
    let json = format!(
        r#"{{
          "meta": {{"name": "t"}},
          "workdir": {{"access": "readwrite"}},
          "filesystem": {{"read": ["{ws}/logs-*", "$HOME/docs", "{ws}/link"]}},
          "command_policies": {{
            "commands": {{
              "probe": {{
                "executable": "/bin/cat",
                "from": {{"session": {{"sandbox": {{"fs_read": ["{ws}/data-link", "$HOME/docs"]}}}}}}
              }}
            }}
          }}
        }}"#,
        ws = ws.display()
    );
    let report = report(&t, &json, |run| run.allow_cwd());
    let profile = t.write_profile("dry-run-json", &json);
    let completed = t
        .run()
        .profile(&profile)
        .workdir(t.workspace())
        .allow_cwd()
        .exec(Argv::new("/bin/sh").arg("-c").arg(format!(
            // (The shell reads the state itself: cat is the brokered binary,
            // which the session may run only through its shim.)
            "while IFS= read -r l || [ -n \"$l\" ]; do printf '%s\\n' \"$l\"; done < \"$NONO_CAP_FILE\"; echo ---; probe {}/data-link/secret",
            ws.display()
        )))
        .assert_success("the run applies the profile");
    let stdout = completed.stdout();
    let (state, probed) = stdout
        .split_once("\n---\n")
        .unwrap_or_else(|| panic!("the state, then the probe: {stdout}"));
    let state: Value = serde_json::from_str(state.trim()).unwrap_or_else(|e| {
        panic!(
            "the capability state is JSON ({e}): {state}\nstderr: {}",
            completed.stderr()
        )
    });
    // (Path and access; /proc aside, which the exec widens after the state is
    // written, as the report shows it.)
    let set = |entries: &Value| {
        let mut set: Vec<(String, String)> = entries
            .as_array()
            .expect("an array")
            .iter()
            .map(|e| {
                (
                    e["path"].as_str().expect("a path").to_string(),
                    e["access"].as_str().expect("an access").to_string(),
                )
            })
            .filter(|(path, _)| !path.starts_with("/proc"))
            .collect();
        set.sort();
        set.dedup();
        set
    };
    assert_eq!(
        set(&report["filesystem"]),
        set(&state["fs"]),
        "the report's filesystem is the set the run applies"
    );
    for dir in ["logs-a", "logs-b", "target"] {
        assert!(
            fs_entry(&report, &canon(&ws.join(dir))).is_some(),
            "{dir}: {report}"
        );
    }
    // The brokered command reads through its symlinked grant, which the
    // report lists where it leads.
    assert!(
        probed.contains("secret-7096"),
        "the brokered command reads what its sandbox grants: {probed}"
    );
    let probe = report["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|c| c["command"] == "probe" && c["caller"] == "session" && c["intercept"].is_null())
        .unwrap_or_else(|| panic!("probe listed: {report}"));
    assert!(
        probe["filesystem"]
            .as_array()
            .expect("filesystem")
            .iter()
            .any(|e| e["path"] == canon(&ws.join("data")).as_str() && e["access"] == "read"),
        "{probe}"
    );
    assert_eq!(probe["executable"], canon(Path::new("/bin/cat")).as_str());
}

/// Capability elevation lets the supervisor grant paths beyond the list at
/// runtime: the report says so, and a consumer fails closed.
#[cfg(target_os = "linux")]
#[test]
fn capability_elevation_makes_the_report_incomplete() {
    let t = nono_test!("dry-run-json-elevation");
    let report = report(
        &t,
        r#"{"meta":{"name":"t"},"security":{"capability_elevation":true}}"#,
        |run| run,
    );
    assert!(
        report["incomplete"]
            .as_array()
            .expect("incomplete")
            .iter()
            .any(|i| i
                .as_str()
                .is_some_and(|i| i.starts_with("capability elevation"))),
        "{report}"
    );
    assert!(
        report["out_of_scope"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "what the report does not cover is named: {report}"
    );
}

/// A credential the launch cannot resolve stops the run; the dry run stops
/// with it rather than report a run that never starts.
#[test]
fn a_credential_the_launch_cannot_resolve_fails_the_dry_run_as_the_run() {
    let t = nono_test!("dry-run-json-credential");
    let profile = t.write_profile(
        "dry-run-json",
        r#"{"meta":{"name":"t"},"command_policies":{"credentials":{"tok":{"type":"raw-file","path":"/nonexistent-7096/token"}},"commands":{"probe":{"executable":"/bin/true","sandbox":{"use_credentials":["tok"]}}}}}"#,
    );
    t.run()
        .profile(&profile)
        .workdir(t.workspace())
        .allow_cwd()
        .dry_run_json()
        .exec(Argv::new("/bin/true"))
        .assert_failure("an unresolvable credential stops the dry run, as it stops the run");
}

/// A brokered command whose sandbox goes through a proxy of its own is built
/// as a run builds it: the dry run models the scoped proxy the run would
/// start (its network is out of the report's contract).
#[test]
fn a_command_with_a_proxy_of_its_own_is_reported() {
    let t = nono_test!("dry-run-json-scoped-proxy");
    let report = report(
        &t,
        r#"{"meta":{"name":"t"},"network":{"allow_domain":["example.com"]},"command_policies":{"commands":{"probe":{"executable":"/bin/true","sandbox":{"network":{"allow_domain":["example.org"]}}}}}}"#,
        |run| run.allow_cwd(),
    );
    let probe = report["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|c| c["command"] == "probe" && c["intercept"].is_null())
        .unwrap_or_else(|| panic!("probe listed: {report}"));
    assert_eq!(probe["incomplete"], serde_json::json!([]), "{probe}");
    assert_eq!(probe["executable"], canon(Path::new("/bin/true")).as_str());
}
