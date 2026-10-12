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
                  "session": {{"sandbox": {{"fs_read": ["{ws}/data-link", ".", "{ws}/not-yet"], "exec_paths": ["{ws}/helpers"], "use_credentials": ["tok"]}}}},
                  "caller": {{"sandbox": {{"fs_read": ["{ws}/from-caller"]}}}},
                  "stranger": {{"sandbox": {{"fs_read": ["{ws}/other"]}}}}
                }},
                "intercept": [{{"args": ["x"], "sandbox": {{"fs_read": ["{ws}/intercepted"]}}}}]
              }},
              "caller": {{
                "executable": "/bin/echo",
                "can_use": ["probe"],
                "sandbox": {{"fs_write": ["{ws}/other"]}}
              }},
              "denied": {{
                "executable": "/bin/echo",
                "from": {{"session": "deny"}}
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
    assert_eq!(
        probe["exec_paths"],
        serde_json::json!([ws.join("helpers").to_str().expect("utf-8")])
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        probe["exec_paths"],
        serde_json::json!([]),
        "macOS launches use no exec_paths"
    );
    assert_eq!(probe["cwd_dependent"], serde_json::json!(["."]));
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
    let from_caller = find("probe", "caller")
        .unwrap_or_else(|| panic!("an admitted caller's edge is listed: {report}"));
    assert!(
        has_path(from_caller, &ws.join("from-caller")),
        "{from_caller}"
    );
    assert!(
        find("probe", "stranger").is_none(),
        "an edge from a caller that is no command listing probe in can_use never runs, and is not listed: {report}"
    );
    assert!(
        !commands.iter().any(|c| c["command"] == "denied"),
        "an explicit session deny, with no admitted caller, runs nothing and is not listed: {report}"
    );
    let intercept = commands
        .iter()
        .find(|c| c["command"] == "probe" && c["intercept"] == 0)
        .unwrap_or_else(|| panic!("the intercept rule's sandbox listed: {report}"));
    assert!(intercept["caller"].is_null());
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
    assert_eq!(
        proxied["network"],
        serde_json::json!({"mode": "proxy", "blocked": true})
    );
    let blocked = report(&t, r#"{"meta":{"name":"t"}}"#, |run| run.block_net());
    assert_eq!(
        blocked["network"],
        serde_json::json!({"mode": "blocked", "blocked": true})
    );
    let open = report(&t, r#"{"meta":{"name":"t"}}"#, |run| run);
    assert_eq!(
        open["network"],
        serde_json::json!({"mode": "allowed", "blocked": false})
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
