//! A closed stdout ends `nono` by SIGPIPE, quietly, instead of a panic.
//!
//! `nono why … | head -n 1` closes the pipe after one line. Before
//! `broken_pipe::install`, the next `println!` panicked with "failed printing
//! to stdout: Broken pipe", and under the release profile's `panic = "abort"`
//! that aborted with SIGABRT and dumped core. This test runs the built binary,
//! so it also pins the std panic message the hook recognises.
//!
//! The reader is closed before nono starts, so nono's first write fails and
//! the outcome does not depend on timing. `head -n 1` is the same failure,
//! reached only when nono writes after `head` has exited.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const SIGPIPE: i32 = 13;

fn why(t: &nono_test_support::NonoTest) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nono"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("NONO_") || name.starts_with("XDG_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("HOME", t.home())
        .env("XDG_CONFIG_HOME", t.home().join(".config"))
        .env("XDG_STATE_HOME", t.state())
        .env("NONO_NO_UPDATE_CHECK", "1")
        .current_dir(t.workspace())
        .args(["why", "--op", "read", "--path"])
        .arg(t.home().join(".ssh"));
    cmd
}

#[test]
fn closed_stdout_ends_by_sigpipe_without_panic() {
    let t = nono_test_support::nono_test!("broken-pipe");

    // With a reader, the command prints and succeeds, so the closed case
    // below fails on a real write rather than on something else.
    let open = why(&t).output().expect("run nono why");
    assert!(
        open.status.success() && !open.stdout.is_empty(),
        "nono why must print and succeed with an open stdout: {open:?}"
    );

    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let output = why(&t)
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("run nono why");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("panicked") && !stderr.contains("failed printing"),
        "nono panicked on a closed stdout:\n{stderr}"
    );
    assert_eq!(
        output.status.signal(),
        Some(SIGPIPE),
        "nono must end by SIGPIPE on a closed stdout, as a C tool does: {:?}\n{stderr}",
        output.status
    );
    assert!(
        !output.status.core_dumped(),
        "SIGPIPE's default action dumps no core"
    );
}
