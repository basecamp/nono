//! Runtime enforcement tests for the address a sandboxed TCP `bind(2)` may use.
//!
//! An open port (`network.open_port`, `open_port_range`) is localhost IPC: in
//! proxy mode its connect reaches only loopback, and so does its bind. A
//! listen port (`network.listen_port`) is a server port and binds any address.
//!
//! Linux only: the address check lives in the proxy-mode seccomp supervisor.
//! macOS gets the same rule from its generated Seatbelt profile, which the
//! `sandbox::macos` unit tests cover.

#![cfg(target_os = "linux")]

use nono_test_support::{Argv, nono_test};
use std::net::TcpListener;
use std::process::Command;

/// Absolute path to a system `python3` under a default-allowed bin dir.
fn python3_bin() -> Option<String> {
    ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"]
        .into_iter()
        .find(|cand| {
            Command::new(cand)
                .args(["-c", "import socket"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(str::to_string)
}

/// A TCP port that is free on the host right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("bind an ephemeral host port")
}

/// Python that binds each `(family, address, port)` in turn and prints one
/// line per attempt: `<address> <port> OK` or `<address> <port> <errno name>`.
fn bind_script(attempts: &[(&str, &str, u16)]) -> String {
    let mut script = String::from(
        "import errno, socket\n\
         def t(fam, addr, port):\n\
         \x20   s = socket.socket(fam, socket.SOCK_STREAM)\n\
         \x20   s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         \x20   try:\n\
         \x20       s.bind((addr, port)); s.listen(); print(addr, port, 'OK')\n\
         \x20   except OSError as e:\n\
         \x20       print(addr, port, errno.errorcode.get(e.errno, e.errno))\n\
         \x20   finally:\n\
         \x20       s.close()\n",
    );
    for (family, addr, port) in attempts {
        script.push_str(&format!("t(socket.{family}, {addr:?}, {port})\n"));
    }
    script
}

#[test]
fn proxy_mode_open_port_binds_loopback_only() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let (open, range_start) = (free_port(), free_port());
    let t = nono_test!("tcp-bind-open-port");
    let profile = t.write_profile(
        "tcp-bind-open-port",
        &format!(
            r#"{{"meta":{{"name":"tcp-bind-open-port"}},"workdir":{{"access":"readwrite"}},"network":{{"allow_domain":["example.com"],"open_port":[{open}],"open_port_range":[[{range_start},{range_start}]]}}}}"#
        ),
    );
    let script = bind_script(&[
        ("AF_INET", "127.0.0.1", open),
        ("AF_INET", "0.0.0.0", open),
        ("AF_INET6", "::", open),
        ("AF_INET", "127.0.0.1", range_start),
        ("AF_INET", "0.0.0.0", range_start),
    ]);

    t.run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(&script))
        .assert_success("the bind probe runs")
        .assert_stdout_contains(&format!("127.0.0.1 {open} OK"))
        .assert_stdout_contains(&format!("0.0.0.0 {open} EACCES"))
        .assert_stdout_contains(&format!(":: {open} EACCES"))
        .assert_stdout_contains(&format!("127.0.0.1 {range_start} OK"))
        .assert_stdout_contains(&format!("0.0.0.0 {range_start} EACCES"));
}

#[test]
fn proxy_mode_listen_port_binds_any_address() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let listen = free_port();
    let t = nono_test!("tcp-bind-listen-port");
    let profile = t.write_profile(
        "tcp-bind-listen-port",
        &format!(
            r#"{{"meta":{{"name":"tcp-bind-listen-port"}},"workdir":{{"access":"readwrite"}},"network":{{"allow_domain":["example.com"],"listen_port":[{listen}]}}}}"#
        ),
    );
    let script = bind_script(&[("AF_INET", "0.0.0.0", listen)]);

    t.run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(&script))
        .assert_success("the bind probe runs")
        .assert_stdout_contains(&format!("0.0.0.0 {listen} OK"));
}
