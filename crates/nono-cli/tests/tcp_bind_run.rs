//! Runtime enforcement tests for the address a sandboxed TCP `bind(2)` may use.
//!
//! An open port (`network.open_port`, `open_port_range`) is localhost IPC: in
//! proxy mode its connect reaches only loopback, and so does its bind. A
//! listen port (`network.listen_port`) is a server port and binds any address.
//!
//! `network.ephemeral_port_range` serves a loopback bind to port 0 from a
//! granted range rather than the host's ephemeral ports.
//!
//! Linux only: both live in the proxy-mode seccomp supervisor. Seatbelt has
//! no loopback-only bind filter (its `localhost` covers every address the
//! machine owns) and cannot redirect a bind, so macOS has neither.

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

/// Whether this host can open IPv6 TCP sockets on loopback (it can't when
/// booted with `ipv6.disable=1`).
fn host_has_ipv6() -> bool {
    TcpListener::bind("[::1]:0").is_ok()
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
    let ipv6 = host_has_ipv6();
    let mut attempts = vec![
        ("AF_INET", "127.0.0.1", open),
        ("AF_INET", "0.0.0.0", open),
        ("AF_INET", "127.0.0.1", range_start),
        ("AF_INET", "0.0.0.0", range_start),
    ];
    if ipv6 {
        attempts.push(("AF_INET6", "::", open));
    }
    let script = bind_script(&attempts);

    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(&script))
        .assert_success("the bind probe runs")
        .assert_stdout_contains(&format!("127.0.0.1 {open} OK"))
        .assert_stdout_contains(&format!("0.0.0.0 {open} EACCES"))
        .assert_stdout_contains(&format!("127.0.0.1 {range_start} OK"))
        .assert_stdout_contains(&format!("0.0.0.0 {range_start} EACCES"));
    if ipv6 {
        drop(completed.assert_stdout_contains(&format!(":: {open} EACCES")));
    }
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

/// The start of a block of `len` unprivileged loopback ports outside the
/// host's ephemeral range that are free right now, or `None` when the host
/// leaves no such block.
fn free_block_outside_host_ephemeral(len: u16) -> Option<u16> {
    let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .expect("read the host's ephemeral port range");
    let mut bounds = raw.split_whitespace().filter_map(|s| s.parse::<u32>().ok());
    let (host_start, host_end) = (bounds.next()?, bounds.next()?);
    let len = u32::from(len);
    let candidates = (1024..host_start.saturating_sub(len))
        .chain(host_end + 1..65536u32.saturating_sub(len))
        .step_by(97);
    for start in candidates {
        let all_free =
            (start..start + len).all(|port| TcpListener::bind(("127.0.0.1", port as u16)).is_ok());
        if all_free {
            return Some(start as u16);
        }
    }
    None
}

/// Python that binds loopback port 0 the way a test server does, connects to
/// it, closes it and binds the same port again (Capybara's port probe), then
/// tries a port-0 bind off loopback and a connect to a host listener on one
/// of the host's own ephemeral ports. Last, a worker thread binds port 0,
/// as a browser's I/O thread does for its DevTools port.
fn ephemeral_script(host_port: u16) -> String {
    format!(
        "import errno, socket\n\
         def err(e): return errno.errorcode.get(e.errno, e.errno)\n\
         s = socket.socket()\n\
         try:\n\
         \x20   s.bind(('127.0.0.1', 0)); s.listen(); port = s.getsockname()[1]\n\
         \x20   print('bound', port)\n\
         except OSError as e:\n\
         \x20   print('bind0', err(e)); raise SystemExit(0)\n\
         c = socket.socket(); c.connect(('127.0.0.1', port)); print('connect-own OK'); c.close()\n\
         s.close()\n\
         r = socket.socket(); r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         r.bind(('127.0.0.1', port)); r.listen(); print('rebind OK'); r.close()\n\
         x = socket.socket()\n\
         try:\n\
         \x20   x.bind(('0.0.0.0', 0)); print('any0 OK')\n\
         except OSError as e:\n\
         \x20   print('any0', err(e))\n\
         y = socket.socket()\n\
         try:\n\
         \x20   y.connect(('127.0.0.1', {host_port})); print('host OK')\n\
         except OSError as e:\n\
         \x20   print('host', err(e))\n\
         import threading\n\
         out = []\n\
         def worker():\n\
         \x20   w = socket.socket()\n\
         \x20   try:\n\
         \x20       w.bind(('127.0.0.1', 0)); out.append('thread-bound %d' % w.getsockname()[1])\n\
         \x20   except OSError as e:\n\
         \x20       out.append('thread-bind0 %s' % err(e))\n\
         th = threading.Thread(target=worker); th.start(); th.join(); print(out[0])\n"
    )
}

#[test]
fn proxy_mode_port_zero_bind_uses_ephemeral_port_range() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let Some(start) = free_block_outside_host_ephemeral(10) else {
        eprintln!("skipping: no free port block outside the host's ephemeral range");
        return;
    };
    let end = start + 9;
    // A host process's own port-0 listener, on the host's ephemeral range.
    let host_listener = TcpListener::bind("127.0.0.1:0").expect("bind a host listener");
    let host_port = host_listener.local_addr().expect("host addr").port();

    let t = nono_test!("tcp-bind-ephemeral");
    let profile = t.write_profile(
        "tcp-bind-ephemeral",
        &format!(
            r#"{{"meta":{{"name":"tcp-bind-ephemeral"}},"workdir":{{"access":"readwrite"}},"network":{{"allow_domain":["example.com"],"ephemeral_port_range":[{start},{end}]}}}}"#
        ),
    );
    let completed = t
        .run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(ephemeral_script(host_port)))
        .assert_success("the ephemeral probe runs")
        .assert_stdout_contains("connect-own OK")
        .assert_stdout_contains("rebind OK")
        .assert_stdout_contains("any0 EACCES")
        .assert_stdout_contains("host EACCES");
    let bound: u16 = completed
        .stdout()
        .lines()
        .find_map(|line| line.strip_prefix("bound "))
        .and_then(|port| port.trim().parse().ok())
        .expect("the probe prints the bound port");
    assert!(
        (start..=end).contains(&bound),
        "port-0 bind got {bound}, outside the ephemeral range {start}..={end}"
    );
    let thread_bound: u16 = completed
        .stdout()
        .lines()
        .find_map(|line| line.strip_prefix("thread-bound "))
        .and_then(|port| port.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "a worker thread's port-0 bind is served too\n{}",
                completed.stdout()
            )
        });
    assert!(
        (start..=end).contains(&thread_bound),
        "worker-thread port-0 bind got {thread_bound}, outside {start}..={end}"
    );
    drop(host_listener);
}

#[test]
fn proxy_mode_port_zero_bind_without_range_is_denied() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 available");
        return;
    };
    let t = nono_test!("tcp-bind-no-ephemeral");
    let profile = t.write_profile(
        "tcp-bind-no-ephemeral",
        r#"{"meta":{"name":"tcp-bind-no-ephemeral"},"workdir":{"access":"readwrite"},"network":{"allow_domain":["example.com"]}}"#,
    );
    t.run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(ephemeral_script(1)))
        .assert_success("the ephemeral probe runs")
        .assert_stdout_contains("bind0 EACCES");
}
