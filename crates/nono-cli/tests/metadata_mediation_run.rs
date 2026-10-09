//! Runtime enforcement tests for `linux.metadata_mediation = "write_grants"`.
//!
//! Landlock does not mediate the chmod and utime syscall families. With
//! metadata mediation on, the supervisor emulates each such call and allows it
//! only where Landlock would allow a write. Every case is exercised against a
//! write-granted file, a read-granted file and an ungranted file, by path and
//! by descriptor (including `O_PATH`), through symlinks, from a non-leader
//! thread, and with the listener shared with AF_UNIX mediation.
#![cfg(target_os = "linux")]

use nono_test_support::{Argv, NonoTest, nono_test};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

/// 2000-01-01T00:00:00Z, the timestamp every probe tries to set.
const PROBE_EPOCH: i64 = 946_684_800;

/// Runs each metadata syscall the kernel offers on this architecture against
/// each target named on the command line, and prints `<op> <target> <result>`
/// with `ok` or the errno name. Raw syscalls, so libc cannot pick another one.
const PROBE: &str = r#"
import ctypes, errno, fcntl, os, platform, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
AT_FDCWD, NOFOLLOW, EMPTY = -100, 0x100, 0x1000
NR = {
    "x86_64": dict(chmod=90, fchmod=91, utime=132, utimes=235, futimesat=261,
                   fchmodat=268, utimensat=280, fchmodat2=452),
    "aarch64": dict(fchmod=52, fchmodat=53, utimensat=88, fchmodat2=452),
}[platform.machine()]
T = 946684800
ts = (ctypes.c_long * 4)(T, 0, T, 0)
tv = (ctypes.c_long * 4)(T, 0, T, 0)
ub = (ctypes.c_long * 2)(T, T)

def sc(name, *args):
    if name not in NR:
        return None
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(NR[name]), *args)
    return "ok" if r == 0 else errno.errorcode[ctypes.get_errno()]

def with_fd(path, flags, fn):
    try:
        fd = os.open(path, flags)
    except OSError as e:
        return "open:" + errno.errorcode[e.errno]
    try:
        return fn(fd)
    finally:
        os.close(fd)

def ops(p):
    b = p.encode()
    yield "fchmodat", sc("fchmodat", AT_FDCWD, b, 0o600)
    yield "fchmodat2", sc("fchmodat2", AT_FDCWD, b, 0o600, 0)
    yield "chmod", sc("chmod", b, 0o600)
    yield "fchmod_rdonly", with_fd(p, os.O_RDONLY, lambda fd: sc("fchmod", fd, 0o600))
    yield "fchmod_wronly", with_fd(p, os.O_WRONLY, lambda fd: sc("fchmod", fd, 0o600))
    yield "fchmodat2_opath_empty", with_fd(p, os.O_PATH, lambda fd: sc("fchmodat2", fd, b"", 0o600, EMPTY))
    yield "chmod_proc_self_fd_opath", with_fd(p, os.O_PATH, lambda fd: sc("fchmodat", AT_FDCWD, b"/proc/self/fd/%d" % fd, 0o600))
    yield "utimensat", sc("utimensat", AT_FDCWD, b, ts, 0)
    yield "utimensat_now", sc("utimensat", AT_FDCWD, b, None, 0)
    yield "utimes", sc("utimes", b, tv)
    yield "utime", sc("utime", b, ub)
    yield "futimesat", sc("futimesat", AT_FDCWD, b, tv)
    yield "futimens_rdonly", with_fd(p, os.O_RDONLY, lambda fd: sc("utimensat", fd, None, ts, 0))
    yield "utimensat_opath_empty", with_fd(p, os.O_PATH, lambda fd: sc("utimensat", fd, b"", ts, EMPTY))

def flock_ops(p):
    yield "flock_sh", with_fd(p, os.O_RDONLY, lambda fd: fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB) or "ok")
    yield "flock_ex", with_fd(p, os.O_RDONLY, lambda fd: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB) or "ok")
    def opath(fd):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return "ok"
        except OSError as e:
            return errno.errorcode[e.errno]
    yield "flock_opath", with_fd(p, os.O_PATH, opath)

def report(label, results):
    for op, result in results:
        if result is not None:
            print(op, label, result, flush=True)

mode, *targets = sys.argv[1:]
for target in targets:
    label, path = target.split("=", 1)
    if mode == "ops":
        report(label, ops(path))
    elif mode == "thread":
        out = []
        t = threading.Thread(target=lambda: out.extend(ops(path)))
        t.start(); t.join()
        report(label, out)
    elif mode == "flock":
        report(label, flock_ops(path))
    elif mode == "dirfd":
        dirname, name = os.path.split(path)
        report(label, [("fchmodat_dirfd", with_fd(dirname, os.O_PATH | os.O_DIRECTORY,
            lambda fd: sc("fchmodat", fd, name.encode(), 0o600)))])
    elif mode == "nofollow":
        b = path.encode()
        report(label, [
            ("fchmodat2_nofollow", sc("fchmodat2", AT_FDCWD, b, 0o600, NOFOLLOW)),
            ("utimensat_nofollow", sc("utimensat", AT_FDCWD, b, ts, NOFOLLOW)),
        ])
    elif mode == "write":
        report(label, [("open_wronly", with_fd(path, os.O_WRONLY, lambda fd: "ok"))])
"#;

fn python3_bin() -> Option<String> {
    ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"]
        .into_iter()
        .find(|cand| {
            Command::new(cand)
                .args(["-c", "import ctypes, fcntl"])
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .map(str::to_string)
}

/// `own/` is write-granted, `ro/` read-granted, `none/` ungranted; each holds
/// a file `f`. `own/` also holds symlinks into each, and a symlinked
/// directory into `none/`.
struct Fixture {
    t: NonoTest,
    root: PathBuf,
}

impl Fixture {
    fn new(prefix: &str) -> Self {
        let t = nono_test!(prefix);
        let root = fs::canonicalize(t.root())
            .expect("tempdir exists")
            .join("tree");
        for dir in ["own", "ro", "none"] {
            fs::create_dir_all(root.join(dir)).expect("fresh tempdir");
            let file = root.join(dir).join("f");
            fs::write(&file, "x").expect("fresh tempdir");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("own file");
        }
        symlink("f", root.join("own/link-own")).expect("fresh tempdir");
        symlink("../ro/f", root.join("own/link-ro")).expect("fresh tempdir");
        symlink("../none/f", root.join("own/link-none")).expect("fresh tempdir");
        symlink("../none", root.join("own/dir-none")).expect("fresh tempdir");
        Self { t, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn profile(&self, linux: &str) -> nono_test_support::Profile {
        let own = self.path("own");
        let ro = self.path("ro");
        self.t.write_profile(
            "metadata",
            &format!(
                r#"{{"meta":{{"name":"metadata"}},"workdir":{{"access":"readwrite"}},"linux":{linux},"filesystem":{{"allow":["{}"],"read":["{}"]}}}}"#,
                own.display(),
                ro.display()
            ),
        )
    }

    /// Run the probe in `mode` over `targets` (`label=relative path`) and
    /// return `(op, label) -> result`.
    fn probe(
        &self,
        py: &str,
        linux: &str,
        mode: &str,
        targets: &[(&str, &str)],
    ) -> BTreeMap<(String, String), String> {
        let profile = self.profile(linux);
        let mut argv = Argv::new(py).arg("-c").arg(PROBE).arg(mode);
        for (label, rel) in targets {
            argv = argv.arg(format!("{label}={}", self.path(rel).display()));
        }
        let completed = self
            .t
            .run()
            .profile(&profile)
            .exec(argv)
            .assert_success("the probe reports results; it does not fail");
        completed
            .stdout()
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                match (fields.next(), fields.next(), fields.next()) {
                    (Some(op), Some(label), Some(result)) => {
                        Some(((op.to_string(), label.to_string()), result.to_string()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// The ungranted file must be unwritable in the sandbox, or every
    /// "denied" assertion below would be judging a granted file. This fails
    /// when the test tree sits under a default write grant such as `$TMPDIR`.
    fn assert_ungranted_is_unwritable(&self, py: &str) {
        let results = self.probe(py, MEDIATED, "write", &[("none", "none/f")]);
        assert_eq!(
            results
                .get(&("open_wronly".into(), "none".into()))
                .map(String::as_str),
            Some("open:EACCES"),
            "{} must lie outside every default write grant (is $TMPDIR above it?)",
            self.path("none/f").display()
        );
    }

    fn assert_untouched(&self, rel: &str) {
        let meta = fs::metadata(self.path(rel)).expect("fixture file");
        assert_eq!(meta.mode() & 0o7777, 0o644, "{rel}: mode changed");
        assert_ne!(meta.mtime(), PROBE_EPOCH, "{rel}: mtime changed");
        assert_ne!(meta.atime(), PROBE_EPOCH, "{rel}: atime changed");
    }
}

const MEDIATED: &str = r#"{"metadata_mediation":"write_grants"}"#;
const MEDIATED_WITH_AF_UNIX: &str =
    r#"{"metadata_mediation":"write_grants","af_unix_mediation":"pathname"}"#;

/// A label, the test its every result must pass, and what that test means.
type Expectation<'a> = (&'a str, fn(&str) -> bool, &'a str);

/// Every op on every label must have the expected result, and the probe must
/// have reported at least one op per label. Reports every mismatch at once.
fn assert_results(results: &BTreeMap<(String, String), String>, expect: &[Expectation<'_>]) {
    let mut mismatches = Vec::new();
    for (label, accept, what) in expect {
        let seen: Vec<_> = results.iter().filter(|((_, l), _)| l == label).collect();
        if seen.is_empty() {
            mismatches.push(format!("{label}: no results"));
        }
        for ((op, _), result) in seen {
            if !accept(result) {
                mismatches.push(format!("{op} on {label}: expected {what}, got {result}"));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

fn ok(result: &str) -> bool {
    result == "ok"
}

/// Denied by mediation, or never reachable because Landlock refused the open.
fn denied(result: &str) -> bool {
    result == "EACCES" || result == "open:EACCES"
}

fn run_mode_and_time_matrix(prefix: &str, linux: &str, mode: &str) {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 with ctypes");
        return;
    };
    let f = Fixture::new(prefix);
    f.assert_ungranted_is_unwritable(&py);
    let results = f.probe(
        &py,
        linux,
        mode,
        &[
            ("own", "own/f"),
            ("ro", "ro/f"),
            ("none", "none/f"),
            ("link-own", "own/link-own"),
            ("link-ro", "own/link-ro"),
            ("link-none", "own/link-none"),
            ("dir-none", "own/dir-none/f"),
        ],
    );
    assert_results(
        &results,
        &[
            ("own", ok, "ok"),
            ("link-own", ok, "ok"),
            ("ro", denied, "EACCES"),
            ("none", denied, "EACCES"),
            ("link-ro", denied, "EACCES"),
            ("link-none", denied, "EACCES"),
            ("dir-none", denied, "EACCES"),
        ],
    );
    f.assert_untouched("ro/f");
    f.assert_untouched("none/f");
    let own = fs::metadata(f.path("own/f")).expect("fixture file");
    assert_eq!(own.mode() & 0o7777, 0o600);
}

#[test]
fn metadata_mediation_confines_mode_and_time_changes_to_write_grants() {
    run_mode_and_time_matrix("metadata-matrix", MEDIATED, "ops");
}

#[test]
fn metadata_mediation_applies_to_every_thread() {
    run_mode_and_time_matrix("metadata-thread", MEDIATED, "thread");
}

#[test]
fn metadata_mediation_shares_the_listener_with_af_unix_mediation() {
    run_mode_and_time_matrix("metadata-af-unix", MEDIATED_WITH_AF_UNIX, "ops");
}

#[test]
fn metadata_mediation_resolves_relative_names_from_the_dirfd() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 with ctypes");
        return;
    };
    let f = Fixture::new("metadata-dirfd");
    let results = f.probe(
        &py,
        MEDIATED,
        "dirfd",
        &[("own", "own/f"), ("ro", "ro/f"), ("none", "none/f")],
    );
    assert_results(
        &results,
        &[
            ("own", ok, "ok"),
            ("ro", denied, "EACCES"),
            ("none", denied, "EACCES"),
        ],
    );
    f.assert_untouched("none/f");
}

#[test]
fn metadata_mediation_judges_a_symlink_itself_when_not_following() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 with ctypes");
        return;
    };
    let f = Fixture::new("metadata-nofollow");
    let results = f.probe(&py, MEDIATED, "nofollow", &[("link-none", "own/link-none")]);
    // The link lives in a write grant, so its own times may change; its mode
    // cannot change on Linux at all, and the target must not change instead.
    let get = |op: &str| {
        results
            .get(&(op.to_string(), "link-none".to_string()))
            .cloned()
    };
    assert_eq!(get("utimensat_nofollow").as_deref(), Some("ok"));
    if let Some(result) = get("fchmodat2_nofollow") {
        assert!(
            // Python names errno 95 ENOTSUP; Linux aliases it to EOPNOTSUPP.
            matches!(result.as_str(), "EOPNOTSUPP" | "ENOTSUP" | "ENOSYS"),
            "fchmodat2 nofollow on a symlink: {result}"
        );
    }
    f.assert_untouched("none/f");
    let link = fs::symlink_metadata(f.path("own/link-none")).expect("fixture link");
    assert_eq!(link.mtime(), PROBE_EPOCH);
}

/// `flock` is deliberately not mediated: locking needs an open descriptor,
/// which Landlock grants only with read access, and `O_PATH` descriptors
/// cannot be locked. Read-only files stay lockable, shared or exclusive.
#[test]
fn flock_needs_read_access_and_nothing_more() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no system python3 with ctypes");
        return;
    };
    let f = Fixture::new("metadata-flock");
    let results = f.probe(
        &py,
        MEDIATED,
        "flock",
        &[("own", "own/f"), ("ro", "ro/f"), ("none", "none/f")],
    );
    let get = |op: &str, label: &str| {
        results
            .get(&(op.to_string(), label.to_string()))
            .cloned()
            .unwrap_or_default()
    };
    for label in ["own", "ro"] {
        assert_eq!(get("flock_sh", label), "ok", "{label}");
        assert_eq!(get("flock_ex", label), "ok", "{label}");
    }
    assert_eq!(get("flock_sh", "none"), "open:EACCES");
    assert_eq!(get("flock_ex", "none"), "open:EACCES");
    for label in ["own", "ro", "none"] {
        assert_eq!(get("flock_opath", label), "EBADF", "{label}");
    }
}

#[test]
fn profile_show_reports_metadata_mediation() {
    let t = nono_test!("metadata-show");
    t.write_profile(
        "metadata-show",
        r#"{"meta":{"name":"metadata-show"},"linux":{"metadata_mediation":"write_grants"}}"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_nono"))
        .args(["profile", "show", "--json"])
        .arg(profile_path(&t, "metadata-show"))
        .env("HOME", t.home())
        .env("XDG_CONFIG_HOME", t.home().join(".config"))
        .env("XDG_STATE_HOME", t.state())
        .env("NONO_NO_UPDATE_CHECK", "1")
        .output()
        .expect("nono runs");
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("profile show --json prints JSON");
    assert_eq!(
        json.pointer("/linux/metadata_mediation"),
        Some(&serde_json::json!("write_grants")),
        "{json}"
    );
}

fn profile_path(t: &NonoTest, name: &str) -> PathBuf {
    Path::new(t.home()).join(format!("{name}.json"))
}
