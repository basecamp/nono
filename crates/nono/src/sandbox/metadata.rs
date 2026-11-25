//! Supervisor-side emulation of file mode and timestamp changes (Linux).
//!
//! Landlock does not mediate `chmod(2)`, `fchmod(2)`, `fchmodat(2)`,
//! `fchmodat2(2)`, `utime(2)`, `utimes(2)`, `futimesat(2)` or `utimensat(2)`,
//! so a sandboxed process can change the mode bits and timestamps of any file
//! it can name, including files it has no grant to read.
//!
//! [`PreparedSeccompNotifyFilter::with_metadata_notifications`] traps these
//! calls. For each one the supervisor:
//!
//! 1. reads the arguments and resolves the target to a descriptor of its own,
//!    following the kernel's rules for that call (`dirfd`, `AT_EMPTY_PATH`,
//!    `AT_SYMLINK_NOFOLLOW`, `NULL` pathnames): [`read_metadata_request`];
//! 2. decides on that inode (the policy lives with the caller);
//! 3. applies the change to the same descriptor, [`MetadataRequest::apply`],
//!    and completes the notification with the result.
//!
//! The child's own syscall never runs. Nothing the child changes after the
//! notification (the pathname bytes, a symlink, which file a descriptor number
//! refers to) can redirect the change to an inode the decision did not see.
//!
//! Errors carry the errno the kernel would have returned, so the child sees
//! native failures (`ENOENT`, `EBADF`, `EINVAL`, `EPERM`, ...) unchanged.
//!
//! [`PreparedSeccompNotifyFilter::with_metadata_notifications`]:
//!     super::PreparedSeccompNotifyFilter::with_metadata_notifications

use super::linux::{
    METADATA_SYSCALLS, OpenHow, SYS_FCHMOD, SYS_FCHMODAT, SYS_FCHMODAT2, SYS_UTIMENSAT,
    SeccompNotif,
};
#[cfg(target_arch = "x86_64")]
use super::linux::{SYS_CHMOD, SYS_FUTIMESAT, SYS_UTIME, SYS_UTIMES};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// `PATH_MAX`, including the terminating NUL, as `getname()` enforces it.
const PATH_MAX: usize = 4096;
/// Chunk size for reading a pathname from the child: never crosses a page.
const READ_CHUNK: usize = 4096;
/// `PIDFD_THREAD` (Linux 6.9): a pidfd for a thread rather than a process.
const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
/// Attempts at an `openat2` that reports `EAGAIN` for a concurrent rename.
const RESOLVE_ATTEMPTS: usize = 3;

/// Whether `nr` is one of the native syscalls that change mode bits or
/// timestamps (those trapped by `with_metadata_notifications`).
#[must_use]
pub fn is_metadata_syscall(nr: i32) -> bool {
    METADATA_SYSCALLS.contains(&nr)
}

/// One timestamp of a `utime`-family call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// Seconds since the epoch.
    pub seconds: i64,
    /// Nanoseconds, or `UTIME_NOW` / `UTIME_OMIT`.
    pub nanoseconds: i64,
}

/// The change a trapped call asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataChange {
    /// Set the mode bits (`chmod` family).
    Mode(libc::mode_t),
    /// Set the access and modification times (`utime` family). `None` means
    /// both are set to the current time.
    Times(Option<[Timestamp; 2]>),
}

/// The inode a trapped call targets, opened by the supervisor.
#[derive(Debug)]
pub struct MetadataTarget {
    fd: OwnedFd,
    path: Option<PathBuf>,
    via_writable_fd: bool,
    symlink: bool,
}

impl MetadataTarget {
    /// The target's absolute path, as the kernel reports it for the
    /// supervisor's descriptor, provided that path still names this very
    /// inode from the supervisor's root.
    ///
    /// `None` for an object with no filesystem path (a pipe, socket or
    /// anonymous inode), and for one whose reported path names something else
    /// or nothing: a file unlinked while open, or one reached through another
    /// mount namespace or a detached mount, where the reported path is
    /// relative to a root that is not the supervisor's.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether the child named the target through a descriptor it holds open
    /// for writing. Such a descriptor already passed Landlock's write check
    /// when it was opened, or was handed to the sandbox from outside.
    ///
    /// Only reported when the descriptor could be duplicated with
    /// `pidfd_getfd(2)`, which shares the child's open file description and
    /// so its access mode; never inferred from a separate lookup.
    #[must_use]
    pub fn via_writable_fd(&self) -> bool {
        self.via_writable_fd
    }
}

/// A trapped mode or timestamp change, resolved and ready for a decision.
#[derive(Debug)]
pub struct MetadataRequest {
    change: MetadataChange,
    target: Option<MetadataTarget>,
}

impl MetadataRequest {
    /// What the call asks to change.
    #[must_use]
    pub fn change(&self) -> MetadataChange {
        self.change
    }

    /// The inode the call targets, or `None` when the kernel would return 0
    /// without looking anything up (`utimensat` with both times
    /// `UTIME_OMIT`).
    #[must_use]
    pub fn target(&self) -> Option<&MetadataTarget> {
        self.target.as_ref()
    }

    /// Apply the change to the resolved inode, with the supervisor's
    /// credentials (the same user as the child).
    ///
    /// # Errors
    ///
    /// Returns the error the kernel reports for the change, which is the one
    /// the child's own call would have returned.
    pub fn apply(&self) -> io::Result<()> {
        let Some(target) = &self.target else {
            return Ok(());
        };
        match self.change {
            MetadataChange::Mode(mode) => {
                // As fchmodat2(AT_SYMLINK_NOFOLLOW) does since Linux 6.6. This
                // also keeps the procfs path below from following a symlink to
                // an inode nobody resolved or decided on.
                if target.symlink {
                    return Err(errno(libc::EOPNOTSUPP));
                }
                // An O_PATH descriptor cannot be fchmod()ed; its procfs link
                // names exactly the inode it holds.
                let link = CString::new(format!("/proc/self/fd/{}", target.fd.as_raw_fd()))
                    .map_err(|_| errno(libc::EINVAL))?;
                // SAFETY: `link` is a valid NUL-terminated string that outlives
                // the call.
                check(unsafe { libc::fchmodat(libc::AT_FDCWD, link.as_ptr(), mode, 0) })
            }
            MetadataChange::Times(times) => {
                let raw = times.map(|times| {
                    times.map(|t| libc::timespec {
                        tv_sec: t.seconds as libc::time_t,
                        tv_nsec: t.nanoseconds as libc::c_long,
                    })
                });
                let pointer = raw
                    .as_ref()
                    .map_or(std::ptr::null(), |times| times.as_ptr());
                // SAFETY: the descriptor is open, the empty path is a valid C
                // string, and `pointer` is null or points at two timespecs that
                // outlive the call. AT_EMPTY_PATH works on O_PATH descriptors,
                // and on a symlink's own descriptor sets the link's times.
                check(unsafe {
                    libc::utimensat(
                        target.fd.as_raw_fd(),
                        c"".as_ptr(),
                        pointer,
                        libc::AT_EMPTY_PATH,
                    )
                })
            }
        }
    }
}

/// How a trapped call names its target.
enum Name {
    /// A pathname, relative to `dirfd` unless absolute. Empty only with
    /// `AT_EMPTY_PATH`, when it names `dirfd` itself.
    Path {
        dirfd: i32,
        path: CString,
        follow: bool,
    },
    /// A descriptor. `O_PATH` descriptors fail with `EBADF` unless allowed.
    Fd { fd: i32, allow_opath: bool },
}

/// Read a trapped mode or timestamp change and resolve its target.
///
/// Reads the arguments from the notifying thread's memory and opens the
/// target from the thread's own working directory, root and descriptor table.
/// The caller must check the notification is still pending
/// (`notif_id_valid`) after this returns and before acting on it.
///
/// # Errors
///
/// Returns the errno the kernel would have returned for the call
/// (`EFAULT`, `EINVAL`, `ENOENT`, `EBADF`, `ENAMETOOLONG`, ...), or `ENOSYS`
/// for a syscall this module does not handle.
pub fn read_metadata_request(notif: &SeccompNotif) -> io::Result<MetadataRequest> {
    let child = Child { tid: notif.pid };
    let args = notif.data.args;
    let (name, change) = match notif.data.nr {
        #[cfg(target_arch = "x86_64")]
        SYS_CHMOD => (
            child.path_name(libc::AT_FDCWD, args[0], 0)?,
            MetadataChange::Mode(mode_arg(args[1])),
        ),
        SYS_FCHMOD => (
            Name::Fd {
                fd: args[0] as i32,
                allow_opath: false,
            },
            MetadataChange::Mode(mode_arg(args[1])),
        ),
        SYS_FCHMODAT => (
            child.path_name(args[0] as i32, args[1], 0)?,
            MetadataChange::Mode(mode_arg(args[2])),
        ),
        SYS_FCHMODAT2 => {
            let flags = args[3] as i32;
            if flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) != 0 {
                return Err(errno(libc::EINVAL));
            }
            (
                child.path_name(args[0] as i32, args[1], flags)?,
                MetadataChange::Mode(mode_arg(args[2])),
            )
        }
        #[cfg(target_arch = "x86_64")]
        SYS_UTIME => {
            let times = child.read_utimbuf(args[1])?;
            (
                child.path_name(libc::AT_FDCWD, args[0], 0)?,
                MetadataChange::Times(times),
            )
        }
        #[cfg(target_arch = "x86_64")]
        SYS_UTIMES => {
            let times = child.read_timevals(args[1])?;
            (
                child.path_name(libc::AT_FDCWD, args[0], 0)?,
                MetadataChange::Times(times),
            )
        }
        #[cfg(target_arch = "x86_64")]
        SYS_FUTIMESAT => {
            let times = child.read_timevals(args[2])?;
            (
                child.fd_or_path_name(args[0] as i32, args[1], 0)?,
                MetadataChange::Times(times),
            )
        }
        SYS_UTIMENSAT => {
            let times = child.read_timespecs(args[2])?;
            if let Some([atime, mtime]) = times
                && atime.nanoseconds == libc::UTIME_OMIT
                && mtime.nanoseconds == libc::UTIME_OMIT
            {
                // The kernel returns 0 here without looking at the path.
                return Ok(MetadataRequest {
                    change: MetadataChange::Times(times),
                    target: None,
                });
            }
            let flags = args[3] as i32;
            let name = if args[1] == 0 {
                if flags != 0 && args[0] as i32 != libc::AT_FDCWD {
                    return Err(errno(libc::EINVAL));
                }
                child.fd_or_path_name(args[0] as i32, 0, flags)?
            } else {
                if flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) != 0 {
                    return Err(errno(libc::EINVAL));
                }
                child.path_name(args[0] as i32, args[1], flags)?
            };
            (name, MetadataChange::Times(times))
        }
        _ => return Err(errno(libc::ENOSYS)),
    };
    Ok(MetadataRequest {
        change,
        target: Some(child.resolve(name)?),
    })
}

/// `umode_t` is 16 bits; the syscall entry truncates the register.
fn mode_arg(arg: u64) -> libc::mode_t {
    libc::mode_t::from(arg as u16)
}

/// The notifying thread, by its thread id as seccomp reports it.
struct Child {
    tid: u32,
}

impl Child {
    /// Name a pathname argument. `pointer` is the child's `const char *`.
    fn path_name(&self, dirfd: i32, pointer: u64, flags: i32) -> io::Result<Name> {
        let path = self.read_path(pointer)?;
        if path.is_empty() && flags & libc::AT_EMPTY_PATH == 0 {
            return Err(errno(libc::ENOENT));
        }
        Ok(Name::Path {
            dirfd,
            path,
            follow: flags & libc::AT_SYMLINK_NOFOLLOW == 0,
        })
    }

    /// `futimesat`/`utimensat`: a `NULL` pathname names `dirfd` itself
    /// (`O_PATH` refused), except with `AT_FDCWD`, which faults.
    fn fd_or_path_name(&self, dirfd: i32, pointer: u64, flags: i32) -> io::Result<Name> {
        if pointer != 0 {
            return self.path_name(dirfd, pointer, flags);
        }
        if dirfd == libc::AT_FDCWD {
            return Err(errno(libc::EFAULT));
        }
        Ok(Name::Fd {
            fd: dirfd,
            allow_opath: false,
        })
    }

    fn resolve(&self, name: Name) -> io::Result<MetadataTarget> {
        match name {
            Name::Fd { fd, allow_opath } => {
                let dup = self.dup_fd(fd)?;
                if dup.opath && !allow_opath {
                    return Err(errno(libc::EBADF));
                }
                describe(dup.fd, dup.writable)
            }
            Name::Path {
                dirfd,
                path,
                follow,
            } => {
                let bytes = path.to_bytes();
                if bytes.is_empty() {
                    // AT_EMPTY_PATH: the target is dirfd itself.
                    if dirfd == libc::AT_FDCWD {
                        return describe(self.open_proc("cwd")?, false);
                    }
                    let dup = self.dup_fd(dirfd)?;
                    return describe(dup.fd, dup.writable);
                }
                if let Some((fd, rest)) = self.proc_fd_reference(bytes) {
                    // /proc/self/fd/N names the child's descriptor N, not the
                    // supervisor's; resolving it here would reach our own.
                    if rest.is_empty() && follow {
                        let dup = self.dup_fd(fd)?;
                        return describe(dup.fd, dup.writable);
                    }
                    if !rest.is_empty() {
                        let base = self.open_fd_link(fd)?;
                        let rest = CString::new(rest).map_err(|_| errno(libc::EINVAL))?;
                        return describe(open_at(&base, &rest, follow, false)?, false);
                    }
                }
                let target = if bytes.first() == Some(&b'/') {
                    // Absolute: from the child's root, which may not be ours.
                    open_at(&self.open_proc("root")?, &path, follow, true)?
                } else if dirfd == libc::AT_FDCWD {
                    open_at(&self.open_proc("cwd")?, &path, follow, false)?
                } else {
                    open_at(&self.open_fd_link(dirfd)?, &path, follow, false)?
                };
                describe(target, false)
            }
        }
    }

    /// Recognise `/proc/self/fd/N`, `/proc/thread-self/fd/N` and
    /// `/proc/<own pid or tid>/fd/N`, optionally followed by `/rest`. glibc
    /// reaches `fchmodat(AT_SYMLINK_NOFOLLOW)` this way on kernels without
    /// `fchmodat2`. Anything else that crosses a procfs magic link is refused
    /// by `RESOLVE_NO_MAGICLINKS`.
    fn proc_fd_reference<'a>(&self, path: &'a [u8]) -> Option<(i32, &'a [u8])> {
        let rest = path.strip_prefix(b"/proc/")?;
        let slash = rest.iter().position(|&b| b == b'/')?;
        let (owner, rest) = rest.split_at(slash);
        let ours = match owner {
            b"self" | b"thread-self" => true,
            digits => std::str::from_utf8(digits)
                .ok()
                .and_then(|text| text.parse::<u32>().ok())
                .is_some_and(|pid| pid == self.tid || Some(pid) == self.tgid()),
        };
        if !ours {
            return None;
        }
        let rest = rest.strip_prefix(b"/fd/")?;
        let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        let (number, rest) = rest.split_at(end);
        let fd = std::str::from_utf8(number).ok()?.parse::<i32>().ok()?;
        Some((fd, rest.strip_prefix(b"/").unwrap_or(rest)))
    }

    fn tgid(&self) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.tid)).ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .and_then(|value| value.trim().parse().ok())
    }

    /// Open `/proc/<tid>/<entry>` as an `O_PATH` descriptor.
    fn open_proc(&self, entry: &str) -> io::Result<OwnedFd> {
        let path = CString::new(format!("/proc/{}/{}", self.tid, entry))
            .map_err(|_| errno(libc::EINVAL))?;
        // SAFETY: `path` is a valid NUL-terminated string.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        // SAFETY: a non-negative return is a fresh descriptor we now own.
        check_fd(fd).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Open the file behind the child's descriptor `fd`, for use as a lookup
    /// base: identity only, no access mode.
    fn open_fd_link(&self, fd: i32) -> io::Result<OwnedFd> {
        if fd < 0 {
            return Err(errno(libc::EBADF));
        }
        self.open_proc(&format!("fd/{fd}")).map_err(|error| {
            if error.raw_os_error() == Some(libc::ENOENT) {
                errno(libc::EBADF)
            } else {
                error
            }
        })
    }

    /// Duplicate the child's descriptor `fd` into the supervisor.
    ///
    /// `pidfd_getfd(2)` shares the child's open file description, so its
    /// access mode is the child's, read from the very descriptor the change
    /// is applied to. Where pidfds are unavailable (a seccomp profile denies
    /// them, say), fall back to reopening the procfs link: the inode is the
    /// same, but the access mode would come from a second lookup the child
    /// could race, so that path never reports a writable descriptor.
    fn dup_fd(&self, fd: i32) -> io::Result<ChildFd> {
        if fd < 0 {
            return Err(errno(libc::EBADF));
        }
        match self.pidfd().and_then(|pidfd| pidfd_getfd(&pidfd, fd)) {
            Ok(dup) => {
                // SAFETY: F_GETFL on an owned descriptor takes no pointers.
                let flags = check_fd(unsafe { libc::fcntl(dup.as_raw_fd(), libc::F_GETFL) })?;
                Ok(ChildFd {
                    fd: dup,
                    opath: flags & libc::O_PATH != 0,
                    writable: flags & libc::O_PATH == 0
                        && matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR),
                })
            }
            Err(error) if error.raw_os_error() == Some(libc::EBADF) => Err(error),
            Err(_) => Ok(ChildFd {
                fd: self.open_fd_link(fd)?,
                opath: false,
                writable: false,
            }),
        }
    }

    /// A pidfd for the notifying thread's descriptor table.
    fn pidfd(&self) -> io::Result<OwnedFd> {
        // A thread-group leader takes a plain pidfd; any other thread needs
        // PIDFD_THREAD (Linux 6.9), or else its process's pidfd, which shares
        // the descriptor table unless the thread unshared it.
        pidfd_open(self.tid, 0)
            .or_else(|_| pidfd_open(self.tid, PIDFD_THREAD))
            .or_else(|error| match self.tgid() {
                Some(tgid) if tgid != self.tid => pidfd_open(tgid, 0),
                _ => Err(error),
            })
    }

    /// Read a NUL-terminated pathname as `getname()` does.
    fn read_path(&self, pointer: u64) -> io::Result<CString> {
        if pointer == 0 {
            return Err(errno(libc::EFAULT));
        }
        let mut bytes = Vec::with_capacity(256);
        let mut cursor = pointer;
        while bytes.len() < PATH_MAX {
            let to_boundary = READ_CHUNK - (cursor as usize % READ_CHUNK);
            let want = to_boundary.min(PATH_MAX - bytes.len());
            let start = bytes.len();
            bytes.resize(start + want, 0);
            let read = self.read_memory(cursor, &mut bytes[start..])?;
            bytes.truncate(start + read);
            if let Some(nul) = bytes[start..].iter().position(|&b| b == 0) {
                bytes.truncate(start + nul);
                return CString::new(bytes).map_err(|_| errno(libc::EINVAL));
            }
            if read < want {
                return Err(errno(libc::EFAULT));
            }
            cursor = cursor.wrapping_add(read as u64);
        }
        Err(errno(libc::ENAMETOOLONG))
    }

    fn read_exact(&self, pointer: u64, buffer: &mut [u8]) -> io::Result<()> {
        if pointer == 0 || self.read_memory(pointer, buffer)? != buffer.len() {
            return Err(errno(libc::EFAULT));
        }
        Ok(())
    }

    fn read_memory(&self, pointer: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let remote = libc::iovec {
            iov_base: pointer as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        // SAFETY: `local` describes `buffer`, which is valid for writes of its
        // length; `remote` is only dereferenced by the kernel, in the child.
        let read =
            unsafe { libc::process_vm_readv(self.tid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if read < 0 {
            let error = io::Error::last_os_error();
            // An unmapped address is the child's EFAULT; anything else (the
            // child is gone, or cannot be inspected) is ours.
            return Err(if error.raw_os_error() == Some(libc::EFAULT) {
                errno(libc::EFAULT)
            } else {
                error
            });
        }
        Ok(read as usize)
    }

    /// Read `N` native-endian 64-bit words; a null pointer reads as `None`.
    fn read_words<const N: usize>(&self, pointer: u64) -> io::Result<Option<[i64; N]>> {
        if pointer == 0 {
            return Ok(None);
        }
        let mut raw = vec![0_u8; N * 8];
        self.read_exact(pointer, &mut raw)?;
        let (chunks, _) = raw.as_chunks::<8>();
        let mut words = [0_i64; N];
        for (word, chunk) in words.iter_mut().zip(chunks) {
            *word = i64::from_ne_bytes(*chunk);
        }
        Ok(Some(words))
    }

    /// `struct timespec[2]` (64-bit layout).
    fn read_timespecs(&self, pointer: u64) -> io::Result<Option<[Timestamp; 2]>> {
        Ok(self.read_words::<4>(pointer)?.map(|[s0, n0, s1, n1]| {
            [
                Timestamp {
                    seconds: s0,
                    nanoseconds: n0,
                },
                Timestamp {
                    seconds: s1,
                    nanoseconds: n1,
                },
            ]
        }))
    }

    /// `struct timeval[2]`, validated and converted as `futimesat` does.
    #[cfg(target_arch = "x86_64")]
    fn read_timevals(&self, pointer: u64) -> io::Result<Option<[Timestamp; 2]>> {
        let Some([s0, u0, s1, u1]) = self.read_words::<4>(pointer)? else {
            return Ok(None);
        };
        let convert = |seconds: i64, micros: i64| {
            if (0..1_000_000).contains(&micros) {
                Ok(Timestamp {
                    seconds,
                    nanoseconds: micros * 1_000,
                })
            } else {
                Err(errno(libc::EINVAL))
            }
        };
        Ok(Some([convert(s0, u0)?, convert(s1, u1)?]))
    }

    /// `struct utimbuf` (two `time_t`), as `utime` reads it.
    #[cfg(target_arch = "x86_64")]
    fn read_utimbuf(&self, pointer: u64) -> io::Result<Option<[Timestamp; 2]>> {
        Ok(self.read_words::<2>(pointer)?.map(|words| {
            words.map(|seconds| Timestamp {
                seconds,
                nanoseconds: 0,
            })
        }))
    }
}

/// A duplicate of one of the child's descriptors.
struct ChildFd {
    fd: OwnedFd,
    opath: bool,
    writable: bool,
}

/// Open `path` relative to `base` as an `O_PATH` descriptor, refusing procfs
/// magic links (which would resolve in the supervisor's context, not the
/// child's). With `in_root`, `base` is the child's root and the lookup cannot
/// leave it.
fn open_at(base: &OwnedFd, path: &CStr, follow: bool, in_root: bool) -> io::Result<OwnedFd> {
    let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | nofollow) as u64,
        mode: 0,
        resolve: libc::RESOLVE_NO_MAGICLINKS | if in_root { libc::RESOLVE_IN_ROOT } else { 0 },
    };
    let mut attempts = 0;
    loop {
        attempts += 1;
        // SAFETY: `base` is open, `path` is NUL-terminated, and `how` is a
        // correctly sized open_how that outlives the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                base.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: a non-negative return is a fresh descriptor we now own.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // A rename raced a scoped lookup; the kernel asks for a retry.
            Some(libc::EAGAIN) if attempts < RESOLVE_ATTEMPTS => continue,
            // A magic link refused under RESOLVE_IN_ROOT. No chmod/utime
            // caller expects EXDEV; ELOOP is what the unscoped refusal returns.
            Some(libc::EXDEV) => return Err(errno(libc::ELOOP)),
            _ => return Err(error),
        }
    }
}

fn describe(fd: OwnedFd, via_writable_fd: bool) -> io::Result<MetadataTarget> {
    // SAFETY: an all-zero `stat` is a valid value for fstat to overwrite.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` is valid for writes.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) })?;
    let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    let path = link
        .is_absolute()
        .then_some(link)
        .filter(|path| names_inode(path, &stat));
    Ok(MetadataTarget {
        path,
        symlink: stat.st_mode & libc::S_IFMT == libc::S_IFLNK,
        via_writable_fd,
        fd,
    })
}

/// Whether `path`, resolved from the supervisor's root without following a
/// final symlink, is the inode `stat` describes. A policy decided on the path
/// string is then a decision on this inode.
fn names_inode(path: &Path, stat: &libc::stat) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .is_ok_and(|named| named.dev() == stat.st_dev && named.ino() == stat.st_ino)
}

fn pidfd_open(pid: u32, flags: libc::c_uint) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes only scalar arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, flags) };
    // SAFETY: a non-negative return is a fresh descriptor we now own.
    check_fd(fd as i32).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn pidfd_getfd(pidfd: &OwnedFd, fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_getfd takes only scalar arguments.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0_u32) };
    // SAFETY: a non-negative return is a fresh close-on-exec descriptor we own.
    check_fd(dup as i32).map(|dup| unsafe { OwnedFd::from_raw_fd(dup) })
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn check_fd(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! The supervisor and the "child" are the same thread here: resolution
    //! reads this thread's memory, procfs entries and descriptor table.

    use super::super::linux::SeccompData;
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn notif(nr: i32, args: [u64; 6]) -> SeccompNotif {
        SeccompNotif {
            id: 0,
            // SAFETY: gettid takes no arguments and cannot fail.
            pid: unsafe { libc::gettid() } as u32,
            flags: 0,
            data: SeccompData {
                nr,
                arch: 0,
                instruction_pointer: 0,
                args,
            },
        }
    }

    const AT_FDCWD: u64 = libc::AT_FDCWD as i64 as u64;

    fn c(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    fn open(path: &Path, flags: i32) -> OwnedFd {
        let path = c(path);
        // SAFETY: valid C string; a non-negative return is ours to own.
        let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
        assert!(fd >= 0, "open: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let file = root.join("file");
        std::fs::write(&file, "x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        (dir, root, file)
    }

    fn request(nr: i32, args: [u64; 6]) -> io::Result<MetadataRequest> {
        read_metadata_request(&notif(nr, args))
    }

    fn errno_of(result: io::Result<MetadataRequest>) -> i32 {
        result.unwrap_err().raw_os_error().unwrap()
    }

    fn target(request: &MetadataRequest) -> &MetadataTarget {
        request.target().expect("a target")
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn fchmodat_resolves_the_named_inode_and_applies_to_it() {
        let (_dir, _root, file) = fixture();
        let path = c(&file);
        let request = request(
            SYS_FCHMODAT,
            [AT_FDCWD, path.as_ptr() as u64, 0o600, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(request.change(), MetadataChange::Mode(0o600));
        assert_eq!(target(&request).path(), Some(file.as_path()));
        assert!(!target(&request).via_writable_fd());
        request.apply().unwrap();
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn symlinks_are_followed_unless_the_call_says_otherwise() {
        let (_dir, root, file) = fixture();
        let link = root.join("link");
        symlink(&file, &link).unwrap();
        let path = c(&link);

        let followed = request(
            SYS_FCHMODAT,
            [AT_FDCWD, path.as_ptr() as u64, 0o600, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(target(&followed).path(), Some(file.as_path()));

        let nofollow = request(
            SYS_FCHMODAT2,
            [
                AT_FDCWD,
                path.as_ptr() as u64,
                0o600,
                libc::AT_SYMLINK_NOFOLLOW as u64,
                0,
                0,
            ],
        )
        .unwrap();
        assert_eq!(target(&nofollow).path(), Some(link.as_path()));
        // As the kernel does since fchmodat2: a symlink's mode cannot change,
        // and its target must not change instead.
        assert_eq!(
            nofollow.apply().unwrap_err().raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(mode(&file), 0o644);
    }

    #[test]
    fn relative_paths_resolve_from_the_callers_dirfd() {
        let (_dir, root, file) = fixture();
        let dirfd = open(&root, libc::O_PATH | libc::O_DIRECTORY);
        let name = c(Path::new("file"));
        let request = request(
            SYS_FCHMODAT,
            [
                dirfd.as_raw_fd() as u64,
                name.as_ptr() as u64,
                0o600,
                0,
                0,
                0,
            ],
        )
        .unwrap();
        assert_eq!(target(&request).path(), Some(file.as_path()));
    }

    #[test]
    fn descriptors_report_whether_they_were_opened_for_writing() {
        let (_dir, _root, file) = fixture();
        for (flags, writable) in [
            (libc::O_RDONLY, false),
            (libc::O_WRONLY, true),
            (libc::O_RDWR, true),
        ] {
            let fd = open(&file, flags);
            let request = request(SYS_FCHMOD, [fd.as_raw_fd() as u64, 0o600, 0, 0, 0, 0]).unwrap();
            assert_eq!(target(&request).path(), Some(file.as_path()));
            assert_eq!(
                target(&request).via_writable_fd(),
                writable,
                "flags {flags:#o}"
            );
        }
        // fchmod and futimens refuse O_PATH descriptors, and so does emulation.
        let opath = open(&file, libc::O_PATH | libc::O_RDWR);
        assert_eq!(
            errno_of(request(
                SYS_FCHMOD,
                [opath.as_raw_fd() as u64, 0o600, 0, 0, 0, 0]
            )),
            libc::EBADF
        );
        assert_eq!(
            errno_of(request(
                SYS_UTIMENSAT,
                [opath.as_raw_fd() as u64, 0, 0, 0, 0, 0]
            )),
            libc::EBADF
        );
        assert_eq!(
            errno_of(request(SYS_FCHMOD, [9999, 0o600, 0, 0, 0, 0])),
            libc::EBADF
        );
    }

    #[test]
    fn at_empty_path_names_the_descriptor_itself() {
        let (_dir, _root, file) = fixture();
        let opath = open(&file, libc::O_PATH);
        let empty = c(Path::new(""));
        let args = |flags: i32| {
            [
                opath.as_raw_fd() as u64,
                empty.as_ptr() as u64,
                0o600,
                flags as u64,
                0,
                0,
            ]
        };
        assert_eq!(errno_of(request(SYS_FCHMODAT2, args(0))), libc::ENOENT);
        let request = request(SYS_FCHMODAT2, args(libc::AT_EMPTY_PATH)).unwrap();
        assert_eq!(target(&request).path(), Some(file.as_path()));
        assert!(!target(&request).via_writable_fd());
        request.apply().unwrap();
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn unlinked_files_have_no_path() {
        let (_dir, _root, file) = fixture();
        let fd = open(&file, libc::O_RDONLY);
        std::fs::remove_file(&file).unwrap();
        let request = request(SYS_FCHMOD, [fd.as_raw_fd() as u64, 0o600, 0, 0, 0, 0]).unwrap();
        assert_eq!(target(&request).path(), None);
        assert!(!target(&request).via_writable_fd());
    }

    #[test]
    fn proc_self_fd_names_the_callers_descriptor() {
        let (_dir, _root, file) = fixture();
        let opath = open(&file, libc::O_PATH);
        for form in ["/proc/self/fd", "/proc/thread-self/fd"] {
            let path = c(Path::new(&format!("{form}/{}", opath.as_raw_fd())));
            let request = request(
                SYS_FCHMODAT,
                [AT_FDCWD, path.as_ptr() as u64, 0o600, 0, 0, 0],
            )
            .unwrap();
            assert_eq!(target(&request).path(), Some(file.as_path()), "{form}");
        }
    }

    #[test]
    fn other_procfs_magic_links_are_refused() {
        let (_dir, _root, file) = fixture();
        let fd = open(&file, libc::O_RDONLY);
        // /dev/fd is a symlink into /proc/self/fd, which would resolve in the
        // supervisor's context rather than the child's.
        let path = c(Path::new(&format!("/dev/fd/{}", fd.as_raw_fd())));
        assert_eq!(
            errno_of(request(
                SYS_FCHMODAT,
                [AT_FDCWD, path.as_ptr() as u64, 0o600, 0, 0, 0]
            )),
            libc::ELOOP
        );
    }

    #[test]
    fn utimensat_follows_the_kernels_argument_rules() {
        let (_dir, _root, file) = fixture();
        let fd = open(&file, libc::O_RDONLY);
        let path = c(&file);
        let times = [
            libc::timespec {
                tv_sec: 946_684_800,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 946_684_800,
                tv_nsec: 0,
            },
        ];
        let times_ptr = times.as_ptr() as u64;

        let by_path = request(
            SYS_UTIMENSAT,
            [AT_FDCWD, path.as_ptr() as u64, times_ptr, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(
            by_path.change(),
            MetadataChange::Times(Some(
                [Timestamp {
                    seconds: 946_684_800,
                    nanoseconds: 0
                }; 2]
            ))
        );
        by_path.apply().unwrap();
        let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(
            mtime,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800)
        );

        // A NULL pathname names dirfd, and then takes no flags.
        let by_fd = request(
            SYS_UTIMENSAT,
            [fd.as_raw_fd() as u64, 0, times_ptr, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(target(&by_fd).path(), Some(file.as_path()));
        assert_eq!(
            errno_of(request(
                SYS_UTIMENSAT,
                [
                    fd.as_raw_fd() as u64,
                    0,
                    times_ptr,
                    libc::AT_SYMLINK_NOFOLLOW as u64,
                    0,
                    0
                ]
            )),
            libc::EINVAL
        );
        assert_eq!(
            errno_of(request(SYS_UTIMENSAT, [AT_FDCWD, 0, times_ptr, 0, 0, 0])),
            libc::EFAULT
        );
        // NULL times means "now".
        let now = request(SYS_UTIMENSAT, [fd.as_raw_fd() as u64, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(now.change(), MetadataChange::Times(None));

        // Both UTIME_OMIT: the kernel returns 0 before any lookup.
        let omit = [libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        }; 2];
        let missing = c(Path::new("/nonexistent/nono-metadata"));
        let request = request(
            SYS_UTIMENSAT,
            [
                AT_FDCWD,
                missing.as_ptr() as u64,
                omit.as_ptr() as u64,
                0,
                0,
                0,
            ],
        )
        .unwrap();
        assert!(request.target().is_none());
        request.apply().unwrap();
    }

    #[test]
    fn bad_arguments_fail_as_the_kernel_would() {
        let (_dir, _root, file) = fixture();
        let path = c(&file);
        assert_eq!(
            errno_of(request(SYS_FCHMODAT, [AT_FDCWD, 0, 0o600, 0, 0, 0])),
            libc::EFAULT
        );
        assert_eq!(
            errno_of(request(SYS_FCHMODAT, [AT_FDCWD, 8, 0o600, 0, 0, 0])),
            libc::EFAULT
        );
        assert_eq!(
            errno_of(request(
                SYS_FCHMODAT2,
                [AT_FDCWD, path.as_ptr() as u64, 0o600, 0x8000_0000, 0, 0]
            )),
            libc::EINVAL
        );
        let long = c(Path::new(&"a/".repeat(PATH_MAX)));
        assert_eq!(
            errno_of(request(
                SYS_FCHMODAT,
                [AT_FDCWD, long.as_ptr() as u64, 0o600, 0, 0, 0]
            )),
            libc::ENAMETOOLONG
        );
        let missing = c(Path::new("/nonexistent/nono-metadata"));
        assert_eq!(
            errno_of(request(
                SYS_FCHMODAT,
                [AT_FDCWD, missing.as_ptr() as u64, 0o600, 0, 0, 0]
            )),
            libc::ENOENT
        );
        assert_eq!(
            errno_of(request(libc::SYS_read as i32, [0; 6])),
            libc::ENOSYS
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn legacy_x86_64_entry_points_are_read_like_their_successors() {
        let (_dir, _root, file) = fixture();
        let path = c(&file);
        let chmod = request(SYS_CHMOD, [path.as_ptr() as u64, 0o1600, 0, 0, 0, 0]).unwrap();
        assert_eq!(chmod.change(), MetadataChange::Mode(0o1600));
        assert_eq!(target(&chmod).path(), Some(file.as_path()));

        let utimbuf = [946_684_800_i64, 946_684_801];
        let utime = request(
            SYS_UTIME,
            [path.as_ptr() as u64, utimbuf.as_ptr() as u64, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(
            utime.change(),
            MetadataChange::Times(Some([
                Timestamp {
                    seconds: 946_684_800,
                    nanoseconds: 0
                },
                Timestamp {
                    seconds: 946_684_801,
                    nanoseconds: 0
                },
            ]))
        );

        let timevals = [1_i64, 999_999, 2, 0];
        let utimes = request(
            SYS_UTIMES,
            [path.as_ptr() as u64, timevals.as_ptr() as u64, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(
            utimes.change(),
            MetadataChange::Times(Some([
                Timestamp {
                    seconds: 1,
                    nanoseconds: 999_999_000
                },
                Timestamp {
                    seconds: 2,
                    nanoseconds: 0
                },
            ]))
        );
        let invalid = [1_i64, 1_000_000, 2, 0];
        assert_eq!(
            errno_of(request(
                SYS_UTIMES,
                [path.as_ptr() as u64, invalid.as_ptr() as u64, 0, 0, 0, 0]
            )),
            libc::EINVAL
        );

        let fd = open(&file, libc::O_RDONLY);
        let futimesat = request(
            SYS_FUTIMESAT,
            [fd.as_raw_fd() as u64, 0, timevals.as_ptr() as u64, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(target(&futimesat).path(), Some(file.as_path()));
    }

    #[test]
    fn proc_fd_references_are_recognised_only_for_the_caller() {
        let child = Child { tid: 4242 };
        assert_eq!(
            child.proc_fd_reference(b"/proc/self/fd/3"),
            Some((3, &b""[..]))
        );
        assert_eq!(
            child.proc_fd_reference(b"/proc/thread-self/fd/12/sub/dir"),
            Some((12, &b"sub/dir"[..]))
        );
        assert_eq!(
            child.proc_fd_reference(b"/proc/4242/fd/7"),
            Some((7, &b""[..]))
        );
        assert_eq!(child.proc_fd_reference(b"/proc/1/fd/7"), None);
        assert_eq!(child.proc_fd_reference(b"/proc/self/fdinfo/7"), None);
        assert_eq!(child.proc_fd_reference(b"/proc/self/fd/x"), None);
        assert_eq!(child.proc_fd_reference(b"/proc/self/fd"), None);
        assert_eq!(child.proc_fd_reference(b"/dev/fd/3"), None);
    }

    #[test]
    fn metadata_syscalls_are_recognised() {
        for &nr in METADATA_SYSCALLS {
            assert!(is_metadata_syscall(nr));
        }
        assert!(!is_metadata_syscall(libc::SYS_flock as i32));
        assert!(!is_metadata_syscall(libc::SYS_openat as i32));
    }
}
