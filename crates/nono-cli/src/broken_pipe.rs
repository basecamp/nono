//! A closed stdout or stderr ends nono quietly, as it ends a C tool.
//!
//! Rust ignores SIGPIPE before `main`, so a write to a pipe whose reader has
//! gone (`nono why … | head -n 1`) fails with `EPIPE`, and `println!` and
//! `eprintln!` turn that failure into a panic: "failed printing to stdout:
//! Broken pipe (os error 32)". Release builds set `panic = "abort"`, so the
//! process aborts with SIGABRT and dumps core.
//!
//! Restoring SIGPIPE's default disposition for the whole process would end
//! those prints quietly, but it would also make every other write to a closed
//! peer fatal. The supervisor socket and the PTY proxy's attach socket are std
//! `UnixStream`s, which on Linux write with plain `write(2)`, and the PTY proxy
//! writes the terminal with raw `write(2)` and ignores the result. All of them
//! rely on SIGPIPE being ignored, so that a peer that went away is an `EPIPE`
//! error they handle rather than the end of the supervisor.
//!
//! So SIGPIPE stays ignored, and only the print macros' own failure on a
//! closed pipe changes. The panic hook recognises that one message, restores
//! SIGPIPE's default disposition and raises it, so the process ends by SIGPIPE
//! (status 141 in a shell). SIGPIPE's default action terminates without a core.
//! Any other panic, a print that fails for another reason (`ENOSPC` on a
//! redirect) included, goes to the previous hook unchanged.

/// Installs the hook. Call it first thing in `main`, before anything prints.
#[cfg(unix)]
pub(crate) fn install() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload_as_str().is_some_and(is_closed_pipe_print) {
            end_by_sigpipe();
        }
        previous(info);
    }));
}

#[cfg(not(unix))]
pub(crate) fn install() {}

/// Whether `message` is the panic std's print macros raise when stdout or
/// stderr is a pipe with no reader: `failed printing to {stream}: {error}`,
/// where the error is `EPIPE`. The error part is compared with std's own
/// rendering of `EPIPE`, so only the fixed prefix depends on std's wording,
/// and `tests/broken_pipe_run.rs` pins that against the built binary.
#[cfg(unix)]
fn is_closed_pipe_print(message: &str) -> bool {
    let epipe = std::io::Error::from_raw_os_error(nix::errno::Errno::EPIPE as i32);
    message
        .strip_prefix("failed printing to ")
        .and_then(|rest| {
            rest.strip_prefix("stdout: ")
                .or_else(|| rest.strip_prefix("stderr: "))
        })
        .is_some_and(|error| error == epipe.to_string())
}

/// Ends the process by SIGPIPE, as a C tool writing to a closed pipe ends.
#[cfg(unix)]
fn end_by_sigpipe() -> ! {
    use nix::sys::signal::{SigHandler, SigSet, Signal, raise, signal};

    // SAFETY: SIG_DFL installs no handler, so no handler code can run in a
    // signal context. The process is about to end in any case.
    let _ = unsafe { signal(Signal::SIGPIPE, SigHandler::SigDfl) };
    // A thread that blocks SIGPIPE would leave the raised signal pending.
    let _ = SigSet::from(Signal::SIGPIPE).thread_unblock();
    let _ = raise(Signal::SIGPIPE);
    // Reached only if the signal could not be delivered: exit with the status
    // a shell reports for a process SIGPIPE ended.
    std::process::exit(128 + Signal::SIGPIPE as i32)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn print_failure(stream: &str, errno: nix::errno::Errno) -> String {
        format!(
            "failed printing to {stream}: {}",
            std::io::Error::from_raw_os_error(errno as i32)
        )
    }

    #[test]
    fn recognises_a_print_to_a_closed_stdout_or_stderr() {
        assert!(is_closed_pipe_print(&print_failure(
            "stdout",
            nix::errno::Errno::EPIPE
        )));
        assert!(is_closed_pipe_print(&print_failure(
            "stderr",
            nix::errno::Errno::EPIPE
        )));
    }

    #[test]
    fn leaves_other_print_failures_and_panics_alone() {
        assert!(!is_closed_pipe_print(&print_failure(
            "stdout",
            nix::errno::Errno::ENOSPC
        )));
        assert!(!is_closed_pipe_print(&print_failure(
            "stdin",
            nix::errno::Errno::EPIPE
        )));
        assert!(!is_closed_pipe_print(
            "called `Option::unwrap()` on a `None` value"
        ));
        assert!(!is_closed_pipe_print(&format!(
            "context: {}",
            print_failure("stdout", nix::errno::Errno::EPIPE)
        )));
    }
}
