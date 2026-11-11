# basecamp/nono `integration`

This branch is upstream [nolabs-ai/nono](https://github.com/nolabs-ai/nono) `main` plus fixes we have
prepared for upstream that have not landed yet. `.github/workflows/rebuild-integration.yml`
rebuilds it daily and after every change to it (`.github/integration/rebuild`): reset to
the upstream `main` commit pinned in `.github/integration/upstream`, the topic branches
in `.github/integration/topics` merged in order, upstream's workflows removed,
force-pushed. So never base work on it: base topic branches on the pinned upstream commit or an
earlier one (a topic is merged whole, so one based on a later upstream commit brings that history
with it, past the pin), and
change what it carries with a pull request to `.github/integration/topics`. A topic
branch that does not merge stops the rebuild and opens an issue labelled
`integration-rebuild`.

Upstream moving does not move it. Each day the same workflow tries upstream `main`'s tip:
when every topic branch merges onto it, a pull request labelled `integration-upstream`
moves the pin there; when one does not, an issue with that label names the topic branch
and its conflicting files, and the pin stays.

`.github/workflows/build-integration.yml` builds each rebuild for x86_64-unknown-linux-gnu,
aarch64-apple-darwin and x86_64-apple-darwin, attests build provenance, and publishes a
prerelease tagged `integration-<sha12>`.

## Upstream base

Pinned: nolabs-ai/nono `main` at [`cd5af88229dd`](https://github.com/nolabs-ai/nono/commit/cd5af88229dd47fb5360c5079d53812218a4e7ae) (`feat(proxy): approvals for allow_domain endpoints (#2266)`).

## Carried topic branches

Each is merged with `--no-ff`, in this order.

| Branch | Commit | Fixes |
|---|---|---|
| [`fix/supervisor-audit-rate-limited-capability-requests`](https://github.com/basecamp/nono/tree/fix/supervisor-audit-rate-limited-capability-requests) | `d08572c2d84e` | Remainder of nolabs-ai/nono#2043 after #2047: capability requests, and requests for unix socket approvals, refused by the approval rate limiter left no audit record |
| [`fix/drain-command-proxy-audit`](https://github.com/basecamp/nono/tree/fix/drain-command-proxy-audit) | `5d232348cb7d` | Follow-up to nolabs-ai/nono#1981: command-scoped proxy audit events were never drained into the session audit record |
| [`fix/profile-show-sandbox-policy`](https://github.com/basecamp/nono/tree/fix/profile-show-sandbox-policy) | `148a98d47b93` | `nono profile show` / `profile diff` omitted `linux.sandbox_policy` in text and JSON |
| [`metadata-ops-confine`](https://github.com/basecamp/nono/tree/metadata-ops-confine) | `93404799aa55` | nolabs-ai/nono#914: Landlock does not mediate chmod/utime; `linux.metadata_mediation = "write_grants"` confines them to write grants |
| [`feat/proxy-resolved-address-classes-cd5af88`](https://github.com/basecamp/nono/tree/feat/proxy-resolved-address-classes-cd5af88) | `c5bc009e67b1` | `network.resolved_addresses`: with `public_only`, an allowed name that resolves to a loopback, private or shared (CGNAT) address is refused unless an exception names that class for it, and one that resolves to an unspecified address is refused with no exception possible (a link-local one is refused in any case) (upstream draft not filed) |
| [`feat/dry-run-json`](https://github.com/basecamp/nono/tree/feat/dry-run-json) | `a7fa43586e64` | `nono run --dry-run --json`: the launch plan's capability set as JSON (filesystem and Unix-socket grants with resolved and written paths, access and source; network mode and port exceptions; resource limits; each brokered command's sandbox as its launch builds it; on macOS, every file rule of the Seatbelt profile the launch applies, read back from the profile itself into `seatbelt_grants` with its scope — `literal`, `subpath`, `children` or `atomic_temp` — and any rule not shown bounded named in `incomplete`), planned without reading any credential source, so a launcher checks what a run applies without parsing the text summary (report version 3, which drops `metadata_paths` and `metadata_children`; upstream draft not filed) |
| [`fix/open-port-bind-loopback`](https://github.com/basecamp/nono/tree/fix/open-port-bind-loopback) | `c4fd14a4b500` | An open port (`network.open_port`, `open_port_range`) binds only on loopback in Linux proxy mode, as its connect already reaches only loopback: a bind to `0.0.0.0`, `::` or a LAN address on it fails with `EADDRNOTAVAIL`, which port probers skip (macOS unchanged: Seatbelt cannot hold a bind to loopback) (upstream draft not filed) |
| [`fix/cli-stdout-broken-pipe`](https://github.com/basecamp/nono/tree/fix/cli-stdout-broken-pipe) | `f98f58d5137c` | A closed stdout or stderr (`nono why … \| head -n 1`) ends nono by SIGPIPE, status 141 and no core, instead of a "failed printing to stdout: Broken pipe" panic that aborted with SIGABRT and dumped core under `panic = "abort"`; SIGPIPE stays ignored, so the supervisor and proxy still see EPIPE as an error (upstream draft not filed) |
| [`feat/proxy-host-denial-message-cd5af88`](https://github.com/basecamp/nono/tree/feat/proxy-host-denial-message-cd5af88) | `de87c6bd7f53` | `network.allowlist_denial_message`: the profile words the 403 that refuses a host outside the allowlist (`{host}` replaced by the host, ` [rule: net.allowlist]` appended, sent as the reason phrase and a plain-text body with an `X-Nono-Denied-By: net.allowlist` header), so an agent reading it is told what to do instead of retrying; what is allowed, denied and audited is unchanged, other refusals keep the default response, and with no message the response is byte for byte today's (upstream draft not filed) |
| [`fix/seatbelt-keep-write-grant-root`](https://github.com/basecamp/nono/tree/fix/seatbelt-keep-write-grant-root) | `1d8e7666f467` | On macOS, a directory write grant's root stays in place, as Landlock keeps it on Linux (where removing or renaming a directory needs write access to its parent): the Seatbelt profile denies `file-write-unlink` on the root alone, in each spelling the grant's write rules use, so `rmdir R` and `mv R elsewhere` fail with EPERM while writing, removing and renaming inside R are unchanged; a root whose parent lies within a directory write grant stays removable, and single-file grants are unchanged (upstream draft not filed) |
