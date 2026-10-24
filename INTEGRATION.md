# basecamp/nono `integration`

This branch is upstream [nolabs-ai/nono](https://github.com/nolabs-ai/nono) `main` plus fixes we have
prepared for upstream that have not landed yet. `.github/workflows/rebuild-integration.yml`
rebuilds it daily and after every change to it (`.github/integration/rebuild`): reset to
upstream `main`, the topic branches in `.github/integration/topics` merged in order,
upstream's workflows removed, force-pushed. So never base work on it: base topic branches
on upstream `main`, and change what it carries with a pull request to
`.github/integration/topics`. A topic branch that does not merge stops the rebuild and
opens an issue labelled `integration-rebuild`.

`.github/workflows/build-integration.yml` builds each rebuild for x86_64-unknown-linux-gnu,
aarch64-apple-darwin and x86_64-apple-darwin, attests build provenance, and publishes a
prerelease tagged `integration-<sha12>`.

## Upstream base

nolabs-ai/nono `main` at [`11d9e6b8e522`](https://github.com/nolabs-ai/nono/commit/11d9e6b8e522a87325134e5399cc458f11e5bba7) (`chore(deps): bump ctutils to 0.4.4 (#2192)`).

## Carried topic branches

Each is merged with `--no-ff`, in this order.

| Branch | Commit | Fixes |
|---|---|---|
| [`fix/supervisor-audit-rate-limited-capability-requests`](https://github.com/basecamp/nono/tree/fix/supervisor-audit-rate-limited-capability-requests) | `7828b5c12414` | Remainder of nolabs-ai/nono#2043 after #2047: capability requests refused by the approval rate limiter left no audit record |
| [`fix/drain-command-proxy-audit`](https://github.com/basecamp/nono/tree/fix/drain-command-proxy-audit) | `58d03df3571d` | Follow-up to nolabs-ai/nono#1981: command-scoped proxy audit events were never drained into the session audit record |
| [`fix/profile-show-sandbox-policy`](https://github.com/basecamp/nono/tree/fix/profile-show-sandbox-policy) | `148a98d47b93` | `nono profile show` / `profile diff` omitted `linux.sandbox_policy` in text and JSON |
| [`metadata-ops-confine`](https://github.com/basecamp/nono/tree/metadata-ops-confine) | `93404799aa55` | nolabs-ai/nono#914: Landlock does not mediate chmod/utime; `linux.metadata_mediation = "write_grants"` confines them to write grants |
| [`feat/proxy-resolved-address-classes`](https://github.com/basecamp/nono/tree/feat/proxy-resolved-address-classes) | `5f08e2b51d18` | `network.resolved_addresses`: with `public_only`, an allowed name that resolves to a loopback, private or shared (CGNAT) address is refused unless an exception names that class for it, and one that resolves to an unspecified address is refused with no exception possible (a link-local one is refused in any case) (upstream draft not filed) |
| [`feat/dry-run-json`](https://github.com/basecamp/nono/tree/feat/dry-run-json) | `869b9c60fc71` | `nono run --dry-run --json`: the launch plan's capability set as JSON (filesystem and Unix-socket grants with resolved and written paths, access and source; network mode and port exceptions; resource limits; each brokered command's sandbox as its launch builds it), planned without reading any credential source, so a launcher checks what a run applies without parsing the text summary (upstream draft not filed) |
| [`fix/open-port-bind-loopback`](https://github.com/basecamp/nono/tree/fix/open-port-bind-loopback) | `821471e68fd6` | An open port (`network.open_port`, `open_port_range`) binds only on loopback in Linux proxy mode, as its connect already reaches only loopback: a bind to `0.0.0.0`, `::` or a LAN address on it fails with `EADDRNOTAVAIL`, which port probers skip (macOS unchanged: Seatbelt cannot hold a bind to loopback) (upstream draft not filed) |
| [`fix/cli-stdout-broken-pipe`](https://github.com/basecamp/nono/tree/fix/cli-stdout-broken-pipe) | `f98f58d5137c` | A closed stdout or stderr (`nono why … \| head -n 1`) ends nono by SIGPIPE, status 141 and no core, instead of a "failed printing to stdout: Broken pipe" panic that aborted with SIGABRT and dumped core under `panic = "abort"`; SIGPIPE stays ignored, so the supervisor and proxy still see EPIPE as an error (upstream draft not filed) |
| [`perf/elf-bounded-reads`](https://github.com/basecamp/nono/tree/perf/elf-bounded-reads) | `9ce7adeb62ad` | nolabs-ai/nono#2143: the session exec gate (`command_policies`) read every executable on PATH whole to parse its ELF headers, gigabytes at each start; `parse_elf` now reads only the ELF header, program headers, `PT_INTERP`, `PT_DYNAMIC` and the dynamic string table, with bounded positional reads (a region over its bound is a parse error) and the same answers (upstream PR not yet filed) |
