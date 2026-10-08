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

nolabs-ai/nono `main` at [`9edf3ea93956`](https://github.com/nolabs-ai/nono/commit/9edf3ea93956e3bef7b089e8b4a20a6102416eb7) (`chore(deps): bump jsonc-parser from 0.33.1 to 0.34.0 (#2059)`).

## Carried topic branches

Each is merged with `--no-ff`, in this order.

| Branch | Commit | Fixes |
|---|---|---|
| [`fix/supervisor-audit-rate-limited-capability-requests`](https://github.com/basecamp/nono/tree/fix/supervisor-audit-rate-limited-capability-requests) | `7828b5c12414` | Remainder of nolabs-ai/nono#2043 after #2047: capability requests refused by the approval rate limiter left no audit record |
| [`fix/drain-command-proxy-audit`](https://github.com/basecamp/nono/tree/fix/drain-command-proxy-audit) | `58d03df3571d` | Follow-up to nolabs-ai/nono#1981: command-scoped proxy audit events were never drained into the session audit record |
| [`fix/profile-show-sandbox-policy`](https://github.com/basecamp/nono/tree/fix/profile-show-sandbox-policy) | `148a98d47b93` | `nono profile show` / `profile diff` omitted `linux.sandbox_policy` in text and JSON |
| [`fix/claude-securestorage-config-dir`](https://github.com/basecamp/nono/tree/fix/claude-securestorage-config-dir) | `730021fa4f02` | nolabs-ai/nono#1950: export empty `CLAUDE_SECURESTORAGE_CONFIG_DIR` alongside the injected `CLAUDE_CONFIG_DIR` |
