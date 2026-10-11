# The fork's integration recipe

This directory belongs to the fork. basecamp/nono's `integration` branch is rebuilt from upstream
`main` plus the topic branches listed in `topics`, so the fork's builds never wait on upstream.
A PR that changes this directory (a carry PR: adding, reordering or dropping a topic, or changing
the rebuild) follows the fork's rules, not upstream's contribution workflow:

- Upstream's NEP requirement, DCO sign-off and disclosure on the upstream issue apply when a
  change is submitted to nolabs-ai/nono: to that submission and the topic branch's commits in it.
  They don't apply to a carry PR, which submits nothing upstream.
- Review a carry PR for what it changes here. The topic exists and merges in recipe order
  (`test-rebuild` is the offline check), its line says what it fixes and where it stands
  upstream, and the rebuild still holds.

Everything outside this directory and the fork's two workflows is upstream's, rebuilt on every
run, and upstream's AGENTS.md governs it.
