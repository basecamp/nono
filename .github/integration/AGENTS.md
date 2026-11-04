# The fork's integration recipe

This directory belongs to the fork. basecamp/nono's `integration` branch is rebuilt from upstream
`main` plus the topic branches listed in `topics`, so the fork's builds never wait on upstream.
A PR that changes this directory (a carry PR: adding, reordering or dropping a topic, or changing
the rebuild) follows the fork's rules, not upstream's contribution workflow:

- Upstream's NEP requirement, DCO sign-off and disclosure on the upstream issue apply when a
  change is submitted to nolabs-ai/nono: to that submission and the topic branch's commits in it.
  They don't apply to a carry PR, which submits nothing upstream.
- Review a carry PR for what it changes here. The topic exists and merges onto current upstream
  in recipe order: check that with a real dry run, `.github/integration/rebuild --layer <the PR's
  head>` without `--push`, which fetches upstream and merges every topic. `test-rebuild` is
  separate: it checks the rebuild's own logic against synthetic repositories, not the recipe.
  The topic's line says what it fixes and where it stands upstream, accurately, because it is
  copied into INTEGRATION.md.

This note covers this directory only. The fork's two workflows
(`.github/workflows/build-integration.yml`, `rebuild-integration.yml`) are fork CI, not a carry,
and a change to them gets an ordinary review. Everything else is upstream's, rebuilt on every
run, and upstream's AGENTS.md governs it.
