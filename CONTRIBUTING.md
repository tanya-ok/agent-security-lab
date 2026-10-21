# Development

```sh
uv sync --locked
uv run python -m unittest discover -s tests -v
uv run ruff check src tests lab
uv run ruff format --check src tests lab
node --check web/app.js
node --check web/runtime.js
```

Change source pins only after reviewing a new component commit. Never overwrite
a dirty snapshot to make verification pass. Keep application changes in the
component repository, then explicitly update its lock entry. Existing historical
worktrees, snapshots and failed runs stay recoverable; there is no global cleanup.

Keep logs and secrets out of commits. Local Beads is the task tracker; portable
exports omit personal issues and actor fields. A demo report is not an AI
Assurance executed record or permission to change applicability.

For first-run debugging, inspect `.data/latest.json`, then that run's numbered
private log. Do not paste secrets, complete API responses or private VM config.
All publication and pushes require explicit maintainer authorization.

Control changes also need browser acceptance: cancel a run with Stop, verify the
panel stays online, restart the stack, then complete all demos. Keep raw logs
private and record only scoped, synthetic results in validation documents.

For service controls, verify an owned host restart, a Kubernetes rollout, shared
operation exclusion and safe log rendering. Keep free-form log text out of every
browser response. Test namespace/controller ownership and UID/revision guards.

GitHub CI runs the local launcher regression suite only. It does not provision
VMs, run the full security portfolio, use a physical authenticator or establish
production readiness. Repeat the owned local integration and browser checks for
runtime changes. See [security reporting](SECURITY.md) for private reports.

## Documentation

`make docs-check` builds the Zensical site strictly from `docs/`. Preview with
`uv run --locked --group docs zensical serve`. GitHub Pages is the planned
destination; CI builds the site but does not deploy it. Publication needs explicit
maintainer approval.

Restart recovery must reject foreign ownership, partial registrations and policy
failures. Its only write path recreates the fixed workload registrations when
the owned SPIRE registry is empty and its public bundle changed. Identity reuse
verifies native policy with the existing Login service credential in memory; it
never provisions an account, grants a role or resets a profile.
