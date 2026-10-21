# Agent instructions

- Read AGENTS.local.md if present. Never commit local instructions or secrets.
- Local demos only. No push, publication, cloud deployment or model API calls without explicit authorization.
- English artifacts, plain hyphens, original code and public documentation only.
- PR bodies use one concise paragraph. Avoid calendar dates in prose and commit subjects; preserve timestamps in raw evidence and Git metadata.
- Beads is private by default. Labels local/private/security/personal always block export; public requires an explicitly reviewed ID and title. Export only the minimal public projection with tools/publication.py.
- Keep undisclosed findings, reproduction details, internal paths, raw diagnostics and local access instructions in ignored owner-only storage. Never include them in PRs, docs, screenshots, CI artifacts or public task text.
- Run the publication boundary check on staged content before commits and on the exact branch/history before any approved push. Passing a scan never authorizes publication. Never push backup refs or all refs.
- Leave source repositories unchanged. Materialize only reviewed locked commits.
- VM operations must use this repository's owned LIMA_HOME, never the default Lima home.
- Stop only owned processes/VMs. Preserve persistent GRC and VM data. Only the owned synthetic security/identity namespaces are disposable during down/reset-security. No global cleanup.
- Do not install AI Assurance profiles. Evidence never grants execution authority.
- Synthetic identity acceptance uses only the fixed isolated fixture. Never reset, renew or alter the owner identity to pass a demo. Preservation, freshness and cleanup failures must fail the run.
- Test source tampering, ownership, process identity, failure reporting and dependency ordering.
- Before local commits run unittest, Ruff and git diff --check. Never bypass hooks.


Use `bd --sandbox` for this local tracker. No automatic sync or push.
