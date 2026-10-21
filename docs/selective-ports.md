# Selective ports onto current main

Local only; no push or PR creation.

The earlier 22-head compatibility matrix is a historical snapshot. After checking
old-only code against current main, no missing runtime behavior was selected.
Current guards and newer tests are retained. Old branches remain intact.

One useful documentation change was missing: Engineering OS ownership guidance.
It now lives on `codex/ownership-boundary-docs`, one commit above current main.
The original SVG is retained, with a concise explainer that makes ownership an
explicit team agreement rather than an enforced security rule. No application,
CI, dependency, lockfile, fixture or secret-scanning code changed.

| Project | Historical branch | Disposition |
|---|---|---|
| hipaa-fhir-mcp | `docs/development-review-2026-10-04` | Superseded: current runtime includes schema-validated/minimized responses, transport separation and more audit regressions. |
| hipaa-fhir-mcp | `feat/kubernetes-security-lab` | Runtime files equal current main; exclude obsolete installed assurance scaffold and historical documentation reversions. |
| hipaa-fhir-mcp | `fix/fhir-response-boundary` | Already shipped and extended: original response fix is in the historical lab lineage; current schema/audit/runtime tests replace the old implementation. |
| mcp-spiffe-bridge | `codex/bridge-tls-rotation` | Superseded: current main includes rotation and stronger TLS session, socket lifetime, key/bundle validation, reconnect and immutable config checks. |
| mcp-spiffe-bridge | `codex/development-review-2026-10-04` | Superseded by current transport and credential lifecycle; do not replace newer tests or package configuration. |
| mcp-svid-auth | `codex/development-review-2026-10-04` | Superseded: current lab, packaging and auth checks replace this older snapshot; Docker/Podman restoration is excluded. |
| mcp-spiffe-bridge | `codex/kubernetes-security-lab` | Runtime files equal current main; only obsolete assurance state and administrative documentation differ. |
| mcp-svid-auth | `codex/kubernetes-security-lab` | Superseded: preserve current IPv6/NAT64 filtering, audit-tail integrity, signal-safe policy reload and bounded child termination. |
| engineering-os | `claude/typescript-migration-status-6dc0ce` | Runtime superseded; ownership explainer selected from the later planning snapshot on an isolated docs branch. |
| engineering-os | `feat/phase-2-claude-layer` | Runtime superseded by current portfolio adapters, plan workflow and host/index guards; ownership explainer selected separately. |
| engineering-os | `feat/portable-planning-demo` | Planning runtime already shipped. Port only the ownership diagram/explainer; retain current fixture names, secret scanning and CI. |
| it-grc | `feat/it-grc` | Tree equals current main; no duplicate port or empty PR. |
| ecs-contract | `codex/development-review-2026-10-04` | No runtime delta; obsolete assurance state and historical documentation are excluded. ECS remains standalone. |
| ecs-contract | `codex/offline-ownership-demo` | Superseded: current main adds serialization, safe output escaping, richer resolver errors and containerd Vault. Do not restore older variants. |

## Validation

Both Engineering OS packages passed formatting, type checks, tests, build and
package-boundary checks. The anonymization and secret-scan regression suites,
full-tree privacy gate and strict Zensical build passed. The diagram and page
were visually reviewed locally. The new branch merges cleanly with both current
main and the separate assurance proposal. Its runtime/CI/package blobs equal main.

Existing viewer and assurance proposal scopes remain separate. Proposal source
pins still need the actual reviewed published AI Assurance commit; no profile
installation or execution evidence is authorized by this review.
