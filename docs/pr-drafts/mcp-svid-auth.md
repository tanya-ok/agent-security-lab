# mcp-svid-auth PR drafts

## fix: Scope Headlamp browsing to lab namespaces

Initialize Headlamp browsing defaults to security-lab and spire-system so fresh sessions request the namespaces allowed by existing RBAC. Recover invalid saved settings and return a fixed error when storage is unavailable, without expanding permissions, and keep task exports local. Combined checks passed 562 Python and 8 JavaScript tests, lint, types and strict documentation; manual passkey/resource browsing and restart checks passed separately. Review the diff before publication, then pin the actual approved published commit in the lab.

## chore: Propose scoped AI Assurance review and exclude local state

Document a scoped evidence plan for audiences, credentials, token isolation and audit boundaries, and exclude .ai-assurance from source distributions with archive regressions. Combined viewer/proposal checks and strict documentation passed. The proposal pins a locally verified AI Assurance revision; check its remote availability before adoption and publish the prepared base before opening. Task exports stay local. No profile is installed, applicability approval is not granted and no execution evidence is created; GitHub CI has not run.
