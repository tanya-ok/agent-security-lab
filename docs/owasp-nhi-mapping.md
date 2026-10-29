# OWASP Non-Human Identities Top 10 mapping

How the lab addresses each risk in the
[OWASP Non-Human Identities Top 10 (2025)](https://owasp.org/www-project-non-human-identities-top-10/).
This is the maintainer's reading of the lab against the list. It is not an
assessment, a certification or a claim of full coverage.

| Risk | What the lab does | Where | What stays open |
|---|---|---|---|
| NHI1 Improper offboarding | Agent access is a SPIFFE ID in a policy file. Removing the entry denies new tokens at the next reload; issued tokens expire within 5 minutes. | `mcp-svid-auth` policy reload | No automatic offboarding from an inventory or HR source. |
| NHI2 Secret leakage | Agents hold no static API key. Error responses and audit lines use fixed strings, never tokens or exception text. The diagnostic report is allowlisted. | `mcp-svid-auth` invariants, lab `history.py` | Provisioning secrets listed in the README still exist. |
| NHI3 Vulnerable third-party NHI | Source repositories are pinned by commit and verified by Git blob hashes before execution. Images and Actions are pinned by digest or SHA. | `lab.lock.json`, `Lab.verify` | No SBOM or signature verification of upstream images. |
| NHI4 Insecure authentication | Workloads authenticate with short-lived JWT-SVIDs (ES256, `iat` required, lifetime capped, optional replay rejection). The bridge requires mTLS with X.509-SVIDs. People sign in with passkeys. | `mcp-svid-auth`, `mcp-spiffe-bridge`, ZITADEL | Local provisioning PATs live 2 days. |
| NHI5 Overprivileged NHI | Scopes are per SPIFFE ID and per resource, deny by default. Token exchange can only narrow: the result is bounded by both the subject token and the actor policy. | `policy.py`, `--token-exchange` | Data already inside a granted scope can still be misused. |
| NHI6 Insecure cloud deployment configuration | Out of scope: the lab is local only. Kubernetes runs in an owned Lima VM with read-only Headlamp access. | `docs/architecture.md` | No cloud configuration is tested. |
| NHI7 Long-lived secrets | Access tokens live 5 minutes and bind to one audience. SVIDs rotate through SPIRE. | `mcp-svid-auth` | The README lists the remaining long-lived secrets honestly. |
| NHI8 Environment isolation | Security and GRC run in separate VMs with an owned `LIMA_HOME`. Only synthetic data and `example.org` trust domains are used. | lab launcher | Isolation is local VM separation, not separate accounts. |
| NHI9 NHI reuse | Each workload has its own SPIFFE ID. A token for one MCP server is rejected by another (audience binding, tested in the attack scenario). | attack scenario, resource server | Shared identities are possible if an operator registers them. |
| NHI10 Human use of NHI | People use passkeys through ZITADEL, a separate boundary from workload identity. Delegated tokens name both parties (`sub` and `act.sub`). | ZITADEL, token exchange | Human identity provider tokens are not accepted as a delegation subject yet. |

## Evidence

- `make attack-scenarios` in `mcp-svid-auth` produces a JSON report of the
  required denials and a `not_prevented` list.
- `tests/test_token_exchange.py` covers narrowing, chains, foreign keys and
  audience mismatch.
- The lab demo imports a fresh security report into CISO Assistant for human
  review. A passed run is not certification.
