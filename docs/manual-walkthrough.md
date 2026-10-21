# Try the local lab

Use **Brave** for the existing owner passkey. Keep all inputs synthetic.
Start at [the lab panel](http://127.0.0.1:18879/).

| Step | Open and check | Expected result |
|---|---|---|
| 1. Panel | Overview: inspect the latest **demo** run and expand its stages. | Every recorded stage passes. A passed **up** operation proves startup only. Use its run ID to identify fresh evidence. |
| 2. Health | [Versions & health](http://127.0.0.1:18879/runtime). | 2/2 VMs, 16/16 containers, 4/4 application checks and 6/6 verified source pins. Viewer is Reachable; authentication is separate. Credentials show observed, unexpired lifetimes. |
| 3. Passkey and resources | [Security viewer](http://localhost:4466/c/main/security-lab): sign in with the existing owner passkey. Select `security-lab`, then open Pods, Deployments and Services. | The namespace resources load. Namespaces are limited by RBAC; cluster-wide lists, Nodes and Secrets may be denied. Do not create another passkey or reset the profile. |
| 4. GRC administration | [CISO Assistant](https://localhost:18443/): sign in using the account in the owner-only walkthrough. Open [Compliance assessments](https://localhost:18443/compliance-assessments), then **IT GRC lab evidence: NIST SP 800-66 rev2**. | Open requirements under **164.312** and their evidence. The latest successful run is referenced. Mapped requirements remain **Partially compliant / In review**; unsupported **164.310** controls retain `not_verified`. |
| 5. Task graph | [Engineering OS](http://127.0.0.1:18766/): hover over a graph node, select it, then inspect Projects and Ready. | Fictional tasks show dependencies and details. Ready tasks have no unresolved blocking dependency. |
| 6. Documentation | [Zensical site](http://127.0.0.1:18880/): open Architecture, Passkey sign-in, Publication review and Engineering notes. | Navigation, diagrams, screenshots and links render. This is a static documentation site, with no admin login or editing panel. |
| 7. Diagnostics | Runtime: Engineering OS **View logs**, then **Restart**, only when no demo is running. | A bounded diagnostic view opens; restart completes and health returns. Protected identity services cannot be restarted individually. |

## Local access instructions

The owner-only walkthrough contains local addresses, the synthetic account and
credential-file locations. Keep it outside Git and the documentation build. Never
copy passwords, one-time codes or raw response data into a report or screenshot.
CISO Assistant authentication is separate from the Security viewer passkey.
Local CA trust is an owner step; do not bypass browser warnings.

## Zensical or ZITADEL?

**Zensical** builds the documentation; changes come from Markdown and configuration
in this repository, followed by a strict build. There is no Zensical admin UI.

**ZITADEL** handles passkey sign-in. Enter it through the viewer's login flow.
The local proxy exposes Login V2 and fixed public OIDC routes. Its `/ui/console`
admin route is deliberately blocked. The viewer operator is not an identity
administrator; a blocked console is expected and does not mean viewer access failed.

## Scenarios without a standalone page

The execution trail covers 18 SPIRE/OAuth/FHIR scenarios, 11 synthetic WebAuthn/OIDC
checks, 4 closed Google-provider checks, both independent package demos, a fresh
GRC import and the bounded AI Assurance experiment. Bridge and AI Assurance have
no standalone web interface or health endpoint. Synthetic WebAuthn runs in a separate disposable identity profile and does not sign
your browser in. Real Google login and physical passkey confirmation are owner steps. Existing
authentication-method metadata and the owner profile are compared before and
after synthetic acceptance. The created test fixture must be removed before the
run can pass.

Each full run rolls out only the stateless FHIR service before collecting its
four audit records. This avoids mixing earlier runs' records and preserves the
ZITADEL identity, enrolled passkey and persistent GRC storage. Failed rollout or
failed evidence verification stops the run before GRC imports a result.

## If a check fails

- Inspect the failed stage and Runtime **View logs**. Never infer expiry from a generic authorization error.
- Use **Reconnect local access** only when the panel offers it after diagnosing ready workloads and valid observed credentials.
- A physical passkey prompt must be confirmed by the owner. Do not share one-time codes or credential values.
- **Stop stack** removes disposable security identities, keys and notes. Do not use Stop/Start as troubleshooting while preserving your enrolled passkey. Leave the stack running for this walkthrough.
- Runtime warnings refresh only while the page is open; there is no background notification.

## Recorded owner acceptance

The maintainer previously confirmed real passkey sign-in in Brave and access to
Pods, Deployments and Services. See the [owner-reported result](viewer-owner-acceptance.json).
That observation is separate from the latest automated run and is not a new
physical passkey verification by an agent.
