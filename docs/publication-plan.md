# Publication review

The maintainer selected direct publication to `main`, without pull requests.
Prepared changes are combined into one commit per project above its reviewed base.
Repository publication and Pages deployment remain separate operations.
[Portfolio review](portfolio-pr-review.md) links to the canonical one-paragraph
PR descriptions; [selective ports](selective-ports.md) records old-branch decisions.

| Project | Prepared scope |
|---|---|
| [mcp-svid-auth](pr-drafts/mcp-svid-auth.md) | Viewer fix, assurance proposal and source-archive exclusion |
| [hipaa-fhir-mcp](pr-drafts/hipaa-fhir-mcp.md) | Synthetic FHIR assurance proposal |
| [mcp-spiffe-bridge](pr-drafts/mcp-spiffe-bridge.md) | Node-only transport assurance proposal |
| [engineering-os](pr-drafts/engineering-os.md) | Assurance proposal and ownership documentation |
| [it-grc](pr-drafts/it-grc.md) | Bounded GRC assurance proposal |
| [ai-assurance](pr-drafts/ai-assurance.md) | Initial main with verified bundle and documentation workflow |
| [agent-security-lab](pr-drafts/agent-security-lab.md) | Initial main after source availability and repository checks |
| [ecs-contract](pr-drafts/ecs-contract.md) | No PR from superseded snapshots; stays standalone |

## Review order

Publish AI Assurance and the five component main branches before the lab.
The lab lock selects those exact final component commits, including the combined
viewer fix. Review the trusted source and the five project-specific proposals.
Private CI collection for bridge and IT GRC remains deferred. Profiles are not
installed and evidence does not authorize actions.

Initial imports require verified repository ownership, visibility, empty targets
and source access. Existing repositories use the reviewed cleaned main bases.
Other branches, tags and hosting references require separate cleanup; replacing
main alone does not erase every copy of old history. Local historical worktrees
and recovery references are retained and are never publication targets.

## Validation

[Manual viewer acceptance](viewer-owner-acceptance.json),
[preserved-profile restart](restart-validation.json) and
[bounded local model review](local-model-review.md) are separate records.
The full portfolio run and component checks do not imply GitHub CI execution,
production readiness or certification. Raw evidence retains its capture metadata.

[Dependency review](dependency-review.md) records upstream updates separately from
the tested runtime baseline.

## Public material boundary

Only files in the publication manifest are candidates for publication. The local
checker verifies their exact contents, rejects private paths and disallowed Beads
fields, and scans generated documentation. A manifest match is not owner approval.

Beads is private by default. `local`, `private`, `security` and `personal` labels
always veto public export. Only explicitly selected `public` issues may contribute
an ID, reviewed title, status, priority and type. Notes, descriptions, actors,
comments, dependencies and diagnostic details never enter the public projection.

Unreviewed findings, reproduction instructions, raw security reports, local access
instructions and detailed dependency audits remain in ignored owner-only storage.
They must not enter public issues, PRs, articles, screenshots or CI artifacts.
Private work is not copied into public titles or summaries. Public text must retain
accurate validation limits and must not imply unresolved work has been fixed.

Before publication, review the exact branch, its reachable history, documentation
and screenshots locally. Secret detection and automated checks reduce risk; they
cannot guarantee that every sensitive detail is recognized. No remote write is
authorized by passing these checks. Never push backup refs or use mirror/all-ref
pushes for this portfolio.
