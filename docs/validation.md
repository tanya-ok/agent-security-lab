# Verified local runs

## Local publication checks

AI Assurance 0.2.1 passed 46 offline regression tests, lint, types, bundle-version
checks, strict documentation and package builds. Its reviewed source pin is
updated in all five adoption proposals and the lab lock. No profile was installed.

Both Pages workflows passed syntax and permission checks plus 48 event/branch/
opt-in cases each. Builds use strict Zensical and public-output checks; upload and
deploy require approved `main` and `PAGES_ENABLED=true`. GitHub execution and site
activation remain unperformed. These are local publication checks, separate from
the recorded full live acceptance below.

The recorded full local run after SSO configuration passed all 24 command stages:
18 shared security scenarios, 11 isolated WebAuthn/OIDC checks, 4 closed
Google-provider checks, both installed package demos, fresh GRC verification/import
and the bounded AI Assurance control experiment. The final gate verified live
interfaces, ready workloads, all six source pins and observed credential lifetimes.
[Safe result summary](latest-validation.json).

The owner profile and authentication-method metadata matched before and after the
entire run. Synthetic identity acceptance used a separate disposable profile,
which was removed after testing. Additional read-only checks verified retained GRC
SSO settings, the explicit subject binding, PKCE S256 with state and nonce, the
exact callback, issuer backchannel, invalid token rejection and recovery access.

131 Python tests, 5 JavaScript tests and Ruff passed. The owner previously
confirmed the existing physical passkey in the organization console and GRC SSO;
this automated rerun did not repeat that ceremony or perform real Google login.
Raw diagnostics remain private. Publication is held for owner approval; GitHub CI
has not run. Historical records below retain their original scope.

## Publication preparation

Internal task exports stay local; only a reviewed minimal public roadmap is
included. Source locks select the prepared local bases, viewer and AI Assurance
revisions. Proposal references use the same reviewed AI Assurance
source revision, with installation still unauthorized. The recorded live
acceptance above predates the current source and workflow changes; it is not a new full run against
the refreshed lock. Remote source availability remains a separate adoption gate.

## Historical acceptance

**Recorded pass.** Run `20261015T073658Z-8a16ba` completed all 20 command steps.

| Boundary | Verified result |
|---|---|
| Shared SPIRE/OAuth/FHIR stack | 18 real-stack scenarios |
| Synthetic human identity | 11 user-verifying WebAuthn/OIDC checks |
| Closed Google-provider setup | 4 checks; no Google contact or real login |
| Independent packages | Bridge TLS/credential lifecycle and FHIR stdio/HTTPS/audit demos passed |
| IT GRC | Fresh report imported; API, NetworkPolicy, role restrictions, ledger and readback passed |
| AI Assurance | Bounded synthetic experiment passed; no profile installation |
| Engineering OS | Fictional dashboard API healthy; 30 graph nodes |
| Launcher | 18 regression tests, Ruff lint/format, JavaScript syntax and secret scan passed |
| Initial read-only hub, before controls | GET 200; foreign Host 403; private runtime path 404; POST 501 |

Acceptance includes cold startup and the corrected owned stop/start cycle.
The security component deliberately stores SPIRE state and bootstrap PATs in
memory. Normal teardown removes its labelled synthetic namespaces before VM
shutdown; persistent GRC evidence and saved reports survive. An unexpected power
loss requires explicit recovery, not silent reset after an authentication failure.
Earlier failed attempts remain in ignored private run history.

All six source working trees and the default Lima VM states were unchanged.
No Git remote, push, cloud deployment, real account, model API or trust-store
change was made. The two owned VMs and loopback hub remain running for inspection.
Source commits and retained artifact hashes are in [validation.json](validation.json).

The browser installer initially removed older shared cache entries. Chromium
revisions 1223 and 1228, their headless shells and FFmpeg 1011 were restored;
automatic browser garbage collection is now disabled and covered by a test.

A passed local run does not prove production readiness, HIPAA compliance, real
Google login, physical-passkey enrollment or model safety. Raw logs, secrets and
full runtime reports stay outside Git under `.data/`.


## Browser controls acceptance

**Recorded pass.** The panel's own buttons completed this cycle:

1. Run all demos, then Cancel & stop during execution. The cancelled run remains
   failed in private history, as expected; scoped teardown passed.
2. Both owned VMs and demo listeners stopped. The panel stayed available.
3. Start stack recreated the synthetic security profile and restarted every interface.
4. Run all demos completed 19 command stages, including 18 security scenarios,
   11 synthetic WebAuthn/OIDC checks, 4 closed Google-provider checks, independent
   package demos, fresh GRC import, the AI control experiment and a 30-node graph.
5. Reloading the page during the run preserved the operation and its live progress.

The current launcher passes 29 unit tests, Ruff lint/format and JavaScript syntax
checks. Live requests confirmed concurrent start 409, foreign origin 403 and
unknown action 400; the CLI also refused a parallel mutation. Prior retained
artifact hashes, all six clean source repositories, pinned source snapshots and
the default Lima VM states were verified. Raw logs and credentials were not served.

Run `20261015T083304Z-e03516` is retained locally. [Browser acceptance data](browser-controls-validation.json)
contains the timestamps, source pins, artifact hashes and lifecycle run IDs.
The stack and control panel remain running. No remote, push, cloud deployment,
model API call, real Google login or physical-passkey enrollment was used.


## Versions and health page

**Recorded verification.** `/runtime` showed 6 verified source pins, 16/16
ready containers, 2 running VMs, 4/4 application checks and a separately reachable
viewer. Running version labels matched observed image repositories and digests.
The page detected an intentionally stopped fixture dashboard (3/4 checks), then
automatically detected recovery (4/4). Expanded image details survived refresh.

44 unit tests, Ruff lint/format, both JavaScript syntax checks and `git diff --check`
passed. Tests cover unverified source versions, missing workloads, absent image
IDs, Kubernetes timeout, malformed health payloads, TLS failure without fallback,
redirect refusal, foreign listeners, private-field filtering and cache expiry.
The runtime API rejected a foreign Host with 403. All six source worktrees and
the default Lima states were unchanged. Demo services remain running.

This change did not rerun the full scenario suite or write new AI Assurance
evidence. [Runtime observations](runtime-validation.json) record the checked
state; these values are dated observations, not promises of continuing health.


## Service controls and diagnostic logs

**Recorded verification.** Browser buttons restarted the fixture dashboard, FHIR,
GRC backend/worker and ZITADEL Login. Kubernetes rollouts completed; Login's
pod-bound proxy forwarding reconnected. Parallel restart buttons were disabled.
A host process shutdown race found during acceptance was fixed and regression
covered; the earlier failed attempt remains in private run history.

All 18 fixed log targets were read successfully through the safe diagnostic
projection. Protected identity restart, unknown targets and foreign origins were
rejected with 409, 400 and 403 respectively. Final observations showed 16/16 ready
containers and 4/4 application checks; source worktrees and default Lima states
were unchanged. 59 tests, Ruff, both JavaScript syntax checks and diff checks passed.
This validates service operations, not a fresh complete scenario suite.
[Acceptance record](service-validation.json) · [Operation boundaries](service-operations.md)


## Local access recovery

**Recorded verification.** The running lab had 16 ready containers but no host
viewer, discovery or Login listeners. The new recovery notice was visible and its
Reconnect local access button completed the existing viewer/proxy restart.
Fresh observations then showed 16/16 ready containers and 4/4 application checks;
the recovery diagnosis cleared. Protected identity pod names and all GRC pod names
were unchanged. All six source worktrees were clean and the retained default Lima
baseline still matched. No identity reset, GRC restart or full scenario rerun occurred.

62 tests passed, including healthy, partially offline, missing, unknown, degraded
and stopped cases for the recovery guidance. Ruff, both JavaScript syntax checks
and diff checks passed. [Before/after acceptance](reconnect-validation.json).


## Desktop monitoring and complete recovery

**Recorded pass.** Run `20261018T062904Z-8dc440` completed all 20 stages:
18 SPIRE/OAuth/FHIR scenarios, 11 synthetic WebAuthn/OIDC checks, 4 closed
Google-provider checks, both independent package demos, fresh GRC import and
readback, the bounded AI control experiment and the 30-node fictional dashboard.
The GRC input hash matches this run's newly retained security report. Earlier
failed attempts remain in private run history.

Desktop tool discovery now includes stable user, Homebrew and system paths without
loading shell profiles. A separate Lima SSH-over-VSOCK failure was resolved in
these two owned VM configurations. Both VMs retain 4 GiB; GRC storage and VM disks
were preserved. The maintainer separately approved recreating the disposable
security namespaces after confirmed synthetic credential expiry and transport
failures. This intentionally replaced synthetic identities, keys and notes.

The panel's session-protected `grc-tls` restart completed in run
`20261018T063600Z-9266a1`. Its new HTTPS tunnel returned 200 with local CA validation
enabled. Persistent claim UIDs and the CA were unchanged. The bounded safe log
endpoint also responded successfully. 66 launcher tests, Ruff lint/format and
both JavaScript syntax checks passed.

Ollama was temporarily paused with explicit permission while the complete suite
ran. Shared model workloads must not be stopped automatically by the lab. The
final dated runtime observation and shared-service restoration are recorded in
[the recovery acceptance record](recovery-validation.json), together with source
worktree and default Lima baseline checks. Health remains separate from scenario
evidence, real sign-in and production readiness.


## Test credential expiry warning

**Recorded verification.** The runtime page reads actual expiration metadata
for the two synthetic ZITADEL service-account PATs. Recorded expiration timestamps remain in the acceptance record; the live panel
reads current metadata. Dates and countdowns render in the viewer's local time;
24 hours remaining triggers the warning. Expired, unknown and stopped states do
not claim successful access. Expired or unknown metadata suppresses proxy
reconnect guidance. No PAT value is selected, returned or renewed.

76 Python tests and 5 JavaScript tests passed with Ruff lint/format and JavaScript
syntax checks. Browser acceptance covered the live current expiry plus expiring,
expired and unknown states in a separate read-only UI fixture. Real credential
values and expiration dates were not changed. The existing viewer reconnect
restored elapsed local forwarding without replacing the identity profile; final
observations showed 16/16 containers ready and 4/4 application checks passed.
No full scenario suite was rerun for this read-only feature.
[Acceptance record](credential-expiry-validation.json).


## Namespace-scoped viewer recovery

**Recorded verification.** Component fix `aba6eb8` passed 560 Python tests,
8 JavaScript regressions, Ruff, strict mypy, identifier checks, a secret scan,
actionlint and a strict docs build. In a separate disposable VM, all 18 security
scenarios passed. A fresh browser displayed Pods, Deployments and Services.
Supported namespaced HTTP reads returned 200; cluster-wide Pods, Nodes, Secrets
and an unrelated namespace returned 403, and a pod mutation returned 405.
Server authorization was unchanged. The test namespaces were removed and the
validation VM stopped; original lab VMs, operator profile and GRC data were
preserved. [Acceptance record](viewer-validation.json).

This is component recovery acceptance, not a new complete 20-stage portfolio
run and not combined physical-passkey acceptance after the fix. The last complete
portfolio run remains the recorded full-run result. GitHub CI is configured for
the launcher regression suite only and has not run on GitHub.

## Preserved-profile restart

The controlled security VM stop/start and automatic startup recovery passed,
followed by all 18 security scenarios. Final health was 16/16 ready containers,
4/4 application checks and 6/6 source pins. Existing operator profile bytes,
READY passkey, viewer role and approval were preserved; GRC remained running.
Ninety Python tests, including fourteen restart regressions, five JavaScript tests,
Ruff, actionlint and the strict Zensical build passed. See
[restart evidence](restart-validation.json) and [recovery boundaries](restart-recovery.md).
This is separate from the earlier owner-confirmed physical passkey sign-in and
resource browsing, and is not another full-portfolio run.
