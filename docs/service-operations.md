# Service operations

Use **Versions & health** from the local panel. Service cards offer Restart and
View logs; expand a container for its own controls. A shared status line reports
progress and failures. The log dialog supports refresh and keyboard dismissal.

| Target | Restart behavior |
|---|---|
| Engineering OS | Stop the exact owned fixture process, wait for port release, start it again |
| Viewer | Reconnect the host viewer and shared identity proxy |
| FHIR, authorization and notes workloads | Restart the selected owned deployment and wait for rollout |
| Headlamp, ZITADEL Login | Roll out the deployment, then reconnect viewer/identity forwarding |
| GRC backend/worker | Restart their shared deployment; persistent database and attachment claims remain |
| GRC frontend | Restart only the selected deployment; persistent claims remain |
| GRC TLS | Wait for the TLS rollout, then reconnect its fixed HTTPS tunnel; persistent claims remain |
| PostgreSQL, ZITADEL, SPIRE server/agent | Logs available; individual restart disabled because temporary identity state would be lost |

Restart never deletes a namespace, volume, credential, profile or saved report.
After unexpected VM power loss, the existing explicit stack recovery still applies.
A ready rollout is not a new passed scenario suite or compliance result.

## Boundaries

`POST /api/service` accepts exactly `action` (`restart` or `logs`) and a fixed
service ID. Host, Origin, session token, fetch context and the 1024-byte JSON limit
are the same as the existing browser controls. No path, pod, selector, command,
namespace or CLI arguments come from the browser. A shared filesystem lock refuses
parallel mutations and full demos. Logs use at most two concurrent requests.

Kubernetes operations use only this lab's Lima home, fixed VM and namespace.
Both namespace and controller ownership are checked. A restart patch tests the
controller UID and resource version before adding one rollout annotation; other
annotations remain unchanged. The runner waits up to 120 seconds for rollout.
Headlamp/Login restarts reconnect their pod-bound local forwards. Persistent GRC
claims are not reset. A successful GRC TLS rollout reconnects only
`it-grc-https.service` in the owned VM so forwarding does not retain an old pod
connection. Host processes retain the existing PID identity protection.

## Log privacy

The browser receives a diagnostic projection of at most 100 recent lines and
32 KiB. Container samples cover 15 minutes. The dashboard uses its retained host
log; the viewer shows Headlamp container diagnostics. Raw messages, URLs, JSON
fields, tokens, credentials, request data, pod specs and stderr are never served.
Only parsed timestamps, known severity labels, recognized diagnostic categories
and HTTP response codes can appear. Unclassified content is counted and hidden.
An empty view means no recognized signals in the sample, not proof of health.
Original private logs remain unchanged.


## Offline local access

The current locked component driver limits its viewer and identity forwarders to
8 hours (`scripts/kubernetes_ui.py` and `scripts/zitadel_demo.py` in mcp-svid-auth).
After that interval a VM can still show ready workloads while its host interfaces
are no longer listening. Other interruptions can produce the same observation.

The page recommends **Reconnect local access** only when the security VM and all
expected workloads are ready, at least one viewer/identity listener is stopped,
and none of the three interface checks is degraded, unknown or missing. A stopped
VM still needs the regular Start action. An authentication or workload failure
needs investigation; it does not trigger a proxy recovery suggestion.

The button submits the existing session-protected `restart` action for `viewer`.
It validates the existing identity and reconnects owned forwarding through
`ui-stop` and `ui`, under the shared operation lock. It never restarts protected identity pods or resets their data.
Recovery is explicitly requested by the user; observations alone never execute it.
The notice disappears on the next fresh successful health observation. Stale or
unavailable inventory hides the guidance. No new command or API authority is added.


## Desktop tool discovery

Desktop sessions can omit Homebrew and system directories from `PATH`. The
launcher preserves explicitly selected tools and appends stable local-user,
Homebrew and system tool directories. Empty and relative entries are excluded.
The same path is used by monitoring, source verification, CLI checks and spawned
operations. No shell initialization files are executed and no secrets are added.


## Expiring synthetic identity credentials

The locked identity driver creates bootstrap and Login PATs with a two-day
lifetime. A ready pod and a successful discovery response do not prove those
credentials remain valid. Reconnecting forwarding cannot renew an expired PAT.
A confirmed expiry needs an explicit renewal of the disposable test profile;
unknown authorization or policy failures must not trigger an automatic reset.

The runtime page reads the bootstrap and Login PAT expiration timestamps from the
owned ZITADEL database projection. It displays a local date and countdown, warns
at 24 hours remaining and marks elapsed dates Expired. Unknown includes missing,
ambiguous, malformed or unavailable metadata. A stopped VM pauses the observation.
Expired or unknown metadata suppresses the proxy reconnect suggestion.

The observer verifies the pinned snapshot and database controller ownership. Its
fixed query runs in a read-only transaction with a 3-second statement limit; no
PAT value, account ID or secret column is selected. The browser receives only
fixed labels, states and validated expiry timestamps. This adapter targets the
locked ZITADEL projection schema; an incompatible schema returns Unknown. File
modification times and assumed two-day lifetimes never determine the displayed
expiry. Expiration metadata does not attest revocation, mounted-token identity or
successful sign-in. Observations refresh with health every 15 seconds; no
background notification runs when the panel is closed.

The normal Stop / Start cycle recreates synthetic security and identity state
while preserving GRC storage. Targeted `reset-identity` also removes the synthetic
identity namespace. Retain a private database/configuration backup when preserving
an old demonstration profile matters. Never include that backup in Git or a
browser diagnostic response.

## Host memory

Heavy local models compete with the VMs for memory. During an earlier recovery,
a model used approximately 10 GiB and repeatedly reloaded after a model-only stop.
The shared Ollama service was paused only after explicit user approval. No model
files or launch-agent configuration were removed. Shared runtimes must not be
stopped automatically by the lab.

Both owned VMs retain their original 4 GiB allocation. Temporarily reducing GRC
to 2.5 GiB did not resolve the observed transport failure and was reverted. This
is a local observation, not a portable minimum-memory claim. Full-run results are
recorded separately in the validation report.

## Owned VM transport recovery

On this host, Lima 2.2.1 repeatedly logged `accept: operation not supported on
socket` for SSH-over-VSOCK forwarding. A VM reported as Running could still fail
SSH and Kubernetes observations. Both owned VMs were gracefully restarted with
`ssh.overVsock: false` in their local runtime configuration. Lima documents this
[transport setting](https://lima-vm.io/docs/config/port/). Locked source profiles
were not changed.

The security namespace reset was separately approved because it deletes synthetic
identities, keys and notes. VM disks and persistent GRC data were preserved. A
transport error never authorizes an automatic identity reset.
