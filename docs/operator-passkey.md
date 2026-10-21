# Operator passkey sign-in

Manual local enrollment uses a dedicated `operator@example.org` account, separate
from the synthetic acceptance users. No real email or Google identity is linked.

1. Open the private `.data/operator-passkey/START.html` in Brave. Copy its private
   registration link and paste it into the address bar. Do not share the link.
2. On the native ZITADEL page, create the passkey yourself. Confirm the
   authenticator's user-verification prompt on your device. The relying party is
   `localhost`. No agent should create, emulate or operate your authenticator.
3. Return to the maintainer after registration. Read back the registered passkey
   metadata, verify the unchanged native passkey policy and profile identity, then
   grant only the viewer role and approve that exact stable subject. Reload only
   the owned viewer proxy. Do not approve an empty or unverified registration.
4. Open `http://localhost:4466/c/main/security-lab`, sign in as the operator and
   confirm the passkey prompt yourself. A successful real sign-in is a separate
   acceptance gate; synthetic tests do not prove it.

The private handoff is bound to the current namespace, organization, project and
user IDs. Files use owner-only permissions; enrollment codes, links and runtime
credentials stay outside Git and chat. Reissue an expired invitation only for the
same unapproved account after checking for an existing registration.

## Canceled or failed authenticator prompt

The pinned Login V2 page begins registration automatically on arrival. ZITADEL
consumes the one-time invitation when it issues the WebAuthn challenge, before
successful authenticator confirmation. If the device prompt fails or is canceled,
reloading the page or pressing Continue can show "An error on registering passkey"
with server error `COMMAND-Eeb2a`. This does not prove browser incompatibility.

Check passkey metadata and the operator's code-check events first. If no READY
passkey exists and the account is still unapproved, issue a new invitation for the
same account. Open it once and complete the device prompt. Do not reset the lab,
weaken the native policy or approve the account as a workaround.

During the recorded check, read-only event metadata confirmed a successful invitation check at
07:19:34 UTC, followed by failed reuse checks. The operator reported that the
system authenticator prompt appeared but could not be completed. No READY passkey
or viewer approval existed at diagnosis.

The profile remains disposable. Do not stop or reset the stack during enrollment.
Normal teardown removes the server-side registration; the authenticator may keep
a now-unused localhost entry. Do not present this as durable production access.

References: [ZITADEL registration links](https://zitadel.com/docs/reference/api/user/zitadel.user.v2.UserService.CreatePasskeyRegistrationLink),
[registered passkey metadata](https://zitadel.com/docs/reference/api/user/zitadel.user.v2.UserService.ListPasskeys),
[pinned Login V2 paths](https://github.com/zitadel/zitadel/blob/v4.19.4/cmd/defaults.yaml),
[one-time code consumption](https://github.com/zitadel/zitadel/blob/v4.19.4/internal/command/user_v2_passkey.go).

## Initial manual acceptance

During the recorded check, ZITADEL recorded the operator passkey as verified.
Read-back showed one `AUTH_FACTOR_STATE_READY` key and unchanged native policy.
The exact operator subject received only the active project `viewer` role and was
added to the existing approved-subject list. The owned viewer proxies restarted
successfully in run `20261020T073615Z-a40721`. The consumed invitation was retired.
Unauthenticated requests still receive the sign-in gate. The operator subsequently
reached Headlamp but reported "You don't have permissions to view this resource"
in every resource section. Effective Kubernetes RBAC permits namespaced Pods,
Services and Deployments in `security-lab` and Pods in `spire-system`; cluster-wide
Pods, Nodes, Secrets and mutations are denied. Authentication succeeded, but
resource browsing did not pass manual acceptance. The UI failure remains open.

The owner requested stopping the stack before further diagnosis. Shutdown run
`20261020T073954Z-62e862` stopped both owned VMs and all six loopback listeners.
No namespaces were deleted; VM disks, GRC data and saved reports were retained.
The identity bootstrap credentials are memory-backed; preserved-state restart
recovery was still unverified at that point. See the later restart result below.

## Namespace-browsing fix

The resource failure was traced to Headlamp's default cluster-wide lists, while
the viewer has only namespaced RoleBindings. Component fix `aba6eb8` configures
explicit `security-lab` and `spire-system` browsing defaults and preserves RBAC.
A separate disposable VM passed fresh-browser Pods, Deployments and Services,
all eight live positive/negative HTTP checks and the full 18-scenario security
demo. The primary lab and its private operator profile were not started or reset.

The lab now pins that fix. Its new source snapshot was materialized from the
reviewed commit; private runtime files were preserved unchanged and the previous
source snapshot was retained. See [bounded acceptance](viewer-validation.json).
The standalone test did not establish the combined real-passkey result.

## Combined owner acceptance

The existing operator key was READY, its exact subject approved, its active role
viewer-only and the native policy unchanged before the manual handoff. Startup
needed scoped recovery of memory-backed bootstrap and SPIRE state after the VM
stop. No namespace was deleted and the operator profile was not reset or enrolled
again. Preflight reached 16/16 ready containers, 4/4 healthy application checks
and 6/6 verified source pins.

The maintainer then confirmed passkey sign-in in Brave and successful access to
Pods, Deployments and Services. This is a real owner-reported browser check; the
agent did not operate the authenticator. It closes `asl-tyd`. It does not repeat
the earlier automated denial cases or the full-portfolio run. See the separate
[owner acceptance record](viewer-owner-acceptance.json).

## Preserved-profile restart

The launcher now verifies the existing native policy with the already-mounted
Login service credential, held in memory only. A known empty SPIRE memory state
is restored without deleting namespaces. Unknown state, partial registrations,
foreign ownership or policy failure stops startup without a reset or fallback.

A controlled security-VM stop/start passed, then all 18 security scenarios passed.
The original profile bytes, READY passkey, viewer-only grant and exact approval
were read back unchanged. Final health was 16/16 containers, 4/4 application
checks and 6/6 source pins. GRC stayed running. This closes `asl-63y` for that bounded
restart case; it does not claim a new manual authenticator ceremony after restart.
See [restart evidence](restart-validation.json). Normal teardown still removes
the disposable server-side identity registration.
