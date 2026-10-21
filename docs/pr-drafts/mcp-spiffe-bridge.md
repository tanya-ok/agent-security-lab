# mcp-spiffe-bridge PR drafts

## chore: Propose a Node-only transport assurance profile

Document an evidence plan for mTLS peer identity, trust-domain checks, SVID refresh and bounded audit output. Keep the package Node-only and the Python verifier in a separate environment. Lint, types, tests, builds and strict documentation passed. The proposal pins a locally verified AI Assurance revision whose remote availability must be checked before adoption; the prepared base must be published before opening; task exports stay local; private CI collection remains deferred pending a reviewed collector. No profile or Python dependency is installed and no private CI execution is claimed.
