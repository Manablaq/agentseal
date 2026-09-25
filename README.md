# AgentSeal

**Proof-of-Capability infrastructure for autonomous agents, secured by GenLayer consensus.**

AgentSeal certifies whether a bound autonomous agent demonstrated a specific
capability under an immutable, versioned evaluation policy.

## Current release phase

The Intelligent Contract backend is implemented and the local multi-validator
supported-runtime verification matrix is complete.

Verified local/runtime properties include owner-only policy creation, immutable
policy versions, bounded policy fields, manifest SHA-256 binding, canonical
manifest-URL validation, Direct Mode security coverage, assessment retry
semantics, certificate issuance/revocation/expiry, challenge rejection/upholding,
permissionless expiry recovery, and finalized stable/drift/fail runtime paths.

The committed `fee-profile.json` is derived from finalized RC7 evidence for the
full 13-operation Bradbury matrix. Its conservative 2× execution-budget envelope
is an AgentSeal release policy, not a GenLayer protocol requirement.

**Bradbury deployment and Bradbury live-finality verification are still
pending.** The project must not be presented as live-network released until
those stages and the final backend audit are complete.

The production fixture endpoint is available at the preserved Vercel project
URL. Its deployed repaired bytes are SHA-256 recorded, but Vercel metadata did
not independently establish a cryptographic Git-commit binding; documentation
must preserve that limitation.

Frontend development remains forbidden until the backend is deployed,
live-verified, audited, and frozen.

Required order:

Research and feasibility
-> architecture freeze
-> explicit architecture amendment where required
-> Intelligent Contract implementation
-> deterministic verification
-> Direct Mode verification
-> adversarial verification
-> local multi-validator runtime verification
-> fee-profile certification
-> canonical Bradbury deployment
-> Bradbury stable PASS/challenge/revocation proof
-> Bradbury drift challenge/upheld-revocation proof
-> Bradbury FAIL proof
-> expiry/liveness proof
-> backend certification freeze
-> frontend

No frontend code or frontend directory should exist before backend freeze.
