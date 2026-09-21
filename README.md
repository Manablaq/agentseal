# AgentSeal

**Proof-of-Capability infrastructure for autonomous agents, secured by GenLayer consensus.**

AgentSeal certifies whether a bound autonomous agent demonstrated a specific
capability under an immutable, versioned evaluation policy.

## Current release phase

Backend implementation in progress.

The Phase 1 protocol and architecture freeze is preserved and explicitly
amended by `docs/ARCHITECTURE_AMENDMENT_V1.md` where Phase 2 security and
runtime verification established stronger requirements.

The deterministic policy core has been implemented. Current verified properties
include owner-only policy creation, immutable policy versions, bounded policy
fields, manifest SHA-256 binding, canonical manifest-URL validation, and Direct
Mode security coverage.

The consequential assessment, certificate, challenge, expiry, Bradbury
deployment, and live finality paths remain incomplete and must not be presented
as released functionality.

Frontend development remains forbidden until the backend is completely
implemented, tested, deployed, live-verified, and frozen.

Required order:

Research and feasibility
-> architecture freeze
-> explicit architecture amendment where required
-> Intelligent Contract implementation
-> deterministic verification
-> Direct Mode verification
-> adversarial verification
-> multi-validator runtime verification
-> deployment-resource preflight
-> canonical Bradbury deployment
-> live PASS proof
-> live FAIL proof
-> live INCONCLUSIVE proof
-> live challenge/revocation proof
-> expiry proof
-> backend certification freeze
-> frontend

No frontend code or frontend directory should exist before backend freeze.
