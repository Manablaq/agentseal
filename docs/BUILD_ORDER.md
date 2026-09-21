# AgentSeal mandatory build order

This build order is a release invariant.

## Phase 0 — feasibility baseline

Verify:

- exact GenLayer toolchain;
- current Bradbury behavior;
- runtime limitations;
- deployment/resource constraints;
- consensus semantics;
- finality semantics;
- ERC-8004 interoperability assumptions;
- threat model.

No frontend.

## Phase 1 — protocol and state-machine freeze

Freeze:

- agent identity binding;
- capability policy model;
- certification lifecycle;
- challenge lifecycle;
- expiry behavior;
- evidence model;
- exact consequential verdict;
- recovery semantics.

No frontend.

## Phase 2 — Intelligent Contract implementation

Implement the smallest complete AgentSeal core.

No frontend.

## Phase 3 — backend verification

Require:

- GenVM lint/type validation;
- Direct Mode tests;
- positive cases;
- negative cases;
- malformed input;
- boundary limits;
- replay resistance;
- cross-agent isolation;
- cross-policy isolation;
- unavailable evidence;
- prompt injection;
- leader fabrication;
- validator disagreement;
- expiry;
- challenge;
- revocation.

No frontend.

## Phase 4 — supported-runtime verification

Exercise genuine leader/validator execution.

Persist raw results before decoding.

No frontend.

## Phase 5 — Bradbury deployment preflight

Before authorization:

- exact source SHA-256;
- exact source byte size;
- encoded deployment payload measurement;
- gas/resource preflight;
- fee profile;
- network identity;
- signer balance;
- latest/pending nonce;
- final deployment authorization.

No frontend.

## Phase 6 — canonical Bradbury deployment

Deploy only after every preceding gate passes.

Deployment success requires:

- outer submission accepted by the network;
- GenLayer transaction identified;
- transaction reaches Finalized;
- execution succeeds;
- canonical deployed address is extracted;
- deployed configuration is verified.

No frontend.

## Phase 7 — live backend certification

Require finalized live proofs for:

- PASS;
- FAIL;
- challenge/revocation;
- expiry;
- evidence unavailable / INCONCLUSIVE.

No frontend.

## Phase 8 — backend freeze

Freeze:

- contract source hash;
- canonical contract address;
- policy hashes;
- transaction IDs;
- reproducible verification report.

Only after Phase 8 may frontend development begin.
