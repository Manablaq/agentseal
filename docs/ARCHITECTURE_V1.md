# AgentSeal architecture v1

Status: pre-implementation architecture candidate.

## Protocol question

AgentSeal answers:

> Has this exact bound agent demonstrated capability X under immutable policy Y?

AgentSeal does not claim that an agent is universally trustworthy, safe,
honest, competent, or legally compliant.

## V1 topology

V1 starts with one deliberately compact GenLayer Intelligent Contract.

This is intentional:

- minimize deployment payload;
- minimize GenVM complexity;
- avoid an unnecessary monolith;
- avoid required IC-to-IC calls;
- keep certification state and semantic consensus under one authority.

The contract may be split later only when measurement proves that doing so is
safer and the runtime interaction mechanism has been independently verified.

## ERC-8004 position

ERC-8004 is an interoperability target, not a mandatory runtime dependency.

AgentSeal binds an external agent identity reference and immutable registration
material.

A later adapter may integrate AgentSeal results with an ERC-8004 Validation
Registry after the GenLayer core is independently proven.

## Identity binding

A certification must bind at least:

- agent identity namespace;
- agent identity identifier;
- registration digest;
- endpoint;
- endpoint configuration digest.

Changing consequential identity or endpoint material invalidates applicability
of the existing certificate.

## Capability policy

Every activated capability policy is immutable.

A policy update creates a new version.

A request binds:

- capability ID;
- policy ID;
- policy version;
- policy digest;
- identity reference;
- registration digest;
- endpoint digest;
- request ID.

## Consequential verdict

Only:

- PASS
- FAIL
- INCONCLUSIVE

may emerge from semantic evaluation.

PASS may create a certificate.

FAIL never creates a certificate.

INCONCLUSIVE represents insufficient or unavailable evidence and must never be
silently converted to PASS or FAIL.

## Certificate lifecycle

REQUESTED
  -> PASS -> ACTIVE
  -> FAIL
  -> INCONCLUSIVE

ACTIVE
  -> EXPIRED
  -> CHALLENGED
       -> PASS -> ACTIVE
       -> FAIL -> REVOKED
       -> INCONCLUSIVE -> ACTIVE until original expiry

A network failure alone cannot revoke an otherwise valid certificate.

## Consensus requirement

Validators must independently perform substantive evaluation.

A validator must not simply:

- check leader JSON shape;
- check that the leader emitted an allowed enum;
- trust leader evidence;
- trust leader reasoning;
- copy the leader's remote response.

Only exact consequential fields control state.

Narrative explanation is non-consequential.

## Remote-content security

Remote agent output and web content are untrusted.

Required controls include:

- endpoint binding;
- policy binding;
- explicit status handling;
- request size limits;
- response size limits;
- prompt-injection isolation;
- strict structured evaluator output;
- malformed-response handling;
- transient-failure handling.

HTTP 404, timeout, 5xx, or malformed content must not automatically become
FAIL.

Unavailable evidence must not become PASS.

## Finality

Accepted is provisional.

Externally authoritative AgentSeal certificates must be read from finalized
state.

Consensus state and execution success are distinct conditions.

## Explicit V1 exclusions

Until the core certification mechanism is live and proven:

- no staking;
- no slashing;
- no protocol token;
- no governance;
- no required IC-to-IC dependency;
- no EVM settlement adapter;
- no frontend;
- no arbitrary user-supplied evaluator code.
