# AgentSeal architecture v1

Status: frozen for AgentSeal v1 core implementation.

## Protocol question

AgentSeal answers:

> Did this exact wallet-bound agent endpoint demonstrate capability X under immutable policy Y?

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

AgentSeal v1 does not treat an arbitrary external agent identifier as proof of
ownership.

The authoritative v1 subject is the GenLayer transaction sender.

A later adapter may associate finalized AgentSeal results with ERC-8004 only
after independently verifying the external identity, current owner or operator,
profile material, and endpoint binding.

## Identity binding

The authoritative certificate subject is:

`gl.message.sender_address`

A certification additionally binds:

- exact profile digest;
- exact HTTPS endpoint;
- capability ID;
- policy ID;
- policy version;
- manifest identity.

Changing consequential profile or endpoint material means the old certificate
does not apply to the changed binding.

## Capability policy

Every activated capability policy is immutable.

A policy update creates a new version.

A request binds:

- agent wallet;
- profile digest;
- endpoint;
- capability ID;
- policy ID;
- policy version;
- manifest ID;
- assessment ID.

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

Assessment:

PENDING
  -> PASS -> ACTIVE certificate
  -> FAIL -> FAILED
  -> INCONCLUSIVE -> bounded retry or INCONCLUSIVE_FINAL
  -> deadline -> EXPIRED

Certificate:

ACTIVE
  -> EXPIRED
  -> challenge opened while certificate remains active
       -> PASS -> ACTIVE
       -> FAIL -> REVOKED
       -> INCONCLUSIVE -> bounded retry, then ACTIVE if exhausted

Opening a challenge alone does not revoke or suspend a certificate.

Infrastructure failure alone cannot revoke an otherwise valid certificate.

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

Transport failure, timeout, non-success HTTP status, unavailable manifest
evidence, or evaluator/provider failure is INCONCLUSIVE.

A successfully returned agent protocol response with a consequential binding
mismatch or malformed required protocol payload is FAIL.

Unavailable evidence must never become PASS.

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
