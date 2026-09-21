# AgentSeal standards positioning v1

Status: Phase 1 standards position retained during core implementation and subject to `ARCHITECTURE_AMENDMENT_V1.md`.

## Core purpose

AgentSeal is a behavioral proof-of-capability protocol.

Its question is deliberately narrow:

> Did this exact wallet-bound agent endpoint demonstrate capability X under
> immutable AgentSeal policy Y?

AgentSeal does not certify universal trustworthiness, legal compliance,
general intelligence, permanent competence, or universal safety.

## ERC-8004

ERC-8004 is treated as an interoperability target.

AgentSeal v1 does not accept an arbitrary external agent identifier as proof
that the caller owns or operates that agent.

The authoritative v1 AgentSeal subject is the GenLayer transaction sender.

A future ERC-8004 adapter must independently verify:

- canonical Identity Registry;
- exact agent ID;
- current owner or authorized operator;
- canonical registration/profile data;
- profile digest;
- endpoint binding.

Only after those checks may an adapter associate an AgentSeal result with an
ERC-8004 identity.

## ERC-8126

AgentSeal does not claim to implement or replace ERC-8126.

The intended distinction is:

- ERC-8126: security/authenticity/risk-oriented verification;
- AgentSeal: demonstrated behavioral capability under an explicit policy.

These systems may complement each other.

## ERC-8273

AgentSeal does not implement ERC-8273.

AgentSeal provides semantic capability evaluation.

A future integration may use a finalized AgentSeal result as evidence in an
attestation-gated execution system.

## V1 identity rule

The authoritative v1 subject is:

`agent_wallet = gl.message.sender_address`

Every certification also binds:

- exact profile digest;
- exact HTTPS evaluation endpoint;
- exact capability ID;
- exact policy version;
- exact policy manifest identity.

## Meaning of a certificate

An AgentSeal certificate means only:

> The signing wallet's bound endpoint demonstrated the named capability under
> the exact recorded AgentSeal policy and test manifest during the recorded
> certification process.

It does not prove performance outside that defined scope.

## V1 provenance and suite-scope clarification

AgentSeal v1 policy provenance is rooted in protocol-owner approval of an exact
policy tuple that includes the SHA-256 digest of the expected manifest bytes.

The manifest authority label is descriptive metadata. AgentSeal v1 does not
claim that this label alone authenticates an external publisher or signing key.

The public deterministic evaluation suite is not represented as a hidden-test
or unpredictability mechanism.

Accordingly, an AgentSeal v1 certificate means that the exact bound subject
and endpoint demonstrated the capability under the recorded policy, manifest,
and selected cases. It does not establish capability outside that scope.
