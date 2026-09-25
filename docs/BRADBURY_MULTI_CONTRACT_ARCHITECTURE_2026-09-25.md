# AgentSeal Bradbury multi-contract architecture freeze — 2026-09-25

## Status

This document freezes the Bradbury-compatible architecture derived from the
verified monolithic AgentSeal release.

The original monolithic contract remains the semantic reference and MUST NOT be
rewritten or deleted:

- `contracts/agentseal.py`
- SHA-256:
  `61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d`
- source bytes: `93611`
- source lines: `3253`

The split exists because the frozen monolith cannot currently be transported
through Bradbury's supported deployment paths:

- serialized deployment payload bytes: `93621`
- full ConsensusMain calldata bytes: `93860`
- `gen_call` rejected the deployment payload because its hex calldata length
  was `187244`, exceeding that RPC path's `131072` maximum
- ordinary deployment gas estimation returned `BlockPubdataLimitReached`

No Bradbury deployment transaction was submitted while establishing these
facts.

## Architectural rule

Do not split storage or evaluator logic arbitrarily.

The Bradbury release is divided into four Intelligent Contracts:

1. `AgentSealRegistry`
2. `AgentSealChallenge`
3. `AgentSealAssessmentEvaluator`
4. `AgentSealChallengeEvaluator`

The monolithic `AgentSeal` contract remains the behavioral specification used
for parity tests.

## 1. AgentSealRegistry

Authoritative owner of:

- owner identity
- policy count and policy records
- assessment count and assessment records
- live-assessment binding index
- certificate records
- active-certificate binding index
- revocation records

Public behavior retained here includes the logical equivalents of:

- `get_owner`
- `get_policy_count`
- `policy_exists`
- `get_policy`
- `create_policy`
- `disable_policy`
- `get_assessment_count`
- `assessment_exists`
- `get_assessment`
- `get_live_assessment_id`
- `create_assessment`
- `evaluate_assessment`
- `expire_assessment`
- `certificate_exists`
- `get_certificate`
- `get_active_certificate_id`
- `expire_certificate`
- `revoke_certificate`
- `get_revocation`

`evaluate_assessment` remains the user-facing entry point. It performs the
deterministic authorization/state/snapshot checks and then emits a finalized
message to `AgentSealAssessmentEvaluator`.

The parent call does NOT increment the assessment attempt count merely because
it emitted an evaluator request. State consequence is applied only when a
valid authenticated evaluator callback arrives.

The evaluator callback must be accepted only when:

- immediate sender is the configured assessment evaluator
- assessment still exists and is pending
- the returned attempt number equals current `attempt_count + 1`
- the live-assessment binding still points at this assessment
- policy/assessment snapshot bindings are still exact
- verdict is exactly `PASS`, `FAIL`, or `INCONCLUSIVE`

A stale or duplicate callback must not alter consequential state.

A PASS callback issues the certificate inside Registry so assessment and
certificate state remain atomically authoritative in one contract.

Direct certificate revocation remains authoritative in Registry.

Challenge-driven revocation is accepted only from the configured
`AgentSealChallenge` address and must revalidate certificate identity,
binding, active status and challenge metadata before writing the revocation.

## 2. AgentSealChallenge

Authoritative owner of:

- challenge count
- challenge records
- open-challenge-by-certificate index

Public behavior retained here includes the logical equivalents of:

- `get_challenge_count`
- `challenge_exists`
- `get_challenge`
- `get_open_challenge_id`
- `open_challenge`
- `evaluate_challenge`
- `expire_challenge`

Registry certificate and policy state are read synchronously through IC
`view()` calls.

`open_challenge` must verify against Registry that the referenced certificate:

- exists
- is ACTIVE
- is not effectively expired
- is still the active certificate for its binding
- has no conflicting revocation

`evaluate_challenge` performs deterministic challenge/certificate/policy
snapshot checks and emits a finalized message to
`AgentSealChallengeEvaluator`.

A valid FAIL result maps to the original monolithic consequence:

- challenge status becomes `UPHELD`
- open-challenge index is cleared
- a finalized authenticated message requests Registry to record
  `CHALLENGE_CONSENSUS` revocation

A valid PASS result maps to:

- challenge status becomes `REJECTED`
- open-challenge index is cleared

INCONCLUSIVE follows the same attempt-limit behavior as the monolith.

Registry direct revocation may emit a finalized cancellation message to this
contract when an open challenge exists. Challenge callbacks must re-check the
Registry certificate state before applying a verdict so an already-revoked
certificate cannot later be reactivated or inconsistently adjudicated.

## 3. AgentSealAssessmentEvaluator

Contains no authoritative AgentSeal business state.

Its constructor permanently binds it to `AgentSealRegistry`.

It accepts evaluation requests only when:

- `gl.message.sender_address` is the configured Registry

The original user is preserved through the internal-message chain as
`gl.message.origin_address`.

This contract retains the monolith's assessment-specific:

- manifest fetch and digest binding
- strict manifest parsing
- deterministic case selection
- evaluation ID construction
- endpoint POST request construction
- endpoint response validation
- semantic evaluator prompt
- `PASS` / `FAIL` / `INCONCLUSIVE` normalization
- leader/validator exact agreement on consequential verdict and selected case IDs
- `run_nondet_unsafe` validation behavior

The resulting callback to Registry is emitted `on="finalized"`.

## 4. AgentSealChallengeEvaluator

Contains no authoritative AgentSeal business state.

Its constructor permanently binds it to `AgentSealChallenge`.

It accepts evaluation requests only when:

- `gl.message.sender_address` is the configured Challenge contract

It retains the challenge-specific domain separation from the monolith,
including:

- certificate/challenge/policy exact snapshot binding
- challenge selection material
- `agentseal-challenge-v1` evaluation identity
- manifest digest binding
- endpoint binding
- exact leader/validator agreement on verdict and selected case IDs

The resulting callback to Challenge is emitted `on="finalized"`.

## Canonical AgentSeal address

For semantic domain binding that previously used the monolithic contract
address, the split release uses the `AgentSealRegistry` address as the
canonical AgentSeal address.

Both evaluator contracts receive/use this Registry address where the original
algorithm requires the AgentSeal contract address.

This prevents assessment and challenge selection from accidentally depending
on whichever helper/evaluator contract happens to execute the nondeterministic
work.

## Internal message safety

All consequence-bearing IC-to-IC messages use:

`on="finalized"`

Do not use `on="accepted"`.

Every callback must authenticate `gl.message.sender_address`.

Where original-user identity matters, use the preserved
`gl.message.origin_address`.

No callback may trust a user-supplied sender/origin field when the same value
is available from GenLayer transaction context.

Callbacks must be stale-safe and replay-safe.

A failed evaluator child transaction must leave the authoritative
assessment/challenge eligible for a later explicit retry until its existing
deadline or attempt limit makes that impossible.

## Component wiring and deployment order

Use this order:

1. deploy `AgentSealRegistry`
2. deploy `AgentSealAssessmentEvaluator(registry_address)`
3. deploy `AgentSealChallenge(registry_address)` with evaluator unset
4. deploy `AgentSealChallengeEvaluator(challenge_address)`
5. owner calls Registry one-time component configuration:
   - assessment evaluator address
   - challenge address
6. owner calls Challenge one-time evaluator configuration:
   - challenge evaluator address

Configuration rules:

- owner only
- zero/unset before configuration
- exactly once
- non-zero component addresses
- no mutable replacement path in the release contract

No application operation may be allowed before required component
configuration is complete.

## Public-operation mapping

The existing external workflow remains logically recognizable:

1. deploy split release
2. create policy on Registry
3. create stable assessment on Registry
4. evaluate stable assessment through Registry
5. open stable challenge on Challenge
6. evaluate stable challenge through Challenge
7. revoke stable certificate on Registry
8. create drift assessment on Registry
9. evaluate drift assessment through Registry
10. open drift challenge on Challenge
11. evaluate drift challenge through Challenge
12. create fail assessment on Registry
13. evaluate fail assessment through Registry

An external operation may create finalized internal child transactions.
Progress-5 live evidence must track the complete child-message finality chain
before declaring the external operation settled.

## Semantic parity requirements

The split release must preserve the proven monolithic consequences:

- stable assessment -> `PASSED`
- stable certificate -> active
- stable challenge evaluation -> `REJECTED`
- stable certificate remains active after rejected challenge
- direct subject revocation ->
  `REVOKED` / `SUBJECT_SELF_REVOKE`
- drift assessment -> `PASSED`
- drift challenge -> `UPHELD`
- drift certificate ->
  `REVOKED` / `CHALLENGE_CONSENSUS`
- fail assessment -> `FAILED`
- fail assessment issues no certificate

The following remain mandatory:

- approved immutable/versioned evidence bindings
- manifest digest equality
- endpoint response binding
- exact consequential validator agreement
- correctable `INCONCLUSIVE` behavior
- deadline/expiry recovery
- maximum attempt bounds
- replay/stale callback protection
- direct-revocation authorization
- challenge/revocation consistency

## Bradbury deployability gates

Source-byte size by itself is not the release criterion.

Before ANY split-contract Bradbury deployment, every candidate contract must
individually pass:

1. `genvm-lint check`
2. `genvm-lint typecheck`
3. contract-specific Direct Mode regression
4. cross-contract Direct Mode integration
5. full monolith-vs-split behavioral parity suite
6. read-only Bradbury `gen_call` deployment simulation
7. read-only Bradbury ordinary deployment gas estimation
8. payload/calldata size recording
9. no existing deployment/checkpoint reconciliation conflict

No contract is submitted merely because its source is under an approximate
size threshold.

## Repository safety

Development occurs on:

`release/agentseal-bradbury-split-v1`

The synchronized monolithic release commit remains:

`93c2d87b99b1159f1e2cdb2b18f7420e5d2fe510`

Do not rewrite history or replace the existing monolithic evidence.

Do not push the split release to `main` until parity, deployment preflight and
reviewer-readiness gates pass.

## Next implementation checkpoint

Implement the four contracts from the frozen monolithic semantics, then run:

- lint
- typecheck
- source/payload sizing
- Direct Mode component tests
- cross-contract lifecycle tests
- exact stable/drift/fail parity
- read-only Bradbury deployment simulation/estimate for each artifact

Only after all four artifacts independently satisfy the Bradbury read-only
deployment gates may Progress 4 proceed to its first blockchain write.
