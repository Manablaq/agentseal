# AgentSeal threat model v1

Every item below is a mandatory release consideration.

## Identity

- identity substitution
- profile digest substitution
- external identity mapping substitution
- endpoint substitution
- stale profile material
- cross-agent certificate replay
- unauthorized certification request

## Policy

- mutable policy replacement
- wrong policy version
- wrong capability
- stale policy
- policy digest mismatch
- malicious policy prompt injection
- oversized policy

## Agent endpoint / evidence

- agent response prompt injection
- validator-targeted response variation
- timeout
- HTTP 404
- HTTP 5xx
- malformed response
- oversized response
- content-type mismatch
- inconsistent validator observations
- endpoint changed after request creation

## Consensus

- leader fabricates PASS
- leader fabricates FAIL
- leader omits mandatory checks
- leader evaluates a different policy
- validator performs shape-only validation
- validator accepts leader evidence without independent retrieval

## State

- request replay
- duplicate request
- duplicate certificate
- challenge replay
- revocation replay
- stale certificate treated as active
- expired certificate treated as active
- cross-agent contamination
- cross-policy contamination
- endpoint mutation while certificate remains apparently valid

## Lifecycle

- indefinitely pending request
- indefinitely pending challenge
- infrastructure failure interpreted as semantic failure
- Accepted interpreted as Finalized
- finalized consensus with failed execution interpreted as certificate success

Each threat must eventually be addressed by a deterministic guard, a test, a
runtime proof, or an explicitly documented protocol assumption.
