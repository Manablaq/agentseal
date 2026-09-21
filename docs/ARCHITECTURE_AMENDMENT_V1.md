# AgentSeal v1 architecture amendment

Status: mandatory amendment to the Phase 1 frozen design before assessment implementation.

This document records security and provenance decisions established during
Phase 2 implementation and runtime verification. Where this amendment is more
specific than the original v1 design documents, this amendment governs.

It does not authorize frontend development or Bradbury deployment.

## A1. Manifest content binding

Every policy version binds an exact `manifest_digest` in addition to the
manifest URL, manifest ID, and manifest authority metadata.

The digest algorithm for AgentSeal v1 is SHA-256.

The digest is:

- computed over the exact fetched HTTP response-body bytes;
- encoded as exactly 64 lowercase hexadecimal characters;
- verified before manifest parsing or semantic evaluation;
- independently recomputed by the leader and every validator.

A manifest fetched from the expected URL is not authoritative merely because
the URL, manifest ID, or descriptive authority label matches.

If the fetched body digest does not match the policy-bound digest, AgentSeal
must not evaluate the agent against that body and must not issue a certificate.

A manifest digest mismatch is an evidence-integrity failure and is classified
as `INCONCLUSIVE`, not as behavioral `FAIL` by the agent.

## A2. Evidence authority and trust root

The AgentSeal v1 protocol owner is the policy and manifest trust root.

Creating a policy version is an explicit owner approval of the exact tuple:

- capability ID;
- policy ID and version;
- criteria;
- manifest URL;
- manifest ID;
- manifest authority metadata;
- manifest SHA-256 digest;
- validity horizon;
- maximum certificate TTL.

The `manifest_authority` string is descriptive metadata. It does not by itself
cryptographically authenticate an external publisher.

Content integrity comes from the policy-bound SHA-256 digest. Authority in v1
comes from the protocol owner approving that exact digest and policy tuple.

A future decentralized publisher model must bind authenticated publisher
identities, signing keys, or signatures before claiming publisher-level
cryptographic provenance.

## A3. Canonical remote URL policy

Remote URLs that can drive validator retrieval must be deterministically
validated before use.

The v1 baseline requires:

- HTTPS;
- a canonical lowercase DNS hostname;
- no URL credentials or userinfo;
- no fragment;
- no explicit port;
- no whitespace;
- no IP-literal hostname;
- no single-label hostname;
- no localhost or local-use hostname accepted by the contract policy;
- bounded URL length;
- syntactically valid bounded DNS labels.

The manifest-policy core already applies these rules to manifest URLs.

The assessment endpoint must receive equivalent deterministic URL validation
before assessment implementation is considered complete.

## A4. DNS and network-isolation boundary

Lexical hostname validation is not proof that DNS resolution will always map
to a public network address.

AgentSeal therefore does not claim that contract-side URL parsing alone solves
DNS rebinding or all SSRF-style network risks.

Bradbury/runtime network-egress behavior must be verified before backend freeze.
If the runtime cannot provide an acceptable network-isolation guarantee, the
protocol must adopt an additional endpoint restriction before release.

## A5. Public-suite and anti-gaming scope

AgentSeal v1 does not claim hidden tests, secret test cases, or unpredictable
evaluation challenges.

The v1 manifest is versioned, policy-bound evidence. Its cases may be public.
The deterministic two-case selection mechanism exists for reproducibility and
bounded evaluation cost; it is not a secrecy or anti-overfitting mechanism.

A v1 certificate therefore means only that the exact bound wallet and endpoint
demonstrated the named capability under the exact policy, manifest, and
selected cases used by the recorded assessment.

It must not be presented as proof of general capability outside that scope.

Public-suite overfitting is a known limitation of the v1 certificate meaning,
not a property that AgentSeal claims to prevent.

Any future hidden, randomized, rotating, or challenge-generated test model
requires a new explicit protocol design and trust analysis.

## A6. Failure classification refinement

The following governing-evidence failures are `INCONCLUSIVE`:

- manifest transport failure;
- manifest non-success HTTP response;
- empty manifest body;
- manifest SHA-256 mismatch;
- manifest body that cannot be safely parsed;
- manifest metadata that does not match the bound policy.

These conditions prevent trustworthy evaluation and therefore do not establish
behavioral failure by the agent.

A successfully returned agent protocol response with wrong consequential
binding remains `FAIL` as defined by the original protocol specification.

## A7. Runtime facts established before this amendment

The pinned development stack has directly demonstrated:

- `response.status` as the web-response status API;
- response body may be absent and must be checked before decoding;
- non-success HTTP response can be classified as `INCONCLUSIVE`;
- empty successful response can be classified as `INCONCLUSIVE`;
- independent validator rerun can agree with identical observations;
- independent validator rerun rejects changed observations;
- nondeterministic validator closures pass Direct Mode pickling checks;
- SHA-256 can hash exact fetched response-body bytes;
- changed manifest bytes produce a different independently observed digest.

These Direct Mode results do not substitute for live Bradbury multi-validator,
resource, gas, execution, or finality verification.

## A8. Remaining pre-assessment security gates

Before the consequential assessment path is implemented, the implementation
must still define and verify:

- deterministic validation of the subject endpoint URL;
- endpoint request and response wire schema;
- exact manifest parsing schema and required fields;
- manifest case-count enforcement;
- deterministic two-case selection from contract-generated assessment state;
- response-body and request-size bounds;
- malformed UTF-8 and malformed JSON behavior;
- prompt-injection-resistant evaluator instructions and structured output;
- exact consequential result encoding;
- lifecycle storage schema and replay guards.

No unresolved item in this section may be silently replaced by an assumption.

## A9. Remaining release gates

Before backend freeze and frontend work:

- live Bradbury PASS must be finalized with successful execution;
- live Bradbury FAIL must be finalized with successful execution;
- live Bradbury INCONCLUSIVE behavior must be proven;
- live challenge/revocation behavior must be proven;
- deterministic expiry must be proven;
- deployment source and encoded payload sizes must be measured;
- deployment resource behavior must be preflighted;
- runtime network-egress assumptions must be verified or further restricted;
- canonical deployed address and exact source hash must be recorded.

Accepted remains provisional and is never equivalent to Finalized.
