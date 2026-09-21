# AgentSeal protocol specification v1

Status: Phase 1 design freeze amended by `ARCHITECTURE_AMENDMENT_V1.md` during core implementation.

## 1. Protocol question

AgentSeal answers exactly:

> Did this wallet-bound autonomous-agent endpoint demonstrate capability X
> under immutable policy version Y?

The answer is scoped to one defined evaluation policy.

It is not a claim of universal trustworthiness or permanent competence.

## 2. Agent identity

The authoritative v1 agent wallet is always:

`gl.message.sender_address`

A caller cannot nominate another wallet as the certificate subject.

Every assessment additionally binds:

- profile digest;
- HTTPS endpoint;
- capability ID;
- policy ID;
- policy version.

## 3. Policy authority

AgentSeal v1 has a protocol owner.

Only the owner may create capability-policy versions.

Once created, a policy semantic contents are immutable.

Changing criteria requires a new version.

A policy may later be disabled for new requests without rewriting previously
finalized history.

## 4. Policy fields

A policy binds at least:

- capability ID;
- explicit version;
- mandatory evaluation criteria;
- authoritative manifest URL;
- manifest ID;
- manifest authority;
- policy-valid-until timestamp;
- maximum certificate TTL;
- active flag.

Certification callers cannot supply or replace the policy evidence source.

## 5. Evaluation manifest

The manifest is versioned evidence bound by the policy before certification.

It contains:

- schema identifier;
- manifest ID;
- authority;
- capability ID;
- policy version;
- bounded test cases.

Each test case contains:

- case ID;
- task;
- reference material.

The first release targets a bounded manifest of 4 to 32 cases.

Each assessment evaluates exactly two cases selected deterministically from the
assessment identity and manifest.

## 6. Endpoint protocol

The bound agent endpoint must use HTTPS.

The evaluation request binds:

- protocol version;
- evaluation ID;
- agent wallet;
- profile digest;
- capability ID;
- policy version;
- selected test cases.

The endpoint response must echo:

- protocol version;
- evaluation ID;
- agent wallet;
- profile digest;
- capability ID;
- policy version;
- one result for every requested case.

A successful HTTP response with mismatched binding fields is a protocol
failure rather than unavailable infrastructure.

## 7. Semantic verdicts

The only consequential semantic verdicts are:

- `PASS`
- `FAIL`
- `INCONCLUSIVE`

`PASS` may issue an active certificate.

`FAIL` never issues a certificate.

`INCONCLUSIVE` never issues a certificate.

No confidence score, tolerance band, approximate match, or narrative reasoning
may convert a non-PASS result into PASS.

## 8. Failure classification

The following are `INCONCLUSIVE`:

- manifest transport failure;
- manifest non-success response;
- manifest content unavailable or unparsable;
- agent endpoint timeout;
- agent endpoint transport failure;
- agent endpoint non-success response;
- evaluator/provider failure;
- evaluator result that cannot be safely classified.

The following are `FAIL` after a successful agent HTTP response:

- wrong evaluation ID;
- wrong agent wallet;
- wrong profile digest;
- wrong capability ID;
- wrong policy version;
- missing requested case;
- substituted case ID;
- malformed agent protocol payload;
- behavioral failure against mandatory criteria.

Infrastructure failure must never silently become `PASS` or `FAIL`.

## 9. Prompt-injection boundary

Agent output, manifest material, web content, and reference material are
untrusted evidence.

Instructions found inside that evidence are data only.

They must never override:

- the evaluation policy;
- the evaluator role;
- the required output schema;
- the consequential verdict rules.

## 10. Independent consensus

The leader performs the complete substantive evaluation independently.

The leader must:

1. retrieve the manifest bound by the governing policy;
2. verify the manifest identity and policy binding;
3. derive the exact two selected test cases;
4. invoke the exact bound agent endpoint;
5. verify the endpoint response binding;
6. evaluate both case results against every mandatory criterion;
7. return the compact consequential result.

Each validator independently repeats those same substantive operations.

A validator must not merely:

- check JSON shape;
- check that the leader returned an allowed enum;
- trust leader reasoning;
- trust leader-provided remote evidence;
- reuse the leader endpoint response;
- accept a confidence score as equivalent to a verdict.

The validator performs its own retrieval, endpoint invocation, and semantic
evaluation before comparing consequential fields.

If independent validator observation cannot safely reproduce the leader result,
the validator must reject equivalence.

## 11. Consequential result

The nondeterministic result is deliberately minimal.

Its consequential fields are:

- verdict;
- case A ID;
- case B ID.

The verdict value must be exactly one of:

- `PASS`
- `FAIL`
- `INCONCLUSIVE`

The selected case identifiers must match exactly.

No fuzzy comparison, tolerance range, confidence threshold, majority of fields,
or approximately equivalent output may transform one consequential result into
another.

Free-form reasoning may be useful operational evidence but is never itself a
state-changing consensus value.

Storage mutation occurs only after the nondeterministic consensus result has
returned to deterministic contract execution.

## 12. Assessment lifecycle

Every certification assessment begins in `PENDING`.

A completed semantic evaluation transitions the assessment to exactly one of:

- `PASS` -> issue an `ACTIVE` certificate;
- `FAIL` -> terminal `FAILED` assessment;
- `INCONCLUSIVE` -> retryable inconclusive assessment.

An inconclusive assessment may be retried only while:

- its deadline has not passed; and
- its maximum attempt count has not been exhausted.

When the attempt limit is exhausted, the assessment becomes
`INCONCLUSIVE_FINAL`.

When the assessment deadline passes before successful completion, deterministic
expiry cleanup moves the assessment to `EXPIRED`.

Neither `INCONCLUSIVE_FINAL` nor `EXPIRED` may create a certificate.

## 13. Certificate lifecycle

A certificate created by a finalized PASS begins as `ACTIVE`.

An active certificate may become:

- `EXPIRED` when its deterministic expiry time passes;
- subject to one open challenge;
- `REVOKED` only after a finalized challenge evaluation returns `FAIL`.

Opening a challenge does not itself revoke, suspend, or invalidate the
certificate.

A challenge evaluation returning `PASS` closes the challenge and leaves the
certificate active.

A challenge evaluation returning `INCONCLUSIVE` may be retried only within its
bounded attempt and deadline window.

If an inconclusive challenge exhausts its retry window, the challenge closes
without revocation and the certificate remains subject to its original expiry.

## 14. Liveness and bounded recovery

Every assessment stores:

- creation time;
- deadline;
- attempt count;
- maximum attempt count.

Every challenge stores equivalent bounded lifecycle information.

No request or challenge may remain permanently actionable.

After a deadline, deterministic cleanup must be callable without requiring a
successful nondeterministic evaluation.

Transport, provider, or evidence unavailability therefore cannot lock the
protocol forever.

Retries are explicit state transitions.

A failed transaction must never be blindly rebroadcast merely because its
outcome is unknown.

## 15. Certificate lifetime

Certificate lifetime is bounded by the governing policy.

The effective certificate expiry is no later than both:

- issuance time plus the requested certificate TTL; and
- the governing policy validity deadline.

The requested TTL must also respect the policy maximum certificate TTL.

A certificate therefore cannot outlive the validity horizon of the policy
under which it was issued.

## 16. Replay protection

Assessment IDs are generated by contract state.

Challenge IDs are generated by contract state.

Callers cannot choose either identifier.

Every assessment is bound to the exact:

- agent wallet;
- profile digest;
- endpoint;
- capability ID;
- policy ID;
- policy version.

Only one live assessment for the same exact binding may exist at a time.

Only one open challenge for a certificate may exist at a time.

A terminal assessment cannot be settled again.

A resolved challenge cannot be resolved again.

A revoked certificate cannot be reactivated by replaying an older PASS result.

An expired certificate cannot be extended by replaying its original issuance.

## 17. State isolation

State belonging to one agent must not mutate another agent.

State belonging to one assessment must not mutate another assessment.

State belonging to one capability or policy version must not mutate another
capability or policy version.

State belonging to one certificate must not mutate another certificate.

State belonging to one challenge must not mutate another challenge.

All mutating methods must verify the complete relevant binding before applying
any consequential transition.

## 18. Finality and execution

`Accepted` is provisional and is not equivalent to `Finalized`.

An externally authoritative AgentSeal certificate requires finalized consensus
and successful execution.

A consensus decision whose execution failed is not application success.

Reviewer evidence must preserve both transaction lifecycle and execution result.

Production consumers making irreversible trust decisions must read finalized
contract state rather than provisional state.

Transaction identifiers must be persisted before any polling or finality wait.

An unknown write outcome must be investigated read-only before any retry.

Blind transaction rebroadcast is forbidden.

## 19. V1 scope exclusions

The initial AgentSeal certification core intentionally excludes:

- staking;
- slashing;
- protocol token;
- DAO governance;
- required synchronous IC-to-IC calls;
- ERC-8004 write adapter;
- ERC-8126 implementation;
- ERC-8273 implementation;
- frontend.

These exclusions reduce deployment size, runtime coupling, and attack surface
while the certification primitive itself is being proven.

No excluded subsystem may be added before the core backend passes its complete
verification and Bradbury finality gates.

## 20. Phase 2 architecture amendment incorporation

`ARCHITECTURE_AMENDMENT_V1.md` is a mandatory part of the AgentSeal v1
protocol definition.

The policy-bound manifest identity now includes:

- authoritative manifest URL;
- manifest ID;
- manifest authority metadata;
- exact SHA-256 digest of the expected manifest response-body bytes.

The SHA-256 digest is encoded as 64 lowercase hexadecimal characters.

The leader and every validator must independently hash the exact fetched body
before parsing or semantic evaluation.

A fetched manifest whose SHA-256 digest differs from the policy-bound digest
is governing-evidence failure and therefore `INCONCLUSIVE`; it is not evidence
that the assessed agent behaviorally failed.

The protocol owner is the v1 trust root that approves the exact policy and
manifest digest tuple. `manifest_authority` is descriptive metadata and is not
by itself cryptographic publisher authentication.

The deterministic two-case selection from the public immutable manifest is a
reproducibility and bounded-cost mechanism. It is not a hidden-test,
unpredictability, or anti-overfitting guarantee.

Consequently, a certificate is scoped to the exact policy, manifest, and
selected cases recorded for that assessment.

Remote URLs capable of driving validator retrieval require deterministic URL
validation. Contract-side lexical URL validation does not by itself prove DNS
or network-layer isolation; the live runtime assumption remains a backend
freeze gate.
