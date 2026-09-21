# AgentSeal assessment protocol v1

Status: frozen assessment design before consequential assessment implementation.

This document governs the AgentSeal v1 assessment path together with
`PROTOCOL_SPEC_V1.md` and `ARCHITECTURE_AMENDMENT_V1.md`.

All byte limits below are AgentSeal v1 engineering limits. They are not
represented as universal GenLayer protocol or GenVM limits.

## 1. Production constants

- assessment window: 86,400 seconds;
- maximum semantic evaluation attempts: 3;
- maximum manifest response body: 65,536 bytes;
- manifest case count: minimum 4, maximum 32;
- maximum case task: 2,048 UTF-8 bytes;
- maximum case reference material: 8,192 UTF-8 bytes;
- maximum endpoint request body: 65,536 UTF-8 bytes;
- maximum endpoint response body: 65,536 bytes;
- maximum result output per case: 8,192 UTF-8 bytes;
- maximum evaluator prompt: 131,072 UTF-8 bytes;
- maximum endpoint URL length: 512 characters;
- profile digest: exactly 64 lowercase hexadecimal characters.

## 2. Assessment creation

The public creation API accepts only profile digest, endpoint, policy ID,
policy version, and requested certificate TTL.

The certificate subject is always `gl.message.sender_address`.
Capability, manifest URL, manifest ID, authority, criteria, and manifest
digest come only from the immutable governing policy.

The profile digest is a SHA-256-shaped binding value supplied by the subject.
V1 does not claim independent provenance for the underlying profile material.

Creation requires an existing active policy that has not expired.
The requested certificate TTL must be positive and no greater than the
governing policy maximum.

The assessment deadline is the earlier of creation time plus 86,400 seconds
and the governing policy validity deadline.

Policy disablement prevents new assessments but does not rewrite an already
created assessment. Policy expiry still bounds evaluation and certification.

## 3. Endpoint validation

The assessment endpoint uses the same deterministic lexical URL policy as the
manifest URL: HTTPS, canonical lowercase DNS host, no credentials, no fragment,
no explicit port, no whitespace, no IP literal, no single-label host, no
contract-rejected local-use hostname, bounded URL length, and bounded valid
DNS labels.

This lexical policy is not represented as complete DNS-rebinding or SSRF
protection. Runtime network-egress verification remains a backend-freeze gate.

## 4. Manifest retrieval and exact schema

Leader and validators independently GET the policy-bound manifest URL.
Only HTTP status 200 with a non-empty body no larger than 65,536 bytes proceeds.

Before parsing, SHA-256 of the exact response-body bytes must equal the
policy-bound `manifest_digest`.

The body must decode as strict UTF-8 JSON with no duplicate object keys.
The top-level value must be an object with exactly these keys:
`schema`, `manifest_id`, `authority`, `capability_id`, `policy_id`,
`policy_version`, and `cases`.

`schema` must equal `agentseal-manifest-v1`.
Manifest ID, authority, capability ID, policy ID, and policy version must
exactly match the governing policy.

`cases` must contain 4 through 32 objects in manifest array order.
Each case has exactly `case_id`, `task`, and `reference`.
Case IDs satisfy the normal AgentSeal identifier rules and must be unique.
Task is non-empty and at most 2,048 UTF-8 bytes.
Reference is a string of at most 8,192 UTF-8 bytes.

Any manifest transport, status, size, digest, UTF-8, JSON, duplicate-key,
schema, metadata, case-count, duplicate-case, or field-bound failure is
`INCONCLUSIVE` and uses empty consequential case IDs.

## 5. Deterministic two-case selection

Case selection is public and deterministic. It is not an unpredictability
or anti-overfitting mechanism.

Selection material is canonical JSON with sorted keys and compact separators
containing chain ID, contract address, assessment ID, subject wallet, profile
digest, endpoint, capability ID, policy ID, policy version, manifest ID, and
manifest digest.

The SHA-256 digest of the UTF-8 selection material is the selection seed.
Bytes 0 through 7 interpreted as an unsigned big-endian integer select case A
modulo the case count.
Bytes 8 through 15 interpreted as an unsigned big-endian integer select an
index modulo case-count-minus-one; that index is shifted past case A when
necessary so case B is always distinct.

Selected order is A then B and is not resorted.

## 6. Evaluation ID and replay domain separation

Attempt number is current stored attempt count plus one.

The evaluation ID is exactly:
`agentseal-v1:<chain-id>:<contract-address>:<assessment-id>:<attempt-number>`.

The chain ID and contract address domain-separate responses across networks and
AgentSeal deployments.

If consensus does not complete and storage does not mutate, a later retry of
the same state may reuse that same evaluation ID; no attempt is counted until
a consensus result returns to deterministic execution.

## 7. Endpoint request wire format

The selected agent endpoint receives HTTP POST with
`content-type: application/json`.

The canonical JSON request uses sorted keys and compact separators and contains
exactly: `protocol`, `evaluation_id`, `agent_wallet`, `profile_digest`,
`capability_id`, `policy_id`, `policy_version`, `manifest_id`,
`manifest_digest`, and `cases`.

`protocol` is exactly `agentseal-evaluation-v1`.
`cases` contains exactly the selected A and B objects, each with
`case_id`, `task`, and `reference`.

If canonical request encoding exceeds 65,536 UTF-8 bytes, the result is
`INCONCLUSIVE`; it is not behavioral failure by the agent.

## 8. Endpoint response wire format

Only HTTP status 200 with a non-empty body no larger than 65,536 bytes proceeds.
Transport failure, exception, timeout, non-200 status, or empty/oversized body
is `INCONCLUSIVE`.

A successful body must decode as strict UTF-8 JSON with no duplicate keys.
The top-level object must contain exactly: `protocol`, `evaluation_id`,
`agent_wallet`, `profile_digest`, `capability_id`, `policy_id`,
`policy_version`, `manifest_id`, and `results`.

Every echoed binding must exactly match the request.
`results` must contain exactly two objects in A-then-B order.
Each result contains exactly `case_id` and `output`.
Case IDs must exactly equal selected A then selected B.
Each output must be a string no larger than 8,192 UTF-8 bytes.

After a successful HTTP 200 response, malformed UTF-8, malformed JSON,
duplicate keys, wrong schema, wrong binding, missing or extra result,
substituted case ID, wrong order, or oversized case output is `FAIL`.

Response Content-Type metadata is not consequential; exact bytes and exact JSON
protocol validation control interpretation.

## 9. Evaluator boundary

Policy criteria are trusted owner-approved instructions.
Manifest task/reference material and agent outputs are untrusted evidence.
Untrusted evidence is embedded as JSON data and never concatenated as trusted
evaluator instructions.

The evaluator prompt must not exceed 131,072 UTF-8 bytes.
Prompt construction overflow is `INCONCLUSIVE`.

Structured evaluation uses `gl.nondet.exec_prompt(..., response_format="json")`.
The evaluator must return exactly one object with exactly one key: `verdict`.
Allowed values are exactly `PASS`, `FAIL`, or `INCONCLUSIVE`.

Provider failure or any unclassifiable evaluator result is `INCONCLUSIVE`.
`PASS` is permitted only when both selected results satisfy every mandatory
criterion. Established mandatory-criterion failure produces `FAIL`.

## 10. Consequential consensus result

The nondeterministic result contains exactly `verdict`, `case_a_id`, and
`case_b_id`.

Manifest-level `INCONCLUSIVE` uses empty strings for both case IDs.
Once a valid manifest has selected cases, all later PASS, FAIL, or INCONCLUSIVE
results carry the exact selected case IDs.

Leader and validators independently repeat manifest retrieval, digest checking,
parsing, selection, endpoint invocation, binding validation, and semantic
evaluation. Exact consequential fields must agree.

## 11. Assessment lifecycle

Contract-generated assessment IDs start from deterministic contract state;
callers cannot choose assessment IDs.

Storage status starts `PENDING`.
Retryable `INCONCLUSIVE` keeps status `PENDING`, records the last verdict/case
IDs, and increments attempt count.
Third `INCONCLUSIVE` becomes `INCONCLUSIVE_FINAL`.
PASS becomes `PASSED`. FAIL becomes `FAILED`.

Every consensus result that reaches deterministic execution increments the
attempt count exactly once. Validator disagreement or an unfinalized/failed
transaction cannot be treated as a counted semantic attempt.

Only the assessment subject may invoke semantic evaluation or retry.
After deadline, evaluation is forbidden and deterministic expiry cleanup is
permissionless. Expiry changes a still-pending assessment to `EXPIRED`.

Terminal states clear the live-assessment binding.

## 12. Binding and duplicate protection

The live-assessment binding covers subject wallet, profile digest, endpoint,
capability ID, policy ID, policy version, manifest ID, and manifest digest.

At most one live assessment may exist for the same exact binding.
Changing endpoint or profile digest creates a different binding and cannot make
an older certificate apply to that changed binding.

## 13. PASS certificate issuance

Only PASS may issue a certificate, in the same deterministic state transition
that marks the assessment `PASSED`.

The certificate binds assessment ID, subject wallet, profile digest, endpoint,
capability ID, policy ID/version, manifest ID/digest, selected case A/B IDs,
issuance time, and expiry time.

Certificate expiry is the earlier of issuance plus requested certificate TTL
and policy `valid_until`.

FAIL, INCONCLUSIVE, INCONCLUSIVE_FINAL, and EXPIRED issue no certificate.
Externally authoritative certificate use still requires finalized consensus
and successful execution.

## 14. Implementation gates before this freeze may be called implemented

Implementation must still prove duplicate-key rejection, exact manifest schema
validation, exact selection algorithm execution, endpoint URL equivalence with
the hardened manifest URL rules, wire-size enforcement, replay protection,
lifecycle transitions, state isolation, and independent validator disagreement
behavior before the assessment implementation checkpoint is committed.

## 15. Precision rules established before implementation

The following rules remove remaining implementation discretion.

### 15.1 Canonical JSON encoding

Every AgentSeal-generated canonical JSON value used for hashing, request wire
encoding, binding-key derivation, or deterministic selection uses exactly:

- `sort_keys=True`;
- `separators=(",", ":")`;
- `ensure_ascii=True`.

The resulting string is UTF-8 encoded before byte-length measurement or hashing.
Incoming remote JSON is not considered canonical merely because it parses.

### 15.2 Canonical address representation

Every wallet or contract address included in canonical JSON, evaluation IDs,
binding material, endpoint requests, or endpoint-response comparisons uses the
42-character lowercase `0x` representation produced from the runtime Address.

Checksummed and lowercase textual representations of the same address are not
mixed inside consequential wire or hashing material.

Chain ID is an integer inside canonical JSON and its base-10 representation is
used inside the colon-delimited evaluation ID.

### 15.3 Strict JSON scalar typing

Incoming `policy_version` must satisfy `type(value) is int`; JSON booleans are
not accepted as integers even though Python boolean values are integer-like.

Every string field must be an actual JSON string. Arrays and objects must have
the exact required JSON container type. Numeric coercion from strings, floats,
or booleans is forbidden.

Duplicate object keys at any nesting depth are rejected before semantic use.

### 15.4 Deadline equality and validity boundaries

Assessment semantic evaluation is permitted only while both:

- `now < assessment.deadline`; and
- `now < policy.valid_until`.

Therefore equality with either boundary is already expired for evaluation.
Permissionless assessment expiry applies when `now >= assessment.deadline`.

A certificate is semantically active only while `now < certificate.expires_at`.
At `now >= certificate.expires_at`, it must not satisfy an active-certificate
query even if deterministic cleanup has not yet persisted `EXPIRED`.

### 15.5 Collision-resistant live-binding key

The live-assessment and active-certificate binding key is the lowercase SHA-256
hex digest of canonical JSON containing exactly:

- `domain`: `agentseal-binding-v1`;
- `subject_wallet`;
- `profile_digest`;
- `endpoint`;
- `capability_id`;
- `policy_id`;
- `policy_version`;
- `manifest_id`;
- `manifest_digest`.

The JSON uses the canonical encoding and address rules in this section.
Requested certificate TTL is deliberately not part of the identity binding.

### 15.6 Active-certificate uniqueness

At most one semantically active certificate may exist for one exact binding.

Creation of a new assessment for a binding is rejected while that binding has
a certificate whose status is `ACTIVE` and whose `expires_at` is still greater
than `now`.

An expired or revoked certificate does not permanently block recertification.
A pending live assessment for the same binding independently blocks duplicates.

### 15.7 Identifier allocation

Assessment IDs are positive sequential contract-generated integers beginning at
1. Creation increments assessment count exactly once and uses the new value.

Each successful PASS creates exactly one certificate whose certificate ID is
equal to its originating assessment ID. A non-PASS assessment cannot allocate
a certificate ID.

### 15.8 Selection algorithm conformance vector

The selection algorithm from section 5 is frozen together with this known
conformance vector:

- case count: 5;
- selection-material SHA-256:
  `b81c1061141176a097396d3efc70abef311c62c2ec9707b0051c1e0098b4591b`;
- selected case-A array index: 0;
- selected case-B array index: 4.

Implementations that do not reproduce this vector are not AgentSeal v1
selection-compatible.

Runtime verification has also proven distinct A/B indexes for every permitted
manifest case count from 4 through 32.
