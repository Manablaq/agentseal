# AgentSeal v1 invariants

Status: mandatory release gates for the v1 certification core.

Every invariant must be enforced by implementation, deterministic validation,
tests, runtime evidence, or an explicitly documented protocol assumption.

## Identity and binding

1. Certificate subject always equals the signing request wallet.
2. A caller cannot certify another wallet as subject.
3. Every assessment binds an exact profile digest.
4. Every assessment binds an exact HTTPS endpoint.
5. Every assessment binds one capability ID.
6. Every assessment binds one policy ID and version.
7. Endpoint responses must echo the exact consequential binding.
8. A binding mismatch after successful HTTP response cannot produce PASS.

## Policy and provenance

9. Only the protocol owner may create policy versions in v1.
10. Existing policy semantic contents cannot be edited.
11. Semantic policy changes require a new version.
12. Certification callers cannot replace the manifest source.
13. New assessments cannot use inactive policies.
14. New assessments cannot use policies past their validity horizon.
15. Manifest identity must match the governing policy.
16. A certificate cannot outlive its governing policy.

## Evidence and failure classification

17. Manifest transport failure is INCONCLUSIVE.
18. Agent transport failure is INCONCLUSIVE.
19. Evaluator/provider failure is INCONCLUSIVE.
20. Unclassifiable evaluator output is INCONCLUSIVE.
21. Successful endpoint response with wrong binding is FAIL.
22. Missing or substituted requested case after successful response is FAIL.
23. Behavioral failure against mandatory criteria is FAIL.
24. INCONCLUSIVE can never issue a certificate.
25. Infrastructure failure can never silently become PASS.
26. Infrastructure failure can never silently become FAIL.

## Consensus

27. The leader retrieves the bound manifest independently.
28. Each validator retrieves the bound manifest independently.
29. The leader invokes the bound agent endpoint independently.
30. Each validator invokes the bound agent endpoint independently.
31. Validators independently perform semantic evaluation.
32. Shape-only validator approval is forbidden.
33. Leader-provided evidence is not authoritative to validators.
34. Leader narrative reasoning is not consequential consensus state.
35. PASS, FAIL, and INCONCLUSIVE are exact consequential verdicts.
36. Selected case IDs are exact consequential values.
37. Fuzzy matching cannot transform one consequential verdict into another.
38. Storage mutation occurs only after nondeterministic consensus returns.

## Lifecycle and liveness

39. Every assessment has a bounded deadline.
40. Every assessment has a bounded maximum attempt count.
41. Every challenge has a bounded deadline.
42. Every challenge has a bounded maximum attempt count.
43. Expired assessments can be deterministically closed.
44. An abandoned challenge cannot permanently suspend a certificate.
45. Opening a challenge alone cannot revoke a certificate.
46. Challenge infrastructure failure cannot revoke a certificate.
47. Only finalized challenge FAIL may semantically revoke a certificate.
48. A certificate cannot remain active beyond deterministic expiry.

## Replay and isolation

49. Callers cannot choose assessment IDs.
50. Callers cannot choose challenge IDs.
51. A terminal assessment cannot be settled twice.
52. A resolved challenge cannot be resolved twice.
53. A revoked certificate cannot be restored by replaying an older PASS.
54. An expired certificate cannot be extended by replaying old issuance.

## Finality and execution

55. Accepted is not equivalent to Finalized.
56. Reviewer-facing success requires finalized consensus.
57. Reviewer-facing success also requires successful execution.
58. Transaction identifiers are persisted before finality polling.
59. Unknown write outcomes are investigated read-only before retry.
60. Blind transaction rebroadcast is forbidden.

## Deployment and release

61. Exact contract source bytes are measured before deployment.
62. Exact encoded deployment payload size is measured before deployment.
63. Deployment resource and gas behavior is preflighted before authorization.
64. No engineering source budget is represented as a universal protocol limit.
65. Network identity is verified before every Bradbury write.
66. Signer balance and nonce state are verified before every Bradbury write.
67. A deployment write requires an explicit deployment authorization gate.
68. A failed deployment is never blindly repeated.
69. Canonical deployment requires finalized consensus and successful execution.
70. The canonical deployed address must be independently extracted and recorded.

## Product release

71. Live PASS behavior must be proven before backend freeze.
72. Live FAIL behavior must be proven before backend freeze.
73. Live INCONCLUSIVE behavior must be proven before backend freeze.
74. Live challenge and revocation behavior must be proven before backend freeze.
75. Expiry behavior must be proven before backend freeze.
76. Backend freeze records the exact contract source hash.
77. Backend freeze records the canonical deployed address.
78. Backend freeze records policy and manifest identities.
79. No frontend code may exist before backend freeze.
80. Frontend state must never present demo data as live protocol state.

## Phase 2 amendment invariants

81. Every policy version binds an exact manifest SHA-256 digest.
82. The manifest digest is computed over the exact fetched response-body bytes.
83. Manifest digest encoding is exactly 64 lowercase hexadecimal characters.
84. The leader verifies the policy-bound manifest digest before parsing.
85. Every validator independently verifies the same digest before parsing.
86. Manifest digest mismatch is INCONCLUSIVE and cannot produce PASS.
87. The manifest authority label is not treated as cryptographic publisher authentication.
88. The protocol owner is the v1 trust root approving the exact policy and manifest digest tuple.
89. Public deterministic case selection is not represented as a hidden-test or anti-overfitting guarantee.
90. Certificate meaning is scoped to the exact policy, manifest, and selected cases.
91. Manifest URLs must satisfy deterministic canonical URL validation before retrieval.
92. Assessment endpoint URLs must satisfy equivalent deterministic validation before use.
93. Lexical URL validation is not represented as proof of DNS or network-layer isolation.
94. Runtime network-egress assumptions must be verified or further restricted before backend freeze.
