# AgentSeal

**Proof-of-Capability infrastructure for autonomous agents, secured by GenLayer consensus.**

AgentSeal certifies whether a bound autonomous agent demonstrated a specific
capability under an immutable, versioned evaluation policy.

## Current backend release

The R7 Intelligent Contract backend has completed its Bradbury deployment,
live-finality matrix, and Step-5 finality/evidence certification.

The deployed R7 release uses the split-contract architecture at source commit
`1ec79cc9ba9bf711e73df5ecea2cec0f621c8b2a` with policy version `2`,
manifest `agentseal-bradbury-manifest-v2`, and a certificate TTL of `604800`
seconds.

Bradbury chain ID: `4221`.

R7 addresses:

- PolicyRegistry:
  `0x551355C4690AAd6066626A87E94f24d71593B8a7`
- Registry:
  `0xdbED185B52871ac70B5Cd114A26a2B7912224BBF`
- CertificateRegistry:
  `0xB683ab8DeCE80b1d170473D4FBd4b83083BcaA73`
- DeterministicSupport:
  `0x2B811C62F1e29E7edE29127c7bABEDC65fb8A162`
- Challenge:
  `0x8ed9D8cb10BC4EDb4Ebb8f412f4Be68be7abf6Cd`
- SemanticJudge:
  `0x3188310A01d64FACf6b1216aAF2722c748d03d28`
- AssessmentEvidenceEvaluator:
  `0x70CAcB92efc405D98E6Afdc4f8BEf691448Bfc2C`
- ChallengeEvidenceEvaluator:
  `0x09f6404544A6F7bEAA157a84487D650A18001C91`

## Certified live matrix

The R7 Bradbury execution used exactly-once root submission semantics:

- setup roots finalized: `12/12`
- semantic-matrix roots finalized: `11/11`
- total root send calls: `23`
- successful root EVM receipts: `23/23`
- unique GenLayer root/descendant transactions audited: `44`
- required GenLayer final status: `FINALIZED` (`7`)
- required execution result: `FINISHED_WITH_RETURN` (`1`)
- blind retry performed: `NO`

The semantic matrix proves:

- stable assessment: `PASSED`
- stable challenge: `REJECTED`
- stable certificate direct revocation:
  `REVOKED / SUBJECT_SELF_REVOKE`
- drift assessment: `PASSED`
- drift challenge: `UPHELD`
- drift certificate revocation:
  `REVOKED / CHALLENGE_CONSENSUS`
- fail assessment: `FAILED`
- fail certificate: not issued
- final live bindings: none
- final active certificates: none

Step-5 audit fingerprint:

`dd054837e3a60776285040dcae05eaaa5cf2d3bbf92d8fe9d4ad2375a5240541`

See:

- `docs/BRADBURY_R7_CERTIFICATION_2026-10-01.md`
- `docs/evidence/agentseal-bradbury-r7-certification.json`

## Verification status

The R7 source hashes are frozen and the Step-6 preflight verified the complete
local regression and all eight split contracts with the pinned GenVM linter.

The former opt-in Bradbury integration test targeted the superseded monolithic
policy-v1/manifest-v1 release path. It is no longer a live-write entry point.
The file now provides a non-writing R7 release-identity guard while preserving
the exactly-once submission-checkpoint helper used by the regression suite.

`fee-profile.json` and the RC7 fee-profile evidence remain historical RC7
artifacts. They are not the R7 Bradbury execution ledger.

## Production fixture

The preserved fixture project remains:

`https://agentseal-bradbury-fixtures.vercel.app`

The fixture service was not redeployed for this R7 certification. The service
continues to serve the stable/drift/fail behavior used by the certified matrix.

The earlier Vercel metadata limitation remains explicit: deployment metadata did
not independently establish a cryptographic Git-commit binding for the deployed
fixture bytes.

## Backend boundary

The backend release is live-verified and Step-5 certified. Step 6 packages and
freezes reviewer-facing release evidence; it does not perform additional
blockchain writes.

Frontend work is outside this backend certification scope.
