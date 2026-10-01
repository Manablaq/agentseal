# AgentSeal Progress 5 checkpoint — 2026-09-25

This filename is retained for continuity. It records the historical local RC7
checkpoint from 2026-09-25 and is superseded for current release status by the
R7 Bradbury certification completed on 2026-10-01.

## Historical RC7 checkpoint

At the 2026-09-25 checkpoint, AgentSeal had completed the local supported-runtime
matrix and fee-profile work, but the later R7 canonical Bradbury deployment had
not yet been executed.

Historical identities from that checkpoint included:

- base commit entering final reconciliation:
  `1bb1ff6972af9f744a2f86bd560abae68d78c179`
- base tree:
  `caaea11bad57bf41adb9943f3cd7de58d121be97`
- repaired fixture-service SHA-256:
  `07e77dbf04030ecffd9f8adc616603e78be245466451028bd37a4de9b174a59a`
- agent profile SHA-256:
  `bc32dc6c11ac40ce5593a38dbb01a073dc52258bcb9efd0ad7189109b440df39`
- manifest-v1 SHA-256:
  `adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa`
- frozen manifest/source commit:
  `e8e9d90c124e4b77d2371b57ab7f60fe2d6f4a35`

The historical local matrix proved stable PASS, stable challenge rejection,
subject self-revocation, drift PASS, drift challenge upholding with consensus
revocation, FAIL without certificate issuance, and explicit expiry/liveness
recovery.

The historical `fee-profile.json` remains an RC7 artifact:

- SHA-256:
  `5a45f83b7d5af82452bb20221bf9f4afb0b6014fd2e075744c2d37947b9e992e`
- schema: `agentseal-fee-profile-v1`
- target chain ID: `4221`
- operation count: `13`
- conservative execution-budget multiplier: `2x` (`20000` bps)

## Superseding R7 Bradbury release

The current backend release is the split-contract R7 deployment sourced from:

- source commit:
  `1ec79cc9ba9bf711e73df5ecea2cec0f621c8b2a`
- source tree:
  `1d775b839f9bed381b4981d56fbfb870d8c8b905`
- policy ID:
  `agentseal-bradbury-v1`
- policy version:
  `2`
- manifest ID:
  `agentseal-bradbury-manifest-v2`
- manifest SHA-256:
  `e6bc4f7737f990c94cbf49b98343fab2c1474d1ba2108d627856e7465be36507`
- certificate TTL:
  `604800` seconds

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

The R7 live certification proves:

- setup roots finalized: `12/12`
- semantic matrix roots finalized: `11/11`
- total root sends: `23`
- root EVM receipts successful: `23/23`
- unique GenLayer transactions audited:
  `44`
- every recorded GenLayer transaction:
  `FINALIZED / execution_result=1`
- blind retry:
  `NO`
- stable result:
  `PASSED -> REJECTED challenge -> SUBJECT_SELF_REVOKE`
- drift result:
  `PASSED -> UPHELD challenge -> CHALLENGE_CONSENSUS revocation`
- fail result:
  `FAILED`, no certificate
- final active certificates:
  none

Step-5 audit fingerprint:

`dd054837e3a60776285040dcae05eaaa5cf2d3bbf92d8fe9d4ad2375a5240541`

The detailed reviewer-facing release record is
`docs/BRADBURY_R7_CERTIFICATION_2026-10-01.md`.

## Production fixture continuity

The existing production fixture project and stable URL were preserved:

`https://agentseal-bradbury-fixtures.vercel.app`

No additional Vercel deployment was required for the R7 certification.

The original metadata limitation remains: Vercel deployment metadata did not
independently provide a cryptographic Git-commit binding for the fixture bytes.

## Current safety boundary

The 2026-09-25 no-write statement was true only for that historical checkpoint.
It must not be interpreted as the current backend state.

As of the R7 certification:

- canonical Bradbury split-contract deployment: complete
- Bradbury setup writes: complete and finalized
- Bradbury stable/drift/fail matrix: complete and finalized
- finality/evidence audit: complete
- additional blind retry: none
- additional fixture deployment: none
- frontend work: outside this backend certification scope
