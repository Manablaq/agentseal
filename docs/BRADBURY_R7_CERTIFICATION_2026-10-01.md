# AgentSeal R7 Bradbury backend certification — 2026-10-01

## Certification scope

This record certifies the AgentSeal split-contract R7 backend on Bradbury
Testnet after completion of the live setup, semantic matrix, exactly-once
reconciliation, and read-only finality/evidence audit.

No blockchain write is performed by this document or by the Step-6
release-surface patch that adds it.

## Immutable source identity

- Deployed source commit:
  `1ec79cc9ba9bf711e73df5ecea2cec0f621c8b2a`
- Deployed source tree:
  `1d775b839f9bed381b4981d56fbfb870d8c8b905`
- Manifest:
  `fixtures/bradbury/agentseal-manifest-v2.json`
- Manifest ID:
  `agentseal-bradbury-manifest-v2`
- Manifest SHA-256:
  `e6bc4f7737f990c94cbf49b98343fab2c1474d1ba2108d627856e7465be36507`
- Policy:
  `agentseal-bradbury-v1`
- Policy version:
  `2`
- Certificate TTL:
  `604800` seconds

The immutable manifest URL used by the release is:

`https://raw.githubusercontent.com/Manablaq/agentseal/1ec79cc9ba9bf711e73df5ecea2cec0f621c8b2a/fixtures/bradbury/agentseal-manifest-v2.json`

## Bradbury identities

- Chain ID: `4221`
- ConsensusMain:
  `0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D`
- Owner:
  `0x1f87Ae197af539253978d435aD45cCf28Fb95024`
- Subject:
  `0xeBA20FeF2026C69982f76E360A62F53A37c0d06B`

Contracts:

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

## Exactly-once live execution

Setup:

- finalized roots: `12/12`
- root send calls: `12`
- blind retry: `NO`

Semantic matrix:

- finalized roots: `11/11`
- root send calls: `11`
- stable roots: `5`
- drift roots: `4`
- fail roots: `2`
- blind retry: `NO`

Combined:

- total root send calls: `23`
- successful root EVM receipts: `23/23`
- unique GenLayer root/descendant transactions independently audited: `44`
- required final status: `FINALIZED` (`7`)
- required execution result: `FINISHED_WITH_RETURN` (`1`)

The certification audit performed no blockchain writes, signing, keychain
access, or `eth_sendRawTransaction` calls.

## Semantic result

Stable path:

1. assessment 1 `PASSED`
2. certificate 1 `ACTIVE`
3. challenge 1 `REJECTED`
4. certificate remained `ACTIVE`
5. direct subject revocation -> `REVOKED`
6. revocation source -> `SUBJECT_SELF_REVOKE`

Drift path:

1. assessment 2 `PASSED`
2. certificate 2 `ACTIVE`
3. challenge 2 opened
4. challenge 2 `UPHELD`
5. certificate 2 -> `REVOKED`
6. revocation source -> `CHALLENGE_CONSENSUS`

Fail path:

1. assessment 3 `FAILED`
2. certificate ID `0`
3. no certificate issued

Final state:

- assessments: `3`
- challenges: `2`
- live assessment bindings: none
- active certificates: none

## Audit identity

Step-5 audit fingerprint:

`dd054837e3a60776285040dcae05eaaa5cf2d3bbf92d8fe9d4ad2375a5240541`

The portable machine-readable companion is:

`docs/evidence/agentseal-bradbury-r7-certification.json`

## Fixture continuity

The production fixture URL is preserved unchanged:

`https://agentseal-bradbury-fixtures.vercel.app`

No additional Vercel deployment was performed for R7.

Vercel metadata did not independently expose a cryptographic Git-commit binding
for the deployed fixture bytes; this limitation remains explicit.

## Reviewer note

The previous write-capable pytest integration path targeted the superseded
monolithic policy-v1 / manifest-v1 backend. It is not a valid R7 replay path and
must not be rerun against Bradbury.

The current integration file is intentionally non-writing: it verifies R7
release identity and preserves the exactly-once checkpoint helper regression.
The actual R7 Bradbury write history is certified by the evidence described
above.
