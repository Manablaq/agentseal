# AgentSeal Progress 5 completion checkpoint — 2026-09-25

This file is the final local Progress 5 checkpoint. The legacy filename is
preserved for continuity. Bradbury deployment remains a separate next phase and
has not yet been performed.

## Repository and source identity

- Base commit entering final reconciliation:
  `1bb1ff6972af9f744a2f86bd560abae68d78c179`.
- Base tree:
  `caaea11bad57bf41adb9943f3cd7de58d121be97`.
- Contract SHA-256:
  `61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d`.
- Repaired fixture-service SHA-256:
  `07e77dbf04030ecffd9f8adc616603e78be245466451028bd37a4de9b174a59a`.
- Agent profile SHA-256:
  `bc32dc6c11ac40ce5593a38dbb01a073dc52258bcb9efd0ad7189109b440df39`.
- Manifest SHA-256:
  `adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa`.
- Frozen manifest/source commit:
  `e8e9d90c124e4b77d2371b57ab7f60fe2d6f4a35`.

## Production fixture deployment

The repaired fixture was deployed exactly once to the existing Vercel project:

- Project: `agentseal-bradbury-fixtures`.
- Project ID: `prj_BvYSfGxbOoVuOCCjopVAVh4cK0St`.
- Deployment ID: `dpl_GGKtqVBPGcnUTabP2ZEUmsRMQpJ8`.
- Stable URL: `https://agentseal-bradbury-fixtures.vercel.app`.
- Exact repaired fixture SHA-256:
  `07e77dbf04030ecffd9f8adc616603e78be245466451028bd37a4de9b174a59a`.

The deployment was produced from CLI-staged repaired bytes. Vercel metadata did
not independently expose a cryptographic Git-commit binding for those deployed
bytes. This limitation remains explicit.

## RC7 supported-runtime verification

- Isolated simulator chain ID: `61127`.
- Contract address: `0x0aD72A9a303bDF888d3bf7d76e3568248a353199`.
- Subject: `0xF97489d7C61187BA2F99d89fe75274BBa7776908`.
- Validator count: `5`.
- Validator model: `openai/gpt-5-mini`.
- Stage-1 manifest SHA-256:
  `9e2650427414dd68b0c14e6c2f0908f20c1a9f328502b2428033c57b04ea5c99`.
- Stage-2 manifest SHA-256:
  `a22c8e790cecc8019b2a04ba863e93af160f897c693d55c5c839400051f6f15a`.

The final local semantic matrix proves:

- Stable assessment: `PASSED`.
- Stable challenge: `REJECTED`; certificate remained active.
- Direct subject revocation: certificate `REVOKED`, source
  `SUBJECT_SELF_REVOKE`.
- Drift assessment: `PASSED`.
- Drift challenge: `UPHELD`; certificate `REVOKED`, source
  `CHALLENGE_CONSENSUS`.
- Fail assessment: `FAILED`; certificate ID `0`; no certificate issued.

Stage-1 and Stage-2 writes were submitted once, tracked to `FINALIZED`, and
their finality evidence was SHA-256 recorded.

## Expiry and liveness recovery

The original stable certificate used a 900-second TTL. Operation 05 finalized,
but its certificate/challenge expired before operation 06 could be submitted.
The explicit permissionless expiry paths were then exercised to materialize the
expired challenge and certificate.

A fresh stable lifecycle used the policy maximum 3600-second TTL and completed
stable challenge evaluation and direct revocation with finality. The Bradbury
integration test now uses `CERT_TTL = 3600`.

## Final fee profile

- Artifact: `fee-profile.json`.
- SHA-256:
  `5a45f83b7d5af82452bb20221bf9f4afb0b6014fd2e075744c2d37947b9e992e`.
- Schema: `agentseal-fee-profile-v1`.
- Target chain ID: `4221`.
- Operation count: `13`.
- Conservative execution-budget multiplier: `2×` (`20000` bps).
- The multiplier is an AgentSeal release-safety policy, not a GenLayer protocol
  requirement.
- Portable evidence ledger:
  `docs/RC7_FEE_PROFILE_EVIDENCE_2026-09-25.md`.

## Retry and finality hardening

The Bradbury integration checkpoint persists submission intent before a write.
An ambiguous submission result is marked `OUTCOME_UNKNOWN` and is not blindly
retried; chain state must be reconciled first.

The RC7 state reader checks chain identity before contract reads and
distinguishes latest-final from latest-nonfinal probing.

## Final local release gates

- `genvm-lint check contracts/agentseal.py`: PASS.
- `genvm-lint typecheck contracts/agentseal.py`: PASS.
- Exact Direct Mode regression:
  `363 passed in 8.01s`.
- Safe non-live release guards:
  `7 passed in 0.02s`.
- `fee-profile.json` structure/portability guard: PASS.
- `artifacts/.gitkeep` restored to the exact tracked empty file after the test
  harness cleared the artifacts directory.
- Bradbury live integration remains opt-in behind
  `AGENTSEAL_RUN_BRADBURY_SUPPORTED_RUNTIME=1`.

## Safety boundary

At this checkpoint:

- Bradbury contract deployment: **not performed**.
- Bradbury contract writes: **none**.
- Additional Vercel deployment: **none**.
- Local RC7 runtime matrix: **complete**.
- Final fee profile: **complete**.
- Local release verification: **complete**.
- Next phase: canonical Bradbury deployment, followed by the live finalized
  13-operation matrix and final backend audit/freeze.
