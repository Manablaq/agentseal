# AgentSeal Progress 5 checkpoint — 2026-09-25

This document records the repository/runtime checkpoint reached during the isolated RC7 fee-profile workflow. It is a status record, not a claim that Progress 5 is complete.

## Repository repair

- Branch: `release/agentseal-bradbury-fixtures-v1`
- Parent before this checkpoint commit: `e8e9d90c124e4b77d2371b57ab7f60fe2d6f4a35`
- Certified fixture repair: change the issuance evaluation-ID prefix accepted by `fixtures/bradbury/service/fixture_service.py` from `agentseal-evaluation-v1:` to the contract-canonical `agentseal-v1:`.
- Repaired fixture source SHA-256: `07e77dbf04030ecffd9f8adc616603e78be245466451028bd37a4de9b174a59a`.
- Full regression after the repair: `363 passed, 1 skipped`.
- No contract source change was required.

## Production fixture deployment

The repaired fixture was deployed exactly once to the existing Vercel project:

- Project: `agentseal-bradbury-fixtures`
- Project ID: `prj_BvYSfGxbOoVuOCCjopVAVh4cK0St`
- Deployment ID: `dpl_GGKtqVBPGcnUTabP2ZEUmsRMQpJ8`
- Deployment URL: `https://agentseal-bradbury-fixtures-r38znddk8-mr-albert-s-projects.vercel.app`
- Stable URL preserved: `https://agentseal-bradbury-fixtures.vercel.app`
- Exact operation-04 attempt-2 fixture request now returns HTTP 200 with the deterministic `live-01` and `live-06` reference outputs.
- The deployment was produced from CLI-staged repaired bytes; the live fixture implementation is therefore not independently Git-commit-pinned by Vercel metadata. This limitation must not be represented as a cryptographic source binding.

## Current isolated RC7 operation-04 state

- Assessment ID: `1`
- Assessment status: `PENDING`
- Effective status: `PENDING`
- Attempt count: `1 / 3`
- Last verdict: `INCONCLUSIVE`
- Selected cases: `live-01`, `live-06`
- Certificate: absent
- Database transaction count: `6`
- Operation-04 attempt 2 has **not** been submitted or consumed on-chain.
- Checkpoint and fee-profile candidate remained unchanged through the failed simulation diagnostics.

## Attempt-2 deterministic binding

- Evaluation ID: `agentseal-v1:61127:0x0ad72a9a303bdf888d3bf7d76e3568248a353199:1:2`
- Selection-material SHA-256: `97b0e11bc74e08f0d0bef3a58c5f2e34707e1c7eab62863609a34634bd15dfb3`
- Stable exact response SHA-256 from R2I: `37e7e6e1dfea106d4d89a8c5b28ae71f53cf77ff5b68f4591269cb26b128ef56`

## R2I semantic simulation result

The deterministic endpoint failure was resolved, but the single authorized post-repair semantic fee simulation did not complete:

- Estimate request SHA-256: `3cce9840728b11076a93e1540d0c72abc87647d28cf6ced04fcf2a17ac792155`
- Estimate response SHA-256: `47f6763aa3839b28d5be7993d8596cf6215e0e97b46899c097786ebce1d8be97`
- JSON-RPC error code: `-32603`
- Error: `GenVM internal error: LLM_EXECUTION_ERROR`
- The simulation persisted no transaction and did not increment the assessment attempt count.

## Corrected runtime classification (R2L)

R2K's earlier `PROVIDER_UPSTREAM_5XX_FAILURE` classification was invalid: its bare `504` match came from the source-code location `src/lib.rs:504`, not an HTTP 504 response.

R2L's context-aware result is:

`GENVM_LLM_EXECUTION_ERROR_UNDERLYING_PROVIDER_CAUSE_NOT_EXPOSED`

R2L found no explicit provider HTTP 401, 403, 429, or 5xx status, and no explicit authentication, rate-limit, timeout, network, or upstream-failure phrase. Therefore the underlying provider/runtime cause remains unresolved.

R2L summary SHA-256:

`e1e0f87f4adb13143f2756eb0e4750a67a4ab19da5b63ffd3d31675a426624d0`

## Safety boundary

At this checkpoint:

- No Bradbury blockchain write was performed.
- No operation-04 attempt-2 transaction was submitted.
- No blind semantic simulation retry is authorized by this record.
- The next step is a non-blind provider/runtime health check that does not consume operation-04 attempt 2.
- Only after runtime health is established should a new read-only fee preflight and a separately authorized one-shot local RC7 attempt-2 submission be considered.

## Remaining Progress 5 work

After the runtime blocker is resolved, Progress 5 still needs operation-04 attempt 2/finality and the planned operations 05–13, followed by final fee-profile/checkpoint reconciliation. Bradbury live-network work remains a separate later phase.
