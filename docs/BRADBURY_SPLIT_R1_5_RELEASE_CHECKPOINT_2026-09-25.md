# AgentSeal Bradbury Split R1.5 Release Checkpoint

Date: 2026-09-25

## Release identity

- Branch: `release/agentseal-bradbury-split-v1`
- Verified parent commit: `93c2d87b99b1159f1e2cdb2b18f7420e5d2fe510`
- Remote main observed at freeze: `93c2d87b99b1159f1e2cdb2b18f7420e5d2fe510`
- Frozen monolith SHA-256: `61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d`
- Architecture SHA-256: `bc2ff46c81e70ab92fc106671a96c391a8a4bc4a6f1a6889712cff18b1879bee`

## Split artifacts

- `contracts/agentseal_registry.py`
  - SHA-256: `78a90c8d481ce1916525140fff852a50c112933d7390bb9bb6c312268634750f`
- `contracts/agentseal_challenge.py`
  - SHA-256: `83af923a2bcef7a0c197dd307f70889eea07bfe58b68354e83a410825ad86bb8`
- `contracts/agentseal_assessment_evaluator.py`
  - SHA-256: `16a9674adba592ad530e51d8c808791f1dcab70a35bc5b36a946ab19dcbbb8e2`
- `contracts/agentseal_challenge_evaluator.py`
  - SHA-256: `58616f754d4e54fc2ed9739d2574341f6a6b23f42d7600e2228037e02c6b1ca4`
- `tests/test_agentseal_split_r1_5.py`
  - SHA-256: `da83cd37d5a44c082bd3b2634932fd2e4f5e7ce8130135a1e362cd71ef600c4f`

## Local verification

- Frozen monolith Direct Mode regression: **363 / 363 passed**
- Split Direct + GLSim parity suite: **6 / 6 passed**
- GenVM lint: **passed with zero warnings**
- GenVM typecheck: **passed**
- Stable assessment/challenge lifecycle: **passed**
- Drift challenge / consensus revocation lifecycle: **passed**
- Terminal failed-assessment lifecycle: **passed**
- Challenge-consensus revocation initiator parity: **request-bound caller preserved**
- Frozen monolith remained unchanged.

## Bradbury read-only deployment admission

Network:

- Chain ID: **4221**
- ConsensusMain: `0x0112Bf6e83497965A5fdD6Dad1E447a6E004271D`
- Legacy six-argument `addTransaction` selector: `0xe71d5196`
- Initial validators: **5**
- Maximum rotations: **3**

Read-only results:

| Artifact | gen_call deploy | eth_estimateGas |
| --- | --- | ---: |
| Registry | PASS | 32666892 |
| Assessment evaluator | PASS | 20178109 |
| Challenge | PASS | 19016059 |
| Challenge evaluator | PASS | 22983004 |

The preflight used only `eth_chainId`, `eth_getCode`,
`gen_call`, and `eth_estimateGas`.

No private key was used. No transaction was signed. No
`eth_sendRawTransaction` call was made. No blockchain write occurred.

## Evidence

- Preflight schema: `agentseal-bradbury-readonly-split-preflight-r2`
- Transport: `curl`
- Read-only preflight summary SHA-256:
  `13e2583e956b07de372275b1c06766051dc2d1b68f3c205a9e8314cdcbd0ac4a`
- Raw evidence integrity manifest SHA-256:
  `3ec071fb075d415eee9d98e13a19e448c1a8d9df21a601262dfda3650f633595`
- Raw evidence directory captured locally:
  `agentseal-bradbury-readonly-preflight-r2-20260925T083700Z`

The Python urllib R1 probe was rejected at the HTTP edge with
error 1010 before JSON-RPC execution. The R2 curl canary reached
Bradbury successfully and all four deployment artifacts then
passed both read-only admission gates.

## Release boundary

This checkpoint authorizes no blockchain write by itself.

The next phase is the exact Bradbury deployment sequence with
persistent pre-submit checkpoints and no blind retry:

1. Registry deployment.
2. Assessment evaluator deployment bound to the finalized Registry.
3. Challenge deployment bound to the finalized Registry.
4. Challenge evaluator deployment bound to finalized Challenge and Registry.
5. Registry one-time component configuration.
6. Challenge one-time evaluator configuration.
7. Live finality and semantic lifecycle matrix.

Every consequential submission must persist the exact unsigned
envelope, nonce, source/deployment fingerprint, signed EVM
transaction hash, and submission intent before broadcast.
