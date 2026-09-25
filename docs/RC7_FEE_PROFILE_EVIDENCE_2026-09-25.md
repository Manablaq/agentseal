# AgentSeal RC7 fee-profile evidence — 2026-09-25

This ledger records the local RC7 measurements used to construct the committed
Bradbury fee profile. It is evidence provenance, not a claim that Bradbury
execution has already occurred.

## Environment

- Isolated RC7 simulator chain ID: `61127`.
- Target chain: Bradbury `4221`.
- Contract SHA-256: `61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d`.
- Agent profile SHA-256: `bc32dc6c11ac40ce5593a38dbb01a073dc52258bcb9efd0ad7189109b440df39`.
- Manifest SHA-256: `adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa`.
- Repaired fixture-service SHA-256: `07e77dbf04030ecffd9f8adc616603e78be245466451028bd37a4de9b174a59a`.
- Validator model during the completed semantic matrix: `openai/gpt-5-mini`.
- Stage-1 manifest SHA-256: `9e2650427414dd68b0c14e6c2f0908f20c1a9f328502b2428033c57b04ea5c99`.
- Stage-2 manifest SHA-256: `a22c8e790cecc8019b2a04ba863e93af160f897c693d55c5c839400051f6f15a`.
- No Bradbury blockchain write was made by the measurement workflow.

## Fee envelope policy

The pre-existing certified fee-profile candidate used a conservative
`executionBudgetPerRound` equal to **2×** the simulator's measured recommended
execution budget for operations 01–03. The final profile carries that same
2× policy across all 13 operations for consistency and underfunding resistance.

This 2× multiplier is an **AgentSeal release-safety policy**, not a GenLayer
protocol requirement. Bradbury still calculates the live fee value and live
price caps from its current fee policy when the integration runner executes.

## Operation evidence

| Operation | Local GenLayer tx | Measured recommended execution budget | Profile execution budget | Final raw evidence SHA-256 |
| --- | --- | ---: | ---: | --- |
| 01_deploy_agentseal | `0x2c45fc1806a5708b421d9ed6e0e91cfa93c3c8e062076a3fd89924b1749ebcf4` | 94353600000000 | 188707200000000 | `4983a1e109e55332572cf856256a939b1e68622602b4bade611372a0751c1992` |
| 02_create_policy | `0xaae47d8d7eaaade82ba3c772759172ce698e8aa047d6e7cb106273100038dc45` | 94353600000000 | 188707200000000 | `cd9e594ad97f5f3eb2bb6b4ab5df8384d7421adf0bb65bfbc91af6d44bc20a0c` |
| 03_create_stable_assessment | `0x6dec3519bca9a5cef41ce2c81a9f55f625b7bd2d40f983f395f43bc39b8fedd7` | 94353600000000 | 188707200000000 | `d1f1ff4e81f8c2255bd755aec7b27f2a64d6b7bd2d3fe7c45506bd39334e346a` |
| 04_evaluate_stable_assessment | `0xefd1501c89c1ab68141d2cb0c910bf3c5931655b59073d198e284dbf6429b54e` | 94608000000000 | 189216000000000 | `34b4d2bfca6668fba134cb5170ff5d26f5e8a82be60716d523b4ba0eb69ddb7b` |
| 05_open_stable_challenge | `0xfb8107f2e24ea02711e4e34890b612f66b139c8c40872aaba5c344c42128df66` | 94353600000000 | 188707200000000 | `d98fd58da7549ba716ebddec07f91b3cd822838b7b2de7decc71b3b3d07aa71c` |
| 06_evaluate_stable_challenge | `0xc690bc4613a6f23a9308ef67a27db11c9bb459d6c2cd4fc5151ebc68edb5b7fb` | 94608000000000 | 189216000000000 | `4a108bc451aa3b6ae1057eface5eaa9bcf5c40fb0348420c7a0eacdbf17983c5` |
| 07_revoke_stable_certificate | `0xc34abffd94ab4e48460244f05a49ad90841482e6d190a685490063801694d888` | 94353600000000 | 188707200000000 | `2b40df632bc2381e2fa62b9a48796a0ecc4717d12e2655ba21ab5d8b080150d6` |
| 08_create_drift_assessment | `0x4e2ea7f975e02d68ce6831321c47595495223d11e74f59bb0abd13b610117203` | 94353600000000 | 188707200000000 | `9876d57a0facd96e34a6f8763711f54d7b8505948ff1837c2a82686bc3e7ddbe` |
| 09_evaluate_drift_assessment | `0x4785166bc3f8082fff49a6f34087a92fd8be04a57328a861ed33719bb3442509` | 94608000000000 | 189216000000000 | `c0808caa5ed58fe43daa463bc061b6f38d377bf3128343aa565d5989beb8a1bd` |
| 10_open_drift_challenge | `0x79827cf7162fb4e531e92e1ad1a2cde8079b9ca5b932217553c8208be37e20a2` | 94353600000000 | 188707200000000 | `8a65c937957162b473e5f1957ea2aad867a8bc082a7bbd24a96cfd4d5bd3966f` |
| 11_evaluate_drift_challenge | `0xdb9eeb61753c688352312e1c5bc11a85cc44b4c67045a206a4a8c6a112a6ff75` | 94608000000000 | 189216000000000 | `6df7f2d1f82c707ea4e18eb9694c09135e4ca5cbdc31cc54ca4d73089d9dcbaf` |
| 12_create_fail_assessment | `0x5d8d48b233a7da813b7b05114eb07177fd79ed856ec0e10e954fe6322ed97934` | 94353600000000 | 188707200000000 | `0ea542b03378f63e1dd9020cc433314dd1b86c218b6031a090b9bc0c2cf39747` |
| 13_evaluate_fail_assessment | `0xb5a6fbd42ec6d827f3182f22eb6e7548af2c09f6aacbdfaece49ec45ad9c944b` | 94608000000000 | 189216000000000 | `b57317d426b0651f8fb1905097e86c659a99838fc31df699923b4969fd418da9` |

## Stable-lifecycle recovery note

The first stable certificate used a 900-second TTL. Operation 05 finalized, but
the certificate/challenge later expired before operation 06 could be submitted.
The contract's explicit permissionless liveness paths were then exercised:
the expired challenge and certificate were materialized as expired. A fresh
stable assessment used the policy maximum 3600-second TTL and completed the
intended stable challenge evaluation (`REJECTED`) and subject revocation
(`SUBJECT_SELF_REVOKE`) with finality.

The Bradbury integration test therefore uses `CERT_TTL = 3600`.

## Fixture provenance limitation

The repaired fixture was deployed once to the existing Vercel project and the
stable URL was preserved. Vercel deployment metadata did not independently bind
that production deployment to a Git commit. The repository records the exact
repaired fixture SHA-256 instead of claiming a cryptographic Vercel-to-commit
binding.
