# AgentSeal verified GenLayer baseline

Baseline date: 2026-09-21.

## Python requirements verified from pinned upstream sources

genlayer-py:

- version: 0.18.0
- commit: a3dc35e04898e3889cbfa855bcaf7d2664675b8f
- requires Python >=3.12

genlayer-test:

- version: 0.29.2
- commit: 9c09578b143905471fb0657dd53bdaf18da8e35f
- requires Python >=3.12
- requires genlayer-py >=0.18.0,<0.19.0

genvm-linter:

- upstream commit: 28450e665666300fc648dbe495110dfd0cb6a7b4
- version at that commit: 0.11.1-rc.2
- requires Python >=3.10

AgentSeal initial backend baseline therefore uses Python 3.12.x.

## Bradbury

Current target network:

- network: Bradbury
- chain ID: 4221
- currency: GEN

## Deployment-resource finding

We do not assume a universal source-size limit.

Current public GenLayer CLI issue evidence shows deployment admission can be
affected by both gas and deployment payload/calldata.

Therefore every release must measure:

- source bytes;
- encoded deployment bytes;
- estimated resource requirement;
- actual preflight behavior.

Reference:

https://github.com/genlayerlabs/genlayer-cli/issues/419

## Transaction gas-estimation finding

A current public issue documents a case where using the exact gas estimate for
a Bradbury write reverted before GenVM while identical calldata succeeded with
a larger explicit gas limit.

AgentSeal deployment/write tooling therefore must not blindly assume the raw
estimate is always a sufficient execution limit.

Reference:

https://github.com/genlayerlabs/genlayer-cli/issues/402

## IC-to-IC finding

A current open report describes cross-IC method dispatch failing even when the
target method is correctly registered.

AgentSeal V1 therefore has no mandatory IC-to-IC dependency.

Reference:

https://github.com/genlayerlabs/genlayer-cli/issues/420

## Studio development deployment finding

A current open report documents FeesDistributionMissing when deploying through
the tested Studio-dev SDK path.

Studio-dev is not treated as AgentSeal's canonical deployment proof.

Reference:

https://github.com/genlayerlabs/genlayer-cli/issues/421

## Finality invariant

Accepted is not Finalized.

External AgentSeal consequences require finalized consensus and successful
execution.

## Nondeterministic execution invariant

State mutation remains outside nondeterministic execution.

Leader and validators independently evaluate consequential semantic facts.

Validator logic must perform substantive independent verification.

## Remote data invariant

Remote content may fail, change, personalize, disagree between validators, or
contain adversarial instructions.

AgentSeal therefore exposes explicit unavailable/inconclusive outcomes rather
than converting infrastructure failure into a semantic judgment.
