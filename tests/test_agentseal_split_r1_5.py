from __future__ import annotations

import ast
import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glsim.engine import SimEngine
from glsim.state import StateStore


ROOT = Path(__file__).resolve().parents[1]

MONOLITH = ROOT / "contracts" / "agentseal.py"

POLICY = ROOT / "contracts" / "agentseal_policy_registry.py"
REGISTRY = ROOT / "contracts" / "agentseal_registry.py"
CERTIFICATE_REGISTRY = ROOT / "contracts" / "agentseal_certificate_registry.py"
SUPPORT = ROOT / "contracts" / "agentseal_deterministic_support.py"
CHALLENGE = ROOT / "contracts" / "agentseal_challenge.py"
SEMANTIC_JUDGE = ROOT / "contracts" / "agentseal_semantic_judge.py"
ASSESSMENT_EVALUATOR = (
    ROOT / "contracts" / "agentseal_assessment_evidence_evaluator.py"
)
CHALLENGE_EVALUATOR = (
    ROOT / "contracts" / "agentseal_challenge_evidence_evaluator.py"
)

# Historical monolith-parity guards remain intentionally bound to the
# pre-R3 evaluator files. They are not deployment fingerprints.
LEGACY_ASSESSMENT_EVALUATOR = (
    ROOT / "contracts" / "agentseal_assessment_evaluator.py"
)
LEGACY_CHALLENGE_EVALUATOR = (
    ROOT / "contracts" / "agentseal_challenge_evaluator.py"
)

EXPECTED_SHA256 = {
    MONOLITH:
        "61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d",
    POLICY:
        "da593bf8276c1603c2ca1af2933057eef59cd80eeef72e0d5682f3dc0e755240",
    REGISTRY:
        "885ce68a6e547a71e29b8ff5549061909a6830a98bcaebe49db7cc93cde0b4e2",
    CERTIFICATE_REGISTRY:
        "9ec3d55a8e142ef371a13e8e46e1f3c179bc48da40e2e033a7da73a7cdffe583",
    SUPPORT:
        "d1de52f8900ffa98cd2f5178f76de0b792d31f0e3e97e611a565c0781be3c71c",
    CHALLENGE:
        "6b63365669d6288fc6df712767e14647a62fc12e17759f9e46746a8a27c3c026",
    SEMANTIC_JUDGE:
        "28b1d33d5ca52613b7d033258b84e1c6128542c2f23a9ca617554e0313084ee2",
    ASSESSMENT_EVALUATOR:
        "1c3e2c16b18636c5261b87b107abf4b5452363089e175ca3fbaa5c357da6e52c",
    CHALLENGE_EVALUATOR:
        "510a0639ca061d47a9d8c2f02d4807e9037859f568105be70f9d0af15cc4ac0b",
}

OWNER = "0x" + "11" * 20
SUBJECT = "0x" + "22" * 20
CHALLENGER = "0x" + "33" * 20
EVALUATION_CALLER = "0x" + "44" * 20

POLICY_ID = "agentseal-split-policy-v1"
CAPABILITY_ID = "research"
MANIFEST_ID = "agentseal-split-manifest-v1"
MANIFEST_AUTHORITY = "AgentSeal Split Parity Authority"
CRITERIA = "Return correct structured research results."
MANIFEST_URL = "https://evidence.example.com/agentseal-split-manifest.json"
ENDPOINT = "https://agent.example.com/evaluate"

PROFILE_STABLE = "b" * 64
PROFILE_DRIFT = "c" * 64
PROFILE_FAIL = "d" * 64

DAY = 86_400


ASSESSMENT_PARITY_METHODS = {
    "_canonical_json",
    "_utf8_size",
    "_strict_json_loads",
    "_identifier_is_valid",
    "_validate_manifest_payload",
    "_select_case_indexes",
    "_build_endpoint_request",
    "_validate_endpoint_response",
    "_normalize_evaluator_result",
    "_build_evaluator_prompt",
    "_selection_material",
    "_evaluation_id",
    "_semantic_evaluation_once",
    "_semantic_evaluation_consensus",
}

CHALLENGE_PARITY_METHODS = {
    "_canonical_json",
    "_utf8_size",
    "_strict_json_loads",
    "_identifier_is_valid",
    "_validate_manifest_payload",
    "_select_case_indexes",
    "_build_endpoint_request",
    "_validate_endpoint_response",
    "_normalize_evaluator_result",
    "_build_evaluator_prompt",
    "_challenge_assessment_view",
    "_challenge_selection_material",
    "_challenge_evaluation_id",
    "_challenge_evaluation_once",
    "_challenge_evaluation_consensus",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _class_methods(path: Path, class_name: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == class_name
    )
    return {
        node.name: node
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
    }


def _normalized_method(node: ast.FunctionDef) -> str:
    # AST equality deliberately ignores formatting introduced by ast.unparse.
    return ast.dump(node, include_attributes=False)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _manifest_payload() -> dict:
    return {
        "schema": "agentseal-manifest-v1",
        "manifest_id": MANIFEST_ID,
        "authority": MANIFEST_AUTHORITY,
        "capability_id": CAPABILITY_ID,
        "policy_id": POLICY_ID,
        "policy_version": 1,
        "cases": [
            {
                "case_id": f"case-{index}",
                "task": f"task {index}",
                "reference": f"reference {index}",
            }
            for index in range(4)
        ],
    }


def _web_response(status: int, body: bytes) -> dict:
    return {
        "ok": {
            "response": {
                "status": status,
                "headers": {
                    "content-type": "application/json",
                },
                "body": body,
            }
        }
    }


class SemanticHarness:
    def __init__(self, manifest_raw: bytes) -> None:
        self.manifest_raw = manifest_raw
        self.verdict = "PASS"
        self.web_events: list[dict] = []
        self.llm_events: list[dict] = []
        self.endpoint_requests: list[dict] = []

    def web_handler(self, data: dict) -> dict:
        event = dict(data)
        self.web_events.append(event)

        method = str(event.get("method", "GET")).upper()

        if method == "GET":
            return _web_response(200, self.manifest_raw)

        if method == "POST":
            body = json.loads(bytes(event["body"]).decode("utf-8"))
            self.endpoint_requests.append(body)

            payload = {
                "protocol": "agentseal-evaluation-v1",
                "evaluation_id": body["evaluation_id"],
                "agent_wallet": body["agent_wallet"],
                "profile_digest": body["profile_digest"],
                "capability_id": body["capability_id"],
                "policy_id": body["policy_id"],
                "policy_version": body["policy_version"],
                "manifest_id": body["manifest_id"],
                "results": [
                    {
                        "case_id": body["cases"][0]["case_id"],
                        "output": "split parity output a",
                    },
                    {
                        "case_id": body["cases"][1]["case_id"],
                        "output": "split parity output b",
                    },
                ],
            }

            return _web_response(200, _canonical_bytes(payload))

        raise AssertionError(f"unexpected web method: {method}")

    def llm_handler(self, data: dict) -> dict:
        self.llm_events.append(dict(data))
        return {"ok": {"verdict": self.verdict}}


def _addr(value: str):
    from genlayer.py.types import Address

    return Address(bytes.fromhex(value[2:]))


def _engine_call(engine, to: str, method: str, args: list | None = None, *, sender: str):
    return engine.call_method(
        to,
        method,
        args or [],
        {},
        sender=sender,
    )


def _engine_read(engine, to: str, method: str, args: list | None = None):
    return engine.call_method(
        to,
        method,
        args or [],
        {},
        sender=OWNER,
    )


@contextmanager
def _sim_engine(seed: str, harness: SemanticHarness | None = None):
    state = StateStore(
        chain_id=61127,
        seed=seed,
    )

    engine = SimEngine(
        state,
        web_handler=(
            harness.web_handler
            if harness is not None
            else None
        ),
        llm_handler=(
            harness.llm_handler
            if harness is not None
            else None
        ),
    )

    engine.num_validators = 1
    engine.max_rotations = 3
    engine.activate()

    try:
        yield engine
    finally:
        engine.deactivate()


def _drain_messages(engine, registry_address: str, *, limit: int = 24) -> int:
    steps = 0

    while engine._post_queue:
        steps += 1
        if steps > limit:
            raise AssertionError(
                f"post-message queue did not drain within {limit} steps: "
                f"{engine._post_queue!r}"
            )

        # A harmless top-level view causes GLSim to advance exactly one
        # queued PostMessage after the view returns.
        _engine_read(
            engine,
            registry_address,
            "get_owner",
        )

    return steps


def _deploy_split(engine):
    policy_address, _ = engine.deploy(
        str(POLICY),
        [],
        {},
        sender=OWNER,
    )

    registry_address, _ = engine.deploy(
        str(REGISTRY),
        [_addr(policy_address)],
        {},
        sender=OWNER,
    )

    certificate_registry_address, _ = engine.deploy(
        str(CERTIFICATE_REGISTRY),
        [
            _addr(registry_address),
            _addr(policy_address),
        ],
        {},
        sender=OWNER,
    )

    support_address, _ = engine.deploy(
        str(SUPPORT),
        [_addr(certificate_registry_address)],
        {},
        sender=OWNER,
    )

    challenge_address, _ = engine.deploy(
        str(CHALLENGE),
        [_addr(certificate_registry_address)],
        {},
        sender=OWNER,
    )

    semantic_judge_address, _ = engine.deploy(
        str(SEMANTIC_JUDGE),
        [
            _addr(registry_address),
            _addr(challenge_address),
        ],
        {},
        sender=OWNER,
    )

    assessment_evaluator_address, _ = engine.deploy(
        str(ASSESSMENT_EVALUATOR),
        [
            _addr(registry_address),
            _addr(semantic_judge_address),
        ],
        {},
        sender=OWNER,
    )

    challenge_evaluator_address, _ = engine.deploy(
        str(CHALLENGE_EVALUATOR),
        [
            _addr(challenge_address),
            _addr(registry_address),
            _addr(semantic_judge_address),
            _addr(support_address),
        ],
        {},
        sender=OWNER,
    )

    _engine_call(
        engine,
        certificate_registry_address,
        "configure_challenge",
        [_addr(challenge_address)],
        sender=OWNER,
    )

    _engine_call(
        engine,
        semantic_judge_address,
        "configure_evaluators",
        [
            _addr(assessment_evaluator_address),
            _addr(challenge_evaluator_address),
        ],
        sender=OWNER,
    )

    _engine_call(
        engine,
        registry_address,
        "configure_components",
        [
            _addr(certificate_registry_address),
            _addr(assessment_evaluator_address),
            _addr(semantic_judge_address),
            _addr(support_address),
        ],
        sender=OWNER,
    )

    _engine_call(
        engine,
        challenge_address,
        "configure_evaluator",
        [
            _addr(challenge_evaluator_address),
            _addr(semantic_judge_address),
            _addr(support_address),
        ],
        sender=OWNER,
    )

    return {
        "policy": policy_address,
        "registry": registry_address,
        "certificate_registry":
            certificate_registry_address,
        "support": support_address,
        "challenge": challenge_address,
        "semantic_judge": semantic_judge_address,
        "assessment_evaluator":
            assessment_evaluator_address,
        "challenge_evaluator":
            challenge_evaluator_address,
    }


def _create_policy(
    engine,
    policy_registry: str,
    manifest_raw: bytes,
) -> None:
    valid_until = (
        int(
            datetime.now(
                timezone.utc
            ).timestamp()
        )
        + (10 * DAY)
    )

    _engine_call(
        engine,
        policy_registry,
        "create_policy",
        [
            POLICY_ID,
            CAPABILITY_ID,
            1,
            CRITERIA,
            MANIFEST_URL,
            MANIFEST_ID,
            MANIFEST_AUTHORITY,
            hashlib.sha256(
                manifest_raw
            ).hexdigest(),
            valid_until,
            3600,
        ],
        sender=OWNER,
    )


def _create_assessment(
    engine,
    registry: str,
    profile_digest: str,
) -> int:
    return int(
        _engine_call(
            engine,
            registry,
            "create_assessment",
            [
                profile_digest,
                ENDPOINT,
                POLICY_ID,
                1,
                900,
            ],
            sender=SUBJECT,
        )
    )


def _evaluate_assessment(
    engine,
    registry: str,
    assessment_id: int,
    harness: SemanticHarness,
    verdict: str,
) -> int:
    harness.verdict = verdict

    _engine_call(
        engine,
        registry,
        "evaluate_assessment",
        [assessment_id],
        sender=SUBJECT,
    )

    steps = _drain_messages(
        engine,
        registry,
    )

    assert not engine._post_queue
    return steps


def _open_challenge(
    engine,
    challenge: str,
    certificate_id: int,
) -> int:
    return int(
        _engine_call(
            engine,
            challenge,
            "open_challenge",
            [certificate_id],
            sender=CHALLENGER,
        )
    )


def _evaluate_challenge(
    engine,
    registry: str,
    challenge: str,
    challenge_id: int,
    harness: SemanticHarness,
    verdict: str,
) -> int:
    harness.verdict = verdict

    _engine_call(
        engine,
        challenge,
        "evaluate_challenge",
        [challenge_id],
        sender=EVALUATION_CALLER,
    )

    steps = _drain_messages(
        engine,
        registry,
    )

    assert not engine._post_queue
    return steps


def test_split_release_exact_source_fingerprints():
    for path, expected in EXPECTED_SHA256.items():
        assert path.exists(), path
        assert _sha(path) == expected, path


def test_split_evaluator_consensus_ast_is_identical_to_frozen_monolith():
    monolith_methods = _class_methods(MONOLITH, "AgentSeal")

    assessment_methods = _class_methods(
        LEGACY_ASSESSMENT_EVALUATOR,
        "AgentSealAssessmentEvaluator",
    )

    challenge_methods = _class_methods(
        LEGACY_CHALLENGE_EVALUATOR,
        "AgentSealChallengeEvaluator",
    )

    assert ASSESSMENT_PARITY_METHODS <= assessment_methods.keys()
    assert CHALLENGE_PARITY_METHODS <= challenge_methods.keys()

    for name in sorted(ASSESSMENT_PARITY_METHODS):
        assert _normalized_method(assessment_methods[name]) == _normalized_method(
            monolith_methods[name]
        ), name

    for name in sorted(CHALLENGE_PARITY_METHODS):
        assert _normalized_method(challenge_methods[name]) == _normalized_method(
            monolith_methods[name]
        ), name


def test_policy_registry_direct_mode_component_smoke(
    direct_vm,
    direct_deploy,
):
    # R3 Registry requires an external PolicyRegistry Address.
    # Direct Mode is deliberately single-contract here, so its
    # root PolicyRegistry is the correct independent smoke target.
    policy_registry = direct_deploy(
        str(POLICY)
    )

    owner = policy_registry.get_owner()
    policy_count = policy_registry.get_policy_count()

    assert isinstance(
        owner,
        str,
    )

    assert owner.startswith(
        "0x"
    )

    assert policy_count == 0


def test_split_glsim_component_wiring_and_one_time_configuration():
    with _sim_engine(
        "agentseal-split-r17-r3-wiring"
    ) as engine:
        a = _deploy_split(
            engine
        )

        registry = _engine_read(
            engine,
            a["registry"],
            "get_components",
        )

        certificate_registry = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_components",
        )

        challenge = _engine_read(
            engine,
            a["challenge"],
            "get_components",
        )

        judge = _engine_read(
            engine,
            a["semantic_judge"],
            "get_components",
        )

        support = _engine_read(
            engine,
            a["support"],
            "get_components",
        )

        assessment_evaluator = _engine_read(
            engine,
            a[
                "assessment_evaluator"
            ],
            "get_components",
        )

        challenge_evaluator = _engine_read(
            engine,
            a[
                "challenge_evaluator"
            ],
            "get_components",
        )

        assert registry[
            "configured"
        ] is True

        assert (
            registry[
                "policy_registry"
            ].lower()
            == a["policy"].lower()
        )

        assert (
            registry[
                "certificate_registry"
            ].lower()
            == a[
                "certificate_registry"
            ].lower()
        )

        assert (
            registry[
                "assessment_evaluator"
            ].lower()
            == a[
                "assessment_evaluator"
            ].lower()
        )

        assert (
            registry[
                "semantic_judge"
            ].lower()
            == a[
                "semantic_judge"
            ].lower()
        )

        assert (
            registry[
                "deterministic_support"
            ].lower()
            == a[
                "support"
            ].lower()
        )

        assert certificate_registry[
            "configured"
        ] is True

        assert (
            certificate_registry[
                "registry"
            ].lower()
            == a[
                "registry"
            ].lower()
        )

        assert (
            certificate_registry[
                "policy_registry"
            ].lower()
            == a[
                "policy"
            ].lower()
        )

        assert (
            certificate_registry[
                "challenge_contract"
            ].lower()
            == a[
                "challenge"
            ].lower()
        )

        assert challenge[
            "configured"
        ] is True

        assert (
            challenge[
                "certificate_registry"
            ].lower()
            == a[
                "certificate_registry"
            ].lower()
        )

        assert (
            challenge[
                "challenge_evaluator"
            ].lower()
            == a[
                "challenge_evaluator"
            ].lower()
        )

        assert (
            challenge[
                "semantic_judge"
            ].lower()
            == a[
                "semantic_judge"
            ].lower()
        )

        assert (
            challenge[
                "deterministic_support"
            ].lower()
            == a[
                "support"
            ].lower()
        )

        assert judge[
            "configured"
        ] is True

        assert (
            judge[
                "registry"
            ].lower()
            == a[
                "registry"
            ].lower()
        )

        assert (
            judge[
                "challenge_contract"
            ].lower()
            == a[
                "challenge"
            ].lower()
        )

        assert (
            judge[
                "assessment_evaluator"
            ].lower()
            == a[
                "assessment_evaluator"
            ].lower()
        )

        assert (
            judge[
                "challenge_evaluator"
            ].lower()
            == a[
                "challenge_evaluator"
            ].lower()
        )

        assert (
            support[
                "certificate_registry"
            ].lower()
            == a[
                "certificate_registry"
            ].lower()
        )

        assert (
            assessment_evaluator[
                "registry"
            ].lower()
            == a[
                "registry"
            ].lower()
        )

        assert (
            assessment_evaluator[
                "semantic_judge"
            ].lower()
            == a[
                "semantic_judge"
            ].lower()
        )

        assert (
            challenge_evaluator[
                "challenge_contract"
            ].lower()
            == a[
                "challenge"
            ].lower()
        )

        assert (
            challenge_evaluator[
                "registry"
            ].lower()
            == a[
                "registry"
            ].lower()
        )

        assert (
            challenge_evaluator[
                "semantic_judge"
            ].lower()
            == a[
                "semantic_judge"
            ].lower()
        )

        assert (
            challenge_evaluator[
                "deterministic_support"
            ].lower()
            == a[
                "support"
            ].lower()
        )

        with pytest.raises(
            Exception,
            match=(
                "COMPONENTS_ALREADY_CONFIGURED"
            ),
        ):
            _engine_call(
                engine,
                a["registry"],
                "configure_components",
                [
                    _addr(
                        a[
                            "certificate_registry"
                        ]
                    ),
                    _addr(
                        a[
                            "assessment_evaluator"
                        ]
                    ),
                    _addr(
                        a[
                            "semantic_judge"
                        ]
                    ),
                    _addr(
                        a[
                            "support"
                        ]
                    ),
                ],
                sender=OWNER,
            )

        with pytest.raises(
            Exception,
            match=(
                "CHALLENGE_CONTRACT_ALREADY_CONFIGURED"
            ),
        ):
            _engine_call(
                engine,
                a[
                    "certificate_registry"
                ],
                "configure_challenge",
                [
                    _addr(
                        a[
                            "challenge"
                        ]
                    )
                ],
                sender=OWNER,
            )

        with pytest.raises(
            Exception,
            match=(
                "EVALUATORS_ALREADY_CONFIGURED"
            ),
        ):
            _engine_call(
                engine,
                a[
                    "semantic_judge"
                ],
                "configure_evaluators",
                [
                    _addr(
                        a[
                            "assessment_evaluator"
                        ]
                    ),
                    _addr(
                        a[
                            "challenge_evaluator"
                        ]
                    ),
                ],
                sender=OWNER,
            )

        with pytest.raises(
            Exception,
            match=(
                "CHALLENGE_EVALUATOR_ALREADY_CONFIGURED"
            ),
        ):
            _engine_call(
                engine,
                a[
                    "challenge"
                ],
                "configure_evaluator",
                [
                    _addr(
                        a[
                            "challenge_evaluator"
                        ]
                    ),
                    _addr(
                        a[
                            "semantic_judge"
                        ]
                    ),
                    _addr(
                        a[
                            "support"
                        ]
                    ),
                ],
                sender=OWNER,
            )


def test_split_glsim_stable_drift_fail_end_to_end_parity():
    manifest_raw = _canonical_bytes(
        _manifest_payload()
    )

    harness = SemanticHarness(
        manifest_raw
    )

    with _sim_engine(
        "agentseal-split-r17-r3-lifecycle",
        harness,
    ) as engine:
        a = _deploy_split(
            engine
        )

        _create_policy(
            engine,
            a["policy"],
            manifest_raw,
        )

        stable_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_STABLE,
        )

        assert stable_id == 1

        stable_steps = _evaluate_assessment(
            engine,
            a["registry"],
            stable_id,
            harness,
            "PASS",
        )

        assert stable_steps >= 4

        stable_assessment = _engine_read(
            engine,
            a["registry"],
            "get_assessment",
            [stable_id],
        )

        stable_certificate = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_certificate",
            [stable_id],
        )

        assert stable_assessment[
            "status"
        ] == "PASSED"

        assert stable_assessment[
            "attempt_count"
        ] == 1

        assert stable_assessment[
            "certificate_delivery_pending"
        ] is False

        assert stable_certificate[
            "status"
        ] == "ACTIVE"

        assert stable_certificate[
            "effective_status"
        ] == "ACTIVE"

        stable_challenge_id = _open_challenge(
            engine,
            a["challenge"],
            stable_id,
        )

        assert stable_challenge_id == 1

        stable_challenge_steps = _evaluate_challenge(
            engine,
            a["registry"],
            a["challenge"],
            stable_challenge_id,
            harness,
            "PASS",
        )

        assert stable_challenge_steps >= 2

        stable_challenge = _engine_read(
            engine,
            a["challenge"],
            "get_challenge",
            [stable_challenge_id],
        )

        stable_certificate_after = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_certificate",
            [stable_id],
        )

        assert stable_challenge[
            "status"
        ] == "REJECTED"

        assert stable_challenge[
            "attempt_count"
        ] == 1

        assert stable_certificate_after[
            "status"
        ] == "ACTIVE"

        _engine_call(
            engine,
            a[
                "certificate_registry"
            ],
            "revoke_certificate",
            [stable_id],
            sender=SUBJECT,
        )

        _drain_messages(
            engine,
            a["registry"],
        )

        stable_revocation = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_revocation",
            [stable_id],
        )

        stable_certificate_revoked = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_certificate",
            [stable_id],
        )

        assert stable_certificate_revoked[
            "status"
        ] == "REVOKED"

        assert stable_revocation[
            "source"
        ] == "SUBJECT_SELF_REVOKE"

        assert (
            stable_revocation[
                "initiator"
            ].lower()
            == SUBJECT.lower()
        )

        drift_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_DRIFT,
        )

        assert drift_id == 2

        _evaluate_assessment(
            engine,
            a["registry"],
            drift_id,
            harness,
            "PASS",
        )

        drift_assessment = _engine_read(
            engine,
            a["registry"],
            "get_assessment",
            [drift_id],
        )

        drift_certificate = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_certificate",
            [drift_id],
        )

        assert drift_assessment[
            "status"
        ] == "PASSED"

        assert drift_certificate[
            "status"
        ] == "ACTIVE"

        drift_challenge_id = _open_challenge(
            engine,
            a["challenge"],
            drift_id,
        )

        assert drift_challenge_id == 2

        drift_steps = _evaluate_challenge(
            engine,
            a["registry"],
            a["challenge"],
            drift_challenge_id,
            harness,
            "FAIL",
        )

        assert drift_steps >= 4

        drift_challenge = _engine_read(
            engine,
            a["challenge"],
            "get_challenge",
            [drift_challenge_id],
        )

        drift_revocation = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_revocation",
            [drift_id],
        )

        drift_certificate_after = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "get_certificate",
            [drift_id],
        )

        delivery_pending = _engine_read(
            engine,
            a["challenge"],
            "get_revocation_delivery_pending",
            [drift_challenge_id],
        )

        assert drift_challenge[
            "status"
        ] == "UPHELD"

        assert drift_certificate_after[
            "status"
        ] == "REVOKED"

        assert drift_revocation[
            "source"
        ] == "CHALLENGE_CONSENSUS"

        assert drift_revocation[
            "challenge_id"
        ] == drift_challenge_id

        assert (
            drift_revocation[
                "initiator"
            ].lower()
            == EVALUATION_CALLER.lower()
        )

        assert delivery_pending is False

        fail_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_FAIL,
        )

        assert fail_id == 3

        _evaluate_assessment(
            engine,
            a["registry"],
            fail_id,
            harness,
            "FAIL",
        )

        fail_assessment = _engine_read(
            engine,
            a["registry"],
            "get_assessment",
            [fail_id],
        )

        fail_certificate_exists = _engine_read(
            engine,
            a[
                "certificate_registry"
            ],
            "certificate_exists",
            [fail_id],
        )

        assert fail_assessment[
            "status"
        ] == "FAILED"

        assert fail_assessment[
            "attempt_count"
        ] == 1

        assert fail_certificate_exists is False

        assert len(
            harness.endpoint_requests
        ) == 5

        assert len(
            harness.llm_events
        ) == 5

        assert not engine._post_queue


def test_split_challenge_initiator_capture_is_request_bound():
    methods = _class_methods(
        CHALLENGE,
        "AgentSealChallenge",
    )

    evaluate = methods[
        "evaluate_challenge"
    ]

    apply_result = methods[
        "apply_challenge_evaluation_result"
    ]

    retry = methods[
        "retry_challenge_revocation"
    ]

    def is_map(
        node: ast.AST,
    ) -> bool:
        return (
            isinstance(node, ast.Subscript)
            and isinstance(
                node.value,
                ast.Attribute,
            )
            and isinstance(
                node.value.value,
                ast.Name,
            )
            and node.value.value.id == "self"
            and node.value.attr
            == "revocation_initiator_by_challenge"
        )

    def is_sender(
        node: ast.AST,
    ) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "sender_address"
            and isinstance(
                node.value,
                ast.Attribute,
            )
            and node.value.attr == "message"
            and isinstance(
                node.value.value,
                ast.Name,
            )
            and node.value.value.id == "gl"
        )

    request_assignments = [
        node
        for node in ast.walk(evaluate)
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and is_map(node.targets[0])
        )
    ]

    assert len(request_assignments) == 1
    assert is_sender(
        request_assignments[0].value
    )

    for fn in (
        apply_result,
        retry,
    ):
        writes = [
            node
            for node in ast.walk(fn)
            if (
                isinstance(node, ast.Assign)
                and any(
                    is_map(target)
                    for target in node.targets
                )
            )
        ]

        assert writes == []

    dispatches = [
        node
        for node in ast.walk(evaluate)
        if (
            isinstance(node, ast.Call)
            and isinstance(
                node.func,
                ast.Attribute,
            )
            and node.func.attr
            == "evaluate_challenge"
        )
    ]

    assert len(dispatches) == 1

    assert (
        request_assignments[0].lineno
        < dispatches[0].lineno
    )

    for fn in (
        apply_result,
        retry,
    ):
        calls = [
            node
            for node in ast.walk(fn)
            if (
                isinstance(node, ast.Call)
                and isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr
                == "apply_challenge_revocation"
            )
        ]

        assert len(calls) == 1
        assert len(calls[0].args) >= 3
        assert is_map(calls[0].args[2])


def test_split_certificate_ttl_starts_at_actual_issuance_after_finalized_delivery_delay():
    manifest_raw = _canonical_bytes(
        _manifest_payload()
    )
    harness = SemanticHarness(
        manifest_raw
    )

    with _sim_engine(
        "agentseal-split-r17-r3-ttl-finality-delay",
        harness,
    ) as engine:
        a = _deploy_split(
            engine
        )
        _create_policy(
            engine,
            a["policy"],
            manifest_raw,
        )
        assessment_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_STABLE,
        )

        harness.verdict = "PASS"
        _engine_call(
            engine,
            a["registry"],
            "evaluate_assessment",
            [assessment_id],
            sender=SUBJECT,
        )

        # The top-level evaluate_assessment call already drains exactly one
        # queued PostMessage (the assessment evaluator). Therefore the queue
        # now starts at judge_assessment. Drain only judge + registry apply,
        # and prove that issue_certificate is still pending before the warp.
        assert len(engine._post_queue) == 1
        assert engine._post_queue[0]["method"] == "judge_assessment"

        for expected_method in (
            "judge_assessment",
            "apply_assessment_evaluation_result",
        ):
            assert len(engine._post_queue) == 1
            assert engine._post_queue[0]["method"] == expected_method
            _engine_read(
                engine,
                a["registry"],
                "get_owner",
            )

        assert len(engine._post_queue) == 1
        assert engine._post_queue[0]["method"] == "issue_certificate"

        current = datetime.fromisoformat(
            engine.vm._datetime.replace(
                "Z",
                "+00:00",
            )
        )
        delayed_issue_epoch = (
            int(current.timestamp())
            + 1200
        )
        engine.vm.warp(
            datetime.fromtimestamp(
                delayed_issue_epoch,
                timezone.utc,
            ).isoformat().replace(
                "+00:00",
                "Z",
            )
        )

        # Drain certificate issuance and its registry acknowledgement.
        # GLSim may drain both finalized messages during one harmless read,
        # so the regression must verify the final state rather than assume
        # a scheduler-specific intermediate queue length.
        issuance_steps = _drain_messages(
            engine,
            a["registry"],
        )
        assert issuance_steps >= 1
        assert not engine._post_queue

        assessment = _engine_read(
            engine,
            a["registry"],
            "get_assessment",
            [assessment_id],
        )
        certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [assessment_id],
        )

        assert assessment["status"] == "PASSED"
        assert assessment["certificate_delivery_pending"] is False
        assert certificate["status"] == "ACTIVE"
        assert certificate["effective_status"] == "ACTIVE"
        assert certificate["issued_at"] == delayed_issue_epoch
        assert certificate["expires_at"] == delayed_issue_epoch + 900
        assert (
            certificate["expires_at"]
            - certificate["issued_at"]
        ) == 900

