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
REGISTRY = ROOT / "contracts" / "agentseal_registry.py"
CHALLENGE = ROOT / "contracts" / "agentseal_challenge.py"
ASSESSMENT_EVALUATOR = ROOT / "contracts" / "agentseal_assessment_evaluator.py"
CHALLENGE_EVALUATOR = ROOT / "contracts" / "agentseal_challenge_evaluator.py"

EXPECTED_SHA256 = {
    MONOLITH: "61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d",
    REGISTRY: "78a90c8d481ce1916525140fff852a50c112933d7390bb9bb6c312268634750f",
    CHALLENGE: "83af923a2bcef7a0c197dd307f70889eea07bfe58b68354e83a410825ad86bb8",
    ASSESSMENT_EVALUATOR: "16a9674adba592ad530e51d8c808791f1dcab70a35bc5b36a946ab19dcbbb8e2",
    CHALLENGE_EVALUATOR: "58616f754d4e54fc2ed9739d2574341f6a6b23f42d7600e2228037e02c6b1ca4",
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


def _drain_messages(engine, registry_address: str, *, limit: int = 12) -> int:
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
    registry_address, _ = engine.deploy(
        str(REGISTRY),
        [],
        {},
        sender=OWNER,
    )

    registry = _addr(registry_address)

    assessment_evaluator_address, _ = engine.deploy(
        str(ASSESSMENT_EVALUATOR),
        [registry],
        {},
        sender=OWNER,
    )

    challenge_address, _ = engine.deploy(
        str(CHALLENGE),
        [registry],
        {},
        sender=OWNER,
    )

    challenge = _addr(challenge_address)

    challenge_evaluator_address, _ = engine.deploy(
        str(CHALLENGE_EVALUATOR),
        [challenge, registry],
        {},
        sender=OWNER,
    )

    _engine_call(
        engine,
        registry_address,
        "configure_components",
        [
            _addr(assessment_evaluator_address),
            challenge,
        ],
        sender=OWNER,
    )

    _engine_call(
        engine,
        challenge_address,
        "configure_evaluator",
        [
            _addr(challenge_evaluator_address),
        ],
        sender=OWNER,
    )

    return {
        "registry": registry_address,
        "assessment_evaluator": assessment_evaluator_address,
        "challenge": challenge_address,
        "challenge_evaluator": challenge_evaluator_address,
    }


def _create_policy(engine, registry: str, manifest_raw: bytes) -> None:
    valid_until = int(datetime.now(timezone.utc).timestamp()) + (10 * DAY)

    _engine_call(
        engine,
        registry,
        "create_policy",
        [
            POLICY_ID,
            CAPABILITY_ID,
            1,
            CRITERIA,
            MANIFEST_URL,
            MANIFEST_ID,
            MANIFEST_AUTHORITY,
            hashlib.sha256(manifest_raw).hexdigest(),
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
        ASSESSMENT_EVALUATOR,
        "AgentSealAssessmentEvaluator",
    )

    challenge_methods = _class_methods(
        CHALLENGE_EVALUATOR,
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


def test_registry_direct_mode_component_smoke(direct_vm, direct_deploy):
    registry = direct_deploy(str(REGISTRY))

    owner = registry.get_owner()
    components = registry.get_components()

    assert isinstance(owner, str)
    assert owner.startswith("0x")
    assert components["configured"] is False
    assert components["assessment_evaluator"] == "0x" + ("00" * 20)
    assert components["challenge_contract"] == "0x" + ("00" * 20)


def test_split_glsim_component_wiring_and_one_time_configuration():
    with _sim_engine(
        "agentseal-split-wiring-r2"
    ) as engine:
        addresses = _deploy_split(engine)

        registry_components = _engine_read(
            engine,
            addresses["registry"],
            "get_components",
        )

        challenge_components = _engine_read(
            engine,
            addresses["challenge"],
            "get_components",
        )

        assert registry_components["configured"] is True
        assert registry_components["assessment_evaluator"].lower() == (
            addresses["assessment_evaluator"].lower()
        )
        assert registry_components["challenge_contract"].lower() == (
            addresses["challenge"].lower()
        )

        assert challenge_components["configured"] is True
        assert challenge_components["registry"].lower() == (
            addresses["registry"].lower()
        )
        assert challenge_components["challenge_evaluator"].lower() == (
            addresses["challenge_evaluator"].lower()
        )

        with pytest.raises(Exception, match="COMPONENTS_ALREADY_CONFIGURED"):
            _engine_call(
                engine,
                addresses["registry"],
                "configure_components",
                [
                    _addr(addresses["assessment_evaluator"]),
                    _addr(addresses["challenge"]),
                ],
                sender=OWNER,
            )

        with pytest.raises(Exception, match="CHALLENGE_EVALUATOR_ALREADY_CONFIGURED"):
            _engine_call(
                engine,
                addresses["challenge"],
                "configure_evaluator",
                [_addr(addresses["challenge_evaluator"])],
                sender=OWNER,
            )


def test_split_glsim_stable_drift_fail_end_to_end_parity():
    manifest_raw = _canonical_bytes(_manifest_payload())
    harness = SemanticHarness(manifest_raw)

    with _sim_engine(
        "agentseal-split-lifecycle-r2",
        harness,
    ) as engine:
        addresses = _deploy_split(engine)
        registry = addresses["registry"]
        challenge = addresses["challenge"]

        _create_policy(
            engine,
            registry,
            manifest_raw,
        )

        # Stable assessment -> PASS -> active certificate.
        stable_assessment_id = _create_assessment(
            engine,
            registry,
            PROFILE_STABLE,
        )
        assert stable_assessment_id == 1

        stable_steps = _evaluate_assessment(
            engine,
            registry,
            stable_assessment_id,
            harness,
            "PASS",
        )
        assert stable_steps >= 1

        stable_assessment = _engine_read(
            engine,
            registry,
            "get_assessment",
            [stable_assessment_id],
        )
        stable_certificate = _engine_read(
            engine,
            registry,
            "get_certificate",
            [stable_assessment_id],
        )

        assert stable_assessment["status"] == "PASSED"
        assert stable_assessment["attempt_count"] == 1
        assert stable_certificate["status"] == "ACTIVE"
        assert stable_certificate["effective_status"] == "ACTIVE"
        assert stable_certificate["certificate_id"] == stable_assessment_id

        # Stable challenge -> semantic PASS -> challenge REJECTED.
        stable_challenge_id = _open_challenge(
            engine,
            challenge,
            stable_assessment_id,
        )
        assert stable_challenge_id == 1

        stable_challenge_steps = _evaluate_challenge(
            engine,
            registry,
            challenge,
            stable_challenge_id,
            harness,
            "PASS",
        )
        assert stable_challenge_steps >= 1

        stable_challenge = _engine_read(
            engine,
            challenge,
            "get_challenge",
            [stable_challenge_id],
        )
        stable_certificate_after_challenge = _engine_read(
            engine,
            registry,
            "get_certificate",
            [stable_assessment_id],
        )

        assert stable_challenge["status"] == "REJECTED"
        assert stable_challenge["attempt_count"] == 1
        assert stable_certificate_after_challenge["status"] == "ACTIVE"
        assert stable_certificate_after_challenge["effective_status"] == "ACTIVE"

        # Direct subject revocation retains original monolith consequence.
        _engine_call(
            engine,
            registry,
            "revoke_certificate",
            [stable_assessment_id],
            sender=SUBJECT,
        )
        _drain_messages(engine, registry)

        stable_revocation = _engine_read(
            engine,
            registry,
            "get_revocation",
            [stable_assessment_id],
        )
        stable_certificate_revoked = _engine_read(
            engine,
            registry,
            "get_certificate",
            [stable_assessment_id],
        )

        assert stable_certificate_revoked["status"] == "REVOKED"
        assert stable_revocation["source"] == "SUBJECT_SELF_REVOKE"
        assert stable_revocation["initiator"].lower() == SUBJECT.lower()

        # Drift assessment -> PASS -> active certificate.
        drift_assessment_id = _create_assessment(
            engine,
            registry,
            PROFILE_DRIFT,
        )
        assert drift_assessment_id == 2

        _evaluate_assessment(
            engine,
            registry,
            drift_assessment_id,
            harness,
            "PASS",
        )

        drift_assessment = _engine_read(
            engine,
            registry,
            "get_assessment",
            [drift_assessment_id],
        )
        drift_certificate = _engine_read(
            engine,
            registry,
            "get_certificate",
            [drift_assessment_id],
        )

        assert drift_assessment["status"] == "PASSED"
        assert drift_certificate["status"] == "ACTIVE"
        assert drift_certificate["effective_status"] == "ACTIVE"

        # Drift challenge -> semantic FAIL -> UPHELD -> challenge consensus revocation.
        drift_challenge_id = _open_challenge(
            engine,
            challenge,
            drift_assessment_id,
        )
        assert drift_challenge_id == 2

        drift_challenge_steps = _evaluate_challenge(
            engine,
            registry,
            challenge,
            drift_challenge_id,
            harness,
            "FAIL",
        )
        # callback -> registry revocation -> acknowledgment requires multiple pumps.
        assert drift_challenge_steps >= 3

        drift_challenge = _engine_read(
            engine,
            challenge,
            "get_challenge",
            [drift_challenge_id],
        )
        drift_revocation = _engine_read(
            engine,
            registry,
            "get_revocation",
            [drift_assessment_id],
        )
        drift_certificate_revoked = _engine_read(
            engine,
            registry,
            "get_certificate",
            [drift_assessment_id],
        )
        delivery_pending = _engine_read(
            engine,
            challenge,
            "get_revocation_delivery_pending",
            [drift_challenge_id],
        )

        assert drift_challenge["status"] == "UPHELD"
        assert drift_certificate_revoked["status"] == "REVOKED"
        assert drift_revocation["source"] == "CHALLENGE_CONSENSUS"
        assert drift_revocation["challenge_id"] == drift_challenge_id
        assert drift_revocation["initiator"].lower() == EVALUATION_CALLER.lower()
        assert delivery_pending is False

        # Fail assessment -> FAIL -> terminal, no certificate.
        fail_assessment_id = _create_assessment(
            engine,
            registry,
            PROFILE_FAIL,
        )
        assert fail_assessment_id == 3

        _evaluate_assessment(
            engine,
            registry,
            fail_assessment_id,
            harness,
            "FAIL",
        )

        fail_assessment = _engine_read(
            engine,
            registry,
            "get_assessment",
            [fail_assessment_id],
        )
        fail_certificate_exists = _engine_read(
            engine,
            registry,
            "certificate_exists",
            [fail_assessment_id],
        )

        assert fail_assessment["status"] == "FAILED"
        assert fail_assessment["attempt_count"] == 1
        assert fail_certificate_exists is False

        assert len(harness.endpoint_requests) == 5
        assert len(harness.llm_events) == 5
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
