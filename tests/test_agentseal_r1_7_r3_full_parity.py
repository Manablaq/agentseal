from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glsim.engine import SimEngine
from glsim.state import StateStore


REPO = Path(os.environ["AGENTSEAL_REPO"])
R3 = Path(os.environ["AGENTSEAL_R3_DIR"])

POLICY = R3 / "agentseal_policy_registry.py"
REGISTRY = R3 / "agentseal_registry.py"
CERTIFICATE_REGISTRY = R3 / "agentseal_certificate_registry.py"
SUPPORT = R3 / "agentseal_deterministic_support.py"
CHALLENGE = R3 / "agentseal_challenge.py"
SEMANTIC_JUDGE = R3 / "agentseal_semantic_judge.py"
ASSESSMENT_EVALUATOR = R3 / "agentseal_assessment_evidence_evaluator.py"
CHALLENGE_EVALUATOR = R3 / "agentseal_challenge_evidence_evaluator.py"

EXPECTED_SHA256 = {
    ASSESSMENT_EVALUATOR: "07e2c5ba44c90f2236c58b87da88c0263b1995e38b634172b2fdee1172c2bbbf",
    CERTIFICATE_REGISTRY: "d6cfa80f8a7228e4c05cbbf35f01e484049a7404b2e872cc5f9ae9b386ce107f",
    CHALLENGE: "6b63365669d6288fc6df712767e14647a62fc12e17759f9e46746a8a27c3c026",
    CHALLENGE_EVALUATOR: "af6844036f705ec2380f560633aab679bbaf4d0cdcb14b5ac4c7c472fcb99037",
    SUPPORT: "cbe6b49a5523630a1426eb92dc14b5550875058cd8cb292bdf472ddaa59ce5ca",
    POLICY: "da593bf8276c1603c2ca1af2933057eef59cd80eeef72e0d5682f3dc0e755240",
    REGISTRY: "885ce68a6e547a71e29b8ff5549061909a6830a98bcaebe49db7cc93cde0b4e2",
    SEMANTIC_JUDGE: "28b1d33d5ca52613b7d033258b84e1c6128542c2f23a9ca617554e0313084ee2",
}

OWNER = "0x" + "11" * 20
SUBJECT = "0x" + "22" * 20
CHALLENGER = "0x" + "33" * 20
EVALUATION_CALLER = "0x" + "44" * 20
SECOND_CALLER = "0x" + "55" * 20

POLICY_ID = "agentseal-r17-policy-v1"
CAPABILITY_ID = "research"
MANIFEST_ID = "agentseal-r17-manifest-v1"
MANIFEST_AUTHORITY = "AgentSeal R1.7 Parity Authority"
CRITERIA = "Return correct structured research results."
MANIFEST_URL = "https://evidence.example.com/agentseal-r17-manifest.json"
ENDPOINT = "https://agent.example.com/evaluate"

PROFILE_STABLE = "b" * 64
PROFILE_DRIFT = "c" * 64
PROFILE_FAIL = "d" * 64
PROFILE_STALE = "e" * 64
PROFILE_EXPIRY = "f" * 64
PROFILE_CHALLENGE_EXPIRY = "a" * 64

DAY = 86_400


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
                "headers": {"content-type": "application/json"},
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
                        "output": "r1.7 parity output a",
                    },
                    {
                        "case_id": body["cases"][1]["case_id"],
                        "output": "r1.7 parity output b",
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


def _engine_call(
    engine,
    to: str,
    method: str,
    args: list | None = None,
    *,
    sender: str,
):
    return engine.call_method(
        to,
        method,
        args or [],
        {},
        sender=sender,
    )


def _engine_read(
    engine,
    to: str,
    method: str,
    args: list | None = None,
):
    return engine.call_method(
        to,
        method,
        args or [],
        {},
        sender=OWNER,
    )


@contextmanager
def _sim_engine(seed: str, harness: SemanticHarness | None = None):
    state = StateStore(chain_id=61127, seed=seed)
    engine = SimEngine(
        state,
        web_handler=harness.web_handler if harness is not None else None,
        llm_handler=harness.llm_handler if harness is not None else None,
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
        _engine_read(engine, registry_address, "get_owner")
    return steps


def _deploy_r3(engine) -> dict[str, str]:
    policy, _ = engine.deploy(str(POLICY), [], {}, sender=OWNER)
    registry, _ = engine.deploy(
        str(REGISTRY),
        [_addr(policy)],
        {},
        sender=OWNER,
    )
    cert, _ = engine.deploy(
        str(CERTIFICATE_REGISTRY),
        [_addr(registry), _addr(policy)],
        {},
        sender=OWNER,
    )
    support, _ = engine.deploy(
        str(SUPPORT),
        [_addr(cert)],
        {},
        sender=OWNER,
    )
    challenge, _ = engine.deploy(
        str(CHALLENGE),
        [_addr(cert)],
        {},
        sender=OWNER,
    )
    judge, _ = engine.deploy(
        str(SEMANTIC_JUDGE),
        [_addr(registry), _addr(challenge)],
        {},
        sender=OWNER,
    )
    assessment_evaluator, _ = engine.deploy(
        str(ASSESSMENT_EVALUATOR),
        [_addr(registry), _addr(judge)],
        {},
        sender=OWNER,
    )
    challenge_evaluator, _ = engine.deploy(
        str(CHALLENGE_EVALUATOR),
        [
            _addr(challenge),
            _addr(registry),
            _addr(judge),
            _addr(support),
        ],
        {},
        sender=OWNER,
    )

    _engine_call(
        engine,
        cert,
        "configure_challenge",
        [_addr(challenge)],
        sender=OWNER,
    )
    _engine_call(
        engine,
        judge,
        "configure_evaluators",
        [
            _addr(assessment_evaluator),
            _addr(challenge_evaluator),
        ],
        sender=OWNER,
    )
    _engine_call(
        engine,
        registry,
        "configure_components",
        [
            _addr(cert),
            _addr(assessment_evaluator),
            _addr(judge),
            _addr(support),
        ],
        sender=OWNER,
    )
    _engine_call(
        engine,
        challenge,
        "configure_evaluator",
        [
            _addr(challenge_evaluator),
            _addr(judge),
            _addr(support),
        ],
        sender=OWNER,
    )

    return {
        "policy": policy,
        "registry": registry,
        "certificate_registry": cert,
        "support": support,
        "challenge": challenge,
        "semantic_judge": judge,
        "assessment_evaluator": assessment_evaluator,
        "challenge_evaluator": challenge_evaluator,
    }


def _advance_engine_time(engine, seconds: int) -> None:
    current = datetime.fromisoformat(
        engine.vm._datetime.replace("Z", "+00:00")
    )
    advanced = datetime.fromtimestamp(
        int(current.timestamp()) + int(seconds),
        timezone.utc,
    )
    engine.vm.warp(
        advanced.isoformat().replace("+00:00", "Z")
    )


def _create_policy(
    engine,
    policy_registry: str,
    manifest_raw: bytes,
    *,
    valid_for: int = 10 * DAY,
    max_ttl: int = 3600,
) -> None:
    valid_until = int(datetime.now(timezone.utc).timestamp()) + valid_for
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
            hashlib.sha256(manifest_raw).hexdigest(),
            valid_until,
            max_ttl,
        ],
        sender=OWNER,
    )


def _create_assessment(
    engine,
    registry: str,
    profile_digest: str,
    *,
    ttl: int = 900,
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
                ttl,
            ],
            sender=SUBJECT,
        )
    )


def _evaluate_assessment(
    engine,
    addresses: dict[str, str],
    assessment_id: int,
    harness: SemanticHarness,
    verdict: str,
) -> int:
    harness.verdict = verdict
    _engine_call(
        engine,
        addresses["registry"],
        "evaluate_assessment",
        [assessment_id],
        sender=SUBJECT,
    )
    steps = _drain_messages(engine, addresses["registry"])
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
    addresses: dict[str, str],
    challenge_id: int,
    harness: SemanticHarness,
    verdict: str,
    *,
    sender: str = EVALUATION_CALLER,
) -> int:
    harness.verdict = verdict
    _engine_call(
        engine,
        addresses["challenge"],
        "evaluate_challenge",
        [challenge_id],
        sender=sender,
    )
    steps = _drain_messages(engine, addresses["registry"])
    assert not engine._post_queue
    return steps


def _certificate_payload(certificate: dict) -> str:
    payload = {
        "certificate_id": certificate["certificate_id"],
        "assessment_id": certificate["assessment_id"],
        "subject_wallet": certificate["subject_wallet"],
        "profile_digest": certificate["profile_digest"],
        "endpoint": certificate["endpoint"],
        "capability_id": certificate["capability_id"],
        "policy_id": certificate["policy_id"],
        "policy_version": certificate["policy_version"],
        "manifest_id": certificate["manifest_id"],
        "manifest_digest": certificate["manifest_digest"],
        "case_a_id": certificate["case_a_id"],
        "case_b_id": certificate["case_b_id"],
        "binding_key": certificate["binding_key"],
        "issued_at": certificate["issued_at"],
        "expires_at": certificate["expires_at"],
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def test_r3_exact_fingerprints_and_component_wiring():
    for path, expected in EXPECTED_SHA256.items():
        assert path.exists(), path
        assert _sha(path) == expected, path

    with _sim_engine("agentseal-r17-r3-wiring") as engine:
        a = _deploy_r3(engine)

        registry_components = _engine_read(
            engine, a["registry"], "get_components"
        )
        cert_components = _engine_read(
            engine, a["certificate_registry"], "get_components"
        )
        challenge_components = _engine_read(
            engine, a["challenge"], "get_components"
        )
        judge_components = _engine_read(
            engine, a["semantic_judge"], "get_components"
        )
        support_components = _engine_read(
            engine, a["support"], "get_components"
        )
        ae_components = _engine_read(
            engine, a["assessment_evaluator"], "get_components"
        )
        ce_components = _engine_read(
            engine, a["challenge_evaluator"], "get_components"
        )

        assert registry_components["configured"] is True
        assert registry_components["policy_registry"].lower() == a["policy"].lower()
        assert registry_components["certificate_registry"].lower() == a["certificate_registry"].lower()
        assert registry_components["assessment_evaluator"].lower() == a["assessment_evaluator"].lower()
        assert registry_components["semantic_judge"].lower() == a["semantic_judge"].lower()
        assert registry_components["deterministic_support"].lower() == a["support"].lower()

        assert cert_components["configured"] is True
        assert cert_components["registry"].lower() == a["registry"].lower()
        assert cert_components["policy_registry"].lower() == a["policy"].lower()
        assert cert_components["challenge_contract"].lower() == a["challenge"].lower()

        assert challenge_components["configured"] is True
        assert challenge_components["certificate_registry"].lower() == a["certificate_registry"].lower()
        assert challenge_components["challenge_evaluator"].lower() == a["challenge_evaluator"].lower()
        assert challenge_components["semantic_judge"].lower() == a["semantic_judge"].lower()
        assert challenge_components["deterministic_support"].lower() == a["support"].lower()

        assert judge_components["configured"] is True
        assert judge_components["registry"].lower() == a["registry"].lower()
        assert judge_components["challenge_contract"].lower() == a["challenge"].lower()
        assert judge_components["assessment_evaluator"].lower() == a["assessment_evaluator"].lower()
        assert judge_components["challenge_evaluator"].lower() == a["challenge_evaluator"].lower()

        assert support_components["certificate_registry"].lower() == a["certificate_registry"].lower()
        assert ae_components["registry"].lower() == a["registry"].lower()
        assert ae_components["semantic_judge"].lower() == a["semantic_judge"].lower()
        assert ce_components["challenge_contract"].lower() == a["challenge"].lower()
        assert ce_components["registry"].lower() == a["registry"].lower()
        assert ce_components["semantic_judge"].lower() == a["semantic_judge"].lower()
        assert ce_components["deterministic_support"].lower() == a["support"].lower()

        with pytest.raises(Exception, match="COMPONENTS_ALREADY_CONFIGURED"):
            _engine_call(
                engine,
                a["registry"],
                "configure_components",
                [
                    _addr(a["certificate_registry"]),
                    _addr(a["assessment_evaluator"]),
                    _addr(a["semantic_judge"]),
                    _addr(a["support"]),
                ],
                sender=OWNER,
            )

        with pytest.raises(Exception, match="CHALLENGE_EVALUATOR_ALREADY_CONFIGURED"):
            _engine_call(
                engine,
                a["challenge"],
                "configure_evaluator",
                [
                    _addr(a["challenge_evaluator"]),
                    _addr(a["semantic_judge"]),
                    _addr(a["support"]),
                ],
                sender=OWNER,
            )

        with pytest.raises(Exception, match="EVALUATORS_ALREADY_CONFIGURED"):
            _engine_call(
                engine,
                a["semantic_judge"],
                "configure_evaluators",
                [
                    _addr(a["assessment_evaluator"]),
                    _addr(a["challenge_evaluator"]),
                ],
                sender=OWNER,
            )


def test_r3_stable_drift_fail_end_to_end_parity():
    manifest_raw = _canonical_bytes(_manifest_payload())
    harness = SemanticHarness(manifest_raw)

    with _sim_engine("agentseal-r17-r3-lifecycle", harness) as engine:
        a = _deploy_r3(engine)
        _create_policy(engine, a["policy"], manifest_raw)

        stable_assessment_id = _create_assessment(
            engine, a["registry"], PROFILE_STABLE
        )
        assert stable_assessment_id == 1
        assert _evaluate_assessment(
            engine, a, stable_assessment_id, harness, "PASS"
        ) >= 4

        stable_assessment = _engine_read(
            engine, a["registry"], "get_assessment", [stable_assessment_id]
        )
        stable_certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [stable_assessment_id],
        )
        assert stable_assessment["status"] == "PASSED"
        assert stable_assessment["attempt_count"] == 1
        assert stable_assessment["certificate_delivery_pending"] is False
        assert stable_certificate["status"] == "ACTIVE"
        assert stable_certificate["effective_status"] == "ACTIVE"

        stable_challenge_id = _open_challenge(
            engine, a["challenge"], stable_assessment_id
        )
        assert stable_challenge_id == 1
        assert _evaluate_challenge(
            engine, a, stable_challenge_id, harness, "PASS"
        ) >= 2

        stable_challenge = _engine_read(
            engine,
            a["challenge"],
            "get_challenge",
            [stable_challenge_id],
        )
        stable_certificate_after = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [stable_assessment_id],
        )
        assert stable_challenge["status"] == "REJECTED"
        assert stable_challenge["attempt_count"] == 1
        assert stable_certificate_after["status"] == "ACTIVE"

        _engine_call(
            engine,
            a["certificate_registry"],
            "revoke_certificate",
            [stable_assessment_id],
            sender=SUBJECT,
        )
        _drain_messages(engine, a["registry"])

        stable_revocation = _engine_read(
            engine,
            a["certificate_registry"],
            "get_revocation",
            [stable_assessment_id],
        )
        assert stable_revocation["source"] == "SUBJECT_SELF_REVOKE"
        assert stable_revocation["initiator"].lower() == SUBJECT.lower()

        drift_assessment_id = _create_assessment(
            engine, a["registry"], PROFILE_DRIFT
        )
        assert drift_assessment_id == 2
        _evaluate_assessment(
            engine, a, drift_assessment_id, harness, "PASS"
        )

        drift_challenge_id = _open_challenge(
            engine, a["challenge"], drift_assessment_id
        )
        assert drift_challenge_id == 2
        assert _evaluate_challenge(
            engine, a, drift_challenge_id, harness, "FAIL"
        ) >= 4

        drift_challenge = _engine_read(
            engine,
            a["challenge"],
            "get_challenge",
            [drift_challenge_id],
        )
        drift_revocation = _engine_read(
            engine,
            a["certificate_registry"],
            "get_revocation",
            [drift_assessment_id],
        )
        drift_certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [drift_assessment_id],
        )
        pending = _engine_read(
            engine,
            a["challenge"],
            "get_revocation_delivery_pending",
            [drift_challenge_id],
        )

        assert drift_challenge["status"] == "UPHELD"
        assert drift_certificate["status"] == "REVOKED"
        assert drift_revocation["source"] == "CHALLENGE_CONSENSUS"
        assert drift_revocation["challenge_id"] == drift_challenge_id
        assert drift_revocation["initiator"].lower() == EVALUATION_CALLER.lower()
        assert pending is False

        fail_assessment_id = _create_assessment(
            engine, a["registry"], PROFILE_FAIL
        )
        assert fail_assessment_id == 3
        _evaluate_assessment(
            engine, a, fail_assessment_id, harness, "FAIL"
        )

        fail_assessment = _engine_read(
            engine, a["registry"], "get_assessment", [fail_assessment_id]
        )
        fail_certificate_exists = _engine_read(
            engine,
            a["certificate_registry"],
            "certificate_exists",
            [fail_assessment_id],
        )
        assert fail_assessment["status"] == "FAILED"
        assert fail_assessment["attempt_count"] == 1
        assert fail_certificate_exists is False

        assert len(harness.endpoint_requests) == 5
        assert len(harness.llm_events) == 5
        assert not engine._post_queue


def test_r3_stale_assessment_callback_and_duplicate_certificate_delivery_are_safe():
    manifest_raw = _canonical_bytes(_manifest_payload())
    harness = SemanticHarness(manifest_raw)

    with _sim_engine("agentseal-r17-r3-stale-assessment", harness) as engine:
        a = _deploy_r3(engine)
        _create_policy(engine, a["policy"], manifest_raw)

        assessment_id = _create_assessment(
            engine, a["registry"], PROFILE_STALE
        )
        harness.verdict = "PASS"

        _engine_call(
            engine,
            a["registry"],
            "evaluate_assessment",
            [assessment_id],
            sender=SUBJECT,
        )

        with pytest.raises(Exception, match="ASSESSMENT_EVALUATION_STALE"):
            _engine_call(
                engine,
                a["registry"],
                "apply_assessment_evaluation_result",
                [assessment_id, 1, 999, "PASS", "stale-a", "stale-b"],
                sender=a["semantic_judge"],
            )

        _drain_messages(engine, a["registry"])

        assessment = _engine_read(
            engine, a["registry"], "get_assessment", [assessment_id]
        )
        certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [assessment_id],
        )
        assert assessment["status"] == "PASSED"
        assert assessment["certificate_delivery_pending"] is False

        _engine_call(
            engine,
            a["registry"],
            "acknowledge_certificate_issuance",
            [
                assessment_id,
                assessment_id,
                assessment["binding_key"],
            ],
            sender=a["certificate_registry"],
        )

        _engine_call(
            engine,
            a["certificate_registry"],
            "issue_certificate",
            [_certificate_payload(certificate)],
            sender=a["registry"],
        )
        _drain_messages(engine, a["registry"])

        after = _engine_read(
            engine, a["registry"], "get_assessment", [assessment_id]
        )
        certificate_after = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [assessment_id],
        )
        assert after["status"] == "PASSED"
        assert after["certificate_delivery_pending"] is False
        assert certificate_after["status"] == "ACTIVE"
        assert not engine._post_queue


def test_r3_stale_challenge_callback_replay_and_duplicate_revocation_are_safe():
    manifest_raw = _canonical_bytes(_manifest_payload())
    harness = SemanticHarness(manifest_raw)

    with _sim_engine("agentseal-r17-r3-stale-challenge", harness) as engine:
        a = _deploy_r3(engine)
        _create_policy(engine, a["policy"], manifest_raw)

        assessment_id = _create_assessment(
            engine, a["registry"], PROFILE_DRIFT
        )
        _evaluate_assessment(engine, a, assessment_id, harness, "PASS")

        challenge_id = _open_challenge(
            engine, a["challenge"], assessment_id
        )
        harness.verdict = "FAIL"

        _engine_call(
            engine,
            a["challenge"],
            "evaluate_challenge",
            [challenge_id],
            sender=EVALUATION_CALLER,
        )

        with pytest.raises(Exception, match="CHALLENGE_EVALUATION_PENDING"):
            _engine_call(
                engine,
                a["challenge"],
                "evaluate_challenge",
                [challenge_id],
                sender=SECOND_CALLER,
            )

        with pytest.raises(Exception, match="CHALLENGE_EVALUATION_STALE"):
            _engine_call(
                engine,
                a["challenge"],
                "apply_challenge_evaluation_result",
                [challenge_id, 1, 999, "FAIL", "stale-a", "stale-b"],
                sender=a["semantic_judge"],
            )

        _drain_messages(engine, a["registry"])

        challenge = _engine_read(
            engine, a["challenge"], "get_challenge", [challenge_id]
        )
        revocation = _engine_read(
            engine,
            a["certificate_registry"],
            "get_revocation",
            [assessment_id],
        )
        certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [assessment_id],
        )

        assert challenge["status"] == "UPHELD"
        assert certificate["status"] == "REVOKED"
        assert revocation["source"] == "CHALLENGE_CONSENSUS"
        assert revocation["initiator"].lower() == EVALUATION_CALLER.lower()

        _engine_call(
            engine,
            a["challenge"],
            "acknowledge_revocation",
            [challenge_id, assessment_id],
            sender=a["certificate_registry"],
        )

        _engine_call(
            engine,
            a["certificate_registry"],
            "apply_challenge_revocation",
            [
                assessment_id,
                challenge_id,
                _addr(EVALUATION_CALLER),
                certificate["binding_key"],
            ],
            sender=a["challenge"],
        )
        _drain_messages(engine, a["registry"])

        _engine_call(
            engine,
            a["challenge"],
            "retry_challenge_revocation",
            [challenge_id],
            sender=SECOND_CALLER,
        )

        revocation_after = _engine_read(
            engine,
            a["certificate_registry"],
            "get_revocation",
            [assessment_id],
        )
        pending = _engine_read(
            engine,
            a["challenge"],
            "get_revocation_delivery_pending",
            [challenge_id],
        )
        assert revocation_after["initiator"].lower() == EVALUATION_CALLER.lower()
        assert revocation_after["challenge_id"] == challenge_id
        assert pending is False
        assert not engine._post_queue


def test_r3_assessment_challenge_and_certificate_expiry_liveness():
    manifest_raw = _canonical_bytes(_manifest_payload())

    with _sim_engine("agentseal-r17-r3-assessment-expiry") as engine:
        a = _deploy_r3(engine)
        _create_policy(
            engine,
            a["policy"],
            manifest_raw,
            valid_for=2,
            max_ttl=60,
        )

        assessment_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_EXPIRY,
            ttl=30,
        )
        _advance_engine_time(engine, 3)

        _engine_call(
            engine,
            a["registry"],
            "expire_assessment",
            [assessment_id],
            sender=SECOND_CALLER,
        )

        assessment = _engine_read(
            engine, a["registry"], "get_assessment", [assessment_id]
        )
        assert assessment["status"] == "EXPIRED"
        assert assessment["certificate_delivery_pending"] is False
        assert _engine_read(
            engine,
            a["registry"],
            "get_live_assessment_id",
            [assessment["binding_key"]],
        ) == 0

    harness = SemanticHarness(manifest_raw)

    with _sim_engine("agentseal-r17-r3-challenge-expiry", harness) as engine:
        a = _deploy_r3(engine)
        _create_policy(
            engine,
            a["policy"],
            manifest_raw,
            valid_for=60,
            max_ttl=4,
        )

        assessment_id = _create_assessment(
            engine,
            a["registry"],
            PROFILE_CHALLENGE_EXPIRY,
            ttl=4,
        )
        _evaluate_assessment(engine, a, assessment_id, harness, "PASS")

        challenge_id = _open_challenge(
            engine,
            a["challenge"],
            assessment_id,
        )

        _advance_engine_time(engine, 5)

        _engine_call(
            engine,
            a["challenge"],
            "expire_challenge",
            [challenge_id],
            sender=SECOND_CALLER,
        )
        _engine_call(
            engine,
            a["certificate_registry"],
            "expire_certificate",
            [assessment_id],
            sender=SECOND_CALLER,
        )

        challenge = _engine_read(
            engine,
            a["challenge"],
            "get_challenge",
            [challenge_id],
        )
        certificate = _engine_read(
            engine,
            a["certificate_registry"],
            "get_certificate",
            [assessment_id],
        )
        assert challenge["status"] == "EXPIRED"
        assert certificate["status"] == "EXPIRED"
        assert _engine_read(
            engine,
            a["challenge"],
            "get_open_challenge_id",
            [assessment_id],
        ) == 0
        assert _engine_read(
            engine,
            a["certificate_registry"],
            "get_active_certificate_id",
            [certificate["binding_key"]],
        ) == 0
