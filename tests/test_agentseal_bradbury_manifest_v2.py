from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fixtures.bradbury.service import fixture_service


REPO = Path(__file__).resolve().parents[1]
V1 = REPO / "fixtures" / "bradbury" / "agentseal-manifest-v1.json"
V2 = REPO / "fixtures" / "bradbury" / "agentseal-manifest-v2.json"

EXPECTED_V1_SHA256 = "adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa"
EXPECTED_V2_SHA256 = "e6bc4f7737f990c94cbf49b98343fab2c1474d1ba2108d627856e7465be36507"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_r7_manifest_v2_is_exact_versioned_successor():
    v1 = _load(V1)
    v2 = _load(V2)

    assert _sha(V1) == EXPECTED_V1_SHA256
    assert _sha(V2) == EXPECTED_V2_SHA256

    assert v1["schema"] == "agentseal-manifest-v1"
    assert v2["schema"] == "agentseal-manifest-v1"

    assert v1["policy_id"] == "agentseal-bradbury-v1"
    assert v2["policy_id"] == v1["policy_id"]

    assert v1["policy_version"] == 1
    assert v2["policy_version"] == 2

    assert v1["manifest_id"] == "agentseal-bradbury-manifest-v1"
    assert v2["manifest_id"] == "agentseal-bradbury-manifest-v2"

    for field in ("authority", "capability_id", "cases"):
        assert v2[field] == v1[field]

    canonical = json.dumps(
        v2,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert V2.read_bytes() == canonical


def test_existing_fixture_service_accepts_v2_request_bindings_without_service_change(monkeypatch):
    v1 = _load(V1)
    v2 = _load(V2)

    monkeypatch.setattr(fixture_service, "MANIFEST_PATH", V1)

    cases = [
        {
            "case_id": case["case_id"],
            "task": case["task"],
            "reference": case["reference"],
        }
        for case in v2["cases"][:2]
    ]
    base = {
        "protocol": "agentseal-evaluation-v1",
        "evaluation_id": "agentseal-v1:r7-manifest-v2-regression",
        "agent_wallet": "0x" + "22" * 20,
        "profile_digest": "b" * 64,
        "capability_id": v2["capability_id"],
        "policy_id": v2["policy_id"],
        "policy_version": v2["policy_version"],
        "manifest_id": v2["manifest_id"],
        "cases": cases,
    }

    stable = fixture_service._build_response("stable", dict(base))
    assert stable["policy_version"] == 2
    assert stable["manifest_id"] == "agentseal-bradbury-manifest-v2"
    assert [x["output"] for x in stable["results"]] == [
        cases[0]["reference"],
        cases[1]["reference"],
    ]

    challenge = dict(base)
    challenge["evaluation_id"] = "agentseal-challenge-v1:r7-manifest-v2-regression"
    drift = fixture_service._build_response("drift", challenge)
    assert all(
        result["output"] == fixture_service.INTENTIONAL_MISMATCH
        for result in drift["results"]
    )

    fail = fixture_service._build_response("fail", dict(base))
    assert all(
        result["output"] == fixture_service.INTENTIONAL_MISMATCH
        for result in fail["results"]
    )
