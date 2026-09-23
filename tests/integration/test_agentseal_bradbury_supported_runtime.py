from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import pytest
from genlayer_py import create_account, create_client
from genlayer_py.assertions import tx_execution_succeeded
from genlayer_py.chains import testnet_bradbury
from genlayer_py.types import TransactionStatus

REPO = Path(__file__).resolve().parents[2]
CONTRACT = REPO / "contracts" / "agentseal.py"
PROFILE_FIXTURE = REPO / "fixtures" / "bradbury" / "agentseal-profile-v1.json"
MANIFEST_FIXTURE = REPO / "fixtures" / "bradbury" / "agentseal-manifest-v1.json"
FEE_PROFILE = REPO / "fee-profile.json"
CHECKPOINT = REPO / "artifacts" / "agentseal-bradbury-supported-runtime-checkpoint.json"

RUN_GATE = "AGENTSEAL_RUN_BRADBURY_SUPPORTED_RUNTIME"
OWNER_KEY_ENV = "AGENTSEAL_BRADBURY_OWNER_PRIVATE_KEY"
SUBJECT_KEY_ENV = "AGENTSEAL_BRADBURY_SUBJECT_PRIVATE_KEY"
MANIFEST_URL_ENV = "AGENTSEAL_BRADBURY_MANIFEST_URL"
STABLE_ENDPOINT_ENV = "AGENTSEAL_BRADBURY_STABLE_ENDPOINT"
DRIFT_ENDPOINT_ENV = "AGENTSEAL_BRADBURY_DRIFT_ENDPOINT"
FAIL_ENDPOINT_ENV = "AGENTSEAL_BRADBURY_FAIL_ENDPOINT"
FIXTURE_SOURCE_SHA_ENV = "AGENTSEAL_BRADBURY_FIXTURE_SOURCE_SHA"

EXPECTED_CHAIN_ID = 4221
EXPECTED_CONTRACT_SHA = "61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d"
EXPECTED_PROFILE_SHA = "bc32dc6c11ac40ce5593a38dbb01a073dc52258bcb9efd0ad7189109b440df39"
EXPECTED_MANIFEST_SHA = "adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa"

POLICY_ID = "agentseal-bradbury-v1"
CAPABILITY_ID = "research"
MANIFEST_ID = "agentseal-bradbury-manifest-v1"
MANIFEST_AUTHORITY = "AgentSeal Bradbury Fixture Authority"
CRITERIA = "PASS only when both selected outputs exactly match their case references; otherwise FAIL."
POLICY_VERSION = 1
CERT_TTL = 900
POLICY_MAX_TTL = 3600

OPERATION_KEYS = [
    "01_deploy_agentseal",
    "02_create_policy",
    "03_create_stable_assessment",
    "04_evaluate_stable_assessment",
    "05_open_stable_challenge",
    "06_evaluate_stable_challenge",
    "07_revoke_stable_certificate",
    "08_create_drift_assessment",
    "09_evaluate_drift_assessment",
    "10_open_drift_challenge",
    "11_evaluate_drift_challenge",
    "12_create_fail_assessment",
    "13_evaluate_fail_assessment",
]

ALLOWED_ESTIMATE_OPTION_KEYS = {
    "leaderTimeunitsAllocation",
    "validatorTimeunitsAllocation",
    "appealRounds",
    "executionBudgetPerRound",
    "executionConsumed",
    "totalMessageFees",
    "rotations",
    "messageAllocations",
    "priceCapHeadroomBps",
}

pytestmark = pytest.mark.skipif(
    os.getenv(RUN_GATE) != "1",
    reason=f"Bradbury execution is opt-in only; set {RUN_GATE}=1 after prerequisites are ready.",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise AssertionError(f"required live environment variable missing: {name}")
    return value


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if hasattr(value, "hex"):
        try:
            raw = str(value.hex())
            return raw if raw.startswith("0x") else "0x" + raw
        except Exception:
            pass
    return str(value)


def _tx_hash_text(value: object) -> str:
    text = str(_json_safe(value))
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return "0x" + text.lower()
    return text.lower()


def _load_checkpoint() -> dict[str, Any]:
    if not CHECKPOINT.exists():
        return {"schema": "agentseal-bradbury-checkpoint-v1", "steps": {}, "state": {}}
    value = json.loads(CHECKPOINT.read_text(encoding="utf-8"))
    assert value["schema"] == "agentseal-bradbury-checkpoint-v1"
    return value


def _save_checkpoint(value: dict[str, Any]) -> None:
    CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
    temp = CHECKPOINT.with_suffix(".tmp")
    temp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(CHECKPOINT)


def _receipt_contract_address(receipt: dict[str, Any]) -> str:
    return str(receipt["tx_data_decoded"]["contract_address"])


def _load_fee_profile(
    manifest_url: str,
    stable_endpoint: str,
    drift_endpoint: str,
    fail_endpoint: str,
    fixture_source_sha: str,
) -> dict[str, Any]:
    assert FEE_PROFILE.exists(), "fee-profile.json is required before any Bradbury write"
    profile = json.loads(FEE_PROFILE.read_text(encoding="utf-8"))
    assert profile["schema"] == "agentseal-fee-profile-v1"
    assert profile["chain_id"] == EXPECTED_CHAIN_ID
    assert profile["contract_sha256"] == EXPECTED_CONTRACT_SHA
    assert profile["manifest_sha256"] == EXPECTED_MANIFEST_SHA
    assert profile["profile_sha256"] == EXPECTED_PROFILE_SHA
    assert profile["fixture_source_sha"] == fixture_source_sha
    assert profile["inputs"] == {
        "manifest_url": manifest_url,
        "stable_endpoint": stable_endpoint,
        "drift_endpoint": drift_endpoint,
        "fail_endpoint": fail_endpoint,
    }

    operations = profile["operations"]
    assert set(operations) == set(OPERATION_KEYS)

    for key in OPERATION_KEYS:
        entry = operations[key]
        options = entry["estimate_options"]
        assert isinstance(options, dict) and options
        assert set(options).issubset(ALLOWED_ESTIMATE_OPTION_KEYS)
        for forbidden in (
            "maxPriceGenPerTimeUnit",
            "storageFeeMaxGasPrice",
            "receiptFeeMaxGasPrice",
            "feeValue",
            "fee_value",
        ):
            assert forbidden not in options
        measurement = entry["measurement"]
        assert measurement["measured"] is True
        assert re.fullmatch(r"[0-9a-f]{64}", measurement["raw_evidence_sha256"])

    return profile


def _fees_for(client, fee_profile: dict[str, Any], operation: str) -> dict[str, Any]:
    options = fee_profile["operations"][operation]["estimate_options"]
    estimate = client.estimate_transaction_fees(options=options)
    fees = {
        "distribution": estimate["distribution"],
        "feeValue": estimate["feeValue"],
    }
    allocations = estimate.get("messageAllocations") or estimate.get("message_allocations")
    if allocations is not None:
        fees["messageAllocations"] = allocations
    return fees


def _finalize_step(checkpoint, client, step_key: str, submit):
    record = checkpoint["steps"].get(step_key)

    if record is None:
        tx_hash = submit()
        record = {
            "tx_hash": _tx_hash_text(tx_hash),
            "submitted": True,
            "finalized": False,
        }
        checkpoint["steps"][step_key] = record
        _save_checkpoint(checkpoint)

    if record.get("finalized") is True:
        return record["receipt"]

    receipt = client.wait_for_transaction_receipt(
        transaction_hash=record["tx_hash"],
        status=TransactionStatus.FINALIZED,
        interval=10,
        retries=180,
        full_transaction=True,
    )
    assert tx_execution_succeeded(receipt), f"{step_key} finalized without successful execution"

    safe = _json_safe(receipt)
    assert isinstance(safe, dict)
    record["receipt"] = safe
    record["finalized"] = True
    _save_checkpoint(checkpoint)
    return safe


def _write(client, account, address, operation, fee_profile, function_name, args):
    return client.write_contract(
        address=address,
        function_name=function_name,
        account=account,
        args=args,
        fees=_fees_for(client, fee_profile, operation),
    )


def _read(client, address, function_name, args=None):
    return client.read_contract(
        address=address,
        function_name=function_name,
        args=args or [],
    )


def _assert_fixture_urls(manifest_url, stable_endpoint, drift_endpoint, fail_endpoint, source_sha):
    for value in (manifest_url, stable_endpoint, drift_endpoint, fail_endpoint):
        assert value.startswith("https://")
    assert re.fullmatch(r"[0-9a-f]{40}", source_sha)
    assert stable_endpoint.rstrip("/").endswith("/stable")
    assert drift_endpoint.rstrip("/").endswith("/drift")
    assert fail_endpoint.rstrip("/").endswith("/fail")
    manifest_pattern = re.compile(
        r"^https://raw\.githubusercontent\.com/Manablaq/agentseal/"
        r"[0-9a-f]{40}/fixtures/bradbury/agentseal-manifest-v1\.json$"
    )
    assert manifest_pattern.fullmatch(manifest_url)


def test_agentseal_bradbury_supported_runtime_finality_matrix():
    assert testnet_bradbury.id == EXPECTED_CHAIN_ID
    assert _sha256(CONTRACT) == EXPECTED_CONTRACT_SHA
    assert _sha256(PROFILE_FIXTURE) == EXPECTED_PROFILE_SHA
    assert _sha256(MANIFEST_FIXTURE) == EXPECTED_MANIFEST_SHA

    owner_key = _required_env(OWNER_KEY_ENV)
    subject_key = _required_env(SUBJECT_KEY_ENV)
    manifest_url = _required_env(MANIFEST_URL_ENV)
    stable_endpoint = _required_env(STABLE_ENDPOINT_ENV)
    drift_endpoint = _required_env(DRIFT_ENDPOINT_ENV)
    fail_endpoint = _required_env(FAIL_ENDPOINT_ENV)
    source_sha = _required_env(FIXTURE_SOURCE_SHA_ENV).lower()

    _assert_fixture_urls(
        manifest_url,
        stable_endpoint,
        drift_endpoint,
        fail_endpoint,
        source_sha,
    )

    owner = create_account(owner_key)
    subject = create_account(subject_key)
    assert str(owner.address).lower() != str(subject.address).lower()

    fee_profile = _load_fee_profile(
        manifest_url,
        stable_endpoint,
        drift_endpoint,
        fail_endpoint,
        source_sha,
    )

    owner_client = create_client(chain=testnet_bradbury, account=owner)
    subject_client = create_client(chain=testnet_bradbury, account=subject)
    checkpoint = _load_checkpoint()

    deploy_receipt = _finalize_step(
        checkpoint,
        owner_client,
        step_key="01_deploy_agentseal",
        submit=lambda: owner_client.deploy_contract(
            code=CONTRACT.read_text(encoding="utf-8"),
            account=owner,
            args=[],
            fees=_fees_for(owner_client, fee_profile, "01_deploy_agentseal"),
        ),
    )
    contract_address = _receipt_contract_address(deploy_receipt)
    checkpoint["state"]["contract_address"] = contract_address
    _save_checkpoint(checkpoint)

    valid_until = int(time.time()) + 7 * 86_400
    _finalize_step(
        checkpoint,
        owner_client,
        step_key="02_create_policy",
        submit=lambda: _write(
            owner_client,
            owner,
            contract_address,
            "02_create_policy",
            fee_profile,
            "create_policy",
            [
                POLICY_ID,
                CAPABILITY_ID,
                POLICY_VERSION,
                CRITERIA,
                manifest_url,
                MANIFEST_ID,
                MANIFEST_AUTHORITY,
                EXPECTED_MANIFEST_SHA,
                valid_until,
                POLICY_MAX_TTL,
            ],
        ),
    )
    policy = _read(owner_client, contract_address, "get_policy", [POLICY_ID, POLICY_VERSION])
    assert policy["active"] is True
    assert policy["manifest_digest"] == EXPECTED_MANIFEST_SHA

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="03_create_stable_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "03_create_stable_assessment",
            fee_profile,
            "create_assessment",
            [EXPECTED_PROFILE_SHA, stable_endpoint, POLICY_ID, POLICY_VERSION, CERT_TTL],
        ),
    )
    stable_id = int(_read(subject_client, contract_address, "get_assessment_count"))
    assert _read(subject_client, contract_address, "get_assessment", [stable_id])["status"] == "PENDING"

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="04_evaluate_stable_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "04_evaluate_stable_assessment",
            fee_profile,
            "evaluate_assessment",
            [stable_id],
        ),
    )
    stable_assessment = _read(subject_client, contract_address, "get_assessment", [stable_id])
    stable_certificate = _read(subject_client, contract_address, "get_certificate", [stable_id])
    assert stable_assessment["status"] == "PASSED"
    assert stable_certificate["status"] == "ACTIVE"

    _finalize_step(
        checkpoint,
        owner_client,
        step_key="05_open_stable_challenge",
        submit=lambda: _write(
            owner_client,
            owner,
            contract_address,
            "05_open_stable_challenge",
            fee_profile,
            "open_challenge",
            [stable_id],
        ),
    )
    stable_challenge_id = int(_read(owner_client, contract_address, "get_challenge_count"))

    _finalize_step(
        checkpoint,
        owner_client,
        step_key="06_evaluate_stable_challenge",
        submit=lambda: _write(
            owner_client,
            owner,
            contract_address,
            "06_evaluate_stable_challenge",
            fee_profile,
            "evaluate_challenge",
            [stable_challenge_id],
        ),
    )
    assert _read(owner_client, contract_address, "get_challenge", [stable_challenge_id])["status"] == "REJECTED"
    assert _read(owner_client, contract_address, "get_certificate", [stable_id])["status"] == "ACTIVE"

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="07_revoke_stable_certificate",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "07_revoke_stable_certificate",
            fee_profile,
            "revoke_certificate",
            [stable_id],
        ),
    )
    assert _read(subject_client, contract_address, "get_certificate", [stable_id])["status"] == "REVOKED"
    assert _read(subject_client, contract_address, "get_revocation", [stable_id])["source"] == "SUBJECT_SELF_REVOKE"

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="08_create_drift_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "08_create_drift_assessment",
            fee_profile,
            "create_assessment",
            [EXPECTED_PROFILE_SHA, drift_endpoint, POLICY_ID, POLICY_VERSION, CERT_TTL],
        ),
    )
    drift_id = int(_read(subject_client, contract_address, "get_assessment_count"))

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="09_evaluate_drift_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "09_evaluate_drift_assessment",
            fee_profile,
            "evaluate_assessment",
            [drift_id],
        ),
    )
    assert _read(subject_client, contract_address, "get_assessment", [drift_id])["status"] == "PASSED"
    assert _read(subject_client, contract_address, "get_certificate", [drift_id])["status"] == "ACTIVE"

    _finalize_step(
        checkpoint,
        owner_client,
        step_key="10_open_drift_challenge",
        submit=lambda: _write(
            owner_client,
            owner,
            contract_address,
            "10_open_drift_challenge",
            fee_profile,
            "open_challenge",
            [drift_id],
        ),
    )
    drift_challenge_id = int(_read(owner_client, contract_address, "get_challenge_count"))

    _finalize_step(
        checkpoint,
        owner_client,
        step_key="11_evaluate_drift_challenge",
        submit=lambda: _write(
            owner_client,
            owner,
            contract_address,
            "11_evaluate_drift_challenge",
            fee_profile,
            "evaluate_challenge",
            [drift_challenge_id],
        ),
    )
    assert _read(owner_client, contract_address, "get_challenge", [drift_challenge_id])["status"] == "UPHELD"
    assert _read(owner_client, contract_address, "get_certificate", [drift_id])["status"] == "REVOKED"
    assert _read(owner_client, contract_address, "get_revocation", [drift_id])["source"] == "CHALLENGE_CONSENSUS"

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="12_create_fail_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "12_create_fail_assessment",
            fee_profile,
            "create_assessment",
            [EXPECTED_PROFILE_SHA, fail_endpoint, POLICY_ID, POLICY_VERSION, CERT_TTL],
        ),
    )
    fail_id = int(_read(subject_client, contract_address, "get_assessment_count"))

    _finalize_step(
        checkpoint,
        subject_client,
        step_key="13_evaluate_fail_assessment",
        submit=lambda: _write(
            subject_client,
            subject,
            contract_address,
            "13_evaluate_fail_assessment",
            fee_profile,
            "evaluate_assessment",
            [fail_id],
        ),
    )
    failed = _read(subject_client, contract_address, "get_assessment", [fail_id])
    assert failed["status"] == "FAILED"
    assert int(failed["certificate_id"]) == 0
    assert _read(subject_client, contract_address, "certificate_exists", [fail_id]) is False

    checkpoint["state"]["matrix_complete"] = True
    _save_checkpoint(checkpoint)
