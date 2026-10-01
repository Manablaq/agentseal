from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from genlayer_py.assertions import tx_execution_succeeded
from genlayer_py.types import TransactionStatus


REPO = Path(__file__).resolve().parents[2]

MANIFEST = REPO / "fixtures" / "bradbury" / "agentseal-manifest-v2.json"
CERTIFICATION = (
    REPO
    / "docs"
    / "evidence"
    / "agentseal-bradbury-r7-certification.json"
)

CHAIN_ID = 4221
POLICY_ID = "agentseal-bradbury-v1"
POLICY_VERSION = 2
MANIFEST_ID = "agentseal-bradbury-manifest-v2"
MANIFEST_SHA256 = "e6bc4f7737f990c94cbf49b98343fab2c1474d1ba2108d627856e7465be36507"
CERT_TTL = 604800
AUDIT_FINGERPRINT = "dd054837e3a60776285040dcae05eaaa5cf2d3bbf92d8fe9d4ad2375a5240541"

R7_SOURCE_SHA256 = {
    REPO / "contracts" / "agentseal_policy_registry.py":
        "da593bf8276c1603c2ca1af2933057eef59cd80eeef72e0d5682f3dc0e755240",
    REPO / "contracts" / "agentseal_registry.py":
        "885ce68a6e547a71e29b8ff5549061909a6830a98bcaebe49db7cc93cde0b4e2",
    REPO / "contracts" / "agentseal_certificate_registry.py":
        "9ec3d55a8e142ef371a13e8e46e1f3c179bc48da40e2e033a7da73a7cdffe583",
    REPO / "contracts" / "agentseal_deterministic_support.py":
        "d1de52f8900ffa98cd2f5178f76de0b792d31f0e3e97e611a565c0781be3c71c",
    REPO / "contracts" / "agentseal_challenge.py":
        "6b63365669d6288fc6df712767e14647a62fc12e17759f9e46746a8a27c3c026",
    REPO / "contracts" / "agentseal_semantic_judge.py":
        "28b1d33d5ca52613b7d033258b84e1c6128542c2f23a9ca617554e0313084ee2",
    REPO / "contracts" / "agentseal_assessment_evidence_evaluator.py":
        "1c3e2c16b18636c5261b87b107abf4b5452363089e175ca3fbaa5c357da6e52c",
    REPO / "contracts" / "agentseal_challenge_evidence_evaluator.py":
        "510a0639ca061d47a9d8c2f02d4807e9037859f568105be70f9d0af15cc4ac0b",
}

R7_ADDRESSES = {
    "policy_registry": "0x551355C4690AAd6066626A87E94f24d71593B8a7",
    "registry": "0xdbED185B52871ac70B5Cd114A26a2B7912224BBF",
    "certificate_registry": "0xB683ab8DeCE80b1d170473D4FBd4b83083BcaA73",
    "deterministic_support": "0x2B811C62F1e29E7edE29127c7bABEDC65fb8A162",
    "challenge": "0x8ed9D8cb10BC4EDb4Ebb8f412f4Be68be7abf6Cd",
    "semantic_judge": "0x3188310A01d64FACf6b1216aAF2722c748d03d28",
    "assessment_evaluator": "0x70CAcB92efc405D98E6Afdc4f8BEf691448Bfc2C",
    "challenge_evaluator": "0x09f6404544A6F7bEAA157a84487D650A18001C91",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _finalize_step(checkpoint, client, step_key: str, submit):
    """Exactly-once checkpoint helper retained for regression coverage.

    This helper persists PREPARED before submission, records OUTCOME_UNKNOWN on
    an ambiguous submit exception, and never blindly calls submit again once an
    unresolved record exists. The current R7 integration module itself contains
    no Bradbury write test.
    """

    record = checkpoint["steps"].get(step_key)

    if record is None:
        record = {
            "submission_state": "PREPARED",
            "finalized": False,
        }
        checkpoint["steps"][step_key] = record
        _save_checkpoint(checkpoint)

        try:
            tx_hash = submit()
        except BaseException:
            record["submission_state"] = "OUTCOME_UNKNOWN"
            _save_checkpoint(checkpoint)
            raise

        record["tx_hash"] = _tx_hash_text(tx_hash)
        record["submitted"] = True
        record["submission_state"] = "SUBMITTED"
        _save_checkpoint(checkpoint)

    if not record.get("tx_hash"):
        raise RuntimeError(
            f"{step_key} has no transaction hash and submission state "
            f"{record.get('submission_state', 'UNKNOWN')}; reconcile chain state "
            "before any further write"
        )

    if record.get("finalized") is True:
        return record["receipt"]

    receipt = client.wait_for_transaction_receipt(
        transaction_hash=record["tx_hash"],
        status=TransactionStatus.FINALIZED,
        interval=10,
        retries=180,
        full_transaction=True,
    )
    assert tx_execution_succeeded(receipt), (
        f"{step_key} finalized without successful execution"
    )

    safe = _json_safe(receipt)
    assert isinstance(safe, dict)
    record["receipt"] = safe
    record["finalized"] = True
    _save_checkpoint(checkpoint)
    return safe


def _save_checkpoint(_value: dict[str, Any]) -> None:
    """Overridden by checkpoint-guard tests.

    The historical live writer used a persisted checkpoint file. R7 live writes
    are complete and are not rerunnable from pytest, so the release-identity
    module intentionally has no default on-disk checkpoint target.
    """

    raise RuntimeError(
        "R7_BRADBURY_LIVE_WRITES_ARE_CERTIFIED_AND_NOT_RERUNNABLE_FROM_PYTEST"
    )


def _certification() -> dict[str, Any]:
    value = json.loads(CERTIFICATION.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_r7_split_source_and_manifest_identity():
    for path, expected in R7_SOURCE_SHA256.items():
        assert path.is_file(), path
        assert _sha256(path) == expected, path

    assert MANIFEST.is_file()
    assert _sha256(MANIFEST) == MANIFEST_SHA256

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema"] == "agentseal-manifest-v1"
    assert manifest["policy_id"] == POLICY_ID
    assert manifest["policy_version"] == POLICY_VERSION
    assert manifest["manifest_id"] == MANIFEST_ID


def test_r7_portable_certification_binds_live_release():
    cert = _certification()

    assert cert["schema"] == "agentseal-bradbury-r7-certification-v1"
    assert cert["chain_id"] == CHAIN_ID
    assert cert["policy_id"] == POLICY_ID
    assert cert["policy_version"] == POLICY_VERSION
    assert cert["manifest_id"] == MANIFEST_ID
    assert cert["manifest_sha256"] == MANIFEST_SHA256
    assert cert["certificate_ttl_seconds"] == CERT_TTL
    assert cert["addresses"] == R7_ADDRESSES

    assert cert["setup_roots_finalized"] == 12
    assert cert["matrix_roots_finalized"] == 11
    assert cert["total_root_send_calls"] == 23
    assert cert["root_evm_receipts_success"] == 23
    assert cert["unique_genlayer_transactions_audited"] == 44
    assert cert["required_genlayer_final_status_code"] == 7
    assert cert["required_genlayer_execution_result"] == 1
    assert cert["exact_final_matrix_verified"] is True
    assert cert["blind_retry_performed"] is False
    assert cert["audit_fingerprint"] == AUDIT_FINGERPRINT

    assert cert["audit_writes"] == 0
    assert cert["audit_signing"] is False
    assert cert["audit_keychain_access"] is False
    assert cert["audit_eth_send_raw_transaction_calls"] == 0


def test_r7_integration_module_is_not_a_bradbury_write_entrypoint():
    source = Path(__file__).read_text(encoding="utf-8")

    forbidden = (
        "deploy_" + "contract(",
        "write_" + "contract(",
        "create_" + "account(",
        "AGENTSEAL_RUN_" + "BRADBURY_SUPPORTED_RUNTIME",
        "AGENTSEAL_BRADBURY_OWNER_" + "PRIVATE_KEY",
        "AGENTSEAL_BRADBURY_SUBJECT_" + "PRIVATE_KEY",
    )
    for token in forbidden:
        assert token not in source
