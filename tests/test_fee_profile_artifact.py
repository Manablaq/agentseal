from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROFILE = REPO / "fee-profile.json"

EXPECTED_OPERATIONS = [
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

DETERMINISTIC_BUDGET_OPERATIONS = {
    "01_deploy_agentseal",
    "02_create_policy",
    "03_create_stable_assessment",
    "05_open_stable_challenge",
    "07_revoke_stable_certificate",
    "08_create_drift_assessment",
    "10_open_drift_challenge",
    "12_create_fail_assessment",
}
SEMANTIC_BUDGET_OPERATIONS = set(EXPECTED_OPERATIONS) - DETERMINISTIC_BUDGET_OPERATIONS

ALLOWED_KEYS = {
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


def test_fee_profile_is_complete_portable_and_conservative():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))

    assert profile["schema"] == "agentseal-fee-profile-v1"
    assert profile["chain_id"] == 4221
    assert profile["contract_sha256"] == "61801db265c19b58f09d14b446af2c46fcb6da050852879a01df01a78f1b726d"
    assert profile["profile_sha256"] == "bc32dc6c11ac40ce5593a38dbb01a073dc52258bcb9efd0ad7189109b440df39"
    assert profile["manifest_sha256"] == "adebc57268330448f68b1773c29d064f115c1cdbac316e19e2af68df2b611dfa"
    assert profile["measurement_environment"]["conservative_execution_budget_multiplier_bps"] == 20_000
    assert list(profile["operations"]) == EXPECTED_OPERATIONS

    serialized = PROFILE.read_text(encoding="utf-8")
    assert "/Users/" not in serialized
    assert "\\Users\\" not in serialized

    for key, entry in profile["operations"].items():
        options = entry["estimate_options"]
        assert options
        assert set(options).issubset(ALLOWED_KEYS)
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
        assert measurement["final_status"] == "FINALIZED"
        assert re.fullmatch(r"[0-9a-f]{64}", measurement["raw_evidence_sha256"])
        assert re.fullmatch(r"0x[0-9a-f]{64}", measurement["local_transaction_id"])

    for key in DETERMINISTIC_BUDGET_OPERATIONS:
        assert (
            profile["operations"][key]["estimate_options"]["executionBudgetPerRound"]
            == 188_707_200_000_000
        )

    for key in SEMANTIC_BUDGET_OPERATIONS:
        assert (
            profile["operations"][key]["estimate_options"]["executionBudgetPerRound"]
            == 189_216_000_000_000
        )
