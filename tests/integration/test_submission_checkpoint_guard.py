from __future__ import annotations

import copy
import importlib.util
import time
from pathlib import Path

import pytest


RUNTIME_TEST_PATH = Path(__file__).with_name(
    "test_agentseal_bradbury_supported_runtime.py"
)
SPEC = importlib.util.spec_from_file_location(
    "agentseal_bradbury_supported_runtime", RUNTIME_TEST_PATH
)
assert SPEC is not None and SPEC.loader is not None
RUNTIME_TEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME_TEST)

STATE_READER_PATH = Path(__file__).parents[2] / "scripts" / "read_rc7_assessment_state.py"
STATE_READER_SPEC = importlib.util.spec_from_file_location(
    "agentseal_rc7_readonly_state", STATE_READER_PATH
)
assert STATE_READER_SPEC is not None and STATE_READER_SPEC.loader is not None
STATE_READER = importlib.util.module_from_spec(STATE_READER_SPEC)
STATE_READER_SPEC.loader.exec_module(STATE_READER)


class _FinalityClient:
    def wait_for_transaction_receipt(self, **_kwargs):
        return {"status": "FINALIZED", "execution": "success"}


def _capture_checkpoint_writes(monkeypatch):
    writes = []
    monkeypatch.setattr(
        RUNTIME_TEST,
        "_save_checkpoint",
        lambda checkpoint: writes.append(copy.deepcopy(checkpoint)),
    )
    monkeypatch.setattr(RUNTIME_TEST, "tx_execution_succeeded", lambda _receipt: True)
    return writes


def test_submission_intent_is_persisted_before_write(monkeypatch):
    writes = _capture_checkpoint_writes(monkeypatch)
    checkpoint = {"steps": {}, "state": {}}
    tx_hash = "ab" * 32

    def submit():
        assert writes[-1]["steps"]["step-1"] == {
            "submission_state": "PREPARED",
            "finalized": False,
        }
        return tx_hash

    receipt = RUNTIME_TEST._finalize_step(
        checkpoint, _FinalityClient(), "step-1", submit
    )

    assert receipt["status"] == "FINALIZED"
    assert checkpoint["steps"]["step-1"]["tx_hash"] == "0x" + tx_hash
    assert checkpoint["steps"]["step-1"]["submission_state"] == "SUBMITTED"
    assert checkpoint["steps"]["step-1"]["finalized"] is True


def test_ambiguous_submission_is_never_retried(monkeypatch):
    _capture_checkpoint_writes(monkeypatch)
    checkpoint = {"steps": {}, "state": {}}
    calls = 0

    def ambiguous_submit():
        nonlocal calls
        calls += 1
        raise TimeoutError("response lost after possible submission")

    with pytest.raises(TimeoutError):
        RUNTIME_TEST._finalize_step(
            checkpoint, _FinalityClient(), "step-1", ambiguous_submit
        )

    assert checkpoint["steps"]["step-1"]["submission_state"] == "OUTCOME_UNKNOWN"
    with pytest.raises(RuntimeError, match="reconcile chain state"):
        RUNTIME_TEST._finalize_step(
            checkpoint, _FinalityClient(), "step-1", ambiguous_submit
        )
    assert calls == 1


def test_readonly_state_snapshot_marks_attempt_two_admissible_only_before_deadline():
    assessment = {
        "assessment_id": 1,
        "status": "PENDING",
        "effective_status": "PENDING",
        "attempt_count": 1,
        "max_attempt_count": 3,
        "last_verdict": "INCONCLUSIVE",
        "deadline": 2_000,
        "policy_id": "policy-v1",
        "policy_version": 1,
        "certificate_id": 0,
    }
    policy = {"active": True, "valid_until": 3_000}

    admissible = STATE_READER.build_snapshot(
        assessment, policy, now=1_000, contract_address="0x" + "11" * 20
    )
    expired = STATE_READER.build_snapshot(
        assessment, policy, now=2_000, contract_address="0x" + "11" * 20
    )

    assert admissible["read_only"] is True
    assert admissible["attempt_2_admissible"] is True
    assert admissible["assessment"]["seconds_until_deadline"] == 1_000
    assert expired["attempt_2_admissible"] is False
    assert expired["assessment"]["seconds_until_deadline"] == 0


def test_readonly_state_reader_uses_ephemeral_sender_and_only_view_calls(monkeypatch):
    calls = []

    class _ReadOnlyClient:
        def __init__(self, *, chain_config, account):
            assert chain_config.id == 61127
            assert account.address
            self.local_account = account
            self.provider = type(
                "_Provider",
                (),
                {
                    "url": "http://127.0.0.1:4000/api",
                    "make_request": lambda _self, method, params: (
                        {"result": "0xeec7"}
                        if method == "eth_chainId"
                        else {"result": {"blocksBehind": 0}}
                    ),
                },
            )()

        def read_contract(self, **kwargs):
            calls.append(kwargs)
            if kwargs["function_name"] == "get_assessment":
                return {
                    "assessment_id": 1,
                    "status": "PENDING",
                    "effective_status": "PENDING",
                    "attempt_count": 1,
                    "max_attempt_count": 3,
                    "deadline": int(time.time()) + 600,
                    "policy_id": "policy-v1",
                    "policy_version": 1,
                    "certificate_id": 0,
                }
            if kwargs["function_name"] == "get_policy":
                return {"active": True, "valid_until": int(time.time()) + 900}
            if kwargs["function_name"] == "certificate_exists":
                assert kwargs["args"] == [0]
                return False
            raise AssertionError(f"unexpected view {kwargs['function_name']}")

    monkeypatch.setattr(STATE_READER, "GenLayerClient", _ReadOnlyClient)
    result = STATE_READER.read_state("0x" + "11" * 20, 1)

    assert result["read_only"] is True
    assert result["chain_id"] == 61127
    assert result["rpc_chain_id"] == 61127
    assert result["assessment"]["certificate_exists"] is False
    assert [call["function_name"] for call in calls] == [
        "get_assessment",
        "get_policy",
        "certificate_exists",
    ]
    assert all(
        call["transaction_hash_variant"]
        == STATE_READER.TransactionHashVariant.LATEST_FINAL
        for call in calls
    )


def test_readonly_state_reader_stops_before_contract_calls_on_wrong_chain(
    monkeypatch,
):
    rpc_methods = []

    class _WrongChainClient:
        def __init__(self, *, chain_config, account):
            self.provider = type(
                "_Provider",
                (),
                {
                    "url": "http://127.0.0.1:4000/api",
                    "make_request": lambda _self, method, params: (
                        rpc_methods.append(method) or {"result": "0xf22f"}
                    ),
                },
            )()

        def read_contract(self, **kwargs):
            raise AssertionError("contract read must not run on a wrong chain")

    monkeypatch.setattr(STATE_READER, "GenLayerClient", _WrongChainClient)
    with pytest.raises(STATE_READER.RC7StateReadError, match="chain ID") as exc_info:
        STATE_READER.read_state("0x" + "11" * 20, 1)

    assert exc_info.value.diagnostic["actual_chain_id"] == 61999
    assert rpc_methods == ["eth_chainId"]


def test_readonly_state_reader_probes_finalized_and_accepted_before_classifying_missing_contract(
    monkeypatch,
):
    variants = []

    class _MissingContractClient:
        def __init__(self, *, chain_config, account):
            self.provider = type(
                "_Provider",
                (),
                {
                    "url": "http://127.0.0.1:4000/api",
                    "make_request": lambda _self, method, params: (
                        {"result": "0xeec7"}
                        if method == "eth_chainId"
                        else {"result": {"blocksBehind": 0}}
                    ),
                },
            )()

        def read_contract(self, **kwargs):
            variants.append(kwargs["transaction_hash_variant"])
            raise RuntimeError("Contract 0x... not found")

    monkeypatch.setattr(STATE_READER, "GenLayerClient", _MissingContractClient)
    with pytest.raises(STATE_READER.RC7StateReadError, match="not found") as exc_info:
        STATE_READER.read_state("0x" + "11" * 20, 1)

    assert variants == [
        STATE_READER.TransactionHashVariant.LATEST_FINAL,
        STATE_READER.TransactionHashVariant.LATEST_NONFINAL,
    ]
    assert "does not distinguish" in exc_info.value.diagnostic["observed_fact"]
