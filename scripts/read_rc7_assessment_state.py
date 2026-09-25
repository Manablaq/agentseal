#!/usr/bin/env python3
"""Read finalized local RC7 assessment state without submitting a transaction."""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

from genlayer_py.chains import localnet
from genlayer_py.client.genlayer_client import GenLayerClient
from genlayer_py.types.transactions import TransactionHashVariant
from eth_account import Account

EXPECTED_LOCALNET_CHAIN_ID = 61127


class RC7StateReadError(RuntimeError):
    def __init__(self, message: str, *, diagnostic: dict[str, Any]):
        super().__init__(message)
        self.diagnostic = diagnostic


def _unix_seconds(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unexpected {field} value in contract read") from exc


def build_snapshot(
    assessment: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: int,
    contract_address: str,
) -> dict[str, Any]:
    deadline = _unix_seconds(assessment.get("deadline"), "assessment.deadline")
    policy_valid_until = _unix_seconds(
        policy.get("valid_until"), "policy.valid_until"
    )
    attempt_count = _unix_seconds(
        assessment.get("attempt_count"), "assessment.attempt_count"
    )
    max_attempt_count = _unix_seconds(
        assessment.get("max_attempt_count"), "assessment.max_attempt_count"
    )
    next_attempt = attempt_count + 1
    status = str(assessment.get("status", ""))
    effective_status = str(assessment.get("effective_status", ""))
    policy_active = policy.get("active") is True
    pending_and_unexpired = (
        status == "PENDING"
        and effective_status == "PENDING"
        and now < deadline
    )
    policy_current = policy_active and now < policy_valid_until
    next_attempt_admissible = (
        pending_and_unexpired
        and policy_current
        and next_attempt <= max_attempt_count
    )

    observed_at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    return {
        "schema": "agentseal-rc7-readonly-state-v1",
        "read_only": True,
        "chain": localnet.name,
        "chain_id": EXPECTED_LOCALNET_CHAIN_ID,
        "state_variant": TransactionHashVariant.LATEST_FINAL.value,
        "contract_address": contract_address,
        "observed_at_utc": observed_at,
        "assessment": {
            "assessment_id": assessment.get("assessment_id"),
            "status": status,
            "effective_status": effective_status,
            "attempt_count": attempt_count,
            "max_attempt_count": max_attempt_count,
            "next_attempt_number": next_attempt,
            "last_verdict": assessment.get("last_verdict"),
            "deadline_unix": deadline,
            "seconds_until_deadline": deadline - now,
            "certificate_id": assessment.get("certificate_id"),
        },
        "policy": {
            "policy_id": assessment.get("policy_id"),
            "policy_version": assessment.get("policy_version"),
            "active": policy_active,
            "valid_until_unix": policy_valid_until,
            "seconds_until_valid_until": policy_valid_until - now,
        },
        "next_attempt_admissible": next_attempt_admissible,
        "attempt_2_admissible": (
            next_attempt_admissible and next_attempt == 2
        ),
    }


def read_state(
    contract_address: str,
    assessment_id: int,
    *,
    rpc_url: str = "http://127.0.0.1:4200/api",
) -> dict[str, Any]:
    # genlayer-py requires a sender address for `gen_call`, even for view calls.
    # Use a throwaway in-memory account; it is never funded, persisted, or used
    # to sign or submit a transaction. Constructing the client directly also
    # avoids the SDK factory's optional consensus-contract discovery request.
    chain_config = copy.deepcopy(localnet)
    # The pinned genlayer-py commit still labels its localnet as 61999. The
    # AgentSeal RC7 deployment and the supplied GenLayer docs identify localnet
    # as 61127. Verify the live RPC chain ID rather than trusting that constant.
    chain_config.id = EXPECTED_LOCALNET_CHAIN_ID
    chain_config.rpc_urls["default"]["http"] = [rpc_url]
    client = GenLayerClient(chain_config=chain_config, account=Account.create())
    endpoint = client.provider.url
    chain_id_response = client.provider.make_request(
        method="eth_chainId", params=[]
    )
    raw_chain_id = chain_id_response.get("result")
    try:
        actual_chain_id = int(raw_chain_id, 16)
    except (TypeError, ValueError) as exc:
        raise RC7StateReadError(
            "RPC returned an invalid eth_chainId; no contract reads were attempted",
            diagnostic={
                "rpc_url": endpoint,
                "expected_chain_id": EXPECTED_LOCALNET_CHAIN_ID,
                "rpc_chain_id": raw_chain_id,
            },
        ) from exc
    if actual_chain_id != EXPECTED_LOCALNET_CHAIN_ID:
        raise RC7StateReadError(
            "RPC chain ID does not match the RC7 localnet deployment; no contract reads were attempted",
            diagnostic={
                "rpc_url": endpoint,
                "expected_chain_id": EXPECTED_LOCALNET_CHAIN_ID,
                "rpc_chain_id": raw_chain_id,
                "actual_chain_id": actual_chain_id,
            },
        )

    try:
        sync_response = client.provider.make_request(method="gen_syncing", params=[])
        sync_state = sync_response.get("result")
        sync_error = None
    except Exception as exc:
        # Some local RPC builds predate gen_syncing. The chain-ID and contract
        # probes remain authoritative for this read-only diagnosis.
        sync_state = None
        sync_error = str(exc)
    read_options = {
        "transaction_hash_variant": TransactionHashVariant.LATEST_FINAL,
    }
    try:
        assessment = client.read_contract(
            address=contract_address,
            function_name="get_assessment",
            args=[assessment_id],
            **read_options,
        )
    except Exception as final_error:
        try:
            client.read_contract(
                address=contract_address,
                function_name="get_assessment",
                args=[assessment_id],
                transaction_hash_variant=TransactionHashVariant.LATEST_NONFINAL,
            )
        except Exception as accepted_error:
            raise RC7StateReadError(
                "RC7 contract was not found in either finalized or latest accepted state on the verified localnet RPC",
                diagnostic={
                    "rpc_url": endpoint,
                    "rpc_chain_id": actual_chain_id,
                    "sync_state": sync_state,
                    "contract_address": contract_address,
                    "assessment_id": assessment_id,
                    "latest_final_error": str(final_error),
                    "latest_accepted_error": str(accepted_error),
                    "observed_fact": "Both finalized and latest accepted state returned contract not found. This proves the queried RPC state lacks this address; it does not distinguish a different localnet database/instance from an incorrect recorded address.",
                    "next_safe_step": "Reconcile the original deployment transaction/address and localnet database before any redeploy or assessment write.",
                },
            ) from final_error
        raise RC7StateReadError(
            "RC7 contract is visible in latest accepted state but absent from finalized state; stop before any write",
            diagnostic={
                "rpc_url": endpoint,
                "rpc_chain_id": actual_chain_id,
                "sync_state": sync_state,
                "contract_address": contract_address,
                "assessment_id": assessment_id,
                "latest_final_error": str(final_error),
                "latest_accepted_state": "contract and assessment are visible",
                "next_safe_step": "Reconcile deployment/assessment finality before proceeding.",
            },
        ) from final_error
    if not isinstance(assessment, dict):
        raise ValueError("get_assessment returned an unexpected value")

    policy_id = assessment.get("policy_id")
    policy_version = assessment.get("policy_version")
    if not isinstance(policy_id, str) or not isinstance(policy_version, int):
        raise ValueError("assessment did not contain a valid policy binding")

    policy = client.read_contract(
        address=contract_address,
        function_name="get_policy",
        args=[policy_id, policy_version],
        **read_options,
    )
    if not isinstance(policy, dict):
        raise ValueError("get_policy returned an unexpected value")

    certificate_id = _unix_seconds(
        assessment.get("certificate_id", 0), "assessment.certificate_id"
    )
    certificate_exists = client.read_contract(
        address=contract_address,
        function_name="certificate_exists",
        args=[certificate_id],
        **read_options,
    )
    snapshot = build_snapshot(
        assessment,
        policy,
        now=int(time.time()),
        contract_address=contract_address,
    )
    snapshot["rpc_url"] = endpoint
    snapshot["rpc_chain_id"] = actual_chain_id
    snapshot["sync_state"] = sync_state
    if sync_error is not None:
        snapshot["sync_error"] = sync_error
    snapshot["assessment"]["certificate_exists"] = certificate_exists is True
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract-address", required=True)
    parser.add_argument("--assessment-id", type=int, default=1)
    parser.add_argument(
        "--rpc-url",
        required=True,
        help="Explicit RC7 RPC endpoint; its chain ID is checked before reads.",
    )
    args = parser.parse_args()

    try:
        result = read_state(
            args.contract_address,
            args.assessment_id,
            rpc_url=args.rpc_url,
        )
    except Exception as exc:
        result = {
            "schema": "agentseal-rc7-readonly-state-v1",
            "read_only": True,
            "state_read_succeeded": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        if isinstance(exc, RC7StateReadError):
            result["diagnostic"] = exc.diagnostic
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1

    result["state_read_succeeded"] = True
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
