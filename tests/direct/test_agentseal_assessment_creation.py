import os

import pytest

CONTRACT = os.environ["AGENTSEAL_CONTRACT"]

NOW_ISO = "2026-09-21T12:00:00Z"
NOW = 1789992000
DAY = 86_400
PROFILE = "b" * 64
MANIFEST_DIGEST = "a" * 64
ENDPOINT = "https://agent.example.com/evaluate"
ENDPOINT_2 = "https://agent.example.com/evaluate-v2"


def _create_policy(
    contract,
    *,
    valid_until=NOW + (10 * DAY),
    max_ttl=3600,
):
    contract.create_policy(
        "policy-v1",
        "research",
        1,
        "Return correct structured research results.",
        "https://evidence.example.com/manifest.json",
        "manifest-v1",
        "AgentSeal Test Authority",
        MANIFEST_DIGEST,
        valid_until,
        max_ttl,
    )


def _deploy_ready(direct_vm, direct_deploy, **policy_kwargs):
    direct_vm.warp(NOW_ISO)
    contract = direct_deploy(CONTRACT)
    _create_policy(contract, **policy_kwargs)
    return contract


def test_initial_assessment_state(direct_vm, direct_deploy):
    direct_vm.warp(NOW_ISO)
    contract = direct_deploy(CONTRACT)
    assert contract.get_assessment_count() == 0
    assert contract.assessment_exists(1) is False


def test_create_assessment_exact_storage(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    assessment_id = contract.create_assessment(
        PROFILE,
        ENDPOINT,
        "policy-v1",
        1,
        900,
    )
    assert assessment_id == 1
    assert contract.get_assessment_count() == 1
    value = contract.get_assessment(1)
    assert value["assessment_id"] == 1
    assert value["profile_digest"] == PROFILE
    assert value["endpoint"] == ENDPOINT
    assert value["capability_id"] == "research"
    assert value["policy_id"] == "policy-v1"
    assert value["policy_version"] == 1
    assert value["manifest_id"] == "manifest-v1"
    assert value["manifest_digest"] == MANIFEST_DIGEST
    assert value["requested_certificate_ttl"] == 900
    assert len(value["binding_key"]) == 64
    assert value["status"] == "PENDING"
    assert value["effective_status"] == "PENDING"
    assert value["created_at"] == NOW
    assert value["deadline"] == NOW + DAY
    assert value["attempt_count"] == 0
    assert value["max_attempt_count"] == 3
    assert value["last_verdict"] == ""
    assert value["case_a_id"] == ""
    assert value["case_b_id"] == ""
    assert value["certificate_id"] == 0


def test_subject_is_message_sender(direct_vm, direct_deploy, direct_owner):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.create_assessment(PROFILE, ENDPOINT, "policy-v1", 1, 900)
    from genlayer.py.types import Address
    expected = Address(direct_owner).as_hex.lower()
    assert contract.get_assessment(1)["subject_wallet"] == expected


def test_ids_increment_for_distinct_bindings(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    first = contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    )
    second = contract.create_assessment(
        PROFILE, ENDPOINT_2, "policy-v1", 1, 900
    )
    assert first == 1
    assert second == 2
    assert contract.get_assessment_count() == 2


def test_profile_digest_length_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("PROFILE_DIGEST_LENGTH"):
        contract.create_assessment(
            "b" * 63, ENDPOINT, "policy-v1", 1, 900
        )


def test_profile_digest_uppercase_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("PROFILE_DIGEST_FORMAT"):
        contract.create_assessment(
            "B" * 64, ENDPOINT, "policy-v1", 1, 900
        )


def test_http_endpoint_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_HTTPS_REQUIRED"):
        contract.create_assessment(
            PROFILE,
            "http://agent.example.com/evaluate",
            "policy-v1",
            1,
            900,
        )


def test_endpoint_credentials_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_CREDENTIALS_FORBIDDEN"):
        contract.create_assessment(
            PROFILE,
            "https://user@agent.example.com/evaluate",
            "policy-v1",
            1,
            900,
        )


def test_endpoint_explicit_port_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_PORT_FORBIDDEN"):
        contract.create_assessment(
            PROFILE,
            "https://agent.example.com:443/evaluate",
            "policy-v1",
            1,
            900,
        )


def test_endpoint_local_host_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_LOCAL_HOST_FORBIDDEN"):
        contract.create_assessment(
            PROFILE,
            "https://agent.local/evaluate",
            "policy-v1",
            1,
            900,
        )


def test_endpoint_noncanonical_uppercase_host_rejected(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_HOST_NOT_CANONICAL"):
        contract.create_assessment(
            PROFILE,
            "https://Agent.example.com/evaluate",
            "policy-v1",
            1,
            900,
        )


def test_missing_policy_rejected(direct_vm, direct_deploy):
    direct_vm.warp(NOW_ISO)
    contract = direct_deploy(CONTRACT)
    with direct_vm.expect_revert("POLICY_NOT_FOUND"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "missing", 1, 900
        )


def test_inactive_policy_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.disable_policy("policy-v1", 1)
    with direct_vm.expect_revert("POLICY_INACTIVE"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 900
        )


def test_expired_policy_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(
        direct_vm,
        direct_deploy,
        valid_until=NOW + 60,
    )
    direct_vm.warp("2026-09-21T12:01:00Z")
    with direct_vm.expect_revert("POLICY_EXPIRED"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 900
        )


def test_zero_requested_ttl_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("CERTIFICATE_TTL_POLICY_RANGE"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 0
        )


def test_requested_ttl_above_policy_max_rejected(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(
        direct_vm,
        direct_deploy,
        max_ttl=600,
    )
    with direct_vm.expect_revert("CERTIFICATE_TTL_POLICY_RANGE"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 601
        )


def test_deadline_uses_full_assessment_window(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    )
    assert contract.get_assessment(1)["deadline"] == NOW + DAY


def test_deadline_clamps_to_policy_valid_until(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(
        direct_vm,
        direct_deploy,
        valid_until=NOW + 3600,
    )
    contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    )
    assert contract.get_assessment(1)["deadline"] == NOW + 3600


def test_exact_live_binding_duplicate_rejected(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    )
    with direct_vm.expect_revert("LIVE_ASSESSMENT_EXISTS"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 900
        )


def test_requested_ttl_is_not_part_of_binding(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 300
    )
    first_key = contract.get_assessment(1)["binding_key"]
    with direct_vm.expect_revert("LIVE_ASSESSMENT_EXISTS"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy-v1", 1, 600
        )
    assert contract.get_assessment(1)["binding_key"] == first_key


def test_different_endpoint_is_distinct_binding(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    assert contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    ) == 1
    assert contract.create_assessment(
        PROFILE, ENDPOINT_2, "policy-v1", 1, 900
    ) == 2
    assert (
        contract.get_assessment(1)["binding_key"]
        != contract.get_assessment(2)["binding_key"]
    )


def test_different_sender_is_distinct_subject_and_binding(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    from gltest.direct.loader import create_address
    alice = create_address("agentseal-alice")
    bob = create_address("agentseal-bob")

    direct_vm.sender = alice
    assert contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    ) == 1

    direct_vm.sender = bob
    assert contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    ) == 2

    first = contract.get_assessment(1)
    second = contract.get_assessment(2)
    assert first["subject_wallet"] != second["subject_wallet"]
    assert first["binding_key"] != second["binding_key"]


def test_deadline_equality_effective_expiry_and_permissionless_cleanup(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    )
    binding_key = contract.get_assessment(1)["binding_key"]
    deadline = contract.get_assessment(1)["deadline"]

    assert deadline == NOW + DAY
    assert contract.get_live_assessment_id(binding_key) == 1

    direct_vm.warp("2026-09-22T12:00:00Z")

    before = contract.get_assessment(1)
    assert before["status"] == "PENDING"
    assert before["effective_status"] == "EXPIRED"
    assert contract.get_live_assessment_id(binding_key) == 0

    from gltest.direct.loader import create_address
    direct_vm.sender = create_address("permissionless-cleaner")
    contract.expire_assessment(1)

    after = contract.get_assessment(1)
    assert after["status"] == "EXPIRED"
    assert after["effective_status"] == "EXPIRED"
    assert contract.get_live_assessment_id(binding_key) == 0


def test_create_reconciles_expired_live_assessment(
    direct_vm, direct_deploy
):
    contract = _deploy_ready(direct_vm, direct_deploy)
    assert contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    ) == 1
    binding_key = contract.get_assessment(1)["binding_key"]

    direct_vm.warp("2026-09-22T12:00:00Z")

    assert contract.create_assessment(
        PROFILE, ENDPOINT, "policy-v1", 1, 900
    ) == 2
    assert contract.get_assessment(1)["status"] == "EXPIRED"
    assert contract.get_assessment(2)["status"] == "PENDING"
    assert contract.get_live_assessment_id(binding_key) == 2


def test_endpoint_length_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_LENGTH"):
        contract.create_assessment(
            PROFILE, "https://", "policy-v1", 1, 900
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_whitespace_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_WHITESPACE"):
        contract.create_assessment(
            PROFILE,
            "https://agent.example.com/eval uate",
            "policy-v1",
            1,
            900,
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_format_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_FORMAT"):
        contract.create_assessment(
            PROFILE,
            "https://agent.example.com:abc/evaluate",
            "policy-v1",
            1,
            900,
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_host_required_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_HOST_REQUIRED"):
        contract.create_assessment(
            PROFILE, "https:///evaluate", "policy-v1", 1, 900
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_fragment_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_FRAGMENT_FORBIDDEN"):
        contract.create_assessment(
            PROFILE,
            "https://agent.example.com/evaluate#fragment",
            "policy-v1",
            1,
            900,
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_ipv4_literal_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_IP_LITERAL_FORBIDDEN"):
        contract.create_assessment(
            PROFILE,
            "https://127.0.0.1/evaluate",
            "policy-v1",
            1,
            900,
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_single_label_host_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_PUBLIC_HOST_REQUIRED"):
        contract.create_assessment(
            PROFILE, "https://agent/evaluate", "policy-v1", 1, 900
        )
    assert contract.get_assessment_count() == 0


def test_endpoint_invalid_host_label_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)
    with direct_vm.expect_revert("ENDPOINT_HOST_FORMAT"):
        contract.create_assessment(
            PROFILE,
            "https://-agent.example.com/evaluate",
            "policy-v1",
            1,
            900,
        )
    assert contract.get_assessment_count() == 0


def test_policy_id_validation_rejected(direct_vm, direct_deploy):
    contract = _deploy_ready(direct_vm, direct_deploy)

    with direct_vm.expect_revert("POLICY_ID_LENGTH"):
        contract.create_assessment(PROFILE, ENDPOINT, "", 1, 900)

    with direct_vm.expect_revert("POLICY_ID_FORMAT"):
        contract.create_assessment(
            PROFILE, ENDPOINT, "policy/v1", 1, 900
        )

    assert contract.get_assessment_count() == 0
