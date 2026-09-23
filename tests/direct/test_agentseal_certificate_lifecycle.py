import ast
import hashlib
import json
import os

import pytest


CONTRACT = os.environ["AGENTSEAL_CONTRACT"]

NOW_ISO = "2026-09-21T12:00:00Z"
EXPIRY_900_ISO = "2026-09-21T12:15:00Z"
AFTER_EXPIRY_900_ISO = "2026-09-21T12:15:01Z"
POLICY_CAP_ISO = "2026-09-21T12:10:00Z"
NOW = 1789992000
DAY = 86_400
CHAIN_ID = 987654321

POLICY_ID = "policy-v1"
CAPABILITY_ID = "research"
MANIFEST_ID = "manifest-v1"
MANIFEST_AUTHORITY = "AgentSeal Test Authority"
CRITERIA = "Return correct structured research results."
MANIFEST_URL = "https://evidence.example.com/manifest.json"
ENDPOINT = "https://agent.example.com/evaluate"
ENDPOINT_2 = "https://agent-two.example.com/evaluate"

PROFILE_A = "b" * 64
PROFILE_B = "c" * 64


def _canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _manifest_payload():
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


def _web_response(status, body):
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


def _address(seed):
    from gltest.direct.loader import create_address

    return create_address(seed)


def _create_policy(
    contract,
    manifest_raw,
    *,
    valid_until=None,
    max_ttl=3600,
):
    if valid_until is None:
        valid_until = NOW + (10 * DAY)

    contract.create_policy(
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
    )


def _install_pass_handlers(
    direct_vm,
    manifest_raw,
):
    events = {
        "web": [],
        "llm": [],
    }

    def web_handler(data):
        event = dict(data)
        events["web"].append(event)

        method = str(
            event.get("method", "GET")
        ).upper()

        if method == "GET":
            return _web_response(
                200,
                manifest_raw,
            )

        if method == "POST":
            body = json.loads(
                bytes(
                    event["body"]
                ).decode("utf-8")
            )

            payload = {
                "protocol":
                    "agentseal-evaluation-v1",
                "evaluation_id":
                    body["evaluation_id"],
                "agent_wallet":
                    body["agent_wallet"],
                "profile_digest":
                    body["profile_digest"],
                "capability_id":
                    body["capability_id"],
                "policy_id":
                    body["policy_id"],
                "policy_version":
                    body["policy_version"],
                "manifest_id":
                    body["manifest_id"],
                "results": [
                    {
                        "case_id":
                            body["cases"][0][
                                "case_id"
                            ],
                        "output":
                            "step3 lifecycle output a",
                    },
                    {
                        "case_id":
                            body["cases"][1][
                                "case_id"
                            ],
                        "output":
                            "step3 lifecycle output b",
                    },
                ],
            }

            return _web_response(
                200,
                _canonical_bytes(payload),
            )

        raise AssertionError(
            f"unexpected web method: {method}"
        )

    def llm_handler(data):
        events["llm"].append(
            dict(data)
        )
        return {
            "ok": {
                "verdict": "PASS",
            }
        }

    direct_vm._live_web_handler = (
        web_handler
    )
    direct_vm._live_llm_handler = (
        llm_handler
    )

    return events


def _evaluate_pass(
    direct_vm,
    contract,
    assessment_id,
    manifest_raw,
):
    events = _install_pass_handlers(
        direct_vm,
        manifest_raw,
    )

    direct_vm.clear_validators()

    contract.evaluate_assessment(
        assessment_id
    )

    assert direct_vm.run_validator() is True

    return events


def _ready(
    direct_vm,
    direct_deploy,
    *,
    profile=PROFILE_A,
    endpoint=ENDPOINT,
    requested_ttl=900,
    valid_until=None,
):
    direct_vm.warp(NOW_ISO)
    direct_vm._chain_id = CHAIN_ID

    manifest_raw = _canonical_bytes(
        _manifest_payload()
    )
    contract = direct_deploy(CONTRACT)

    _create_policy(
        contract,
        manifest_raw,
        valid_until=valid_until,
    )

    assessment_id = int(
        contract.create_assessment(
            profile,
            endpoint,
            POLICY_ID,
            1,
            requested_ttl,
        )
    )

    return (
        contract,
        assessment_id,
        manifest_raw,
    )


def _ready_pass(
    direct_vm,
    direct_deploy,
    *,
    profile=PROFILE_A,
    endpoint=ENDPOINT,
    requested_ttl=900,
    valid_until=None,
):
    (
        contract,
        assessment_id,
        manifest_raw,
    ) = _ready(
        direct_vm,
        direct_deploy,
        profile=profile,
        endpoint=endpoint,
        requested_ttl=requested_ttl,
        valid_until=valid_until,
    )

    _evaluate_pass(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
    )

    return (
        contract,
        assessment_id,
        manifest_raw,
    )


def _certificate_record(
    contract,
    certificate_id,
):
    return contract.certificates[
        contract._certificate_key(
            certificate_id
        )
    ]


def _method_source(name):
    source = open(
        CONTRACT,
        "r",
        encoding="utf-8",
    ).read()
    tree = ast.parse(source)
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "AgentSeal"
    )
    method = next(
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
        and node.name == name
    )
    return (
        ast.get_source_segment(
            source,
            method,
        )
        or ""
    )


def _public_surface():
    source = open(
        CONTRACT,
        "r",
        encoding="utf-8",
    ).read()
    tree = ast.parse(source)
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "AgentSeal"
    )

    views = []
    writes = []
    methods = {}

    for node in cls.body:
        if not isinstance(
            node,
            ast.FunctionDef,
        ):
            continue

        methods[
            node.name
        ] = node

        decorators = {
            ast.unparse(decorator)
            for decorator
            in node.decorator_list
        }

        if "gl.public.view" in decorators:
            views.append(node.name)

        if "gl.public.write" in decorators:
            writes.append(node.name)

    return (
        sorted(views),
        sorted(writes),
        methods,
    )


def _two_active_certificates(
    direct_vm,
    direct_deploy,
):
    direct_vm.warp(NOW_ISO)
    direct_vm._chain_id = CHAIN_ID

    manifest_raw = _canonical_bytes(
        _manifest_payload()
    )
    contract = direct_deploy(CONTRACT)

    _create_policy(
        contract,
        manifest_raw,
    )

    a_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        a_id,
        manifest_raw,
    )

    b_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        b_id,
        manifest_raw,
    )

    return (
        contract,
        a_id,
        b_id,
        manifest_raw,
    )


# CURRENTNESS_VIEW_SEMANTICS = 6


def test_s3_currentness_preexpiry_certificate_reports_active(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    certificate = contract.get_certificate(
        certificate_id
    )

    assert certificate["status"] == "ACTIVE"
    assert (
        certificate["effective_status"]
        == "ACTIVE"
    )


def test_s3_currentness_preexpiry_active_index_returns_certificate(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    assert (
        contract.get_active_certificate_id(
            binding
        )
        == certificate_id
    )


def test_s3_currentness_boundary_effective_expired_before_materialization(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )

    certificate = contract.get_certificate(
        certificate_id
    )

    assert certificate["status"] == "ACTIVE"
    assert (
        certificate["effective_status"]
        == "EXPIRED"
    )


def test_s3_currentness_boundary_active_id_zero(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )

    assert (
        contract.get_active_certificate_id(
            binding
        )
        == 0
    )


def test_s3_currentness_boundary_raw_index_still_historical_before_materialization(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )

    assert int(
        contract.active_certificate_by_binding.get(
            binding
        )
        or 0
    ) == certificate_id


def test_s3_currentness_certificate_exists_after_time_expiry(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )

    assert (
        contract.certificate_exists(
            certificate_id
        )
        is True
    )


# EXPIRE_AUTH_AND_BOUNDARY = 6


def test_s3_expire_missing_certificate_rejected(
    direct_vm,
    direct_deploy,
):
    direct_vm.warp(NOW_ISO)
    contract = direct_deploy(
        CONTRACT
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_NOT_FOUND"
    ):
        contract.expire_certificate(
            999
        )


def test_s3_expire_preexpiry_owner_rejected(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_NOT_EXPIRED"
    ):
        contract.expire_certificate(
            certificate_id
        )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "ACTIVE"
    )


def test_s3_expire_preexpiry_outsider_rejected(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    direct_vm.sender = _address(
        "agentseal-s3-preexpiry-outsider"
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_NOT_EXPIRED"
    ):
        contract.expire_certificate(
            certificate_id
        )


def test_s3_expire_permissionless_exact_boundary_succeeds(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    direct_vm.warp(
        EXPIRY_900_ISO
    )
    direct_vm.sender = _address(
        "agentseal-s3-boundary-outsider"
    )

    contract.expire_certificate(
        certificate_id
    )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "EXPIRED"
    )


def test_s3_expire_permissionless_after_boundary_succeeds(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    direct_vm.warp(
        AFTER_EXPIRY_900_ISO
    )
    direct_vm.sender = _address(
        "agentseal-s3-after-boundary-outsider"
    )

    contract.expire_certificate(
        certificate_id
    )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "EXPIRED"
    )


def test_s3_expire_repeat_rejected_as_not_active(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    direct_vm.warp(
        EXPIRY_900_ISO
    )

    contract.expire_certificate(
        certificate_id
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_NOT_ACTIVE"
    ):
        contract.expire_certificate(
            certificate_id
        )


# EXPIRE_INDEX_INTEGRITY = 5


def test_s3_index_missing_raw_active_index_rejected(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.active_certificate_by_binding[
        binding
    ] = 0

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
    ):
        contract.expire_certificate(
            certificate_id
        )


def test_s3_index_corruption_rejection_preserves_certificate_active(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.active_certificate_by_binding[
        binding
    ] = 0

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
    ):
        contract.expire_certificate(
            certificate_id
        )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "ACTIVE"
    )


def test_s3_index_success_clears_raw_active_index(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    assert int(
        contract.active_certificate_by_binding.get(
            binding
        )
        or 0
    ) == 0


def test_s3_index_success_clears_effective_active_id(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    assert (
        contract.get_active_certificate_id(
            binding
        )
        == 0
    )


def test_s3_index_expiring_one_binding_does_not_clear_other_raw_index(
    direct_vm,
    direct_deploy,
):
    (
        contract,
        a_id,
        b_id,
        _,
    ) = _two_active_certificates(
        direct_vm,
        direct_deploy,
    )

    a_binding = contract.get_certificate(
        a_id
    )["binding_key"]
    b_binding = contract.get_certificate(
        b_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        a_id
    )

    assert int(
        contract.active_certificate_by_binding.get(
            a_binding
        )
        or 0
    ) == 0
    assert int(
        contract.active_certificate_by_binding.get(
            b_binding
        )
        or 0
    ) == b_id


# REPLACEMENT_AFTER_EXPIRY = 8


def test_s3_replacement_unexpired_certificate_blocks_same_binding_assessment(
    direct_vm,
    direct_deploy,
):
    contract, _certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_EXISTS"
    ):
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )


def test_s3_replacement_explicit_expiry_allows_fresh_same_binding_assessment(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    old_binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )

    assert new_id != certificate_id
    assert (
        contract.get_assessment(
            new_id
        )["binding_key"]
        == old_binding
    )


def test_s3_replacement_fresh_assessment_is_pending_and_live(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )

    assert (
        contract.get_assessment(
            new_id
        )["status"]
        == "PENDING"
    )
    assert (
        contract.get_live_assessment_id(
            binding
        )
        == new_id
    )


def test_s3_replacement_no_new_certificate_before_fresh_pass(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )

    assert (
        contract.certificate_exists(
            new_id
        )
        is False
    )


def test_s3_replacement_fresh_pass_certificate_id_equals_new_assessment(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, manifest_raw = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        new_id,
        manifest_raw,
    )

    assert (
        contract.get_certificate(
            new_id
        )["certificate_id"]
        == new_id
    )


def test_s3_replacement_fresh_certificate_preserves_same_binding(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, manifest_raw = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        new_id,
        manifest_raw,
    )

    assert (
        contract.get_certificate(
            new_id
        )["binding_key"]
        == binding
    )


def test_s3_replacement_fresh_certificate_is_active_and_current(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, manifest_raw = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        new_id,
        manifest_raw,
    )

    replacement = contract.get_certificate(
        new_id
    )

    assert replacement["status"] == "ACTIVE"
    assert (
        replacement["effective_status"]
        == "ACTIVE"
    )
    assert (
        contract.get_active_certificate_id(
            binding
        )
        == new_id
    )
    assert replacement["issued_at"] == NOW + 900
    assert replacement["expires_at"] == NOW + 1800


def test_s3_replacement_old_certificate_remains_expired_and_queryable(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, manifest_raw = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    new_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        new_id,
        manifest_raw,
    )

    old = contract.get_certificate(
        certificate_id
    )

    assert old["status"] == "EXPIRED"
    assert (
        old["certificate_id"]
        == certificate_id
    )
    assert (
        contract.certificate_exists(
            certificate_id
        )
        is True
    )


# HISTORICAL_IMMUTABILITY = 5


@pytest.mark.parametrize(
    "fields",
    [
        [
            "certificate_id",
            "assessment_id",
        ],
        [
            "subject_wallet",
            "profile_digest",
            "endpoint",
        ],
        [
            "capability_id",
            "policy_id",
            "policy_version",
            "manifest_id",
            "manifest_digest",
        ],
        [
            "case_a_id",
            "case_b_id",
            "binding_key",
        ],
        [
            "issued_at",
            "expires_at",
        ],
    ],
)
def test_s3_history_expiry_preserves_all_non_status_certificate_fields(
    direct_vm,
    direct_deploy,
    fields,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    before = dict(
        contract.get_certificate(
            certificate_id
        )
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    after = dict(
        contract.get_certificate(
            certificate_id
        )
    )

    for field in fields:
        assert after[field] == before[field]

    assert after["status"] == "EXPIRED"


# POLICY_INTERACTION = 4


def test_s3_policy_disable_does_not_retroactively_invalidate_unexpired_certificate(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )
    binding = contract.get_certificate(
        certificate_id
    )["binding_key"]

    contract.disable_policy(
        POLICY_ID,
        1,
    )

    certificate = contract.get_certificate(
        certificate_id
    )

    assert certificate["status"] == "ACTIVE"
    assert (
        certificate["effective_status"]
        == "ACTIVE"
    )
    assert (
        contract.get_active_certificate_id(
            binding
        )
        == certificate_id
    )


def test_s3_policy_disabled_policy_does_not_block_objective_expiry(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    contract.disable_policy(
        POLICY_ID,
        1,
    )
    direct_vm.warp(
        EXPIRY_900_ISO
    )
    direct_vm.sender = _address(
        "agentseal-s3-disabled-policy-outsider"
    )

    contract.expire_certificate(
        certificate_id
    )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "EXPIRED"
    )


def test_s3_policy_valid_until_caps_certificate_expiry(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
        requested_ttl=900,
        valid_until=NOW + 600,
    )

    assert (
        contract.get_certificate(
            certificate_id
        )["expires_at"]
        == NOW + 600
    )


def test_s3_policy_expired_policy_blocks_replacement_after_certificate_expiry(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
        requested_ttl=900,
        valid_until=NOW + 600,
    )

    direct_vm.warp(
        POLICY_CAP_ISO
    )
    contract.expire_certificate(
        certificate_id
    )

    with direct_vm.expect_revert(
        "POLICY_EXPIRED"
    ):
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )


# CROSS_BINDING_ISOLATION = 4


def test_s3_isolation_expiring_a_leaves_b_stored_active(
    direct_vm,
    direct_deploy,
):
    contract, a_id, b_id, _ = _two_active_certificates(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        a_id
    )

    assert (
        contract.get_certificate(
            a_id
        )["status"]
        == "EXPIRED"
    )
    assert (
        contract.get_certificate(
            b_id
        )["status"]
        == "ACTIVE"
    )


def test_s3_isolation_expiring_a_leaves_b_raw_index_unchanged(
    direct_vm,
    direct_deploy,
):
    contract, a_id, b_id, _ = _two_active_certificates(
        direct_vm,
        direct_deploy,
    )
    b_binding = contract.get_certificate(
        b_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        a_id
    )

    assert int(
        contract.active_certificate_by_binding.get(
            b_binding
        )
        or 0
    ) == b_id


def test_s3_isolation_expiring_a_leaves_b_assessment_unchanged(
    direct_vm,
    direct_deploy,
):
    contract, a_id, b_id, _ = _two_active_certificates(
        direct_vm,
        direct_deploy,
    )
    before = dict(
        contract.get_assessment(
            b_id
        )
    )

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        a_id
    )

    assert dict(
        contract.get_assessment(
            b_id
        )
    ) == before


def test_s3_isolation_replacing_a_does_not_overwrite_b_raw_index(
    direct_vm,
    direct_deploy,
):
    (
        contract,
        a_id,
        b_id,
        manifest_raw,
    ) = _two_active_certificates(
        direct_vm,
        direct_deploy,
    )
    b_binding = contract.get_certificate(
        b_id
    )["binding_key"]

    direct_vm.warp(
        EXPIRY_900_ISO
    )
    contract.expire_certificate(
        a_id
    )

    new_a_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )
    _evaluate_pass(
        direct_vm,
        contract,
        new_a_id,
        manifest_raw,
    )

    assert int(
        contract.active_certificate_by_binding.get(
            b_binding
        )
        or 0
    ) == b_id


# STEP4_BOUNDARY_GUARDS = 4


def test_s3_step4_public_surface_matches_frozen_challenge_revocation_abi():
    views, writes, methods = _public_surface()

    assert len(views) == 16
    assert len(writes) == 10

    for name in [
        "get_challenge_count",
        "challenge_exists",
        "get_challenge",
        "get_open_challenge_id",
        "get_revocation",
    ]:
        assert name in views
        assert name in methods

    for name in [
        "open_challenge",
        "evaluate_challenge",
        "expire_challenge",
        "revoke_certificate",
    ]:
        assert name in writes
        assert name in methods


def test_s3_step4_expire_method_has_no_revoked_or_challenge_logic():
    source = _method_source(
        "expire_certificate"
    )

    assert "REVOKED" not in source
    assert "challenge" not in source.lower()


def test_s3_step4_expire_method_is_permissionless_deterministic_and_delegates_once():
    source = _method_source(
        "expire_certificate"
    )

    assert "gl.message." not in source
    assert "gl.nondet." not in source
    assert "run_nondet" not in source
    assert "strict_eq" not in source
    assert source.count(
        "self._reconcile_active_certificate("
    ) == 1


def test_s3_step4_revoked_certificate_is_not_changed_by_expire_method(
    direct_vm,
    direct_deploy,
):
    contract, certificate_id, _ = _ready_pass(
        direct_vm,
        direct_deploy,
    )

    _certificate_record(
        contract,
        certificate_id,
    ).status = "REVOKED"

    direct_vm.warp(
        EXPIRY_900_ISO
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_NOT_ACTIVE"
    ):
        contract.expire_certificate(
            certificate_id
        )

    assert (
        contract.get_certificate(
            certificate_id
        )["status"]
        == "REVOKED"
    )
