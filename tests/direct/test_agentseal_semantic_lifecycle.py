import ast
import hashlib
import json
import os

import pytest


CONTRACT = os.environ["AGENTSEAL_CONTRACT"]

NOW_ISO = "2026-09-21T12:00:00Z"
DEADLINE_ISO = "2026-09-22T12:00:00Z"
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
PROFILE_C = "d" * 64


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

    return contract, assessment_id, manifest_raw


def _assessment_record(contract, assessment_id):
    return contract.assessments[
        contract._assessment_key(assessment_id)
    ]


def _policy_record(contract):
    return contract.policies[
        contract._policy_key(POLICY_ID, 1)
    ]


def _install_handlers(
    direct_vm,
    manifest_raw,
    *,
    verdict="PASS",
    get_mode="success",
    llm_payload=None,
):
    events = {
        "web": [],
        "llm": [],
        "post_bodies": [],
    }

    if llm_payload is None:
        llm_payload = {
            "verdict": verdict,
        }

    def web_handler(data):
        event = dict(data)
        events["web"].append(event)

        method = str(
            event.get("method", "GET")
        ).upper()

        if method == "GET":
            if get_mode == "transport":
                raise RuntimeError(
                    "SIMULATED_MANIFEST_TRANSPORT"
                )

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
            events["post_bodies"].append(
                body
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
                            "lifecycle output a",
                    },
                    {
                        "case_id":
                            body["cases"][1][
                                "case_id"
                            ],
                        "output":
                            "lifecycle output b",
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
            "ok": llm_payload,
        }

    direct_vm._live_web_handler = (
        web_handler
    )
    direct_vm._live_llm_handler = (
        llm_handler
    )

    return events


def _evaluate(
    direct_vm,
    contract,
    assessment_id,
    manifest_raw,
    *,
    verdict="PASS",
    get_mode="success",
    llm_payload=None,
):
    events = _install_handlers(
        direct_vm,
        manifest_raw,
        verdict=verdict,
        get_mode=get_mode,
        llm_payload=llm_payload,
    )

    direct_vm.clear_validators()

    contract.evaluate_assessment(
        assessment_id
    )

    assert direct_vm.run_validator() is True

    return events


def _snapshot(
    contract,
    assessment_id,
):
    assessment = contract.get_assessment(
        assessment_id
    )
    binding_key = assessment[
        "binding_key"
    ]

    return {
        "assessment": assessment,
        "live_id":
            contract.get_live_assessment_id(
                binding_key
            ),
        "certificate_exists":
            contract.certificate_exists(
                assessment_id
            ),
        "active_certificate_id":
            contract.get_active_certificate_id(
                binding_key
            ),
    }


def _method_node(name):
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
    return source, method


def _method_source(name):
    source, method = _method_node(name)
    return ast.get_source_segment(
        source,
        method,
    ) or ""


def _rooted_in_self(target):
    node = target

    while isinstance(node, ast.Subscript):
        node = node.value

    while isinstance(node, ast.Attribute):
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return True

        node = node.value

    return (
        isinstance(node, ast.Name)
        and node.id == "self"
    )


def _statement_has_self_write(statement):
    for node in ast.walk(statement):
        if isinstance(node, ast.Assign):
            if any(
                _rooted_in_self(target)
                for target in node.targets
            ):
                return True

        if isinstance(node, ast.AnnAssign):
            if _rooted_in_self(
                node.target
            ):
                return True

        if isinstance(node, ast.AugAssign):
            if _rooted_in_self(
                node.target
            ):
                return True

    return False


def _direct_self_write(method):
    return any(
        _statement_has_self_write(
            statement
        )
        for statement in method.body
    )


def _seed_other_certificate(
    contract,
    other_assessment_id,
    *,
    case_a_id="seed-a",
    case_b_id="seed-b",
):
    policy = _policy_record(contract)
    assessment = _assessment_record(
        contract,
        other_assessment_id,
    )

    return contract._issue_pass_certificate(
        assessment,
        policy,
        NOW,
        case_a_id,
        case_b_id,
    )


# AUTHORIZATION_AND_EXISTENCE = 5


def test_a5_auth_missing_assessment_rejected(
    direct_vm,
    direct_deploy,
):
    direct_vm.warp(NOW_ISO)
    direct_vm._chain_id = CHAIN_ID
    contract = direct_deploy(CONTRACT)

    with direct_vm.expect_revert(
        "ASSESSMENT_NOT_FOUND"
    ):
        contract.evaluate_assessment(1)


def test_a5_auth_contract_owner_has_no_subject_bypass(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    owner = contract.owner
    subject = _address(
        "agentseal-a5-subject-owner-bypass"
    )

    direct_vm.sender = subject

    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    direct_vm.sender = owner
    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_SUBJECT_REQUIRED"
    ):
        contract.evaluate_assessment(
            second_id
        )

    assert events["web"] == []
    assert events["llm"] == []
    assert assessment_id == 1


def test_a5_auth_arbitrary_outsider_rejected_before_nondet(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    direct_vm.sender = _address(
        "agentseal-a5-outsider"
    )
    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_SUBJECT_REQUIRED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


def test_a5_auth_exact_subject_can_evaluate(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_assessment(
            assessment_id
        )["status"]
        == "PASSED"
    )


def test_a5_auth_rejected_caller_leaves_state_exact(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    before = _snapshot(
        contract,
        assessment_id,
    )

    direct_vm.sender = _address(
        "agentseal-a5-rejected-caller"
    )
    _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_SUBJECT_REQUIRED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    after = _snapshot(
        contract,
        assessment_id,
    )
    assert after == before


# STATUS_DEADLINE_POLICY_VALIDITY = 6


@pytest.mark.parametrize(
    "terminal_status",
    [
        "PASSED",
        "FAILED",
        "INCONCLUSIVE_FINAL",
    ],
)
def test_a5_status_terminal_state_rejected(
    direct_vm,
    direct_deploy,
    terminal_status,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = _assessment_record(
        contract,
        assessment_id,
    )
    assessment.status = terminal_status

    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_NOT_PENDING"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


def test_a5_status_deadline_equality_rejected(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    direct_vm.warp(DEADLINE_ISO)
    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_EXPIRED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []


def test_a5_status_policy_valid_until_rechecked(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    policy = _policy_record(contract)
    policy.valid_until = NOW

    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "POLICY_EXPIRED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []


def test_a5_status_policy_disabled_after_creation_does_not_invalidate(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    contract.disable_policy(
        POLICY_ID,
        1,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_assessment(
            assessment_id
        )["status"]
        == "PASSED"
    )


# POLICY_ASSESSMENT_SNAPSHOT_CONSISTENCY = 6


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability_id", "tampered-capability"),
        ("policy_id", "tampered-policy"),
        ("version", 2),
        ("manifest_id", "tampered-manifest"),
        ("manifest_digest", "f" * 64),
    ],
)
def test_a5_snapshot_policy_record_mismatch_rejected(
    direct_vm,
    direct_deploy,
    field,
    value,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    policy = _policy_record(contract)
    setattr(
        policy,
        field,
        value,
    )

    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_POLICY_SNAPSHOT_MISMATCH"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


def test_a5_snapshot_missing_policy_key_rejected(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = _assessment_record(
        contract,
        assessment_id,
    )
    assessment.policy_id = (
        "missing-policy"
    )

    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "POLICY_NOT_FOUND"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []


# ATTEMPT_NUMBER_AND_EXACT_ONCE_INCREMENT = 5


@pytest.mark.parametrize(
    "verdict",
    [
        "PASS",
        "FAIL",
        "INCONCLUSIVE",
    ],
)
def test_a5_attempt_first_execution_increments_exactly_once(
    direct_vm,
    direct_deploy,
    verdict,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict=verdict,
    )

    assert (
        contract.get_assessment(
            assessment_id
        )["attempt_count"]
        == 1
    )


def test_a5_attempt_retry_uses_attempt_number_two_in_evaluation_id(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    first = _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="INCONCLUSIVE",
    )
    second = _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="INCONCLUSIVE",
    )

    assert (
        first["post_bodies"][0][
            "evaluation_id"
        ].endswith(":1")
    )
    assert (
        second["post_bodies"][0][
            "evaluation_id"
        ].endswith(":2")
    )
    assert (
        contract.get_assessment(
            assessment_id
        )["attempt_count"]
        == 2
    )


def test_a5_attempt_exhausted_guard_precedes_nondet(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = _assessment_record(
        contract,
        assessment_id,
    )
    assessment.attempt_count = 3

    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_ATTEMPTS_EXHAUSTED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


# PASS_ATOMIC_CERTIFICATE_ISSUANCE = 8


def test_a5_passcert_id_equals_assessment_and_link_exact(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assessment = contract.get_assessment(
        assessment_id
    )
    certificate = contract.get_certificate(
        assessment_id
    )

    assert (
        certificate["certificate_id"]
        == assessment_id
    )
    assert (
        certificate["assessment_id"]
        == assessment_id
    )
    assert (
        assessment["certificate_id"]
        == assessment_id
    )


def test_a5_passcert_identity_snapshot_exact(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    before = contract.get_assessment(
        assessment_id
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    certificate = contract.get_certificate(
        assessment_id
    )

    for field in [
        "subject_wallet",
        "profile_digest",
        "endpoint",
        "capability_id",
        "policy_id",
        "policy_version",
        "manifest_id",
        "manifest_digest",
        "binding_key",
    ]:
        assert certificate[field] == before[field]


def test_a5_passcert_case_ids_exact_from_consensus(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assessment = contract.get_assessment(
        assessment_id
    )
    certificate = contract.get_certificate(
        assessment_id
    )

    assert assessment["case_a_id"] != ""
    assert assessment["case_b_id"] != ""
    assert (
        certificate["case_a_id"]
        == assessment["case_a_id"]
    )
    assert (
        certificate["case_b_id"]
        == assessment["case_b_id"]
    )


def test_a5_passcert_active_status_and_index(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assessment = contract.get_assessment(
        assessment_id
    )
    certificate = contract.get_certificate(
        assessment_id
    )

    assert certificate["status"] == "ACTIVE"
    assert (
        contract.get_active_certificate_id(
            assessment["binding_key"]
        )
        == assessment_id
    )


def test_a5_passcert_issued_at_is_transaction_time(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_certificate(
            assessment_id
        )["issued_at"]
        == NOW
    )


def test_a5_passcert_expiry_uses_requested_ttl(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
        requested_ttl=900,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_certificate(
            assessment_id
        )["expires_at"]
        == NOW + 900
    )


def test_a5_passcert_expiry_clamps_policy_valid_until(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
        requested_ttl=900,
        valid_until=NOW + 600,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_certificate(
            assessment_id
        )["expires_at"]
        == NOW + 600
    )


def test_a5_passcert_status_and_certificate_observable_atomically(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="PASS",
    )

    state = _snapshot(
        contract,
        assessment_id,
    )

    assert (
        state["assessment"]["status"]
        == "PASSED"
    )
    assert state["certificate_exists"] is True
    assert (
        state["assessment"][
            "certificate_id"
        ]
        == assessment_id
    )


# FAIL_TERMINAL_TRANSITION = 4


def test_a5_fail_persists_terminal_result_fields(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="FAIL",
    )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert assessment["status"] == "FAILED"
    assert assessment["attempt_count"] == 1
    assert assessment["last_verdict"] == "FAIL"
    assert assessment["case_a_id"] != ""
    assert assessment["case_b_id"] != ""


def test_a5_fail_allocates_no_certificate(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="FAIL",
    )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert assessment["certificate_id"] == 0
    assert (
        contract.certificate_exists(
            assessment_id
        )
        is False
    )
    assert (
        contract.get_active_certificate_id(
            assessment["binding_key"]
        )
        == 0
    )


def test_a5_fail_clears_live_binding_index(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    binding_key = contract.get_assessment(
        assessment_id
    )["binding_key"]

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="FAIL",
    )

    assert (
        contract.get_live_assessment_id(
            binding_key
        )
        == 0
    )


def test_a5_fail_cannot_be_retried_and_does_not_reenter_nondet(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="FAIL",
    )

    events = _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_NOT_PENDING"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


# INCONCLUSIVE_RETRY_AND_FINALIZATION = 7


@pytest.mark.parametrize(
    "attempts,expected_status,expected_live",
    [
        (1, "PENDING", 1),
        (2, "PENDING", 1),
        (3, "INCONCLUSIVE_FINAL", 0),
    ],
)
def test_a5_inconclusive_retry_state_machine(
    direct_vm,
    direct_deploy,
    attempts,
    expected_status,
    expected_live,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    binding_key = contract.get_assessment(
        assessment_id
    )["binding_key"]

    for _ in range(attempts):
        _evaluate(
            direct_vm,
            contract,
            assessment_id,
            manifest_raw,
            verdict="INCONCLUSIVE",
        )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert assessment["attempt_count"] == attempts
    assert (
        assessment["last_verdict"]
        == "INCONCLUSIVE"
    )
    assert (
        assessment["status"]
        == expected_status
    )
    assert (
        contract.get_live_assessment_id(
            binding_key
        )
        == (
            assessment_id
            if expected_live
            else 0
        )
    )


def test_a5_inconclusive_preselection_failure_persists_empty_case_ids(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        get_mode="transport",
    )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert (
        assessment["last_verdict"]
        == "INCONCLUSIVE"
    )
    assert assessment["case_a_id"] == ""
    assert assessment["case_b_id"] == ""
    assert assessment["status"] == "PENDING"


def test_a5_inconclusive_selected_failure_persists_selected_case_ids(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    _evaluate(
        direct_vm,
        contract,
        assessment_id,
        manifest_raw,
        verdict="INCONCLUSIVE",
    )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert assessment["case_a_id"] != ""
    assert assessment["case_b_id"] != ""
    assert (
        assessment["case_a_id"]
        != assessment["case_b_id"]
    )


def test_a5_inconclusive_never_allocates_certificate_across_retries(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    for _ in range(2):
        _evaluate(
            direct_vm,
            contract,
            assessment_id,
            manifest_raw,
            verdict="INCONCLUSIVE",
        )

    assert (
        contract.certificate_exists(
            assessment_id
        )
        is False
    )
    assert (
        contract.get_assessment(
            assessment_id
        )["certificate_id"]
        == 0
    )


def test_a5_inconclusive_final_rejects_fourth_call_before_nondet(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    for _ in range(3):
        _evaluate(
            direct_vm,
            contract,
            assessment_id,
            manifest_raw,
            verdict="INCONCLUSIVE",
        )

    events = _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_NOT_PENDING"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []
    assert events["llm"] == []


# LIVE_BINDING_INDEX_TRANSITIONS = 4


@pytest.mark.parametrize(
    "verdict,attempts,expected_live",
    [
        ("PASS", 1, 0),
        ("FAIL", 1, 0),
        ("INCONCLUSIVE", 1, 1),
        ("INCONCLUSIVE", 3, 0),
    ],
)
def test_a5_live_binding_transition_matrix(
    direct_vm,
    direct_deploy,
    verdict,
    attempts,
    expected_live,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    binding_key = contract.get_assessment(
        assessment_id
    )["binding_key"]

    for _ in range(attempts):
        _evaluate(
            direct_vm,
            contract,
            assessment_id,
            manifest_raw,
            verdict=verdict,
        )

    assert (
        contract.get_live_assessment_id(
            binding_key
        )
        == (
            assessment_id
            if expected_live
            else 0
        )
    )


# CERTIFICATE_COLLISION_AND_BINDING_INTEGRITY = 6


def test_a5_certguard_existing_certificate_key_rejected_without_attempt_commit(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = _assessment_record(
        contract,
        assessment_id,
    )
    policy = _policy_record(contract)

    contract._issue_pass_certificate(
        assessment,
        policy,
        NOW,
        "seed-a",
        "seed-b",
    )

    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "CERTIFICATE_ALREADY_EXISTS"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    current = contract.get_assessment(
        assessment_id
    )
    assert current["status"] == "PENDING"
    assert current["attempt_count"] == 0


def test_a5_certguard_missing_active_certificate_index_target_rejected(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = _assessment_record(
        contract,
        assessment_id,
    )

    contract.active_certificate_by_binding[
        assessment.binding_key
    ] = 999

    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert (
        contract.get_assessment(
            assessment_id
        )["attempt_count"]
        == 0
    )


def test_a5_certguard_wrong_binding_active_index_rejected(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    _seed_other_certificate(
        contract,
        second_id,
    )

    first = _assessment_record(
        contract,
        first_id,
    )

    contract.active_certificate_by_binding[
        first.binding_key
    ] = second_id

    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
    ):
        contract.evaluate_assessment(
            first_id
        )

    assert (
        contract.get_assessment(
            first_id
        )["attempt_count"]
        == 0
    )


def test_a5_certguard_existing_active_certificate_same_binding_rejected(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    _seed_other_certificate(
        contract,
        second_id,
    )

    first = _assessment_record(
        contract,
        first_id,
    )
    other_certificate = contract.certificates[
        contract._certificate_key(
            second_id
        )
    ]
    other_certificate.binding_key = (
        first.binding_key
    )

    contract.active_certificate_by_binding[
        first.binding_key
    ] = second_id

    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_EXISTS"
    ):
        contract.evaluate_assessment(
            first_id
        )


def test_a5_certguard_expired_active_index_is_not_silently_overwritten(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    _seed_other_certificate(
        contract,
        second_id,
    )

    first = _assessment_record(
        contract,
        first_id,
    )
    other_certificate = contract.certificates[
        contract._certificate_key(
            second_id
        )
    ]
    other_certificate.binding_key = (
        first.binding_key
    )
    other_certificate.expires_at = NOW

    contract.active_certificate_by_binding[
        first.binding_key
    ] = second_id

    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )

    with direct_vm.expect_revert(
        "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
    ):
        contract.evaluate_assessment(
            first_id
        )


def test_a5_certguard_unrelated_active_binding_is_preserved(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )
    second = contract.get_assessment(
        second_id
    )

    _seed_other_certificate(
        contract,
        second_id,
    )

    _evaluate(
        direct_vm,
        contract,
        first_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_active_certificate_id(
            second["binding_key"]
        )
        == second_id
    )


# CROSS_ASSESSMENT_AND_CROSS_AGENT_ISOLATION = 6


def test_a5_isolation_pass_one_assessment_leaves_other_pending(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    before_second = contract.get_assessment(
        second_id
    )

    _evaluate(
        direct_vm,
        contract,
        first_id,
        manifest_raw,
        verdict="PASS",
    )

    after_second = contract.get_assessment(
        second_id
    )

    assert after_second == before_second


def test_a5_isolation_different_agents_have_distinct_subjects_and_bindings(
    direct_vm,
    direct_deploy,
):
    contract, first_id, _ = _ready(
        direct_vm,
        direct_deploy,
    )

    bob = _address(
        "agentseal-a5-isolation-bob"
    )
    direct_vm.sender = bob

    second_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )

    first = contract.get_assessment(
        first_id
    )
    second = contract.get_assessment(
        second_id
    )

    assert (
        first["subject_wallet"]
        != second["subject_wallet"]
    )
    assert (
        first["binding_key"]
        != second["binding_key"]
    )


def test_a5_isolation_agent_cannot_evaluate_other_agent_assessment(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )

    direct_vm.sender = _address(
        "agentseal-a5-isolation-outsider"
    )
    events = _install_handlers(
        direct_vm,
        manifest_raw,
    )

    with direct_vm.expect_revert(
        "ASSESSMENT_SUBJECT_REQUIRED"
    ):
        contract.evaluate_assessment(
            assessment_id
        )

    assert events["web"] == []


def test_a5_isolation_bob_pass_does_not_clear_alice_live_index(
    direct_vm,
    direct_deploy,
):
    contract, alice_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    alice = contract.get_assessment(
        alice_id
    )

    bob = _address(
        "agentseal-a5-isolation-bob-pass"
    )
    direct_vm.sender = bob

    bob_id = int(
        contract.create_assessment(
            PROFILE_A,
            ENDPOINT,
            POLICY_ID,
            1,
            900,
        )
    )

    _evaluate(
        direct_vm,
        contract,
        bob_id,
        manifest_raw,
        verdict="PASS",
    )

    assert (
        contract.get_live_assessment_id(
            alice["binding_key"]
        )
        == alice_id
    )


def test_a5_isolation_alice_fail_does_not_mutate_bob_assessment(
    direct_vm,
    direct_deploy,
):
    contract, alice_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    owner = contract.owner

    bob = _address(
        "agentseal-a5-isolation-bob-fail"
    )
    direct_vm.sender = bob

    bob_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )
    bob_before = contract.get_assessment(
        bob_id
    )

    direct_vm.sender = owner

    _evaluate(
        direct_vm,
        contract,
        alice_id,
        manifest_raw,
        verdict="FAIL",
    )

    bob_after = contract.get_assessment(
        bob_id
    )
    assert bob_after == bob_before


def test_a5_isolation_certificate_and_case_ids_do_not_leak_to_other_assessment(
    direct_vm,
    direct_deploy,
):
    contract, first_id, manifest_raw = _ready(
        direct_vm,
        direct_deploy,
    )
    second_id = int(
        contract.create_assessment(
            PROFILE_B,
            ENDPOINT_2,
            POLICY_ID,
            1,
            900,
        )
    )

    _evaluate(
        direct_vm,
        contract,
        first_id,
        manifest_raw,
        verdict="PASS",
    )

    second = contract.get_assessment(
        second_id
    )

    assert second["certificate_id"] == 0
    assert second["case_a_id"] == ""
    assert second["case_b_id"] == ""
    assert (
        contract.certificate_exists(
            second_id
        )
        is False
    )


# NONDET_ACCEPTANCE_REQUIRED_BEFORE_STATE_MUTATION = 4


def test_a5_nondet_exactly_one_consensus_call_and_two_storage_copies():
    source = _method_source(
        "evaluate_assessment"
    )

    assert source.count(
        "gl.storage.copy_to_memory("
    ) == 2
    assert source.count(
        "self._semantic_evaluation_consensus("
    ) == 1
    assert (
        "gl.message.contract_address"
        in source
    )
    assert (
        "int(gl.message.chain_id)"
        in source
    )


def test_a5_nondet_no_self_storage_write_before_consensus_statement():
    _source, method = _method_node(
        "evaluate_assessment"
    )

    consensus_index = next(
        index
        for index, statement
        in enumerate(method.body)
        if (
            "_semantic_evaluation_consensus"
            in ast.unparse(statement)
        )
    )

    assert not any(
        _statement_has_self_write(
            statement
        )
        for statement
        in method.body[
            :consensus_index
        ]
    )


def test_a5_nondet_attempt_verdict_and_case_writes_follow_consensus():
    source = _method_source(
        "evaluate_assessment"
    )

    consensus = source.index(
        "self._semantic_evaluation_consensus("
    )

    for fragment in [
        "assessment.attempt_count =",
        "assessment.last_verdict =",
        "assessment.case_a_id =",
        "assessment.case_b_id =",
    ]:
        assert source.index(
            fragment
        ) > consensus


def test_a5_nondet_verdict_validation_and_certificate_issue_precede_result_writes():
    source = _method_source(
        "evaluate_assessment"
    )

    consensus = source.index(
        "self._semantic_evaluation_consensus("
    )
    verdict_validation = source.index(
        'verdict != "PASS"'
    )
    certificate = source.index(
        "self._issue_pass_certificate("
    )
    result_write = source.index(
        "assessment.attempt_count ="
    )

    assert (
        consensus
        < verdict_validation
        < certificate
        < result_write
    )
    assert (
        "raise gl.vm.UserError"
        not in source[
            result_write:
        ]
    )


# A4_AND_STEP1_REGRESSION_GUARDS = 3


def test_a5_regression_a4_private_core_still_has_exact_consensus_and_no_storage_writes():
    source = _method_source(
        "_semantic_evaluation_consensus"
    )
    assert (
        '{"verdict", "case_a_id", "case_b_id"}'
        in source
    )
    assert source.count(
        "gl.vm.run_nondet_unsafe("
    ) == 1

    for name in [
        "_build_evaluator_prompt",
        "_semantic_evaluation_once",
        "_semantic_evaluation_consensus",
    ]:
        _source, method = _method_node(
            name
        )
        assert (
            _direct_self_write(method)
            is False
        )


def test_a5_regression_step1_create_assessment_initial_state_preserved(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, _ = _ready(
        direct_vm,
        direct_deploy,
    )

    assessment = contract.get_assessment(
        assessment_id
    )

    assert assessment["status"] == "PENDING"
    assert assessment["attempt_count"] == 0
    assert assessment["last_verdict"] == ""
    assert assessment["case_a_id"] == ""
    assert assessment["case_b_id"] == ""
    assert assessment["certificate_id"] == 0
    assert (
        contract.get_live_assessment_id(
            assessment["binding_key"]
        )
        == assessment_id
    )


def test_a5_regression_step1_permissionless_expiry_cleanup_preserved(
    direct_vm,
    direct_deploy,
):
    contract, assessment_id, _ = _ready(
        direct_vm,
        direct_deploy,
    )
    assessment = contract.get_assessment(
        assessment_id
    )
    binding_key = assessment[
        "binding_key"
    ]

    direct_vm.warp(DEADLINE_ISO)
    direct_vm.sender = _address(
        "agentseal-a5-expiry-outsider"
    )

    contract.expire_assessment(
        assessment_id
    )

    final = contract.get_assessment(
        assessment_id
    )

    assert final["status"] == "EXPIRED"
    assert (
        contract.get_live_assessment_id(
            binding_key
        )
        == 0
    )
