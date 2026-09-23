import ast
import datetime
import hashlib
import json
import os

import pytest


CONTRACT = os.environ["AGENTSEAL_CONTRACT"]

NOW_ISO = "2026-09-21T12:00:00Z"
NOW = 1789992000
DAY = 86_400
CHAIN_ID = 987654321
CERT_TTL = 900

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

CERTIFICATE_HISTORY_FIELDS = [
    "certificate_id",
    "assessment_id",
    "subject_wallet",
    "profile_digest",
    "endpoint",
    "capability_id",
    "policy_id",
    "policy_version",
    "manifest_id",
    "manifest_digest",
    "case_a_id",
    "case_b_id",
    "binding_key",
    "issued_at",
    "expires_at",
]


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


def _normalize_address(value):
    if hasattr(value, "as_hex"):
        return str(value.as_hex).lower()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "0x" + bytes(value).hex()
    return str(value).lower()


def _iso(timestamp):
    return (
        datetime.datetime.fromtimestamp(
            int(timestamp),
            tz=datetime.timezone.utc,
        )
        .isoformat()
        .replace("+00:00", "Z")
    )


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


def _install_handlers(
    direct_vm,
    manifest_raw,
    *,
    verdict,
    events=None,
):
    if events is None:
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
            request_payload = json.loads(
                bytes(
                    event["body"]
                ).decode("utf-8")
            )

            response_payload = {
                "protocol": "agentseal-evaluation-v1",
                "evaluation_id": request_payload[
                    "evaluation_id"
                ],
                "agent_wallet": request_payload[
                    "agent_wallet"
                ],
                "profile_digest": request_payload[
                    "profile_digest"
                ],
                "capability_id": request_payload[
                    "capability_id"
                ],
                "policy_id": request_payload[
                    "policy_id"
                ],
                "policy_version": request_payload[
                    "policy_version"
                ],
                "manifest_id": request_payload[
                    "manifest_id"
                ],
                "results": [
                    {
                        "case_id": request_payload[
                            "cases"
                        ][0]["case_id"],
                        "output": "step4 output a",
                    },
                    {
                        "case_id": request_payload[
                            "cases"
                        ][1]["case_id"],
                        "output": "step4 output b",
                    },
                ],
            }

            return _web_response(
                200,
                _canonical_bytes(
                    response_payload
                ),
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
                "verdict": verdict,
            }
        }

    direct_vm._live_web_handler = (
        web_handler
    )
    direct_vm._live_llm_handler = (
        llm_handler
    )

    return events


def _evaluate_assessment_pass(
    direct_vm,
    contract,
    assessment_id,
    manifest_raw,
):
    _install_handlers(
        direct_vm,
        manifest_raw,
        verdict="PASS",
    )
    direct_vm.clear_validators()
    contract.evaluate_assessment(
        assessment_id
    )
    assert direct_vm.run_validator() is True


def _issue_certificate(
    direct_vm,
    contract,
    manifest_raw,
    *,
    subject,
    profile=PROFILE_A,
    endpoint=ENDPOINT,
    requested_ttl=CERT_TTL,
):
    direct_vm.sender = subject
    certificate_id = int(
        contract.create_assessment(
            profile,
            endpoint,
            POLICY_ID,
            1,
            requested_ttl,
        )
    )
    _evaluate_assessment_pass(
        direct_vm,
        contract,
        certificate_id,
        manifest_raw,
    )
    return certificate_id


def _ready_active(
    direct_vm,
    direct_deploy,
    *,
    seed,
    profile=PROFILE_A,
    endpoint=ENDPOINT,
    requested_ttl=CERT_TTL,
    max_ttl=3600,
    valid_until=None,
):
    direct_vm.warp(NOW_ISO)
    direct_vm._chain_id = CHAIN_ID

    owner = _address(seed + "-owner")
    subject = _address(seed + "-subject")
    challenger = _address(seed + "-challenger")
    evaluator = _address(seed + "-evaluator")
    outsider = _address(seed + "-outsider")

    direct_vm.sender = owner
    contract = direct_deploy(CONTRACT)

    manifest_raw = _canonical_bytes(
        _manifest_payload()
    )

    _create_policy(
        contract,
        manifest_raw,
        valid_until=valid_until,
        max_ttl=max_ttl,
    )

    certificate_id = _issue_certificate(
        direct_vm,
        contract,
        manifest_raw,
        subject=subject,
        profile=profile,
        endpoint=endpoint,
        requested_ttl=requested_ttl,
    )

    return {
        "contract": contract,
        "manifest_raw": manifest_raw,
        "certificate_id": certificate_id,
        "owner": owner,
        "subject": subject,
        "challenger": challenger,
        "evaluator": evaluator,
        "outsider": outsider,
    }


def _open_challenge(
    direct_vm,
    fixture,
    *,
    caller=None,
):
    if caller is None:
        caller = fixture["challenger"]
    direct_vm.sender = caller
    return int(
        fixture["contract"].open_challenge(
            fixture["certificate_id"]
        )
    )


def _evaluate_challenge(
    direct_vm,
    fixture,
    challenge_id,
    verdict,
    *,
    caller=None,
):
    if caller is None:
        caller = fixture["evaluator"]

    direct_vm.sender = caller
    events = _install_handlers(
        direct_vm,
        fixture["manifest_raw"],
        verdict=verdict,
    )
    direct_vm.clear_validators()
    fixture["contract"].evaluate_challenge(
        challenge_id
    )
    assert direct_vm.run_validator() is True
    return events


def _certificate_history(contract, certificate_id):
    certificate = dict(
        contract.get_certificate(
            certificate_id
        )
    )
    return {
        key: certificate[key]
        for key in CERTIFICATE_HISTORY_FIELDS
    }


def _contract_source():
    return open(
        CONTRACT,
        "r",
        encoding="utf-8",
    ).read()


def _contract_class():
    source = _contract_source()
    tree = ast.parse(source)
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "AgentSeal"
    )


def _classes():
    tree = ast.parse(
        _contract_source()
    )
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }


def _methods():
    cls = _contract_class()
    return {
        node.name: node
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
    }


def _method_source(name):
    source = _contract_source()
    methods = _methods()
    return (
        ast.get_source_segment(
            source,
            methods[name],
        )
        or ""
    )


def _public_surface():
    methods = _methods()
    views = []
    writes = []

    for node in methods.values():
        decorators = {
            ast.unparse(decorator)
            for decorator in node.decorator_list
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


def _rooted_in_self(target):
    node = target
    while isinstance(
        node,
        (ast.Attribute, ast.Subscript),
    ):
        node = node.value
    return (
        isinstance(node, ast.Name)
        and node.id == "self"
    )


def _method_has_self_write(method):
    for node in ast.walk(method):
        if isinstance(node, ast.Assign):
            if any(
                _rooted_in_self(target)
                for target in node.targets
            ):
                return True
        if isinstance(node, ast.AnnAssign):
            if _rooted_in_self(node.target):
                return True
        if isinstance(node, ast.AugAssign):
            if _rooted_in_self(node.target):
                return True
    return False


def _payload_ref(node):
    if not isinstance(node, ast.Subscript):
        return None
    if not isinstance(node.value, ast.Name):
        return None
    key = node.slice
    if not (
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
    ):
        return None
    return (
        node.value.id,
        key.value,
    )


def _payload_equality_pairs(method):
    pairs = set()
    for node in ast.walk(method):
        if not (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
        ):
            continue
        left = _payload_ref(node.left)
        right = _payload_ref(
            node.comparators[0]
        )
        if left and right:
            pairs.add((left, right))
    return pairs


# DIRECT_REVOKE_AUTH_AND_TRANSITION = 10


@pytest.mark.parametrize(
    "scenario",
    [
        "subject_success",
        "owner_success",
        "outsider_rejected",
        "missing_rejected",
        "expired_rejected",
        "second_revoke_rejected",
        "corrupt_active_index_rejected",
        "subject_cancels_pending_challenge",
        "owner_cancels_pending_challenge",
        "static_no_nondet",
    ],
)
def test_s4_direct_revoke_auth_and_transition(
    direct_vm,
    direct_deploy,
    scenario,
):
    if scenario == "static_no_nondet":
        source = _method_source(
            "revoke_certificate"
        )
        assert "gl.nondet." not in source
        assert "run_nondet" not in source
        assert "strict_eq" not in source
        assert source.count(
            "self._record_certificate_revocation("
        ) == 1
        return

    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-direct-" + scenario,
    )
    contract = fixture["contract"]
    certificate_id = fixture[
        "certificate_id"
    ]

    if scenario == "outsider_rejected":
        direct_vm.sender = fixture["outsider"]
        with direct_vm.expect_revert(
            "REVOCATION_NOT_AUTHORIZED"
        ):
            contract.revoke_certificate(
                certificate_id
            )
        assert contract.get_certificate(
            certificate_id
        )["status"] == "ACTIVE"
        return

    if scenario == "missing_rejected":
        direct_vm.sender = fixture["owner"]
        with direct_vm.expect_revert(
            "CERTIFICATE_NOT_FOUND"
        ):
            contract.revoke_certificate(999999)
        return

    if scenario == "expired_rejected":
        expires_at = contract.get_certificate(
            certificate_id
        )["expires_at"]
        direct_vm.warp(_iso(expires_at))
        direct_vm.sender = fixture["subject"]
        with direct_vm.expect_revert(
            "CERTIFICATE_EXPIRED"
        ):
            contract.revoke_certificate(
                certificate_id
            )
        return

    if scenario == "corrupt_active_index_rejected":
        binding = contract.get_certificate(
            certificate_id
        )["binding_key"]
        contract.active_certificate_by_binding[
            binding
        ] = 0
        direct_vm.sender = fixture["subject"]
        with direct_vm.expect_revert(
            "ACTIVE_CERTIFICATE_INDEX_CORRUPT"
        ):
            contract.revoke_certificate(
                certificate_id
            )
        return

    challenge_id = 0
    if scenario in {
        "subject_cancels_pending_challenge",
        "owner_cancels_pending_challenge",
    }:
        challenge_id = _open_challenge(
            direct_vm,
            fixture,
        )

    if scenario in {
        "owner_success",
        "owner_cancels_pending_challenge",
    }:
        direct_vm.sender = fixture["owner"]
        expected_source = "OWNER_AUTHORITY_REVOKE"
        expected_initiator = fixture["owner"]
    else:
        direct_vm.sender = fixture["subject"]
        expected_source = "SUBJECT_SELF_REVOKE"
        expected_initiator = fixture["subject"]

    contract.revoke_certificate(
        certificate_id
    )

    certificate = contract.get_certificate(
        certificate_id
    )
    revocation = contract.get_revocation(
        certificate_id
    )

    assert certificate["status"] == "REVOKED"
    assert revocation["source"] == expected_source
    assert _normalize_address(
        revocation["initiator"]
    ) == _normalize_address(
        expected_initiator
    )

    if scenario == "second_revoke_rejected":
        with direct_vm.expect_revert(
            "CERTIFICATE_NOT_ACTIVE"
        ):
            contract.revoke_certificate(
                certificate_id
            )
        return

    if challenge_id:
        challenge = contract.get_challenge(
            challenge_id
        )
        assert challenge["status"] == "CANCELLED"
        assert contract.get_open_challenge_id(
            certificate_id
        ) == 0
        assert revocation[
            "challenge_id"
        ] == challenge_id
    else:
        assert revocation["challenge_id"] == 0


# CHALLENGE_OPEN_NONCONSEQUENTIAL = 8


@pytest.mark.parametrize(
    "scenario",
    [
        "pending_snapshot_exact",
        "count_increment",
        "challenger_recorded",
        "certificate_unchanged",
        "active_index_preserved",
        "duplicate_pending_rejected",
        "missing_certificate_rejected",
        "expired_certificate_rejected",
    ],
)
def test_s4_challenge_open_nonconsequential(
    direct_vm,
    direct_deploy,
    scenario,
):
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-open-" + scenario,
    )
    contract = fixture["contract"]
    certificate_id = fixture[
        "certificate_id"
    ]

    if scenario == "missing_certificate_rejected":
        direct_vm.sender = fixture["outsider"]
        with direct_vm.expect_revert(
            "CERTIFICATE_NOT_FOUND"
        ):
            contract.open_challenge(999999)
        return

    if scenario == "expired_certificate_rejected":
        expires_at = contract.get_certificate(
            certificate_id
        )["expires_at"]
        direct_vm.warp(_iso(expires_at))
        direct_vm.sender = fixture["outsider"]
        with direct_vm.expect_revert(
            "CERTIFICATE_EXPIRED"
        ):
            contract.open_challenge(
                certificate_id
            )
        return

    before_certificate = dict(
        contract.get_certificate(
            certificate_id
        )
    )
    before_count = contract.get_challenge_count()

    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )
    challenge = contract.get_challenge(
        challenge_id
    )
    certificate = contract.get_certificate(
        certificate_id
    )

    if scenario == "pending_snapshot_exact":
        assert challenge["status"] == "PENDING"
        assert challenge["certificate_id"] == certificate_id
        assert challenge["binding_key"] == certificate["binding_key"]
        assert challenge["policy_id"] == certificate["policy_id"]
        assert challenge["policy_version"] == certificate["policy_version"]
        assert challenge["manifest_id"] == certificate["manifest_id"]
        assert challenge["manifest_digest"] == certificate["manifest_digest"]
        assert challenge["attempt_count"] == 0
        assert challenge["max_attempt_count"] == 3
        return

    if scenario == "count_increment":
        assert contract.get_challenge_count() == before_count + 1
        assert contract.challenge_exists(challenge_id) is True
        return

    if scenario == "challenger_recorded":
        assert _normalize_address(
            challenge["challenger"]
        ) == _normalize_address(
            fixture["challenger"]
        )
        return

    if scenario == "certificate_unchanged":
        assert certificate == before_certificate
        return

    if scenario == "active_index_preserved":
        assert contract.get_active_certificate_id(
            certificate["binding_key"]
        ) == certificate_id
        return

    if scenario == "duplicate_pending_rejected":
        direct_vm.sender = fixture["outsider"]
        with direct_vm.expect_revert(
            "OPEN_CHALLENGE_EXISTS"
        ):
            contract.open_challenge(
                certificate_id
            )
        assert contract.get_open_challenge_id(
            certificate_id
        ) == challenge_id
        return

    raise AssertionError(
        "unhandled challenge-open scenario"
    )


# CHALLENGE_SEMANTIC_BINDING = 12


@pytest.mark.parametrize(
    "scenario",
    [
        "selection_domain_exact",
        "evaluation_domain_exact",
        "selection_excludes_attempt",
        "evaluation_binds_attempt",
        "policy_disable_nonretroactive",
        "binds_binding_key",
        "binds_policy_id",
        "binds_policy_version",
        "binds_manifest_id",
        "binds_manifest_digest",
        "policy_snapshot_guard",
        "active_index_guard",
    ],
)
def test_s4_challenge_semantic_binding(
    direct_vm,
    direct_deploy,
    scenario,
):
    if scenario == "selection_domain_exact":
        source = _method_source(
            "_challenge_selection_material"
        )
        assert '"agentseal-challenge-selection-v1"' in source
        return

    if scenario == "evaluation_domain_exact":
        source = _method_source(
            "_challenge_evaluation_id"
        )
        assert '"agentseal-challenge-v1:"' in source
        return

    if scenario == "selection_excludes_attempt":
        source = _method_source(
            "_challenge_selection_material"
        )
        assert "attempt_number" not in source
        return

    if scenario == "evaluation_binds_attempt":
        source = _method_source(
            "_challenge_evaluation_id"
        )
        assert "attempt_number" in source
        assert "+ str(attempt_number)" in source
        return

    if scenario in {
        "binds_binding_key",
        "binds_policy_id",
        "binds_policy_version",
        "binds_manifest_id",
        "binds_manifest_digest",
        "policy_snapshot_guard",
        "active_index_guard",
    }:
        source = _method_source(
            "evaluate_challenge"
        )
        expected = {
            "binds_binding_key": "challenge.binding_key",
            "binds_policy_id": "challenge.policy_id",
            "binds_policy_version": "challenge.policy_version",
            "binds_manifest_id": "challenge.manifest_id",
            "binds_manifest_digest": "challenge.manifest_digest",
            "policy_snapshot_guard": "CHALLENGE_POLICY_SNAPSHOT_MISMATCH",
            "active_index_guard": "ACTIVE_CERTIFICATE_INDEX_CORRUPT",
        }[scenario]
        assert expected in source
        return

    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-binding-policy-disable",
    )
    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )
    direct_vm.sender = fixture["owner"]
    fixture["contract"].disable_policy(
        POLICY_ID,
        1,
    )
    _evaluate_challenge(
        direct_vm,
        fixture,
        challenge_id,
        "PASS",
    )
    assert fixture["contract"].get_challenge(
        challenge_id
    )["status"] == "REJECTED"


# CHALLENGE_CONSENSUS_EXACTNESS = 8


@pytest.mark.parametrize(
    "scenario",
    [
        "one_run_nondet",
        "validator_return_guard",
        "validator_reexecutes_worker",
        "verdict_exact",
        "case_a_exact",
        "case_b_exact",
        "no_fuzzy_fields",
        "storage_free",
    ],
)
def test_s4_challenge_consensus_exactness(
    scenario,
):
    methods = _methods()
    method = methods[
        "_challenge_evaluation_consensus"
    ]
    source = _method_source(
        "_challenge_evaluation_consensus"
    )

    if scenario == "one_run_nondet":
        assert source.count(
            "gl.vm.run_nondet_unsafe("
        ) == 1
        return

    if scenario == "validator_return_guard":
        assert "gl.vm.Return" in source
        assert "return False" in source
        return

    if scenario == "validator_reexecutes_worker":
        assert source.count(
            "self._challenge_evaluation_once("
        ) == 2
        return

    if scenario in {
        "verdict_exact",
        "case_a_exact",
        "case_b_exact",
    }:
        field = {
            "verdict_exact": "verdict",
            "case_a_exact": "case_a_id",
            "case_b_exact": "case_b_id",
        }[scenario]
        pairs = _payload_equality_pairs(
            method
        )
        assert (
            ("validator_payload", field),
            ("leader_payload", field),
        ) in pairs or (
            ("leader_payload", field),
            ("validator_payload", field),
        ) in pairs
        return

    if scenario == "no_fuzzy_fields":
        lowered = source.lower()
        for forbidden in [
            "tolerance",
            "confidence",
            "similar",
            "reasoning",
            "explanation",
        ]:
            assert forbidden not in lowered
        return

    assert _method_has_self_write(
        method
    ) is False


# CHALLENGE_VERDICT_TRANSITIONS = 10


@pytest.mark.parametrize(
    "scenario",
    [
        "pass_rejected",
        "pass_certificate_active",
        "pass_open_index_cleared",
        "pass_no_revocation",
        "fail_upheld",
        "fail_certificate_revoked",
        "fail_active_index_cleared",
        "fail_revocation_source",
        "fail_revocation_initiator",
        "terminal_case_ids_recorded",
    ],
)
def test_s4_challenge_verdict_transitions(
    direct_vm,
    direct_deploy,
    scenario,
):
    verdict = (
        "PASS"
        if scenario.startswith("pass_")
        else "FAIL"
    )
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-verdict-" + scenario,
    )
    contract = fixture["contract"]
    certificate_id = fixture[
        "certificate_id"
    ]
    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )
    _evaluate_challenge(
        direct_vm,
        fixture,
        challenge_id,
        verdict,
    )
    challenge = contract.get_challenge(
        challenge_id
    )
    certificate = contract.get_certificate(
        certificate_id
    )

    if scenario == "pass_rejected":
        assert challenge["status"] == "REJECTED"
    elif scenario == "pass_certificate_active":
        assert certificate["status"] == "ACTIVE"
    elif scenario == "pass_open_index_cleared":
        assert contract.get_open_challenge_id(
            certificate_id
        ) == 0
    elif scenario == "pass_no_revocation":
        assert contract._revocation_key(
            certificate_id
        ) not in contract.revocations
    elif scenario == "fail_upheld":
        assert challenge["status"] == "UPHELD"
    elif scenario == "fail_certificate_revoked":
        assert certificate["status"] == "REVOKED"
    elif scenario == "fail_active_index_cleared":
        assert contract.get_active_certificate_id(
            certificate["binding_key"]
        ) == 0
    elif scenario == "fail_revocation_source":
        assert contract.get_revocation(
            certificate_id
        )["source"] == "CHALLENGE_CONSENSUS"
    elif scenario == "fail_revocation_initiator":
        revocation = contract.get_revocation(
            certificate_id
        )
        assert _normalize_address(
            revocation["initiator"]
        ) == _normalize_address(
            fixture["evaluator"]
        )
    elif scenario == "terminal_case_ids_recorded":
        assert challenge["case_a_id"] != ""
        assert challenge["case_b_id"] != ""
        assert challenge["attempt_count"] == 1
        assert challenge["last_verdict"] == verdict
    else:
        raise AssertionError(
            "unhandled verdict scenario"
        )


# INCONCLUSIVE_AND_EXPIRY_RECOVERY = 8


@pytest.mark.parametrize(
    "scenario",
    [
        "inconclusive_one_pending",
        "inconclusive_two_pending",
        "inconclusive_three_final",
        "inconclusive_final_index_cleared",
        "inconclusive_certificate_unchanged",
        "expiry_view_effective_expired",
        "expire_materializes_and_preserves_certificate",
        "expired_challenge_index_clears",
    ],
)
def test_s4_inconclusive_and_expiry_recovery(
    direct_vm,
    direct_deploy,
    scenario,
):
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-recovery-" + scenario,
    )
    contract = fixture["contract"]
    certificate_id = fixture[
        "certificate_id"
    ]
    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )

    if scenario.startswith("inconclusive_"):
        before = dict(
            contract.get_certificate(
                certificate_id
            )
        )
        for attempt in [1, 2, 3]:
            _evaluate_challenge(
                direct_vm,
                fixture,
                challenge_id,
                "INCONCLUSIVE",
            )
            challenge = contract.get_challenge(
                challenge_id
            )
            if scenario == "inconclusive_one_pending" and attempt == 1:
                assert challenge["status"] == "PENDING"
                assert challenge["attempt_count"] == 1
                return
            if scenario == "inconclusive_two_pending" and attempt == 2:
                assert challenge["status"] == "PENDING"
                assert challenge["attempt_count"] == 2
                return
        challenge = contract.get_challenge(
            challenge_id
        )
        if scenario == "inconclusive_three_final":
            assert challenge["status"] == "INCONCLUSIVE_FINAL"
            assert challenge["attempt_count"] == 3
        elif scenario == "inconclusive_final_index_cleared":
            assert contract.get_open_challenge_id(
                certificate_id
            ) == 0
        elif scenario == "inconclusive_certificate_unchanged":
            assert dict(
                contract.get_certificate(
                    certificate_id
                )
            ) == before
            assert contract._revocation_key(
                certificate_id
            ) not in contract.revocations
        return

    challenge = contract.get_challenge(
        challenge_id
    )
    before_certificate = dict(
        contract.get_certificate(
            certificate_id
        )
    )
    direct_vm.warp(
        _iso(challenge["deadline"])
    )

    if scenario == "expiry_view_effective_expired":
        at_boundary = contract.get_challenge(
            challenge_id
        )
        assert at_boundary["status"] == "PENDING"
        assert at_boundary["effective_status"] == "EXPIRED"
        return

    contract.expire_challenge(
        challenge_id
    )
    after = contract.get_challenge(
        challenge_id
    )

    if scenario == "expire_materializes_and_preserves_certificate":
        assert after["status"] == "EXPIRED"
        after_certificate = dict(
            contract.get_certificate(
                certificate_id
            )
        )
        assert after_certificate["status"] == "ACTIVE"
        assert (
            after_certificate["effective_status"]
            == "EXPIRED"
        )
        for field, before_value in before_certificate.items():
            if field == "effective_status":
                continue
            assert (
                after_certificate[field]
                == before_value
            )
        assert contract._revocation_key(
            certificate_id
        ) not in contract.revocations
        return

    assert scenario == "expired_challenge_index_clears"
    assert contract.get_open_challenge_id(
        certificate_id
    ) == 0


# HISTORY_INDEX_INTEGRITY = 6


@pytest.mark.parametrize(
    "scenario",
    [
        "pass_preserves_certificate_history",
        "fail_preserves_nonstatus_certificate_history",
        "direct_revoke_preserves_nonstatus_certificate_history",
        "terminal_challenge_remains_queryable",
        "revocation_record_not_rewritten",
        "revoked_active_index_zero",
    ],
)
def test_s4_history_index_integrity(
    direct_vm,
    direct_deploy,
    scenario,
):
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-history-" + scenario,
    )
    contract = fixture["contract"]
    certificate_id = fixture[
        "certificate_id"
    ]
    before_history = _certificate_history(
        contract,
        certificate_id,
    )

    if scenario == "direct_revoke_preserves_nonstatus_certificate_history":
        direct_vm.sender = fixture["subject"]
        contract.revoke_certificate(
            certificate_id
        )
        assert _certificate_history(
            contract,
            certificate_id,
        ) == before_history
        return

    if scenario == "revocation_record_not_rewritten":
        direct_vm.sender = fixture["subject"]
        contract.revoke_certificate(
            certificate_id
        )
        before = dict(
            contract.get_revocation(
                certificate_id
            )
        )
        direct_vm.sender = fixture["owner"]
        with direct_vm.expect_revert(
            "CERTIFICATE_NOT_ACTIVE"
        ):
            contract.revoke_certificate(
                certificate_id
            )
        assert dict(
            contract.get_revocation(
                certificate_id
            )
        ) == before
        return

    if scenario == "revoked_active_index_zero":
        direct_vm.sender = fixture["subject"]
        contract.revoke_certificate(
            certificate_id
        )
        binding = contract.get_certificate(
            certificate_id
        )["binding_key"]
        assert contract.get_active_certificate_id(
            binding
        ) == 0
        return

    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )
    verdict = (
        "PASS"
        if scenario in {
            "pass_preserves_certificate_history",
            "terminal_challenge_remains_queryable",
        }
        else "FAIL"
    )
    _evaluate_challenge(
        direct_vm,
        fixture,
        challenge_id,
        verdict,
    )

    if scenario == "pass_preserves_certificate_history":
        assert _certificate_history(
            contract,
            certificate_id,
        ) == before_history
    elif scenario == "fail_preserves_nonstatus_certificate_history":
        assert _certificate_history(
            contract,
            certificate_id,
        ) == before_history
        assert contract.get_certificate(
            certificate_id
        )["status"] == "REVOKED"
    else:
        assert contract.challenge_exists(
            challenge_id
        ) is True
        terminal = contract.get_challenge(
            challenge_id
        )
        assert terminal["status"] == "REJECTED"


# REPLACEMENT_RECOVERY = 5


@pytest.mark.parametrize(
    "scenario",
    [
        "direct_revocation_allows_fresh_replacement",
        "challenge_revocation_allows_fresh_replacement",
        "old_revoked_certificate_remains_revoked",
        "old_revocation_record_remains_queryable",
        "replacement_becomes_active_index",
    ],
)
def test_s4_replacement_recovery(
    direct_vm,
    direct_deploy,
    scenario,
):
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-replacement-" + scenario,
    )
    contract = fixture["contract"]
    old_id = fixture["certificate_id"]
    old_binding = contract.get_certificate(
        old_id
    )["binding_key"]

    if scenario == "direct_revocation_allows_fresh_replacement":
        direct_vm.sender = fixture["subject"]
        contract.revoke_certificate(old_id)
    else:
        challenge_id = _open_challenge(
            direct_vm,
            fixture,
        )
        _evaluate_challenge(
            direct_vm,
            fixture,
            challenge_id,
            "FAIL",
        )

    replacement_id = _issue_certificate(
        direct_vm,
        contract,
        fixture["manifest_raw"],
        subject=fixture["subject"],
        profile=PROFILE_A,
        endpoint=ENDPOINT,
        requested_ttl=CERT_TTL,
    )

    if scenario in {
        "direct_revocation_allows_fresh_replacement",
        "challenge_revocation_allows_fresh_replacement",
    }:
        assert replacement_id != old_id
        assert contract.get_certificate(
            replacement_id
        )["status"] == "ACTIVE"
    elif scenario == "old_revoked_certificate_remains_revoked":
        assert contract.get_certificate(
            old_id
        )["status"] == "REVOKED"
    elif scenario == "old_revocation_record_remains_queryable":
        revocation = contract.get_revocation(
            old_id
        )
        assert revocation["certificate_id"] == old_id
    elif scenario == "replacement_becomes_active_index":
        assert contract.get_active_certificate_id(
            old_binding
        ) == replacement_id
        assert contract.get_certificate(
            replacement_id
        )["binding_key"] == old_binding
    else:
        raise AssertionError(
            "unhandled replacement scenario"
        )


# CROSS_CERTIFICATE_ISOLATION = 3


@pytest.mark.parametrize(
    "scenario",
    [
        "challenge_fail_a_leaves_b_active",
        "direct_revoke_a_leaves_b_index",
        "challenge_a_does_not_mutate_b_history",
    ],
)
def test_s4_cross_certificate_isolation(
    direct_vm,
    direct_deploy,
    scenario,
):
    fixture = _ready_active(
        direct_vm,
        direct_deploy,
        seed="s4-isolation-" + scenario,
        profile=PROFILE_A,
        endpoint=ENDPOINT,
    )
    contract = fixture["contract"]
    a_id = fixture["certificate_id"]
    subject_b = _address(
        "s4-isolation-b-" + scenario
    )
    b_id = _issue_certificate(
        direct_vm,
        contract,
        fixture["manifest_raw"],
        subject=subject_b,
        profile=PROFILE_B,
        endpoint=ENDPOINT_2,
        requested_ttl=CERT_TTL,
    )
    before_b = dict(
        contract.get_certificate(b_id)
    )
    b_binding = before_b["binding_key"]

    if scenario == "direct_revoke_a_leaves_b_index":
        direct_vm.sender = fixture["subject"]
        contract.revoke_certificate(a_id)
        assert contract.get_active_certificate_id(
            b_binding
        ) == b_id
        return

    challenge_id = _open_challenge(
        direct_vm,
        fixture,
    )
    _evaluate_challenge(
        direct_vm,
        fixture,
        challenge_id,
        "FAIL",
    )

    if scenario == "challenge_fail_a_leaves_b_active":
        assert contract.get_certificate(
            b_id
        )["status"] == "ACTIVE"
        assert contract.get_active_certificate_id(
            b_binding
        ) == b_id
    else:
        assert dict(
            contract.get_certificate(b_id)
        ) == before_b


# NONREGRESSION = 2


@pytest.mark.parametrize(
    "scenario",
    [
        "public_abi_and_storage_surface",
        "private_consensus_cores_storage_free",
    ],
)
def test_s4_nonregression(
    scenario,
):
    views, writes, methods = _public_surface()

    if scenario == "public_abi_and_storage_surface":
        assert len(views) == 16
        assert len(writes) == 10
        assert {
            "get_challenge_count",
            "challenge_exists",
            "get_challenge",
            "get_open_challenge_id",
            "get_revocation",
        }.issubset(set(views))
        assert {
            "open_challenge",
            "evaluate_challenge",
            "expire_challenge",
            "revoke_certificate",
        }.issubset(set(writes))
        classes = _classes()
        assert "ChallengeRecord" in classes
        assert "RevocationRecord" in classes
        source = _contract_source()
        for field in [
            "challenge_count",
            "challenges",
            "open_challenge_by_certificate",
            "revocations",
        ]:
            assert field in source
        return

    for name in [
        "_semantic_evaluation_once",
        "_semantic_evaluation_consensus",
        "_challenge_assessment_view",
        "_challenge_selection_material",
        "_challenge_evaluation_id",
        "_challenge_evaluation_once",
        "_challenge_evaluation_consensus",
    ]:
        assert name in methods
        assert _method_has_self_write(
            methods[name]
        ) is False
