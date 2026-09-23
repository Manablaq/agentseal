import ast
import hashlib
import json
import os
from pathlib import Path

import pytest


CONTRACT = os.environ["AGENTSEAL_CONTRACT"]

NOW_ISO = "2026-09-21T12:00:00Z"
NOW = 1789992000
DAY = 86_400
PROFILE = "b" * 64
MANIFEST_DIGEST = "a" * 64
ENDPOINT = "https://agent.example.com/evaluate"

POLICY_ID = "policy-v1"
CAPABILITY_ID = "research"
MANIFEST_ID = "manifest-v1"
MANIFEST_AUTHORITY = "AgentSeal Test Authority"


def _create_policy(contract):
    contract.create_policy(
        POLICY_ID,
        CAPABILITY_ID,
        1,
        "Return correct structured research results.",
        "https://evidence.example.com/manifest.json",
        MANIFEST_ID,
        MANIFEST_AUTHORITY,
        MANIFEST_DIGEST,
        NOW + (10 * DAY),
        3600,
    )


def _ready(direct_vm, direct_deploy):
    direct_vm.warp(NOW_ISO)
    contract = direct_deploy(CONTRACT)
    _create_policy(contract)
    assessment_id = contract.create_assessment(
        PROFILE,
        ENDPOINT,
        POLICY_ID,
        1,
        900,
    )
    policy = contract.policies[
        contract._policy_key(POLICY_ID, 1)
    ]
    assessment = contract.assessments[
        contract._assessment_key(assessment_id)
    ]
    return contract, policy, assessment


def _case(index, *, task=None, reference=None, case_id=None):
    return {
        "case_id": case_id or f"case-{index}",
        "task": task if task is not None else f"task {index}",
        "reference": (
            reference
            if reference is not None
            else f"reference {index}"
        ),
    }


def _manifest(count=4):
    return {
        "schema": "agentseal-manifest-v1",
        "manifest_id": MANIFEST_ID,
        "authority": MANIFEST_AUTHORITY,
        "capability_id": CAPABILITY_ID,
        "policy_id": POLICY_ID,
        "policy_version": 1,
        "cases": [_case(i) for i in range(count)],
    }


def _selected_cases():
    return [_case(0), _case(1)]


def _response(assessment, evaluation_id, *, results=None):
    if results is None:
        results = [
            {"case_id": "case-0", "output": "output a"},
            {"case_id": "case-1", "output": "output b"},
        ]
    return {
        "protocol": "agentseal-evaluation-v1",
        "evaluation_id": evaluation_id,
        "agent_wallet": assessment.subject_wallet.as_hex.lower(),
        "profile_digest": assessment.profile_digest,
        "capability_id": assessment.capability_id,
        "policy_id": assessment.policy_id,
        "policy_version": int(assessment.policy_version),
        "manifest_id": assessment.manifest_id,
        "results": results,
    }


def _response_bytes(assessment, evaluation_id, **kwargs):
    return json.dumps(
        _response(assessment, evaluation_id, **kwargs),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _evaluation_id(contract, assessment, attempt=1):
    return contract._evaluation_id(
        int(assessment.assessment_id),
        attempt,
        4221,
        contract.owner,
    )


def _source_constants():
    source = Path(CONTRACT).read_text(encoding="utf-8")
    tree = ast.parse(source)
    result = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id in {
            "MAX_MANIFEST_RESPONSE_BYTES",
            "MIN_MANIFEST_CASE_COUNT",
            "MAX_MANIFEST_CASE_COUNT",
            "MAX_CASE_TASK_BYTES",
            "MAX_CASE_REFERENCE_BYTES",
            "MAX_ENDPOINT_REQUEST_BYTES",
            "MAX_ENDPOINT_RESPONSE_BYTES",
            "MAX_RESULT_OUTPUT_BYTES",
            "MAX_EVALUATOR_PROMPT_BYTES",
            "MANIFEST_SCHEMA",
            "EVALUATION_PROTOCOL",
            "ALLOWED_EVALUATOR_VERDICTS",
        }:
            result[target.id] = ast.literal_eval(node.value)
    return result


def test_frozen_protocol_constants_exact():
    assert _source_constants() == {
        "MAX_MANIFEST_RESPONSE_BYTES": 65_536,
        "MIN_MANIFEST_CASE_COUNT": 4,
        "MAX_MANIFEST_CASE_COUNT": 32,
        "MAX_CASE_TASK_BYTES": 2_048,
        "MAX_CASE_REFERENCE_BYTES": 8_192,
        "MAX_ENDPOINT_REQUEST_BYTES": 65_536,
        "MAX_ENDPOINT_RESPONSE_BYTES": 65_536,
        "MAX_RESULT_OUTPUT_BYTES": 8_192,
        "MAX_EVALUATOR_PROMPT_BYTES": 131_072,
        "MANIFEST_SCHEMA": "agentseal-manifest-v1",
        "EVALUATION_PROTOCOL": "agentseal-evaluation-v1",
        "ALLOWED_EVALUATOR_VERDICTS": (
            "PASS",
            "FAIL",
            "INCONCLUSIVE",
        ),
    }


def test_canonical_json_sorted_compact_ascii(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert (
        contract._canonical_json(
            {"z": "é", "a": 1, "m": [2, 3]}
        )
        == '{"a":1,"m":[2,3],"z":"\\u00e9"}'
    )


def test_utf8_size_counts_encoded_bytes(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._utf8_size("é") == 2
    assert contract._utf8_size("abc") == 3


def test_strict_json_accepts_valid_object(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._strict_json_loads(
        b'{"a":1,"b":{"c":2}}'
    ) == {"a": 1, "b": {"c": 2}}


def test_strict_json_rejects_non_bytes(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_BYTES_REQUIRED"):
        contract._strict_json_loads('{"a":1}')


def test_strict_json_rejects_invalid_utf8(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_UTF8"):
        contract._strict_json_loads(b'{"a":"\xff"}')


def test_strict_json_rejects_malformed_json(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_PARSE"):
        contract._strict_json_loads(b'{"a":')


def test_strict_json_rejects_top_level_duplicate_key(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_DUPLICATE_KEY"):
        contract._strict_json_loads(b'{"a":1,"a":2}')


def test_strict_json_rejects_nested_duplicate_key(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_DUPLICATE_KEY"):
        contract._strict_json_loads(
            b'{"outer":{"x":1,"x":2}}'
        )


def test_identifier_rules_accept_frozen_charset(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._identifier_is_valid(
        "Abc-XYZ_019"
    ) is True


def test_identifier_rules_reject_wrong_type(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._identifier_is_valid(123) is False


def test_identifier_rules_reject_empty(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._identifier_is_valid("") is False


def test_identifier_rules_reject_over_64(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._identifier_is_valid("a" * 65) is False


def test_identifier_rules_reject_other_character(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._identifier_is_valid("case.1") is False


def test_manifest_accepts_exact_four_cases(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._validate_manifest_payload(
        _manifest(4), policy
    ) == _manifest(4)["cases"]


def test_manifest_accepts_exact_32_cases(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert len(
        contract._validate_manifest_payload(
            _manifest(32), policy
        )
    ) == 32


def test_manifest_rejects_non_object(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("MANIFEST_TOP_LEVEL"):
        contract._validate_manifest_payload([], policy)


def test_manifest_rejects_missing_key(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    del payload["authority"]
    with direct_vm.expect_revert("MANIFEST_KEYS"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_extra_key(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["extra"] = 1
    with direct_vm.expect_revert("MANIFEST_KEYS"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_schema_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["schema"] = "other"
    with direct_vm.expect_revert("MANIFEST_SCHEMA"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_manifest_id_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["manifest_id"] = "other"
    with direct_vm.expect_revert("MANIFEST_ID"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_authority_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["authority"] = "Other Authority"
    with direct_vm.expect_revert("MANIFEST_AUTHORITY"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_capability_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["capability_id"] = "other"
    with direct_vm.expect_revert("MANIFEST_CAPABILITY"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_policy_id_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["policy_id"] = "other"
    with direct_vm.expect_revert("MANIFEST_POLICY_ID"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_policy_version_mismatch(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["policy_version"] = 2
    with direct_vm.expect_revert(
        "MANIFEST_POLICY_VERSION"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_policy_version_bool(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["policy_version"] = True
    with direct_vm.expect_revert(
        "MANIFEST_POLICY_VERSION"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_cases_wrong_type(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"] = {}
    with direct_vm.expect_revert("MANIFEST_CASES_TYPE"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_three_cases(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("MANIFEST_CASE_COUNT"):
        contract._validate_manifest_payload(
            _manifest(3), policy
        )


def test_manifest_rejects_33_cases(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("MANIFEST_CASE_COUNT"):
        contract._validate_manifest_payload(
            _manifest(33), policy
        )


def test_manifest_rejects_case_wrong_type(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0] = "bad"
    with direct_vm.expect_revert("MANIFEST_CASE_TYPE"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_case_missing_key(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    del payload["cases"][0]["reference"]
    with direct_vm.expect_revert("MANIFEST_CASE_KEYS"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_case_extra_key(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["extra"] = 1
    with direct_vm.expect_revert("MANIFEST_CASE_KEYS"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_invalid_case_id(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["case_id"] = "case.0"
    with direct_vm.expect_revert("MANIFEST_CASE_ID"):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_duplicate_case_id(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][1]["case_id"] = (
        payload["cases"][0]["case_id"]
    )
    with direct_vm.expect_revert(
        "MANIFEST_DUPLICATE_CASE_ID"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_task_wrong_type(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["task"] = 1
    with direct_vm.expect_revert(
        "MANIFEST_CASE_TASK_TYPE"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_empty_task(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["task"] = ""
    with direct_vm.expect_revert(
        "MANIFEST_CASE_TASK_SIZE"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_accepts_task_exact_2048_utf8_bytes(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["task"] = "é" * 1024
    result = contract._validate_manifest_payload(
        payload, policy
    )
    assert result[0]["task"] == "é" * 1024


def test_manifest_rejects_task_2049_utf8_bytes(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["task"] = (
        ("é" * 1024) + "a"
    )
    with direct_vm.expect_revert(
        "MANIFEST_CASE_TASK_SIZE"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_rejects_reference_wrong_type(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["reference"] = 1
    with direct_vm.expect_revert(
        "MANIFEST_CASE_REFERENCE_TYPE"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_manifest_accepts_reference_exact_8192_utf8_bytes(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["reference"] = "é" * 4096
    result = contract._validate_manifest_payload(
        payload, policy
    )
    assert result[0]["reference"] == "é" * 4096


def test_manifest_rejects_reference_8193_utf8_bytes(
    direct_vm, direct_deploy
):
    contract, policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    payload = _manifest()
    payload["cases"][0]["reference"] = (
        ("é" * 4096) + "a"
    )
    with direct_vm.expect_revert(
        "MANIFEST_CASE_REFERENCE_SIZE"
    ):
        contract._validate_manifest_payload(payload, policy)


def test_selection_material_exact_canonical_fields(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    material = contract._selection_material(
        assessment, 4221, contract.owner
    )
    assert material == json.dumps(
        {
            "assessment_id": 1,
            "capability_id": CAPABILITY_ID,
            "chain_id": 4221,
            "contract_address": contract.owner.as_hex.lower(),
            "endpoint": ENDPOINT,
            "manifest_digest": MANIFEST_DIGEST,
            "manifest_id": MANIFEST_ID,
            "policy_id": POLICY_ID,
            "policy_version": 1,
            "profile_digest": PROFILE,
            "subject_wallet": (
                assessment.subject_wallet.as_hex.lower()
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def test_selection_material_domain_separates_chain(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    a = contract._selection_material(
        assessment, 4221, contract.owner
    )
    b = contract._selection_material(
        assessment, 4222, contract.owner
    )
    assert a != b


def test_selection_algorithm_matches_independent_reference(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    material = contract._selection_material(
        assessment, 4221, contract.owner
    )
    seed = hashlib.sha256(
        material.encode("utf-8")
    ).digest()
    for case_count in (4, 5, 16, 32):
        expected_a = int.from_bytes(
            seed[0:8], "big"
        ) % case_count
        expected_b = int.from_bytes(
            seed[8:16], "big"
        ) % (case_count - 1)
        if expected_b >= expected_a:
            expected_b += 1
        assert contract._select_case_indexes(
            material, case_count
        ) == (expected_a, expected_b)


def test_selection_indexes_are_distinct_across_bounds(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    material = contract._selection_material(
        assessment, 4221, contract.owner
    )
    for case_count in range(4, 33):
        case_a, case_b = contract._select_case_indexes(
            material, case_count
        )
        assert 0 <= case_a < case_count
        assert 0 <= case_b < case_count
        assert case_a != case_b


def test_selection_rejects_case_count_below_four(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("SELECTION_CASE_COUNT"):
        contract._select_case_indexes("material", 3)


def test_selection_rejects_case_count_above_32(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("SELECTION_CASE_COUNT"):
        contract._select_case_indexes("material", 33)


def test_evaluation_id_exact_format(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    value = contract._evaluation_id(
        1, 2, 4221, contract.owner
    )
    assert value == (
        "agentseal-v1:4221:"
        + contract.owner.as_hex.lower()
        + ":1:2"
    )


def test_evaluation_id_domain_separates_chain(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._evaluation_id(
        1, 1, 4221, contract.owner
    ) != contract._evaluation_id(
        1, 1, 4222, contract.owner
    )


def test_evaluation_id_rejects_zero_assessment_id(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "EVALUATION_ASSESSMENT_ID"
    ):
        contract._evaluation_id(
            0, 1, 4221, contract.owner
        )


def test_evaluation_id_rejects_zero_attempt(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "EVALUATION_ATTEMPT_NUMBER"
    ):
        contract._evaluation_id(
            1, 0, 4221, contract.owner
        )


def test_evaluation_id_rejects_attempt_above_three(
    direct_vm, direct_deploy
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "EVALUATION_ATTEMPT_NUMBER"
    ):
        contract._evaluation_id(
            1, 4, 4221, contract.owner
        )


def test_endpoint_request_exact_canonical_payload(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    selected = _selected_cases()
    raw = contract._build_endpoint_request(
        assessment, evaluation_id, selected
    )
    assert isinstance(raw, bytes)
    assert raw == json.dumps(
        {
            "agent_wallet": (
                assessment.subject_wallet.as_hex.lower()
            ),
            "capability_id": CAPABILITY_ID,
            "cases": selected,
            "evaluation_id": evaluation_id,
            "manifest_digest": MANIFEST_DIGEST,
            "manifest_id": MANIFEST_ID,
            "policy_id": POLICY_ID,
            "policy_version": 1,
            "profile_digest": PROFILE,
            "protocol": "agentseal-evaluation-v1",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def test_endpoint_request_rejects_wrong_case_count(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_COUNT"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0)],
        )


def test_endpoint_request_rejects_case_wrong_type(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_TYPE"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0), "bad"],
        )


def test_endpoint_request_rejects_case_key_shape(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    bad = _case(1)
    bad["extra"] = 1
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_KEYS"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0), bad],
        )


def test_endpoint_request_rejects_invalid_case_id(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    bad = _case(1, case_id="bad.case")
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_ID"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0), bad],
        )


def test_endpoint_request_rejects_non_string_task(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    bad = _case(1)
    bad["task"] = 1
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_TASK"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0), bad],
        )


def test_endpoint_request_rejects_non_string_reference(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    bad = _case(1)
    bad["reference"] = 1
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_CASE_REFERENCE"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            [_case(0), bad],
        )


def test_endpoint_request_rejects_over_65536_bytes(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    selected = [
        _case(0, reference="x" * 40_000),
        _case(1, reference="y" * 40_000),
    ]
    with direct_vm.expect_revert(
        "ENDPOINT_REQUEST_TOO_LARGE"
    ):
        contract._build_endpoint_request(
            assessment,
            _evaluation_id(contract, assessment),
            selected,
        )


def test_endpoint_response_accepts_exact_binding(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    assert contract._validate_endpoint_response(
        _response_bytes(assessment, evaluation_id),
        assessment,
        evaluation_id,
        _selected_cases(),
    ) == [
        {"case_id": "case-0", "output": "output a"},
        {"case_id": "case-1", "output": "output b"},
    ]


def test_endpoint_response_empty_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_EMPTY"
    ):
        contract._validate_endpoint_response(
            b"",
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_exact_65536_reaches_json_gate(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_PARSE"):
        contract._validate_endpoint_response(
            b" " * 65_536,
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_65537_rejected_by_size(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_TOO_LARGE"
    ):
        contract._validate_endpoint_response(
            b" " * 65_537,
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_invalid_utf8_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_UTF8"):
        contract._validate_endpoint_response(
            b'{"x":"\xff"}',
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_malformed_json_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert("JSON_PARSE"):
        contract._validate_endpoint_response(
            b'{"x":',
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_duplicate_key_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "JSON_DUPLICATE_KEY"
    ):
        contract._validate_endpoint_response(
            b'{"x":1,"x":2}',
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_non_object_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_TOP_LEVEL"
    ):
        contract._validate_endpoint_response(
            b"[]",
            assessment,
            _evaluation_id(contract, assessment),
            _selected_cases(),
        )


def test_endpoint_response_missing_key_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    del payload["manifest_id"]
    raw = json.dumps(payload).encode("utf-8")
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_KEYS"
    ):
        contract._validate_endpoint_response(
            raw,
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_extra_key_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["extra"] = 1
    raw = json.dumps(payload).encode("utf-8")
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_KEYS"
    ):
        contract._validate_endpoint_response(
            raw,
            assessment,
            evaluation_id,
            _selected_cases(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol", "other"),
        ("evaluation_id", "other"),
        ("agent_wallet", "0x" + ("0" * 40)),
        ("profile_digest", "c" * 64),
        ("capability_id", "other"),
        ("policy_id", "other"),
        ("manifest_id", "other"),
    ],
)
def test_endpoint_response_string_binding_mismatch_rejected(
    direct_vm,
    direct_deploy,
    field,
    value,
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload[field] = value
    raw = json.dumps(payload).encode("utf-8")
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_BINDING"
    ):
        contract._validate_endpoint_response(
            raw,
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_policy_version_mismatch_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["policy_version"] = 2
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_POLICY_VERSION"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_policy_version_bool_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["policy_version"] = True
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_POLICY_VERSION"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_selected_case_count_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_EXPECTED_CASE_COUNT"
    ):
        contract._validate_endpoint_response(
            _response_bytes(assessment, evaluation_id),
            assessment,
            evaluation_id,
            [_case(0)],
        )


def test_endpoint_response_results_wrong_type_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"] = {}
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_RESULTS_COUNT"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_results_wrong_count_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(
        assessment,
        evaluation_id,
        results=[
            {"case_id": "case-0", "output": "a"}
        ],
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_RESULTS_COUNT"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_result_wrong_type_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(
        assessment,
        evaluation_id,
        results=[
            "bad",
            {"case_id": "case-1", "output": "b"},
        ],
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_RESULT_TYPE"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_result_key_shape_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][0]["extra"] = 1
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_RESULT_KEYS"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_case_a_substitution_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][0]["case_id"] = "case-2"
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_CASE_ID"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_case_b_substitution_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][1]["case_id"] = "case-2"
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_CASE_ID"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_output_wrong_type_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][0]["output"] = 1
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_OUTPUT_TYPE"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


def test_endpoint_response_output_exact_8192_utf8_bytes_allowed(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][0]["output"] = "é" * 4096
    result = contract._validate_endpoint_response(
        json.dumps(payload).encode("utf-8"),
        assessment,
        evaluation_id,
        _selected_cases(),
    )
    assert result[0]["output"] == "é" * 4096


def test_endpoint_response_output_8193_utf8_bytes_rejected(
    direct_vm, direct_deploy
):
    contract, _policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    payload = _response(assessment, evaluation_id)
    payload["results"][0]["output"] = (
        ("é" * 4096) + "a"
    )
    with direct_vm.expect_revert(
        "ENDPOINT_RESPONSE_OUTPUT_SIZE"
    ):
        contract._validate_endpoint_response(
            json.dumps(payload).encode("utf-8"),
            assessment,
            evaluation_id,
            _selected_cases(),
        )


@pytest.mark.parametrize(
    "verdict",
    ["PASS", "FAIL", "INCONCLUSIVE"],
)
def test_evaluator_normalizer_accepts_exact_verdicts(
    direct_vm,
    direct_deploy,
    verdict,
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._normalize_evaluator_result(
        {"verdict": verdict}
    ) == verdict


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"verdict": "UNKNOWN"},
        {"verdict": 1},
        {"verdict": "PASS", "extra": 1},
    ],
)
def test_evaluator_normalizer_collapses_invalid_to_inconclusive(
    direct_vm,
    direct_deploy,
    payload,
):
    contract, _policy, _assessment = _ready(
        direct_vm, direct_deploy
    )
    assert contract._normalize_evaluator_result(
        payload
    ) == "INCONCLUSIVE"


def test_helpers_do_not_mutate_assessment_state(
    direct_vm, direct_deploy
):
    contract, policy, assessment = _ready(
        direct_vm, direct_deploy
    )
    before = contract.get_assessment(1)
    manifest = _manifest()
    cases = contract._validate_manifest_payload(
        manifest, policy
    )
    material = contract._selection_material(
        assessment, 4221, contract.owner
    )
    case_a, case_b = contract._select_case_indexes(
        material, len(cases)
    )
    selected = [cases[case_a], cases[case_b]]
    evaluation_id = _evaluation_id(
        contract, assessment
    )
    contract._build_endpoint_request(
        assessment, evaluation_id, selected
    )
    response = _response(
        assessment,
        evaluation_id,
        results=[
            {
                "case_id": selected[0]["case_id"],
                "output": "a",
            },
            {
                "case_id": selected[1]["case_id"],
                "output": "b",
            },
        ],
    )
    contract._validate_endpoint_response(
        json.dumps(response).encode("utf-8"),
        assessment,
        evaluation_id,
        selected,
    )
    assert contract._normalize_evaluator_result(
        {"verdict": "PASS"}
    ) == "PASS"
    assert contract.get_assessment(1) == before
