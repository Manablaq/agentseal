# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import hashlib
import json
from dataclasses import dataclass
from genlayer import *
MAX_IDENTIFIER_LENGTH = 64
ASSESSMENT_MAX_ATTEMPTS = 3
MAX_MANIFEST_RESPONSE_BYTES = 65536
MIN_MANIFEST_CASE_COUNT = 4
MAX_MANIFEST_CASE_COUNT = 32
MAX_CASE_TASK_BYTES = 2048
MAX_CASE_REFERENCE_BYTES = 8192
MAX_ENDPOINT_REQUEST_BYTES = 65536
MAX_ENDPOINT_RESPONSE_BYTES = 65536
MAX_RESULT_OUTPUT_BYTES = 8192
MANIFEST_SCHEMA = 'agentseal-manifest-v1'
EVALUATION_PROTOCOL = 'agentseal-evaluation-v1'

@allow_storage
@dataclass
class PolicyRecord:
    policy_id: str
    capability_id: str
    version: u64
    criteria: str
    manifest_url: str
    manifest_id: str
    manifest_authority: str
    manifest_digest: str
    valid_until: u64
    max_certificate_ttl: u64
    active: bool
    created_at: u64

@allow_storage
@dataclass
class AssessmentRecord:
    assessment_id: u256
    subject_wallet: Address
    profile_digest: str
    endpoint: str
    capability_id: str
    policy_id: str
    policy_version: u64
    manifest_id: str
    manifest_digest: str
    requested_certificate_ttl: u64
    binding_key: str
    status: str
    created_at: u64
    deadline: u64
    attempt_count: u64
    max_attempt_count: u64
    last_verdict: str
    case_a_id: str
    case_b_id: str
    certificate_id: u256

class AgentSealAssessmentEvidenceEvaluator(gl.Contract):
    registry: Address
    semantic_judge: Address

    def __init__(self, registry: Address, semantic_judge: Address):
        if registry == Address(b'\x00' * 20) or semantic_judge == Address(b'\x00' * 20) or registry == semantic_judge:
            raise gl.vm.UserError('COMPONENT_ADDRESS_INVALID')
        self.registry = registry
        self.semantic_judge = semantic_judge

    @gl.public.view
    def get_components(self) -> dict:
        return {'registry': self.registry.as_hex, 'semantic_judge': self.semantic_judge.as_hex}

    def _decode_snapshot(self, snapshot_json: str) -> tuple[PolicyRecord, AssessmentRecord]:
        try:
            snapshot = json.loads(snapshot_json)
            if type(snapshot) is not dict or set(snapshot.keys()) != {'policy', 'assessment'}:
                raise gl.vm.UserError('shape')
            p = snapshot['policy']
            a = snapshot['assessment']
            policy = PolicyRecord(policy_id=p['policy_id'], capability_id=p['capability_id'], version=u64(int(p['version'])), criteria=p['criteria'], manifest_url=p['manifest_url'], manifest_id=p['manifest_id'], manifest_authority=p['manifest_authority'], manifest_digest=p['manifest_digest'], valid_until=u64(int(p['valid_until'])), max_certificate_ttl=u64(int(p['max_certificate_ttl'])), active=bool(p['active']), created_at=u64(int(p['created_at'])))
            assessment = AssessmentRecord(assessment_id=u256(int(a['assessment_id'])), subject_wallet=Address(a['subject_wallet']), profile_digest=a['profile_digest'], endpoint=a['endpoint'], capability_id=a['capability_id'], policy_id=a['policy_id'], policy_version=u64(int(a['policy_version'])), manifest_id=a['manifest_id'], manifest_digest=a['manifest_digest'], requested_certificate_ttl=u64(int(a['requested_certificate_ttl'])), binding_key=a['binding_key'], status=a['status'], created_at=u64(int(a['created_at'])), deadline=u64(int(a['deadline'])), attempt_count=u64(int(a['attempt_count'])), max_attempt_count=u64(int(a['max_attempt_count'])), last_verdict=a['last_verdict'], case_a_id=a['case_a_id'], case_b_id=a['case_b_id'], certificate_id=u256(int(a['certificate_id'])))
            return (policy, assessment)
        except Exception as exc:
            raise gl.vm.UserError('ASSESSMENT_SNAPSHOT_INVALID') from exc

    def _forced(self, verdict: str, case_a_id: str='', case_b_id: str='') -> dict:
        return {'mode': 'FORCED', 'forced_verdict': verdict, 'case_a_id': case_a_id, 'case_b_id': case_b_id, 'selected_cases': [], 'normalized_results': [], 'evaluation_id': ''}

    def _evidence_once(self, policy: PolicyRecord, assessment: AssessmentRecord, attempt_number: int, chain_id: int) -> dict:
        if policy.capability_id != assessment.capability_id or policy.policy_id != assessment.policy_id or int(policy.version) != int(assessment.policy_version) or (policy.manifest_id != assessment.manifest_id) or (policy.manifest_digest != assessment.manifest_digest):
            return self._forced('INCONCLUSIVE')
        try:
            response = gl.nondet.web.get(policy.manifest_url)
            if int(response.status) != 200 or not isinstance(response.body, (bytes, bytearray)):
                return self._forced('INCONCLUSIVE')
            raw = bytes(response.body)
        except Exception:
            return self._forced('INCONCLUSIVE')
        if len(raw) < 1 or len(raw) > MAX_MANIFEST_RESPONSE_BYTES:
            return self._forced('INCONCLUSIVE')
        if hashlib.sha256(raw).hexdigest() != assessment.manifest_digest:
            return self._forced('INCONCLUSIVE')
        try:
            payload = self._strict_json_loads(raw)
            cases = self._validate_manifest_payload(payload, policy)
            a, b = self._select_case_indexes(self._selection_material(assessment, chain_id, self.registry), len(cases))
        except Exception:
            return self._forced('INCONCLUSIVE')
        selected = [cases[a], cases[b]]
        case_a_id = selected[0]['case_id']
        case_b_id = selected[1]['case_id']
        try:
            evaluation_id = self._evaluation_id(int(assessment.assessment_id), attempt_number, chain_id, self.registry)
            request = self._build_endpoint_request(assessment, evaluation_id, selected)
        except Exception:
            return self._forced('INCONCLUSIVE', case_a_id, case_b_id)
        try:
            response = gl.nondet.web.request(assessment.endpoint, method='POST', headers={'content-type': 'application/json'}, body=request)
            if int(response.status) != 200 or not isinstance(response.body, (bytes, bytearray)):
                return self._forced('INCONCLUSIVE', case_a_id, case_b_id)
            endpoint_raw = bytes(response.body)
        except Exception:
            return self._forced('INCONCLUSIVE', case_a_id, case_b_id)
        if len(endpoint_raw) < 1 or len(endpoint_raw) > MAX_ENDPOINT_RESPONSE_BYTES:
            return self._forced('INCONCLUSIVE', case_a_id, case_b_id)
        try:
            normalized = self._validate_endpoint_response(endpoint_raw, assessment, evaluation_id, selected)
        except Exception:
            return self._forced('FAIL', case_a_id, case_b_id)
        return {'mode': 'EVALUATE', 'forced_verdict': '', 'case_a_id': case_a_id, 'case_b_id': case_b_id, 'selected_cases': selected, 'normalized_results': normalized, 'evaluation_id': evaluation_id}

    def _evidence_consensus(self, policy: PolicyRecord, assessment: AssessmentRecord, attempt_number: int) -> dict:
        chain_id = int(gl.message.chain_id)

        def leader_fn() -> dict:
            return self._evidence_once(policy, assessment, attempt_number, chain_id)

        def validator_fn(leader_result: object) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            leader_payload = leader_result.calldata
            validator_payload = self._evidence_once(policy, assessment, attempt_number, chain_id)
            return type(leader_payload) is dict and type(validator_payload) is dict and (validator_payload == leader_payload)
        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        if type(result) is not dict or set(result.keys()) != {'mode', 'forced_verdict', 'case_a_id', 'case_b_id', 'selected_cases', 'normalized_results', 'evaluation_id'}:
            raise gl.vm.UserError('ASSESSMENT_EVIDENCE_CONSENSUS_INVALID')
        return result

    @gl.public.write
    def evaluate_assessment(self, snapshot_json: str, attempt_number: int, request_nonce: int) -> None:
        if gl.message.sender_address != self.registry:
            raise gl.vm.UserError('REGISTRY_REQUIRED')
        policy, assessment = self._decode_snapshot(snapshot_json)
        if attempt_number != int(assessment.attempt_count) + 1:
            raise gl.vm.UserError('ASSESSMENT_ATTEMPT_MISMATCH')
        evidence = self._evidence_consensus(policy, assessment, attempt_number)
        gl.get_contract_at(self.semantic_judge).emit(on='finalized').judge_assessment(snapshot_json, self._canonical_json(evidence), int(assessment.assessment_id), attempt_number, request_nonce)

    def _canonical_json(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    def _utf8_size(self, value: str) -> int:
        return len(value.encode('utf-8'))

    def _strict_json_loads(self, raw: bytes) -> object:
        if not isinstance(raw, (bytes, bytearray)):
            raise gl.vm.UserError('JSON_BYTES_REQUIRED')
        try:
            text = bytes(raw).decode('utf-8', errors='strict')
        except UnicodeDecodeError as exc:
            raise gl.vm.UserError('JSON_UTF8') from exc

        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
            result: dict = {}
            for key, value in pairs:
                if key in result:
                    raise gl.vm.UserError('JSON_DUPLICATE_KEY')
                result[key] = value
            return result
        try:
            return json.loads(text, object_pairs_hook=reject_duplicates)
        except ValueError as exc:
            if str(exc) == 'JSON_DUPLICATE_KEY':
                raise
            raise gl.vm.UserError('JSON_PARSE') from exc

    def _identifier_is_valid(self, value: object) -> bool:
        if type(value) is not str:
            return False
        if len(value) < 1 or len(value) > MAX_IDENTIFIER_LENGTH:
            return False
        allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        for char in value:
            if char not in allowed:
                return False
        return True

    def _validate_manifest_payload(self, payload: object, policy: PolicyRecord) -> list[dict]:
        if type(payload) is not dict:
            raise gl.vm.UserError('MANIFEST_TOP_LEVEL')
        expected_keys = {'schema', 'manifest_id', 'authority', 'capability_id', 'policy_id', 'policy_version', 'cases'}
        if set(payload.keys()) != expected_keys:
            raise gl.vm.UserError('MANIFEST_KEYS')
        if type(payload['schema']) is not str or payload['schema'] != MANIFEST_SCHEMA:
            raise gl.vm.UserError('MANIFEST_SCHEMA')
        if type(payload['manifest_id']) is not str or payload['manifest_id'] != policy.manifest_id:
            raise gl.vm.UserError('MANIFEST_ID')
        if type(payload['authority']) is not str or payload['authority'] != policy.manifest_authority:
            raise gl.vm.UserError('MANIFEST_AUTHORITY')
        if type(payload['capability_id']) is not str or payload['capability_id'] != policy.capability_id:
            raise gl.vm.UserError('MANIFEST_CAPABILITY')
        if type(payload['policy_id']) is not str or payload['policy_id'] != policy.policy_id:
            raise gl.vm.UserError('MANIFEST_POLICY_ID')
        if type(payload['policy_version']) is not int or payload['policy_version'] != int(policy.version):
            raise gl.vm.UserError('MANIFEST_POLICY_VERSION')
        cases = payload['cases']
        if type(cases) is not list:
            raise gl.vm.UserError('MANIFEST_CASES_TYPE')
        if len(cases) < MIN_MANIFEST_CASE_COUNT or len(cases) > MAX_MANIFEST_CASE_COUNT:
            raise gl.vm.UserError('MANIFEST_CASE_COUNT')
        seen_case_ids: set[str] = set()
        validated_cases: list[dict] = []
        for case in cases:
            if type(case) is not dict:
                raise gl.vm.UserError('MANIFEST_CASE_TYPE')
            if set(case.keys()) != {'case_id', 'task', 'reference'}:
                raise gl.vm.UserError('MANIFEST_CASE_KEYS')
            case_id = case['case_id']
            task = case['task']
            reference = case['reference']
            if not self._identifier_is_valid(case_id):
                raise gl.vm.UserError('MANIFEST_CASE_ID')
            if case_id in seen_case_ids:
                raise gl.vm.UserError('MANIFEST_DUPLICATE_CASE_ID')
            if type(task) is not str:
                raise gl.vm.UserError('MANIFEST_CASE_TASK_TYPE')
            task_size = self._utf8_size(task)
            if task_size < 1 or task_size > MAX_CASE_TASK_BYTES:
                raise gl.vm.UserError('MANIFEST_CASE_TASK_SIZE')
            if type(reference) is not str:
                raise gl.vm.UserError('MANIFEST_CASE_REFERENCE_TYPE')
            if self._utf8_size(reference) > MAX_CASE_REFERENCE_BYTES:
                raise gl.vm.UserError('MANIFEST_CASE_REFERENCE_SIZE')
            seen_case_ids.add(case_id)
            validated_cases.append({'case_id': case_id, 'task': task, 'reference': reference})
        return validated_cases

    def _select_case_indexes(self, selection_material: str, case_count: int) -> tuple[int, int]:
        if case_count < MIN_MANIFEST_CASE_COUNT or case_count > MAX_MANIFEST_CASE_COUNT:
            raise gl.vm.UserError('SELECTION_CASE_COUNT')
        seed = hashlib.sha256(selection_material.encode('utf-8')).digest()
        case_a = int.from_bytes(seed[0:8], 'big') % case_count
        case_b = int.from_bytes(seed[8:16], 'big') % (case_count - 1)
        if case_b >= case_a:
            case_b += 1
        return (case_a, case_b)

    def _build_endpoint_request(self, assessment: AssessmentRecord, evaluation_id: str, selected_cases: list[dict]) -> bytes:
        if len(selected_cases) != 2:
            raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_COUNT')
        normalized_cases: list[dict] = []
        for case in selected_cases:
            if type(case) is not dict:
                raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_TYPE')
            if set(case.keys()) != {'case_id', 'task', 'reference'}:
                raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_KEYS')
            if not self._identifier_is_valid(case['case_id']):
                raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_ID')
            if type(case['task']) is not str:
                raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_TASK')
            if type(case['reference']) is not str:
                raise gl.vm.UserError('ENDPOINT_REQUEST_CASE_REFERENCE')
            normalized_cases.append({'case_id': case['case_id'], 'task': case['task'], 'reference': case['reference']})
        material = self._canonical_json({'agent_wallet': assessment.subject_wallet.as_hex.lower(), 'capability_id': assessment.capability_id, 'cases': normalized_cases, 'evaluation_id': evaluation_id, 'manifest_digest': assessment.manifest_digest, 'manifest_id': assessment.manifest_id, 'policy_id': assessment.policy_id, 'policy_version': int(assessment.policy_version), 'profile_digest': assessment.profile_digest, 'protocol': EVALUATION_PROTOCOL})
        encoded = material.encode('utf-8')
        if len(encoded) > MAX_ENDPOINT_REQUEST_BYTES:
            raise gl.vm.UserError('ENDPOINT_REQUEST_TOO_LARGE')
        return encoded

    def _validate_endpoint_response(self, raw: bytes, assessment: AssessmentRecord, evaluation_id: str, selected_cases: list[dict]) -> list[dict]:
        if len(raw) < 1:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_EMPTY')
        if len(raw) > MAX_ENDPOINT_RESPONSE_BYTES:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_TOO_LARGE')
        payload = self._strict_json_loads(raw)
        if type(payload) is not dict:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_TOP_LEVEL')
        expected_keys = {'protocol', 'evaluation_id', 'agent_wallet', 'profile_digest', 'capability_id', 'policy_id', 'policy_version', 'manifest_id', 'results'}
        if set(payload.keys()) != expected_keys:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_KEYS')
        exact_bindings = {'protocol': EVALUATION_PROTOCOL, 'evaluation_id': evaluation_id, 'agent_wallet': assessment.subject_wallet.as_hex.lower(), 'profile_digest': assessment.profile_digest, 'capability_id': assessment.capability_id, 'policy_id': assessment.policy_id, 'manifest_id': assessment.manifest_id}
        for key, expected in exact_bindings.items():
            if type(payload[key]) is not str or payload[key] != expected:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_BINDING')
        if type(payload['policy_version']) is not int or payload['policy_version'] != int(assessment.policy_version):
            raise gl.vm.UserError('ENDPOINT_RESPONSE_POLICY_VERSION')
        if len(selected_cases) != 2:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_EXPECTED_CASE_COUNT')
        results = payload['results']
        if type(results) is not list or len(results) != 2:
            raise gl.vm.UserError('ENDPOINT_RESPONSE_RESULTS_COUNT')
        normalized_results: list[dict] = []
        for index in range(2):
            result = results[index]
            if type(result) is not dict:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_RESULT_TYPE')
            if set(result.keys()) != {'case_id', 'output'}:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_RESULT_KEYS')
            expected_case_id = selected_cases[index]['case_id']
            if type(result['case_id']) is not str or result['case_id'] != expected_case_id:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_CASE_ID')
            output = result['output']
            if type(output) is not str:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_OUTPUT_TYPE')
            if self._utf8_size(output) > MAX_RESULT_OUTPUT_BYTES:
                raise gl.vm.UserError('ENDPOINT_RESPONSE_OUTPUT_SIZE')
            normalized_results.append({'case_id': result['case_id'], 'output': output})
        return normalized_results

    def _selection_material(self, assessment: AssessmentRecord, chain_id: int, contract_address: Address) -> str:
        return self._canonical_json({'assessment_id': int(assessment.assessment_id), 'capability_id': assessment.capability_id, 'chain_id': int(chain_id), 'contract_address': contract_address.as_hex.lower(), 'endpoint': assessment.endpoint, 'manifest_digest': assessment.manifest_digest, 'manifest_id': assessment.manifest_id, 'policy_id': assessment.policy_id, 'policy_version': int(assessment.policy_version), 'profile_digest': assessment.profile_digest, 'subject_wallet': assessment.subject_wallet.as_hex.lower()})

    def _evaluation_id(self, assessment_id: int, attempt_number: int, chain_id: int, contract_address: Address) -> str:
        if assessment_id < 1:
            raise gl.vm.UserError('EVALUATION_ASSESSMENT_ID')
        if attempt_number < 1 or attempt_number > ASSESSMENT_MAX_ATTEMPTS:
            raise gl.vm.UserError('EVALUATION_ATTEMPT_NUMBER')
        return 'agentseal-v1:' + str(int(chain_id)) + ':' + contract_address.as_hex.lower() + ':' + str(assessment_id) + ':' + str(attempt_number)
