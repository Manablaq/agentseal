# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from genlayer import *
ASSESSMENT_WINDOW_SECONDS = 86400
ASSESSMENT_MAX_ATTEMPTS = 3
EVALUATION_REQUEST_TIMEOUT_SECONDS = 600
ALLOWED_EVALUATOR_VERDICTS = ('PASS', 'FAIL', 'INCONCLUSIVE')

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

class AgentSealRegistry(gl.Contract):
    owner: Address
    policy_registry: Address
    certificate_registry: Address
    assessment_evaluator: Address
    semantic_judge: Address
    deterministic_support: Address
    assessment_count: u256
    assessments: TreeMap[str, AssessmentRecord]
    live_assessment_by_binding: TreeMap[str, u256]
    assessment_request_nonce: TreeMap[str, u64]
    assessment_pending_nonce: TreeMap[str, u64]
    assessment_pending_since: TreeMap[str, u64]
    certificate_delivery_pending: TreeMap[str, bool]
    certificate_delivery_payload: TreeMap[str, str]

    def __init__(self, policy_registry: Address):
        if policy_registry == Address(b'\x00' * 20):
            raise gl.vm.UserError('POLICY_REGISTRY_ADDRESS_ZERO')
        self.owner = gl.message.sender_address
        self.policy_registry = policy_registry
        self.certificate_registry = Address(b'\x00' * 20)
        self.assessment_evaluator = Address(b'\x00' * 20)
        self.semantic_judge = Address(b'\x00' * 20)
        self.deterministic_support = Address(b'\x00' * 20)
        self.assessment_count = u256(0)

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError('OWNER_REQUIRED')

    def _require_configured(self) -> None:
        if self.certificate_registry == Address(b'\x00' * 20) or self.assessment_evaluator == Address(b'\x00' * 20) or self.semantic_judge == Address(b'\x00' * 20) or (self.deterministic_support == Address(b'\x00' * 20)):
            raise gl.vm.UserError('COMPONENTS_NOT_CONFIGURED')

    @gl.public.write
    def configure_components(self, certificate_registry: Address, assessment_evaluator: Address, semantic_judge: Address, deterministic_support: Address) -> None:
        self._require_owner()
        if self.certificate_registry != Address(b'\x00' * 20) or self.assessment_evaluator != Address(b'\x00' * 20) or self.semantic_judge != Address(b'\x00' * 20) or (self.deterministic_support != Address(b'\x00' * 20)):
            raise gl.vm.UserError('COMPONENTS_ALREADY_CONFIGURED')
        values = [certificate_registry, assessment_evaluator, semantic_judge, deterministic_support]
        for value in values:
            if value == Address(b'\x00' * 20) or value == self.policy_registry or value == gl.message.contract_address:
                raise gl.vm.UserError('COMPONENT_ADDRESS_INVALID')
        if certificate_registry == assessment_evaluator or certificate_registry == semantic_judge or certificate_registry == deterministic_support or (assessment_evaluator == semantic_judge) or (assessment_evaluator == deterministic_support) or (semantic_judge == deterministic_support):
            raise gl.vm.UserError('COMPONENT_ADDRESS_COLLISION')
        self.certificate_registry = certificate_registry
        self.assessment_evaluator = assessment_evaluator
        self.semantic_judge = semantic_judge
        self.deterministic_support = deterministic_support

    @gl.public.view
    def get_components(self) -> dict:
        return {'policy_registry': self.policy_registry.as_hex, 'certificate_registry': self.certificate_registry.as_hex, 'assessment_evaluator': self.assessment_evaluator.as_hex, 'semantic_judge': self.semantic_judge.as_hex, 'deterministic_support': self.deterministic_support.as_hex, 'configured': self.certificate_registry != Address(b'\x00' * 20) and self.assessment_evaluator != Address(b'\x00' * 20) and (self.semantic_judge != Address(b'\x00' * 20)) and (self.deterministic_support != Address(b'\x00' * 20))}

    @gl.public.write
    def create_assessment(self, profile_digest: str, endpoint: str, policy_id: str, policy_version: int, requested_certificate_ttl: int) -> int:
        self._require_configured()
        now = self._now()
        subject_wallet = gl.message.sender_address
        ctx = gl.get_contract_at(self.deterministic_support).view().prepare_assessment_request(subject_wallet, profile_digest, endpoint, policy_id, policy_version, requested_certificate_ttl, now)
        binding_key = ctx['binding_key']
        if int(gl.get_contract_at(self.certificate_registry).view().get_active_certificate_id(binding_key)) != 0:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_EXISTS')
        self._reconcile_live_assessment(binding_key, now)
        deadline = now + ASSESSMENT_WINDOW_SECONDS
        if deadline > int(ctx['valid_until']):
            deadline = int(ctx['valid_until'])
        assessment_id = int(self.assessment_count) + 1
        self.assessments[self._assessment_key(assessment_id)] = AssessmentRecord(assessment_id=u256(assessment_id), subject_wallet=subject_wallet, profile_digest=profile_digest, endpoint=endpoint, capability_id=ctx['capability_id'], policy_id=ctx['policy_id'], policy_version=u64(int(ctx['policy_version'])), manifest_id=ctx['manifest_id'], manifest_digest=ctx['manifest_digest'], requested_certificate_ttl=u64(requested_certificate_ttl), binding_key=binding_key, status='PENDING', created_at=u64(now), deadline=u64(deadline), attempt_count=u64(0), max_attempt_count=u64(ASSESSMENT_MAX_ATTEMPTS), last_verdict='', case_a_id='', case_b_id='', certificate_id=u256(0))
        self.live_assessment_by_binding[binding_key] = u256(assessment_id)
        self.assessment_count = u256(assessment_id)
        return assessment_id

    @gl.public.write
    def evaluate_assessment(self, assessment_id: int) -> None:
        self._require_configured()
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        if gl.message.sender_address != assessment.subject_wallet:
            raise gl.vm.UserError('ASSESSMENT_SUBJECT_REQUIRED')
        if assessment.status != 'PENDING':
            raise gl.vm.UserError('ASSESSMENT_NOT_PENDING')
        if bool(self.certificate_delivery_pending.get(key) or False):
            raise gl.vm.UserError('CERTIFICATE_ISSUANCE_PENDING')
        now = self._now()
        if now >= int(assessment.deadline):
            raise gl.vm.UserError('ASSESSMENT_EXPIRED')
        if int(assessment.attempt_count) >= int(assessment.max_attempt_count):
            raise gl.vm.UserError('ASSESSMENT_ATTEMPTS_EXHAUSTED')
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        policy = gl.get_contract_at(self.deterministic_support).view().assessment_policy_context(assessment.policy_id, int(assessment.policy_version), assessment.capability_id, assessment.manifest_id, assessment.manifest_digest, now)
        pending = int(self.assessment_pending_nonce.get(key) or 0)
        if pending != 0:
            started = int(self.assessment_pending_since.get(key) or 0)
            if now < started + EVALUATION_REQUEST_TIMEOUT_SECONDS:
                raise gl.vm.UserError('ASSESSMENT_EVALUATION_PENDING')
        request_nonce = int(self.assessment_request_nonce.get(key) or 0) + 1
        self.assessment_request_nonce[key] = u64(request_nonce)
        self.assessment_pending_nonce[key] = u64(request_nonce)
        self.assessment_pending_since[key] = u64(now)
        snapshot = self._canonical_json({'policy': policy, 'assessment': self._assessment_snapshot(assessment)})
        gl.get_contract_at(self.assessment_evaluator).emit(on='finalized').evaluate_assessment(snapshot, int(assessment.attempt_count) + 1, request_nonce)

    @gl.public.write
    def apply_assessment_evaluation_result(self, assessment_id: int, attempt_number: int, request_nonce: int, verdict: str, case_a_id: str, case_b_id: str) -> None:
        if gl.message.sender_address != self.semantic_judge:
            raise gl.vm.UserError('SEMANTIC_JUDGE_REQUIRED')
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        if assessment.status != 'PENDING':
            raise gl.vm.UserError('ASSESSMENT_NOT_PENDING')
        if int(self.assessment_pending_nonce.get(key) or 0) != request_nonce or request_nonce == 0:
            raise gl.vm.UserError('ASSESSMENT_EVALUATION_STALE')
        if attempt_number != int(assessment.attempt_count) + 1:
            raise gl.vm.UserError('ASSESSMENT_ATTEMPT_MISMATCH')
        if verdict not in ALLOWED_EVALUATOR_VERDICTS:
            raise gl.vm.UserError('SEMANTIC_VERDICT_INVALID')
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        now = self._now()
        if now >= int(assessment.deadline):
            assessment.status = 'EXPIRED'
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            self.assessment_pending_nonce[key] = u64(0)
            self.assessment_pending_since[key] = u64(0)
            return
        ctx = gl.get_contract_at(self.deterministic_support).view().assessment_result_context(assessment.policy_id, int(assessment.policy_version), assessment.capability_id, assessment.manifest_id, assessment.manifest_digest, now, verdict, assessment_id, assessment.subject_wallet, assessment.profile_digest, assessment.endpoint, int(assessment.requested_certificate_ttl), assessment.binding_key, case_a_id, case_b_id)
        if ctx['state'] == 'EXPIRED':
            assessment.status = 'EXPIRED'
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            self.assessment_pending_nonce[key] = u64(0)
            self.assessment_pending_since[key] = u64(0)
            return
        assessment.attempt_count = u64(attempt_number)
        assessment.last_verdict = verdict
        assessment.case_a_id = case_a_id
        assessment.case_b_id = case_b_id
        self.assessment_pending_nonce[key] = u64(0)
        self.assessment_pending_since[key] = u64(0)
        if verdict == 'FAIL':
            assessment.status = 'FAILED'
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            return
        if verdict == 'INCONCLUSIVE':
            if attempt_number >= int(assessment.max_attempt_count):
                assessment.status = 'INCONCLUSIVE_FINAL'
                self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            return
        if int(gl.get_contract_at(self.certificate_registry).view().get_active_certificate_id(assessment.binding_key)) != 0:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_EXISTS')
        assessment.certificate_id = u256(assessment_id)
        self.certificate_delivery_payload[key] = ctx['payload']
        self.certificate_delivery_pending[key] = True
        gl.get_contract_at(self.certificate_registry).emit(on='finalized').issue_certificate(ctx['payload'])

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _assessment_snapshot(self, assessment: AssessmentRecord) -> dict:
        return {'assessment_id': int(assessment.assessment_id), 'subject_wallet': assessment.subject_wallet.as_hex.lower(), 'profile_digest': assessment.profile_digest, 'endpoint': assessment.endpoint, 'capability_id': assessment.capability_id, 'policy_id': assessment.policy_id, 'policy_version': int(assessment.policy_version), 'manifest_id': assessment.manifest_id, 'manifest_digest': assessment.manifest_digest, 'requested_certificate_ttl': int(assessment.requested_certificate_ttl), 'binding_key': assessment.binding_key, 'status': assessment.status, 'created_at': int(assessment.created_at), 'deadline': int(assessment.deadline), 'attempt_count': int(assessment.attempt_count), 'max_attempt_count': int(assessment.max_attempt_count), 'last_verdict': assessment.last_verdict, 'case_a_id': assessment.case_a_id, 'case_b_id': assessment.case_b_id, 'certificate_id': int(assessment.certificate_id)}

    def _reconcile_live_assessment(self, binding_key: str, now: int) -> None:
        assessment_id = int(self.live_assessment_by_binding.get(binding_key) or 0)
        if assessment_id == 0:
            return
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        assessment = self.assessments[key]
        if assessment.binding_key != binding_key or assessment.status != 'PENDING':
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        if bool(self.certificate_delivery_pending.get(key) or False):
            raise gl.vm.UserError('LIVE_ASSESSMENT_EXISTS')
        if now < int(assessment.deadline):
            raise gl.vm.UserError('LIVE_ASSESSMENT_EXISTS')
        assessment.status = 'EXPIRED'
        self.live_assessment_by_binding[binding_key] = u256(0)

    def _assessment_key(self, assessment_id: int) -> str:
        return str(assessment_id)

    def _canonical_json(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    @gl.public.view
    def get_owner(self) -> str:
        return self.owner.as_hex

    @gl.public.view
    def get_assessment_count(self) -> int:
        return int(self.assessment_count)

    @gl.public.view
    def assessment_exists(self, assessment_id: int) -> bool:
        return self._assessment_key(assessment_id) in self.assessments

    @gl.public.view
    def get_assessment(self, assessment_id: int) -> dict:
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        effective_status = assessment.status
        if effective_status == 'PENDING' and (not bool(self.certificate_delivery_pending.get(key) or False)) and (self._now() >= int(assessment.deadline)):
            effective_status = 'EXPIRED'
        result = self._assessment_snapshot(assessment)
        result['effective_status'] = effective_status
        result['certificate_delivery_pending'] = bool(self.certificate_delivery_pending.get(key) or False)
        return result

    @gl.public.view
    def get_live_assessment_id(self, binding_key: str) -> int:
        assessment_id = int(self.live_assessment_by_binding.get(binding_key) or 0)
        if assessment_id == 0:
            return 0
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        assessment = self.assessments[key]
        if assessment.binding_key != binding_key or assessment.status != 'PENDING':
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        if bool(self.certificate_delivery_pending.get(key) or False):
            return assessment_id
        if self._now() >= int(assessment.deadline):
            return 0
        return assessment_id

    @gl.public.view
    def get_certificate_delivery_pending(self, assessment_id: int) -> bool:
        return bool(self.certificate_delivery_pending.get(self._assessment_key(assessment_id)) or False)

    @gl.public.write
    def retry_certificate_issuance(self, assessment_id: int) -> None:
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        if assessment.status != 'PENDING' or not bool(self.certificate_delivery_pending.get(key) or False):
            raise gl.vm.UserError('CERTIFICATE_ISSUANCE_NOT_PENDING')
        payload = self.certificate_delivery_payload.get(key) or ''
        if payload == '':
            raise gl.vm.UserError('CERTIFICATE_ISSUANCE_PAYLOAD_MISSING')
        gl.get_contract_at(self.certificate_registry).emit(on='finalized').issue_certificate(payload)

    @gl.public.write
    def acknowledge_certificate_issuance(self, assessment_id: int, certificate_id: int, binding_key: str) -> None:
        if gl.message.sender_address != self.certificate_registry:
            raise gl.vm.UserError('CERTIFICATE_REGISTRY_REQUIRED')
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        if assessment.status == 'PASSED':
            if int(assessment.certificate_id) != certificate_id or assessment.binding_key != binding_key:
                raise gl.vm.UserError('CERTIFICATE_ACK_CONFLICT')
            return
        if assessment.status != 'PENDING' or not bool(self.certificate_delivery_pending.get(key) or False):
            raise gl.vm.UserError('CERTIFICATE_ACK_STALE')
        if certificate_id != assessment_id or int(assessment.certificate_id) != certificate_id or assessment.binding_key != binding_key:
            raise gl.vm.UserError('CERTIFICATE_ACK_MISMATCH')
        assessment.status = 'PASSED'
        self.certificate_delivery_pending[key] = False
        self.certificate_delivery_payload[key] = ''
        self.live_assessment_by_binding[binding_key] = u256(0)

    @gl.public.write
    def expire_assessment(self, assessment_id: int) -> None:
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('ASSESSMENT_NOT_FOUND')
        assessment = self.assessments[key]
        if assessment.status != 'PENDING':
            raise gl.vm.UserError('ASSESSMENT_NOT_PENDING')
        if bool(self.certificate_delivery_pending.get(key) or False):
            raise gl.vm.UserError('CERTIFICATE_ISSUANCE_PENDING')
        if self._now() < int(assessment.deadline):
            raise gl.vm.UserError('ASSESSMENT_NOT_EXPIRED')
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        assessment.status = 'EXPIRED'
        self.live_assessment_by_binding[assessment.binding_key] = u256(0)
        self.assessment_pending_nonce[key] = u64(0)
        self.assessment_pending_since[key] = u64(0)
