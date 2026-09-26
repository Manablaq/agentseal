# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from dataclasses import dataclass
from datetime import datetime, timezone
from genlayer import *
ASSESSMENT_WINDOW_SECONDS = 86400
ASSESSMENT_MAX_ATTEMPTS = 3
EVALUATION_REQUEST_TIMEOUT_SECONDS = 600
ALLOWED_EVALUATOR_VERDICTS = ('PASS', 'FAIL', 'INCONCLUSIVE')

@allow_storage
@dataclass
class ChallengeRecord:
    challenge_id: u256
    certificate_id: u256
    challenger: Address
    binding_key: str
    policy_id: str
    policy_version: u64
    manifest_id: str
    manifest_digest: str
    status: str
    created_at: u64
    deadline: u64
    attempt_count: u64
    max_attempt_count: u64
    last_verdict: str
    case_a_id: str
    case_b_id: str

class AgentSealChallenge(gl.Contract):
    owner: Address
    certificate_registry: Address
    challenge_evaluator: Address
    semantic_judge: Address
    deterministic_support: Address
    challenge_count: u256
    challenges: TreeMap[str, ChallengeRecord]
    open_challenge_by_certificate: TreeMap[str, u256]
    evaluation_request_nonce: TreeMap[str, u64]
    evaluation_pending_nonce: TreeMap[str, u64]
    evaluation_pending_since: TreeMap[str, u64]
    revocation_delivery_pending: TreeMap[str, bool]
    revocation_initiator_by_challenge: TreeMap[str, Address]

    def __init__(self, certificate_registry: Address):
        if certificate_registry == Address(b'\x00' * 20):
            raise gl.vm.UserError('CERTIFICATE_REGISTRY_ADDRESS_ZERO')
        self.owner = gl.message.sender_address
        self.certificate_registry = certificate_registry
        self.challenge_evaluator = Address(b'\x00' * 20)
        self.semantic_judge = Address(b'\x00' * 20)
        self.deterministic_support = Address(b'\x00' * 20)
        self.challenge_count = u256(0)

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError('OWNER_REQUIRED')

    def _require_configured(self) -> None:
        if self.challenge_evaluator == Address(b'\x00' * 20) or self.semantic_judge == Address(b'\x00' * 20) or self.deterministic_support == Address(b'\x00' * 20):
            raise gl.vm.UserError('CHALLENGE_COMPONENTS_NOT_CONFIGURED')

    @gl.public.write
    def configure_evaluator(self, evaluator: Address, semantic_judge: Address, deterministic_support: Address) -> None:
        self._require_owner()
        if self.challenge_evaluator != Address(b'\x00' * 20) or self.semantic_judge != Address(b'\x00' * 20) or self.deterministic_support != Address(b'\x00' * 20):
            raise gl.vm.UserError('CHALLENGE_EVALUATOR_ALREADY_CONFIGURED')
        values = [evaluator, semantic_judge, deterministic_support]
        for value in values:
            if value == Address(b'\x00' * 20) or value == self.certificate_registry or value == gl.message.contract_address:
                raise gl.vm.UserError('CHALLENGE_COMPONENT_ADDRESS_INVALID')
        if evaluator == semantic_judge or evaluator == deterministic_support or semantic_judge == deterministic_support:
            raise gl.vm.UserError('CHALLENGE_COMPONENT_ADDRESS_INVALID')
        self.challenge_evaluator = evaluator
        self.semantic_judge = semantic_judge
        self.deterministic_support = deterministic_support

    @gl.public.view
    def get_components(self) -> dict:
        return {'certificate_registry': self.certificate_registry.as_hex, 'challenge_evaluator': self.challenge_evaluator.as_hex, 'semantic_judge': self.semantic_judge.as_hex, 'deterministic_support': self.deterministic_support.as_hex, 'configured': self.challenge_evaluator != Address(b'\x00' * 20) and self.semantic_judge != Address(b'\x00' * 20) and (self.deterministic_support != Address(b'\x00' * 20))}

    @gl.public.write
    def open_challenge(self, certificate_id: int) -> int:
        self._require_configured()
        certificate = gl.get_contract_at(self.deterministic_support).view().challenge_open_context(certificate_id)
        now = self._now()
        self._reconcile_open_challenge(certificate_id, now)
        challenge_id = int(self.challenge_count) + 1
        deadline = now + ASSESSMENT_WINDOW_SECONDS
        if deadline > int(certificate['expires_at']):
            deadline = int(certificate['expires_at'])
        self.challenges[self._challenge_key(challenge_id)] = ChallengeRecord(challenge_id=u256(challenge_id), certificate_id=u256(certificate_id), challenger=gl.message.sender_address, binding_key=certificate['binding_key'], policy_id=certificate['policy_id'], policy_version=u64(int(certificate['policy_version'])), manifest_id=certificate['manifest_id'], manifest_digest=certificate['manifest_digest'], status='PENDING', created_at=u64(now), deadline=u64(deadline), attempt_count=u64(0), max_attempt_count=u64(ASSESSMENT_MAX_ATTEMPTS), last_verdict='', case_a_id='', case_b_id='')
        self.challenge_count = u256(challenge_id)
        self.open_challenge_by_certificate[str(certificate_id)] = u256(challenge_id)
        return challenge_id

    @gl.public.write
    def evaluate_challenge(self, challenge_id: int) -> None:
        self._require_configured()
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if challenge.status != 'PENDING':
            raise gl.vm.UserError('CHALLENGE_NOT_PENDING')
        now = self._now()
        if now >= int(challenge.deadline):
            raise gl.vm.UserError('CHALLENGE_EXPIRED')
        if int(challenge.attempt_count) >= int(challenge.max_attempt_count):
            raise gl.vm.UserError('CHALLENGE_ATTEMPTS_EXHAUSTED')
        certificate_id = int(challenge.certificate_id)
        if int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0) != challenge_id:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        ctx = gl.get_contract_at(self.deterministic_support).view().challenge_evaluation_context(certificate_id, challenge.binding_key, challenge.policy_id, int(challenge.policy_version), challenge.manifest_id, challenge.manifest_digest, challenge_id, challenge.challenger, challenge.status, int(challenge.created_at), int(challenge.deadline), int(challenge.attempt_count), int(challenge.max_attempt_count), challenge.last_verdict, challenge.case_a_id, challenge.case_b_id)
        if ctx['state'] == 'REVOKED':
            challenge.status = 'CANCELLED'
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
            return
        pending = int(self.evaluation_pending_nonce.get(key) or 0)
        if pending != 0:
            started = int(self.evaluation_pending_since.get(key) or 0)
            if now < started + EVALUATION_REQUEST_TIMEOUT_SECONDS:
                raise gl.vm.UserError('CHALLENGE_EVALUATION_PENDING')
        request_nonce = int(self.evaluation_request_nonce.get(key) or 0) + 1
        self.evaluation_request_nonce[key] = u64(request_nonce)
        self.evaluation_pending_nonce[key] = u64(request_nonce)
        self.evaluation_pending_since[key] = u64(now)
        self.revocation_initiator_by_challenge[key] = gl.message.sender_address
        snapshot = ctx['snapshot']
        gl.get_contract_at(self.challenge_evaluator).emit(on='finalized').evaluate_challenge(snapshot, int(challenge.attempt_count) + 1, request_nonce)

    @gl.public.write
    def apply_challenge_evaluation_result(self, challenge_id: int, attempt_number: int, request_nonce: int, verdict: str, case_a_id: str, case_b_id: str) -> None:
        if gl.message.sender_address != self.semantic_judge:
            raise gl.vm.UserError('SEMANTIC_JUDGE_REQUIRED')
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if challenge.status != 'PENDING':
            raise gl.vm.UserError('CHALLENGE_NOT_PENDING')
        if int(self.evaluation_pending_nonce.get(key) or 0) != request_nonce or request_nonce == 0:
            raise gl.vm.UserError('CHALLENGE_EVALUATION_STALE')
        if attempt_number != int(challenge.attempt_count) + 1:
            raise gl.vm.UserError('CHALLENGE_ATTEMPT_MISMATCH')
        if verdict not in ALLOWED_EVALUATOR_VERDICTS:
            raise gl.vm.UserError('CHALLENGE_VERDICT_INVALID')
        certificate_id = int(challenge.certificate_id)
        state = gl.get_contract_at(self.deterministic_support).view().challenge_apply_state(certificate_id, challenge.binding_key)
        if state != 'OK':
            challenge.status = 'CANCELLED'
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
            self.evaluation_pending_nonce[key] = u64(0)
            self.evaluation_pending_since[key] = u64(0)
            return
        now = self._now()
        if now >= int(challenge.deadline):
            challenge.status = 'EXPIRED'
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
            self.evaluation_pending_nonce[key] = u64(0)
            self.evaluation_pending_since[key] = u64(0)
            return
        challenge.attempt_count = u64(attempt_number)
        challenge.last_verdict = verdict
        challenge.case_a_id = case_a_id
        challenge.case_b_id = case_b_id
        self.evaluation_pending_nonce[key] = u64(0)
        self.evaluation_pending_since[key] = u64(0)
        if verdict == 'PASS':
            challenge.status = 'REJECTED'
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
            return
        if verdict == 'FAIL':
            challenge.status = 'UPHELD'
            self.revocation_delivery_pending[key] = True
            gl.get_contract_at(self.certificate_registry).emit(on='finalized').apply_challenge_revocation(certificate_id, challenge_id, self.revocation_initiator_by_challenge[key], challenge.binding_key)
            return
        if attempt_number >= int(challenge.max_attempt_count):
            challenge.status = 'INCONCLUSIVE_FINAL'
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)

    @gl.public.write
    def retry_challenge_revocation(self, challenge_id: int) -> None:
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if challenge.status != 'UPHELD':
            raise gl.vm.UserError('CHALLENGE_NOT_UPHELD')
        if not bool(self.revocation_delivery_pending.get(key) or False):
            return
        certificate_id = int(challenge.certificate_id)
        state = gl.get_contract_at(self.deterministic_support).view().challenge_revocation_state(certificate_id, challenge_id, challenge.binding_key)
        if state == 'MATCH':
            self.revocation_delivery_pending[key] = False
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
            return
        if key not in self.revocation_initiator_by_challenge:
            raise gl.vm.UserError('CHALLENGE_REVOCATION_INITIATOR_MISSING')
        gl.get_contract_at(self.certificate_registry).emit(on='finalized').apply_challenge_revocation(certificate_id, challenge_id, self.revocation_initiator_by_challenge[key], challenge.binding_key)

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _challenge_key(self, challenge_id: int) -> str:
        return str(challenge_id)

    def _reconcile_open_challenge(self, certificate_id: int, now: int) -> None:
        challenge_id = int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0)
        if challenge_id == 0:
            return
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        challenge = self.challenges[key]
        if int(challenge.certificate_id) != certificate_id:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        if challenge.status == 'UPHELD' and bool(self.revocation_delivery_pending.get(key) or False):
            raise gl.vm.UserError('CHALLENGE_REVOCATION_PENDING')
        if challenge.status == 'PENDING':
            if now < int(challenge.deadline):
                raise gl.vm.UserError('OPEN_CHALLENGE_EXISTS')
            challenge.status = 'EXPIRED'
        self.open_challenge_by_certificate[str(certificate_id)] = u256(0)

    @gl.public.view
    def get_owner(self) -> str:
        return self.owner.as_hex

    @gl.public.view
    def get_revocation_delivery_pending(self, challenge_id: int) -> bool:
        return bool(self.revocation_delivery_pending.get(self._challenge_key(challenge_id)) or False)

    @gl.public.view
    def get_blocking_challenge_state(self, certificate_id: int) -> dict:
        challenge_id = int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0)
        if challenge_id == 0:
            return {'challenge_id': 0, 'status': '', 'revocation_delivery_pending': False}
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        challenge = self.challenges[key]
        if int(challenge.certificate_id) != certificate_id:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        if challenge.status == 'UPHELD' and bool(self.revocation_delivery_pending.get(key) or False):
            return {'challenge_id': challenge_id, 'status': 'UPHELD', 'revocation_delivery_pending': True}
        if challenge.status != 'PENDING':
            return {'challenge_id': 0, 'status': '', 'revocation_delivery_pending': False}
        if self._now() >= int(challenge.deadline):
            return {'challenge_id': 0, 'status': '', 'revocation_delivery_pending': False}
        return {'challenge_id': challenge_id, 'status': 'PENDING', 'revocation_delivery_pending': False}

    @gl.public.write
    def acknowledge_revocation(self, challenge_id: int, certificate_id: int) -> None:
        if gl.message.sender_address != self.certificate_registry:
            raise gl.vm.UserError('CERTIFICATE_REGISTRY_REQUIRED')
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if challenge.status != 'UPHELD' or int(challenge.certificate_id) != certificate_id:
            raise gl.vm.UserError('CHALLENGE_REVOCATION_ACK_MISMATCH')
        self.revocation_delivery_pending[key] = False
        if int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0) == challenge_id:
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)

    @gl.public.write
    def cancel_for_direct_revocation(self, certificate_id: int, challenge_id: int) -> None:
        if gl.message.sender_address != self.certificate_registry:
            raise gl.vm.UserError('CERTIFICATE_REGISTRY_REQUIRED')
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if int(challenge.certificate_id) != certificate_id:
            raise gl.vm.UserError('CHALLENGE_CERTIFICATE_MISMATCH')
        if challenge.status != 'PENDING':
            return
        now = self._now()
        challenge.status = 'EXPIRED' if now >= int(challenge.deadline) else 'CANCELLED'
        if int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0) == challenge_id:
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)
        self.evaluation_pending_nonce[key] = u64(0)
        self.evaluation_pending_since[key] = u64(0)

    @gl.public.write
    def sync_certificate_revocation(self, certificate_id: int) -> None:
        challenge_id = int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0)
        if challenge_id == 0:
            return
        if not bool(gl.get_contract_at(self.certificate_registry).view().revocation_exists(certificate_id)):
            return
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[key]
        if challenge.status == 'PENDING':
            challenge.status = 'EXPIRED' if self._now() >= int(challenge.deadline) else 'CANCELLED'
            self.evaluation_pending_nonce[key] = u64(0)
            self.evaluation_pending_since[key] = u64(0)
        if challenge.status != 'UPHELD' or not bool(self.revocation_delivery_pending.get(key) or False):
            self.open_challenge_by_certificate[str(certificate_id)] = u256(0)

    @gl.public.view
    def get_open_challenge_id(self, certificate_id: int) -> int:
        challenge_id = int(self.open_challenge_by_certificate.get(str(certificate_id)) or 0)
        if challenge_id == 0:
            return 0
        key = self._challenge_key(challenge_id)
        if key not in self.challenges:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        challenge = self.challenges[key]
        if int(challenge.certificate_id) != certificate_id:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        if challenge.status != 'PENDING':
            return 0
        if self._now() >= int(challenge.deadline):
            return 0
        return challenge_id

    @gl.public.view
    def get_challenge_count(self) -> int:
        return int(self.challenge_count)

    @gl.public.view
    def challenge_exists(self, challenge_id: int) -> bool:
        return self._challenge_key(challenge_id) in self.challenges

    @gl.public.view
    def get_challenge(self, challenge_id: int) -> dict:
        challenge_key = self._challenge_key(challenge_id)
        if challenge_key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[challenge_key]
        effective_status = challenge.status
        if effective_status == 'PENDING' and self._now() >= int(challenge.deadline):
            effective_status = 'EXPIRED'
        return {'challenge_id': int(challenge.challenge_id), 'certificate_id': int(challenge.certificate_id), 'challenger': challenge.challenger.as_hex, 'binding_key': challenge.binding_key, 'policy_id': challenge.policy_id, 'policy_version': int(challenge.policy_version), 'manifest_id': challenge.manifest_id, 'manifest_digest': challenge.manifest_digest, 'status': challenge.status, 'effective_status': effective_status, 'created_at': int(challenge.created_at), 'deadline': int(challenge.deadline), 'attempt_count': int(challenge.attempt_count), 'max_attempt_count': int(challenge.max_attempt_count), 'last_verdict': challenge.last_verdict, 'case_a_id': challenge.case_a_id, 'case_b_id': challenge.case_b_id}

    @gl.public.write
    def expire_challenge(self, challenge_id: int) -> None:
        challenge_key = self._challenge_key(challenge_id)
        if challenge_key not in self.challenges:
            raise gl.vm.UserError('CHALLENGE_NOT_FOUND')
        challenge = self.challenges[challenge_key]
        if challenge.status != 'PENDING':
            raise gl.vm.UserError('CHALLENGE_NOT_PENDING')
        now = self._now()
        if now < int(challenge.deadline):
            raise gl.vm.UserError('CHALLENGE_NOT_EXPIRED')
        open_challenge_id = int(self.open_challenge_by_certificate.get(str(challenge.certificate_id)) or 0)
        if open_challenge_id != challenge_id:
            raise gl.vm.UserError('OPEN_CHALLENGE_INDEX_CORRUPT')
        challenge.status = 'EXPIRED'
        self.open_challenge_by_certificate[str(challenge.certificate_id)] = u256(0)
