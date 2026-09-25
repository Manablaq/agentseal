# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from genlayer import *

MAX_IDENTIFIER_LENGTH = 64
MAX_AUTHORITY_LENGTH = 128
MAX_MANIFEST_URL_LENGTH = 512
MAX_ENDPOINT_URL_LENGTH = 512
MAX_CRITERIA_LENGTH = 8192
MAX_POLICY_VALIDITY_SECONDS = 31_536_000
MAX_CERTIFICATE_TTL_SECONDS = 2_592_000
MAX_POLICY_VERSION = 4_294_967_295
ASSESSMENT_WINDOW_SECONDS = 86_400
ASSESSMENT_MAX_ATTEMPTS = 3
EVALUATION_REQUEST_TIMEOUT_SECONDS = 600

MAX_MANIFEST_RESPONSE_BYTES = 65_536
MIN_MANIFEST_CASE_COUNT = 4
MAX_MANIFEST_CASE_COUNT = 32
MAX_CASE_TASK_BYTES = 2_048
MAX_CASE_REFERENCE_BYTES = 8_192
MAX_ENDPOINT_REQUEST_BYTES = 65_536
MAX_ENDPOINT_RESPONSE_BYTES = 65_536
MAX_RESULT_OUTPUT_BYTES = 8_192
MAX_EVALUATOR_PROMPT_BYTES = 131_072
MANIFEST_SCHEMA = "agentseal-manifest-v1"
EVALUATION_PROTOCOL = "agentseal-evaluation-v1"
ALLOWED_EVALUATOR_VERDICTS = ("PASS", "FAIL", "INCONCLUSIVE")

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

@allow_storage
@dataclass
class CertificateRecord:
    certificate_id: u256
    assessment_id: u256
    subject_wallet: Address
    profile_digest: str
    endpoint: str
    capability_id: str
    policy_id: str
    policy_version: u64
    manifest_id: str
    manifest_digest: str
    case_a_id: str
    case_b_id: str
    binding_key: str
    status: str
    issued_at: u64
    expires_at: u64

@allow_storage
@dataclass
class RevocationRecord:
    certificate_id: u256
    source: str
    initiator: Address
    challenge_id: u256
    binding_key: str
    revoked_at: u64

class AgentSealRegistry(gl.Contract):
    owner: Address
    policy_count: u256
    policies: TreeMap[str, PolicyRecord]
    assessment_count: u256
    assessments: TreeMap[str, AssessmentRecord]
    live_assessment_by_binding: TreeMap[str, u256]
    certificates: TreeMap[str, CertificateRecord]
    active_certificate_by_binding: TreeMap[str, u256]
    revocations: TreeMap[str, RevocationRecord]
    assessment_evaluator: Address
    challenge_contract: Address
    assessment_request_nonce: TreeMap[str, u64]
    assessment_pending_nonce: TreeMap[str, u64]
    assessment_pending_since: TreeMap[str, u64]
    def __init__(self):
        self.owner = gl.message.sender_address
        self.policy_count = u256(0)
        self.assessment_count = u256(0)
        self.assessment_evaluator = Address(b"\x00" * 20)
        self.challenge_contract = Address(b"\x00" * 20)

    def _require_configured(self) -> None:
        if self.assessment_evaluator == Address(b"\x00" * 20) or self.challenge_contract == Address(b"\x00" * 20):
            raise gl.vm.UserError("COMPONENTS_NOT_CONFIGURED")

    @gl.public.write
    def configure_components(self, assessment_evaluator: Address, challenge_contract: Address) -> None:
        self._require_owner()
        if self.assessment_evaluator != Address(b"\x00" * 20) or self.challenge_contract != Address(b"\x00" * 20):
            raise gl.vm.UserError("COMPONENTS_ALREADY_CONFIGURED")
        if assessment_evaluator == Address(b"\x00" * 20) or challenge_contract == Address(b"\x00" * 20):
            raise gl.vm.UserError("COMPONENT_ADDRESS_ZERO")
        if assessment_evaluator == challenge_contract:
            raise gl.vm.UserError("COMPONENT_ADDRESS_COLLISION")
        if assessment_evaluator == gl.message.contract_address or challenge_contract == gl.message.contract_address:
            raise gl.vm.UserError("COMPONENT_SELF_REFERENCE")
        self.assessment_evaluator = assessment_evaluator
        self.challenge_contract = challenge_contract

    @gl.public.view
    def get_components(self) -> dict:
        return {
            "assessment_evaluator": self.assessment_evaluator.as_hex,
            "challenge_contract": self.challenge_contract.as_hex,
            "configured": self.assessment_evaluator != Address(b"\x00" * 20) and self.challenge_contract != Address(b"\x00" * 20),
        }

    @gl.public.view
    def revocation_exists(self, certificate_id: int) -> bool:
        return self._revocation_key(certificate_id) in self.revocations

    def _policy_snapshot(self, policy: PolicyRecord) -> dict:
        return {
            "policy_id": policy.policy_id,
            "capability_id": policy.capability_id,
            "version": int(policy.version),
            "criteria": policy.criteria,
            "manifest_url": policy.manifest_url,
            "manifest_id": policy.manifest_id,
            "manifest_authority": policy.manifest_authority,
            "manifest_digest": policy.manifest_digest,
            "valid_until": int(policy.valid_until),
            "max_certificate_ttl": int(policy.max_certificate_ttl),
            "active": policy.active,
            "created_at": int(policy.created_at),
        }

    def _assessment_snapshot(self, assessment: AssessmentRecord) -> dict:
        return {
            "assessment_id": int(assessment.assessment_id),
            "subject_wallet": assessment.subject_wallet.as_hex.lower(),
            "profile_digest": assessment.profile_digest,
            "endpoint": assessment.endpoint,
            "capability_id": assessment.capability_id,
            "policy_id": assessment.policy_id,
            "policy_version": int(assessment.policy_version),
            "manifest_id": assessment.manifest_id,
            "manifest_digest": assessment.manifest_digest,
            "requested_certificate_ttl": int(assessment.requested_certificate_ttl),
            "binding_key": assessment.binding_key,
            "status": assessment.status,
            "created_at": int(assessment.created_at),
            "deadline": int(assessment.deadline),
            "attempt_count": int(assessment.attempt_count),
            "max_attempt_count": int(assessment.max_attempt_count),
            "last_verdict": assessment.last_verdict,
            "case_a_id": assessment.case_a_id,
            "case_b_id": assessment.case_b_id,
            "certificate_id": int(assessment.certificate_id),
        }

    @gl.public.write
    def evaluate_assessment(self, assessment_id: int) -> None:
        self._require_configured()
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError("ASSESSMENT_NOT_FOUND")
        assessment = self.assessments[key]
        if gl.message.sender_address != assessment.subject_wallet:
            raise gl.vm.UserError("ASSESSMENT_SUBJECT_REQUIRED")
        if assessment.status != "PENDING":
            raise gl.vm.UserError("ASSESSMENT_NOT_PENDING")
        now = self._now()
        if now >= int(assessment.deadline):
            raise gl.vm.UserError("ASSESSMENT_EXPIRED")
        attempt_count = int(assessment.attempt_count)
        max_attempt_count = int(assessment.max_attempt_count)
        if attempt_count >= max_attempt_count:
            raise gl.vm.UserError("ASSESSMENT_ATTEMPTS_EXHAUSTED")
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")
        policy_key = self._policy_key(assessment.policy_id, int(assessment.policy_version))
        if policy_key not in self.policies:
            raise gl.vm.UserError("POLICY_NOT_FOUND")
        policy = self.policies[policy_key]
        if (
            policy.capability_id != assessment.capability_id
            or policy.policy_id != assessment.policy_id
            or int(policy.version) != int(assessment.policy_version)
            or policy.manifest_id != assessment.manifest_id
            or policy.manifest_digest != assessment.manifest_digest
        ):
            raise gl.vm.UserError("ASSESSMENT_POLICY_SNAPSHOT_MISMATCH")
        if now >= int(policy.valid_until):
            raise gl.vm.UserError("POLICY_EXPIRED")
        pending = int(self.assessment_pending_nonce.get(key) or 0)
        if pending != 0:
            started = int(self.assessment_pending_since.get(key) or 0)
            if now < started + EVALUATION_REQUEST_TIMEOUT_SECONDS:
                raise gl.vm.UserError("ASSESSMENT_EVALUATION_PENDING")
        request_nonce = int(self.assessment_request_nonce.get(key) or 0) + 1
        self.assessment_request_nonce[key] = u64(request_nonce)
        self.assessment_pending_nonce[key] = u64(request_nonce)
        self.assessment_pending_since[key] = u64(now)
        snapshot = self._canonical_json(
            {
                "policy": self._policy_snapshot(policy),
                "assessment": self._assessment_snapshot(assessment),
            }
        )
        gl.get_contract_at(self.assessment_evaluator).emit(on="finalized").evaluate_assessment(
            snapshot,
            attempt_count + 1,
            request_nonce,
        )

    @gl.public.write
    def apply_assessment_evaluation_result(
        self,
        assessment_id: int,
        attempt_number: int,
        request_nonce: int,
        verdict: str,
        case_a_id: str,
        case_b_id: str,
    ) -> None:
        if gl.message.sender_address != self.assessment_evaluator:
            raise gl.vm.UserError("ASSESSMENT_EVALUATOR_REQUIRED")
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError("ASSESSMENT_NOT_FOUND")
        assessment = self.assessments[key]
        if assessment.status != "PENDING":
            raise gl.vm.UserError("ASSESSMENT_NOT_PENDING")
        if int(self.assessment_pending_nonce.get(key) or 0) != request_nonce or request_nonce == 0:
            raise gl.vm.UserError("ASSESSMENT_EVALUATION_STALE")
        if attempt_number != int(assessment.attempt_count) + 1:
            raise gl.vm.UserError("ASSESSMENT_ATTEMPT_MISMATCH")
        if verdict not in ALLOWED_EVALUATOR_VERDICTS:
            raise gl.vm.UserError("SEMANTIC_VERDICT_INVALID")
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")
        now = self._now()
        if now >= int(assessment.deadline):
            assessment.status = "EXPIRED"
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            self.assessment_pending_nonce[key] = u64(0)
            self.assessment_pending_since[key] = u64(0)
            return
        policy_key = self._policy_key(assessment.policy_id, int(assessment.policy_version))
        if policy_key not in self.policies:
            raise gl.vm.UserError("POLICY_NOT_FOUND")
        policy = self.policies[policy_key]
        if (
            policy.capability_id != assessment.capability_id
            or policy.policy_id != assessment.policy_id
            or int(policy.version) != int(assessment.policy_version)
            or policy.manifest_id != assessment.manifest_id
            or policy.manifest_digest != assessment.manifest_digest
        ):
            raise gl.vm.UserError("ASSESSMENT_POLICY_SNAPSHOT_MISMATCH")
        if now >= int(policy.valid_until):
            assessment.status = "EXPIRED"
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
        if verdict == "PASS":
            self._issue_pass_certificate(assessment, policy, now, case_a_id, case_b_id)
            assessment.status = "PASSED"
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            return
        if verdict == "FAIL":
            assessment.status = "FAILED"
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)
            return
        if attempt_number >= int(assessment.max_attempt_count):
            assessment.status = "INCONCLUSIVE_FINAL"
            self.live_assessment_by_binding[assessment.binding_key] = u256(0)

    @gl.public.write
    def expire_assessment(self, assessment_id: int) -> None:
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError("ASSESSMENT_NOT_FOUND")
        assessment = self.assessments[key]
        if assessment.status != "PENDING":
            raise gl.vm.UserError("ASSESSMENT_NOT_PENDING")
        if self._now() < int(assessment.deadline):
            raise gl.vm.UserError("ASSESSMENT_NOT_EXPIRED")
        if int(self.live_assessment_by_binding.get(assessment.binding_key) or 0) != assessment_id:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")
        assessment.status = "EXPIRED"
        self.live_assessment_by_binding[assessment.binding_key] = u256(0)
        self.assessment_pending_nonce[key] = u64(0)
        self.assessment_pending_since[key] = u64(0)

    @gl.public.write
    def revoke_certificate(self, certificate_id: int) -> None:
        self._require_configured()
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key not in self.certificates:
            raise gl.vm.UserError("CERTIFICATE_NOT_FOUND")
        certificate = self.certificates[certificate_key]
        if certificate.status != "ACTIVE":
            raise gl.vm.UserError("CERTIFICATE_NOT_ACTIVE")
        now = self._now()
        if now >= int(certificate.expires_at):
            raise gl.vm.UserError("CERTIFICATE_EXPIRED")
        if int(self.active_certificate_by_binding.get(certificate.binding_key) or 0) != certificate_id:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")
        caller = gl.message.sender_address
        if caller != certificate.subject_wallet and caller != self.owner:
            raise gl.vm.UserError("REVOCATION_NOT_AUTHORIZED")
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key in self.revocations:
            raise gl.vm.UserError("REVOCATION_ALREADY_EXISTS")
        challenge_state = gl.get_contract_at(self.challenge_contract).view().get_blocking_challenge_state(certificate_id)
        challenge_id = int(challenge_state["challenge_id"])
        challenge_status = challenge_state["status"]
        if challenge_status == "UPHELD" and bool(challenge_state["revocation_delivery_pending"]):
            raise gl.vm.UserError("CHALLENGE_REVOCATION_PENDING")
        source = "SUBJECT_SELF_REVOKE" if caller == certificate.subject_wallet else "OWNER_AUTHORITY_REVOKE"
        self._record_certificate_revocation(certificate, now, source, caller, challenge_id)
        if challenge_id != 0 and challenge_status == "PENDING":
            gl.get_contract_at(self.challenge_contract).emit(on="finalized").cancel_for_direct_revocation(
                certificate_id,
                challenge_id,
            )

    @gl.public.write
    def apply_challenge_revocation(
        self,
        certificate_id: int,
        challenge_id: int,
        initiator: Address,
        binding_key: str,
    ) -> None:
        if gl.message.sender_address != self.challenge_contract:
            raise gl.vm.UserError("CHALLENGE_CONTRACT_REQUIRED")
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key in self.revocations:
            existing = self.revocations[revocation_key]
            if (
                existing.source != "CHALLENGE_CONSENSUS"
                or int(existing.challenge_id) != challenge_id
                or existing.binding_key != binding_key
            ):
                raise gl.vm.UserError("REVOCATION_RECORD_CONFLICT")
            gl.get_contract_at(self.challenge_contract).emit(on="finalized").acknowledge_revocation(
                challenge_id,
                certificate_id,
            )
            return
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key not in self.certificates:
            raise gl.vm.UserError("CERTIFICATE_NOT_FOUND")
        certificate = self.certificates[certificate_key]
        if certificate.status != "ACTIVE":
            raise gl.vm.UserError("CERTIFICATE_NOT_ACTIVE")
        if certificate.binding_key != binding_key:
            raise gl.vm.UserError("CHALLENGE_REVOCATION_BINDING_MISMATCH")
        if int(self.active_certificate_by_binding.get(binding_key) or 0) != certificate_id:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")
        self._record_certificate_revocation(
            certificate,
            self._now(),
            "CHALLENGE_CONSENSUS",
            initiator,
            challenge_id,
        )
        gl.get_contract_at(self.challenge_contract).emit(on="finalized").acknowledge_revocation(
            challenge_id,
            certificate_id,
        )

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError('OWNER_REQUIRED')

    def _validate_identifier(self, value: str, label: str) -> None:
        if len(value) < 1 or len(value) > MAX_IDENTIFIER_LENGTH:
            raise gl.vm.UserError(label + '_LENGTH')
        allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        for char in value:
            if char not in allowed:
                raise gl.vm.UserError(label + '_FORMAT')

    def _validate_manifest_url(self, value: str) -> None:
        if len(value) < 9 or len(value) > MAX_MANIFEST_URL_LENGTH:
            raise gl.vm.UserError('MANIFEST_URL_LENGTH')
        if ' ' in value or '\n' in value or '\r' in value or ('\t' in value):
            raise gl.vm.UserError('MANIFEST_URL_WHITESPACE')
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise gl.vm.UserError('MANIFEST_URL_FORMAT')
        if parsed.scheme != 'https':
            raise gl.vm.UserError('MANIFEST_URL_HTTPS_REQUIRED')
        if not parsed.netloc or parsed.hostname is None:
            raise gl.vm.UserError('MANIFEST_URL_HOST_REQUIRED')
        if parsed.fragment:
            raise gl.vm.UserError('MANIFEST_URL_FRAGMENT_FORBIDDEN')
        if parsed.username is not None or parsed.password is not None:
            raise gl.vm.UserError('MANIFEST_URL_CREDENTIALS_FORBIDDEN')
        if port is not None:
            raise gl.vm.UserError('MANIFEST_URL_PORT_FORBIDDEN')
        host = parsed.hostname
        if parsed.netloc != host:
            raise gl.vm.UserError('MANIFEST_URL_HOST_NOT_CANONICAL')
        if len(host) > 253 or host.startswith('.') or host.endswith('.'):
            raise gl.vm.UserError('MANIFEST_URL_HOST_FORMAT')
        if host == 'localhost' or host.endswith('.localhost') or host.endswith('.local') or host.endswith('.internal') or (host == 'home.arpa') or host.endswith('.home.arpa'):
            raise gl.vm.UserError('MANIFEST_URL_LOCAL_HOST_FORBIDDEN')
        if ':' in host or host.replace('.', '').isdigit():
            raise gl.vm.UserError('MANIFEST_URL_IP_LITERAL_FORBIDDEN')
        labels = host.split('.')
        if len(labels) < 2:
            raise gl.vm.UserError('MANIFEST_URL_PUBLIC_HOST_REQUIRED')
        allowed = 'abcdefghijklmnopqrstuvwxyz0123456789-'
        for label in labels:
            if len(label) < 1 or len(label) > 63:
                raise gl.vm.UserError('MANIFEST_URL_HOST_FORMAT')
            if label.startswith('-') or label.endswith('-'):
                raise gl.vm.UserError('MANIFEST_URL_HOST_FORMAT')
            for char in label:
                if char not in allowed:
                    raise gl.vm.UserError('MANIFEST_URL_HOST_FORMAT')

    def _validate_assessment_endpoint(self, value: str) -> None:
        if len(value) < 9 or len(value) > MAX_ENDPOINT_URL_LENGTH:
            raise gl.vm.UserError('ENDPOINT_LENGTH')
        if ' ' in value or '\n' in value or '\r' in value or ('\t' in value):
            raise gl.vm.UserError('ENDPOINT_WHITESPACE')
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise gl.vm.UserError('ENDPOINT_FORMAT')
        if parsed.scheme != 'https':
            raise gl.vm.UserError('ENDPOINT_HTTPS_REQUIRED')
        if not parsed.netloc or parsed.hostname is None:
            raise gl.vm.UserError('ENDPOINT_HOST_REQUIRED')
        if parsed.fragment:
            raise gl.vm.UserError('ENDPOINT_FRAGMENT_FORBIDDEN')
        if parsed.username is not None or parsed.password is not None:
            raise gl.vm.UserError('ENDPOINT_CREDENTIALS_FORBIDDEN')
        if port is not None:
            raise gl.vm.UserError('ENDPOINT_PORT_FORBIDDEN')
        host = parsed.hostname
        if parsed.netloc != host:
            raise gl.vm.UserError('ENDPOINT_HOST_NOT_CANONICAL')
        if len(host) > 253 or host.startswith('.') or host.endswith('.'):
            raise gl.vm.UserError('ENDPOINT_HOST_FORMAT')
        if host == 'localhost' or host.endswith('.localhost') or host.endswith('.local') or host.endswith('.internal') or (host == 'home.arpa') or host.endswith('.home.arpa'):
            raise gl.vm.UserError('ENDPOINT_LOCAL_HOST_FORBIDDEN')
        if ':' in host or host.replace('.', '').isdigit():
            raise gl.vm.UserError('ENDPOINT_IP_LITERAL_FORBIDDEN')
        labels = host.split('.')
        if len(labels) < 2:
            raise gl.vm.UserError('ENDPOINT_PUBLIC_HOST_REQUIRED')
        allowed = 'abcdefghijklmnopqrstuvwxyz0123456789-'
        for label in labels:
            if len(label) < 1 or len(label) > 63:
                raise gl.vm.UserError('ENDPOINT_HOST_FORMAT')
            if label.startswith('-') or label.endswith('-'):
                raise gl.vm.UserError('ENDPOINT_HOST_FORMAT')
            for char in label:
                if char not in allowed:
                    raise gl.vm.UserError('ENDPOINT_HOST_FORMAT')

    def _validate_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError('MANIFEST_DIGEST_LENGTH')
        for char in value:
            if char not in '0123456789abcdef':
                raise gl.vm.UserError('MANIFEST_DIGEST_FORMAT')

    def _validate_profile_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError('PROFILE_DIGEST_LENGTH')
        for char in value:
            if char not in '0123456789abcdef':
                raise gl.vm.UserError('PROFILE_DIGEST_FORMAT')

    def _policy_key(self, policy_id: str, version: int) -> str:
        return policy_id + ':' + str(version)

    def _assessment_key(self, assessment_id: int) -> str:
        return str(assessment_id)

    def _certificate_key(self, certificate_id: int) -> str:
        return str(certificate_id)

    def _binding_key(self, subject_wallet: Address, profile_digest: str, endpoint: str, policy: PolicyRecord) -> str:
        material = json.dumps({'capability_id': policy.capability_id, 'domain': 'agentseal-binding-v1', 'endpoint': endpoint, 'manifest_digest': policy.manifest_digest, 'manifest_id': policy.manifest_id, 'policy_id': policy.policy_id, 'policy_version': int(policy.version), 'profile_digest': profile_digest, 'subject_wallet': subject_wallet.as_hex.lower()}, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def _reconcile_live_assessment(self, binding_key: str, now: int) -> None:
        assessment_id = int(self.live_assessment_by_binding.get(binding_key) or 0)
        if assessment_id == 0:
            return
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        assessment = self.assessments[key]
        if assessment.binding_key != binding_key:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        if assessment.status != 'PENDING':
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        if now < int(assessment.deadline):
            raise gl.vm.UserError('LIVE_ASSESSMENT_EXISTS')
        assessment.status = 'EXPIRED'
        self.live_assessment_by_binding[binding_key] = u256(0)

    def _canonical_json(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    def _reconcile_active_certificate(self, binding_key: str, now: int) -> None:
        certificate_id = int(self.active_certificate_by_binding.get(binding_key) or 0)
        if certificate_id == 0:
            return
        key = self._certificate_key(certificate_id)
        if key not in self.certificates:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        certificate = self.certificates[key]
        if certificate.binding_key != binding_key:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        if certificate.status == 'ACTIVE':
            if now < int(certificate.expires_at):
                raise gl.vm.UserError('ACTIVE_CERTIFICATE_EXISTS')
            certificate.status = 'EXPIRED'
            self.active_certificate_by_binding[binding_key] = u256(0)
            return
        if certificate.status == 'EXPIRED' or certificate.status == 'REVOKED':
            self.active_certificate_by_binding[binding_key] = u256(0)
            return
        raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')

    @gl.public.view
    def get_owner(self) -> str:
        return self.owner.as_hex

    @gl.public.view
    def get_policy_count(self) -> int:
        return int(self.policy_count)

    @gl.public.view
    def policy_exists(self, policy_id: str, version: int) -> bool:
        key = self._policy_key(policy_id, version)
        return key in self.policies

    @gl.public.view
    def get_policy(self, policy_id: str, version: int) -> dict:
        key = self._policy_key(policy_id, version)
        if key not in self.policies:
            raise gl.vm.UserError('POLICY_NOT_FOUND')
        policy = self.policies[key]
        return {'policy_id': policy.policy_id, 'capability_id': policy.capability_id, 'version': int(policy.version), 'criteria': policy.criteria, 'manifest_url': policy.manifest_url, 'manifest_id': policy.manifest_id, 'manifest_authority': policy.manifest_authority, 'manifest_digest': policy.manifest_digest, 'valid_until': int(policy.valid_until), 'max_certificate_ttl': int(policy.max_certificate_ttl), 'active': policy.active, 'created_at': int(policy.created_at)}

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
        if assessment.status == 'PENDING' and self._now() >= int(assessment.deadline):
            effective_status = 'EXPIRED'
        return {'assessment_id': int(assessment.assessment_id), 'subject_wallet': assessment.subject_wallet.as_hex.lower(), 'profile_digest': assessment.profile_digest, 'endpoint': assessment.endpoint, 'capability_id': assessment.capability_id, 'policy_id': assessment.policy_id, 'policy_version': int(assessment.policy_version), 'manifest_id': assessment.manifest_id, 'manifest_digest': assessment.manifest_digest, 'requested_certificate_ttl': int(assessment.requested_certificate_ttl), 'binding_key': assessment.binding_key, 'status': assessment.status, 'effective_status': effective_status, 'created_at': int(assessment.created_at), 'deadline': int(assessment.deadline), 'attempt_count': int(assessment.attempt_count), 'max_attempt_count': int(assessment.max_attempt_count), 'last_verdict': assessment.last_verdict, 'case_a_id': assessment.case_a_id, 'case_b_id': assessment.case_b_id, 'certificate_id': int(assessment.certificate_id)}

    @gl.public.view
    def get_live_assessment_id(self, binding_key: str) -> int:
        assessment_id = int(self.live_assessment_by_binding.get(binding_key) or 0)
        if assessment_id == 0:
            return 0
        key = self._assessment_key(assessment_id)
        if key not in self.assessments:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        assessment = self.assessments[key]
        if assessment.binding_key != binding_key:
            raise gl.vm.UserError('LIVE_ASSESSMENT_INDEX_CORRUPT')
        if assessment.status != 'PENDING':
            return 0
        if self._now() >= int(assessment.deadline):
            return 0
        return assessment_id

    @gl.public.view
    def certificate_exists(self, certificate_id: int) -> bool:
        return self._certificate_key(certificate_id) in self.certificates

    @gl.public.view
    def get_certificate(self, certificate_id: int) -> dict:
        key = self._certificate_key(certificate_id)
        if key not in self.certificates:
            raise gl.vm.UserError('CERTIFICATE_NOT_FOUND')
        certificate = self.certificates[key]
        effective_status = certificate.status
        if certificate.status == 'ACTIVE' and self._now() >= int(certificate.expires_at):
            effective_status = 'EXPIRED'
        return {'certificate_id': int(certificate.certificate_id), 'assessment_id': int(certificate.assessment_id), 'subject_wallet': certificate.subject_wallet.as_hex.lower(), 'profile_digest': certificate.profile_digest, 'endpoint': certificate.endpoint, 'capability_id': certificate.capability_id, 'policy_id': certificate.policy_id, 'policy_version': int(certificate.policy_version), 'manifest_id': certificate.manifest_id, 'manifest_digest': certificate.manifest_digest, 'case_a_id': certificate.case_a_id, 'case_b_id': certificate.case_b_id, 'binding_key': certificate.binding_key, 'status': certificate.status, 'effective_status': effective_status, 'issued_at': int(certificate.issued_at), 'expires_at': int(certificate.expires_at)}

    @gl.public.view
    def get_active_certificate_id(self, binding_key: str) -> int:
        certificate_id = int(self.active_certificate_by_binding.get(binding_key) or 0)
        if certificate_id == 0:
            return 0
        key = self._certificate_key(certificate_id)
        if key not in self.certificates:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        certificate = self.certificates[key]
        if certificate.binding_key != binding_key:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        if certificate.status != 'ACTIVE':
            return 0
        if self._now() >= int(certificate.expires_at):
            return 0
        return certificate_id

    @gl.public.write
    def expire_certificate(self, certificate_id: int) -> None:
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key not in self.certificates:
            raise gl.vm.UserError('CERTIFICATE_NOT_FOUND')
        certificate = self.certificates[certificate_key]
        if certificate.status != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_NOT_ACTIVE')
        now = self._now()
        if now < int(certificate.expires_at):
            raise gl.vm.UserError('CERTIFICATE_NOT_EXPIRED')
        active_certificate_id = int(self.active_certificate_by_binding.get(certificate.binding_key) or 0)
        if active_certificate_id != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        self._reconcile_active_certificate(certificate.binding_key, now)

    def _revocation_key(self, certificate_id: int) -> str:
        return str(certificate_id)

    def _record_certificate_revocation(self, certificate: CertificateRecord, now: int, source: str, initiator: Address, challenge_id: int) -> None:
        certificate_id = int(certificate.certificate_id)
        certificate.status = 'REVOKED'
        self.active_certificate_by_binding[certificate.binding_key] = u256(0)
        self.revocations[self._revocation_key(certificate_id)] = RevocationRecord(certificate_id=u256(certificate_id), source=source, initiator=initiator, challenge_id=u256(challenge_id), binding_key=certificate.binding_key, revoked_at=u64(now))

    @gl.public.view
    def get_revocation(self, certificate_id: int) -> dict:
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key not in self.revocations:
            raise gl.vm.UserError('REVOCATION_NOT_FOUND')
        revocation = self.revocations[revocation_key]
        return {'certificate_id': int(revocation.certificate_id), 'source': revocation.source, 'initiator': revocation.initiator.as_hex, 'challenge_id': int(revocation.challenge_id), 'binding_key': revocation.binding_key, 'revoked_at': int(revocation.revoked_at)}

    @gl.public.write
    def create_policy(self, policy_id: str, capability_id: str, version: int, criteria: str, manifest_url: str, manifest_id: str, manifest_authority: str, manifest_digest: str, valid_until: int, max_certificate_ttl: int) -> None:
        self._require_owner()
        self._validate_identifier(policy_id, 'POLICY_ID')
        self._validate_identifier(capability_id, 'CAPABILITY_ID')
        self._validate_identifier(manifest_id, 'MANIFEST_ID')
        if version < 1 or version > MAX_POLICY_VERSION:
            raise gl.vm.UserError('POLICY_VERSION_RANGE')
        if len(criteria) < 1 or len(criteria) > MAX_CRITERIA_LENGTH:
            raise gl.vm.UserError('CRITERIA_LENGTH')
        if len(manifest_authority) < 1 or len(manifest_authority) > MAX_AUTHORITY_LENGTH:
            raise gl.vm.UserError('MANIFEST_AUTHORITY_LENGTH')
        self._validate_manifest_url(manifest_url)
        self._validate_digest(manifest_digest)
        now = self._now()
        if valid_until <= now:
            raise gl.vm.UserError('POLICY_ALREADY_EXPIRED')
        if valid_until - now > MAX_POLICY_VALIDITY_SECONDS:
            raise gl.vm.UserError('POLICY_VALIDITY_TOO_LONG')
        if max_certificate_ttl < 1 or max_certificate_ttl > MAX_CERTIFICATE_TTL_SECONDS:
            raise gl.vm.UserError('CERTIFICATE_TTL_RANGE')
        key = self._policy_key(policy_id, version)
        if key in self.policies:
            raise gl.vm.UserError('POLICY_VERSION_EXISTS')
        self.policies[key] = PolicyRecord(policy_id=policy_id, capability_id=capability_id, version=u64(version), criteria=criteria, manifest_url=manifest_url, manifest_id=manifest_id, manifest_authority=manifest_authority, manifest_digest=manifest_digest, valid_until=u64(valid_until), max_certificate_ttl=u64(max_certificate_ttl), active=True, created_at=u64(now))
        self.policy_count = u256(int(self.policy_count) + 1)

    @gl.public.write
    def disable_policy(self, policy_id: str, version: int) -> None:
        self._require_owner()
        key = self._policy_key(policy_id, version)
        if key not in self.policies:
            raise gl.vm.UserError('POLICY_NOT_FOUND')
        policy = self.policies[key]
        if not policy.active:
            raise gl.vm.UserError('POLICY_ALREADY_DISABLED')
        policy.active = False

    @gl.public.write
    def create_assessment(self, profile_digest: str, endpoint: str, policy_id: str, policy_version: int, requested_certificate_ttl: int) -> int:
        self._validate_profile_digest(profile_digest)
        self._validate_assessment_endpoint(endpoint)
        self._validate_identifier(policy_id, 'POLICY_ID')
        if policy_version < 1 or policy_version > MAX_POLICY_VERSION:
            raise gl.vm.UserError('POLICY_VERSION_RANGE')
        policy_key = self._policy_key(policy_id, policy_version)
        if policy_key not in self.policies:
            raise gl.vm.UserError('POLICY_NOT_FOUND')
        policy = self.policies[policy_key]
        now = self._now()
        if not policy.active:
            raise gl.vm.UserError('POLICY_INACTIVE')
        if now >= int(policy.valid_until):
            raise gl.vm.UserError('POLICY_EXPIRED')
        if requested_certificate_ttl < 1 or requested_certificate_ttl > int(policy.max_certificate_ttl):
            raise gl.vm.UserError('CERTIFICATE_TTL_POLICY_RANGE')
        subject_wallet = gl.message.sender_address
        binding_key = self._binding_key(subject_wallet, profile_digest, endpoint, policy)
        self._reconcile_active_certificate(binding_key, now)
        self._reconcile_live_assessment(binding_key, now)
        deadline = now + ASSESSMENT_WINDOW_SECONDS
        if deadline > int(policy.valid_until):
            deadline = int(policy.valid_until)
        assessment_id = int(self.assessment_count) + 1
        self.assessments[self._assessment_key(assessment_id)] = AssessmentRecord(assessment_id=u256(assessment_id), subject_wallet=subject_wallet, profile_digest=profile_digest, endpoint=endpoint, capability_id=policy.capability_id, policy_id=policy.policy_id, policy_version=policy.version, manifest_id=policy.manifest_id, manifest_digest=policy.manifest_digest, requested_certificate_ttl=u64(requested_certificate_ttl), binding_key=binding_key, status='PENDING', created_at=u64(now), deadline=u64(deadline), attempt_count=u64(0), max_attempt_count=u64(ASSESSMENT_MAX_ATTEMPTS), last_verdict='', case_a_id='', case_b_id='', certificate_id=u256(0))
        self.live_assessment_by_binding[binding_key] = u256(assessment_id)
        self.assessment_count = u256(assessment_id)
        return assessment_id

    def _issue_pass_certificate(self, assessment: AssessmentRecord, policy: PolicyRecord, now: int, case_a_id: str, case_b_id: str) -> int:
        certificate_id = int(assessment.assessment_id)
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key in self.certificates:
            raise gl.vm.UserError('CERTIFICATE_ALREADY_EXISTS')
        active_certificate_id = int(self.active_certificate_by_binding.get(assessment.binding_key) or 0)
        if active_certificate_id != 0:
            active_key = self._certificate_key(active_certificate_id)
            if active_key not in self.certificates:
                raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
            active_certificate = self.certificates[active_key]
            if active_certificate.binding_key != assessment.binding_key:
                raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
            if active_certificate.status == 'ACTIVE' and now < int(active_certificate.expires_at):
                raise gl.vm.UserError('ACTIVE_CERTIFICATE_EXISTS')
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        expires_at = now + int(assessment.requested_certificate_ttl)
        if expires_at > int(policy.valid_until):
            expires_at = int(policy.valid_until)
        self.certificates[certificate_key] = CertificateRecord(certificate_id=u256(certificate_id), assessment_id=assessment.assessment_id, subject_wallet=assessment.subject_wallet, profile_digest=assessment.profile_digest, endpoint=assessment.endpoint, capability_id=assessment.capability_id, policy_id=assessment.policy_id, policy_version=assessment.policy_version, manifest_id=assessment.manifest_id, manifest_digest=assessment.manifest_digest, case_a_id=case_a_id, case_b_id=case_b_id, binding_key=assessment.binding_key, status='ACTIVE', issued_at=u64(now), expires_at=u64(expires_at))
        self.active_certificate_by_binding[assessment.binding_key] = u256(certificate_id)
        assessment.certificate_id = u256(certificate_id)
        return certificate_id
