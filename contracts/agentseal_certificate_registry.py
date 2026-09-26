# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from genlayer import *

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

class AgentSealCertificateRegistry(gl.Contract):
    owner: Address
    registry: Address
    policy_registry: Address
    challenge_contract: Address
    certificates: TreeMap[str, CertificateRecord]
    active_certificate_by_binding: TreeMap[str, u256]
    revocations: TreeMap[str, RevocationRecord]

    def __init__(self, registry: Address, policy_registry: Address):
        if registry == Address(b'\x00' * 20) or policy_registry == Address(b'\x00' * 20):
            raise gl.vm.UserError('COMPONENT_ADDRESS_ZERO')
        if registry == policy_registry:
            raise gl.vm.UserError('COMPONENT_ADDRESS_COLLISION')
        self.owner = gl.message.sender_address
        self.registry = registry
        self.policy_registry = policy_registry
        self.challenge_contract = Address(b'\x00' * 20)

    def _require_configured(self) -> None:
        if self.challenge_contract == Address(b'\x00' * 20):
            raise gl.vm.UserError('CHALLENGE_CONTRACT_NOT_CONFIGURED')

    @gl.public.write
    def configure_challenge(self, challenge_contract: Address) -> None:
        self._require_owner()
        if self.challenge_contract != Address(b'\x00' * 20):
            raise gl.vm.UserError('CHALLENGE_CONTRACT_ALREADY_CONFIGURED')
        if challenge_contract == Address(b'\x00' * 20) or challenge_contract == self.registry or challenge_contract == self.policy_registry or (challenge_contract == gl.message.contract_address):
            raise gl.vm.UserError('CHALLENGE_CONTRACT_ADDRESS_INVALID')
        self.challenge_contract = challenge_contract

    @gl.public.view
    def get_components(self) -> dict:
        return {'registry': self.registry.as_hex, 'policy_registry': self.policy_registry.as_hex, 'challenge_contract': self.challenge_contract.as_hex, 'configured': self.challenge_contract != Address(b'\x00' * 20)}

    @gl.public.view
    def get_owner(self) -> str:
        return self.owner.as_hex

    @gl.public.view
    def get_policy(self, policy_id: str, version: int) -> dict:
        return gl.get_contract_at(self.policy_registry).view().get_policy(policy_id, version)

    @gl.public.write
    def issue_certificate(self, payload_json: str) -> None:
        if gl.message.sender_address != self.registry:
            raise gl.vm.UserError('REGISTRY_REQUIRED')
        try:
            p = json.loads(payload_json)
            expected = {'certificate_id', 'assessment_id', 'subject_wallet', 'profile_digest', 'endpoint', 'capability_id', 'policy_id', 'policy_version', 'manifest_id', 'manifest_digest', 'case_a_id', 'case_b_id', 'binding_key', 'issued_at', 'expires_at'}
            if type(p) is not dict or set(p.keys()) != expected:
                raise gl.vm.UserError('shape')
            certificate_id = int(p['certificate_id'])
            assessment_id = int(p['assessment_id'])
            policy_version = int(p['policy_version'])
            issued_at = int(p['issued_at'])
            expires_at = int(p['expires_at'])
            subject_wallet = Address(p['subject_wallet'])
            if certificate_id < 1 or assessment_id != certificate_id:
                raise gl.vm.UserError('id')
            if issued_at < 1 or expires_at <= issued_at:
                raise gl.vm.UserError('time')
        except Exception as exc:
            raise gl.vm.UserError('CERTIFICATE_PAYLOAD_INVALID') from exc
        key = self._certificate_key(certificate_id)
        if key in self.certificates:
            existing = self.certificates[key]
            if int(existing.assessment_id) != assessment_id or existing.subject_wallet != subject_wallet or existing.profile_digest != p['profile_digest'] or (existing.endpoint != p['endpoint']) or (existing.capability_id != p['capability_id']) or (existing.policy_id != p['policy_id']) or (int(existing.policy_version) != policy_version) or (existing.manifest_id != p['manifest_id']) or (existing.manifest_digest != p['manifest_digest']) or (existing.case_a_id != p['case_a_id']) or (existing.case_b_id != p['case_b_id']) or (existing.binding_key != p['binding_key']) or (int(existing.issued_at) != issued_at) or (int(existing.expires_at) != expires_at):
                raise gl.vm.UserError('CERTIFICATE_RECORD_CONFLICT')
            gl.get_contract_at(self.registry).emit(on='finalized').acknowledge_certificate_issuance(assessment_id, certificate_id, existing.binding_key)
            return
        now = self._now()
        self._reconcile_active_certificate(p['binding_key'], now)
        status = 'ACTIVE' if now < expires_at else 'EXPIRED'
        self.certificates[key] = CertificateRecord(certificate_id=u256(certificate_id), assessment_id=u256(assessment_id), subject_wallet=subject_wallet, profile_digest=p['profile_digest'], endpoint=p['endpoint'], capability_id=p['capability_id'], policy_id=p['policy_id'], policy_version=u64(policy_version), manifest_id=p['manifest_id'], manifest_digest=p['manifest_digest'], case_a_id=p['case_a_id'], case_b_id=p['case_b_id'], binding_key=p['binding_key'], status=status, issued_at=u64(issued_at), expires_at=u64(expires_at))
        if status == 'ACTIVE':
            self.active_certificate_by_binding[p['binding_key']] = u256(certificate_id)
        else:
            self.active_certificate_by_binding[p['binding_key']] = u256(0)
        gl.get_contract_at(self.registry).emit(on='finalized').acknowledge_certificate_issuance(assessment_id, certificate_id, p['binding_key'])

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError('OWNER_REQUIRED')

    def _certificate_key(self, certificate_id: int) -> str:
        return str(certificate_id)

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
    def revocation_exists(self, certificate_id: int) -> bool:
        return self._revocation_key(certificate_id) in self.revocations

    @gl.public.view
    def get_revocation(self, certificate_id: int) -> dict:
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key not in self.revocations:
            raise gl.vm.UserError('REVOCATION_NOT_FOUND')
        revocation = self.revocations[revocation_key]
        return {'certificate_id': int(revocation.certificate_id), 'source': revocation.source, 'initiator': revocation.initiator.as_hex, 'challenge_id': int(revocation.challenge_id), 'binding_key': revocation.binding_key, 'revoked_at': int(revocation.revoked_at)}

    @gl.public.write
    def revoke_certificate(self, certificate_id: int) -> None:
        self._require_configured()
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key not in self.certificates:
            raise gl.vm.UserError('CERTIFICATE_NOT_FOUND')
        certificate = self.certificates[certificate_key]
        if certificate.status != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_NOT_ACTIVE')
        now = self._now()
        if now >= int(certificate.expires_at):
            raise gl.vm.UserError('CERTIFICATE_EXPIRED')
        if int(self.active_certificate_by_binding.get(certificate.binding_key) or 0) != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        caller = gl.message.sender_address
        if caller != certificate.subject_wallet and caller != self.owner:
            raise gl.vm.UserError('REVOCATION_NOT_AUTHORIZED')
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key in self.revocations:
            raise gl.vm.UserError('REVOCATION_ALREADY_EXISTS')
        challenge_state = gl.get_contract_at(self.challenge_contract).view().get_blocking_challenge_state(certificate_id)
        challenge_id = int(challenge_state['challenge_id'])
        challenge_status = challenge_state['status']
        if challenge_status == 'UPHELD' and bool(challenge_state['revocation_delivery_pending']):
            raise gl.vm.UserError('CHALLENGE_REVOCATION_PENDING')
        source = 'SUBJECT_SELF_REVOKE' if caller == certificate.subject_wallet else 'OWNER_AUTHORITY_REVOKE'
        self._record_certificate_revocation(certificate, now, source, caller, challenge_id)
        if challenge_id != 0 and challenge_status == 'PENDING':
            gl.get_contract_at(self.challenge_contract).emit(on='finalized').cancel_for_direct_revocation(certificate_id, challenge_id)

    @gl.public.write
    def apply_challenge_revocation(self, certificate_id: int, challenge_id: int, initiator: Address, binding_key: str) -> None:
        if gl.message.sender_address != self.challenge_contract:
            raise gl.vm.UserError('CHALLENGE_CONTRACT_REQUIRED')
        revocation_key = self._revocation_key(certificate_id)
        if revocation_key in self.revocations:
            existing = self.revocations[revocation_key]
            if existing.source != 'CHALLENGE_CONSENSUS' or int(existing.challenge_id) != challenge_id or existing.binding_key != binding_key:
                raise gl.vm.UserError('REVOCATION_RECORD_CONFLICT')
            gl.get_contract_at(self.challenge_contract).emit(on='finalized').acknowledge_revocation(challenge_id, certificate_id)
            return
        certificate_key = self._certificate_key(certificate_id)
        if certificate_key not in self.certificates:
            raise gl.vm.UserError('CERTIFICATE_NOT_FOUND')
        certificate = self.certificates[certificate_key]
        if certificate.status != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_NOT_ACTIVE')
        if certificate.binding_key != binding_key:
            raise gl.vm.UserError('CHALLENGE_REVOCATION_BINDING_MISMATCH')
        if int(self.active_certificate_by_binding.get(binding_key) or 0) != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        self._record_certificate_revocation(certificate, self._now(), 'CHALLENGE_CONSENSUS', initiator, challenge_id)
        gl.get_contract_at(self.challenge_contract).emit(on='finalized').acknowledge_revocation(challenge_id, certificate_id)
