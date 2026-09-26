# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import hashlib
import json
from urllib.parse import urlsplit
from genlayer import *
MAX_IDENTIFIER_LENGTH = 64
MAX_ENDPOINT_URL_LENGTH = 512
MAX_POLICY_VERSION = 4294967295
ASSESSMENT_MAX_ATTEMPTS = 3

class AgentSealDeterministicSupport(gl.Contract):
    certificate_registry: Address

    def __init__(self, certificate_registry: Address):
        if certificate_registry == Address(b'\x00' * 20):
            raise gl.vm.UserError('CERTIFICATE_REGISTRY_ADDRESS_ZERO')
        self.certificate_registry = certificate_registry

    @gl.public.view
    def get_components(self) -> dict:
        return {'certificate_registry': self.certificate_registry.as_hex}

    def _policy(self, policy_id: str, policy_version: int) -> dict:
        return gl.get_contract_at(self.certificate_registry).view().get_policy(policy_id, policy_version)

    def _validate_identifier(self, value: str, label: str) -> None:
        if len(value) < 1 or len(value) > MAX_IDENTIFIER_LENGTH:
            raise gl.vm.UserError(label + '_LENGTH')
        allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        for char in value:
            if char not in allowed:
                raise gl.vm.UserError(label + '_FORMAT')

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

    def _validate_profile_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError('PROFILE_DIGEST_LENGTH')
        for char in value:
            if char not in '0123456789abcdef':
                raise gl.vm.UserError('PROFILE_DIGEST_FORMAT')

    def _binding_key(self, subject_wallet: Address, profile_digest: str, endpoint: str, policy: dict) -> str:
        material = json.dumps({'capability_id': policy['capability_id'], 'domain': 'agentseal-binding-v1', 'endpoint': endpoint, 'manifest_digest': policy['manifest_digest'], 'manifest_id': policy['manifest_id'], 'policy_id': policy['policy_id'], 'policy_version': int(policy['version']), 'profile_digest': profile_digest, 'subject_wallet': subject_wallet.as_hex.lower()}, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def _canonical_json(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    @gl.public.view
    def prepare_assessment_request(self, subject_wallet: Address, profile_digest: str, endpoint: str, policy_id: str, policy_version: int, requested_certificate_ttl: int, now: int) -> dict:
        self._validate_profile_digest(profile_digest)
        self._validate_assessment_endpoint(endpoint)
        self._validate_identifier(policy_id, 'POLICY_ID')
        if policy_version < 1 or policy_version > MAX_POLICY_VERSION:
            raise gl.vm.UserError('POLICY_VERSION_RANGE')
        policy = self._policy(policy_id, policy_version)
        if not bool(policy['active']):
            raise gl.vm.UserError('POLICY_INACTIVE')
        if now >= int(policy['valid_until']):
            raise gl.vm.UserError('POLICY_EXPIRED')
        if requested_certificate_ttl < 1 or requested_certificate_ttl > int(policy['max_certificate_ttl']):
            raise gl.vm.UserError('CERTIFICATE_TTL_POLICY_RANGE')
        return {'binding_key': self._binding_key(subject_wallet, profile_digest, endpoint, policy), 'capability_id': policy['capability_id'], 'policy_id': policy['policy_id'], 'policy_version': int(policy['version']), 'manifest_id': policy['manifest_id'], 'manifest_digest': policy['manifest_digest'], 'valid_until': int(policy['valid_until'])}

    def _validated_assessment_policy(self, policy_id: str, policy_version: int, capability_id: str, manifest_id: str, manifest_digest: str) -> dict:
        policy = self._policy(policy_id, policy_version)
        if policy['capability_id'] != capability_id or policy['policy_id'] != policy_id or int(policy['version']) != policy_version or (policy['manifest_id'] != manifest_id) or (policy['manifest_digest'] != manifest_digest):
            raise gl.vm.UserError('ASSESSMENT_POLICY_SNAPSHOT_MISMATCH')
        return policy

    @gl.public.view
    def assessment_policy_context(self, policy_id: str, policy_version: int, capability_id: str, manifest_id: str, manifest_digest: str, now: int) -> dict:
        policy = self._validated_assessment_policy(policy_id, policy_version, capability_id, manifest_id, manifest_digest)
        if now >= int(policy['valid_until']):
            raise gl.vm.UserError('POLICY_EXPIRED')
        return policy

    @gl.public.view
    def assessment_result_context(self, policy_id: str, policy_version: int, capability_id: str, manifest_id: str, manifest_digest: str, now: int, verdict: str, assessment_id: int, subject_wallet: Address, profile_digest: str, endpoint: str, requested_certificate_ttl: int, binding_key: str, case_a_id: str, case_b_id: str) -> dict:
        policy = self._validated_assessment_policy(policy_id, policy_version, capability_id, manifest_id, manifest_digest)
        if now >= int(policy['valid_until']):
            return {'state': 'EXPIRED', 'payload': ''}
        if verdict != 'PASS':
            return {'state': 'OK', 'payload': ''}
        expires_at = now + requested_certificate_ttl
        if expires_at > int(policy['valid_until']):
            expires_at = int(policy['valid_until'])
        payload = self._canonical_json({'certificate_id': assessment_id, 'assessment_id': assessment_id, 'subject_wallet': subject_wallet.as_hex.lower(), 'profile_digest': profile_digest, 'endpoint': endpoint, 'capability_id': capability_id, 'policy_id': policy_id, 'policy_version': policy_version, 'manifest_id': manifest_id, 'manifest_digest': manifest_digest, 'case_a_id': case_a_id, 'case_b_id': case_b_id, 'binding_key': binding_key, 'issued_at': now, 'expires_at': expires_at})
        return {'state': 'OK', 'payload': payload}

    @gl.public.view
    def challenge_open_context(self, certificate_id: int) -> dict:
        registry = gl.get_contract_at(self.certificate_registry)
        if bool(registry.view().revocation_exists(certificate_id)):
            raise gl.vm.UserError('REVOCATION_RECORD_CONFLICT')
        certificate = registry.view().get_certificate(certificate_id)
        if certificate['status'] != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_NOT_ACTIVE')
        if certificate['effective_status'] != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_EXPIRED')
        if int(registry.view().get_active_certificate_id(certificate['binding_key'])) != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        return certificate

    @gl.public.view
    def challenge_evaluation_context(self, certificate_id: int, binding_key: str, policy_id: str, policy_version: int, manifest_id: str, manifest_digest: str, challenge_id: int, challenger: Address, status: str, created_at: int, deadline: int, attempt_count: int, max_attempt_count: int, last_verdict: str, case_a_id: str, case_b_id: str) -> dict:
        registry = gl.get_contract_at(self.certificate_registry)
        if bool(registry.view().revocation_exists(certificate_id)):
            return {'state': 'REVOKED', 'snapshot': ''}
        certificate = registry.view().get_certificate(certificate_id)
        if certificate['status'] != 'ACTIVE' or certificate['effective_status'] != 'ACTIVE':
            raise gl.vm.UserError('CERTIFICATE_NOT_ACTIVE')
        if binding_key != certificate['binding_key'] or policy_id != certificate['policy_id'] or policy_version != int(certificate['policy_version']) or (manifest_id != certificate['manifest_id']) or (manifest_digest != certificate['manifest_digest']):
            raise gl.vm.UserError('CHALLENGE_CERTIFICATE_SNAPSHOT_MISMATCH')
        if int(registry.view().get_active_certificate_id(binding_key)) != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        policy = registry.view().get_policy(certificate['policy_id'], int(certificate['policy_version']))
        if policy['capability_id'] != certificate['capability_id'] or policy['policy_id'] != certificate['policy_id'] or int(policy['version']) != int(certificate['policy_version']) or (policy['manifest_id'] != certificate['manifest_id']) or (policy['manifest_digest'] != certificate['manifest_digest']):
            raise gl.vm.UserError('CHALLENGE_POLICY_SNAPSHOT_MISMATCH')
        challenge = {'challenge_id': challenge_id, 'certificate_id': certificate_id, 'challenger': challenger.as_hex.lower(), 'binding_key': binding_key, 'policy_id': policy_id, 'policy_version': policy_version, 'manifest_id': manifest_id, 'manifest_digest': manifest_digest, 'status': status, 'created_at': created_at, 'deadline': deadline, 'attempt_count': attempt_count, 'max_attempt_count': max_attempt_count, 'last_verdict': last_verdict, 'case_a_id': case_a_id, 'case_b_id': case_b_id}
        snapshot = self._canonical_json({'policy': policy, 'certificate': certificate, 'challenge': challenge})
        return {'state': 'OK', 'snapshot': snapshot}

    @gl.public.view
    def challenge_apply_state(self, certificate_id: int, binding_key: str) -> str:
        registry = gl.get_contract_at(self.certificate_registry)
        if bool(registry.view().revocation_exists(certificate_id)):
            return 'REVOKED'
        certificate = registry.view().get_certificate(certificate_id)
        if certificate['status'] != 'ACTIVE' or certificate['effective_status'] != 'ACTIVE':
            return 'INACTIVE'
        if int(registry.view().get_active_certificate_id(binding_key)) != certificate_id:
            raise gl.vm.UserError('ACTIVE_CERTIFICATE_INDEX_CORRUPT')
        return 'OK'

    @gl.public.view
    def challenge_revocation_state(self, certificate_id: int, challenge_id: int, binding_key: str) -> str:
        registry = gl.get_contract_at(self.certificate_registry)
        if not bool(registry.view().revocation_exists(certificate_id)):
            return 'MISSING'
        revocation = registry.view().get_revocation(certificate_id)
        if revocation['source'] != 'CHALLENGE_CONSENSUS' or int(revocation['challenge_id']) != challenge_id or revocation['binding_key'] != binding_key:
            raise gl.vm.UserError('REVOCATION_RECORD_CONFLICT')
        return 'MATCH'

    @gl.public.view
    def prepare_challenge_evidence(self, snapshot_json: str, attempt_number: int, chain_id: int, registry_address: Address) -> str:
        try:
            snapshot = json.loads(snapshot_json)
        except Exception as exc:
            raise gl.vm.UserError('CHALLENGE_SNAPSHOT_INVALID') from exc
        if type(snapshot) is not dict or set(snapshot.keys()) != {'policy', 'certificate', 'challenge'}:
            raise gl.vm.UserError('CHALLENGE_SNAPSHOT_INVALID')
        try:
            p = snapshot['policy']
            c = snapshot['certificate']
            h = snapshot['challenge']
            challenge_id = int(h['challenge_id'])
            attempt_count = int(h['attempt_count'])
        except Exception as exc:
            raise gl.vm.UserError('CHALLENGE_SNAPSHOT_INVALID') from exc
        if attempt_number != attempt_count + 1:
            raise gl.vm.UserError('CHALLENGE_ATTEMPT_MISMATCH')
        if challenge_id < 1 or attempt_number < 1 or attempt_number > ASSESSMENT_MAX_ATTEMPTS:
            return self._canonical_json({'forced': True, 'challenge_id': challenge_id})
        try:
            relationship_ok = int(h['certificate_id']) == int(c['certificate_id']) and h['binding_key'] == c['binding_key'] and (h['policy_id'] == c['policy_id']) and (int(h['policy_version']) == int(c['policy_version'])) and (h['manifest_id'] == c['manifest_id']) and (h['manifest_digest'] == c['manifest_digest']) and (p['policy_id'] == c['policy_id']) and (int(p['version']) == int(c['policy_version'])) and (p['manifest_id'] == c['manifest_id']) and (p['manifest_digest'] == c['manifest_digest'])
            if not relationship_ok:
                return self._canonical_json({'forced': True, 'challenge_id': challenge_id})
            assessment = {'assessment_id': int(c['assessment_id']), 'subject_wallet': c['subject_wallet'], 'profile_digest': c['profile_digest'], 'endpoint': c['endpoint'], 'capability_id': c['capability_id'], 'policy_id': c['policy_id'], 'policy_version': int(c['policy_version']), 'manifest_id': c['manifest_id'], 'manifest_digest': c['manifest_digest'], 'requested_certificate_ttl': 0, 'binding_key': c['binding_key'], 'status': 'PASSED', 'created_at': int(c['issued_at']), 'deadline': int(c['expires_at']), 'attempt_count': 0, 'max_attempt_count': ASSESSMENT_MAX_ATTEMPTS, 'last_verdict': 'PASS', 'case_a_id': c['case_a_id'], 'case_b_id': c['case_b_id'], 'certificate_id': int(c['certificate_id'])}
            selection_material = self._canonical_json({'binding_key': c['binding_key'], 'capability_id': c['capability_id'], 'certificate_id': int(c['certificate_id']), 'chain_id': int(chain_id), 'challenge_id': challenge_id, 'contract_address': registry_address.as_hex.lower(), 'domain': 'agentseal-challenge-selection-v1', 'endpoint': c['endpoint'], 'manifest_digest': c['manifest_digest'], 'manifest_id': c['manifest_id'], 'policy_id': c['policy_id'], 'policy_version': int(c['policy_version']), 'profile_digest': c['profile_digest'], 'subject_wallet': c['subject_wallet']})
            evaluation_id = 'agentseal-challenge-v1:' + str(int(chain_id)) + ':' + registry_address.as_hex.lower() + ':' + str(challenge_id) + ':' + str(attempt_number)
            return self._canonical_json({'forced': False, 'challenge_id': challenge_id, 'policy': p, 'assessment': assessment, 'manifest_digest': c['manifest_digest'], 'endpoint': c['endpoint'], 'selection_material': selection_material, 'evaluation_id': evaluation_id})
        except Exception as exc:
            raise gl.vm.UserError('CHALLENGE_SNAPSHOT_INVALID') from exc
