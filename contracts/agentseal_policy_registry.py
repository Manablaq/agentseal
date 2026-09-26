# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from genlayer import *
MAX_IDENTIFIER_LENGTH = 64
MAX_AUTHORITY_LENGTH = 128
MAX_MANIFEST_URL_LENGTH = 512
MAX_CRITERIA_LENGTH = 8192
MAX_POLICY_VALIDITY_SECONDS = 31536000
MAX_CERTIFICATE_TTL_SECONDS = 2592000
MAX_POLICY_VERSION = 4294967295

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

class AgentSealPolicyRegistry(gl.Contract):
    owner: Address
    policy_count: u256
    policies: TreeMap[str, PolicyRecord]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.policy_count = u256(0)

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

    def _validate_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError('MANIFEST_DIGEST_LENGTH')
        for char in value:
            if char not in '0123456789abcdef':
                raise gl.vm.UserError('MANIFEST_DIGEST_FORMAT')

    def _policy_key(self, policy_id: str, version: int) -> str:
        return policy_id + ':' + str(version)

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
