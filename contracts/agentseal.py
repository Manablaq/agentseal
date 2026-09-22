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


class AgentSeal(gl.Contract):
    owner: Address
    policy_count: u256
    policies: TreeMap[str, PolicyRecord]
    assessment_count: u256
    assessments: TreeMap[str, AssessmentRecord]
    live_assessment_by_binding: TreeMap[str, u256]
    certificates: TreeMap[str, CertificateRecord]
    active_certificate_by_binding: TreeMap[str, u256]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.policy_count = u256(0)
        self.assessment_count = u256(0)

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("OWNER_REQUIRED")

    def _validate_identifier(self, value: str, label: str) -> None:
        if len(value) < 1 or len(value) > MAX_IDENTIFIER_LENGTH:
            raise gl.vm.UserError(label + "_LENGTH")

        allowed = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789-_"
        )

        for char in value:
            if char not in allowed:
                raise gl.vm.UserError(label + "_FORMAT")

    def _validate_manifest_url(self, value: str) -> None:
        if len(value) < 9 or len(value) > MAX_MANIFEST_URL_LENGTH:
            raise gl.vm.UserError("MANIFEST_URL_LENGTH")

        if (
            " " in value
            or "\n" in value
            or "\r" in value
            or "\t" in value
        ):
            raise gl.vm.UserError("MANIFEST_URL_WHITESPACE")

        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise gl.vm.UserError("MANIFEST_URL_FORMAT")

        if parsed.scheme != "https":
            raise gl.vm.UserError("MANIFEST_URL_HTTPS_REQUIRED")

        if not parsed.netloc or parsed.hostname is None:
            raise gl.vm.UserError("MANIFEST_URL_HOST_REQUIRED")

        if parsed.fragment:
            raise gl.vm.UserError("MANIFEST_URL_FRAGMENT_FORBIDDEN")

        if parsed.username is not None or parsed.password is not None:
            raise gl.vm.UserError("MANIFEST_URL_CREDENTIALS_FORBIDDEN")

        if port is not None:
            raise gl.vm.UserError("MANIFEST_URL_PORT_FORBIDDEN")

        host = parsed.hostname

        if parsed.netloc != host:
            raise gl.vm.UserError("MANIFEST_URL_HOST_NOT_CANONICAL")

        if len(host) > 253 or host.startswith(".") or host.endswith("."):
            raise gl.vm.UserError("MANIFEST_URL_HOST_FORMAT")

        if (
            host == "localhost"
            or host.endswith(".localhost")
            or host.endswith(".local")
            or host.endswith(".internal")
            or host == "home.arpa"
            or host.endswith(".home.arpa")
        ):
            raise gl.vm.UserError("MANIFEST_URL_LOCAL_HOST_FORBIDDEN")

        if ":" in host or host.replace(".", "").isdigit():
            raise gl.vm.UserError("MANIFEST_URL_IP_LITERAL_FORBIDDEN")

        labels = host.split(".")

        if len(labels) < 2:
            raise gl.vm.UserError("MANIFEST_URL_PUBLIC_HOST_REQUIRED")

        allowed = "abcdefghijklmnopqrstuvwxyz0123456789-"

        for label in labels:
            if len(label) < 1 or len(label) > 63:
                raise gl.vm.UserError("MANIFEST_URL_HOST_FORMAT")

            if label.startswith("-") or label.endswith("-"):
                raise gl.vm.UserError("MANIFEST_URL_HOST_FORMAT")

            for char in label:
                if char not in allowed:
                    raise gl.vm.UserError("MANIFEST_URL_HOST_FORMAT")

    def _validate_assessment_endpoint(self, value: str) -> None:
        if len(value) < 9 or len(value) > MAX_ENDPOINT_URL_LENGTH:
            raise gl.vm.UserError("ENDPOINT_LENGTH")

        if (
            " " in value
            or "\n" in value
            or "\r" in value
            or "\t" in value
        ):
            raise gl.vm.UserError("ENDPOINT_WHITESPACE")

        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise gl.vm.UserError("ENDPOINT_FORMAT")

        if parsed.scheme != "https":
            raise gl.vm.UserError("ENDPOINT_HTTPS_REQUIRED")

        if not parsed.netloc or parsed.hostname is None:
            raise gl.vm.UserError("ENDPOINT_HOST_REQUIRED")

        if parsed.fragment:
            raise gl.vm.UserError("ENDPOINT_FRAGMENT_FORBIDDEN")

        if parsed.username is not None or parsed.password is not None:
            raise gl.vm.UserError("ENDPOINT_CREDENTIALS_FORBIDDEN")

        if port is not None:
            raise gl.vm.UserError("ENDPOINT_PORT_FORBIDDEN")

        host = parsed.hostname

        if parsed.netloc != host:
            raise gl.vm.UserError("ENDPOINT_HOST_NOT_CANONICAL")

        if len(host) > 253 or host.startswith(".") or host.endswith("."):
            raise gl.vm.UserError("ENDPOINT_HOST_FORMAT")

        if (
            host == "localhost"
            or host.endswith(".localhost")
            or host.endswith(".local")
            or host.endswith(".internal")
            or host == "home.arpa"
            or host.endswith(".home.arpa")
        ):
            raise gl.vm.UserError("ENDPOINT_LOCAL_HOST_FORBIDDEN")

        if ":" in host or host.replace(".", "").isdigit():
            raise gl.vm.UserError("ENDPOINT_IP_LITERAL_FORBIDDEN")

        labels = host.split(".")

        if len(labels) < 2:
            raise gl.vm.UserError("ENDPOINT_PUBLIC_HOST_REQUIRED")

        allowed = "abcdefghijklmnopqrstuvwxyz0123456789-"

        for label in labels:
            if len(label) < 1 or len(label) > 63:
                raise gl.vm.UserError("ENDPOINT_HOST_FORMAT")

            if label.startswith("-") or label.endswith("-"):
                raise gl.vm.UserError("ENDPOINT_HOST_FORMAT")

            for char in label:
                if char not in allowed:
                    raise gl.vm.UserError("ENDPOINT_HOST_FORMAT")

    def _validate_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError("MANIFEST_DIGEST_LENGTH")

        for char in value:
            if char not in "0123456789abcdef":
                raise gl.vm.UserError("MANIFEST_DIGEST_FORMAT")

    def _validate_profile_digest(self, value: str) -> None:
        if len(value) != 64:
            raise gl.vm.UserError("PROFILE_DIGEST_LENGTH")

        for char in value:
            if char not in "0123456789abcdef":
                raise gl.vm.UserError("PROFILE_DIGEST_FORMAT")

    def _policy_key(self, policy_id: str, version: int) -> str:
        return policy_id + ":" + str(version)

    def _assessment_key(self, assessment_id: int) -> str:
        return str(assessment_id)

    def _certificate_key(self, certificate_id: int) -> str:
        return str(certificate_id)

    def _binding_key(
        self,
        subject_wallet: Address,
        profile_digest: str,
        endpoint: str,
        policy: PolicyRecord,
    ) -> str:
        material = json.dumps(
            {
                "capability_id": policy.capability_id,
                "domain": "agentseal-binding-v1",
                "endpoint": endpoint,
                "manifest_digest": policy.manifest_digest,
                "manifest_id": policy.manifest_id,
                "policy_id": policy.policy_id,
                "policy_version": int(policy.version),
                "profile_digest": profile_digest,
                "subject_wallet": subject_wallet.as_hex.lower(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _reconcile_live_assessment(
        self,
        binding_key: str,
        now: int,
    ) -> None:
        assessment_id = int(
            self.live_assessment_by_binding.get(binding_key) or 0
        )

        if assessment_id == 0:
            return

        key = self._assessment_key(assessment_id)

        if key not in self.assessments:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        assessment = self.assessments[key]

        if assessment.binding_key != binding_key:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        if assessment.status != "PENDING":
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        if now < int(assessment.deadline):
            raise gl.vm.UserError("LIVE_ASSESSMENT_EXISTS")

        assessment.status = "EXPIRED"
        self.live_assessment_by_binding[binding_key] = u256(0)

    def _reconcile_active_certificate(
        self,
        binding_key: str,
        now: int,
    ) -> None:
        certificate_id = int(
            self.active_certificate_by_binding.get(binding_key) or 0
        )

        if certificate_id == 0:
            return

        key = self._certificate_key(certificate_id)

        if key not in self.certificates:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")

        certificate = self.certificates[key]

        if certificate.binding_key != binding_key:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")

        if certificate.status == "ACTIVE":
            if now < int(certificate.expires_at):
                raise gl.vm.UserError("ACTIVE_CERTIFICATE_EXISTS")

            certificate.status = "EXPIRED"
            self.active_certificate_by_binding[binding_key] = u256(0)
            return

        if (
            certificate.status == "EXPIRED"
            or certificate.status == "REVOKED"
        ):
            self.active_certificate_by_binding[binding_key] = u256(0)
            return

        raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")

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
            raise gl.vm.UserError("POLICY_NOT_FOUND")

        policy = self.policies[key]

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
            raise gl.vm.UserError("ASSESSMENT_NOT_FOUND")

        assessment = self.assessments[key]
        effective_status = assessment.status

        if (
            assessment.status == "PENDING"
            and self._now() >= int(assessment.deadline)
        ):
            effective_status = "EXPIRED"

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
            "requested_certificate_ttl": int(
                assessment.requested_certificate_ttl
            ),
            "binding_key": assessment.binding_key,
            "status": assessment.status,
            "effective_status": effective_status,
            "created_at": int(assessment.created_at),
            "deadline": int(assessment.deadline),
            "attempt_count": int(assessment.attempt_count),
            "max_attempt_count": int(assessment.max_attempt_count),
            "last_verdict": assessment.last_verdict,
            "case_a_id": assessment.case_a_id,
            "case_b_id": assessment.case_b_id,
            "certificate_id": int(assessment.certificate_id),
        }

    @gl.public.view
    def get_live_assessment_id(self, binding_key: str) -> int:
        assessment_id = int(
            self.live_assessment_by_binding.get(binding_key) or 0
        )

        if assessment_id == 0:
            return 0

        key = self._assessment_key(assessment_id)

        if key not in self.assessments:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        assessment = self.assessments[key]

        if assessment.binding_key != binding_key:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        if assessment.status != "PENDING":
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
            raise gl.vm.UserError("CERTIFICATE_NOT_FOUND")

        certificate = self.certificates[key]
        effective_status = certificate.status

        if (
            certificate.status == "ACTIVE"
            and self._now() >= int(certificate.expires_at)
        ):
            effective_status = "EXPIRED"

        return {
            "certificate_id": int(certificate.certificate_id),
            "assessment_id": int(certificate.assessment_id),
            "subject_wallet": certificate.subject_wallet.as_hex.lower(),
            "profile_digest": certificate.profile_digest,
            "endpoint": certificate.endpoint,
            "capability_id": certificate.capability_id,
            "policy_id": certificate.policy_id,
            "policy_version": int(certificate.policy_version),
            "manifest_id": certificate.manifest_id,
            "manifest_digest": certificate.manifest_digest,
            "case_a_id": certificate.case_a_id,
            "case_b_id": certificate.case_b_id,
            "binding_key": certificate.binding_key,
            "status": certificate.status,
            "effective_status": effective_status,
            "issued_at": int(certificate.issued_at),
            "expires_at": int(certificate.expires_at),
        }

    @gl.public.view
    def get_active_certificate_id(self, binding_key: str) -> int:
        certificate_id = int(
            self.active_certificate_by_binding.get(binding_key) or 0
        )

        if certificate_id == 0:
            return 0

        key = self._certificate_key(certificate_id)

        if key not in self.certificates:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")

        certificate = self.certificates[key]

        if certificate.binding_key != binding_key:
            raise gl.vm.UserError("ACTIVE_CERTIFICATE_INDEX_CORRUPT")

        if certificate.status != "ACTIVE":
            return 0

        if self._now() >= int(certificate.expires_at):
            return 0

        return certificate_id

    @gl.public.write
    def create_policy(
        self,
        policy_id: str,
        capability_id: str,
        version: int,
        criteria: str,
        manifest_url: str,
        manifest_id: str,
        manifest_authority: str,
        manifest_digest: str,
        valid_until: int,
        max_certificate_ttl: int,
    ) -> None:
        self._require_owner()

        self._validate_identifier(policy_id, "POLICY_ID")
        self._validate_identifier(capability_id, "CAPABILITY_ID")
        self._validate_identifier(manifest_id, "MANIFEST_ID")

        if version < 1 or version > MAX_POLICY_VERSION:
            raise gl.vm.UserError("POLICY_VERSION_RANGE")

        if len(criteria) < 1 or len(criteria) > MAX_CRITERIA_LENGTH:
            raise gl.vm.UserError("CRITERIA_LENGTH")

        if (
            len(manifest_authority) < 1
            or len(manifest_authority) > MAX_AUTHORITY_LENGTH
        ):
            raise gl.vm.UserError("MANIFEST_AUTHORITY_LENGTH")

        self._validate_manifest_url(manifest_url)
        self._validate_digest(manifest_digest)

        now = self._now()

        if valid_until <= now:
            raise gl.vm.UserError("POLICY_ALREADY_EXPIRED")

        if valid_until - now > MAX_POLICY_VALIDITY_SECONDS:
            raise gl.vm.UserError("POLICY_VALIDITY_TOO_LONG")

        if (
            max_certificate_ttl < 1
            or max_certificate_ttl > MAX_CERTIFICATE_TTL_SECONDS
        ):
            raise gl.vm.UserError("CERTIFICATE_TTL_RANGE")

        key = self._policy_key(policy_id, version)

        if key in self.policies:
            raise gl.vm.UserError("POLICY_VERSION_EXISTS")

        self.policies[key] = PolicyRecord(
            policy_id=policy_id,
            capability_id=capability_id,
            version=u64(version),
            criteria=criteria,
            manifest_url=manifest_url,
            manifest_id=manifest_id,
            manifest_authority=manifest_authority,
            manifest_digest=manifest_digest,
            valid_until=u64(valid_until),
            max_certificate_ttl=u64(max_certificate_ttl),
            active=True,
            created_at=u64(now),
        )

        self.policy_count = u256(int(self.policy_count) + 1)

    @gl.public.write
    def disable_policy(self, policy_id: str, version: int) -> None:
        self._require_owner()

        key = self._policy_key(policy_id, version)

        if key not in self.policies:
            raise gl.vm.UserError("POLICY_NOT_FOUND")

        policy = self.policies[key]

        if not policy.active:
            raise gl.vm.UserError("POLICY_ALREADY_DISABLED")

        policy.active = False

    @gl.public.write
    def create_assessment(
        self,
        profile_digest: str,
        endpoint: str,
        policy_id: str,
        policy_version: int,
        requested_certificate_ttl: int,
    ) -> int:
        self._validate_profile_digest(profile_digest)
        self._validate_assessment_endpoint(endpoint)
        self._validate_identifier(policy_id, "POLICY_ID")

        if policy_version < 1 or policy_version > MAX_POLICY_VERSION:
            raise gl.vm.UserError("POLICY_VERSION_RANGE")

        policy_key = self._policy_key(policy_id, policy_version)

        if policy_key not in self.policies:
            raise gl.vm.UserError("POLICY_NOT_FOUND")

        policy = self.policies[policy_key]
        now = self._now()

        if not policy.active:
            raise gl.vm.UserError("POLICY_INACTIVE")

        if now >= int(policy.valid_until):
            raise gl.vm.UserError("POLICY_EXPIRED")

        if (
            requested_certificate_ttl < 1
            or requested_certificate_ttl > int(policy.max_certificate_ttl)
        ):
            raise gl.vm.UserError("CERTIFICATE_TTL_POLICY_RANGE")

        subject_wallet = gl.message.sender_address
        binding_key = self._binding_key(
            subject_wallet,
            profile_digest,
            endpoint,
            policy,
        )

        self._reconcile_active_certificate(binding_key, now)
        self._reconcile_live_assessment(binding_key, now)

        deadline = now + ASSESSMENT_WINDOW_SECONDS

        if deadline > int(policy.valid_until):
            deadline = int(policy.valid_until)

        assessment_id = int(self.assessment_count) + 1

        self.assessments[
            self._assessment_key(assessment_id)
        ] = AssessmentRecord(
            assessment_id=u256(assessment_id),
            subject_wallet=subject_wallet,
            profile_digest=profile_digest,
            endpoint=endpoint,
            capability_id=policy.capability_id,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            manifest_id=policy.manifest_id,
            manifest_digest=policy.manifest_digest,
            requested_certificate_ttl=u64(requested_certificate_ttl),
            binding_key=binding_key,
            status="PENDING",
            created_at=u64(now),
            deadline=u64(deadline),
            attempt_count=u64(0),
            max_attempt_count=u64(ASSESSMENT_MAX_ATTEMPTS),
            last_verdict="",
            case_a_id="",
            case_b_id="",
            certificate_id=u256(0),
        )

        self.live_assessment_by_binding[binding_key] = u256(assessment_id)
        self.assessment_count = u256(assessment_id)

        return assessment_id

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

        live_id = int(
            self.live_assessment_by_binding.get(
                assessment.binding_key
            ) or 0
        )

        if live_id != assessment_id:
            raise gl.vm.UserError("LIVE_ASSESSMENT_INDEX_CORRUPT")

        assessment.status = "EXPIRED"
        self.live_assessment_by_binding[assessment.binding_key] = u256(0)
