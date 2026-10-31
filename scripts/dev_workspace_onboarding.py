"""Pure first-administrator guidance from caller-supplied sanitized observations.

No database, runtime, credential, identity or application object is inspected here.
Public bindings and fingerprints detect drift; they never authorize enrollment.
The SBO-98 private mutation gate remains closed and is neither imported nor called.
Future enablement requires independently authenticated operator/runtime authority,
exact target/identity/action binding, expiry, single use and revocation checks at
the existing privileged child and mutation boundaries. A caller assertion cannot
provide that authority. Passwords belong only in the existing HTTPS activation UI.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

_CONTEXT_FIELDS = frozenset(
    {
        "repository_id",
        "worktree_id",
        "instance_id",
        "commit",
        "generation",
        "config_generation",
        "database_provider_id",
        "database_host",
        "database_port",
        "database_name",
        "schema_revision",
        "activation_origin",
        "auth_mode",
    }
)
_STATUS_FIELDS = frozenset(
    {
        "code",
        "state",
        "platform_admin_available",
        "enrollment_required",
        "existing_users_present",
        "bootstrap_enabled",
        "live_readiness_verified",
    }
)
_STATES = frozenset(
    {
        "EXISTING_ADMIN",
        "NOT_INITIALIZED",
        "ENROLLMENT_REQUIRED",
        "ENROLLMENT_PENDING",
        "ENROLLMENT_COMPLETED",
        "CONFLICT",
        "UNKNOWN",
        "HCL_APPROVAL_REQUIRED",
    }
)
_REQUIRED_IDENTITY_FIELDS = ("email", "first_name", "last_name", "phone", "operator_reference")
_GATE = "ENROLLMENT_READINESS_CONTRACT_REQUIRED"
_GUIDANCE = {
    "inspect-approved-installation": "Obtain an explicitly approved read-only inspection of the exact installation and schema; this planner performs none.",
    "review-prerequisite-plan": "Review the setup prerequisite plan. Database preparation, credentials and certificate trust need their separate approvals.",
    "review-native-prerequisites": "Before Native onboarding, obtain approved read-only validation of JWT signing and verification, the encrypted security-mail outbox, Redis, SMTP, background workers and verified HTTPS. None has been inspected by this guidance.",
    "inspect-native-administrator-status": "After exact database target and schema confirmation, obtain an approved read-only status inspection of existing users, effective Platform Administrator privileges and the Native bootstrap reservation. Preserve existing, pending and completed state; do not assume enrollment is required.",
    "use-existing-administrator": "Use the existing effective administrator through normal verified sign-in; do not create another or reset privileges.",
    "review-required-identity": "After independent authorization is approved, collect all required identity fields privately, including the approved operator reference.",
    "independent-authorization-required": "Live initial creation and resend remain blocked by the existing privileged gate pending independent runtime and operator authorization.",
    "pending-reservation-workflow": "The approved bootstrap service may create one pending reservation and encrypted activation outbox entry only after the existing gate is separately approved and enabled.",
    "preserve-pending-reservation": "Preserve the pending reservation; never create a duplicate. Inspect approved activation delivery before considering separately authorized resend or recovery.",
    "verified-https-activation": "After approved delivery, the human opens the activation link from the isolated approved mailbox in verified HTTPS and chooses a compliant password in that application page. Never enter it in chat, shell, planner input or logs.",
    "verify-effective-grant": "After normal activation, use an approved status check to verify the effective Platform Administrator grant and audit completion.",
    "disable-temporary-capability": "Retain the durable reservation and audit history and keep temporary creation capability disabled after completion.",
    "preserve-completed-reservation": "Initial enrollment is completed and cannot reopen, even if its original account is unavailable. Preserve history and request separately approved administrator recovery.",
    "operator-review-required": "Preserve current state and obtain operator review of the conflicting or unknown installation observation; no mutation or automatic retry is proposed.",
    "external-identity-approval": "Use the existing external-provider identity and administrator procedure only after Engineering Lead and IdP-owner approval; Native enrollment is not an external identity route.",
}
_STEPS = {
    "EXISTING_ADMIN": ("use-existing-administrator",),
    "NOT_INITIALIZED": ("review-prerequisite-plan",),
    "ENROLLMENT_REQUIRED": (
        "review-required-identity",
        "independent-authorization-required",
        "pending-reservation-workflow",
        "verified-https-activation",
        "verify-effective-grant",
        "disable-temporary-capability",
    ),
    "ENROLLMENT_PENDING": (
        "preserve-pending-reservation",
        "independent-authorization-required",
        "verified-https-activation",
        "verify-effective-grant",
        "disable-temporary-capability",
    ),
    "ENROLLMENT_COMPLETED": ("preserve-completed-reservation", "disable-temporary-capability"),
    "CONFLICT": ("operator-review-required",),
    "UNKNOWN": ("inspect-approved-installation", "operator-review-required"),
    "HCL_APPROVAL_REQUIRED": ("external-identity-approval",),
}
_CODES = {
    "EXISTING_ADMIN": {"ONBOARDING_EXISTING_ADMIN"},
    "NOT_INITIALIZED": {"ONBOARDING_PREREQUISITES_REQUIRED", "ONBOARDING_HTTPS_ACTIVATION_REQUIRED"},
    "ENROLLMENT_REQUIRED": {_GATE},
    "ENROLLMENT_PENDING": {"ONBOARDING_PENDING_RESERVATION_PRESERVED"},
    "ENROLLMENT_COMPLETED": {"ONBOARDING_COMPLETED_RESERVATION_PRESERVED"},
    "CONFLICT": {
        "ONBOARDING_CONTEXT_CHANGED",
        "ONBOARDING_SCHEMA_CHANGED",
        "ONBOARDING_EXTERNAL_NATIVE_STATUS_REFUSED",
        "ONBOARDING_STATUS_CONFLICT",
    },
    "UNKNOWN": {"ONBOARDING_INSPECTION_REQUIRED", "ONBOARDING_SCHEMA_UNVERIFIED", "ONBOARDING_RESERVATION_UNVERIFIED"},
    "HCL_APPROVAL_REQUIRED": {"HCL_OPERATOR_IDP_APPROVAL_REQUIRED"},
}


class OnboardingPlanError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise OnboardingPlanError(code) from None


def _public_id(value, *, uuid_only=False):
    if type(value) is not str:
        _fail("ONBOARDING_PUBLIC_ID_INVALID")
    if not uuid_only and re.fullmatch(r"[0-9a-f]{64}", value):
        return
    try:
        if str(UUID(value)) == value:
            return
    except ValueError:
        pass
    _fail("ONBOARDING_PUBLIC_ID_INVALID")


def _origin(value):
    if value is None:
        return
    if type(value) is not str or len(value) > 512:
        _fail("ONBOARDING_ACTIVATION_ORIGIN_INVALID")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            or parsed.port is not None
            and not 1 <= parsed.port <= 65535
            or value.rstrip("/") != "https://" + parsed.netloc
            or len(parsed.hostname) > 253
            or parsed.hostname != "::1"
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
                parsed.hostname,
            )
            is None
        ):
            raise ValueError()
    except ValueError:
        _fail("ONBOARDING_ACTIVATION_ORIGIN_INVALID")


@dataclass(frozen=True, slots=True, repr=False)
class OnboardingContext:
    repository_id: str
    worktree_id: str
    instance_id: str
    commit: str
    generation: int
    config_generation: str | int | None
    database_provider_id: str | None
    database_host: str | None
    database_port: int | None
    database_name: str | None
    schema_revision: str | None
    activation_origin: str | None
    auth_mode: str

    def __post_init__(self):
        _public_id(self.repository_id)
        _public_id(self.worktree_id)
        _public_id(self.instance_id, uuid_only=True)
        if type(self.commit) is not str or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.commit):
            _fail("ONBOARDING_COMMIT_INVALID")
        if type(self.generation) is not int or not 1 <= self.generation <= 2147483647:
            _fail("ONBOARDING_GENERATION_INVALID")
        if self.config_generation is not None:
            if type(self.config_generation) is int:
                if not 1 <= self.config_generation <= 2147483647:
                    _fail("ONBOARDING_CONFIG_GENERATION_INVALID")
            else:
                _public_id(self.config_generation)
        if self.database_provider_id is not None:
            _public_id(self.database_provider_id)
        if self.database_host is not None and (
            type(self.database_host) is not str or self.database_host not in {"127.0.0.1", "localhost", "::1"}
        ):
            _fail("ONBOARDING_DATABASE_TARGET_INVALID")
        if self.database_port is not None and (
            type(self.database_port) is not int or not 1 <= self.database_port <= 65535
        ):
            _fail("ONBOARDING_DATABASE_TARGET_INVALID")
        if self.database_name is not None and (
            type(self.database_name) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", self.database_name) is None
        ):
            _fail("ONBOARDING_DATABASE_TARGET_INVALID")
        if self.schema_revision is not None and (
            type(self.schema_revision) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_]{0,127}", self.schema_revision) is None
        ):
            _fail("ONBOARDING_SCHEMA_INVALID")
        _origin(self.activation_origin)
        if type(self.auth_mode) is not str or self.auth_mode not in {"native", "hcl"}:
            _fail("ONBOARDING_AUTH_MODE_INVALID")

    def __repr__(self):
        return "<OnboardingContext: public installation binding>"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != _CONTEXT_FIELDS:
            _fail("ONBOARDING_CONTEXT_FIELDS_INVALID")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PublicEnrollmentStatus:
    code: str
    state: str
    platform_admin_available: bool
    enrollment_required: bool
    existing_users_present: bool
    bootstrap_enabled: bool
    live_readiness_verified: bool = False

    def __post_init__(self):
        if type(self.code) is not str or self.code not in {
            "ADMIN_READY",
            "ENROLLMENT_REQUIRED",
            "PENDING_ACTIVATION",
            "BOOTSTRAP_RESERVED",
        }:
            _fail("ONBOARDING_STATUS_CODE_INVALID")
        if type(self.state) is not str or self.state not in {"NOT_STARTED", "PENDING", "COMPLETED", "UNKNOWN"}:
            _fail("ONBOARDING_RESERVATION_STATE_INVALID")
        for name in _STATUS_FIELDS - {"code", "state"}:
            if type(getattr(self, name)) is not bool:
                _fail("ONBOARDING_STATUS_BOOL_REQUIRED")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != _STATUS_FIELDS:
            _fail("ONBOARDING_STATUS_FIELDS_INVALID")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class OnboardingStep:
    code: str
    executable: bool = False

    def __post_init__(self):
        if type(self.code) is not str or self.code not in _GUIDANCE or self.executable is not False:
            _fail("ONBOARDING_ACTION_INVALID")

    @property
    def guidance(self):
        return _GUIDANCE[self.code]

    def to_dict(self):
        return {"code": self.code, "guidance": self.guidance, "executable": False}


@dataclass(frozen=True, slots=True)
class OnboardingOverview:
    """Static guidance, with no installation binding or observed readiness."""

    auth_mode: str

    def __post_init__(self):
        if type(self.auth_mode) is not str or self.auth_mode not in {"native", "hcl"}:
            _fail("ONBOARDING_AUTH_MODE_INVALID")

    @property
    def state(self):
        return "UNKNOWN" if self.auth_mode == "native" else "HCL_APPROVAL_REQUIRED"

    @property
    def code(self):
        return "ONBOARDING_INSPECTION_REQUIRED" if self.auth_mode == "native" else "HCL_OPERATOR_IDP_APPROVAL_REQUIRED"

    @property
    def inspection_performed(self):
        return False

    @property
    def live_enrollment_authorized(self):
        return False

    @property
    def required_identity_fields(self):
        return ()

    @property
    def steps(self):
        codes = (
            (
                "inspect-approved-installation",
                "review-prerequisite-plan",
                "review-native-prerequisites",
                "inspect-native-administrator-status",
                "independent-authorization-required",
            )
            if self.auth_mode == "native"
            else ("inspect-approved-installation", "external-identity-approval")
        )
        return tuple(OnboardingStep(code) for code in codes)

    def to_dict(self):
        return {
            "version": 1,
            "auth_mode": self.auth_mode,
            "state": self.state,
            "code": self.code,
            "inspection_performed": False,
            "live_enrollment_authorized": False,
            "live_gate": _GATE if self.auth_mode == "native" else "HCL_OPERATOR_IDP_APPROVAL_REQUIRED",
            "required_identity_fields": [],
            "steps": [step.to_dict() for step in self.steps],
            "guidance_only": True,
        }


def uninspected_guidance(auth_mode):
    """Return public next steps without inspecting or fabricating an installation."""
    return OnboardingOverview(auth_mode)


@dataclass(frozen=True, slots=True)
class OnboardingPlan:
    state: str
    code: str
    context: OnboardingContext = field(repr=False)
    fingerprint: str = field(repr=False)
    live_enrollment_authorized: bool = False

    def __post_init__(self):
        if (
            type(self.state) is not str
            or self.state not in _STATES
            or type(self.code) is not str
            or self.code not in _CODES[self.state]
        ):
            _fail("ONBOARDING_PLAN_INVALID")
        if (
            type(self.context) is not OnboardingContext
            or type(self.fingerprint) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.fingerprint) is None
        ):
            _fail("ONBOARDING_PLAN_INVALID")
        if self.live_enrollment_authorized is not False:
            _fail("ONBOARDING_LIVE_ENROLLMENT_GATED")
        if (self.context.auth_mode == "hcl" and self.state.startswith("ENROLLMENT_")) or (
            self.context.auth_mode == "native" and self.state == "HCL_APPROVAL_REQUIRED"
        ):
            _fail("ONBOARDING_AUTH_MODE_CONFLICT")

    @property
    def required_identity_fields(self):
        return _REQUIRED_IDENTITY_FIELDS if self.state == "ENROLLMENT_REQUIRED" else ()

    @property
    def steps(self):
        return tuple(OnboardingStep(code) for code in _STEPS[self.state])

    def to_dict(self):
        return {
            "version": 1,
            "state": self.state,
            "code": self.code,
            "context": self.context.to_dict(),
            "fingerprint": self.fingerprint,
            "required_identity_fields": list(self.required_identity_fields),
            "steps": [step.to_dict() for step in self.steps],
            "live_enrollment_authorized": False,
            "live_gate": _GATE if self.context.auth_mode == "native" else "HCL_OPERATOR_IDP_APPROVAL_REQUIRED",
            "observation_only": True,
        }


def _context(value):
    return value if type(value) is OnboardingContext else OnboardingContext.from_dict(value)


def _classify(expected, observed, status, schema_state):
    if observed is None:
        return "UNKNOWN", "ONBOARDING_INSPECTION_REQUIRED"
    # A missing schema is a prerequisite state, not a confirmed schema mismatch.
    for name in _CONTEXT_FIELDS - {"schema_revision"}:
        if getattr(expected, name) != getattr(observed, name):
            return "CONFLICT", "ONBOARDING_CONTEXT_CHANGED"
    if schema_state == "NOT_INITIALIZED" or any(
        getattr(observed, name) is None
        for name in (
            "config_generation",
            "database_provider_id",
            "database_host",
            "database_port",
            "database_name",
        )
    ):
        return "NOT_INITIALIZED", "ONBOARDING_PREREQUISITES_REQUIRED"
    if schema_state == "UNKNOWN":
        return "UNKNOWN", "ONBOARDING_SCHEMA_UNVERIFIED"
    if schema_state == "INCOMPATIBLE" or observed.schema_revision != expected.schema_revision:
        return "CONFLICT", "ONBOARDING_SCHEMA_CHANGED"
    if observed.schema_revision is None:
        return "NOT_INITIALIZED", "ONBOARDING_PREREQUISITES_REQUIRED"
    if expected.auth_mode == "hcl":
        if status is not None:
            return "CONFLICT", "ONBOARDING_EXTERNAL_NATIVE_STATUS_REFUSED"
        return "HCL_APPROVAL_REQUIRED", "HCL_OPERATOR_IDP_APPROVAL_REQUIRED"
    if observed.activation_origin is None:
        return "NOT_INITIALIZED", "ONBOARDING_HTTPS_ACTIVATION_REQUIRED"
    if status is None:
        return "UNKNOWN", "ONBOARDING_INSPECTION_REQUIRED"
    if status.state == "UNKNOWN":
        return "UNKNOWN", "ONBOARDING_RESERVATION_UNVERIFIED"
    consistent = (
        status.enrollment_required is (status.code == "ENROLLMENT_REQUIRED")
        and status.platform_admin_available is (status.code == "ADMIN_READY")
        and (not status.platform_admin_available or status.existing_users_present)
        and (status.state != "PENDING" or status.existing_users_present)
        and (status.code != "ENROLLMENT_REQUIRED" or status.state == "NOT_STARTED")
        and (status.code != "PENDING_ACTIVATION" or status.state == "PENDING")
        and (status.code != "BOOTSTRAP_RESERVED" or status.state == "COMPLETED")
    )
    if not consistent:
        return "CONFLICT", "ONBOARDING_STATUS_CONFLICT"
    if status.platform_admin_available:
        return "EXISTING_ADMIN", "ONBOARDING_EXISTING_ADMIN"
    if status.state == "COMPLETED":
        return "ENROLLMENT_COMPLETED", "ONBOARDING_COMPLETED_RESERVATION_PRESERVED"
    if status.state == "PENDING":
        return "ENROLLMENT_PENDING", "ONBOARDING_PENDING_RESERVATION_PRESERVED"
    return "ENROLLMENT_REQUIRED", _GATE


def plan_onboarding(*, expected_context, observed_context=None, status=None, schema_state="UNKNOWN"):
    """Classify public observations only; no inspection or mutation is performed."""
    expected = _context(expected_context)
    observed = None if observed_context is None else _context(observed_context)
    if type(schema_state) is not str or schema_state not in {"READY", "NOT_INITIALIZED", "INCOMPATIBLE", "UNKNOWN"}:
        _fail("ONBOARDING_SCHEMA_STATE_INVALID")
    public_status = (
        None
        if status is None
        else (status if type(status) is PublicEnrollmentStatus else PublicEnrollmentStatus.from_dict(status))
    )
    state, code = _classify(expected, observed, public_status, schema_state)
    public = [
        expected.to_dict(),
        observed.to_dict() if observed else None,
        public_status.to_dict() if public_status else None,
        schema_state,
        state,
        code,
    ]
    fingerprint = hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return OnboardingPlan(state, code, expected, fingerprint)


def revalidate_onboarding(plan, *, observed_context=None, status=None, schema_state="UNKNOWN"):
    """Reject drift, never convert a matching fingerprint into authorization."""
    if type(plan) is not OnboardingPlan:
        _fail("ONBOARDING_PLAN_INVALID")
    current = plan_onboarding(
        expected_context=plan.context, observed_context=observed_context, status=status, schema_state=schema_state
    )
    if not hmac.compare_digest(current.fingerprint, plan.fingerprint):
        _fail("ONBOARDING_PLAN_CHANGED")
    return current


if __name__ == "__main__":
    raise SystemExit("ONBOARDING_GUIDANCE_ONLY: use the unified developer launcher; live enrollment is blocked.")
