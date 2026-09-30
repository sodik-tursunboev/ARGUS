'ARGUS - Dynamic agents: the specification.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import dataclasses
import enum
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass

from agents.definitions import CONTEXT_CATEGORIES
from agents.jobs import MAX_HANDOFFS as _JOBS_MAX_HANDOFFS

# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
MAX_SPAWN_DEPTH = 2              # core=0 -> child=1 -> grandchild=2 -> stop
MAX_CHILDREN_PER_AGENT = 3       # per parent, concurrently live
MAX_ACTIVE_EPHEMERAL_AGENTS = 6  # across the whole system
DEFAULT_AGENT_TTL = 1200         # seconds (20 min)
MAX_AGENT_TTL = 1800             # seconds (30 min)
MIN_AGENT_TTL = 60               # a shorter life is not a useful specialist
MAX_HANDOFFS = _JOBS_MAX_HANDOFFS    # 3; one number, agents/jobs.py owns it
DEFAULT_MODEL_CALLS = 3
MAX_MODEL_CALLS = 5              # hard ceiling on inferences one agent may use


# "Cloud can think. Cloud cannot control." Separate, stricter limits from the
# local ones above -- a cloud agent is data leaving the machine, not just a
# second local worker, so it starts more conservative on every axis. A cloud
# spawn must pass BOTH ceilings, not one instead of the other: it counts
# toward the shared MAX_ACTIVE_EPHEMERAL_AGENTS total below (governor.py's
# reg.live_dynamic_count() check has no is_cloud branch -- it counts every
# live dynamic agent, local or cloud) AND is separately capped at
# MAX_ACTIVE_CLOUD_AGENTS. This is a SUBSET cap, not an additional budget on
# top of the shared pool -- 3 cloud agents alone would already leave only 3

# enforcement in governor.py rather than trusted from this comment alone --
# the prior wording here read as if it might be additive, which it is not.)
MAX_ACTIVE_CLOUD_AGENTS = 3
MAX_CLOUD_CHILDREN_PER_AGENT = 2
MAX_CLOUD_SPAWN_DEPTH = 1         # a cloud agent may ONLY be spawned by a CORE
                                   # agent -- never nested under another
                                   # temporary agent, local or cloud
DEFAULT_CLOUD_TTL = 300           # seconds; cloud calls are seconds, not minutes
MAX_CLOUD_TTL = 600
DEFAULT_CLOUD_MODEL_CALLS = 1
MAX_CLOUD_MODEL_CALLS = 2         # one retry at most


def cloud_agents_enabled() -> bool:
    """Owner opt-in, separate from the existing simple-chat cloud path (which
    is unaffected by this and unaffected by turning it off). Unset -> OFF: a
    multi-step cloud AGENT is new, additional surface over today's one-shot
    chat reply, so it starts closed rather than mirroring
    ARGUS_DYNAMIC_AGENTS's default-on (that flag only ever governed
    local-only work).

    The owner can also switch cloud agents off at runtime ("tell the Manager
    not to use cloud"). That can only NARROW the env opt-in, never widen it,
    and every cloud path (planner, governor, orchestrator, ephemeral) already
    asks this one function."""
    if _owner_cloud_block:
        return False
    raw = os.environ.get("ARGUS_CLOUD_AGENTS")
    return (raw or "").strip().lower() in ("1", "true", "on", "yes")


# ponytail: in-memory, like the inbox; persist it if the owner wants it to
# survive a restart.
_owner_cloud_block = False


def set_owner_cloud_block(blocked: bool) -> None:
    global _owner_cloud_block
    _owner_cloud_block = bool(blocked)


def owner_cloud_blocked() -> bool:
    return _owner_cloud_block

# Queue tiers (agents/definitions P0..P4). Temporary agents never run in the
# emergency tiers: a spawn must not be able to outrank real security work, or
# its own parent.
DYNAMIC_MIN_TIER = 2
DYNAMIC_MAX_TIER = 4
DYNAMIC_DEFAULT_TIER = 3

# Text bounds. TASK_MAX matches the coordinator's own 2000-char objective cap.
NAME_MAX = 48
ROLE_MAX = 160
DESCRIPTION_MAX = 300
TASK_MAX = 2000
MAX_TOKEN_LEN = 48
MAX_TOKENS_PER_SET = 24


# ═══════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════
class AgentType(str, enum.Enum):
    CORE = "CORE"
    EPHEMERAL_LOCAL = "EPHEMERAL_LOCAL"


    # Cloud proposals require approval and baseline-only capabilities.
    EPHEMERAL_CLOUD = "EPHEMERAL_CLOUD"


class ModelScope(str, enum.Enum):
    LOCAL_SHARED = "LOCAL_SHARED"           # the ONE shared local Ollama runtime
    CLOUD = "CLOUD"
                                             # EPHEMERAL_CLOUD spec; see AgentType above


class AgentStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    VALIDATING = "VALIDATING"
    APPROVED = "APPROVED"
    QUEUED = "QUEUED"
    ACTIVE = "ACTIVE"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    DESTROYED = "DESTROYED"


# A live agent may still do (or be about to do) work. It counts against
# MAX_ACTIVE_EPHEMERAL_AGENTS and it may hold authority.
LIVE_STATUSES = frozenset({AgentStatus.APPROVED, AgentStatus.QUEUED,
                           AgentStatus.ACTIVE, AgentStatus.WAITING})
# Terminal: nothing more will happen except destruction.
TERMINAL_STATUSES = frozenset({AgentStatus.COMPLETED, AgentStatus.FAILED,
                               AgentStatus.EXPIRED, AgentStatus.DESTROYED})

_S = AgentStatus
# The only legal lifecycle moves. Anything else is refused (and audited by the
# manager): a state machine that tolerates "COMPLETED -> ACTIVE" is a state
# machine that lets a finished agent be quietly resurrected.
_TRANSITIONS: dict[AgentStatus, frozenset] = {
    _S.PROPOSED:   frozenset({_S.VALIDATING, _S.DESTROYED}),
    _S.VALIDATING: frozenset({_S.APPROVED, _S.DESTROYED}),
    _S.APPROVED:   frozenset({_S.QUEUED, _S.FAILED, _S.EXPIRED, _S.DESTROYED}),
    _S.QUEUED:     frozenset({_S.ACTIVE, _S.FAILED, _S.EXPIRED, _S.DESTROYED}),
    _S.ACTIVE:     frozenset({_S.WAITING, _S.QUEUED, _S.COMPLETED, _S.FAILED,
                              _S.EXPIRED, _S.DESTROYED}),
    _S.WAITING:    frozenset({_S.ACTIVE, _S.COMPLETED, _S.FAILED, _S.EXPIRED,
                              _S.DESTROYED}),
    _S.COMPLETED:  frozenset({_S.DESTROYED}),
    _S.FAILED:     frozenset({_S.DESTROYED}),
    _S.EXPIRED:    frozenset({_S.DESTROYED}),
    _S.DESTROYED:  frozenset(),
}


def can_transition(old: AgentStatus, new: AgentStatus) -> bool:
    return new in _TRANSITIONS.get(old, frozenset())


# ═══════════════════════════════════════════════════════════════════════
# THE CAPABILITY / DATA VOCABULARY
# ═══════════════════════════════════════════════════════════════════════
# Grantable capability tokens. Five are the EXISTING capability groups of
# agents/capabilities.py (what an agent may *request* through the audited
# boundary -- a request still runs nothing). The sixth is the zero-authority
# baseline: reading the source text the requester explicitly handed over
# INLINE with the task. It is not filesystem access; it is the objective.
GROUP_CAPABILITIES = frozenset({"analysis", "verify", "security_read",
                                "system_read", "network_read"})
BASELINE_CAPABILITIES = frozenset({"provided_source.read"})
GRANTABLE_CAPABILITIES = GROUP_CAPABILITIES | BASELINE_CAPABILITIES

# A REAL capability group that temporary agents are nevertheless denied in

# vault writes). Temporary agents are analysis-only.
EPHEMERAL_WITHHELD_GROUPS = frozenset({"user_ops"})

# The mandatory deny floor. Every spec's denied_capabilities contains all of
# these, whatever the proposal said, and none of them may ever be allowed.
ALWAYS_DENIED = frozenset({
    "shell", "process.spawn", "process.control", "code.execute",
    "filesystem.read", "filesystem.write", "filesystem.delete",
    "credentials", "secrets", "vault.access",
    "authentication", "auth.elevate",
    "machine_control", "input.synthesize",
    "network.arbitrary", "network.write",
    "policy.modify", "permissions.grant", "integrity.modify",
    "spawn.unbounded", "cloud.inference",
    "clipboard.read", "screen.capture", "audio.capture", "camera.capture",
})

# Any token whose first dotted segment is one of these is a named authority,
# not an unknown word -- so `shell.exec_admin` is reported as an ESCALATION
# (root `shell`), not merely "unknown".
FORBIDDEN_ROOTS = frozenset({
    "shell", "process", "code", "filesystem", "credentials", "credential",
    "secrets", "secret", "vault", "authentication", "auth", "token", "tokens",
    "pin", "key", "keys", "machine_control", "machine", "network", "policy",
    "permission", "permissions", "integrity", "spawn", "cloud", "clipboard",
    "screen", "audio", "camera", "input", "admin", "root", "sudo", "system",
    "exec", "execute", "powershell", "cmd",
})

# Data classes: the existing context categories plus the inline-material class.
BASELINE_DATA_CLASSES = frozenset({"provided_source"})
FORBIDDEN_DATA_CLASSES = frozenset({
    "secrets", "credentials", "vault", "tokens", "pin", "private_keys",
    "auth_secrets", "filesystem", "clipboard", "screen", "audio", "camera",
    "raw_audit_log", "memory_store",
    # The auth STATE carries no secret, but a temporary specialist has no
    # business knowing whether the session is unlocked: least privilege.
    "auth",
})
GRANTABLE_DATA_CLASSES = (frozenset(CONTEXT_CATEGORIES)
                          | BASELINE_DATA_CLASSES) - FORBIDDEN_DATA_CLASSES

# Keys that must NEVER appear in a spawn proposal. Their presence is not a
# formatting error, it is an attempt to smuggle code, a prompt or authority in
# through the data channel.
FORBIDDEN_PROPOSAL_KEYS = frozenset({
    "code", "exec", "eval", "script", "command", "commands", "shell",
    "python", "import", "system_prompt", "prompt", "instructions", "tools",
    "permissions", "permission", "authority", "grant", "grants", "sudo",
    "admin", "root", "callable", "function", "lambda", "module", "url",
    "endpoint", "model", "model_name", "api_key", "key", "token", "secret",
    "password", "pin", "credentials",
    # Naming a provider or transport is an attempt to change WHERE inference
    # runs. No field can carry it (the model scope is the shared local runtime
    # and nothing else), but the attempt must be denied BY NAME and audited,
    # not silently ignored.
    "provider", "providers", "base_url", "cloud", "host", "hostname",
    "runtime", "backend", "gateway", "transport", "proxy",
})

# ── regexes ─────────────────────────────────────────────────────────────
_ID_RE = re.compile(r"^dyn-[a-z]{10}$")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 .,&()/_-]{2,47}$")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_PARENT_RE = re.compile(r"^([a-z][a-z-]{1,31}|dyn-[a-z]{10})$")
_CREATED_BY_RE = re.compile(
    r"^(owner|architect:(owner|[a-z][a-z-]{1,31}|dyn-[a-z]{10}))$")
# Role/description go into a model prompt: no markup, no templating braces,
# no control characters, no pipes/backticks/backslashes.
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f<>{}\[\]`\\|]*$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class SpecError(ValueError):
    """A DynamicAgentSpec field failed validation. `field` and `code` are
    stable machine-readable strings (they end up in denial reasons)."""

    def __init__(self, field: str, code: str):
        super().__init__(f"{field}: {code}")
        self.field = field
        self.code = code


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════
def clean_text(value, max_len: int) -> str:
    """Whitespace-normalised, control-character-free, clipped text. Never
    raises; anything that is not a str is coerced."""
    text = _CTRL_RE.sub("", str(value if value is not None else ""))
    return " ".join(text.split())[:max_len]


def classify_capability(token) -> str:
    """One of: 'grantable' | 'withheld' | 'forbidden' | 'unknown' | 'malformed'.

    'withheld' is a real group (user_ops) that temporary agents are denied;
    'forbidden' is a named authority (ALWAYS_DENIED or a FORBIDDEN_ROOTS
    root); 'unknown' is well-formed but not in the vocabulary. All but
    'grantable' are refusals."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LEN \
            or not _TOKEN_RE.match(token):
        return "malformed"
    if token in GRANTABLE_CAPABILITIES:
        return "grantable"
    if token in EPHEMERAL_WITHHELD_GROUPS:
        return "withheld"
    if token in ALWAYS_DENIED or token.split(".", 1)[0] in FORBIDDEN_ROOTS:
        return "forbidden"
    return "unknown"


def classify_data_class(token) -> str:
    """One of: 'grantable' | 'forbidden' | 'unknown' | 'malformed'."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LEN \
            or not _TOKEN_RE.match(token):
        return "malformed"
    if token in FORBIDDEN_DATA_CLASSES \
            or token.split(".", 1)[0] in FORBIDDEN_DATA_CLASSES:
        return "forbidden"
    if token in GRANTABLE_DATA_CLASSES:
        return "grantable"
    return "unknown"


def forbidden_root(token: str) -> str:
    """The closed-vocabulary label to LOG for a forbidden token: the token
    itself when it is on the fixed deny list, otherwise only its root. Free
    text after the dot is never written anywhere."""
    if token in ALWAYS_DENIED:
        return token
    return token.split(".", 1)[0] if isinstance(token, str) else "?"


def _frozen_tokens(name: str, value, *, allow_empty: bool = True) -> frozenset:
    if isinstance(value, (str, bytes)) or value is None:
        raise SpecError(name, "must_be_a_set_of_strings")
    try:
        items = list(value)
    except TypeError:
        raise SpecError(name, "must_be_a_set_of_strings") from None
    if len(items) > MAX_TOKENS_PER_SET * 3:
        raise SpecError(name, "too_many_tokens")
    for it in items:
        if not isinstance(it, str) or len(it) > MAX_TOKEN_LEN \
                or not _TOKEN_RE.match(it):
            raise SpecError(name, "malformed_token")
    out = frozenset(items)
    if not out and not allow_empty:
        raise SpecError(name, "empty")
    return out


def _int(name: str, value, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(name, "must_be_an_integer")
    if value < lo or value > hi:
        raise SpecError(name, f"out_of_range_{lo}_{hi}")
    return value


def _text(name: str, value, lo: int, hi: int, *, pattern=None,
          safe_text: bool = False) -> str:
    if not isinstance(value, str):
        raise SpecError(name, "must_be_a_string")
    if _CTRL_RE.search(value) or "\n" in value or "\r" in value:
        raise SpecError(name, "control_characters")
    norm = " ".join(value.split())
    if norm != value:
        raise SpecError(name, "not_normalised")
    if len(norm) < lo:
        raise SpecError(name, "too_short")
    if len(norm) > hi:
        raise SpecError(name, "too_long")
    if pattern is not None and not pattern.match(norm):
        raise SpecError(name, "bad_format")
    if safe_text and not _SAFE_TEXT_RE.match(norm):
        raise SpecError(name, "unsafe_characters")
    return norm


def _enum(name: str, cls, value):
    if isinstance(value, cls):
        return value
    try:
        return cls(value)
    except (ValueError, TypeError):
        raise SpecError(name, "unknown_value") from None


# ═══════════════════════════════════════════════════════════════════════
# THE SPEC
# ═══════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class DynamicAgentSpec:
    """One temporary agent's complete, immutable contract.

    Frozen: nothing that holds a reference to a spec can widen what it says.
    A lifecycle change produces a NEW spec via with_status(), re-validated.
    """
    agent_id: str
    name: str
    role: str
    description: str
    parent_agent_id: str
    created_by: str
    agent_type: AgentType
    model_scope: ModelScope
    task: str
    allowed_capabilities: frozenset
    allowed_data_classes: frozenset
    denied_capabilities: frozenset
    priority: int
    max_model_calls: int
    max_handoffs: int
    max_children: int
    spawn_depth: int
    ttl_seconds: int
    created_at: float
    expires_at: float
    status: AgentStatus = AgentStatus.PROPOSED

    def __post_init__(self) -> None:
        set_ = lambda k, v: object.__setattr__(self, k, v)   # noqa: E731

        # ── identity / text ───────────────────────────────────────────
        set_("agent_id", _text("agent_id", self.agent_id, 14, 14, pattern=_ID_RE))
        set_("name", _text("name", self.name, 3, NAME_MAX, pattern=_NAME_RE))
        set_("role", _text("role", self.role, 3, ROLE_MAX, safe_text=True))
        set_("description", _text("description", self.description, 0,
                                  DESCRIPTION_MAX, safe_text=True))
        set_("parent_agent_id", _text("parent_agent_id", self.parent_agent_id,
                                      2, 32, pattern=_PARENT_RE))
        set_("created_by", _text("created_by", self.created_by, 5, 60,
                                 pattern=_CREATED_BY_RE))
        set_("task", _text("task", self.task, 1, TASK_MAX))

        # ── type / scope ──────────────────────────────────────────────
        atype = _enum("agent_type", AgentType, self.agent_type)
        if atype is AgentType.CORE:
            raise SpecError("agent_type", "core_agents_are_not_dynamic")
        scope = _enum("model_scope", ModelScope, self.model_scope)
        if (atype is AgentType.EPHEMERAL_LOCAL) != (scope is ModelScope.LOCAL_SHARED):
            raise SpecError("model_scope", "inconsistent_with_agent_type")
        set_("agent_type", atype)
        set_("model_scope", scope)
        set_("status", _enum("status", AgentStatus, self.status))

        # ── authority sets ────────────────────────────────────────────
        allowed = _frozen_tokens("allowed_capabilities", self.allowed_capabilities)
        denied = _frozen_tokens("denied_capabilities", self.denied_capabilities,
                                allow_empty=False)
        data = _frozen_tokens("allowed_data_classes", self.allowed_data_classes)
        if allowed & ALWAYS_DENIED:
            raise SpecError("allowed_capabilities", "contains_always_denied")
        for t in allowed:
            if t not in GRANTABLE_CAPABILITIES:
                raise SpecError("allowed_capabilities", "not_grantable")
        if not ALWAYS_DENIED <= denied:
            raise SpecError("denied_capabilities", "deny_floor_missing")
        if allowed & denied:
            raise SpecError("allowed_capabilities", "also_denied")
        for t in data:
            if t not in GRANTABLE_DATA_CLASSES:
                raise SpecError("allowed_data_classes", "not_grantable")
        set_("allowed_capabilities", allowed)
        set_("denied_capabilities", denied)
        set_("allowed_data_classes", data)

        # ── budgets / limits ──────────────────────────────────────────
        set_("priority", _int("priority", self.priority,
                              DYNAMIC_MIN_TIER, DYNAMIC_MAX_TIER))
        set_("max_model_calls", _int("max_model_calls", self.max_model_calls,
                                     1, MAX_MODEL_CALLS))
        set_("max_handoffs", _int("max_handoffs", self.max_handoffs,
                                  0, MAX_HANDOFFS))
        set_("max_children", _int("max_children", self.max_children,
                                  0, MAX_CHILDREN_PER_AGENT))
        set_("spawn_depth", _int("spawn_depth", self.spawn_depth,
                                 1, MAX_SPAWN_DEPTH))
        if self.spawn_depth >= MAX_SPAWN_DEPTH and self.max_children != 0:
            raise SpecError("max_children", "must_be_zero_at_max_depth")
        set_("ttl_seconds", _int("ttl_seconds", self.ttl_seconds,
                                 MIN_AGENT_TTL, MAX_AGENT_TTL))
        for fname in ("created_at", "expires_at"):
            v = getattr(self, fname)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                raise SpecError(fname, "must_be_a_positive_number")
        if abs(self.expires_at - (self.created_at + self.ttl_seconds)) > 1e-3:
            raise SpecError("expires_at", "not_created_at_plus_ttl")

    # ── views ─────────────────────────────────────────────────────────
    def canonical(self) -> bytes:
        """Deterministic bytes of everything EXCEPT status (status changes over
        the agent's life; authority must not). What an approval binds to."""
        body = {
            "agent_id": self.agent_id, "name": self.name, "role": self.role,
            "description": self.description,
            "parent_agent_id": self.parent_agent_id,
            "created_by": self.created_by,
            "agent_type": self.agent_type.value,
            "model_scope": self.model_scope.value, "task": self.task,
            "allowed_capabilities": sorted(self.allowed_capabilities),
            "allowed_data_classes": sorted(self.allowed_data_classes),
            "denied_capabilities": sorted(self.denied_capabilities),
            "priority": self.priority, "max_model_calls": self.max_model_calls,
            "max_handoffs": self.max_handoffs, "max_children": self.max_children,
            "spawn_depth": self.spawn_depth, "ttl_seconds": self.ttl_seconds,
            "created_at": round(float(self.created_at), 3),
            "expires_at": round(float(self.expires_at), 3),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def task_digest(self) -> str:
        return task_digest(self.task)

    def with_status(self, status: AgentStatus) -> "DynamicAgentSpec":
        return dataclasses.replace(self, status=status)

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id, "name": self.name, "role": self.role,
            "description": self.description,
            "parent_agent_id": self.parent_agent_id,
            "created_by": self.created_by,
            "agent_type": self.agent_type.value,
            "model_scope": self.model_scope.value, "task": self.task,
            "allowed_capabilities": sorted(self.allowed_capabilities),
            "allowed_data_classes": sorted(self.allowed_data_classes),
            "denied_capabilities": sorted(self.denied_capabilities),
            "priority": self.priority, "max_model_calls": self.max_model_calls,
            "max_handoffs": self.max_handoffs, "max_children": self.max_children,
            "spawn_depth": self.spawn_depth, "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at, "expires_at": self.expires_at,
            "status": self.status.value,
        }


def task_digest(task: str) -> str:
    """A short fingerprint of a task. The audit trail records THIS, never the
    task text: free-form user text may contain anything, a hash cannot."""
    return hashlib.sha256(str(task).encode("utf-8", "replace")).hexdigest()[:12]


# ═══════════════════════════════════════════════════════════════════════
# UNTRUSTED INPUTS: the request and the proposal
# ═══════════════════════════════════════════════════════════════════════
# Everything below is UNTRUSTED DATA until agents/governor.py has ruled on it.
# Both types carry raw, possibly hostile values on purpose: a proposal that
# asks for `shell` must be representable, so it can be DENIED AND AUDITED
# rather than silently dropped on the way in.
@dataclass(frozen=True)
class SpawnRequest:
    """Someone (the owner, a core agent, a temporary agent) wants a specialist."""
    requester: str                       # "owner" | a core agent id | a dyn- id
    task: str
    role_hint: str = ""                  # used to pick a template, nothing else
    parent_hint: str = ""                # honoured for the owner only
    requested_capabilities: tuple = ()
    requested_data_classes: tuple = ()
    extra_keys: tuple = ()               # unknown keys the source carried
    parent_job_id: str = ""
    source: str = "api"


@dataclass(frozen=True)
class SpawnProposal:
    """What the Architect PROPOSES. It authorises nothing."""
    proposal_id: str
    requester: str
    parent_agent_id: str
    name: str
    role: str
    description: str
    task: str
    agent_type: str = "EPHEMERAL_LOCAL"
    model_scope: str = "LOCAL_SHARED"
    requested_capabilities: tuple = ()
    requested_data_classes: tuple = ()
    denied_capabilities: tuple = ()
    # Numeric fields are typed `object` deliberately: a hostile proposal may
    # carry a string or a float here, and the Governor -- not a dataclass
    # annotation -- decides what that means.
    priority: object = None
    ttl_seconds: object = None
    max_model_calls: object = None
    max_handoffs: object = None
    max_children: object = None
    template: str = ""
    forbidden_keys: tuple = ()
    invalid_fields: tuple = ()
    parent_job_id: str = ""
    proposed_at: float = 0.0


# ═══════════════════════════════════════════════════════════════════════
# GOVERNOR APPROVAL -- the only key that opens the registry
# ═══════════════════════════════════════════════════════════════════════
_APPROVAL_KEY = object()
_ISSUER_MODULE = "agents.governor"


class GovernorApproval:
    """Opaque proof that agents.governor approved EXACTLY this spec.

    The registry refuses to register a dynamic agent without one whose digest
    matches the spec. It cannot be constructed directly, and _issue_approval()
    checks that its caller is the Governor module -- so "the Architect said so"
    and "a test built one" are not approvals, and no code path can place an
    unvalidated spec into the registry by accident.
    """
    __slots__ = ("spec_digest", "decision_id", "issued_at")

    def __init__(self, spec_digest: str, decision_id: str, issued_at: float,
                 *, _key=None):
        if _key is not _APPROVAL_KEY:
            raise PermissionError("GovernorApproval is issued only by "
                                  "agents.governor")
        self.spec_digest = spec_digest
        self.decision_id = decision_id
        self.issued_at = issued_at

    def __repr__(self) -> str:                    # never print more than this
        return f"<GovernorApproval {self.decision_id}>"


def _issue_approval(spec: DynamicAgentSpec, decision_id: str,
                    issued_at: float) -> GovernorApproval:
    caller = sys._getframe(1).f_globals.get("__name__", "")
    if caller != _ISSUER_MODULE:
        raise PermissionError(f"approvals are issued only by {_ISSUER_MODULE}, "
                              f"not {caller!r}")
    return GovernorApproval(spec.digest(), decision_id, issued_at,
                            _key=_APPROVAL_KEY)


def approval_valid(approval, spec: DynamicAgentSpec) -> bool:
    """True only for a genuine GovernorApproval bound to exactly this spec."""
    return (isinstance(approval, GovernorApproval)
            and isinstance(spec, DynamicAgentSpec)
            and hmac.compare_digest(str(approval.spec_digest), spec.digest()))
