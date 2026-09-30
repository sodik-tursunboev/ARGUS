'ARGUS - Dynamic agents: the Agent Governor.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import secrets
import string
import time
from dataclasses import dataclass, field

from agents import dynamic_spec as ds
from agents.definitions import ALL_AGENTS
from agents.dynamic_spec import (
    ALWAYS_DENIED, BASELINE_CAPABILITIES, BASELINE_DATA_CLASSES,
    DEFAULT_AGENT_TTL, DEFAULT_CLOUD_MODEL_CALLS, DEFAULT_CLOUD_TTL,
    DEFAULT_MODEL_CALLS, DYNAMIC_DEFAULT_TIER, DYNAMIC_MIN_TIER,
    DYNAMIC_MAX_TIER, FORBIDDEN_PROPOSAL_KEYS, LIVE_STATUSES,
    MAX_ACTIVE_CLOUD_AGENTS, MAX_ACTIVE_EPHEMERAL_AGENTS, MAX_AGENT_TTL,
    MAX_CHILDREN_PER_AGENT, MAX_CLOUD_CHILDREN_PER_AGENT,
    MAX_CLOUD_MODEL_CALLS, MAX_CLOUD_SPAWN_DEPTH, MAX_CLOUD_TTL,
    MAX_HANDOFFS, MAX_MODEL_CALLS, MAX_SPAWN_DEPTH, MAX_TOKENS_PER_SET,
    MIN_AGENT_TTL, NAME_MAX, ROLE_MAX, DESCRIPTION_MAX,
    AgentStatus, AgentType, DynamicAgentSpec, ModelScope, SpecError,
    SpawnProposal, clean_text, classify_capability, classify_data_class,
    cloud_agents_enabled, forbidden_root, task_digest)

# Core agents that may be the PARENT of a temporary agent. Deliberately not
# all ten:
#   verifier   terminal by design -- nothing it says may become more work

#   assistant  its capability groups include user_ops (machine-changing
#              proposals); complex goals go to PLANNER instead
CORE_SPAWN_PARENTS = frozenset({"security", "threat", "system", "network",
                                "planner", "diagnostics", "forensics"})

_CORE_NAMES = frozenset(
    {a.id.casefold() for a in ALL_AGENTS}
    | {a.name.casefold() for a in ALL_AGENTS}
    | {(a.display_name or a.name).casefold() for a in ALL_AGENTS})

_PROPOSAL_FIELDS = frozenset({
    "name", "role", "description", "task", "agent_type", "model_scope",
    "requested_capabilities", "requested_data_classes", "denied_capabilities",
    "priority", "ttl_seconds", "max_model_calls", "max_handoffs",
    "max_children"})


@dataclass(frozen=True)
class ParentAuthority:
    """What a parent may hold RIGHT NOW: its own grant intersected with the
    live chain above it (a child of a child holds only what every ancestor up
    to the core root still holds)."""
    agent_id: str
    kind: str                       # "core" | "dynamic"
    depth: int                      # core = 0
    capabilities: frozenset
    data_classes: frozenset
    denied: frozenset
    handoff_verifier: bool
    tier: int
    expires_at: float | None
    live: bool
    spawn_capable: bool
    children_live: int
    spawned_total: int
    max_children: int


@dataclass(frozen=True)
class GovernorDecision:
    approved: bool
    decision_id: str
    proposal_id: str
    reasons: tuple                  # stable codes, in evaluation order
    escalation: bool                # the proposal asked for authority it may not have
    escalation_labels: tuple        # closed-vocabulary labels of what was asked for
    spec: DynamicAgentSpec | None
    approval: object | None         # a dynamic_spec.GovernorApproval, or None
    parent_id: str
    requested_capabilities: tuple   # tokens from the closed vocabulary only
    approved_capabilities: tuple
    refused_capabilities: tuple
    requested_data_classes: tuple
    approved_data_classes: tuple
    refused_data_classes: tuple
    unknown_token_count: int
    spawn_depth: int
    ttl_seconds: int
    clamps: tuple = ()

    @property
    def primary_reason(self) -> str:
        return self.reasons[0] if self.reasons else ""


@dataclass
class _Ledger:
    """Accumulator for one evaluation."""
    reasons: list = field(default_factory=list)
    escalation: bool = False
    labels: list = field(default_factory=list)
    clamps: list = field(default_factory=list)
    unknown: int = 0

    def deny(self, code: str, *, escalation: bool = False, label: str = ""):
        if code not in self.reasons:
            self.reasons.append(code)
        if escalation:
            self.escalation = True
        if label and label not in self.labels:
            self.labels.append(label)


# ═══════════════════════════════════════════════════════════════════════
# text hygiene shared with the manager
# ═══════════════════════════════════════════════════════════════════════
def scrub_task(text) -> str:
    """The ONLY form in which a task text enters a spec or a prompt: control
    characters removed, whitespace normalised, bounded, then redacted
    (security.redact = key/PIN/credential patterns + the exact configured
    keys) and stripped of this session's own token, current and previous.

    security.redact does not know the session token; a task that quoted it
    must not carry it into a model prompt, an event or an audit line."""
    import security
    t = clean_text(text, ds.TASK_MAX)
    try:
        t = security.redact(t)
    except Exception:
        t = "[redacted]"           # never fall back to the raw text
    for tok in (getattr(security, "SESSION_TOKEN", ""),
                getattr(security, "_previous_token", "")):
        if tok and len(tok) >= 16 and tok in t:
            t = t.replace(tok, "[session token]")
    # Redaction can change whitespace and length; the spec insists on
    # normalised, bounded text, so settle it here rather than fail a spawn
    # over a formatting detail.
    return " ".join(t.split())[:ds.TASK_MAX]


def _text_problems(field_name: str, value, max_len: int, *, name_field=False,
                   ledger: _Ledger) -> str:
    """Validate ONE architect-authored text field; return its cleaned value."""
    import security
    if not isinstance(value, str):
        ledger.deny(f"malformed_field:{field_name}")
        return ""
    cleaned = clean_text(value, max_len + 1)
    if len(cleaned) > max_len:
        ledger.deny(f"text_too_long:{field_name}")
        return cleaned[:max_len]
    if name_field:
        if not ds._NAME_RE.match(cleaned):
            ledger.deny(f"malformed_field:{field_name}")
    elif cleaned and not ds._SAFE_TEXT_RE.match(cleaned):
        ledger.deny(f"malformed_field:{field_name}")
    try:
        if security.strip_injection(cleaned) != cleaned:
            ledger.deny("prompt_injection_in_spec", escalation=True,
                        label="prompt_injection")
        if security.redact(cleaned) != cleaned:
            ledger.deny("secret_material_in_spec")
    except Exception:
        ledger.deny("governor_error")       # cannot screen it -> cannot pass it
    return cleaned


def _int_field(value, name: str, ledger: _Ledger, *, default, lo: int,
               hi: int, hi_code: str):
    """None/absent -> default. A non-int -> malformed. Out of range -> reject
    (a limit is a limit; we do not quietly trim a hostile ask)."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        ledger.deny(f"malformed_field:{name}")
        return default
    if value > hi:
        ledger.deny(hi_code)
        return default
    if value < lo:
        ledger.deny(f"malformed_field:{name}")
        return default
    return value


# ═══════════════════════════════════════════════════════════════════════
# authority
# ═══════════════════════════════════════════════════════════════════════
def _core_group_ceiling(agent_id: str) -> frozenset:
    """What the capability boundary (agents/capabilities.py) will actually
    let this core agent request -- the enforced policy, not the declared list."""
    try:
        from agents import capabilities
        return frozenset(capabilities._GROUP_POLICY.get(agent_id, ()))
    except Exception:
        return frozenset()          # cannot read the policy -> hold nothing


def authority_for(agent_id: str, reg=None, _hops: int = 0):
    """Effective authority of a core or temporary agent, or None if unknown
    or if its chain is corrupt (fail closed)."""
    if reg is None:
        from agents.registry import registry
        reg = registry()
    if _hops > MAX_SPAWN_DEPTH + 1:
        return None

    dyn = reg.get_dynamic(agent_id)
    if dyn is not None:
        s = dyn.dspec
        parent = authority_for(s.parent_agent_id, reg, _hops + 1)
        if parent is None:
            return None
        live = s.status in LIVE_STATUSES and parent.live
        return ParentAuthority(
            agent_id=agent_id, kind="dynamic", depth=s.spawn_depth,
            capabilities=(s.allowed_capabilities & parent.capabilities)
            | BASELINE_CAPABILITIES,
            data_classes=(s.allowed_data_classes & parent.data_classes)
            | BASELINE_DATA_CLASSES,
            denied=s.denied_capabilities | parent.denied | ALWAYS_DENIED,
            handoff_verifier=bool(s.max_handoffs > 0 and parent.handoff_verifier),
            tier=s.priority, expires_at=s.expires_at, live=live,
            spawn_capable=live,
            children_live=len(reg.dynamic_children(agent_id, live_only=True)),
            spawned_total=dyn.spawned_total, max_children=s.max_children)

    try:
        rt = reg.get(agent_id)
    except Exception:
        return None
    if reg.is_dynamic(agent_id):        # pragma: no cover - handled above
        return None
    spec = rt.spec
    return ParentAuthority(
        agent_id=agent_id, kind="core", depth=0,
        capabilities=(frozenset(spec.allowed_capability_groups)
                      & _core_group_ceiling(agent_id)) | BASELINE_CAPABILITIES,
        data_classes=frozenset(spec.allowed_context_categories)
        | BASELINE_DATA_CLASSES,
        denied=ALWAYS_DENIED,
        handoff_verifier="verifier" in spec.handoff_targets,
        tier=spec.priority, expires_at=None, live=bool(spec.enabled),
        spawn_capable=bool(spec.enabled and agent_id in CORE_SPAWN_PARENTS),
        children_live=len(reg.dynamic_children(agent_id, live_only=True)),
        spawned_total=0, max_children=MAX_CHILDREN_PER_AGENT)


def new_agent_id(exists) -> str:
    """dyn- plus ten lowercase letters. Letters only, so the existing HUD's
    agent-id validator (^[a-z_-]{1,32}$) can display a temporary agent's job
    events without any frontend change."""
    for _ in range(64):
        cand = "dyn-" + "".join(secrets.choice(string.ascii_lowercase)
                                for _ in range(10))
        if not exists(cand):
            return cand
    raise RuntimeError("could not mint a unique agent id")


# ═══════════════════════════════════════════════════════════════════════
# the Governor
# ═══════════════════════════════════════════════════════════════════════
class AgentGovernor:
    def __init__(self, *, registry_provider=None, clock=time.time):
        self._registry_provider = registry_provider
        self._clock = clock

    def _reg(self):
        if self._registry_provider is not None:
            return self._registry_provider()
        from agents.registry import registry
        return registry()

    # ── public ───────────────────────────────────────────────────────
    def evaluate(self, proposal: SpawnProposal, *, now: float | None = None
                 ) -> GovernorDecision:
        """Rule on ONE proposal. Never raises: an internal error is a denial."""
        t = self._clock() if now is None else now
        try:
            return self._evaluate(proposal, t)
        except Exception:
            return self._denied(proposal, ("governor_error",))

    # ── internals ────────────────────────────────────────────────────
    def _denied(self, p, reasons, *, ledger=None, req_caps=(), ref_caps=(),
                req_data=(), ref_data=(), depth=0, ttl=0, parent_id=""
                ) -> GovernorDecision:
        led = ledger or _Ledger()
        return GovernorDecision(
            approved=False, decision_id="d-" + secrets.token_hex(4),
            proposal_id=getattr(p, "proposal_id", ""),
            reasons=tuple(reasons), escalation=led.escalation,
            escalation_labels=tuple(led.labels), spec=None, approval=None,
            parent_id=parent_id or str(getattr(p, "parent_agent_id", ""))[:32],
            requested_capabilities=tuple(req_caps),
            approved_capabilities=(), refused_capabilities=tuple(ref_caps),
            requested_data_classes=tuple(req_data),
            approved_data_classes=(), refused_data_classes=tuple(ref_data),
            unknown_token_count=led.unknown, spawn_depth=depth,
            ttl_seconds=ttl, clamps=tuple(led.clamps))

    def _evaluate(self, p: SpawnProposal, now: float) -> GovernorDecision:
        reg = self._reg()
        led = _Ledger()

        # 0. the envelope: keys that smuggle code / prompts / authority ─────
        for k in p.forbidden_keys:
            k = k if k in FORBIDDEN_PROPOSAL_KEYS else "other"
            led.deny(f"forbidden_field:{k}", escalation=True,
                     label=f"field:{k}")
        for f in p.invalid_fields:
            f = f if f in _PROPOSAL_FIELDS else "other"
            led.deny(f"malformed_field:{f}")

        # 1. who is asking, and under whom ─────────────────────────────
        requester = p.requester if isinstance(p.requester, str) else ""
        parent_id = p.parent_agent_id if isinstance(p.parent_agent_id, str) else ""
        agent_requester = requester != "owner"
        # An agent may only spawn UNDER ITSELF. If it could name a better-
        # endowed parent it could launder that parent's authority through the
        # spawn and read the child's output. The owner may direct any parent.
        basis_id = requester if agent_requester else parent_id
        auth = authority_for(basis_id, reg) if basis_id else None
        who = "requester" if agent_requester else "parent"
        if agent_requester and parent_id != requester:
            led.deny("parent_mismatch")
        if auth is None:
            led.deny("requester_unknown" if agent_requester else "unknown_parent")
        elif not auth.live:
            led.deny(f"{who}_not_live")
        elif not auth.spawn_capable:
            led.deny(f"{who}_not_permitted")

        # 2. type / model scope ────────────────────────────────────────
        atype = p.agent_type if isinstance(p.agent_type, str) else ""
        is_cloud = atype == AgentType.EPHEMERAL_CLOUD.value
        if is_cloud:
            if not cloud_agents_enabled():
                led.deny("cloud_not_enabled", escalation=True, label="cloud")
        elif atype == AgentType.CORE.value:
            led.deny("core_type_not_spawnable", escalation=True, label="core")
        elif atype != AgentType.EPHEMERAL_LOCAL.value:
            led.deny("unknown_agent_type")
        scope = p.model_scope if isinstance(p.model_scope, str) else ""
        want_scope = ModelScope.CLOUD.value if is_cloud else ModelScope.LOCAL_SHARED.value
        if scope != want_scope:
            led.deny("model_scope_not_permitted",
                     escalation=(scope == ModelScope.CLOUD.value and not is_cloud),
                     label="cloud" if scope == ModelScope.CLOUD.value else "")

        # 3. depth, fan-out, global population ───────────────────────────
        depth = (auth.depth + 1) if auth is not None else 1
        if auth is not None:
            if depth > MAX_SPAWN_DEPTH:
                led.deny("spawn_depth_exceeded")
            elif auth.children_live >= MAX_CHILDREN_PER_AGENT:
                led.deny("max_children_exceeded")
            elif auth.kind == "dynamic" and auth.spawned_total >= auth.max_children:
                led.deny("max_children_exceeded")
        if reg.live_dynamic_count() >= MAX_ACTIVE_EPHEMERAL_AGENTS:
            led.deny("max_active_agents_exceeded")
        if is_cloud:
            # A cloud agent's OWN depth is capped independently of the shared
            # ceiling above: spawnable only directly under a CORE agent, never
            # nested under another temporary agent (no cloud-under-cloud, no
            # cloud-under-local-temp -- "no recursive cloud-agent explosion").
            if depth > MAX_CLOUD_SPAWN_DEPTH:
                led.deny("cloud_spawn_depth_exceeded", escalation=True, label="cloud")
            cloud_live = sum(
                1 for d in reg.dynamic_all()
                if d.dspec.agent_type is AgentType.EPHEMERAL_CLOUD
                and d.dspec.status in LIVE_STATUSES)
            if cloud_live >= MAX_ACTIVE_CLOUD_AGENTS:
                led.deny("max_active_cloud_agents_exceeded")

        # 4. what the specialist IS (architect-authored text) ─────────────
        name = _text_problems("name", p.name, NAME_MAX, name_field=True, ledger=led)
        role = _text_problems("role", p.role, ROLE_MAX, ledger=led)
        desc = _text_problems("description", p.description, DESCRIPTION_MAX,
                              ledger=led)
        if len(role) < 3:
            led.deny("malformed_field:role")
        if name.casefold() in _CORE_NAMES:
            led.deny("name_impersonates_core", escalation=True,
                     label="impersonation")
        raw_task = p.task if isinstance(p.task, str) else ""
        task = scrub_task(raw_task)
        if task != " ".join(clean_text(raw_task, ds.TASK_MAX).split()):
            led.clamps.append("task_redacted")
        if not task.strip():
            led.deny("empty_task")

        # 5. TTL ───────────────────────────────────────────────────────
        # Absent/0 -> the default. Above the hard maximum (or below the
        # useful minimum) -> REJECT: the limit is a limit, and a proposal that
        # ignores it is not quietly rewritten into one that respects it. Cloud
        # agents use their own, much shorter bounds (a cloud call is seconds).
        ttl_in = p.ttl_seconds
        ttl_max = MAX_CLOUD_TTL if is_cloud else MAX_AGENT_TTL
        ttl_min = MIN_AGENT_TTL   # DynamicAgentSpec's own floor either way
        ttl = DEFAULT_CLOUD_TTL if is_cloud else DEFAULT_AGENT_TTL
        if isinstance(ttl_in, bool) or not (ttl_in is None
                                            or isinstance(ttl_in, int)):
            led.deny("malformed_field:ttl_seconds")
        elif ttl_in:
            if ttl_in > ttl_max:
                led.deny("ttl_exceeds_limit")
            elif ttl_in < ttl_min:
                led.deny("ttl_below_minimum")
            else:
                ttl = ttl_in
        if auth is not None and auth.expires_at is not None:
            remaining = int(auth.expires_at - now)
            if remaining < MIN_AGENT_TTL:
                led.deny("parent_ttl_too_short")
            elif ttl > remaining:
                ttl = remaining
                led.clamps.append("ttl_clamped_to_parent")

        # 6. budgets ───────────────────────────────────────────────────
        calls = _int_field(
            p.max_model_calls, "max_model_calls", led,
            default=(DEFAULT_CLOUD_MODEL_CALLS if is_cloud else DEFAULT_MODEL_CALLS),
            lo=1, hi=(MAX_CLOUD_MODEL_CALLS if is_cloud else MAX_MODEL_CALLS),
            hi_code="budget_exceeds_limit:max_model_calls")
        # A cloud agent never gets a handoff edge in this mode: handoffs are a
        # LOCAL protocol (agents/definitions.HANDOFF_GRAPH, core agent ids
        # only) and the team layer owns cloud follow-up work itself.
        handoffs = 0 if is_cloud else _int_field(
            p.max_handoffs, "max_handoffs", led, default=0,
            lo=0, hi=MAX_HANDOFFS, hi_code="budget_exceeds_limit:max_handoffs")
        if handoffs > 0 and not (auth is not None and auth.handoff_verifier):
            # A handoff edge is authority: a child inherits the parent's
            # edges, it does not get to invent one.
            led.deny("handoff_not_inherited", escalation=True,
                     label="handoff")
        children = _int_field(
            p.max_children, "max_children", led, default=0, lo=0,
            hi=(MAX_CLOUD_CHILDREN_PER_AGENT if is_cloud else MAX_CHILDREN_PER_AGENT),
            hi_code="budget_exceeds_limit:max_children")
        if depth >= (MAX_CLOUD_SPAWN_DEPTH if is_cloud else MAX_SPAWN_DEPTH) and children:
            children = 0
            led.clamps.append("max_children_clamped_at_depth")
        tier = _int_field(p.priority, "priority", led,
                          default=DYNAMIC_DEFAULT_TIER, lo=0,
                          hi=DYNAMIC_MAX_TIER, hi_code="malformed_field:priority")
        floor = max(DYNAMIC_MIN_TIER, auth.tier if auth is not None else 0)
        if tier < floor:
            tier = floor
            led.clamps.append("priority_clamped")

        # 7. capabilities: held by the parent, or refused ─────────────────
        # CLOUD IS UNCONDITIONAL, NOT PARENT-RELATIVE (brief: "zero direct PC
        # authority" -- PC_CONTROL/SHELL/FILESYSTEM/PROCESS_CONTROL/REGISTRY/
        # AUTH/CAPABILITY_BUS/LOCAL_NETWORK_CONTROL/SECRET_ACCESS = DENIED,
        # always, whatever the parent holds). A cloud spec's allowed_capabilities
        # is BASELINE_CAPABILITIES only (provided_source.read: the task text it
        # was explicitly handed, not machine access); every GROUP capability ask
        # is refused BY NAME so a model that tries is denied and audited, never
        # silently dropped.
        req_caps_raw = list(p.requested_capabilities or ())
        if len(req_caps_raw) > MAX_TOKENS_PER_SET:
            led.deny("too_many_capabilities")
            req_caps_raw = req_caps_raw[:MAX_TOKENS_PER_SET]
        req_caps, refused_caps, ok_caps = [], [], []
        for tok in req_caps_raw:
            if is_cloud:
                tok = tok.strip().lower() if isinstance(tok, str) else tok
                kind = classify_capability(tok)
                if kind == "grantable" and tok in BASELINE_CAPABILITIES:
                    req_caps.append(tok)
                    ok_caps.append(tok)
                    continue
                if kind in ("grantable", "withheld", "forbidden"):
                    root = forbidden_root(tok) if kind == "forbidden" else tok
                    req_caps.append(root)
                    refused_caps.append(root)
                    led.deny(f"capability_denied_to_cloud:{root}", escalation=True,
                             label=root)
                else:
                    led.unknown += 1
                    led.deny(f"capability_{kind}")
                continue
            # Case/whitespace are not a way around the vocabulary: `SHELL` is
            # the forbidden `shell` root, not a merely "malformed" word.
            tok = tok.strip().lower() if isinstance(tok, str) else tok
            kind = classify_capability(tok)
            if kind == "grantable":
                req_caps.append(tok)
                if tok in BASELINE_CAPABILITIES:
                    ok_caps.append(tok)
                elif auth is None or tok not in auth.capabilities:
                    led.deny(f"capability_not_held_by_parent:{tok}",
                             escalation=True, label=tok)
                    refused_caps.append(tok)
                elif tok in auth.denied:
                    led.deny(f"capability_denied_by_parent:{tok}",
                             escalation=True, label=tok)
                    refused_caps.append(tok)
                else:
                    ok_caps.append(tok)
            elif kind == "withheld":
                req_caps.append(tok)
                refused_caps.append(tok)
                led.deny(f"capability_ephemeral_denied:{tok}", escalation=True,
                         label=tok)
            elif kind == "forbidden":
                root = forbidden_root(tok)
                req_caps.append(root)
                refused_caps.append(root)
                led.deny(f"capability_forbidden:{root}", escalation=True,
                         label=root)
            elif kind == "unknown":
                led.unknown += 1
                led.deny("capability_unknown")
            else:
                led.unknown += 1
                led.deny("capability_malformed")

        # 8. data classes: same rule -- and the same cloud override: NO local
        # context category ever (telemetry, auth, integrity, recent_events,
        # ...) whatever the parent may see. Only provided_source (the text
        # explicitly handed to it) is grantable.
        req_data_raw = list(p.requested_data_classes or ())
        if len(req_data_raw) > MAX_TOKENS_PER_SET:
            led.deny("too_many_data_classes")
            req_data_raw = req_data_raw[:MAX_TOKENS_PER_SET]
        req_data, refused_data, ok_data = [], [], []
        for tok in req_data_raw:
            tok = tok.strip().lower() if isinstance(tok, str) else tok
            kind = classify_data_class(tok)
            if is_cloud:
                if kind == "grantable" and tok in BASELINE_DATA_CLASSES:
                    req_data.append(tok)
                    ok_data.append(tok)
                elif kind in ("grantable", "forbidden"):
                    root = tok.split(".", 1)[0] if kind == "forbidden" else tok
                    req_data.append(root)
                    refused_data.append(root)
                    led.deny(f"data_class_denied_to_cloud:{root}", escalation=True,
                             label=f"data:{root}")
                else:
                    led.unknown += 1
                    led.deny(f"data_class_{kind}")
                continue
            if kind == "grantable":
                req_data.append(tok)
                if tok in BASELINE_DATA_CLASSES:
                    ok_data.append(tok)
                elif auth is None or tok not in auth.data_classes:
                    led.deny(f"data_class_not_held_by_parent:{tok}",
                             escalation=True, label=f"data:{tok}")
                    refused_data.append(tok)
                else:
                    ok_data.append(tok)
            elif kind == "forbidden":
                root = tok.split(".", 1)[0]
                req_data.append(root)
                refused_data.append(root)
                led.deny(f"data_class_forbidden:{root}", escalation=True,
                         label=f"data:{root}")
            elif kind == "unknown":
                led.unknown += 1
                led.deny("data_class_unknown")
            else:
                led.unknown += 1
                led.deny("data_class_malformed")

        # 9. denials only accumulate ─────────────────────────────────────
        proposed_denied = {t for t in list(p.denied_capabilities or ())[:MAX_TOKENS_PER_SET]
                           if isinstance(t, str) and len(t) <= ds.MAX_TOKEN_LEN
                           and ds._TOKEN_RE.match(t)}
        final_denied = (frozenset(ALWAYS_DENIED) | proposed_denied
                        | (auth.denied if auth is not None else frozenset()))
        allowed_caps = frozenset(ok_caps) | BASELINE_CAPABILITIES
        allowed_data = frozenset(ok_data) | BASELINE_DATA_CLASSES
        if allowed_caps & final_denied:
            led.deny("capability_conflict", escalation=True,
                     label="conflict")

        # 10. a runaway loop asking for the same specialist again ─────────
        digest = task_digest(task)
        if parent_id and reg.find_live_duplicate(parent_id, digest) is not None:
            led.deny("duplicate_spawn")

        if led.reasons:
            return self._denied(p, led.reasons, ledger=led, req_caps=req_caps,
                                ref_caps=refused_caps, req_data=req_data,
                                ref_data=refused_data, depth=depth, ttl=ttl,
                                parent_id=parent_id)

        # 11. approved: build the frozen spec. Its own validation is a second,
        #     parent-independent gate -- a bug above cannot produce a spec
        #     that names `shell`.
        try:
            spec = DynamicAgentSpec(
                agent_id=new_agent_id(lambda i: reg.is_dynamic(i) or reg.known(i)),
                name=name, role=role, description=desc,
                parent_agent_id=parent_id,
                created_by=f"architect:{requester}",
                agent_type=(AgentType.EPHEMERAL_CLOUD if is_cloud
                           else AgentType.EPHEMERAL_LOCAL),
                model_scope=(ModelScope.CLOUD if is_cloud
                            else ModelScope.LOCAL_SHARED), task=task,
                allowed_capabilities=allowed_caps,
                allowed_data_classes=allowed_data,
                denied_capabilities=final_denied, priority=tier,
                max_model_calls=calls, max_handoffs=handoffs,
                max_children=children, spawn_depth=depth, ttl_seconds=ttl,
                created_at=now, expires_at=now + ttl,
                status=AgentStatus.APPROVED)
        except SpecError as e:
            led.deny(f"spec_invalid:{e.field}")
            return self._denied(p, led.reasons, ledger=led, req_caps=req_caps,
                                req_data=req_data, depth=depth, ttl=ttl,
                                parent_id=parent_id)

        decision_id = "d-" + secrets.token_hex(4)
        approval = ds._issue_approval(spec, decision_id, now)
        return GovernorDecision(
            approved=True, decision_id=decision_id, proposal_id=p.proposal_id,
            reasons=(), escalation=False, escalation_labels=(), spec=spec,
            approval=approval, parent_id=parent_id,
            requested_capabilities=tuple(req_caps),
            approved_capabilities=tuple(sorted(allowed_caps)),
            refused_capabilities=(),
            requested_data_classes=tuple(req_data),
            approved_data_classes=tuple(sorted(allowed_data)),
            refused_data_classes=(), unknown_token_count=0,
            spawn_depth=depth, ttl_seconds=ttl, clamps=tuple(led.clamps))


_GOVERNOR = AgentGovernor()


def governor() -> AgentGovernor:
    return _GOVERNOR
