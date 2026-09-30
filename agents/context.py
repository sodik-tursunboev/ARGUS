'ARGUS - Local agents: bounded context sources.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

# Bounds are small on purpose: llama3.2:3b on a 4 GB card has num_ctx 4096 and
# the router keeps prompts tight for the same reason. Total context stays
# within roughly 1.5k tokens worst case.
_MAX_FINDINGS = 6
_MAX_EVENTS = 8
_MAX_TELEMETRY_FIELDS = 16
_MAX_CHARS_PER_BLOCK = 1200

# Fallback view for pre-V2 callers that ask by category table directly
# (tests, tooling). The coordinator uses the per-spec categories from
# definitions.py; this table must remain a SUBSET of the union of specs.
AGENT_CONTEXT_SOURCES = {
    "security": ("auth", "integrity", "threat_summary", "recent_events"),
    "threat": ("threat_summary", "recent_events"),
    "assistant": ("agent_state", "task_state"),
    "system": ("telemetry",),
    "network": ("network", "netpolicy"),
    "verifier": ("task_state", "job_evidence"),
    "planner": ("task_state", "capability_catalog", "agent_state"),
    "diagnostics": ("runtime_health", "telemetry", "recent_events"),
    "forensics": ("recent_events", "threat_summary", "job_evidence"),
    "response": ("threat_summary", "recent_events", "task_state"),
}


# ── sources ──────────────────────────────────────────────────────────────────

def _src_auth() -> str:
    import auth
    st = auth.status()
    return (f"auth: enabled={st.get('enabled')} "
            f"unlocked={st.get('unlocked')} locked_out={st.get('locked_out')}")


def _src_integrity() -> str:
    import integrity
    st = integrity.status()
    return f"integrity: state={st.get('state', 'unknown')} {st.get('note', '')}".strip()


def _src_threat_summary() -> str:
    import threatmon
    st = threatmon.summary_state()
    dets = st.get("detectors", [])
    counts = ", ".join(
        f"{d.get('detector', '?')}={d.get('findings_total', 0)}" for d in dets[:8])
    return f"threat level={st.get('level', 'unknown')} | detectors: {counts or 'none'}"


def _src_recent_events() -> str:
    import security
    lines = security.read_security_events(n=_MAX_EVENTS)
    if not lines:
        return "recent security events: none"
    trimmed = [ln[:200] for ln in lines[:_MAX_EVENTS]]
    return "recent security events (newest first):\n" + "\n".join(trimmed)


def _src_telemetry() -> str:
    # The sampler's live snapshot via the API module (single source of truth
    # for the same numbers the HUD shows). Lazy import avoids pulling FastAPI
    # into unit tests.
    import main as _main
    snap = _main._snapshot
    fields = {}
    for key in ("cpu", "mem_pct", "mem_used_gb", "mem_total_gb", "disk_pct",
                "disk_free_gb", "gpu_pct", "gpu_available", "swap_pct",
                "net_sent_gb", "net_recv_gb", "battery", "charging"):
        if len(fields) >= _MAX_TELEMETRY_FIELDS:
            break
        val = snap.get(key)
        if val is not None:
            fields[key] = val
    pairs = ", ".join(f"{k}={v}" for k, v in fields.items())
    anomaly = snap.get("anomalies") or []
    line = f"telemetry: {pairs or 'no readings yet'}"
    if anomaly:
        line += f" | anomalies: {len(anomaly)} recorded"
    return line


def _src_network() -> str:
    import main as _main
    snap = _main._snapshot
    return (f"network: sent={snap.get('net_sent_gb', 0)} GB "
            f"received={snap.get('net_recv_gb', 0)} GB (session counters)")


def _src_netpolicy() -> str:
    import netpolicy
    st = netpolicy.status()
    return f"netpolicy: {st.get('mode', 'unknown')} egress={'ok' if st.get('egress_ok', True) else 'restricted'}"


def _src_agent_state() -> str:
    # Other agents' coarse states, for the assistant's "what is ARGUS doing".
    from agents.registry import registry
    rows = [f"{rt.spec.id}={rt.state}" for rt in registry().all()]
    return "agents: " + ", ".join(rows)


def _src_task_state() -> str:
    from agent.task_state import current_task
    t = current_task()
    if not t.active:
        return "task: none in progress"
    return (f"task: state={t.state} goal={t.goal[:120]} "
            f"done={len(t.completed_actions)} pending={len(t.pending_actions)}")


def _src_runtime_health() -> str:
    """V2: the diagnostics feed. REAL subsystem signals only -- model server
    reachability (from the same endpoint the HUD's boot check uses), live WS
    client count, sampler freshness, and the most recent audit failures.
    Everything absent is reported as absent, never guessed."""
    lines = []
    try:
        import config
        import requests as _rq
        r = _rq.get(f"{config.OLLAMA_HOST}/api/tags", timeout=2)
        lines.append(f"model server: {'reachable' if r.ok else 'http ' + str(r.status_code)}")
    except Exception as e:
        lines.append(f"model server: UNREACHABLE ({type(e).__name__})")
    try:
        import main as _main
        hub = getattr(_main, "_hud_events", None)
        n = len(hub._clients) if hub is not None else None
        lines.append(f"live hud sockets: {'none connected' if n == 0 else n}")
        snap_age = time.time() - getattr(_main, "START_TIME", time.time())
        lines.append(f"orchestrator uptime_s: {int(snap_age)}")
    except Exception as e:
        lines.append(f"orchestrator state: unavailable ({type(e).__name__})")
    try:
        import security
        fails = [ln for ln in security.read_security_events(n=20) if "failed" in ln.lower()][:4]
        lines.append("recent failures: " + ("; ".join(ln[:120] for ln in fails) if fails else "none recorded"))
    except Exception:
        lines.append("recent failures: (events source unavailable)")
    return "runtime health:\n" + "\n".join(lines)


def _src_job_evidence() -> str:
    """V2: the evidence the coordinator attaches to the CURRENT job (verifier
    and forensics read what the parent job produced -- bounded, redacted by
    the coordinator's funnel, never the whole history)."""
    from agents.evidence import current_evidence
    ev = current_evidence()
    if not ev:
        return "job evidence: none attached"
    lines = [f"- [{e.get('source', 'unknown')}] {str(e.get('text', ''))[:200]}"
             for e in ev[:_MAX_EVENTS]]
    return "attached job evidence (bounded):\n" + "\n".join(lines)


def _src_capability_catalog() -> str:
    """V2: what PLANNER may propose, derived from the same reviewed group
    table the capability boundary enforces -- never a hand-typed list that
    could name something the boundary would refuse."""
    from agents.capabilities import _GROUPS, _GROUP_POLICY
    lines = []
    for group in sorted(_GROUP_POLICY.get("planner", ())):
        pairs = sorted(_GROUPS.get(group, ()))
        lines.append(f"{group}: " + (", ".join(f"{s}/{a}" for s, a in pairs) or "(none)"))
    return "capability catalog (proposal-only; requesting runs nothing):\n" + "\n".join(lines)


_SOURCES = {
    "auth": _src_auth,
    "integrity": _src_integrity,
    "threat_summary": _src_threat_summary,
    "recent_events": _src_recent_events,
    "telemetry": _src_telemetry,
    "network": _src_network,
    "netpolicy": _src_netpolicy,
    "agent_state": _src_agent_state,
    "task_state": _src_task_state,
    "runtime_health": _src_runtime_health,
    "job_evidence": _src_job_evidence,
    "capability_catalog": _src_capability_catalog,
}


def _categories_for(agent_id: str) -> tuple[str, ...]:
    """The spec is the authority; the fallback table only serves ids that no
    longer exist (impossible in practice) or pre-spec callers."""
    import agents.definitions as defs
    spec = defs.get_spec(agent_id)
    if spec is not None:
        return spec.allowed_context_categories
    # A TEMPORARY agent sees only the data classes its approved spec names
    # (already a subset of its parent's), and only those that are real context
    # sources -- "provided_source" is the objective itself, not a source.
    # Anything unknown gets nothing (the fallback table has no such id).
    try:
        from agents.registry import registry
        dyn = registry().get_dynamic(agent_id)
        if dyn is not None:
            return tuple(sorted(c for c in dyn.dspec.allowed_data_classes
                                if c in _SOURCES))
    except Exception:
        return ()
    return AGENT_CONTEXT_SOURCES.get(agent_id, ())


def context_block(agent_id: str, *, max_items: int | None = None) -> str:
    """Render one agent's bounded context. Never raises: a failing source
    becomes '(source unavailable)' and the job still runs. Every block is
    timestamped so the model cannot mistake stale for live."""
    allowed = _categories_for(agent_id)
    cap = max_items or 8
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    blocks = [f"local time: {now}"]
    for name in allowed[:cap]:
        fn = _SOURCES.get(name)
        if fn is None:
            continue
        try:
            text = str(fn())
        except Exception as e:
            text = f"({name} source unavailable: {type(e).__name__})"
        blocks.append(f"[{name}] {text[:_MAX_CHARS_PER_BLOCK]}")
    return "\n".join(blocks)
