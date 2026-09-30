"""
ARGUS - Dynamic agents: the spawn audit record.

Every spawn DECISION (approved or denied) and every lifecycle END (completed,
failed, expired, destroyed) is written to ARGUS's existing HMAC-chained audit
log through security.audit(). No new log, no new writer.

WHAT IS RECORDED, per decision: requesting agent, proposed agent, parent,
task (as a digest -- see below), requested / approved / refused capabilities,
requested / approved / refused data classes, policy result, spawn depth, TTL,
creation time, and (on the lifecycle line) the termination reason.

NO SECRETS IN THE LOG, BY CONSTRUCTION -- not by hoping redaction catches them:
  * the task is recorded as a 12-hex digest + its length, never its text;
  * agent references are written only if they are REGISTERED ids (or "owner"),
    otherwise "?" -- an id field cannot carry free text;
  * capability / data tokens are written only from the closed vocabulary: a
    forbidden token is reduced to its fixed root, an unknown one to a COUNT;
  * the agent's name is written as a hyphen slug (spaces and punctuation
    become "-"), which also keeps it clear of redact()'s password-shape rule;
  * every value is key=value -- never a bare number, because redact() treats
    a bare 4-12 digit token as a possible PIN and spends a KDF on it;
  * security.audit() then redacts and clips the line anyway (second line of
    defence, not the first).
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

from agents.dynamic_spec import task_digest

_TOK = re.compile(r"^[a-z][a-z0-9_.]*$")
_ID = re.compile(r"^(owner|[a-z][a-z-]{1,31}|dyn-[a-z]{10})$")
_DETAIL_MAX = 150          # security.audit clips detail at 160


def safe_ref(value) -> str:
    """An agent reference that is safe to write: a registered id or 'owner'."""
    v = value if isinstance(value, str) else ""
    if v == "owner":
        return v
    try:
        from agents.registry import registry
        reg = registry()
        if reg.known(v) or reg.is_dynamic(v):
            return v
    except Exception:
        pass
    return "?"


def trusted_id(value) -> str:
    """For ids read from a record WE created (a destroyed agent is no longer
    registered, so safe_ref would blank it): shape-checked only."""
    v = value if isinstance(value, str) else ""
    return v if _ID.match(v) else "?"


def slug(name) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(name or "")).strip("-")[:40]
    return s or "-"


def join_tokens(tokens, limit: int = 8) -> str:
    toks = [t for t in (tokens or ()) if isinstance(t, str) and _TOK.match(t)]
    if not toks:
        return "-"
    head = ",".join(toks[:limit])
    return head + (f"+{len(toks) - limit}more" if len(toks) > limit else "")


def _clip(text: str, n: int = _DETAIL_MAX) -> str:
    return text if len(text) <= n else text[:n]


def build_decision_lines(*, decision, proposal, requester, agent_id, policy,
                         stage, task, created_at) -> list:
    """(event, detail, outcome) tuples for one spawn decision. Pure: builds
    strings from closed vocabularies and writes nothing."""
    approved = bool(decision.approved)
    rid = safe_ref(requester)
    aid = trusted_id(agent_id) if agent_id else "-"
    parent = safe_ref(decision.parent_id)
    depth = int(decision.spawn_depth or 0)
    ttl = int(decision.ttl_seconds or 0)
    outcome = ("approved" if approved else
               "denied:" + "+".join(decision.reasons)[:100])
    lines = [(
        "agent_spawn",
        _clip(f"stage={stage} req={rid} id={aid} par={parent} "
              f"type=EPHEMERAL_LOCAL depth={depth} ttl={ttl} "
              f"pol={policy or '-'} esc={'yes' if decision.escalation else 'no'} "
              f"prop={_safe_pid(decision.proposal_id)}"),
        outcome)]
    # An APPROVED spec's name has been screened (charset, injection, and
    # "redaction changes nothing"). A DENIED proposal's name has not, so it is
    # written only if it is one of the Architect's own template names.
    name = getattr(decision.spec, "name", "") if decision.spec else \
        getattr(proposal, "name", "")
    if not approved and name not in _template_names():
        name = ""
    lines.append((
        "agent_spawn_task",
        _clip(f"id={aid} name={slug(name) if name else '?'} "
              f"digest={task_digest(task)} chars={len(task or '')} "
              f"created_at={int(created_at or 0)}"),
        "ok"))
    lines.append((
        "agent_spawn_caps",
        _clip(f"id={aid} requested={join_tokens(decision.requested_capabilities)} "
              f"approved={join_tokens(decision.approved_capabilities)}"),
        "ok"))
    lines.append((
        "agent_spawn_data",
        _clip(f"id={aid} requested={join_tokens(decision.requested_data_classes)} "
              f"approved={join_tokens(decision.approved_data_classes)}"),
        "ok"))
    if not approved:
        lines.append((
            "agent_spawn_refused",
            _clip(f"id={aid} caps={join_tokens(decision.refused_capabilities)} "
                  f"data={join_tokens(decision.refused_data_classes)} "
                  f"unknown={int(decision.unknown_token_count)} "
                  f"labels={join_tokens(decision.escalation_labels)}"),
            "denied"))
    return lines


def _safe_pid(pid) -> str:
    return pid if isinstance(pid, str) and re.match(r"^[pd]-[0-9a-f]{8}$", pid) \
        else "-"


def _template_names() -> frozenset:
    try:
        from agents.architect import architect
        return frozenset(t["name"] for t in architect().templates())
    except Exception:
        return frozenset()


def build_lifecycle_line(*, agent_id, parent_id, status, reason, depth,
                         life_s) -> tuple:
    return ("agent_lifecycle",
            _clip(f"id={trusted_id(agent_id)} par={trusted_id(parent_id)} "
                  f"status={status} reason={_reason(reason)} depth={int(depth)} "
                  f"life={int(max(0, life_s))}s"),
            "ok")


def _reason(reason) -> str:
    r = re.sub(r"[^a-z0-9_:+.-]", "_", str(reason or "").lower())[:60]
    return r or "-"


def write_lines(lines) -> None:
    """Append to the existing chained audit log. Never raises: an audit
    failure must not take the agent layer down (and security.audit itself
    swallows OSError)."""
    try:
        import security
    except Exception:
        return
    for event, detail, outcome in lines:
        try:
            security.audit(event, detail, outcome)
        except Exception:
            pass
