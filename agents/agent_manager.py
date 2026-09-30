"""
ARGUS - The Agent Manager (AGENT_MANAGER): workforce coordination + the voice
the organisation uses to talk to its CEO.

THE ORGANISATION
    CEO (the human owner -- an interaction role, never an automated agent)
    └── AGENT MANAGER (this module)
        ├── the ten permanent core agents (agents/definitions.py)
        └── temporary specialists (agents/ephemeral.py), each hired for one
            goal through Architect -> Governor -> policy, and destroyed after

WHAT THE MANAGER DOES, and where each piece actually lives. It is a thin
coordination layer over machinery that already exists and already enforces
the rules -- it does not re-implement any of it:
  * understand a goal / decide team vs one agent -> agents/team_planner.assess
    (deterministic playbooks; core agents first, specialists only where the
    playbook says they materially help). The Manager adds the EXPLANATION of
    a specialisation gap and asks the CEO before an optional hire.
  * form and run teams, replace failed workers (bounded) -> agents/orchestrator
  * hire -> the orchestrator's Architect -> Governor spawn at dispatch time
  * pick ONE worker when one is enough -> select_worker() below: specialisation
    match + live workload + validated history, deterministic, among agents
    that are ALREADY enabled -- selection never widens who may do what
  * talk to the CEO -> agents/inbox.py (rate-limited, structured, redacted)
  * remember how workers performed -> PerformanceMemory below (real outcomes
    only: completed/failed jobs, verifier verdicts, latency)

WHAT THE MANAGER CANNOT DO (and why that holds in code, not in a prompt):
  * grant a permission or widen a scope -- it never builds a spec; every hire
    is an Architect proposal that the Governor rules on, and a child's
    authority is a subset of its parent's (agents/governor.py);
  * authenticate, authorise or execute -- nothing here imports auth/router/
    skills, and the agents/ AST guard (tests) forbids dispatch/authorize/
    execute calls in this package. A CEO reply of "yes" is a preference
    recorded in the inbox, never an auth factor;
  * raise a budget -- global limits (MAX_ACTIVE_EPHEMERAL_AGENTS, cloud caps,
    MAX_ACTIVE_TEAMS, one heavy inference at a time) are enforced below it;
  * send private data to the cloud -- the cloud path exists only through
    team_planner's cloud_gate check, and LOCAL_REQUIRED never becomes cloud;
  * change its own authority -- it has none to change.

HERMES. The Hermes adapter lives on an unmerged feature branch; it is not in
this tree, so HERMES is never offered as a backend (state() reports it as
NOT_MERGED, with zero workers).

THE WORKFORCE SNAPSHOT. state() is the one normalized workforce view. Every
worker, whatever its backend, carries the same WorkerState fields: id,
display_name, role, specialization, worker_type (CORE / TEMP_LOCAL / HERMES /
CLOUD), backend, provider, model, state, current_task, team_id, manager_id,
parent_agent_id, capabilities, approved_scope, created_at, expires_at and
city_location. They are read from the registry, the ephemeral records and the
orchestrator; nothing is estimated.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from agents import inbox as ib
from agents.definitions import ALL_AGENTS, get_spec

MANAGER_ID = "manager"
MANAGER_NAME = "Agent Manager"
MANAGER_ROLE = "Team orchestrator"

BACKEND_CORE = "ARGUS_CORE"
BACKEND_TEMP_LOCAL = "ARGUS_TEMP_LOCAL"
BACKEND_CLOUD = "CLOUD_SPECIALIST"

CORE_IDS = tuple(a.id for a in ALL_AGENTS)

HIRE_PENDING_TTL_S = 900.0
MAX_HIRES_KEPT = 30
TEAM_TERMINAL = frozenset({"COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "TIMED_OUT"})
WORKING = frozenset({"running", "thinking", "responding", "executing", "preparing",
                     "verifying", "waiting_auth", "active"})

# Why a core agent is NOT enough for a given specialist template. One sentence
# each, written for the CEO -- the explanation IS the reason, never "I decided
# to hire someone". Keys must match team_planner.SPECIALIST_PARENT (tested).
GAP_REASONS = {
    "log_analysis": "DIAGNOSTICS reads ARGUS's runtime-health signals, but this task needs "
                    "line-by-line analysis of the log text you supplied.",
    "python_security": "SECURITY assesses ARGUS's own posture; reviewing supplied Python "
                       "source for injection, unsafe deserialisation or hardcoded secrets "
                       "is a separate specialisation.",
    "dependency_review": "No core agent reads dependency manifests; this needs a reviewer "
                         "for pinned versions and look-alike package names.",
    "code_review": "No core agent reads supplied source code -- PLANNER can only suggest "
                   "how to proceed.",
    "backend_specialist": "No core agent reviews backend or API code.",
    "frontend_specialist": "No core agent reviews frontend or UI code.",
    "system_health": "SYSTEM could not finish this; a focused System Health specialist "
                     "retries it once.",
    "network_posture": "NETWORK could not finish this; a focused Network Posture "
                       "specialist retries it once.",
    "threat_triage": "THREAT could not finish this; a focused Threat Triage specialist "
                     "retries it once.",
    "cloud_research": "This is general, public research with no local data in it, and "
                      "cloud workers are enabled. They can think; they cannot touch this "
                      "machine.",
    "cloud_writing": "This is general writing work with no local data in it, and cloud "
                     "workers are enabled. They can think; they cannot touch this machine.",
}

# Specialisation keywords per core agent, for select_worker's match score.
# Deliberately close to agents/routing.py's table (which remains the primary
# signal); this only breaks ties and lets workload/history matter.
_ROLE_WORDS = {
    "security": r"secur|auth|integrity|policy|audit|posture|password|lock",
    "threat": r"threat|detect|malware|virus|attack|suspicious|alert|intrusion",
    "assistant": r"explain|summar|help|what is|how do|tell me",
    "system": r"cpu|memory|ram|disk|gpu|process|slow|performance|resource|temperature",
    "network": r"network|wi-?fi|internet|dns|connection|port|firewall|latency|vpn",
    "verifier": r"verif|check the result|confirm|validate|evidence",
    "planner": r"plan|steps|organi[sz]e|schedule|break down|how should",
    "diagnostics": r"error|crash|fail|log|service|broken|not working|diagnos",
    "forensics": r"forensic|timeline|evidence|hash|trace|what happened",
    "response": r"respond|contain|remediat|recover|incident",
}
_ROLE_RX = {k: re.compile(v, re.I) for k, v in _ROLE_WORDS.items()}

# "What are you doing?" and friends -- answered from runtime state, no model.
STATUS_RX = re.compile(
    r"\b(what(?:'s| are| is)? (?:you|u) (?:doing|working on|up to)|status|progress"
    r"(?: report)?|what(?:'s| is) your (?:task|job|assignment)|are you (?:busy|working|"
    r"free|idle)|current (?:task|assignment|job)|how(?:'s| is) it going)\b", re.I)

# Each worker's department in the AI City: the same district ids the HUD draws
# (hud-v2/src/lib/city/cityAgents.ts AGENT_HOME). It answers "where is X?".
CITY_HOME = {"security": "security-district", "threat": "security-district",
             "forensics": "security-district", "response": "security-district",
             "system": "operations-center", "network": "operations-center",
             "diagnostics": "operations-center", "verifier": "verification-institute",
             "planner": "agent-hq", "assistant": "agent-hq", MANAGER_ID: "agent-hq"}
TEMP_HOME, CLOUD_HOME = "specialist-district", "cloud-embassy"
_PLACE = {"security-district": "the Security District", "operations-center":
          "the Operations Center", "verification-institute": "the Verification Institute",
          "agent-hq": "Agent HQ", TEMP_HOME: "the Specialist District",
          CLOUD_HOME: "the Cloud Embassy"}

# "All workers must work / give each one a new task": one real, read-only
# review per core agent, in its own domain, over the live context the
# coordinator already gives it. Nothing here can act -- each is an ordinary
# analysis job; any action it proposes still goes through policy and auth.
ROUTINE_TASKS = {
    "security": "Review ARGUS's current security posture (policy, authentication, integrity, audit) and report anything that needs the owner's attention.",
    "threat": "Triage the recent detections and security events: is anything suspicious, and how severe is it?",
    "assistant": "Write the owner a short plain-language summary of ARGUS's current state.",
    "system": "Check the current CPU, memory, disk and GPU load and report any resource pressure, with the numbers.",
    "network": "Review the current network connections and network policy and report anything unusual.",
    "verifier": "Check the most recent completed results: does their evidence support their conclusions?",
    "planner": "Propose a short, prioritised maintenance plan for this PC based on its current state.",
    "diagnostics": "Check ARGUS's runtime health and recent failures and report any problem and its likely cause.",
    "forensics": "Review the recent audit trail and events for anything that deserves a closer look, in time order.",
    "response": "Review the current alerts; for any that need action, draft a reversible response plan (no execution).",
}

_ALL_WORK = re.compile(
    r"^(?:please\s+)?(?:(?:all|every(?:one|body))(?:\s+(?:of\s+)?(?:the\s+|my\s+)?(?:core\s+)?"
    r"(?:agents?|workers?|robots?))?\s+(?:(?:must|should|need\s+to|have\s+to)\s+"
    r"(?:start\s+|get\s+(?:back\s+)?to\s+|go\s+(?:back\s+)?to\s+)?"
    r"|start\s+|get\s+(?:back\s+)?to\s+|go\s+(?:back\s+)?to\s+|back\s+to\s+|to\s+)(?:work|working)\b"
    r"|(?:assign|give)\s+(?:a\s+)?(?:new\s+)?(?:tasks?|jobs?|work)\s+to\s+(?:each|every|all)\b"
    r"|(?:assign|give)\s+to\s+(?:each|every|all)\b"
    r"|(?:assign|give)\s+(?:each|every|all)(?:\s+(?:one|agent|worker|of\s+them|agents|workers))?\s+(?:a\s+)?"
    r"(?:new\s+)?(?:tasks?|jobs?|work)\b"
    r"|(?:put|get|set)\s+(?:everyone|everybody|all\s+(?:the\s+)?(?:agents|workers|robots))\s+(?:to\s+|back\s+to\s+)?work)",
    re.I)

# Reported, never faked: the adapter sits on an unmerged branch, and Hermes
# needs a 64K context window that this machine's local model cannot give.
BACKEND_HERMES = {"id": "HERMES", "available": False, "status": "NOT_MERGED",
                  "note": "adapter on branch feature/hermes-agent-integration, not merged; "
                          "Hermes needs a 64K context this machine's local model cannot give"}


def _now() -> float:
    return time.time()


def _display(agent_id: str) -> str:
    if agent_id == MANAGER_ID:
        return MANAGER_NAME
    spec = get_spec(agent_id)
    return spec.name if spec is not None else agent_id


def _role_title(agent_id: str) -> str:
    if agent_id == MANAGER_ID:
        return MANAGER_ROLE
    spec = get_spec(agent_id)
    return (spec.role if spec is not None else "specialist").upper()


# ═══════════════════════════════════════════════════════════════════════
# Performance memory -- validated history only
# ═══════════════════════════════════════════════════════════════════════
class PerformanceMemory:
    """Per-worker outcome counters built ONLY from real results: a job that
    finished, a verifier verdict on a team that worker served in. Temporary
    specialists are recorded per TEMPLATE ("template:log_analysis") because
    the individual dies with its goal while the specialisation recurs.

    History informs WHICH already-permitted worker the Manager prefers. It
    never feeds the Governor, the capability layer or auth -- nothing reads
    it there (tested)."""

    FIELDS = ("tasks_completed", "tasks_failed", "verifications", "verified",
              "latency_total_s", "latency_samples", "last_used")

    def __init__(self, path: str = ""):
        self.path = path
        self._lock = threading.RLock()
        self._data: dict = {}
        self._dirty = 0
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for key, rec in list(raw.items())[:200]:
            if not isinstance(key, str) or not isinstance(rec, dict):
                continue
            # Every field present, each a number: a hand-edited or corrupt
            # value reads as 0 rather than crashing the Manager Office.
            clean = {k: (rec.get(k) if isinstance(rec.get(k), (int, float))
                         and not isinstance(rec.get(k), bool) else 0) for k in self.FIELDS}
            spec = rec.get("specializations", {})
            clean["specializations"] = {str(k)[:40]: int(v) for k, v in spec.items()
                                        if isinstance(v, int)} if isinstance(spec, dict) else {}
            self._data[key[:48]] = clean

    def _rec(self, key: str) -> dict:
        self._load()
        rec = self._data.get(key)
        if rec is None:
            rec = {k: 0 for k in self.FIELDS}
            rec["specializations"] = {}
            self._data[key] = rec
        return rec

    def record_job(self, key: str, ok: bool, latency_s: float = 0.0) -> None:
        with self._lock:
            rec = self._rec(key)
            rec["tasks_completed" if ok else "tasks_failed"] += 1
            if ok and 0 < latency_s < 3600:
                rec["latency_total_s"] += round(latency_s, 3)
                rec["latency_samples"] += 1
            rec["last_used"] = _now()
            self._touch()

    def record_verdict(self, key: str, verified: bool, specialization: str = "") -> None:
        with self._lock:
            rec = self._rec(key)
            rec["verifications"] += 1
            if verified:
                rec["verified"] += 1
                if specialization:
                    sp = rec["specializations"]
                    sp[specialization[:40]] = sp.get(specialization[:40], 0) + 1
            self._touch()

    def _touch(self) -> None:
        self._dirty += 1
        if self._dirty >= 5:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self.path or not self._dirty:
                return
            try:
                tmp = self.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._data, f, indent=1, sort_keys=True)
                os.replace(tmp, self.path)
                self._dirty = 0
            except OSError:
                pass

    def view(self, key: str) -> dict:
        with self._lock:
            self._load()
            rec = self._data.get(key)
            if rec is None:
                return {"tasks_completed": 0, "tasks_failed": 0, "verification_pass_rate": None,
                        "average_latency_s": None, "specializations": {}, "last_used": 0}
            done, failed = rec["tasks_completed"], rec["tasks_failed"]
            return {
                "tasks_completed": done, "tasks_failed": failed,
                "verification_pass_rate": (round(rec["verified"] / rec["verifications"], 3)
                                           if rec["verifications"] else None),
                "average_latency_s": (round(rec["latency_total_s"] / rec["latency_samples"], 2)
                                      if rec["latency_samples"] else None),
                "specializations": dict(rec["specializations"]),
                "last_used": rec["last_used"],
            }

    def score(self, key: str, specialization: str = "") -> float:
        """0..1.5 bonus for a proven worker; 0 with no history (a newcomer is
        never penalised for being new, only a failing record costs)."""
        v = self.view(key)
        done, failed = v["tasks_completed"], v["tasks_failed"]
        bonus = 0.0
        if done + failed >= 3:
            bonus += (done / (done + failed)) - 0.5          # -0.5 .. +0.5
        if v["verification_pass_rate"] is not None:
            bonus += (v["verification_pass_rate"] - 0.5) * 0.8
        if specialization and v["specializations"].get(specialization, 0) >= 2:
            bonus += 0.6
        return round(bonus, 3)



# ═══════════════════════════════════════════════════════════════════════
# Hire requests (the CEO's say in OPTIONAL hires)
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class HireRequest:
    hire_id: str
    request_id: str
    goal: str                       # scrubbed
    material: str                   # scrubbed; never sent anywhere but the team
    playbook: str
    specialists: list               # [{template, name, parent, backend, ttl_s, gap}]
    existing_roles: list
    fallback_agent: str
    state: str = "PENDING"          # PENDING | APPROVED | DECLINED | EXPIRED | FAILED
    created_at: float = field(default_factory=_now)
    decided_at: float = 0.0
    team_id: str = ""
    job_id: str = ""
    message_id: str = ""
    reason: str = ""

    def view(self) -> dict:
        return {"hire_id": self.hire_id, "request_id": self.request_id,
                "state": self.state, "playbook": self.playbook,
                "specialists": [dict(s) for s in self.specialists],
                "existing_roles": list(self.existing_roles),
                "fallback_agent": self.fallback_agent, "created_at": self.created_at,
                "decided_at": self.decided_at, "team_id": self.team_id,
                "job_id": self.job_id, "message_id": self.message_id,
                "reason": self.reason}


def _templates() -> dict:
    try:
        from agents.architect import architect
        return {t["key"]: t for t in architect().templates()}
    except Exception:
        return {}


def specialist_brief(template: str) -> dict:
    """The structured explanation of one planned hire: what, why, where, how
    long. Everything here is read from the Architect's template table and
    GAP_REASONS -- nothing is invented per request."""
    t = _templates().get(template, {})
    from agents.team_planner import SPECIALIST_PARENT
    cloud = bool(t.get("cloud"))
    return {"template": template, "name": t.get("name", template.replace("_", " ").title()),
            "role": t.get("role", ""), "parent": SPECIALIST_PARENT.get(template, "planner"),
            "backend": BACKEND_CLOUD if cloud else BACKEND_TEMP_LOCAL,
            "ttl_s": int(t.get("ttl", 0) or 0),
            "gap": GAP_REASONS.get(template, "No core agent covers this specialisation.")}


# ═══════════════════════════════════════════════════════════════════════
# The Manager
# ═══════════════════════════════════════════════════════════════════════
class AgentManager:
    def __init__(self, *, coord=None, orch=None, dyn=None, box=None,
                 perf: PerformanceMemory | None = None, clock=_now,
                 auto_thread: bool = True):
        self._coord_override = coord
        self._orch_override = orch
        self._dyn_override = dyn
        self._box = box
        self.perf = perf if perf is not None else PerformanceMemory(_default_perf_path())
        self.clock = clock
        self.auto_thread = auto_thread
        self._lock = threading.RLock()
        self._hires: dict = {}                  # hire_id -> HireRequest
        self._hire_log: deque = deque(maxlen=MAX_HIRES_KEPT)   # team hiring events
        self._jobs: dict = {}                   # job_id -> {"thread", "kind", "ref"}
        self._goals: dict = {}                  # request_id -> {"goal", "material"}
        self._teams_seen: dict = {}             # team_id -> {"announced": bool}
        self._events: deque = deque(maxlen=500)
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._wired_coord = None
        self.auto_hire = os.environ.get("ARGUS_MANAGER_AUTO_HIRE", "") == "1"

    # ── collaborators ────────────────────────
    def _coord(self):
        if self._coord_override is not None:
            return self._coord_override
        from agents.coordinator import coordinator
        return coordinator()

    def _orch(self):
        if self._orch_override is not None:
            return self._orch_override
        from agents.orchestrator import orchestrator
        return orchestrator()

    def _dyn(self):
        if self._dyn_override is not None:
            return self._dyn_override
        from agents.ephemeral import manager
        return manager()

    def box(self) -> ib.Inbox:
        return self._box if self._box is not None else ib.inbox()

    def _ensure_wired(self) -> None:
        coord = self._coord()
        with self._lock:
            if self._wired_coord is not coord:
                coord.add_hook(self)
                self._wired_coord = coord
            if self.auto_thread and (self._thread is None or not self._thread.is_alive()):
                self._thread = threading.Thread(target=self._loop, daemon=True,
                                                name="agents-manager")
                self._thread.start()

    def _loop(self) -> None:
        while True:
            self._wake.wait(1.0)
            self._wake.clear()
            try:
                self.drain()
            except Exception:
                pass

    # ── event intake: NEVER blocks, never takes another module's lock ─
    def observe(self, event_type: str, payload: dict) -> None:
        """Called from agents/events.emit for every agent/team event. Only
        enqueues: emit() may run under the orchestrator's or the ephemeral
        manager's lock, so any real work happens later on our own thread."""
        if not (event_type.startswith("team.") or event_type in (
                "agent.destroyed", "agent.spawn_denied")):
            return
        self._events.append((event_type, dict(payload or {})))
        self._ensure_wired()
        self._wake.set()

    # coordinator hook: job outcomes (all sources) -> performance; our own
    # jobs (manager / chat / followup) -> a message back to the CEO.
    def job_finished(self, job, state, reason) -> None:
        self._events.append(("job.finished", {
            "job_id": job.job_id, "agent_id": job.agent_id, "state": state,
            "reason": str(reason or ""), "source": job.source,
            "latency": (job.completed_at - job.started_at)
            if job.started_at and job.completed_at else 0.0,
            "result": str(job.result or ""),
            "caps": [f"{c.get('skill', '')}/{c.get('action', '')}"
                     for c in (job.requested_capabilities or [])][:4]}))
        self._wake.set()

    def drain(self) -> int:
        n = 0
        while self._events:
            try:
                event_type, payload = self._events.popleft()
            except IndexError:
                break
            try:
                if event_type == "job.finished":
                    self._on_job(payload)
                else:
                    self._on_event(event_type, payload)
            except Exception:
                pass
            n += 1
        if n:
            self.perf.flush()
        return n

    # ── goals from the CEO ───────────────────────────────────────────
    def submit_goal(self, goal: str, material: str = "", *, source: str = "ceo",
                    request_id: str = "") -> dict:
        """The CEO's front door. Existing workforce first; a hire only when
        the playbook needs one, and then only after asking (unless the owner
        switched ARGUS_MANAGER_AUTO_HIRE on)."""
        from agents.governor import scrub_task
        from agents import team_planner
        self._ensure_wired()
        goal = scrub_task(goal)
        material = self._orch()._scrub(material)
        rid = request_id or ("req-" + secrets.token_hex(4))
        self._goals[rid] = {"goal": goal, "material": material, "at": self.clock()}
        while len(self._goals) > 50:
            self._goals.pop(next(iter(self._goals)))
        a = team_planner.assess(goal, material)
        if not goal:
            return {"outcome": "declined", "reason": "empty_goal", "request_id": rid}
        if not a.needs_team:
            if a.reason == "no_material" and a.playbook == "code_review":
                return self._ask_for_material(rid, goal)
            agent_id, scores = self.select_worker(goal, preferred=a.single_agent)
            return self._assign(agent_id, goal, material, rid, scores,
                                why=("One agent is enough for this -- no team and no hire "
                                     "needed."))
        if a.specialists and not self.auto_hire:
            return self._request_hire(rid, goal, material, a)
        return self._start_team(rid, goal, material)

    def _assign(self, agent_id: str, goal: str, material: str, rid: str,
                scores: list, why: str, parent_job: str = "") -> dict:
        text = goal if not material else f"{goal}\n\nMATERIAL SUPPLIED BY THE OWNER:\n{material}"
        job, err = self._coord().submit(agent_id, text, source="manager",
                                        parent_job_id=parent_job)
        if job is None:
            self.box().post(sender_agent_id=MANAGER_ID, sender_name=MANAGER_NAME,
                            sender_role=MANAGER_ROLE, type=ib.FAILURE,
                            title=f"Couldn't assign that to {_display(agent_id)}",
                            body=f"The queue refused the job ({err}). Nothing was started.",
                            priority=ib.ATTN_IMPORTANT, request_id=rid, thread=MANAGER_ID)
            return {"outcome": "failed", "reason": err, "agent_id": agent_id,
                    "request_id": rid}
        self._jobs[job.job_id] = {"thread": agent_id, "kind": "assignment", "ref": rid}
        self.box().post(sender_agent_id=MANAGER_ID, sender_name=MANAGER_NAME,
                        sender_role=MANAGER_ROLE, type=ib.PROGRESS,
                        title=f"Assigned to {_display(agent_id)}",
                        body=why, priority=ib.ATTN_INFO, request_id=rid, job_id=job.job_id,
                        thread=MANAGER_ID)
        return {"outcome": "assigned", "agent_id": agent_id, "job_id": job.job_id,
                "request_id": rid, "selection": scores[:4]}

    def _start_team(self, rid: str, goal: str, material: str) -> dict:
        sub = self._orch().submit_complex_task(goal, material, request_id=rid[:40])
        if not sub.accepted:
            self.box().post(sender_agent_id=MANAGER_ID, sender_name=MANAGER_NAME,
                            sender_role=MANAGER_ROLE, type=ib.FAILURE,
                            title="I couldn't form a team for that",
                            body=f"The orchestrator declined it ({sub.reason}).",
                            priority=ib.ATTN_IMPORTANT, request_id=rid, thread=MANAGER_ID)
            return {"outcome": "failed", "reason": sub.reason, "request_id": rid,
                    "single_agent": sub.single_agent}
        # Team messages (formed / hired / result) come from the event stream,
        # so a team started by voice gets exactly the same reporting.
        self._goals.setdefault(rid, {"goal": goal, "material": material,
                                     "at": self.clock()})["team_id"] = sub.team_id
        return {"outcome": "team", "team_id": sub.team_id, "request_id": rid,
                "plan": sub.plan}

    def _request_hire(self, rid: str, goal: str, material: str, a) -> dict:
        specs = [specialist_brief(t) for t in a.specialists]
        fallback = specs[0]["parent"] if specs else (a.roles[0] if a.roles else "assistant")
        if a.roles:
            fallback = a.roles[0]
        hire = HireRequest(hire_id="hire-" + secrets.token_hex(4), request_id=rid,
                           goal=goal, material=material, playbook=a.playbook,
                           specialists=specs, existing_roles=list(a.roles),
                           fallback_agent=fallback, created_at=self.clock())
        lines = []
        for s in specs:
            ttl = f"{s['ttl_s'] // 60} minutes" if s["ttl_s"] >= 60 else f"{s['ttl_s']} seconds"
            lines.append(f"SPECIALIZATION GAP: {s['gap']} PROPOSED: {s['name']}. "
                         f"BACKEND: {'LOCAL TEMP' if s['backend'] == BACKEND_TEMP_LOCAL else 'CLOUD (thinks only)'}. "
                         f"TTL: {ttl}. Reports to {s['parent'].upper()}.")
        existing = ", ".join(r.upper() for r in a.roles) or _display(fallback).upper()
        lines.append(f"Or I can use only existing agents ({existing}). The Governor still "
                     f"rules on any hire; your 'hire' is a preference, not a permission.")
        msg = self.box().post(
            sender_agent_id=MANAGER_ID, sender_name=MANAGER_NAME, sender_role=MANAGER_ROLE,
            type=ib.APPROVAL_REQUEST,
            title=f"Hire request: {', '.join(s['name'] for s in specs)}",
            body=" ".join(lines), priority=ib.ATTN_IMPORTANT, requires_reply=True,
            reply_options=("hire", "existing", "cancel"), request_id=rid,
            hire_id=hire.hire_id, thread=MANAGER_ID)
        hire.message_id = msg.message_id if msg is not None else ""
        with self._lock:
            self._hires[hire.hire_id] = hire
            while len(self._hires) > MAX_HIRES_KEPT:
                self._hires.pop(next(iter(self._hires)))
        return {"outcome": "hire_pending", "hire_id": hire.hire_id, "request_id": rid,
                "message_id": hire.message_id, "hire": hire.view()}

    def _ask_for_material(self, rid: str, goal: str, what: str = "code") -> dict:
        msg = self.box().post(
            sender_agent_id="planner", sender_name=_display("planner"), sender_role="PLANNER",
            type=ib.QUESTION,
            title=(f"I need the {what} itself before a specialist can work on it"
                   if what == "log" else "I need the code itself before this can be reviewed"),
            body=f"Agents cannot read files on their own. Reply with the {what} text "
                 "and I'll resume this exact request -- or choose "
                 "'advise' and PLANNER will suggest how to proceed without it.",
            priority=ib.ATTN_NORMAL, requires_reply=True, reply_options=("advise",),
            request_id=rid, thread="planner")
        return {"outcome": "question", "request_id": rid,
                "message_id": msg.message_id if msg else ""}

    def decide_hire(self, hire_id: str, choice: str) -> dict:
        with self._lock:
            hire = self._hires.get(hire_id)
        if hire is None:
            return {"ok": False, "reason": "no_such_hire"}
        self._expire_hires()
        if hire.state != "PENDING":
            return {"ok": False, "reason": f"hire_{hire.state.lower()}"}
        hire.decided_at = self.clock()
        if choice == "hire":
            out = self._start_team(hire.request_id, hire.goal, hire.material)
            hire.state = "APPROVED" if out["outcome"] == "team" else "FAILED"
            hire.team_id = out.get("team_id", "")
            hire.reason = out.get("reason", "ceo_approved")
            return {"ok": out["outcome"] == "team", "hire": hire.view(), **out}
        if choice == "existing":
            hire.state = "DECLINED"
            hire.reason = "ceo_chose_existing"
            agent_id, scores = self.select_worker(hire.goal, preferred=hire.fallback_agent,
                                                  candidates=[hire.fallback_agent]
                                                  + [r for r in hire.existing_roles])
            out = self._assign(agent_id, hire.goal, hire.material, hire.request_id, scores,
                               why="You chose existing agents only -- no specialist hired.")
            hire.job_id = out.get("job_id", "")
            return {"ok": out["outcome"] == "assigned", "hire": hire.view(), **out}
        hire.state = "DECLINED"
        hire.reason = "ceo_cancelled"
        return {"ok": True, "hire": hire.view(), "outcome": "cancelled"}

    def _expire_hires(self) -> None:
        t = self.clock()
        with self._lock:
            for h in self._hires.values():
                if h.state == "PENDING" and t - h.created_at > HIRE_PENDING_TTL_S:
                    h.state, h.reason = "EXPIRED", "no_reply"

    # ── worker selection ─────────────────────────────────────────────
    def select_worker(self, text: str, *, preferred: str = "",
                      candidates=None, specialization: str = "") -> tuple:
        """Deterministic choice of ONE enabled core agent. Score =
        specialisation (routing's pick / role keywords) - live workload +
        validated history. Returns (agent_id, [(agent_id, score, parts)...]).
        Only agents the registry reports ENABLED are candidates: selection
        can prefer, never permit."""
        from agents.registry import registry
        reg = registry()
        pool = [c for c in (candidates or CORE_IDS) if c in CORE_IDS]
        load = self._workload()
        scored = []
        for aid in dict.fromkeys(pool):
            try:
                rt = reg.get(aid)
            except Exception:
                continue
            if not rt.spec.enabled:
                continue
            match = (3.0 if aid == preferred else 0.0) + (
                1.0 if _ROLE_RX.get(aid) and _ROLE_RX[aid].search(text or "") else 0.0)
            w = load.get(aid, {"active": 0, "queued": 0})
            busy = 0.8 * w["active"] + 0.4 * w["queued"]
            hist = self.perf.score(aid, specialization)
            scored.append((aid, round(match - busy + hist, 3),
                           {"match": match, "workload": -busy, "history": hist}))
        if not scored:
            return (preferred or "assistant"), []
        order = {a: i for i, a in enumerate(CORE_IDS)}
        scored.sort(key=lambda s: (-s[1], order.get(s[0], 99)))
        return scored[0][0], scored

    def _workload(self) -> dict:
        """active / queued jobs per agent, from the coordinator's own history."""
        out: dict = {}
        try:
            for j in self._coord().jobs(limit=100):
                w = out.setdefault(j["agent_id"], {"active": 0, "queued": 0})
                if j["state"] == "queued":
                    w["queued"] += 1
                elif j["state"] in ("running", "waiting_auth", "executing", "verifying"):
                    w["active"] += 1
        except Exception:
            pass
        return out

    # ── direct chat ──────────────────────────────────────────────────
    def chat(self, agent_id: str, text: str) -> dict:
        """The CEO speaks to one agent. Status questions are answered from
        runtime state (no model). Anything else becomes a normal analysis job
        for that agent: it may analyse and PROPOSE; nothing it says can
        execute -- an action still goes through policy -> auth -> capability
        bus via the ordinary command path."""
        self._ensure_wired()
        agent_id = str(agent_id or "").strip()[:40]
        text = ib.clean(text, ib.REPLY_MAX)
        if not text:
            return {"ok": False, "reason": "empty_message"}
        kind = self._kind_of(agent_id)
        if kind is None:
            return {"ok": False, "reason": "unknown_agent"}
        self.box().post(sender_agent_id="ceo", sender_name="CEO", sender_role="CEO",
                        type=ib.INFO, title=text[:ib.TITLE_MAX], body=text,
                        recipient=agent_id, thread=agent_id, priority=ib.ATTN_INFO)
        if agent_id == MANAGER_ID:
            if STATUS_RX.search(text):
                return self._reply_status(MANAGER_ID)
            # "Tell me about SYSTEM", "where is SECURITY", "cancel that
            # specialist": the same org commands ARGUS itself understands,
            # answered from state -- only anything else is a new goal.
            answer = self.org_query(text)
            if answer:
                msg = self.box().post(
                    sender_agent_id=MANAGER_ID, sender_name=MANAGER_NAME,
                    sender_role=MANAGER_ROLE, type=ib.INFO, title="Answer", body=answer,
                    priority=ib.ATTN_INFO, thread=MANAGER_ID,
                    scope=f"org:{self.clock():.3f}")
                return {"ok": True, "answered_from": "runtime_state",
                        "message_id": msg.message_id if msg else "", "text": answer}
            out = self.submit_goal(text, source="chat")
            return {"ok": out.get("outcome") not in ("failed", "declined"), **out}
        if STATUS_RX.search(text):
            return self._reply_status(agent_id)
        if kind == "temp":
            msg = self.box().post(
                sender_agent_id=agent_id, sender_name=self._temp_name(agent_id),
                sender_role="SPECIALIST", type=ib.INFO,
                title="I take work only from the Agent Manager",
                body="Temporary specialists are hired for one goal and take work only "
                     "through the Manager's hiring pipeline. Ask the Agent Manager, or "
                     "ask me what I'm doing.",
                priority=ib.ATTN_INFO, thread=agent_id, scope=f"chat:{agent_id}:{self.clock():.0f}")
            return {"ok": False, "reason": "temporary_agents_take_work_from_manager",
                    "message_id": msg.message_id if msg else ""}
        job, err = self._coord().submit(agent_id, text, source="chat")
        if job is None:
            msg = self.box().post(
                sender_agent_id=agent_id, sender_name=_display(agent_id),
                sender_role=_role_title(agent_id), type=ib.FAILURE,
                title="I couldn't take that on right now", body=f"Reason: {err}.",
                priority=ib.ATTN_NORMAL, thread=agent_id)
            return {"ok": False, "reason": err, "message_id": msg.message_id if msg else ""}
        self._jobs[job.job_id] = {"thread": agent_id, "kind": "chat", "ref": ""}
        pos = 0
        try:
            from agents.registry import registry
            pos = registry().get(agent_id).queue_position
        except Exception:
            pass
        self.box().post(
            sender_agent_id=agent_id, sender_name=_display(agent_id),
            sender_role=_role_title(agent_id), type=ib.PROGRESS,
            title="On it",
            body=(f"Queued as job {job.job_id}" + (f" (position {pos})" if pos else "")
                  + ". I analyse and propose; any action still needs your approval "
                    "through the normal command path."),
            priority=ib.ATTN_INFO, thread=agent_id, job_id=job.job_id)
        return {"ok": True, "job_id": job.job_id, "agent_id": agent_id}

    def _kind_of(self, agent_id: str):
        if agent_id == MANAGER_ID:
            return "manager"
        if agent_id in CORE_IDS:
            return "core"
        try:
            from agents.registry import registry
            if registry().get_dynamic(agent_id) is not None:
                return "temp"
        except Exception:
            pass
        return None

    def _temp_name(self, agent_id: str) -> str:
        try:
            from agents.registry import registry
            rec = registry().get_dynamic(agent_id)
            return rec.dspec.name if rec is not None else "Specialist"
        except Exception:
            return "Specialist"

    def describe(self, agent_id: str) -> str:
        """One or two sentences about what this agent is doing RIGHT NOW,
        read from the registry, the coordinator and the orchestrator."""
        if agent_id == MANAGER_ID:
            return self._manager_report()
        from agents.registry import registry
        reg = registry()
        if agent_id not in CORE_IDS:
            rec = reg.get_dynamic(agent_id)
            if rec is None:
                return "I'm no longer running."
            v = self._dyn().view(rec, now=self.clock())
            task = v.get("current_task") or ""
            return (f"I'm a temporary {rec.dspec.name}, status {v['state']}, "
                    f"{int(v.get('ttl_remaining_s', 0))} seconds of my time left"
                    + (f". Working on: {task[:120]}" if task else "") + ".")
        rt = reg.get(agent_id)
        state = rt.state or "idle"
        parts = []
        job = self._coord().job(rt.current_job_id) if rt.current_job_id else None
        if state in WORKING and job:
            parts.append(f"I'm {state} on job {job['job_id']}: {job.get('objective', '')[:140]}")
        elif state == "queued":
            parts.append(f"I have work queued (position {rt.queue_position})")
        elif state == "disabled":
            parts.append("I'm disabled right now")
        else:
            parts.append("I'm idle")
        team = self._team_of(agent_id)
        if team:
            parts.append(f"I'm on team {team['team_id']} ({team['state']})"
                         + (f", task {team['task_id']}: {team['title']}" if team.get("task_id") else ""))
        parts.append(f"{rt.completed_jobs} job(s) completed, {rt.failed_jobs} failed so far")
        return ". ".join(parts) + "."

    def _team_of(self, agent_id: str) -> dict | None:
        return self._team_index().get(agent_id)

    def _team_index(self) -> dict:
        """agent_id -> the live team it serves: its open task if it has one,
        else plain membership. One pass over the live teams."""
        out: dict = {}
        try:
            for t in self._orch().teams():
                if t["state"] in TEAM_TERMINAL:
                    continue
                full = self._orch().team(t["team_id"]) or {}
                for task in full.get("tasks", []):
                    aid = task.get("agent_id")
                    if aid and task.get("state") not in (
                            "COMPLETED", "FAILED", "CANCELLED", "SKIPPED", "TIMED_OUT"):
                        out.setdefault(aid, {"team_id": t["team_id"], "state": t["state"],
                                             "task_id": task["task_id"],
                                             "title": task.get("title", "")})
                for m in full.get("members", []):
                    if m.get("agent_id"):
                        out.setdefault(m["agent_id"], {"team_id": t["team_id"],
                                                       "state": t["state"]})
        except Exception:
            pass
        return out

    def _reply_status(self, agent_id: str) -> dict:
        name = self._temp_name(agent_id) if self._kind_of(agent_id) == "temp" else _display(agent_id)
        msg = self.box().post(
            sender_agent_id=agent_id, sender_name=name,
            sender_role=_role_title(agent_id) if agent_id in CORE_IDS or agent_id == MANAGER_ID
            else "SPECIALIST",
            type=ib.INFO, title="Status", body=self.describe(agent_id),
            priority=ib.ATTN_INFO, thread=agent_id,
            scope=f"status:{agent_id}:{self.clock():.3f}")
        return {"ok": True, "answered_from": "runtime_state",
                "message_id": msg.message_id if msg else "",
                "text": msg.body if msg else self.describe(agent_id)}

    def _manager_report(self) -> str:
        st = self.state()
        wf = st["workforce"]
        parts = [f"{wf['active']} of {wf['total']} workers are active, {wf['idle']} idle"]
        if wf["temporary"]:
            parts.append(f"{wf['temporary']} temporary specialist(s) on staff")
        teams = [t for t in st["teams"] if t["state"] not in TEAM_TERMINAL]
        if teams:
            parts.append("running: " + "; ".join(
                f"{t['team_id']} {t['state']} {int(round(t['progress'] * 100))}%" for t in teams[:3]))
        else:
            parts.append("no team is running")
        if st["pending_hires"]:
            parts.append(f"{st['pending_hires']} hire request(s) waiting for you")
        if wf["queued_work"]:
            parts.append(f"{wf['queued_work']} job(s) queued for the shared model")
        return ". ".join(parts) + "."

    # ── CEO replies ──────────────────────────────────────────────────
    def reply(self, message_id: str, *, text: str = "", choice: str = "") -> dict:
        """Record the CEO's reply and route it back to the SAME request /
        hire / agent -- by reference, never by replaying a conversation."""
        box = self.box()
        msg, err = box.record_reply(message_id, text=text, choice=choice)
        if msg is None:
            return {"ok": False, "reason": err}
        choice = (choice or "").lower()
        text_c = ib.clean(text, ib.REPLY_MAX)
        # Material pasted as an answer keeps its lines and length (the inbox
        # copy above is the bounded display version); the orchestrator's own
        # _scrub redacts and bounds it before any agent sees it.
        material = str(text or "")[:6000]
        if msg.hire_id:
            return {"ok": True, "routed_to": "hire", **self.decide_hire(msg.hire_id, choice or "cancel")}
        if msg.type == ib.QUESTION and msg.request_id and msg.request_id in self._goals:
            g = self._goals[msg.request_id]
            if choice == "advise":
                out = self._assign("planner", g["goal"], "", msg.request_id, [],
                                   why="You asked PLANNER for advice instead.")
                return {"ok": out["outcome"] == "assigned", "routed_to": "planner", **out}
            # The reply IS the missing material: resume the same request id.
            out = self.submit_goal(g["goal"], material, request_id=msg.request_id)
            return {"ok": out.get("outcome") not in ("failed", "declined"),
                    "routed_to": "request", **out}
        if msg.type == ib.QUESTION and msg.team_id and choice == "retry":
            g = next((v for v in self._goals.values() if v.get("team_id") == msg.team_id), None)
            if g is not None:
                out = self._start_team("req-" + secrets.token_hex(4), g["goal"], g["material"])
                return {"ok": out["outcome"] == "team", "routed_to": "team_retry", **out}
            return {"ok": False, "reason": "original_request_gone"}
        target = msg.sender_agent_id
        if text_c and target and target != "ceo" and self._kind_of(target) == "core":
            # A follow-up to that agent, carrying only a reference to the job it
            # answers (the coordinator adds that job's bounded context).
            job, why = self._coord().submit(
                target, f"Follow-up from the owner on \"{msg.title}\": {text_c}",
                source="chat", parent_job_id=msg.job_id)
            if job is None:
                return {"ok": False, "reason": why}
            self._jobs[job.job_id] = {"thread": target, "kind": "chat", "ref": msg.message_id}
            return {"ok": True, "routed_to": target, "job_id": job.job_id}
        if text_c and target == MANAGER_ID:
            out = self.chat(MANAGER_ID, text_c)
            return {"routed_to": MANAGER_ID, **out}
        return {"ok": True, "routed_to": "recorded"}

    # ── event handlers (manager thread) ──────────────────────────────
    def _post(self, **kw):
        kw.setdefault("sender_agent_id", MANAGER_ID)
        kw.setdefault("sender_name", MANAGER_NAME)
        kw.setdefault("sender_role", MANAGER_ROLE)
        kw.setdefault("thread", kw["sender_agent_id"])
        return self.box().post(**kw)

    def _on_job(self, p: dict) -> None:
        aid, state = p["agent_id"], p["state"]
        ok = state == "completed"
        if aid in CORE_IDS and state in ("completed", "failed"):
            self.perf.record_job(aid, ok, p.get("latency", 0.0))
        ref = self._jobs.pop(p["job_id"], None)
        if ref is None:
            return
        name = _display(aid)
        caps = p.get("caps") or []
        note = (f" I also proposed {len(caps)} action(s) ({', '.join(caps)}) -- nothing was "
                f"executed; approve them through the normal command path." if caps else "")
        if ok:
            self._post(sender_agent_id=aid, sender_name=name, sender_role=_role_title(aid),
                       type=ib.RESULT, title="Done" if ref["kind"] == "chat" else "Result",
                       body=(p.get("result") or "Finished with no summary.") + note,
                       priority=ib.ATTN_NORMAL, job_id=p["job_id"],
                       request_id=ref.get("ref", "") if ref["kind"] == "assignment" else "",
                       thread=aid)
        elif state in ("failed", "cancelled", "blocked"):
            self._post(sender_agent_id=aid, sender_name=name, sender_role=_role_title(aid),
                       type=ib.FAILURE, title=f"I couldn't finish ({state})",
                       body=f"Reason: {p.get('reason') or 'unknown'}.",
                       priority=ib.ATTN_NORMAL, job_id=p["job_id"], thread=aid)

    def _on_event(self, et: str, p: dict) -> None:
        team_id = p.get("team_id", "")
        if et == "team.created":
            if team_id in self._teams_seen:
                return
            self._teams_seen[team_id] = {"at": self.clock()}
            while len(self._teams_seen) > 100:
                self._teams_seen.pop(next(iter(self._teams_seen)))
            self._announce_team(team_id)
        elif et == "team.agent_requested":
            brief = specialist_brief(p.get("template", ""))
            if p.get("decision") == "denied":
                reason = str(p.get("reason", "policy"))
                if reason.startswith("submit_refused"):
                    # Approved, then released before its first job was queued
                    # (e.g. the CEO cancelled it) -- not a Governor denial,
                    # and it must not be reported as one.
                    self._log_hire(team_id, p, "CANCELLED", brief)
                    self._post(type=ib.INFO, title=f"Hire stopped: {brief['name']}",
                               body=f"The {brief['name']} was released before it started "
                                    f"({reason}). The team continues with existing agents.",
                               priority=ib.ATTN_INFO, team_id=team_id)
                    return
                self._log_hire(team_id, p, "DENIED", brief)
                self._post(type=ib.WARNING, title=f"Hire denied: {brief['name']}",
                           body=f"The Governor refused the {brief['name']} "
                                f"({reason}). The team continues without "
                                f"it or reports what it could not finish.",
                           priority=ib.ATTN_IMPORTANT, team_id=team_id)
            else:
                self._log_hire(team_id, p, "REQUESTED", brief)
        elif et == "team.agent_spawned":
            brief = specialist_brief(p.get("template", ""))
            self._log_hire(team_id, p, "HIRED", brief, agent_id=p.get("agent_id", ""))
            ttl = brief["ttl_s"]
            self._post(type=ib.INFO, title=f"Hired: {brief['name']}",
                       body=f"The Governor approved it. {brief['gap']} Backend: "
                            f"{'local, temporary' if brief['backend'] == BACKEND_TEMP_LOCAL else 'cloud, thinks only'}"
                            f"; time limit {max(1, ttl // 60)} min; reports to "
                            f"{brief['parent'].upper()}. It is destroyed when the goal ends.",
                       priority=ib.ATTN_NORMAL, team_id=team_id)
        elif et == "team.replanned":
            self._post(type=ib.PROGRESS, title="Adjusted the team",
                       body=f"Some work failed, so I added replacement task(s) "
                            f"{', '.join(p.get('added') or []) or ''} within the team's replan "
                            f"budget.", priority=ib.ATTN_INFO, team_id=team_id)
        elif et == "team.verification_completed":
            verdict = str(p.get("verdict", "")).upper()
            if verdict and verdict not in ("VERIFIED", "PARTIALLY_VERIFIED"):
                self._post(sender_agent_id="verifier", sender_name=_display("verifier"),
                           sender_role="VERIFIER", type=ib.WARNING,
                           title="The conclusion isn't sufficiently supported",
                           body=f"My verdict: {verdict.replace('_', ' ').lower()}. The team "
                                f"may replan once to gather more evidence; the final report "
                                f"will say what stays unproven.",
                           priority=ib.ATTN_IMPORTANT, team_id=team_id)
        elif et in ("team.completed", "team.partial", "team.failed", "team.cancelled",
                    "team.timed_out"):
            self._team_finished(team_id, p)
        elif et == "agent.destroyed":
            reason = str(p.get("reason", ""))
            for h in self._hire_log:
                if h.get("agent_id") == p.get("agent_id"):
                    h["state"] = "RELEASED"
                    h["reason"] = reason
            if reason in ("owner_cancel", "ceo_cancel"):
                self._post(type=ib.INFO, title=f"Released {p.get('name', 'a specialist')}",
                           body="Cancelled at your request. Its workstation is powered down "
                                "and it can take no further work.",
                           priority=ib.ATTN_INFO, scope=f"release:{p.get('agent_id', '')}")
        elif et == "agent.spawn_denied" and p.get("requester") == "owner":
            self._post(type=ib.WARNING, title="A specialist request was denied",
                       body=f"The Governor refused it at the {p.get('stage', 'policy')} stage "
                            f"({', '.join(p.get('reasons') or [])[:120]}).",
                       priority=ib.ATTN_NORMAL, scope=f"deny:{p.get('proposal_id', '')}")

    def _log_hire(self, team_id, p, state, brief, agent_id: str = "") -> None:
        for h in self._hire_log:
            if h["team_id"] == team_id and h["task_id"] == p.get("task_id", "") \
                    and h["template"] == brief["template"]:
                h.update(state=state, updated_at=self.clock(),
                         agent_id=agent_id or h.get("agent_id", ""),
                         reason=p.get("reason", h.get("reason", "")))
                return
        self._hire_log.append({"team_id": team_id, "task_id": p.get("task_id", ""),
                               "template": brief["template"], "name": brief["name"],
                               "parent": brief["parent"], "backend": brief["backend"],
                               "ttl_s": brief["ttl_s"], "gap": brief["gap"], "state": state,
                               "agent_id": agent_id, "reason": p.get("reason", ""),
                               "created_at": self.clock(), "updated_at": self.clock()})

    def _announce_team(self, team_id: str) -> None:
        try:
            t = self._orch().team(team_id)
        except Exception:
            t = None
        if not t:
            return
        members = [m for m in t.get("members", [])]
        core = [m["role"].upper() for m in members if m.get("kind") == "core"]
        temps = [specialist_brief(m["role"])["name"] for m in members if m.get("kind") != "core"]
        body = "Team: " + ", ".join(core) + "."
        body += (f" Planned hire(s): {', '.join(temps)} -- the Governor rules on each."
                 if temps else " No hire needed: existing agents cover this.")
        self._post(type=ib.PROGRESS, title="Team formed", body=body,
                   priority=ib.ATTN_INFO, team_id=team_id)

    def _team_finished(self, team_id: str, p: dict) -> None:
        try:
            t = self._orch().team(team_id) or {}
        except Exception:
            t = {}
        result = t.get("result") or {}
        state = str(p.get("state") or result.get("state") or "").upper()
        verdict = str(result.get("verdict") or p.get("verdict") or "").upper()
        # performance: real outcomes only
        for task in result.get("tasks", []):
            aid = task.get("agent_id", "")
            if aid in CORE_IDS and task.get("kind") != "verify" and verdict:
                if task.get("state") == "COMPLETED":
                    self.perf.record_verdict(aid, verdict in ("VERIFIED", "PARTIALLY_VERIFIED"),
                                             result.get("playbook", ""))
            elif task.get("worker_type") in ("specialist", "cloud") and task.get("role"):
                key = f"template:{task['role']}"
                if task.get("state") in ("COMPLETED", "FAILED", "TIMED_OUT"):
                    self.perf.record_job(key, task.get("state") == "COMPLETED",
                                         float(task.get("duration_s") or 0.0))
        observed = (result.get("findings") or {}).get("observed") or []
        proposals = result.get("action_proposals") or []
        body = [str(result.get("summary") or f"{state}.")]
        if observed:
            body.append(f"Key finding: {observed[0].get('text', '')[:200]}")
        if proposals:
            body.append(f"{len(proposals)} suggested action(s) -- nothing was executed; "
                        f"approve through the normal command path (auth still applies).")
        missing = result.get("missing_work") or []
        if missing:
            body.append(f"{len(missing)} part(s) not completed.")
        sensitive = result.get("playbook") == "compromise_investigation" and observed and proposals
        priority = (ib.ATTN_CRITICAL if sensitive else
                    ib.ATTN_IMPORTANT if state in ("PARTIAL", "FAILED", "TIMED_OUT") else
                    ib.ATTN_NORMAL)
        mtype = ib.RESULT if state in ("COMPLETED", "PARTIAL") else (
            ib.INFO if state == "CANCELLED" else ib.FAILURE)
        self._post(type=mtype, title=f"Team result: {state.lower().replace('_', ' ')}",
                   body=" ".join(body), priority=priority, team_id=team_id)
        if result.get("retry_useful") and state in ("PARTIAL", "FAILED", "TIMED_OUT"):
            self._post(type=ib.QUESTION, title="Retry the unfinished part?",
                       body="Some work could not be completed. I can start a fresh team for "
                            "the same goal (same limits, same Governor rules).",
                       priority=ib.ATTN_NORMAL, requires_reply=True,
                       reply_options=("retry",), team_id=team_id)
        if priority == ib.ATTN_CRITICAL:
            try:
                import announce
                announce.say("agent_attention")
            except Exception:
                pass

    # ── observability ────────────────────────────────────────────────
    def state(self, *, redact=None) -> dict:
        """Everything the Manager Office shows, read live. No field is
        estimated: a count is a count of real records."""
        red = redact or (lambda x: x)
        from agents.registry import registry
        from agents.dynamic_spec import (LIVE_STATUSES, MAX_ACTIVE_CLOUD_AGENTS,
                                         MAX_ACTIVE_EPHEMERAL_AGENTS, cloud_agents_enabled,
                                         owner_cloud_blocked)
        from agents.team_schema import MAX_ACTIVE_TEAMS, MAX_HEAVY_MODEL_INFERENCE
        self._expire_hires()
        reg = registry()
        load = self._workload()
        teams_by_agent = self._team_index()
        try:
            local_model = self._coord()._runtime.status().get("model_id", "")
        except Exception:
            local_model = ""
        agents = []
        for rt in reg.all():
            aid = rt.spec.id
            w = load.get(aid, {"active": 0, "queued": 0})
            team = teams_by_agent.get(aid)
            agents.append({
                "id": aid, "name": rt.spec.name, "kind": "core", "role": rt.spec.role,
                "display_name": rt.spec.display_name or rt.spec.name,
                "worker_type": "CORE", "specialization": rt.spec.role,
                "backend": BACKEND_CORE, "state": rt.state,
                "current_job_id": rt.current_job_id, "queue_position": rt.queue_position,
                "active_tasks": w["active"], "queued_tasks": w["queued"],
                "team_id": team["team_id"] if team else "",
                "current_task": red(team.get("title", "")) if team else "",
                "manager_id": MANAGER_ID, "parent_agent_id": "", "reports_to": MANAGER_ID,
                "capabilities": list(rt.spec.allowed_capability_groups),
                "approved_scope": list(rt.spec.allowed_context_categories),
                "created_at": 0, "expires_at": 0,
                "provider": "local", "model": local_model, "ttl_remaining_s": 0,
                "city_location": CITY_HOME.get(aid, "agent-hq"),
                "performance": self.perf.view(aid)})
        temps = []
        dyn = self._dyn()
        for rec in reg.dynamic_all():
            if rec.dspec.status not in LIVE_STATUSES:
                continue
            v = dyn.view(rec, now=self.clock(), redact=red)
            cloud = v.get("type") == "EPHEMERAL_CLOUD"
            team = teams_by_agent.get(v["id"])
            temps.append({
                "id": v["id"], "name": v["name"], "kind": "cloud" if cloud else "temp",
                "display_name": v["name"], "role": v.get("role", ""),
                "worker_type": "CLOUD" if cloud else "TEMP_LOCAL",
                "specialization": re.sub(r"\s+Specialist$", "", v["name"]),
                "backend": BACKEND_CLOUD if cloud else BACKEND_TEMP_LOCAL,
                "state": v["state"], "parent": v.get("parent", ""),
                "parent_agent_id": v.get("parent", ""), "manager_id": MANAGER_ID,
                "reports_to": v.get("parent", "") or MANAGER_ID,
                "created_by": v.get("created_by", ""), "current_task": v.get("current_task", ""),
                "team_id": team["team_id"] if team else "",
                "capabilities": v.get("allowed_capabilities", []),
                "approved_scope": v.get("allowed_data_classes", []),
                "created_at": v.get("created_at", 0), "expires_at": v.get("expires_at", 0),
                # A cloud provider is picked per call (cloud_worker's tiers), so
                # none is claimed before the call; the local model is known.
                "provider": "cloud" if cloud else "local",
                "model": "" if cloud else v.get("model", ""),
                "ttl_remaining_s": v.get("ttl_remaining_s", 0),
                "city_location": CLOUD_HOME if cloud else TEMP_HOME})
        working = sum(1 for a in agents if a["state"] in WORKING or a["active_tasks"])
        working += sum(1 for a in temps if a["state"] in ("ACTIVE",))
        try:
            teams = self._orch().teams(redact=red)
        except Exception:
            teams = []
        with self._lock:
            hires = [h.view() for h in self._hires.values()]
        pending = [h for h in hires if h["state"] == "PENDING"]
        try:
            queued = self._coord().queue_depth()
        except Exception:
            queued = 0
        # One shared local runtime (MAX_HEAVY_MODEL_INFERENCE): who holds it,
        # and who is WAITING_FOR_MODEL behind it.
        try:
            ms = self._coord()._runtime.status()     # the runtime its jobs wait on
            running = ms.get("active_job") or ""
            job = self._coord().job(running) if running else None
            model_queue = {"model": ms.get("model_id", ""), "available": bool(ms.get("available")),
                           "busy": bool(ms.get("busy")), "running_job": running,
                           "running_agent": (job or {}).get("agent_id", "")}
        except Exception:
            model_queue = {"model": local_model, "available": False, "busy": False,
                           "running_job": "", "running_agent": ""}
        model_queue["queue_depth"] = queued
        model_queue["waiting"] = [a["id"] for a in agents + temps
                                  if a["state"].lower() == "queued"]
        active_teams = [t for t in teams if t["state"] not in TEAM_TERMINAL]
        try:
            dyn_on = bool(dyn.enabled)
        except Exception:
            dyn_on = False
        return {
            "manager": {"id": MANAGER_ID, "name": MANAGER_NAME, "role": MANAGER_ROLE,
                        "state": ("coordinating" if active_teams else
                                  "awaiting_ceo" if pending else "standing_by"),
                        "cannot": ["grant permissions", "bypass auth or policy",
                                   "execute machine actions", "send local data to the cloud",
                                   "raise budgets", "change its own authority"]},
            "ceo": {"role": "CEO", "display": "You (owner)", "name": ""},
            "workforce": {"total": len(agents) + len(temps), "core": len(agents),
                          "temporary": len(temps), "active": working,
                          "idle": len(agents) + len(temps) - working,
                          "temp_local": sum(1 for a in temps if a["kind"] == "temp"),
                          "cloud": sum(1 for a in temps if a["kind"] == "cloud"),
                          "hermes": 0, "queued_work": queued},
            "agents": agents, "temporaries": temps, "model_queue": model_queue,
            "cloud_blocked_by_owner": owner_cloud_blocked(),
            "teams": [{"team_id": t["team_id"], "state": t["state"],
                       "progress": (t["progress"]["fraction"] if isinstance(t.get("progress"), dict)
                                    else 0.0),
                       "goal": t.get("goal", ""), "temporary_count": t.get("temporary_count", 0),
                       "member_count": t.get("member_count", 0)} for t in teams[:8]],
            "active_teams": len(active_teams),
            "pending_hires": len(pending), "hire_requests": hires[-10:],
            "hiring_log": [dict(h) for h in list(self._hire_log)[-10:]],
            "backends": [
                {"id": BACKEND_CORE, "available": True, "note": "10 permanent agents"},
                {"id": BACKEND_TEMP_LOCAL, "available": dyn_on,
                 "note": "temporary local specialists (Governor-approved)"},
                {"id": BACKEND_CLOUD, "available": bool(cloud_agents_enabled()),
                 "note": ("switched off by you" if owner_cloud_blocked() else
                          "cloud-safe work only; thinks, never controls")},
                dict(BACKEND_HERMES),
            ],
            "limits": {"max_active_temporary": MAX_ACTIVE_EPHEMERAL_AGENTS,
                       "max_active_cloud": MAX_ACTIVE_CLOUD_AGENTS,
                       "max_active_teams": MAX_ACTIVE_TEAMS,
                       "max_heavy_inference": MAX_HEAVY_MODEL_INFERENCE,
                       "auto_hire": self.auto_hire},
            "inbox": self.box().summary(),
        }

    def org_query(self, text: str) -> str | None:
        """Natural organisational commands (voice or text) answered from REAL
        state, or turned into the same requests the HUD would send. Returns
        the reply, or None when the text is not an org command. Nothing here
        can do what the same request via the API could not."""
        s = " ".join(str(text or "").split())[:300]
        if not s:
            return None
        low = s.lower()
        names = {a.id: a.id for a in ALL_AGENTS}
        names.update({"manager": MANAGER_ID, "agent manager": MANAGER_ID})

        from agents.registry import registry
        from agents.dynamic_spec import (LIVE_STATUSES, cloud_agents_enabled,
                                         set_owner_cloud_block)
        live = [r for r in registry().dynamic_all() if r.dspec.status in LIVE_STATUSES]
        for r in live:                       # "log analysis (specialist)" -> its id
            nm = r.dspec.name.lower()
            names[nm] = r.dspec.agent_id
            names.setdefault(re.sub(r"\s+specialist$", "", nm), r.dspec.agent_id)

        def agent_in(fragment: str) -> str:
            f = fragment.lower()
            for key in sorted(names, key=len, reverse=True):
                if re.search(rf"\b{re.escape(key)}\b", f):
                    return names[key]
            return ""

        def agent_exact(fragment: str) -> str:
            # The WHOLE fragment must name a worker: "where is the network
            # adapter" and "tell me about system performance" are PC
            # questions, not org commands.
            f = re.sub(r"^(?:the|my|our)\s+|\s+agents?$", "",
                       fragment.strip(" .?!,").lower())
            return names.get(f, "")

        def label(aid: str) -> str:
            rec = registry().get_dynamic(aid) if aid not in CORE_IDS and aid != MANAGER_ID else None
            return rec.dspec.name if rec is not None else _display(aid) if aid == MANAGER_ID \
                else aid.upper()

        # ── everyone to work: one real job each ──────────────────────────────
        # Spoken orders come wrapped ("My day was good, all workers must work"):
        # each clause is tested, questions and negations never are (academy._clauses).
        from agents.academy import _clauses
        if any(_ALL_WORK.search(c) for c in _clauses(re.sub(r"^(?:hey\s+)?argus[,! ]+", "", s, flags=re.I))):
            return self._everyone_to_work()

        # ── the owner narrows the Manager's options (never widens authority) ──
        if re.search(r"\b(?:do not|don't|dont|not to|stop|no longer|never) (?:use|using) "
                     r"(?:the )?cloud\b", low):
            set_owner_cloud_block(True)
            return ("Understood -- no cloud specialists from now on. Cloud agents are off until "
                    "you allow them again, so all agent work stays on this machine.")
        if re.search(r"\b(?:you (?:can|may)|(?:it's |it is )?ok(?:ay)? to|go ahead and) "
                     r"use (?:the )?cloud\b|\ballow (?:the )?cloud\b", low):
            set_owner_cloud_block(False)
            return ("Cloud specialists are allowed again -- for cloud-safe work only; they "
                    "think, they never control." if cloud_agents_enabled() else
                    "Your block is lifted, but cloud agents are switched off in ARGUS's "
                    "settings (ARGUS_CLOUD_AGENTS), so nothing uses the cloud.")
        if re.search(r"\buse (?:only )?(?:the )?existing agents\b|\bdon'?t hire\b", low):
            with self._lock:
                pending = [h for h in self._hires.values() if h.state == "PENDING"]
            if not pending:
                return "There's no hire request waiting -- existing agents are already on it."
            out = self.decide_hire(pending[-1].hire_id, "existing")
            return (f"No hire. {label(out.get('agent_id', '')) or 'An existing agent'} has it "
                    f"instead." if out.get("ok") else f"I couldn't: {out.get('reason')}.")
        m = re.search(r"\b(?:create|hire|get|bring in|spin up) (?:me )?an? (?:[\w-]+ ){0,3}"
                      r"specialist\b(?: (?:for|to|on|about) (.+))?", s, re.I)
        if m:
            subject = (m.group(1) or "").strip(" .?!")
            if re.search(r"\blogs?\b|traceback|crash\w*|stack ?trace", subject, re.I):
                rid = "req-" + secrets.token_hex(4)
                self._goals[rid] = {"goal": "Analyse the failure in the supplied log",
                                    "material": "", "at": self.clock()}
                self._ask_for_material(rid, self._goals[rid]["goal"], what="log")
                return ("Send me the log text -- the request is in your agent inbox. Once "
                        "I have it I'll put the Log Analysis Specialist hire to you.")
            if not subject:
                return "What should the specialist work on?"
            out = self.submit_goal(subject)
            return self._outcome_text(out)
        if re.search(r"\b(?:cancel|stop|abort|end) (?:the |that |this |my )?(?:active |current "
                     r"|running )?team\b", low):
            try:
                open_teams = [t for t in self._orch().teams() if t["state"] not in TEAM_TERMINAL]
            except Exception:
                open_teams = []
            if not open_teams:
                return "There is no active team to cancel."
            t = max(open_teams, key=lambda x: x.get("created_at", 0))
            ok = self._orch().cancel_team(t["team_id"], "owner_cancel")
            return (f"Cancelling team {t['team_id']}. Its workers stop and any specialist is "
                    f"released." if ok else "It had already finished.")

        # ── questions about the workforce, answered from real state ──────────
        if re.search(r"\bwho(?:'s| is| are)? (?:working|busy) on (?:my|the|this|that) "
                     r"(?:task|goal|request|job)\b|\bwho(?:'s| is) (?:on|handling) (?:my|the) "
                     r"(?:task|goal|request)\b", low):
            return self._who_on_my_task()
        if re.search(r"\bwho(?:'s| is| are)? (?:working|busy)\b", low):
            st = self.state()
            busy = [a["name"] for a in st["agents"] if a["state"] in WORKING or a["active_tasks"]]
            busy += [a["name"] for a in st["temporaries"] if a["state"] == "ACTIVE"]
            return ("Right now: " + ", ".join(busy) + ".") if busy else \
                "Nobody is working right now -- every agent is idle."
        if re.search(r"\b(?:ask )?(?:the )?(?:agent )?manager\b.*\b(status|progress|report|"
                     r"update)\b", low) or re.search(r"\bprogress report\b", low):
            self._ensure_wired()
            return self._manager_report()
        if re.search(r"\b(?:which|what) (?:agents?|workers?) (?:are|is) (?:idle|free|available)\b"
                     r"|\bwho(?:'s| is| are)? (?:idle|free|available)\b", low):
            st = self.state()
            idle = [a["name"] for a in st["agents"]
                    if a["state"] == "idle" and not a["active_tasks"] and not a["queued_tasks"]]
            return (("Idle right now: " + ", ".join(idle) + ".") if idle
                    else "Nobody is idle -- every core agent has work.")
        m = re.search(r"\bhow many (cloud |hermes |temp(?:orary)? |local )?"
                      r"(?:agents|workers|specialists|robots)\b", low)
        if m:
            wf = self.state()["workforce"]
            kind = (m.group(1) or "").strip()
            if kind == "cloud":
                return (f"{wf['cloud']} cloud specialist(s) right now." + (
                    "" if cloud_agents_enabled() else " Cloud agents are switched off."))
            if kind == "hermes":
                return "None. Hermes isn't integrated into ARGUS, so there are no Hermes workers."
            if kind:
                return f"{wf['temp_local']} temporary local specialist(s) right now."
            return (f"{wf['total']} agents: {wf['core']} core, {wf['temp_local']} temporary "
                    f"local, {wf['cloud']} cloud. No Hermes workers -- Hermes isn't integrated.")
        if re.search(r"\bwho (?:was|were|got|have you|did you|has been) (?:been )?hired\b"
                     r"|\bhired today\b", low):
            day0 = time.mktime(time.localtime(self.clock())[:3] + (0, 0, 0, 0, 0, -1))
            hired = [h for h in self._hire_log if h["state"] in ("HIRED", "RELEASED")
                     and h["created_at"] >= day0]
            if not hired:
                return "Nobody has been hired today."
            return "Hired today: " + "; ".join(
                f"{h['name']} ({'still working' if h['state'] == 'HIRED' else 'released'})"
                for h in hired) + "."
        if re.search(r"\b(?:what|which) (?:ai |language )?(?:model|llm) (?:are|is|do|does) "
                     r"(?:you|the agents|agents|they|argus|\w+) (?:using|use|running|run)\b", low):
            mq = self.state()["model_queue"]
            return (f"The agents share one local model, {mq['model'] or 'unknown'}"
                    + (", busy right now" if mq["busy"] else ", idle")
                    + (f", with {mq['queue_depth']} job(s) waiting" if mq["queue_depth"] else "")
                    + ". Cloud specialists get a cloud provider chosen per call.")
        m = re.search(r"\bwhere(?:'s| is| are)? (.+?)(?: right now| now| at)?[?.!]*$", low)
        if m:
            aid = agent_exact(m.group(1))
            if aid:
                return self._where(aid)
        m = (re.search(r"\b(?:tell me about|what do you know about) ((?:the )?(?:.+? "
                       r"(?:agent|specialist)|agent manager|manager))[?.!]*$", low)
             or re.search(r"\bwho is (.+?)[?.!]*$", low))
        if m:
            aid = agent_exact(m.group(1))
            if aid:
                why = next((h["gap"] for h in reversed(self._hire_log)
                            if h.get("agent_id") == aid), "")
                return self._where(aid) + " " + self.describe(aid) + (
                    f" Hired because: {why}" if why else "")
        m = re.search(r"\bwhat (?:is|'s) (.+?) doing\b", low)
        if m:
            aid = agent_in(m.group(1))
            if aid:
                return self.describe(aid)
        if re.search(r"\bshow (?:me )?(?:the |my )?(?:active |current )?team\b"
                     r"|\bwhat(?:'s| is) the (?:active|current) team\b", low):
            return self._team_report()
        m = re.search(r"\bwhy (?:was|were|did you (?:hire|create)) (.+?)\s*(?:hired|created|"
                      r"spawned)?[?.!]*$", low)
        named = agent_exact(m.group(1)) if m else ""
        if re.search(r"\bwhy did you hire\b", low) or (named and named not in CORE_IDS):
            hires = [h for h in self._hire_log if h["state"] in ("HIRED", "RELEASED")
                     and (not named or h.get("agent_id") == named)]
            if not hires:
                return "I haven't hired any specialist recently."
            h = hires[-1]
            return f"I hired the {h['name']} because: {h['gap']}"
        if re.search(r"\bcancel (?:that|the) (?:temporary agent|temp(?:orary)? specialist|"
                     r"specialist|temp agent)\b", low):
            if not live:
                return "There is no temporary specialist to cancel."
            newest = max(live, key=lambda r: r.dspec.created_at)
            ok = self._dyn().destroy(newest.dspec.agent_id, "owner_cancel")
            return (f"Cancelled the {newest.dspec.name}." if ok
                    else "I couldn't cancel it -- it may already be finishing.")
        m = re.search(r"\bsend (\w+) to help (\w+)\b", low)
        if m:
            a, b = agent_in(m.group(1)), agent_in(m.group(2))
            if a in CORE_IDS and b in CORE_IDS:
                parent = registry().get(b).current_job_id
                out = self._assign(a, f"Assist {b.upper()} with its current task: analyse "
                                      f"its objective and add what your specialisation "
                                      f"contributes.", "", "req-" + secrets.token_hex(4), [],
                                   why=f"You sent {a.upper()} to help {b.upper()}.",
                                   parent_job=parent)
                return (f"Sent {a.upper()} to help {b.upper()}." if out["outcome"] == "assigned"
                        else f"I couldn't: {out.get('reason')}.")
        m = re.search(r"\b(?:tell|ask) (.+?) to (.+)$", s, re.I)
        if m:
            parts = [agent_exact(p) for p in re.split(r",|&|\band\b", m.group(1), flags=re.I)]
            if parts and all(p in CORE_IDS for p in parts):
                return self._assign_many(list(dict.fromkeys(parts)), m.group(2).strip())
        m = re.search(r"\bcreate a team (?:for|to) (.+)$", s, re.I)
        if m:
            return self._outcome_text(self.submit_goal(m.group(1)))
        return None

    def _everyone_to_work(self) -> str:
        """One new, role-specific job per enabled core agent. They share one
        local model, so the queue runs them one at a time and each robot is
        shown queued, then working. User work outranks study: an agent that
        was at the Academy leaves class for this (coordinator.submit)."""
        from agents.registry import registry
        given, refused = [], []
        for aid in CORE_IDS:
            try:
                if not registry().get(aid).spec.enabled:
                    continue
            except Exception:
                continue
            out = self._assign(aid, ROUTINE_TASKS[aid], "", "req-" + secrets.token_hex(4), [],
                               why="Everyone to work: a routine review in its own domain.")
            (given if out["outcome"] == "assigned" else refused).append(aid.upper())
        if not given:
            return "I couldn't give anyone a task -- the job queue refused them all."
        return (f"All {len(given)} agents have a new task. They share one local model, so "
                f"they run one after another; results come to your inbox."
                + (f" Refused: {', '.join(refused)}." if refused else ""))

    def _outcome_text(self, out: dict) -> str:
        return {
            "team": "Team formed -- I'll report back in your agent inbox.",
            "hire_pending": "This needs a specialist hire -- the request is in your "
                            "agent inbox for approval.",
            "assigned": f"One agent is enough: {str(out.get('agent_id', '')).upper()} has it.",
            "question": "I need one clarification first -- it's in your agent inbox.",
        }.get(out.get("outcome"), f"I couldn't: {out.get('reason', 'declined')}.")

    def _assign_many(self, targets: list, objective: str) -> str:
        """"Ask SYSTEM and DIAGNOSTICS to check this": one ordinary job each.
        A deictic objective ("this", "their conclusion") gets the owner's
        latest goal as context; the VERIFIER gets the newest finished result
        from another agent as its parent job, which is exactly the bounded
        context the coordinator already knows how to attach."""
        recent = max(self._goals.values(), key=lambda g: g["at"], default=None)
        text = objective
        if recent and self.clock() - recent["at"] < 1800 and re.search(
                r"\b(this|that|it|these|those|their|them)\b", objective, re.I):
            text = f"{objective}\n\nCONTEXT -- the owner's most recent goal: {recent['goal']}"
        jobs = []
        for aid in targets:
            parent = ""
            if aid == "verifier":
                parent = next((j["job_id"] for j in self._coord().jobs(limit=50)
                               if j["state"] == "completed" and j["agent_id"] != "verifier"), "")
            out = self._assign(aid, text, "", "req-" + secrets.token_hex(4), [],
                               why="Assigned at your request.", parent_job=parent)
            if out["outcome"] != "assigned":
                return f"I couldn't give it to {aid.upper()}: {out.get('reason')}."
            jobs.append((aid, out["job_id"]))
        if len(jobs) == 1:
            return f"{jobs[0][0].upper()} has it (job {jobs[0][1]})."
        return (" and ".join(a.upper() for a, _ in jobs) + " have it (jobs "
                + ", ".join(j for _, j in jobs) + ").")

    def _where(self, aid: str) -> str:
        """Where a worker is, in city terms: its department and what it is
        doing there. The HUD draws the robot at the same district."""
        from agents.registry import registry
        if aid == MANAGER_ID:
            return "The Agent Manager is at Agent HQ, in its glass office."
        if aid in CORE_IDS:
            rt = registry().get(aid)
            team = self._team_of(aid)
            return (f"{aid.upper()} works in {_PLACE[CITY_HOME.get(aid, 'agent-hq')]} and is "
                    f"{rt.state or 'idle'}" + (f", on team {team['team_id']}" if team else "")
                    + ".")
        rec = registry().get_dynamic(aid)
        if rec is None:
            return "That specialist is no longer running."
        cloud = rec.dspec.agent_type.value == "EPHEMERAL_CLOUD"
        return (f"The {rec.dspec.name} is in {_PLACE[CLOUD_HOME if cloud else TEMP_HOME]} "
                f"({rec.dspec.status.value.lower()}), reporting to "
                f"{(rec.dspec.parent_agent_id or MANAGER_ID).upper()}.")

    def _team_report(self) -> str:
        try:
            open_teams = [t for t in self._orch().teams() if t["state"] not in TEAM_TERMINAL]
        except Exception:
            open_teams = []
        if not open_teams:
            return "There is no active team."
        t = max(open_teams, key=lambda x: x.get("created_at", 0))
        full = self._orch().team(t["team_id"]) or {}
        prog = t["progress"]["fraction"] if isinstance(t.get("progress"), dict) else 0.0
        doing = [f"{(x.get('agent_id') or x.get('role', '?')).upper()} ({x.get('title', '')})"
                 for x in full.get("tasks", []) if x.get("state") == "RUNNING"]
        waiting = [(x.get("agent_id") or x.get("role", "?")).upper()
                   for x in full.get("tasks", [])
                   if x.get("state") in ("PENDING", "BLOCKED", "READY", "QUEUED", "WAITING")]
        return (f"Team {t['team_id']} is {t['state'].lower()}, {int(round(prog * 100))}% done"
                + (f". Working: {', '.join(doing)}" if doing else "")
                + (f". Waiting on dependencies: {', '.join(dict.fromkeys(waiting))}"
                   if waiting else "") + ".")

    def _who_on_my_task(self) -> str:
        """The owner's most recent goal, and who is actually on it."""
        if not self._goals:
            return self._team_report()
        rid, g = max(self._goals.items(), key=lambda kv: kv[1]["at"])
        if g.get("team_id"):
            full = self._orch().team(g["team_id"]) or {}
            if full.get("state") in TEAM_TERMINAL:
                return f"That goal's team ({g['team_id']}) has finished: {full['state'].lower()}."
            names = [(m.get("agent_id") or m.get("role", "?")).upper()
                     for m in full.get("members", [])]
            return f"Team {g['team_id']} is on it: {', '.join(names)}."
        job = next((j for j, v in self._jobs.items() if v.get("ref") == rid), "")
        if job:
            j = self._coord().job(job) or {}
            return f"{str(j.get('agent_id', '')).upper()} has it (job {job}, {j.get('state', '?')})."
        with self._lock:
            waiting = any(h.request_id == rid and h.state == "PENDING" for h in self._hires.values())
        return ("Nobody yet -- it's waiting for your answer on the hire request."
                if waiting else "Nobody is on it right now.")



def _default_perf_path() -> str:
    if os.environ.get("ARGUS_NO_AGENT_PERF") == "1":
        return ""
    try:
        import paths
        return paths.writable("agent_performance.json")
    except Exception:
        return ""


_MANAGER = AgentManager()


def agent_manager() -> AgentManager:
    return _MANAGER


def observe(event_type: str, payload: dict) -> None:
    """agents/events.emit's observer entry point. Never raises."""
    try:
        _MANAGER.observe(event_type, payload)
    except Exception:
        pass


def org_query(text: str) -> str | None:
    try:
        return _MANAGER.org_query(text)
    except Exception:
        return None


_ORG_FIRST = re.compile(r"^\W*(?:(?:hey )?argus\W+)?(?:where|who)(?:'s| is| are)\b", re.I)
# ...and it stays read-only: anything that could reach an action handler waits
# for its normal turn in the router's ladder.
_ORG_ACTION = re.compile(r"\b(?:cancel|stop|abort|end|tell|ask|send|create|hire|use|allow|"
                         r"don'?t|not to)\b", re.I)


def org_first(text: str) -> str | None:
    """The org questions the router must see BEFORE its fast intents, which
    read "where is X" as a file search and "who is X" as a knowledge lookup.
    Only "where/who is <exactly one of ARGUS's workers>" (and the other
    "who is ..." org questions) answer here; "where is my downloads folder"
    still falls through to files/find untouched."""
    s = str(text or "")
    if not _ORG_FIRST.search(s) or _ORG_ACTION.search(s):
        return None
    return org_query(s)
