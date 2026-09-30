'ARGUS - Agent teams: deterministic task decomposition.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import dataclasses
import re
from dataclasses import dataclass

from agents.definitions import get_spec
from agents.dynamic_spec import DYNAMIC_DEFAULT_TIER, clean_text
from agents.team_schema import (DEFAULT_TASK_TIMEOUT_S, DEFAULT_TEAM_RUNTIME_S,
                                MAX_EPHEMERAL_PER_TEAM, MAX_GOAL_CHARS,
                                MAX_OBJECTIVE_CHARS, MAX_TASKS,
                                MAX_TEAM_MEMBERS, MAX_TEAM_RUNTIME_S,
                                FailurePolicy, PlanError, TaskKind, TaskState,
                                TeamMember, TeamPlan, TeamTaskSpec, team_id_for)

# Architect template keys the planner may name, with the core parent each one
# spawns under; keep this mapping aligned with agents/architect.py.
SPECIALIST_PARENT = {
    "python_security": "security", "dependency_review": "security",
    "backend_specialist": "planner", "frontend_specialist": "planner",
    "log_analysis": "diagnostics", "system_health": "system",
    "network_posture": "network", "threat_triage": "threat",
    "code_review": "planner",
    # Cloud templates (agents/architect.py CLOUD_TEMPLATES) -- their parent is
    # always PLANNER: cloud work is general-purpose, not tied to a security/
    # system/network domain the way a local specialist's is.
    "cloud_research": "planner", "cloud_writing": "planner",
}
CLOUD_ROLES = frozenset({"cloud_research", "cloud_writing"})
# A failed CORE task may be retried once by its specialist (replan strategy 1).
CORE_TO_SPECIALIST = {"system": "system_health", "network": "network_posture",
                      "threat": "threat_triage", "diagnostics": "log_analysis"}

INVESTIGATIVE = re.compile(
    r"\b(why|investigat\w*|check (?:whether|if)|is (?:it|this|my|the)\b.*\b"
    r"(?:compromised|infected|hacked|safe|secure|slow|broken)|find out|"
    r"figure out|diagnos\w*|analy[sz]\w*|review\w*|audit\w*|assess\w*|"
    r"determine|whether|what(?:'s| is) (?:causing|wrong)|look into|inspect\w*|"
    r"evaluat\w*|explain|understand|root cause|troubleshoot\w*)\b", re.I)
SUSPICIOUS = re.compile(
    r"\b(suspicious|compromis\w*|infect\w*|hack\w*|malware|virus|intrusion|"
    r"breach\w*|attack\w*|backdoor|rootkit|trojan|ransomware|keylogger|"
    r"exfiltrat\w*|unauthori[sz]ed)\b", re.I)
_PYTHON = re.compile(r"\b(python|\.py|pip|django|flask|fastapi)\b", re.I)
_CODE_MATERIAL = re.compile(r"\b(def |class |import |function |const |let |var |"
                            r"#include|public |private |return )")
_LOG_MATERIAL = re.compile(r"(traceback|exception|error|warn|fatal|\d{2}:\d{2}:\d{2})",
                           re.I)


@dataclass(frozen=True)
class Assessment:
    needs_team: bool
    playbook: str
    reason: str
    single_agent: str            # the ONE agent to use when no team is needed
    roles: tuple = ()            # core roles a team would use
    specialists: tuple = ()      # template keys a team would request

    def as_dict(self) -> dict:
        return {"needs_team": self.needs_team, "playbook": self.playbook,
                "reason": self.reason, "single_agent": self.single_agent,
                "roles": list(self.roles), "specialists": list(self.specialists)}


@dataclass(frozen=True)
class _Step:
    key: str
    role: str                     # core agent id, or a template key
    title: str
    objective: str
    deps: tuple = ()
    when: str = ""                # regex over the goal; "" = always
    needs_material: bool = False  # only with owner-supplied material
    caps: tuple = ()              # requested capability tokens (closed vocab)
    order: int = 0                # inclusion priority when specialists are capped
    unless: str = ""              # skipped when this other step is included

    @property
    def is_specialist(self) -> bool:
        return self.role in SPECIALIST_PARENT


@dataclass(frozen=True)
class Playbook:
    key: str
    patterns: tuple
    steps: tuple
    extra_evidence: tuple = ()    # core roles a replan may add for more evidence

    def matches(self, goal: str) -> bool:
        return any(re.search(p, goal, re.I) for p in self.patterns)

    def included(self, goal: str, material: str) -> list:
        out = []
        for s in self.steps:
            if s.when and not re.search(s.when, goal, re.I):
                continue
            if s.needs_material and not material:
                continue
            if s.unless and any(o.key == s.unless for o in out):
                continue
            out.append(s)
        return out


_SEC = (r"\b(secur\w*|vulnerab\w*|insecure|injection|unsafe|exploit\w*|"
        r"credential\w*|hardcoded)\b")
_PERF = r"\b(performance|slow\w*|latency|bottleneck\w*|optimi[sz]\w*|efficien\w*)\b"

PLAYBOOKS: tuple = (
    Playbook(
        "machine_health",
        (r"\b(slow\w*|sluggish|lag\w*|performance|resource\w*|cpu|memory|ram|"
         r"disk|gpu|freez\w*|hang\w*|overheat\w*|fan)\b",),
        (
            _Step("sys", "system", "Collect resource evidence",
                  "Summarise CPU, memory, disk, GPU and swap load and the top "
                  "process consumers from the telemetry you are given, with "
                  "the numbers. Flag anything abnormal and say what is absent."),
            _Step("diag", "diagnostics", "Inspect recent failures",
                  "Review runtime health and recent failures or errors for "
                  "causes of degraded performance. Separate observed failures "
                  "from hypotheses and name the most likely cause."),
            _Step("threat", "threat", "Analyse suspicious indicators",
                  "Review the detections and recent security events you are "
                  "given for any indicator that the slowdown is malicious. "
                  "Never invent a detection; an empty picture is a valid answer.",
                  when=SUSPICIOUS.pattern),
            _Step("forensics", "forensics", "Correlate the evidence",
                  "Correlate the evidence collected by the other tasks into a "
                  "timeline: what was observed, by which source, and what it "
                  "supports. Keep observation and interpretation apart.",
                  deps=("sys", "diag", "threat"), when=SUSPICIOUS.pattern),
        ),
        extra_evidence=("threat", "security", "network")),
    Playbook(
        "compromise_investigation",
        (SUSPICIOUS.pattern,),
        (
            _Step("sec", "security", "Assess security posture",
                  "Assess the security posture you are given: authentication "
                  "state, integrity state, policy posture and audit findings. "
                  "Say what each finding means and what to verify next."),
            _Step("threat", "threat", "Analyse indicators",
                  "Correlate the detections and recent security events you are "
                  "given into a prioritised triage with severity taken only "
                  "from the evidence. If there are no detections, say so."),
            _Step("forensics", "forensics", "Correlate the evidence",
                  "Correlate the posture assessment and the triage into a "
                  "timeline that separates OBSERVED records from INFERENCE, "
                  "and state whether the evidence supports compromise.",
                  deps=("sec", "threat")),
        ),
        extra_evidence=("system", "diagnostics", "network")),
    Playbook(
        "network_investigation",
        (r"\b(network\w*|wi-?fi|internet|dns|connection\w*|connectivity|"
         r"firewall|ports?|latency|packet\w*|egress|vpn)\b",),
        (
            _Step("net", "network", "Summarise network posture",
                  "Summarise the connection state, traffic counters and network "
                  "policy posture you are given and flag anything unexpected. "
                  "Never probe; report what ARGUS already recorded."),
            _Step("diag", "diagnostics", "Inspect runtime failures",
                  "Review runtime health and recent failures for causes of the "
                  "network problem. Distinguish observed failures from "
                  "hypotheses."),
        ),
        extra_evidence=("system", "security")),
    Playbook(
        "failure_diagnosis",
        (r"\b(crash\w*|error\w*|exception\w*|traceback|fail\w*|broken|"
         r"won't (?:start|open|run)|not (?:working|starting|responding)|"
         r"stopped working|keeps closing)\b",),
        (
            _Step("diag", "diagnostics", "Diagnose the failure",
                  "Analyse the runtime health signals and recent failures you "
                  "are given and form a diagnosis: most likely cause, the "
                  "evidence for it, and what to check next."),
            _Step("logs", "log_analysis", "Analyse the supplied logs",
                  "Analyse the supplied log or traceback text for the likely "
                  "cause of the failure. Quote the exact lines that support "
                  "each finding and name what is inferred.",
                  needs_material=True),
            _Step("sys", "system", "Check resource pressure",
                  "Check the telemetry you are given for resource pressure that "
                  "could explain the failure, with the numbers.",
                  when=r"\b(memory|ram|cpu|disk|slow\w*|freez\w*|hang\w*)\b"),
        ),
        extra_evidence=("system", "security")),
    Playbook(
        "code_review",
        (r"\b(code|project|codebase|repo(?:sitory)?|source|script\w*|module\w*|"
         r"function\w*|python|javascript|typescript|backend|frontend|api)\b"
         r".{0,60}\b(review\w*|audit\w*|analy[sz]\w*|check\w*|inspect\w*)\b",
         r"\b(review\w*|audit\w*|analy[sz]\w*|check\w*|inspect\w*)\b.{0,60}"
         r"\b(code|project|codebase|repo(?:sitory)?|source|script\w*|module\w*|"
         r"function\w*|python|javascript|typescript|backend|frontend|api)\b"),
        (
            _Step("pysec", "python_security", "Review Python source for security",
                  "Review the supplied Python source for security weaknesses: "
                  "injection, unsafe deserialisation, weak cryptography, "
                  "hardcoded credentials. Cite the exact lines for each finding.",
                  when=_SEC + r".*" + _PYTHON.pattern + r"|" + _PYTHON.pattern
                  + r".*" + _SEC, order=0),
            _Step("sec", "code_review", "Review supplied code for security",
                  "Review the supplied code for security weaknesses and unsafe "
                  "patterns. Cite the exact lines for each finding and separate "
                  "what the code shows from what you infer.",
                  when=_SEC, order=1, unless="pysec"),
            _Step("perf", "code_review", "Review supplied code for performance",
                  "Review the supplied code for performance problems: "
                  "unbounded loops, repeated work, blocking calls, memory "
                  "growth. Cite the exact lines and say what is inferred.",
                  when=_PERF, order=2),
            _Step("deps", "dependency_review", "Review the dependency list",
                  "Review the supplied dependency or requirements list for "
                  "unpinned versions, known-risk patterns and look-alike names.",
                  when=r"\b(dependenc\w*|requirements?|packages?|pip|npm)\b",
                  order=3),
            _Step("gen", "code_review", "Review the supplied code",
                  "Review the supplied code for correctness, safety and clarity "
                  "problems. Cite the exact lines and separate observation from "
                  "inference.",
                  when=r"^(?!.*(" + _SEC[2:-2] + "|" + _PERF[2:-2]
                  + r"|dependenc\w*|requirements?|packages?)).*$", order=4),
        ),
        extra_evidence=()),
)
_BY_KEY = {p.key: p for p in PLAYBOOKS}


# General/public, multi-part work: research it, compare options, and
# recommend one. Never matched for a LOCAL_REQUIRED or MIXED goal -- see
# assess() below, which runs skills/cloud_gate.classify() on the goal BEFORE
# this playbook is even considered, the SAME classifier every ordinary cloud
# chat reply is gated by.
CLOUD_PLAYBOOK = Playbook(
    "general_research",
    (r"\bresearch\b.{0,80}\bcompare\b", r"\bcompare\b.{0,80}\brecommend",
     r"\b(research|investigate|compare|evaluate)\b.{0,60}\b(options?|"
     r"approaches?|alternatives?|architectures?|frameworks?|tools?|"
     r"libraries?|providers?|services?|platforms?|technologies?|solutions?)\b"
     r".{0,60}\b(compare|recommend|best|trade-?offs?|pros?\s+and\s+cons?)\b"),
    (
        _Step("research", "cloud_research", "Research the options",
              "Research the options named in the goal from general/public "
              "knowledge and summarise what each one is.", order=0),
        _Step("compare", "cloud_research", "Compare and recommend",
              "Compare the options researched and give a clear recommendation "
              "with reasons, and the trade-offs of each.", order=1),
    ))


def playbook(key: str) -> Playbook | None:
    return _BY_KEY.get(key)


# Most specific first: a compromise question that also mentions "slow" is an
# investigation, not a health check; a code review that mentions "errors" is
# a review, not a failure diagnosis.
_MATCH_ORDER = ("compromise_investigation", "code_review", "failure_diagnosis",
                "network_investigation", "machine_health")


def _match_playbook(goal: str) -> Playbook | None:
    for key in _MATCH_ORDER:
        if _BY_KEY[key].matches(goal):
            return _BY_KEY[key]
    return None


def _single_agent(goal: str) -> str:
    try:
        from agents.routing import route
        return route(goal)
    except Exception:
        return "assistant"


def _cap_specialists(steps: list) -> list:
    """At most MAX_EPHEMERAL_PER_TEAM specialists, keeping the most relevant
    (lowest `order`); core steps are never dropped."""
    spec = sorted([s for s in steps if s.is_specialist], key=lambda s: s.order)
    keep = set(s.key for s in spec[:MAX_EPHEMERAL_PER_TEAM])
    return [s for s in steps if not s.is_specialist or s.key in keep]


def _cloud_eligible(text: str, material: str = "") -> bool:
    """Section 4/5/7's gate, reused rather than restated: the SAME classifier
    every ordinary cloud chat reply is gated by. Cloud-eligible only when
    BOTH the goal AND any supplied material are GENERAL (not local_required) --
    MIXED is folded into local_required by cloud_gate itself, so "both"
    already defaults to local here too (section 7, "DEFAULT = LOCAL"). The
    material check matters even for an unmistakably general goal: "research
    X and compare Y" is a public question whatever is pasted alongside it,
    and material is never assumed safe just because the goal is."""
    try:
        from agents.dynamic_spec import cloud_agents_enabled
        if not cloud_agents_enabled():
            return False
        import skills.cloud_gate as cloud_gate
        if cloud_gate.classify(text).local_required:
            return False
        if material and cloud_gate.is_sensitive(material):
            return False
        return True
    except Exception:
        return False                       # fail closed: unclassifiable -> not eligible


def assess(goal: str, material: str = "") -> Assessment:
    """Is a team warranted? Pure* and cheap: the only network-adjacent-looking
    step is the cloud-eligibility check, which is itself a local, offline
    classifier (skills/cloud_gate.classify) -- no network call, no model call,
    same as everything else here."""
    text = clean_text(goal, MAX_GOAL_CHARS)
    if not text:
        return Assessment(False, "", "empty_goal", "assistant")
    pb = _match_playbook(text)
    if pb is None:
        if CLOUD_PLAYBOOK.matches(text) and _cloud_eligible(text, material):
            steps = CLOUD_PLAYBOOK.included(text, material)
            specs = tuple(dict.fromkeys(s.role for s in steps))
            if len(steps) >= 2:
                return Assessment(True, CLOUD_PLAYBOOK.key, "multi_step", "",
                                  (), specs)
        return Assessment(False, "", "no_playbook", _single_agent(text))
    if not INVESTIGATIVE.search(text) and not material:
        return Assessment(False, pb.key, "not_investigative", _single_agent(text))
    steps = _cap_specialists(pb.included(text, material))
    roles = tuple(dict.fromkeys(s.role for s in steps if not s.is_specialist))
    specs = tuple(dict.fromkeys(s.role for s in steps if s.is_specialist))
    if len(steps) < 2 and not specs:
        # One core agent does this on its own (plain routing); a specialist,
        # even alone, needs the team layer: spawn, budget, verify, destroy.
        single = roles[0] if roles else _single_agent(text)
        return Assessment(False, pb.key, "single_agent_sufficient", single,
                          roles, specs)
    if pb.key == "code_review" and not material:
        # Agents cannot read files. A code review with nothing supplied to
        # read is a question for PLANNER (what to supply, how to proceed),
        # not a task for a team.
        return Assessment(False, pb.key, "no_material", "planner", roles, specs)
    return Assessment(True, pb.key, "multi_step", "", roles, specs)


def _core_priority(role: str) -> int:
    spec = get_spec(role)
    return max(1, min(4, spec.priority)) if spec is not None else 3


def _core_scope(role: str) -> tuple:
    spec = get_spec(role)
    cats = tuple(spec.allowed_context_categories) if spec is not None else ()
    return tuple(sorted(set(cats) | {"team_evidence"}))


def build_plan(goal: str, material: str = "", *, request_id: str,
               now: float, priority: int = 2,
               max_runtime_seconds: int | None = None,
               max_model_calls: int | None = None,
               failure_policy: FailurePolicy = FailurePolicy.REPLAN,
               assessment: Assessment | None = None) -> TeamPlan:
    """Goal -> validated TeamPlan. Raises PlanError when no team is warranted
    (callers use assess() first) or the plan cannot be built within limits."""
    text = clean_text(goal, MAX_GOAL_CHARS)
    a = assessment or assess(text, material)
    if not a.needs_team:
        raise PlanError("no_team_needed", a.reason)
    is_cloud_plan = a.playbook == CLOUD_PLAYBOOK.key
    pb = CLOUD_PLAYBOOK if is_cloud_plan else _BY_KEY[a.playbook]
    steps = _cap_specialists(pb.included(text, material))
    members: list = []
    member_of: dict = {}          # role (core) or step key (specialist) -> member id
    tasks: list = []
    ids: dict = {}                # step key -> task id
    for s in steps:
        if s.is_specialist:
            mid = f"M{len(members) + 1}"
            members.append(TeamMember(
                mid, s.role, "cloud" if is_cloud_plan else "specialist",
                parent_agent_id=SPECIALIST_PARENT[s.role]))
            member_of[s.key] = mid
        elif s.role not in member_of:
            mid = f"M{len(members) + 1}"
            members.append(TeamMember(mid, s.role, "core", agent_id=s.role))
            member_of[s.role] = mid
    for n, s in enumerate(steps, start=1):
        ids[s.key] = f"T{n}"
    for s in steps:
        deps = tuple(ids[d] for d in s.deps if d in ids)
        if s.is_specialist:
            tasks.append(TeamTaskSpec(
                ids[s.key], s.title, s.objective, member_of[s.key], s.role,
                dependencies=deps, inputs=tuple(f"task:{d}" for d in deps),
                allowed_data_scope=("provided_source", "team_evidence"),
                requested_capabilities=tuple(s.caps),
                priority=DYNAMIC_DEFAULT_TIER, lineage=(s.role,)))
        else:
            tasks.append(TeamTaskSpec(
                ids[s.key], s.title, s.objective, member_of[s.role], s.role,
                assigned_agent_id=s.role, dependencies=deps,
                inputs=tuple(f"task:{d}" for d in deps),
                allowed_data_scope=_core_scope(s.role),
                requested_capabilities=tuple(s.caps),
                priority=_core_priority(s.role), lineage=(s.role,)))
    members, tasks = _with_verify(members, tasks)
    n_spec = sum(1 for m in members if m.kind != "core")
    return TeamPlan(
        team_id=team_id_for(request_id), request_id=request_id, goal=text,
        created_at=now, members=tuple(members), tasks=tuple(tasks),
        priority=priority, max_agents=MAX_TEAM_MEMBERS,
        max_ephemeral_agents=min(MAX_EPHEMERAL_PER_TEAM, max(n_spec, 1)),
        max_model_calls=max_model_calls or _default_calls(len(tasks)),
        max_runtime_seconds=min(MAX_TEAM_RUNTIME_S,
                                max_runtime_seconds or DEFAULT_TEAM_RUNTIME_S),
        failure_policy=failure_policy)


def _default_calls(n_tasks: int) -> int:
    # one call per task, one retry each, plus room for a replan -- then capped
    from agents.team_schema import DEFAULT_MODEL_CALLS, MAX_MODEL_CALLS
    return max(DEFAULT_MODEL_CALLS, min(MAX_MODEL_CALLS, n_tasks * 2 + 4))


def _free_id(used) -> str:
    n = 1
    while f"T{n}" in used:
        n += 1
    return f"T{n}"


def _with_verify(members: list, tasks: list, *, verify_deps=None) -> tuple:
    """Append the independent VERIFY task (core VERIFIER) depending on every
    analysis task, adding the verifier as a member if it is not one yet."""
    members = list(members)
    tasks = list(tasks)
    vid = next((m.member_id for m in members if m.role == "verifier"), "")
    if not vid:
        vid = f"M{len(members) + 1}"
        members.append(TeamMember(vid, "verifier", "core", agent_id="verifier"))
    deps = tuple(verify_deps) if verify_deps is not None else tuple(
        t.task_id for t in tasks if t.kind is TaskKind.AGENT)
    tasks.append(TeamTaskSpec(
        _free_id({t.task_id for t in tasks}), "Verify the team's conclusions",
        "Independently judge whether the goal was achieved from the evidence "
        "the tasks produced: are required tasks complete, is the evidence "
        "present, are the conclusions supported, are there contradictions.",
        vid, "verifier", kind=TaskKind.VERIFY, assigned_agent_id="verifier",
        dependencies=deps, inputs=tuple(f"task:{d}" for d in deps),
        trigger="all_terminal", allowed_data_scope=_core_scope("verifier"),
        expected_output_schema="verdict", priority=_core_priority("verifier"),
        max_attempts=2, lineage=("verifier",)))
    return members, tasks


# ═══════════════════════════════════════════════════════════════════════
# extension: handoffs and replans ADD tasks; nothing is rewritten
# ═══════════════════════════════════════════════════════════════════════
def _next_ids(plan: TeamPlan):
    used = {t.task_id for t in plan.tasks}
    while True:
        tid = _free_id(used)
        used.add(tid)
        yield tid


def extend_plan(plan: TeamPlan, new_members, new_tasks, *,
                verified_task_ids=()) -> TeamPlan:
    """A new TeamPlan = the old one + members + agent tasks, with ONE pending
    VERIFY task depending on every agent task. A VERIFY task that already ran
    (in `verified_task_ids`) is kept as history; a pending one is re-pointed
    at the full set (its id is preserved so the run's record stays valid);
    if none is pending, a fresh one is appended."""
    members = list(plan.members) + list(new_members)
    agent_tasks = [t for t in plan.tasks if t.kind is TaskKind.AGENT] + list(new_tasks)
    old_verify = [t for t in plan.tasks if t.kind is TaskKind.VERIFY]
    all_agent_ids = tuple(t.task_id for t in agent_tasks)
    tasks = list(agent_tasks)
    pending = [t for t in old_verify if t.task_id not in verified_task_ids]
    done = [t for t in old_verify if t.task_id in verified_task_ids]
    tasks += done
    if pending:
        v = pending[-1]
        tasks += [t for t in pending if t is not v]
        tasks.append(dataclasses.replace(
            v, dependencies=all_agent_ids,
            inputs=tuple(f"task:{d}" for d in all_agent_ids)))
    else:
        members, tasks = _with_verify(members, tasks, verify_deps=all_agent_ids)
    tasks.sort(key=lambda t: int(t.task_id[1:]))
    return dataclasses.replace(plan, members=tuple(members), tasks=tuple(tasks))


def handoff_task(plan: TeamPlan, from_task: TeamTaskSpec, to_role: str,
                 requested: str, context_refs) -> tuple:
    """(new_member_or_None, new_task) for an ACCEPTED handoff to a core agent.
    Lineage carries the chain of roles so a cycle is detectable."""
    gen = _next_ids(plan)
    tid = next(gen)
    member = next((m for m in plan.members if m.kind == "core"
                   and m.agent_id == to_role), None)
    new_member = None
    if member is None:
        new_member = TeamMember(f"M{len(plan.members) + 1}", to_role, "core",
                                agent_id=to_role)
        member = new_member
    objective = clean_text(
        f"Continue the analysis handed to you by {from_task.required_role}: "
        f"{requested or from_task.objective}", MAX_OBJECTIVE_CHARS)
    task = TeamTaskSpec(
        tid, clean_text(f"Handoff: {from_task.title}", 80), objective,
        member.member_id, to_role, assigned_agent_id=to_role,
        dependencies=(from_task.task_id,),
        inputs=tuple(r for r in context_refs if isinstance(r, str)
                     and re.match(r"^ev-[0-9a-f]{8}$", r))[:8],
        allowed_data_scope=_core_scope(to_role),
        priority=_core_priority(to_role), required=False, max_attempts=1,
        lineage=tuple(from_task.lineage) + (to_role,), origin="handoff")
    return new_member, task


@dataclass(frozen=True)
class ReplanProposal:
    members: tuple
    tasks: tuple
    strategy: tuple               # codes, in order applied
    replaced: tuple               # (old_task_id, new_task_id)

    @property
    def empty(self) -> bool:
        return not self.tasks


def replan(plan: TeamPlan, task_view: list, reason: str, *, playbook_key: str,
           ephemeral_left: int, agents_left: int, goal: str) -> ReplanProposal:
    """Deterministic strategies, bounded by what is left of the budgets.

    task_view: [{task_id, kind, state, role, member_kind, required, origin,
                 replaced_by, title, objective, parent_agent_id}]
    reason: task_failed | insufficient_evidence | contradicted | partial
    """
    members, tasks, strategy, replaced = [], [], [], []
    existing_roles = {m.role for m in plan.members}
    gen = _next_ids(plan)
    n_tasks = len(plan.tasks)
    ephemeral_left = max(0, ephemeral_left)
    agents_left = max(0, agents_left)

    def room() -> bool:
        return n_tasks + len(tasks) + 1 < MAX_TASKS      # +1: the verify task

    failed = [t for t in task_view
              if t["kind"] == TaskKind.AGENT.value and t["required"]
              and t["state"] in (TaskState.FAILED.value, TaskState.TIMED_OUT.value,
                                 TaskState.SKIPPED.value)
              and not t["replaced_by"]]
    for t in failed:
        if not room():
            break
        role = t["role"]
        if t["member_kind"] == "core" and role in CORE_TO_SPECIALIST \
                and ephemeral_left > 0:
            tmpl = CORE_TO_SPECIALIST[role]
            mid = f"M{len(plan.members) + len(members) + 1}"
            members.append(TeamMember(mid, tmpl, "specialist",
                                      parent_agent_id=SPECIALIST_PARENT[tmpl]))
            tid = next(gen)
            tasks.append(TeamTaskSpec(
                tid, clean_text(f"{t['title']} (specialist)", 80),
                t["objective"], mid, tmpl,
                allowed_data_scope=("provided_source", "team_evidence"),
                priority=DYNAMIC_DEFAULT_TIER, max_attempts=1,
                lineage=(role, tmpl), origin="replan"))
            ephemeral_left -= 1
            strategy.append(f"specialist_for:{role}")
            replaced.append((t["task_id"], tid))
        elif t["member_kind"] == "specialist" and agents_left > 0:
            parent = t["parent_agent_id"] or SPECIALIST_PARENT.get(role, "")
            if parent not in ("security", "threat", "system", "network",
                              "diagnostics", "forensics", "planner"):
                continue
            core_member = next((m for m in plan.members + tuple(members)
                                if m.kind == "core" and m.agent_id == parent), None)
            if core_member is None:
                core_member = TeamMember(
                    f"M{len(plan.members) + len(members) + 1}", parent, "core",
                    agent_id=parent)
                members.append(core_member)
                agents_left -= 1
            tid = next(gen)
            tasks.append(TeamTaskSpec(
                tid, clean_text(f"{t['title']} (core fallback)", 80),
                t["objective"], core_member.member_id, parent,
                assigned_agent_id=parent, allowed_data_scope=_core_scope(parent),
                priority=_core_priority(parent), max_attempts=1,
                lineage=(role, parent), origin="replan"))
            strategy.append(f"core_fallback_for:{role}")
            replaced.append((t["task_id"], tid))

    if reason in ("insufficient_evidence", "contradicted") and room():
        pb = _BY_KEY.get(playbook_key)
        for role in (pb.extra_evidence if pb else ()):
            if role in existing_roles or agents_left <= 0:
                continue
            spec = get_spec(role)
            if spec is None or not spec.enabled:
                continue
            mid = f"M{len(plan.members) + len(members) + 1}"
            members.append(TeamMember(mid, role, "core", agent_id=role))
            tid = next(gen)
            tasks.append(TeamTaskSpec(
                tid, clean_text(f"Additional evidence from {role}", 80),
                clean_text(
                    f"Collect additional evidence relevant to this goal from the "
                    f"context you are given, with sources and numbers, and say "
                    f"plainly what is absent. Goal: {goal}", MAX_OBJECTIVE_CHARS),
                mid, role, assigned_agent_id=role,
                allowed_data_scope=_core_scope(role),
                priority=_core_priority(role), required=False, max_attempts=1,
                lineage=(role,), origin="replan"))
            strategy.append(f"extra_evidence:{role}")
            agents_left -= 1
            break
    return ReplanProposal(tuple(members), tuple(tasks), tuple(strategy),
                          tuple(replaced))
