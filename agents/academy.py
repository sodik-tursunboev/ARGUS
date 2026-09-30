"""Synthetic, lower-priority training for existing ARGUS core agents.

Training uses the normal coordinator/model queue, never tools or live machine
context. A separate verifier job and deterministic checks gate a curated
lesson. Lessons can inform later analysis; they never change agent authority.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.

import json
import os
import re
import threading
import time
import uuid

import paths
import security
from agents.coordinator import coordinator
from agents.registry import registry


# Each exercise is synthetic, with a human-reviewed expected principle. The
# deterministic key is checked independently of either model's verdict.
CURRICULUM = {
    "system": ("Windows diagnostics", "A synthetic Windows service will not start and the system disk is 96% full. Diagnose without changing the machine.", (("disk", "storage", "space"), ("service", "startup")), "Check free disk space and service startup evidence before proposing a repair."),
    "network": ("DNS diagnostics", "A synthetic host reaches an IP address but not example.test; its configured DNS resolver times out. Isolate the fault.", (("dns", "resolver"), ("timeout", "unreachable", "failure")), "Test the configured DNS resolver separately from IP connectivity."),
    "security": ("Configuration review", "A synthetic policy report says firewall is disabled but provides no evidence of an intrusion. Give a defensive assessment.", (("firewall",), ("no evidence", "not evidence", "unknown", "cannot conclude")), "Report a disabled firewall as risk, not proof of compromise."),
    "threat": ("Persistence detection", "A synthetic scheduled task launches an unknown binary at login; the binary hash has not been checked. Triage the indicator.", (("scheduled task", "persistence"), ("hash", "signature", "verify")), "Treat a login task as a persistence indicator and verify the binary before concluding malware."),
    "forensics": ("Timeline reconstruction", "A synthetic log shows file creation at 10:02 and execution at 10:04; the clock offset is unknown. Reconstruct cautiously.", (("10:02", "creation"), ("10:04", "execution"), ("clock", "offset")), "Order observed events and disclose unknown clock offset."),
    "diagnostics": ("Root-cause isolation", "A synthetic app fails after an update, but an unrelated warning occurred earlier. Separate correlation from cause.", (("update",), ("warning",), ("evidence", "test", "compare")), "Test the update hypothesis; an earlier warning alone does not establish cause."),
    "planner": ("Team selection", "A synthetic PC slowdown needs resource evidence and failure-log analysis. Choose a minimal team and verifier.", (("system",), ("diagnostics",), ("verifier", "verify")), "Use System and Diagnostics for independent evidence, then Verifier; do not spawn extra workers by default."),
    "verifier": ("Unsupported-claim detection", "A synthetic report says malware was removed, but supplies only a model opinion and no scan or audit evidence. Evaluate the claim.", (("unsupported", "not verified", "insufficient"), ("evidence", "scan", "audit")), "Reject the removal claim until independent evidence is provided."),
    "response": ("Safe response planning", "A synthetic alert names a suspicious process but no confirmed compromise. Propose reversible next steps only.", (("isolate", "observe", "inspect"), ("approval", "authorize", "reversible")), "Inspect and preserve evidence first; request authorization before disruptive action."),
    "assistant": ("Clarification and summary", "A synthetic user says 'fix it' with no target or symptom. Respond helpfully without inventing a task.", (("clarify", "which", "what"), ("target", "issue", "symptom")), "Ask for the target and symptom rather than inventing the user's intent."),
}
ACTIVE = {"SCHEDULED", "QUEUED", "ACTIVE", "EVALUATING"}
TERMINAL = {"PASSED", "FAILED", "CANCELLED"}


class Academy:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}
        self._job_map: dict[str, tuple[str, str]] = {}
        self._lessons: dict[str, dict] = {}
        self._load_lessons()
        coordinator().add_hook(self)

    def _load_lessons(self):
        try:
            with open(paths.writable("academy_lessons.json"), encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._lessons = {k: v for k, v in data.items()
                                 if k in CURRICULUM and isinstance(v, dict)
                                 and v.get("lesson") == CURRICULUM[k][3]}
        except (OSError, ValueError, TypeError):
            self._lessons = {}

    def _save_lessons(self):
        target = paths.writable("academy_lessons.json")
        temp = target + ".tmp"
        try:
            with open(temp, "w", encoding="utf-8") as f:
                json.dump(self._lessons, f, ensure_ascii=False, sort_keys=True)
            os.replace(temp, target)
        except OSError:
            # Never claim a lesson is durable when persistence failed.
            self._lessons = {}

    def lessons_for(self, agent_id: str) -> str:
        with self._lock:
            item = self._lessons.get(agent_id)
            return str(item.get("lesson", ""))[:300] if item else ""

    def train(self, agent_ids: list[str], topic: str = "") -> dict:
        ids = list(dict.fromkeys(str(a).lower().strip() for a in agent_ids))[:10]
        if not ids or any(a not in CURRICULUM for a in ids):
            return {"ok": False, "reason": "unknown_core_agent", "sessions": []}
        if topic:
            terms = topic.lower().split()
            if any(not all(term in CURRICULUM[a][0].lower() for term in terms) for a in ids):
                return {"ok": False, "reason": "curriculum_not_available", "sessions": []}
        created = []
        with self._lock:
            for agent_id in ids:
                if any(s["agent_id"] == agent_id and s["state"] in ACTIVE
                       for s in self._sessions.values()):
                    continue
                skill, scenario, checks, _lesson = CURRICULUM[agent_id]
                sid = "study-" + uuid.uuid4().hex[:12]
                session = {"session_id": sid, "agent_id": agent_id,
                           "curriculum": skill, "skill": skill,
                           "scenario": scenario, "state": "SCHEDULED",
                           "backend": "LOCAL_CORE", "provider": "OLLAMA",
                           "model": coordinator()._runtime.model_id(),
                           "score": None, "verifier_result": "",
                           "evidence": [], "job_id": "", "verifier_job_id": "",
                           "created_at": time.time(), "started_at": None,
                           "finished_at": None, "reason": ""}
                self._sessions[sid] = session
                created.append(sid)
            self._trim()
        for sid in created:
            with self._lock:
                session = self._sessions[sid]
                aid, skill, scenario = session["agent_id"], session["skill"], session["scenario"]
            objective = (f"ACADEMY_SESSION={sid} PHASE=student. SYNTHETIC ACADEMY EXERCISE ({skill}). {scenario} "
                         "Return structured findings and evidence. No tools, no live machine action.")
            job, why = coordinator().submit(aid, objective, priority=4, source="academy")
            with self._lock:
                if job:
                    session["job_id"] = job.job_id
                    if session["state"] == "SCHEDULED":
                        session["state"] = "ACTIVE" if job.state == "running" else "QUEUED"
                    self._job_map[job.job_id] = (sid, "student")
                else:
                    session["state"] = "FAILED"
                    session["reason"] = why
                    session["finished_at"] = time.time()
        return {"ok": bool(created), "reason": "queued" if created else "already_training",
                "sessions": [self._public(self._sessions[sid]) for sid in created]}

    def _trim(self):
        if len(self._sessions) <= 80:
            return
        old = sorted((s for s in self._sessions.values() if s["state"] in TERMINAL),
                     key=lambda s: s["created_at"])
        for session in old[:len(self._sessions) - 80]:
            self._sessions.pop(session["session_id"], None)

    def owns_job(self, job) -> bool:
        return job.source == "academy"

    def _resolve(self, job):
        mapped = self._job_map.get(job.job_id)
        if mapped:
            return mapped
        # The coordinator starts its worker immediately after submission. A
        # fast local response can arrive before submit() returns a job id.
        # The bounded, server-generated session marker closes that race.
        marker = re.search(r"ACADEMY_SESSION=(study-[a-f0-9]{12}) PHASE=(student|verifier)",
                           job.objective)
        if marker and marker.group(1) in self._sessions:
            mapped = (marker.group(1), marker.group(2))
            self._job_map[job.job_id] = mapped
        return mapped

    def job_started(self, job):
        with self._lock:
            mapped = self._resolve(job)
            if mapped:
                session = self._sessions.get(mapped[0])
                if session and session["state"] not in TERMINAL:
                    session["state"] = "ACTIVE" if mapped[1] == "student" else "EVALUATING"
                    session["started_at"] = session["started_at"] or time.time()

    def after_result(self, _coord, job, _raw, result, _ctx):
        with self._lock:
            mapped = self._resolve(job)
            if not mapped:
                return
            session = self._sessions.get(mapped[0])
            if not session or session["state"] in TERMINAL:
                return
            if mapped[1] == "student":
                text = " ".join([result.summary, result.analysis, *result.findings,
                                 *result.evidence]).lower()
                checks = CURRICULUM[session["agent_id"]][2]
                matched = sum(any(term in text for term in group) for group in checks)
                session["score"] = round(100 * matched / len(checks))
                session["evidence"] = [security.redact(x)[:250] for x in result.evidence[:4]]
                session["candidate"] = security.redact(result.summary)[:500]
            else:
                session["verifier_result"] = result.verification or "insufficient_evidence"

    def job_finished(self, job, state, reason):
        with self._lock:
            mapped = self._resolve(job)
            self._job_map.pop(job.job_id, None)
            if not mapped:
                return
            sid, phase = mapped
            session = self._sessions.get(sid)
            if not session or session["state"] in TERMINAL:
                return
            if state != "completed":
                session["state"] = "CANCELLED" if state == "cancelled" else "FAILED"
                session["reason"] = reason or state
                session["finished_at"] = time.time()
                return
            if phase == "verifier":
                passed = session["score"] == 100 and session["verifier_result"] == "verified"
                session["state"] = "PASSED" if passed else "FAILED"
                session["reason"] = "" if passed else "verification_failed"
                session["finished_at"] = time.time()
                if passed:
                    aid = session["agent_id"]
                    self._lessons[aid] = {"skill": session["skill"],
                                          "lesson": CURRICULUM[aid][3],
                                          "session_id": sid, "verified_at": time.time()}
                    self._save_lessons()
                return
            session["state"] = "EVALUATING"
            aid, scenario = session["agent_id"], session["scenario"]
            candidate = session.get("candidate", "")
        objective = (f"ACADEMY_SESSION={sid} PHASE=verifier. Independently verify this SYNTHETIC training answer. Scenario: {scenario} "
                     f"Candidate: {candidate}. Return verification=verified only if supported; "
                     "otherwise not_verified or insufficient_evidence. No tools or live context.")
        verifier, why = coordinator().submit("verifier", objective, priority=4,
                                              source="academy")
        with self._lock:
            if verifier:
                session["verifier_job_id"] = verifier.job_id
                self._job_map[verifier.job_id] = (sid, "verifier")
            else:
                session["state"] = "FAILED"
                session["reason"] = f"verifier_unavailable:{why}"
                session["finished_at"] = time.time()

    def cancel(self, agent_id: str) -> bool:
        with self._lock:
            sessions = [s for s in self._sessions.values()
                        if s["agent_id"] == agent_id and s["state"] in ACTIVE]
            ids = [s["verifier_job_id"] or s["job_id"] for s in sessions]
            for session in sessions:
                session["state"] = "CANCELLED"
                session["reason"] = "owner_cancel_or_user_work"
                session["finished_at"] = time.time()
        for jid in ids:
            if jid:
                coordinator().cancel(jid)
        return bool(sessions)

    @staticmethod
    def _public(session):
        return {k: v for k, v in session.items() if k != "candidate"}

    def state(self) -> dict:
        with self._lock:
            sessions = sorted(self._sessions.values(), key=lambda s: s["created_at"], reverse=True)
            now = time.time()
            counts = {state: sum(s["state"] == state for s in sessions)
                      for state in (*ACTIVE, *TERMINAL)}
            counts["completed_today"] = sum(s["state"] == "PASSED" and
                                            s["finished_at"] and now - s["finished_at"] < 86400
                                            for s in sessions)
            counts["failed_today"] = sum(s["state"] == "FAILED" and
                                         s["finished_at"] and now - s["finished_at"] < 86400
                                         for s in sessions)
            return {"sessions": [self._public(s) for s in sessions[:60]],
                    "counts": counts, "lessons": dict(self._lessons),
                    "backend": "LOCAL_CORE", "hermes": "NOT_MERGED"}


_ACADEMY: Academy | None = None
_INIT_LOCK = threading.Lock()


def academy() -> Academy:
    global _ACADEMY
    if _ACADEMY is None:
        with _INIT_LOCK:
            if _ACADEMY is None:
                _ACADEMY = Academy()
    return _ACADEMY


def cancel_for_work(agent_id: str):
    """User work outranks optional study. No instance is created just to cancel."""
    if _ACADEMY is not None:
        _ACADEMY.cancel(agent_id)


_TRAIN = re.compile(r"^(?:send|train|teach|have)\s+(.+?)\s+(?:to\s+(?:academy|study)|on\s+(.+)|practice\s+(.+))\.?$", re.I)
_STOP = re.compile(r"^stop\s+(\w+)(?:'s)?\s+training\.?$", re.I)
# "Send all agents to ARGUS Academy to learn", "enroll all agents to academy",
# "all agents go to the academy", "everyone go study", "train all the workers":
# an order that names EVERY agent and the Academy/study. Every core agent is
# enrolled; they study one at a time on the shared local model, the rest wait
# in class. Spoken requests arrive wrapped in other words ("My day was good,
# just sent all local agents to ARGUS Academy") and in any tense, so each
# CLAUSE is tested (see _clauses) -- a question or a negation never matches.
_WHO = r"(?:all|every(?:one|body)|each)(?:\s+(?:of\s+)?(?:the\s+|my\s+|our\s+)?(?:local\s+|core\s+|argus\s+)*(?:agents?|workers?|robots?|ones?))?"
_WHERE = r"(?:(?:go|going|went)\s+)?(?:(?:in)?to\s+)?(?:the\s+)?(?:argus\s+)?(?:academy|school|class(?:es)?|study|learn|train(?:ing)?)"
_ALL_STUDY = re.compile(
    r"^(?:(?:send|sent|sending|enrol+|enrol+ed|enrol+ing|take|took|move|moved|put|have|let|make|get|got|"
    r"bring|brought|train|teach)\s+)?" + _WHO + r"\b"
    r"(?:\s+(?:must|should|need\s+to|have\s+to|to|go|now|and|all))*"
    r"\s+" + _WHERE +
    r"(?:\s+(?:and\s+|to\s+)?(?:learn|study|train)(?:ing)?)*\s*$", re.I)
_TRAIN_ALL = re.compile(r"^(?:train|teach|enrol+)\s+" + _WHO + r"\s*$", re.I)
_STOP_ALL = re.compile(r"^(?:stop|end|cancel)\s+(?:all\s+)?(?:the\s+)?(?:academy\s+)?"
                       r"(?:training|studying|study|classes|lessons)(?:\s+for\s+(?:all|everyone))?\s*$", re.I)
# "The Academy is empty", "no one is sitting in the academy", "who's at the
# Academy": answered from the real sessions -- the chat model cannot see them
# and would otherwise improvise.
_STATUS = re.compile(
    r"\bacademy\b.{0,40}\b(?:empty|nobody|no\s*one|no-one|nothing)\b"
    r"|\b(?:nobody|no\s*one|no-one)\b.{0,40}\b(?:academy|class(?:room)?)\b"
    r"|\bwho(?:'s|\s+is|\s+are)\s+(?:in|at|sitting\s+in|studying\s+(?:in|at))\s+(?:the\s+)?(?:argus\s+)?academy\b"
    r"|^(?:who(?:'s|\s+is)\s+studying|academy\s+status)$", re.I)
_FILLER = re.compile(r"^(?:(?:ok(?:ay)?|so|and|then|now|just|please|also|argus|hey|well|alright|"
                     r"i|i've|i\s+have|i'd\s+like\s+to|we|we've|let's|lets|go\s+ahead\s+and|can\s+you|"
                     r"could\s+you|would\s+you|will\s+you)\b[\s,]*)+", re.I)
_QUESTION = re.compile(r"^(?:did|do|does|are|is|was|were|has|have\s+you|can\s+(?!you\b)|should|would\s+(?!you\b)|"
                       r"why|how|what|when|where|whether|if)\b", re.I)
_NEGATED = re.compile(r"\b(?:don'?t|do\s+not|never|not|no\s+longer|stop\s+sending)\b", re.I)


def _clauses(text: str):
    """The sentence's clauses, each with its lead-in filler removed. A clause
    that is a question or a negation is dropped: only orders remain."""
    for part in re.split(r"[.;!?]+|,\s*|\s+and\s+then\s+|\s+then\s+", text):
        clause = _FILLER.sub("", part.strip()).strip(" ,")
        if clause and not _QUESTION.match(clause) and not _NEGATED.search(clause):
            yield clause


def _status_reply() -> str:
    sessions = academy().state()["sessions"]
    open_ = [s for s in sessions if s["state"] in ACTIVE]
    if open_:
        studying = [s["agent_id"].upper() for s in open_ if s["state"] == "ACTIVE"]
        checked = [s["agent_id"].upper() for s in open_ if s["state"] == "EVALUATING"]
        waiting = len(open_) - len(studying) - len(checked)
        parts = [f"{len(open_)} agent{'s are' if len(open_) != 1 else ' is'} at the Academy"]
        if studying:
            parts.append(f"{', '.join(studying)} studying")
        if checked:
            parts.append(f"{', '.join(checked)} being checked")
        if waiting:
            parts.append(f"{waiting} waiting for the shared model")
        return ": ".join(parts[:1]) + (" -- " + "; ".join(parts[1:]) if len(parts) > 1 else "") + "."
    done = [s for s in sessions if s["state"] in TERMINAL]
    last = (f" The last class: {sum(s['state'] == 'PASSED' for s in done)} passed, "
            f"{sum(s['state'] == 'FAILED' for s in done)} failed." if done else "")
    return ("The Academy is empty -- nobody is enrolled right now." + last
            + " Say \"send all agents to the Academy\" and they will go.")


def _enrol_everyone() -> str:
    ids = [a.spec.id for a in registry().all() if a.spec.id in CURRICULUM and a.spec.enabled]
    out = academy().train(ids)
    enrolled = len(out["sessions"])
    already = sum(1 for s in academy().state()["sessions"] if s["state"] in ACTIVE) - enrolled
    if not out["ok"]:
        return "Every agent is already enrolled at the Academy."
    return (f"Sending {enrolled} agents to the ARGUS Academy"
            + (f" ({already} already there)" if already > 0 else "")
            + ". They study one at a time on the shared local model; the rest wait in class.")


def command(text: str) -> str | None:
    """Strict Academy intent; every unrelated command falls through unchanged."""
    clean = re.sub(r"^(?:hey\s+)?argus[,! ]+", "", str(text or "").strip(), flags=re.I).strip()
    low = clean.lower().rstrip("?.!")
    clauses = list(_clauses(clean))
    if any((_ALL_STUDY.match(c) or _TRAIN_ALL.match(c)) and "idle" not in c.lower() for c in clauses):
        return _enrol_everyone()
    if any(_STOP_ALL.match(c) for c in clauses):
        stopped = [a for a in CURRICULUM if academy().cancel(a)]
        return (f"Stopped Academy training for {len(stopped)} agents." if stopped
                else "No agent is training right now.")
    if _STATUS.search(low):
        return _status_reply()
    m = re.match(r"^what did (\w+) learn$", low)
    if m and m.group(1) in CURRICULUM:
        lesson = academy().lessons_for(m.group(1))
        return f"{m.group(1).upper()} learned: {lesson}" if lesson else f"No verified Academy lesson for {m.group(1).upper()} yet."
    m = _STOP.match(clean)
    if m and m.group(1).lower() in CURRICULUM:
        return (f"Stopped {m.group(1).upper()}'s training." if academy().cancel(m.group(1).lower())
                else f"{m.group(1).upper()} is not training.")
    if low in ("go study", "send all idle agents to academy", "send all idle agents to study"):
        ids = [a.spec.id for a in registry().all() if a.spec.id in CURRICULUM and a.state == "idle"]
        out = academy().train(ids)
        return f"Queued {len(out['sessions'])} idle agents for synthetic Academy exercises." if out["ok"] else "No idle core agents are available to study."
    m = _TRAIN.match(clean)
    if not m:
        return None
    names = [part.strip().lower() for part in re.split(r"\s+and\s+|,", m.group(1))]
    if not names or any(name not in CURRICULUM for name in names):
        return "Academy can currently train only named local core agents; Hermes training is unavailable."
    out = academy().train(names, (m.group(2) or m.group(3) or "").strip())
    if not out["ok"]:
        return f"Academy could not schedule that: {out['reason'].replace('_', ' ')}."
    return "Queued Academy training for " + ", ".join(s["agent_id"].upper() for s in out["sessions"]) + "."
