'ARGUS - Agent teams: evidence and provenance.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import enum
import hashlib
import re
import time
from dataclasses import dataclass

from agents.governor import scrub_task

MAX_REFS_PER_TEAM = 60
SUMMARY_CHARS = 300


class SourceType(str, enum.Enum):
    TELEMETRY = "TELEMETRY"
    FILE = "FILE"
    LOG = "LOG"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    SECURITY_EVENT = "SECURITY_EVENT"
    USER_INPUT = "USER_INPUT"
    CAPABILITY_RESULT = "CAPABILITY_RESULT"
    MODEL_ANALYSIS = "MODEL_ANALYSIS"


class EvidenceClass(str, enum.Enum):
    OBSERVED = "OBSERVED"
    USER_SUPPLIED = "USER_SUPPLIED"
    INFERRED = "INFERRED"


# Which kind of source each agents/context.py category is.
CONTEXT_SOURCE_TYPES = {
    "telemetry": SourceType.TELEMETRY, "network": SourceType.NETWORK,
    "netpolicy": SourceType.NETWORK, "recent_events": SourceType.SECURITY_EVENT,
    "threat_summary": SourceType.SECURITY_EVENT,
    "integrity": SourceType.SECURITY_EVENT, "auth": SourceType.SECURITY_EVENT,
    "runtime_health": SourceType.LOG, "agent_state": SourceType.PROCESS,
    "task_state": SourceType.LOG, "job_evidence": SourceType.LOG,
    "capability_catalog": SourceType.LOG,
}

_STOP = frozenset("the a an and or of to in on at is are was were be been it "
                  "this that with for from as by has have had not no can may "
                  "could would should about into over under than then there "
                  "their they them its also very more most some any all".split())
_NUM = re.compile(r"\d+(?:\.\d+)?")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")


def safe_text(text, limit: int = SUMMARY_CHARS) -> str:
    """The ONLY form in which text moves between agents or into a record:
    redacted (keys, PINs, this session's token), stripped of instruction-shaped
    phrases (a specialist's output is data, and may have been shaped by a
    hostile document it read), normalised and clipped."""
    t = scrub_task(text)
    try:
        import security
        t = security.strip_injection(t)
    except Exception:
        t = ""                       # cannot neutralise -> pass nothing
    return " ".join(t.split())[:limit]


def _tokens(text: str):
    nums = {("%g" % float(n)) for n in _NUM.findall(text)}
    words = {w.lower() for w in _WORD.findall(text)} - _STOP
    return nums, words


def _segments(text: str) -> list:
    """A source block is matched as a whole AND line by line (context blocks
    are multi-line; a claim usually restates ONE line of one)."""
    segs = [s.strip() for s in re.split(r"[\n|;]+", text or "") if s.strip()]
    return segs + ([text] if len(segs) > 1 else [])


def ground(text: str, sources) -> str:
    """The id of the source `text` is grounded in, or "".

    sources: iterable of (source_id, source_text). A claim WITH numbers is
    grounded if it shares at least one number AND one word with a source
    segment; a claim without numbers needs two shared words and a Jaccard
    overlap of at least 0.34 with a segment. Best score wins; ties go to the
    earlier source. Deterministic, cheap, and deliberately conservative -- it
    errs toward "not grounded"."""
    t_nums, t_words = _tokens(text or "")
    best, best_score = "", 0.0
    for sid, stext in sources:
        for seg in _segments(stext):
            s_nums, s_words = _tokens(seg)
            shared_w = t_words & s_words
            union = t_words | s_words
            jac = len(shared_w) / len(union) if union else 0.0
            if t_nums:
                shared_n = t_nums & s_nums
                ok = bool(shared_n) and bool(shared_w)
                score = len(shared_n) + jac
            else:
                ok = len(shared_w) >= 2 and jac >= 0.34
                score = jac
            if ok and score > best_score:
                best, best_score = sid, score
    return best


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source_type: SourceType
    source_agent: str
    source_capability: str
    timestamp: float
    classification: EvidenceClass
    summary: str
    task_id: str = ""
    grounded: bool = True
    derived_from: str = ""
    integrity: str = ""

    def compute_integrity(self) -> str:
        body = "|".join((self.evidence_id, self.source_type.value,
                         self.source_agent, self.source_capability,
                         f"{self.timestamp:.3f}", self.classification.value,
                         self.summary, self.task_id, str(self.grounded),
                         self.derived_from))
        return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]

    def as_dict(self) -> dict:
        return {"evidence_id": self.evidence_id,
                "source_type": self.source_type.value,
                "source_agent": self.source_agent,
                "source_capability": self.source_capability,
                "timestamp": self.timestamp,
                "classification": self.classification.value,
                "summary": self.summary, "task_id": self.task_id,
                "grounded": self.grounded, "derived_from": self.derived_from,
                "integrity": self.integrity}

    @property
    def is_observed_source(self) -> bool:
        """Can this ref SUPPORT an OBSERVED finding?"""
        return (self.classification is not EvidenceClass.INFERRED
                and self.grounded)


class EvidenceStore:
    """One team's evidence. Bounded, deduplicated, tamper-evident."""

    def __init__(self, max_refs: int = MAX_REFS_PER_TEAM):
        self.max_refs = max_refs
        self._refs: dict = {}
        self.dropped = 0

    def add(self, source_type: SourceType, source_agent: str,
            source_capability: str, summary: str, *, task_id: str = "",
            classification: EvidenceClass | None = None,
            grounded: bool = True, derived_from: str = "",
            timestamp: float | None = None):
        text = safe_text(summary)
        if not text:
            return None
        cls = classification or (
            EvidenceClass.INFERRED if source_type is SourceType.MODEL_ANALYSIS
            else EvidenceClass.USER_SUPPLIED if source_type is SourceType.USER_INPUT
            else EvidenceClass.OBSERVED)
        eid = "ev-" + hashlib.sha256("|".join((
            source_type.value, source_agent, source_capability, text,
            task_id)).encode("utf-8", "replace")).hexdigest()[:8]
        if eid in self._refs:
            return self._refs[eid]
        if len(self._refs) >= self.max_refs:
            self.dropped += 1
            return None
        ref = EvidenceRef(
            evidence_id=eid, source_type=source_type, source_agent=source_agent,
            source_capability=source_capability,
            timestamp=time.time() if timestamp is None else timestamp,
            classification=cls, summary=text, task_id=task_id,
            grounded=bool(grounded), derived_from=derived_from)
        object.__setattr__(ref, "integrity", ref.compute_integrity())
        self._refs[eid] = ref
        return ref

    def get(self, evidence_id: str):
        return self._refs.get(evidence_id)

    def all(self) -> list:
        return list(self._refs.values())

    def by_task(self, task_id: str) -> list:
        return [r for r in self._refs.values() if r.task_id == task_id]

    def lines(self, ids, max_chars: int = 900) -> list:
        """Compact, source-tagged lines for an agent's INPUTS block."""
        out, used = [], 0
        for i in ids:
            r = self._refs.get(i)
            if r is None:
                continue
            line = f"[{r.evidence_id} {r.source_type.value}/{r.classification.value}] {r.summary}"
            if used + len(line) > max_chars:
                break
            out.append(line)
            used += len(line)
        return out

    def counts(self) -> dict:
        c = {k.value: 0 for k in EvidenceClass}
        for r in self._refs.values():
            c[r.classification.value] += 1
        c["total"] = len(self._refs)
        c["ungrounded"] = sum(1 for r in self._refs.values() if not r.grounded)
        return c

    def verify_integrity(self) -> list:
        """Ids whose stored hash no longer matches their content."""
        return [r.evidence_id for r in self._refs.values()
                if r.integrity != r.compute_integrity()]
