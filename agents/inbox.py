"""
ARGUS - Agent Messenger / CEO inbox.

The one place an agent may address the owner (the CEO), and the one place the
owner's replies land. Structured messages only: a closed set of types and
attention levels, plain text that is clipped, tag-stripped and redacted
before it is stored, and bounded references (team / task / job / hire ids) --
never a copy of a conversation.

WHAT A MESSAGE CANNOT DO. Nothing here executes, schedules or authorises
anything. A message is data for a human to read. A reply is data routed back
to the task it answers (agents/agent_manager.py decides where); a reply of
"yes" is a PREFERENCE, never authentication -- every machine action still
goes through policy -> auth -> capability bus exactly as before.

SPAM IS A BUG. Ten agents narrating every model call would make the inbox the
thing the owner mutes, which costs the one message that mattered. So every
post goes through a per-task budget (MAX_AGENT_MESSAGES_PER_TASK, of which at
most MAX_PROGRESS_MESSAGES_PER_TASK may be progress chatter), a de-duplication
window and a global per-minute cap. Questions, approval requests and failures
are exempt from the progress budget -- not from the total -- because those
are the messages the owner actually needs.

EVENTS carry ids and closed-vocabulary codes only (agents/events.py hygiene):
the HUD is told THAT a message exists and re-reads the redacted text over
the authenticated REST API.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from agents import events

# ── vocabulary ───────────────────────────────────────────────────────────
INFO = "INFO"
PROGRESS = "PROGRESS"
QUESTION = "QUESTION"
WARNING = "WARNING"
APPROVAL_REQUEST = "APPROVAL_REQUEST"
RESULT = "RESULT"
FAILURE = "FAILURE"
MESSAGE_TYPES = frozenset({INFO, PROGRESS, QUESTION, WARNING, APPROVAL_REQUEST,
                           RESULT, FAILURE})

# Attention levels (how loudly the HUD surfaces it). CRITICAL is rare by
# construction: agents/agent_manager.py is the only caller that uses it.
ATTN_INFO = "INFO"            # inbox only
ATTN_NORMAL = "NORMAL"        # inbox + small notification
ATTN_IMPORTANT = "IMPORTANT"  # notification + highlighted inbox
ATTN_CRITICAL = "CRITICAL"    # prominent alert (+ optional spoken kind)
ATTENTION = (ATTN_INFO, ATTN_NORMAL, ATTN_IMPORTANT, ATTN_CRITICAL)

CEO = "CEO"
AGENT_MESSAGE = "agent.message"
AGENT_REPLY = "agent.reply"

# ── limits (env-overridable, the "configurable limits" of the design) ────
def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


MAX_AGENT_MESSAGES_PER_TASK = _env_int("ARGUS_MAX_AGENT_MESSAGES_PER_TASK", 6, 1, 50)
MAX_PROGRESS_MESSAGES_PER_TASK = _env_int("ARGUS_MAX_PROGRESS_MESSAGES_PER_TASK", 2, 0, 20)
MAX_MESSAGES_PER_MINUTE = _env_int("ARGUS_MAX_AGENT_MESSAGES_PER_MINUTE", 12, 1, 120)
DEDUPE_WINDOW_S = 60.0
MAX_MESSAGES = 200           # bounded history, like every other ARGUS store
TITLE_MAX = 90
BODY_MAX = 700
REPLY_MAX = 400
MAX_OPTIONS = 4

_TAG = re.compile(r"<[^<>]{0,200}>")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_OPTION = re.compile(r"^[a-z][a-z_]{1,23}$")


def _redact(text: str) -> str:
    try:
        import security
        return security.redact(text)
    except Exception:
        return text


def clean(text, limit: int) -> str:
    """Plain, bounded, redacted text. Tags are removed rather than escaped:
    nothing an agent writes is ever markup, and the HUD renders text only."""
    s = _CTRL.sub(" ", _TAG.sub("", str(text or "")))
    s = re.sub(r"[ \t]{2,}", " ", s).strip()
    s = _redact(s)
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


@dataclass
class AgentMessage:
    message_id: str
    sender_agent_id: str
    sender_name: str
    sender_role: str
    type: str
    title: str
    body: str
    priority: str = ATTN_NORMAL
    requires_reply: bool = False
    reply_options: tuple = ()
    recipient: str = CEO
    request_id: str = ""
    task_id: str = ""
    team_id: str = ""
    job_id: str = ""
    hire_id: str = ""
    # Direct-chat thread this belongs to (the agent's id); "" = inbox only.
    thread: str = ""
    created_at: float = field(default_factory=time.time)
    read: bool = False
    resolved: bool = False
    replies: list = field(default_factory=list)

    @property
    def from_ceo(self) -> bool:
        return self.sender_agent_id == "ceo"

    def section(self) -> str:
        """The inbox section the HUD files it under (design §18)."""
        if self.from_ceo:
            return "SENT"
        if self.type in (QUESTION, APPROVAL_REQUEST) and not self.resolved:
            return "QUESTIONS"
        if self.priority in (ATTN_IMPORTANT, ATTN_CRITICAL) or self.type in (WARNING, FAILURE):
            return "IMPORTANT"
        if self.type == RESULT:
            return "RESULTS"
        return "PROGRESS"

    def as_dict(self) -> dict:
        return {
            "message_id": self.message_id, "request_id": self.request_id,
            "task_id": self.task_id, "team_id": self.team_id,
            "job_id": self.job_id, "hire_id": self.hire_id,
            "sender_agent_id": self.sender_agent_id, "sender_name": self.sender_name,
            "sender_role": self.sender_role, "recipient": self.recipient,
            "type": self.type, "title": self.title, "body": self.body,
            "priority": self.priority, "requires_reply": self.requires_reply,
            "reply_options": list(self.reply_options), "thread": self.thread,
            "created_at": self.created_at, "read": self.read,
            "resolved": self.resolved, "section": self.section(),
            "replies": [dict(r) for r in self.replies],
        }


class Inbox:
    def __init__(self, *, clock=time.time):
        self.clock = clock
        self._lock = threading.RLock()
        self._msgs: deque = deque(maxlen=MAX_MESSAGES)
        self._scope_count: dict = {}      # scope -> [total, progress]
        self._recent: deque = deque()     # post timestamps (global rate)
        self._fingerprints: dict = {}     # (sender, title, scope) -> ts
        self.stats = {"posted": 0, "suppressed": 0, "replies": 0}

    # ── posting ──────────────────────────────────────────────────────
    def post(self, *, sender_agent_id: str, sender_name: str, sender_role: str,
             type: str, title: str, body: str = "", priority: str = ATTN_NORMAL,
             requires_reply: bool = False, reply_options=(), request_id: str = "",
             task_id: str = "", team_id: str = "", job_id: str = "",
             hire_id: str = "", thread: str = "", recipient: str = CEO,
             scope: str = "") -> AgentMessage | None:
        """Store one message. Returns None when it was suppressed by a limit
        (the caller need not care -- suppression is the point)."""
        if type not in MESSAGE_TYPES:
            raise ValueError(f"unknown message type {type!r}")
        if priority not in ATTENTION:
            raise ValueError(f"unknown attention level {priority!r}")
        options = tuple(o for o in (reply_options or ()) if _OPTION.match(str(o)))[:MAX_OPTIONS]
        t = self.clock()
        scope = scope or team_id or job_id or hire_id or request_id or thread
        title_c = clean(title, TITLE_MAX)
        from_ceo = sender_agent_id == "ceo"
        with self._lock:
            if not from_ceo and not self._admit(type, priority, sender_agent_id,
                                                title_c, scope, t):
                self.stats["suppressed"] += 1
                return None
            msg = AgentMessage(
                message_id="msg-" + secrets.token_hex(5),
                sender_agent_id=clean(sender_agent_id, 40),
                sender_name=clean(sender_name, 48), sender_role=clean(sender_role, 48),
                type=type, title=title_c, body=clean(body, BODY_MAX), priority=priority,
                requires_reply=bool(requires_reply), reply_options=options,
                recipient=clean(recipient, 40), request_id=clean(request_id, 40),
                task_id=clean(task_id, 8), team_id=clean(team_id, 20),
                job_id=clean(job_id, 20), hire_id=clean(hire_id, 20),
                thread=clean(thread, 40), created_at=t, read=from_ceo)
            self._msgs.append(msg)
            self.stats["posted"] += 1
        events.emit(AGENT_MESSAGE, {
            "message_id": msg.message_id, "sender_agent_id": msg.sender_agent_id,
            "type": msg.type, "priority": msg.priority, "team_id": msg.team_id,
            "requires_reply": msg.requires_reply, "thread": msg.thread, "ts": t})
        return msg

    def _admit(self, type_, priority, sender, title, scope, t) -> bool:
        """Rate limits. Called under the lock."""
        while self._recent and self._recent[0] < t - 60:
            self._recent.popleft()
        urgent = type_ in (QUESTION, APPROVAL_REQUEST, FAILURE) or priority == ATTN_CRITICAL
        if len(self._recent) >= MAX_MESSAGES_PER_MINUTE and not urgent:
            return False
        fp = (sender, title, scope)
        last = self._fingerprints.get(fp)
        if last is not None and t - last < DEDUPE_WINDOW_S:
            return False
        if scope:
            total, progress = self._scope_count.get(scope, (0, 0))
            if total >= MAX_AGENT_MESSAGES_PER_TASK:
                return False
            chatter = type_ in (PROGRESS, INFO)
            if chatter and progress >= MAX_PROGRESS_MESSAGES_PER_TASK:
                return False
            self._scope_count[scope] = (total + 1, progress + (1 if chatter else 0))
            if len(self._scope_count) > 500:
                self._scope_count.pop(next(iter(self._scope_count)))
        self._fingerprints[fp] = t
        if len(self._fingerprints) > 500:
            self._fingerprints.pop(next(iter(self._fingerprints)))
        self._recent.append(t)
        return True

    # ── replies ──────────────────────────────────────────────────────
    def record_reply(self, message_id: str, *, text: str = "", choice: str = ""
                     ) -> tuple:
        """Attach the CEO's reply. Returns (message, error_code). Validation
        only -- routing the reply is agents/agent_manager.py's job."""
        text_c = clean(text, REPLY_MAX)
        choice = str(choice or "").strip().lower()
        with self._lock:
            msg = self.get(message_id)
            if msg is None:
                return None, "no_such_message"
            if msg.from_ceo:
                return None, "not_replyable"
            if choice and choice not in msg.reply_options:
                return None, "invalid_choice"
            # An APPROVAL is a closed decision; a QUESTION may be answered in
            # the CEO's own words (that text is often the missing material).
            if (msg.type == APPROVAL_REQUEST and msg.reply_options
                    and not msg.resolved and not choice):
                return None, "choice_required"
            if not choice and not text_c:
                return None, "empty_reply"
            if msg.requires_reply and msg.resolved and choice:
                return None, "already_answered"
            msg.replies.append({"text": text_c, "choice": choice, "at": self.clock()})
            msg.read = True
            if msg.requires_reply:
                msg.resolved = True
            self.stats["replies"] += 1
        events.emit(AGENT_REPLY, {"message_id": message_id, "choice": choice,
                                  "ts": self.clock()})
        return msg, ""

    def mark_read(self, message_id: str) -> bool:
        with self._lock:
            msg = self.get(message_id)
            if msg is None:
                return False
            msg.read = True
            return True

    # ── reads ────────────────────────────────────────────────────────
    def get(self, message_id: str) -> AgentMessage | None:
        with self._lock:
            for m in self._msgs:
                if m.message_id == message_id:
                    return m
        return None

    def messages(self, *, thread: str = "", limit: int = 60) -> list:
        """Newest first. With `thread`, only that agent's direct-chat thread
        (both directions); without, everything addressed to the CEO."""
        with self._lock:
            items = list(self._msgs)
        if thread:
            items = [m for m in items if m.thread == thread]
        else:
            items = [m for m in items if not m.from_ceo]
        return [m.as_dict() for m in reversed(items)][:max(1, min(200, limit))]

    def summary(self) -> dict:
        with self._lock:
            items = [m for m in self._msgs if not m.from_ceo]
        sections: dict = {"IMPORTANT": 0, "QUESTIONS": 0, "PROGRESS": 0, "RESULTS": 0}
        for m in items:
            if not m.read:
                sections[m.section()] = sections.get(m.section(), 0) + 1
        return {"unread": sum(1 for m in items if not m.read),
                "open_questions": sum(1 for m in items if m.requires_reply and not m.resolved),
                "unread_by_section": sections, "total": len(items),
                "stats": dict(self.stats),
                "limits": {"per_task": MAX_AGENT_MESSAGES_PER_TASK,
                           "progress_per_task": MAX_PROGRESS_MESSAGES_PER_TASK,
                           "per_minute": MAX_MESSAGES_PER_MINUTE}}



_INBOX = Inbox()


def inbox() -> Inbox:
    return _INBOX
