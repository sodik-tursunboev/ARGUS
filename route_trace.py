"""
ARGUS - Route trace: what each request did, what it cost, and how it ended.

THE QUESTIONS THIS ANSWERS. "Why was that slow", "did that just go to the
cloud", "which model said that" and "did ARGUS ignore me" used to be answered by
reading print() lines and guessing. Nothing tied the pieces of one request
together: the HTTP handler, the router, the provider clients and the skills each
knew a fragment, none of them had a request id, and a request that died between
two of them left no record at all.

This module is the one place a request is written down. It does three jobs and
nothing else.

  1. TRACE. A RequestTrace is opened when a command arrives and closed with
     EXACTLY ONE terminal state: COMPLETED, FAILED, DENIED, TIMEOUT or
     CANCELLED. A request nobody closes is not left open forever -- see
     reap_stale(). It also carries the counters that make the cost of a request
     visible: how many model calls it made, how many of them left the machine,
     how many were retries, and which provider actually produced the words.

  2. BUDGET. A per-turn ceiling on hosted-model calls, enforced at the provider
     edge (provider_call) so it does not depend on every caller remembering it.
     One user message used to be able to cost four hosted calls: a streamed
     answer whose first sentence was short was abandoned and asked again, and
     the second attempt re-ran the whole tier list. The limit is what makes
     that impossible rather than merely fixed in the one place someone looked.

  3. RUNTIME TRUTH. What the running system is ACTUALLY configured with and
     actually used -- read from config and from the last real call, never typed
     into a reply. "What model are you using" is answered from here.

WHAT IT MUST NEVER DO. It is instrumentation plus a spending limit. It does not
decide what is PRIVATE (skills/cloud_gate.py decides that, first, and its
refusal is raised before any budget is consulted), it does not authorise
anything (auth.py does), and no hook in here may raise into a request. The single
deliberate exception is CloudBudgetExceeded, which provider_call converts into
the provider's OWN "unavailable" error so the callers' existing fallbacks handle
it exactly as they handle a rate limit.

WHAT IT MUST NEVER RECORD. The request text. Only its length is kept. Events and
reasons carry categories ("rate_limited", "local_unavailable"), never words the
person said, and everything is passed through security.redact before it is
stored, because a summary is served to a debug endpoint.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import contextlib
import contextvars
import itertools
import os
import secrets
import threading
import time
from collections import deque


# ── route classes ──────────────────────────────────────────────────────────
class Route:
    """The path a request took. ONE of these per request, set by the router."""

    DETERMINISTIC = "DETERMINISTIC"     # answered by code from metadata: no model, no machine state
    LOCAL_DIRECT = "LOCAL_DIRECT"       # a local capability ran, chosen by rules: no model
    LOCAL_REQUIRED = "LOCAL_REQUIRED"   # depends on this machine / private state; nothing leaves it
    LOCAL_REASONING = "LOCAL_REASONING"  # local state + the LOCAL model to think about it
    CLOUD_GENERAL = "CLOUD_GENERAL"     # nothing private in it: a hosted model may answer
    EXPLICIT_WEB = "EXPLICIT_WEB"       # the internet was asked for, or is genuinely needed
    COMPLEX_LOCAL = "COMPLEX_LOCAL"     # bounded multi-step work, kept local
    COMPLEX_CLOUD_SAFE = "COMPLEX_CLOUD_SAFE"
                                        # team), confirmed general/public before

    DENIED = "DENIED"                   # refused before anything ran


ROUTES = (Route.DETERMINISTIC, Route.LOCAL_DIRECT, Route.LOCAL_REQUIRED,
          Route.LOCAL_REASONING, Route.CLOUD_GENERAL, Route.EXPLICIT_WEB,
          Route.COMPLEX_LOCAL, Route.COMPLEX_CLOUD_SAFE, Route.DENIED)

# Routes where the machine's own rules answer and a model has no business being
# called. A model call under one of these is a bug the invariant check reports.
ZERO_MODEL_ROUTES = frozenset({Route.DETERMINISTIC, Route.LOCAL_DIRECT})

# Routes that must stay on this machine. A hosted call or a web lookup under one
# of these is a privacy failure the invariant check reports.
LOCAL_ROUTES = frozenset({Route.LOCAL_DIRECT, Route.LOCAL_REQUIRED,
                          Route.LOCAL_REASONING, Route.COMPLEX_LOCAL})


class State:
    """How a request ended. Every request gets exactly one."""

    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


STATES = (State.COMPLETED, State.FAILED, State.DENIED, State.TIMEOUT,
          State.CANCELLED)

# Only the local model server is "local". Anything else is treated as hosted, so
# a provider added tomorrow is counted (and budgeted) until someone says otherwise.
LOCAL_PROVIDERS = frozenset({"ollama"})


# ── limits ─────────────────────────────────────────────────────────────────
# Conservative on purpose. Each can be overridden by an ARGUS_<NAME> environment
# variable or, if the owner adds it there, by the same name in config.py. They
# live here rather than in config.py only because config.py is integrity-CRITICAL
# and ACL-locked; moving them is a one-line change for whoever holds that key.
DEFAULT_MAX_CLOUD_CALLS_PER_USER_TURN = 2   # primary attempt + one failover
DEFAULT_MAX_CLOUD_RETRIES = 1               # re-asks after a failed attempt
DEFAULT_MAX_CLOUD_CONTEXT = 2400            # characters of history per hosted call
DEFAULT_MAX_CLOUD_OUTPUT = 400              # completion tokens per hosted call
# A reasoning model spends part of max_tokens thinking. 220 measured EMPTY replies
# (see groq_client.MAX_TOKENS), so the default equals what already works; the cap
# exists so it can be lowered deliberately, not so it silently is.

DEFAULT_REQUEST_DEADLINE = 180.0            # seconds before an open request is TIMEOUT

RING = 200                                  # finished traces kept for inspection
MAX_EVENTS = 48                             # per request; later ones are counted, not kept
MAX_ATTEMPTS = 8


def _limit(name: str, default: int) -> int:
    """env ARGUS_<name>, then config.<name>, then the default.

    Anything that is not a non-negative integer falls back to the DEFAULT rather
    than raising: a typo in an environment variable must never be the thing that
    turns a spending limit off. Zero is a valid, deliberate value (no hosted
    calls at all).
    """
    raw = os.environ.get("ARGUS_" + name)
    if raw is None:
        try:
            import config
            raw = getattr(config, name, None)
        except Exception:      # noqa: BLE001 -- config must not be able to break this
            raw = None
    if raw is None:
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def limits() -> dict:
    """The four limits, and the one number they add up to.

    What a zero means, since it is a legal value: CALLS 0 is "no hosted calls at
    all" (a kill switch); RETRIES 0 is "one attempt, no re-ask"; CONTEXT 0 is "send
    no history"; OUTPUT 0 is NOT "no output" -- a call that may produce nothing is
    useless -- so it is treated as unset and the default applies."""
    calls = _limit("MAX_CLOUD_CALLS_PER_USER_TURN", DEFAULT_MAX_CLOUD_CALLS_PER_USER_TURN)
    retries = _limit("MAX_CLOUD_RETRIES", DEFAULT_MAX_CLOUD_RETRIES)
    out = _limit("MAX_CLOUD_OUTPUT", DEFAULT_MAX_CLOUD_OUTPUT) or DEFAULT_MAX_CLOUD_OUTPUT
    return {
        "max_cloud_calls_per_user_turn": calls,
        "max_cloud_retries": retries,
        # The number that is actually enforced: the two limits describe the same
        # ceiling from two sides, so the stricter one wins.
        "max_cloud_calls_effective": min(calls, 1 + retries),
        "max_cloud_context": _limit("MAX_CLOUD_CONTEXT", DEFAULT_MAX_CLOUD_CONTEXT),
        "max_cloud_output": out,
    }


def _deadline() -> float:
    raw = os.environ.get("ARGUS_REQUEST_DEADLINE")
    try:
        v = float(raw) if raw is not None else DEFAULT_REQUEST_DEADLINE
    except ValueError:
        v = DEFAULT_REQUEST_DEADLINE
    return v if v > 0 else DEFAULT_REQUEST_DEADLINE


class CloudBudgetExceeded(Exception):
    """This request has used its allowance of hosted-model calls."""


# ── text hygiene ───────────────────────────────────────────────────────────
_redact_fn = None


def _safe(text, limit: int = 80) -> str:
    """One short line, redacted. Categories go in; user words must not."""
    global _redact_fn
    s = " ".join(str(text or "").split())
    if _redact_fn is None:
        try:
            import security
            _redact_fn = security.redact
        except Exception:      # noqa: BLE001
            _redact_fn = lambda x: x   # noqa: E731
    try:
        s = _redact_fn(s)
    except Exception:          # noqa: BLE001
        pass
    return s[:limit]


# ── the trace ──────────────────────────────────────────────────────────────
class RequestTrace:
    """Everything known about ONE request. Mutated only through its methods, and
    only ever under its own lock, because a streamed reply is produced on a
    different thread from the one that opened it."""

    def __init__(self, request_id: str, channel: str, chars: int, queue_depth: int):
        self._lock = threading.Lock()
        self.request_id = request_id
        self.channel = channel
        self.chars = int(chars or 0)
        self.queue_depth = int(queue_depth)
        self.started = time.perf_counter()
        self.started_wall = time.time()
        self.ended = 0.0
        # what was decided
        self.route = ""
        self.reason = ""
        self.scope = ""
        self.local_required = None
        self.frame = ""
        self.policy_kinds = ()
        self.capability = ""
        # what it cost
        self.local_calls = 0
        self.cloud_calls = 0
        self.cloud_refused = 0
        self.retries = 0
        self.web_calls = 0
        self.attempts = []
        # Hosted providers already ASKED this turn, in order. brain skips a tier
        # that is in here, so a cascade that is re-entered (a stream that gave up,
        # a fallback that runs the whole ladder again) can never put the same
        # question to the same provider twice.
        self.cloud_tried = []
        # who actually produced the words
        self.provider = ""
        self.model = ""
        self.engine = ""
        # how it ended
        self.state = ""
        self.detail = ""
        self.violations = []
        # False for a request refused before its handler ran: the guard already
        # audits (and de-duplicates) those, and a second un-throttled row per
        # attempt would let a client flooding a bad token flood the log too.
        self.audit_end = True
        self._hint = ""
        self._hint_detail = ""
        self.events = []
        self.events_dropped = 0

    # -- reading -----------------------------------------------------------
    @property
    def model_calls(self) -> int:
        return self.local_calls + self.cloud_calls

    @property
    def done(self) -> bool:
        return bool(self.state)

    def elapsed_ms(self) -> int:
        end = self.ended or time.perf_counter()
        return int(round((end - self.started) * 1000))

    # -- recording ---------------------------------------------------------
    def _event_locked(self, name: str, detail: str = "") -> None:
        if len(self.events) >= MAX_EVENTS:
            self.events_dropped += 1
            return
        ms = int(round((time.perf_counter() - self.started) * 1000))
        self.events.append((ms, name, _safe(detail)))

    def event(self, name: str, detail: str = "") -> None:
        try:
            with self._lock:
                self._event_locked(name, detail)
        except Exception:      # noqa: BLE001 -- instrumentation never raises
            pass

    def set_route(self, route: str, reason: str = "") -> None:
        """The path this request took. The LAST call wins: a request first known
        to be private (LOCAL_REQUIRED) and then found to need the local model
        (LOCAL_REASONING) ends up recorded as the more specific one."""
        try:
            with self._lock:
                if route != self.route:
                    self._event_locked("route_selected", f"{route} {reason}".strip())
                self.route = route
                if reason:
                    self.reason = _safe(reason, 120)
        except Exception:      # noqa: BLE001
            pass

    def note_policy(self, decision) -> None:
        """Copies what the privacy classifier decided. Duck-typed on purpose
        (scope / local_required / frame / reasons) so this module never imports
        the classifier. Only the KINDS of reason are kept -- "acts on their own
        thing", not the snippet of the request that triggered it."""
        try:
            kinds = []
            for why in (getattr(decision, "reasons", ()) or ())[:3]:
                kind = str(why).split(":", 1)[0].strip()
                if kind and kind not in kinds:
                    kinds.append(_safe(kind, 48))
            with self._lock:
                self.scope = _safe(getattr(decision, "scope", ""), 24)
                lr = getattr(decision, "local_required", None)
                self.local_required = None if lr is None else bool(lr)
                self.frame = _safe(getattr(decision, "frame", ""), 24)
                self.policy_kinds = tuple(kinds)
                self._event_locked("policy", f"{self.scope} local={self.local_required}")
        except Exception:      # noqa: BLE001
            pass

    def note_capability(self, skill: str, action: str = "") -> None:
        try:
            with self._lock:
                self.capability = _safe(f"{skill}/{action}" if action else skill, 48)
                self._event_locked("capability_started", self.capability)
        except Exception:      # noqa: BLE001
            pass

    def capability_done(self, status: str = "ok", ms: float = 0.0) -> None:
        self.event("capability_finished", f"{status} {int(ms)}ms")

    def note_web(self, kind: str = "lookup") -> None:
        """A request's words went to a web source (search engine, reference
        site). Counted so the invariant check can prove a local request never did."""
        try:
            with self._lock:
                self.web_calls += 1
                self._event_locked("web_lookup", kind)
        except Exception:      # noqa: BLE001
            pass

    def deny(self, reason: str) -> None:
        """Refused before anything ran (policy, authentication, egress)."""
        self.set_route(Route.DENIED, reason)
        with self._lock:
            self._hint, self._hint_detail = State.DENIED, _safe(reason, 120)

    def fail(self, reason: str) -> None:
        """Could not be done. The person may still have been told why -- that is
        a reply, not a completion."""
        with self._lock:
            if self._hint != State.DENIED:
                self._hint, self._hint_detail = State.FAILED, _safe(reason, 120)
            self._event_locked("error", reason)

    # -- provider calls ----------------------------------------------------
    def _start_call(self, provider: str, model: str, cloud: bool) -> None:
        with self._lock:
            if cloud:
                allowed = limits()["max_cloud_calls_effective"]
                if self.cloud_calls >= allowed:
                    self.cloud_refused += 1
                    self._event_locked("cloud_refused", f"{provider} limit={allowed}")
                    raise CloudBudgetExceeded(
                        f"this request has used its {allowed} hosted-model "
                        f"call{'s' if allowed != 1 else ''}")
                if self.cloud_calls >= 1:
                    self.retries += 1
                self.cloud_calls += 1
                if provider not in self.cloud_tried:
                    self.cloud_tried.append(provider)
            else:
                self.local_calls += 1
                # The route is chosen BEFORE a skill runs, and some rule-chosen
                # skills (summarise a document, read the screen) use the local
                # model inside. That is not a bug in the skill; it is a route that
                # was labelled by what was expected rather than by what happened,
                # so it is corrected here instead of being reported as a violation.
                if self.route == Route.LOCAL_DIRECT:
                    self.route = Route.LOCAL_REASONING
                    self._event_locked("route_selected",
                                       "LOCAL_REASONING (skill used the local model)")
            self._event_locked("provider_started", f"{provider}/{model}")

    def _end_call(self, provider: str, model: str, cloud: bool, ok: bool,
                  error: str, ms: int) -> None:
        with self._lock:
            if len(self.attempts) < MAX_ATTEMPTS:
                self.attempts.append({"provider": provider, "model": model,
                                      "cloud": cloud, "ok": ok,
                                      "error": _safe(error, 32), "ms": ms})
            if ok:
                self.provider, self.model = provider, model
                self.engine = "cloud" if cloud else "local"
            self._event_locked("provider_finished",
                               f"{provider} {'ok' if ok else (error or 'failed')} {ms}ms")

    # -- ending ------------------------------------------------------------
    def finish(self, state: str | None = None, detail: str = "") -> bool:
        """Close the request. IDEMPOTENT: the first call wins, so a handler's
        `finally` can call it without knowing whether an earlier layer already
        did. With no state given, a DENIED/FAILED marker set earlier is used,
        else COMPLETED. Returns True if this call was the one that closed it."""
        with self._lock:
            if self.state:
                return False
            chosen = state if state in STATES else (self._hint or State.COMPLETED)
            self.state = chosen
            self.detail = _safe(detail or self._hint_detail, 120)
            self.ended = time.perf_counter()
            self._event_locked("response_created" if chosen == State.COMPLETED else
                               chosen.lower(), self.detail)
            self.violations = _invariants(self)
        _retire(self)
        return True

    def delivered(self) -> None:
        """The reply reached the transport (the HTTP response was returned, or the
        last streamed chunk was handed on). It does not prove a person heard it."""
        self.event("response_delivered")

    # -- exporting ---------------------------------------------------------
    def summary(self, events: bool = False) -> dict:
        with self._lock:
            out = {
                "request_id": self.request_id,
                "channel": self.channel,
                "route": self.route or "",
                "reason": self.reason,
                "scope": self.scope,
                "local_required": self.local_required,
                "policy": list(self.policy_kinds),
                "capability": self.capability,
                "provider": self.provider,
                "model": self.model,
                # local | cloud | none: who produced the words. "none" means no
                # model did -- a rule or a skill answered.
                "engine": self.engine or "none",
                # Whether anything from this request was SENT off the machine,
                # whether or not the far end answered.
                "left_machine": bool(self.cloud_calls or self.web_calls),
                # A hosted attempt failed or was refused and the LOCAL model
                # answered instead: the request was cloud-eligible but is not
                # what the route name says it was.
                "fallback": bool((self.cloud_refused or any(
                    a["cloud"] and not a["ok"] for a in self.attempts))
                    and self.engine == "local"),
                "tiers_tried": list(self.cloud_tried),
                "model_calls": self.model_calls,
                "local_calls": self.local_calls,
                "cloud_calls": self.cloud_calls,
                "cloud_refused": self.cloud_refused,
                "web_calls": self.web_calls,
                "retries": self.retries,
                "attempts": [dict(a) for a in self.attempts],
                "state": self.state or "IN_FLIGHT",
                "detail": self.detail,
                "latency_ms": self.elapsed_ms(),
                "queue_depth": self.queue_depth,
                "violations": list(self.violations),
            }
            if events:
                out["events"] = [{"ms": ms, "event": n, "detail": d}
                                 for ms, n, d in self.events]
                out["events_dropped"] = self.events_dropped
            return out

    def describe(self) -> str:
        s = self.summary()
        who = f"{s['provider']}/{s['model']}" if s["provider"] else "no-model"
        return (f"{s['request_id']} {s['route'] or '-'} {who} "
                f"calls={s['model_calls']}(cloud {s['cloud_calls']}, local "
                f"{s['local_calls']}) retries={s['retries']} web={s['web_calls']} "
                f"{s['latency_ms']}ms {s['state']}"
                + (f" [{s['detail']}]" if s["detail"] else "")
                + (f" VIOLATIONS: {'; '.join(s['violations'])}" if s["violations"] else ""))


def _invariants(t: RequestTrace) -> list:
    """What must be true of a finished request, checked when it finishes.

    A tripwire, not a gate: it cannot stop anything (the edges do that) but it
    makes a routing bug LOUD -- a "local" request that reached a hosted model is
    reported in the console line, the debug endpoint and the audit log, instead
    of being discovered from a bill. Called with t._lock held."""
    bad = []
    if t.route == Route.DETERMINISTIC and (t.local_calls or t.cloud_calls):
        bad.append(f"{t.route} made {t.local_calls + t.cloud_calls} model call(s)")
    # COMPLEX_LOCAL is private only when the classifier said the request was: a
    # plan built from a general question may legitimately end in a hosted answer.
    private = bool(t.local_required) or t.route in (
        Route.LOCAL_REQUIRED, Route.LOCAL_REASONING, Route.LOCAL_DIRECT)
    if private and t.cloud_calls:
        bad.append(f"local request made {t.cloud_calls} hosted call(s)")
    if private and t.web_calls:
        bad.append(f"local request made {t.web_calls} web lookup(s)")
    cap = limits()["max_cloud_calls_effective"]
    if t.cloud_calls > cap:
        bad.append(f"{t.cloud_calls} hosted calls exceeds the limit of {cap}")
    return bad


# ── registry ───────────────────────────────────────────────────────────────
_reg_lock = threading.RLock()
_open: dict = {}
_done: deque = deque(maxlen=RING)
_ids = itertools.count(1)
_untracked = {"cloud_calls": 0, "local_calls": 0}
_CURRENT: "contextvars.ContextVar[RequestTrace | None]" = contextvars.ContextVar(
    "argus_request_trace", default=None)


def begin(channel: str = "command", chars: int = 0) -> RequestTrace:
    """Open a trace. Does NOT make it current -- use bound() for that -- because
    a streamed reply opens its trace in one place and runs in another."""
    reap_stale()
    with _reg_lock:
        depth = len(_open)
        rid = f"{next(_ids):05d}-{secrets.token_hex(2)}"
        t = RequestTrace(rid, channel, chars, depth)
        _open[rid] = t
    t.event("request_received", f"{channel} chars={int(chars or 0)}")
    t.event("queue_state", f"in_flight={depth + 1}")
    return t


def current():
    """The trace of the request in flight on this thread, or None (a scheduled
    task, a background refill, a diagnostic)."""
    return _CURRENT.get()


def cloud_tried() -> list:
    """Hosted providers already asked during the request in flight (empty outside
    one). See RequestTrace.cloud_tried."""
    t = current()
    return list(t.cloud_tried) if t is not None else []


def reject(channel: str, reason: str) -> None:
    """Record a request that was refused BEFORE its handler ran (bad token, rate
    limit). Those never reach the code that opens a trace, so without this they
    are exactly the requests that leave no state at all."""
    try:
        t = begin(channel, 0)
        t.audit_end = False
        t.deny(reason)
        t.finish()
    except Exception:          # noqa: BLE001 -- recording a refusal must not break it
        pass


@contextlib.contextmanager
def bound(trace):
    """Make TRACE current for everything that runs inside the block."""
    token = _CURRENT.set(trace)
    try:
        yield trace
    finally:
        try:
            _CURRENT.reset(token)
        except ValueError:     # token minted in another Context (a thread hop)
            _CURRENT.set(None)


@contextlib.contextmanager
def request(channel: str = "command", chars: int = 0):
    """begin + bound + a guarantee of a terminal state.

    An exception that escapes the block is recorded as FAILED (by class name
    only -- the message can carry request text) and re-raised. GeneratorExit and
    cancellation are recorded as CANCELLED. Anything still open at the end is
    COMPLETED, unless something already marked it DENIED or FAILED."""
    t = begin(channel, chars)
    try:
        with bound(t):
            yield t
    except GeneratorExit:
        t.finish(State.CANCELLED, "client closed")
        raise
    except BaseException as e:      # noqa: BLE001 -- recorded, then re-raised
        t.finish(State.FAILED, type(e).__name__)
        raise
    finally:
        t.finish()


def scoped_iter(trace, iterator):
    """Re-enter TRACE around EVERY step of a generator.

    A streamed reply is pulled one chunk at a time and the web framework may
    pull each chunk on a different worker thread, each holding its own copy of
    the context -- so a value set once at the top of the generator is gone by
    the second sentence. Entering per step is what makes the counters and the
    budget hold on the streaming path, which is the one voice actually uses."""
    it = iter(iterator)
    try:
        while True:
            with bound(trace):
                try:
                    item = next(it)
                except StopIteration:
                    return
            yield item
    finally:
        close = getattr(it, "close", None)
        if close:
            try:
                close()
            except Exception:  # noqa: BLE001
                pass


def _log(line: str) -> None:
    """The one place a finished request is written to the console. A seam: swap
    it for a logger, or silence it, without touching the trace itself."""
    try:
        print(f"[trace] {line}")
    except Exception:          # noqa: BLE001 -- a console that cannot encode this
        pass


def _retire(t: RequestTrace) -> None:
    with _reg_lock:
        _open.pop(t.request_id, None)
        _done.append(t)
    _log(t.describe())
    # COMPLETED is already in the audit log as a command/reply pair. Every OTHER
    # ending is exactly the case that used to leave no record, so it gets one.
    if (t.state != State.COMPLETED or t.violations) and t.audit_end:
        try:
            import security
            security.audit("request_end", f"{t.request_id} {t.route or '-'}",
                           f"{t.state} {t.detail}".strip()
                           + (" | " + "; ".join(t.violations) if t.violations else ""))
        except Exception:      # noqa: BLE001
            pass


def reap_stale(now: float | None = None) -> int:
    """Give every request that has been open too long a terminal state.

    "Every request ends in a visible state" has to hold for the one whose worker
    hung and the one whose client walked away without closing the stream, so it
    is enforced here instead of being left to the layer that failed. Called on
    every begin() and every read; a wedged request is therefore closed by the
    next one to arrive."""
    limit = _deadline()
    t_now = now if now is not None else time.perf_counter()
    with _reg_lock:
        stale = [t for t in _open.values() if (t_now - t.started) > limit]
    n = 0
    for t in stale:
        if t.finish(State.TIMEOUT, f"no terminal state within {int(limit)}s"):
            n += 1
    return n


def in_flight() -> int:
    with _reg_lock:
        return len(_open)


def recent(n: int = 20, events: bool = False) -> list:
    """Newest first. Open requests are included, marked IN_FLIGHT."""
    reap_stale()
    with _reg_lock:
        pool = list(_open.values()) + list(_done)
    pool.sort(key=lambda t: t.started_wall, reverse=True)
    return [t.summary(events=events) for t in pool[:max(0, int(n))]]


def last_finished(need_model: bool = False):
    """The most recent finished trace; with need_model, the most recent that a
    model actually answered."""
    with _reg_lock:
        for t in reversed(_done):
            if not need_model or t.provider:
                return t
    return None




# ── module-level shortcuts (all safe with no request in flight) ────────────
def event(name: str, detail: str = "") -> None:
    t = current()
    if t is not None:
        t.event(name, detail)


def set_route(route: str, reason: str = "") -> None:
    t = current()
    if t is not None:
        t.set_route(route, reason)


def note_web(kind: str = "lookup") -> None:
    t = current()
    if t is not None:
        t.note_web(kind)


def fail(reason: str) -> None:
    t = current()
    if t is not None:
        t.fail(reason)


def deny(reason: str) -> None:
    t = current()
    if t is not None:
        t.deny(reason)


# ── provider edge ──────────────────────────────────────────────────────────
@contextlib.contextmanager
def provider_call(provider: str, model: str = "", *, cloud: bool | None = None,
                  refuse_with=None):
    """Wrap ONE call to a model provider.

    On entry, for a hosted provider, the request's budget is checked and a call
    is counted; on exit the outcome is recorded (so "which model actually said
    this" is a fact, not a guess). With no request in flight (a background refill,
    a diagnostic) nothing is budgeted -- there is no turn to budget against --
    but the call is still counted in _untracked so it is not invisible.

    refuse_with: an exception CLASS. If the budget is spent, this is raised
    instead of CloudBudgetExceeded, so a caller that already catches its own
    provider's "unavailable" error moves on to its fallback with no new code.

    Place this AFTER cloud_gate.guard_egress(): privacy is decided before cost,
    and a local-only request must be refused for being local-only, not for being
    over budget.
    """
    is_cloud = (provider not in LOCAL_PROVIDERS) if cloud is None else bool(cloud)
    t = current()
    if t is not None:
        try:
            t._start_call(provider, model, is_cloud)
        except CloudBudgetExceeded as e:
            if refuse_with is not None:
                raise refuse_with(str(e)) from None
            raise
    else:
        with _reg_lock:
            _untracked["cloud_calls" if is_cloud else "local_calls"] += 1

    t0 = time.perf_counter()
    ok, err = False, ""
    try:
        yield
        ok = True
    except GeneratorExit:
        # A consumer that stops reading a stream it already got its answer from.
        ok, err = True, "closed_early"
        raise
    except BaseException as e:     # noqa: BLE001 -- recorded, then re-raised
        err = type(e).__name__
        # The provider clients raise their own *Unavailable with a SANITISED
        # category ("rate_limited", "timeout") -- never raw exception text, by
        # design -- so that is worth recording instead of the class name.
        if err.endswith("Unavailable") and e.args:
            err = str(e.args[0])
        raise
    finally:
        ms = int(round((time.perf_counter() - t0) * 1000))
        if not is_cloud:
            # Only a call that CONNECTED and worked proves the server is up, and only
            # a refused/unreachable connection proves it is down. A timeout or an
            # HTTP error says the server was slow or unhappy, not absent, and must
            # not flip "available" to False.
            if ok:
                _note_ollama(True)
            elif err in _DOWN_ERRORS:
                _note_ollama(False)
        if t is not None:
            try:
                t._end_call(provider, model, is_cloud, ok, err, ms)
            except Exception:  # noqa: BLE001
                pass


def trim_history(history, max_chars: int | None = None) -> list:
    """The part of a conversation a hosted call is allowed to carry.

    Newest messages win: the last exchange is what a follow-up refers to, and the
    oldest is what it can most afford to lose. Whole messages only, except that a
    single message bigger than the whole allowance is cut rather than dropped, so
    the latest turn is never silently missing. Returns plain {"role","content"}
    dicts -- nothing else a history entry carries can travel."""
    cap = limits()["max_cloud_context"] if max_chars is None else int(max_chars)
    if cap <= 0:
        return []
    clean = []
    for entry in (history or []):
        if isinstance(entry, dict) and entry.get("role") and entry.get("content"):
            clean.append({"role": entry["role"], "content": str(entry["content"])})
    kept, used = [], 0
    for m in reversed(clean):
        n = len(m["content"])
        if used + n > cap:
            if not kept:                      # the newest one alone is too big
                kept.append({"role": m["role"], "content": m["content"][:cap]})
            break
        kept.append(m)
        used += n
    kept.reverse()
    # A reply with no question in front of it is context the model has to guess at.
    while kept and kept[0]["role"] != "user":
        kept.pop(0)
    return kept


def cap_output(tokens: int) -> int:
    """A hosted call's completion-token ceiling: what the client wanted, but never
    more than MAX_CLOUD_OUTPUT."""
    return min(int(tokens), limits()["max_cloud_output"])


# ── capability -> route ────────────────────────────────────────────────────
_DETERMINISTIC_SKILLS = frozenset({"social", "calc"})
_DETERMINISTIC_PAIRS = frozenset({("pc", "time")})
_CHAIN_SKILLS = frozenset({"plan", "agent"})
_WEB_SKILLS = frozenset({"research", "weather"})


def _is_web(skill: str, action: str) -> bool:
    try:
        from skills import cloud_gate
        return bool(cloud_gate.is_web_lookup(skill, action)) or skill in _WEB_SKILLS
    except Exception:          # noqa: BLE001 -- fall back to the local list
        return (skill in _WEB_SKILLS
                or (skill == "knowledge" and action in ("lookup", "define"))
                or (skill == "web" and action != "open_url"))


def route_for_capability(skill: str, action: str = "") -> str:
    """The route class of a capability that ran WITHOUT a model choosing it.

    Rules, not learning: a skill either answers from metadata (DETERMINISTIC), acts
    on or reads this machine (LOCAL_DIRECT), goes to the public web (EXPLICIT_WEB)
    or is a multi-step plan (COMPLEX_LOCAL)."""
    if skill in _CHAIN_SKILLS:
        return Route.COMPLEX_LOCAL
    if skill in _DETERMINISTIC_SKILLS or (skill, action) in _DETERMINISTIC_PAIRS:
        return Route.DETERMINISTIC
    if _is_web(skill, action):
        return Route.EXPLICIT_WEB
    return Route.LOCAL_DIRECT


# ── runtime truth ──────────────────────────────────────────────────────────
# The last thing a REAL call to the local model server told us. Kept fresh by
# provider_call itself, so "is the local model up" is usually a free read of what
# just happened rather than a probe -- the /status poll must never wait on Ollama.
_ollama_seen = {"ok": None, "at": 0.0}
OLLAMA_FRESH = 60.0      # seconds a real call's outcome is trusted without a probe
_DOWN_ERRORS = frozenset({"ConnectionError", "ConnectTimeout", "NewConnectionError",
                          "MaxRetryError", "ConnectionRefusedError"})


def _note_ollama(ok: bool) -> None:
    _ollama_seen["ok"] = bool(ok)
    _ollama_seen["at"] = time.time()


def local_model_available(probe: bool = False):
    """True / False if known, None if it has never been observed.

    A real call within OLLAMA_FRESH seconds decides it. Otherwise, with probe=True,
    ask the server (one short GET, tags only -- no generation); with probe=False
    report whatever was last seen, however old."""
    fresh = (time.time() - _ollama_seen["at"]) <= OLLAMA_FRESH
    if _ollama_seen["ok"] is not None and (fresh or not probe):
        return _ollama_seen["ok"]
    if not probe:
        return None
    try:
        import requests

        import config
        r = requests.get(f"{config.OLLAMA_HOST}/api/tags", timeout=1.5)
        r.raise_for_status()
        names = {str(m.get("name", "")) for m in (r.json().get("models") or [])}
        want = str(getattr(config, "OLLAMA_MODEL", ""))
        # "llama3.2" with no tag means "llama3.2:latest"; a tagged name must match
        # exactly, because llama3.2:1b being present says nothing about llama3.2:3b.
        ok = bool(want) and (want in names or (":" not in want and f"{want}:latest" in names))
    except Exception:          # noqa: BLE001 -- unreachable IS the answer
        ok = False
    _note_ollama(ok)
    return ok


def _cloud_tiers() -> list:
    """The configured hosted tiers, in the order brain tries them. Booleans and
    ids only: a key, or any part of one, never appears here."""
    tiers = []
    try:
        import config
        import groq_client
        tiers.append({"provider": "groq", "model": str(config.GROQ_MODEL),
                      "configured": bool((config.GROQ_API_KEY or "").strip()),
                      "available": bool(groq_client.available())})
    except Exception:          # noqa: BLE001
        pass
    try:
        import config
        import gemini_client
        tiers.append({"provider": "gemini", "model": str(config.GEMINI_MODEL),
                      "configured": bool((config.GEMINI_API_KEY or "").strip()),
                      "available": bool(gemini_client.available())})
    except Exception:          # noqa: BLE001
        pass
    return tiers


def runtime_info(probe: bool = False) -> dict:
    """What ARGUS is running on, right now. Every value comes from config or from
    what a real call just did -- none is typed here.

    current_* describe the last request a model actually answered; current_route
    describes the last request of any kind."""
    try:
        import config
    except Exception:          # noqa: BLE001
        config = None
    any_last = last_finished()
    used = last_finished(need_model=True)
    return {
        "current_route": any_last.route if any_last else "",
        "current_provider": used.provider if used else "",
        "current_model": used.model if used else "",
        "current_engine": used.engine if used else "",
        "local_model": str(getattr(config, "OLLAMA_MODEL", "")) if config else "",
        "local_router_model": str(getattr(config, "OLLAMA_ROUTER_MODEL", "")) if config else "",
        "local_model_available": local_model_available(probe=probe),
        "cloud_enabled": bool(getattr(config, "CLOUD_ENABLED", False)) if config else False,
        "cloud_tiers": _cloud_tiers(),
        "limits": limits(),
        "in_flight": in_flight(),
        # Model calls made OUTSIDE any user turn since this process started -- a
        # background refill, another subsystem, a diagnostic. They are not budgeted
        # (there is no turn to budget against) but they are not invisible either:
        # this is where a hidden cost shows up.
        "background_calls": dict(_untracked),
    }
