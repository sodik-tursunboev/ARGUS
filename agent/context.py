"""Freshness-aware local World State.

This module turns a few existing, read-only context sources into typed facts
instead of making an agent treat a sentence such as "Notepad is focused" as
timeless truth.  It neither dispatches actions nor reads the clipboard: the
clipboard has its own L2 gate and must not become available through a cheaper
context route.

WorldState is local-only.  ``as_dict(redact_sensitive=True)`` is provided for
safe display/logging; it is not a cloud export mechanism.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from dataclasses import dataclass
import time
from typing import Any, Callable


@dataclass(frozen=True)
class Fact:
    """One observed value with its source, age limit, and sensitivity."""
    name: str
    value: Any
    source: str
    observed_at: float
    ttl_s: float
    confidence: str = "high"
    sensitive: bool = False

    def fresh(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) - self.observed_at <= self.ttl_s


@dataclass(frozen=True)
class WorldState:
    """A small, immutable snapshot of local context facts.

    Facts that cannot be observed are omitted rather than represented as a
    plausible default.  This makes absence explicit and prevents an agent
    from acting as though unavailable context were a known empty value.
    """
    facts: tuple[Fact, ...]

    def get(self, name: str, now: float | None = None) -> Fact | None:
        for fact in self.facts:
            if fact.name == name and fact.fresh(now):
                return fact
        return None

    def as_dict(self, redact_sensitive: bool = True,
                now: float | None = None) -> dict[str, dict]:
        """A copy suitable for a local status view, never mutable state."""
        out = {}
        for fact in self.facts:
            out[fact.name] = {
                "value": "[redacted]" if redact_sensitive and fact.sensitive else fact.value,
                "source": fact.source,
                "observed_at": fact.observed_at,
                "ttl_s": fact.ttl_s,
                "fresh": fact.fresh(now),
                "confidence": fact.confidence,
                "sensitive": fact.sensitive,
            }
        return out


def capture(now: float | None = None,
            focused_window: Callable[[], dict] | None = None,
            last_file: Callable[[], str] | None = None,
            selected_text: Callable[[], str] | None = None,
            visible_ui: Callable[[], dict] | None = None,
            clipboard_state: Callable[[], dict] | None = None,
            running_processes: Callable[[], dict] | None = None,
            network_state: Callable[[], dict] | None = None,
            active_tasks: Callable[[], dict] | None = None,
            user_presence: Callable[[], dict] | None = None,
            security_findings: Callable[[], list] | None = None) -> WorldState:
    """Capture the supported local facts, best-effort and read-only.

    Injectable providers make this deterministic to test.  Normal callers use
    the existing context sources, which already own the Windows API details.
    Each source is isolated so one unavailable integration never fabricates or
    removes facts from another source.
    """
    observed_at = time.time() if now is None else now
    facts: list[Fact] = []

    if focused_window is None:
        try:
            from skills import pc_skill
            focused_window = pc_skill.focused_window
        except Exception:
            focused_window = None
    if focused_window is not None:
        try:
            window = focused_window() or {}
            title = str(window.get("title", "") or "").strip()
            process = str(window.get("process", "") or "").strip()
            if title or process:
                facts.append(Fact(
                    name="focused_window", value={"title": title, "process": process},
                    source="pc_skill.focused_window", observed_at=observed_at,
                    ttl_s=5.0, confidence="high"))
                if process:
                    facts.append(Fact(
                        name="active_application", value=process,
                        source="pc_skill.focused_window", observed_at=observed_at,
                        ttl_s=5.0, confidence="high"))
        except Exception:
            pass

    if last_file is None:
        try:
            from skills import followup_skill
            last_file = followup_skill.last_file
        except Exception:
            last_file = None
    if last_file is not None:
        try:
            path = str(last_file() or "").strip()
            if path:
                facts.append(Fact(
                    name="selected_file", value=path,
                    source="followup_skill.last_file", observed_at=observed_at,
                    ttl_s=300.0, confidence="high", sensitive=True))
                facts.append(Fact(
                    name="recent_files", value=(path,),
                    source="followup_skill.last_file", observed_at=observed_at,
                    ttl_s=300.0, confidence="high", sensitive=True))
        except Exception:
            pass

    # Selection/UI providers are opt-in. Their contents can be private and a
    # full UI tree is expensive; callers that explicitly obtained them may add
    # them to this local snapshot without creating an automatic cloud route.
    for name, provider, source, ttl in (
        ("selected_text", selected_text, "explicit.selected_text", 10.0),
        ("visible_ui", visible_ui, "explicit.visible_ui", 5.0),
    ):
        if provider is not None:
            try:
                value = provider()
                if value:
                    facts.append(Fact(name=name, value=value, source=source,
                                      observed_at=observed_at, ttl_s=ttl,
                                      confidence="medium", sensitive=True))
            except Exception:
                pass

    # Never read clipboard contents here: control/clipboard_read owns the L2
    # gate. An explicit provider may report safe posture metadata (format/count,
    # not content); otherwise WorldState records why the value is unavailable.
    if clipboard_state is not None:
        try:
            value = clipboard_state() or {}
            facts.append(Fact(name="clipboard_state", value=value,
                              source="explicit.clipboard_state",
                              observed_at=observed_at, ttl_s=5.0,
                              confidence="medium", sensitive=True))
        except Exception:
            pass
    else:
        facts.append(Fact(
            name="clipboard_state", value={"content": "not_captured", "gate": "L2"},
            source="privacy_policy", observed_at=observed_at, ttl_s=5.0,
            confidence="high", sensitive=False))

    if running_processes is None:
        try:
            from skills import apps_skill
            running_processes = apps_skill._running_processes
        except Exception:
            running_processes = None
    if running_processes is not None:
        try:
            processes = running_processes() or {}
            names = tuple(sorted(str(name) for name in processes)[:100])
            facts.append(Fact(
                name="running_processes", value=names,
                source="apps_skill._running_processes", observed_at=observed_at,
                ttl_s=10.0, confidence="high", sensitive=True))
        except Exception:
            pass

    if network_state is None:
        try:
            from skills import network_skill
            network_state = network_skill.interface_state
        except Exception:
            network_state = None
    if network_state is not None:
        try:
            state = network_state() or {}
            if state:
                facts.append(Fact(
                    name="network_state", value=state,
                    source="network_skill.interface_state",
                    observed_at=observed_at, ttl_s=10.0,
                    confidence="high", sensitive=True))
        except Exception:
            pass

    if active_tasks is None:
        try:
            import router
            active_tasks = router.plan_snapshot
        except Exception:
            active_tasks = None
    if active_tasks is not None:
        try:
            task = active_tasks() or {}
            # Expose only lifecycle and counts. Targets and results can contain
            # user data and already have a gated TaskState surface.
            state = str(task.get("state", "none"))
            summary = {"state": state}
            if state == "staged":
                summary["pending"] = len(task.get("steps", ()))
            elif state == "paused":
                summary["pending"] = len(task.get("remaining_steps", ()))
                summary["completed"] = len(task.get("results", ()))
            facts.append(Fact(
                name="active_tasks", value=summary,
                source="router.plan_snapshot", observed_at=observed_at,
                ttl_s=2.0, confidence="high"))
        except Exception:
            pass

    if user_presence is None:
        try:
            import presencewatch
            user_presence = presencewatch.status
        except Exception:
            user_presence = None
    if user_presence is not None:
        try:
            status = user_presence() or {}
            safe_status = {
                key: status[key] for key in
                ("running", "watching_for_return", "locked_for_s", "session_s", "can_unlock")
                if key in status
            }
            facts.append(Fact(
                name="user_presence", value=safe_status,
                source="presencewatch.status", observed_at=observed_at,
                ttl_s=10.0, confidence="medium", sensitive=True))
        except Exception:
            pass

    if security_findings is None:
        try:
            import threatmon
            security_findings = lambda: threatmon.recent(5)
        except Exception:
            security_findings = None
    if security_findings is not None:
        try:
            findings = []
            for finding in (security_findings() or [])[:5]:
                if not isinstance(finding, dict):
                    continue
                # Paths, command lines and process details remain in the
                # local security surface; WorldState keeps only posture data.
                findings.append({
                    key: finding[key] for key in
                    ("severity", "detector", "technique", "ts") if key in finding
                })
            facts.append(Fact(
                name="security_findings", value=tuple(findings),
                source="threatmon.recent", observed_at=observed_at,
                ttl_s=5.0, confidence="high", sensitive=True))
        except Exception:
            pass

    facts.append(Fact(name="current_time", value=observed_at,
                      source="local_clock", observed_at=observed_at,
                      ttl_s=1.0, confidence="high"))
    return WorldState(tuple(facts))
