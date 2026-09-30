"""
ARGUS - WMI event-subscription persistence collector (MITRE T1546.003).

THE LIMITATION THIS REMOVES. threatmon/persistence.py has always listed WMI
event subscriptions as its one uncovered surface, and the MITRE grid rendered
T1546.003 grey with the note "needs an undeclared dependency that would be
missing in the frozen exe". That blocker was a packaging choice, not a
capability limit: the permanent subscription namespace (root\\subscription:
__EventFilter, __EventConsumer, __FilterToConsumerBinding) is reachable
through plain COM, and comtypes -- already a declared runtime dependency and
already used by this same detector for the Task Scheduler COM API -- can
drive it with no new package and nothing extra to bundle. A one-line collector
plus one row flip in mitre.py closes the gap honestly.

WHAT IT READS. Three fixed queries, non-elevated, over the WMI COM API:

  __EventFilter             -- WHEN the subscription fires (boot, logon, interval)
  __EventConsumer           -- WHAT runs (ActiveScriptConsumer, CommandLineConsumer,
                               or a logged LDAP/NT event consumer)
  __FilterToConsumerBinding -- the pair that turns an event into an execution

A real T1546.003 implant needs all three; the diff engine only ever sees the
(entry_id -> value) records this collector returns, and an added binding is a
finding exactly the way an added Run key is.

WHY QUERIES AND NOT PERMANENT-EVENT NOTIFICATION. Subscribing to WMI events
here would create exactly the surface the detector watches, require a hidden
message pump, and add a standing callback path into this process for
attacker-influenced data. Polling the namespace keeps this module a reader.

WHAT IT CANNOT DO. It cannot see subscriptions outside root\\subscription
(rare, needs the same namespace read) and cannot attribute the writer --
pid stays 0 like every other surface here. MECSVC (the permanent consumer
host) legitimately exists on Windows with zero bindings; the diff only fires
when a BINDING or filter APPEARS, so the built-in objects sitting in the
baseline never alert.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os

TECHNIQUE = "T1546.003"

# concretized by comtypes' dynamic dispatch -- same pattern collect_tasks uses.
_WQL = {
    "wmi_filter": "SELECT * FROM __EventFilter",
    "wmi_consumer": "SELECT * FROM __EventConsumer",
    "wmi_binding": "SELECT * FROM __FilterToConsumerBinding",
}


def _describe(obj) -> str:
    """One line per object: name + what it would run, best effort."""
    name = (getattr(obj, "Name", "") or getattr(obj, "__PATH", "") or "?")
    kind = ""
    # ActiveScriptEventConsumer exposes ScriptingEngine/ScriptText;
    # CommandLineEventConsumer exposes CommandLineTemplate. Reading the
    # attributes that exist is how we describe each kind uniformly.
    for attr in ("CommandLineTemplate", "ScriptText", "ScriptFileName",
                 "ExecutablePath", "Name"):
        v = getattr(obj, attr, None)
        if v:
            kind = f"{attr}={str(v)[:160]}"
            break
    return f"{name} :: {kind}".strip()


def _query_all() -> dict:
    """The three fixed queries. Raises into the caller (collect_all isolates)."""
    import comtypes.client

    out = {}
    loc = comtypes.client.CreateObject("WbemScripting.SWbemLocator", dynamic=True)
    svc = loc.ConnectServer(None, "root\\subscription")
    for surf, wql in _WQL.items():
        try:
            results = svc.ExecQuery(wql)
        except Exception as e:
            # One unreadable class must not lose the other two: record the
            # surface as failed by re-raising only if we got nothing at all.
            if not any(k.startswith(surf.split("_")[0]) for k in out):
                raise
            continue
        for obj in results:
            try:
                eid = f"{surf}:{obj.__PATH or obj.Name or '?'}"
                out[eid] = {
                    "value": _describe(obj)[:280],
                    "when": "",
                    "where": f"root\\subscription ({surf})",
                    "item": (getattr(obj, "Name", "") or "?")[:120],
                }
            except Exception:
                continue
    return out


# Tests point this at a canned result so a run never depends on live WMI.
COLLECT_OVERRIDE = None


def collect_wmi() -> dict:
    """The collector in persistence.COLLECTORS shape: {entry_id: entry}."""
    if COLLECT_OVERRIDE is not None:
        return dict(COLLECT_OVERRIDE)
    return _query_all()


def classify_wmi_entry(item: str, value: str) -> tuple:
    """(severity, reasons) for a NEW WMI subscription object.

    Pure, so the diff pipeline can grade it like classify_entry does for a
    Run key. Filters alone are inert (they only say WHEN); consumers and
    bindings are the execution half.
    """
    low = f"{item} {value}".lower()
    # A binding is the activation edge between filter and consumer. It is
    # actionable even when its textual value contains only object references,
    # so never downgrade it merely because no executable name is embedded.
    if "binding" in low:
        return "high", ["WMI filter-to-consumer binding can trigger execution"]
    if "consumer" in low:
        if "script" in low or "commandline" in low or ".exe" in low \
                or "scrcons" in low:
            return "high", ["WMI consumer can execute code on trigger"]
        return "medium", ["WMI subscription object appeared"]
    return "low", ["WMI event filter appeared (inert without a consumer)"]
