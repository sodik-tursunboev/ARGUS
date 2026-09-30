"""
ARGUS - Local agents: service wiring (composition root).

main.py calls start() exactly once at boot. Every failure inside is caught
and logged: the agent layer is an ADDITION to ARGUS, and a broken addition
must not take the orchestrator down at boot. Mirrors the boot discipline of
integrity.start_watch() / sandbox hardening in main.py.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time


def start() -> dict:
    try:
        from agents import coordinator as _coord
        _coord.start()
        st = _coord.coordinator().status()
        print(f"[agents] {len(st['agents'])} agents on shared model "
              f"{st['model']['model_id']} (concurrency "
              f"{st['model']['max_concurrency']})")
    except Exception as e:
        print(f"[agents] not started: {type(e).__name__}: {e}")
        return {}
    # Bounded autonomy (owner-requested): the ten agents cycle real read-only
    # analysis work on the background tier. Own error handling; a failure to
    # start it leaves the request-driven layer fully intact.
    try:
        from agents import autonomy
        autonomy.start()
        st["autonomy"] = autonomy.status()
    except Exception as e:
        print(f"[agents] autonomy not started: {type(e).__name__}: {e}")
    # Dynamic (temporary) agents: nothing is created at boot -- this only
    # reports whether the pipeline is armed. Own error handling, like the rest.
    try:
        from agents import dynamic_spec as _ds
        from agents import ephemeral
        m = ephemeral.manager()
        st["dynamic"] = m.summary()
        print(f"[agents] dynamic agents {'on' if m.enabled else 'off'} "
              f"(<= {_ds.MAX_ACTIVE_EPHEMERAL_AGENTS} temporary, depth "
              f"<= {_ds.MAX_SPAWN_DEPTH}, TTL {_ds.DEFAULT_AGENT_TTL}s, "
              f"shared model, kill-switch: POST /api/agents/dynamic/enabled)")
    except Exception as e:
        print(f"[agents] dynamic agents unavailable: {type(e).__name__}: {e}")
    return st


def uptime_note() -> str:
    return f"agents layer up since {time.strftime('%Y-%m-%d %H:%M')}"
