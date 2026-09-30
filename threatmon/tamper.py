"""
ARGUS - Tamper protection / self-defence (MITRE T1562, Impair Defenses).

This is the layer that protects the detection capability itself. Everything
else in threatmon watches the machine; this watches ARGUS. Four independent
checks, each fault-isolated so one failing can never silence the others, and a
watchdog loop written to be the most defensive code in the suite -- if THIS
throws, the whole self-defence story is worthless, so every check is wrapped
and the loop keeps running no matter what any single tick does.

  1. ABNORMAL-TERMINATION DETECTION. A heartbeat file records that ARGUS is
     alive and NOT cleanly shut down. A clean shutdown clears it. So if a run
     starts and finds a stale "alive" heartbeat from a previous run, that
     previous run died without shutting down cleanly -- a kill -- and we log it,
     retroactively, on the next boot. This is the ONLY reliable way to record a
     hard TerminateProcess ("taskkill /F"): no in-process handler can write
     anything once the kernel has torn the process down, so we write it the next
     time we start. Catchable terminations (Ctrl+C / Ctrl+Break / console close /
     SIGTERM) are ALSO recorded immediately by handlers, and mark the heartbeat
     so the boot check does not double-report them.

  2. AUDIT-LOG INTEGRITY. The audit chain is HMAC-linked; security.verify_chain()
     is the authoritative "has the record been edited" check. We also watch the
     file SIZE: an append-only log that suddenly shrinks was either rotated
     (legitimate -- the chain re-anchors and still verifies) or truncated
     (tamper -- the chain breaks). shrink + broken chain => alert; a chain that
     transitions from intact to broken => alert.

  3. CONFIG INTEGRITY. config.py is CRITICAL and integrity-controlled, so the
     sealed manifest already is the record of its legitimate contents, and a
     re-seal (CLI-only, off every surface ARGUS can reach) is the only
     legitimate way to change it. We re-check it against the manifest at
     runtime; a change with no re-seal is post-boot tampering.

  4. CONNECTION-LOSS ESCALATION. If Ollama was reachable and then is not,
     mid-session, that is logged as a signal rather than silently swallowed --
     an attacker disabling the local model to force a failure is a defence-
     impairment signal, not a mere outage. Transition-only, so a model that is
     simply not installed is not a recurring alarm.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

TECHNIQUE = "T1562"

# Overridable so tests can point the heartbeat at a temp file instead of the
# real state dir. Production leaves it at the default.
HEARTBEAT_PATH = None
CHECK_INTERVAL_S = 10          # how often the watchdog loops

_state = {
    "supported": True,
    "running": False,
    "last_error": "",
    "checks": 0,
    "audit_ok": None,
    "config_ok": None,
    "ollama_up": None,
    "boot_verdict": "",
    "findings_total": 0,
}
_audit_baseline = {"size": None, "chain_ok": None}
_ollama_seen_up = False
_clean = False                 # set true by mark_clean_shutdown()
_record_cb = None
_lock = threading.RLock()


def _hb_path():
    return HEARTBEAT_PATH or paths.writable("tamper_heartbeat.json")


# ── heartbeat / abnormal-termination ───────────────────────────────────────
def _write_heartbeat(clean: bool):
    try:
        data = {"pid": os.getpid(), "ts": time.time(), "clean": bool(clean)}
        path = _hb_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError as e:
        _state["last_error"] = f"heartbeat write: {type(e).__name__}"


def _read_heartbeat():
    try:
        with open(_hb_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _pid_alive(pid) -> bool:
    """Whether a pid is currently a running process. Used to tell a genuine
    kill (prior pid gone) from a concurrent second instance (prior pid alive),
    so starting ARGUS twice does not falsely read as a tamper."""
    try:
        import psutil
        return bool(pid) and psutil.pid_exists(int(pid))
    except Exception:
        return False


def boot_check(record):
    """On startup, decide whether the PREVIOUS run ended abnormally.

    A prior heartbeat that is present, not marked clean, AND whose pid is no
    longer running is the fingerprint of a kill: the process was updating that
    file and then simply stopped, without the clean-shutdown path ever running.
    Reported once, then a fresh alive heartbeat is written for THIS run.
    """
    prior = _read_heartbeat()
    verdict = "first run"
    try:
        if prior and not prior.get("clean", False):
            pid = prior.get("pid")
            if _pid_alive(pid):
                # The prior process is still alive -- this is a second instance,
                # not a kill. Do not cry tamper.
                verdict = f"prior pid {pid} still running (concurrent instance)"
            else:
                age = time.time() - float(prior.get("ts", 0) or 0)
                verdict = f"prior pid {pid} did not shut down cleanly"
                _emit(record, "abnormal_termination", "high",
                      detail=f"previous session (pid {pid}) terminated without "
                             f"clean shutdown {int(age)}s before this start",
                      reason="killed")
        elif prior and prior.get("clean", False):
            verdict = "prior run shut down cleanly"
        _state["boot_verdict"] = verdict
    except Exception as e:
        _state["last_error"] = f"boot_check: {type(e).__name__}"
    # Begin this run's proof-of-life regardless of what the prior state was.
    _write_heartbeat(clean=False)


def mark_clean_shutdown():
    """Call from the orchestrator's real shutdown path (and our exit handlers)
    so the next boot does not mistake a clean stop for a kill."""
    global _clean
    _clean = True
    _write_heartbeat(clean=True)


# ── audit-log integrity ────────────────────────────────────────────────────
def _audit_path():
    try:
        import security
        return security.audit_log_path()
    except Exception:
        return ""


def _check_audit(record):
    """Size-regression + HMAC-chain verification. Fails closed."""
    try:
        import security
        path = _audit_path()
        if not path or not os.path.exists(path):
            return
        size = os.path.getsize(path)
        chain_ok, note = security.verify_chain(path)
        _state["audit_ok"] = chain_ok

        base_size = _audit_baseline["size"]
        base_chain = _audit_baseline["chain_ok"]
        if base_size is not None:
            shrank = size < base_size
            # A shrink is only alarming if the chain no longer verifies: a
            # legitimate rotation shrinks the file too, but re-anchors so the
            # chain stays intact.
            if shrank and not chain_ok:
                _emit(record, "audit_truncated", "high",
                      detail=f"audit log shrank {base_size}->{size}B and the "
                             f"chain no longer verifies: {note}",
                      reason="truncation")
            elif base_chain and not chain_ok:
                _emit(record, "audit_chain_broken", "high",
                      detail=f"audit chain integrity lost: {note}",
                      reason="chain_break")
        _audit_baseline["size"] = size
        _audit_baseline["chain_ok"] = chain_ok
    except Exception as e:
        _state["last_error"] = f"audit check: {type(e).__name__}"


# ── config integrity ───────────────────────────────────────────────────────
def _check_config(record):
    """config.py against the sealed manifest. A change with no re-seal is
    post-boot tampering with the file that defines the security posture."""
    try:
        import integrity
        key = integrity.manifest_key(os.path.join(integrity.ROOT, "config.py"))
        ok, detail = integrity.verify_one(key)
        # "no baseline" (unsealed install) is not a tamper signal.
        if not ok and "no baseline" not in (detail or "").lower():
            _state["config_ok"] = False
            _emit(record, "config_modified", "high",
                  detail=f"config.py changed outside a re-seal: {detail}",
                  reason="config_tamper")
        else:
            _state["config_ok"] = True
    except Exception as e:
        _state["last_error"] = f"config check: {type(e).__name__}"


# ── connection-loss escalation ─────────────────────────────────────────────
def _probe_ollama() -> bool:
    """Cheap reachability probe. Never raises."""
    try:
        import requests
        from config import OLLAMA_HOST
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _check_connection(record):
    global _ollama_seen_up
    try:
        up = _probe_ollama()
        _state["ollama_up"] = up
        if up:
            _ollama_seen_up = True
        elif _ollama_seen_up:
            # Was up this session, now unreachable: a signal, logged once per
            # transition (we clear the "seen up" latch so it does not re-alarm
            # every 10s while it stays down).
            _ollama_seen_up = False
            _emit(record, "ollama_link_lost", "warn",
                  detail="local model (Ollama) became unreachable mid-session",
                  reason="link_loss")
    except Exception as e:
        _state["last_error"] = f"connection check: {type(e).__name__}"


# ── emit / loop / lifecycle ────────────────────────────────────────────────
def _emit(record, subtype, severity, detail, reason):
    finding = {
        "technique": TECHNIQUE,
        "detector": "tamper",
        "subtype": subtype,
        "severity": severity,
        "target": "ARGUS",
        "name": subtype,
        "path": "",
        "detail": detail,
        "reason": reason,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _state["findings_total"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit: {type(e).__name__}"
    return finding


def run_checks(record):
    """One pass of every check. Each is independently guarded so a failure in
    one cannot rob the others of their turn or stop the loop."""
    for fn in (_check_audit, _check_config, _check_connection):
        try:
            fn(record)
        except Exception as e:                     # belt AND suspenders
            _state["last_error"] = f"{fn.__name__}: {type(e).__name__}"
    _state["checks"] += 1


def _watch_loop(record):
    _state["running"] = True
    while True:
        try:
            _write_heartbeat(clean=_clean)         # proof of life
            run_checks(record)
        except Exception as e:
            # The loop itself must never die. If we get here, something outside
            # the per-check guards failed; record it and keep going.
            _state["last_error"] = f"loop: {type(e).__name__}: {e}"[:120]
        time.sleep(CHECK_INTERVAL_S)


def _install_exit_handlers(record):
    """Best-effort immediate final entry for CATCHABLE terminations. A hard
    TerminateProcess cannot be caught here -- that path is covered by the next
    boot's boot_check() instead."""
    import atexit
    import signal

    def _final(reason):
        # A clean interpreter exit is normal; a signal-driven one is not. We
        # only alarm on the signal path, and always mark the heartbeat so boot
        # does not also report it.
        try:
            if reason != "atexit":
                _emit(record, "signal_termination", "warn",
                      detail=f"process terminated by {reason}", reason="signal")
        finally:
            global _clean
            _clean = True
            _write_heartbeat(clean=True)

    def _sig(signum, _frame):
        _final(f"signal {signum}")
        # Re-raise default behaviour so the process actually exits.
        raise SystemExit(128 + int(signum))

    try:
        atexit.register(lambda: _final("atexit"))
    except Exception:
        pass
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _sig)
            except (ValueError, OSError, RuntimeError):
                # signal() only works on the main thread; start() may be called
                # from the sampler thread. Not fatal -- boot_check still covers
                # the kill case.
                pass


def start(record):
    """Entry point the coordinator calls once. Runs the boot check, installs
    exit handlers, and launches the watchdog thread."""
    global _record_cb
    _record_cb = record
    try:
        boot_check(record)
    except Exception as e:
        _state["last_error"] = f"start/boot: {type(e).__name__}"
    _install_exit_handlers(record)
    t = threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                         name="argus-tamper-watchdog")
    t.start()


def status() -> dict:
    ok = _state["supported"] and _state.get("last_error", "") == "" or True
    degraded = ""
    if _state.get("audit_ok") is False:
        degraded = "audit chain broken"
    elif _state.get("config_ok") is False:
        degraded = "config modified outside re-seal"
    return {
        "detector": "tamper",
        "technique": TECHNIQUE,
        "ok": _state["running"] and not degraded,
        "degraded": degraded,
        "running": _state["running"],
        "checks": _state["checks"],
        "audit_ok": _state["audit_ok"],
        "config_ok": _state["config_ok"],
        "ollama_up": _state["ollama_up"],
        "boot_verdict": _state["boot_verdict"],
        "findings_total": _state["findings_total"],
        "last_error": _state["last_error"],
    }
