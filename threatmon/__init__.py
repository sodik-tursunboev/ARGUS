"""
ARGUS - Threat-detection coordinator.

One place the sampler calls, one place detections are recorded, logged and
surfaced. Each detector stays small and single-purpose; this module owns the
cross-cutting parts so they are done ONCE and identically:

  * de-duplication so the same standing condition is not re-alerted every tick,
  * MITRE-tagged logging to the tamper-evident audit chain (technique + basename
    only -- the full path is forensic and stays in the LOCAL detections store,
    never the chained log and never the cloud),
  * a capped in-memory ring plus a bounded on-disk record for the SECURITY panel
    and the security summary,
  * the live "which techniques are actually covered" set the MITRE grid renders.

Two kinds of detector plug in here. POLL detectors expose scan(processes) and
run on the sampler's 5-second tick (lsass_link, lolbin). THREAD detectors
expose start(record) and run their own background loop (canary file-watch,
tamper watchdog); they call back into record() from their own thread, which is
why the buffer is lock-guarded. Both are added deliberately, one per shipped
feature -- this list is the suite's scope, not an auto-loader.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import threading
import time
from collections import deque

import paths
from threatmon import (canary, clipboard, defenses, listening, lolbin, lsass,
                       lsass_link, mitre, netconfig, persistence, privacy,
                       tamper, usbwatch)

# Detectors that run on the sampler tick. Grows by one per shipped priority.
# lsass_link is the LINK to the elevated helper (threatmon/lsass_link.py): it
# asks the helper to scan under SeDebugPrivilege and re-validates every
# finding locally, keeping the orchestrator free of the capability while
# covering elevated dumps. It falls back to the in-process threatmon.lsass
# scan (imported by lsass_link itself) when the helper is absent, and reports
# that fallback as degraded rather than as full coverage.
POLL_DETECTORS = [lsass_link, lolbin]
# Detectors that run their own thread and call record() themselves.
THREAD_DETECTORS = [tamper, canary, persistence, privacy, netconfig, usbwatch,
                    listening, defenses]
# Passive detectors: invoked from an existing code path (the clipboard read),
# not polled and not threaded here. Listed only so their status() and coverage
# show up in the panel/summary alongside the rest.
PASSIVE_DETECTORS = [clipboard]

_BUFFER_MAX = 200
_COOLDOWN_S = 300          # don't re-alert the same standing condition inside 5m
_DISK_MAX_BYTES = 512 * 1024

_lock = threading.RLock()
_buffer = deque(maxlen=_BUFFER_MAX)
_last_seen = {}            # dedup key -> last-alerted epoch
_counts = {}              # technique -> count this session
_started = False


def _detections_path():
    return paths.writable("detections.jsonl")


def _dedup_key(f: dict) -> str:
    # A detector may supply its own dedup key when the default dimensions do not
    # capture what "the same standing condition" means for it -- canary trips,
    # for instance, are the same condition per (file, action, accessor), not per
    # (pid, target_pid). Otherwise: (detector, owner pid, technique, target). A
    # NEW escalation -- different owner or technique -- is a different key and
    # alerts immediately.
    if f.get("dedup"):
        return str(f["dedup"])
    return f"{f.get('detector')}|{f.get('pid')}|{f.get('technique')}|{f.get('target_pid', '')}"


def _persist(record: dict):
    """Append one detection to the bounded on-disk record. Best-effort."""
    try:
        path = _detections_path()
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
        # Trim if it has grown past the cap: keep the newest _BUFFER_MAX lines.
        try:
            if path and __import__("os").path.getsize(path) > _DISK_MAX_BYTES:
                with open(path, "r", encoding="utf-8") as fh:
                    tail = fh.readlines()[-_BUFFER_MAX:]
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.writelines(tail)
                __import__("os").replace(tmp, path)
        except OSError:
            pass
    except OSError:
        pass


def _log(record: dict):
    """Log a detection to the audit chain. Never raises into the caller."""
    try:
        import os as _os

        import security
        # Structured, chained, SAFE fields only (no full path -- by design).
        security.security_event(
            security.THREAT_DETECTED,
            component=record.get("detector", "threatmon"),
            pid=int(record.get("pid", 0) or 0),
            technique=record.get("technique", ""),
            file=_os.path.basename(record.get("path", "") or "") or "(unknown)",
            reason=record.get("reason", record.get("detector", "detection")),
            status="alert",
        )
        # Free-form, chained, LOCAL: carries the full forensic line (incl. path)
        # into the audit log on this machine, where redact() still scrubs any
        # secret-shaped substring. This is the "log immediately with name, PID,
        # full path, timestamp" record the spec asks for.
        detail = (f"{record.get('name', '?')} pid={record.get('pid', '?')} "
                  f"-> {record.get('target', '?')} "
                  f"[{','.join(record.get('rights', []) or [])}] "
                  f"{record.get('path', '')}")
        security.audit(f"threat_{record.get('detector', 'x')}", detail,
                       record.get("technique", ""))
    except Exception as e:                       # logging must never crash a scan
        print(f"[threatmon] log failed: {type(e).__name__}: {e}")


def record(finding: dict) -> dict | None:
    """Register one finding: dedup, count, log, buffer, persist.

    Returns the stored record, or None if it was suppressed as a duplicate of a
    still-standing condition. Thread-safe: THREAD detectors call this too.
    """
    if not finding:
        return None
    now = time.time()
    key = _dedup_key(finding)
    with _lock:
        last = _last_seen.get(key, 0)
        if now - last < _COOLDOWN_S:
            return None
        _last_seen[key] = now
        rec = dict(finding)
        rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
        # An epoch alongside the human timestamp. Correlation needs to ask
        # "how far apart were these", and re-parsing a formatted local-time
        # string to answer that is both slower and wrong across a DST change.
        # Named at_epoch to match privacy.py, which already learned this.
        rec.setdefault("at_epoch", now)
        tid = rec.get("technique", "")
        _counts[tid] = _counts.get(tid, 0) + 1
        _buffer.append(rec)
    _log(rec)
    _persist(rec)
    _maybe_lock(rec)
    _maybe_speak(rec)
    # Zero-trust intake: an active high/critical detection is one of the
    # strongest signals that this session is under hostile influence, so it
    # feeds the score the same way auth failures do. Never raises into the
    # detector's caller.
    try:
        import zt
        zt.note_threat(str(rec.get("severity", "")))
    except Exception as e:
        print(f"[threatmon] zt intake failed: {type(e).__name__}: {e}")
    return rec


def _maybe_lock(rec: dict) -> None:
    """Lock the session if this is critical and lockdown is armed.

    BEFORE _maybe_speak, so the lock happens and the spoken line can then
    describe a screen that is already locked rather than one about to be.
    Off by default, critical only -- see threatmon/lockdown.py for why this
    is the one autonomous action ARGUS is allowed against a threat, and why
    it is locking rather than killing or quarantining.
    """
    try:
        from . import lockdown
        if lockdown.consider(rec):
            # It announced the lock itself, which supersedes the ordinary
            # spoken alert -- two lines about the same event is noise.
            rec["_locked"] = True
    except Exception as e:
        print(f"[threatmon] lockdown check failed: {type(e).__name__}: {e}")


def latest_alert() -> dict:
    """The newest high/critical finding, shaped for the HUD.

    This is the other half of the spoken alert. The spoken line deliberately
    withholds the specifics -- a room is not private -- and then says the
    detail is on your screen. This is what makes that true rather than a
    promise ARGUS does not keep.

    Local only. Nothing here leaves the machine; it rides the /telemetry poll
    the HUD already makes, behind the same token middleware as every other
    reading.
    """
    with _lock:
        for rec in reversed(_buffer):
            if rec.get("severity") not in ("critical", "high"):
                continue
            reasons = rec.get("reasons") or []
            return {
                "at": rec.get("ts", ""),
                "severity": rec.get("severity", ""),
                "detector": rec.get("detector", ""),
                "technique": rec.get("technique", ""),
                "name": rec.get("name", ""),
                "target": rec.get("target", ""),
                "action": rec.get("action", ""),
                "where": rec.get("where", "") or rec.get("surface", ""),
                "path": rec.get("path", ""),
                # The human-readable "why", which is the thing that makes a
                # finding actionable rather than alarming.
                "why": (reasons if isinstance(reasons, list) else [str(reasons)])[:4],
            }
    return {}


def _maybe_speak(rec: dict) -> None:
    """Say it out loud, if it is worth interrupting for. Never raises.

    Detections have always been silent: they reach the HUD and the audit log,
    and you find them by going and looking. Which means the one time it
    matters -- something happening while you are working -- ARGUS knows and
    says nothing.

    WHAT IT SAYS IS A CATEGORY, NOT THE FINDING. announce carries a kind and
    the words live on the speaking side, so what leaves this function is
    "persistence" and never a path, a process name or a command line. That is
    deliberate beyond the usual reason: a room is not private, and someone
    standing behind you should learn that ARGUS noticed something rather than
    exactly what it found.

    This is LOCAL speech, not the cloud path -- the standing rule that this
    machine's telemetry never reaches a third party is untouched, because
    nothing here leaves the machine.

    Never raises, and deliberately last in record(): the finding is already
    logged and persisted by the time this runs, so a broken speaker cannot
    cost a detection.
    """
    try:
        import announce

        if rec.get("_locked"):
            return          # the lock already spoke; two lines is noise
        if rec.get("severity") not in announce.SPEAK_SEVERITIES:
            return
        kind = announce.DETECTOR_KINDS.get(rec.get("detector", ""),
                                           "threat_generic")
        announce.say(kind, urgent=(rec.get("severity") == "critical"))
    except Exception as e:
        print(f"[threatmon] speak failed: {type(e).__name__}: {e}")


def poll(processes=None) -> list:
    """Run every POLL detector once. Called from the sampler's own try/except,
    but each detector is ALSO isolated here so one throwing cannot rob the
    others of their turn. Returns the records actually stored this tick.
    """
    stored = []
    for det in POLL_DETECTORS:
        try:
            for finding in det.scan(processes) or []:
                rec = record(finding)
                if rec:
                    stored.append(rec)
        except Exception as e:
            # Fail closed: note it, keep going. The detector's own status()
            # will also reflect the failure for the summary.
            print(f"[threatmon] {getattr(det, '__name__', det)}: "
                  f"{type(e).__name__}: {e}")
    return stored


def start():
    """Start THREAD detectors once. Safe to call more than once."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    for det in THREAD_DETECTORS:
        try:
            det.start(record)
        except Exception as e:
            print(f"[threatmon] start {getattr(det, '__name__', det)}: "
                  f"{type(e).__name__}: {e}")


def recent(n: int = 20) -> list:
    with _lock:
        return list(_buffer)[-n:][::-1]      # newest first


def active_providers() -> set:
    """Detector keys currently healthy enough to count as live coverage."""
    live = set()
    for det in POLL_DETECTORS + THREAD_DETECTORS + PASSIVE_DETECTORS:
        try:
            st = det.status()
            if st.get("ok"):
                live.add(st.get("detector"))
        except Exception:
            pass
    # The pre-existing resource-anomaly detector is always-on and lives outside
    # this package; credit its coverage so the grid reflects reality.
    live.add("anomaly")
    return live


def detector_status() -> list:
    """Per-detector health, for the SECURITY panel and the honest summary."""
    out = []
    for det in POLL_DETECTORS + THREAD_DETECTORS + PASSIVE_DETECTORS:
        try:
            out.append(det.status())
        except Exception as e:
            out.append({"detector": getattr(det, "__name__", "?"),
                        "ok": False, "degraded": f"status error: {type(e).__name__}"})
    return out


def mitre_grid() -> list:
    return mitre.grid(active_providers())


def summary_state() -> dict:
    """Everything the security-summary needs, in one call. Local only."""
    with _lock:
        counts = dict(_counts)
        recent_list = list(_buffer)[-10:][::-1]
    return {
        "detectors": detector_status(),
        "counts": counts,
        "recent": recent_list,
        "active_providers": sorted(active_providers()),
        "grid": mitre_grid(),
    }


# ── "what changed on my machine?" ────────────────────────────────────────────
#
# A DIFFERENT QUESTION FROM security_summary(), and the difference is worth
# stating because the two sit next to each other. The summary is POSTURE: how
# things stand, per detector, right now. This is EVENTS: what is different
# since a point in time, in the order it happened.
#
# It became worth building only once there were enough baseline-diff detectors
# to make one answer out of several -- persistence, netconfig, listening,
# defenses and usbwatch all record "this changed" findings, and before this the
# only way to see them together was five separate questions.
#
# DELIBERATELY NOT CORRELATION. Two findings a minute apart are shown a minute
# apart and nothing more is claimed about them: no chains, no incidents, no
# scoring. That is a standing rule of this project -- this is one person's PC,
# not a SOC console -- and it is also the honest limit, because nothing in user
# mode can attribute a registry write to the process that made it. The
# chronology is real; anything built on top of it would be a guess wearing a
# diagram.
_CHANGE_DETECTORS = ("persistence", "netconfig", "listening", "defenses",
                     "usb", "canary", "tamper")

# What each detector's findings are, in the words someone would use for them.
_CHANGE_NOUNS = {
    "persistence": "startup entries",
    "netconfig": "network routing settings",
    "listening": "what accepts connections",
    "defenses": "security protections",
    "usb": "removable devices",
    "canary": "tripwire files",
    "tamper": "ARGUS's own protection",
}


def persisted(hours: float = 24.0) -> list:
    """Detections from the ON-DISK record, newest first.

    recent() reads the in-memory ring, which starts empty at every launch -- so
    "what changed since yesterday" answered from it would report nothing after
    a restart, which is both wrong and reassuring, the worst combination. The
    bounded jsonl record survives the process; this reads that.

    Never raises: a missing or half-written file is treated as no history.
    """
    cutoff = time.time() - max(0.0, float(hours)) * 3600
    out = []
    try:
        path = _detections_path()
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        lines = []

    for line in lines[-_BUFFER_MAX * 4:]:
        try:
            rec = json.loads(line)
        except ValueError:
            continue                    # a torn last line, mid-append
        if not isinstance(rec, dict):
            continue
        at = rec.get("at_epoch")
        if at is None:
            try:
                at = time.mktime(time.strptime(rec.get("ts", ""),
                                               "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                continue
        if float(at) >= cutoff:
            rec["_at"] = float(at)
            out.append(rec)

    # The in-memory ring may hold findings from THIS session that the disk
    # write has not caught up with, and merging both is what makes the answer
    # complete. Keyed on (detector, dedup, timestamp) so a record present in
    # both does not appear twice.
    seen = {(r.get("detector"), r.get("dedup"), int(r.get("_at", 0)))
            for r in out}
    with _lock:
        live = list(_buffer)
    for rec in live:
        at = rec.get("at_epoch") or 0
        if at < cutoff:
            continue
        key = (rec.get("detector"), rec.get("dedup"), int(at))
        if key in seen:
            continue
        rec = dict(rec)
        rec["_at"] = float(at)
        out.append(rec)

    out.sort(key=lambda r: r.get("_at", 0), reverse=True)
    return out


def _epoch_of(rec: dict) -> float:
    """When a detection happened, from whichever field carries it.

    persisted() stamps "_at" as it reads, but a record can reach the report
    from the in-memory ring or from a caller that never went through it -- and
    a report that silently sorts every finding as "time zero" still produces
    confident, well-formed, wrongly-ordered prose. Reading the record's own
    fields instead of a stamp added in passing removes the chance.
    """
    at = rec.get("_at") or rec.get("at_epoch")
    if at:
        try:
            return float(at)
        except (TypeError, ValueError):
            pass
    try:
        return time.mktime(time.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _when(at: float, now: float) -> str:
    mins = max(0, int((now - at) / 60))
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins} minutes ago"
    hours = mins / 60.0
    if hours < 24:
        return f"{int(round(hours))} hours ago"
    return time.strftime("%a %H:%M", time.localtime(at))


def changes_report(hours: float = 24.0) -> str:
    """A spoken answer to "what's changed on my machine?".

    Composed here, deterministically and locally, for the same reason
    security_summary() is: it is telemetry about this machine, and no phrasing
    of the question may route it to a model.

    LEADS WITH SEVERITY, THEN TIME. A critical finding from this morning
    outranks a low one from a minute ago -- reading strictly newest-first would
    open on a USB stick being unplugged and bury a firewall going down.
    """
    try:
        recs = [r for r in persisted(hours)
                if r.get("detector") in _CHANGE_DETECTORS]
    except Exception as e:
        return (f"I couldn't read my own detection record just now "
                f"({type(e).__name__}).")

    window = ("the last day" if 20 <= hours <= 28 else
              f"the last {int(round(hours))} hours" if hours >= 1 else
              f"the last {int(round(hours * 60))} minutes")

    if not recs:
        return (f"Nothing has changed on this machine in {window}, Boss — no "
                f"new startup entries, no new listeners, nothing touched your "
                f"defences or your network settings.")

    rank = {"critical": 0, "high": 1, "medium": 2, "warn": 2, "low": 3}
    now = time.time()
    recs.sort(key=lambda r: (rank.get(r.get("severity", "low"), 3),
                             -_epoch_of(r)))

    serious = [r for r in recs if r.get("severity") in ("critical", "high")]
    lead = recs[0]
    noun = _CHANGE_NOUNS.get(lead.get("detector", ""), "something")

    bits = [f"{len(recs)} thing{'s' if len(recs) != 1 else ''} changed in "
            f"{window}"]

    reasons = lead.get("reasons") or []
    why = reasons[0] if isinstance(reasons, list) and reasons else ""
    bits.append(f"the one I'd look at first is {noun} — "
                f"{lead.get('name', 'something')} {_when(_epoch_of(lead), now)}"
                + (f", {why}" if why else ""))

    if len(serious) > 1:
        bits.append(f"{len(serious) - 1} other{'s' if len(serious) > 2 else ''} "
                    f"at that level too")

    # A count per area, so he knows where to look without hearing every line.
    by_det = {}
    for r in recs[1:]:
        key = _CHANGE_NOUNS.get(r.get("detector", ""), "other")
        by_det[key] = by_det.get(key, 0) + 1
    if by_det:
        listed = ", ".join(f"{v} in {k}" for k, v in
                           sorted(by_det.items(), key=lambda kv: -kv[1])[:3])
        bits.append(f"the rest: {listed}")

    bits.append("the detail is on your screen")

    out = []
    for b in bits:
        b = b.strip()
        if b:
            out.append(b[0].upper() + b[1:])
    return ". ".join(out) + "."


def overall_level() -> str:
    """NOMINAL / ELEVATED / CRITICAL, from the recorded detections' severities.
    A 'critical' or 'high' finding this session is CRITICAL; a 'medium'/'warn'
    is ELEVATED; nothing is NOMINAL."""
    with _lock:
        sevs = [r.get("severity", "") for r in _buffer]
    if any(s in ("critical", "high") for s in sevs):
        return "CRITICAL"
    if any(s in ("medium", "warn") for s in sevs):
        return "ELEVATED"
    return "NOMINAL"


def security_summary() -> dict:
    """A plain-language verdict synthesised from the real detector state.

    DETERMINISTIC AND LOCAL BY CONSTRUCTION. It calls no language model and
    makes no network request, so security telemetry about this machine cannot
    reach the cloud path no matter how the request was phrased -- the property
    the spec demands is structural here, not a routing promise that could be
    got around. And it never hides a blind spot: a detector in a degraded state
    is named in the verdict rather than silently omitted, because a summary that
    conceals what it cannot see is worse than none.
    """
    st = summary_state()
    dstat = {d.get("detector"): d for d in st["detectors"]}
    lines, degraded = [], []

    def total(key):
        return int(dstat.get(key, {}).get("findings_total", 0) or 0)

    # Credential dumping
    d = dstat.get("lsass")
    if d:
        if d.get("degraded"):
            degraded.append(f"LSASS monitoring is degraded ({d['degraded']})")
        lines.append("No LSASS credential-access attempts this session."
                     if not total("lsass")
                     else f"{total('lsass')} LSASS credential-access attempt(s) "
                          f"detected — investigate immediately.")

    # Canary tokens
    d = dstat.get("canary")
    if d:
        trips = int(d.get("trips_total", 0) or 0)
        watched = int(d.get("watched", 0) or 0)
        if d.get("degraded"):
            degraded.append(f"canary tokens are degraded ({d['degraded']})")
        lines.append(f"Canary tokens clean ({watched} decoys watched)."
                     if not trips
                     else f"A canary decoy was accessed {trips} time(s) — "
                          f"someone touched a file only an intruder would.")

    # Tamper / self-defence
    d = dstat.get("tamper")
    if d:
        if d.get("audit_ok") is False:
            degraded.append("the audit-log integrity check reports a broken chain")
        if d.get("config_ok") is False:
            degraded.append("config.py has changed outside a re-seal")
        bv = d.get("boot_verdict") or ""
        if "did not shut down cleanly" in bv:
            lines.append("The previous session did not shut down cleanly — "
                         "possible forced termination.")
        elif not total("tamper"):
            lines.append("No tampering with ARGUS detected.")
        else:
            lines.append(f"{total('tamper')} tamper signal(s) recorded this session.")

    # LOLBins
    d = dstat.get("lolbin")
    if d:
        lines.append("No suspicious use of Windows LOLBins detected."
                     if not total("lolbin")
                     else f"{total('lolbin')} suspicious LOLBin invocation(s) "
                          f"(encoded/proxy execution) detected.")

    # Persistence / autostart
    d = dstat.get("persistence")
    if d:
        if d.get("degraded"):
            degraded.append(f"autostart monitoring is degraded ({d['degraded']})")
        n = total("persistence")
        if not n:
            lines.append(f"No autostart changes since the baseline "
                         f"({int(d.get('entries', 0) or 0)} entries watched across "
                         f"{int(d.get('surfaces', 0) or 0)} surfaces).")
        else:
            lines.append(f"{n} autostart change(s) since the baseline — something "
                         f"asked to run at every boot.")
        # The uncovered surface is a standing blind spot, not an incident, so it
        # belongs in the honest-limits line rather than the findings.
        if d.get("uncovered"):
            degraded.append(f"{d['uncovered']} is not monitored")

    # Privacy / camera + microphone
    d = dstat.get("privacy")
    if d:
        if d.get("degraded"):
            degraded.append(f"privacy watch is degraded ({d['degraded']})")
        n = total("privacy")
        if not n:
            lines.append("Nothing unexpected has used your camera or microphone.")
        else:
            lines.append(f"{n} app(s) used your camera or microphone for the "
                         f"first time — worth a look at what they were.")

    # Network integrity: hosts / DNS / proxy
    d = dstat.get("netconfig")
    if d:
        if d.get("degraded"):
            degraded.append(f"network-integrity monitoring is degraded "
                            f"({d['degraded']})")
        n = total("netconfig")
        if not n:
            lines.append("Your hosts file, DNS servers and proxy settings are "
                         "unchanged — traffic is still going where it should.")
        else:
            lines.append(f"{n} change(s) to your hosts file, DNS or proxy "
                         f"settings — something may be redirecting your traffic.")
        if d.get("hosts_writable"):
            degraded.append("your hosts file can be modified without admin "
                            "rights, so anything running as you can rewrite it")

    # Windows' own defences
    d = dstat.get("defenses")
    if d:
        if d.get("degraded"):
            degraded.append(f"the defensive-posture check is degraded "
                            f"({d['degraded']})")
        n = total("defenses")
        weak = int(d.get("weak", 0) or 0)
        if n:
            lines.append(f"{n} of your security protections changed state — "
                         f"something switched a defence on or off.")
        elif weak:
            lines.append(f"{weak} of your Windows security protections "
                         f"{'are' if weak != 1 else 'is'} not on. Ask me "
                         f"whether you're protected for the detail.")
        else:
            lines.append("Every Windows protection I can check is on.")

    # Network listeners / attack surface
    d = dstat.get("listening")
    if d:
        if d.get("degraded"):
            degraded.append(f"the listening-port sentinel is degraded "
                            f"({d['degraded']})")
        n = total("listening")
        world = int(d.get("world_reachable", 0) or 0)
        if not n:
            lines.append(f"Nothing new is accepting connections "
                         f"({world} listener(s) reachable from the network, "
                         f"unchanged since the baseline).")
        else:
            lines.append(f"{n} change(s) to what this machine accepts "
                         f"connections on — something started or stopped "
                         f"listening.")

    # Clipboard
    d = dstat.get("clipboard")
    if d:
        if total("clipboard"):
            lines.append(f"Clipboard wallet-address changes flagged "
                         f"{total('clipboard')} time(s) — possible clipper.")

    level = overall_level()
    verdict = f"Overall security posture: {level}. " + " ".join(lines)
    if degraded:
        verdict += (" I have blind spots you should know about: "
                    + "; ".join(degraded) + ".")

    return {
        "level": level,
        "verdict": verdict,
        "degraded": degraded,
        "recent": st["recent"],
        "grid": st["grid"],
        "detectors": st["detectors"],
        "generated_locally": True,     # never routed to any model or the cloud
    }
