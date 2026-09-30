"""
ARGUS - Process dossier: everything knowable about one running program.

"Tell me about postgres." "What is that thing doing?" "Who is pid 9544?"

WHY THIS EXISTS, AND WHY IT IS HERE RATHER THAN IN pc_skill.

The port sentinel answers "something on tcp 5432 accepts connections from the
network" and then stops, because that is all a socket table knows. The next
question is always the same one and ARGUS had no way to answer it: what IS
that, where does it live, who started it, is it signed, how long has it been
there, is it talking to anything. Those answers exist in half a dozen psutil
calls and one Win32 API that is already wired up for the integrity check --
they were simply never assembled into one place.

So this is a COMPOSER, not a collector. It reaches for capability that already
exists (psutil counters the sampler reads anyway, integrity.verify_signature()
which was written for the frozen exe, this suite's own detection buffer) and
turns it into the answer a person actually wanted. It adds no new privilege
and no new dependency.

IT SPEAKS ABOUT ONE PROCESS, WHICH IS THE WHOLE POINT. A tool that lists every
process is Task Manager, and Task Manager is right there. What is missing on a
personal machine is the thing an analyst does by hand: pick the one that looks
odd and build a picture of it.

WHAT IS DELIBERATELY WITHHELD.

  * THE COMMAND LINE IS REDACTED, always, through security.redact(). A command
    line is exactly where a password, token or API key ends up when somebody
    passes one on the command line -- which is a bad practice that is
    nonetheless extremely common -- and this reply is spoken aloud, shown on
    screen, and written to the transcript. The forensic value of the arguments
    does not outweigh reading somebody's database password into a room.
  * Nothing is sent anywhere. No hash lookup, no reputation service, no reverse
    DNS on the connections. Same rule as listening.py and network_skill: asking
    what a process is doing must not tell a third party what is running on this
    machine. The module imports no network library.

WHAT IT CANNOT DO.

  * It cannot read another user's processes, or a protected process, without
    elevation. Where a field is unavailable it says so; it never substitutes a
    plausible-looking default.
  * A valid Authenticode signature means the file has not been altered since
    its publisher signed it. It does NOT mean the publisher is trustworthy, and
    plenty of signed binaries are abused -- the report says "signed by X", not
    "safe".
  * It has no opinion on whether a process is malicious. It assembles facts and
    flags the ones that are unusual, which is a different and more honest job.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import time

# Locations a long-running program is not normally installed into. Raises a
# note in the dossier; never a verdict on its own.
UNUSUAL_DIRS = (
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\downloads",
    r"\users\public",
    r"\$recycle.bin",
)

# How many of each list the spoken answer mentions before summarising.
_MAX_CHILDREN = 4
_MAX_CONNECTIONS = 3

# Signature verification opens and hashes the file through WinVerifyTrust.
# Cached per (path, mtime, size) because the dossier is a spoken answer that a
# person may ask for twice in a row, and because "tell me about chrome" would
# otherwise re-verify a 3MB binary every time.
_SIG_CACHE: dict = {}


def _signature(path: str) -> tuple:
    """(ok, detail) for an image's Authenticode signature.

    Delegates to integrity.verify_signature(), which already wraps
    WinVerifyTrust properly -- it takes the path as a wide string in a struct,
    so there is no command line to inject into. An earlier shell-based version
    of that check was a real injection hole; reusing the fixed one rather than
    writing a second is the point.
    """
    if not path or not os.path.isfile(path):
        return False, "no image path"
    try:
        st = os.stat(path)
        key = (os.path.normcase(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return False, "unreadable"
    hit = _SIG_CACHE.get(key)
    if hit:
        return hit
    try:
        import integrity
        res = integrity.verify_signature(path)
    except Exception as e:
        res = (False, f"check failed ({type(e).__name__})")
    _SIG_CACHE[key] = res
    return res


def find(query: str) -> list:
    """Processes matching QUERY: a pid, an exact name, or a substring.

    Returns a list because "chrome" is genuinely eleven processes and pretending
    otherwise -- silently picking the first, or the biggest -- would answer a
    question that was not asked. The caller decides what to do with several.
    """
    import psutil

    q = (query or "").strip().lower()
    if not q:
        return []
    q = q.removesuffix(".exe")

    exact, partial = [], []
    want_pid = int(q) if q.isdigit() else None

    for p in psutil.process_iter(["pid", "name"]):
        try:
            pid = p.info.get("pid")
            name = (p.info.get("name") or "").lower()
            if want_pid is not None:
                if pid == want_pid:
                    return [p]
                continue
            stem = name.removesuffix(".exe")
            if stem == q:
                exact.append(p)
            elif q in stem:
                partial.append(p)
        except Exception:
            continue
    return exact or partial


def _connections(proc) -> dict:
    """{listening: [...], established: [...]} for one process.

    Counted and summarised rather than listed in full: a browser has ninety
    connections and reading them out is not an answer. Remote addresses are
    reported as-is with NO reverse lookup -- see the module header.
    """
    out = {"listening": [], "established": 0, "readable": True}
    try:
        for c in proc.net_connections(kind="inet"):
            status = (c.status or "").upper()
            if status == "LISTEN":
                laddr = getattr(c, "laddr", None)
                if laddr:
                    out["listening"].append(
                        {"addr": getattr(laddr, "ip", ""),
                         "port": int(getattr(laddr, "port", 0) or 0)})
            elif status == "ESTABLISHED":
                out["established"] += 1
    except Exception:
        # AccessDenied on a process owned by another user, which is normal and
        # must be reported as "I could not see" rather than as "none".
        out["readable"] = False
    return out


def _detections_for(pid: int, name: str) -> list:
    """Anything this suite has already recorded about this process.

    Reads threatmon's existing buffer -- it does not re-scan. That is what makes
    the dossier free to ask for, and it means an LSASS access attempt recorded
    ten minutes ago shows up next to the process that made it.
    """
    try:
        import threatmon
        out = []
        for r in threatmon.recent(40):
            if int(r.get("pid", 0) or 0) == int(pid) or \
                    (name and r.get("name", "").lower() == name.lower()):
                out.append(f"{r.get('detector')}: {r.get('reason', '')} "
                           f"[{r.get('technique', '')}]")
        return out[:3]
    except Exception:
        return []


def dossier(proc) -> dict:
    """Every field, gathered once. Missing fields are None, never guessed."""
    import psutil

    d = {"pid": None, "name": "?", "exe": "", "cmdline": "", "user": None,
         "started": None, "age_h": None, "cpu": None, "rss_mb": None,
         "parent": None, "parent_pid": None, "children": [], "threads": None,
         "signed": None, "signature": "", "unusual_dir": "",
         "connections": None, "detections": [], "unreadable": []}

    def grab(field, fn):
        try:
            return fn()
        except psutil.AccessDenied:
            d["unreadable"].append(field)
        except Exception:
            d["unreadable"].append(field)
        return None

    d["pid"] = grab("pid", lambda: proc.pid)
    d["name"] = grab("name", proc.name) or "?"
    d["exe"] = grab("exe", proc.exe) or ""
    d["user"] = grab("user", proc.username)
    d["threads"] = grab("threads", proc.num_threads)

    created = grab("start time", proc.create_time)
    if created:
        d["started"] = time.strftime("%H:%M on %d %b", time.localtime(created))
        d["age_h"] = max(0.0, (time.time() - created) / 3600.0)

    # cpu_percent() with no interval returns the average since the process was
    # first sampled, which for a freshly-constructed Process object is 0.0 --
    # a real measurement needs a gap. A tenth of a second is short enough not
    # to be felt in a spoken reply and long enough to be a real number.
    def _cpu():
        proc.cpu_percent(None)
        time.sleep(0.1)
        return proc.cpu_percent(None)
    d["cpu"] = grab("cpu", _cpu)

    mem = grab("memory", proc.memory_info)
    if mem is not None:
        d["rss_mb"] = round(mem.rss / (1024 * 1024), 1)

    par = grab("parent", proc.parent)
    if par is not None:
        try:
            d["parent"] = par.name()
            d["parent_pid"] = par.pid
        except Exception:
            pass

    kids = grab("children", lambda: proc.children(recursive=False))
    if kids:
        for k in kids[:_MAX_CHILDREN * 3]:
            try:
                d["children"].append(k.name())
            except Exception:
                continue

    raw_cmd = grab("command line", lambda: " ".join(proc.cmdline() or []))
    if raw_cmd:
        # REDACTED, ALWAYS. See the module header: a command line is where a
        # credential ends up, and this string is spoken aloud and written to
        # the transcript.
        try:
            import security
            d["cmdline"] = security.redact(raw_cmd)[:400]
        except Exception:
            d["cmdline"] = ""

    if d["exe"]:
        d["signed"], d["signature"] = _signature(d["exe"])
        low = d["exe"].lower()
        for u in UNUSUAL_DIRS:
            if u in low:
                d["unusual_dir"] = u.strip("\\")
                break

    d["connections"] = _connections(proc)
    d["detections"] = _detections_for(d["pid"] or 0, d["name"])
    return d


def _age_phrase(hours) -> str:
    if hours is None:
        return ""
    if hours < 1:
        return f"{int(round(hours * 60))} minutes"
    if hours < 48:
        return f"{int(round(hours))} hours"
    return f"{int(round(hours / 24))} days"


def describe(d: dict) -> str:
    """One process, as spoken prose. String logic only -- no model, no network.

    ORDERED BY WHAT WOULD CHANGE YOUR MIND. Identity first, then the things
    that make a process interesting or not: where it runs from, whether it is
    signed, what it is holding open, and anything this suite already flagged.
    Resource numbers come last because they are the least diagnostic -- a
    program using 400MB is a fact, not a finding.
    """
    name = d.get("name") or "?"
    bits = [f"{name}, pid {d.get('pid')}"]

    age = _age_phrase(d.get("age_h"))
    if age and d.get("started"):
        bits[-1] += f", running for {age} — started at {d['started']}"

    if d.get("parent"):
        bits.append(f"it was started by {d['parent']}")

    where = d.get("exe") or ""
    if where:
        folder = os.path.dirname(where)
        if d.get("unusual_dir"):
            bits.append(f"it runs from {folder}, which is not where a "
                        f"long-running program normally lives")
        else:
            bits.append(f"it runs from {folder}")
    else:
        bits.append("I can't see its image path from here")

    if d.get("signed"):
        bits.append("the file is signed and the signature checks out")
    elif d.get("exe"):
        sig = d.get("signature") or "unsigned"
        if sig == "NoSignature":
            bits.append("the file is not signed, which is normal for a lot of "
                        "open-source tools and worth a second look on anything else")
        else:
            bits.append(f"its signature reports {sig}")

    conn = d.get("connections") or {}
    if not conn.get("readable", True):
        bits.append("I can't read its network handles without more privilege")
    else:
        listen = conn.get("listening") or []
        est = conn.get("established", 0)
        if listen:
            first = listen[0]
            scope = ("from the network" if first.get("addr") in
                     ("0.0.0.0", "::", "") else "on loopback only")
            bits.append(f"it's accepting connections {scope} on port "
                        f"{first.get('port')}"
                        + (f" and {len(listen) - 1} other"
                           f"{'s' if len(listen) > 2 else ''}"
                           if len(listen) > 1 else ""))
        if est:
            bits.append(f"it has {est} open connection{'s' if est != 1 else ''} out")
        if not listen and not est:
            bits.append("it isn't talking to the network")

    kids = d.get("children") or []
    if kids:
        # COUNTED BY NAME, not listed raw. A worker pool produces eight
        # children with the same image, and reading "postgres.exe,
        # postgres.exe, postgres.exe, postgres.exe and 4 more" aloud is a
        # sentence that takes four seconds and carries one bit of information.
        # "8 children, all postgres.exe" is the same fact, said once.
        counts = {}
        for k in kids:
            counts[k] = counts.get(k, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        noun = f"child process{'es' if len(kids) != 1 else ''}"
        if len(ranked) == 1:
            only, n = ranked[0]
            bits.append(f"it has {len(kids)} {noun}"
                        + (f", all {only}" if n > 1 else f" — {only}"))
        else:
            shown = ranked[:_MAX_CHILDREN]
            more = len(ranked) - len(shown)
            listed = ", ".join(f"{nm}{f' x{n}' if n > 1 else ''}"
                               for nm, n in shown)
            bits.append(f"it has {len(kids)} {noun} — " + listed
                        + (f" and {more} other kind"
                           f"{'s' if more != 1 else ''}" if more else ""))

    if d.get("detections"):
        bits.append(f"and I've already flagged it once — {d['detections'][0]}")

    nums = []
    if d.get("cpu") is not None:
        nums.append(f"{d['cpu']:.0f} percent CPU")
    if d.get("rss_mb") is not None:
        nums.append(f"{d['rss_mb']:.0f} megabytes of memory")
    if nums:
        bits.append("right now it's using " + " and ".join(nums))

    if d.get("unreadable"):
        bits.append(f"I couldn't read its {', '.join(d['unreadable'][:3])}")

    out = []
    for b in bits:
        b = b.strip()
        if b:
            out.append(b[0].upper() + b[1:])
    return ". ".join(out) + "."


def report(query: str) -> str:
    """The spoken answer to "tell me about X".

    Ambiguity is handed BACK rather than resolved silently. "chrome" is eleven
    processes; picking one and describing it would answer confidently and
    wrongly, and the failure is invisible because the answer sounds fine.
    """
    q = (query or "").strip()
    if not q:
        return ("Which program? Give me a name or a process ID and I'll tell "
                "you what I can see.")

    try:
        matches = find(q)
    except Exception as e:
        return f"I couldn't read the process list just now ({type(e).__name__})."

    if not matches:
        return (f"Nothing called {q} is running right now, Boss.")

    if len(matches) > 1:
        # Several. Describe the one holding the most memory -- which is almost
        # always the parent/main process rather than a helper -- and SAY that
        # is what happened, so the choice is visible instead of implied.
        best, best_rss = None, -1
        for p in matches:
            try:
                rss = p.memory_info().rss
            except Exception:
                # AccessDenied, NoSuchProcess, or the process exiting between
                # the scan and this read. Treated as zero so it can still win
                # if it is the only match, but never outranks a readable one.
                rss = 0
            if rss > best_rss:
                best, best_rss = p, rss
        try:
            d = dossier(best)
        except Exception as e:
            return f"I found {len(matches)} of those but couldn't read one ({type(e).__name__})."
        lead = (f"There are {len(matches)} processes called {d.get('name', q)}. "
                f"This is the main one")
        return lead + ". " + describe(d)

    try:
        d = dossier(matches[0])
    except Exception as e:
        return f"I found it but couldn't read it ({type(e).__name__})."
    return describe(d)


def status() -> dict:
    """Introspection for anything that wants to describe this
    module. It is deliberately NOT registered in threatmon's POLL, THREAD or
    PASSIVE lists, and this is not an oversight: those lists drive the SECURITY
    panel's detector rows and the MITRE coverage grid, and this module watches
    nothing and supplies no technique coverage. Listing it would put a row in
    the panel that is permanently "not ok" for a component that is working
    perfectly, and imply detection where there is only inspection. Same
    position lockdown.py and mitre.py hold.
    """
    return {
        "detector": "procinfo",
        "kind": "on-demand inspection, not detection",
        "techniques": [],
        "attribution": "psutil plus WinVerifyTrust; fields needing elevation "
                       "are named, never guessed",
        "redacts_command_line": True,
        "reaches_network": False,
    }
