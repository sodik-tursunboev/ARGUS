"""
ARGUS - Machine control.

The additions I'd argue earn their place in a real assistant:

  media    — play/pause/skip works with Spotify, YouTube, VLC, anything, because
             it sends the same hardware media keys your keyboard does. No
             per-app integration needed.
  dictate  — types into whatever window has focus. Turns ARGUS into a dictation
             tool for any text field on the system.
  stats    — spoken system health. Useful when something feels slow.
  snapshot — screenshots straight into the vault, timestamped.
  lock     — walking away, hands full.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import os
import re
import time
from datetime import datetime

import psutil

# Windows virtual key codes for hardware media keys
VK_MEDIA_NEXT = 0xB0
VK_MEDIA_PREV = 0xB1
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3

KEYEVENTF_KEYUP = 0x0002


def _tap(vk_code: int):
    user32 = ctypes.windll.user32
    user32.keybd_event(vk_code, 0, 0, 0)
    time.sleep(0.03)
    user32.keybd_event(vk_code, 0, KEYEVENTF_KEYUP, 0)


def media(action: str) -> str:
    mapping = {
        "play_pause": (VK_MEDIA_PLAY_PAUSE, "Toggled playback."),
        "next": (VK_MEDIA_NEXT, "Next track."),
        "previous": (VK_MEDIA_PREV, "Previous track."),
        "stop": (VK_MEDIA_STOP, "Stopped playback."),
    }
    if action not in mapping:
        return "I didn't follow that media command."
    vk, msg = mapping[action]
    _tap(vk)
    return msg


VK_LWIN = 0x5B
VK_MENU = 0x12   # Alt
VK_R = 0x52


def _combo_tap(vk_codes: tuple):
    """Presses several keys together, released in reverse order -- same
    keybd_event() primitive _tap() already uses for the single media keys,
    extended to a chord."""
    user32 = ctypes.windll.user32
    for vk in vk_codes:
        user32.keybd_event(vk, 0, 0, 0)
        time.sleep(0.02)
    for vk in reversed(vk_codes):
        user32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)


def toggle_screen_recording() -> str:
    """Win+Alt+R -- the built-in Xbox Game Bar recorder's own start/stop
    shortcut. Hands off to Windows' own recorder rather than this project
    building and maintaining a second one, the same reasoning lock_screen()
    already uses for the lock screen itself."""
    _combo_tap((VK_LWIN, VK_MENU, VK_R))
    return "Toggled screen recording (Windows' own Game Bar recorder)."


_POWER_PLANS = {"balanced": "Balanced", "power saver": "Power saver",
                "high performance": "High performance"}


def power_plan(name: str = "") -> str:
    """Reads or switches the active Windows power plan. NAME empty reads;
    given, must match one of Windows' own three built-in plan names --
    never an arbitrary GUID a caller supplies, so this can only ever select
    a plan Windows itself ships, not one crafted to do something else.
    Needs "powercfg" in execpolicy.ALLOWED_EXECUTABLES; see that module's
    own comment on why that's a deliberate, reviewed addition."""
    import execpolicy

    try:
        out = execpolicy.run(["powercfg", "/list"], timeout=8, text=True).stdout
    except execpolicy.ExecDenied as e:
        return f"I can't check that: {e}"
    except Exception as e:
        return f"I couldn't read power plans: {e}"

    plans = {}   # {lower name: guid}
    active_name = None
    for line in out.splitlines():
        m = re.search(r"Power Scheme GUID:\s*([0-9a-fA-F-]+)\s*\(([^)]+)\)(\s*\*)?", line)
        if m:
            guid, label, is_active = m.group(1), m.group(2).strip(), bool(m.group(3))
            plans[label.lower()] = guid
            if is_active:
                active_name = label

    if not (name or "").strip():
        return f"Current power plan: {active_name or 'unknown'}."

    wanted = _POWER_PLANS.get(name.strip().lower())
    if not wanted or wanted.lower() not in plans:
        return (f"I only switch between Windows' own plans: "
                f"{', '.join(_POWER_PLANS.values())}.")
    try:
        execpolicy.run(["powercfg", "/setactive", plans[wanted.lower()]], timeout=8)
    except execpolicy.ExecDenied as e:
        return f"I can't do that: {e}"
    except Exception as e:
        return f"I couldn't switch power plans: {e}"
    return f"Switched to {wanted}."


def camera_status() -> str:
    """READ-ONLY: whether Windows' global camera privacy switch currently
    allows apps to use the camera. No toggle here -- see this project's own
    scope note on why a write to CapabilityAccessManager isn't included."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
            r"\ConsentStore\webcam")
        value, _ = winreg.QueryValueEx(key, "Value")
    except FileNotFoundError:
        return "I can't find this machine's camera privacy setting."
    except Exception as e:
        return f"I couldn't check the camera setting: {e}"
    return ("Apps are allowed to use the camera." if value == "Allow"
            else "Apps are blocked from using the camera.")


def dictate(text: str) -> str:
    """Types text into the focused window. Small delay first so you can click
    into the target field after speaking.

    THIS IS THE MOST DANGEROUS FUNCTION IN ARGUS and it does not look like it.
    keyboard.write() types into whatever window has focus, the `keyboard`
    library sends "\\n" as Enter, and the text originates from a language
    model. With a terminal focused that is shell execution, reached without
    any skill named "shell" existing. It previously typed whatever it was
    given, unchecked and unbounded.

    execpolicy.check_dictation refuses control characters, caps the length,
    and refuses outright when the focused window is a terminal. It REFUSES
    rather than stripping: quietly typing part of what was asked would tell
    the user something happened that did not, and would let an attacker learn
    which characters survive.
    """
    import execpolicy

    ok, reason = execpolicy.check_dictation(text)
    if not ok:
        return reason
    try:
        import keyboard
    except ImportError:
        return "The keyboard package isn't installed."
    time.sleep(1.2)
    keyboard.write(text, delay=0.01)
    return "Typed."


def work_area():
    """(x, y, w, h) of the usable desktop, taskbar excluded.

    Lives here rather than in window_skill, which is what needs it, for a
    capability reason worth stating: the scanner counts ctypes.windll as a
    filesystem signature, so putting this in window_skill would have meant
    declaring `filesystem` on a module that manages window geometry and
    touches no file. Granting a capability to satisfy a heuristic is exactly
    the over-permission this project's own notes warn about. pc_skill already
    declares filesystem and screen, and "how big is the usable desktop" is a
    system query, which is this module's job.

    SPI_GETWORKAREA is the only thing that knows where the taskbar is, so
    tiling to screen height would put the bottom of every window underneath
    it. Falls back to the full screen rather than refusing: a window placed
    slightly under the taskbar still beats "I couldn't work out your screen".
    """
    try:
        import ctypes
        from ctypes import wintypes

        rect = wintypes.RECT()
        # SPI_GETWORKAREA = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0,
                                                      ctypes.byref(rect), 0):
            return (rect.left, rect.top,
                    rect.right - rect.left, rect.bottom - rect.top)
    except Exception:
        pass
    try:
        import ctypes
        u = ctypes.windll.user32
        return (0, 0, u.GetSystemMetrics(0), u.GetSystemMetrics(1))
    except Exception:
        return (0, 0, 1920, 1080)


def system_stats() -> str:
    cpu = psutil.cpu_percent(interval=0.4)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("C:\\")

    parts = [
        f"CPU at {cpu:.0f} percent",
        f"memory at {mem.percent:.0f} percent, {mem.available / (1024**3):.1f} gigabytes free",
        f"disk {disk.percent:.0f} percent full",
    ]

    battery = psutil.sensors_battery()
    if battery:
        state = "charging" if battery.power_plugged else "on battery"
        parts.append(f"battery {battery.percent:.0f} percent, {state}")

    return "System status: " + ", ".join(parts) + "."


def live_readings(top: int = 5) -> str:
    """A compact snapshot of THIS machine, for the LOCAL model to reason over when
    the person asks why it is slow, hot or full.

    It exists because "why is my pc slow" used to reach the local model with
    nothing to reason about: the request was correctly kept off the cloud, then
    answered by a model that had been shown no readings and could only say so.
    Local retrieval first, local reasoning second -- this is the retrieval.

    WHAT IS IN IT: percentages, sizes, uptime, and the NAMES of the busiest
    processes. WHAT IS NOT: command lines, file paths, window titles, user names
    or network addresses. What a program is called is enough to explain a slow
    machine, and the rest is more than even a local model needs to be shown.

    Per-process CPU is sampled over a real interval (see stoppable()) and summed
    by program name, expressed as a share of the WHOLE machine rather than of one
    core, because "chrome 210%" means nothing to anyone.
    """
    cores = psutil.cpu_count(logical=True) or 1
    procs = []
    for p in psutil.process_iter(["name"]):
        try:
            p.cpu_percent(None)             # prime the counter
            procs.append(p)
        except Exception:
            continue
    overall = psutil.cpu_percent(interval=0.35)     # the sample window for both

    cpu_by, mem_by = {}, {}
    for p in procs:
        try:
            name = (p.info.get("name") or "?").lower()
            cpu_by[name] = cpu_by.get(name, 0.0) + p.cpu_percent(None) / cores
            mem_by[name] = mem_by.get(name, 0) + p.memory_info().rss
        except Exception:
            continue

    vm = psutil.virtual_memory()
    lines = [f"CPU: {overall:.0f}% overall across {cores} logical cores",
             f"Memory: {vm.percent:.0f}% used, {vm.available / 2**30:.1f} GB free "
             f"of {vm.total / 2**30:.1f} GB"]
    try:
        du = psutil.disk_usage("C:\\")
        lines.append(f"Disk C: {du.percent:.0f}% full, {du.free / 2**30:.0f} GB free")
    except Exception:
        pass
    try:
        hours = (time.time() - psutil.boot_time()) / 3600
        lines.append(f"Uptime: {hours / 24:.1f} days" if hours >= 48
                     else f"Uptime: {hours:.1f} hours")
    except Exception:
        pass
    b = psutil.sensors_battery()
    if b is not None:
        lines.append(f"Battery: {b.percent:.0f}%, "
                     f"{'plugged in' if b.power_plugged else 'on battery'}")
    busiest = sorted(cpu_by.items(), key=lambda kv: -kv[1])[:top]
    if busiest:
        lines.append("Busiest by CPU: " + ", ".join(
            f"{n} {c:.0f}%" for n, c in busiest))
    biggest = sorted(mem_by.items(), key=lambda kv: -kv[1])[:top]
    if biggest:
        lines.append("Biggest in memory: " + ", ".join(
            f"{n} {m / 2**30:.1f} GB" for n, m in biggest))
    return "\n".join(lines)


def battery() -> str:
    """Just the battery, and how long it has left.

    system_stats() already mentions the percentage, but only as one clause in
    a sentence about CPU and memory -- so "how long have I got?" was answered
    with a paragraph that did not contain the answer. psutil reports secsleft
    and nothing used it.
    """
    b = psutil.sensors_battery()
    if b is None:
        return "This machine doesn't report a battery — it's probably on mains power."

    pct = f"{b.percent:.0f} percent"
    if b.power_plugged:
        if b.percent >= 99:
            return f"Battery is full at {pct}, plugged in."
        return f"Battery is at {pct} and charging."

    # POWER_TIME_UNKNOWN / UNLIMITED are negative sentinels, not durations.
    # Formatting them naively produces "minus one minutes remaining", which is
    # the kind of output that makes a whole assistant feel broken.
    secs = b.secsleft
    if secs is None or secs < 0:
        return f"Battery is at {pct}, on battery power. Windows hasn't estimated a time yet."

    hours, minutes = divmod(int(secs) // 60, 60)
    if hours and minutes:
        left = f"about {hours} hour{'s' if hours != 1 else ''} {minutes} minutes"
    elif hours:
        left = f"about {hours} hour{'s' if hours != 1 else ''}"
    else:
        left = f"about {minutes} minutes"
    # Says "on battery" explicitly. "16 percent, about 16 minutes remaining"
    # leaves the power state to be inferred from the word "remaining", and the
    # one thing someone asking about battery wants stated is whether it is
    # currently draining.
    if b.percent <= 20:
        return (f"Battery is at {pct} on battery power, {left} remaining "
                f"— worth plugging in.")
    return f"Battery is at {pct} on battery power, {left} remaining."


def uptime() -> str:
    boot = datetime.fromtimestamp(psutil.boot_time())
    delta = datetime.now() - boot
    hours = delta.total_seconds() / 3600
    if hours < 1:
        return f"This machine has been up for {int(delta.total_seconds() / 60)} minutes."
    if hours < 48:
        return f"This machine has been up for {hours:.1f} hours."
    return f"This machine has been up for {delta.days} days."


def snapshot() -> str:
    """Saves a screenshot into the vault's outputs folder."""
    from PIL import ImageGrab
    from config import VAULT_PATH

    out_dir = os.path.join(VAULT_PATH, "outputs")
    os.makedirs(out_dir, exist_ok=True)
    name = f"screenshot_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.png"
    path = os.path.join(out_dir, name)
    ImageGrab.grab().save(path)
    return f"Screenshot saved to the vault as {name}."


SILENT = "__SILENT__"

# Continuous dictation is a MODE, and the mode lives in the voice process --
# that is the side holding the transcript. Authorization, though, is decided
# here in the orchestrator like every other action, so what crosses back is a
# sentinel the listener obeys rather than a decision it makes. Same shape as
# SILENT above, and for the same reason: the process that owns the device does
# the deed, the process that owns the policy says whether it may.
DICTATE_ON = "__DICTATE_ON__"
DICTATE_OFF = "__DICTATE_OFF__"


def dictate_mode(on: bool) -> str:
    """Enter or leave continuous dictation.

    Returns a sentinel, not prose: by the time this runs, auth has already
    allowed it (see auth.py's table), and the listener needs an instruction
    rather than a sentence. It speaks its own confirmation on the way in, so
    what you hear comes from the side that actually started listening.
    """
    return DICTATE_ON if on else DICTATE_OFF


def stop_speaking() -> str:
    """Stop in-progress speech and return the silent sentinel."""
    import tts
    tts.stop()
    try:
        import router
        router.cancel_active_team()
    except Exception:
        pass
    return SILENT


def lock_screen() -> str:
    ctypes.windll.user32.LockWorkStation()
    return "Locking."


# ── UI AUTOMATION ────────────────────────────────────────────────────────────
#
# THE DIFFERENCE BETWEEN AN ASSISTANT AND AN AGENT.
#
# Everything else in this file does a thing somebody wrote a function for.
# That ceiling is the real one: ARGUS can only ever do what has been
# hand-coded, so every new application means new code. Windows UI Automation
# removes the ceiling -- it exposes any application as a tree of elements with
# control patterns, so "click Save in Notepad" and "click Send in Outlook" are
# the same operation against different trees, and neither needs ARGUS to know
# anything about the program.
#
# IT COSTS NO NEW DEPENDENCY. comtypes is already declared, pinned in
# requirements.lock, and in build_exe.py's hiddenimports -- persistence.py
# uses it for the Task Scheduler. Measured working here: the desktop tree
# reads, ElementFromHandle resolves the foreground window, FindAll returns its
# buttons, and Invoke/Value/Toggle/Selection/ExpandCollapse/Scroll/Text/Window
# patterns are all present.
#
# WHY IT IS NOT A GENERIC "DO ANYTHING" HOLE. This is the most powerful thing
# in ARGUS and it is the one most worth being careful with, because a UI tree
# contains buttons that spend money, send messages and delete accounts. Three
# rules, enforced in code rather than in the prompt:
#
#   1. READING IS FREE, ACTING IS NOT. Reading a tree tells you what is on
#      screen. Invoking an element changes the world.
#   2. DESTRUCTIVE-SOUNDING ELEMENTS NEED A SECOND WORD. A fixed list --
#      Delete, Remove, Uninstall, Format, Send, Pay, Buy, Confirm, Yes -- is
#      staged and asked about rather than clicked. It is a blunt rule and it
#      is meant to be: the cost of a needless question is a second, and the
#      cost of a wrong click is somebody's money or somebody's data.
#   3. ARGUS WILL NOT DRIVE ITS OWN INTERFACE. Its HUD is excluded, so it
#      cannot be talked into clicking its own unlock, settings or repair
#      controls -- the same rule that keeps it out of its own source.
#
# NOT COVERED, and stated rather than implied: applications that draw their own
# UI without exposing it (most games, some Electron apps in their content
# area, anything canvas-based) return a tree with nothing useful in it. That is
# a real limit of UIA, not a bug here, and ui_tree() says so rather than
# reporting an empty list as "nothing to click".

_uia = {"api": None, "mod": None}

# Element names that get a confirmation instead of a click. Matched as whole
# words, case-insensitively, against the element's name.
UI_DESTRUCTIVE = (
    "delete", "remove", "uninstall", "format", "erase", "wipe", "reset",
    "send", "pay", "buy", "purchase", "order", "subscribe", "transfer",
    "confirm", "yes", "ok", "accept", "agree", "publish", "post", "submit",
    "shut down", "restart", "sign out", "log out", "close account",
)

_ui_pending = {"element": None, "label": "", "window": "", "at": 0.0}
UI_CONFIRM_WINDOW = 60.0


def _uia_api():
    """(IUIAutomation, generated module) or (None, None). Never raises.

    Built lazily and cached: comtypes.client.GetModule() generates a Python
    wrapper for the type library on first use, which is the expensive part and
    must not happen on the boot path for a feature that may never be used.
    """
    if _uia["api"] is not None:
        return _uia["api"], _uia["mod"]
    try:
        import comtypes
        import comtypes.client
        mod = comtypes.client.GetModule("UIAutomationCore.dll")
        api = comtypes.client.CreateObject(
            "{ff48dba4-60ef-4201-aa87-54103eef594e}",     # CUIAutomation
            interface=mod.IUIAutomation)
        _uia.update(api=api, mod=mod)
        return api, mod
    except Exception:
        return None, None


def _is_argus_window(el) -> bool:
    """Is this ARGUS's own interface? Rule 3.

    Matched on the window title, which is what UIA gives for a WebView-hosted
    HUD -- there is no process identity to compare against, because the HUD
    runs inside ARGUS's own interpreter.
    """
    try:
        name = (el.CurrentName or "").upper()
    except Exception:
        return False
    return "A.R.G.U.S" in name or name.startswith("ARGUS")


def _ui_root(window: str = ""):
    """The element to search under: a named window, or the foreground one."""
    api, mod = _uia_api()
    if api is None:
        return None, None, "UI automation isn't available on this machine."

    if not (window or "").strip():
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            el = api.ElementFromHandle(hwnd)
        except Exception as e:
            return None, None, f"I couldn't read the active window ({type(e).__name__})."
        if _is_argus_window(el):
            return None, None, ("That's my own window — I won't drive my own "
                                "interface. Name another window.")
        return el, mod, ""

    want = window.strip().lower()
    try:
        root = api.GetRootElement()
        walker = api.ControlViewWalker
        child = walker.GetFirstChildElement(root)
        best = None
        skipped_self = False
        while child:
            try:
                nm = (child.CurrentName or "")
                if want in nm.lower():
                    # SAY WHEN IT WAS REFUSED, not "not found". Silently
                    # skipping ARGUS's own window and then reporting that no
                    # such window exists is a lie about a rule -- the rule is
                    # worth stating, and "I can't find it" sends him looking
                    # for a problem that is actually a deliberate refusal.
                    if _is_argus_window(child):
                        skipped_self = True
                    else:
                        best = child
                        break
            except Exception:
                pass
            child = walker.GetNextSiblingElement(child)
    except Exception as e:
        return None, None, f"I couldn't read the desktop ({type(e).__name__})."
    if best is None:
        if skipped_self:
            return None, None, ("That's my own window — I won't drive my own "
                                "interface.")
        return None, None, f"I can't find a window called {window}."
    return best, mod, ""


def _ui_elements(root, mod, limit: int = 60) -> list:
    """Interactive elements under ROOT, as plain dicts.

    Restricted to the control types a person can ACT on. A raw descendant walk
    of a modern application returns thousands of panes and text runs, which is
    a tree nobody can use and a prompt nobody can afford.
    """
    kinds = {
        mod.UIA_ButtonControlTypeId: "button",
        mod.UIA_EditControlTypeId: "text field",
        mod.UIA_CheckBoxControlTypeId: "checkbox",
        mod.UIA_ComboBoxControlTypeId: "dropdown",
        mod.UIA_RadioButtonControlTypeId: "radio",
        mod.UIA_MenuItemControlTypeId: "menu item",
        mod.UIA_TabItemControlTypeId: "tab",
        mod.UIA_ListItemControlTypeId: "list item",
        mod.UIA_HyperlinkControlTypeId: "link",
    }
    out = []
    api, _ = _uia_api()
    for type_id, label in kinds.items():
        if len(out) >= limit:
            break
        try:
            cond = api.CreatePropertyCondition(
                mod.UIA_ControlTypePropertyId, type_id)
            found = root.FindAll(mod.TreeScope_Descendants, cond)
        except Exception:
            continue
        for i in range(min(found.Length, limit)):
            if len(out) >= limit:
                break
            try:
                el = found.GetElement(i)
                name = (el.CurrentName or "").strip()
                if not name:
                    continue
                out.append({"name": name[:80], "kind": label, "el": el,
                            "enabled": bool(el.CurrentIsEnabled)})
            except Exception:
                continue
    return out


def ui_tree(window: str = "") -> str:
    """What is on screen and actionable. READ ONLY.

    The honest answer when an application exposes nothing is that it exposes
    nothing -- games, canvas apps and some Electron content areas draw their
    own UI and UIA cannot see inside. Reporting that as "no buttons" would
    make a real limitation look like an empty window.
    """
    root, mod, err = _ui_root(window)
    if err:
        return err
    try:
        title = (root.CurrentName or "that window").strip()
    except Exception:
        title = "that window"
    els = _ui_elements(root, mod)
    if not els:
        return (f"{title} doesn't expose anything I can work with. Some "
                f"programs draw their own interface and Windows can't see "
                f"inside them — I'd have to go by what's on screen instead.")

    by_kind = {}
    for e in els:
        by_kind.setdefault(e["kind"], []).append(e["name"])
    bits = [f"{title} has {len(els)} things I can work with"]
    for kind in ("button", "text field", "checkbox", "dropdown", "tab",
                 "menu item", "link", "list item", "radio"):
        names = by_kind.get(kind) or []
        if not names:
            continue
        shown = ", ".join(names[:5])
        more = len(names) - min(5, len(names))
        bits.append(f"{len(names)} {kind}{'s' if len(names) != 1 else ''}: "
                    f"{shown}{f' and {more} more' if more else ''}")
    return ". ".join(b[0].upper() + b[1:] for b in bits) + "."


def _ui_match(els: list, name: str):
    """Best element for NAME: exact, then prefix, then substring."""
    want = (name or "").strip().lower()
    if not want:
        return None
    exact = [e for e in els if e["name"].lower() == want]
    if exact:
        return exact[0]
    prefix = [e for e in els if e["name"].lower().startswith(want)]
    if prefix:
        return prefix[0]
    part = [e for e in els if want in e["name"].lower()]
    return part[0] if part else None


def ui_read(name: str, window: str = "") -> str:
    """Read one element's text or state. READ ONLY."""
    root, mod, err = _ui_root(window)
    if err:
        return err
    el = _ui_match(_ui_elements(root, mod), name)
    if el is None:
        return f"I can't find anything called {name} in that window."
    node = el["el"]
    try:
        val = node.GetCurrentPattern(mod.UIA_ValuePatternId)
        if val:
            import comtypes
            v = val.QueryInterface(mod.IUIAutomationValuePattern).CurrentValue
            if v:
                return f"{el['name']} contains: {str(v)[:300]}"
    except Exception:
        pass
    try:
        toggle = node.GetCurrentPattern(mod.UIA_TogglePatternId)
        if toggle:
            state = toggle.QueryInterface(
                mod.IUIAutomationTogglePattern).CurrentToggleState
            return (f"{el['name']} is "
                    f"{'on' if state == 1 else 'off' if state == 0 else 'mixed'}.")
    except Exception:
        pass
    return (f"{el['name']} is a {el['kind']} and it's "
            f"{'enabled' if el['enabled'] else 'greyed out'}.")


def ui_has_pending() -> bool:
    return (_ui_pending["element"] is not None
            and time.time() - _ui_pending["at"] <= UI_CONFIRM_WINDOW)


def ui_cancel() -> str:
    had = ui_has_pending()
    _ui_pending.update(element=None, label="", window="", at=0.0)
    return "Left it alone." if had else "There was nothing waiting."


def _looks_destructive(name: str) -> str:
    low = f" {(name or '').lower()} "
    for word in UI_DESTRUCTIVE:
        if f" {word} " in low or low.strip() == word:
            return word
    return ""


def _ui_invoke(node, mod) -> str:
    """Actually press it. Tries the right pattern for the control."""
    for pat_id, iface, call in (
            (mod.UIA_InvokePatternId, "IUIAutomationInvokePattern", "Invoke"),
            (mod.UIA_TogglePatternId, "IUIAutomationTogglePattern", "Toggle"),
            (mod.UIA_SelectionItemPatternId,
             "IUIAutomationSelectionItemPattern", "Select"),
            (mod.UIA_ExpandCollapsePatternId,
             "IUIAutomationExpandCollapsePattern", "Expand")):
        try:
            pat = node.GetCurrentPattern(pat_id)
            if not pat:
                continue
            getattr(pat.QueryInterface(getattr(mod, iface)), call)()
            return ""
        except Exception:
            continue
    return "that element doesn't support being activated"


def ui_click(name: str, window: str = "", confirmed: bool = False) -> str:
    """Activate an element by name. ACTS on the machine.

    Stages rather than clicking when the element's name is in
    UI_DESTRUCTIVE -- see rule 2 in the header.
    """
    root, mod, err = _ui_root(window)
    if err:
        return err
    els = _ui_elements(root, mod)
    el = _ui_match(els, name)
    if el is None:
        near = ", ".join(e["name"] for e in els[:5])
        return (f"I can't find {name} in that window."
                + (f" I can see {near}." if near else ""))
    if not el["enabled"]:
        return f"{el['name']} is greyed out, so there's nothing to press."

    danger = _looks_destructive(el["name"])
    if danger and not confirmed:
        _ui_pending.update(element=el["el"], label=el["name"],
                           window=window, at=time.time())
        return (f"{el['name']} looks like it does something I can't undo — "
                f"it says {danger}. Want me to press it?")

    problem = _ui_invoke(el["el"], mod)
    if problem:
        return f"I found {el['name']} but {problem}."
    try:
        import security
        security.audit("ui_click", f"{el['name'][:40]}", "ok")
    except Exception:
        pass
    return f"Pressed {el['name']}."


def ui_confirm_click() -> str:
    if not ui_has_pending():
        _ui_pending.update(element=None, label="", window="", at=0.0)
        return "That expired — ask me again."
    node = _ui_pending["element"]
    label = _ui_pending["label"]
    _ui_pending.update(element=None, label="", window="", at=0.0)
    _, mod = _uia_api()
    if mod is None:
        return "UI automation isn't available any more."
    problem = _ui_invoke(node, mod)
    if problem:
        return f"I tried {label} but {problem}."
    try:
        import security
        security.audit("ui_click", f"{label[:40]} (confirmed)", "ok")
    except Exception:
        pass
    return f"Pressed {label}."


def ui_type(name: str, value: str, window: str = "") -> str:
    """Put text into a named field. ACTS on the machine.

    Uses the Value pattern rather than synthesising keystrokes: the text goes
    into the field that was named, not into whatever has focus at the moment
    the keys land. That distinction is the whole reason execpolicy guards
    dictate() so carefully -- a keystroke path can type into a terminal.
    """
    root, mod, err = _ui_root(window)
    if err:
        return err
    el = _ui_match(_ui_elements(root, mod), name)
    if el is None:
        return f"I can't find a field called {name} in that window."
    try:
        pat = el["el"].GetCurrentPattern(mod.UIA_ValuePatternId)
        if not pat:
            return f"{el['name']} isn't something I can type into."
        vp = pat.QueryInterface(mod.IUIAutomationValuePattern)
        if vp.CurrentIsReadOnly:
            return f"{el['name']} is read-only."
        vp.SetValue(str(value))
    except Exception as e:
        return f"I couldn't set that ({type(e).__name__})."
    try:
        import security
        # The VALUE is never logged -- a text field is exactly where a password
        # or a token is typed, and this reply is also spoken aloud.
        security.audit("ui_type", f"field={el['name'][:40]} len={len(str(value))}", "ok")
    except Exception:
        pass
    return f"Put that into {el['name']}."


# ── UI AUTOMATION, PART 2: the interactions a real application needs ─────────
#
# Part 1 above reads a tree and presses a button. That is enough to prove the
# approach and not enough to drive a program: real UI has dropdowns that must
# be opened before an item can be picked, tables whose cells are the answer,
# dialogs that appear on top of everything and must be dismissed, sliders,
# menus, and things that only respond to a right-click or a double-click.
#
# EVERY PATTERN FIRST, THE MOUSE LAST. UIA control patterns (Invoke, Toggle,
# ExpandCollapse, SelectionItem, RangeValue, Scroll, Grid) act on the element
# semantically -- they work whether or not it is visible, and they cannot miss.
# Synthesised mouse input is the fallback for the cases UIA genuinely has no
# pattern for (a right-click, a double-click, a hover, a drag), and it is aimed
# at the element's OWN measured bounding rectangle, never at a remembered
# coordinate -- which is what "much more powerful than hard-coding
# coordinates" means in practice.
#
# THE SAME THREE RULES APPLY. Reading is free, acting is gated at L2, a
# destructive-looking name is staged and asked about, and ARGUS's own window
# is never a target. A drag is treated as an action on its SOURCE element, so
# dragging something called "Delete" asks first exactly as clicking it would.

_MOUSEEVENTF_LEFTDOWN = 0x0002
_MOUSEEVENTF_LEFTUP = 0x0004
_MOUSEEVENTF_RIGHTDOWN = 0x0008
_MOUSEEVENTF_RIGHTUP = 0x0010
_MOUSEEVENTF_WHEEL = 0x0800
_WHEEL_DELTA = 120


def _ui_find(name: str, window: str = ""):
    """(element_dict, mod, error). One lookup shared by every action below."""
    root, mod, err = _ui_root(window)
    if err:
        return None, None, err
    els = _ui_elements(root, mod, limit=120)
    el = _ui_match(els, name)
    if el is None:
        near = ", ".join(e["name"] for e in els[:5])
        return None, None, (f"I can't find {name} in that window."
                            + (f" I can see {near}." if near else ""))
    return el, mod, ""


def _ui_centre(node) -> tuple:
    """(x, y) of the element's centre, from its LIVE bounding rectangle."""
    try:
        r = node.CurrentBoundingRectangle
        left, top, right, bottom = int(r.left), int(r.top), int(r.right), int(r.bottom)
    except Exception:
        return None
    if right <= left or bottom <= top:
        return None
    return (left + right) // 2, (top + bottom) // 2


def _mouse_move(x: int, y: int) -> None:
    ctypes.windll.user32.SetCursorPos(int(x), int(y))


def _mouse_click(x: int, y: int, button: str = "left", count: int = 1) -> None:
    """Synthesised click(s) at (x, y). Fallback only -- see the header."""
    down = _MOUSEEVENTF_LEFTDOWN if button == "left" else _MOUSEEVENTF_RIGHTDOWN
    up = _MOUSEEVENTF_LEFTUP if button == "left" else _MOUSEEVENTF_RIGHTUP
    _mouse_move(x, y)
    for _ in range(max(1, count)):
        ctypes.windll.user32.mouse_event(down, 0, 0, 0, 0)
        ctypes.windll.user32.mouse_event(up, 0, 0, 0, 0)
        time.sleep(0.05)


def _gate(el: dict, verb: str, window: str):
    """Stage a destructive-looking element instead of acting. Returns the
    question to ask, or "" if the action may proceed."""
    danger = _looks_destructive(el["name"])
    if not danger:
        return ""
    _ui_pending.update(element=el["el"], label=el["name"], window=window,
                       at=time.time())
    return (f"{el['name']} looks like it does something I can't undo — it "
            f"says {danger}. Want me to {verb} it?")


def ui_double_click(name: str, window: str = "") -> str:
    """Double-click an element. Mouse fallback: UIA has no double-click pattern."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    q = _gate(el, "double-click", window)
    if q:
        return q
    c = _ui_centre(el["el"])
    if not c:
        return f"{el['name']} isn't on screen, so I can't double-click it."
    _mouse_click(*c, button="left", count=2)
    _audit_ui("ui_double_click", el["name"])
    return f"Double-clicked {el['name']}."


def ui_right_click(name: str, window: str = "") -> str:
    """Right-click an element, which opens its context menu."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    c = _ui_centre(el["el"])
    if not c:
        return f"{el['name']} isn't on screen, so I can't right-click it."
    _mouse_click(*c, button="right")
    _audit_ui("ui_right_click", el["name"])
    return (f"Opened the menu on {el['name']}. Tell me which item to pick, or "
            f"ask what's in the menu.")


def ui_hover(name: str, window: str = "") -> str:
    """Move the pointer over an element -- reveals tooltips and hover states."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    c = _ui_centre(el["el"])
    if not c:
        return f"{el['name']} isn't on screen."
    _mouse_move(*c)
    return f"Hovering over {el['name']}."


def ui_drag(source: str, destination: str, window: str = "") -> str:
    """Drag one element onto another. Gated on the SOURCE's name."""
    src, mod, err = _ui_find(source, window)
    if err:
        return err
    dst, _, err = _ui_find(destination, window)
    if err:
        return err
    q = _gate(src, "drag", window)
    if q:
        return q
    a, b = _ui_centre(src["el"]), _ui_centre(dst["el"])
    if not a or not b:
        return "One of those isn't on screen, so I can't drag between them."
    u = ctypes.windll.user32
    _mouse_move(*a)
    u.mouse_event(_MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    # A handful of intermediate moves: many drop targets only register a drag
    # once the pointer has actually travelled, not when it teleports.
    for i in range(1, 8):
        x = a[0] + (b[0] - a[0]) * i // 8
        y = a[1] + (b[1] - a[1]) * i // 8
        _mouse_move(x, y)
        time.sleep(0.02)
    _mouse_move(*b)
    time.sleep(0.05)
    u.mouse_event(_MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    _audit_ui("ui_drag", f"{src['name']} -> {dst['name']}")
    return f"Dragged {src['name']} onto {dst['name']}."


def ui_scroll(direction: str = "down", amount: int = 3, name: str = "",
              window: str = "") -> str:
    """Scroll an element (or the window). Pattern first, wheel second."""
    api, mod = _uia_api()
    if api is None:
        return "UI automation isn't available on this machine."
    if name:
        el, mod, err = _ui_find(name, window)
        if err:
            return err
        node, label = el["el"], el["name"]
    else:
        root, mod, err = _ui_root(window)
        if err:
            return err
        node, label = root, "the window"
    d = (direction or "down").lower()
    amount = max(1, min(int(amount or 3), 20))

    # ScrollPattern: semantic, and it scrolls the element whether or not the
    # pointer is over it.
    try:
        pat = node.GetCurrentPattern(mod.UIA_ScrollPatternId)
        if pat:
            sp = pat.QueryInterface(mod.IUIAutomationScrollPattern)
            NA, INC, DEC = 5, 1, 2          # ScrollAmount_NoAmount / SmallIncrement / SmallDecrement
            for _ in range(amount):
                if d in ("down",):
                    sp.Scroll(NA, INC)
                elif d in ("up",):
                    sp.Scroll(NA, DEC)
                elif d in ("right",):
                    sp.Scroll(INC, NA)
                elif d in ("left",):
                    sp.Scroll(DEC, NA)
            return f"Scrolled {label} {d}."
    except Exception:
        pass
    # Wheel fallback, aimed at the element.
    c = _ui_centre(node)
    if not c:
        return f"{label} doesn't scroll and isn't on screen."
    _mouse_move(*c)
    delta = -_WHEEL_DELTA if d == "down" else _WHEEL_DELTA
    for _ in range(amount):
        ctypes.windll.user32.mouse_event(_MOUSEEVENTF_WHEEL, 0, 0, delta, 0)
        time.sleep(0.02)
    return f"Scrolled {label} {d}."


def ui_select(item: str, name: str = "", window: str = "") -> str:
    """Pick an item in a dropdown, list, tab strip or menu.

    A dropdown has to be OPENED before its items exist in the tree, so if a
    container is named it is expanded first and the item searched for after.
    """
    if name:
        el, mod, err = _ui_find(name, window)
        if err:
            return err
        try:
            pat = el["el"].GetCurrentPattern(mod.UIA_ExpandCollapsePatternId)
            if pat:
                pat.QueryInterface(mod.IUIAutomationExpandCollapsePattern).Expand()
                time.sleep(0.25)             # let the popup populate
        except Exception:
            pass
    it, mod, err = _ui_find(item, window)
    if err:
        return err
    q = _gate(it, "select", window)
    if q:
        return q
    for pat_id, iface, call in (
            (mod.UIA_SelectionItemPatternId, "IUIAutomationSelectionItemPattern", "Select"),
            (mod.UIA_InvokePatternId, "IUIAutomationInvokePattern", "Invoke")):
        try:
            pat = it["el"].GetCurrentPattern(pat_id)
            if pat:
                getattr(pat.QueryInterface(getattr(mod, iface)), call)()
                _audit_ui("ui_select", it["name"])
                return f"Selected {it['name']}."
        except Exception:
            continue
    c = _ui_centre(it["el"])
    if c:
        _mouse_click(*c)
        _audit_ui("ui_select", it["name"])
        return f"Selected {it['name']}."
    return f"I found {it['name']} but couldn't select it."


def ui_set_slider(name: str, value: float, window: str = "") -> str:
    """Set a slider or spinner to a value via RangeValue."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    try:
        pat = el["el"].GetCurrentPattern(mod.UIA_RangeValuePatternId)
        if not pat:
            return f"{el['name']} isn't a slider."
        rv = pat.QueryInterface(mod.IUIAutomationRangeValuePattern)
        lo, hi = float(rv.CurrentMinimum), float(rv.CurrentMaximum)
        v = max(lo, min(hi, float(value)))
        rv.SetValue(v)
    except Exception as e:
        return f"I couldn't set that ({type(e).__name__})."
    _audit_ui("ui_slider", f"{el['name']}={v:g}")
    return f"Set {el['name']} to {v:g}."


def ui_toggle(name: str, window: str = "", want=None) -> str:
    """Tick or untick a checkbox / switch. want=True/False makes it idempotent."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    try:
        pat = el["el"].GetCurrentPattern(mod.UIA_TogglePatternId)
        if not pat:
            return f"{el['name']} isn't a checkbox or switch."
        tp = pat.QueryInterface(mod.IUIAutomationTogglePattern)
        state = tp.CurrentToggleState             # 0 off, 1 on, 2 indeterminate
        if want is not None and bool(state == 1) == bool(want):
            return f"{el['name']} is already {'on' if want else 'off'}."
        tp.Toggle()
        after = tp.CurrentToggleState
    except Exception as e:
        return f"I couldn't toggle that ({type(e).__name__})."
    _audit_ui("ui_toggle", el["name"])
    return f"{el['name']} is now {'on' if after == 1 else 'off' if after == 0 else 'mixed'}."


def ui_expand(name: str, window: str = "", collapse: bool = False) -> str:
    """Expand or collapse a tree node, menu or group."""
    el, mod, err = _ui_find(name, window)
    if err:
        return err
    try:
        pat = el["el"].GetCurrentPattern(mod.UIA_ExpandCollapsePatternId)
        if not pat:
            return f"{el['name']} doesn't expand."
        ec = pat.QueryInterface(mod.IUIAutomationExpandCollapsePattern)
        (ec.Collapse if collapse else ec.Expand)()
    except Exception as e:
        return f"I couldn't do that ({type(e).__name__})."
    return f"{'Collapsed' if collapse else 'Expanded'} {el['name']}."


def ui_table(name: str = "", window: str = "", max_rows: int = 8) -> str:
    """Read a table or grid: headers, then rows. READ ONLY."""
    api, mod = _uia_api()
    if api is None:
        return "UI automation isn't available on this machine."
    if name:
        el, mod, err = _ui_find(name, window)
        if err:
            return err
        node, label = el["el"], el["name"]
    else:
        root, mod, err = _ui_root(window)
        if err:
            return err
        # The first grid in the window.
        try:
            cond = api.CreatePropertyCondition(
                mod.UIA_IsGridPatternAvailablePropertyId, True)
            node = root.FindFirst(mod.TreeScope_Descendants, cond)
        except Exception:
            node = None
        if node is None:
            return "I can't see a table in that window."
        try:
            label = node.CurrentName or "the table"
        except Exception:
            label = "the table"
    try:
        pat = node.GetCurrentPattern(mod.UIA_GridPatternId)
        if not pat:
            return f"{label} isn't a table I can read."
        grid = pat.QueryInterface(mod.IUIAutomationGridPattern)
        rows, cols = int(grid.CurrentRowCount), int(grid.CurrentColumnCount)
    except Exception as e:
        return f"I couldn't read that table ({type(e).__name__})."
    if rows == 0 or cols == 0:
        return f"{label} is empty."
    out = []
    for r in range(min(rows, max_rows)):
        cells = []
        for c in range(min(cols, 8)):
            try:
                item = grid.GetItem(r, c)
                txt = (item.CurrentName or "").strip()
                if not txt:
                    vp = item.GetCurrentPattern(mod.UIA_ValuePatternId)
                    if vp:
                        txt = str(vp.QueryInterface(
                            mod.IUIAutomationValuePattern).CurrentValue or "")
                cells.append(txt[:30] or "-")
            except Exception:
                cells.append("?")
        out.append(" | ".join(cells))
    more = rows - min(rows, max_rows)
    return (f"{label}: {rows} row{'s' if rows != 1 else ''}, {cols} column"
            f"{'s' if cols != 1 else ''}. " + " ; ".join(out)
            + (f" ; and {more} more rows." if more else "."))


def ui_dialog(window: str = "") -> str:
    """Is a dialog in the way? Names it and its buttons. READ ONLY.

    A dialog is the thing that silently breaks every automated sequence: the
    plan clicks Save, a "Replace existing file?" box appears, and every step
    after that presses buttons on a window that is no longer in front. Being
    able to ASK is what lets the task loop notice.
    """
    api, mod = _uia_api()
    if api is None:
        return "UI automation isn't available on this machine."
    try:
        root = api.GetRootElement()
        cond = api.CreatePropertyCondition(
            mod.UIA_ControlTypePropertyId, mod.UIA_WindowControlTypeId)
        wins = root.FindAll(mod.TreeScope_Children, cond)
    except Exception as e:
        return f"I couldn't read the desktop ({type(e).__name__})."
    found = []
    for i in range(wins.Length):
        try:
            w = wins.GetElement(i)
            pat = w.GetCurrentPattern(mod.UIA_WindowPatternId)
            if not pat:
                continue
            wp = pat.QueryInterface(mod.IUIAutomationWindowPattern)
            if not wp.CurrentIsModal:
                continue
            if _is_argus_window(w):
                continue
            name = (w.CurrentName or "").strip() or "an unnamed dialog"
            btn_cond = api.CreatePropertyCondition(
                mod.UIA_ControlTypePropertyId, mod.UIA_ButtonControlTypeId)
            btns = w.FindAll(mod.TreeScope_Descendants, btn_cond)
            names = []
            for j in range(min(btns.Length, 6)):
                try:
                    n = (btns.GetElement(j).CurrentName or "").strip()
                    if n:
                        names.append(n)
                except Exception:
                    pass
            found.append((name, names))
        except Exception:
            continue
    if not found:
        return "No dialog is in the way."
    name, names = found[0]
    return (f"There's a dialog up: {name[:60]}"
            + (f", with {', '.join(names)}." if names else ".")
            + (f" And {len(found) - 1} more behind it." if len(found) > 1 else ""))


def ui_wait(name: str, timeout: float = 10.0, window: str = "") -> str:
    """Wait until an element appears. The honest stand-in for an event listener.

    A UIA event subscription needs a COM callback object living on a message
    pump, which the orchestrator's request threads do not have. Polling the
    tree every 300ms for a bounded time answers the question the task loop
    actually asks -- "has the thing I need shown up yet" -- without any of that.
    """
    deadline = time.time() + max(0.5, min(float(timeout), 60.0))
    while time.time() < deadline:
        el, _mod, err = _ui_find(name, window)
        if not err:
            return f"{el['name']} is there."
        time.sleep(0.3)
    return f"{name} didn't appear within {int(timeout)} seconds."


def ui_verify(name: str, expect: str = "", window: str = "") -> str:
    """Check an element's state after an action. READ ONLY.

    expect is one of: on, off, enabled, disabled, present, or text the field
    should contain. Verification is what turns "I pressed Save" into "the
    document is saved" -- and what lets a plan stop when it is not.
    """
    want = (expect or "present").strip().lower()
    el, mod, err = _ui_find(name, window)
    if err:
        return f"No — {err}" if want != "absent" else f"Yes — {name} is gone."
    if want == "absent":
        return f"No — {el['name']} is still there."
    if want == "present":
        return f"Yes — {el['name']} is there."
    if want in ("enabled", "disabled"):
        ok = el["enabled"] == (want == "enabled")
        return (f"{'Yes' if ok else 'No'} — {el['name']} is "
                f"{'enabled' if el['enabled'] else 'greyed out'}.")
    if want in ("on", "off", "checked", "unchecked", "ticked", "unticked"):
        try:
            pat = el["el"].GetCurrentPattern(mod.UIA_TogglePatternId)
            state = pat.QueryInterface(mod.IUIAutomationTogglePattern).CurrentToggleState
        except Exception:
            return f"{el['name']} isn't something that's on or off."
        is_on = state == 1
        ok = is_on == (want in ("on", "checked", "ticked"))
        return f"{'Yes' if ok else 'No'} — {el['name']} is {'on' if is_on else 'off'}."
    # Text the field should contain.
    try:
        pat = el["el"].GetCurrentPattern(mod.UIA_ValuePatternId)
        val = str(pat.QueryInterface(mod.IUIAutomationValuePattern).CurrentValue or "")
    except Exception:
        val = el["name"]
    ok = want in val.lower()
    return (f"{'Yes' if ok else 'No'} — {el['name']} "
            f"{'contains' if ok else 'does not contain'} that.")


def ui_screenshot(name: str = "", window: str = "") -> str:
    """Capture one element (or the window) to the vault. Uses the same
    Pillow path snapshot() does, cropped to the element's live rectangle."""
    from PIL import ImageGrab

    if name:
        el, mod, err = _ui_find(name, window)
        if err:
            return err
        node, label = el["el"], el["name"]
    else:
        root, mod, err = _ui_root(window)
        if err:
            return err
        node, label = root, "window"
    try:
        r = node.CurrentBoundingRectangle
        box = (int(r.left), int(r.top), int(r.right), int(r.bottom))
    except Exception:
        return f"I can't find where {label} is on screen."
    if box[2] <= box[0] or box[3] <= box[1]:
        return f"{label} isn't visible."
    try:
        from config import VAULT_PATH
        img = ImageGrab.grab(bbox=box)
        out_dir = os.path.join(VAULT_PATH, "outputs")
        os.makedirs(out_dir, exist_ok=True)
        safe = re.sub(r"[^\w-]+", "_", label)[:40] or "element"
        path = os.path.join(out_dir, f"ui_{safe}_{time.strftime('%Y%m%d-%H%M%S')}.png")
        img.save(path)
    except Exception as e:
        return f"I couldn't capture that ({type(e).__name__})."
    return f"Captured {label} to {os.path.basename(path)}."


def _audit_ui(kind: str, detail: str) -> None:
    try:
        import security
        security.audit(kind, detail[:60], "ok")
    except Exception:
        pass


# ── local machine controls ───────────────────────────────────────────────────
#
# Everything here is Win32 through ctypes or a registry read. No new
# executable, no new dependency, nothing that leaves the machine -- which is
# the standing rule for anything that CONTROLS this computer rather than
# answering a question about the world.
#
# Each one is a thing that was genuinely missing rather than a variation on
# something ARGUS already did. The test of "genuinely missing" used here: is
# there a reason to say it out loud instead of clicking it, and does ARGUS have
# no other way to do it.

# SetThreadExecutionState flags. ES_CONTINUOUS makes the state stick until it
# is cleared rather than applying to one call.
_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001
_ES_DISPLAY_REQUIRED = 0x00000002

_awake = {"on": False}


def keep_awake(on: bool = True, screen: bool = True) -> str:
    """Stop the machine sleeping. The classic "I'm watching this, don't lock".

    Uses SetThreadExecutionState rather than nudging the mouse, which is what
    a keep-awake utility usually does and which fights the user for the
    pointer. This is the supported API and it is exactly reversible.

    NOT PERSISTENT ACROSS A RESTART, deliberately: a machine that silently
    refuses to sleep forever because of something said last week is a laptop
    that cooks in a bag. It lasts as long as ARGUS is running.
    """
    flags = _ES_CONTINUOUS
    if on:
        flags |= _ES_SYSTEM_REQUIRED
        if screen:
            flags |= _ES_DISPLAY_REQUIRED
    try:
        ok = ctypes.windll.kernel32.SetThreadExecutionState(flags)
    except Exception as e:
        return f"I couldn't change the sleep setting ({type(e).__name__})."
    if not ok:
        return "Windows refused to change the sleep setting."
    _awake["on"] = bool(on)
    if on:
        return ("I'll keep the machine awake"
                + (" and the screen on" if screen else "")
                + " until you tell me otherwise, or until I'm restarted.")
    return "Back to normal sleep settings."


def awake_status() -> str:
    return ("I'm holding the machine awake right now."
            if _awake["on"] else
            "Normal sleep settings — I'm not holding anything awake.")


def empty_recycle_bin(confirm: bool = False) -> str:
    """Empty the Recycle Bin.

    IRREVERSIBLE, so it measures first and asks. The bin is the last safety
    net under every delete on this machine -- including ARGUS's own
    files_skill, which deletes TO the bin precisely so a mistake is
    recoverable. Emptying it without asking would quietly remove the thing
    that makes the rest of the file handling safe.
    """
    SHERB_NOCONFIRMATION = 0x01
    SHERB_NOPROGRESSUI = 0x02
    SHERB_NOSOUND = 0x04

    if not confirm:
        # SHQueryRecycleBin gives the real size and count, so the question is
        # about something specific rather than "are you sure".
        class _RBINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_ulonglong),
                        ("i64Size", ctypes.c_ulonglong),
                        ("i64NumItems", ctypes.c_ulonglong)]
        info = _RBINFO()
        info.cbSize = ctypes.sizeof(_RBINFO)
        try:
            rc = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        except Exception as e:
            return f"I couldn't read the Recycle Bin ({type(e).__name__})."
        if rc != 0:
            return "I couldn't read the Recycle Bin."
        if not info.i64NumItems:
            return "The Recycle Bin is already empty, Boss."
        mb = info.i64Size / (1024 * 1024)
        size = f"{mb / 1024:.1f} gigabytes" if mb >= 1024 else f"{mb:.0f} megabytes"
        return (f"The Recycle Bin holds {info.i64NumItems} item"
                f"{'s' if info.i64NumItems != 1 else ''}, {size}. Emptying it "
                f"can't be undone — say yes and I'll do it.")

    try:
        rc = ctypes.windll.shell32.SHEmptyRecycleBinW(
            None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
    except Exception as e:
        return f"That didn't work ({type(e).__name__})."
    if rc != 0:
        return "Windows wouldn't empty it."
    try:
        import security
        security.audit("recycle_bin", "emptied", "ok")
    except Exception:
        pass
    return "Recycle Bin emptied."


_THEME_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"


def dark_mode(on: bool = None) -> str:
    """Read or set the Windows light/dark theme.

    HKCU only -- this is a per-user preference and needs no elevation. Both
    values are written: Windows tracks the shell (taskbar, Start) and app
    themes separately, and setting one leaves a half-switched desktop that
    looks like a bug.
    """
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _THEME_KEY) as k:
            apps = int(winreg.QueryValueEx(k, "AppsUseLightTheme")[0])
    except Exception:
        apps = 1

    if on is None:
        return ("You're in dark mode." if not apps else "You're in light mode.")

    want_light = 0 if on else 1
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _THEME_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "AppsUseLightTheme", 0, winreg.REG_DWORD, want_light)
            winreg.SetValueEx(k, "SystemUsesLightTheme", 0, winreg.REG_DWORD, want_light)
    except Exception as e:
        return f"I couldn't change the theme ({type(e).__name__})."
    # Nudge the shell so open windows repaint instead of waiting for a restart.
    try:
        HWND_BROADCAST, WM_SETTINGCHANGE = 0xFFFF, 0x001A
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0,
            ctypes.c_wchar_p("ImmersiveColorSet"), 0, 1000, None)
    except Exception:
        pass
    return f"Switched to {'dark' if on else 'light'} mode."


def display_info() -> str:
    """Monitors, resolution and scaling. Read-only."""
    try:
        user32 = ctypes.windll.user32
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass                      # already set, or an older Windows
        count = user32.GetSystemMetrics(80)          # SM_CMONITORS
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        vw = user32.GetSystemMetrics(78)             # SM_CXVIRTUALSCREEN
        vh = user32.GetSystemMetrics(79)
    except Exception as e:
        return f"I couldn't read the display settings ({type(e).__name__})."
    bits = [f"{count} monitor{'s' if count != 1 else ''}",
            f"the main one is {w} by {h}"]
    if count > 1:
        bits.append(f"the whole desktop spans {vw} by {vh}")
    return ". ".join(b[0].upper() + b[1:] for b in bits) + "."


def system_info() -> str:
    """What this machine actually is. Read-only, local, no network."""
    import platform
    import winreg

    bits = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            product = winreg.QueryValueEx(k, "ProductName")[0]
            build = winreg.QueryValueEx(k, "CurrentBuild")[0]
            try:
                display = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except FileNotFoundError:
                display = ""
        # Windows 11 still reports "Windows 10 Pro" in ProductName; the build
        # number is what actually distinguishes them, so it is corrected here
        # rather than read back wrong.
        if str(product).startswith("Windows 10") and int(build) >= 22000:
            product = str(product).replace("Windows 10", "Windows 11", 1)
        bits.append(f"{product}{f' {display}' if display else ''}, build {build}")
    except Exception:
        bits.append(platform.platform())

    try:
        cores = psutil.cpu_count(logical=False) or 0
        threads = psutil.cpu_count(logical=True) or 0
        bits.append(f"{cores} cores and {threads} threads")
    except Exception:
        pass
    try:
        gb = psutil.virtual_memory().total / (1024 ** 3)
        bits.append(f"{gb:.0f} gigabytes of memory")
    except Exception:
        pass
    try:
        up = time.time() - psutil.boot_time()
        hrs = up / 3600
        bits.append(f"up {int(hrs)} hours" if hrs >= 1
                    else f"up {int(up / 60)} minutes")
    except Exception:
        pass
    return ". ".join(b[0].upper() + b[1:] for b in bits) + "."


def installed_programs(query: str = "") -> str:
    """What is installed, from the uninstall registry. Read-only.

    Both registry views AND both hives: a 32-bit installer writes under
    Wow6432Node and a per-user install writes under HKCU, so reading only
    HKLM's native view misses a large fraction of what is actually on a
    machine -- which would make "is X installed" answer no when it is.
    """
    import winreg

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
    ]
    found = {}
    for hive, sub, view in roots:
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | view) as root:
                n = winreg.QueryInfoKey(root)[0]
                for i in range(n):
                    try:
                        name = winreg.EnumKey(root, i)
                        with winreg.OpenKey(root, name) as k:
                            disp = str(winreg.QueryValueEx(k, "DisplayName")[0]).strip()
                            if not disp:
                                continue
                            try:
                                ver = str(winreg.QueryValueEx(k, "DisplayVersion")[0])
                            except FileNotFoundError:
                                ver = ""
                            found[disp] = ver
                    except OSError:
                        continue
        except OSError:
            continue

    q = (query or "").strip().lower()
    if q:
        hits = {d: v for d, v in found.items() if q in d.lower()}
        if not hits:
            return f"I can't find anything installed matching {query}, Boss."
        first = sorted(hits)[:4]
        listed = ", ".join(f"{d}{f' {hits[d]}' if hits[d] else ''}" for d in first)
        more = len(hits) - len(first)
        return (f"Yes — {listed}" + (f", and {more} more" if more > 0 else "") + ".")
    return (f"{len(found)} programs are installed. Ask me about one by name "
            f"and I'll tell you the version.")


def window_on_top(name: str, on: bool = True) -> str:
    """Pin a window above the others, or unpin it.

    Matched the same way window_skill matches, so "keep spotify on top" finds
    the same window "focus spotify" would -- two different answers to the same
    words would be worse than not having the feature.
    """
    if not (name or "").strip():
        return "Which window?"
    try:
        import pygetwindow as gw
        wins = [w for w in gw.getAllWindows()
                if w.title and name.lower() in w.title.lower()]
    except Exception as e:
        return f"I couldn't look at the windows ({type(e).__name__})."
    if not wins:
        return f"I can't find a window matching {name}."
    win = max(wins, key=lambda w: (w.width or 0) * (w.height or 0))
    HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOACTIVATE = 0x0002, 0x0001, 0x0010
    try:
        ctypes.windll.user32.SetWindowPos(
            win._hWnd, HWND_TOPMOST if on else HWND_NOTOPMOST,
            0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
    except Exception as e:
        return f"That didn't work ({type(e).__name__})."
    return (f"{win.title[:48]} is pinned on top." if on
            else f"{win.title[:48]} is back to normal.")


# ── stopping processes ───────────────────────────────────────────────────────
#
# "Can you stop unused processes on my PC?" -- asked with the CPU at eighty
# percent, and answered with silence, because the router read the leading
# "stop" as "be quiet" (see intent.py's interrupt block). The routing is fixed
# there; this is the capability that makes the fixed routing worth reaching.
#
# ARGUS DOES NOT DECIDE WHAT "UNUSED" MEANS. That is the whole design. Nothing
# on this machine can reliably tell an idle background task from the render
# the owner is waiting on -- "no visible window" is wrong for every worker
# process, "low recent CPU" is wrong for anything that just finished a chunk,
# and being wrong means killing work. So this MEASURES, proposes a named
# shortlist, and stops only what he agrees to. The judgement stays with him;
# what ARGUS contributes is the measurement and the safety rules.
#
# THE SAFETY RULES ARE NOT NEGOTIABLE BY PHRASING:
#   * pid <= 4, System and the Idle process are never touched.
#   * Nothing whose image lives under %SystemRoot% -- those are Windows'
#     services, and stopping one can take the session down with it.
#   * Nothing belonging to ARGUS itself, including this process and its
#     parents, checked through integrity.is_protected().
#   * A hard cap per confirmation, so one "yes" can never clear the process
#     table.
#   * terminate() first, kill() only if it will not go -- terminate lets a
#     program flush and exit, which is the difference between closing an
#     editor and losing what was in it.

STOP_CONFIRM_WINDOW = 90.0      # seconds an offer stays answerable
STOP_MAX_PER_BATCH = 6          # one yes can never clear the process table
STOP_MIN_CPU = 2.0              # below this it is not what is making it hot

_stop_pending = {"targets": [], "at": 0.0, "phrase": ""}


def focused_window() -> dict:
    """What the owner is actually looking at right now.

    THE MISSING HALF OF "CLOSE IT". followup_skill can resolve a pronoun
    against what was last SAID, which covers "open chrome" then "close it".
    It cannot cover the far more common case: the owner is looking at a
    window, says "close it", and has never mentioned the program at all. That
    referent is not in the conversation, it is on the screen.

    Lives here rather than in followup_skill because reading it needs
    ctypes.windll, which the capability scanner counts as a filesystem
    capability -- pc_skill declares it, followup_skill declares nothing, and a
    skill quietly gaining a capability is a boot-aborting violation. Reaching
    for it through this function keeps followup_skill honest.

    Returns {} rather than raising when there is nothing focused, which is a
    real state: the desktop, a lock screen, or a window with no title.
    """
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return {}
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = (buf.value or "").strip()
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    except Exception:
        return {}
    if not title:
        return {}
    name, exe = "", ""
    try:
        p = psutil.Process(int(pid.value))
        name = p.name() or ""
        try:
            exe = p.exe() or ""
        except Exception:
            exe = ""
    except Exception:
        pass
    return {"title": title, "process": name, "exe": exe,
            "pid": int(pid.value or 0)}


def whats_focused() -> str:
    """The spoken version. Read-only."""
    w = focused_window()
    if not w:
        return "Nothing's in focus right now — you're on the desktop."
    prog = w.get("process") or ""
    return (f"You're looking at {w['title'][:70]}"
            + (f", which is {prog}." if prog else "."))


def _foreground_pids() -> set:
    """The process behind the window the owner is looking at, plus its parents.

    THE ONE SIGNAL FOR "IN USE" THAT IS ACTUALLY TRUE. Everything else --
    window visibility, recent CPU, process age -- is a guess that is wrong for
    worker processes. What has focus right now is not a guess.

    It matters because the shortlist is ranked by CPU, and the heaviest thing
    on a machine is very often the thing being used: measured here, the top of
    the list was the browser engine and the editor the owner was working in. A
    blind yes to that list would have closed his own session, which is the
    single worst outcome this feature can produce.

    Parents included: an Electron app's busiest process is a child, and
    stopping it takes the visible window down just as effectively.
    """
    out = set()
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return out
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        cur = int(pid.value)
        for _ in range(6):                 # walk up, bounded
            if not cur or cur in out:
                break
            out.add(cur)
            try:
                cur = psutil.Process(cur).ppid()
            except Exception:
                break
    except Exception:
        pass
    return out


def _protected_process(proc, exe: str, foreground: set = None) -> str:
    """Why this process must not be stopped, or "" if it may be."""
    if foreground:
        try:
            if proc.pid in foreground:
                return "the program you're using right now"
        except Exception:
            pass
    try:
        pid = proc.pid
    except Exception:
        return "unreadable"
    if pid <= 4:
        return "a system process"
    name = ""
    try:
        name = (proc.name() or "").lower()
    except Exception:
        pass
    if name in ("system", "system idle process", "registry", "memory compression"):
        return "a system process"
    if not exe:
        # No image path usually means a protected or another user's process.
        # Refusing is the safe reading: an unattributable process is exactly
        # the one where a wrong guess is least recoverable.
        return "something I can't identify well enough to stop safely"
    low = exe.lower()
    root = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
    if low.startswith(root + os.sep):
        return "part of Windows itself"
    try:
        import integrity
        if integrity.is_protected(exe):
            return "part of me"
    except Exception:
        return "unverifiable while my integrity check is unavailable"
    # This interpreter and everything above it in the tree.
    try:
        if pid == os.getpid() or pid == os.getppid():
            return "part of me"
    except Exception:
        pass
    return ""


def stoppable(limit: int = 8) -> list:
    """The heaviest processes this user could safely stop, worst first.

    CPU is sampled over a real interval. psutil's cpu_percent() with no
    interval returns the average since the process object was created, which
    for a freshly-built list is 0.0 for everything -- a shortlist ranked by
    zero is a shortlist in arbitrary order.
    """
    procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            p.cpu_percent(None)             # prime the counter
            procs.append(p)
        except Exception:
            continue
    time.sleep(0.35)

    foreground = _foreground_pids()
    rows = []
    for p in procs:
        try:
            cpu = p.cpu_percent(None)
            try:
                exe = p.exe() or ""
            except Exception:
                exe = ""
            why_not = _protected_process(p, exe, foreground)
            if why_not:
                continue
            rows.append({
                "pid": p.pid,
                "name": p.name(),
                "exe": exe,
                "cpu": round(cpu, 1),
                "mb": round(p.memory_info().rss / (1024 * 1024), 1),
            })
        except Exception:
            continue
    rows.sort(key=lambda r: (-r["cpu"], -r["mb"]))
    return rows[:limit]


def has_pending_stop() -> bool:
    return (bool(_stop_pending["targets"])
            and time.time() - _stop_pending["at"] <= STOP_CONFIRM_WINDOW)


def cancel_stop() -> str:
    had = has_pending_stop()
    _stop_pending.update(targets=[], at=0.0, phrase="")
    return "Left them running." if had else "There was nothing waiting."


def stage_stop(query: str = "") -> str:
    """Measure, propose, and ASK. Stops nothing.

    A NAMED program is matched by name; anything else is treated as "what is
    making this machine hot", which is the question actually being asked when
    somebody says "stop the unused processes".
    """
    raw = (query or "").strip().lower()
    # Strip the generic vocabulary so "stop unused processes on my pc" reduces
    # to nothing (meaning "whatever is busy") while "stop chrome" keeps
    # "chrome". Word-boundary only, so it cannot eat part of a name.
    q = re.sub(r"\b(the|my|all|any|some|unused|unnecessary|useless|idle|"
               r"background|extra|other|running|processes?|tasks?|programs?|"
               r"apps?|applications?|services?|on|pc|computer|machine|laptop)\b",
               " ", raw)
    q = re.sub(r"\s+", " ", q).strip()

    try:
        rows = stoppable(limit=12)
    except Exception as e:
        return f"I couldn't read the process list ({type(e).__name__})."

    if q:
        # THE RAW PHRASE IS TRIED FIRST. Scrubbing is right for a generic
        # request and wrong for a name: "my-render-program-v2" contains the
        # word "program", so the scrubber cut a hole in the middle of it and
        # ARGUS reported that "my-render- -v2" was not running. Matching the
        # untouched phrase first means a real name is never damaged by
        # vocabulary meant for a different kind of sentence.
        wanted = [r for r in rows if raw and raw in r["name"].lower()]
        if not wanted:
            wanted = [r for r in rows if q in r["name"].lower()]
        if not wanted:
            # It may be running but protected -- say which, rather than
            # "not found", which would be false and unhelpful.
            fg = _foreground_pids()
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    nm = (p.info.get("name") or "").lower()
                    if (raw and raw in nm) or (q and q in nm):
                        try:
                            exe = p.exe() or ""
                        except Exception:
                            exe = ""
                        why = _protected_process(p, exe, fg)
                        if why:
                            return (f"{p.info['name']} is {why}, so I won't "
                                    f"stop it.")
                except Exception:
                    continue
            # Quote what he SAID, not the scrubbed form. "Nothing called
            # 'definitely-not- -xyz' is running" reads like ARGUS is broken,
            # because it is repeating back a string he never uttered.
            return f"Nothing called {raw or q} is running, Boss."
        targets = wanted[:STOP_MAX_PER_BATCH]
    else:
        busy = [r for r in rows if r["cpu"] >= STOP_MIN_CPU]
        if not busy:
            top = rows[0] if rows else None
            if not top:
                return ("Nothing is using enough CPU to be worth stopping, and "
                        "everything else is either Windows or mine.")
            return (f"Nothing is actually busy right now — the heaviest thing "
                    f"I can safely stop is {top['name']} at {top['cpu']} "
                    f"percent. Name a program and I'll stop that one.")
        targets = busy[:STOP_MAX_PER_BATCH]

    _stop_pending.update(targets=targets, at=time.time(), phrase=query or "")

    listed = ", ".join(f"{t['name']} at {t['cpu']} percent" for t in targets[:4])
    more = len(targets) - min(4, len(targets))
    return (f"I can stop {len(targets)} thing{'s' if len(targets) != 1 else ''}: "
            f"{listed}{f', and {more} more' if more else ''}. "
            f"They'll be asked to close first, so anything unsaved gets a "
            f"chance. Want me to?")


def confirm_stop() -> str:
    """Carry out the staged stop. The only function here that kills anything."""
    if not has_pending_stop():
        _stop_pending.update(targets=[], at=0.0, phrase="")
        return ("That offer expired — ask me again and I'll take a fresh "
                "reading.")
    targets = list(_stop_pending["targets"])
    _stop_pending.update(targets=[], at=0.0, phrase="")

    stopped, refused, gone = [], [], []
    # Re-read the foreground: up to ninety seconds have passed since the offer,
    # and he may well have clicked into one of the things on the list while
    # deciding.
    foreground = _foreground_pids()
    for t in targets[:STOP_MAX_PER_BATCH]:
        try:
            p = psutil.Process(t["pid"])
            # RE-VERIFY. Windows reuses pids, and the offer is up to ninety
            # seconds old -- by now that number could be the owner's editor.
            if (p.name() or "").lower() != (t["name"] or "").lower():
                refused.append(f"{t['name']} (that process id is something "
                               f"else now)")
                continue
            try:
                exe = p.exe() or ""
            except Exception:
                exe = ""
            why = _protected_process(p, exe, foreground)
            if why:
                refused.append(f"{t['name']} ({why})")
                continue
            p.terminate()
            try:
                p.wait(timeout=4)
            except Exception:
                p.kill()
            stopped.append(t["name"])
        except psutil.NoSuchProcess:
            gone.append(t["name"])
        except psutil.AccessDenied:
            refused.append(f"{t['name']} (Windows wouldn't let me)")
        except Exception as e:
            refused.append(f"{t['name']} ({type(e).__name__})")

    try:
        import security
        security.audit("process_stop",
                       f"stopped={len(stopped)} refused={len(refused)}",
                       "ok" if stopped else "none")
    except Exception:
        pass

    bits = []
    if stopped:
        bits.append(f"Stopped {', '.join(stopped[:4])}"
                    + (f" and {len(stopped) - 4} more" if len(stopped) > 4 else ""))
    if gone:
        bits.append(f"{', '.join(gone[:2])} had already exited")
    if refused:
        bits.append(f"I left {refused[0]}")
    if not bits:
        return "Nothing was stopped."
    out = ". ".join(b[0].upper() + b[1:] for b in bits) + "."
    if stopped:
        out += " Give it a few seconds and ask me how the CPU looks."
    return out


# ── the clock, and which clock ───────────────────────────────────────────────
#
# ARGUS read the machine's local time and had no opinion about it, which is
# right until it isn't: a laptop that travels, a machine whose Windows timezone
# was never corrected, or an owner who thinks in a timezone other than the one
# the OS is set to. Asked for as "argus time is not right, must be
# timezone setup on settings".
#
# THE DEFAULT IS STILL THE MACHINE. With nothing configured this behaves
# exactly as before -- datetime.now(), the OS's own local time -- because on a
# correctly-set machine that IS the right answer and a preference nobody set
# should not be able to make the clock wrong.
#
# Stored in the writable state directory rather than in config.py or
# settings.py: both of those are integrity-CRITICAL and ACL-hardened, so a
# setting the owner is expected to change cannot live in either without turning
# every change into a re-seal. Same reasoning config_secrets.py is excluded
# from the manifest for.
TZ_OVERRIDE_PATH = None         # tests point this at a temp file
_tz_cache = {"stamp": None, "name": ""}


def _tz_path():
    if TZ_OVERRIDE_PATH:
        return TZ_OVERRIDE_PATH
    import paths
    return paths.writable("timezone.json")


def get_timezone() -> str:
    """The configured timezone NAME, or "" for "use the machine's".

    Cached against the file's own (mtime, size) because _context() in brain.py
    reads this on every prompt build -- a stat() per turn is free, a JSON parse
    per turn is not.
    """
    import json
    try:
        st = os.stat(_tz_path())
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        _tz_cache.update(stamp=None, name="")
        return ""
    if _tz_cache["stamp"] == stamp:
        return _tz_cache["name"]
    try:
        with open(_tz_path(), encoding="utf-8") as fh:
            name = str(json.load(fh).get("timezone", "") or "")
    except (OSError, ValueError):
        name = ""
    _tz_cache.update(stamp=stamp, name=name)
    return name


def resolve_timezone(name: str):
    """A tzinfo for NAME, or None. Never raises.

    zoneinfo is stdlib from 3.9 and reads the OS's own tz database on Windows
    via tzdata, which is already a dependency of nothing here -- so a missing
    database is a real possibility and is handled by returning None, which
    falls back to machine local time rather than to an exception on the clock.
    """
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return None


def now() -> datetime:
    """The time ARGUS should answer with. One definition, used everywhere."""
    tz = resolve_timezone(get_timezone())
    return datetime.now(tz) if tz else datetime.now()


def set_timezone(name: str) -> str:
    """Set or clear the timezone. Validated BEFORE it is written.

    Writing an unresolvable name would leave a preference that silently does
    nothing on every later read -- the clock would go on being wrong and the
    setting would claim to be set, which is the worst of both.
    """
    import json

    wanted = (name or "").strip()
    if wanted.lower() in ("", "auto", "automatic", "system", "machine",
                          "default", "local", "reset", "clear"):
        try:
            os.remove(_tz_path())
        except OSError:
            pass
        _tz_cache.update(stamp=None, name="")
        return (f"Back to the machine's own timezone. That's "
                f"{time.strftime('%H:%M')} right now.")

    # Accept the spoken form too: "europe slash tashkent", "europe tashkent".
    candidate = wanted.replace(" slash ", "/").replace(" ", "_")
    if "/" not in candidate and "_" in candidate:
        head, _, tail = candidate.partition("_")
        candidate = f"{head}/{tail}"
    candidate = "/".join(p.strip("_").title() if "/" in candidate else p
                         for p in candidate.split("/"))

    tz = resolve_timezone(candidate)
    if tz is None:
        return (f"I don't recognise {wanted} as a timezone. They look like "
                f"Europe/Berlin or Asia/Tashkent — region slash city.")
    try:
        os.makedirs(os.path.dirname(_tz_path()), exist_ok=True)
        tmp = _tz_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"timezone": candidate}, fh)
        os.replace(tmp, _tz_path())
    except OSError as e:
        return f"I couldn't save that ({type(e).__name__})."
    _tz_cache.update(stamp=None, name="")
    stamp = datetime.now(tz)
    return (f"Timezone set to {candidate}. That makes it "
            f"{stamp.strftime('%I:%M %p').lstrip('0')} for you now.")


def timezone_status() -> dict:
    """What the clock is doing, for the settings panel."""
    name = get_timezone()
    tz = resolve_timezone(name)
    current = datetime.now(tz) if tz else datetime.now()
    return {
        "configured": name,
        "effective": name or (time.tzname[time.daylight and time.localtime().tm_isdst > 0] or "machine local"),
        "following_machine": not name,
        "now": current.strftime("%Y-%m-%d %H:%M:%S"),
        "offset": current.strftime("%z") or time.strftime("%z"),
        "resolved": tz is not None or not name,
    }


def what_time() -> str:
    name = get_timezone()
    tz = resolve_timezone(name)
    n = datetime.now(tz) if tz else datetime.now()
    clock = (n.strftime('%-I:%M %p') if os.name != "nt"
             else n.strftime('%I:%M %p').lstrip('0'))
    # The zone is named ONLY when one was deliberately set AND it actually
    # resolved. Two separate conditions: on a machine following its own clock,
    # "it's 9:15 on Thursday" is the answer and appending a timezone nobody
    # chose is noise on every time question -- but naming a zone whose database
    # could not be loaded is worse than noise, because the clock is then
    # showing machine local time under someone else's city name.
    tail = f" in {name.split('/')[-1].replace('_', ' ')}" if (name and tz) else ""
    return f"It's {clock}{tail} on {n.strftime('%A, %B %d')}."


def last_task() -> str:
    """Describe the most recently finished or stopped task."""
    try:
        from agent.working_memory import recent_tasks
        tasks = recent_tasks(1)
        if not tasks:
            return "I haven't finished a task yet this session."
        t = tasks[0]
        if t.ok:
            return f"The last thing I finished was {t.goal}. {t.outcome}"
        return (f"The last thing I worked on was {t.goal}, but it didn't "
                f"finish cleanly. {t.outcome}")
    except Exception:
        return "I'm not sure what I did last."
