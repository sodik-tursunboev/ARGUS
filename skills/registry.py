'ARGUS - Capability registry (Skill Discovery / Command Registry).'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

# Map of skill -> description. `since` is the ARGUS version the skill was
# first introduced in (skill versioning). `read_only` says whether the skill
# can only report, never act.
SKILLS = {
    "apps": {
        "description": "open, close and list applications",
        "since": "1.0.0",
        "read_only": False,
        "actions": {
            "open": "open an app by name", "close": "close an app by name",
            "list": "list running apps",
        },
    },
    "window": {
        "description": "pull windows into view, arrange them, and report them",
        "since": "1.0.0",
        "read_only": False,
        "actions": {
            "focus": "focus a window", "minimize": "minimize a window",
            "maximize": "maximize a window", "minimize_all": "minimize everything",
            "list": "list open windows",
        },
    },
    "timer": {
        "description": "set and manage timers and reminders",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"set": "set a timer", "list": "list timers", "cancel": "cancel a timer"},
    },
    "privacy": {
        "description": "pause or resume listening, or report its state",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"on": "resume listening", "off": "pause listening", "status": "listening state"},
    },
    "privacy_watch": {
        "description": "report which apps have recently used your camera and microphone",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"usage": "report recent camera and microphone use"},
    },
    "cleanup": {
        "description": "measure and empty temp and cache directories",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"scan": "measure reclaimable temp space", "run": "run a pending cleanup",
                    "cancel": "cancel a pending cleanup"},
    },
    "face": {
        "description": "enrol and check your face as an authentication factor",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"enroll": "enroll a face", "forget": "forget the enrolled face",
                    "check": "check the enrolled face", "watch": "watch for your face",
                    "unwatch": "stop watching for your face"},
    },
    "intel": {
        "description": "give a curated brief from public sources",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"brief": "give an intel brief", "clear": "clear the intel session"},
    },
    "briefing": {
        "description": "report this machine's session history and detections",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"brief": "give the wake briefing"},
    },
    "phone": {
        "description": "check or trigger calls on a connected phone",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"call": "place a phone call", "status": "report the phone's status"},
    },
    # "telegram" is intentionally NOT here: the module lives in disabled/ and
    # the router does not dispatch it, so listing it would claim a capability
    # ARGUS no longer has. Auth LEVELS still name it for a pair that is now
    # unreachable -- dead but harmless.
    "proactive": {
        "description": "control whether ARGUS may volunteer remarks",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"on": "allow unprompted remarks", "off": "stop unprompted remarks"},
    },
    "diag": {
        "description": "run full system health and security diagnostics",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"full": "full health check", "ports": "what accepts incoming connections",
                    "defenses": "whether the machine's protections are on",
                    "changes": "what changed on this machine recently",
                    "process": "profile one running program",
                    "fixes": "what is safely repairable right now"},
    },
    "remedy": {
        "description": "apply a vetted repair that ARGUS proposed",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"offer": "offer the pending repair", "apply": "apply it (L2)",
                    "cancel": "cancel a staged repair"},
    },
    "security": {
        "description": "security posture, live security state, kill switch and recovery",
        "since": "1.4.2",
        "read_only": True,
        "actions": {"summary": "security posture summary",
                    "state": "the live security state machine reading",
                    "killall": "the owner's emergency stop -- revokes every "
                               "outstanding approval and drops staged work",
                    "recover": "owner recovery: verify the installation and "
                               "return to normal (needs Windows Hello)"},
    },
    "anomaly": {
        "description": "report whether running processes look unusual",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"check": "check for process anomalies"},
    },
    "vault": {
        "description": "store, read and search your private notes",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"write": "save a note", "read": "read a note", "search": "search your notes"},
    },
    "audit": {
        "description": "report what ARGUS itself has recently done",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"read": "read ARGUS's activity log"},
    },
    "vision": {
        "description": "look at the screen and answer about what's there",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"describe": "describe what is on screen",
                    "read_text": "OCR the whole screen",
                    "locate_text": "find where a phrase is on screen",
                    "verify_text": "say whether a phrase is on screen",
                    "cursor_location": "where the cursor is",
                    "click_text": "click visible text (staged)",
                    "drag_text": "drag visible text (staged)",
                    "visual_confirm": "confirm a staged visual click",
                    "visual_cancel": "cancel a staged visual click"},
    },
    "power": {
        "description": "shut down, restart, sleep or sign out (PIN-confirmed)",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"request": "stage a power action", "confirm": "confirm it with the PIN",
                    "cancel": "cancel a staged power action"},
    },
    "calc": {
        "description": "calculate arithmetic, percentages and unit conversions",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"calculate": "do arithmetic", "convert": "convert units"},
    },
    "knowledge": {
        "description": "look up facts, definitions, spellings and translations",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"lookup": "look up a fact", "define": "define a word", "spell": "spell a word",
                    "translate": "translate text", "summarize_clipboard": "summarize the clipboard"},
    },
    "research": {
        "description": "research the web for current information",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"quick": "quick web search", "deep": "deep web research"},
    },
    "chat": {
        "description": "answer general questions conversationally",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"reply": "have a conversation"},
    },
    "auth": {
        "description": "lock, unlock and report authentication state",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"lock": "lock ARGUS", "unlock": "unlock ARGUS", "status": "auth state"},
    },
    "youtube": {
        "description": "play something on YouTube",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"play": "play a video"},
    },
    "web": {
        "description": "open a URL in the browser",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"open_url": "open a URL"},
    },
    "social": {
        "description": "answer pleasantries and questions about ARGUS",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"hello": "greet", "thanks": "answer thanks", "goodbye": "say goodbye",
                    "joke": "tell a joke", "who_are_you": "say who ARGUS is",
                    "who_built_you": "say who built ARGUS", "about_creator": "about the creator",
                    "what_can_you_do": "list capabilities", "compliment": "answer a compliment",
                    "are_you_there": "check presence", "sorry": "answer an apology",
                    "how_are_you": "answer how ARGUS is"},
    },
    "files": {
        "description": "find, open, move, rename and manage files and folders",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"find": "find files", "open": "open a file", "move": "move files",
                    "copy": "copy files", "rename": "rename files", "mkdir": "make a folder",
                    "compress": "compress files", "extract": "extract an archive",
                    "metadata": "file details", "recent": "recent files",
                    "duplicates": "find duplicate files", "delete": "delete files",
                    "confirm_delete": "confirm a staged deletion",
                    "content_search": "find files that mention a phrase",
                    "permissions": "who owns a file and whether you can touch it",
                    "inspect": "a file's origin and signature, from Windows itself",
                    "cancel_delete": "cancel a staged deletion",
                    "has_pending_delete": "whether a deletion is sitting staged",
                    "restore": "restore a file from the Recycle Bin (PIN-confirmed)",
                    "create": "create a text or markdown file (refuses to overwrite)"},
    },
    "pc": {
        "description": "report and control this machine's hardware state",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"stats": "CPU, memory and disk now", "battery": "battery state",
                    "uptime": "how long the machine has been up",
                    "snapshot": "take a state snapshot", "lock": "lock the machine",
                    "time": "the time", "last_task": "the last finished task",
                    "media": "media keys", "dictate": "type into the focused window",
                    "screen_record": "record the screen", "camera_status": "camera state",
                    "power_plan": "power plan", "focused": "the focused window",
                    "heavy": "what is using the CPU", "sysinfo": "system information",
                    "display": "display info", "installed": "installed programs",
                    # UI automation over the Windows UIA tree (pc_skill.py).
                    # The router dispatches these already; registering them here
                    # makes them a first-class, speakable surface.
                    "ui_tree": "describe a window's controls", "ui_read": "read a control's text",
                    "ui_click": "click a control", "ui_type": "type into a control",
                    "ui_select": "select a control or list item", "ui_toggle": "toggle a checkbox or switch",
                    "ui_table": "read a table", "ui_verify": "check a control shows the right text",
                    "ui_screenshot": "capture a window's UI",
                    "ui_double_click": "double-click a control", "ui_right_click": "right-click a control",
                    "ui_hover": "hover over a control", "ui_drag": "drag a control",
                    "ui_scroll": "scroll a control", "ui_set_slider": "set a slider value",
                    "ui_expand": "expand a tree or combo", "ui_dialog": "handle a dialog",
                    "ui_wait": "wait for a control to appear"},
    },
    "storage": {
        "description": "report how much space is free and what is using it",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"free": "free space per drive", "largest": "what is using space",
                    "analyze": "break a folder down by what is filling it"},
    },
    "control": {
        "description": "control volume, brightness, clipboard and microphone",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"volume_set": "set volume", "volume_up": "raise volume",
                    "volume_down": "lower volume", "mute": "mute", "unmute": "unmute",
                    "brightness_set": "set brightness", "clipboard_read": "read the clipboard",
                    "clipboard_write": "write the clipboard", "mic_mute": "mute the mic",
                    "mic_unmute": "unmute the mic", "mic_status": "mic state"},
    },
    "net": {
        "description": "report connectivity, network and bandwidth",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"online": "is the internet up", "wifi": "current wi-fi",
                    "ip": "local IP", "data": "bandwidth used", "connections": "open connections",
                    "wifi_on": "turn wi-fi on", "wifi_off": "turn wi-fi off"},
    },
    "weather": {
        "description": "report the current weather",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"get": "current weather for a city"},
    },
    "email": {
        "description": "search, read and send email (sending is PIN-confirmed)",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"search": "search mail", "read": "read mail", "attachments": "list attachments",
                    "contacts": "find a contact", "send": "send mail (staged)",
                    "reply": "reply to mail (staged)", "forward": "forward mail (staged)",
                    "confirm": "confirm a staged send", "cancel": "cancel a staged send"},
    },
    "sysext": {
        "description": "report printers, devices, network drives and DNS",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"printers": "list printers", "print_queue": "print queue",
                    "devices": "connected devices", "network_drives": "network drives",
                    "dns": "resolve a hostname", "port": "test a host:port",
                    "ping": "ping a host", "bluetooth_status": "bluetooth state",
                    "bluetooth_on": "bluetooth on", "bluetooth_off": "bluetooth off"},
    },
    "dev": {
        "description": "report ARGUS's own git status",
        "since": "1.0.0",
        "read_only": True,
        "actions": {"status": "git status", "log": "recent commits", "diff": "working tree diff",
                    "branch": "current branch"},
    },
    "browser": {
        "description": "drive a separate managed browser for multi-step site tasks",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"navigate": "go to a URL", "search": "search the web",
                    "tab_open": "open a tab", "tab_close": "close a tab",
                    "tab_switch": "switch tabs", "tab_search": "find a tab",
                    "list_tabs": "list open tabs", "back": "go back", "forward": "go forward",
                    "refresh": "reload", "launch": "start the browser", "close": "close it",
                    "extract_text": "read page text", "find_elements": "list clickable items",
                    "click": "click visible text", "follow_link": "follow a link",
                    "fill": "fill a form field", "screenshot": "capture a page",
                    "zoom": "set zoom", "downloads": "list downloads",
                    "bookmarks_list": "list bookmarks", "bookmark_add": "bookmark this page",
                    "bookmark_remove": "remove a bookmark", "history_search": "search history",
                    "submit": "submit a form (staged)", "download": "download (staged)",
                    "upload": "upload (staged)", "confirm": "confirm a staged action",
                    "cancel": "cancel a staged action",
                    "task": "run a multi-step website task (plan with browser writes)"},
    },
    "document": {
        "description": "read, summarise and manipulate PDF, Word and text files",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"read": "read a document", "summarize": "summarise a document",
                    "search": "find a phrase in a document", "info": "document details",
                    "merge": "merge documents", "split": "split a document by page",
                    "create": "create a text document document"},
    },
    "schedule": {
        "description": "schedule background read-only checks",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"once": "run once later", "every": "recur on an interval",
                    "list": "list scheduled checks", "status": "scheduler state",
                    "cancel": "cancel a check", "pause": "pause a check",
                    "resume": "resume a check", "results": "read a check's results"},
    },
    "profile": {
        "description": "remember facts about the user and report them",
        "since": "1.0.0",
        "read_only": False,
        "actions": {"remember": "remember a fact", "summary": "recall what is known",
                    "forget": "forget a fact"},
    },
    "personalize": {
        "description": "structured local preferences, aliases and learned workflows",
        "since": "7.0.0",
        "read_only": False,
        "actions": {
            "set_preference": "set a known behavioral preference",
            "set_alias": "map a word to an app or resource",
            "forget": "remove a preference or alias",
            "confirm_workflow": "approve the last suggested workflow",
            "reject_workflow": "decline the last suggested workflow",
            "run_workflow": "run a saved workflow's steps",
            "delete_workflow": "remove a saved workflow",
            "summary": "recall what preferences/aliases/workflows are known",
            "explain": "explain why a preference or alias is what it is",
        },
    },
    "context": {
        "description": "say what is in front of the user: the app, window, file and selection",
        "since": "1.1.0",
        "read_only": True,
        "actions": {"current": "what the user is looking at",
                    "selection": "what is selected right now",
                    "file": "the file ARGUS most recently found"},
    },
    "health": {
        "description": "report a rolling health picture of CPU, memory and disk",
        "since": "1.1.0",
        "read_only": True,
        "actions": {"check": "health check now", "report": "how the machine has been"},
    },
    "system": {
        "description": "query runtime configuration, feature flags and ARGUS's own telemetry",
        "since": "1.1.0",
        "read_only": False,
        "actions": {"stats": "ARGUS usage and latency stats", "flags": "list feature flags",
                    "flag": "read one feature flag", "settings": "list current settings",
                    "set_flag": "set a feature flag"},
    },
    "monitor": {
        "description": "watch a condition until it is true, then report",
        "since": "1.1.0",
        "read_only": False,
        "actions": {"set": "start watching a condition", "list": "list monitors",
                    "status": "monitor state", "cancel": "stop a monitor",
                    "results": "read a monitor's results"},
    },

    # monitor, not a widening of it: monitor still never acts, watched still
    # never RUNS anything -- firing stages an already-validated plan for the
    # owner's go ahead. See watched_skill.py's module docstring for the full

    # is meant to satisfy without loosening monitor's.
    "watched": {
        "description": "watch a condition, then stage an owner-approved plan for it",
        "since": "1.3.0",
        "read_only": False,
        "actions": {"set": "watch a condition with a task attached",
                    "list": "list watched tasks",
                    "status": "watched-task state",
                    "cancel": "stop a watched task",
                    "results": "read a watched task's results"},
    },

    # EVENT: the schedule re-stages the stored plan each run, the owner's
    # go ahead still runs it. Expiry, run ceiling and budget ledger all
    # carry over from the scheduler/watched discipline.
    "goals": {
        "description": "repeat a task on a schedule; each run stages the plan and waits for you",
        "since": "1.4.2",
        "read_only": False,
        "actions": {"create": "start a persistent goal (schedule + task)",
                    "list": "list persistent goals",
                    "status": "persistent-goal state",
                    "cancel": "stop a persistent goal",
                    "results": "read a goal's prepared results"},
    },
    # -- 1.1.0: sections 11, 13, 14, 15 of the skill vision ---------------
    "service": {
        "description": "view and manage Windows services",
        "since": "1.1.0",
        "read_only": False,
        "actions": {"list": "list services with their state",
                    "status": "one service's state",
                    "start": "start a service (PIN-confirmed)",
                    "stop": "stop a service (PIN-confirmed)",
                    "restart": "restart a service (PIN-confirmed)",
                    "cancel": "cancel a staged service action"},
    },
    "env_var": {
        "description": "read and set your user environment variables",
        "since": "1.1.0",
        "read_only": False,
        "actions": {"list": "list your environment variables",
                    "get": "one variable's value",
                    "set": "set a variable (PIN-confirmed)",
                    "cancel": "cancel a staged set"},
    },
    "security_log": {
        "description": "read recent Windows event logs (security, application, system)",
        "since": "1.1.0",
        "read_only": True,
        "actions": {"read": "recent event log entries",
                    "status": "which logs exist and their size"},
    },
    # zt: the zero-trust session layer and its TPM hardware factor. Mostly a
    # reporting surface over zt.py/hwkey.py; on/off and the hw enrolment
    # actions are L2-gated writes (see auth.py LEVELS).
    "zt": {
        "description": "report and control the zero-trust session layer and the TPM hardware factor",
        "since": "1.2.0",
        "read_only": False,
        "actions": {"status": "session trust score, band and signals",
                    "describe": "the same, as one sentence",
                    "on": "enable zero-trust scoring (fresh auth)",
                    "off": "disable zero-trust scoring (fresh auth)",
                    "enroll_hw": "enrol the TPM hardware factor (fresh auth)",
                    "forget_hw": "remove the hardware enrolment (fresh auth)",
                    "check_hw": "test the TPM factor now",
                    "hw_status": "report the hardware factor"},
    },
    # history: the /clear-memory surface (see auth.py LEVELS/KNOWN_ACTIONS).
    # "clear" permanently discards the persisted conversation. It is reached
    # from the HUD's /clear-memory button, NOT by voice -- the router's branch
    # for this skill refuses rather than pretending to have cleared anything,
    # and this entry exists so the registry walks the pair in both directions.
    "history": {
        "description": "discard the persisted conversation",
        "since": "1.1.0",
        "read_only": False,
        "actions": {"clear": "discard the conversation history"},
    },
}

# Number of times we may refer a caller to these before it becomes noise.
_DESCRIBE_FALLBACK = "I'll check my registry."


def describe(skill: str) -> str:
    """A spoken one-line description of a skill, or a refusal."""
    entry = SKILLS.get((skill or "").strip())
    if not entry:
        return ""
    return f"{entry['description']}"


def all_capabilities() -> list:
    """Ordered "I can <...>" lines for social_skill / 'what can you do'."""
    out = []
    for name in sorted(SKILLS):
        entry = SKILLS[name]
        if entry["actions"]:
            verbs = "/".join(sorted(entry["actions"]))
            out.append(f"{entry['description']} ({name}: {verbs})")
    return out


def router_help() -> str:
    """List registered skill actions for consistency checks."""
    lines = []
    for name in sorted(SKILLS):
        actions = sorted(SKILLS[name]["actions"])
        lines.append(f'{name} [{",".join(actions)}]')
    return "\n".join(lines)


def command(query: str) -> str:
    """Command Registry lookup: 'how do I X' / 'can you X' answered from the
    registry itself rather than from the model's memory of itself."""
    q = (query or "").strip().lower()
    if not q:
        return ""
    for name in sorted(SKILLS):
        entry = SKILLS[name]
        hay = f"{name} {entry['description']} {' '.join(entry['actions'])}"
        if q in hay.lower():
            return (f"That's the {name} skill: {entry['description']}. "
                    f"e.g. {name}/{next(iter(entry['actions']))}.")
    return ""


def is_read_only(skill: str) -> bool:
    entry = SKILLS.get((skill or "").strip())
    return bool(entry and entry.get("read_only"))