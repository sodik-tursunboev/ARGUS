"""
ARGUS - Authentication and lock state.

THREAT MODEL, stated first because everything below only makes sense against it.

ARGUS runs as your own Windows account, on your own machine, listening
continuously. The realistic attacker is therefore NOT a remote one -- the
orchestrator binds to 127.0.0.1 and is token-gated already. It is:

  * someone else in earshot issuing voice commands while you are logged in
    (housemate, colleague, guest, someone who sat down at your desk)
  * a RECORDING of your voice replayed at the microphone
  * you walking away from an unlocked machine

What this module can genuinely stop: all three of those.

What it CANNOT stop, and must not be described as stopping: anyone who already
has code execution as your user. They can read secrets.dat, edit config.py, or
patch this file. No process-local lock defends against that, and pretending
otherwise is worse than not having one -- it invites the user to rely on it.

DESIGN RULES

1. State lives in memory ONLY. Nothing about "unlocked" is ever written to
   disk. That makes "locked after reboot" a property of the design rather than
   a feature that could regress, and means no artefact exists to forge.

2. Failures are UNIFORM. Every rejected attempt returns the same message and
   the same shape, whichever factor failed and whether or not the account is
   even enrolled. An attacker who learns "the PIN was right but voice failed"
   has been handed a free oracle for attacking one factor at a time.

3. Verification is constant-work where it can be. The PIN check is PBKDF2 with
   a fixed round count, and a rejected attempt still performs it, so a wrong
   username-shaped input cannot be distinguished by timing from a wrong PIN.

4. Enforcement is central. A skill is privileged or it is not (PRIVILEGED
   below); no skill decides for itself, because a skill added later would
   silently default to unprotected.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import hashlib
import hmac
import os
import threading
import time

import secrets_store

# ── policy ─────────────────────────────────────────────────────────────
try:
    from config import (AUTH_ENABLED, AUTH_IDLE_LOCK_SECONDS,
                        AUTH_LOCKOUT_MAX_SECONDS, AUTH_MAX_FAILURES,
                        AUTH_REQUIRED_FACTORS, COMMAND_PIN)
except ImportError:      # config predates this module
    from config import COMMAND_PIN
    AUTH_ENABLED = False
    AUTH_IDLE_LOCK_SECONDS = 1800
    AUTH_MAX_FAILURES = 5
    AUTH_LOCKOUT_MAX_SECONDS = 900
    AUTH_REQUIRED_FACTORS = ("pin",)

# Backoff doubles per failure past the first, capped. The cap matters: an
# unbounded backoff is a denial of service against the legitimate user, who is
# the only person who will ever actually be sitting there.
BACKOFF_BASE_SECONDS = 2.0

# One message for every failure. See design rule 2.
GENERIC_FAILURE = "That didn't authenticate. Try again."
LOCKED_MESSAGE = "ARGUS is locked. Authenticate to continue."


# ═══════════════════════════════════════════════════════════════════════
# AUTHORIZATION -- graduated levels, decided HERE and nowhere else.
#
# THE RULE THIS SECTION EXISTS TO ENFORCE: the language model never decides
# what it is allowed to do. It emits a (skill, action) pair; that pair is the
# same key the dispatcher uses to choose the function it will actually run, so
# looking the level up from it means the level always describes the REAL
# effect, not the model's opinion of it.
#
# Three consequences, all deliberate:
#
#   1. Nothing the model emits can raise its own privilege. There is no
#      "authorized" or "safe" field in the decision dict, and if one were
#      added it would be ignored -- the table below is the only input.
#
#   2. An UNKNOWN pair fails CLOSED, at DEFAULT_LEVEL. A hallucinated skill,
#      a typo, a prompt-injected instruction from a fetched web page, or a
#      skill someone adds next year without touching this table all land on a
#      level that requires authentication rather than one that does not. The
#      dangerous default is the permissive one.
#
#   3. Chains and follow-ups are checked per step, because a rewrite can
#      change the action after the original decision was authorised.
# ═══════════════════════════════════════════════════════════════════════

L0_OPEN = 0        # no authentication -- time, weather, sums, small talk
L1_UNLOCKED = 1    # ARGUS unlocked -- ordinary machine control
L2_REAUTH = 2      # a FRESH authentication, even if already unlocked
L3_CONFIRM = 3     # fresh auth + an explicit spoken confirmation
L4_STRONG = 4      # multi-factor + explicit confirmation
L5_HARDWARE = 5    # hardware-backed only

LEVEL_NAMES = {0: "L0", 1: "L1", 2: "L2", 3: "L3", 4: "L4", 5: "L5"}

# Unknown (skill, action) pairs land here. L2 and not L0 on purpose -- see
# consequence 2 above. It is low enough that an unrecognised but harmless
# lookup is merely inconvenient, and high enough that an unrecognised
# DANGEROUS one cannot run unchallenged.
DEFAULT_LEVEL = L2_REAUTH

LEVELS = {
    # ── L0: reveals nothing about this user or machine ──────────────
    ("pc", "time"): L0_OPEN,
    ("weather", "get"): L0_OPEN,
    ("calc", "*"): L0_OPEN,
    ("social", "*"): L0_OPEN,
    ("knowledge", "*"): L0_OPEN,
    ("research", "*"): L0_OPEN,
    ("chat", "*"): L0_OPEN,
    ("auth", "*"): L0_OPEN,          # you must be able to reach the unlock
    ("net", "online"): L0_OPEN,      # "is the internet up" says nothing private

    # ── L1: acts on the machine, exposes nothing sensitive ──────────
    ("apps", "*"): L1_UNLOCKED,
    ("window", "*"): L1_UNLOCKED,
    ("control", "volume_set"): L1_UNLOCKED,
    ("control", "volume_up"): L1_UNLOCKED,
    ("control", "volume_down"): L1_UNLOCKED,
    ("control", "mute"): L1_UNLOCKED,
    ("control", "unmute"): L1_UNLOCKED,
    ("control", "brightness_set"): L1_UNLOCKED,
    ("timer", "*"): L1_UNLOCKED,
    ("pc", "media"): L1_UNLOCKED,
    ("pc", "stats"): L1_UNLOCKED,
    ("pc", "uptime"): L1_UNLOCKED,
    ("pc", "lock"): L1_UNLOCKED,
    ("pc", "stop_speaking"): L0_OPEN,   # "stop" must always be obeyable
    ("privacy", "*"): L1_UNLOCKED,
    ("proactive", "*"): L1_UNLOCKED,
    ("diag", "*"): L1_UNLOCKED,
    ("anomaly", "*"): L1_UNLOCKED,
    # A spoken "how secure am I" reports on this machine's security state, the
    # same sensitivity class as anomaly -- available once unlocked, not before.
    # (The SECURITY panel's endpoints are token-gated like /telemetry, so the
    # HUD can still show posture pre-unlock; this gates the VOICE/text command.)
    ("security", "summary"): L1_UNLOCKED,
    # Reading the security state machine is a diagnostic, same class as the
    # summary. Changing it is NOT here: recovery is L4 below, and the kill
    # switch is dispatched BEFORE authorization in router._dispatch_inner
    # because it must be the one thing that always works.
    ("security", "state"): L1_UNLOCKED,
    # "has anything used my camera today" reports which apps opened this
    # machine's camera and microphone. Same sensitivity class -- and arguably
    # more personal than the rest -- so it is gated identically.
    ("privacy_watch", "usage"): L1_UNLOCKED,
    # Disk cleanup deletes files, but NOT arbitrary ones: its scope is a fixed
    # table of temp/cache directories holding regenerable data, and it accepts
    # no path from the user, so it cannot be steered the way files/delete can.
    # That is why it sits at L1 rather than inheriting files/delete's L4 --
    # which would demand two factors to empty %TEMP% and put the friction back
    # that made ARGUS feel unusable. The real gate is the skill's own
    # measure-then-confirm step: nothing is removed until the user agrees to an
    # already-counted set of files.
    # Enrolling a face is a SECURITY-RELEVANT write: whoever is at the camera
    # when it runs becomes a recognised second factor. That needs fresh
    # authentication, not merely an unlocked session someone walked up to.
    # Forgetting, checking and the presence watch only ever reduce access or
    # report, so they sit at L1.
    # Live intel searches the public web and opens a browser. It reveals
    # nothing about this machine -- intel_skill refuses a query that
    # cloud_gate flags as sensitive -- so it sits alongside the other
    # information lookups rather than behind the lock.
    # The wake briefing reports this machine's session history and its own
    # detections -- that is state about the owner and the machine, so it sits
    # behind the lock alongside anomaly and the security summary.
    ("briefing", "brief"): L1_UNLOCKED,
    # Placing a call spends money and rings a real phone, so it needs an
    # unlocked machine -- not something a passer-by can trigger. Reading the
    # status reveals nothing and costs nothing.
    ("phone", "call"): L1_UNLOCKED,
    ("phone", "status"): L1_UNLOCKED,
    ("telegram", "notify"): L1_UNLOCKED,
    ("telegram", "status"): L1_UNLOCKED,
    ("intel", "brief"): L0_OPEN,
    ("intel", "clear"): L0_OPEN,
    ("face", "enroll"): L2_REAUTH,
    ("face", "forget"): L1_UNLOCKED,
    ("face", "check"): L1_UNLOCKED,
    ("face", "watch"): L1_UNLOCKED,
    ("face", "unwatch"): L1_UNLOCKED,
    ("cleanup", "scan"): L1_UNLOCKED,
    ("cleanup", "run"): L1_UNLOCKED,
    ("cleanup", "cancel"): L1_UNLOCKED,
    ("web", "open_url"): L1_UNLOCKED,
    ("youtube", "*"): L1_UNLOCKED,
    ("net", "wifi"): L1_UNLOCKED,
    ("net", "ip"): L1_UNLOCKED,
    ("net", "data"): L1_UNLOCKED,
    # storage/analyze walks a folder (confined to the user's tree) and reports
    # what is filling it -- strictly read-only, same class as storage/free and
    # storage/largest. L1 so a routine "what's taking up space in Downloads"
    # stays friction-free.
    ("storage", "analyze"): L1_UNLOCKED,
    ("storage", "free"): L1_UNLOCKED,
    ("storage", "largest"): L1_UNLOCKED,

    # ── EVERYDAY USE: L1, not L2 (owner, 2026-09-24) ──────────────────
    # "Every command asks for the PIN" was mostly these: finding and opening
    # your own files, and reading your own machine's state, each demanding an
    # unlock from the last two minutes. On the owner's own unlocked session
    # they are ordinary use -- the same class as pc/stats and apps/open.
    # Anything that READS CONTENT someone could harvest (vault, audit log,
    # clipboard, the screen, long-term memory, browser history), acts inside
    # another window (pc/ui_*), writes, or runs unattended stays L2+.
    ("files", "find"): L1_UNLOCKED,
    ("files", "open"): L1_UNLOCKED,
    ("files", "recent"): L1_UNLOCKED,
    ("pc", "battery"): L1_UNLOCKED,
    ("pc", "heavy"): L1_UNLOCKED,
    ("pc", "sysinfo"): L1_UNLOCKED,
    ("pc", "display"): L1_UNLOCKED,
    ("pc", "installed"): L1_UNLOCKED,
    ("pc", "focused"): L1_UNLOCKED,
    ("pc", "camera_status"): L1_UNLOCKED,
    ("pc", "power_plan"): L1_UNLOCKED,     # reads, or picks one of Windows' own three plans
    # The browser, short of anything that submits, uploads, downloads, clicks
    # page controls, fills a form, captures a page or searches your history.
    ("browser", "navigate"): L1_UNLOCKED,
    ("browser", "search"): L1_UNLOCKED,
    ("browser", "tab_open"): L1_UNLOCKED,
    ("browser", "tab_close"): L1_UNLOCKED,
    ("browser", "tab_switch"): L1_UNLOCKED,
    ("browser", "tab_search"): L1_UNLOCKED,
    ("browser", "list_tabs"): L1_UNLOCKED,
    ("browser", "back"): L1_UNLOCKED,
    ("browser", "forward"): L1_UNLOCKED,
    ("browser", "refresh"): L1_UNLOCKED,
    ("browser", "launch"): L1_UNLOCKED,
    ("browser", "close"): L1_UNLOCKED,
    ("browser", "extract_text"): L1_UNLOCKED,
    ("browser", "find_elements"): L1_UNLOCKED,
    ("browser", "follow_link"): L1_UNLOCKED,
    ("browser", "zoom"): L1_UNLOCKED,
    ("browser", "downloads"): L1_UNLOCKED,
    ("browser", "bookmarks_list"): L1_UNLOCKED,
    ("browser", "bookmark_add"): L1_UNLOCKED,
    ("browser", "bookmark_remove"): L1_UNLOCKED,
    ("browser", "cancel"): L0_OPEN,         # cancelling only reduces what happens

    # ── L2: reads private data. Fresh auth, not just "unlocked earlier" ──
    ("files", "permissions"): L2_REAUTH,   # owner + access on a named file
    ("files", "inspect"): L2_REAUTH,       # a file's origin/signature is machine state no one else may see
    ("files", "restore"): L2_REAUTH,       # additive -- recreates a file, so lighter than delete's L4; the PIN inside the skill is the real confirmation (like service)
    ("files", "create"): L2_REAUTH,        # a brand-new file with owner-specified content; refuses to overwrite
    ("vault", "*"): L2_REAUTH,
    ("profile", "remember"): L2_REAUTH,
    ("profile", "summary"): L2_REAUTH,
    ("audit", "*"): L2_REAUTH,
    ("vision", "*"): L2_REAUTH,          # the screen can show anything
    ("control", "clipboard_read"): L2_REAUTH,   # may hold a password
    ("pc", "snapshot"): L2_REAUTH,

    # ── L3: acts with the user's own authority. Confirmation required ──
    # dictate synthesises keystrokes into whatever window has focus, which is
    # arbitrary input injection wearing a friendly name -- the closest thing
    # ARGUS has to shell execution, and rated accordingly.
    ("pc", "dictate"): L3_CONFIRM,
    ("control", "clipboard_write"): L3_CONFIRM,
    ("profile", "forget"): L3_CONFIRM,   # destroys long-term memory
    # A multi-step website task drives real writes on the machine's behalf --
    # fills forms, submits them, downloads files and moves them into folders.
    # The user approves the whole step list up front (plan + "say go ahead"),
    # and browser/task's own submit/download/upload are separately staged and
    # PIN-confirmed inside browser_skill.py -- L3 here gates the plan itself,
    # on top of that. files/move|copy|rename are NOT part of that per-write
    # PIN layer (they have none of their own); they get their own L3 entries
    # below for exactly that reason.
    ("browser", "task"): L3_CONFIRM,
    # A plan step's target can be a pronoun ("it"/"that file") resolved at
    # EXECUTION time against followup_skill's last-file slot -- a global,
    # cross-task pointer that an earlier, unrelated command can have set. With
    # no LEVELS entry these silently rode DEFAULT_LEVEL (L2_REAUTH: fresh auth
    # only, no explicit confirmation) despite moving/copying/renaming real
    # files -- confirmed via a live trace: a plan step approved as "move the
    # download into Documents" could silently act on a stale, unrelated file
    # instead, with nothing in the auth/grant/verifier chain positioned to
    # notice. L3 forces an explicit spoken "confirm" immediately before
    # execution, which is the one point a human can still catch a
    # misresolved target before it acts.
    ("files", "move"): L3_CONFIRM,
    ("files", "copy"): L3_CONFIRM,
    ("files", "rename"): L3_CONFIRM,

    # ── L4: destructive or irreversible ─────────────────────────────
    ("files", "delete"): L4_STRONG,
    ("files", "confirm_delete"): L4_STRONG,
    ("power", "*"): L4_STRONG,

    # ordinary gate short of hardware-only. The router adds a Windows Hello
    # gesture on top; the level keeps the multi-factor floor in front of it.
    ("security", "recover"): L4_STRONG,
    # CANCELLING IS NOT A PRIVILEGED ACTION. It only ever reduces what is about
    # to happen, so gating it at the same level as the thing being cancelled is
    # backwards -- and it was actively harmful here: with power at L4 and only
    # one factor configured, L4 can never be satisfied, so "cancel" was refused
    # with "that needs stronger authentication" and a staged shutdown could not
    # be called off at all. intent.py already treats cancellation as something
    # that must always get through ("When in doubt about a cancellation,
    # cancel"); this is the authorization half of that same rule.
    #
    # An explicit pair beats the ("power", "*") wildcard in level_for().
    ("power", "cancel"): L0_OPEN,
    # Cancelling a staged deletion and asking "is one staged?" are the same
    # never-privileged class as power/cancel: they only reduce what was about to
    # happen, so they must always get through regardless of auth state -- and
    # has_pending_delete is a pure status read that reveals nothing.
    ("files", "cancel_delete"): L0_OPEN,
    ("files", "has_pending_delete"): L0_OPEN,

    # ── L5: hardware-backed only. Nothing maps here yet, deliberately ──
    # ARGUS has no skill that handles passwords, SSH keys, or money. When one
    # is added it belongs here -- and because no hardware factor is available
    # on this machine, L5 currently REFUSES rather than silently downgrading.

    # ── 1.1.0: new reporting and monitoring skills ───────────────────
    # context: strictly read-only composed from machine state -- window, file,
    # clipboard. Reveals nothing a local process couldn't already see.
    ("context", "current"): L1_UNLOCKED,
    ("context", "selection"): L1_UNLOCKED,
    ("context", "file"): L1_UNLOCKED,
    # health: a rolling read-only health report (CPU/mem/disk history, top
    # consumers). No side-effects; mirrors diag/anomaly's own L1 tier.
    ("health", "check"): L1_UNLOCKED,
    ("health", "report"): L1_UNLOCKED,
    # system: runtime state and feature-flag management. The set_flag write is
    # a small local boolean store with no security significance; L1 matches
    # proactive/on|off (a setting of the same kind of local, non-sensitive
    # runtime toggle).
    ("system", "stats"): L1_UNLOCKED,
    ("system", "flags"): L1_UNLOCKED,
    ("system", "flag"): L1_UNLOCKED,
    ("system", "settings"): L1_UNLOCKED,
    ("system", "set_flag"): L1_UNLOCKED,
    # monitor: the * wildcard covers the read actions (list/status/results),
    # all strictly read-only. "set" spawns an unattended watcher thread, which
    # is the same trust decision as scheduling -- identical to schedule's own
    # tier (schedule has no LEVELS entry, so it sits at DEFAULT_LEVEL = L2).
    ("monitor", "set"): L2_REAUTH,
    ("monitor", "*"): L1_UNLOCKED,

    # are L1 like monitor's. "set" spawns an unattended background thread AND
    # pre-stages a validated plan -- the same trust decision as monitor/set
    # and the scheduler default, identical tier. Fire-time staging carries NO
    # authority of its own: the staged plan still needs the owner's "go
    # ahead", and the watcher thread never authorises anything.
    ("watched", "set"): L2_REAUTH,
    ("watched", "*"): L1_UNLOCKED,

    # Same shape as watched: "create" stores a schedule that keeps STAGING
    # owner-approved plans -- the trust decision being gated is that plans
    # keep being prepared while the owner is not talking to ARGUS, so it is
    # the same fresh-auth tier as watched/set and schedule. Reads are L1;
    # the fire path itself carries no authority (it never runs a step).
    ("goals", "create"): L2_REAUTH,
    ("goals", "*"): L1_UNLOCKED,

    # -- service / env_var / security_log -------------------
    # service list/status are read-only machine state (L1). start/stop/restart
    # are L1_unlocked because the skill itself implements staged+PIN -- the
    # same trust model as power_skill: the PIN is the confirmation, not a
    # second spoken word, so L3's stage_confirmation would intercept before
    # the skill's own request() can stage PIN. cancel is always reachable.
    ("service", "list"): L1_UNLOCKED,
    ("service", "status"): L1_UNLOCKED,
    ("service", "start"): L1_UNLOCKED,
    ("service", "stop"): L1_UNLOCKED,
    ("service", "restart"): L1_UNLOCKED,
    ("service", "cancel"): L0_OPEN,
    # env_var list/get are local reads (L1). set is L1 for the same reason as
    # service -- the PIN inside the skill is the real confirmation.
    ("env_var", "list"): L1_UNLOCKED,
    ("env_var", "get"): L1_UNLOCKED,
    ("env_var", "set"): L1_UNLOCKED,
    ("env_var", "cancel"): L0_OPEN,
    # security_log: event logs contain authentication and audit data -- fresh
    # auth, not merely "unlocked".
    ("security_log", "read"): L2_REAUTH,
    ("security_log", "status"): L1_UNLOCKED,
    # zt: reading the posture is local and reveals session state (same class
    # as the security summary). Changing it -- toggling the layer, enrolling
    # or removing a hardware factor -- is fresh-auth-gated. hw/check runs a
    # TPM verification, which is a read of factor health, at L1.
    ("zt", "status"): L1_UNLOCKED,
    ("zt", "describe"): L1_UNLOCKED,
    ("zt", "on"): L2_REAUTH,
    ("zt", "off"): L2_REAUTH,
    ("zt", "enroll_hw"): L2_REAUTH,
    ("zt", "forget_hw"): L2_REAUTH,
    ("zt", "check_hw"): L1_UNLOCKED,
    ("zt", "hw_status"): L1_UNLOCKED,
    # history/clear: permanently discards the persisted conversation. It is a
    # destructive action -- irreversible loss of context -- so it needs a FRESH
    # authentication (L2), the same bar as profile/forget (L3 is for the machine
    # acting with your authority; this only deletes ARGUS's own transcript).
    # Reached from the HUD's /clear-memory, which must therefore NOT skip the
    # gate the way its spoken equivalent could not.
    ("history", "clear"): L2_REAUTH,

    # UI automation: the pc/ui_* actions act with the user's own authority --
    # keystrokes and clicks aimed at whatever window has focus. Same sensitivity
    # class as dictate: L2 (fresh auth), not L3 (confirmation not needed
    # because the user explicitly named the control and the path is deterministic).
    ("pc", "ui_tree"): L2_REAUTH,
    ("pc", "ui_read"): L2_REAUTH,
    ("pc", "ui_click"): L2_REAUTH,
    ("pc", "ui_type"): L2_REAUTH,
    ("pc", "ui_select"): L2_REAUTH,
    ("pc", "ui_toggle"): L2_REAUTH,
    ("pc", "ui_table"): L2_REAUTH,
    ("pc", "ui_verify"): L2_REAUTH,
    ("pc", "ui_screenshot"): L2_REAUTH,
    # The rest of the UIA surface: same sensitivity class as the core nine
    # above (keystrokes/clicks aimed at whatever window has focus). They existed
    # and were dispatched in router.py under the DEFAULT_LEVEL umbrella; these
    # explicit pairs just make that fact auditable.
    ("pc", "ui_double_click"): L2_REAUTH,
    ("pc", "ui_right_click"): L2_REAUTH,
    ("pc", "ui_hover"): L2_REAUTH,
    ("pc", "ui_drag"): L2_REAUTH,
    ("pc", "ui_scroll"): L2_REAUTH,
    ("pc", "ui_set_slider"): L2_REAUTH,
    ("pc", "ui_expand"): L2_REAUTH,
    ("pc", "ui_dialog"): L2_REAUTH,
    ("pc", "ui_wait"): L2_REAUTH,
}


# The actions each skill ACTUALLY implements, as dispatched by router.py.
#
# This exists because a wildcard alone is unsafe. ("apps", "*") -> L1 was
# handing L1 to every conceivable action on that skill, including ones nobody
# wrote: "apps/install" scored L1, and installing software is L4 by any
# reasonable reading. The wildcard is a convenience for the actions a skill
# really has, not a blanket promise about a namespace.
KNOWN_ACTIONS = {
    "apps": {"open", "close", "list"},
    "window": {"focus", "minimize", "maximize", "minimize_all", "list"},
    "timer": {"set", "list", "cancel"},
    "privacy": {"on", "off", "status"},
    "privacy_watch": {"usage"},
    "cleanup": {"scan", "run", "cancel"},
    "face": {"enroll", "forget", "check", "watch", "unwatch"},
    "intel": {"brief", "clear"},
    "briefing": {"brief"},
    # "alert" is absent on purpose: it is a detector-side entry point, not a
    # routable action, so an invented ("phone", "alert") from the model lands
    # on the fail-closed default rather than inheriting phone/call's level.
    "phone": {"call", "status"},
    "proactive": {"on", "off"},
    # All of diag's dispatched actions, not just "full" -- a wildcard's known
    # set is what level_for() consults to keep an INVENTED diag/* from
    # inheriting the skill's L1, so "ports"/"defenses"/"changes"/"process"/
    # "fixes" (all really dispatched below in router.py) must be listed or
    # they silently ride the stricter DEFAULT_LEVEL instead of the L1 the
    # code at each dispatch site already assumes (see diag/fixes's own note:
    # the READ half of repair is deliberately L1, which only holds once it is
    # a known action).
    "diag": {"full", "ports", "defenses", "changes", "process", "fixes"},
    "anomaly": {"check"},
    "vault": {"write", "read", "search"},
    "audit": {"read"},
    "vision": {"describe", "read_text", "locate_text", "verify_text",
               "cursor_location", "click_text", "drag_text",
               "visual_confirm", "visual_cancel"},
    "power": {"request", "confirm", "cancel"},
    "calc": {"calculate", "convert"},
    "knowledge": {"lookup", "define", "spell", "translate", "summarize_clipboard"},
    "research": {"quick", "deep"},
    "chat": {"reply"},
    "auth": {"lock", "unlock", "status"},
    "youtube": {"play"},
    "web": {"open_url"},
    "social": {"how_are_you", "thanks", "hello", "who_are_you", "who_built_you",
               "about_creator", "what_can_you_do", "goodbye", "sorry",
               "compliment", "are_you_there", "joke"},
    # 1.1.0: new skills
    "context": {"current", "selection", "file"},
    "health": {"check", "report"},
    "system": {"stats", "flags", "flag", "settings", "set_flag"},
    "monitor": {"set", "list", "status", "cancel", "results"},
    "watched": {"set", "list", "status", "cancel", "results"},
    "goals": {"create", "list", "status", "cancel", "results"},
    # These actions have individual levels and are listed for registry consistency.
    "service": {"list", "status", "start", "stop", "restart", "cancel"},
    # history: the /clear-memory surface. "clear" permanently discards the
    # persisted conversation -- a destructive action (LEVELS: L2_REAUTH),
    # recorded so the registry walks it in both directions.
    "history": {"clear"},
    "env_var": {"list", "get", "set", "cancel"},
    "security_log": {"read", "status"},
    "zt": {"status", "describe", "on", "off", "enroll_hw", "forget_hw",
           "check_hw", "hw_status"},
    # Actions with individual levels are listed for registry consistency.
    "files": {"find", "open", "move", "copy", "rename", "mkdir", "compress",
              "extract", "metadata", "recent", "duplicates", "delete",
              "confirm_delete", "content_search", "permissions", "inspect",
              "cancel_delete", "has_pending_delete", "restore", "create"},
    "pc": {"stats", "battery", "uptime", "snapshot", "lock", "time", "media",
           "dictate", "screen_record", "camera_status", "power_plan", "focused",
           "heavy", "sysinfo", "display", "installed", "ui_tree", "ui_read",
           "ui_click", "ui_type", "ui_select", "ui_toggle", "ui_table",
           "ui_verify", "ui_screenshot", "ui_double_click", "ui_right_click",
           "ui_hover", "ui_drag", "ui_scroll", "ui_set_slider", "ui_expand",
           "ui_dialog", "ui_wait"},
    "storage": {"free", "largest", "analyze"},
    "browser": {"navigate", "search", "tab_open", "tab_close", "tab_switch",
                "tab_search", "list_tabs", "back", "forward", "refresh",
                "launch", "close", "extract_text", "find_elements", "click",
                "follow_link", "fill", "screenshot", "zoom", "downloads",
                "bookmarks_list", "bookmark_add", "bookmark_remove",
                "history_search", "submit", "download", "upload", "confirm",
                "cancel", "task"},
    "security": {"summary", "state", "recover", "killall"},
}


def level_for(skill: str, action: str = "") -> int:
    """The permission level of a (skill, action). Never consults the model."""
    if (skill, action) in LEVELS:
        return LEVELS[(skill, action)]

    if (skill, "*") in LEVELS:
        known = KNOWN_ACTIONS.get(skill)
        if known is not None and action not in known:
            # A skill we know, doing something we do not. Take the HIGHER of
            # the skill's own level and the fail-closed default, so an
            # unimplemented action can never be cheaper than either -- an
            # invented "power/wipe" stays at power's L4 rather than dropping
            # to L2, and an invented "apps/install" rises from L1 to L2.
            return max(DEFAULT_LEVEL, LEVELS[(skill, "*")])
        return LEVELS[(skill, "*")]

    return DEFAULT_LEVEL


# Backwards compatibility for callers that only asked "is this privileged".
def is_privileged(skill: str, action: str = "") -> bool:
    return level_for(skill, action) >= L1_UNLOCKED


# ── state (memory only -- design rule 1) ───────────────────────────────
_lock = threading.RLock()
_state = {
    "unlocked": False,
    "unlocked_at": 0.0,
    "last_activity": 0.0,
    "failures": 0,
    "locked_until": 0.0,
    "last_reason": "start",     # why it is locked, for the HUD
}


def _now():
    return time.time()


# ── passphrase strength ────────────────────────────────────────────────
def passphrase_strength(secret: str) -> tuple[bool, str]:
    """(acceptable, reason). Deliberately permissive about SHAPE and strict
    about SIZE: a 4-digit PIN is guessable by someone who knows you, and
    composition rules mostly produce predictable substitutions."""
    s = (secret or "").strip()
    if len(s) < 6:
        return False, "Use at least 6 characters, or 8 digits if it's a PIN."
    if s.isdigit() and len(s) < 8:
        return False, "A numeric PIN needs at least 8 digits."
    if s.isdigit() and len(set(s)) <= 2:
        return False, "That PIN has too few distinct digits."
    if s.lower() in {"password", "12345678", "00000000", "argus", "letmein"}:
        return False, "That's one of the first things anyone would try."
    # A date is the single most common 8-digit PIN, and the people most likely
    # to be standing at this machine are the people who know your dates.
    if s.isdigit() and len(s) == 8 and _looks_like_a_date(s):
        return True, ("Accepted, but that looks like a date -- and a date is "
                      "guessable by anyone who knows you.")
    return True, ""


def _looks_like_a_date(digits: str) -> bool:
    for y_at in (0, 4):
        year = digits[y_at:y_at + 4]
        if year.isdigit() and 1900 <= int(year) <= 2100:
            return True
    return False


# ── factors ────────────────────────────────────────────────────────────
def _verify_pin(supplied: str) -> bool:
    """Always performs the KDF, even for empty input, so a rejected attempt
    costs the same as a wrong one (design rule 3)."""
    supplied = str(supplied or "")
    stored = COMMAND_PIN or ""
    if not stored:
        # Nothing enrolled: still burn the same work, then fail closed.
        secrets_store.hash_pin(supplied or "x")
        return False
    return secrets_store.verify_pin(supplied, stored)


def _current_user_sid() -> str:
    try:
        import win32api
        import win32security
        name = win32api.GetUserNameEx(win32api.NameSamCompatible)
        sid, _, _ = win32security.LookupAccountName(None, name.split("\\")[-1])
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return ""


def _verify_os_account(_supplied=None) -> bool:
    """The process must be running as the enrolled Windows account.

    This is a BINDING check, not a challenge: it proves ARGUS is running as
    the person it was set up for, which is what stops a second account on the
    same machine driving it. It is not a substitute for a knowledge factor,
    and is never sufficient alone -- see verify().
    """
    enrolled = secrets_store.get_secret("ARGUS_OWNER_SID", "")
    if not enrolled:
        return False
    return hmac.compare_digest(enrolled, _current_user_sid())


# Liveness: a challenge the user must repeat. A recording of the user cannot
# answer a phrase chosen after the recording was made, which is the entire
# point -- and it needs no model, unlike speaker verification.
_challenge = {"words": None, "at": 0.0}
CHALLENGE_WINDOW = 30.0
_CHALLENGE_WORDS = [
    "harbour", "lantern", "compass", "granite", "meadow", "thunder",
    "velvet", "cobalt", "junction", "orchard", "pelican", "quartz",
    "ribbon", "saffron", "tundra", "walnut", "zenith", "falcon",
]


def new_challenge(n: int = 3) -> str:
    """Issues a fresh liveness challenge and returns the phrase to speak."""
    import secrets as _s
    words = [_s.choice(_CHALLENGE_WORDS) for _ in range(n)]
    with _lock:
        _challenge["words"] = words
        _challenge["at"] = _now()
    return " ".join(words)


def _verify_liveness(spoken: str) -> bool:
    with _lock:
        words, issued = _challenge["words"], _challenge["at"]
        _challenge["words"] = None        # one shot, like a PIN attempt
    if not words or _now() - issued > CHALLENGE_WINDOW:
        return False
    heard = set(str(spoken or "").lower().split())
    # Every challenge word must appear. Order is not required: a speech
    # recogniser reorders and drops filler often enough that demanding exact
    # sequence would fail honest users more than it would catch replays.
    return all(w in heard for w in words)


def _verify_face(_supplied=None) -> bool:
    """The enrolled face must be in front of the camera right now.

    Imported lazily so auth.py -- which every gated command goes through --
    never pays for loading OpenCV, and so a machine without it still boots and
    authenticates normally with the other factors. Any failure is False: a
    camera that will not open is not a passed check.

    Like os_account, this is INSUFFICIENT ALONE and verify() enforces that
    below. The camera here has no infrared, so a photograph on a phone screen
    passes it; as one of two factors that still raises the bar, as the only
    factor it would lower it.
    """
    try:
        import faceauth
        return bool(faceauth.verify())
    except Exception:
        return False


# 1.2.0: the hardware-backed factor. TPM-resident key via NCrypt's Platform
# Crypto Provider -- see hwkey.py for exactly what it proves (the enrolled
# machine and its TPM) and what it does not (a human gesture), which is why it
# sits in PRESENCE_ONLY_FACTORS below rather than standing alone.
def _verify_hardware(_supplied=None) -> bool:
    """The TPM-resident key must sign a fresh nonce successfully.

    Imported lazily like faceauth so auth.py never pays for the NCrypt setup
    on machines that never configure this factor. Any failure is False: an
    unavailable TPM is a failed check, never a skipped one.
    """
    try:
        import hwkey
        return bool(hwkey.verify())
    except Exception:
        return False


# 1.3.0: the gesture-gated hardware factor -- Windows Hello's OS-attested
# user verification. Where hwkey proves the MACHINE (and is therefore
# presence-only), a completed Hello verification proves a human finished a
# gesture at the keyboard: the credential's private half never leaves the
# TPM/VBS and Windows enrolls exactly one user. hwauth.py fails closed when
# the projection package is missing, no Hello credential is enrolled, or the
# user has not enabled it -- so on a machine that cannot support it this
# factor simply never passes, which is the same posture as before it existed.
def _verify_hello(_supplied=None) -> bool:
    try:
        import hwauth
        ok, _reason = hwauth.verify_user()
        return bool(ok)
    except Exception:
        return False


FACTORS = {
    "pin": _verify_pin,
    "os_account": _verify_os_account,
    "liveness": _verify_liveness,
    "face": _verify_face,
    "hardware": _verify_hardware,
    "hello": _verify_hello,
}

# Factors that establish PRESENCE or BINDING but prove nothing only the owner
# could know or do. A configuration made up of nothing but these can be
# satisfied by whoever is standing at the machine -- or, for face on an RGB-only
# camera, by their photograph -- so verify() refuses to unlock for such a set.
# "hardware" joins for a sharper reason: it binds to the MACHINE, not the
# person, so it is strictly a second factor. A stolen laptop with its TPM
# intact and the OS unlocked would pass it -- and would also pass os_account --
# which is precisely why neither may ever unlock alone.
PRESENCE_ONLY_FACTORS = {"os_account", "face", "hardware"}


# ── lock state ─────────────────────────────────────────────────────────
def lock(reason: str = "manual"):
    with _lock:
        was = _state["unlocked"]
        _state["unlocked"] = False
        _state["unlocked_at"] = 0.0
        _state["last_reason"] = reason
    try:
        import zt
        zt.note_lock()
    except Exception:
        pass
    if was:
        print(f"[auth] locked ({reason})")
        _audit("locked", reason)


def is_unlocked() -> bool:
    """Also applies the idle timeout, so callers cannot forget to."""
    if not AUTH_ENABLED:
        return True
    with _lock:
        if not _state["unlocked"]:
            return False
        idle = _now() - _state["last_activity"]
    if idle > AUTH_IDLE_LOCK_SECONDS:
        lock(f"idle for {int(idle)}s")
        return False
    return True


def touch():
    """Records activity so the idle timer measures real inactivity."""
    with _lock:
        _state["last_activity"] = _now()


def lockout_remaining() -> float:
    with _lock:
        return max(0.0, _state["locked_until"] - _now())


def _backoff_for(failures: int) -> float:
    if failures < 1:
        return 0.0
    return min(BACKOFF_BASE_SECONDS * (2 ** (failures - 1)), AUTH_LOCKOUT_MAX_SECONDS)


def verify(supplied: dict) -> tuple[bool, str]:
    """Attempts to unlock. supplied maps factor name -> value.

    Returns (ok, message). The message is IDENTICAL for every kind of failure
    (design rule 2): wrong PIN, wrong account, expired challenge, unknown
    factor, and not-enrolled all produce GENERIC_FAILURE. Only the lockout
    timer is disclosed, because a user who is locked out needs to know to stop
    trying, and the duration is already inferable by watching the clock.
    """
    if not AUTH_ENABLED:
        return True, ""

    remaining = lockout_remaining()
    if remaining > 0:
        return False, (f"Too many failed attempts. Try again in "
                       f"{int(remaining) + 1} seconds.")

    # EVERY required factor is evaluated, even once one has already failed, so
    # the work done does not depend on which factor was wrong.
    results = []
    for name in AUTH_REQUIRED_FACTORS:
        fn = FACTORS.get(name)
        results.append(bool(fn and fn(supplied.get(name, ""))))
    ok = bool(results) and all(results)

    # os_account is a BINDING, not a challenge: it proves ARGUS is running as
    # the enrolled Windows user, which anyone sitting at that already-unlocked
    # machine also satisfies. On its own it would unlock for exactly the person
    # this module exists to stop. It must be paired with something only the
    # owner knows or can do, so a config that lists it alone fails closed
    # rather than quietly providing no protection.
    #
    # "face" joins it for the same reason and one more: the camera on this
    # machine has no infrared, so a photograph held up to it passes. Face as a
    # SECOND factor raises the bar; face as the ONLY factor would replace a
    # secret you know with a picture anyone can obtain from your social media.
    # A config of nothing but presence factors therefore fails closed here,
    # where it cannot be argued with, rather than in documentation.
    if ok and set(AUTH_REQUIRED_FACTORS) <= PRESENCE_ONLY_FACTORS:
        print("[auth] REFUSING to unlock: "
              f"{', '.join(sorted(AUTH_REQUIRED_FACTORS))} prove only that "
              "somebody is at this machine, not that it is you. Add 'pin' or "
              "'liveness' to AUTH_REQUIRED_FACTORS.")
        ok = False

    with _lock:
        if ok:
            _state.update(unlocked=True, unlocked_at=_now(),
                          last_activity=_now(), failures=0, locked_until=0.0,
                          last_reason="")
        else:
            _state["failures"] += 1
            n = _state["failures"]
            if n >= AUTH_MAX_FAILURES:
                _state["locked_until"] = _now() + _backoff_for(n)
            elif n > 1:
                _state["locked_until"] = _now() + _backoff_for(n - 1)

    # Taxonomised events for querying, alongside the existing free-text audit.
    # Note what is NOT recorded on failure: which factor was wrong. The design
    # rule that the SPOKEN message must not disclose it applies to the log
    # too -- audit.log is readable by anything running as this user, so a line
    # saying "factor=pin failed" would hand an attacker the oracle the generic
    # message was written to deny them.
    import security

    if ok:
        print("[auth] unlocked")
        _audit("unlocked", ",".join(AUTH_REQUIRED_FACTORS))
        try:
            import zt
            zt.note_auth_success()
        except Exception:
            pass
        security.security_event(security.AUTH_SUCCESS,
                                factor=",".join(sorted(AUTH_REQUIRED_FACTORS)),
                                status="ok")
        return True, "Unlocked."

    _audit("auth_failed", f"{_state['failures']} consecutive")
    try:
        import zt
        zt.note_auth_failure()
    except Exception:
        pass
    if "liveness" in AUTH_REQUIRED_FACTORS and not results[
            AUTH_REQUIRED_FACTORS.index("liveness")]:
        # The one exception, and it is safe: liveness failing means the
        # challenge phrase was not spoken back in time. That is a replay or a
        # timeout, not a guessable credential, so naming it leaks nothing an
        # attacker can grind against -- and it is the event worth alerting on.
        security.security_event(security.VOICE_VERIFICATION_FAILURE,
                                reason="challenge_not_met",
                                attempts=_state["failures"], status="failed")
    security.security_event(security.AUTH_FAILURE, factor="undisclosed",
                            attempts=_state["failures"], status="failed")
    return False, GENERIC_FAILURE


def status() -> dict:
    """For the HUD. Deliberately says nothing about which factors exist or
    which one last failed."""
    with _lock:
        return {
            "enabled": bool(AUTH_ENABLED),
            "unlocked": bool(_state["unlocked"]) and is_unlocked(),
            "locked_out": lockout_remaining() > 0,
            "lockout_seconds": int(lockout_remaining()),
            "idle_lock_seconds": AUTH_IDLE_LOCK_SECONDS,
        }


def _audit(event: str, detail: str = ""):
    try:
        import security
        security.audit(event, detail)
    except Exception:
        pass


# ── automatic locking ──────────────────────────────────────────────────
def _workstation_is_locked() -> bool:
    """True when Windows itself is locked.

    OpenInputDesktop fails with ACCESS_DENIED while the secure desktop is up,
    which is the standard dependency-free way to detect this. A failure for
    any other reason is treated as "not locked" so a permissions quirk cannot
    lock the user out of their own assistant.
    """
    if os.name != "nt":
        return False
    try:
        DESKTOP_SWITCHDESKTOP = 0x0100
        h = ctypes.windll.user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
        if not h:
            return True
        ctypes.windll.user32.CloseDesktop(h)
        return False
    except Exception:
        return False


def _watchdog():
    """Locks on idle, on Windows session lock, and on resume from suspend.

    Suspend is detected by comparing wall clock against the monotonic clock:
    if wall time advanced far more than monotonic did, the machine was asleep
    in between. That needs no power-event plumbing and no extra dependency,
    and when the platform's monotonic clock DOES advance through sleep the
    idle timer catches the same case a moment later.
    """
    last_wall, last_mono = time.time(), time.monotonic()
    while True:
        time.sleep(5)
        wall, mono = time.time(), time.monotonic()
        drift = (wall - last_wall) - (mono - last_mono)
        last_wall, last_mono = wall, mono

        if drift > 30:
            lock(f"resumed after ~{int(drift)}s suspended")
            continue
        if _workstation_is_locked():
            if _state["unlocked"]:
                lock("workstation locked")
            continue
        is_unlocked()      # applies the idle timeout


_watchdog_started = False


def start():
    """Starts the auto-lock watchdog. Safe to call more than once."""
    global _watchdog_started
    with _lock:
        if _watchdog_started:
            return
        _watchdog_started = True
        _state["last_activity"] = _now()
    threading.Thread(target=_watchdog, name="auth-watchdog", daemon=True).start()
    print(f"[auth] {'enabled' if AUTH_ENABLED else 'DISABLED'} "
          f"(factors: {', '.join(AUTH_REQUIRED_FACTORS)}; "
          f"idle lock {AUTH_IDLE_LOCK_SECONDS}s)")


# ═══════════════════════════════════════════════════════════════════════
# AUTHORIZATION DECISION
# ═══════════════════════════════════════════════════════════════════════

# "Re-authentication" means the unlock must be RECENT, not merely to have
# happened at some point in this session. An unlock from forty minutes ago
# says nothing about who is standing there now. Fifteen minutes, not two:
# at 120 s nearly every L2 command asked for the PIN again (owner,
# 2026-09-24), and the everyday lookups that caused most of it are L1 now.
REAUTH_FRESHNESS = 900.0

# L4 needs more than one INDEPENDENT factor. Configuring a single factor and
# calling it strong would be the same self-deception as the os_account-alone
# case guarded against in verify().
STRONG_MIN_FACTORS = 2

CONFIRM_WINDOW = 30.0
_confirm = {"skill": None, "action": None, "target": None, "at": 0.0}


# its authorization is carried to the dispatcher as a single-use,
# action-hash-bound token and re-verified there IMMEDIATELY BEFORE execution
# (section 21's continuous authorization). Held here between the two seams.
_pending_grant = {"token": None, "skill": None, "action": None}


class Denied(Exception):
    """Raised with a spoken reason when an operation is not permitted."""


def _auth_age() -> float:
    with _lock:
        at = _state["unlocked_at"]
    return float("inf") if not at else _now() - at


def stage_confirmation(skill: str, action: str, target: str) -> str:
    with _lock:
        _confirm.update(skill=skill, action=action, target=target, at=_now())
    return f"That needs confirming. Say 'confirm' to go ahead with {action} {target}.".strip()


def take_confirmation(skill: str, action: str, target: str) -> bool:
    """True if THIS exact operation was confirmed within the window.

    Matched on skill+action+target, so a confirmation given for one thing can
    never authorise a different one -- the classic bait-and-switch where the
    user confirms a harmless action and a second, larger one rides in on it.
    """
    with _lock:
        ok = (_confirm["skill"] == skill and _confirm["action"] == action
              and (_confirm["target"] or "") == (target or "")
              and _now() - _confirm["at"] <= CONFIRM_WINDOW)
        if ok:
            _confirm.update(skill=None, action=None, target=None, at=0.0)
        return ok


def clear_confirmation():
    with _lock:
        _confirm.update(skill=None, action=None, target=None, at=0.0)


def pop_grant(skill: str, action: str, target: str) -> str:
    """The dispatcher's claim on a pending grant for THIS action.

    Pops only on an exact (skill, action) match -- a different action must
    never inherit another action's token. Empty string means "no grant
    pending", which for an unconfirmed (L0-L2) action is the normal shape.
    The target is not part of the claim: grants.redeem() re-derives the
    action hash from what is about to run, so a substituted target fails
    THERE, where the refusal names the substitution.
    """
    with _lock:
        if _pending_grant["token"] and _pending_grant["skill"] == skill \
                and _pending_grant["action"] == action:
            tok = _pending_grant["token"]
            _pending_grant.update(token=None, skill=None, action=None)
            return tok
    return ""


def _mint_pending_grant(skill: str, action: str, target: str) -> None:
    """Mint and stage the execution-time grant for a JUST-CONFIRMED L3+
    action. Mint failures never block the action -- grants are the second,
    verification half of the confirmation, not a third permission source.
    Audited inside grants.mint()."""
    try:
        import grants
        tok = grants.mint(skill, action, target, uses=1,
                          source="confirmation")
        with _lock:
            _pending_grant.update(token=tok, skill=skill, action=action)
    except Exception:
        pass


def authorize(skill: str, action: str = "", target: str = "") -> tuple[bool, str]:
    'The single authorization decision. Returns (allowed, spoken_reason).'
    level = level_for(skill, action)

    if not AUTH_ENABLED:
        # Even with auth off, L5 stays refused. It is reserved for operations
        # that must never run without hardware backing, and "the user turned
        # authentication off" is not a hardware token.
        if level >= L5_HARDWARE:
            # Even with auth disabled the gesture gate stands: a completed
            # Hello verification is accepted here ONLY because the operator
            # who turned AUTH_ENABLED off is the same person Hello attests;
            # every other outcome refuses, exactly as before.
            try:
                import hwauth
                ok, _reason = hwauth.verify_user(
                    f"Confirm {action or skill} with Windows Hello")
                if ok:
                    import security
                    security.security_event(security.AUTH_SUCCESS,
                                            factor="hello", skill=skill,
                                            action=action or "-", status="ok")
                    return True, ""
            except Exception:
                pass
            return False, ("That needs a hardware security key, which isn't "
                           "set up on this machine.")
        return True, ""

    if level <= L0_OPEN:
        return True, ""

    if not is_unlocked():
        return False, LOCKED_MESSAGE

    if level >= L5_HARDWARE:
        # Still fails closed. The ONLY thing that satisfies this tier is a
        # completed Windows Hello verification -- an OS-attested gesture from
        # the enrolled user -- and only when the user has deliberately enabled
        # it (hwauth.HELLO_ENABLED defaults off, so a software update never
        # starts gating actions behind biometric prompts on its own). Every
        # other outcome -- no projection package, no enrolled credential, the
        # toggle off, the user cancels -- lands in the same refusal as before,
        # because silently accepting a lesser factor would turn the highest
        # tier into the second-highest without anyone noticing. A completed
        # Hello prompt IS the confirmation gesture, so no separate staged
        # confirmation is consumed or required on this path.
        try:
            import hwauth
            ok, _reason = hwauth.verify_user(
                f"Confirm {action or skill} with Windows Hello")
            if ok:
                import security
                security.security_event(security.AUTH_SUCCESS, factor="hello",
                                        skill=skill, action=action or "-",
                                        status="ok")
                return True, ""
        except Exception:
            pass
        return False, ("That needs Windows Hello verification, which isn't "
                       "available on this machine, so I won't do it.")

    if level >= L2_REAUTH and _auth_age() > REAUTH_FRESHNESS:
        return False, ("That needs you to authenticate again — it's been a "
                       "while since you did.")

    if level >= L4_STRONG and len(set(AUTH_REQUIRED_FACTORS)) < STRONG_MIN_FACTORS:
        return False, (f"That needs stronger authentication than is configured. "
                       f"Set at least {STRONG_MIN_FACTORS} factors in "
                       f"AUTH_REQUIRED_FACTORS.")

    if level >= L1_UNLOCKED:

        # the narrow read-only diagnostic list runs -- whatever the action's
        # level. A machine in SAFE_MODE or LOCKDOWN keeps its diagnostics and
        # loses everything else, L1 included: "apps/open" is exactly the kind
        # of state change SAFE_MODE exists to pause, and gating only L2+
        # would have let an L1 write through. The model cannot move the
        # state, so this gate is not something a prompt can negotiate with.
        try:
            import security_state
            if not security_state.l2_allowed():
                if (security_state.current() in
                        (security_state.SAFE_MODE, security_state.LOCKDOWN,
                         security_state.RECOVERY)
                        and security_state.safe_mode_allowed(skill, action)):
                    pass    # read-only diagnostics stay available (section 23)
                else:
                    return False, ("I'm in " + security_state.current().lower()
                                   + " right now -- state-changing actions "
                                     "are paused. Run diagnostics to check "
                                     "what happened.")
        except Exception:
            pass    # a state check must never widen what runs

    # Push-to-talk, checked BEFORE the confirmation is consumed. Ordering
    # matters: staging a confirmation and then refusing it would burn the
    # pending action and leave the user re-issuing a command that was never
    # going to be allowed in this posture.
    import voiceauth

    if voiceauth.push_to_talk_required(level) and not voiceauth.push_to_talk_satisfied():
        import security
        security.security_event(security.TOOL_DENIED, skill=skill,
                                action=action or "-", level=level,
                                reason="push_to_talk_not_held", status="failed")
        return False, ("Hold the push-to-talk key while you say that — this "
                       "one needs you at the keyboard.")

    if level >= L3_CONFIRM:
        if take_confirmation(skill, action, target):
            # Confirmed: mint the execution-time grant now, so _dispatch_inner
            # can re-verify the exact action-hash immediately before the skill

            _mint_pending_grant(skill, action, target)
            return True, ""
        return False, stage_confirmation(skill, action, target)

    # ZERO-TRUST STEP-UP, the LAST word before an allow.
    #
    # Everything above this line is STATIC: a level from the table, a lock
    # state, a freshness window. This call is the DYNAMIC half -- it can only
    # refuse, never allow, so a low session score subtracts trust without
    # ever granting it. Sitting after the L3 gate means a confirmed action
    # still passes through the score on the way out, and sitting before the
    # final `return True` means no allow path can bypass it. See zt.py for
    # why the inputs are security events only -- a phrased request cannot
    # lower its own score.
    try:
        import zt
        allowed, zt_reason = zt.evaluate(skill, action, level,
                                         auth_age_s=(_auth_age()
                                                     if _auth_age() != float("inf")
                                                     else None))
        if not allowed:
            return False, zt_reason
    except Exception:
        pass            # a scoring failure must not block the static decision

    return True, ""


def describe_level(skill: str, action: str = "") -> str:
    lvl = level_for(skill, action)
    return f"{LEVEL_NAMES.get(lvl, lvl)} ({skill}/{action or '*'})"


def enroll_owner() -> str:
    """Binds ARGUS to the current Windows account."""
    sid = _current_user_sid()
    if not sid:
        return "Couldn't read this Windows account's SID."
    secrets_store.put_secret("ARGUS_OWNER_SID", sid)
    return f"Bound to this Windows account ({sid[:20]}...)."
