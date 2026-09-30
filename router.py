"""
ARGUS - Router

Tier 1: intent.match() — pattern rules, no model call.
Tier 2: local LLM decides.

Conversational answers get the user profile injected, so ARGUS answers with
your context rather than generically.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import time
import webbrowser

import auth
import execpolicy
import intent
import brain
import route_trace
from ollama_client import chat_json
from skills import (
    cleanup_skill,
    apps_skill,
    browser_skill,
    document_skill,
    dev_skill,
    scheduler_skill,
    email_skill,
    system_ext_skill,
    vault_skill,
    web_skill,
    timer_skill,
    control_skill,
    vision_skill,
    weather_skill,
    research_skill,
    profile_skill,
    personalize_skill,
    pc_skill,
    storage_skill,
    window_skill,
    files_skill,
    power_skill,
    network_skill,
    diagnostics,
    social_skill,
    calc_skill,
    knowledge_skill,
    privacy_skill,
    clarify_skill,
    followup_skill,
    proactive_skill,
    anomaly_skill,
    cloud_gate,
    context_skill,
    health_skill,
    system_skill,
    monitor_skill,
    service_skill,
    env_skill,
    security_log_skill,
    zt_skill,
    watched_skill,
    goals_skill,
    telemetry,
    registry,
)
import security

ROUTING_PROMPT = """You are ARGUS's command router. Output ONLY a JSON object.
No markdown fences, no explanation.

Skills:
- "apps": action="open"|"close"|"list", target=app name
- "weather": action="get", target=city (empty for home city)
- "research": action="quick"|"deep", target=what to look up
- "knowledge": action="lookup", target=topic (for factual "what/who is X" questions)
- "youtube": action="play", target=what to play
- "vault": action="write" (target=title, reply=content) | "read"
- "profile": action="remember" (target=fact, reply=section) | "summary" | "forget"
- "timer": action="set", target=seconds as number, reply=reminder text
- "control": action="volume_set"|"volume_up"|"volume_down"|"mute"|"unmute"|"brightness_set"|"clipboard_read"|"clipboard_write"|"mic_mute"|"mic_unmute"|"mic_status" -- mic_mute/unmute is the microphone DEVICE at the OS mixer, not ARGUS's own listening pause (that's "privacy")
- "pc": action="stats"|"battery"|"uptime"|"snapshot"|"lock"|"time"|"media"|"dictate"|"screen_record"|"camera_status"|"power_plan" (target empty reads the current plan; target="balanced"|"power saver"|"high performance" switches it)
- "storage": action="free" (space left, per drive; target = the phrase, which
  may name a drive) | "largest" (what is using space; target = a folder name
  or empty for the home folder) | "analyze" (break a folder down by what is
  filling it; target = a folder name or empty). Read-only -- it never deletes
  anything.
- "window": action="focus"|"minimize"|"maximize", target=window name
- "files": action="find"|"open"|"permissions", target=filename -- "permissions"
  reports the owner and whether you can read/write it, nothing more
  | action="content_search" target=a phrase -- which files MENTION it,
  distinct from "find" (which matches filenames, not what's inside them)
  | action="restore" target=the file's remembered NAME -- restore it from the
  Recycle Bin to its original folder; STAGES and asks for the PIN ("get X back
  from the recycle bin", "undelete X")
  | action="create" target=the new name, reply=the text content, where=optional
  folder -- a brand-new text/markdown file; refuses to overwrite
- "vision": action="describe", target=question about the screen -- a MODEL's
  general impression, for open-ended questions ("what's on my screen")
  | action="read_text" (no target) -- OCRs the whole screen and returns the
  actual text on it, for "what does it say"/"read this"
  | action="locate_text"|"verify_text" target=a word or phrase -- WHERE it is
  on screen, or whether it's there at all, e.g. "where does it say Save",
  "do I have an error message showing"
  | action="cursor_location" (no target)
  | action="click_text" target=the visible text to click -- the FALLBACK for
    an app that draws its own UI and exposes nothing to pc/ui_click (that is
    always tried first for anything that names a normal window control)
  | action="drag_text" target="<source text>|<destination text>"
  | action="visual_confirm"|"visual_cancel" -- answering "want me to click
    it?" from a destructive-looking visual click
- "anomaly": action="check" -- has anything about running processes looked
  unusual recently (a new process using a lot of CPU, a known process
  spiking, spawning far more children than usual)
- "net": action="online"|"wifi"|"ip"|"data" -- connectivity, which network,
  local IP address, how much bandwidth has been used
  | action="wifi_on"|"wifi_off" -- enables/disables the Wi-Fi adapter itself,
  distinct from "wifi" (which only reads the current connection)
- "calc": action="calculate" (arithmetic, percentages) | "convert" (units,
  currency, temperature). target = the full expression as spoken
- "privacy": action="on"|"off"|"status" -- stop/resume listening, privacy
  or mute mode. target = number of minutes if one was given
- "diag": action="full" -- a full system health check ("is everything
  okay", "run diagnostics", "is anything wrong with the machine")
  | action="ports" -- what on this machine ACCEPTS incoming connections
  ("what's listening", "what ports are open", "is anything exposed",
  "what can reach my machine"). NOT outbound connections -- that is
  "net"/"connections"
  | action="defenses" -- whether this machine's own protections are on
  ("am I protected", "is my firewall on", "is Defender running", "check
  my defences", "how hardened am I")
  | action="changes", target=the phrase (it may name a window like "24
  hours" or "3 days") -- what is DIFFERENT about this machine since a
  point in time: new startup entries, new listeners, security settings
  that moved, network settings that moved ("what's changed", "anything
  new on my machine", "what happened while I was out")
  | action="process", target=<program name or pid> -- a profile of ONE
  running program ("what is postgres", "tell me about chrome", "what's
  pid 4210 doing", "is svchost signed"). Use this whenever the user
  names a program and asks what it is or what it is doing on the
  machine. NOT for opening or closing it -- that is "apps"
- "audit": action="read" -- what ARGUS itself has recently done, its
  activity log. NOT the user's own notes (that is "vault")
- "power": action="request", target="shutdown"|"restart"|"sleep"|"signout".
  This only STAGES the action; it is confirmed separately with a PIN, so
  classifying it here can never power anything off on its own
- "social": action="how_are_you"|"who_are_you"|"who_built_you"|
  "about_creator"|"what_can_you_do"|"joke"|"thanks"|"goodbye" -- pleasantries
  and questions about ARGUS itself, who made it, or what it can do
- "remedy": action="offer" -- the user is asking ARGUS to FIX something it
  detected ("can you fix it", "sort it out", "repair that"). This only
  ASKS; the repair itself is confirmed separately, so classifying it here
  can never change anything on its own
- "web": action="open_url", target = the URL, for "open <something>.com"
- "browser": a SEPARATE, managed browser window (not your default browser)
  for multi-step site tasks -- "go to the site, find X, download it" is
  several of these in a row, not one action.
  action="navigate"|"search" target=url or search terms
  | action="tab_open"|"tab_close"|"tab_switch"|"tab_search" target=url or a
    phrase matching an open tab's title
  | action="list_tabs"|"back"|"forward"|"refresh"|"launch"|"close" (no target)
  | action="extract_text" target=optional CSS selector (empty = whole page)
  | action="find_elements" target=optional phrase to filter clickable items by
  | action="click"|"follow_link" target=the visible text to click
  | action="fill" target="<field>|<value>" (field name, a pipe, then the value)
  | action="screenshot" target=optional label
  | action="zoom" target=percentage, e.g. "150"
  | action="downloads"|"bookmarks_list" (no target)
  | action="bookmark_add" target=optional label for the current page
  | action="bookmark_remove"|"history_search" target=a matching phrase
  | action="submit" target=optional form name -- STAGES submitting the
    current page's form, does not submit it; asks for the PIN
  | action="download" target=the link or button text to download -- STAGES
    only; asks for the PIN
  | action="upload" target="<field>|<file>" -- STAGES only; asks for the PIN
  | action="confirm" target=the PIN just given
  | action="cancel" -- drops whatever submit/download/upload is staged
- "document": PDF/Word/text files -- target names the file the same way
  "files"/"find" does.
  action="read" target=filename -- the actual text in the document
  | action="summarize" target=filename -- a spoken summary of it
  | action="search" target="<filename>|<phrase>" -- find a phrase inside it
  | action="info" target=filename -- page/word count, size, kind
  | action="merge" target="<file one> and <file two>[, reply=<output name>]"
  | action="split" target=filename -- one PDF into one file per page
  | action="create" target=<the dictated text>, reply=<output name> -- a NEW
    .docx (there's no PDF equivalent -- see document_skill's own docstring)
- "schedule": background/recurring checks -- ONLY for a read-only pair
  already listed under CHAINABLE above (pc/stats, pc/uptime, weather/get,
  research/quick, knowledge/lookup, net/online, net/wifi, net/ip, net/data,
  files/find, diag/full, diag/ports, diag/defenses, diag/changes, audit/read,
  anomaly/check, security/summary, storage/free, storage/largest,
  health/check, health/report, context/current, context/selection,
  context/file, system/stats, and the other CHAINABLE pairs). Never
  files/delete, power, browser, or anything that acts -- those are refused
  regardless of what's asked. "monitor" is NOT a scheduled pair: a watch
  waits on the machine's own state, not a read-only skill on a timer.
  action="once" target="<skill>|<action>|<inner target>|<seconds from now>[|<only tell me if the result contains this>]"
  | action="every" target="<skill>|<action>|<inner target>|<interval seconds>[|<only tell me if the result contains this>]"
  | action="list"|"status" (no target)
  | action="cancel"|"pause"|"resume" target=a task id or description
  | action="results" target=optional task id or description
- "email": action="search"|"read"|"attachments" target=a phrase matching
  subject or sender | action="contacts" target=a name or address fragment
  | action="send" target="<to>|<subject>|<body>" -- STAGES, asks for the PIN
  | action="reply" target="<phrase matching the email>|<body>" -- STAGES
  | action="forward" target="<phrase matching the email>|<to>" -- STAGES
  | action="confirm" target=the PIN | action="cancel"
- "sysext": read-only device/network extras.
  action="printers" (no target) | action="print_queue" target=optional
  printer name | action="devices" target="network"|"disk"|empty
  | action="network_drives" (no target) | action="dns" target=a hostname
  | action="port" target="<host>:<port>" | action="ping" target=a host
  | action="bluetooth_status"|"bluetooth_on"|"bluetooth_off" (no target)
- "dev": read-only git reporting on ARGUS's own repo.
  action="status" (no target) | action="log" target=how many commits, a
  number | action="diff" target="staged" for staged changes, empty for
  unstaged | action="branch" (no target)
- "proactive": action="on"|"off" -- whether ARGUS may volunteer remarks
- "context": the current SCENE -- what is in front of the user right now.
  Always local, always read-only, never acts; the pieces (window, tab,
  clipboard) are the machine's own state, not a model's guess.
  action="current" (no target) -- the focused app, its window, the open
  editor file if one is visible, the active browser tab, and a clipboard
  preview ("what am I looking at", "what's on my screen")
  | action="selection" -- what is selected right now (clipboard first, else
  the last file ARGUS found)
  | action="file" -- the last file ARGUS found, if any ("what file", "my
  current file")
- "health": a rolling health picture of CPU, memory and disk -- how the
  machine has BEEN, not just this second (that is "pc"/"stats"). Read-only.
  action="check", target=optional look-back window like "1 hour" or "3 days"
  (default 1 hour) -- the numbers now plus their range over the window,
  the busiest process, any recent anomalies
  | action="report" (no target) -- "healthy", or the one or two sustained
  things actually worth attention
- "system": ARGUS's own runtime state. Reading is harmless and local;
  only set_flag writes a small boolean feature-flag store.
  action="stats" -- the router's own usage and latency this session
  | action="flags"|"flag", target=optional flag name -- the feature-flag
  catalogue and whether each is on
  | action="settings" -- what settings ARGUS is running with
  | action="set_flag", target="<name>|<on or off>" -- toggle one flag
- "monitor": watch ONE allowlisted condition until it becomes true, then
  report it once and stop. Watches are read-only probes (a file check, a
  battery read, a CPU sample, a network probe, a folder count) -- they never
  act, and they are NOT the scheduler: a scheduled pair runs a read-only
  skill on a timer, a monitor waits on the machine's state itself.
  target=the condition, one of: "file_exists <path>" |
  "battery_above <pct>" | "battery_below <pct>" | "net_online" |
  "net_wifi_name <network name>" | "cpu_above <pct>" | "cpu_below <pct>" |
  "folder_has <path>, <count>" | "file_size_above <path>, <mb>"
  action="set" target=that condition ("tell me when battery is above 80")
  | action="list"|"status" (no target) | action="cancel" target=a monitor id
  or description | action="results" target=optional id or description
- "watched": a watched TASK -- wait for an allowlisted condition, then stage
  an owner-approved plan for it. The condition is the same allowlist monitor
  uses; the plan is composed and validated at SET time and the owner hears
  it; firing STAGES the stored plan (never runs anything) and needs the
  usual "go ahead". Use when the ask is explicitly "watch for X, then Y".
  action="set", target="<condition> then <goal>" ("watch for battery_above
  80, then check what's using the CPU") | action="list"|"status" (no target)
  | action="cancel" target=a watched-task id or description
  | action="results" target=optional id or description
- "goals": a persistent goal -- repeat a task on a schedule, where
  each run stages the validated plan and waits for the usual "go ahead";
  the schedule recurs, the execution never does. Use when the ask starts
  with "every morning/day/hour" or "in N minutes" and names recurring work.
  action="create", target="every morning, prepare a system briefing"
  | action="list"|"status" (no target) | action="cancel" target=a goal id
  or description | action="results" target=optional id or description
- "service": Windows services. Reading is local and harmless; start/stop/
  restart ALWAYS stage first and ask for the command PIN (never execute).
  action="status", target=service name OR display name ("is spooler running",
  "is printing set up") -- matches "spooler" to "Print Spooler"
  | action="list", target=optional word to narrow ("what services are
  running", "list stopped services")
  | action="start"|"stop"|"restart", target=service name -- STAGE ONLY, a
  PIN confirmation follows ("restart the print spooler")
  | action="cancel" (no target) -- abandon a staged service action
- "env_var": the user's environment variables. Reading is local and
  harmless; setting ALWAYS stages first and asks for the command PIN.
  action="list", target=optional word to filter ("what are my environment
  variables", "show me my PATH-like variables")
  | action="get", target=exact variable name ("what is PATH")
  | action="set", target="<NAME>|<value>" -- STAGE ONLY, a PIN confirmation
  follows ("set MYTOKEN to abc123" -> "MYTOKEN|abc123")
  | action="cancel" (no target) -- abandon a staged set
- "security_log": the Windows event logs (security / application / system).
  Read-only. The security log reveals logon history and needs fresh
  authentication, so it is never chained or auto-scheduled.
  action="read", target="<log> [<count>]" like "security 10" or "application
  5" (default: system, max 20) ("what's in the security log", "check the
  event log", "any failed logins lately")
  | action="status" (no target) -- which logs exist and how many records
- "zt": ARGUS's zero-trust session layer and its TPM hardware factor.
  action="status"|"describe" (no target) -- the current session-trust score,
    its band, and what is currently moving it ("how trusted is this session",
    "zero trust status")
  | action="on"|"off" -- the scoring layer itself. Static permission levels
    are untouched either way; off means only that the dynamic score stops
    refusing. A security-relevant toggle, so fresh authentication applies.
  | action="enroll_hw"|"forget_hw"|"check_hw"|"hw_status" (no target) -- the
    TPM-backed hardware factor: enrol, remove, test, or report it.
- "personalize": structured, deterministically-resolved preferences/aliases/
  workflows -- DIFFERENT from "profile" (which is freeform facts about the
  user). action="set_preference" target=one of default_browser|
  default_editor|default_terminal|default_music_app|response_verbosity|
  preferred_language|security_report_detail, reply=the value ("use Firefox
  by default" -> target="default_browser" reply="Firefox"; "keep answers
  short" -> target="response_verbosity" reply="concise")
  | action="set_alias" target=the word, reply=what it means ("when I say
  editor I mean VS Code" -> target="editor" reply="VS Code"; "call this
  project ARGUS" -> target="this project" reply="ARGUS")
  | action="forget" target=the preference key or alias word ("don't use
  Chrome for that anymore" about a default -> target=the relevant key;
  "forget what terminal means" -> target="terminal")
  | action="confirm_workflow"|"reject_workflow" (no target) -- answering a
  workflow suggestion ARGUS just offered
  | action="run_workflow" target=the workflow's name ("start work mode")
  | action="delete_workflow" target=the workflow's name
  | action="summary" (no target) -- what preferences/aliases/workflows are known
  | action="explain" target=the key/alias/topic -- "why did you open
  Firefox", "why do you keep security reports detailed"
- "chat": action="reply" -- anything conversational, open-ended, or that
  doesn't clearly match another skill. Do NOT write the answer yourself
  here; a separate model with the actual conversation and web-search
  access handles "chat". Just classify it as "chat" and stop.

CRITICAL RULES:
- Use "profile" ONLY when the user is explicitly telling you a fact about
  themselves, or explicitly asking what you know about them. Small talk like
  "how are you" is NEVER profile — that is "chat".
- Use "personalize", not "profile", when the statement sets a SPECIFIC
  behavioral switch (a default app, a verbosity level, a word-to-app
  mapping) rather than a general fact. "I work as a nurse" is "profile"
  (remember). "Use Firefox by default" is "personalize" (set_preference).
  When genuinely unsure between the two, prefer "profile" -- it is the
  safer default and never silently changes ARGUS's behavior.
- "chat" is the RIGHT answer for anything open-ended, conversational,
  explanatory, or opinion-based -- "why is the sky blue", "explain how
  encryption works", "do you know about X", "what do you think about Y",
  "tell me something interesting". Do NOT send these to "knowledge" or
  "research".
- Use "knowledge" ONLY for a narrow lookup the user explicitly asked for:
  define a word, spell it, translate it. Use "research" only when the answer
  genuinely needs CURRENT information from the web (today's news, a live
  price, a recent event).
- If nothing else clearly fits, use "chat". Leave reply empty for "chat" --
  it is never used.
- Only use "steps" (below) when the request genuinely needs more than one
  piece of information combined -- "check my CPU and tell me what's eating
  it" needs BOTH cpu stats AND the process list, not just one of them. A
  single request, even a detailed one, is still ONE decision in the normal
  shape. When unsure, use the normal shape.

Shape: {"skill":"...","action":"...","target":"...","reply":"..."}

For a request that needs two or three READ-ONLY lookups combined into one
answer, use this shape instead -- each item uses the same skill/action
vocabulary as above:
{"steps":[{"skill":"...","action":"...","target":"..."}, ...]}

Example -- "check my cpu and tell me what's eating it" needs BOTH pieces,
so it is NOT {"skill":"pc","action":"stats",...} alone, it is:
{"steps":[{"skill":"pc","action":"stats","target":""},{"skill":"apps","action":"list","target":""}]}"""

# Every (skill, action) pair steps= is allowed to contain. Deliberately
# read-only: apps/open, power/*, control/*, timer/set, profile/remember and
# every other skill with a real side effect are excluded on purpose. Chaining
# means the model picks a SEQUENCE to run without a human looking at each one
# individually first -- fine for "tell me two things", genuinely dangerous
# for "open two apps and change a setting" if the model's plan is wrong. The
# measured router accuracy on a SINGLE decision is real (71% on one test
# set); asking it to also decide that every step in a sequence is safe is a
# strictly harder problem, so the safety boundary is enforced here in code,
# not left to the model's own judgement.
CHAINABLE = {
    ("pc", "stats"), ("pc", "uptime"), ("pc", "time"),
    # The READ half of UI automation: describing a control tree, reading a
    # control's text, and verifying a control's text are pure reports (same
    # class as stats/uptime). Clicking, typing, dragging and the rest act on
    # whatever window has focus, and stay out of the auto-run sequence.
    ("pc", "ui_tree"), ("pc", "ui_read"), ("pc", "ui_verify"),
    ("weather", "get"),
    ("research", "quick"), ("research", "deep"),
    ("knowledge", "lookup"), ("knowledge", "define"),
    ("knowledge", "spell"), ("knowledge", "translate"),
    ("net", "online"), ("net", "wifi"), ("net", "ip"), ("net", "data"),
    ("vault", "search"), ("vault", "read"),
    # The read-only half of the file/storage surface. metadata/permissions/
    # recent/duplicates and storage/free|largest are pure reports; analyze is
    # a read-only walk. This also closes pre-existing drift: the schedule
    # section of ROUTING_PROMPT already claimed storage/free and storage/largest
    # were chainable, but CHAINABLE never listed them -- now both claims hold.
    ("files", "find"), ("files", "metadata"), ("files", "permissions"),
    ("files", "recent"), ("files", "duplicates"),
    ("storage", "free"), ("storage", "largest"), ("storage", "analyze"),
    ("window", "list"),
    ("apps", "list"),
    ("diag", "full"), ("diag", "ports"), ("diag", "defenses"),
    ("diag", "changes"),
    ("audit", "read"),
    ("anomaly", "check"),
    ("security", "summary"),
    ("privacy_watch", "usage"),
    ("profile", "summary"),
    ("calc", "convert"), ("calc", "calculate"),
    # 1.1.0: the new read-only reporting skills. health and context only ever
    # report the machine's own state; system/stats reports ARGUS's own usage.
    # (monitor is deliberately NOT chained -- a watch is a scheduled-style
    # capability class and gets reviewed as one, per its module docstring.)
    ("health", "check"), ("health", "report"),
    ("context", "current"), ("context", "selection"), ("context", "file"),
    ("system", "stats"),
    # Only read-only actions are chainable. Confirmed writes stay out.
    ("service", "list"), ("service", "status"),
    ("env_var", "list"), ("env_var", "get"),
    ("security_log", "read"), ("security_log", "status"),
    # 1.2.0: zero-trust reporting. Pure reads of session state, same class as
    # security/summary. The toggles and factor enrolment stay out -- a chain
    # must not hide a fresh-auth gate.
    ("zt", "status"), ("zt", "describe"), ("zt", "hw_status"),
}
MAX_CHAIN_STEPS = 3




def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


_QUESTION_LEAD = re.compile(
    r"^(who|what|why|when|where|how|is|are|do|does|did|can|could|will|would)\b"
)


def _looks_like_a_question(target: str) -> bool:
    """Shared by profile/remember and profile/forget -- see both call sites.
    Only guards the LLM-inferred path: explicit dictation ("remember that
    I...", "forget about...") is parsed by intent.py's own regex, which can
    never capture a bare question word first, so genuine dictation is never
    at risk here."""
    return bool(_QUESTION_LEAD.match(target.strip().lower()))


_LOOKUP_STOPWORDS = frozenset(
    "the a an of in on at to for and or is are was were what which who "
    "how why when where does do did bigger smaller larger faster slower "
    "than more less most least best worse".split())


def _looks_relevant(topic: str, article: str) -> bool:
    """Does a Wikipedia result actually concern the thing that was asked?

    Compared on CONTENT WORDS only. Wikipedia's search matches titles, so
    "largest ocean" can return "ocean sunfish" and "the moon bigger than
    australia" can return Rhea, a moon of Saturn -- both share a word with the
    query and neither answers it.

    Deliberately lenient: it needs a MAJORITY of the topic's content words to
    appear, so a genuine article with different phrasing still passes, while
    an article that merely brushed one keyword does not.
    """
    words = [w for w in re.findall(r"[a-z]+", (topic or "").lower())
             if w not in _LOOKUP_STOPWORDS and len(w) > 2]
    if not words:
        return True          # nothing to judge on; let the caller decide
    body = (article or "").lower()
    hits = sum(1 for w in words if w in body)
    return hits >= max(1, (len(words) + 1) // 2)


# Set by _dispatch_inner when auth refused the command, read and reset by
# _dispatch() to label the telemetry outcome. A module-level slot rather
# than a change to _dispatch_inner's return value, because that return IS
# the spoken reply and has no second channel. Dispatch is serial by
# construction (see _last_dispatch below), so one slot is honest.
_last_refused = False


def _egress_scope(skill: str, action: str):
    """The request's routing decision, if running this (skill, action) would carry
    a local-only request to a search engine or reference site; otherwise None.
    Outside a request (a scheduled task, a background check) there is no scope
    and so nothing to refuse."""
    scope = cloud_gate.current()
    if scope is not None and scope.local_required \
            and cloud_gate.is_web_lookup(skill, action):
        return scope
    return None


def _withhold_web(skill: str, action: str, scope) -> str:
    """Refuse a web lookup for a request the routing policy marked local-only,
    and say what was and was not done.

    Recorded as a TOOL_DENIED event like any other refusal, so "did anything try
    to send that off this machine?" is a query against the security log rather
    than a matter of trust. The reply states that nothing was searched -- the
    person should never have to wonder whether it was.
    """
    global _last_refused
    _last_refused = True
    try:
        security.security_event(security.TOOL_DENIED, skill=skill,
                                action=action or "-",
                                reason="local_required_egress", status="failed")
    except Exception:
        pass
    print(f"[route] policy withheld {skill}/{action}: {scope.describe()}")
    return cloud_gate.DENIED_MIXED_WEB if (scope.mixed and scope.web) \
        else cloud_gate.DENIED_WEB


def _dispatch(d: dict, user_text: str, history: list | None, via: str = "") -> str:
    """Thin wrapper around _dispatch_inner(): catches whatever an individual
    skill didn't already catch itself, and reports it specifically instead
    of letting it bubble up to main.py's outer handler, which only knows
    how to say "Something went wrong handling that" -- true, but useless
    for figuring out what actually broke. Only "control" and "pc" had their
    own local try/except before this; everything else (apps, weather,
    vault, files, window, seventeen others) had no skill-specific handling
    at all, so a real failure in any of them produced the same generic
    non-answer regardless of what actually went wrong. This doesn't change
    what happens on success -- only what the user hears when something
    genuinely fails.

    VIA labels which router path produced this dispatch ("fast", "followup",
    "model", "plan", "chain", or "" for a scheduled/known call) and rides into
    skills/telemetry.py's per-command record, so "how is ARGUS doing" can say
    which path is actually serving commands rather than only how many ran.
    """
    skill = d.get("skill", "chat")
    action = d.get("action", "")
    global _last_refused
    _last_refused = False
    started = time.time()
    trace = route_trace.current()
    if trace is not None:
        trace.note_capability(skill, action)
    try:
        reply = _dispatch_inner(d, user_text, history)
        # NOTHING may return silence. A skill that returns "" or None reaches
        # the speaker as no reply at all, which from the user's side is
        # identical to not being heard -- the single most common complaint
        # about this assistant, and the hardest to diagnose because there is
        # no error and no log line.
        #
        # Found in exactly that state: "unlock argus" returned auth.verify()'s
        # empty message when AUTH_ENABLED was False. This is the backstop, so
        # the next skill to do it is merely awkward rather than invisible.
        if reply is None or not str(reply).strip():
            action = d.get("action", "")
            print(f"[route] {skill}/{action} returned an empty reply")
            security.security_event(security.TOOL_DENIED, skill=skill,
                                    action=action or "-", reason="empty_reply",
                                    status="failed")
            reply = "I did that, but I don't have anything to report back."

        # A staged action must not silence the rest of the assistant. ARGUS
        # answers the question that was actually asked and MENTIONS what is
        # still waiting, rather than refusing everything until the
        # confirmation window expires. See intent.py's power block.
        if skill != "power":
            try:
                if power_skill.has_pending():
                    reply = (f"{str(reply).rstrip('.')}. "
                             f"By the way, I'm still waiting for the PIN to "
                             f"confirm that power request — or say cancel.")
                elif service_skill.has_pending():
                    reply = (f"{str(reply).rstrip('.')}. "
                             f"By the way, I'm still waiting for the PIN to "
                             f"confirm that service change — or say cancel.")
                elif env_skill.has_pending():
                    reply = (f"{str(reply).rstrip('.')}. "
                             f"By the way, I'm still waiting for the PIN to "
                             f"confirm that environment variable change — or "
                             f"say cancel.")
            except Exception:
                pass

        # Same shape, for a plan paused mid-run (see _NEEDS_AUTH /
        # _run_steps). If the pause was specifically "the machine was
        # locked" and it verifiably is not locked any more, this SILENTLY
        # continues the plan and folds the result in -- see
        # _maybe_resume_paused_plan()'s own docstring for why only that one
        # pause class resumes automatically. Any other pause reason just
        # gets restated, the same reminder shape as power's above.
        if skill != "plan":
            try:
                resumed = _maybe_resume_paused_plan()
                if resumed:
                    reply = f"{str(reply).rstrip('.')}. Also — {resumed}"
                elif plan_paused_pending():
                    reply = (f"{str(reply).rstrip('.')}. By the way, I've still "
                            f"got a task paused, waiting: {_plan_paused['reason']}")
            except Exception:
                pass
        telemetry.record(skill, action,
                         "refused" if _last_refused else "ok",
                         (time.time() - started) * 1000.0, via)
        if not _last_refused:
            # Bounded, in-memory, best-effort pattern signal for workflow
            # suggestions -- same "never raises, never
            # blocks the reply" shape telemetry.record itself follows.
            personalize_skill.note_dispatch(skill, action, d.get("target", ""))
        if trace is not None:
            _note_dispatch_result(trace, skill, action, started)
        return reply
    except Exception as e:
        print(f"[dispatch] {skill}: {type(e).__name__}: {e}")
        telemetry.record(skill, action, "failed",
                         (time.time() - started) * 1000.0, via)
        if trace is not None:
            trace.capability_done("failed", (time.time() - started) * 1000.0)
            trace.fail(type(e).__name__)
        return f"The {skill} skill hit a problem: {e}"


def _note_dispatch_result(trace, skill: str, action: str, started: float) -> None:
    """What a finished dispatch means for the request trace: a refusal (the
    authorization gate, a confirmation, the egress veto) ends it DENIED, and a web
    lookup that was allowed to run is counted, so a request that left the machine
    says so. Recording only."""
    ms = (time.time() - started) * 1000.0
    try:
        if _last_refused:
            trace.capability_done("refused", ms)
            trace.deny("refused by policy, authentication or confirmation")
            return
        trace.capability_done("ok", ms)
        if cloud_gate.is_web_lookup(skill, action):
            trace.note_web(skill)
    except Exception:   # noqa: BLE001 -- instrumentation never affects a request
        pass


def dispatch_known(skill: str, action: str, target: str = "") -> str:
    """Runs an ALREADY-RESOLVED (skill, action, target) through the exact
    same _dispatch() every spoken command goes through -- same
    auth.authorize() gate, same audit, same empty-reply backstop.

    For a caller that isn't classifying a fresh utterance but already knows
    the pair it wants to run -- scheduler_skill's background executor is the
    reason this exists, so a scheduled task gets IDENTICAL authorization to
    a live one (locked machine, stale re-auth, an L3 gate -- all apply
    exactly as they would to the same command spoken aloud) rather than a
    second, parallel execution path with its own chance to be more
    permissive. NOT a way around _dispatch()'s own rules: this is the same
    front door, just reachable without a user_text string to parse first.
    """
    return _dispatch({"skill": skill, "action": action, "target": target}, "", None)


# ── what just ran, for the HUD ───────────────────────────────────────────────
#
# ARGUS's skills were invisible: you spoke, a sentence came back, and nothing
# said WHICH of thirty-odd capabilities produced it. That matters beyond
# curiosity -- when a command is misrouted, the reply is often plausible
# enough that the only clue is the answer feeling slightly off. Seeing
# "PRIVACY WATCH" light up when you asked about your camera is confirmation;
# seeing "CHAT" light up is the bug, immediately.
#
# Recorded here rather than returned through handle(), whose signature the
# voice process also uses. Single-user, one command at a time by construction
# (the HUD disables its input while busy and the voice pipeline is serial), so
# a last-value slot is honest; it is not a queue and does not pretend to be.
_last_dispatch = {"skill": "", "action": "", "at": 0.0}


def last_dispatch() -> dict:
    return dict(_last_dispatch)


def last_refused() -> bool:
    """Whether the most recently serialized dispatch was policy-refused.

    This is display metadata for the local HUD response, not an authorization
    signal: authorization has already completed in ``_dispatch_inner``.
    """
    return bool(_last_refused)


# The authorization gate's everyday prompts, word for word: auth.LOCKED_MESSAGE,
# the L2 freshness refusal, auth.stage_confirmation(). Not a sign of anyone
# probing -- see the zero-trust intake in _dispatch_inner().
_AUTH_PROMPT = re.compile(
    r"is locked\. authenticate|needs you to authenticate again|needs confirming\. say", re.I)

# Keep this dispatch list explicit for frozen builds without source inspection.
_DISPATCHED_SKILLS = frozenset({
    "anomaly", "apps", "audit", "auth", "briefing", "browser", "calc", "chat",
    "cleanup", "context", "control", "dev", "diag", "document", "email",
    "env_var", "face", "files", "gesture", "goals", "health", "history",
    "intel", "knowledge", "lockdown", "monitor", "net", "netconfig", "pc",
    "persistence", "personalize", "phone", "plan", "power", "privacy",
    "privacy_watch", "proactive", "profile", "remedy", "research", "schedule",
    "security", "security_log", "service", "social", "storage", "sysext",
    "system", "timer", "usb", "vault", "vision", "watched", "weather",
    "web", "window", "youtube", "zt",
})


def _dispatch_inner(d: dict, user_text: str, history: list | None) -> str:
    skill = d.get("skill", "chat")
    action = d.get("action", "reply")
    target = str(d.get("target", "") or "")
    _last_dispatch.update(skill=skill, action=action, at=time.time())


    # authorization gate on purpose. It is the owner's emergency stop and
    # must work while locked, degraded, or otherwise contained -- and it is
    # safe to leave ungated because the action can only STOP things: grants
    # are revoked, staged plans are dropped, watchers suspend, and nothing
    # whatsoever is started. The intent matcher pins it to explicit phrases;
    # a model producing it uninvited merely stops its own work, which is the
    # fail-safe direction.
    if skill == "security" and action == "killall":
        return plan_kill_switch()

    # ROUTING CORRECTION, BEFORE ENFORCEMENT. A question the model mislabelled
    # as profile/remember or profile/forget was never one of those commands, so
    # it must not be authorized as one. profile/forget is L3_CONFIRM: reaching
    # authorize() first meant "why do you know that" was answered with "that
    # needs confirming. Say 'confirm' to go ahead with forget why do you know
    # that" -- staging a confirmation for a forget the user never asked for.
    #
    # Safe to sit ahead of the gate because the ONLY outcome is falling through
    # to ordinary conversation, which is strictly LESS privileged than the
    # command being corrected away from. It can never escalate; it can only
    # downgrade a misclassification into chat.
    if skill == "profile" and action in ("remember", "forget") \
            and _looks_like_a_question(target):
        return brain.answer(user_text, history)

    # Same correction, same reasoning: a skill no branch below handles -- the
    # local classifier inventing one ("charging bay/send", "argus academy/
    # enroll", "status/list" are real entries from the owner's audit log) --
    # ends in brain.answer() at the bottom of this function anyway. Asking for
    # the PIN first (such a pair rides auth's fail-closed DEFAULT_LEVEL) meant
    # authenticating for a command that could never run: the owner's "it asks
    # for my PIN even when there's no need" (2026-09-24). Only ever a
    # downgrade to conversation; a skill that EXISTS still meets the gate.
    if skill not in _DISPATCHED_SKILLS:
        print(f"[route] no skill '{skill}' -- answering as conversation")
        return brain.answer(user_text, history)

    # THE ROUTING-POLICY VETO -- the last of three places a local request is kept
    # off the web (the others: _resolve() drops a web fast-path for one, and
    # _decide() filters what the local classifier may pick). This is the one that
    # holds for EVERY caller, because everything that runs a skill comes through
    # here: the fast path, the model's choice, a chain step, a follow-up, and a
    # skill that fell through to another skill.
    #
    # Before authorization, not after: it is a routing refusal with no side
    # effects, so a locked machine should not be asked to authenticate for
    # something that was never going to run, and a vetoed request must not become
    # the context an elliptical follow-up resolves against (followup_skill.record
    # is below). Outside a request -- a scheduled task, a background check -- no
    # scope is set and this does nothing, which is right: those are things the
    # owner explicitly asked for by name.
    #
    # Check egress scope before dispatch; this predicate can only deny.
    scope = _egress_scope(skill, action)
    if scope is not None:
        return _withhold_web(skill, action, scope)

    # ENFORCEMENT. The ONLY place authorization is decided, and it is decided
    # from the (skill, action) pair the dispatcher is about to act on -- never
    # from anything the model asserted about its own permissions. See auth.py's
    # AUTHORIZATION header.
    #
    # Placed before followup_skill.record() below so a REFUSED command does not
    # become the context an elliptical follow-up ("do it again") resolves
    # against, which would let a denial be replayed into an approval.
    allowed, reason = auth.authorize(skill, action, target)
    if not allowed:
        global _last_refused
        _last_refused = True
        # Zero-trust intake: a refusal is one of the signals the session
        # score is built from. Never raises into dispatch. NOT the everyday
        # prompts -- "unlock first", "authenticate again", "say confirm":
        # those are the owner's normal flow, and counting them dropped the
        # session into zt's low band, where the NEXT command demanded a fresh
        # PIN, which was another refusal... (the spiral the owner hit,
        # 2026-09-24). Anything else a refusal says -- stronger auth, safe
        # mode, push-to-talk, zt's own verdict -- still counts.
        if not _AUTH_PROMPT.search(reason):
            try:
                import zt
                zt.note_denied()
            except Exception:
                pass
        security.audit("blocked",
                       f"{auth.describe_level(skill, action)} denied", reason[:60])
        # Taxonomised alongside the free-text audit line, not instead of it:
        # the audit log is what the user hears back from "what have you done",
        # while this is the queryable record. A denial at L3 or above is
        # reported as an escalation attempt rather than a routine refusal --
        # those are the ones worth counting, since asking for a shutdown
        # while locked is a different event from asking for the weather.
        lvl = auth.level_for(skill, action)
        security.security_event(
            security.PRIVILEGE_ESCALATION_ATTEMPT if lvl >= auth.L3_CONFIRM
            else security.TOOL_DENIED,
            skill=skill, action=action or "-", level=lvl, status="failed")
        return reason
    auth.touch()


    # Sits after authorize() and before ANY skill runs: if an action-hash-bound
    # grant was staged for this exact action (a confirmed L3+ command, or a
    # plan step under its staged-plan approval), it is re-verified NOW against
    # what is actually about to execute. A substituted target, a mutated
    # argument, or a replayed token refuses here, at the last possible moment,
    # instead of trusting an approval that may no longer describe the action.
    # No grant pending is the NORMAL shape (L0-L2 actions); the redeem can
    # only refuse, never allow, so a grants-layer failure is a denial, not a
    # fallback (section 25).
    _tok = auth.pop_grant(skill, action, target)
    if _tok:
        import grants
        _ok, _why = grants.redeem(_tok, skill, action, target)
        if not _ok:
            _last_refused = True
            try:
                import zt
                zt.note_denied()
            except Exception:
                pass
            security.audit("blocked", f"grant redeem refused {skill}/{action}",
                           _why[:60])
            return f"That no longer matches what was approved, so I've stopped: {_why}"

    # Remember what was just acted on so an elliptical follow-up ("close it",
    # "what about tomorrow") can be resolved against it. Recorded here rather
    # than at the call sites so every route -- fast path, LLM path and the
    # clarify re-dispatch -- is covered by one line. followup_skill decides
    # for itself which skills are worth remembering.
    followup_skill.record(skill, action, target)

    # Hybrid cloud routing: if this exchange touches the machine or the person's
    # data, start the sticky window now, before dispatch, so even a follow-up
    # said WHILE this request is still running (a fast one) is covered -- and
    # flag the exchange local, so main.py files the reply into history as
    # something no hosted model may ever be shown as "context".
    #
    # "Touches the machine" is now everything EXCEPT the skills whose output is
    # public information (see cloud_gate.is_local_required_skill). It used to be
    # a short allowlist, so a document read or an email search left no mark at
    # all and its reply went into history as ordinary conversation. Marking
    # doesn't depend on whether the dispatch below succeeds -- the skill/action
    # pair alone is what makes it sensitive, not its outcome.
    if cloud_gate.is_local_required_skill(skill, action):
        cloud_gate.mark_local_exchange()

    if skill == "apps":
        if action == "open":
            return apps_skill.open_app(target)
        if action == "close":
            return apps_skill.close_app(target)
        if action == "list":
            return apps_skill.list_running()
        if action == "save_workspace":
            return apps_skill.save_workspace(target)
        if action == "restore_workspace":
            return apps_skill.restore_workspace(target)
        if action == "list_workspaces":
            return apps_skill.list_workspaces()
        if action == "forget_workspace":
            return apps_skill.forget_workspace(target)

    if skill == "weather":
        return weather_skill.get_weather(target)

    if skill == "research":
        return research_skill.research(target, deep=(action == "deep"))

    if skill == "web":
        if action == "open_url":
            # target comes from the language model. webbrowser.open() will hand
            # file://, javascript: or any registered protocol handler to the
            # default browser, so the scheme is checked before it gets there.
            ok, resolved = execpolicy.check_url(target)
            if not ok:
                return resolved
            web_skill.open_in_preferred_browser(resolved)
            return "Opening it now."
        # show_page=True: this arm is reached only when the user explicitly
        # asked to look something up, which is the case the browser-opening
        # behaviour exists for. brain.answer()'s silent escalation uses the
        # default (False) -- see research_skill.quick_answer().
        return research_skill.quick_answer(target, show_page=True)

    if skill == "youtube":
        return web_skill.play_youtube(target)

    if skill == "profile":
        if action == "remember":
            # BUGFIX, found in the real audit log: "WHO AMI" (Whisper running
            # "who am i" together) and "why are you red" both got routed here
            # by the LLM classifier and stored VERBATIM as facts about the
            # user -- then read back as real personal information on every
            # later "who am i". Both were questions, not statements, and the
            # LLM router misjudged them; a starts-with-a-question-word check
            # is intent.py's own fast-path route to profile/summary already
            # trusts for the same words, just applied here as a guard instead
            # of a router. This only touches the LLM-inferred path -- explicit
            # dictation ("remember that I...") is parsed by intent.py's own
            # regex, which can never capture a bare question word first, so
            # a genuine "remember that I like coffee" is never at risk here.
            #
            # A caught question isn't discarded with an error -- it's very
            # likely a real question that deserves a real answer, so it falls
            # through to the same brain.answer() path anything else
            # unmatched reaches, instead of a dead end either way.
            if _looks_like_a_question(target):
                return brain.answer(user_text, history)
            return profile_skill.remember(target, d.get("reply", "About"))
        if action == "summary":
            return profile_skill.summary()
        if action == "forget":
            # Same failure shape as remember above, same real incident even:
            # "Yeah, I'm done." was misrouted to forget("user is done") by the
            # LLM router, and profile_skill.forget() -- which has no way to
            # know the target is nonsense -- correctly reported finding
            # nothing, producing a reply utterly disconnected from what was
            # actually said 16 seconds earlier. forget() doesn't corrupt
            # storage the way remember() did, so this is lower-stakes, but
            # it's the identical bug: a misclassified question/statement
            # deserves a real answer, not a guaranteed-confusing non-match.
            if _looks_like_a_question(target):
                return brain.answer(user_text, history)
            return profile_skill.forget(target)

    if skill == "personalize":
        reply_arg = d.get("reply", "")
        if action == "set_preference":
            return personalize_skill.set_preference(target, reply_arg)
        if action == "set_alias":
            return personalize_skill.set_alias(target, reply_arg)
        if action == "forget":
            key = (target or "").strip().lower().replace(" ", "_")
            if key in personalize_skill.KNOWN_PREFERENCE_KEYS:
                return personalize_skill.forget_preference(key)
            return personalize_skill.forget_alias(target)
        if action == "confirm_workflow":
            pending = personalize_skill.pending_suggestions()
            if not pending:
                return "There's no workflow suggestion waiting on an answer."
            s = pending[-1]
            return personalize_skill.create_workflow(
                f"workflow {s['suggestion_id'][:6]}", s["actions"],
                description="Learned from repeated use.", source="SUGGESTED",
                suggestion_id=s["suggestion_id"])
        if action == "reject_workflow":
            pending = personalize_skill.pending_suggestions()
            if not pending:
                return "There's no workflow suggestion waiting on an answer."
            return personalize_skill.reject_suggestion(pending[-1]["suggestion_id"])
        if action == "run_workflow":
            out = personalize_skill.run_workflow(target)
            if not out["ok"]:
                return out["error"]
            return f"Ran the \"{target}\" workflow — {len(out['results'])} step{'s' if len(out['results']) != 1 else ''} done."
        if action == "delete_workflow":
            return personalize_skill.delete_workflow(target)
        if action == "explain":
            return personalize_skill.explain(target)
        return personalize_skill.summary()

    if skill == "vault":
        if action == "write":
            return vault_skill.write_note(target or "note", d.get("reply", user_text))
        if action == "search":
            return vault_skill.search(target)
        if action == "read":
            return vault_skill.read_recent()

    if skill == "timer":
        if action == "list":
            return timer_skill.list_pending()
        if action == "cancel":
            return timer_skill.cancel(target)
        try:
            return timer_skill.set_timer(int(float(target)), d.get("reply", "Timer done."))
        except (ValueError, TypeError):
            return "I couldn't work out how long to set that for."

    if skill == "storage":
        try:
            if action == "analyze":
                return storage_skill.analyze(target)
            if action == "largest":
                return storage_skill.largest(target)
            return storage_skill.free_space(target)
        except Exception as e:
            return f"I couldn't check the disks: {e}"

    if skill == "pc":
        try:
            if action == "stop_speaking":
                # Also clears a staged power action, a pending file
                # deletion, and a pending disambiguation question —
                # "cancel" should mean cancel, whatever's actually pending.
                if power_skill.has_pending():
                    power_skill.cancel()
                if files_skill.has_pending_delete():
                    files_skill.cancel_delete()
                if browser_skill.has_pending():
                    browser_skill.cancel()
                if email_skill.has_pending():
                    email_skill.cancel()
                if service_skill.has_pending():
                    service_skill.cancel()
                if env_skill.has_pending():
                    env_skill.cancel()
                if plan_paused_pending():
                    cancel_paused_plan()
                if clarify_skill.has_pending():
                    clarify_skill.cancel()
                return pc_skill.stop_speaking()
            if action == "stats":
                return pc_skill.system_stats()
            if action == "battery":
                return pc_skill.battery()
            if action == "uptime":
                return pc_skill.uptime()
            if action == "snapshot":
                return pc_skill.snapshot()
            if action == "lock":
                return pc_skill.lock_screen()
            if action == "time":
                return pc_skill.what_time()
            if action == "last_task":
                return pc_skill.last_task()
            # ── UI automation ───────────────────────────────────────────────
            # Reading a window's controls is a report; pressing one changes
            # the world. Both sit at DEFAULT_LEVEL (L2_REAUTH) because pc has
            # no wildcard in auth.LEVELS -- and for the acting half that is
            # exactly right. See pc_skill's UI AUTOMATION header for the three
            # rules that bound it.
            if action == "focused":
                return pc_skill.whats_focused()
            if action == "ui_tree":
                return pc_skill.ui_tree(target)
            if action == "ui_read":
                name, _, win = (target or "").partition(" in ")
                return pc_skill.ui_read(name.strip(), win.strip())
            if action == "ui_click":
                name, _, win = (target or "").partition(" in ")
                return pc_skill.ui_click(name.strip(), win.strip())
            if action == "ui_confirm":
                return pc_skill.ui_confirm_click()
            if action == "ui_cancel":
                return pc_skill.ui_cancel()
            if action == "ui_type":
                # "<text> into <field>" -- the field is named last because
                # that is how people say it out loud.
                text, _, field = (target or "").rpartition(" into ")
                if not field:
                    return ("Say it as: type <what> into <which field>.")
                return pc_skill.ui_type(field.strip(), text.strip())
            # Part 2: the interactions a real application needs. Every acting
            # one is gated at L2 by the fail-closed default and staged on a
            # destructive-looking name; the reading ones (table, dialog,
            # verify, wait) change nothing.
            if action == "ui_double_click":
                return pc_skill.ui_double_click(target)
            if action == "ui_right_click":
                return pc_skill.ui_right_click(target)
            if action == "ui_hover":
                return pc_skill.ui_hover(target)
            if action == "ui_drag":
                src, _, dst = (target or "").partition("|")
                return pc_skill.ui_drag(src.strip(), dst.strip())
            if action == "ui_scroll":
                d, _, rest = (target or "down").partition("|")
                return pc_skill.ui_scroll(d.strip() or "down", 3, rest.strip())
            if action == "ui_select":
                item, _, container = (target or "").partition("|")
                return pc_skill.ui_select(item.strip(), container.strip())
            if action == "ui_slider":
                name, _, val = (target or "").partition("|")
                try:
                    return pc_skill.ui_set_slider(name.strip(), float(val))
                except ValueError:
                    return "Say it as: set <slider> to <number>."
            if action == "ui_toggle":
                name, _, want = (target or "").partition("|")
                w = {"on": True, "off": False}.get(want.strip().lower())
                return pc_skill.ui_toggle(name.strip(), want=w)
            if action == "ui_expand":
                return pc_skill.ui_expand(target)
            if action == "ui_collapse":
                return pc_skill.ui_expand(target, collapse=True)
            if action == "ui_table":
                return pc_skill.ui_table(target)
            if action == "ui_dialog":
                return pc_skill.ui_dialog()
            if action == "ui_wait":
                return pc_skill.ui_wait(target)
            if action == "ui_verify":
                name, _, expect = (target or "").partition("|")
                return pc_skill.ui_verify(name.strip(), expect.strip())
            if action == "ui_screenshot":
                return pc_skill.ui_screenshot(target)

            # ── local machine controls ──────────────────────────────────────
            # All Win32 through ctypes or a registry read; nothing spawns a
            # process and nothing leaves the machine. Each sits at
            # DEFAULT_LEVEL (L2_REAUTH) because pc has no wildcard in
            # auth.LEVELS -- correct for the ones that CHANGE something, and
            # heavier than it needs to be for the read-only ones, which is the
            # same KNOWN_ACTIONS gap noted against diag.
            if action == "keep_awake":
                return pc_skill.keep_awake(True)
            if action == "allow_sleep":
                return pc_skill.keep_awake(False)
            if action == "awake_status":
                return pc_skill.awake_status()
            if action == "empty_bin":
                # Measures and asks. The confirming half is a separate action,
                # so classifying this can never empty anything.
                return pc_skill.empty_recycle_bin(confirm=False)
            if action == "empty_bin_confirm":
                return pc_skill.empty_recycle_bin(confirm=True)
            if action == "dark_mode":
                return pc_skill.dark_mode(True)
            if action == "light_mode":
                return pc_skill.dark_mode(False)
            if action == "theme":
                return pc_skill.dark_mode(None)
            if action == "display":
                return pc_skill.display_info()
            if action == "sysinfo":
                return pc_skill.system_info()
            if action == "installed":
                return pc_skill.installed_programs(target)
            if action == "pin_window":
                return pc_skill.window_on_top(target, True)
            if action == "unpin_window":
                return pc_skill.window_on_top(target, False)
            if action == "stop_processes":
                # STAGES only. The offer names what it would stop and asks;
                # pc/confirm_stop is the half that acts, and both sit at
                # DEFAULT_LEVEL (L2_REAUTH) because ("pc", "stop_processes")
                # has no entry in auth.LEVELS and pc has no wildcard -- the
                # fail-closed default doing exactly the right thing for
                # something that ends running programs.
                return pc_skill.stage_stop(target)
            if action == "confirm_stop":
                return pc_skill.confirm_stop()
            if action == "cancel_stop":
                return pc_skill.cancel_stop()
            if action == "heavy":
                rows = pc_skill.stoppable(limit=5)
                if not rows:
                    return ("Nothing outside Windows' own services is using "
                            "much right now, Boss.")
                listed = "; ".join(f"{r['name']} at {r['cpu']} percent and "
                                   f"{int(r['mb'])} megabytes" for r in rows[:3])
                return (f"The heaviest things I could stop are {listed}. "
                        f"Say \"stop unused processes\" and I'll offer a list.")
            if action == "timezone":
                # SETTING the clock is a configuration change and lands on
                # DEFAULT_LEVEL (L2_REAUTH) -- ("pc", "timezone") is not in
                # auth.LEVELS and pc has no wildcard, so it fails closed. That
                # is the right gate for this: it changes what every later
                # answer about time means. READING it rides pc/time, which is
                # L0, so "what timezone are you using" costs nothing.
                if not (target or "").strip():
                    st = pc_skill.timezone_status()
                    if st["following_machine"]:
                        return (f"I'm following this machine's own clock — "
                                f"{st['effective']}, and it's {st['now'][11:16]} "
                                f"right now. Say \"set timezone to\" and a "
                                f"region and city to pin it.")
                    return (f"I'm using {st['configured']}, so it's "
                            f"{st['now'][11:16]} for you. Say \"set timezone "
                            f"to automatic\" to follow the machine again.")
                return pc_skill.set_timezone(target)
            if action == "media":
                return pc_skill.media(target)
            if action == "screen_record":
                return pc_skill.toggle_screen_recording()
            if action == "camera_status":
                return pc_skill.camera_status()
            if action == "power_plan":
                return pc_skill.power_plan(target)
            if action == "dictate":
                return pc_skill.dictate(target)
            # Continuous dictation. Authorized here like every other action;
            # what goes back is a sentinel the voice process obeys, because
            # the transcript lives on that side. Every chunk it then types
            # still passes execpolicy.check_dictation -- the mode changes
            # WHEN text is typed, never what is allowed to be typed.
            if action in ("dictate_on", "dictate_off"):
                return pc_skill.dictate_mode(action == "dictate_on")
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "control":
        try:
            if action == "volume_set":
                return control_skill.volume_set(int(float(target)))
            if action == "volume_up":
                return control_skill.volume_adjust(10)
            if action == "volume_down":
                return control_skill.volume_adjust(-10)
            if action == "mute":
                return control_skill.mute(True)
            if action == "unmute":
                return control_skill.mute(False)
            if action == "brightness_set":
                return control_skill.brightness_set(int(float(target)))
            if action == "clipboard_read":
                return control_skill.clipboard_read()
            if action == "clipboard_write":
                return control_skill.clipboard_write(target)
            if action == "mic_mute":
                return control_skill.mic_mute(True)
            if action == "mic_unmute":
                return control_skill.mic_mute(False)
            if action == "mic_status":
                return control_skill.mic_status()
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "power":
        if action == "request":
            return power_skill.request(target)
        if action == "pending_reminder":
            # Something is staged and the user said something that is not a
            # PIN and not a cancellation. Say so WITHOUT touching the attempt
            # counter -- see intent.py: forwarding ordinary speech to confirm
            # burned three attempts on "you awake", "you look great" and
            # "hey there", then locked the user out.
            if not power_skill.has_pending():
                return brain.answer(user_text, history)
            return ("I'm still waiting for the PIN to confirm that. "
                    "Say the digits, or say cancel.")
        if action == "confirm":
            # BUGFIX: "yes" previously always routed here, so saying yes in any
            # other context got "there's nothing waiting for confirmation".
            # With nothing staged, treat it as ordinary conversation.
            if not power_skill.has_pending():
                return brain.answer(user_text, history)
            # target carries whatever the user actually typed/said (a PIN
            # attempt, or "yes", or gibberish) -- power_skill checks it
            # against config.COMMAND_PIN itself. A bare "yes" reaches here
            # with target="" and correctly fails the PIN check.
            return power_skill.confirm(target)
        if action == "cancel":
            # A bare "cancel" reaches here regardless of what's ACTUALLY
            # pending -- intent.py routes every cancel-word to power/cancel
            # unconditionally (see its own comment on why a files-specific
            # cancel check would be unreachable dead code otherwise). So
            # this also clears a pending file deletion, same shape as
            # pc/stop_speaking clearing power+files+clarify together above.
            # Reports the file cancellation specifically when there was one
            # -- power_skill.cancel()'s own "Nothing to cancel" would
            # otherwise silently swallow the fact that something WAS just
            # cancelled, just not the thing that message is about.
            # A staged REPAIR offer is cleared here too, for the same reason
            # the file deletion is: this is the universal "call it off" path,
            # and an offer left armed after the user said cancel is an offer a
            # later "yes" could still land on.
            try:
                from threatmon import remedy as _remedy
                if _remedy.pending():
                    _remedy.cancel()
            except Exception:
                pass
            if plan_is_pending():
                cancel_plan()
            if files_skill.has_pending_delete():
                file_result = files_skill.cancel_delete()
                power_skill.cancel()
                return file_result
            if browser_skill.has_pending():
                browser_result = browser_skill.cancel()
                power_skill.cancel()
                return browser_result
            if email_skill.has_pending():
                email_result = email_skill.cancel()
                power_skill.cancel()
                return email_result
            # A staged SERVICE or ENVIRONMENT-VARIABLE write is cleared by the
            # same universal "call it off" path -- an armed service stop that
            # survived a later "cancel" would be the same class of surprise as
            # a deletion that did. Report the service/variable cancellation
            # specifically, exactly like the file/browser/email blocks above.
            if service_skill.has_pending():
                service_result = service_skill.cancel()
                power_skill.cancel()
                return service_result
            if env_skill.has_pending():
                env_result = env_skill.cancel()
                power_skill.cancel()
                return env_result
            if plan_paused_pending():
                plan_result = cancel_paused_plan()
                power_skill.cancel()
                return plan_result
            return power_skill.cancel()

    if skill == "diag":
        # "What's listening on my machine" is a DIAGNOSTIC, and putting it here
        # rather than under a new skill name is the reason it works at all
        # without an elevated edit to auth.py: ("diag", "*") is already
        # L1_UNLOCKED, which is exactly the sensitivity class this belongs to --
        # the same one anomaly/check and security/summary sit in. A new skill
        # name would have fallen to DEFAULT_LEVEL (L2_REAUTH) and demanded a
        # fresh PIN to answer a read-only question.
        if action == "fixes":
            # The READ half of guided repair: what could be repaired, without
            # staging or running anything. L1 because it is a report; the
            # acting half is remedy/* at L2. See the remedy branch below.
            try:
                from threatmon import remedy as _remedy
                found = _remedy.latest_fixable()
                if not found:
                    return ("Nothing needs repairing right now, Boss — "
                            "nothing recent that I have a safe fix for.")
                keys = _remedy.available_for(found)
                spec = _remedy.FIXES[keys[0]]
                return (f"I could {spec['describe'](found)}. Say \"fix it\" "
                        f"and I'll ask you to confirm first.")
            except Exception as e:
                return (f"I couldn't work out what's repairable right now "
                        f"({type(e).__name__}).")
        if action == "changes":
            # One answer over five baseline-diff detectors. Composed locally by
            # threatmon for the same reason security/summary is -- and it is a
            # DIFFERENT question from that one: the summary is posture, this is
            # events in the order they happened.
            try:
                import threatmon
                hours = 24.0
                # "in the last N hours/days", when the phrase carried one.
                m = re.search(r"(\d{1,3})\s*(hour|day|week)", target or "")
                if m:
                    n = int(m.group(1))
                    hours = n * {"hour": 1, "day": 24, "week": 168}[m.group(2)]
                    hours = min(hours, 24 * 30)     # the record is bounded
                return threatmon.changes_report(hours)
            except Exception as e:
                return (f"I couldn't put together a change report right now "
                        f"({type(e).__name__}).")
        if action == "process":
            # The natural follow-up to diag/ports ("something is listening on
            # 5432" -> "what IS postgres"). Composed locally by the detector
            # suite: what is running on this machine, where it lives and what
            # it is connected to is telemetry about the machine, and the
            # command line it reports is redacted at source before it is ever
            # spoken. See threatmon/procinfo.py.
            try:
                from threatmon import procinfo as _procinfo
                return _procinfo.report(target)
            except Exception as e:
                return (f"I couldn't look at that process right now "
                        f"({type(e).__name__}).")
        if action == "defenses":
            # Same rule as ports below and as security/summary: which of this
            # machine's protections are on is telemetry about this machine, so
            # it is composed by the detector and never handed to a model.
            try:
                from threatmon import defenses as _defenses
                return _defenses.report()
            except Exception as e:
                return (f"I couldn't read your security settings right now "
                        f"({type(e).__name__}).")
        if action == "ports":
            # Composed locally by the detector, never by a model. What accepts
            # connections on this machine is telemetry about it, and it must
            # not travel to a third party just to be phrased nicely -- the same
            # rule network_skill.outbound() and persistence.report() follow.
            try:
                from threatmon import listening as _listening
                return _listening.report()
            except Exception as e:
                return (f"I couldn't read the socket table right now "
                        f"({type(e).__name__}).")
        return diagnostics.run_diagnostics(verbose=True)

    if skill == "net":
        if action == "online":
            return network_skill.is_online()
        if action == "wifi":
            return network_skill.wifi_info()
        if action == "ip":
            return network_skill.local_ip()
        if action == "data":
            return network_skill.data_usage()
        if action == "wifi_on":
            return network_skill.wifi_set(True)
        if action == "wifi_off":
            return network_skill.wifi_set(False)

    if skill == "window":
        if action == "focus":
            return window_skill.focus(target)
        if action == "minimize":
            return window_skill.minimize(target)
        if action == "maximize":
            return window_skill.maximize(target)
        if action == "minimize_all":
            return window_skill.minimize_all()
        if action == "list":
            return window_skill.list_windows()
        if action == "snap":
            # "<window>|<side>" -- the pipe is chosen because a window title
            # can contain almost anything else, including commas, dashes and
            # the word "on".
            name, _, side = (target or "").partition("|")
            return window_skill.snap(name.strip(), side.strip())
        if action == "arrange":
            # "<window>|<side>;<window>|<side>"
            pairs = []
            for part in (target or "").split(";"):
                name, _, side = part.partition("|")
                if name.strip():
                    pairs.append((name.strip(), side.strip()))
            return window_skill.arrange(pairs)

    if skill == "files" and action in ("move", "copy", "rename", "mkdir",
                                       "compress", "extract", "metadata",
                                       "recent", "duplicates"):
        # FILE OPERATIONS. Every one is confined to the search roots and
        # refuses anything inside ARGUS's own installation -- see
        # files_skill's FILE OPERATIONS header. None of them deletes:
        # deletion stays at files/delete, L4, behind a PIN, to the Recycle Bin.
        #
        # target carries "<what> -> <where>" for the two-argument operations,
        # split here rather than in the skill so the skill's own functions
        # keep a plain (query, destination) signature that a test can call.
        src, _, dest = (target or "").partition("|")
        src, dest = src.strip(), dest.strip()
        if action == "move":
            return files_skill.move(src, dest)
        if action == "copy":
            return files_skill.copy(src, dest)
        if action == "rename":
            return files_skill.rename(src, dest)
        if action == "mkdir":
            return files_skill.make_folder(src, dest)
        if action == "compress":
            return files_skill.compress(src, dest)
        if action == "extract":
            return files_skill.extract(src, dest)
        if action == "metadata":
            return files_skill.metadata(src)
        if action == "permissions":
            return files_skill.permissions(target)
        if action == "content_search":
            return files_skill.content_search(target)
        if action == "recent":
            m = re.search(r"(\d{1,3})\s*(hour|day)", target or "")
            hours = (int(m.group(1)) * (24 if m.group(2) == "day" else 1)
                     if m else 24)
            return files_skill.recent(min(hours, 24 * 14))
        if action == "duplicates":
            return files_skill.duplicates()

    if skill == "files":
        if action == "inspect":
            # Answered from what Windows itself knows -- signature, origin,
            # age. Never a hash sent to a reputation service: a hash is an
            # identifier, and it would tell a third party which files you have.
            return files_skill.inspect(target)
        if action == "open":
            return files_skill.open_file(target)
        if action == "delete":
            return files_skill.stage_delete(target)
        if action == "confirm_delete":
            if not files_skill.has_pending_delete():
                return brain.answer(user_text, history)
            return files_skill.confirm_delete(target)
        if action == "cancel_delete":
            return files_skill.cancel_delete()
        if action == "restore":
            return files_skill.restore(target)
        if action == "confirm_restore":
            return files_skill.restore_confirm(target)
        if action == "cancel_restore":
            return files_skill.restore_cancel()
        if action == "create":
            reply = d.get("reply", "")
            return files_skill.create(target, reply)
        return files_skill.find(target)

    if skill == "browser":
        try:
            if action == "task":
                # The website-task mode: route the GOAL (not a single browser
                # action) through the web-flavoured plan runner. A multi-step
                # "go to the site, log in, find the invoice, download it, put
                # it in my invoices folder" is several of the actions below in
                # a row -- the allowlist for this mode is PLANNABLE |
                # WEB_TASK_ACTIONS, gated at L3 (browser/task), with every
                # staged write inside still pausing for its own PIN. This is
                # the ordinary plan machinery, just given the write steps an
                # ordinary plan deliberately refuses.
                return plan_and_stage(target or user_text, web=True)
            if action == "navigate":
                return browser_skill.navigate(target)
            if action == "search":
                return browser_skill.search(target)
            if action == "tab_open":
                return browser_skill.tab_open(target)
            if action == "tab_close":
                return browser_skill.tab_close(target)
            if action == "tab_switch":
                return browser_skill.tab_switch(target)
            if action == "tab_search":
                return browser_skill.tab_search(target)
            if action == "tab_reorder":
                return browser_skill.tab_reorder()
            if action == "list_tabs":
                return browser_skill.list_tabs()
            if action == "back":
                return browser_skill.back()
            if action == "forward":
                return browser_skill.forward()
            if action == "refresh":
                return browser_skill.refresh()
            if action == "launch":
                return browser_skill.launch()
            if action == "close":
                return browser_skill.close()
            if action == "extract_text":
                return browser_skill.extract_text(target)
            if action == "find_elements":
                return browser_skill.find_elements(target)
            if action == "click":
                return browser_skill.click(target)
            if action == "follow_link":
                return browser_skill.follow_link(target)
            if action == "fill":
                field, _, value = (target or "").partition("|")
                if not value:
                    return "Say it as: fill <field> with <value>."
                return browser_skill.fill(field.strip(), value.strip())
            if action == "screenshot":
                return browser_skill.screenshot(target)
            if action == "zoom":
                try:
                    return browser_skill.zoom(int(float(target)))
                except (ValueError, TypeError):
                    return "What percentage should I zoom to?"
            if action == "downloads":
                return browser_skill.downloads()
            if action == "bookmark_add":
                return browser_skill.bookmark_add(target)
            if action == "bookmarks_list":
                return browser_skill.bookmarks_list()
            if action == "bookmark_remove":
                return browser_skill.bookmark_remove(target)
            if action == "history_search":
                return browser_skill.history_search(target)
            # ── staged: submit / download / upload -- see browser_skill's own
            # module docstring for why these three, and only these three, need
            # a PIN. Each STAGES here; browser_skill.confirm() does the acting
            # half, same split as files_skill.stage_delete/confirm_delete.
            if action == "submit":
                return browser_skill.stage_submit(target)
            if action == "download":
                return browser_skill.stage_download(target)
            if action == "upload":
                field, _, path = (target or "").partition("|")
                if not path:
                    return "Say it as: upload <file> into <field>."
                return browser_skill.stage_upload(field.strip(), path.strip())
            if action == "confirm":
                # Same shape as power/confirm just above: with nothing of
                # browser_skill's own staged, a bare PIN-shaped utterance or a
                # "yes" is ordinary conversation, not a failed confirmation.
                if not browser_skill.has_pending():
                    return brain.answer(user_text, history)
                return browser_skill.confirm(target)
            if action == "cancel":
                return browser_skill.cancel()
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "privacy":
        if action == "on":
            return privacy_skill.enable(int(target) if target.isdigit() else None)
        if action == "off":
            return privacy_skill.disable()
        return privacy_skill.status()

    if skill == "proactive":
        if action == "off":
            # SAY WHAT IT ACTUALLY COVERS. announce._blocked() consults
            # proactive_skill.is_enabled() for EVERY unprompted utterance, not
            # just the nudges -- so turning this off also silences spoken
            # threat alerts, break reminders and the welcome-back line. That is
            # a defensible default (one switch for "stop talking at me"), but
            # it was silent about it, and a user who thinks they muted
            # suggestions has actually muted the credential-access warning too.
            #
            # Detection, logging and the HUD are untouched either way: this
            # silences the speaker, never the sensor, and the reply now says
            # so rather than leaving him to find out by not being told.
            return (proactive_skill.disable().rstrip(".")
                    + ". That covers spoken security alerts as well — I'll "
                    + "still detect and log everything, and it's all on the "
                    + "screen, I just won't say it out loud.")
        return (proactive_skill.enable().rstrip(".")
                + ". Spoken security alerts are back on too.")

    if skill == "auth":
        if action == "lock":
            auth.lock("asked to")
            return "Locked."
        if action == "status":
            s = auth.status()
            if not s["enabled"]:
                return "Authentication is switched off in config."
            if s["locked_out"]:
                return f"Locked out for another {s['lockout_seconds']} seconds."
            return "Unlocked." if s["unlocked"] else auth.LOCKED_MESSAGE
        if action == "unlock":
            # The spoken text carries whatever the user offered -- a PIN, a
            # challenge phrase, or nothing. It is handed to EVERY configured
            # factor rather than parsed into one, so the reply cannot reveal
            # which factor was being checked, let alone which one failed.
            ok, message = auth.verify({name: target
                                       for name in auth.AUTH_REQUIRED_FACTORS})
            if not ok and "liveness" in auth.AUTH_REQUIRED_FACTORS:
                return f"{message} Say: {auth.new_challenge()}"
            # auth.verify() returns (True, "") when AUTH_ENABLED is False --
            # nothing to verify, so nothing to say. Returned as-is, that empty
            # string reached the speaker and "unlock argus" produced SILENCE:
            # no reply, no error, indistinguishable from not being heard.
            return message or ("Authentication is switched off in config, so "
                               "I'm already unlocked.")
        return auth.status().get("unlocked") and "Unlocked." or auth.LOCKED_MESSAGE

    if skill == "remedy":
        # GUIDED REPAIR. A NEW skill name on purpose, and the reason is the
        # fail-closed default: auth.LEVELS has no entry for it, so
        # DEFAULT_LEVEL applies and every action here demands L2_REAUTH -- a
        # PIN typed in the last fifteen minutes. That is exactly the right gate for
        # something that changes the machine, and it costs no edit to auth.py.
        #
        # The split matters too: "what can you fix" is a READ and lives at
        # diag/fixes (L1). Only the acting half is here.
        from threatmon import remedy as _remedy
        if action == "apply":
            return _remedy.apply_pending()
        if action == "cancel":
            return _remedy.cancel()
        return _remedy.offer()

    if skill == "plan":
        # The task loop. A NEW skill name on purpose: auth.LEVELS has no entry,
        # so DEFAULT_LEVEL applies and staging or running a plan needs a fresh
        # authentication. Correct for something that turns one sentence into
        # several actions -- and note that this gate is IN ADDITION to each
        # step being authorised separately as it runs. See the TASK LOOP header.
        if action == "run":
            # The "go ahead" IS the plan's whole-plan approval, so this is
            # where its per-step execution grants are minted (P1, sections
            # 4.2/4.3). uses=MAX_STEP_RETRIES+1: the bounded correction loop
            # may legitimately re-run one step; the grant count-down bounds it
            # with the same ceiling. Minted against the STAGED goal; _run_steps
            # re-derives each step's hash at redemption, so anything that
            # mutated between approval and execution fails closed.
            _mint_plan_grants(goal=_plan.get("goal", ""))
            return run_plan(user_text, history)
        if action == "cancel":
            return cancel_plan()
        if action == "resume":
            return resume_paused_plan(user_text, history)
        if action == "cancel_paused":
            return cancel_paused_plan()
        return plan_and_stage(target or user_text)

    if skill == "audit":
        return security.read_audit(8)

    if skill == "anomaly":
        return anomaly_skill.recent_summary()

    if skill == "phone":
        from skills import phone_skill
        if action == "status":
            s = phone_skill.status()
            if not s["configured"]:
                return ("Phone calling isn't set up yet. Run "
                        "tools/set_phone_secrets.py to add the Twilio details.")
            # Credentials alone are not readiness. On a trial account the
            # words have to come from a TwiML Bin, so without one every call
            # connects and then fails -- and saying "ready" here would be a
            # lie told in exactly the situation where it costs a real call to
            # find out otherwise.
            if not s.get("twiml_bin"):
                return ("The Twilio details are stored, but there's no TwiML "
                        "Bin configured. On a trial account I can't speak "
                        "without one — calls would connect and then fail. "
                        "PHONE.md has the two-minute fix.")
            return (f"Phone calling is ready. {s['calls_today']} of "
                    f"{s['daily_limit']} calls used today; quiet hours are "
                    f"{s['quiet_hours']}.")
        # alert() is deliberately NOT reachable from here -- it is for
        # detectors, and routing it would give the model a way to trigger an
        # alert call. Only the explicit "call me" path is user-facing.
        return phone_skill.call(target)

    if skill == "net" and action == "connections":
        # Composed locally, with no reverse DNS and no reputation lookups:
        # asking what this machine is connected to must not itself report
        # that to anyone. See network_skill's header.
        return network_skill.connections_report()

    if skill == "usb":
        # Composed locally. What is attached to this machine is telemetry
        # about it, and it never reaches a model to be phrased.
        try:
            from threatmon import usbwatch as _usb
            return _usb.report()
        except Exception as e:
            return (f"I couldn't check removable devices right now "
                    f"({type(e).__name__}).")

    if skill == "persistence":
        # Composed locally by the detector, never by a model -- what launches
        # at boot on this machine is exactly the detail that must not travel
        # to a third party just to be phrased nicely.
        try:
            from threatmon import persistence as _persistence
            return _persistence.report()
        except Exception as e:
            return (f"I couldn't check your startup entries right now "
                    f"({type(e).__name__}).")

    if skill == "netconfig":
        try:
            from threatmon import netconfig as _netconfig
            return _netconfig.report()
        except Exception as e:
            return (f"I couldn't check your network settings right now "
                    f"({type(e).__name__}).")

    if skill == "lockdown":
        from threatmon import lockdown as _lockdown
        if action == "disarm":
            return _lockdown.arm(False)
        if action == "status":
            s = _lockdown.status()
            if not s["armed"]:
                return ("Auto-lockdown is off. I'll warn you about critical "
                        "detections but I won't lock the screen. Say \"arm "
                        "lockdown\" to change that.")
            return (f"Auto-lockdown is armed. {s['locks_today']} of "
                    f"{s['daily_limit']} locks today. Critical detections "
                    f"only.")
        return _lockdown.arm(True)

    if skill == "gesture":
        import gesturewatch
        if action == "disarm":
            return gesturewatch.disarm()
        if action == "status":
            s = gesturewatch.status()
            if not s["available"]:
                return "I can't use the camera for gestures right now."
            if not s["armed"]:
                return (f"Not watching. I've read {s['gestures_seen']} "
                        f"gestures since starting. Say \"watch my hands\" to "
                        f"arm it.")
            return (f"Watching, {s['seconds_left']} seconds left. "
                    f"{s['gestures_seen']} gestures read so far.")
        # arm() is time-boxed and releases the camera itself -- see the module
        # docstring on why this is never ambient.
        return gesturewatch.arm()

    if skill == "briefing":
        from skills import briefing_skill
        if action == "review":
            # ARGUS reading back its OWN transcript for things it did not
            # understand. Composed by string logic, not by asking a model how
            # it thinks it performed -- which would produce a confident essay
            # rather than a list.
            return briefing_skill.review_report()
        # current_info(), NOT record_start(): asking "what did I miss" is not a
        # session start, and recording it as one would poison the median that
        # the "usual for you" verdict is computed from.
        text = briefing_skill.brief(briefing_skill.current_info())
        return text or "Nothing to report — quiet since you were last here."

    if skill == "intel":
        from skills import intel_skill
        if action == "clear":
            return intel_skill.clear()
        # A bare topic word ("world"/"tech"/"security") selects a curated
        # query; anything longer is the user's own question, searched as asked.
        tgt = (target or "").strip()
        if tgt.lower() in ("world", "tech", "security", "local"):
            return intel_skill.brief(topic=tgt.lower())
        return intel_skill.brief(query=tgt, topic="world")

    if skill == "face":
        import faceauth
        if action == "enroll":
            return faceauth.enroll()
        if action == "forget":
            return faceauth.forget()
        if action == "watch":
            return faceauth.set_presence(True)
        if action == "unwatch":
            return faceauth.set_presence(False)
        return faceauth.recognise()[1]

    if skill == "cleanup":
        from skills import cleanup_skill
        if action == "run":
            return cleanup_skill.run()
        if action == "cancel":
            return cleanup_skill.cancel()
        return cleanup_skill.stage()

    if skill == "privacy_watch" and action == "usage":
        # Which apps opened the camera/mic, from the local consent-store
        # timeline. Pure string logic in threatmon.privacy -- no model, no
        # network -- for the same reason as the security summary below.
        try:
            from threatmon import privacy as _privacy
            return _privacy.usage_report(24)
        except Exception as e:
            return (f"I couldn't check camera and microphone usage right now "
                    f"({type(e).__name__}).")

    if skill == "security" and action == "summary":
        # Synthesised deterministically and locally by threatmon -- no model
        # call, no network -- so this machine's security state cannot leak to
        # the cloud tier. Reached only via intent.match (above the cloud path).
        try:
            import threatmon
            return threatmon.security_summary()["verdict"]
        except Exception as e:
            return (f"I couldn't compile a security summary right now "
                    f"({type(e).__name__}).")

    if skill == "security" and action == "state":
        # Section 22's state machine, visible to the owner. L1 read.
        try:
            import security_state
            s = security_state.status()
            grants_line = ""
            try:
                import grants
                grants_line = f" {grants.describe()}."
            except Exception:
                pass
            return (f"Security state: {s['state']}" +
                    (f" -- {s['reason']}" if s.get("reason") else "") +
                    f" (for {int(s.get('age_s', 0))} seconds)." + grants_line)
        except Exception as e:
            return (f"I couldn't read the security state right now "
                    f"({type(e).__name__}).")

    if skill == "security" and action == "recover":
        # Section 63: break-glass is OUTSIDE ordinary agent control. The
        # L4 table entry means this needs the strong-factor path; on top of
        # that, a completed Windows Hello gesture is required -- an owner
        # presence proof, not merely an unlocked session. Recovery then
        # must still PROVE the repair through the manifest before NORMAL
        # returns (security_state.verify_return()).
        try:
            import hwauth
            ok, _why = hwauth.verify_user("Confirm recovery with Windows Hello")
            if not ok:
                return ("Recovery needs you to confirm with Windows Hello "
                        "-- it's the one thing I won't do on a session "
                        "alone.")
        except Exception as e:
            return (f"Recovery needs Windows Hello, which isn't available "
                    f"right now ({type(e).__name__}).")
        import security_state
        if not security_state.enter_recovery("owner recovery procedure"):
            return ("There's nothing to recover from -- I'm not in a "
                    "locked-down state.")
        ok, note = security_state.verify_return()
        if ok:
            return ("Recovery complete: the installation verified clean, "
                    "and I'm back to normal. Grants and staged plans were "
                    "cleared during lockdown.")
        return (f"I'm in recovery, but I'm not going back to normal yet: "
                f"{note} Check the integrity report, repair what it names, "
                "and say 'security recover' again.")

    if skill == "social":
        # target carries only a discriminator ("model") for the runtime-metadata
        # answers -- see social_skill.respond. It is never spoken back.
        return social_skill.respond(action, target)

    if skill == "calc":
        # THE ROUTER'S CHOICE IS SANITY-CHECKED, NOT TRUSTED.
        #
        # The LLM router sent comparison questions here:
        #
        #   "is Python faster than C"        -> calc/calculate
        #   "which is faster python or c"    -> calc/convert
        #
        # and the user heard "I couldn't parse that as a calculation" for a
        # question that has a perfectly good answer. The model picked a skill
        # on the word "faster"; the calculator is the one component that can
        # say with certainty whether something is arithmetic, so it is asked.
        #
        # Only applies to the LLM-routed path -- intent.py's fast path already
        # tests looks_like_math before choosing calc, so a genuine sum is
        # never bounced here.
        probe = target or user_text
        if not (calc_skill.looks_like_math(probe) or re.search(r"\d", probe)):
            print(f"[route] calc rejected {probe[:40]!r} — not arithmetic, "
                  f"answering it instead")
            return brain.answer(user_text, history)
        if action == "convert":
            return calc_skill.convert(target)
        return calc_skill.calculate(target)

    if skill == "knowledge":
        if action == "define":
            out = knowledge_skill.define(target)
            return out or brain.answer(user_text, history)
        if action == "spell":
            return knowledge_skill.spell(target)
        if action == "translate":
            return knowledge_skill.translate(target, d.get("reply", "Spanish"))
        if action == "summarize_clipboard":
            import pyperclip
            return knowledge_skill.summarize(pyperclip.paste())
        if action == "lookup":
            out = knowledge_skill.lookup(target)
            # RELEVANCE, not merely "an article came back".
            #
            # Wikipedia's search returns the best TITLE match, which for a
            # descriptive phrase is often an article about something else
            # entirely: "is the moon bigger than australia" came back with
            # Rhea, a moon of Saturn. An article that shares no content word
            # with the question is not an answer to it, and a confidently
            # wrong answer is worse than none -- so the model gets it instead.
            if out and _looks_relevant(target, out):
                return out
            if out:
                print(f"[route] wikipedia result looks unrelated to "
                      f"{target[:34]!r} — answering instead")
            # Nothing useful on Wikipedia — let the model answer rather than
            # failing or misleading.
            return brain.answer(user_text, history)

    if skill == "vision":
        try:
            if action == "describe" or not action:
                return vision_skill.describe_screen(target)
            if action == "read_text":
                return vision_skill.read_text()
            if action == "locate_text":
                return vision_skill.locate_text(target)
            if action == "verify_text":
                return vision_skill.verify_text(target)
            if action == "cursor_location":
                return vision_skill.cursor_location()
            if action == "click_text":
                return vision_skill.click_text(target)
            if action == "visual_confirm":
                if not vision_skill.visual_has_pending():
                    return brain.answer(user_text, history)
                return vision_skill.visual_confirm_click()
            if action == "visual_cancel":
                return vision_skill.visual_cancel()
            if action == "drag_text":
                src, _, dst = (target or "").partition("|")
                if not dst:
                    return "Say it as: drag <this> to <that>."
                return vision_skill.drag_text(src.strip(), dst.strip())
        except Exception as e:
            return f"That didn't work: {e}"
        return vision_skill.describe_screen(target)

    if skill == "document":
        try:
            if action == "read":
                return document_skill.extract_text(target)
            if action == "summarize":
                return document_skill.summarize(target)
            if action == "search":
                name, _, phrase = (target or "").partition("|")
                if not phrase:
                    return "Search for what, in which document?"
                return document_skill.search_in(name.strip(), phrase.strip())
            if action == "info":
                return document_skill.metadata(target)
            if action == "merge":
                out = (d.get("reply", "") or "merged").strip()
                return document_skill.pdf_merge(target, out)
            if action == "split":
                return document_skill.pdf_split(target)
            if action == "create":
                out = (d.get("reply", "") or "note").strip()
                return document_skill.create_document(target, out)
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "schedule":
        try:
            if action in ("once", "every"):
                parts = [p.strip() for p in (target or "").split("|")]
                if len(parts) not in (4, 5):
                    return "Say it as: <what> | <how often or how soon in seconds>."
                inner_skill, inner_action, inner_target, seconds = parts[:4]
                contains = parts[4] if len(parts) == 5 else ""
                return scheduler_skill.schedule(inner_skill, inner_action, inner_target,
                                                seconds, recurring=(action == "every"),
                                                contains=contains)
            if action == "list":
                return scheduler_skill.list_tasks()
            if action == "status":
                return scheduler_skill.status()
            if action == "cancel":
                return scheduler_skill.cancel(target)
            if action == "pause":
                return scheduler_skill.pause(target)
            if action == "resume":
                return scheduler_skill.resume(target)
            if action == "results":
                return scheduler_skill.results(target)
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "email":
        try:
            if action == "search":
                return email_skill.search(target)
            if action == "read":
                return email_skill.read(target)
            if action == "attachments":
                return email_skill.list_attachments(target)
            if action == "contacts":
                return email_skill.contacts_search(target)
            if action == "send":
                parts = (target or "").split("|")
                if len(parts) != 3:
                    return "Say it as: send to <address> | <subject> | <message>."
                to, subject, body = (p.strip() for p in parts)
                return email_skill.stage_send(to, subject, body)
            if action == "reply":
                query, _, body = (target or "").partition("|")
                if not body:
                    return "Reply to which email, and say what?"
                return email_skill.stage_reply(query.strip(), body.strip())
            if action == "forward":
                query, _, to = (target or "").partition("|")
                if not to:
                    return "Forward which email, and to whom?"
                return email_skill.stage_forward(query.strip(), to.strip())
            if action == "confirm":
                if not email_skill.has_pending():
                    return brain.answer(user_text, history)
                return email_skill.confirm(target)
            if action == "cancel":
                return email_skill.cancel()
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "sysext":
        try:
            if action == "printers":
                return system_ext_skill.printers()
            if action == "print_queue":
                return system_ext_skill.print_queue(target)
            if action == "devices":
                return system_ext_skill.devices(target)
            if action == "network_drives":
                return system_ext_skill.network_drives()
            if action == "dns":
                return system_ext_skill.dns_lookup(target)
            if action == "port":
                return system_ext_skill.check_port(target)
            if action == "ping":
                return system_ext_skill.ping(target)
            if action == "bluetooth_status":
                return system_ext_skill.bluetooth_status()
            if action == "bluetooth_on":
                return system_ext_skill.bluetooth_set(True)
            if action == "bluetooth_off":
                return system_ext_skill.bluetooth_set(False)
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "dev":
        try:
            if action == "status":
                return dev_skill.git_status()
            if action == "log":
                try:
                    n = int(float(target)) if target else 10
                except (ValueError, TypeError):
                    n = 10
                return dev_skill.git_log(n)
            if action == "diff":
                return dev_skill.git_diff(staged=(target or "").strip().lower() == "staged")
            if action == "branch":
                return dev_skill.git_branch()
        except Exception as e:
            return f"That didn't work: {e}"

    if skill == "context":
        if action == "current":
            return context_skill.current(screen="screen" in target.lower())
        if action == "selection":
            return context_skill.selection()
        if action == "file":
            return context_skill.file()

    if skill == "health":
        if action == "check":
            return health_skill.check()
        if action == "report":
            return health_skill.report()

    if skill == "system":
        if action == "stats":
            return system_skill.stats()
        if action in ("flags", "flag"):
            return system_skill.flags(target)
        if action == "settings":
            return system_skill.settings()
        if action == "set_flag":
            # Prompt format: target="<name>|<on or off>", e.g. "telemetry|on".
            name, _, on_off = target.partition("|")
            name = name.strip()
            on_off = on_off.strip().lower()
            if not name or not on_off:
                return ("Which flag and on or off? "
                        "Like 'set_flag telemetry|on'.")
            on = on_off in ("on", "true", "1", "yes")
            if not on and on_off not in ("off", "false", "0", "no"):
                return "I need on or off after the flag name."
            return system_skill.set_flag(name, on)

    if skill == "watched":

        # plan, it never runs one. set/list/status/cancel/results are the
        # ordinary owner-facing surface; everything bounded about them lives
        # in watched_skill.py's own docstring.
        if action == "set":
            return watched_skill.set_watch(target)
        if action == "list":
            return watched_skill.list_tasks(target)
        if action == "cancel":
            return watched_skill.cancel(target)
        if action == "status":
            return watched_skill.status()
        if action == "results":
            return watched_skill.results(target)

    if skill == "goals":

        # plan on a cadence, it never runs one. The fire path re-validates
        # the stored steps and charges agent/budgets.py at every fire --
        # see goals_skill.py's module docstring.
        if action == "create":
            return goals_skill.create(target)
        if action == "list":
            return goals_skill.list_tasks(target)
        if action == "cancel":
            return goals_skill.cancel(target)
        if action == "status":
            return goals_skill.status()
        if action == "results":
            return goals_skill.results(target)

    if skill == "monitor":
        if action == "set":
            return monitor_skill.watch(target)
        if action == "list":
            return monitor_skill.list_watches(target)
        if action == "cancel":
            return monitor_skill.cancel(target)
        if action == "status":
            return monitor_skill.status()
        if action == "results":
            return monitor_skill.results(target)

    if skill == "service":
        # start/stop/restart arrive here as "request" -- the model asks the
        # skill to STAGE the action, never to execute it. The staged action is
        # then confirmed by a separate service/confirm dispatch that intent.py
        # routes PIN digits to (same shape as power/confirm and files/
        # confirm_delete). Auth gates the WRITE at L1 (the skill-internal PIN is
        # the real confirmation -- see service_skill.py's docstring for why L3
        # conflicted with the skill's own staged+PIN).
        if action == "list":
            return service_skill.list_services(target)
        if action == "status":
            return service_skill.status(target)
        if action in ("start", "stop", "restart"):
            return service_skill.request(action, target)
        if action == "pending_reminder":
            if not service_skill.has_pending():
                return brain.answer(user_text, history)
            return ("I'm still waiting for the PIN to confirm that service "
                    "change. Say the digits, or say cancel.")
        if action == "confirm":
            if not service_skill.has_pending():
                return brain.answer(user_text, history)
            return service_skill.confirm(target)
        if action == "cancel":
            return service_skill.cancel()

    if skill == "env_var":
        # Same staged shape as service above: set stages (env_skill.request),
        # a PIN confirm, and a universal cancel. The model never executes a
        # write directly -- auth + the skill module both assume a staged flow.
        if action == "list":
            return env_skill.list_env(target)
        if action == "get":
            return env_skill.get_env(target)
        if action == "set":
            if "|" in (target or ""):
                nname, _, value = target.partition("|")
                return env_skill.request(nname.strip(), value.strip())
            return env_skill.request(target)
        if action == "pending_reminder":
            if not env_skill.has_pending():
                return brain.answer(user_text, history)
            return ("I'm still waiting for the PIN to confirm that "
                    "environment variable change. Say the digits, or say "
                    "cancel.")
        if action == "confirm":
            if not env_skill.has_pending():
                return brain.answer(user_text, history)
            return env_skill.confirm(target)
        if action == "cancel":
            return env_skill.cancel()

    if skill == "security_log":
        if action == "read":
            return security_log_skill.read(target)
        if action == "status":
            return security_log_skill.status(target)

    if skill == "zt":
        if action == "status" or action == "describe":
            return zt_skill.status()
        if action == "on":
            return zt_skill.set_enabled(True)
        if action == "off":
            return zt_skill.set_enabled(False)
        if action == "enroll_hw":
            return zt_skill.hw_enroll()
        if action == "forget_hw":
            return zt_skill.hw_forget()
        if action == "check_hw":
            return zt_skill.hw_check()
        if action == "hw_status":
            return zt_skill.hw_status()
        return "I don't know that zero-trust command."

    # "chat" (and anything else unrecognized) always goes through brain.answer()
    # rather than trusting a "reply" the router model may have written itself.
    # The router uses OLLAMA_ROUTER_MODEL under json_mode specifically for
    # reliable structured output, not conversational quality -- OLLAMA_MODEL
    # (via brain.answer/chat_stream) is the one actually chosen for that, and
    # only brain.answer() applies the Wikipedia/web escalation cascade.
    if skill == "history":
        # history/clear is the HUD's /clear-memory surface: it is authorised
        # and audited THERE under ("history","clear"), reached only by the
        # button, never by voice. If the model ever routes a command here, the
        # honest move is to refuse -- a spoken "clear your memory" that quietly
        # did nothing would be indistinguishable from one that worked, and this
        # exists so the registry's dispatch walk can find the branch.
        return ("I don't clear conversation memory from voice -- it's the HUD's "
                "Conversation Memory button, and it's audited there. "
                "I haven't cleared anything.")

    if skill == "chat":
        return brain.answer(user_text, history)

    reply = d.get("reply")
    if reply and str(reply).strip():
        return _strip_think(str(reply))
    return brain.answer(user_text, history)


# ═══════════════════════════════════════════════════════════════════════════
# THE TASK LOOP:  plan → execute → observe → correct
# ═══════════════════════════════════════════════════════════════════════════
#
# WHAT THIS IS FOR. Everything above answers ONE request with ONE skill. That
# is a command dispatcher, and the ceiling is obvious the moment a request
# needs two things done in order: "find the invoice and open it", "check what's
# eating the CPU and stop it". Each half exists; nothing joins them.
#
# This joins them. A goal is decomposed into steps by the LOCAL model, the plan
# is validated against an allowlist, shown to the owner, and only run once he
# says yes -- then each step is executed, its result OBSERVED, and the run
# stopped and reported if a step does not do what the plan expected.
#
# ──────────────────────────────────────────────────────────────────────────
# THE FIVE RULES IT IS BUILT FROM. Every one of them exists because a planner
# is the single most dangerous component in an assistant: it is the part that
# turns one sentence into many actions.
#
# 1. THE PLAN IS NOT A PERMISSION. Every step calls auth.authorize()
#    INDIVIDUALLY, at the moment it runs, through the same _dispatch() every
#    spoken command uses. A plan that contains a step the owner is not
#    authorised for fails at that step -- it does not inherit permission from
#    the plan having been approved, and approving a plan is not approving its
#    contents. This is rule 5 of the project ("never let the model decide
#    whether it has permission") applied to the one place it is easiest to
#    lose.
#
# 2. THE ALLOWLIST IS CODE, NOT PROMPT. PLANNABLE below is the complete set of
#    (skill, action) pairs a plan may contain. A model that asks for anything
#    else gets the plan rejected, whole. Nothing irreversible is on it: no
#    power, no files/delete, no remedy/apply, no dictation. Those remain
#    single, deliberate, spoken commands with their own confirmations -- a
#    thing that ends your session or deletes your work should never be a step
#    inside something else. A step that needs FRESH authorisation (the
#    machine locked, a re-auth gone stale, an L3+ confirmation) is not an
#    exception to this: it PAUSES (see _NEEDS_AUTH / _run_steps) rather than
#    running early on the strength of the plan alone, and resumes only once
#    that authorisation is actually satisfied, checked the same way a live
#    command's would be.
#
# 3. IT IS PROPOSED, NOT PERFORMED. plan_and_stage() returns a description and
#    waits. "ARGUS must be able to do anything I ask, but with permission" is
#    the requirement, and the plan being readable BEFORE it runs is what makes
#    the permission meaningful -- approving "sort out my CPU" is not consent,
#    approving "check what's using the CPU, then stop these three programs" is.
#
# 4. OBSERVE, THEN DECIDE -- BUT THE DECISION IS BOUNDED TO THREE WORDS. Each
#    step's reply is inspected before the next one starts. A clean success
#    just continues; a failure gets ONE MORE local-model call
#    (_observe_decision, CORRECT_PROMPT) that may answer ONLY continue, retry
#    the SAME step exactly as approved, or abort -- never a different skill,
#    action, or target than what the owner already approved. That is the
#    "Correct" in Plan -> Execute -> Observe -> Correct: correcting whether to
#    keep going, not correcting WHAT to do. Bounded on two axes at once
#    (MAX_STEP_RETRIES per step, MAX_PLAN_RETRIES for the whole plan) and cut
#    off immediately, before a THIRD model call, if two consecutive attempts
#    at the same step produce the IDENTICAL observation -- see the loop
#    breaker in _run_steps(), which also raises announce.say("plan_loop_broken")
#    so a stuck plan is heard, not just logged.
#
# 5. THE MODEL IS LOCAL. Decomposing a goal, AND the bounded correction
#    decision in rule 4, both go through ollama_client.chat_json -- the same
#    local-only client _decide() itself uses, never the cloud tiers
#    cloud_gate.py guards. Handing over either half of "what should happen
#    next" is exactly what _decide() already refuses to send to a cloud
#    provider; the correction step is held to the identical rule.
#
# WHAT IT IS STILL NOT, even with the above: there is no free re-planning
# (the model never gets to substitute an action the owner did not approve,
# only continue/retry/abort THIS one), no background goals (nothing here
# runs unattended -- that's scheduler_skill.py's job, deliberately on a
# MUCH narrower allowlist than PLANNABLE), and no unbounded retry (both a
# per-step and a whole-plan ceiling apply, and identical output stops it
# even earlier). Failure recovery still means STOPPING AND SAYING SO once
# the bounds are exhausted -- rule 4 widens what happens BEFORE that point,
# not what happens instead of it.

# Render planner capabilities from the registry to keep descriptions aligned
# with dispatch and authorization.
def _render_capability_block(pairs) -> str:
    """Render registered (skill, action) pairs as planner capabilities."""
    by_skill: dict[str, list[str]] = {}
    for skill, action in sorted(pairs):
        desc = registry.SKILLS.get(skill, {}).get("actions", {}).get(action, "")
        by_skill.setdefault(skill, []).append(
            f'"{action}"' + (f" ({desc})" if desc else ""))
    return "\n".join(f'- "{skill}": ' + " | ".join(actions)
                     for skill, actions in sorted(by_skill.items()))


def _build_plan_prompt(web: bool = False) -> str:
    """The planner's full system prompt. Called once at import time for each
    of PLAN_PROMPT/WEB_TASK_PROMPT below (not per-call: neither PLANNABLE nor
    WEB_TASK_ACTIONS changes at runtime), after both of those and
    WEB_TASK_ACTIONS are defined -- see the two assignments right after
    PLANNABLE's own definition below, and why they cannot move earlier.
    """
    capabilities = _render_capability_block(
        PLANNABLE | (WEB_TASK_ACTIONS if web else set()))
    if web:
        return f'''You are ARGUS's website-task planner. The user described one
multi-step task on the web in a single command, and doing it as one plan is
what they asked for. Break it into the smallest sequence of steps that achieves
it. Output ONLY a JSON object.

Shape: {{"steps":[{{"skill":"...","action":"...","target":"...","expect":"..."}},
 ...],"constraints":["explicit user constraint"],
 "assumptions":["needed assumption"],"strategy":"short description",
 "artifacts":["expected output"]}}

Use ONLY these skill/action pairs:
{capabilities}

RULES:
- Three to six steps. If one step does it, output one step.
- Put an "expect" field on EVERY step: the concrete page state or file the
  step should produce ("the invoices page lists this month's PDFs"). When a
  later step depends on an earlier result, insert a browser/extract_text or
  browser/find_elements verify step right before the step that needs it.
- Never invent a skill or action not listed above. No apps/, no power/, no
  files/delete.
- Fill is for open, non-password fields only.
- If the goal cannot be done with these steps, output {{"steps":[]}}.'''
    return f'''You are ARGUS's task planner. Break the user's goal into the
smallest sequence of steps that achieves it. Output ONLY a JSON object.

Shape: {{"steps":[{{"skill":"...","action":"...","target":"..."}}, ...],
"constraints":["explicit user constraint"],
"assumptions":["needed assumption"],"strategy":"short description",
"artifacts":["expected output"]}}

Use ONLY these (skill, action) pairs:
{capabilities}

RULES:
- Two to four steps. If one step does it, output one step.
- Never invent a skill or action that is not listed above.
- Steps run in order. Put what must happen first, first.
- If the goal cannot be done with these steps, output {{"steps":[]}}.'''

# The steps a WEBSITE TASK needs that the ordinary plan allowlist lacks. The
# normal PLANNABLE deliberately excludes browser/fill, submit, download,
# upload ("they leave data with, or take data from, somewhere outside this
# machine's control") and files/move (a write outside the browser window).
# A web task is exactly the case where the owner has SAID the whole multi-step
# goal aloud once, approved the step list, and then individually confirms
# every staged write as it happens -- so the write steps join the plan ONLY
# inside this mode, and only under browser/task's L3 gate plus the per-write
# PIN pause. Leaving them out of the ordinary plan keeps the existing
# browser_skill.py:6-9 contract ("no second workflow engine") intact; this is
# a narrow widening of the SAME runner with the SAME bounding caps.
WEB_TASK_ACTIONS = {
    ("browser", "fill"), ("browser", "submit"), ("browser", "download"),
    ("browser", "upload"), ("browser", "follow_link"), ("browser", "refresh"),
    ("browser", "back"), ("browser", "forward"), ("browser", "tab_open"),
    ("browser", "tab_close"), ("browser", "tab_switch"),
    ("browser", "tab_search"), ("browser", "history_search"),
    ("browser", "bookmark_add"), ("browser", "bookmark_remove"),
    ("browser", "zoom"),
    ("files", "move"),
}

# The web-task planner's fixed rules (three to six steps, the "expect" field,
# no apps/power/delete, fill is non-password-only) live inside
# _build_plan_prompt(web=True) now -- its capability list is generated the
# same way PLAN_PROMPT's is, from PLANNABLE | WEB_TASK_ACTIONS via
# registry.SKILLS, so a write action added here is described to the model
# without a fifth hand-typed copy anywhere.

# The complete set a plan may contain. Deliberately WIDER than CHAINABLE
# (which is read-only) because a plan is allowed to act -- and deliberately
# excludes everything irreversible. See rule 2 above.
PLANNABLE = set(CHAINABLE) | {
    ("apps", "open"), ("apps", "close"),
    ("window", "focus"), ("window", "minimize"), ("window", "maximize"),
    ("files", "open"),
    ("pc", "heavy"), ("pc", "sysinfo"), ("pc", "display"), ("pc", "installed"),
    ("pc", "ui_tree"), ("pc", "ui_click"), ("pc", "ui_read"),
    ("diag", "ports"), ("diag", "defenses"), ("diag", "changes"),
    ("diag", "process"), ("diag", "fixes"),
    ("storage", "free"), ("storage", "largest"), ("storage", "analyze"),
    ("control", "volume_set"), ("control", "mute"), ("control", "unmute"),
    ("vault", "write"),
    ("timer", "set"),
    ("net", "connections"),
    # Browsing is reversible with Back and changes nothing outside the
    # browser window, so it's the same tier as apps/open or window/focus
    # above. submit / download / upload are deliberately NOT here -- see
    # rule 2 above and browser_skill's own module docstring: those three
    # leave data with, or take data from, somewhere outside this machine's
    # control, so they stay single, deliberate, PIN-confirmed commands.
    ("browser", "navigate"), ("browser", "search"),
    ("browser", "extract_text"), ("browser", "find_elements"),
    ("browser", "click"), ("browser", "screenshot"), ("browser", "list_tabs"),
    # Same reasoning: OCR reads are reversible reports. click_text/drag_text
    # are deliberately NOT here, same as pc/ui_click isn't -- acting on a
    # visual match (weaker than a real UI Automation name, see vision_skill's
    # module docstring) stays a single, deliberate, individually-confirmed
    # command.
    ("vision", "read_text"), ("vision", "locate_text"),
    ("vision", "verify_text"), ("vision", "cursor_location"),
}

# Built now, not lazily: PLANNABLE and WEB_TASK_ACTIONS are both fixed at
# import time, so there is nothing to gain from recomputing this per call,
# and every caller sharing the same string is what keeps the planner's
# system prompt byte-identical across a run (a prompt that changed on every
# call would be a prompt-cache miss on every call, for no behavioural
# benefit).
PLAN_PROMPT = _build_plan_prompt(web=False)
WEB_TASK_PROMPT = _build_plan_prompt(web=True)

MAX_PLAN_STEPS = 6        # rule 5's "5 to 8 steps" -- 6 is the middle of that
PLAN_TTL_S = 120.0

# Replies that mean a step did NOT do what it said. Matched loosely: a false
# positive stops a plan one step early and says why, which is recoverable; a
# miss means the remaining steps run against a state that never happened.
_STEP_FAILED = re.compile(
    r"\b(?:i (?:can'?t|cannot|couldn'?t|could not|don'?t have)|"
    r"that needs|needs stronger|is locked|authenticate again|"
    r"type your pin to confirm|"
    r"i won'?t|not found|nothing called|no such|didn'?t work|"
    r"hit a problem|went wrong|unavailable|refused)\b", re.I)

# A SUBSET of _STEP_FAILED: refusals that mean "not now", not "not possible".
# These PAUSE the plan (state preserved, resumable) rather than aborting it
# -- the one deliberate exception to "a failed step stops the plan", because
# the step did not fail, it correctly asked for something only the owner can
# supply (a fresh unlock, a PIN, a confirmation word, hands on the
# keyboard). Matched against auth.py's own refusal text, word for word,
# rather than re-deriving the same judgement a second way.
_NEEDS_AUTH = re.compile(
    r"needs you to authenticate again|"       # L2_REAUTH, stale unlock
    r"is locked\. authenticate|"               # auth.LOCKED_MESSAGE
    r"needs confirming\. say|"                 # auth.stage_confirmation()
    r"type your pin to confirm|"                # staged browser write
    r"needs stronger authentication|"          # L4_STRONG, under-configured
    r"hold the push-to-talk", re.I)            # push-to-talk gate

# Bounds for the OBSERVE -> CORRECT half of the loop (rule 4/5). Retrying is
# never free -- each one is a real dispatch, possibly a real side effect --
# so both a PER-STEP and a WHOLE-PLAN ceiling apply; whichever is hit first
# ends the plan. A plan that retried every one of 6 steps to its individual
# cap would be 12 extra dispatches for a "5 to 8 step" goal, which is the
# failure MAX_PLAN_RETRIES is there to cut off.
MAX_STEP_RETRIES = 2
MAX_PLAN_RETRIES = 3

CORRECT_PROMPT = """A step in an ALREADY-APPROVED plan just ran and produced a
result. Decide ONLY one of the following three outcomes. Output ONLY a JSON
object, no markdown, no explanation.

{"decision": "continue"} -- the result is acceptable; move on to the next
  approved step
{"decision": "retry"} -- worth attempting AGAIN, EXACTLY AS APPROVED (the
  identical skill, action and target -- you may not change any of them),
  because the result looks like a transient failure
{"decision": "abort"} -- continuing or retrying would be wrong or pointless

You are choosing only among continue, retry, and abort. You may NEVER
propose a different skill, a different action, or a different target than
the one that already ran -- that is not one of your options, regardless of
what the result suggests might work better."""

_plan = {"steps": [], "goal": "", "at": 0.0}

# Descriptive task memory for the currently staged/paused goal. Metadata may
# explain a decision, but it never becomes an authorization input and never
# alters the executable step list.
_plan_metadata = {
    "goal": "", "task_id": "", "plan_id": "",
    "constraints": [], "assumptions": [], "strategies": [],
    "security_decisions": [], "user_approvals": [], "artifacts": [],
    "final_state": "",
}

# Normalized, read-only evidence collected for the most recent plan run.
# This is deliberately separate from ``done``: ``done`` is the small,
# long-standing execution record used to resume a paused plan, while these
# observations also include failed and paused attempts.  An Observation never
# authorises, retries, or otherwise influences a step; it records what the
# already-authorised dispatcher returned and, where available, a best-effort
# before/after state check.  See agent/observer.py.
_plan_observations = []
_plan_provenance = []


# grants sit here as (action_hash, token) pairs, tied to the goal whose
# approval minted them; _run_steps claims a token by HASH immediately before
# each step dispatches. Hash-keyed rather than index-keyed because a pause
# + resume shifts indices but not identities: identical steps are
# interchangeable, and grants.redeem() still re-verifies the hash of what is
# actually about to run. The list is emptied the moment the run ends or the
# plan leaves the slot -- a grant must never outlive its approval.
_plan_grants: list = []
_plan_grants_goal: str = ""

# A plan PAUSED mid-run, waiting on something only the owner can supply --
# see _NEEDS_AUTH above and _run_steps() below. Separate from _plan (which
# is a plan awaiting its INITIAL go-ahead and has never executed a single
# step) because the two need different data: this one carries the STEPS
# NOT YET RUN and the RESULTS ALREADY COLLECTED, so resuming continues
# instead of starting over.
PLAN_PAUSE_TTL = 300.0  # longer than any single CONFIRM_WINDOW -- finding a
                         # PIN or walking back to unlock the machine takes
                         # longer than typing a PIN you already have staged
_plan_paused = {"steps": [], "goal": "", "done": [], "at": 0.0, "reason": ""}


def plan_is_pending() -> bool:
    return (bool(_plan["steps"])
            and time.time() - _plan["at"] <= PLAN_TTL_S)


def cancel_plan() -> str:
    had = plan_is_pending()
    goal = _plan.get("goal", "")
    if had and _plan_metadata.get("goal") == goal:
        _plan_metadata["final_state"] = "cancelled"
        _plan_metadata["user_approvals"] = [
            x for x in _plan_metadata["user_approvals"]
            if x != "Plan approval pending"] + ["Owner cancelled the staged plan"]
        _remember_plan_outcome(goal, "Owner cancelled the staged plan.", ok=False)
    _plan.update(steps=[], goal="", at=0.0)
    _clear_plan_grants()
    return "Dropped it." if had else "There was no plan waiting."


def _bounded_text_list(value, limit: int = 12, width: int = 240) -> list[str]:
    """Normalize planner-supplied descriptive metadata, never executable data."""
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:limit]:
        item_text = " ".join(str(item or "").split())[:width]
        if item_text and item_text not in out:
            out.append(item_text)
    return out


def _security_notes(steps: list) -> list[str]:
    """Describe the real policy each step will meet at execution time."""
    notes = []
    for i, step in enumerate(steps, 1):
        skill, action = step["skill"], step["action"]
        level = auth.level_for(skill, action)
        label = auth.LEVEL_NAMES.get(level, f"L{level}")
        suffix = "; explicit confirmation required" if level >= auth.L3_CONFIRM else ""
        notes.append(
            f"Step {i} {skill}/{action}: {label}; authorized immediately before execution{suffix}")
    return notes


def _set_plan_metadata(goal: str, steps: list, raw: dict | None = None) -> None:
    """Start descriptive memory for a newly validated plan.

    Planner values are bounded strings for display only. Security notes are
    derived from auth.py and cannot be asserted by the model.
    """
    raw = raw if isinstance(raw, dict) else {}
    strategy = " ".join(str(raw.get("strategy", "") or "").split())[:300]
    existing_task_id = (_plan_metadata.get("task_id", "")
                        if _plan_metadata.get("goal") == goal else "")
    task_id = str(raw.get("task_id", "") or existing_task_id
                  or f"task-{time.time_ns():x}")[:80]
    _plan_metadata.update(
        goal=(goal or "").strip()[:200],
        task_id=task_id,
        plan_id=f"plan-{time.time_ns():x}",
        constraints=_bounded_text_list(raw.get("constraints")),
        assumptions=_bounded_text_list(raw.get("assumptions")),
        strategies=[strategy or describe_plan(steps)],
        security_decisions=_security_notes(steps),
        user_approvals=["Plan approval pending"],
        artifacts=_bounded_text_list(raw.get("artifacts"), limit=8),
        final_state="staged",
    )


def _task_metadata(goal: str) -> dict:
    """Copy metadata only when it belongs to the requested live goal."""
    if not goal or _plan_metadata.get("goal") != goal:
        return {}
    return {
        key: list(value) if isinstance(value, list) else value
        for key, value in _plan_metadata.items() if key != "goal"
    }


def plan_observations() -> list:
    """Return the normalized evidence from the current or latest plan.

    The list is copied so a HUD or conversation caller cannot mutate the
    execution record.  Observation instances themselves are frozen.  This is
    intentionally a read-only reporting API, never an execution API.
    """
    return list(_plan_observations)


def plan_provenance() -> list[dict]:
    """Copy of structured per-attempt provenance for the latest task."""
    return [dict(item, arguments=dict(item.get("arguments", {})),
                 observation=dict(item.get("observation", {})))
            for item in _plan_provenance]


def _record_plan_observation(step: dict, reply: str, before: dict | None,
                             after: dict | None, step_number: int = 0,
                             attempt: int = 1):
    'Best-effort observation, with no effect on plan control flow.'
    try:
        from agent import observer
        observation = observer.observe(
            str(step.get("skill", "")), str(step.get("action", "")),
            str(step.get("target", "") or ""), reply, before, after,
            expected=str(step.get("expect", "") or ""))
        _plan_observations.append(observation)
        skill = str(step.get("skill", ""))
        action = str(step.get("action", ""))
        level = auth.level_for(skill, action)
        _plan_provenance.append({
            "task_id": _plan_metadata.get("task_id", ""),
            "goal": _plan_metadata.get("goal", ""),
            "plan_id": _plan_metadata.get("plan_id", ""),
            "step_id": f"step-{max(1, int(step_number or 1))}",
            "attempt": max(1, int(attempt or 1)),
            "capability": f"{skill}/{action}",
            "arguments": {"target": str(step.get("target", "") or "")[:500]},
            "target": str(step.get("target", "") or "")[:500],
            "expected_observation": str(step.get("expect", "") or "")[:300],
            "policy_decision": ("allowed" if observation.ok else
                                "waiting" if observation.status == "paused"
                                else "refused_or_failed"),
            "required_auth_level": auth.LEVEL_NAMES.get(level, f"L{level}"),
            "authentication_result": ("satisfied" if observation.ok else
                                      "pending" if observation.status == "paused"
                                      else "not_satisfied_or_action_failed"),
            "confirmation": ("explicit" if level >= auth.L3_CONFIRM else
                             "policy" if level > auth.L0_OPEN else "none"),
            "timestamp": time.time(),
            "result": reply[:500],
            "observation": {
                "status": observation.status,
                "verified": observation.verified,
                "changed": observation.changed,
                "expected": observation.expected,
                "expected_met": observation.expected_met,
                "warnings": list(observation.warnings),
                "errors": list(observation.errors),
            },
        })
        return observation
    except Exception:
        return None


def _capture_plan_state(step: dict) -> dict | None:
    """Read a verifier snapshot if this action has one; never raises."""
    try:
        from agent import verifiers
        return verifiers.capture_state(
            str(step.get("skill", "")), str(step.get("action", "")),
            str(step.get("target", "") or ""))
    except Exception:
        return None


def _remember_plan_outcome(goal: str, outcome: str, ok: bool) -> None:
    """Keep a bounded, in-memory outcome for natural task continuity.

    This executes only when a plan reaches a terminal success or stop state;
    a paused plan deliberately retains no final outcome until it is resumed or
    expires.  Memory is observational only and is never consulted by policy,
    authentication, or dispatch.
    """
    try:
        from agent.working_memory import remember_completed
        remember_completed(goal, outcome, ok=ok,
                           metadata=dict(_plan_metadata),
                           provenance=plan_provenance())
    except Exception:
        pass



# One helper, called from exactly one place (_stopped below). Everything it
# can do to the machine is "stage a validated plan the owner still has to
# approve" -- the same front door any first plan goes through. See
# agent/replanner.py for the full framing, and agent/budgets.py for the cap
# that stops a failing goal from being reworked forever.
#
# OPT-IN, and that is deliberate. A live offer costs an extra local-model
# round trip on the failure path of every plan (~2.5s on this hardware), and
# new autonomy ships dark in this codebase for the same reason token
# rotation and the Windows Hello factor did: the owner turns it on once,
# knowingly. Set ARGUS_REPLAN=1 to enable.
_REPLAN_ENV = "ARGUS_REPLAN"


def _replan_offer(goal: str, step: dict, reply: str) -> str:
    """After a plan STOPS: offer a re-worked alternative, or say nothing.

    Honesty rules this helper keeps:
      - It can only STAGE. agent/replanner.propose_alternative() returns
        success only after router.plan_and_stage() has validated the model's
        proposal against the same PLANNABLE allowlist and filled _plan -- the
        owner's "say go ahead" is still the only thing that runs a step.
      - It is BUDGETED per goal (agent/budgets.py): a bounded number of
        alternatives, then the honest stop, so recovery cannot loop.
      - Every failure mode returns "" and the plain stop message stands --
        an offer is an addition, never a replacement for the truth of what
        went wrong. A refusal message ("already tried reworking this") is
        still appended when the replanner produced one, because "why it
        gave up" is owner-facing truth too.
      - Off by default; ARGUS_REPLAN=1 in the environment turns it on.
    """
    try:
        import os
        if not os.environ.get(_REPLAN_ENV):
            return ""
        from agent import replanner
        _staged, message = replanner.propose_alternative(
            goal, dict(step or {}), reply, web=False)
        return message or ""
    except Exception:
        return ""


def _mint_plan_grants(goal: str) -> None:
    """One grant per staged step, stored by action hash, bound to the goal.
    Called only from the plan/run seam (the owner's "go ahead"). Failures
    leave the plan to run on the ordinary per-step authorize() gate -- grants
    are additive verification, never a third permission source."""
    global _plan_grants, _plan_grants_goal
    _plan_grants = []
    _plan_grants_goal = goal
    try:
        import grants
        for step in list(_plan.get("steps") or []):
            tok = grants.mint(step.get("skill", ""), step.get("action", ""),
                              step.get("target", ""), goal=goal,
                              uses=MAX_STEP_RETRIES + 1, source="plan_run")
            _plan_grants.append(
                (grants.action_hash(step.get("skill", ""),
                                    step.get("action", ""),
                                    step.get("target", "")), tok))
    except Exception:
        _plan_grants = []


def _take_plan_grant(goal: str, step: dict) -> str:
    """_run_steps' per-step claim: the token whose hash matches THIS step,
    only while the running goal is still the one the grants were minted for.
    Empty on any mismatch, which leaves the step on the ordinary gate."""
    if goal != _plan_grants_goal:
        return ""
    try:
        import grants
        h = grants.action_hash(step.get("skill", ""), step.get("action", ""),
                               step.get("target", ""))
    except Exception:
        return ""
    for i, (gh, tok) in enumerate(_plan_grants):
        if gh == h:
            _plan_grants.pop(i)
            return tok
    return ""


def _clear_plan_grants() -> None:
    """The plan left the slot or the run ended: its grants die with it.
    Revoked tokens refuse redemption -- the audit trail of a replayed one
    lands in grants.redeem's refusal branch."""
    global _plan_grants, _plan_grants_goal
    if _plan_grants:
        try:
            import grants
            for _gh, tok in _plan_grants:
                grants.revoke(tok)
        except Exception:
            pass
    _plan_grants = []
    _plan_grants_goal = ""


def plan_kill_switch() -> str:
    "Activate the owner's emergency stop."
    import security_state
    security_state.enter_lockdown("owner kill switch", auto=False)
    return ("Kill switch: everything is stopped -- outstanding approvals "
            "revoked, the staged task dropped, and I won't take state-"
            "changing commands until you run recovery.")


def _plan_web_refusal(goal: str, steps: list) -> str:
    """A refusal, or "" if the plan may proceed: a GOAL that refers to this
    machine or the person's data must not get a plan that searches the web.

    PLANNABLE includes the web lookups (research, knowledge) through CHAINABLE,
    and a plan's steps run later under a different utterance -- "go ahead", or a
    watcher firing -- whose own classification says nothing about the goal. So the
    goal is checked ONCE, at the point a plan is accepted, and the plan is refused
    whole rather than quietly edited. Shared by plan_and_stage() and
    stage_validated_plan(), so a plan composed elsewhere (a watched task, the
    replanner) cannot be the way around it.
    """
    scope = cloud_gate.current()
    if not ((scope is not None and scope.local_required)
            or cloud_gate.decide(goal).local_required):
        return ""
    if any(cloud_gate.is_web_lookup(s.get("skill"), s.get("action"))
           for s in steps if isinstance(s, dict)):
        print("[plan] refused: a local goal, but the plan includes a web lookup")
        return ("I can't plan that: it would search the web, and the goal is "
                "about your own machine or data, so it has to stay local. "
                "Ask me for the local steps on their own.")
    return ""


def stage_validated_plan(goal: str, steps: list) -> tuple[bool, str]:
    'Fill _plan with steps that have ALREADY been through validate_plan().'
    clean, refusal = validate_plan(steps, web=False)
    if refusal:
        return False, refusal
    local_refusal = _plan_web_refusal(goal, clean)
    if local_refusal:
        return False, local_refusal
    if plan_paused_pending() or plan_is_pending():
        return False, ("a plan is already waiting for your go ahead -- "
                       "approve or cancel it first")
    clean_goal = (goal or "").strip()[:200]
    try:
        from agent import budgets
        reserved, reason = budgets.reserve_plan(clean_goal, len(clean))
        if not reserved:
            return False, f"I've stopped working on this: {reason}."
    except Exception:
        # The execution boundary remains router.validate_plan/auth; optional
        # accounting may refuse but must never become a second permission path.
        pass
    _plan.update(steps=clean, goal=clean_goal, at=time.time())
    _set_plan_metadata(clean_goal, clean)
    _plan_observations.clear()
    _plan_provenance.clear()
    _clear_plan_grants()
    return True, describe_plan(clean)


def validate_plan(steps, web: bool = False) -> tuple:
    """(clean_steps, refusal). Whole-plan rejection, never partial.

    Checked BEFORE anything runs and as a unit: approving a plan whose third
    step is not permitted, running the first two, and only then discovering
    the problem would leave the machine half-changed with no record of what
    the owner actually agreed to.

    web=True widens the allowlist to PLANNABLE | WEB_TASK_ACTIONS -- the write
    steps a website task needs that an ordinary plan deliberately excludes.
    It never widens the caps: MAX_PLAN_STEPS=6 still applies, and the WRONG
    pair is still refused whole-plan with the identical wording, so a web
    task gets the same bounded, whole-list discipline an ordinary plan gets.
    """
    if not isinstance(steps, list) or not steps:
        return [], ("I can't see a way to do that with what I have. "
                    "Try asking for one thing at a time.")
    if len(steps) > MAX_PLAN_STEPS:
        return [], (f"That would take more than {MAX_PLAN_STEPS} steps. "
                    f"Break it up for me and I'll do the parts.")
    allowed = PLANNABLE | (WEB_TASK_ACTIONS if web else set())
    clean = []
    for s in steps:
        if not isinstance(s, dict):
            return [], "That plan came back malformed, so I've thrown it away."
        skill = str(s.get("skill", "")).strip()
        action = str(s.get("action", "")).strip()
        if (skill, action) not in allowed:
            return [], (f"My plan wanted to use {skill}/{action}, which isn't "
                        f"something I'll do as part of a bigger task. Ask me "
                        f"for that one directly.")
        target = str(s.get("target", "") or "")
        if len(target) > 500:
            return [], "That plan contained a target that was too large, so I've thrown it away."
        clean_step = {"skill": skill, "action": action, "target": target}
        if web:
            expected = " ".join(str(s.get("expect", "") or "").split())[:300]
            if not expected:
                return [], ("That website plan did not say how one of its steps "
                            "would be verified, so I've thrown it away.")
            clean_step["expect"] = expected
        clean.append(clean_step)
    return clean, ""


def describe_plan(steps) -> str:
    """The plan in words, so approving it means something."""
    parts = []
    for i, s in enumerate(steps, 1):
        t = s.get("target", "")
        parts.append(f"{i}. {s['skill']} {s['action']}"
                     + (f" — {t[:44]}" if t else ""))
    return "; ".join(parts)


def plan_and_stage(goal: str, web: bool = False) -> str:
    """Decompose, validate, describe, and ASK. Runs nothing.

    web=True routes the goal through the WEB_TASK_PROMPT and the widened
    validate_plan(web=True) allowlist -- the zero-cost trigger for the whole
    website-task mode. Everything downstream is the ordinary plan runner: the
    step is stored in the same _plan, approved with the same "say go ahead",
    executed by the same _run_steps(), and paused at every staged write by the
    same _NEEDS_AUTH machinery. The only reason this needs a flag at all is so
    an ordinary "write a plan" utterance does not accidentally admit a
    browser/fill step it was never shown.
    """
    goal = (goal or "").strip()
    if not goal:
        return "What would you like me to do?"
    if plan_paused_pending():
        # Without this, a new goal staged here would sit in _plan while the
        # OLD one's remaining steps and already-collected results sit in
        # _plan_paused -- and the PIN/confirm route in intent.py that's
        # about to arrive resumes _plan_paused, not whatever was just
        # staged. One plan actually running at a time; asking again after
        # the paused one is resolved is the same "one thing at a time"
        # discipline the rest of this file already applies to staged
        # confirmations elsewhere.
        return (f"I've still got an earlier task paused, waiting: "
                f"{_plan_paused['reason']} Sort that first, or say "
                f"\"forget that task\" to drop it.")
    try:
        from agent import budgets
        if not budgets.consume_model_call(goal):
            return ("I've stopped working on that goal because its local-model "
                    "call budget is exhausted. Ask me again with a narrower goal.")
    except Exception:
        pass
    try:
        raw = chat_json(WEB_TASK_PROMPT if web else PLAN_PROMPT, goal)
    except Exception as e:
        print(f"[plan] planner unavailable ({type(e).__name__})")
        return ("I can't plan that out right now — the local model isn't "
                "answering. Ask me for one step at a time and I'll do those.")

    steps, refusal = validate_plan((raw or {}).get("steps"), web=web)
    if refusal:
        return refusal

    # See _plan_web_refusal: checked once, here, where the plan is accepted.
    local_refusal = _plan_web_refusal(goal, steps)
    if local_refusal:
        return local_refusal

    try:
        from agent import budgets
        reserved, reason = budgets.reserve_plan(goal, len(steps))
        if not reserved:
            return f"I've stopped working on this: {reason}."
    except Exception:
        pass
    _plan.update(steps=steps, goal=goal, at=time.time())
    _set_plan_metadata(goal, steps, raw)
    # A newly accepted plan starts a new evidence trail. Keep observations
    # through a pause: resuming continues this same approved task.
    _plan_observations.clear()
    _plan_provenance.clear()
    return (f"Here's my plan: {describe_plan(steps)}. "
            f"Say go ahead and I'll run it, and I'll stop if a step doesn't "
            f"work.")


def _observe_decision(step: dict, result_text: str, goal: str = "") -> str:
    """The bounded half of OBSERVE -> CORRECT: continue / retry / abort,
    never a new action. See CORRECT_PROMPT for the constraint stated to the
    model itself; this is the code-side half of the same constraint --
    anything the model returns outside the three words is treated as abort,
    the same fail-closed handling _decide() uses for a malformed routing
    decision."""
    prompt_input = (f"Step: {step['skill']}/{step['action']} "
                    f"target={step.get('target', '')}\nResult: {result_text[:500]}")
    try:
        from agent import budgets
        if goal and not budgets.consume_model_call(goal):
            return "abort"
    except Exception:
        pass
    try:
        raw = chat_json(CORRECT_PROMPT, prompt_input)
    except Exception:
        # The local model being unreachable is not a reason to keep retrying
        # something that already failed -- same "fail closed, not open" the
        # rest of this file uses when a model call is unavailable.
        return "abort"
    decision = str((raw or {}).get("decision", "")).strip().lower()
    return decision if decision in ("continue", "retry", "abort") else "abort"


def _run_steps(steps: list, done: list, total: int, user_text: str,
               history: list | None, goal: str,
               grant_minted: bool = False) -> str:
    """The shared execution body for run_plan() AND resume_paused_plan() --
    one place implementing the per-step loop, so the two entry points can
    never drift into different behaviour for what is, from here, the exact
    same steps. DONE carries results already collected before this call
    (empty for a fresh run_plan(), non-empty when resuming); TOTAL is the
    step count of the ORIGINAL plan, for "X of Y" reporting that stays
    correct across a pause and resume.

    Implements:
      RULE 1 (each step through the ordinary dispatcher -- unchanged from
        before this rewrite: _dispatch() authorises every step individually)
      RULE 2's second half (PAUSE rather than abort on an auth gate)
      RULE 4 (observe, then a BOUNDED continue/retry/abort correction --
        never a different action) -- only spent on a step that looks
        failed; an unambiguous success never costs the extra model call
      RULE 5 (per-step and whole-plan retry caps, and an identical-
        observation loop breaker that fires BEFORE asking the model again)
    """
    def _stopped(step: dict, where: str, tail: str) -> str:
        _plan_paused.update(steps=[], goal="", done=[], at=0.0, reason="")
        head = (f"I got {len(done)} of {total} steps done and then stopped at "
                f"{where}." if done else f"I stopped at {where}.")
        outcome = f"{head} {tail[:160]}"
        if _plan_metadata.get("goal") == goal:
            _plan_metadata["final_state"] = "failed"
        _remember_plan_outcome(goal, outcome, ok=False)

        # a re-worked plan. The offer can only STAGE a validated alternative
        # -- it never runs anything, and it is silent whenever the budget or
        # the allowlist says no.
        offer = _replan_offer(goal, step, tail)
        return f"{outcome} {offer}".rstrip()

    plan_retries = 0
    completed_before_run = len(done)
    i = 0
    while i < len(steps):
        step = steps[i]
        where = f"{step['skill']} {step['action']}"
        last_text = None
        step_retries = 0
        while True:
            # Read-only evidence capture around the normal dispatcher. It
            # never affects policy, authentication, dispatch, or retries.
            before = _capture_plan_state(step)
            # RESUME BRIDGE (web-task mode). A plan PAUSED at a staged browser
            # write has its PIN delivered as the resume utterance -- intent.py's
            # plan-paused block routes any non-cancel words to plan/resume, so
            # a plain re-dispatch of this step would call stage_*() AGAIN and
            # re-pause instead of confirming. If the write is still sitting
            # staged (has_pending()), feed the resume words straight into
            # browser/confirm(). A WRONG PIN leaves it still staged, so we
            # prefix "That didn't work." -- which _STEP_FAILED matches
            # ("didn't work") -- and the bounded observe path ends the plan.
            # Wrong PINs never re-pause and never run away.
            via_bridge = (
                step["skill"] == "browser"
                and step["action"] in ("submit", "download", "upload")
                and user_text and browser_skill.has_pending())
            if via_bridge:
                reply = browser_skill.confirm(user_text)
                text = str(reply or "").strip()
                if browser_skill.has_pending():
                    text = "That didn't work. " + text
            else:
                # RULE 1: through the ordinary dispatcher, which authorises
                # this step INDIVIDUALLY. The plan having been approved -- or
                # a PREVIOUS step having succeeded -- is not a permission for
                # this one.
                # P1 grant binding: claim THIS step's token before dispatch.
                # grant_minted marks that the plan/run seam actually minted
                # (so a grants-layer outage doesn't turn into "every step
                # unbound"); _take_plan_grant returns "" on any goal/hash
                # mismatch, and an empty token leaves the ordinary gate.
                _tok = _take_plan_grant(goal, step) if grant_minted else ""
                if _tok:
                    import grants as _grants
                    _ok, _why = _grants.redeem(_tok, step.get("skill", ""),
                                               step.get("action", ""),
                                               step.get("target", ""),
                                               goal=goal)
                    if not _ok:
                        return _stopped(step, where,
                                        f"That step no longer matches what "
                                        f"was approved ({_why}).")
                try:
                    reply = _dispatch(dict(step), user_text, history, "plan")
                except Exception as e:
                    return _stopped(step, where, f"{type(e).__name__}")
                text = str(reply or "").strip()

            after = _capture_plan_state(step)
            observation = _record_plan_observation(
                step, text, before, after,
                step_number=completed_before_run + i + 1,
                attempt=step_retries + 1)

            # A capability saying "done" is not enough when a real verifier
            # observed no expected state transition. Feed that evidence into
            # the existing bounded correction path; it may retry the identical
            # approved step or stop, but it still cannot invent a new action.
            if (observation is not None and observation.verified
                    and observation.expected_met is False
                    and not _STEP_FAILED.search(text)):
                text = "I couldn't verify the expected state change. " + text

            # A staged browser step's own text ("Type your PIN to confirm.")
            # matches NEITHER _NEEDS_AUTH nor _STEP_FAILED -- it would look
            # like a clean success and the plan would move on with the write
            # never confirmed. has_pending() is the real signal: the step
            # staged and is now sitting waiting. Pause on it exactly like an
            # auth gate would, so the PIN can ride the resume path.
            waiting_for_pin = (
                not via_bridge and step["skill"] == "browser"
                and step["action"] in ("submit", "download", "upload")
                and browser_skill.has_pending())
            if _NEEDS_AUTH.search(text) or waiting_for_pin:
                # RULE 2: pause, don't abort. Everything needed to continue
                # is preserved; see plan_paused_pending()/resume_paused_plan().
                _plan_paused.update(steps=steps[i:], goal=goal, done=list(done),
                                    at=time.time(), reason=text)
                if _plan_metadata.get("goal") == goal:
                    approvals = _plan_metadata["user_approvals"]
                    note = f"Additional owner authorization pending: {text[:160]}"
                    if note not in approvals:
                        approvals.append(note)
                    _plan_metadata["final_state"] = "paused"
                try:
                    security.audit("plan_paused", f"{where}: {text[:100]}", "waiting")
                except Exception:
                    pass
                return text

            if text and not _STEP_FAILED.search(text):
                done.append((step, text))
                break   # clean success -- no model round trip needed

            # Failed or empty. LOOP BREAKER (rule 5) before spending another
            # model call: the IDENTICAL observation as the last attempt at
            # THIS step means a retry would just repeat it.
            if last_text is not None and text == last_text:
                try:
                    import announce
                    announce.say("plan_loop_broken", urgent=True)
                except Exception:
                    pass
                try:
                    security.audit("plan_loop_broken", f"{where}: {text[:100]}", "aborted")
                except Exception:
                    pass
                return _stopped(step, where, f"it gave the identical result "
                                       f"twice running. {text}")
            last_text = text

            # RULE 5: whichever cap is hit first ends the plan -- per-step,
            # so one flaky step cannot burn the whole plan's retry budget
            # alone, and whole-plan, so a plan that retries EVERY step to
            # its individual cap still cannot run away.
            if step_retries >= MAX_STEP_RETRIES or plan_retries >= MAX_PLAN_RETRIES:
                return _stopped(step, where, text or "it returned nothing")

            # RULE 4: observe, then a bounded continue/retry/abort decision --
            # spent ONLY here, on a step that looks like it failed.
            decision = _observe_decision(step, text, goal)
            if decision == "continue":
                # The model reads THIS specific text as acceptable despite
                # matching _STEP_FAILED's loose pattern -- trusted over the
                # regex for this one call, the same way a human reading the
                # actual words would be.
                done.append((step, text))
                break
            if decision == "retry":
                step_retries += 1
                plan_retries += 1
                continue
            return _stopped(step, where, text or "it returned nothing")
        i += 1

    _plan_paused.update(steps=[], goal="", done=[], at=0.0, reason="")
    body = " ".join(t for _, t in done)
    outcome = f"Done — {len(done)} step{'s' if len(done) != 1 else ''}. {body}"[:900]
    if _plan_metadata.get("goal") == goal:
        _plan_metadata["final_state"] = "completed"
    _remember_plan_outcome(goal, outcome, ok=True)
    return outcome


def run_plan(user_text: str, history: list | None) -> str:
    """Execute the staged plan. See _run_steps() for the per-step loop."""
    if not plan_is_pending():
        _plan.update(steps=[], goal="", at=0.0)
        return "That plan expired — ask me again and I'll work it out fresh."
    steps = list(_plan["steps"])
    goal = _plan["goal"]
    _plan.update(steps=[], goal="", at=0.0)
    # The plan has left the slot; its approval is spent. The grants minted
    # at the plan/run seam stay armed ONLY for this run -- _run_steps claims
    # each one as its step executes, and anything unclaimed dies after.
    if _plan_metadata.get("goal") == goal:
        approvals = _plan_metadata["user_approvals"]
        approvals[:] = [x for x in approvals if x != "Plan approval pending"]
        approvals.append("Owner approved the staged plan")
        _plan_metadata["final_state"] = "running"

    try:
        security.audit("plan_run", f"{len(steps)} steps: {describe_plan(steps)}"[:160],
                       "ok")
    except Exception:
        pass

    out = _run_steps(steps, [], len(steps), user_text, history, goal,
                     grant_minted=bool(_plan_grants))
    _clear_plan_grants()
    return out


def plan_paused_pending() -> bool:
    return (bool(_plan_paused["steps"])
            and time.time() - _plan_paused["at"] <= PLAN_PAUSE_TTL)


def cancel_paused_plan() -> str:
    had = plan_paused_pending()
    goal = _plan_paused.get("goal", "")
    _plan_paused.update(steps=[], goal="", done=[], at=0.0, reason="")
    if had and _plan_metadata.get("goal") == goal:
        _plan_metadata["final_state"] = "cancelled"
        _plan_metadata["user_approvals"].append("Owner cancelled the paused plan")
        _remember_plan_outcome(goal, "Owner cancelled the paused task.", ok=False)
    return "Dropped the paused task." if had else "There's no paused task."


def plan_snapshot() -> dict:
    """Read-only view of whatever plan state currently exists, for callers
    outside this module that want to DESCRIBE it rather than drive it (the
    agent package's TaskState is the first of those). Never returns the live
    dicts themselves -- a caller mutating what it thought was a snapshot must
    not be able to reach into _plan/_plan_paused.

    At most one of "staged" (approved, not yet run) or "paused" (mid-run,
    waiting on something only the owner can supply) is ever non-None: this
    module runs one plan at a time, by design (see the PLAN_PAUSE_TTL
    comment). "none" when neither applies.
    """
    if plan_paused_pending():
        # _plan_paused["done"] is a list of (step, result_text) tuples --
        # see the done.append((step, text)) calls in _run_steps().
        snapshot = {
            "state": "paused",
            "goal": _plan_paused["goal"],
            "reason": _plan_paused["reason"],
            "remaining_steps": [dict(s) for s in _plan_paused["steps"]],
            "results": [
                {"skill": step["skill"], "action": step["action"],
                 "target": step.get("target", ""), "result": text}
                for step, text in _plan_paused["done"]
            ],
        }
        snapshot.update(_task_metadata(_plan_paused["goal"]))
        return snapshot
    if plan_is_pending():
        snapshot = {
            "state": "staged",
            "goal": _plan["goal"],
            "steps": [dict(s) for s in _plan["steps"]],
        }
        snapshot.update(_task_metadata(_plan["goal"]))
        return snapshot
    return {"state": "none"}


def resume_paused_plan(user_text: str, history: list | None) -> str:
    """Re-attempts the step that paused the plan. If auth now allows it
    (unlocked or freshened since, or THIS utterance is the PIN/confirmation
    it was waiting for), continues the remaining steps exactly like
    run_plan() does. Otherwise the re-attempt fails the same way, PAUSES
    again, and the same "here's what I still need" message goes back out --
    never a silent no-op and never a second, different explanation."""
    if not plan_paused_pending():
        _plan_paused.update(steps=[], goal="", done=[], at=0.0, reason="")
        return "That paused task expired — ask me again and I'll work it out fresh."
    steps = list(_plan_paused["steps"])
    done = list(_plan_paused["done"])
    goal = _plan_paused["goal"]
    total = len(done) + len(steps)
    _plan_paused.update(steps=[], goal="", done=[], at=0.0, reason="")
    return _run_steps(steps, done, total, user_text, history, goal,
                      grant_minted=not not _plan_grants)


def _maybe_resume_paused_plan() -> str:
    """Silent, automatic continuation -- ONLY for the "machine was locked"
    pause class, and ONLY once it verifiably is not locked any more.

    Every OTHER pause reason (a confirm word, a stale re-auth, push-to-
    talk) is deliberately left to the explicit PIN/confirm-shaped utterance
    path in intent.py instead: silently re-attempting an L3+ gate with no
    new input would just fail again with the identical message, so nothing
    is gained by trying it automatically. Only "was locked, now is not" can
    genuinely change the outcome without the user having said anything new
    -- unlocking happens through auth's own separate mechanism, and this is
    what lets a paused plan continue the moment that happens rather than
    requiring the owner to also remember to ask for it again.
    """
    if not plan_paused_pending():
        return ""
    if auth.LOCKED_MESSAGE not in (_plan_paused.get("reason") or ""):
        return ""
    if not auth.is_unlocked():
        return ""
    return resume_paused_plan("", None)


def _dispatch_chain(steps: list, user_text: str, history: list | None,
                    via: str = "chain") -> str:
    """Executes a validated sequence of read-only lookups and combines their
    results into one spoken reply.

    Every step is checked against CHAINABLE before anything runs -- not
    trusted because the model said "steps", and not checked one at a time
    interleaved with execution either, since that would run the first two
    steps of a three-step plan before discovering the third is unsafe. All
    or nothing, decided up front.

    No extra model call synthesizes the combined answer into one smoother
    sentence -- deliberately. Every additional Ollama round trip on this
    hardware costs real, measured seconds (see today's model comparison:
    3-4s even for a single warm call), and a chain already means at least
    two skill calls; adding a third call just to rephrase their concatenation
    would make the slowest path in the app slower still for a polish gain.
    Plain concatenation of already-complete sentences is a real cost/quality
    trade, not an oversight.
    """
    if not steps or len(steps) > MAX_CHAIN_STEPS:
        return brain.answer(user_text, history)

    parts = []
    for step in steps:
        if not isinstance(step, dict):
            return brain.answer(user_text, history)
        skill, action = step.get("skill"), step.get("action")
        if (skill, action) not in CHAINABLE:
            print(f"[route] chain step rejected (not chainable): {skill}/{action}")
            return brain.answer(user_text, history)
        # CHAINABLE deliberately includes the read-only web lookups (a chain may
        # be "check the weather and search for a fix"), so a chain built for a
        # local-only request has to be checked for them here as well -- all or
        # nothing, up front, exactly like the rest of this validation.
        scope = _egress_scope(skill, action)
        if scope is not None:
            return _withhold_web(skill, action, scope)
        # Authorized PER STEP, up front, alongside the chainable check. A chain
        # is a sequence the model chose without a human looking at each item,
        # so the fact that one step was permitted says nothing about the next
        # -- and checking them only as they execute would run the first two
        # before discovering the third is denied.
        allowed, reason = auth.authorize(skill, action, str(step.get("target", "")))
        if not allowed:
            security.audit("blocked",
                           f"chain step {auth.describe_level(skill, action)}", "denied")
            lvl = auth.level_for(skill, action)
            security.security_event(
                security.PRIVILEGE_ESCALATION_ATTEMPT if lvl >= auth.L3_CONFIRM
                else security.TOOL_DENIED,
                skill=skill, action=action or "-", level=lvl,
                source="chain", status="failed")
            return reason

    for step in steps:
        result = _dispatch(
            {"skill": step.get("skill"), "action": step.get("action"),
             "target": step.get("target", "")},
            user_text, history, via,
        )
        if result and str(result).strip():
            parts.append(str(result).strip())

    if not parts:
        return brain.answer(user_text, history)
    return " ".join(parts)


# ─── Conversational fast path ──────────────────────────────────────────
# Measured, not guessed: a question that misses intent.match() used to cost
# ~2870ms on the local router model BEFORE the answer was even started, and
# the answer itself is 604ms from Groq. 82% of the wait was a 3B model being
# asked to classify something it then classified WRONG -- "why is the sky
# blue", "do you know about uzbekistan" and "explain how encryption works"
# were all sent to a Wikipedia title lookup.
#
# Routing via Groq instead is not the answer either: the routing prompt is
# ~1000 tokens and the free tier allows 8000 tokens/minute, so six routing
# calls would exhaust the budget that the ANSWERS need. Measured as HTTP 429.
#
# So: recognise plainly conversational input locally, for free, and send it
# straight to chat. This is deliberately a HIGH-PRECISION test -- it must
# never swallow a real command -- so it requires an opening conversational
# shape AND the absence of any machine-control word. Anything it is not sure
# about still goes to the LLM router exactly as before.

# Openers that only ever introduce open-ended talk.
# WIDENED, because every miss costs about three seconds.
#
# This pre-filter exists to skip the LLM router for open-ended talk. Measured
# on the final assessment, a question that misses it pays ~2.9s for a routing
# decision before the answer even starts:
#
#   "is Python faster than C"                 3974ms   (opener "is" absent)
#   "which is bigger, the moon or Australia"  3942ms   ("which" absent)
#   "what does CEH stand for"                 3828ms   ("what does" not matched)
#   "what year did the Berlin Wall fall"      3474ms   ("what year" not matched)
#   "um so what is quantum computing"         3078ms   (TWO leading fillers)
#   "hey could you please tell me..."         3326ms   ("please" between)
#
# Widening is safe here in a way it would not be elsewhere: intent.match()
# has already run and claimed every command it recognises, and _MACHINE_WORD
# below still vetoes anything naming the machine. What reaches this point
# with no machine word in it is, in practice, conversation.
_CHATTY_OPENER = re.compile(
    # Any number of leading fillers, not just one.
    r"^(?:(?:so|and|but|ok|okay|hey|well|um|uh|erm|like|right)\s+)*"
    r"(?:"
    # "what is/are/does/did/kind/year/sort..." -- anything but the clock.
    r"what\b(?!\s+(?:time|day|date)\b)"
    r"|why\b|which\b|whose\b|whom\b"
    r"|when\s+(?:was|were|did|is|are|does)\b"
    r"|where\s+(?:was|were|did|is|are|does)\b"
    r"|how\s+(?:come|do(?:es)?|would|can|is|are|did|long|many|much|far|old|tall|big)\b"
    r"|do\s+you\s+(?:know|think|like|have|reckon|believe)\b"
    r"|(?:can|could|would|will)\s+you\s+(?:\w+\s+){0,2}"
    r"(?:tell|explain|help|write|give|suggest|recommend|describe|summari[sz]e)\b"
    r"|tell\s+me\s+(?:about|something|more|why|how|what|a\s+bit)\b"
    r"|explain\b|describe\b|compare\b|define\b"
    r"|should\s+i\b"
    # A bare copula question: "is X faster than Y", "are cats smarter than dogs".
    r"|(?:is|are|was|were)\s+\w+"
    r"|who\s+(?:was|were|is|are|invented|discovered|wrote|created|founded)\b"
    r"|give\s+me\s+(?:some|a\s+few|ideas|advice|info)\b"
    r"|i\s+(?:wonder|want\s+to\s+know|was\s+wondering)\b"
    r")",
    re.I,
)

# Any of these means the machine itself is the object of the sentence, so the
# real router has to look at it. Kept deliberately broad -- a false hit here
# only costs the old behaviour, while a miss would send a command to chat.
_MACHINE_WORD = re.compile(
    r"\b(open|close|quit|launch|start|stop|play|pause|resume|mute|unmute|"
    r"volume|brightness|screenshot|screen|shut\s*down|shutdown|restart|reboot|"
    r"sleep|lock|sign\s*out|log\s*out|timer|remind|reminder|alarm|"
    r"cpu|ram|memory|disk|battery|temperature|process|processes|task|"
    r"wifi|wi-fi|network|internet|ip\b|bandwidth|"
    r"file|files|folder|delete|remove|clipboard|copy|paste|type|dictate|"
    r"window|minimi[sz]e|maximi[sz]e|switch\s+to|focus|"
    r"note|notes|vault|profile|remember|forget|privacy|listen|"
    r"diagnos|anomal|log|audit|weather|youtube|spotify|chrome|telegram|"
    r"discord|steam|explorer|obsidian|notepad|calculator|"
    r"my\s+(?:pc|computer|machine|laptop|system|screen|desktop))\b",
    re.I,
)


# ── verbs that mean DO SOMETHING, not tell me something ─────────────────
# Used in an imperative position: at the start of the sentence, or right
# after "can/could/would/will you" / "please".
_ACTION_VERB = re.compile(
    r"\b(open|launch|start|run|execute|close|quit|kill|exit|"
    r"play|pause|resume|skip|mute|unmute|"
    r"set|turn|increase|decrease|raise|lower|adjust|change|"
    r"take|capture|screenshot|snap|"
    r"delete|remove|erase|move|rename|copy|paste|type|dictate|write|send|"
    r"search|google|look\s+up|find|locate|show|display|list|"
    r"lock|unlock|shut\s*down|shutdown|restart|reboot|sleep|hibernate|"
    r"sign\s*out|log\s*out|"
    r"remind|schedule|snooze|cancel|clear|empty|"
    r"switch|focus|minimi[sz]e|maximi[sz]e|"
    r"save|note|remember|forget|read|summari[sz]e|translate|convert|"
    r"stop|repeat)\b",
    re.I,
)

_IMPERATIVE = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|please|argus)\s+)*"
    r"(?:(?:can|could|would|will|please)\s+you\s+(?:please\s+)?)?"
    r"(?:please\s+)?" + _ACTION_VERB.pattern,
    re.I,
)

_QUESTION = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|um|uh|erm|like|right|argus)\s+)*"
    r"(?:what|why|who|whom|whose|which|when|where|how|is|are|was|were|am|"
    r"do|does|did|can|could|would|should|will|shall|may|might|has|have|had|"
    r"tell\s+me|explain|describe|compare|define)\b",
    re.I,
)


# Appended to the classifier prompt for a request the routing policy marked
# local-only. The model is TOLD what it may not pick, and _keep_local() below
# enforces it whether or not the 3B model obeyed: the prompt is a nudge toward the
# right local skill, the filter is the guarantee.
_LOCAL_ONLY_MENU = """

THIS REQUEST REFERS TO THE USER'S OWN MACHINE OR DATA. Choose only a skill that
reads or acts on this machine -- "files", "document", "vault", "profile", "apps",
"storage", "pc", "diag", "context" and the like. NEVER choose "research",
"knowledge", "web", "browser" (search) or "intel": nothing about this request may
go to the internet. If no local skill fits, answer "chat"."""


def _keep_local(decision: dict) -> dict:
    """A local-only request may not be classified into a web skill, alone or as
    a step of a chain. If the model picked one anyway the whole decision becomes
    chat, which is answered by the local model and nothing else."""
    steps = decision.get("steps") if isinstance(decision, dict) else None
    for step in (steps if isinstance(steps, list) else [decision]):
        if isinstance(step, dict) and cloud_gate.is_web_lookup(
                step.get("skill"), step.get("action")):
            print(f"[route] policy: classifier picked {step.get('skill')}/"
                  f"{step.get('action')} for a local request -- answering "
                  f"locally instead")
            return {"skill": "chat", "action": "reply", "target": ""}
    return decision


def _decide(user_text: str, history: list | None = None, policy=None) -> dict:
    """Ask the MODEL what this is: something to answer, or something to do.

    Reached only for input that _is_conversational() did not claim -- i.e.
    something that looks like it wants an action performed.

    POLICY is the request's routing decision (cloud_gate.Decision). When it says
    the request is local-only the model is given a menu with the web skills
    removed and its answer is filtered against the same list.

    WHY NOT ASK THE MODEL ABOUT EVERYTHING. That was tried and measured, and
    it was worse. Routing every utterance through the model sent plain factual
    questions to the Wikipedia skill: "what is the capital of kazakhstan"
    came back as a paragraph about population rather than "Astana", and "and
    then" returned a disambiguation page about a Japanese novel. Three of
    twenty-three answers became slow where none had been. A model asked
    "which tool fits this?" will find one, because that is the question it
    was given -- so the decision of whether a tool is wanted at all belongs
    before it, and defaults to no.

    THE CLOUD TIER RUNS THIS. The same decision on the local model took up to
    92 seconds and then raised, leaving the person with nothing at all. That
    is where the reported silence actually came from.

    WHAT THIS DOES NOT CHANGE. The model says what it thinks the user MEANT.
    It does not decide what is permitted: _dispatch() still validates every
    (skill, action) against the fixed allowlist, and the security layer still
    authorises the action independently. A model that asks for something not
    on the list gets nothing, exactly as before.
    """
    # ── THE ROUTING DECISION NEVER LEAVES THIS MACHINE ─────────────────────
    #
    # This used to try Groq first, with cloud_gate deciding eligibility. That
    # was defensible on latency grounds and wrong on the one that matters: the
    # thing being classified here is WHAT TO DO TO THIS COMPUTER. Sending it
    # out meant a third party saw "open my banking folder", "delete the
    # invoices", "what's on my screen" -- the imperative half of everything
    # said to the assistant -- and chose which tool ran.
    #
    # Stated by the owner as a rule, in as many words: Ollama for controlling
    # the PC, cloud for conversation only. It is also the better architecture,
    # because it makes the property STRUCTURAL rather than a routing promise:
    # there is now no code path at all from a command to a cloud provider, so
    # there is no phrasing, no jailbreak and no misconfiguration that can send
    # one. cloud_gate can be got wrong; a missing import cannot.
    #
    # WHAT THIS COSTS, honestly: a local classification is slower than Groq's
    # ~174ms, and on a cold model it can be seconds. Three things keep that
    # from being the common case -- intent.match() answers most commands with
    # no model at all, _is_conversational() sends everything that is not a
    # command straight to the answer path, and the model here is the small
    # router model under json_mode rather than the conversational one.
    #
    # CHAT IS UNAFFECTED. brain.answer() still uses the cloud tiers for
    # conversation, under cloud_gate's own rules. What changed is only that
    # the decision about the MACHINE is made on the machine.
    local_only = policy is not None and policy.local_required
    try:
        decision = chat_json(ROUTING_PROMPT + (_LOCAL_ONLY_MENU if local_only else ""),
                             user_text)
        if local_only:
            decision = _keep_local(decision)
        print(f"[route] decided locally -> {decision.get('skill', 'chat')}")
        return decision
    except Exception as e:      # noqa: BLE001 -- never a dead end; see below
        # Never a dead end. If nothing can classify the request, answering it
        # is strictly better than saying nothing.
        print(f"[route] no classifier available ({e.__class__.__name__}); "
              f"answering directly")
        return {"skill": "chat", "action": "reply", "target": user_text}


def _is_conversational(user_text: str) -> bool:
    """Should this go straight to the language model rather than the
    skill-classifying LLM?

    THIS IS THE DEFAULT, AND THAT IS THE POINT.

    It used to be an allowlist: a narrow "chatty opener" regex, vetoed by any
    word that named the machine. Everything else was sent to a local LLM asked
    to choose a skill. Two consequences, both reported repeatedly as "it
    ignores me" and neither of them actually ignoring anything:

      "what is the difference between ram and storage"
          -> vetoed by the word "ram", classified as a skill request, and
             answered with a scan of the home folder.

      "i am a bit worried about my exam next week"
          -> matched no opener (it is a statement, not a question), went to
             the classifier, and came back "Operational. What are we doing?"

    A person talking to an assistant mostly is not issuing commands. So the
    question is inverted: instead of proving the input is chat, ARGUS now has
    to find a reason NOT to treat it as chat. intent.match() has already run
    and claimed every command and every live reading it recognises, so what
    reaches here is either conversation or an unusually phrased action -- and
    an action says so with a verb.

    The cost of a mistake is asymmetric, which is why the default sits where
    it does. Sending an odd command here means ARGUS talks about doing the
    thing instead of doing it, and the person rephrases. Sending a question to
    the classifier means a confident, irrelevant answer to something else
    entirely, which is what made it feel broken.
    """
    t = (user_text or "").strip().lower()
    if not t:
        return False

    # An imperative is a command however it is worded. Let the router look.
    if _IMPERATIVE.match(t):
        return False

    # A QUESTION is a question. Position matters, not presence: the check
    # above already ruled out "could you delete that file", so a verb left
    # inside a question is embedded in it, not commanding it.
    #
    # An earlier version vetoed a question containing an action verb ANYWHERE,
    # which is the very mistake this function exists to correct. "what
    # actually happens when i delete a file" was sent to the classifier and
    # answered "I couldn't find anything matching filename to delete" -- a
    # question about how filesystems work, answered as a failed deletion.
    #
    # The machine-word veto is deliberately not applied here either: "why is
    # my laptop slow" and "what is the difference between ram and storage"
    # both name the machine and both want an explanation.
    if _QUESTION.match(t):
        return True

    # Not a question and not an imperative: a statement. Nothing is being
    # asked for, so this is talk -- even when it happens to contain a word
    # that is elsewhere a command. "i did not sleep well" was routed on the
    # word "sleep" and answered "Running clean. What can I do?"; "i have been
    # staring at this screen all day" was routed on "screen".
    #
    # A terse bare noun is the exception. "volume", "wifi", "brightness" are
    # far more likely clipped commands than the opening of a conversation,
    # and the router is the right place to decide which.
    if len(t.split()) >= 3 or not _MACHINE_WORD.search(t):
        return True

    return False


def _followup(user_text: str):
    """An elliptical follow-up, resolved against the previous exchange.

    Checked AFTER intent.match() rather than before: a fast-path match is an
    explicit, complete instruction and must always win. "open chrome" said
    right after "open discord" is a new command, not a follow-up -- only
    utterances that intent.py itself couldn't place are candidates.
    """
    d = followup_skill.resolve(user_text)
    if d:
        print(f"[route] follow-up -> {d.get('skill')}/{d.get('action')} ({d.get('target')})")
    return d


def handle(user_text: str, history: list | None = None) -> str:
    """Route and answer, with a guarantee: never silence.

    Whatever path _route() takes, an EMPTY reply is turned into a real answer
    from the model instead of reaching the user as nothing at all. Silence is
    the single worst outcome here -- it is indistinguishable from ARGUS not
    having heard, which is exactly the "it ignores me" complaint, and it can be
    produced by any skill that returns "" on an edge case it did not anticipate.
    A structural net is worth more than auditing every skill's return values.

    Two things are deliberately NOT overridden: the __SILENT__ sentinel, which
    is a chosen silence (the stop-talking path), and an authorization refusal,
    which is a real answer the user needs to see rather than a gap to paper over.
    """
    reply = _route(user_text, history)
    if isinstance(reply, str) and reply.strip():
        return reply
    if reply is not None and str(reply).strip() == "__SILENT__":
        return reply
    print("[route] empty reply -> falling back to chat so nothing is ignored")
    try:
        answer = brain.answer(user_text, history)
    except Exception as e:
        return (f"I couldn't work out how to answer that "
                f"({type(e).__name__}). Try asking a different way.")
    return answer if (answer or "").strip() else (
        "I don't have an answer for that one — try asking a different way.")


# A search verb applied to something the person calls THEIRS is a search of this
# machine, not of the web: "search for my thesis", "look up my invoices", "google
# my old resume". intent.py reads the bare verb as a web command, which is how a
# request about a file on this PC became a search-engine query. "find my X" has
# always been a file search (intent's FILES section); this makes its synonyms one.
_SEARCH_MY = re.compile(
    r"^(?:(?:please|hey|argus|can\s+you|could\s+you|would\s+you)\s+)*"
    r"(?:search|look|dig|hunt|google)\s*(?:around\s+)?(?:for|up|out)?\s+"
    r"(?:in\s+)?(?:my|our)\s+(?P<what>.+?)\s*[.?!]*$", re.I)


def _localize(user_text: str):
    """The local search a web-lookup command really meant, or None.

    Only for something that could BE a file. "look up my ip" is a reading of the
    machine and "google my name" is a fact about them; turning either into a search
    for a file called "ip" or "name" would answer a different question.
    """
    m = _SEARCH_MY.match((user_text or "").strip())
    if not m:
        return None
    what = re.sub(r"\b(?:files?|documents?|folders?)\b", " ", m.group("what"))
    what = re.sub(r"\s+", " ", what).strip()
    if not what or cloud_gate.names_a_fact_or_reading(what):
        return None
    print(f"[route] policy: '{user_text.strip()[:40]}' is a search of this "
          f"machine -> files/find {what!r}")
    return {"skill": "files", "action": "find", "target": what}


def _admit(d: dict, user_text: str, decision):
    """Pass a route candidate through the routing policy. Returns (candidate, said):

        (D, None)        it may run as it is
        (search, None)   D was a web lookup for a local request that only LOOKED like
                         a web command: this is the local search it meant
        (None, text)     it must not run, and TEXT says so and says what to do instead

    A web lookup is the only thing withheld. Every other skill is local or public
    already and is authorised, and audited, by the ordinary path."""
    if not (decision.local_required
            and cloud_gate.is_web_lookup(d.get("skill"), d.get("action"))):
        return d, None
    print(f"[route] policy: {d.get('skill')}/{d.get('action')} would send a local "
          f"request to the web -- {decision.describe()}")
    try:
        security.security_event(security.TOOL_DENIED, skill=d.get("skill", "-"),
                                action=d.get("action") or "-",
                                reason="local_required_egress", status="failed")
    except Exception:
        pass
    # They NAMED the web ("search the web for my thesis", "look up my resume on the
    # web"). Quietly turning that into a search of this machine would answer a
    # different question -- and with a target like "resume on the web" -- so it is
    # said out loud instead. A BARE verb ("search for my thesis") is the ambiguous
    # one, and is read as the local search it almost always means.
    if decision.mixed and decision.web:
        return None, cloud_gate.DENIED_MIXED_WEB
    local_search = _localize(user_text)
    if local_search:
        return local_search, None
    return None, cloud_gate.DENIED_WEB



# cloud specialists into ordinary routing) ──────────────────────────────────
#
# ONE team runs at a time, same discipline as the plan slot above: a second
# "why is my PC slow" while the first is still running does not start a
# second investigation, it reports on the one already in flight.
_active_team_id = ""

# Bounded so a synchronous voice/text turn can never hang indefinitely on a
# team that is still within ITS OWN (much larger) max_runtime_seconds. Past
# this, the team keeps running in the background (agents/orchestrator.py's
# own scheduler thread owns it) and the turn ends honestly rather than
# blocking the conversation.
_TEAM_WAIT_S = 90.0


def _team_assessment(user_text: str, decision):
    """agents.team_planner.assess(), gated a second time by THIS request's
    own routing decision -- team_planner runs its own cloud_gate check per
    goal (agents/team_planner._cloud_eligible), but that call is on the bare
    text alone; DECISION here also carries the sticky follow-up window
    (cloud_gate.decide(), not classify()), so a cloud team must additionally
    never be offered when the outer decision -- which knows about the
    conversation, not just this sentence -- already called the turn local.
    """
    try:
        from agents import team_planner
    except Exception:
        return None
    try:
        a = team_planner.assess(user_text)
    except Exception:
        return None
    if not a.needs_team:
        return None
    if decision.local_required and any(
            s in team_planner.CLOUD_ROLES for s in a.specialists):
        return None
    return a


def has_active_team() -> bool:
    if not _active_team_id:
        return False
    from agents.orchestrator import orchestrator
    t = orchestrator().team(_active_team_id)
    return bool(t and t["state"] not in (
        "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "TIMED_OUT"))


def cancel_active_team() -> str:
    """Called from skills/pc_skill.stop_speaking() -- "stop"/"cancel" reaches
    a running team through the SAME utterance that already interrupts TTS,
    rather than needing its own trigger phrase. Never raises: a cancel
    request that finds nothing to cancel is not an error."""
    global _active_team_id
    tid = _active_team_id
    if not tid:
        return ""
    from agents.orchestrator import orchestrator
    orchestrator().cancel_team(tid, "voice_cancel")
    _active_team_id = ""
    return tid


def _team_summary(result: dict) -> str:
    """§17: a spoken summary, not the report. 2-4 short sentences from the
    team's own composed result -- never the raw findings list, never a model
    call to compose it (the team's own `summary` field is already built by
    code, deterministically, in agents/orchestrator.py)."""
    if result is None:
        return "I couldn't get a result for that."
    state = result.get("state", "")
    parts = [str(result.get("summary") or "").rstrip(".") + "."]
    observed = (result.get("findings") or {}).get("observed") or []
    if observed:
        lead = observed[0].get("text", "")
        if lead:
            parts.append(lead.rstrip(".") + ".")
    proposals = result.get("action_proposals") or []
    if proposals:
        first = proposals[0]
        what = f"{first.get('skill', '')} {first.get('action', '')}".strip()
        parts.append(
            f"I'd suggest {what or 'one thing'}"
            + (f" and {len(proposals) - 1} other thing"
               f"{'s' if len(proposals) != 2 else ''}" if len(proposals) > 1 else "")
            + " — say yes and I'll do it.")
    elif state == "PARTIAL":
        missing = result.get("missing_work") or []
        if missing:
            parts.append(f"I couldn't finish {len(missing)} part"
                        f"{'s' if len(missing) != 1 else ''} of that.")
    elif state in ("FAILED", "CANCELLED", "TIMED_OUT"):
        parts.append("I wasn't able to complete that.")
    return " ".join(parts)[:600]


def _run_team(assessment, user_text: str, history: list | None):
    """Submit + bounded wait. Shared by the blocking and streaming team
    dispatchers so they cannot drift apart -- same reasoning as
    _resolve()/_resolve_route() above."""
    global _active_team_id
    from agents.orchestrator import orchestrator
    orch = orchestrator()
    route_trace.event("team_created", assessment.playbook)
    sub = orch.submit_complex_task(user_text)
    if not sub.accepted:
        # The gate said yes; the orchestrator's own (stricter, budget-aware)
        # gate said no -- e.g. a team is already at MAX_ACTIVE_TEAMS. Honest
        # fallback: answer it directly rather than silence.
        return None, brain.answer(user_text, history)
    _active_team_id = sub.team_id
    route_trace.event("team_started", sub.team_id)
    result = orch.wait(sub.team_id, _TEAM_WAIT_S)
    if _active_team_id == sub.team_id:
        _active_team_id = "" if result is not None else _active_team_id
    if result is None:
        return None, ("I'm still working on that — it's taking longer than "
                      "usual. Ask me again in a moment and I'll have it.")
    route_trace.event("team_completed", result.get("state", ""))
    security.audit("agent_team_voice", f"{sub.team_id} {result.get('state')}", "ok")
    global _last_team_result
    _last_team_result = {**result, "_at": time.time()} \
        if result.get("action_proposals") else None
    return result, _team_summary(result)


_last_team_result: dict | None = None

# A clean affirmative ONLY -- intransitive, same anchoring discipline as
# intent.py's STOP pattern above. Deliberately narrow: this only ever
# resolves to a proposal a team already vetted through the real capability
# boundary (agents/capabilities.py, capped at L2 -- REQUEST_RISK_CAP -- so it
# can never be a confirm-gated action), and ONLY within 5 minutes of that
# team's report, so it can never attach to an unrelated later "yes".
_TEAM_ACTION_YES = re.compile(
    r"^(?:yes|yeah|yep|sure|ok|okay|please\s+do|go\s+ahead|do\s+(?:it|that|"
    r"those)|apply\s+that|fix\s+it|do\s+the\s+first\s+one)\s*[.!]?\s*$", re.I)
_TEAM_ACTION_WINDOW_S = 300.0


def _team_action_followup(user_text: str):
    """The one proposal a completed team surfaced, if this utterance plainly
    accepts it. Returns a {skill, action, target} dict for the NORMAL
    _admit()/_dispatch() path -- same auth.authorize() gate, same audit, same
    telemetry as any other command; nothing here executes anything itself.
    """
    global _last_team_result
    r = _last_team_result
    if r is None or not _TEAM_ACTION_YES.match((user_text or "").strip()):
        return None
    if time.time() - r.get("_at", 0.0) > _TEAM_ACTION_WINDOW_S:
        _last_team_result = None
        return None
    proposals = r.get("action_proposals") or []
    if not proposals:
        return None
    p = proposals[0]
    _last_team_result = None    # single-use, like auth's own confirmation slot
    return {"skill": p.get("skill", ""), "action": p.get("action", ""),
           "target": p.get("target", "")}


def _dispatch_team(assessment, user_text: str, history: list | None) -> str:
    _result, text = _run_team(assessment, user_text, history)
    return text


def _stream_team(assessment, user_text: str, history: list | None):
    yield "One moment, I'm looking into that."
    _result, text = _run_team(assessment, user_text, history)
    yield text


def _resolve_route(user_text: str, history: list | None, decision):
    """Which way does this request go? Returns (kind, payload, via):

        ("dispatch", {skill, action, target}, via)   run one skill
        ("chain", [steps], "chain")                  run a read-only sequence
        ("say", text, "policy")                      a fixed reply, nothing run
        ("chat", None, via)                          answer it with the language model

    THE ROUTING POLICY IS ALREADY DECIDED by the time this runs (DECISION), and
    it constrains every branch: a web lookup is never a valid answer for a local
    request, whichever branch proposed it. Written once and shared by the
    blocking and streaming entry points, which used to carry two copies of this
    ladder that could drift apart.

    Order is unchanged: intent.match (deterministic) -> follow-up -> chat as the
    default -> the local classifier. What is new is only that a LOCAL request
    which asks about the content or state of something of theirs ("what does my
    lease say") skips the chat default, because a chat model has nothing to read
    it from -- a skill does. See cloud_gate.Decision.wants_capability.

    One narrow exception runs first: "where is SECURITY?" / "who is the log
    analysis specialist?" -- a question whose WHOLE subject is one of ARGUS's
    own workers -- is about the organisation, and the fast path would read it
    as a file search / knowledge lookup. agents.agent_manager.org_first
    answers only on an exact worker name, so every other "where is ..." still
    reaches files/find. It is read-only state; nothing is dispatched.
    """
    try:
        from agents.agent_manager import org_first
        early = org_first(user_text)
    except Exception:
        early = None
    if early:
        print("[route] organisation question -> agent manager")
        return ("say", early, "agent_manager")
    # Academy commands are local, synthetic analysis requests using the same
    # coordinator queue. Match them before generic fast intents so "send
    # SYSTEM to study" cannot be mistaken for a machine-control skill.
    try:
        from agents.academy import command as academy_command
        study_reply = academy_command(user_text)
    except Exception:
        study_reply = None
    if study_reply:
        print("[route] academy command")
        return ("say", study_reply, "academy")
    fast = intent.match(user_text)
    if fast:
        print(f"[route] fast -> {fast.get('skill')}/{fast.get('action')}")
        fast, said = _admit(fast, user_text, decision)
        if said:
            return ("say", said, "policy")
        if fast:
            return ("dispatch", fast, "fast")

    # How hot a part of THIS machine is has no skill to run: nothing here reads
    # a component temperature. intent.match() has already declined it (None),
    # and two things downstream would still misanswer it. The local classifier is
    # asked whenever cloud_gate frames the phrase as an operation or a lookup
    # ("check my cpu temperature", "is my cpu overheating") or it is a bare
    # fragment ("cpu temps", which _is_conversational reads as a clipped
    # command), and a model asked "which tool fits?" finds one: measured, six of
    # seven came back pc/stats (a CPU LOAD reading offered as the answer to a
    # temperature question) and the seventh an action that does not exist. And
    # the follow-up resolver below retargets the previous command at anything
    # shaped like an ellipsis, so after a weather query "what about my cpu
    # temperature" became weather/get for "my cpu temperature". A fully named
    # question is neither, so it goes to chat before either can act -- except
    # when it is a web request carrying machine detail: that denial, further
    # down, still speaks first.
    if (intent.is_machine_heat_question(user_text)
            and not (decision.local_required and decision.mixed and decision.web)):
        print("[route] machine heat question -> chat (no sensor to read)")
        return ("chat", None, "conversational")

    follow = _followup(user_text)
    if follow:
        follow, said = _admit(follow, user_text, decision)
        if said:
            return ("say", said, "policy")
        if follow:
            return ("dispatch", follow, "followup")

    # A plain "yes" accepting the one thing a just-completed team proposed

    # IS one: an elliptical reference to the team's own report rather than to
    # a skill's last answer. Still just a normal dispatch from here on: the
    # SAME auth.authorize() gate as any command decides whether it actually
    # runs, so nothing about "yes" grants anything a spoken command has to
    # go through its allowlist and risk cap for.
    team_action = _team_action_followup(user_text)
    if team_action:
        team_action, said = _admit(team_action, user_text, decision)
        if said:
            return ("say", said, "policy")
        if team_action:
            return ("dispatch", team_action, "team_action")

    # ORGANISATION COMMANDS ("who is working right now?", "ask the Agent
    # Manager for a progress report", "what is SYSTEM doing?", "cancel that
    # specialist", "tell SECURITY to ..."): answered from the Agent Manager's
    # real runtime state, or turned into the SAME requests the HUD sends
    # (an analysis job, a team goal, releasing a temporary agent). Nothing
    # here dispatches a skill or reaches an executor -- agents/ cannot -- so a
    # spoken org command gains no authority a typed one lacks. Pure regex
    # until one matches: every other request pays microseconds.
    try:
        from agents.agent_manager import org_query
        org_reply = org_query(user_text)
    except Exception:
        org_reply = None
    if org_reply:
        print("[route] organisation command -> agent manager")
        return ("say", org_reply, "agent_manager")

    # They asked for the web AND named something of theirs. Guessing would mean
    # either searching with their machine's details or quietly not searching;
    # the honest third option is to say so and ask for a clean query.
    if decision.local_required and decision.mixed and decision.web:
        return ("say", cloud_gate.DENIED_MIXED_WEB, "policy")


    # no single skill or plain chat answer does justice to. Checked BEFORE
    # the conversational shortcut on purpose -- "why is my PC slow" and
    # "investigate whether this machine is compromised" are both phrased as
    # questions (_is_conversational would otherwise claim them for a single
    # local-model guess with no real telemetry/evidence behind it) -- and
    # reuses agents/team_planner.assess() exactly: a trivial goal declines in
    # ~20us with no model call, so "CPU usage?" and "tell me a joke" are
    # exactly as fast as before this existed.
    if not decision.wants_capability and not has_active_team():
        assessment = _team_assessment(user_text, decision)
        if assessment is not None:
            print(f"[route] team -> {assessment.playbook}")
            return ("team", assessment, "team")

    if not decision.wants_capability and _is_conversational(user_text):
        print("[route] conversational -> chat")
        return ("chat", None, "conversational")

    chosen = _decide(user_text, history, decision)
    if isinstance(chosen.get("steps"), list):
        print(f"[route] chain -> {len(chosen['steps'])} step(s)")
        return ("chain", chosen["steps"], "chain")
    if chosen.get("skill", "chat") == "chat":
        return ("chat", None, "decided")
    return ("dispatch", chosen, "model")


def _resolve(user_text: str, history: list | None, decision):
    """_resolve_route(), plus a note of which route class the answer was.

    The route class (DETERMINISTIC, LOCAL_DIRECT, LOCAL_REASONING, CLOUD_GENERAL,
    EXPLICIT_WEB, COMPLEX_LOCAL, DENIED) is recorded HERE, at the one place every
    request's path is decided, so it is written once and cannot disagree between
    the blocking and the streaming entry point. Recording only: nothing returned
    below differs from what _resolve_route() decided."""
    kind, payload, via = _resolve_route(user_text, history, decision)
    _note_route(kind, payload, via, decision)
    return kind, payload, via


def _note_route(kind: str, payload, via: str, decision) -> None:
    trace = route_trace.current()
    if trace is None:
        return
    R = route_trace.Route
    try:
        if kind == "dispatch":
            skill, action = payload.get("skill", ""), payload.get("action", "")
            route = route_trace.route_for_capability(skill, action)
            # A skill the LOCAL CLASSIFIER chose cost a model call to choose, so it
            # is not a rule-driven path however deterministic the skill itself is.
            if via == "model" and route in (R.DETERMINISTIC, R.LOCAL_DIRECT):
                route = R.LOCAL_REASONING
            trace.set_route(route, f"{via}: {skill}/{action}")
        elif kind == "chain":
            trace.set_route(R.COMPLEX_LOCAL, f"{len(payload)} step(s)")
        elif kind == "team":
            from agents import team_planner
            cloud = any(s in team_planner.CLOUD_ROLES for s in payload.specialists)
            trace.set_route(R.COMPLEX_CLOUD_SAFE if cloud else R.COMPLEX_LOCAL,
                            f"team: {payload.playbook}")
        elif kind == "say" and via == "agent_manager":
            # An organisation command answered from the Agent Manager's state:
            # code, not a model, and not a refusal.
            trace.set_route(R.DETERMINISTIC, "agent manager: organisation command")
        elif kind == "say" and via == "academy":
            trace.set_route(R.DETERMINISTIC, "academy: synthetic training command")
        elif kind == "say":
            # A refusal with fixed wording, and there are two: a web request that
            # also named something private, and a web lookup for a local request
            # that could not be turned into a local search. Compared against the
            # constants, never the text -- the wording is the policy owner's to change.
            if payload == cloud_gate.DENIED_MIXED_WEB:
                trace.deny("web request mixed with local data")
            elif payload == cloud_gate.DENIED_WEB:
                trace.deny("web lookup refused for a local request")
            else:
                trace.deny("refused by routing policy")
        elif decision.local_required:
            trace.set_route(R.LOCAL_REASONING, "answered by the local model")
        elif decision.web_ok:
            trace.set_route(R.EXPLICIT_WEB, "asked for the web")
        else:
            trace.set_route(R.CLOUD_GENERAL, "general conversation")
    except Exception:   # noqa: BLE001 -- instrumentation never affects a request
        pass


def _open_scope(user_text: str):
    """Reset per-request state and decide what this request may touch.

    THE POLICY DECISION IS MADE HERE, FIRST, once, before any tier runs, and
    everything after it -- the router ladder, brain, the clients, the web skills
    -- reads that one answer rather than re-deriving its own.
    """
    # Talking to ARGUS IS activity. The idle lock used to be reset only by a
    # command that passed the gate, so half an hour of conversation re-locked
    # mid-chat and the next machine command asked for the PIN. is_unlocked()
    # applies the idle timeout first, so a request after a real absence still
    # finds ARGUS locked.
    if auth.is_unlocked():
        auth.touch()

    # "local" until proven otherwise -- see cloud_gate.py. Reset at the top of
    # every command so a skill dispatch (which never touches brain.py or a cloud
    # call at all) is correctly tagged by the SAFE default rather than
    # inheriting whatever the PREVIOUS exchange happened to set.
    cloud_gate.reset_engine()
    decision = cloud_gate.decide(user_text)
    trace = route_trace.current()
    if trace is not None:
        trace.event("router_started")
        trace.note_policy(decision)
        if decision.local_required:
            # Provisional: the more specific route (a skill, the local model, a
            # refusal) replaces this once _resolve() knows it.
            trace.set_route(route_trace.Route.LOCAL_REQUIRED,
                            f"policy: {decision.frame or decision.scope}")
    if decision.local_required:
        # Flag the exchange local now, whatever route it takes, so history never
        # forwards its reply to a hosted model. A follow-up that is local only
        # because it followed one does not extend the sticky window (brain and
        # the dispatcher do that, for content).
        cloud_gate.note_exchange_local()
        print(f"[route] policy -> {decision.describe()}")
    return decision


def _route(user_text: str, history: list | None = None) -> str:
    decision = _open_scope(user_text)
    with cloud_gate.request_scope(decision):
        kind, payload, via = _resolve(user_text, history, decision)
        if kind == "dispatch":
            return _dispatch(payload, user_text, history, via)
        if kind == "chain":
            return _dispatch_chain(payload, user_text, history, "chain")
        if kind == "team":
            return _dispatch_team(payload, user_text, history)
        if kind == "say":
            return payload
        return brain.answer(user_text, history, policy=decision)


def _stream_reply(user_text: str, history: list | None, decision):
    kind, payload, _via = _resolve(user_text, history, decision)
    if kind == "dispatch":
        yield _dispatch(payload, user_text, history)
    elif kind == "chain":
        yield _dispatch_chain(payload, user_text, history)
    elif kind == "team":
        yield from _stream_team(payload, user_text, history)
    elif kind == "say":
        yield payload
    else:
        yield from brain.answer_stream(user_text, history, policy=decision)


def handle_stream(user_text: str, history: list | None = None):
    """Like handle(), but yields the reply incrementally when the "chat"
    path is taken, so TTS can start on the first sentence instead of
    waiting for the whole answer. Fast-path matches and every other skill
    are already fast (no LLM generation on the critical path, or a short
    structured call), so they're yielded as a single chunk -- only
    brain.answer_stream() genuinely streams.

    The request scope is re-entered around EVERY step of the reply
    (cloud_gate.scoped_iter), not set once at the top: the web framework may pull
    each chunk on a different worker thread with its own copy of the context, so
    a scope set once would be gone by the second sentence -- and this is the path
    voice uses.
    """
    decision = _open_scope(user_text)
    yield from cloud_gate.scoped_iter(
        decision, _stream_reply(user_text, history, decision))
