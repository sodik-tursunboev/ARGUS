"""
ARGUS - Skill (plugin) governance.

FIRST, AN HONEST FRAMING. The checklist opens with "if Argus can load
plugins". It cannot. There is no dynamic loader, no plugin directory, no
entry-point discovery -- skills are ordinary static imports in router.py and
main.py. That absence is a security property worth keeping, and this module
is not an argument for adding one.

But "no plugin system" does not mean the checklist is inapplicable, because
skills ARE the tool surface: every module in skills/ that between them touch
the filesystem, start processes, write registry values, synthesise
keystrokes, read the clipboard, capture the screen and call out to the
network. Governing them the way you would govern plugins is the useful
reading of the requirement.

THE CONTROL THAT DOES REAL WORK is verify_permissions(). Every skill declares
the capabilities it may use; the declaration is checked against what the code
ACTUALLY imports and calls, derived from the AST. A skill that gains a
capability it never declared -- weather_skill picking up subprocess, say --
fails the check whether that happened through an edit, a bad merge, or
someone dropping a file into skills/.

It is a static check, and static checks have a boundary: a skill that reaches
a capability through getattr(), importlib, or eval is not visible to it.
The guarded arithmetic evaluator is reviewed and exempted by name in
DYNAMIC_EXEC_EXEMPT below. Other dynamic execution is not exempted.

A NOTE ON THE BOM BUG, because it is the reason this module exists in the
shape it does. The capability analyser first reported profile_skill,
execpolicy, router, brain, main and 13 other files as having NO capabilities.
They all begin with a UTF-8 BOM; Python's import machinery strips it, but
ast.parse() on the raw text raises SyntaxError. The first version caught that
exception and returned an empty set -- so the scanner silently reported the
security-critical files as clean. The BOMs are gone now, and analyze() raises
instead of returning empty, because a scanner that fails open is worse than
no scanner at all.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ast
import os

import paths

SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")

# ── capability vocabulary ──────────────────────────────────────────────
# (module, attribute) pairs that constitute each capability. attribute=None
# means importing the module at all is enough.
CAPABILITY_SIGNATURES = {
    "network":    [("requests", None), ("urllib", None), ("socket", None),
                   ("netpolicy", None), ("ddgs", None), ("yt_dlp", None),
                   # stdlib mail clients: email_skill speaks IMAP/SMTP
                   # directly. Without these the scanner reported a skill
                   # that opens remote mailboxes as having no network
                   # capability at all -- exactly the failure the AST view
                   # exists to prevent.
                   ("imaplib", None), ("smtplib", None)],
    # Filesystem mutation and filesystem reading are separate declarations.
    # Both remain explicitly visible in every skill's manifest. Only mutation
    # belongs in DANGEROUS: read-only storage/telemetry helpers must not make
    # a majority of the plugin tree look like machine actuators.
    "filesystem": [("os", "startfile"), ("os", "remove"), ("os", "rename"),
                   ("os", "replace"), ("shutil", None),
                   ("os", "makedirs"),
                   ("os", "mkdir"), ("os", "rmdir"), ("os", "unlink"),
                   ],
    "filesystem_read": [("os", "walk"), ("os", "scandir"),
                        ("os", "listdir"), ("os", "stat"),
                        ("os", "lstat"), ("glob", None), ("pathlib", None)],
    # A direct Windows API call is declared independently of filesystem
    # access; env_skill uses it only to broadcast a setting change.
    "system_api": [("ctypes", "windll")],
    "subprocess": [("subprocess", None), ("execpolicy", "run")],
    # System-state change that is neither a process nor a file: winreg
    # writes. env_skill is its only WRITER -- HKCU\Environment via SetValueEx.
    # apps_skill also declares it for READ-ONLY enumeration of the uninstall
    # keys (installed-program reporting); the AST scanner signatures the
    # winreg import and cannot tell a read from a write, so the declaration
    # carries the capability, not the intent. pc_skill likewise reads display
    # and power-plan state from HKLM. Reads and enumeration of FILES are what
    # the filesystem capability covers.
    "registry":   [("winreg", None)],
    "keystrokes": [("keyboard", None), ("pyautogui", None),
                   ("pygetwindow", None)],
    "clipboard":  [("pyperclip", None)],
    "screen":     [("PIL", None), ("mss", None), ("ImageGrab", None)],
    "model":      [("brain", None), ("ollama_client", None),
                   ("groq_client", None)],
    "audio":      [("sounddevice", None), ("tts", None)],
}

ALL_CAPABILITIES = frozenset(CAPABILITY_SIGNATURES)

# Capabilities that let a skill affect the machine rather than just read or
# compute. A new skill asking for one of these should be a conversation.
DANGEROUS = frozenset({"subprocess", "keystrokes", "filesystem"})

# ── the allowlist ──────────────────────────────────────────────────────
# Derived from an AST sweep of the tree as it stood, then reviewed. This is
# the "plugin allowlist" and "plugin permissions" items together: a module in
# skills/ that is not named here does not get to run, and one that is gets
# only what is listed against it.
SKILL_PERMISSIONS: dict[str, set] = {
    "__init__": set(),
    "anomaly_skill": {"filesystem", "filesystem_read"},
    "apps_skill": {"filesystem", "filesystem_read", "subprocess", "registry"},
    # Playwright inside its OWN persistent profile (never the user's browser),
    # plus downloads, screenshots and bookmarks written under the vault.
    # os.makedirs + open() are the filesystem half. NOT "subprocess": the
    # launch path goes through execpolicy's reviewed Chromium entry and
    # execpolicy.check_url(), and no execpolicy.run() call exists here.
    # NOT "screen": Playwright captures its own pages; the module never
    # imports PIL/ImageGrab/mss, so the scanner correctly sees none of it.
    "browser_skill": {"filesystem", "filesystem_read", "network"},
    "calc_skill": set(),
    # Reads its own session-history file and psutil counters; composes what
    # threatmon already found rather than scanning anything itself.
    "briefing_skill": {"filesystem", "filesystem_read"},
    "clarify_skill": set(),
    # Walks a FIXED table of temp/cache directories and unlinks files in them.
    # Its running-browser safety check is local psutil observation; it is not
    # an undeclared process-control capability.
    "cleanup_skill": {"filesystem", "filesystem_read"},
    "cloud_gate": set(),
    # Reads browser_skill's own context cache (recent file, last target) and
    # followup/pc/vision helpers. All reach-through: the focus read itself is
    # pc_skill's, the same pattern followup_skill uses for the same reason.
    "context_skill": set(),
    # execpolicy.run() with a fixed, per-function argv (git read verbs only).
    # The git binary must be allowlisted in execpolicy.ALLOWED_EXECUTABLES for
    # any of this to run at all. os.path.isdir() is a pure test the scanner
    # does not signature, so no filesystem declaration.
    "dev_skill": {"subprocess"},
    # Walks the temp directory to size it. Previously declared nothing,
    # because the scanner did not count enumeration as a filesystem capability
    # -- a module that recursively reads a directory tree was indistinguishable
    # from one that does pure arithmetic.
    "diagnostics": {"filesystem_read"},
    # Local-model summarise + writes (merge/split/create) under Documents.
    # Reads and writes are open()/os.makedirs(). "model" for the summariser,
    # never network: nothing here reaches a cloud tier.
    "document_skill": {"filesystem", "filesystem_read", "model"},
    # IMAP/SMTP over the stdlib mail clients, pinned by netpolicy's egress
    # classes. NOT "keys": credentials come through secrets_store.get_secret(),
    # the same pattern knowledge_skill uses.
    "email_skill": {"network"},
    # ctypes.windll for the WM_SETTINGCHANGE broadcast (the scanner counts
    # that as filesystem, a known overlap). winreg for the HKCU\Environment
    # write itself -- a genuinely new capability class, "registry", added to
    # the vocabulary alongside this registration.
    "env_skill": {"registry", "system_api"},
    "files_skill": {"filesystem", "filesystem_read", "system_api"},
    "followup_skill": set(),
    # psutil counters and a rolling deque, both read-only.
    "health_skill": set(),
    "history_store": {"filesystem", "filesystem_read"},
    # Searches the public web (via research_skill's ddgs path), opens the
    # sources in a browser, and calls the local model to summarise aloud.
    # NOT "subprocess": webbrowser.open() hands off to the shell rather than
    # spawning, and the scanner correctly detects only network+model. Declaring
    # the extra capability granted more than the skill uses and tipped the
    # "dangerous capabilities are the minority" invariant to 15/30 -- a real
    # over-permission caught by a real test.
    "intel_skill": {"network", "model"},
    "control_skill": {"clipboard"},
    "knowledge_skill": {"model", "network"},
    # Watches stored conditions and polls: os.listdir/os.path.getsize for the
    # file-growth condition, socket.create_connection for reachability,
    # network_skill.wifi_info through the reviewed wifi path (the import of
    # network_skill itself is not signatured, but its socket use is reached
    # through network_skill's own declaration, and this module's own
    # socket.create_connection is what the network declaration covers).
    "monitor_skill": {"filesystem", "filesystem_read", "network"},
    "network_skill": {"network", "subprocess"},
    "passive_memory": set(),
    # Structured preferences and workflow definitions use the owner's vault.
    # Workflow execution still passes through the router's authorization gate.
    "personalize_skill": {"filesystem", "filesystem_read"},
    "pc_skill": {"audio", "filesystem", "filesystem_read", "keystrokes", "screen",
                 "subprocess", "registry", "system_api"},
    # Twilio REST over HTTPS, pinned to api.twilio.com by netpolicy's own
    # "phone" egress class.
    #
    # NOT "keys", even though it reads Twilio credentials: fetching a value
    # through secrets_store.get_secret() is how every skill that needs a
    # credential does it (knowledge_skill declares only model+network for the
    # same pattern), and the scanner reserves "keys" for direct key material
    # handling. Declaring it here would have made phone_skill the only skill
    # in the tree claiming that capability, for something it does not do.
    "phone_skill": {"network"},
    # filesystem: persists the PIN-failure lockout to the state dir so a
    # restart cannot reset it (ARGUS-SEC-004). subprocess: shutdown/rundll32
    # via the execpolicy allowlist.
    "power_skill": {"subprocess", "filesystem", "filesystem_read"},
    "privacy_skill": set(),
    "proactive_skill": set(),
    "profile_skill": {"filesystem", "filesystem_read"},
    # DATA, not behaviour: the capability registry (skills/registry.py)
    # imports nothing the scanner signatures.
    "registry": set(),
    "research_skill": {"model", "network"},
    # json + open() over its own scheduled-check store. Read-only on disk;
    # what it schedules is bounded elsewhere (router.CHAINABLE).
    "scheduler_skill": {"filesystem", "filesystem_read"},
    # Event-log reads go through pywin32's win32evtlog IN-PROCESS -- the
    # module header explains why a Get-WinEvent subprocess would widen the
    # sandbox. win32evtlog is not a signatured module; nothing else here
    # touches a capability. Reads requiring elevation fail closed in-skill.
    "security_log_skill": set(),
    # list/status are psutil enumerations; start/stop/restart go through
    # psutil's service API in-process rather than `sc`/`net` (no shell), with
    # the staged PIN inside the skill. Nothing the scanner signatures.
    "service_skill": set(),
    "social_skill": {"model"},
    # Reads sizes and never writes. "filesystem" here is genuinely read-only:
    # the module has no delete, move or write path at all, which is why
    # reclaiming space is deliberately NOT part of it.
    "storage_skill": {"filesystem_read"},
    # Ping through execpolicy's fixed argv ("ping" is allowlisted there), plus
    # stdlib socket for DNS resolution and host:port tests. No shell ever.
    "system_ext_skill": {"network", "subprocess"},
    # json + open() over its own flags/settings store, plus os.environ writes
    # for the answer-cache bypass. The scanner does not signature os.environ
    # manipulation, and that is fine: process-local state, not a machine
    # capability.
    "system_skill": {"filesystem", "filesystem_read"},
    "telemetry": {"filesystem_read"},
    "timer_skill": {"filesystem", "filesystem_read"},
    "vault_skill": {"filesystem", "filesystem_read"},
    "vision_skill": {"model", "screen", "system_api"},

    # ALL the scanner sees here -- the condition probes are monitor_skill's
    # own _snapshot(), reached through that module's reviewed declaration,
    # and the plan composition goes through router.chat_json at SET time (an
    # import the scanner does not reach, like social_skill's model use
    # through its own declaration). Nothing runs or re-plans at fire time;
    # the fire path only stages through router.stage_validated_plan(), which
    # authorises nothing and runs nothing. Declaring network/model here would
    # grant more than the file itself uses -- the over-permission
    # intel_skill's and phone_skill's entries declined for the same reason.
    "watched_skill": {"filesystem", "filesystem_read"},
    # goals_skill: same shape as watched_skill -- its own JSON store plus a
    # plan staged through router.stage_validated_plan(), which authorises
    # nothing and runs nothing. No subprocess/network/model primitive of its
    # own (planning goes through router's already-declared chat_json path).
    "goals_skill": {"filesystem", "filesystem_read"},
    "weather_skill": {"network"},
    "web_skill": {"network"},
    "window_skill": {"keystrokes"},
    # A reporting surface over zt.py/hwkey.py -- enrolment and session-state
    # writes live in those modules, not here. Nothing the scanner signatures.
    "zt_skill": set(),
}


# Dynamic-execution constructs that are known, reviewed, and accepted. The
# static capability view is only trustworthy while this stays nearly empty:
# every entry is a place where a skill could reach a capability the AST cannot
# see, so each one is justified individually rather than by a blanket rule.
#
#   calc_skill  eval(compile(tree, ...)) on an expression that has already
#               been walked and validated against a node whitelist -- no
#               attribute access, no names, no calls, no subscripts, and a
#               ceiling on operand size so 10**10**10 cannot burn a core.
#               The eval is the evaluator for a calculator; removing it means
#               writing a second arithmetic engine, which is more code and
#               more risk than the guarded one-liner.
DYNAMIC_EXEC_EXEMPT = {
    "calc_skill": {"eval", "compile"},
}


class SkillAnalysisError(Exception):
    """Raised when a skill cannot be analysed.

    Deliberately fatal rather than "assume no capabilities". The BOM bug made
    exactly that mistake and reported the most privileged files in the tree as
    the least.
    """


def analyze(path: str) -> set:
    """Capabilities a module actually uses, from its AST."""
    raw = open(path, "rb").read()
    try:
        # utf-8-sig tolerates a BOM if one ever comes back, rather than
        # failing the whole scan over a byte-order mark.
        src = raw.decode("utf-8-sig")
        tree = ast.parse(src)
    except (SyntaxError, UnicodeDecodeError) as e:
        raise SkillAnalysisError(f"{os.path.basename(path)}: {e}") from e

    names = set()
    open_modes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
            for a in node.names:
                names.add(a.name)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            names.add(f"{node.value.id}.{node.attr}")
            names.add(node.value.id)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "open"):
            mode = node.args[1] if len(node.args) > 1 else next(
                (kw.value for kw in node.keywords if kw.arg == "mode"), None)
            open_modes.append(mode.value if isinstance(mode, ast.Constant)
                              and isinstance(mode.value, str) else "r")

    found = set()
    for cap, sigs in CAPABILITY_SIGNATURES.items():
        for mod, attr in sigs:
            key = mod if attr is None else f"{mod}.{attr}"
            if key in names:
                found.add(cap)
                break
    if any(any(flag in mode for flag in "wax+") for mode in open_modes):
        found.add("filesystem")
    if any(not any(flag in mode for flag in "wax+") for mode in open_modes):
        found.add("filesystem_read")
    return found


def dynamic_import_risks(path: str) -> list:
    """Constructs that would make the static capability view a lie.

    getattr/importlib/eval/exec/__import__ can all reach a capability without
    naming it, so a skill using them is one the AST cannot speak for.
    """
    raw = open(path, "rb").read().decode("utf-8-sig")
    try:
        tree = ast.parse(raw)
    except SyntaxError:
        return ["unparseable"]

    risks = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "__import__", "compile"):
                risks.append(f"{node.func.id}() at line {node.lineno}")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "importlib":
                risks.append(f"importlib.{node.attr} at line {node.lineno}")
    return risks


class Violation:
    def __init__(self, skill, kind, detail):
        self.skill, self.kind, self.detail = skill, kind, detail

    def __repr__(self):
        return f"<{self.kind} {self.skill}: {self.detail}>"


def verify_permissions() -> list:
    """Every skill against its declaration. Returns a list of Violations."""
    violations = []
    on_disk = set()

    for fn in sorted(os.listdir(SKILLS_DIR)):
        if not fn.endswith(".py"):
            continue
        name = fn[:-3]
        on_disk.add(name)
        path = os.path.join(SKILLS_DIR, fn)

        if name not in SKILL_PERMISSIONS:
            violations.append(Violation(
                name, "unregistered",
                "present in skills/ but not on the allowlist"))
            continue

        declared = SKILL_PERMISSIONS[name]
        try:
            actual = analyze(path)
        except SkillAnalysisError as e:
            violations.append(Violation(name, "unanalysable", str(e)[:70]))
            continue

        extra = actual - declared
        if extra:
            violations.append(Violation(
                name, "undeclared_capability",
                f"uses {', '.join(sorted(extra))} without declaring it"))

    for name in SKILL_PERMISSIONS:
        if name not in on_disk:
            violations.append(Violation(name, "missing",
                                        "declared but not present on disk"))

    # Capability analysis catches a skill that gained an ability it did not
    # declare. It does NOT catch a change that stays inside the declared
    # capabilities -- files_skill already declares filesystem access, so
    # rewriting which paths it touches is invisible to the AST scan while
    # being exactly the edit worth catching. The manifest hash does see it.
    try:
        import integrity
        for name in sorted(on_disk):
            # manifest_key(), not a hand-built "skills/x.py": the frozen
            # manifest keys these as _internal/skills/x.py.
            key = integrity.manifest_key(os.path.join(SKILLS_DIR, f"{name}.py"))
            ok, detail = integrity.verify_one(key)
            if not ok and "no baseline" not in detail:
                violations.append(Violation(name, "modified", detail))
    except Exception as e:                       # integrity unavailable
        violations.append(Violation("(all)", "unverified",
                                    f"hashes not checked: {e}"))
    return violations


def is_allowed(skill: str) -> bool:
    return skill in SKILL_PERMISSIONS or f"{skill}_skill" in SKILL_PERMISSIONS


def permissions_for(skill: str) -> set:
    return set(SKILL_PERMISSIONS.get(skill,
               SKILL_PERMISSIONS.get(f"{skill}_skill", set())))


def has_capability(skill: str, capability: str) -> bool:
    return capability in permissions_for(skill)


# ── dependency pinning ─────────────────────────────────────────────────
LOCKFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "requirements.lock")


def check_dependencies() -> tuple[list, list]:
    """(mismatched, missing) against requirements.lock.

    Every dependency in requirements.txt was unpinned, which means two
    installs of ARGUS from the same source can differ in every library it
    uses -- and a compromised release of any of them lands silently on the
    next `pip install`. The lock file records what this machine actually has;
    this compares against it.
    """
    import importlib.metadata as md

    if not os.path.exists(LOCKFILE):
        return [], []

    mismatched, missing = [], []
    for line in open(LOCKFILE, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, _, want = line.partition("==")
        try:
            have = md.version(name.strip())
        except md.PackageNotFoundError:
            missing.append(name.strip())
            continue
        if have != want.strip():
            mismatched.append((name.strip(), want.strip(), have))
    return mismatched, missing


def describe() -> str:
    v = verify_permissions()
    caps = sum(len(c) for c in SKILL_PERMISSIONS.values())
    mismatched, missing = check_dependencies()
    return (f"{len(SKILL_PERMISSIONS)} skills allowlisted, {caps} capability "
            f"grants, {len(v)} violation(s); "
            f"deps: {len(mismatched)} mismatched, {len(missing)} missing")
