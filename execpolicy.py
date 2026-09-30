"""
ARGUS - Execution policy.

WHAT ARGUS ACTUALLY EXECUTES. Audited, not assumed:

  os.startfile      apps_skill (indexed app path), files_skill (a found file)
  subprocess        power_skill (fixed argv), network_skill (netsh), main.py
                    (nvidia-smi), tts_worker (piper CLI)
  keyboard.write    pc_skill.dictate -- types into the FOCUSED window
  webbrowser.open   router web/open_url, web_skill (a YouTube URL)
  eval              calc_skill, already AST-validated against a node whitelist

There is NO generic "run this shell command" skill, and there should not be
one. That absence is the single most valuable property in this list, so the
rest of this module is about the paths that amount to execution WITHOUT
looking like it.

THE TWO THAT ACTUALLY MATTER

1. dictate(). keyboard.write() types into whatever window has focus, and the
   `keyboard` library sends "\\n" as Enter. With a terminal focused, dictation
   IS shell execution -- the text came from a language model, and no shell was
   ever named. This is the closest thing ARGUS has to the "LLM -> run this
   command -> shell" pipeline the checklist warns about.

2. open_file(). os.startfile() on a path found by a filename search. Windows
   resolves that through ShellExecute, so a .bat, .ps1, .cmd, .vbs or .exe is
   RUN, not opened. "open my backup script" was arbitrary script execution.

DESIGN

Every check here is a denial with a spoken reason, never a silent rewrite. A
sanitiser that quietly strips part of a command and runs the remainder is
worse than a refusal: the user believes something happened that did not, and
an attacker gets to probe which parts survive.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import ctypes.wintypes
import os
import re
import subprocess

# ── 1. dictation ───────────────────────────────────────────────────────
# Control characters are the payload here, not the text. \n and \r are Enter;
# \t moves between fields; \x1b is escape. None of them belong in something a
# human asked to have typed.
# \x09 (tab) is INSIDE this range deliberately. The first version wrote
# [\x00-\x08\x0a-\x1f] and left a gap at exactly 0x09 -- the one character the
# comment above names as dangerous. Tab is how you move between fields in a
# form or a login dialog, so "user<TAB>password" is a real payload.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

MAX_DICTATE_CHARS = 500

# Windows whose foreground process means keystrokes become commands. Matched
# on the executable name of the window that will RECEIVE the typing.
_SHELL_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe",
    "conhost.exe", "bash.exe", "wsl.exe", "ubuntu.exe", "git-bash.exe",
    "mintty.exe", "putty.exe", "ssh.exe", "python.exe", "py.exe",
    "regedit.exe", "mmc.exe", "taskmgr.exe",
    # wt.exe is Windows Terminal's actual executable; only the store name
    # "windowsterminal.exe" was listed. This mattered the moment the app
    # index started reading App Paths, because that made "open terminal"
    # work -- so ARGUS gained the ability to launch a shell host it did not
    # recognise as one.
    "wt.exe",
    # Other terminal emulators in common use, for the same reason.
    "alacritty.exe", "wezterm.exe", "wezterm-gui.exe", "hyper.exe",
    "cmder.exe", "conemu.exe", "conemu64.exe", "kitty.exe", "tabby.exe",
    "fluentterminal.exe", "terminus.exe",
    # Remote shells and privilege tools.
    "openssh.exe", "plink.exe", "kitty_portable.exe", "telnet.exe",
    "psexec.exe", "runas.exe", "wscript.exe", "cscript.exe",
}


def foreground_process() -> str:
    """Executable name of the window that currently has focus, lowercased."""
    if os.name != "nt":
        return ""
    try:
        import psutil
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if not hwnd:
            return ""
        pid = ctypes.wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return ""
        return psutil.Process(pid.value).name().lower()
    except Exception:
        return ""


def check_dictation(text: str) -> tuple[bool, str]:
    """(allowed, reason). Refuses rather than sanitising -- see DESIGN."""
    if not text or not text.strip():
        return False, "What should I type?"
    if len(text) > MAX_DICTATE_CHARS:
        return False, (f"That's {len(text)} characters. I'll type at most "
                       f"{MAX_DICTATE_CHARS} at a time.")
    if _CONTROL_CHARS.search(text):
        # The newline is the whole attack: it is what turns typed text into an
        # executed command line.
        return False, ("I won't type control characters — a newline there "
                       "would press Enter for you.")

    focus = foreground_process()
    if focus in _SHELL_PROCESSES:
        return False, (f"The focused window is {focus}. I won't type into a "
                       f"terminal — click into the text field you actually "
                       f"want and ask again.")
    return True, ""


# ── 2. opening files ───────────────────────────────────────────────────
# os.startfile goes through ShellExecute, which RUNS these rather than opening
# them. Denylist rather than allowlist on purpose: the set of things Windows
# will execute is small and well known, while the set of documents a person
# might legitimately open is unbounded, and an allowlist there would make the
# skill useless the first time someone had a file type nobody listed.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".msp", ".scr", ".cpl", ".hta", ".reg",
    ".jar", ".pif", ".gadget", ".inf", ".lnk", ".url", ".application",
    ".msc", ".sh", ".py", ".pyw", ".rb", ".pl", ".php",
}


def check_open_file(path: str) -> tuple[bool, str]:
    # ARGUS's own installation first. .py is already in the extension list
    # below, so auth.py was refused for the right reason by accident -- but
    # config.py's neighbours include .json and .md files that are equally part
    # of the security layer and would have opened. Checked explicitly so the
    # protection does not depend on a coincidence of file extensions.
    import integrity

    if integrity.is_protected(path):
        return False, integrity.refusal(path)

    ext = os.path.splitext(path or "")[1].lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return False, (f"That's a {ext} file — opening it would run it, so I "
                       f"won't do that from a voice command.")
    return True, ""


# ── 3. URLs handed to the browser ──────────────────────────────────────
# webbrowser.open() will happily hand file://, javascript: or an arbitrary
# custom protocol handler to the default browser. Only the two schemes that
# mean "a web page" are allowed.
ALLOWED_URL_SCHEMES = {"http", "https"}

# <letter><letters/digits/+/-/.>* followed by a colon -- the RFC 3986 shape.
_SCHEME_SHAPE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def check_url(url: str) -> tuple[bool, str]:
    from urllib.parse import urlparse

    raw = (url or "").strip()
    if not raw:
        return False, "No address given."

    # BUGFIX, and it defeated the entire check: the test for "does this need a
    # scheme adding" was `"://" not in raw`. "javascript:alert(1)" contains no
    # "://", so https:// was prepended, producing "https://javascript:alert(1)"
    # -- whose scheme then reads as https and passed. Every single-colon
    # scheme (javascript:, vbscript:, data:, ms-settings:, shell:) sailed
    # through the exact check meant to stop them.
    #
    # A scheme is now detected by shape. The dot test distinguishes a real
    # scheme from a host:port, since "example.com:8080" also matches
    # <word>:<rest> but is an address, not a protocol.
    head = raw.split(":", 1)[0]
    has_scheme = bool(_SCHEME_SHAPE.match(raw)) and "." not in head
    if not has_scheme:
        raw = "https://" + raw          # bare "youtube.com" is a web address
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False, "That isn't a valid web address."
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        return False, (f"I only open web addresses, not {parsed.scheme}: links.")
    if not parsed.netloc:
        return False, "That isn't a valid web address."

    # LOOPBACK AND LINK-LOCAL ARE NOT WEB ADDRESSES.
    #
    # This checked the scheme and nothing else, so "open
    # http://127.0.0.1:8420/shutdown" was permitted -- ARGUS pointing a
    # browser at its own control API. The token stops the request itself, but
    # the capability is wrong regardless: 127.0.0.0/8 is where this machine's
    # private services live (ARGUS, databases, admin panels bound to
    # localhost), and 169.254.0.0/16 is link-local, which on a cloud host is
    # the metadata endpoint.
    #
    # Defence in depth, not a duplicate of security.url_is_safe: that guards
    # what ARGUS FETCHES and blocks the whole private range. This guards what
    # ARGUS OPENS IN A BROWSER, where a user may legitimately want their own
    # router or NAS, so ordinary LAN addresses are still allowed.
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return False, "I won't open local service addresses in a browser."
    import ipaddress

    candidates = []
    try:
        candidates.append(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        # SHORT AND NUMERIC FORMS. ipaddress rejects "127.1", "2130706433"
        # and "0x7f000001" because they are not dotted quads -- but Windows,
        # curl and every browser resolve all three to 127.0.0.1, so rejecting
        # them here while the OS accepts them is a bypass, not a validation.
        #
        # inet_aton understands exactly these legacy forms. Only attempted for
        # hosts that could BE numeric, so an ordinary hostname never triggers
        # a lookup of any kind.
        if re.fullmatch(r"[0-9a-fx.]+", host, re.I):
            try:
                import socket as _s

                candidates.append(
                    ipaddress.ip_address(_s.inet_ntoa(_s.inet_aton(host))))
            except (OSError, ValueError):
                pass

    for ip in candidates:
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return False, "I won't open local service addresses in a browser."

    return True, raw


# ── 4. subprocess ──────────────────────────────────────────────────────
# Every external program ARGUS is allowed to start, by basename. Enumerated
# from the audit at the top of this file -- if a future skill needs another
# one, adding it here is a deliberate, reviewable act rather than a side
# effect of writing the skill.
ALLOWED_EXECUTABLES = {
    "shutdown",     # power_skill, with fixed argv
    # network_skill: read-only queries (wifi_info) AND, since wifi_set(),
    # "interface set interface <adapter> enable|disable" -- still a FIXED
    # argv shape with no caller-supplied subcommand, same reviewed-shape
    # guarantee as every other entry here, just no longer read-only.
    "netsh",
    "nvidia-smi",   # main.py sampler
    "piper",        # tts_worker CLI fallback
    "rundll32.exe", "rundll32",   # power_skill sleep
    "git",          # dev_skill, read-only git reporting, fixed argv per function
    "ping",         # system_ext_skill.ping(), fixed argv, host validated first
    "powercfg",     # pc_skill.power_plan(), only Windows' own built-in plan names
}

# A metacharacter in an argv element is not interpreted when shell=False, but
# its PRESENCE means something built a command line as a string somewhere
# upstream, which is exactly the mistake this is meant to catch early.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r]")

DEFAULT_TIMEOUT = 20.0


class ExecDenied(Exception):
    pass


def run(argv, timeout: float = DEFAULT_TIMEOUT, **kwargs):
    """The only way ARGUS should start an external process.

    Enforces: an allowlisted executable, no shell, no metacharacters in
    arguments, a hard timeout, and a killed process on timeout rather than an
    orphan left running.
    """
    # Every external process start is recorded, allowed or not. Only the
    # executable NAME is logged, never the arguments: argv is where a
    # credential would be if one were ever passed on a command line, and a
    # log of "which programs did ARGUS start" is the useful signal anyway.
    import security

    exe = os.path.basename(str(argv[0])).lower() if argv and not isinstance(argv, str) else "?"
    allowed = (exe in ALLOWED_EXECUTABLES
               or exe.removesuffix(".exe") in ALLOWED_EXECUTABLES)
    security.security_event(security.SHELL_COMMAND_REQUESTED, component=exe,
                            count=(len(argv) - 1) if not isinstance(argv, str) else 0,
                            status="ok" if allowed else "failed")

    exe = _validate(argv)

    kwargs.pop("shell", None)          # never, regardless of what a caller asks

    # Run inside a job object rather than a bare subprocess. A Python timeout
    # kills the child it started and nothing else, so a helper that spawns its
    # own children leaves orphans behind after the command was "cancelled".
    # Closing the job handle is a kernel guarantee about the whole tree, and
    # carries memory and process-count caps a timeout cannot express.
    import sandbox

    try:
        return sandbox.run_sandboxed(argv, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        # Said out loud: a silent timeout looks identical to a command that
        # returned nothing, and those need different responses.
        raise ExecDenied(f"{exe} took longer than {timeout:.0f}s and was killed")


def _validate(argv) -> str:
    """Shared gate for run() and spawn(). Returns the executable basename."""
    if isinstance(argv, str):
        raise ExecDenied("commands must be a list of arguments, never a string")
    if not argv:
        raise ExecDenied("no command given")

    exe = os.path.basename(str(argv[0])).lower()
    if exe not in ALLOWED_EXECUTABLES and exe.removesuffix(".exe") not in ALLOWED_EXECUTABLES:
        raise ExecDenied(f"{exe} is not an allowed executable")

    for arg in argv[1:]:
        if _SHELL_METACHARS.search(str(arg)):
            raise ExecDenied(f"argument contains a shell metacharacter: {arg!r}")
    return exe


def spawn(argv, **kwargs):
    """Start a process WITHOUT waiting for it, under the same allowlist.

    run() is the right call for anything that produces output and finishes.
    Two things ARGUS starts do neither:

      rundll32 powrprof.dll,SetSuspendState  does not return until the machine
      wakes up again, so run()'s timeout would fire and kill the suspend.

      shutdown /s /t 5   returns quickly, but there is nothing to collect and
      the machine is about to go away.

    Before this existed, power_skill called subprocess.Popen directly and
    skipped the allowlist, the metacharacter check and the audit event
    entirely -- so the one skill that can power the machine off was the one
    outside the execution policy. Deliberately NOT run inside a job object:
    closing the job handle kills the tree, which is correct for a command
    being waited on and exactly wrong for one meant to outlive this call.
    """
    import security

    exe = _validate(argv)
    security.security_event(security.SHELL_COMMAND_REQUESTED, component=exe,
                            count=len(argv) - 1, source="spawn", status="ok")
    kwargs.pop("shell", None)
    return subprocess.Popen(argv, shell=False, **kwargs)


def describe() -> str:
    return (f"executables: {len(ALLOWED_EXECUTABLES)}; "
            f"blocked file types: {len(EXECUTABLE_EXTENSIONS)}; "
            f"url schemes: {sorted(ALLOWED_URL_SCHEMES)}")
