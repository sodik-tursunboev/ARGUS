"""
ARGUS - File search, and deletion.

Searches your usual folders for a file by name and opens it. Deliberately scoped
to user directories — no full-disk crawl, no system folders.

Deletion reuses power_skill's exact staged-confirmation shape (stage, wait
for config.COMMAND_PIN within a short window, execute) rather than building
a second, parallel confirmation system with its own rules -- deleting a file
is exactly as irreversible as a shutdown a speech recognizer could mishear,
so it gets the same gate, not a lighter one. See power_skill.py's own
docstring for the full reasoning; this only restates what's specific to
files (a path instead of an action name).

Deletion goes to the Recycle Bin via the Windows shell API (ctypes,
SHFileOperationW), not os.remove() -- the same "no new dependency, ctypes
straight to the Windows API" approach pc_skill.py already uses for
lock_screen(), and it means a mistaken deletion (the exact scenario this
whole gate exists to guard against) is still recoverable afterward, same as
a normal Explorer Delete key.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes
import hmac
import os
import re
import time
from ctypes import wintypes

from config import COMMAND_PIN

CONFIRM_WINDOW = 25  # seconds -- identical to power_skill's, same reasoning

_pending = {"path": None, "at": 0.0}
# Restore staging gets its OWN slot on purpose: _pending is the delete gate,
# and the two confirmations must never see each other's state (staging a
# restore while a delete is pending, or a PIN meant for one satisfied by the
# other, would be a confusion worth avoiding at twice the price of one more
# dict). "_pending" stays byte-for-byte the delete contract the suite asserts.
_restore_pending = {"rpath": None, "orig": None, "name": None, "at": 0.0}

SEARCH_ROOTS = [
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Pictures"),
    os.path.expandvars(r"%USERPROFILE%\Videos"),
    r"C:\ARGUS",
]

SKIP_DIRS = {"node_modules", "venv", ".git", "__pycache__", "AppData", ".cache"}
MAX_DEPTH = 4
TIME_BUDGET = 4.0  # seconds — keep it snappy, this is a voice command


# ─── Query understanding ───────────────────────────────────────────────
#
# THE BUG THIS REPLACES, verbatim from a real session:
#
#     "argus find my cv resume from folder"
#       -> "I couldn't find anything matching cv resume from folder."
#
# while C:\Users\example\Desktop\Example_CV.pdf sat right there. The
# match was `if needle in fn.lower()` -- a literal substring test of the WHOLE
# query against the filename. So "cv" worked, "my cv" did not, and "example cv"
# did not match a file named Example_CV.pdf, because the underscore
# and the middle name break the substring.
#
# A filename is not a sentence and a spoken request is not a filename. The two
# have to be reduced to comparable token sets before they can be compared at
# all: strip the words people say around a request, split the filename on the
# separators people actually use, and match token-by-token.
_FILE_STOPWORDS = frozenset("""
my mine the a an this that these those
file files folder folders directory document documents doc docs
from in on at of for to with about into
find get fetch locate search look show open give bring
me my please can could would you i want need
named called about titled saved stored
not no any some all it its is are was were and or but
""".split())

# A term must match at least this fraction of the query to count as a find.
#
# There was no floor at all, so any single weak hit was reported as success:
# "qqzzxx_definitely_not_a_real_file" matched notifier.py, because "not" is a
# substring of "notifier" and one term out of four scored 0.25 -- which the
# code then presented as "Found 7 matches". Answering a nonsense query with a
# confident list of unrelated files is worse than saying nothing was found.
MIN_MATCH_SCORE = 0.5

# Words people use interchangeably for the same document. Expanded BOTH ways,
# so "resume" finds a file called CV and vice versa -- which is the specific
# thing the reported failure needed.
_SYNONYMS = {
    "cv": {"cv", "resume", "curriculum", "vitae"},
    "resume": {"resume", "cv", "curriculum", "vitae"},
    "curriculum": {"curriculum", "cv", "resume", "vitae"},
    "photo": {"photo", "picture", "pic", "img", "image", "snapshot"},
    "picture": {"picture", "photo", "pic", "img", "image"},
    "image": {"image", "img", "photo", "picture", "pic"},
    "presentation": {"presentation", "slides", "deck", "pptx", "ppt"},
    "slides": {"slides", "presentation", "deck", "pptx", "ppt"},
    "spreadsheet": {"spreadsheet", "sheet", "excel", "xlsx", "xls", "csv"},
    "invoice": {"invoice", "bill", "receipt"},
    "report": {"report", "writeup", "summary"},
    "notes": {"notes", "note", "memo"},
    "certificate": {"certificate", "cert", "certification", "diploma"},
    "screenshot": {"screenshot", "screencap", "capture", "screen"},
}

_SPLIT_NAME = re.compile(r"[^a-z0-9]+")
# lowerUPPER and letter-digit boundaries: "ExampleCV2024" -> example cv 2024
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])")


def _query_terms(query: str) -> list:
    """Content words from a spoken request, each expanded to its synonyms.

    Returns a list of SETS -- one per term. A file matches when every set has
    at least one member present in the filename, which is AND across the
    terms the user said and OR within each term's synonyms.
    """
    words = _SPLIT_NAME.split((query or "").lower())
    terms = []
    for w in words:
        if not w or w in _FILE_STOPWORDS or len(w) < 2:
            continue
        terms.append(_SYNONYMS.get(w, {w}))
    return terms


def _name_terms(filename: str) -> set:
    """Every token a filename can reasonably be said to contain."""
    stem, ext = os.path.splitext(filename)
    spaced = _CAMEL.sub(" ", stem)
    parts = {p for p in _SPLIT_NAME.split(spaced.lower()) if p}
    parts.add(stem.lower())                  # the whole stem, for substring hits
    if ext:
        parts.add(ext.lstrip(".").lower())
    return parts


def _match_score(terms: list, filename: str) -> float:
    """Fraction of the user's terms present in FILENAME. 1.0 means all of them.

    A term counts as present when one of its synonyms equals a filename token,
    is a prefix of one (so "doc" finds "documentation"), or appears anywhere in
    the joined name (so "example" is found inside "Example_CV").
    """
    if not terms:
        return 0.0
    name_tokens = _name_terms(filename)
    flat = filename.lower()
    hits = 0
    for synonyms in terms:
        for s in synonyms:
            # A whole-token match, or a prefix of one ("doc" finds
            # "documentation"). The bare substring test needs a LONGER term:
            # at 3 characters "not" is inside "notifier", "cat" inside
            # "certificate", "art" inside "chart" -- all false matches on
            # words that happen to be spelled inside an unrelated filename.
            if (s in name_tokens
                    or (len(s) >= 3 and any(t.startswith(s) for t in name_tokens))
                    or (len(s) >= 5 and s in flat)):
                hits += 1
                break
    return hits / len(terms)


def _walk(root: str, terms: list, deadline: float):
    """Filename search, with ARGUS's own installation excluded.

    SEARCH_ROOTS contains C:\\ARGUS, auth.py sits one level below it, and
    MAX_DEPTH is 4 -- so before the integrity.is_protected() filter below,
    "delete auth" resolved to C:\\ARGUS\\argus-os\\auth.py and staged the
    authorization layer for the Recycle Bin. The same held for execpolicy.py,
    sandbox.py, security.py, secrets_store.py and config.py. Only the PIN gate
    stood in the way, and a user who believes they are deleting a stray
    download types the PIN without hesitating.

    Filtered HERE rather than only at the delete step because find() and
    open_file() share this walk: ARGUS should not offer to open its own
    source, and should not list it as a search result either.
    """
    import integrity

    hits = []
    base_depth = root.rstrip("\\").count("\\")
    for dirpath, dirnames, filenames in os.walk(root):
        if time.time() > deadline:
            break
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        # Prune whole protected directories rather than testing every file
        # inside them -- cheaper, and it keeps the walk out of the venv.
        dirnames[:] = [d for d in dirnames
                       if not integrity.is_protected(os.path.join(dirpath, d))]
        if dirpath.count("\\") - base_depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        for fn in filenames:
            score = _match_score(terms, fn)
            if score < MIN_MATCH_SCORE:
                continue
            full = os.path.join(dirpath, fn)
            if integrity.is_protected(full):
                continue
            try:
                hits.append((full, os.path.getmtime(full), score))
            except OSError:
                continue
    return hits


def _search(query: str):
    """(hits, terms). Hits are (path, mtime, score), best first.

    Ranked by MATCH QUALITY first and recency second. The old code sorted on
    modification time alone, which was fine when the only hits were exact
    substring matches and is wrong now that partial matches are possible: the
    most recently touched loosely-related file would outrank an exact one.
    """
    terms = _query_terms(query)
    if not terms:
        return [], terms

    deadline = time.time() + TIME_BUDGET
    hits = []
    for root in SEARCH_ROOTS:
        if os.path.isdir(root):
            hits.extend(_walk(root, terms, deadline))
        if time.time() > deadline:
            break

    hits.sort(key=lambda h: (round(h[2], 3), h[1]), reverse=True)
    return hits, terms


def find(query: str, open_it: bool = False) -> str:
    if not (query or "").strip():
        return "What file are you looking for?"

    hits, terms = _search(query)
    if not terms:
        return "What file are you looking for?"

    if not hits:
        # Say WHERE it looked and WHAT it looked for. "I couldn't find
        # anything matching cv resume from folder" told the user nothing about
        # whether the problem was the words, the folders, or the depth --
        # and in the reported case the file was on the Desktop the whole time.
        looked = ", ".join(sorted({next(iter(t)) for t in terms}))
        return (f"I couldn't find anything matching {looked} in your Desktop, "
                f"Documents, Downloads, Pictures or Videos.")

    # Everything that matched EVERY term the user said. If nothing did, fall
    # back to the best partial match rather than reporting failure -- a
    # partial answer the user can reject beats a flat "not found" when the
    # file is sitting there.
    best_score = hits[0][2]
    hits = [h for h in hits if h[2] >= best_score]

    # REMEMBER WHAT WAS FOUND, so "move that to Documents" has a referent.
    #
    # followup_skill already records the search QUERY ("my cv"), which is not
    # a path and cannot be moved, copied or renamed. This records the file the
    # search actually resolved to -- the thing the owner is looking at in the
    # answer and will refer to as "that" in the next sentence.
    #
    # Only when the answer is UNAMBIGUOUS. With several equally-good matches
    # there is no "that" yet, and picking the first would make the next
    # command act on a file the owner never saw named.
    if len(hits) == 1:
        try:
            from skills import followup_skill
            followup_skill.remember_file(hits[0][0])
        except Exception:
            pass

    if open_it:
        path = hits[0][0]
        # os.startfile goes through ShellExecute, which RUNS a .bat, .ps1,
        # .cmd, .vbs or .exe rather than opening it. Without this check "open
        # my backup script" was arbitrary script execution by voice, against
        # whatever the filename search happened to rank first.
        import execpolicy

        ok, reason = execpolicy.check_open_file(path)
        if not ok:
            return f"{reason} It's at {path}."
        try:
            os.startfile(path)
            return f"Opening {os.path.basename(path)}."
        except Exception as e:
            return f"Found it but couldn't open it: {e}"

    names = [os.path.basename(h[0]) for h in hits[:4]]
    if len(hits) == 1:
        return f"Found {names[0]}."
    return f"Found {len(hits)} matches. Most recent: " + ", ".join(names) + "."


def resolve_path(query: str, exts: set | None = None) -> tuple:
    """(path, error) -- QUERY resolved to a single file inside SEARCH_ROOTS,
    for a skill that needs the PATH ITSELF rather than a spoken answer (every
    caller in this module wants a sentence back; document_skill.py, and
    anything else that reads file CONTENT, wants the resolved path). Reuses
    the exact _search() ranking find() uses above -- not a second search
    with its own chance to rank differently; see this module's own docstring
    on why that duplication was a bug once already.

    EXTS, given, keeps only hits whose extension is in it: "my resume" is
    ambiguous across a .docx and a screenshot of it, and a caller that only
    understands one kind of file should not be handed the other.
    """
    hits, terms = _search(query)
    if not terms:
        return "", "What file are you looking for?"
    if exts:
        hits = [h for h in hits if os.path.splitext(h[0])[1].lower() in exts]
    if not hits:
        looked = ", ".join(sorted({next(iter(t)) for t in terms}))
        return "", f"I couldn't find anything matching {looked}."
    best_score = hits[0][2]
    hits = [h for h in hits if h[2] >= best_score]
    if len(hits) > 1:
        names = ", ".join(os.path.basename(h[0]) for h in hits[:4])
        return "", f"That matches {len(hits)} files: {names}. Which one did you mean?"
    return hits[0][0], ""


# ── "is this safe?" ──────────────────────────────────────────────────────────
#
# The question you actually ask about a download, answered before you run it.
#
# ENTIRELY LOCAL, AND THAT IS A DELIBERATE LIMIT. The obvious implementation
# hashes the file and asks VirusTotal. That would send a hash of your private
# files to a third party, and a hash IS an identifier -- it tells them you
# have that exact document. Reporting your files to a reputation service is
# the same class of leak this project refuses everywhere else, so this checks
# only what Windows itself can tell us: is it signed, by whom, where did it
# land, and how did it get there.
#
# WHAT IT CANNOT TELL YOU, said out loud in the answer rather than implied:
# a valid signature is not safety. Plenty of signed software is unwanted, and
# certificates get stolen. It reports facts and their weight; it does not
# clear anything.

_RISKY_EXT = {".exe", ".msi", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1",
              ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".reg", ".lnk"}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".cab"}
# Windows marks anything downloaded with Zone.Identifier: an NTFS alternate
# data stream. Its presence is the single most useful fact about a file --
# it means this came from outside the machine.
_ZONE_STREAM = ":Zone.Identifier"


def _downloads_dir():
    return os.path.join(os.path.expanduser("~"), "Downloads")


def _mark_of_the_web(path: str) -> str:
    """Where Windows thinks this file came from, or "".

    Reads the Zone.Identifier alternate data stream. Zone 3 is "internet",
    zone 4 "restricted"; the stream often also carries the actual URL, which
    is the most informative line in the whole check.
    """
    try:
        with open(path + _ZONE_STREAM, "r", encoding="utf-8",
                  errors="replace") as fh:
            blob = fh.read(2048)
    except Exception:
        return ""
    zone = re.search(r"ZoneId=(\d)", blob)
    host = re.search(r"HostUrl=(\S+)", blob) or re.search(r"ReferrerUrl=(\S+)", blob)
    bits = []
    if zone:
        bits.append({"0": "this machine", "1": "the local network",
                     "2": "a trusted site", "3": "the internet",
                     "4": "a restricted site"}.get(zone.group(1), "elsewhere"))
    if host:
        bits.append(host.group(1)[:120])
    return " — ".join(bits)


def _newest_download():
    d = _downloads_dir()
    try:
        entries = [os.path.join(d, f) for f in os.listdir(d)]
    except Exception:
        return ""
    files = [(os.path.getmtime(p), p) for p in entries if os.path.isfile(p)]
    if not files:
        return ""
    return max(files)[1]


def inspect(query: str = "") -> str:
    """What is known about a file, before you run it."""
    q = (query or "").strip()
    if not q or re.match(r"^(?:my\s+)?(?:latest|last|newest|recent)"
                         r"(?:\s+download)?$", q, re.I):
        path = _newest_download()
        if not path:
            return "Your Downloads folder is empty, so there's nothing to check."
    else:
        path = q if os.path.isabs(q) and os.path.exists(q) else ""
        if not path:
            # Downloads first: "check chrome-setup" almost always means the
            # thing that just landed, not a same-named file buried elsewhere.
            cand = os.path.join(_downloads_dir(), q)
            path = cand if os.path.isfile(cand) else ""
        if not path:
            hits, _ = _search(q)
            path = hits[0][0] if hits else ""
        if not path:
            return (f"I couldn't find {q}. Try \"check my latest download\", "
                    f"or give me the full path.")

    name = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    try:
        size = os.path.getsize(path)
        age_h = (time.time() - os.path.getmtime(path)) / 3600.0
    except Exception:
        return f"I couldn't read {name}."

    bits = [f"{name}, {size / 1048576:.1f} megabytes"]
    bits.append("downloaded just now" if age_h < 1 else
                f"about {int(age_h)} hours old" if age_h < 48 else
                f"about {int(age_h / 24)} days old")

    origin = _mark_of_the_web(path)
    if origin:
        bits.append(f"it came from {origin}")
    elif ext in _RISKY_EXT:
        # No mark of the web on an executable means it was not downloaded by a
        # browser -- copied from a USB stick, extracted from an archive, or
        # written by something already running. Worth saying either way.
        bits.append("no download mark, so it didn't come from a browser")

    if ext in _RISKY_EXT:
        ok, detail = False, ""
        try:
            import integrity
            ok, detail = integrity.verify_signature(path)
        except Exception as e:
            detail = f"the signature check failed ({type(e).__name__})"
        if ok:
            bits.append(f"it IS signed — {detail}" if detail else "it is signed")
        else:
            bits.append(f"it is NOT validly signed ({detail})" if detail
                        else "it is not validly signed")
    elif ext in _ARCHIVE_EXT:
        bits.append("it's an archive, so I can't tell what's inside without "
                    "opening it — check what you extract, not this")
    else:
        bits.append("it isn't an executable")

    tail = ""
    if ext in _RISKY_EXT:
        # The honest caveat, stated rather than implied. A signature says who
        # signed it, not that it is safe.
        tail = (" A signature tells you who signed it, not that it's safe — "
                "signed software can still be unwanted, and certificates get "
                "stolen. I can't clear this for you.")
    try:
        import security
        security.audit("file_inspect", f"ext={ext} signed_check={ext in _RISKY_EXT}",
                       "ok")
    except Exception:
        pass
    return ". ".join(bits) + "." + tail


def open_file(query: str) -> str:
    return find(query, open_it=True)


# ─── Deletion (staged, never immediate) ────────────────────────────────

class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


_FO_DELETE = 3
_FO_MOVE = 1                # restore moves the $R core back to its original path
_FOF_ALLOWUNDO = 0x0040     # sends to the Recycle Bin instead of erasing outright
_FOF_NOCONFIRMATION = 0x0010  # skip Explorer's OWN popup -- ARGUS's PIN gate is the confirmation
_FOF_SILENT = 0x0004
_FOF_NOERRORUI = 0x0400


def _recycle(path: str) -> bool:
    """Sends PATH to the Recycle Bin. True on success. pFrom must be a
    double-null-terminated string -- SHFileOperation's calling convention,
    not a typo -- since it accepts multiple paths in one call and needs an
    unambiguous list terminator."""
    # Last gate before the file is actually gone. _walk() already filters
    # protected paths out of every search, so reaching here with one means a
    # path arrived from somewhere else -- a future caller, a rewritten
    # follow-up, a direct call. Checked again rather than assumed, because the
    # cost of being wrong at THIS line is a deleted security layer.
    import integrity
    import security

    if integrity.is_protected(path):
        security.security_event(security.DESTRUCTIVE_ACTION_BLOCKED,
                                skill="files", action="delete",
                                file=path, reason="protected_install")
        return False
    op = _SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = _FO_DELETE
    op.pFrom = path + "\0\0"
    op.pTo = None
    op.fFlags = _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_SILENT | _FOF_NOERRORUI
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return result == 0 and not op.fAnyOperationsAborted


def stage_delete(query: str) -> str:
    """Finds the file and stages it for deletion -- does NOT delete it.

    Reuses find()'s own search (same SEARCH_ROOTS scope, same most-recent
    tiebreak it already uses for open_it=True) rather than a second lookup.
    The exact filename is spoken back here specifically so the confirmation
    step itself is the disambiguation check -- a user who meant a different
    file hears the wrong name and can refuse, so this doesn't also need a
    separate clarify_skill-style "which one?" step on top of the PIN gate.
    Two confirmations for one action is the over-gating this pattern is
    explicitly trying to avoid.
    """
    if not (query or "").strip():
        return "What file should I delete?"

    # The SAME search find() uses, called rather than reimplemented. These two
    # had duplicate copies of the walk-and-sort, so the substring-matching bug
    # had to be fixed twice and the ranking could silently diverge -- which for
    # a delete means staging a different file than the one find() would have
    # shown for the identical words.
    hits, terms = _search(query)
    if not terms:
        return "What file should I delete?"
    if not hits:
        return f"I couldn't find anything matching {query} to delete."

    path = hits[0][0]
    name = os.path.basename(path)

    _pending["path"] = path
    _pending["at"] = time.time()

    if not COMMAND_PIN:
        return (f"You want me to delete {name}, but no command PIN is set in "
                "config.py, so I can't confirm this. Set COMMAND_PIN first.")
    return f'You want me to delete "{name}". Type your PIN in the operator channel to confirm.'


def confirm_delete(supplied: str = "") -> str:
    """Same shape as power_skill.confirm(): re-checks expiry independently
    rather than trusting has_pending_delete() was checked a moment ago (the
    gap between a fast-path match and this actually running is small but
    not zero), refuses a PIN that is merely correct-but-late, and uses a
    constant-time comparison for the same timing-leak reason as everywhere
    else a PIN is checked in this codebase."""
    path = _pending["path"]
    if not path:
        return "There's nothing waiting for confirmation."

    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        _pending["path"] = None
        return "That confirmation expired. Ask me again if you still want it deleted."

    if not COMMAND_PIN:
        _pending["path"] = None
        return "No command PIN is set in config.py, so I can't confirm this."

    # ARGUS-SEC-011 + the fix browser_skill.py's docstring flagged: the old
    # raw compare_digest here compared the typed PIN against config.COMMAND_PIN
    # DIRECTLY -- which is a PBKDF2 hash once migrated, so every typed PIN was
    # 'wrong' and deletion could never be confirmed by PIN at all.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        return "That's not the right PIN. Type it in the operator channel, or say cancel."

    _pending["path"] = None
    name = os.path.basename(path)
    if not os.path.exists(path):
        return f"{name} is already gone — nothing to delete."
    try:
        if _recycle(path):
            return f"Deleted {name}. It's in the Recycle Bin if you need it back."
        return f"I couldn't delete {name} — the operation didn't go through."
    except Exception as e:
        return f"I couldn't delete {name}: {e}"


# ═══════════════════════════════════════════════════════════════════════════
# FILE OPERATIONS: move, copy, rename, create, compress, extract, inspect
# ═══════════════════════════════════════════════════════════════════════════
#
# "ARGUS should be able to operate on your entire filesystem through natural
# language." It now can -- inside a boundary, and the boundary is the feature
# rather than a limitation on it.
#
# CONFINEMENT IS THE WHOLE SAFETY MODEL. Every path on both ends of every
# operation must resolve inside SEARCH_ROOTS, and must not be
# integrity.is_protected(). Checked on the REALPATH, after resolution, so a
# symlink, a junction, an extended-length prefix (\\?\C:\...) or an admin
# share (\\localhost\C$\...) cannot walk out -- integrity._canonical_windows()
# already folds those spellings together, and all three were live bypasses
# when it was written.
#
# WHY NOT JUST "ANYWHERE THE USER CAN WRITE". Because ARGUS is voice-driven and
# a microphone is not an authentication factor. "Move everything from Documents
# to D drive" mis-heard once, executed across the whole disk, is unrecoverable
# in a way that a wrong answer never is. The roots are the five folders a
# person actually keeps work in, plus the project directory.
#
# NOTHING HERE DELETES. Deletion stays where it was: stage_delete /
# confirm_delete, at L4, behind a PIN, and to the Recycle Bin. A move that
# silently overwrote the destination would be a delete wearing a different
# name, so every destination collision is refused rather than resolved.

class FileOpError(Exception):
    """A refusal with a spoken reason."""


def _roots() -> list:
    out = []
    for r in SEARCH_ROOTS:
        try:
            out.append(os.path.normcase(os.path.realpath(r)))
        except OSError:
            continue
    return out


def _confined(path: str) -> str:
    """Resolve PATH and confirm it is somewhere ARGUS may act. Raises if not.

    Returns the resolved absolute path, which is what callers must then use --
    acting on the string that was passed in after checking a different,
    resolved one is how confinement checks get bypassed.
    """
    import integrity

    if not str(path or "").strip():
        raise FileOpError("I need a name to work with.")
    try:
        real = os.path.realpath(os.path.abspath(os.path.expandvars(str(path))))
    except (OSError, ValueError):
        raise FileOpError("That path doesn't make sense to me.")

    if integrity.is_protected(real):
        raise FileOpError(integrity.refusal(real))

    norm = os.path.normcase(real)
    for root in _roots():
        if norm == root or norm.startswith(root + os.sep):
            return real
    raise FileOpError(
        f"{os.path.basename(real) or real} is outside the folders I work in. "
        f"I stay inside your Desktop, Documents, Downloads, Pictures and "
        f"Videos — move it into one of those and I'll handle it.")


def _resolve_existing(query: str) -> str:
    """A path the user named, whether by full path or by search.

    A bare name goes through the same _search() the find command uses, so
    "move the invoice to Documents" works without anybody typing a path.
    """
    q = str(query or "").strip().strip('"')
    if not q:
        raise FileOpError("Which file?")

    # "MOVE THAT TO DOCUMENTS" -- where "that" is the file the last search
    # resolved to. Without this, a pronoun reaches _search() as the literal
    # word "that", matches nothing, and the answer is "I couldn't find
    # anything called that" to a request whose referent was on screen a
    # second earlier.
    if q.lower() in ("that", "it", "this", "that one", "the file",
                     "that file", "this file"):
        try:
            from skills import followup_skill
            remembered = followup_skill.last_file()
        except Exception:
            remembered = ""
        if not remembered:
            raise FileOpError("I'm not sure which file you mean — find it "
                              "first and then tell me what to do with it.")
        if not os.path.exists(remembered):
            raise FileOpError("That file isn't there any more.")
        return _confined(remembered)

    # An explicit path, if it looks like one and exists.
    if (os.sep in q or "/" in q or (len(q) > 2 and q[1] == ":")):
        cand = os.path.expandvars(q)
        if os.path.exists(cand):
            return _confined(cand)
    hits = _search(q)
    if not hits:
        raise FileOpError(f"I couldn't find anything called {q}.")
    if len(hits) > 1:
        names = ", ".join(os.path.basename(h[0] if isinstance(h, tuple) else h)
                          for h in hits[:3])
        raise FileOpError(f"I found more than one: {names}. Which one?")
    first = hits[0]
    return _confined(first[0] if isinstance(first, tuple) else first)


def _resolve_folder(name: str) -> str:
    """A destination folder, by name or by path. Must already exist."""
    n = str(name or "").strip().strip('"')
    if not n:
        raise FileOpError("Where to?")
    # The well-known folders, by their spoken names.
    shortcuts = {
        "desktop": r"%USERPROFILE%\Desktop",
        "documents": r"%USERPROFILE%\Documents",
        "docs": r"%USERPROFILE%\Documents",
        "downloads": r"%USERPROFILE%\Downloads",
        "pictures": r"%USERPROFILE%\Pictures",
        "photos": r"%USERPROFILE%\Pictures",
        "videos": r"%USERPROFILE%\Videos",
    }
    key = n.lower().strip("\\/ ")
    if key in shortcuts:
        return _confined(os.path.expandvars(shortcuts[key]))
    cand = os.path.expandvars(n)
    if os.path.isdir(cand):
        return _confined(cand)
    # A sub-folder of one of the roots, named on its own ("invoices").
    for root in SEARCH_ROOTS:
        guess = os.path.join(os.path.expandvars(root), n)
        if os.path.isdir(guess):
            return _confined(guess)
    raise FileOpError(f"I can't find a folder called {n}.")


def _unique(dest: str) -> str:
    """A destination that does not exist yet.

    NEVER OVERWRITES. A move or copy that replaced the destination would be a
    deletion carried out by a command that does not say delete -- and deletion
    in this module is L4, behind a PIN, and recoverable. Suffixing keeps the
    operation truthful.
    """
    if not os.path.exists(dest):
        return dest
    stem, ext = os.path.splitext(dest)
    for i in range(2, 100):
        cand = f"{stem} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
    raise FileOpError("There are already too many copies of that name.")


def _human_size(n: int) -> str:
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} bytes"


def move(query: str, destination: str) -> str:
    """Move a file or folder into an existing folder."""
    import security
    import shutil

    try:
        src = _resolve_existing(query)
        dst_dir = _resolve_folder(destination)
    except FileOpError as e:
        return str(e)
    if os.path.normcase(os.path.dirname(src)) == os.path.normcase(dst_dir):
        return f"{os.path.basename(src)} is already in there."
    dest = _unique(os.path.join(dst_dir, os.path.basename(src)))
    try:
        shutil.move(src, dest)
    except (OSError, shutil.Error) as e:
        return f"I couldn't move it ({type(e).__name__})."
    security.audit("file_move", f"{os.path.basename(src)} -> {dst_dir}", "ok")
    renamed = os.path.basename(dest) != os.path.basename(src)
    return (f"Moved {os.path.basename(src)} into "
            f"{os.path.basename(dst_dir) or dst_dir}"
            + (f", as {os.path.basename(dest)} — there was already one there."
               if renamed else "."))


def copy(query: str, destination: str) -> str:
    """Copy a file or folder into an existing folder."""
    import security
    import shutil

    try:
        src = _resolve_existing(query)
        dst_dir = _resolve_folder(destination)
    except FileOpError as e:
        return str(e)
    dest = _unique(os.path.join(dst_dir, os.path.basename(src)))
    try:
        if os.path.isdir(src):
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)
    except (OSError, shutil.Error) as e:
        return f"I couldn't copy it ({type(e).__name__})."
    security.audit("file_copy", f"{os.path.basename(src)} -> {dst_dir}", "ok")
    return (f"Copied {os.path.basename(src)} into "
            f"{os.path.basename(dst_dir) or dst_dir}.")


def rename(query: str, new_name: str) -> str:
    """Rename in place. The new name may not contain a path.

    A new name with a separator in it is a MOVE wearing a rename's clothes,
    and it would slip past the destination confinement that move() applies --
    so it is refused and the user is pointed at the command that does check.
    """
    new = str(new_name or "").strip().strip('"')
    if not new:
        return "What should I call it?"
    if os.sep in new or "/" in new or ":" in new:
        return ("That looks like a path rather than a name. If you want it "
                "somewhere else, ask me to move it.")
    if new in (".", "..") or new.strip(". ") == "":
        return "That isn't a usable name."
    import security
    try:
        src = _resolve_existing(query)
    except FileOpError as e:
        return str(e)
    # Keep the extension if the new name has none -- "rename the invoice to
    # january" should not produce an extensionless file Windows cannot open.
    stem, ext = os.path.splitext(src)
    if ext and not os.path.splitext(new)[1]:
        new += ext
    dest = os.path.join(os.path.dirname(src), new)
    if os.path.exists(dest):
        return f"There's already something called {new} in that folder."
    try:
        os.rename(src, _confined(dest))
    except FileOpError as e:
        return str(e)
    except OSError as e:
        return f"I couldn't rename it ({type(e).__name__})."
    security.audit("file_rename", f"{os.path.basename(src)} -> {new}", "ok")
    return f"Renamed to {new}."


def make_folder(name: str, where: str = "") -> str:
    """Create a folder inside one of the roots."""
    import security

    n = str(name or "").strip().strip('"')
    if not n:
        return "What should I call it?"
    if os.sep in n or "/" in n or ":" in n:
        return "Give me just a name and tell me where separately."
    try:
        parent = (_resolve_folder(where) if str(where or "").strip()
                  else _confined(os.path.expandvars(r"%USERPROFILE%\Documents")))
        target = _confined(os.path.join(parent, n))
    except FileOpError as e:
        return str(e)
    if os.path.isdir(target):
        return f"{n} already exists in {os.path.basename(parent)}."
    try:
        os.makedirs(target)
    except OSError as e:
        return f"I couldn't create it ({type(e).__name__})."
    security.audit("folder_create", f"{n} in {parent}", "ok")
    return f"Created {n} in {os.path.basename(parent) or parent}."


def create(name: str, content: str = "", where: str = "") -> str:
    """Create a brand-new text or markdown file with the owner's content.

    Refuses to overwrite -- if a file of that name already exists, that is a
    refusal, not a version bump. Writing over something the owner put there
    would be a delete wearing a different name, exactly what the confinement
    section above says this module never does. A new file with content that
    only came from the owner's own words is the one safe write here.
    """
    import security

    n = str(name or "").strip().strip('"')
    if not n:
        return "What file should I create? Give me a name."
    if os.sep in n or "/" in n or ":" in n:
        return "Give me just a file name and tell me where separately."
    try:
        parent = (_resolve_folder(where) if str(where or "").strip()
                  else _confined(os.path.expandvars(r"%USERPROFILE%\Desktop")))
        target = _confined(os.path.join(parent, n))
    except FileOpError as e:
        return str(e)
    if os.path.exists(target):
        return (f"Already a file called {n} in "
                f"{os.path.basename(parent) or parent} — I won't overwrite it. "
                f"Say a different name or a different folder.")
    try:
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write(str(content or ""))
    except OSError as e:
        return f"I couldn't create it ({type(e).__name__})."
    security.audit("file_create", f"{n} in {parent}", "ok")
    return f"Created {n} in {os.path.basename(parent) or parent}."


def compress(query: str, destination: str = "") -> str:
    """Zip a file or folder. Never replaces an existing archive."""
    import security
    import zipfile

    try:
        src = _resolve_existing(query)
        dst_dir = (_resolve_folder(destination) if str(destination or "").strip()
                   else os.path.dirname(src))
    except FileOpError as e:
        return str(e)
    base = os.path.splitext(os.path.basename(src))[0]
    dest = _unique(os.path.join(dst_dir, base + ".zip"))
    try:
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            if os.path.isdir(src):
                for dirpath, _dirs, files in os.walk(src):
                    for fn in files:
                        full = os.path.join(dirpath, fn)
                        z.write(full, os.path.relpath(full, os.path.dirname(src)))
            else:
                z.write(src, os.path.basename(src))
    except (OSError, zipfile.BadZipFile) as e:
        # THE ONLY os.remove IN THIS SECTION, and it removes the half-written
        # archive ARGUS itself just created a moment ago -- never anything the
        # owner put there. Leaving a truncated .zip behind would look like a
        # successful compression until somebody tried to open it.
        try:
            os.remove(dest)
        except OSError:
            pass
        return f"I couldn't compress it ({type(e).__name__})."
    size = os.path.getsize(dest)
    security.audit("file_compress", f"{os.path.basename(src)} -> {os.path.basename(dest)}", "ok")
    return f"Zipped it to {os.path.basename(dest)}, {_human_size(size)}."


def extract(query: str, destination: str = "") -> str:
    """Unzip an archive into a folder.

    EVERY MEMBER PATH IS CHECKED. A zip entry named ..\\..\\Windows\\System32\\x
    extracts outside the destination on a naive extractall -- the Zip Slip
    traversal, and it is the reason this walks members rather than calling
    extractall(). Only .zip is handled: rar and 7z need a third-party
    extractor, and shelling out to one is exactly what execpolicy exists to
    prevent.
    """
    import security
    import shutil
    import zipfile

    try:
        src = _resolve_existing(query)
    except FileOpError as e:
        return str(e)
    if not src.lower().endswith(".zip"):
        return ("I can only open zip files. For rar or 7z you'll need the "
                "program that made them.")
    try:
        dst_dir = (_resolve_folder(destination) if str(destination or "").strip()
                   else _confined(os.path.join(
                       os.path.dirname(src),
                       os.path.splitext(os.path.basename(src))[0])))
    except FileOpError as e:
        return str(e)

    os.makedirs(dst_dir, exist_ok=True)
    root = os.path.normcase(os.path.realpath(dst_dir))
    written, skipped = 0, 0
    try:
        with zipfile.ZipFile(src) as z:
            for member in z.infolist():
                target = os.path.realpath(os.path.join(dst_dir, member.filename))
                if not os.path.normcase(target).startswith(root + os.sep) \
                        and os.path.normcase(target) != root:
                    skipped += 1          # Zip Slip: refuse, do not sanitise
                    continue
                if member.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(member) as fh, open(target, "wb") as out:
                    shutil.copyfileobj(fh, out)
                written += 1
    except (OSError, zipfile.BadZipFile) as e:
        return f"I couldn't open that archive ({type(e).__name__})."
    security.audit("file_extract",
                   f"{os.path.basename(src)} -> {dst_dir} ({written} files)", "ok")
    out = (f"Extracted {written} file{'s' if written != 1 else ''} into "
           f"{os.path.basename(dst_dir)}.")
    if skipped:
        out += (f" I refused {skipped} entr{'ies' if skipped != 1 else 'y'} that "
                f"tried to write outside that folder — that archive is not "
                f"trustworthy.")
    return out


def metadata(query: str) -> str:
    """Size, dates and type for one file. Read-only."""
    try:
        path = _resolve_existing(query)
        st = os.stat(path)
    except FileOpError as e:
        return str(e)
    except OSError as e:
        return f"I couldn't read it ({type(e).__name__})."
    kind = "folder" if os.path.isdir(path) else (
        os.path.splitext(path)[1].lstrip(".").upper() + " file"
        if os.path.splitext(path)[1] else "file")
    bits = [f"{os.path.basename(path)} is a {kind}"]
    if not os.path.isdir(path):
        bits.append(_human_size(st.st_size))
    bits.append("modified " + time.strftime("%d %b %Y at %H:%M",
                                            time.localtime(st.st_mtime)))
    bits.append(f"it's in {os.path.dirname(path)}")
    return ". ".join(b[0].upper() + b[1:] for b in bits) + "."


def permissions(query: str) -> str:
    """Owner and this account's own access, for one file. Read-only, and
    deliberately shallow -- a full ACL dump is a security-tool feature, not
    a personal-assistant one; owner plus "can I write to this" is what
    "who can touch this file" actually means for a one-person machine."""
    try:
        path = _resolve_existing(query)
    except FileOpError as e:
        return str(e)
    bits = []
    try:
        import win32security
        sd = win32security.GetFileSecurity(
            path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        bits.append(f"owned by {domain}\\{name}")
    except Exception:
        pass
    readable = os.access(path, os.R_OK)
    writable = os.access(path, os.W_OK)
    bits.append("you can read and write it" if readable and writable else
                "you can read it but not write it" if readable else
                "you don't have access to it")
    try:
        import stat as _stat
        if os.stat(path).st_file_attributes & _stat.FILE_ATTRIBUTE_READONLY:
            bits.append("marked read-only")
    except Exception:
        pass
    return f"{os.path.basename(path)}: " + ", ".join(bits) + "."


def recent(hours: float = 24.0, limit: int = 6) -> str:
    """What has changed lately, across the roots. Read-only."""
    import integrity

    cutoff = time.time() - max(0.25, float(hours)) * 3600
    found = []
    deadline = time.time() + TIME_BUDGET
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            if time.time() > deadline:
                break
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIRS and not d.startswith(".")
                       and not integrity.is_protected(os.path.join(dirpath, d))]
            for fn in files:
                full = os.path.join(dirpath, fn)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if st.st_mtime >= cutoff:
                    found.append((st.st_mtime, full, st.st_size))
    if not found:
        return (f"Nothing's changed in your folders in the last "
                f"{int(hours)} hours.")
    found.sort(reverse=True)
    named = "; ".join(
        f"{os.path.basename(p)} ({_human_size(sz)})" for _m, p, sz in found[:limit])
    more = len(found) - min(limit, len(found))
    return (f"{len(found)} file{'s' if len(found) != 1 else ''} changed: "
            f"{named}" + (f", and {more} more." if more else "."))


def duplicates(limit: int = 5) -> str:
    """Files that are byte-identical. Read-only; it never removes anything.

    Grouped by SIZE first and only then hashed. Hashing every file in five
    folders to find duplicates would take minutes; two files of different
    sizes cannot be identical, so the size pass eliminates almost everything
    for the cost of a stat().
    """
    import hashlib
    import integrity

    by_size = {}
    deadline = time.time() + TIME_BUDGET * 2
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            if time.time() > deadline:
                break
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIRS and not d.startswith(".")
                       and not integrity.is_protected(os.path.join(dirpath, d))]
            for fn in files:
                full = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    continue
                if sz < 4096:              # too small to be worth reclaiming
                    continue
                by_size.setdefault(sz, []).append(full)

    groups, wasted = [], 0
    for sz, paths in by_size.items():
        if len(paths) < 2 or time.time() > deadline:
            continue
        digests = {}
        for p in paths:
            try:
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(131072), b""):
                        h.update(chunk)
                digests.setdefault(h.hexdigest(), []).append(p)
            except OSError:
                continue
        for _d, same in digests.items():
            if len(same) > 1:
                groups.append((sz, same))
                wasted += sz * (len(same) - 1)

    if not groups:
        return "I didn't find any duplicate files worth mentioning."
    groups.sort(key=lambda g: -g[0] * (len(g[1]) - 1))
    named = "; ".join(f"{len(g[1])} copies of {os.path.basename(g[1][0])} "
                      f"({_human_size(g[0])} each)" for g in groups[:limit])
    return (f"{len(groups)} set{'s' if len(groups) != 1 else ''} of identical "
            f"files, wasting about {_human_size(wasted)}: {named}. "
            f"I won't delete any of them — tell me which to remove.")


def cancel_delete() -> str:
    if _pending["path"]:
        name = os.path.basename(_pending["path"])
        _pending["path"] = None
        return f"Cancelled. {name} was not deleted."
    return "Nothing to cancel."


def has_pending_delete() -> bool:
    return bool(_pending["path"]) and (time.time() - _pending["at"] <= CONFIRM_WINDOW)


# ─── Content search -- distinct from find(), which matches FILENAMES ──────
_TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json", ".py", ".js", ".ts",
            ".html", ".css", ".xml", ".yaml", ".yml", ".ini", ".cfg"}
_CONTENT_MAX_BYTES = 1_000_000  # skip anything bigger -- a voice command waits seconds, not minutes
_CONTENT_TIME_BUDGET = 6.0


def content_search(phrase: str, limit: int = 5) -> str:
    """Which files MENTION phrase, across SEARCH_ROOTS -- find()'s own
    filename match answers a different question ("what's it called") from
    this one ("what does it say"). Text-like extensions only: a binary
    file's bytes containing PHRASE by coincidence is not a match a person
    means, and decoding one is wasted work find() never had to do."""
    phrase = (phrase or "").strip()
    if not phrase:
        return "Search your files for what?"
    import integrity

    deadline = time.time() + _CONTENT_TIME_BUDGET
    needle = phrase.lower()
    hits = []
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root) or time.time() > deadline:
            continue
        base_depth = root.rstrip("\\").count("\\")
        for dirpath, dirnames, filenames in os.walk(root):
            if time.time() > deadline:
                break
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            dirnames[:] = [d for d in dirnames
                           if not integrity.is_protected(os.path.join(dirpath, d))]
            if dirpath.count("\\") - base_depth > MAX_DEPTH:
                dirnames[:] = []
                continue
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in _TEXT_EXT:
                    continue
                full = os.path.join(dirpath, fn)
                if integrity.is_protected(full):
                    continue
                try:
                    if os.path.getsize(full) > _CONTENT_MAX_BYTES:
                        continue
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except OSError:
                    continue
                idx = text.lower().find(needle)
                if idx < 0:
                    continue
                snippet = text[max(0, idx - 40):idx + len(phrase) + 40].replace("\n", " ").strip()
                hits.append((full, snippet))
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break

    if not hits:
        return f'Nothing in your files mentions "{phrase}".'
    named = "; ".join(f'{os.path.basename(p)}: "...{s}..."' for p, s in hits)
    return f'{len(hits)} file{"s" if len(hits) != 1 else ""} mention "{phrase}": {named}'


# ═══════════════════════════════════════════════════════════════════════════
# RECYCLE BIN RESTORE -- restore a deleted file to its original location.
# ═══════════════════════════════════════════════════════════════════════════
#
# The Recycle Bin keeps each deleted item as a PAIR in $Recycle.Bin\<SID> on
# whichever drive held the file:
#     $R<random>  -- the deleted bytes, renamed to an 8-char random core.
#     $I<random>  -- RECYCLE_BIN_INFO: the original path + deletion time.
# Both share the same core. Windows "Restore" walks the $I files, finds the
# original path, and FO_MOVEs the matching $R core back there (restoring the
# original name in the process). This module does exactly that -- the same
# ctypes SHFileOperationW family _recycle() (:501) already uses for the
# delete side, with FO_MOVE and pTo filled in.
#
# Deliberately NOT the IShellFolder / System.Recycle* COM enumeration: that
# route needs vtable COM calls that can't be driven by a fixed struct and
# can't be unit-tested blind, while the $I/$R format is stable, fixed-offset
# data we can parse defensively and mock in the suite. The recorded original
# path is the only thing ever spoken or acted on -- never the $R core.
#
# Restore is ADDITIVE (it recreates a file that deletion removed), so it is
# lighter than delete's L4 -- but writing a file into a folder is still a
# write the owner should get to confirm, staging behind the same PIN gate as
# every other irreversible-adjacent action. Same CONFIRM_WINDOW, same wording.

def _bin_roots() -> list:
    """Every physical '$Recycle.Bin' container on the machine -- one per drive
    that has one (the name is case-insensitive on Windows, so both spellings
    are probed)."""
    import string

    roots = []
    for letter in string.ascii_uppercase:
        for spelling in (f"{letter}:\\$Recycle.Bin", f"{letter}:\\$RECYCLE.BIN"):
            if os.path.isdir(spelling):
                roots.append(spelling)
                break
    return roots


def _read_info_original(bin_meta_path: str):
    """The original full path recorded in an $I sidecar, or None.

    RECYCLE_BIN_INFO is: uint32 headerSize (24 for v1, 28 for v2), uint64 file
    size, FILETIME deletion time, then -- exactly at offset headerSize -- the
    null-terminated UTF-16 original path. Parsing the header size and reading
    the string from that offset handles both versions without sniffing flags;
    anything that doesn't decode is refused (None), not guessed at."""
    try:
        with open(bin_meta_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 24:
        return None
    header_size = int.from_bytes(data[0:4], "little")
    if header_size < 24 or header_size > len(data):
        return None
    raw = data[header_size:]
    end = raw.find(b"\x00\x00")
    if end < 0:
        end = len(raw) & ~1
    try:
        s = raw[:end].decode("utf-16-le", errors="strict").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    return s or None


def _bin_items() -> list:
    """[(core, r_path, original_path), ...] for every complete pair in the
    bin. A sidecar whose $R sibling is missing, or whose original path won't
    decode, is skipped -- it was mid-delete or corrupt, and restoring it would
    end in a broken file."""
    out = []
    for binfolder in _bin_roots():
        try:
            names = os.listdir(binfolder)
        except OSError:
            continue
        for fn in names:
            if not fn.startswith("$I") or len(fn) <= 2:
                continue
            core = fn[2:]
            rpath = os.path.join(binfolder, "$R" + core)
            if not os.path.exists(rpath):
                continue
            orig = _read_info_original(os.path.join(binfolder, fn))
            if not orig:
                continue
            out.append((core, rpath, orig))
    return out


def _match_bin_item(query: str, items=None):
    """The bin item whose ORIGINAL basename matches QUERY -- what the user
    remembers, never the random core. Exact single match wins; multiple exacts
    or a bare substring go unmatched so restore() can speak the choices."""
    q = (str(query or "").strip().strip('"')).lower()
    if not q:
        return None
    items = items if items is not None else _bin_items()
    exact = [it for it in items if os.path.basename(it[2]).lower() == q]
    if len(exact) == 1:
        return exact[0]
    return None


def restore(query: str) -> str:
    """Find a deleted file by its remembered name and stage its restoration.
    Matches the stage_delete shape: name spoken back, PIN via the operator
    channel, never immediate."""
    if not (query or "").strip():
        return "What should I restore?"
    item = _match_bin_item(query)
    if item is None:
        known = sorted({os.path.basename(it[2]) for it in _bin_items()})
        if not known:
            return ("The Recycle Bin is empty, so there's nothing to restore.")
        names = ", ".join(known[:6])
        return (f"I couldn't find {query.strip()} in the Recycle Bin. "
                f"I can see: {names}. Say the one you want and I'll restore it.")
    _core, rpath, orig = item
    name = os.path.basename(orig)
    # Fail BEFORE staging, not after: the original folder is where the file
    # will land, so it must be somewhere ARGUS is allowed to act right now.
    try:
        _confined(os.path.dirname(orig))
    except FileOpError as e:
        return str(e)
    if os.path.exists(orig):
        return f"{name} is already back where it was."
    if not COMMAND_PIN:
        return (f"You want me to restore {name}, but no command PIN is set in "
                "config.py, so I can't confirm this. Set COMMAND_PIN first.")
    _restore_pending["rpath"] = rpath
    _restore_pending["orig"] = orig
    _restore_pending["name"] = name
    _restore_pending["at"] = time.time()
    return f'You want me to restore "{name}". Type your PIN in the operator channel to confirm.'


def restore_confirm(supplied: str = "") -> str:
    """Same shape as confirm_delete(): independent expiry re-check, constant-
    time PIN compare, state cleared before acting so a failure can't double-run."""
    rpath = _restore_pending["rpath"]
    if not rpath:
        return "There's nothing waiting to be restored."

    if time.time() - _restore_pending["at"] > CONFIRM_WINDOW:
        _restore_pending["rpath"] = None
        return "That confirmation expired. Ask me again if you still want it restored."

    if not COMMAND_PIN:
        _restore_pending["rpath"] = None
        return "No command PIN is set in config.py, so I can't confirm this."

    # ARGUS-SEC-011: shared gate (and the same hash-vs-plaintext fix as
    # confirm_delete above -- the raw compare could never match a migrated PIN).
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        return "That's not the right PIN. Type it in the operator channel, or say cancel."

    name = _restore_pending["name"]
    orig = _restore_pending["orig"]
    rpath = _restore_pending["rpath"]
    _restore_pending["rpath"] = None  # clear BEFORE acting -- a failure must not re-run
    try:
        if not os.path.exists(rpath):
            return f"{name} is no longer in the Recycle Bin — nothing to restore."
        if os.path.exists(orig):
            return f"{name} already exists where it used to be."
        # Final confinement re-check on the realpath of the destination folder,
        # not just the stage-time one -- the gap between them is small but the
        # cost of a wrong path at THIS line is a file written outside the roots.
        import security
        _confined(os.path.dirname(orig))
        if _restore_move(rpath, orig):
            security.audit("file_restore", f"{name} <- {os.path.dirname(orig)}", "ok")
            return f"Restored {name} to {os.path.dirname(orig)}."
        return f"I couldn't restore {name} — the operation didn't go through."
    except FileOpError as e:
        return str(e)
    except Exception as e:
        return f"I couldn't restore {name}: {e}"


def _restore_move(src: str, dst: str) -> bool:
    """SHFileOperationW FO_MOVE of one file back to its original path -- the
    filesystem half of what Explorer's 'Restore' does. pFrom is the $R path,
    pTo is the full original target (folder + original name)."""
    op = _SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = _FO_MOVE
    op.pFrom = src + "\0\0"
    op.pTo = dst + "\0\0"
    op.fFlags = _FOF_NOCONFIRMATION | _FOF_SILENT | _FOF_NOERRORUI
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return result == 0 and not op.fAnyOperationsAborted


def restore_cancel() -> str:
    if _restore_pending["rpath"]:
        name = _restore_pending["name"]
        _restore_pending["rpath"] = None
        return f"Cancelled. {name} was not restored."
    return "Nothing to cancel."


def has_pending_restore() -> bool:
    return bool(_restore_pending["rpath"]) and \
        (time.time() - _restore_pending["at"] <= CONFIRM_WINDOW)
