'ARGUS - Cloud gate and routing policy: what a request is allowed to touch.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import contextlib
import contextvars
import functools
import re
import time
from dataclasses import dataclass

import security

# ═══════════════════════════════════════════════════════════════════════════
# PART 1 -- THE ROUTING POLICY
# ═══════════════════════════════════════════════════════════════════════════

LOCAL_REQUIRED = "local_required"
GENERAL = "general"
EXPLICIT_WEB = "explicit_web"
MIXED = "mixed"

WEB_NONE = ""
WEB_EXPLICIT = "explicit"

# A GENERAL question that neither the local model nor a hosted tier could answer
# may still be looked up on Wikipedia and the web. That fallback has never
# carried anything private -- a request with private context never reaches it --
# and it is what stops a small model's "I don't know" being the final word. Set
# this False to make the internet strictly ask-for-it-only: general questions
# then end at the local model's own answer.
GENERAL_WEB_FALLBACK = True

# Long pastes are classified on their opening only. The signals live in how a
# request is phrased, and a regex sweep over ten thousand characters buys nothing.
_MAX_CHARS = 4000

# Frames, most specific first. The frame is what the router uses to decide
# whether a local request wants a CAPABILITY (a skill that reads or acts) or an
# ANSWER (chat, on the local model).
OPERATION = "operation"     # an imperative over local things: "open X", "read my X"
RETRIEVAL = "retrieval"     # asking about the content/state of something of theirs
STATE = "state"             # the machine itself: "why is my laptop slow"
IDENTITY = "identity"       # who they are / what they did / what ARGUS knows of them
INTERNAL = "internal"       # ARGUS's own state: its memory, logs, tasks, permissions
DATA = "data"               # the text itself carries a path, address or secret
FOLLOWUP = "followup"       # a referential turn right after a local exchange
REFERENCE = "reference"     # a bare mention of something local, no question or command

_PRIORITY = {OPERATION: 7, RETRIEVAL: 6, STATE: 5, IDENTITY: 4,
             INTERNAL: 3, DATA: 2, FOLLOWUP: 1, REFERENCE: 0}


@dataclass(frozen=True)
class Decision:
    """What a request may touch. Immutable: a decision is made once per request
    and read by every layer, so nothing downstream can quietly widen it."""

    scope: str
    local_required: bool
    web: str = WEB_NONE
    reasons: tuple = ()
    by_content: bool = False      # local because of what was SAID, not merely a follow-up
    mixed: bool = False
    frame: str = ""

    @property
    def cloud_ok(self) -> bool:
        """May a hosted model see this request's text at all?"""
        return not self.local_required

    @property
    def web_ok(self) -> bool:
        """Was the internet asked for, and is it permitted for this request?"""
        return (not self.local_required) and self.web == WEB_EXPLICIT

    @property
    def wants_capability(self) -> bool:
        """A local request that needs a skill to read or act, not a chat reply."""
        return self.local_required and self.frame in (OPERATION, RETRIEVAL)

    def describe(self) -> str:
        why = ", ".join(self.reasons[:3]) if self.reasons else "no local context"
        return f"{self.scope} ({why})"


# ── vocabulary ─────────────────────────────────────────────────────────────
def _alt(*words: str) -> str:
    """An alternation, longest first. A space or hyphen inside a word matches
    either or neither, because speech-to-text writes "wifi", "wi-fi" and "wi fi"
    for the same thing."""
    parts = []
    for w in sorted(set(words), key=len, reverse=True):
        parts.append(re.escape(w).replace(r"\ ", r"[\s\-]?").replace(r"\-", r"[\s\-]?"))
    return "|".join(parts)


# The machine and its parts. "memory" alone is left out on purpose: it is a
# word for a person's recall at least as often as for RAM.
_MACHINE = _alt(
    "pc", "computer", "laptop", "macbook", "machine", "workstation",
    "rig", "desktop", "tower", "device", "tablet", "phone", "mobile", "cell",
    "cpu", "gpu", "processor", "ram", "memory usage", "disk", "drive", "ssd",
    "hdd", "nvme", "storage", "usb", "hard drive", "hard disk", "flash drive",
    "partition", "battery", "batteries", "charger", "fan", "temperature", "temp",
    "thermals",
    "screen", "display", "monitor", "keyboard", "mouse", "trackpad", "touchpad",
    "webcam", "camera", "mic", "microphone", "speaker", "headphone", "headset",
    "printer", "scanner", "bluetooth", "wifi", "network", "internet",
    "connection", "ethernet", "router", "modem", "vpn", "firewall", "port",
    "ip", "ip address", "mac address", "dns", "bandwidth", "hotspot", "ssid",
    "bios", "firmware", "driver", "os", "operating system", "registry",
    "volume", "brightness", "clipboard", "uptime", "specs",
)

# Software, and the developer's workspace. Words that are just as often about
# something else -- an "application" for a visa, a "process" for writing, a
# "service" from a company, a "test" at school -- are left out on purpose: the
# frame rules catch them when something is actually being done to them.
_SOFTWARE = _alt(
    "app", "program", "software", "task manager", "extension",
    "add-on", "plugin", "browser", "tab", "window", "windows update",
    "windows defender", "defender", "antivirus", "update", "installation",
    "environment variable", "env var", "setting", "config", "configuration",
    "preference", "permission", "terminal", "script", "code", "codebase",
    "repo", "repository", "project", "branch", "commit", "test suite",
    "log file", "error log", "logfile", "security log", "event log",
    "system log", "crash log",
)

# Files and what people keep in them. Documents are deliberately named by KIND
# here; a particular document (a CV, a lease, a thesis) is handled by the frame
# rules below and never needs an entry.
_FILES = _alt(
    "file", "folder", "directory", "directories", "document", "doc",
    "spreadsheet", "workbook", "presentation", "slides", "slide deck", "pdf",
    "note", "download", "recycle bin", "trash", "archive", "zip", "backup",
    "screenshot", "photo", "picture", "image", "video", "recording",
    "music library", "attachment", "bookmark",
    "browsing history", "search history", "command history", "download history",
    "chat history", "conversation history", "cookie", "cache", "temp files",
    "temp folder",
)

# What ARGUS holds about the person, and what is theirs to keep private.
_PERSONAL = _alt(
    "profile", "vault", "reminder", "timer", "alarm", "schedule", "calendar",
    "appointment", "agenda", "task", "task list", "to-do", "todo", "to-do list",
    "todo list", "goal", "habit", "routine", "contact", "contact list",
    "address book", "email", "e-mail", "inbox", "mail", "message", "text",
    "dm", "voicemail", "password", "passcode", "passphrase", "pin", "login",
    "credential", "account", "api key", "token", "secret", "ssh key",
    "recovery key", "license key", "licence key", "activation key",
    "serial number", "security key", "access code", "seed phrase",
    "private key", "bank", "banking", "bank account", "balance", "statement",
    "transaction", "salary", "income", "budget", "tax", "tax return",
    "credit card", "debit card", "card number", "cvv", "iban", "investment",
    "saving", "passport", "ssn", "social security", "id number", "id card",
    "driver's license", "drivers license", "insurance", "medical", "medication",
    "prescription", "diagnosis", "health record", "health", "doctor",
    "therapist", "location", "home address", "address", "phone number",
    "email address", "birth date", "date of birth", "username", "user name",
    "activity", "activities", "usage", "stats", "statistic", "alert", "detection",
    "threat", "audit log",
)
# Not listed on purpose: "birthday", "age", "name", "startup". As bare nouns they are
# chatter far more often than data ("ideas for my birthday", "names for my startup").
# The FACTS they stand for are caught by the identity frames below ("what's my
# name", "my birthday is", "when is my birthday"), which is where they belong.

# The nouns a deictic "this/that/the current ..." can point at on a machine.
_DEICTIC = _alt(
    "pc", "computer", "laptop", "machine", "device", "screen", "window", "tab",
    "app", "application", "program", "folder", "directory", "file", "document",
    "page", "website", "site", "article", "project", "repo", "repository",
    "codebase", "code", "script", "function", "class", "module", "branch",
    "commit", "build", "test", "error", "bug", "log", "output", "terminal",
    "console", "drive", "disk", "network", "connection", "session", "workspace",
    "desktop", "download", "selection", "clipboard", "image", "photo",
    "picture", "video", "recording", "screenshot", "email", "message", "note",
    "spreadsheet", "presentation", "pdf",
)


# A word that can sit between "my" and its noun ("my HOME wifi password", "my WORK
# laptop's battery"). Articles, prepositions, conjunctions, pronouns and auxiliaries
# cannot: they mark the end of the noun phrase, and letting them through made
# "write my boss AN email" read as "my email" and "my cat LIKES the pc" as "my pc".
_MOD = (r"(?:(?!(?:a|an|the|to|for|of|and|or|but|that|this|these|those|is|are|was|"
        r"were|has|have|had|with|in|on|at|it|i|you|he|she|we|they|not|no|me|us)\b)"
        r"[a-z0-9'\-]+\s+)")


def _possessive(alt: str) -> "re.Pattern":
    # "my" + up to two modifiers + the noun. Two, not more: a longer gap starts
    # matching across clauses.
    return re.compile(
        r"\b(?:my|our)\s+" + _MOD + r"{0,2}?(?:" + alt + r")(?:'?s|es)?\b")


_POSS = {
    "machine": _possessive(_MACHINE),
    "software": _possessive(_SOFTWARE),
    "files": _possessive(_FILES),
    "personal": _possessive(_PERSONAL),
}

_DEICTIC_RE = re.compile(
    r"\b(?:this|that|these|those|the\s+(?:current|active|open|selected|focused)"
    r"|current|active)\s+(?:[a-z0-9'\-]+\s+)?(?:" + _DEICTIC + r")(?:'?s|es)?\b")

# Places that exist as exactly one instance on a machine. "the downloads folder"
# and "the recycle bin" name THIS machine's, with no "my" needed -- unlike "the
# computer" or "the file", which are as often generic. A definition of one ("what
# is the recycle bin", "how does the clipboard work") is still general knowledge.
_PLACE = _alt(
    "downloads folder", "downloads", "desktop", "documents folder",
    "pictures folder", "music folder", "videos folder", "recycle bin", "trash",
    "clipboard", "c drive", "d drive", "e drive", "taskbar", "start menu",
    "task manager", "device manager", "control panel", "registry", "hosts file",
    "system32", "appdata", "temp folder", "startup folder", "event log",
    "security log", "home folder", "home directory", "working directory",
    "current directory",
)
_THE_PLACE = re.compile(r"\bthe\s+(?:" + _PLACE + r")\b")
_DEFINITIONAL = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|um|uh|erm|please|argus)[,\s]+)*"
    r"(?:what(?:'?s|\s+is|\s+are|\s+was)\s+(?:the\s+|a\s+|an\s+)?(?:" + _PLACE + r")\b"
    r"|(?:define|explain|describe|tell\s+me\s+about)\s+(?:the\s+|a\s+|an\s+)?(?:" + _PLACE + r")\b"
    r"|how\s+(?:does|do|is|are)\s+(?:the\s+|a\s+|an\s+)?(?:" + _PLACE + r")\s+work)")
# A file named outright: "the file called notes", "a folder named taxes".
_NAMED_FILE = re.compile(
    r"\b(?:file|folder|document|spreadsheet|pdf|note|script)s?\s+"
    r"(?:called|named|titled)\s+[\w'\"\-]+")
# "logged into the computer", "installed on the pc": a preposition that puts
# something ON the machine, unlike "the history of the computer".
_ON_THE_MACHINE = re.compile(
    r"\b(?:on|into|onto|inside)\s+the\s+(?:computer|pc|laptop|machine|device)\b")

# "on this pc", "locally", "local files" -- location stated outright.
_LOCATIVE = re.compile(
    r"\b(?:on|in|from|inside|within|across)\s+(?:this|the\s+local)\s+"
    r"(?:pc|computer|machine|laptop|device|system|drive|disk|network)\b"
    r"|\bon\s+disk\b"
    r"|\blocal(?:ly)?\s+(?:files?|folders?|drives?|network|copy|copies|machine|"
    r"storage|disk|ip|address|host|install(?:ation)?|version|environment|repo|"
    r"branch|database|documents?|security)\b")


# ── phrasing: who is doing what to what ────────────────────────────────────
_FILL = (r"(?:(?:so|and|but|ok|okay|hey|well|um|uh|erm|please|kindly|argus|then|"
         r"now|also|just|right|alright|yeah|yes|no|listen|look)[,\s]+)*")

# What can stand between the start of a sentence and its verb without stopping
# it being a request: "can you help me", "i need to", "let's".
_LEAD = (
    r"^" + _FILL +
    r"(?:(?:can|could|would|will|might)\s+you\s+(?:please\s+)?(?:help\s+me\s+(?:to\s+)?)?"
    r"|(?:i\s+)?(?:want|need|wanna|have|got)\s+(?:you\s+)?to\s+"
    r"|i(?:'?d|\s+would)\s+like\s+(?:you\s+)?to\s+"
    r"|i\s+(?:need|want|wanna)\s+"
    r"|let'?s\s+|go\s+ahead\s+and\s+|help\s+me\s+(?:to\s+)?|try\s+to\s+"
    r"|you\s+(?:should|can|could|need\s+to)\s+)?"
    r"(?:please\s+)?")

# Verbs that act on THE MACHINE whatever they are given -- there is no general
# meaning of "mute" or "reboot" that is not a command to this computer.
_MACHINE_VERB = (
    r"open|close|launch|quit|kill|terminate|minimi[sz]e|maximi[sz]e|mute|unmute|"
    r"lock|unlock|shut\s*down|restart|reboot|hibernate|sign\s*out|log\s*out|"
    r"screenshot|install|uninstall|delete|erase|wipe|rename|mount|eject|defrag|"
    r"format|click|scroll|dictate|toggle|snap|tile|screen\s*record|"
    # "turn on the wifi", "turn the volume down", "switch it off": the particle
    # can sit either side of the object.
    r"(?:turn|switch)\s+(?:the\s+|my\s+|this\s+|that\s+)?(?:[a-z]+\s+)?(?:on|off|up|down)|"
    r"set\s+(?:a\s+|an\s+|the\s+)?(?:timer|alarm|reminder|volume|brightness)|"
    r"take\s+(?:a\s+)?(?:screenshot|screen\s*shot|picture|photo|capture|snapshot)|"
    r"remind\s+me|snooze|pause|resume|skip")
_OP_MACHINE = re.compile(_LEAD + r"(?P<v>" + _MACHINE_VERB + r")\b")

# Verbs that are local only when they are done TO something of the person's.
# "find my X" is a search of this machine; "find a good pizza place" is not.
_ACT_VERB = (
    r"read|show|display|list|find|locate|look\s+(?:at|for|in|through|over)|"
    r"go\s+(?:through|over)|pull\s+up|bring\s+up|dig\s+up|fetch|"
    r"retrieve|check|scan|analy[sz]e|review|inspect|examine|audit|summari[sz]e|"
    r"explain|describe|proofread|edit|fix|repair|improve|update|refresh|"
    r"clean(?:\s+up)?|clear|empty|organi[sz]e|sort|move|copy|paste|save|export|"
    r"import|convert|compress|extract|zip|unzip|upload|download|send|share|"
    r"attach|forward|email|print|back\s*up|restore|sync|count|compare|merge|"
    r"split|translate|tag|label|open|run|start|stop|execute|debug|test|build|"
    r"compile|deploy|commit|push|pull|clone|tell\s+me\s+(?:about|what'?s\s+in)|"
    r"what'?s\s+in")
_OBJECT = (
    r"(?:me\s+|us\s+)?(?:(?:a|an|the|all|some|any|every|each|both|of|in|at|"
    r"through|into|up|down|out|over|back|on|to|for|about|from|with|inside)\s+)*"
    r"(?:my|our|this|that|these|those|current|active)\b")
_OP_OBJECT = re.compile(_LEAD + r"(?P<v>" + _ACT_VERB + r")\s+" + _OBJECT)

# The people and animals in someone's life. "call my mom", "write my boss an email",
# "search the web for my mom's birthday ideas" put a possessive right where a thing to
# be READ would be, but what it names is a person, not something held on this machine
# -- so the frames that key on POSITION alone (the direct object of a verb, the object
# of a web search) leave them out. A QUESTION about them ("what's my mom's number") is
# still about something of theirs, and _WH_MY catches it.
_PEOPLE = _alt(
    "mom", "mum", "mother", "dad", "father", "parent", "brother", "sister",
    "sibling", "wife", "husband", "partner", "girlfriend", "boyfriend", "fiance",
    "fiancee", "friend", "buddy", "pal", "mate", "kid", "child", "children", "son",
    "daughter", "baby", "family", "grandma", "grandpa", "grandmother",
    "grandfather", "aunt", "uncle", "cousin", "boss", "manager", "teacher",
    "professor", "tutor", "coach", "colleague", "coworker", "neighbor",
    "neighbour", "roommate", "classmate", "dog", "cat", "pet", "puppy", "kitten",
    "team", "class", "crew", "client", "customer",
)
_NOT_A_PERSON = (r"(?!\s+(?:(?:own|old|new|best|good|little|big|younger|older|dear|"
                 r"lovely|favou?rite)\s+)?(?:" + _PEOPLE + r")(?:'?s|es)?\b)")

# The verbs of looking something up on the WEB. They get their own, narrower rule: a
# possessive object only. "search for my thesis" is a search of this machine, but "look
# up that word" or "google this" is at least as likely about something public the two
# of them were just talking about, and treating every "this"/"that" as a local
# reference would refuse ordinary lookups. A possessive is unambiguous.
#
# THE WEB CAN BE NAMED BETWEEN THE VERB AND THE POSSESSIVE -- "search THE WEB for my
# X", "search ONLINE for my X", "google for my X", "look online for my X". Those words
# are fillers like "the" and "for", not a break in the frame. Missing them was a real
# hole, found by a second session: "search the web for my thesis draft" was judged
# general and went to a search engine with the words "my thesis draft".
_WEB_VERB = (r"search|google|bing|duckduckgo|look\s*up|research|investigate|"
             r"find\s+out\s+about|dig\s+into|look\s+into|"
             r"look(?=\s+(?:online|on\s+(?:the\s+)?(?:web|internet|net|google)\b))")
_WEB_WORDS = r"web|internet|net|online|google|bing|duckduckgo|ddg|engine"
_POSSESSIVE_OBJECT = (
    r"(?:me\s+|us\s+)?(?:(?:a|an|the|all|some|any|every|each|both|of|in|at|"
    r"through|into|up|down|out|over|back|on|to|for|about|from|with|inside|"
    + _WEB_WORDS + r")\s+)*"
    r"(?:my|our)\b" + _NOT_A_PERSON)
_OP_WEB_OBJECT = re.compile(
    _LEAD + r"(?P<v>" + _WEB_VERB + r")\s+" + _POSSESSIVE_OBJECT)

# THE DIRECT OBJECT OF ANY VERB. Any word can be the imperative verb -- "turn my X into
# a checklist", "put my X in order", "print my X" -- so this frame is anchored on
# POSITION (the first word of a request, then a possessive), not on a list of verbs.
# That is the difference between a rule and a list: a verb nobody thought of is still
# a verb. People and animals are excluded (_NOT_A_PERSON): "call my mom" acts on a
# person, not on a file.
_DIRECT_DET = (r"(?:a|an|the|all|some|any|every|each|both|another|one|two|three|four|"
               r"five|six|seven|eight|nine|ten|of)")
_OP_DIRECT = re.compile(
    _LEAD + r"(?P<v>[a-z][a-z'\-]*)\s+(?:(?:me|us)\s+)?(?:" + _DIRECT_DET + r"\s+)*"
    r"(?:my|our)\b" + _NOT_A_PERSON)

# SOURCE MATERIAL. Verbs that take somebody's material as the thing they work FROM --
# what is read, counted, checked, converted, extracted or built out of it -- and the
# prepositions that mark it: "a summary OF my X", "the dates OUT OF my X", "a report
# FROM my X", "a cover letter USING my X". A beneficiary or a topic ("a poem FOR my
# mom", "a joke ABOUT my boss", "an email TO my boss") is incidental to the request
# and is deliberately not a source preposition.
_MATERIAL_VERB = (
    r"read|scan|check|review|proofread|edit|fix|repair|improve|update|refresh|"
    r"analy[sz]e|inspect|examine|audit|compare|rate|grade|score|summari[sz]e|"
    r"explain|describe|translate|convert|compress|extract|pull|copy|move|paste|"
    r"save|export|import|upload|download|send|share|forward|attach|email|print|"
    r"back\s*up|restore|sync|merge|split|sort|rank|filter|highlight|tag|label|"
    r"index|count|total|sum|calculate|measure|list|show|display|tell|give|get|"
    r"bring|fetch|retrieve|find|locate|search|look|go|dig|pick|spot|write|draft|"
    r"compose|create|make|generate|produce|prepare|build|put|turn|open|close|"
    r"delete|remove|clean|clear|empty|organi[sz]e|rename|zip|unzip|run|execute|"
    r"test|debug|compile|deploy|quote|cite|note|mark|flag|see|tally")
_OP_SOURCE = re.compile(
    _LEAD + r"(?P<v>" + _MATERIAL_VERB + r")\b(?:\s+[a-z0-9'\-]+){0,8}?\s+"
    r"(?:of|from|out\s+of|inside|within|through|across|using|based\s+on|"
    r"according\s+to|off)\s+(?:all\s+|each\s+|every\s+|both\s+)?(?:of\s+)?(?:my|our)\b")
# "...in my X" and "...on my X", but only for verbs that LOOK for something inside it:
# "find the typo in my X", "count the words in my X". "write a story in my style" is
# not a search of anything.
_INSPECT_VERB = (r"find|locate|check|search|look|scan|count|list|show|tell|give|get|"
                 r"highlight|fix|correct|spot|see|read|edit|change|replace|delete|"
                 r"remove|add|insert|update|rename|sort|filter|total|sum|tag|label|"
                 r"proofread|review|audit|examine|inspect|analy[sz]e|calculate|"
                 r"measure|cite|quote|note|mark|flag")
_OP_SOURCE_IN = re.compile(
    _LEAD + r"(?P<v>" + _INSPECT_VERB + r")\b(?:\s+[a-z0-9'\-]+){0,8}?\s+"
    r"(?:in|on)\s+(?:all\s+|each\s+|every\s+|both\s+)?(?:of\s+)?(?:my|our)\b")
# ...and any material verb when the thing is described as "OF <something> in my X" --
# "make a list of the deadlines in my X", "a count of the pages in my X". The "of ... in"
# shape is what says the something is inside X.
_OP_SOURCE_OF_IN = re.compile(
    _LEAD + r"(?P<v>" + _MATERIAL_VERB + r")\b(?:\s+[a-z0-9'\-]+){0,6}?\s+of\s+"
    r"(?:[a-z0-9'\-]+\s+){0,4}?(?:in|on|inside)\s+(?:all\s+|each\s+|every\s+)?(?:of\s+)?"
    r"(?:my|our)\b")

# Asking for a JUDGEMENT of something of theirs, which cannot be given without reading
# it: "feedback on my X", "your thoughts on my X", "help with my X".
_EVAL_MY = re.compile(
    r"\b(?:feedback|critique|review|comments?|thoughts|opinions?|corrections|edits|"
    r"assessment|evaluation|help)\s+(?:on|with|of|about|regarding)\s+"
    r"(?:all\s+)?(?:of\s+)?(?:my|our)\b" + _NOT_A_PERSON)

# A question ABOUT something of theirs: "what does my X say", "when is my X",
# "is my X ok", "how does my X look". Advice and how-to openers are excluded
# separately (_HOWTO); a bare modal ("can you help me with my X") is not a
# question about X and is not matched.
_WH = (r"what|which|where|when|who|whose|why|"
       r"how(?:\s+(?:much|many|big|large|old|long|far|often|fast|full|hot|heavy|"
       r"small|recent|bad|good|safe|secure|healthy|well|is|are|was|were|does|did|"
       r"do|has|have|had))?|"
       r"is|are|was|were|does|did|do|has|have|had")
_WH_MY = re.compile(r"^" + _FILL + r"(?:" + _WH + r")\b(?P<mid>.*?)\bmy\b(?P<tail>.*)$")
_WH_ANY = re.compile(r"^" + _FILL + r"(?:" + _WH + r")\b")

# "the file I downloaded", "the email I sent Sam", "that thing I was working on":
# a first-person relative clause is a possessive in disguise -- the referent is
# whatever THEY did it to, and only this machine or ARGUS's memory knows which.
# Found in the field by a peer session: "what's the latest file I downloaded"
# names nothing of theirs by "my" and was going to the web.
_REL_I = re.compile(
    r"\b(?:the|that|those|these|this)\s+(?:[a-z0-9'\-]+\s+){0,3}?(?:(?:that|which)\s+)?"
    r"i\s+(?:just\s+|last\s+|recently\s+|previously\s+|already\s+|also\s+|then\s+)?"
    r"(?:downloaded|saved|wrote|written|made|created|sent|received|opened|installed|"
    r"copied|took|taken|bought|ordered|uploaded|edited|worked\s+on|was\s+working\s+on|"
    r"were\s+working\s+on|have\s+been\s+working\s+on|got|left|put|stored|kept|scanned|"
    r"printed|recorded|used|watched|read|played|ran|typed|pasted|deleted|moved|"
    r"renamed|shared|forwarded|attached|signed|filed|submitted|added|changed|"
    r"updated|exported|imported|synced|backed\s+up|bookmarked|pinned)\b")

# Advice and how-to: the possessive is incidental, the answer is general
# instructions. "how do i clear my cache" wants steps, not the cache. The
# subject after the auxiliary matters: "how DO I ..." is a method, "how DOES my
# cv look" is a judgement of a thing.
_HOWTO = re.compile(
    r"^" + _FILL +
    r"(?:how\s+(?:do|can|could|should|would|might|shall)\s+(?:i|we|you|one|someone|people)\b"
    r"|how\s+to\b"
    r"|what\s+(?:should|shall|can|could|would|might)\s+(?:i|we|one)\b"
    r"|what(?:'?s|\s+is)\s+the\s+(?:best|easiest|fastest|quickest|right|proper|"
    r"correct|safest|simplest|cheapest|better)\s+(?:way|method|approach|tool|"
    r"app|program|software|option|thing)\b"
    r"|is\s+there\s+(?:a|any)\s+(?:way|method|trick|tool)\s+to\b"
    r"|(?:can|could|would|will)\s+you\s+(?:please\s+)?(?:teach|show|tell|explain|"
    r"walk)\s+(?:me|us)\s+(?:how|what|why)\b"
    r"|(?:show|teach|tell|explain)\s+(?:me|us)\s+how\b"
    r"|(?:any|some|got\s+any)\s+(?:tips|advice|ideas|suggestions|recommendations|"
    r"pointers)\b"
    r"|(?:tips|steps|guide|tutorial|instructions|advice)\s+(?:for|on|to)\b"
    # Advice about a practice, not a reading of their own thing: "is it bad to
    # keep my laptop plugged in", "should i buy a new phone".
    r"|is\s+it\s+(?:bad|ok|okay|fine|safe|normal|worth|good|wrong|healthy|"
    r"necessary|possible|dangerous|harmful|a\s+good\s+idea)\s+(?:to|for|if)\b"
    r"|would\s+it\s+be\s+(?:bad|ok|okay|better|worth|a\s+good\s+idea)\b"
    r"|should\s+(?:i|we)\b)")

# Questions about the machine's CURRENT state that name no possessive: "how much
# is left", "what's using the cpu", "is the wifi down". The shape is a reading;
# "what is a cpu" has none of these and stays general.
_STATE_Q = re.compile("|".join([
    r"\bhow\s+(?:much|many)\b.{0,32}\b(?:free|left|remaining|available|used|"
    r"installed|running|open|connected|stored|full|taking|using|eating)\b",
    r"\bhow\s+(?:full|hot|warm|fast|slow|loud|bright|charged|old)\s+(?:is|are)\s+"
    r"(?:the\s+|this\s+)?(?:computer|pc|laptop|machine|cpu|gpu|battery|disk|drive|"
    r"ssd|fan|screen|network|connection|wifi|internet)\b",
    r"\bwhat(?:'?s|\s+is|\s+are)\s+(?:currently\s+|now\s+|still\s+)?(?:using|eating|"
    r"hogging|taking\s+up|slowing|draining|running|open|installed|listening|"
    r"connected|blocking|on\s+(?:the\s+)?(?:screen|desktop|clipboard))\b",
    # "what APPS are running", "which WINDOWS are open": a machine noun between
    # the question word and the verb. The noun list is what keeps "which
    # countries are open to tourists" out of it.
    r"\b(?:what|which)\s+(?:[a-z]+\s+)?(?:apps?|applications?|programs?|processes|"
    r"services|windows|tabs|tasks|files|folders|drivers|updates|extensions|"
    r"plugins|devices|ports|connections|users|software)\s+(?:is|are)\s+"
    r"(?:currently\s+|now\s+|still\s+)?(?:running|open|installed|listening|"
    r"connected|active|using|eating|hogging|slowing|draining|taking\s+up|"
    r"on\s+(?:the\s+)?(?:screen|desktop))\b",
    r"\b(?:is|are)\s+(?:the\s+)?(?:internet|wi-?fi|network|vpn|bluetooth|firewall|"
    r"antivirus|defender|printer|camera|webcam|mic|microphone|battery|disk|drive|"
    r"fan|screen)\s+(?:on|off|up|down|working|connected|running|charging|full|fine|"
    r"ok|okay|slow|enabled|disabled|active|blocked|dead|broken|overheating|hot)\b",
    r"\bam\s+i\s+(?:online|connected|offline|protected|secure|infected|hacked|"
    r"logged\s+in|signed\s+in|authenticated|locked\s+out|"
    r"being\s+(?:watched|tracked|spied\s+on|recorded)|safe|exposed|vulnerable)\b",
    r"\bwho(?:'?s|\s+is)\s+(?:connected|logged\s+in|using\s+(?:the|this))\b",
    r"\bwhat\s+(?:am\s+i|are\s+we)\s+(?:looking|staring)\s+at\b",
    # "why is the COMPUTER slow" -- but not "why is machine learning important",
    # "why is computer science hard": the compound terms are excluded.
    r"\bwhy\s+(?:is|are|does|did|has|have)\s+(?:the\s+|this\s+)?(?:computer|pc|"
    r"laptop|machine|internet|wi-?fi|network|system|fan|screen|battery|disk|"
    r"drive|cpu|gpu|ram|browser|startup|boot)\b"
    r"(?!\s+(?:learning|science|vision|graphics|architecture|literacy|ethics|"
    r"history|scientist|engineer|engineering|programming|programmer|game|games|"
    r"model|models|security|theory|design|administration|administrator))",
]))

# "do i have any X", "how many X do i have", "what do i have on Y": asking what
# they hold. There is nothing to answer from except this machine and ARGUS's own
# memory, whatever X is. The exclusions are the idioms ("do i have a choice").
_HAVE_Q = re.compile("|".join([
    r"\bdo\s+i\s+(?:have|got|own)\s+(?:any|a|an|the|some)\b"
    r"(?!\s+(?:chance|choice|idea|clue|point|right|option|problem|reason|say|"
    r"future|hope|shot|prayer|life|friends?|feelings?|talent|gift|fever|cold|"
    r"headache|virus|disease|condition|allerg\w+))",
    r"\bhow\s+(?:much|many)\b.{0,32}\bdo\s+i\s+(?:have|got|own|use)\b",
    r"\b(?:what|which)\b.{0,32}\bdo\s+i\s+(?:have|use|own|run)\b",
]))

# Who they are, what they did, what ARGUS has learned. Stored in ARGUS's own
# memory; never a hosted model's business.
_IDENTITY = re.compile("|".join([
    r"\bwho\s*am\s*i\b",
    # Any inflection: "learn", "learned", "learnt", "stored", "kept" ...
    r"\bwhat\s+(?:do|did|have|would)\s+you\s+(?:know|learn|remember|stor|sav|logg?|"
    r"record|track|keep|kept|note)\w*\b.{0,32}\b(?:about\s+)?(?:me|us|my)\b",
    r"\b(?:where|what\s+(?:city|country|town))\s+do\s+i\s+(?:live|work|stay|study)\b",
    r"\bwhat(?:'?s|\s+is|\s+are)\s+my\s+(?:name|age|job|occupation|profession|"
    r"role|title|company|employer|school|major|city|country|address|email|phone|"
    r"number|birthday|birth\s*date|favou?rite\s+\w+|hobbies|interests|"
    r"preferences?|schedule|plans?|goals?|budget|salary|balance|password|pin|"
    r"username|status)\b",
    r"\bwhat\s+did\s+i\s+(?:say|ask|tell|write|save|search|open|download|install|"
    r"do|work\s+on|watch|listen|buy|order|type|copy|paste|note|record|schedule|"
    r"plan|set)\b",
    r"\bwhat\s+(?:was|were)\s+i\s+(?:doing|working|looking|reading|watching|"
    r"listening|saying|asking)\b",
    r"\bwhat\s+have\s+i\s+(?:been\s+)?(?:doing|working|done|said|asked|searched|"
    r"opened|downloaded|installed|watched|written|saved)\b",
    r"\bwhere\s+did\s+i\s+(?:save|put|leave|download|store|keep|write|copy)\b",
    r"\bwhen\s+did\s+i\s+(?:last|first)\b",
    r"\bhow\s+(?:long|often|many\s+times)\s+(?:have|did|do)\s+i\b",
    r"\bmy\s+(?:name|email|e-?mail|phone|number|address|birthday|birth\s*date|age|"
    r"password|pin|username)\s+(?:is|are|was|=)\b",
    r"\bi\s+(?:live|work|study|was\s+born|grew\s+up)\s+(?:in|at|for|near|on)\b",
    r"\bi\s*(?:am|'?m)\s+\d{1,2}\s*(?:years?\s*old|yo)\b",
    r"\bmy\s+(?:wife|husband|girlfriend|boyfriend|partner|son|daughter|mother|"
    r"father|mom|dad|brother|sister)(?:'?s)?\s+name\s+is\b",
    r"\bwhat\s+(?:happened|changed|went\s+on)\b.{0,24}\b(?:while|since)\b.{0,20}\b(?:i|we)\b",
    r"\bremember\s+(?:that|this|to)\b|\bdon'?t\s+forget\b|\bnote\s+(?:that|down)\b",
]))

# ARGUS itself: its memory, its log, what it is doing, whether it is locked.
_INTERNAL = re.compile("|".join([
    r"\byour\s+(?:memory|memories|logs?|tasks?|plan|plans|permissions?|settings|"
    r"status|state|audit|history|capabilit\w+|skills|watchers?|goals?|queue|"
    r"cache|database|config\w*|records?|version|uptime|activity|actions|"
    r"decisions|knowledge\s+of\s+me)\b",
    r"\bwhat\s+(?:are|were)\s+you\s+(?:doing|running|watching|tracking|logging|"
    r"listening\s+to|working\s+on)\b",
    r"\bwhat\s+(?:have|did)\s+you\s+(?:do|done|learn|learned|remember|store|stored|"
    r"save|saved|log|logged|record|recorded|change|changed|delete|deleted|open|"
    r"opened|run|ran|send|sent)\b",
    r"\bare\s+you\s+(?:listening|recording|watching|tracking|logging|locked|"
    r"unlocked|logged\s+in|authenticated)\b",
    r"\bis\s+argus\s+(?:locked|unlocked|running|listening|online|working|secure|safe)\b",
    r"\bargus'?s?\s+(?:memory|logs?|status|settings|state|history|permissions?|"
    r"tasks?|plan|goals?)\b",
    r"\byou\s+(?:store|keep|save|log|record|track|remember)\b.{0,24}\bmy\b",
]))


# ── the text itself carries local data ─────────────────────────────────────
_PATH = re.compile(
    r"\b[a-z]:[\\/](?![\\/])|\\\\[\w.$-]+\\|%[a-z_]+%|(?:^|\s)~[\\/]"
    r"|(?:^|\s)/(?:home|users|etc|var|usr|opt|tmp|mnt|root)/|\.\.[\\/]"
    # Every repeat below is bounded: an unbounded chain of dot-separated words
    # backtracks quadratically, and a crafted 4000-character string made this
    # gate the slowest thing in the request.
    r"|\b[\w\-]{1,60}[\\/][\w\-./\\]{1,160}\.\w{1,5}\b")

# A document, image, archive, config or log by extension: unambiguous.
_FILE_EXT = re.compile(
    r"\b[\w\-]{1,60}(?:\.[\w\-]{1,40}){0,4}\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|rtf|odt|json|xml|"
    r"ya?ml|toml|ini|cfg|conf|log|zip|rar|7z|iso|exe|msi|dll|png|jpe?g|gif|bmp|"
    r"webp|heic|mp3|mp4|wav|mov|avi|mkv|flac|db|sqlite|bak|tmp|lnk)\b")

# Source-file extensions are also framework and library names -- "what is
# node.js" is a knowledge question -- so they only count when something says a
# FILE is meant.
_CODE_EXT = re.compile(
    r"\b(?:file|script|module|open|edit|run|fix|debug|check|review|see|read)\s+"
    r"(?:the\s+|my\s+|this\s+)?[\w\-]{1,60}\.(?:py|js|ts|tsx|jsx|java|cpp|cs|go|rs|rb|"
    r"php|sh|bat|ps1|sql|md|html|css|c|h)\b")

# An address inside the person's own network, a hardware address, a hostname.
_NET_ID = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|"
    r"169\.254(?:\.\d{1,3}){2})\b"
    r"|\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"
    r"|\b(?:desktop|laptop)-[a-z0-9]{5,}\b|\blocalhost\b")


# ── the internet ───────────────────────────────────────────────────────────
# ASKING for it. Two strengths, because "search" means two things:
#
#   NAMES THE WEB   "search online", "google it", "on the internet". Unambiguous.
#   BARE VERB       "search for X", "look up X", "research X". The same words
#                   are a search of THIS machine when X is theirs -- "search for
#                   my thesis" -- so a bare verb counts as a web request only
#                   when nothing local is in the sentence.
#
# "google" as a company ("who founded google") is not a request and is not matched.
_WEB_NAMED = re.compile("|".join([
    r"\b(?:search|look|check|find|browse|research|read|pull\s+up)\b.{0,40}?"
    r"\b(?:online|on\s+the\s+(?:web|internet|net)|on\s+google|via\s+google)\b",
    r"\b(?:web|internet|online)\s+search\b|\bsearch\s+(?:the\s+)?(?:web|internet|net)\b",
    r"\bgoogle\s+(?:it|this|that|for|search)\b",
    r"\bwhat\s+(?:does|do)\s+the\s+(?:web|internet)\s+say\b",
]))
_WEB_BARE = re.compile("|".join([
    r"^" + _FILL + r"(?:can\s+you\s+)?(?:search|google|bing|duckduckgo)\b",
    r"\blook\s+(?:it|this|that)\s+up\b|^" + _FILL + r"(?:look\s*up|lookup)\b",
    r"^" + _FILL + r"(?:research|look\s+into|dig\s+into|find\s+out\s+about|"
    r"do\s+some\s+research\s+on|deep\s+dive\s+on)\b",
]))

# A general clause riding along with a local one: "... and explain how a
# framework works". Only used to label a request MIXED; the treatment is the same.
_GENERAL_CLAUSE = re.compile(
    r"(?:\band\b|\bthen\b|,|;|\balso\b|\bplus\b)\s*(?:then\s+)?(?:also\s+)?"
    r"(?:explain|describe|tell\s+me|teach|compare|contrast|define|"
    r"what\s+(?:is|are|does)|how\s+(?:does|do|is|are)|why)\b")


# A "my" that points at nothing of theirs: "oh my god", "in my opinion", "what
# would you do in my place", "my pleasure". Stripped before the possessive rules
# run, so an idiom cannot look like a reference to a file. Kept to fixed
# expressions on purpose -- anything open-ended ("my X") is a reference.
_IDIOM = re.compile(
    r"\boh\s+my(?:\s+(?:god|gosh|goodness))?\b"
    r"|\bmy\s+(?:god|gosh|goodness|bad|pleasure|dear|friends?|love|guess|opinion|"
    r"impression|understanding|apologies|apology|thanks|condolences|mistake|fault|"
    r"turn|question|answer|point)\b"
    r"|\b(?:in|to|from|for|on|by)\s+my\s+(?:place|position|shoes|situation|case|"
    r"opinion|view|book|humble|knowledge|perspective|understanding|point\s+of\s+view|"
    r"part|sake|way|own|side|mind)\b"
    r"|\bof\s+my\s+own\b"
    # Set phrases where an imperative verb takes a "my" that is nothing of theirs.
    r"|\b(?:excuse|pardon|forgive|mind|mark|bless|hold|spare)\s+my\s+(?:ignorance|"
    r"language|french|words?|soul|beer|drink|interruption|rudeness|manners|english|"
    r"spelling|typos?|mistakes?)\b")


# ── classification ─────────────────────────────────────────────────────────
_APOSTROPHES = str.maketrans({"’": "'", "‘": "'", "“": '"', "”": '"'})


def _norm(text) -> str:
    t = str(text or "").translate(_APOSTROPHES).lower()
    return re.sub(r"\s+", " ", t).strip()


def _snip(m: "re.Match", limit: int = 40) -> str:
    s = m.group(0).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


# What a web-search command says before the QUERY it is carrying: "search the web
# for", "google", "look up". The how-to test is applied to what follows it, so
# "search the web for how to fix my wifi" is asking for instructions -- a general
# query with an incidental possessive -- exactly as "how do i fix my wifi" is.
_WEB_PREFIX = re.compile(
    r"^" + _FILL + r"(?:(?:can|could|would|will)\s+you\s+)?"
    r"(?:search|look\s*up|google|bing|duckduckgo|research|look)\s*"
    r"(?:(?:on\s+the\s+|the\s+|on\s+)?(?:" + _WEB_WORDS + r")\s*)?"
    r"(?:for\s+|about\s+|up\s+)?")


def _query_of(t: str) -> str:
    m = _WEB_PREFIX.match(t)
    return t[m.end():] if m else t


def _data_signals(raw: str, t: str, hits: list) -> None:
    """The text ITSELF carries something that lives on this machine or is secret.
    These hold whatever the phrasing is, including a how-to."""
    m = _PATH.search(t)
    if m:
        hits.append((DATA, "path: " + _snip(m)))
    m = _FILE_EXT.search(t) or _CODE_EXT.search(t)
    if m:
        hits.append((DATA, "file name: " + _snip(m)))
    m = _NET_ID.search(t)
    if m:
        hits.append((DATA, "network identifier: " + _snip(m)))
    # security.redact() is the authority on what a credential looks like -- an
    # API key shape, "password: x", an email address, a card number. Reused
    # rather than restated so the two never disagree about what is secret.
    if security.redact(raw) != raw:
        hits.append((DATA, "secret-shaped text"))


def _reference_signals(t: str, hits: list) -> None:
    """Something of THEIRS is being acted on, asked about, or named. Skipped for
    a how-to, where the possessive is incidental."""
    m = _OP_MACHINE.match(t)
    if m:
        hits.append((OPERATION, "machine command: " + m.group("v")))

    m = (_OP_OBJECT.match(t) or _OP_WEB_OBJECT.match(t) or _OP_DIRECT.match(t)
         or _OP_SOURCE.match(t) or _OP_SOURCE_IN.match(t) or _OP_SOURCE_OF_IN.match(t))
    if m:
        hits.append((OPERATION, "acts on their own thing: " + _snip(m)))
    m = _EVAL_MY.search(t)
    if m:
        hits.append((RETRIEVAL, "asks for a judgement of their own thing: " + _snip(m)))

    m = _WH_MY.match(t)
    if m:
        # "what's my cpu" is a machine reading; "what's in my X" is a retrieval
        # from something of theirs. The router treats them differently.
        tail = "my " + m.group("tail")[:48]
        machine = bool(_POSS["machine"].search(tail))
        hits.append((STATE if machine else RETRIEVAL,
                     "asks about their own thing: " + (m.group("mid").strip()[:24] or "?") + " my …"))

    for kind, pat in _POSS.items():
        m = pat.search(t)
        if m:
            hits.append((STATE if kind == "machine" else REFERENCE,
                         f"possessive {kind}: " + _snip(m)))

    m = _REL_I.search(t)
    if m:
        hits.append((RETRIEVAL, "something they did: " + _snip(m)))
    m = _DEICTIC_RE.search(t)
    if m:
        hits.append((REFERENCE, "points at something local: " + _snip(m)))
    m = _LOCATIVE.search(t) or _ON_THE_MACHINE.search(t)
    if m:
        hits.append((REFERENCE, "stated location: " + _snip(m)))
    m = _THE_PLACE.search(t)
    if m and not _DEFINITIONAL.match(t):
        hits.append((RETRIEVAL if _WH_ANY.match(t) else REFERENCE,
                     "names a place on this machine: " + _snip(m)))
    m = _NAMED_FILE.search(t)
    if m:
        hits.append((REFERENCE, "names a file: " + _snip(m)))
    m = _STATE_Q.search(t)
    if m:
        hits.append((STATE, "asks for a live reading: " + _snip(m)))
    m = _HAVE_Q.search(t)
    if m:
        hits.append((RETRIEVAL, "asks what they hold: " + _snip(m)))


def _classify(raw: str) -> Decision:
    t = _norm(raw)
    if not t:
        return Decision(GENERAL, False, WEB_NONE, ("empty",), False, False, "")

    hits: list = []
    _data_signals(raw, t, hits)

    m = _IDENTITY.search(t)
    if m:
        hits.append((IDENTITY, "personal: " + _snip(m)))
    m = _INTERNAL.search(t)
    if m:
        hits.append((INTERNAL, "ARGUS's own state: " + _snip(m)))

    if not (_HOWTO.search(t) or _HOWTO.search(_query_of(t))):
        _reference_signals(_IDIOM.sub(" ", t), hits)

    local = bool(hits)
    named = bool(_WEB_NAMED.search(t))
    # A bare "search for X" is a web request only when X is not theirs.
    web = WEB_EXPLICIT if (named or (not local and _WEB_BARE.search(t))) else WEB_NONE
    if not local:
        return Decision(EXPLICIT_WEB if web else GENERAL, False, web,
                        ("explicit web request",) if web else ("no local context",),
                        False, False, "")

    frame = max(hits, key=lambda h: _PRIORITY[h[0]])[0]
    reasons = []
    for _, why in hits:
        if why not in reasons:
            reasons.append(why)
    mixed = bool(web or _GENERAL_CLAUSE.search(t))
    return Decision(MIXED if mixed else LOCAL_REQUIRED, True, web,
                    tuple(reasons[:6]), True, mixed, frame)


_classify_cached = functools.lru_cache(maxsize=512)(_classify)


def classify(text, *, followup_of_local: bool = False) -> Decision:
    """The policy decision for one request. Pure: nothing here reads a clock,
    touches disk or opens a socket, and the same text always gives the same
    answer.

    followup_of_local is supplied by the caller (cloud_gate) when the request
    arrives right after a local exchange AND could be referring back to it. It
    is a parameter rather than state read here so this stays a function of its
    arguments.

    ANY failure to classify is LOCAL_REQUIRED. A gate that opens when it breaks
    is worse than no gate.
    """
    try:
        base = _classify_cached(str(text or "")[:_MAX_CHARS])
    except Exception as e:  # noqa: BLE001 -- fail closed, see above
        return Decision(LOCAL_REQUIRED, True, WEB_NONE,
                        (f"classifier error: {type(e).__name__}",), True, False, DATA)
    if followup_of_local and not base.local_required:
        return Decision(LOCAL_REQUIRED, True, base.web,
                        ("follows a local exchange",), False, False, FOLLOWUP)
    return base


# ── skills, as the dispatcher sees them ────────────────────────────────────
# A skill whose OUTPUT is public information: what it returns says nothing about
# this machine or this person. Everything not named here is treated as local --
# including any skill added tomorrow -- so forgetting to classify a new skill
# fails toward "keep it private", not toward "send it out".
PUBLIC_SKILLS = frozenset({
    "weather", "research", "knowledge", "web", "youtube", "calc", "social",
    "chat", "intel",
})
_NON_PUBLIC_PAIRS = frozenset({("knowledge", "summarize_clipboard")})
_PUBLIC_PAIRS = frozenset({("pc", "time"), ("history", "clear")})


def is_public_skill(skill: str, action: str = "") -> bool:
    if (skill, action) in _NON_PUBLIC_PAIRS:
        return False
    return skill in PUBLIC_SKILLS or (skill, action) in _PUBLIC_PAIRS


def names_a_fact_or_reading(phrase: str) -> bool:
    """Is "my <phrase>" a FACT about the person or a READING of the machine, rather
    than something that could be a file? "my name", "my birthday", "my ip", "my cpu".

    Used by the router when a web command has to be turned into a local search: a
    search of the filesystem for a file called "name" would answer a different
    question than "google my name" asked."""
    t = "my " + _norm(phrase)
    return bool(_IDENTITY.search("what is " + t) or _POSS["machine"].search(t))


def is_web_lookup(skill: str, action: str = "") -> bool:
    """Does this (skill, action) send a request's words to a search engine or a
    reference site as the way of answering it? Those are what a LOCAL_REQUIRED
    request must never reach. Opening a URL in the person's own browser, the
    weather for a configured city, and playing a video are not lookups of the
    request and are not listed."""
    if skill == "research":
        return True
    if skill == "knowledge":
        return action in ("lookup", "define")
    if skill == "web":
        return action != "open_url"
    if skill == "browser":
        return action == "search"
    if skill == "intel":
        return action == "brief"
    return False


# ── enforcement at the edges ───────────────────────────────────────────────
class LocalOnly(Exception):
    """Raised at an egress point while a local-only request is in flight."""


_SCOPE: "contextvars.ContextVar[Decision | None]" = contextvars.ContextVar(
    "argus_route_scope", default=None)

# What is said when a request that refers to something of theirs asked for the web.
# Both say that nothing was searched or sent, and both say what to do INSTEAD: name
# what to look up in their own words, or ask for a look at this machine.
DENIED_WEB = ("That refers to something of yours, your machine or your own data, so "
              "I've kept it off the web and haven't searched anything. Name what "
              "you want looked up and I'll search for that, or say find my, and "
              "the thing, and I'll look on this machine.")
DENIED_MIXED_WEB = ("That mixes a web search with something of yours, and I keep "
                    "that off the web, so I haven't searched. Tell me exactly what "
                    "to look up, worded the way you're happy to send it, and I'll "
                    "search for that. Or say find my, and the thing, and I'll look "
                    "on this machine.")


@contextlib.contextmanager
def request_scope(decision: Decision):
    """Marks the request being handled, for everything that runs inside it.

    A ContextVar, not a module global: a background thread that happens to be
    fetching the weather is a different context and is not affected by someone
    else's local request, and two requests cannot overwrite each other.
    """
    token = _SCOPE.set(decision)
    try:
        yield decision
    finally:
        try:
            _SCOPE.reset(token)
        except ValueError:      # token minted in another Context (a thread hop)
            _SCOPE.set(None)


def scoped_iter(decision: Decision, iterator):
    """Re-enter the request scope around EVERY step of a generator.

    A streamed reply is pulled one chunk at a time, and the web framework may
    pull each chunk on a different worker thread, each with its own copy of the
    context -- so a scope set once at the top of the generator would be gone by
    the second sentence. Entering it per step is what makes the guarantee hold
    for the streaming path, which is the one voice actually uses.
    """
    it = iter(iterator)
    try:
        while True:
            with request_scope(decision):
                try:
                    item = next(it)
                except StopIteration:
                    return
            yield item
    finally:
        close = getattr(it, "close", None)
        if close:
            close()


def current():
    """The Decision of the request in flight, or None outside one (a scheduled
    task, a background check, a diagnostic)."""
    return _SCOPE.get()


def guard_egress(kind: str) -> None:
    """Called at the top of every function that sends a request's words to a
    hosted model or a web source. While a local-only request is in flight it
    refuses -- the backstop behind the router and brain checks, so a code path
    nobody thought of still cannot carry a local request off the machine."""
    d = _SCOPE.get()
    if d is None or not d.local_required:
        return
    try:
        security.security_event(security.TOOL_DENIED, component="routing_policy",
                                reason="local_required_egress", status="failed")
    except Exception:  # noqa: BLE001 -- refusing must not depend on logging
        pass
    raise LocalOnly(f"{kind} refused: this request is local-only")


# ═══════════════════════════════════════════════════════════════════════════
# PART 2 -- THE CLOUD GATE
# ═══════════════════════════════════════════════════════════════════════════

# How long a local-required exchange keeps FOLLOWING turns local too, even
# if their own text contains no sensitive pattern -- same reasoning and
# similar shape to followup_skill's FOLLOWUP_WINDOW, but tracked separately:
# this is a privacy boundary, not a convenience feature, and conflating the
# two would make an unrelated change to elliptical-reference handling
# silently change what's allowed to reach the cloud.
STICKY_WINDOW = 120  # seconds

_last_local_at = 0.0

# Whether the exchange in flight touched anything local -- by what was ASKED
# (the policy said so) or by what RAN (a machine skill was dispatched). main.py
# reads it when it files the exchange into conversation history, so that a reply
# built from local data is never forwarded to a hosted model as "context".
# Reset with the engine at the top of every request; see reset_engine().
_exchange_local = False


def mark_local_exchange():
    """Called after dispatching a local-required skill (see router.py) --
    starts the sticky window so an immediate follow-up defaults to local
    too, without needing its own text to independently look sensitive."""
    global _last_local_at, _exchange_local
    _last_local_at = time.time()
    _exchange_local = True


def note_exchange_local():
    """This exchange is local, but it must NOT extend the sticky window: a turn
    that is local only because it followed a local one would otherwise keep the
    window open for as long as the conversation continued."""
    global _exchange_local
    _exchange_local = True


def exchange_was_local() -> bool:
    return _exchange_local


def recently_local() -> bool:
    return (time.time() - _last_local_at) <= STICKY_WINDOW


def is_local_required_skill(skill: str, action: str) -> bool:
    """True when running this skill/action touches the machine or the person's
    data, so what it returns must never reach a hosted model.

    THE DEFAULT IS LOCAL. This used to be an allowlist of nine skills plus a few
    pc/control/net actions, and everything else -- storage, apps, services,
    documents, email, timers, the browser -- was treated as public by omission.
    So "read my cv" (document/read) started no sticky window and its reply went
    into history as ordinary context. Now only skills whose output is public
    information are exempt (PUBLIC_SKILLS), which means a skill
    added tomorrow is private until someone says otherwise.
    """
    return not is_public_skill(skill, action)


def decide(user_text: str) -> "Decision":
    """THE routing-policy decision for one request, sticky window included.

    The window is applied here rather than inside routing_policy so that module
    stays a pure function of its arguments: whether a turn is a possible
    follow-up to a local exchange is state, and state lives in this file.
    """
    follow = recently_local() and is_possible_followup(user_text)
    return classify(user_text, followup_of_local=follow)


def is_sensitive(text) -> bool:
    """True if TEXT itself contains or references something that must
    never leave this machine. Pure, local, no network -- see this module's
    docstring for why that matters more here than anywhere else in ARGUS.

    Answered by the routing policy, so "sensitive" means one thing everywhere:
    the answer cache, the history tagging, the intel search guard and the chat
    router all ask the same question and get the same answer.

    Accepts a list of strings as well as a string. intel_skill passes its search
    queries as a list, which raised AttributeError on .strip(), was swallowed by
    its own try/except, and turned its "nothing about this machine goes to a
    search engine" check into a no-op that nobody could see.
    """
    if isinstance(text, (list, tuple)):
        text = " ".join(str(part) for part in text)
    if not text or not str(text).strip():
        return False
    return classify(text).local_required


# A turn that names its own subject cannot be leaning on the previous one.
# Three things mark a subject in practice, and none of them need a parser:
#   a long word          photosynthesis, encryption, difference, Lovelace
#   an acronym           TCP, UDP, DNS, VPN
#   a mid-sentence capital   Ada, Uzbekistan, Python
_TOPIC_MIN_LEN = 7
_WORDS = re.compile(r"[A-Za-z]+")

# Pronouns that can point back at the previous turn. Their presence forces
# local regardless of anything else -- see is_possible_followup for why the
# asymmetry is deliberate. "you" is absent on purpose: it addresses ARGUS,
# not the previous subject.
_REFERENTIAL = re.compile(
    r"\b(it|its|it's|that|this|those|these|they|them|their|"
    r"one|ones|same|above|previous|earlier|again|"
    r"he|she|him|her|his|hers)\b", re.I,
)


def _names_a_topic(text: str) -> bool:
    words = _WORDS.findall(text or "")
    if not words:
        return False
    for w in words:
        if len(w) >= _TOPIC_MIN_LEN:
            return True
        if w.isupper() and len(w) >= 2:          # TCP, UDP, DNS
            return True
    # A capital anywhere but the first word is a proper noun, not a sentence
    # start. "who was Ada Lovelace" names its subject; "is it strong" does not.
    for w in words[1:]:
        if w[:1].isupper():
            return True
    return False


def is_possible_followup(user_text: str) -> bool:
    """Could this turn plausibly be referring to the previous one?

    The sticky window used to force EVERY turn local for two minutes after a
    sensitive exchange. That is a real cost, not a theoretical one: Groq
    answers in ~174ms and the local model in ~2533ms, so one question like
    "what do you know about me" made ARGUS roughly 14x slower for the next two
    minutes -- including for "what is photosynthesis", which shares nothing
    with the previous turn and so can leak nothing from it.

    The module docstring states the real rationale: a follow-up stays local
    because it "can plausibly be" a reference. So that is what is tested,
    rather than elapsed time alone.

    BOTH signals are required, and the ordering is deliberately asymmetric
    because the two mistakes are not equally bad. Sending an elliptical
    follow-up to the cloud leaks the previous turn; keeping a self-contained
    question local just makes it slower.

    So a referential pronoun ALONE forces local, even when the turn also names
    something. Topic detection on its own was tried and was wrong in exactly
    the way that matters: "how can I make it stronger" -- said straight after
    a question about a wifi password -- contains the eight-letter word
    "stronger", was scored as naming its own topic, and would have gone to the
    cloud carrying the pronoun that points at the password.

    The cost is that "who was Ada Lovelace and what did she do" also stays
    local, because "she" is indistinguishable from a back-reference without
    parsing. That is a few hundred milliseconds on an uncommon phrasing, paid
    to keep the leak impossible.
    """
    text = (user_text or "").strip()
    if not text:
        return True
    if _REFERENTIAL.search(text):
        return True
    return not _names_a_topic(text)


def route_chat(user_text: str) -> str:
    """The one function brain.py needs for the cloud tier: returns "local" or
    "cloud". Either signal alone forces local -- the request's own content, or
    the sticky window on a turn that could be referring back -- matching the
    "zero exceptions" requirement rather than averaging or requiring both to
    agree. Both are folded into decide().
    """
    return "local" if decide(user_text).local_required else "cloud"


# ── Engine tracking for history tagging and the HUD indicator ──────────
# "local" is the DEFAULT for every exchange, reset at the start of every
# single command (see router.handle()/handle_stream()) -- only flipped to
# "cloud" by brain.py, and only after a real Groq call has already
# SUCCEEDED, never optimistically before the call. A skill dispatch (open
# an app, read the vault, anything that never touches brain.py at all)
# therefore always ends up correctly tagged "local" without needing its own
# explicit call here -- the default already says the true thing.
_last_engine = "local"


def reset_engine():
    global _last_engine, _exchange_local
    _last_engine = "local"
    _exchange_local = False


def set_engine_cloud():
    global _last_engine
    _last_engine = "cloud"


def get_engine() -> str:
    return _last_engine


def filter_history_for_cloud(history: list) -> list:
    """Everything the cloud may see for context: all prior turns EXCEPT the
    sensitive ones.

    WHY THIS CHANGED. The old rule forwarded only exchanges tagged tier=="cloud"
    and withheld everything else. That was over-broad to the point of breaking
    multi-turn conversation: an ordinary knowledge turn answered locally, from
    the answer cache, or from Wikipedia ("tell me about black holes") was
    tagged non-cloud and withheld, so the very next cloud turn ("why do they
    form") arrived with no idea what "they" meant and gave a generic answer.
    Engine choice is not the same question as sensitivity, and privacy is about
    sensitivity.

    THE INVARIANT IT STILL ENFORCES. A turn marked sensitive -- a password, an
    email, anything is_sensitive() flags, which is also what forces such a turn
    to be answered locally -- is never forwarded, in either direction (question
    and its paired answer both carry the flag). So content that had to stay
    local still never reaches the cloud; only innocuous conversational context
    is carried forward. main.py sets the flag from the request text AND from
    whether anything local ran to answer it (exchange_was_local).

    Returns the plain {"role","content"} shape groq_client expects, so a caller
    can't forward the tag itself as content. This is the ONLY function allowed
    to decide a cloud call's history.
    """
    out = []
    for entry in (history or []):
        if not isinstance(entry, dict):
            continue
        sensitive = entry.get("sensitive")
        if sensitive is None:
            # An entry written before this flag existed: fall back to the old
            # conservative rule (forward only what was explicitly cloud), so an
            # untagged legacy turn is never assumed safe.
            sensitive = entry.get("tier") != "cloud"
        if sensitive:
            continue
        out.append({"role": entry.get("role"), "content": entry.get("content")})
    return out
