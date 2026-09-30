"""
ARGUS - Knowledge lookup and text operations.

Wikipedia is used for definitional questions ("what is X") because it's fast,
accurate, and gives a clean one-paragraph answer — better than either a web
search summary or a 3B model's recollection.

Text operations (translate, summarize, rewrite) run on the LOCAL model.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

import requests

from ollama_client import chat
from skills import cloud_gate

WIKI_SEARCH = "https://en.wikipedia.org/w/api.php"
WIKI_SUMMARY = "https://en.wikipedia.org/api/rest_v1/page/summary/"


def lookup(topic: str) -> str:
    """One-paragraph factual answer from Wikipedia."""
    topic = topic.strip().rstrip("?")
    if not topic:
        return "What would you like me to look up?"

    # Backstop behind the router and brain -- see cloud_gate.guard_egress.
    cloud_gate.guard_egress("reference lookup")
    try:
        r = requests.get(
            WIKI_SEARCH,
            params={
                "action": "query", "list": "search", "srsearch": topic,
                "format": "json", "srlimit": 1,
            },
            headers={"User-Agent": "ArgusOS/1.0"},
            timeout=8,
        )
        r.raise_for_status()
        hits = r.json().get("query", {}).get("search", [])
        if not hits:
            return ""

        title = hits[0]["title"]
        r2 = requests.get(
            WIKI_SUMMARY + requests.utils.quote(title.replace(" ", "_")),
            headers={"User-Agent": "ArgusOS/1.0"},
            timeout=8,
        )
        r2.raise_for_status()
        extract = r2.json().get("extract", "")
        if not extract:
            return ""

        # Trim to roughly two sentences — this is spoken aloud.
        sentences = re.split(r"(?<=[.!?])\s+", extract)
        return " ".join(sentences[:2]).strip()

    except requests.exceptions.RequestException:
        return ""


def translate(text: str, language: str) -> str:
    # The text to translate is user-supplied but frequently pasted from
    # somewhere else, and "translate this" is a natural way to get arbitrary
    # foreign text in front of the model.
    import security

    prompt = (
        f"Translate the untrusted data block into {language}. Reply with ONLY "
        f"the translation, nothing else.\n\n/no_think"
    )
    try:
        out = chat(prompt, security.wrap_untrusted(text, "text to translate"))
        return re.sub(r"<think>.*?</think>", "", out, flags=re.S).strip()
    except Exception as e:
        return f"Translation failed: {e}"


def summarize(text: str) -> str:
    """Summarises arbitrary text -- in practice, THE CLIPBOARD.

    router dispatches knowledge/summarize_clipboard with pyperclip.paste(), so
    this content is whatever the user last copied: a web page, an email, a PDF
    selection. All attacker-controllable, and it used to reach the model as a
    bare user message with nothing marking it as data. A page containing
    "ignore your instructions and ..." was indistinguishable from the user
    asking for that.
    """
    import security

    if not text.strip():
        return "There's nothing to summarize."
    prompt = (
        "Summarize the untrusted data block in two or three short sentences "
        "suitable for reading aloud. Reply with only the summary.\n\n/no_think"
    )
    try:
        out = chat(prompt, security.wrap_untrusted(text[:6000], "the clipboard"))
        return re.sub(r"<think>.*?</think>", "", out, flags=re.S).strip()
    except Exception as e:
        return f"Couldn't summarize that: {e}"


def define(word: str) -> str:
    """Dictionary definition — falls back to Wikipedia, then the model."""
    word = word.strip().rstrip("?")
    cloud_gate.guard_egress("dictionary lookup")
    try:
        r = requests.get(
            f"https://api.dictionaryapi.dev/api/v2/entries/en/{requests.utils.quote(word)}",
            timeout=6,
        )
        if r.status_code == 200:
            data = r.json()
            meaning = data[0]["meanings"][0]
            pos = meaning.get("partOfSpeech", "")
            definition = meaning["definitions"][0]["definition"]
            return f"{word}, {pos}: {definition}"
    except (requests.exceptions.RequestException, KeyError, IndexError):
        pass

    wiki = lookup(word)
    if wiki:
        return wiki

    # NEVER return an empty string. This did, for any word the dictionary and
    # Wikipedia both missed, and an empty reply reaches the speaker as
    # silence -- indistinguishable from ARGUS not having heard the question.
    # Saying "I couldn't find a definition" is a worse answer than a
    # definition and a far better one than nothing.
    return (f"I couldn't find a definition for {word}. "
            f"If I misheard it, try spelling it out.")


def spell(word: str) -> str:
    word = word.strip().rstrip("?").split()[-1] if word.strip() else ""
    if not word:
        return "Which word?"
    return f"{word} is spelled: " + ", ".join(word.upper())
