"""
ARGUS - Live intel: answer out loud, show the evidence, open the sources.

The behaviour this implements: ask "what's happening in the world", get a spoken
answer immediately, see the supporting snippets slide onto the HUD, and have the
browser open on the sources while ARGUS is still talking. Answering and showing
the evidence are the same action, not two commands.

ORDER MATTERS, AND IT IS DELIBERATE. The snippets are published to the HUD and
the browser is opened BEFORE the spoken summary is generated. Generating the
summary means a model call; search takes about a second and the model takes
several. Publishing first means the screen fills while ARGUS is still composing,
which is what makes it feel immediate rather than slow. Reversing these two
lines would change nothing functionally and would make the whole thing feel
sluggish.

WHAT IT REFUSES TO DO. The query is checked against cloud_gate.is_sensitive()
before it is sent anywhere. "What is happening in the world" is a public
question; "what is my PIN" or anything naming this machine's security state is
not, and must never be typed into a search engine just because the phrasing
happened to reach this skill. That check is the reason this module exists as its
own skill rather than as a flag on web_skill.

NO NEW DEPENDENCY. Search reuses research_skill's ddgs path, which is already
declared, pinned and bundled. The browser uses the standard library.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
import webbrowser

MAX_ITEMS = 5
SNIPPET_CHARS = 260
# How long a brief stays on the HUD before the overlay retires it.
INTEL_TTL_S = 240

# Topics get a curated query rather than the user's literal words, because
# "what's happening in the world" searched verbatim returns SEO filler.
#
# Every one of these was MEASURED against the live backend, and the obvious
# phrasings lost:
#   "top world news headlines today Reuters AP BBC"  -> 0 results. Naming
#       outlets narrows it to nothing.
#   "world" alone on the news backend -> FIBA World Cup. It collides with
#       "World Cup" and returns sport.
#   "technology news" -> stock tickers and college football.
#   "cybersecurity news" -> a local council's IT outage.
# What is here returned Associated Press / Reuters / CNN / CNBC on the day it
# was tested. Do not "improve" these by making them more specific.
# TWO queries per topic, merged and deduped, for a reason worth keeping: the
# news backend ranks on keyword-in-title, so a single query for "world news"
# surfaced "WORLD NEWS TONIGHT WITH DAVID MUIR remains No. 1" and two follow-ups
# about that presenter -- the phrase matched a TV show's title instead of
# returning world news. Two differently-worded queries do not share that failure,
# and merging them means one bad draw cannot dominate the design.
TOPIC_QUERIES = {
    "world": ["world headlines", "international news"],
    "tech": ["tech industry news", "technology sector"],
    "security": ["data breach news", "cyberattack ransomware"],
    "local": ["top stories today", "breaking news"],
}
# Titles that are about a news PROGRAMME rather than about the news. Cheap
# guard against the self-referential matches the backend keeps surfacing.
_TITLE_NOISE = ("world news tonight", "nightly news", "news at 10",
                "mypanhandle", "press releases")

_lock = threading.RLock()
_latest = {"query": "", "at": 0.0, "items": [], "topic": ""}


def _publish(query: str, topic: str, items: list):
    with _lock:
        _latest.update(query=query, topic=topic, items=items, at=time.time())


def latest() -> dict:
    """What the HUD overlay renders. Empty once the design has aged out."""
    with _lock:
        if not _latest["items"] or time.time() - _latest["at"] > INTEL_TTL_S:
            return {"query": "", "at": 0, "items": [], "topic": ""}
        return {
            "query": _latest["query"],
            "topic": _latest["topic"],
            "at": _latest["at"],
            "age": int(time.time() - _latest["at"]),
            "items": list(_latest["items"]),
        }


def clear() -> str:
    with _lock:
        _latest.update(query="", at=0.0, items=[], topic="")
    return "Cleared the intel panel."


def _domain(url: str) -> str:
    try:
        host = url.split("//", 1)[-1].split("/", 1)[0]
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _shape(results) -> list:
    out = []
    for r in (results or [])[:MAX_ITEMS]:
        title = (r.get("title") or "").strip()
        # .news() returns "url"; .text() returns "href". Both are handled so the
        # fallback path produces identically-shaped items for the HUD.
        url = (r.get("url") or r.get("href") or "").strip()
        body = " ".join((r.get("body") or "").split())
        if not title or not url:
            continue
        out.append({
            "title": title[:140],
            "url": url,
            # .news() names the outlet properly ("Associated Press"); .text()
            # has no such field, so fall back to the domain.
            "source": (r.get("source") or _domain(url))[:40],
            "date": str(r.get("date") or "")[:19],
            "snippet": body[:SNIPPET_CHARS] + ("…" if len(body) > SNIPPET_CHARS else ""),
        })
    return out


def _news(query: str) -> list:
    """One pass over the news backend. [] on any failure."""
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
        with DDGS() as d:
            return _shape(list(d.news(query, max_results=MAX_ITEMS)))
    except Exception:
        return []


def _fetch_items(queries):
    """(items, error) merged across QUERIES, deduped, noise-filtered.

    ddgs.news() carries a real publication date and the outlet's actual name,
    which plain text search does not -- and for "what is happening" the date is
    most of the point. The plain text backend stays as a fallback so an empty
    news result does not fail the whole feature.
    """
    if isinstance(queries, str):
        queries = [queries]

    merged, seen = [], set()
    for q in queries:
        for it in _news(q):
            low = it["title"].lower()
            if any(n in low for n in _TITLE_NOISE):
                continue
            key = it["url"].split("?", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            merged.append(it)
    if merged:
        return merged[:MAX_ITEMS], None

    from skills import research_skill
    results, err = research_skill._search(queries[0], max_results=MAX_ITEMS)
    if err:
        return [], err
    return _shape(results), None


def _spoken(topic: str, items: list, query: str) -> str:
    """A short spoken summary. Falls back to naming the sources if the model
    is unavailable -- an answer that says where to look beats silence."""
    if not items:
        return ""
    digest = "\n".join(f"- {i['title']} ({i['source']}): {i['snippet'][:180]}"
                       for i in items)
    try:
        from ollama_client import chat
        system = (
            "You are ARGUS, a tactical voice assistant, answering out loud. "
            "Summarise these headlines in 2 to 3 short spoken sentences. "
            "Lead with the single most significant item. No markdown, no "
            "lists, no bullet points, no URLs, no headings -- this is read "
            "aloud, so write it exactly as you would say it. Do not mention "
            "that you searched or that these are search results."
        )
        text = chat(system, f"Question: {query}\n\nHeadlines:\n{digest}").strip()
        if 10 < len(text) < 700:
            return text
    except Exception:
        pass
    lead = items[0]
    others = ", ".join(i["source"] for i in items[1:3])
    return (f"Top story: {lead['title']}. From {lead['source']}"
            + (f", plus coverage from {others}." if others else "."))


def brief(query: str = "", topic: str = "world", open_browser: bool = True) -> str:
    """Search, put the evidence on screen, open the sources, then answer.

    Returns the spoken reply. The HUD picks the snippets up from latest() on
    its next telemetry poll -- no websocket, no new endpoint, and it inherits
    the token middleware every other reading already goes through.
    """
    q = (query or "").strip()
    topic = (topic or "world").lower()
    # A user's own question is searched as asked; a bare topic gets the curated
    # query pair above.
    search_q = [q] if q else TOPIC_QUERIES.get(topic, TOPIC_QUERIES["world"])

    # Nothing about this machine goes to a search engine, whatever the phrasing.
    #
    # search_q is a LIST of queries. This used to pass it to is_sensitive()
    # as-is, which called .strip() on a list, raised AttributeError, and was
    # swallowed by the except below -- so the check never once ran. It is joined
    # here, and is_sensitive() also accepts a list now, so neither end can
    # silently disable the other.
    try:
        from skills import cloud_gate
        if cloud_gate.is_sensitive(" ".join(str(part) for part in search_q)):
            return ("That question is about this machine, so I won't put it "
                    "into a search engine. Ask me directly instead.")
    except Exception:
        pass

    items, err = _fetch_items(search_q)
    if err and not items:
        return f"I couldn't reach the news right now. {err}"
    if not items:
        return "I searched but got nothing back worth reporting."

    # Show the evidence FIRST -- see the module docstring on ordering.
    _publish(search_q, topic, items)
    if open_browser:
        try:
            webbrowser.open(items[0]["url"])
        except Exception:
            pass
    try:
        import security
        security.audit("intel_brief", f"topic={topic} items={len(items)}", "ok")
    except Exception:
        pass

    return _spoken(topic, items, q or search_q)


def status() -> dict:
    cur = latest()
    return {"skill": "intel", "items": len(cur["items"]),
            "query": cur["query"], "age": cur.get("age", 0)}
