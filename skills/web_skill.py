"""
ARGUS - Web Skill
Open-ended web search and YouTube playback. Unlike system_skill, these aren't
allowlisted — searching the web or playing a video is low-risk (nothing gets
installed, deleted, or executed), so ARGUS can act on any query here.

YouTube playback works by asking yt-dlp for the top search result's URL
(metadata only, nothing downloaded) and opening that video directly in your
browser — so "play X on youtube" actually starts playing X, not just search results.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import webbrowser
from urllib.parse import quote_plus

from yt_dlp import YoutubeDL


def open_in_preferred_browser(url: str) -> None:
    """Opens a URL, honoring a learned default_browser preference when one
    is set and registered with Python's own webbrowser module (for example, Firefox). Falls back to the OS
    default on any lookup/registration failure -- a preference must never
    turn a working "open the page" into an error."""
    try:
        from skills.personalize_skill import get_preference
        name = get_preference("default_browser")
        if name:
            webbrowser.get(name.lower()).open(url)
            return
    except Exception:
        pass
    webbrowser.open(url)


def search(query: str) -> str:
    url = f"https://www.google.com/search?q={quote_plus(query)}"
    open_in_preferred_browser(url)
    return f"Searching the web for {query}."


def play_youtube(query: str) -> str:
    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "default_search": "ytsearch1",
        "noplaylist": True,
    }
    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(query, download=False)
            if "entries" in info:
                info = info["entries"][0]
            video_url = info.get("webpage_url") or info.get("url")
            title = info.get("title", query)
        if not video_url:
            return f"Couldn't find a video for {query}."
        open_in_preferred_browser(video_url)
        return f"Playing {title} on YouTube."
    except Exception as e:
        return f"Couldn't play that: {e}"
