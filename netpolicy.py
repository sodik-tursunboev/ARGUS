'ARGUS - Network egress policy.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
import time

FIXED = "fixed"
OPEN = "open"
NONE = "none"

# Component -> (class, allowed hosts). Hosts match exactly or as a suffix
# after a leading dot, so "open-meteo.com" covers api. and geocoding-api.
EGRESS: dict[str, tuple[str, frozenset]] = {
    # Both cloud tiers share one class: they are the same capability (send a
    # question to a hosted model) and the same trust decision, so a question
    # cloud_gate refuses must be refused for both. Listing them separately
    # would invite a future edit that permits one and not the other.
    "cloud":     (FIXED, frozenset({"api.groq.com",
                                    "generativelanguage.googleapis.com"})),
    "llm":       (FIXED, frozenset({"localhost", "127.0.0.1"})),
    "knowledge": (FIXED, frozenset({"en.wikipedia.org", "api.dictionaryapi.dev"})),
    "weather":   (FIXED, frozenset({".open-meteo.com"})),
    "search":    (FIXED, frozenset({"duckduckgo.com", ".duckduckgo.com",
                                    "html.duckduckgo.com", "lite.duckduckgo.com"})),
    "research":  (OPEN,  frozenset()),
    # Telephony. Its own class rather than folded into "cloud": placing a phone
    # call is a different capability and a different trust decision from asking
    # a hosted model a question, and it costs money per use. Pinned to Twilio's
    # API host only -- a compromised phone_skill cannot reach anything else,
    # and the class is narrow enough that widening it is a visible edit.
    # BUGFIX: the phone_skill places its calls through check_egress(url,
    # "phone"), but this entry was missing while its comment and telegram's
    # entry landed -- so every real owner call was refused by policy with
    # "phone is a privileged component", and the alert system silently
    # degraded to a spoken apology. Fail-closed held; the missing grant
    # didn't. Restored exactly as the comment describes.
    "phone":        (FIXED, frozenset({"api.twilio.com"})),
    "telegram":     (FIXED, frozenset({"api.telegram.org"})),
    "orchestrator": (FIXED, frozenset({"localhost", "127.0.0.1"})),

    # Privileged. No network, by name, forever.
    "auth":      (NONE, frozenset()),
    "secrets":   (NONE, frozenset()),
    "integrity": (NONE, frozenset()),
    "power":     (NONE, frozenset()),
    "files":     (NONE, frozenset()),
    "execpolicy": (NONE, frozenset()),
    "sandbox":   (NONE, frozenset()),
    "voiceauth": (NONE, frozenset()),
    # The answer cache holds what ARGUS has said, which is the last thing that
    # should ever be able to leave the machine on its own.
    "anscache": (NONE, frozenset()),
}

# Unknown components are denied. A new skill that needs the network has to be
# added here deliberately -- the same fail-closed rule the authorization table
# uses for unknown (skill, action) pairs.
DEFAULT_CLASS = NONE

PRIVILEGED = frozenset(c for c, (cls, _) in EGRESS.items() if cls == NONE)


def _host_allowed(host: str, allowed: frozenset) -> bool:
    host = (host or "").lower()
    for entry in allowed:
        if entry.startswith("."):
            if host.endswith(entry) or host == entry[1:]:
                return True
        elif host == entry:
            return True
    return False


def check_egress(url: str, component: str) -> tuple[bool, str]:
    """(allowed, reason). The single egress decision."""
    from urllib.parse import urlparse

    cls, allowed = EGRESS.get(component, (DEFAULT_CLASS, frozenset()))

    if cls == NONE:
        return False, (f"{component} is a privileged component and is not "
                       f"permitted to make network connections")

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "unparseable URL"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme {parsed.scheme!r} is not permitted"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "no host in URL"

    # Plaintext HTTP is only ever acceptable to loopback. Everything else must
    # be TLS -- and this is enforced rather than assumed, because the audit
    # that found "every remote endpoint is https" was a snapshot, not a
    # guarantee about the next line of code anyone writes.
    is_loopback = host in ("localhost", "127.0.0.1", "::1", "[::1]")
    if parsed.scheme == "http" and not is_loopback:
        return False, f"plaintext http to {host} is not permitted — use https"

    if cls == OPEN:
        import security
        if not security.url_is_safe(url):
            return False, "blocked by the SSRF guard"
        return True, ""

    if not _host_allowed(host, allowed):
        return False, (f"{component} may not connect to {host} "
                       f"(allowed: {', '.join(sorted(allowed))})")
    return True, ""


# ── validated download ─────────────────────────────────────────────────
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_RETRIES = 2

TEXTUAL_TYPES = ("text/", "application/json", "application/xml",
                 "application/xhtml", "application/rss")


class EgressDenied(Exception):
    pass


def fetch(url: str, component: str, *, timeout: float = DEFAULT_TIMEOUT,
          max_bytes: int = MAX_DOWNLOAD_BYTES,
          allow_types: tuple = TEXTUAL_TYPES, **kwargs):
    """Policy-checked GET with a size cap and a content-type check.

    Streams and counts bytes rather than trusting Content-Length: a server
    that lies about its length, or omits the header entirely, would otherwise
    hand back an unbounded body straight into memory and from there into a
    model's context.
    """
    import requests
    import security

    allowed, reason = check_egress(url, component)
    if not allowed:
        security.security_event(security.TOOL_DENIED, component=component,
                                reason="egress_denied", status="failed")
        raise EgressDenied(reason)

    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            # verify defaults to True and is NOT overridable through kwargs --
            # a caller passing verify=False would silently disable certificate
            # validation for the one path meant to enforce it.
            kwargs.pop("verify", None)
            resp = requests.get(url, timeout=timeout, stream=True,
                                verify=True, **kwargs)
            resp.raise_for_status()

            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if allow_types and ctype and not ctype.startswith(allow_types):
                raise EgressDenied(
                    f"unexpected content-type {ctype!r} from {url[:48]}")

            body = bytearray()
            for chunk in resp.iter_content(8192):
                body.extend(chunk)
                if len(body) > max_bytes:
                    resp.close()
                    raise EgressDenied(
                        f"response exceeded {max_bytes} bytes and was dropped")
            return bytes(body)
        except EgressDenied:
            raise
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(0.4 * (attempt + 1))     # bounded, not exponential
            continue
    raise last_err


# ── update / download signature verification ───────────────────────────
def verify_download_signature(path: str) -> tuple[bool, str]:
    """Authenticode check on a downloaded executable or installer.

    ARGUS does not currently download or self-update, so this has no caller.
    It exists because the checklist asks for it and because the moment an
    update mechanism IS added, the check should already be here rather than
    being written under time pressure by whoever adds it.
    """
    import integrity
    return integrity.verify_signature(path)


def describe() -> str:
    fixed = sum(1 for c, _ in EGRESS.values() if c == FIXED)
    return (f"egress classes: {fixed} fixed, "
            f"1 open (SSRF-guarded), {len(PRIVILEGED)} denied; "
            f"max download {MAX_DOWNLOAD_BYTES // 1024}KB; "
            f"retries {MAX_RETRIES}")
