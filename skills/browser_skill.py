"""
ARGUS - Browser Skill

A generic browser-control layer -- one module with primitives (navigate,
click, fill, extract, screenshot, tabs) rather than a skill per site or per
Chrome command. "Go to the website, log in, find the invoice, download it"
is composed from these primitives through the planner already in router.py
(plan_and_stage / run_plan) -- this module does not build a second workflow
engine, it just adds (skill, action) pairs the existing one can use.

Backed by Playwright, driving ONE dedicated Chromium profile under
paths.writable("browser_profile") -- NOT your real Chrome profile. That is
deliberate: ARGUS never fights your already-open browser for the same
profile lock, and never touches your personal cookies, history or bookmarks
by surprise. Log into a site once through ARGUS and the session persists
across runs, same as an ordinary browser. The window is visible
(headless=False) on purpose -- if a site needs a password typed, an OTP, or
a CAPTCHA solved, that happens in the real window, by you; this module does
not automate any of the three.

THREADING. Playwright's sync API is pinned to the OS thread that started it;
calling it from a second thread raises. FastAPI runs each synchronous
request handler on a threadpool worker, and Starlette does not promise the
same worker thread twice, so Playwright cannot just be called inline the way
every other skill calls its OS API. Instead one long-lived daemon thread
(_BrowserThread, started lazily on first use) owns Playwright end to end;
every public function below marshals its work onto that thread through a
queue and blocks for the result -- the caller is already a synchronous
worker thread, so blocking here is no different from any other skill's
blocking OS call.

SAFETY BOUNDARY -- what needs a PIN and what does not. Browsing (navigate,
click, fill, extract, screenshot, tabs) changes nothing outside the browser
window and is always reversible with Back, so it runs immediately, same
tier as files_skill.move or window_skill.focus. Submitting a form,
downloading a file, and uploading a file all hand data to, or take data
from, somewhere outside this machine's control -- so all three are STAGED
and PIN-confirmed, the exact stage/confirm shape files_skill.stage_delete
and power_skill.request already use, with secrets_store.verify_pin() (which
verifies a salted hash, unlike files_skill's own raw compare_digest against
config.COMMAND_PIN -- flagged separately, not fixed here since it's a
different module's bug).

fill() additionally refuses any field whose type is "password" outright --
no PIN reachably unlocks that, ARGUS just never types one in. Same reasoning
as this project's own top-level rule: credentials are typed by the human.

WHAT THIS DELIBERATELY DOES NOT DO:
- Reorder tabs. Browsers don't expose tab order to automation; tab_reorder()
  says so rather than faking success.
- Read or write your actual Chrome bookmarks/history files. bookmark_add/
  bookmarks_list/bookmark_remove keep ARGUS's OWN small saved-link list
  (browser_bookmarks.json); history_search() is this SESSION's visited URLs
  only, not Chrome's history database (which is a different browser profile
  entirely, and typically locked while Chrome is running anyway).
- Bypass a CAPTCHA, or autofill a password or payment field.
- Duplicate research_skill.py's multi-source web lookups ("multi-tab
  research" from the original spec) -- that already runs without needing a
  visible browser, which is strictly better for that use case.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import hashlib
import os
import re
import threading
import time
from queue import Queue

import paths
import secrets_store
from config import COMMAND_PIN

CONFIRM_WINDOW = 25  # seconds -- identical window to every other staged action

_PROFILE_DIR = paths.writable("browser_profile")
_BOOKMARKS_PATH = paths.writable("browser_bookmarks.json")
_HISTORY_MAX = 200
_ZONE_STREAM = ":Zone.Identifier"

# Same five folders files_skill.SEARCH_ROOTS confines its own operations to.
# A voice command should not be able to hand an arbitrary system file to a
# website -- duplicated here rather than imported so this module stays
# self-contained, matching every other skill in this package.
_UPLOAD_ROOTS = [
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Pictures"),
    os.path.expandvars(r"%USERPROFILE%\Videos"),
]

# One staged action at a time: "submit" | "download" | "upload".
# Same shape as files_skill._pending / power_skill._pending.
_pending = {"kind": None, "detail": None, "at": 0.0}

_history = []          # this SESSION's visited URLs only -- see history_search()
_downloads_log = []     # [(filename, url, when)]
_verification_events = []  # bounded, target-hashed success evidence for plans
_verification_seq = 0
_VERIFICATION_MAX = 200


def _target_digest(target: str) -> str:
    """Stable comparison key without retaining typed form values or paths."""
    return hashlib.sha256(str(target or "").encode("utf-8", "replace")).hexdigest()


def _record_verification(action: str, target: str, **state) -> None:
    """Record a browser mutation only after its Playwright call succeeded."""
    global _verification_seq
    _verification_seq += 1
    _verification_events.append({
        "seq": _verification_seq,
        "action": str(action),
        "target_digest": _target_digest(target),
        "state": dict(state),
    })
    del _verification_events[:-_VERIFICATION_MAX]


def verification_snapshot() -> dict:
    """Plain-Python, non-blocking evidence used by agent verifiers.

    This never touches a Playwright object and never includes the raw action
    target. A plan can compare sequence numbers and target digests without
    copying form contents, upload paths, or page selectors into observations.
    """
    if not _verification_events:
        return {"seq": 0, "action": "", "target_digest": "", "state": {}}
    event = _verification_events[-1]
    return {"seq": event["seq"], "action": event["action"],
            "target_digest": event["target_digest"],
            "state": dict(event.get("state") or {})}


# ═══════════════════════════════════════════════════════════════════════════
# THE BROWSER THREAD
# ═══════════════════════════════════════════════════════════════════════════

class _BrowserThread(threading.Thread):
    """Owns Playwright and every page/context object. Every method that
    touches Playwright runs as a job submitted through .call() and executed
    inside run(), on this one thread -- never called directly from outside."""

    def __init__(self):
        super().__init__(daemon=True, name="argus-browser")
        self._jobs = Queue()
        self._ready = threading.Event()
        self._start_error = None
        # NOT "_context" -- threading.Thread already uses that name
        # internally (the contextvars snapshot it propagates into run()),
        # and a subclass attribute of the same name silently shadows it:
        # bt._context read back a contextvars.Context object, not None,
        # so _ensure()'s "if bt._context is None" was always false and the
        # browser never actually launched. Caught by an end-to-end run
        # against a real browser, not by reasoning about the code.
        self._browser_ctx = None
        self._pages = []
        self._active = 0
        # accept_downloads=True on the context (below) means ANY click that
        # happens to trigger a download completes silently, regardless of
        # whether _do_download() was the thing that triggered it -- this flag
        # is the only thing distinguishing an EXPECTED download (stage_download
        # -> confirm() -> _do_download, PIN already checked) from a stray one
        # (a plain click() on what turned out to be a download link/button).
        # See _guard_downloads().
        self._download_expected = False
        self.start()

    def run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            self._start_error = e
            self._ready.set()
            return
        try:
            with sync_playwright() as pw:
                self._pw = pw
                self._ready.set()
                while True:
                    job = self._jobs.get()
                    if job is None:
                        break
                    fn, args, kwargs, box, done = job
                    try:
                        box["value"] = fn(self, *args, **kwargs)
                    except Exception as e:      # noqa: BLE001 -- reported to the caller
                        box["error"] = e
                    finally:
                        done.set()
        finally:
            self._browser_ctx = None
            self._pages = []

    def call(self, fn, *args, timeout: float = 30.0, **kwargs):
        if not self._ready.wait(timeout=15):
            raise RuntimeError("The browser engine didn't start in time.")
        if self._start_error:
            raise RuntimeError(
                "Playwright isn't installed. From the ARGUS venv, run: "
                "pip install playwright && playwright install chromium"
            ) from self._start_error
        box, done = {}, threading.Event()
        self._jobs.put((fn, args, kwargs, box, done))
        if not done.wait(timeout=timeout):
            raise TimeoutError("That browser action took too long.")
        if "error" in box:
            raise box["error"]
        return box.get("value")

    def stop(self):
        self._jobs.put(None)


_thread_lock = threading.Lock()
_thread = None


def _get_thread() -> _BrowserThread:
    """Lazy-started, like every other OS handle in this codebase
    (pc_skill._uia_api, control_skill._get_volume_interface) -- importing
    this module must not spawn Playwright's driver process on every ARGUS
    boot, only the first time a browser action is actually asked for."""
    global _thread
    with _thread_lock:
        if _thread is None:
            _thread = _BrowserThread()
        return _thread


def _err(e: Exception) -> str:
    return str(e).strip().splitlines()[0][:160]


def _guard_downloads(bt: _BrowserThread, page):
    """Cancel any download that starts while nothing is expecting one.
    Registered on every page in the context (see _ensure()'s "page" listener,
    which covers new_page() and window.open() alike) so a plain click() or
    follow_link() cannot complete a download outside the staged/PIN path --
    only _do_download(), which sets _download_expected around its own
    expect_download() block, lets one through."""
    def _on_download(download):
        if not bt._download_expected:
            try:
                download.cancel()
            except Exception:
                pass
    page.on("download", _on_download)


def _ensure(bt: _BrowserThread):
    """Launches the persistent context on first use. Runs ON the browser
    thread -- called only from inside a job function."""
    if bt._browser_ctx is None:
        os.makedirs(_PROFILE_DIR, exist_ok=True)
        bt._browser_ctx = bt._pw.chromium.launch_persistent_context(
            _PROFILE_DIR, headless=False, viewport=None, accept_downloads=True)
        bt._browser_ctx.set_default_timeout(15000)
        # Covers every future page (new tabs, window.open) for the life of
        # this context -- one registration instead of one per new_page() call
        # site, so a future new-tab path can't forget to wire the guard.
        bt._browser_ctx.on("page", lambda pg: _guard_downloads(bt, pg))
        page = bt._browser_ctx.pages[0] if bt._browser_ctx.pages else bt._browser_ctx.new_page()
        _guard_downloads(bt, page)   # the initial page predates the listener above
        bt._pages = [page]
        bt._active = 0
    return bt._browser_ctx


def _page(bt: _BrowserThread):
    ctx = _ensure(bt)
    bt._pages = [p for p in bt._pages if not p.is_closed()] or list(ctx.pages)
    if not bt._pages:
        bt._pages = [ctx.new_page()]
    if bt._active >= len(bt._pages):
        bt._active = len(bt._pages) - 1
    return bt._pages[bt._active]


def _find_tab(bt: _BrowserThread, query: str):
    q = (query or "").lower().strip()
    for i, p in enumerate(bt._pages):
        try:
            if q in (p.title() or "").lower() or q in (p.url or "").lower():
                return i
        except Exception:
            continue
    return None


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    head = raw.split(":", 1)[0]
    has_scheme = bool(_SCHEME_RE.match(raw)) and "." not in head
    return raw if has_scheme else "https://" + raw


def _remember(url: str, title: str):
    _history.append({"url": url, "title": title or url, "at": time.time()})
    del _history[:-_HISTORY_MAX]


# ═══════════════════════════════════════════════════════════════════════════
# LAUNCH / CLOSE
# ═══════════════════════════════════════════════════════════════════════════

def launch() -> str:
    try:
        _get_thread().call(_ensure)
    except Exception as e:
        return f"I couldn't start the browser: {_err(e)}"
    return "Browser is open."


def _do_close(bt):
    if bt._browser_ctx is not None:
        bt._browser_ctx.close()
    bt._browser_ctx = None
    bt._pages = []
    return True


def close() -> str:
    try:
        _get_thread().call(_do_close)
    except Exception as e:
        return f"I couldn't close the browser: {_err(e)}"
    return "Closed the browser."


# ═══════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════

def _do_tab_open(bt, url):
    ctx = _ensure(bt)
    page = ctx.new_page()
    bt._pages.append(page)
    bt._active = len(bt._pages) - 1
    if url:
        page.goto(url, wait_until="domcontentloaded")
    return page.title() or page.url


def tab_open(url: str = "") -> str:
    full = ""
    if (url or "").strip():
        import execpolicy
        ok, msg = execpolicy.check_url(url)
        if not ok:
            return msg
        full = _normalize_url(url)
    try:
        title = _get_thread().call(_do_tab_open, full)
    except Exception as e:
        return f"I couldn't open a new tab: {_err(e)}"
    if full:
        _remember(full, title)
        _record_verification("tab_open", url, title=title, opened_url=full)
        return f"New tab — {title}."
    _record_verification("tab_open", url, title=title)
    return "Opened a new tab."


def _do_tab_close(bt, query):
    bt._pages = [p for p in bt._pages if not p.is_closed()]
    if not bt._pages:
        return None
    idx = _find_tab(bt, query) if query else bt._active
    if idx is None:
        return False
    page = bt._pages[idx]
    title = page.title() or page.url
    page.close()
    del bt._pages[idx]
    ctx = bt._browser_ctx
    if not bt._pages and ctx is not None:
        bt._pages = [ctx.new_page()]
    bt._active = min(bt._active, max(len(bt._pages) - 1, 0))
    return title


def tab_close(query: str = "") -> str:
    try:
        title = _get_thread().call(_do_tab_close, query)
    except Exception as e:
        return f"I couldn't close that tab: {_err(e)}"
    if title is None:
        return "No tabs are open."
    if title is False:
        return f"I don't see a tab matching {query}."
    _record_verification("tab_close", query, closed_title=title)
    return f"Closed {title}."


def _do_tab_switch(bt, query):
    idx = _find_tab(bt, query)
    if idx is None:
        return None
    bt._active = idx
    p = bt._pages[idx]
    p.bring_to_front()
    return p.title() or p.url


def tab_switch(query: str) -> str:
    if not (query or "").strip():
        return "Switch to which tab?"
    try:
        title = _get_thread().call(_do_tab_switch, query)
    except Exception as e:
        return f"I couldn't switch tabs: {_err(e)}"
    if title is None:
        return f"I don't see a tab matching {query}."
    _record_verification("tab_switch", query, active_title=title)
    return f"Switched to {title}."


def _do_tab_search(bt, query):
    bt._pages = [p for p in bt._pages if not p.is_closed()]
    q = query.lower()
    hits = []
    for p in bt._pages:
        try:
            if q in (p.title() or "").lower() or q in (p.url or "").lower():
                hits.append(p.title() or p.url)
        except Exception:
            continue
    return hits


def tab_search(query: str = "") -> str:
    if not (query or "").strip():
        return list_tabs()
    try:
        hits = _get_thread().call(_do_tab_search, query)
    except Exception as e:
        return f"I couldn't search tabs: {_err(e)}"
    if not hits:
        return f"No open tabs match {query}."
    return f"{len(hits)} match{'es' if len(hits) != 1 else ''}: " + "; ".join(hits[:6])


def _do_list_tabs(bt):
    ctx = _ensure(bt)
    bt._pages = [p for p in bt._pages if not p.is_closed()] or list(ctx.pages)
    out = []
    for i, p in enumerate(bt._pages):
        try:
            out.append((i == bt._active, p.title() or p.url))
        except Exception:
            continue
    return out


def list_tabs() -> str:
    try:
        tabs = _get_thread().call(_do_list_tabs)
    except Exception as e:
        return f"I couldn't list tabs: {_err(e)}"
    if not tabs:
        return "No tabs are open."
    parts = [(f"[active] {t}" if a else t) for a, t in tabs]
    return f"{len(tabs)} tab{'s' if len(tabs) != 1 else ''}: " + "; ".join(parts)


def tab_reorder(*_args, **_kwargs) -> str:
    return ("Browsers don't expose tab order to automation -- I can open, "
            "switch, or close tabs, but not reorder them.")


# ═══════════════════════════════════════════════════════════════════════════
# NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════

def _do_navigate(bt, url):
    page = _page(bt)
    page.goto(url, wait_until="domcontentloaded")
    return page.title()


def navigate(url: str) -> str:
    import execpolicy
    ok, msg = execpolicy.check_url(url)
    if not ok:
        return msg
    full = _normalize_url(url)
    try:
        title = _get_thread().call(_do_navigate, full)
    except Exception as e:
        return f"I couldn't open that page: {_err(e)}"
    _remember(full, title)
    return f"Opened {title or full}."


def search(query: str) -> str:
    """A web search inside the MANAGED browser, so a follow-up like "open the
    second result" or "read that page" can act on it -- unlike
    web_skill.search, which opens the system's default browser instead."""
    query = (query or "").strip()
    if not query:
        return "Search for what?"
    from urllib.parse import quote_plus
    return navigate(f"https://www.google.com/search?q={quote_plus(query)}")


def _do_back(bt):
    p = _page(bt)
    p.go_back(wait_until="domcontentloaded")
    return p.title() or p.url


def back() -> str:
    try:
        t = _get_thread().call(_do_back)
    except Exception as e:
        return f"I couldn't go back: {_err(e)}"
    _record_verification("back", "", title=t)
    return f"Back to {t}."


def _do_forward(bt):
    p = _page(bt)
    p.go_forward(wait_until="domcontentloaded")
    return p.title() or p.url


def forward() -> str:
    try:
        t = _get_thread().call(_do_forward)
    except Exception as e:
        return f"I couldn't go forward: {_err(e)}"
    _record_verification("forward", "", title=t)
    return f"Forward to {t}."


def _do_refresh(bt):
    p = _page(bt)
    p.reload(wait_until="domcontentloaded")
    return p.title() or p.url


def refresh() -> str:
    try:
        t = _get_thread().call(_do_refresh)
    except Exception as e:
        return f"I couldn't refresh that: {_err(e)}"
    _record_verification("refresh", "", title=t)
    return f"Refreshed {t}."


# ═══════════════════════════════════════════════════════════════════════════
# READING THE PAGE
# ═══════════════════════════════════════════════════════════════════════════

def _do_extract(bt, selector):
    p = _page(bt)
    if selector:
        text = p.locator(selector).first.inner_text(timeout=5000)
    else:
        text = p.inner_text("body")
    return re.sub(r"\n{3,}", "\n\n", text or "").strip()


def extract_text(selector: str = "") -> str:
    try:
        text = _get_thread().call(_do_extract, selector)
    except Exception as e:
        return f"I couldn't read that page: {_err(e)}"
    if not text:
        return "That page has no readable text."
    return text[:4000]


# Collects visible, labelled, clickable/typeable elements. Deliberately a
# plain DOM scan rather than the accessibility tree pc_skill.ui_tree() reads
# for native apps -- a web page's accessibility tree and its visible DOM
# diverge constantly (ARIA gaps, framework-generated markup), and what a
# voice command actually needs here is "what can I click or fill in", which
# the visible DOM answers more reliably for the general case.
_SCAN_JS = """
() => {
  const sel = 'a,button,input,select,textarea,[role=button],[role=link],[onclick]';
  const out = [];
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) continue;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    let label = (el.innerText || el.value || el.getAttribute('aria-label') ||
                 el.getAttribute('placeholder') || el.getAttribute('title') || '').trim();
    label = label.replace(/\\s+/g, ' ').slice(0, 80);
    if (!label) continue;
    out.push({tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', label});
    if (out.length >= 200) break;
  }
  return out;
}
"""


def _do_find_elements(bt, query):
    p = _page(bt)
    els = p.evaluate(_SCAN_JS)
    if query:
        q = query.lower()
        els = [e for e in els if q in e["label"].lower()]
    return els[:40]


def find_elements(query: str = "") -> str:
    try:
        els = _get_thread().call(_do_find_elements, query)
    except Exception as e:
        return f"I couldn't inspect that page: {_err(e)}"
    if not els:
        return (f"I don't see anything on the page matching {query}." if query
                else "I don't see any clickable elements on this page.")
    return "; ".join(f'{e["tag"]}: "{e["label"]}"' for e in els[:15])


def screenshot(label: str = "") -> str:
    from config import VAULT_PATH
    out_dir = os.path.join(VAULT_PATH, "outputs")
    os.makedirs(out_dir, exist_ok=True)
    safe = re.sub(r"[^\w-]+", "_", label)[:40] or "page"
    path = os.path.join(out_dir, f"browser_{safe}_{time.strftime('%Y%m%d-%H%M%S')}.png")

    def _do(bt, path):
        p = _page(bt)
        p.screenshot(path=path)
        return p.title() or p.url

    try:
        title = _get_thread().call(_do, path)
    except Exception as e:
        return f"I couldn't capture the page: {_err(e)}"
    return f"Captured {title} to {os.path.basename(path)}."


def zoom(percent) -> str:
    try:
        percent = int(percent)
    except (TypeError, ValueError):
        return "What percentage should I zoom to?"
    percent = max(25, min(500, percent))

    def _do(bt, factor):
        _page(bt).evaluate(f"document.body.style.zoom = '{factor}'")
        return True

    try:
        _get_thread().call(_do, percent / 100.0)
    except Exception as e:
        return f"I couldn't change the zoom: {_err(e)}"
    _record_verification("zoom", str(percent), percent=percent)
    return f"Zoomed to {percent}%."


# ═══════════════════════════════════════════════════════════════════════════
# INTERACTION (reversible -- runs immediately, no PIN)
# ═══════════════════════════════════════════════════════════════════════════

# Same recognition _do_submit() uses below to find a submit control by name
# or type. click()/follow_link() share it as a REFUSAL check: the module's
# own docstring promises submit is always staged and PIN-confirmed, but that
# was only true of the specific Python function named _do_submit -- a click()
# on a button matching either signature triggered the exact same real POST
# with none of it. The gate now keys on what the element IS, not which
# function was asked to touch it.
_SUBMIT_NAME_RE = re.compile("submit|send|continue|log ?in|sign ?in", re.I)


def _is_submit_control(target, text) -> bool:
    try:
        if (target.get_attribute("type") or "").lower() == "submit":
            return True
    except Exception:
        pass
    return bool(_SUBMIT_NAME_RE.search(text or ""))


def _do_click(bt, text):
    p = _page(bt)
    for locator in (p.get_by_role("button", name=text, exact=False),
                     p.get_by_role("link", name=text, exact=False),
                     p.get_by_text(text, exact=False)):
        try:
            if locator.count() > 0:
                target = locator.first
                if _is_submit_control(target, text):
                    raise PermissionError("submit control")
                target.scroll_into_view_if_needed(timeout=3000)
                target.click(timeout=5000)
                return p.title() or p.url
        except PermissionError:
            raise
        except Exception:
            continue
    raise LookupError("no match")


def click(text: str) -> str:
    if not (text or "").strip():
        return "Click what?"
    try:
        title = _get_thread().call(_do_click, text)
    except PermissionError:
        return ('That looks like a submit button -- say "submit the form" '
                "so it's staged and PIN-confirmed like any other submit.")
    except LookupError:
        return f"I don't see anything called {text} on the page."
    except Exception as e:
        return f"I couldn't click that: {_err(e)}"
    _record_verification("click", text, title=title)
    return f"Clicked {text}. Now on {title}."


def _do_follow(bt, text):
    p = _page(bt)
    loc = p.get_by_role("link", name=text, exact=False)
    if loc.count() == 0:
        raise LookupError("no match")
    target = loc.first
    if _is_submit_control(target, text):
        raise PermissionError("submit control")
    target.click(timeout=5000)
    return p.title() or p.url


def follow_link(text: str) -> str:
    if not (text or "").strip():
        return "Follow which link?"
    try:
        title = _get_thread().call(_do_follow, text)
    except PermissionError:
        return ('That looks like a submit button -- say "submit the form" '
                "so it's staged and PIN-confirmed like any other submit.")
    except LookupError:
        return f"I don't see a link called {text}."
    except Exception as e:
        return f"I couldn't follow that link: {_err(e)}"
    _record_verification("follow_link", text, title=title)
    return f"Followed the link. Now on {title}."


def _do_fill(bt, field, value):
    p = _page(bt)
    for locator in (p.get_by_label(field, exact=False),
                     p.get_by_placeholder(field, exact=False),
                     p.get_by_role("textbox", name=field, exact=False)):
        try:
            if locator.count() > 0:
                target = locator.first
                if (target.get_attribute("type") or "").lower() == "password":
                    raise PermissionError("password field")
                target.fill(value, timeout=5000)
                return True
        except PermissionError:
            raise
        except Exception:
            continue
    raise LookupError("no match")


def fill(field: str, value: str) -> str:
    if not (field or "").strip():
        return "Fill in which field?"
    try:
        _get_thread().call(_do_fill, field, value)
    except PermissionError:
        return "I don't fill in password fields -- type that one yourself."
    except LookupError:
        return f"I don't see a field called {field} on this page."
    except Exception as e:
        return f"I couldn't fill that in: {_err(e)}"
    _record_verification("fill", f"{field}|{value}", field_digest=_target_digest(field))
    return f"Filled in {field}."


# ═══════════════════════════════════════════════════════════════════════════
# STAGED ACTIONS -- submit / download / upload. See module docstring for why
# these three, and only these three, need a PIN.
# ═══════════════════════════════════════════════════════════════════════════

def has_pending() -> bool:
    return _pending["kind"] is not None and time.time() - _pending["at"] <= CONFIRM_WINDOW


def cancel() -> str:
    had = _pending["kind"] is not None
    _pending.update(kind=None, detail=None, at=0.0)
    return "Cancelled." if had else "There was nothing to cancel."


def stage_submit(form: str = "") -> str:
    _pending.update(kind="submit", detail=form, at=time.time())
    what = f'the "{form}" form' if form else "this page's form"
    if not COMMAND_PIN:
        return (f"You want me to submit {what}, but no command PIN is set in "
                "config.py, so I can't confirm this.")
    return f"You want me to submit {what}. Type your PIN to confirm."


def stage_download(text: str) -> str:
    if not (text or "").strip():
        return "Download what?"
    _pending.update(kind="download", detail=text, at=time.time())
    if not COMMAND_PIN:
        return (f"You want me to download {text}, but no command PIN is set in "
                "config.py, so I can't confirm this.")
    return f'You want me to download "{text}" from the current page. Type your PIN to confirm.'


def _confined_upload_path(query: str):
    q = (query or "").strip()
    if not q:
        return None
    candidates = []
    if os.path.isabs(q) and os.path.isfile(q):
        candidates.append(q)
    else:
        for root in _UPLOAD_ROOTS:
            p = os.path.join(root, q)
            if os.path.isfile(p):
                candidates.append(p)
    for c in candidates:
        real = os.path.realpath(c)
        for root in _UPLOAD_ROOTS:
            rroot = os.path.realpath(root)
            if real == rroot or real.lower().startswith(rroot.lower() + os.sep):
                return real
    return None


def stage_upload(field: str, query: str) -> str:
    if not (field or "").strip() or not (query or "").strip():
        return "Upload what file, into which field?"
    path = _confined_upload_path(query)
    if not path:
        return f"I can't find {query} in your usual folders, so I won't upload it."
    name = os.path.basename(path)
    _pending.update(kind="upload", detail=(field, path, query), at=time.time())
    if not COMMAND_PIN:
        return (f"You want me to upload {name} into {field}, but no command PIN "
                "is set in config.py, so I can't confirm this.")
    return (f'You want me to upload "{name}" into the {field} field on this '
            f"page. Type your PIN to confirm.")


def _do_submit(bt, form):
    p = _page(bt)
    for l in (p.get_by_role("button", name=_SUBMIT_NAME_RE),
              p.locator('button[type="submit"], input[type="submit"]')):
        if l.count() > 0:
            l.first.click(timeout=5000)
            p.wait_for_load_state("domcontentloaded", timeout=10000)
            return p.title() or p.url
    raise LookupError("no submit control")


def _downloads_dir():
    return os.path.join(os.path.expanduser("~"), "Downloads")


def _unique_path(path):
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{root} ({i}){ext}"):
        i += 1
    return f"{root} ({i}){ext}"


def _write_motw(path, url):
    """Playwright's download.save_as() bypasses Windows' Attachment
    Execution Service, so a browser-triggered download would otherwise
    silently lose the Zone.Identifier tag files_skill.inspect() relies on to
    warn about internet-sourced files. Written in the same shape AES itself
    uses so that existing check keeps working on these downloads too."""
    try:
        with open(path + _ZONE_STREAM, "w", encoding="utf-8") as fh:
            fh.write(f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={url}\r\n")
    except Exception:
        pass


def _do_download(bt, text):
    p = _page(bt)
    loc = None
    for l in (p.get_by_role("link", name=text, exact=False),
              p.get_by_role("button", name=text, exact=False),
              p.get_by_text(text, exact=False)):
        if l.count() > 0:
            loc = l.first
            break
    if loc is None:
        raise LookupError("no match")
    bt._download_expected = True
    try:
        with p.expect_download(timeout=20000) as dl_info:
            loc.click(timeout=5000)
        download = dl_info.value
    finally:
        bt._download_expected = False
    dest = _unique_path(os.path.join(_downloads_dir(), download.suggested_filename or "download"))
    download.save_as(dest)
    _write_motw(dest, download.url)
    return os.path.basename(dest), download.url


def _do_upload(bt, field, path):
    p = _page(bt)
    for l in (p.get_by_label(field, exact=False), p.locator('input[type="file"]')):
        if l.count() > 0:
            l.first.set_input_files(path, timeout=5000)
            return True
    raise LookupError("no match")


def confirm(supplied: str = "") -> str:
    kind = _pending["kind"]
    if not kind:
        return "There's nothing waiting for confirmation."
    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        _pending.update(kind=None, detail=None, at=0.0)
        return "That confirmation expired. Ask me again if you still want it."
    if not COMMAND_PIN:
        _pending.update(kind=None, detail=None, at=0.0)
        return "No command PIN is set in config.py, so I can't confirm this."
    # ARGUS-SEC-011: the SHARED gate, not a bare verify_pin. One wrong-PIN
    # budget covers every confirming skill, so grinding three guesses here,
    # three on a staged shutdown and three on a service restart stops
    # multiplying the budget. Handles both a migrated PBKDF2 hash and a
    # legacy plaintext PIN, with compare_digest in both branches.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        return "That's not the right PIN. Type it again, or say cancel."

    detail = _pending["detail"]
    _pending.update(kind=None, detail=None, at=0.0)

    if kind == "submit":
        try:
            title = _get_thread().call(_do_submit, detail)
        except LookupError:
            return "I couldn't find a submit control on this page."
        except Exception as e:
            return f"I couldn't submit that: {_err(e)}"
        _audit("browser_submit", (detail or "page form")[:160])
        _record_verification("submit", detail, title=title)
        return f"Submitted. Now on {title}."

    if kind == "download":
        try:
            name, url = _get_thread().call(_do_download, detail)
        except LookupError:
            return f"I don't see anything called {detail} to download."
        except Exception as e:
            return f"I couldn't download that: {_err(e)}"
        _downloads_log.append((name, url, time.time()))
        _audit("browser_download", f"{name} from {url}"[:160])
        _record_verification("download", detail, filename=name)
        return f"Downloaded {name}."

    if kind == "upload":
        field, path, query = detail
        try:
            _get_thread().call(_do_upload, field, path)
        except LookupError:
            return f"I don't see a field called {field} on this page."
        except Exception as e:
            return f"I couldn't upload that: {_err(e)}"
        _audit("browser_upload", f"{os.path.basename(path)} -> {field}"[:160])
        _record_verification("upload", f"{field}|{query}",
                             filename=os.path.basename(path))
        return f"Uploaded {os.path.basename(path)}."

    return "That confirmation no longer makes sense."


def _audit(event: str, detail: str):
    try:
        import security
        security.audit(event, detail, "ok")
    except Exception:
        pass


def downloads() -> str:
    if not _downloads_log:
        return "Nothing has been downloaded through the browser this session."
    return "; ".join(f"{name} from {url}" for name, url, _ in _downloads_log[-8:])


# ═══════════════════════════════════════════════════════════════════════════
# BOOKMARKS -- ARGUS's own list, not your browser's. See module docstring.
# ═══════════════════════════════════════════════════════════════════════════

def _load_bookmarks() -> list:
    try:
        with open(_BOOKMARKS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_bookmarks(items: list) -> bool:
    try:
        with open(_BOOKMARKS_PATH, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        return True
    except Exception:
        return False


def _do_current(bt):
    if bt._browser_ctx is None:
        return None
    p = _page(bt)
    return p.title() or "untitled", p.url


def bookmark_add(label: str = "") -> str:
    try:
        info = _get_thread().call(_do_current)
    except Exception as e:
        return f"I couldn't read the current page: {_err(e)}"
    if not info:
        return "No page is open in the browser to bookmark."
    title, url = info
    items = _load_bookmarks()
    items.append({"label": (label or title)[:80], "url": url, "at": time.time()})
    _save_bookmarks(items)
    return f"Saved {label or title} to your bookmarks."


def bookmarks_list() -> str:
    items = _load_bookmarks()
    if not items:
        return "You have no saved bookmarks yet."
    return "; ".join(i["label"] for i in items[-10:])


def bookmark_remove(query: str) -> str:
    if not (query or "").strip():
        return "Remove which bookmark?"
    items = _load_bookmarks()
    q = query.lower()
    keep = [i for i in items if q not in i["label"].lower()]
    if len(keep) == len(items):
        return f"I don't have a bookmark matching {query}."
    _save_bookmarks(keep)
    return f"Removed {len(items) - len(keep)} bookmark(s) matching {query}."


# ═══════════════════════════════════════════════════════════════════════════
# HISTORY -- this session only. See module docstring.
# ═══════════════════════════════════════════════════════════════════════════

def history_search(query: str = "") -> str:
    if not _history:
        return "Nothing visited yet this session."
    items = _history
    if query:
        q = query.lower()
        items = [h for h in items if q in h["title"].lower() or q in h["url"].lower()]
    if not items:
        return f"Nothing in this session's browsing matches {query}."
    return "; ".join(h["title"] for h in items[-8:])
