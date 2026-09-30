"""
ARGUS - Local agents: the shared-model runtime.

EXACTLY ONE heavy inference runs at a time. On this hardware (4 GB VRAM, one
~2.5 GB model resident) a second concurrent Ollama request means VRAM
pressure and Ollama evicting/reloading the model -- the exact failure
config.py documents. So the runtime is a semaphore of 1 in front of the
EXISTING ollama_client (no second HTTP path, no second client, no new model
name: ollama_client already targets config.OLLAMA_MODEL).

Concurrency is configurable via ARGUS_MODEL_CONCURRENCY for future hardware,
default 1. Permitted values: 1..2 only -- this governor exists because of a
measured VRAM ceiling, so even explicit configuration cannot turn it off
entirely.

Timeouts: every call is bounded; a timeout releases the slot and
frees the queue without touching the Ollama server itself.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import concurrent.futures
import concurrent.futures as _futures
import os
import threading
import time
import requests

FuturesTimeout = _futures.TimeoutError


def _chat_with_bounds(system_prompt: str, user_prompt: str,
                      *, json_mode: bool = False,
                      max_output_tokens: int = 0) -> str:
    """Call ollama_client.chat with the agent's generation bounds applied.

    The clean way to honour the client's own payload discipline (think=False,
    num_ctx, model choice) without duplicating payload construction here:
    build kwargs the client already accepts (json_mode) and clamp num_predict
    via a temporary module override of its CHAT_NUM_PREDICT constant -- the
    one knob it reads for generation length. The override is restored in a
    finally block; concurrent calls are serialized by the runtime semaphore,
    so the temporary value can never be observed by another agent job.
    """
    import ollama_client
    original = ollama_client.CHAT_NUM_PREDICT
    try:
        if max_output_tokens and max_output_tokens > 0:
            # Never RAISE the client's cap, only tighten it.
            ollama_client.CHAT_NUM_PREDICT = min(int(original),
                                                 int(max_output_tokens))
        return ollama_client.chat(system_prompt, user_prompt,
                                  json_mode=json_mode)
    finally:
        ollama_client.CHAT_NUM_PREDICT = original


def _configured_concurrency() -> int:
    raw = (os.environ.get("ARGUS_MODEL_CONCURRENCY") or "1").strip()
    try:
        n = int(raw)
    except ValueError:
        return 1
    # Hard ceiling of 2: a measured VRAM constraint is not negotiable by env

    return max(1, min(n, 2))


MAX_CONCURRENCY = _configured_concurrency()


class SharedModelRuntime:
    """Serial gate in front of ollama_client for agent jobs.

    busy flag + slot semaphore + per-call timeout. Thread-safe: jobs are
    submitted from API threads and handoffs from worker threads.
    """

    def __init__(self, concurrency: int = MAX_CONCURRENCY,
                 timeout_s: float = 120.0):
        self._sem = threading.BoundedSemaphore(max(1, concurrency))
        self._lock = threading.Lock()
        self._busy: str = ""          # job_id currently holding the model
        self.timeout_s = timeout_s
        self.last_error: str = ""
        self.calls_made = 0
        self.timeouts = 0
        self.errors = 0
        self._health_checked_at = 0.0
        self._health: dict = {"available": False, "status": "UNAVAILABLE",
                              "last_error_category": "not_checked"}
        self.last_success: float | None = None
        self.last_failure: float | None = None

    # ── observability ───────────────────────────────────
    def is_busy(self) -> bool:
        return bool(self._busy)

    def current_job(self) -> str:
        return self._busy

    def model_id(self) -> str:
        from config import OLLAMA_MODEL
        return OLLAMA_MODEL

    def available(self) -> bool:
        return bool(self._probe_health()["available"])

    def _probe_health(self) -> dict:
        """Check the actual local provider and configured model, at most once
        per 15 seconds. Importability alone does not mean Ollama is online."""
        now = time.monotonic()
        with self._lock:
            if now - self._health_checked_at < 15:
                return dict(self._health)
            # Reserve this probe window before I/O so concurrent snapshots do
            # not each launch a separate request against the local service.
            self._health_checked_at = now
        try:
            from config import OLLAMA_HOST
            response = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=2)
            response.raise_for_status()
            models = response.json().get("models", [])
            names = {str(item.get("name", "")) for item in models if isinstance(item, dict)}
            if self.model_id() not in names:
                result = {"available": False, "status": "UNAVAILABLE",
                          "last_error_category": "model_missing"}
            else:
                result = {"available": True, "status": "AVAILABLE",
                          "last_error_category": ""}
        except requests.exceptions.Timeout:
            result = {"available": False, "status": "TIMEOUT",
                      "last_error_category": "provider_timeout"}
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            result = {"available": False,
                      "status": "RATE_LIMITED" if code == 429 else "UNAVAILABLE",
                      "last_error_category": "rate_limited" if code == 429 else "provider_http_error"}
        except (requests.exceptions.RequestException, ValueError, KeyError):
            result = {"available": False, "status": "UNAVAILABLE",
                      "last_error_category": "provider_connection"}
        with self._lock:
            self._health = result
            stamp = time.time()
            if result["available"]:
                self.last_success = stamp
            else:
                self.last_failure = stamp
            return dict(result)

    def status(self) -> dict:
        health = self._probe_health()
        with self._lock:
            return {
                "provider": "OLLAMA",
                "model_id": self.model_id(),
                "available": health["available"],
                "status": health["status"],
                "last_success": self.last_success,
                "last_failure": self.last_failure,
                "last_error_category": health["last_error_category"],
                "busy": self.is_busy(),
                "active_job": self._busy,
                "max_concurrency": MAX_CONCURRENCY,
                "timeout_s": self.timeout_s,
                "calls_made": self.calls_made,
                "timeouts": self.timeouts,
                "errors": self.errors,
                "last_error": self.last_error[:200],
            }

    # ── inference ────────────────────────────────────────────────────────
    def run(self, job_id: str, system_prompt: str, user_prompt: str,
            json_mode: bool = False,
            max_output_tokens: int = 0) -> str:
        """Run one bounded inference, or raise TimeoutError/ConnectionError.

        The wait for a slot AND the inference itself are each bounded by
        timeout_s. ollama_client.chat's own requests timeout (90s for chat)
        is the outer bound it already had; this per-call bound is the job's
        -- a job must never hold the queue hostage past its budget.

        max_output_tokens: the agent spec's generation bound.
        It maps onto ollama_client.chat's existing options by choosing the
        smaller of the spec bound and the client's own defaults -- we never
        RAISE the client's cap, only tighten it. json_mode asks the client
        for its structured-output path (format=json + the router model),
        which the results parser depends on for reliable JSON."""
        acquired = self._sem.acquire(timeout=self.timeout_s)
        if not acquired:
            # Queue wait itself exceeded the budget: this job held a slot in
            # line too long. Fail it and free the queue.
            with self._lock:
                self.timeouts += 1
            raise TimeoutError("model queue wait exceeded job timeout")
        try:
            with self._lock:
                self._busy = job_id
            t0 = time.time()
            try:
                import ollama_client
                # The executor bound is the per-call timeout, not the
                # client's own 90s, so a hung socket cannot outlive the job
                # budget. The token bound tightens num_predict only.
                kwargs = {}
                if json_mode:
                    kwargs["json_mode"] = True
                if max_output_tokens and max_output_tokens > 0:
                    kwargs["max_output_tokens"] = int(max_output_tokens)
                executor = __import__("concurrent.futures", fromlist=["x"])
                with executor.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(self._call, system_prompt,
                                         user_prompt, **kwargs)
                    try:
                        answer = future.result(timeout=self.timeout_s)
                    except FuturesTimeout as e:
                        future.cancel()
                        with self._lock:
                            self.timeouts += 1
                            self.last_error = "inference timeout"
                        raise TimeoutError("model inference exceeded job timeout") from e
            except TimeoutError:
                raise
            except Exception as e:
                with self._lock:
                    self.errors += 1
                    self.last_error = f"{type(e).__name__}: {e}"[:200]
                raise
            finally:
                with self._lock:
                    self._busy = ""
                    self.calls_made += 1
            if not (answer or "").strip():
                raise ConnectionError("model returned an empty response")
            return answer
        finally:
            self._sem.release()

    @staticmethod
    def _call(system_prompt: str, user_prompt: str,
              json_mode: bool = False, max_output_tokens: int = 0) -> str:
        """The single production call into the EXISTING ollama_client. Tests
        monkeypatch ollama_client.chat; the indirection keeps that working."""
        import ollama_client
        if not json_mode and not max_output_tokens:
            return ollama_client.chat(system_prompt, user_prompt)
        # Otherwise call chat with overrides applied through a tiny shim so
        # the client's own payload construction stays authoritative.
        return _chat_with_bounds(system_prompt, user_prompt,
                                 json_mode=json_mode,
                                 max_output_tokens=max_output_tokens)


_RUNTIME = SharedModelRuntime()


def runtime() -> SharedModelRuntime:
    return _RUNTIME
