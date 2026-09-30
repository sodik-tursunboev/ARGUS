"""PREVIEW-ONLY launcher: orchestrator + HUD, no voice/model stack.

This is NOT argus.py and must not become it. The real launcher starts the
voice listener, speech workers, HUD WebView and threat-monitored sampler;
the preview harness runs only the FastAPI orchestrator on 127.0.0.1:8420 so
the HUD page can be served and exercised in a browser without a microphone,
a GPU, or Whisper/Piper loaded.

What is deliberately SKIPPED here, and why:
  sandbox.drop_privileges  - argus.py does this in-process; harmless either
                             way, but the preview is a dev harness, so we
                             keep parity where it is free and skip nothing
                             that would change security posture.
  listener.py / ipc.py     - audio stack; needs a microphone and model files.
  hud WebView window       - the browser preview tab IS the window here.

The security layer is NOT relaxed: auth starts LOCKED, the token middleware
and rate limits are active, and /unlock still demands the real command PIN.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import sys

import paths

paths.ensure_std_streams()

if not paths.is_frozen():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

import uvicorn

from main import app  # noqa: E402  (main.py boots auth/integrity/sampler)


def main() -> None:
    port = int(os.environ.get("ARGUS_PREVIEW_PORT", "8420"))
    print(f"[preview] orchestrator on http://127.0.0.1:{port} "
          f"(HUD at /, token-gated; no voice stack)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
