"""
ARGUS - Install checker.

Reports everything missing in one pass, instead of discovering it one
ImportError at a time.

Run:  python doctor.py
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import importlib
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

ROOT_FILES = [
    "argus.py", "config.py", "main.py", "router.py", "intent.py", "brain.py",
    "listener.py", "tts.py", "ollama_client.py", "security.py", "paths.py",
    "build_exe.py", "install_startup.py", "requirements.txt",
    # Stage 2 process tree: the voice process and its two model workers. Absent
    # from this list until now, so a missing one showed up as a runtime crash
    # instead of here, which is the whole point of this file.
    "ipc.py", "stt_worker.py", "tts_worker.py", "groq_client.py",
    # Imported at load by brain, router, main and all three model clients (request
    # trace, cloud-call budget, runtime truth), so a missing copy is an import
    # crash at startup -- listed so it is reported here instead.
    "route_trace.py",
]

SKILL_FILES = [
    "__init__.py", "anomaly_skill.py", "apps_skill.py", "browser_skill.py",
    "calc_skill.py", "clarify_skill.py", "cleanup_skill.py", "cloud_gate.py",
    "context_skill.py", "control_skill.py", "dev_skill.py", "diagnostics.py",
    "document_skill.py", "email_skill.py", "env_skill.py", "files_skill.py",
    "followup_skill.py", "health_skill.py", "history_store.py",
    "knowledge_skill.py", "monitor_skill.py", "network_skill.py",
    "passive_memory.py", "pc_skill.py", "phone_skill.py", "power_skill.py",
    "privacy_skill.py", "proactive_skill.py", "profile_skill.py",
    "registry.py", "research_skill.py", "scheduler_skill.py",
    "security_log_skill.py", "service_skill.py", "social_skill.py",
    "storage_skill.py", "system_ext_skill.py", "system_skill.py",
    "telemetry.py", "timer_skill.py", "vault_skill.py",
    "vision_skill.py", "weather_skill.py", "web_skill.py",
    "window_skill.py", "zt_skill.py",
]

PACKAGES = [
    ("fastapi", "fastapi"), ("uvicorn", "uvicorn"), ("requests", "requests"),
    ("pydantic", "pydantic"), ("faster_whisper", "faster-whisper"),
    ("piper", "piper-tts"), ("sounddevice", "sounddevice"), ("numpy", "numpy"),
    ("webview", "pywebview"), ("psutil", "psutil"), ("pygetwindow", "pygetwindow"),
    ("pyperclip", "pyperclip"), ("PIL", "Pillow"), ("keyboard", "keyboard"),
    ("plyer", "plyer"), ("comtypes", "comtypes"), ("pycaw", "pycaw"),
    ("screen_brightness_control", "screen-brightness-control"),
    ("yt_dlp", "yt-dlp"), ("ddgs", "ddgs"),
]

GREEN, RED, YELLOW, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def ok(msg):
    print(f"  {GREEN}[ok]{RESET} {msg}")


def bad(msg):
    print(f"  {RED}[MISSING]{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}[warn]{RESET} {msg}")


def main():
    print("\nARGUS install check\n" + "=" * 52)
    problems = []

    print("\nCore files:")
    missing_root = [f for f in ROOT_FILES if not os.path.exists(os.path.join(ROOT, f))]
    if missing_root:
        for f in missing_root:
            bad(f)
        problems.append(f"{len(missing_root)} core file(s) missing from {ROOT}")
    else:
        ok(f"all {len(ROOT_FILES)} present")

    print("\nSkills:")
    skills_dir = os.path.join(ROOT, "skills")
    if not os.path.isdir(skills_dir):
        bad("skills/ folder doesn't exist")
        problems.append("skills/ folder missing")
    else:
        missing_skills = [f for f in SKILL_FILES
                          if not os.path.exists(os.path.join(skills_dir, f))]
        if missing_skills:
            for f in missing_skills:
                bad(f"skills/{f}")
            problems.append(f"{len(missing_skills)} skill file(s) missing")
        else:
            ok(f"all {len(SKILL_FILES)} present")

    print("\nHUD:")
    if os.path.exists(os.path.join(ROOT, "hud", "index.html")):
        ok("hud-v2/dist/index.html")
    else:
        bad("hud-v2/dist/index.html")
        problems.append("HUD missing")

    print("\nVoice model:")
    voices = os.path.join(ROOT, "voices")
    if not os.path.isdir(voices):
        bad("voices/ folder doesn't exist")
        problems.append("voices/ folder missing")
    else:
        onnx = [f for f in os.listdir(voices) if f.endswith(".onnx")]
        if not onnx:
            bad("no .onnx voice file in voices/")
            problems.append("no voice model")
        else:
            ok(f"found {onnx[0]}")
            try:
                sys.path.insert(0, ROOT)
                import config
                want = os.path.join(ROOT, config.PIPER_MODEL_PATH.replace("/", os.sep))
                if os.path.exists(want):
                    ok("config.py path matches")
                else:
                    bad(f"config.py wants {config.PIPER_MODEL_PATH}, which isn't there")
                    problems.append("PIPER_MODEL_PATH mismatch in config.py")
            except Exception as e:
                bad(f"config.py won't load: {e}")
                problems.append("config.py broken")

    print("\nSecrets at rest:")
    try:
        sys.path.insert(0, ROOT)
        import config
        import secrets_store
        try:
            from config_secrets import GROQ_API_KEY as _plain
        except ImportError:
            _plain = ""
        src = secrets_store.secret_source("GROQ_API_KEY", _plain)
        if src == "PLAINTEXT in config":
            warn("GROQ_API_KEY is in plaintext in config_secrets.py")
            warn("  move it:  python manage_secrets.py set-groq-key")
        elif src == "not set":
            warn("GROQ_API_KEY not set — cloud routing is off")
        else:
            ok(f"GROQ_API_KEY from {src}")

        if secrets_store.pin_is_hashed(getattr(config, "COMMAND_PIN", "")):
            ok("COMMAND_PIN is stored as a salted hash")
        elif getattr(config, "COMMAND_PIN", ""):
            warn("COMMAND_PIN is plaintext in config.py")
            warn("  hash it:  python manage_secrets.py set-pin")
    except Exception as e:
        warn(f"couldn't check secret storage: {e}")

    print("\nSecurity:")
    try:
        import config
        if getattr(config, "COMMAND_PIN", ""):
            ok("COMMAND_PIN is set")
        else:
            warn("COMMAND_PIN is empty in config.py")
            warn('shutdown/restart/sleep/sign-out will fail closed -- ARGUS will')
            warn('say "no command PIN is set" and refuse to confirm, until you set one')
    except Exception as e:
        warn(f"couldn't check COMMAND_PIN: {e}")

    print("\nPackages:")
    missing_pkgs = []
    for mod, pip_name in PACKAGES:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing_pkgs.append(pip_name)
    if missing_pkgs:
        for p in missing_pkgs:
            bad(p)
        problems.append(f"{len(missing_pkgs)} package(s) missing")
    else:
        ok(f"all {len(PACKAGES)} installed")

    print("\nGPU acceleration:")
    try:
        import glob
        import site
        roots = [os.path.join(ROOT, "venv", "Lib", "site-packages")]
        try:
            roots.extend(site.getsitepackages())
        except Exception:
            pass
        dlls = []
        for r in roots:
            dlls += glob.glob(os.path.join(r, "nvidia", "cublas", "bin", "cublas64_*.dll"))
        if dlls:
            ok(f"CUDA libraries found ({os.path.basename(dlls[0])})")
        else:
            warn("no CUDA libraries — ARGUS will run speech on CPU (slower but fine)")
            warn("to enable GPU: pip install nvidia-cublas-cu12 nvidia-cudnn-cu12")
    except Exception as e:
        warn(f"couldn't check CUDA: {e}")

    print("\nOllama:")
    try:
        import requests
        import config
        r = requests.get(f"{config.OLLAMA_HOST}/api/tags", timeout=4)
        models = [m["name"] for m in r.json().get("models", [])]
        if models:
            ok(f"running — {len(models)} model(s): {', '.join(models[:4])}")
        if config.OLLAMA_MODEL in models:
            ok(f"{config.OLLAMA_MODEL} is pulled")
        else:
            bad(f"config.py wants '{config.OLLAMA_MODEL}' but Ollama doesn't have it")
            problems.append(f"run: ollama pull {config.OLLAMA_MODEL}")
        if config.OLLAMA_ROUTER_MODEL in models:
            ok(f"{config.OLLAMA_ROUTER_MODEL} (router) is pulled")
        else:
            bad(f"config.py wants router model '{config.OLLAMA_ROUTER_MODEL}' but Ollama doesn't have it")
            problems.append(f"run: ollama pull {config.OLLAMA_ROUTER_MODEL}")
    except Exception:
        bad("can't reach Ollama — is it running?")
        problems.append("Ollama unreachable")

    # Deliberately a REAL API call, not a config read. groq_client.available()
    # only tests that the key string is non-empty -- it returns True for a
    # typo'd, revoked or expired key, so "available" is not the same as
    # "working" and checking it would give false confidence. The only way to
    # know Groq answers is to ask it.
    print("\nCloud (Groq):")
    try:
        import config
        import groq_client

        if not config.CLOUD_ENABLED:
            warn("no GROQ_API_KEY set in config_secrets.py — cloud routing is OFF")
            warn(f"general questions are answered by local {config.OLLAMA_MODEL},")
            warn("which is a far smaller model. Add a key to enable cloud chat.")
        else:
            ok(f"key configured, model {config.GROQ_MODEL}")
            try:
                reply = groq_client.chat(
                    "Reply with exactly one word: ready", "ping")
                if reply and reply.strip():
                    ok(f"live API call succeeded -> {reply.strip()[:40]!r}")
                else:
                    warn("Groq accepted the call but returned nothing")
            except groq_client.GroqUnavailable as e:
                # groq_client collapses every failure to one exception type
                # carrying a sanitized category (never the raw text, which for
                # an auth error can contain the key itself).
                reason = str(e)
                if reason == "authentication_failed":
                    bad("Groq REJECTED the key — wrong, revoked, or expired")
                    problems.append("Groq key rejected — fix config_secrets.py")
                elif reason == "rate_limited":
                    warn("rate limited right now — the key itself is valid")
                    warn("ARGUS backs off for 2 minutes then retries on its own")
                elif reason == "timeout":
                    warn("timed out reaching Groq — slow or blocked network")
                    warn("not fatal: ARGUS falls back to the local model")
                else:
                    bad(f"Groq call failed: {reason}")
                    problems.append(f"Groq unreachable ({reason})")
    except Exception as e:
        warn(f"couldn't check Groq: {e}")

    print("\n" + "=" * 52)
    if problems:
        print(f"{RED}{len(problems)} problem(s):{RESET}")
        for p in problems:
            print(f"  - {p}")
        print("\nFix these, then run: python argus.py")
        sys.exit(1)

    print(f"{GREEN}Everything checks out. Run: python argus.py{RESET}")


if __name__ == "__main__":
    main()
