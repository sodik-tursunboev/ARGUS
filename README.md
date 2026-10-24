# ARGUS | Windows assistant by Sodik Tursunboev
ARGUS is a local-first Windows assistant with voice interaction, a Svelte HUD,
a FastAPI control plane, and guarded host actions. This repository publishes
the general source code and the runtime media needed by the HUD. Local
configuration, user data, credentials and model weights are excluded.

It is designed around a simple boundary: intelligence can propose work; only backend policy, authentication, grants, and execution controls may authorize it.

## Capabilities

- **V2 HUD:** Dashboard, Tasks, Agents, Modules, Security, Logs, Tools, About, Settings, notifications, command palette, detail drawers, and a persistent command surface.
- **Voice pipeline:** wake handling, voice activity detection, STT, intent routing, response generation, and TTS with worker-process separation.
- **Assistant capabilities:** system, app, window, files, browser, research, document, network, automation, privacy, security, and local productivity actions through registered skill modules.
- **Agent kernel:** owner-approved, typed goals and plans; independently authorized steps; observations; bounded retries; and constrained replanning.
- **Security model:** loopback token authentication, freshness and confirmation gates, action-bound grants, zero-trust step-up/refusal, sandboxing, egress policy, audit integrity, tamper detection, safe mode, and recovery controls.

## Documentation

- [Specification](docs/SPECIFICATION.md) — product scope, behavior and API contracts.
- [Local API](docs/API.md) — endpoint inventory and transport requirements.
- [Architecture](docs/ARCHITECTURE.md) — implementation, data flow and build layout.
- [Features](docs/FEATURES.md) — user-facing capability groups and availability.
- [Security model](docs/SECURITY_MODEL.md) — threat model, enforced boundaries and limits.
- [Setup and build](docs/BUILD.md) — source installation and packaging.
- [Security policy](SECURITY.md) — private vulnerability reporting.
- [Phone setup](PHONE.md) — optional Twilio integration.

## Architecture

```text
argus.py
  ├─ boot.py / integrity.py / sandbox.py
  ├─ main.py — FastAPI loopback service and HUD API
  │   ├─ router.py — intent → policy → dispatch
  │   ├─ agent/ — goal, plan, observation, verifier, budget, replan kernel
  │   ├─ skills/ — registered capability modules
  │   └─ threatmon/ — defensive monitoring
  ├─ listener.py — voice and wake pipeline
  │   └─ ipc.py → stt_worker.py / tts_worker.py
  └─ hud-v2/ — Svelte 5 / Vite desktop HUD
```

## Quick start

On Windows, install Python, Node.js and npm. Install Ollama if you want
local-model routing and conversation. Then create a local environment:

```powershell
py -3 -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config.example.py config.py
.\venv\Scripts\python.exe manage_secrets.py set-pin
cd hud-v2
npm ci
npm run build
cd ..
```

The public `config.example.py` has an empty command PIN. The copied `config.py`
is ignored by Git. Place the generated salted hash in local `config.py` before
using protected actions. Cloud keys belong in environment variables or the
local secrets store, never in Git.

The source release omits locally stored voice model weights and the external
3D office asset pack. Install voice models under `voices/` according to
`config.PIPER_MODEL_PATH` before building the Windows executable. The 3D
office scene still renders its code-generated geometry when the external
models are absent, with reduced visual detail. The ARGUS city
models and the HUD core media required at runtime are included.

To start ARGUS from the source checkout:

```powershell
.\venv\Scripts\Activate.ps1
python argus.py
```

The local venv is the canonical interpreter for this source release. Run
the app through it. `requirements.lock` records versions tested
on the original installation; it is a direct-dependency list, not a full
transitive lock.

For HUD work:

```powershell
cd hud-v2
npm run dev
npm run build
npx tsc --noEmit
```

Build the Windows package after validating your local changes:

```powershell
.\venv\Scripts\python.exe build_exe.py
```

This is a source release. It does not include a signed installer, voice model
weights or the optional external 3D office asset pack. See
[Setup and build](docs/BUILD.md) for prerequisites and limitations.

## Licence

GPL-3.0-or-later. Copyright (C) 2026 Sodik Tursunboev. See [LICENSE](LICENSE)
and [COPYRIGHT.md](COPYRIGHT.md).
