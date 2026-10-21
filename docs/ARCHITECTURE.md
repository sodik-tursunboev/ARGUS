# ARGUS architecture

This document describes the implementation in this source release. It is a map of
the code and trust boundaries, not a deployment diagram for other machines.
ARGUS is a Windows desktop application whose UI and voice path talk to a local
Python service. Hosted services are optional integrations.

## Technology and process layout

| Part | Implementation | Responsibility |
| --- | --- | --- |
| Desktop entry | argus.py, boot.py | Starts and checks the local components. |
| Local service | main.py, FastAPI/Uvicorn | Serves the HUD, REST endpoints and WebSocket events on loopback. |
| HUD | hud-v2/, Svelte 5, TypeScript, Vite, Three.js | Presents commands, tasks, agents, telemetry and security state. |
| Voice | listener.py, ipc.py, stt_worker.py, tts_worker.py | Wake handling, speech input and speech output in separated workers. |
| Routing | intent.py, router.py, ollama_client.py | Matches direct commands and routes ambiguous requests with a local model. |
| Capabilities | skills/, skills/registry.py | Implements named actions exposed to the router. |
| Agent work | agent/, agents/ | Stages bounded goals, team work, observations and verification. |
| Protection | auth.py, grants.py, security.py, security_state.py, netpolicy.py, sandbox.py, integrity.py, plugins.py | Enforces access, execution, egress, integrity and audit rules. |
| Monitoring | threatmon/ | Collects defensive signals from the host. |

The normal deployment is a single Windows account and a local HTTP service.
The browser-based HUD can also be served by the same service. It is not a
multiuser server and should not be exposed on a network interface.

## Command flow

~~~text
HUD or microphone
  -> local FastAPI service
  -> intent rules or local Ollama router
  -> named skill/action and normalized target
  -> policy, authentication and optional confirmation
  -> action-bound grant check immediately before execution
  -> skill implementation
  -> audit event, result and optional observation
  -> HUD, WebSocket or speech response
~~~

The model proposes a route or plan. It does not select its own permission
level. The authorization table in auth.py is keyed by the actual skill and
action that router.py dispatches. Unrecognized actions are handled
conservatively. A multi-step plan is validated, bounded and staged for owner
approval before steps run. Each step passes the normal dispatch gate.

The agent kernel in agent/ holds goal, plan, budget, observation and verifier
types. The agents/ package contains named local specialists, a shared model
runtime, team orchestration and a controlled optional cloud specialist path.
Agent output is advice or a proposed action; it is not an execution credential.

## Local transport and data

main.py serves the V2 HUD at /v2/, a WebSocket at /ws and REST endpoints for
commands, status, telemetry, settings, agent work and security reporting.
The service binds to loopback. A per-session bearer token is required for
nonpublic REST endpoints and for the WebSocket handshake. Browser origins are
restricted to the local HUD and listed development origins. Public routes are
limited to health and static presentation assets.

paths.py separates packaged read-only resources from writable runtime data.
Configuration is copied from config.example.py to an ignored local config.py.
The configured vault path holds local state such as memory and audit material;
its contents are not part of this repository. A session token is published to
a user-scoped local file for the HUD. Python virtual environments, model
weights, generated logs, databases and bundled outputs are also excluded.

## Model and external-service boundary

Ollama runs locally by default and is used for conversation and routing.
Whisper and Piper provide local speech input and output when their models and
dependencies are installed. Cloud model providers, web research, weather,
phone calls and messaging are separate capabilities. Cloud use depends on
configuration and policy. netpolicy.py classifies outbound access by
component and denies unknown components by default; skills/cloud_gate.py
applies additional data-scope restrictions to cloud requests.

An operator should review the destination and data class of any optional
integration before enabling it. The absence of a configured integration
must not be interpreted as evidence that a capability was exercised.

## HUD and packaged build

The HUD is built with Vite into hud-v2/dist. Its source includes dashboard
components, typed stores, a 3D city/office view and code-generated fallback
geometry. The committed HUD media and city models are runtime assets. A
separate external office asset pack and local voice model weights are not
redistributed here.

build_exe.py performs a preflight, requires a complete Vite output and
packages the Windows application with PyInstaller. ARGUS.spec and
lsass-helper.spec are build specifications. The optional LSASS helper is a
separate elevated process; the main orchestrator drops unnecessary Windows
privileges at startup. Building an executable does not imply it is signed or
safe to run without local review.

See [Specification](SPECIFICATION.md), [Features](FEATURES.md),
[Setup and build](BUILD.md) and [Security model](SECURITY_MODEL.md).
