# ARGUS features

This catalog groups implemented source modules. Availability depends on the
Windows environment, configured models, permissions, installed integrations
and the current security state. A listed module is not a promise that every
action is enabled by default.

## Interaction and local AI

- Typed commands through the HUD and local service, with a streamed response
  path for conversational output.
- Wake-word voice interaction, speech-to-text, local response generation and
  text-to-speech through isolated workers.
- Direct intent rules for common commands and local-model routing for requests
  that require classification.
- Follow-up resolution, clarification, command chaining within a read-only
  allowlist, and answer caching for suitable responses.
- Optional hosted model tiers with a separate cloud data-scope gate. The
  default local path uses Ollama; hosted features require explicit setup.

## Desktop and productivity

- Launch, close and list applications; focus and arrange windows.
- Timers, reminders, schedules, watched conditions and persistent goals.
- Volume, brightness, microphone and clipboard controls.
- File discovery and content search, metadata, permissions, copy, move,
  rename, compression, restore and staged deletion.
- System status, storage analysis, process information, health checks,
  timezone and power actions.
- Browser interaction, web lookup, research, document handling and email
  actions where their dependencies and credentials are configured.
- Local preferences, remembered profile facts, history and vault notes.

Actions that alter files or machine state have their own authorization and
confirmation levels. The scope of a feature can also be constrained by a
particular skill's implementation.

## Agents and plans

- A typed agent kernel for goals, plan state, budgets, observations and
  independent verifiers.
- Named local specialist agents that share a configured local model runtime.
- Team decomposition, bounded jobs, handoffs, cancellation, evidence and
  status reporting.
- Dynamic specialist proposals under a governor with closed capability and
  data-class vocabularies.
- A staged plan path that validates proposed steps and waits for owner
  approval before execution. Controlled replanning can propose a new staged
  alternative after failure; it does not run that alternative on its own.
- An agent manager, inbox and academy surfaces in the HUD/API for tracking
  work and operator interaction.

## HUD

- Dashboard, task and agent views, command surface, notifications and
  settings.
- Security, audit, diagnostics, telemetry and capability panels.
- A 3D city and office visualization driven by local state, with
  code-generated fallback geometry when optional external models are absent.
- REST and WebSocket adapters that keep the UI tied to the local service.

The 3D view is an interface and visualization. It does not give agents a new
permission path or claim that decorative scene motion represents real work.

## Defensive and privacy features

- Central authorization levels, session lock, optional additional factors,
  confirmation and short-lived action-bound grants.
- Loopback service with token checks, allowed origins, bounded request bodies,
  rate limits and restrictive response headers.
- Network egress classes with deny-by-default behavior for unknown
  components.
- Integrity verification, audit-chain checks, security state transitions,
  safe mode, lockdown and owner recovery.
- Defensive monitoring for selected persistence, process, USB, privacy,
  network configuration and LSASS-handle signals.
- A separate optional elevated LSASS helper. The main assistant does not
  need to retain its privileges to perform ordinary work.

The monitors have explicit coverage gaps and sampling limits. See
[Security model](SECURITY_MODEL.md) before relying on them.

## Optional integrations

The source contains optional paths for cloud models, web services, Twilio
phone calls and messaging. They require local credentials or configuration.
The repository does not contain account credentials, a user profile, voice
model weights or private runtime state.

The exact machine-readable capability and action list is maintained in
skills/registry.py. An action also needs a real dispatch path and a matching
authorization rule before it can run.
