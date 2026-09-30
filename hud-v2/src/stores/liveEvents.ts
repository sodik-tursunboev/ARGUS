import { get } from 'svelte/store';
import { HudWebSocket } from '../services/websocket';
import { publishAgentEnvelope, noteOfficeLinkDegraded } from '../lib/agentEventsBus';
import { agentOffice, refreshAgentOffice } from './agentOffice';
import { teamOffice, refreshTeamOffice, markTeamOfficeDegraded } from './teamOffice';
import { agentManager, refreshManager, refreshInbox } from './agentManager';
import type { HudEventEnvelope } from '../types/argus';
import { agent, setAgentSnapshot, type AgentState, type VoiceMode } from './agent';
import { connection } from './connection';
import { security, patchSecurity, type SecurityPosture } from './security';
import { tasks, setTaskSnapshot } from './tasks';
import type { ArgusTask, ArgusTaskStep, TaskLifecycleStatus, TaskStepStatus } from '../types/argus';
import { telemetry } from './telemetry';
import { snapshotStatus, threatReport } from './snapshotView';
import { addEvent, secret } from './events';
import { notify } from './notifications';
import { requestAuthFromBackend, logAuthEvent } from './authFlow';

let client: HudWebSocket | null = null;
let telemetryFrame: number | null = null;
let queuedTelemetry: Record<string, number | boolean> = {};
const runtimeToken = (window as Window & { __ARGUS_TOKEN__?: string }).__ARGUS_TOKEN__;
const defaultUrl = runtimeToken
  ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`
  : undefined;
const configuredUrl = (import.meta.env.VITE_ARGUS_WS_URL as string | undefined) ?? defaultUrl;
const states = new Set<AgentState>(['booting','standby','listening','understanding','planning','waiting_auth','executing','verifying','completed','warning','blocked','lockdown','error']);
const voiceModes = new Set<VoiceMode>(['idle','listening','processing','speaking','disabled']);
const postures = new Set<SecurityPosture>(['unknown','normal','degraded','warning','critical','blocked','lockdown','recovery']);
const number = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const string = (value: unknown): value is string => typeof value === 'string';
const safeLabel = (value: unknown): string | null => string(value) && /^[a-z0-9._-]{1,64}$/i.test(value) ? value : null;
const taskStates = new Set<TaskLifecycleStatus>(['created','executing','completed','blocked','waiting_auth','failed','replanned']);
const stepStates = new Set<TaskStepStatus>(['pending','active','complete','blocked','waiting_auth','failed','skipped']);
const safeTaskText = (value: unknown): string | null => {
  if (!string(value) || value.length < 1 || value.length > 120) return null;
  return secret.test(value) ? null : value.replace(/[\r\n\t]+/g, ' ').trim();
};
function safeSteps(value: unknown): ArgusTaskStep[] | null {
  if (!Array.isArray(value) || value.length > 24) return null;
  const steps = value.map((item): ArgusTaskStep | null => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const raw = item as Record<string, unknown>;
    const id = typeof raw.id === 'string' || typeof raw.id === 'number' ? String(raw.id) : null;
    const label = safeTaskText(raw.label);
    const status = string(raw.status) && stepStates.has(raw.status as TaskStepStatus) ? raw.status as TaskStepStatus : null;
    return id && label && status ? { id, label, status, inserted: raw.inserted === true } : null;
  });
  return steps.every((step): step is ArgusTaskStep => step !== null) ? steps : null;
}
function mapTask(payload: Record<string, unknown>, eventState?: TaskLifecycleStatus): ArgusTask | null {
  const current = get(tasks); const steps = safeSteps(payload.steps) ?? current.steps;
  const status = eventState ?? (string(payload.status) && taskStates.has(payload.status as TaskLifecycleStatus) ? payload.status as TaskLifecycleStatus : current.status);
  const goal = safeTaskText(payload.goal) ?? current.goal;
  if (!goal || !steps.length || status === 'idle' || status === 'unknown') return null;
  const currentStepId = typeof payload.currentStepId === 'string' || typeof payload.current_step === 'string' || typeof payload.current_step === 'number'
    ? String(payload.currentStepId ?? payload.current_step) : current.currentStepId;
  return { ...current, goal, status, steps, currentStepId, activeCapability: safeLabel(payload.activeCapability) ?? current.activeCapability,
    reason: safeTaskText(payload.reason) ?? current.reason, replanAvailable: payload.replanAvailable === true, revision: number(payload.revision) ? payload.revision : current.revision + 1 };
}
const safeTelemetry = (payload: Record<string, unknown>) => {
  const allowed = ['cpu','mem_pct','mem_used_gb','mem_total_gb','disk_pct','disk_free_gb','gpu_pct','net_sent_gb','net_recv_gb'] as const;
  const next: Record<string, number | boolean> = {};
  for (const key of allowed) if (number(payload[key])) next[key] = payload[key];
  if (typeof payload.gpu_available === 'boolean') next.gpu_available = payload.gpu_available;
  return next;
};

function queueTelemetry(next: Record<string, number | boolean>): void {
  queuedTelemetry = { ...queuedTelemetry, ...next };
  if (telemetryFrame !== null) return;
  telemetryFrame = window.requestAnimationFrame(() => {
    telemetryFrame = null;
    const patch = queuedTelemetry;
    queuedTelemetry = {};
    telemetry.update((current) => {
      const merged = { ...(current ?? {}), ...patch };
      const previous = current as Record<string, unknown> | null;
      return Object.keys(patch).some((key) => previous?.[key] !== patch[key]) ? merged : current;
    });
  });
}

function applyEvent(event: HudEventEnvelope): void {
  const payload = event.payload;
  switch (event.type) {
    case 'agent.state': {
      if (!string(payload.state) || !states.has(payload.state as AgentState)) return;
      const current = get(agent);
      setAgentSnapshot({ ...current, state: payload.state as AgentState, activeCapability: safeLabel(payload.activeCapability) ?? current.activeCapability }); addEvent('AGENT', `Agent state: ${payload.state}`); notify('AGENT', `Agent state: ${payload.state}`, payload.state === 'error' || payload.state === 'blocked' ? 'critical' : 'info', 'agents');
      return;
    }
    case 'voice.state': {
      if (!string(payload.mode) || !voiceModes.has(payload.mode as VoiceMode)) return;
      setAgentSnapshot({ ...get(agent), voice: payload.mode as VoiceMode }); return;
    }
    case 'voice.level': {
      if (!number(payload.level) || payload.level < 0 || payload.level > 1) return;
      setAgentSnapshot({ ...get(agent), voiceLevel: payload.level }); return;
    }
    case 'security.state': {
      if (!string(payload.posture) || !postures.has(payload.posture as SecurityPosture)) return;
      const posture = payload.posture as SecurityPosture;
      patchSecurity({ posture, recoveryPossible: typeof payload.recoveryPossible === 'boolean' ? payload.recoveryPossible : get(security).recoveryPossible, updatedAt: Date.now() });
      if (posture === 'critical' || posture === 'blocked' || posture === 'lockdown') notify('SECURITY', `Security posture: ${posture.toUpperCase()}`, 'critical', 'security');
      if (posture === 'lockdown') setAgentSnapshot({ ...get(agent), state: 'lockdown' });
      else if (posture === 'blocked') setAgentSnapshot({ ...get(agent), state: 'blocked' });
      else if (posture === 'critical') setAgentSnapshot({ ...get(agent), state: 'warning' });
      return;
    }
    case 'auth.state': {
      if (!string(payload.status) || !['unknown','valid','required','expired'].includes(payload.status)) return;
      const previousAuth = get(security).auth;
      patchSecurity({ auth: payload.status as 'unknown' | 'valid' | 'required' | 'expired', updatedAt: Date.now() });
      // lock / unlock transitions for the Authentication page's session trail
      if (previousAuth !== payload.status) {
        if (payload.status === 'valid') logAuthEvent('UNLOCKED');
        else if (previousAuth === 'valid') logAuthEvent('LOCKED');
      }
      if (payload.status === 'required' || payload.status === 'expired') {
        setAgentSnapshot({ ...get(agent), state: 'waiting_auth' });
        /* Authentication auto-open: a live auth.state demand from the backend
           is a genuine mid-session challenge (NOT the LOCKED-at-boot
           baseline, which the backend reports as `unknown` and which stays
           silent). Mirroring it into a pending challenge makes App.svelte
           surface the Authentication page; requestAuthFromBackend no-ops
           while another challenge is already pending. */
        requestAuthFromBackend('session authentication');
      }
      // `unknown` is the locked-without-a-demand baseline: it is not "required", so it is not announced as such
      if (payload.status !== 'unknown') notify('AUTH', payload.status === 'valid' ? 'Authentication valid' : 'Authentication required', payload.status === 'valid' ? 'info' : 'warning', 'authentication');
      return;
    }
    case 'task.created': case 'task.updated': case 'task.completed': case 'task.step.updated': case 'task.failed': case 'task.replanned': case 'task.blocked': case 'task.waiting_auth': {
      const status = event.type === 'task.created' ? 'created' : event.type === 'task.completed' ? 'completed' : event.type === 'task.failed' ? 'failed' : event.type === 'task.replanned' ? 'replanned' : event.type === 'task.blocked' ? 'blocked' : event.type === 'task.waiting_auth' ? 'waiting_auth' : undefined;
      const task = mapTask(payload, status); if (task) { setTaskSnapshot(task); if(status) notify('TASK', `Task ${status}`, status === 'failed' ? 'critical' : status === 'blocked' ? 'warning' : 'info', 'tasks'); } return;
    }
    case 'telemetry.system': case 'telemetry.network': {
      const next = safeTelemetry(payload);
      if (!Object.keys(next).length) return;
      queueTelemetry(next); return;
    }
    case 'telemetry.model': {
      snapshotStatus.update((current) => ({ ...(current ?? {}), ...(string(payload.model) ? { model: payload.model } : {}) })); return;
    }
    case 'security.alert': {
      if (!string(payload.level)) return;
      const current = get(security); const level = payload.level.toUpperCase();
      const severity = string(payload.severity) ? payload.severity.toUpperCase() : level;
      const label = safeTaskText(payload.label) ?? safeTaskText(payload.name) ?? safeTaskText(payload.detector);
      const alerts = label ? [{ id: event.eventId ?? `${event.timestamp}:${label}`, severity, label, timestamp: event.timestamp }, ...current.alerts.filter((alert) => alert.id !== (event.eventId ?? `${event.timestamp}:${label}`))] : current.alerts;
      patchSecurity({ fields: { threatState: level }, posture: level === 'CRITICAL' ? 'critical' : level === 'ELEVATED' || level === 'WARNING' ? 'warning' : current.posture, alerts, updatedAt: Date.now() });
      threatReport.update((currentThreat) => ({ ...(currentThreat ?? {}), level })); if(label) notify('SECURITY', label, level === 'CRITICAL' ? 'critical' : 'warning', 'security'); return;
    }
    case 'security.decision': {
      const policy = string(payload.policy) && ['allow','deny'].includes(payload.policy.toLowerCase()) ? payload.policy.toLowerCase() as 'allow' | 'deny' : 'unknown';
      const auth = string(payload.auth) && ['valid','required','expired'].includes(payload.auth.toLowerCase()) ? payload.auth.toLowerCase() as 'valid' | 'required' | 'expired' : 'unknown';
      const status = string(payload.status) && ['ready','blocked','waiting_auth'].includes(payload.status.toLowerCase()) ? payload.status.toLowerCase() as 'ready' | 'blocked' | 'waiting_auth' : 'unknown';
      const executor = string(payload.executor) && ['user','admin','sandbox'].includes(payload.executor.toLowerCase()) ? payload.executor.toLowerCase() as 'user' | 'admin' | 'sandbox' : 'unknown';
      patchSecurity({ decision: { capability: safeLabel(payload.capability), resource: safeTaskText(payload.resource), policy, auth, executor, status }, auth, updatedAt: Date.now() });
      if (status === 'waiting_auth' || auth === 'required' || auth === 'expired') setAgentSnapshot({ ...get(agent), state: 'waiting_auth' });
      if (status === 'blocked' || policy === 'deny') setAgentSnapshot({ ...get(agent), state: 'blocked' });
      addEvent('POLICY', `Policy ${policy.toUpperCase()}${safeLabel(payload.capability) ? ` · ${safeLabel(payload.capability)}` : ''}`, policy === 'deny' ? 'critical' : 'info');
      return;
    }
    case 'audit.event': {
      if (typeof payload.chainIntact === 'boolean') patchSecurity({ fields: { auditChain: payload.chainIntact ? 'INTACT' : 'FAILED' }, updatedAt: Date.now() });
      return;
    }
    // agent.message / agent.reply: ids-only nudges consumed by stores/agentManager.ts
    // (via lib/agentEventsBus.ts), which re-reads the redacted text over REST.
    default: return;
  }
}

export function startLiveEvents(): () => void {
  client = new HudWebSocket({
    url: configuredUrl,
    protocols: runtimeToken ? ['argus-token', runtimeToken] : undefined,
    onEvent: (event) => {
      applyEvent(event);
      publishAgentEnvelope(event); // Agents Office fan-out (agent.* lifecycle)
      connection.update((current) => ({ ...current, lastSocketEventAt: Date.now() }));
    },
    onState: (socket, message) => {
      if (socket !== 'connected') { noteOfficeLinkDegraded(); markTeamOfficeDegraded(); }
      else {
        // Reconnect: an authoritative snapshot first, deltas resume after
        // -- only for stores the office page has actually loaded,
        // so a reconnect elsewhere in the HUD doesn't silently start polling
        // agent endpoints no page is showing.
        if (get(agentOffice).loaded) void refreshAgentOffice();
        if (get(teamOffice).loaded) void refreshTeamOffice();
        // The workforce snapshot (Manager) and inbox too: a delta missed while
        // the socket was down would otherwise leave a robot on screen that
        // the backend already released.
        if (get(agentManager).link !== 'loading') { void refreshManager(); void refreshInbox(); }
      }
      return connection.update((current) => { if(current.socket !== socket && current.socket !== 'disconnected') notify('CONNECTION', socket === 'connected' ? 'WebSocket connected' : 'WebSocket reconnecting', socket === 'connected' ? 'info' : 'warning', 'logs'); return { ...current, socket, socketRetryCount: socket === 'connected' ? 0 : current.socketRetryCount + (socket === 'reconnecting' ? 1 : 0), message: message ?? current.message }; }); }
  });
  client.connect();
  return () => {
    client?.disconnect(); client = null;
    if (telemetryFrame !== null) window.cancelAnimationFrame(telemetryFrame);
    telemetryFrame = null; queuedTelemetry = {};
  };
}
