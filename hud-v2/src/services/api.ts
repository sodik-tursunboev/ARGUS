import type { FaceStatus } from '../lib/face';
import type { BackendAuthStatus, BackendSecurityReport, BackendStatus, BackendTelemetry, BackendThreatReport, HudSnapshot } from '../types/argus';

const timeoutMs = 4_000;
const configuredBase = import.meta.env.VITE_ARGUS_API_BASE as string | undefined;
// Optional runtime API-base hook, injected by a local host/test harness into the
// integrity-verified page (same contract as __ARGUS_TOKEN__). Product builds
// never set it; the hardcoded local fallback below stays the default.
const runtimeBase = (window as Window & { __ARGUS_API__?: string }).__ARGUS_API__;
const apiBase = runtimeBase || configuredBase || (window.location.port === '8420' ? window.location.origin : 'http://127.0.0.1:8420');
// The local host injects this only at runtime into the integrity-verified page.
// VITE_* variables are build-time public data and must never carry a session token.
const token = (window as Window & { __ARGUS_TOKEN__?: string }).__ARGUS_TOKEN__;

export class ApiError extends Error { constructor(message: string, public readonly kind: 'timeout' | 'network' | 'http' | 'invalid') { super(message); } }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

async function get<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${apiBase}${path}`, { headers: token ? { 'x-argus-token': token } : {}, signal: controller.signal });
    if (!response.ok) throw new ApiError(`HUD snapshot unavailable (${response.status})`, 'http');
    const data: unknown = await response.json();
    if (!object(data)) throw new ApiError('HUD snapshot was malformed', 'invalid');
    // Through unknown so Record<string, unknown> -> concrete DTO casts are
    // structurally checked instead of an unsound direct assertion.
    return data as unknown as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError('HUD snapshot timed out', 'timeout');
    throw new ApiError('Backend is unavailable', 'network');
  } finally { window.clearTimeout(timer); }
}
export async function sendCommand(text: string): Promise<import('../types/argus').CommandResponse> {
  const controller = new AbortController(); const timer = window.setTimeout(() => controller.abort(), 15_000);
  try { const response = await fetch(`${apiBase}/command`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ text }), signal: controller.signal }); if (!response.ok) throw new ApiError(`Command unavailable (${response.status})`, 'http'); const data: unknown = await response.json(); if (!object(data)) throw new ApiError('Command response was malformed', 'invalid'); return data as import('../types/argus').CommandResponse; }
  catch (error) { if (error instanceof ApiError) throw error; if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError('Command timed out', 'timeout'); throw new ApiError('Backend is unavailable', 'network'); }
  finally { window.clearTimeout(timer); }
}
export async function unlock(secret: string): Promise<import('../types/argus').UnlockResponse> {
  const controller = new AbortController(); const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try { const response = await fetch(`${apiBase}/unlock`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ secret }), signal: controller.signal }); if (!response.ok) throw new ApiError(`Authentication unavailable (${response.status})`, 'http'); const data: unknown = await response.json(); if (!object(data)) throw new ApiError('Authentication response was malformed', 'invalid'); return data as import('../types/argus').UnlockResponse; }
  catch (error) { if (error instanceof ApiError) throw error; if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError('Authentication timed out', 'timeout'); throw new ApiError('Authentication service is unavailable', 'network'); }
  finally { window.clearTimeout(timer); }
}
/* ── Verification surface (PIN / face / auth state) ────────────────────
   The backend owns every auth decision; these helpers only READ state and
   forward owner-initiated face actions. No result is interpreted as a
   frontend permission grant. */
export interface AuthStatusDTO { enabled: boolean; unlocked: boolean; locked_out: boolean; lockout_seconds: number; idle_lock_seconds: number; }
export interface FaceStatusDTO { available?: boolean; enrolled?: boolean; samples?: number; presence_watch?: boolean; presence_locks?: number; [k: string]: unknown; }
export async function fetchAuthStatus(): Promise<AuthStatusDTO> {
  return get<AuthStatusDTO>('/auth-status');
}
/** The two O(1) backend reads the fast lane polls (see stores/snapshot.ts). */
export async function fetchStatus(): Promise<import('../types/argus').BackendStatus> {
  return get<import('../types/argus').BackendStatus>('/status');
}
export async function fetchFaceStatus(): Promise<FaceStatusDTO> {
  return get<FaceStatusDTO>('/face/status');
}
export async function postFaceCheck(): Promise<{ ok?: boolean; message?: string; needs_auth?: boolean }> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${apiBase}/face/check`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) },
      body: JSON.stringify({}),
      signal: controller.signal,
    });
    if (!response.ok) return { ok: false, message: `Face check unavailable (${response.status})` };
    return (await response.json()) as { ok?: boolean; message?: string; needs_auth?: boolean };
  } catch {
    return { ok: false, message: 'Face check service is unavailable' };
  } finally {
    window.clearTimeout(timer);
  }
}
export interface SettingField { name: string; class: 'live' | 'restart' | 'locked'; label: string; help: string; value: string | number | boolean | null; }
export async function getSettings(): Promise<{ fields: SettingField[]; needs_restart?: string[] }> { return get<{ fields: SettingField[]; needs_restart?: string[] }>('/settings'); }
export async function saveSetting(name: string, value: string | number | boolean): Promise<{ applied?: string[]; rejected?: Array<{ name?: string; reason?: string }>; needs_restart?: string[] }> {
  const response = await fetch(`${apiBase}/settings`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ changes: { [name]: value } }) });
  if (!response.ok) throw new ApiError(`Settings unavailable (${response.status})`, 'http'); const data: unknown = await response.json(); if (!object(data)) throw new ApiError('Settings response was malformed', 'invalid'); return data as { applied?: string[]; rejected?: Array<{ name?: string; reason?: string }>; needs_restart?: string[] };
}
export async function resetSetting(name: string): Promise<{ removed?: number; needs_restart?: string[] }> {
  const response = await fetch(`${apiBase}/settings/reset`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ name }) });
  if (!response.ok) throw new ApiError(`Settings unavailable (${response.status})`, 'http'); const data: unknown = await response.json(); if (!object(data)) throw new ApiError('Settings response was malformed', 'invalid'); return data as { removed?: number; needs_restart?: string[] };
}



export interface OfficeAgentDTO {
  id: string; name: string; role: string; description: string;
  priority: number; enabled: boolean; allowed_capability_groups: string[];
  shared_model: boolean; state: string; current_job_id: string;
  queue_position: number; last_activity_at: number; completed_jobs: number;
  failed_jobs: number; last_error: string;
}
export interface OfficeModelDTO { model_id: string; available: boolean; busy: boolean; active_job: string; max_concurrency: number; timeout_s: number; calls_made: number; timeouts: number; errors: number; last_error: string; }
export interface AcademySessionDTO {
  session_id: string; agent_id: string; curriculum: string; skill: string;
  scenario: string; state: 'SCHEDULED' | 'QUEUED' | 'ACTIVE' | 'EVALUATING' | 'PASSED' | 'FAILED' | 'CANCELLED';
  backend: string; provider: string; model: string; score: number | null;
  verifier_result: string; evidence: string[]; created_at: number;
  started_at: number | null; finished_at: number | null; reason: string;
}
export interface AcademyDTO {
  sessions: AcademySessionDTO[]; counts: Record<string, number>;
  lessons: Record<string, { skill: string; lesson: string; session_id: string; verified_at: number }>;
  backend: string; hermes: string;
}
export async function fetchAcademy(): Promise<AcademyDTO> { return get<AcademyDTO>('/api/agents/academy'); }
export async function trainAcademy(agentIds: string[], topic = ''): Promise<{ ok: boolean; reason: string; sessions: AcademySessionDTO[] }> {
  const response = await fetch(`${apiBase}/api/agents/academy/train`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) },
    body: JSON.stringify({ agent_ids: agentIds, topic }),
  });
  if (!response.ok) throw new ApiError(`Academy request refused (${response.status})`, 'http');
  return await response.json() as { ok: boolean; reason: string; sessions: AcademySessionDTO[] };
}
export async function cancelAcademy(agentId: string): Promise<void> {
  const response = await fetch(`${apiBase}/api/agents/academy/${encodeURIComponent(agentId)}/cancel`, {
    method: 'POST', headers: token ? { 'x-argus-token': token } : {},
  });
  if (!response.ok) throw new ApiError(`Academy cancellation failed (${response.status})`, 'http');
}
export interface OfficeSnapshotDTO { agents: OfficeAgentDTO[]; model: OfficeModelDTO; queue_depth: number; active_jobs: string[]; active_count: number; tiers: Record<string, string>; }
export interface OfficeJobDTO { job_id: string; agent_id: string; priority: number; state: string; source: string; parent_job_id: string; handoff_depth: number; created_at: number; age_s: number; objective: string; }
export interface AutonomyDTO { enabled: boolean; interval_s: number; cycles: number; jobs_dispatched: number; skipped_busy: number; dispatch_failures: number; last_dispatch_at: number; last_error: string; recent: { ts: number; agent_id: string; job_id: string }[]; }

export async function fetchAutonomyStatus(): Promise<AutonomyDTO> { return get<AutonomyDTO>('/api/agents/autonomy'); }
export async function setAutonomyEnabled(enabled: boolean): Promise<AutonomyDTO> {
  const response = await fetch(`${apiBase}/api/agents/autonomy`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ enabled }) });
  if (!response.ok) throw new ApiError(`Autonomy toggle unavailable (${response.status})`, 'http');
  const data: unknown = await response.json();
  if (!object(data) || typeof data.enabled !== 'boolean') throw new ApiError('Autonomy response was malformed', 'invalid');
  return data as unknown as AutonomyDTO;
}
export interface SkillsDTO { count: number; groups: { skill: string; actions: string[] }[]; note: string; }
export async function fetchSkills(): Promise<SkillsDTO> { return get<SkillsDTO>('/skills'); }
export async function fetchAuditLog(): Promise<string> {
  const response = await fetch(`${apiBase}/audit-log`, { headers: token ? { 'x-argus-token': token } : {} });
  if (!response.ok) throw new ApiError(`Audit log unavailable (${response.status})`, 'http');
  return response.text();
}

export async function fetchAgentsStatus(): Promise<OfficeSnapshotDTO> { return get<OfficeSnapshotDTO>('/api/agents'); }
export async function fetchAgentJobs(): Promise<{ jobs: OfficeJobDTO[]; queue_depth: number }> { return get<{ jobs: OfficeJobDTO[]; queue_depth: number }>('/api/agents/jobs'); }


import type { TeamsListResponse, TeamDetail, DynamicSnapshot } from '../types/argus';
export async function fetchAgentTeams(): Promise<TeamsListResponse> { return get<TeamsListResponse>('/api/agents/teams'); }
export async function fetchAgentTeam(teamId: string): Promise<TeamDetail | null> {
  try { return await get<TeamDetail>(`/api/agents/teams/${encodeURIComponent(teamId)}`); }
  catch (error) { if (error instanceof ApiError && error.kind === 'http') return null; throw error; }
}
export async function cancelAgentTeam(teamId: string, reason = 'owner_cancel'): Promise<boolean> {
  const response = await fetch(`${apiBase}/api/agents/teams/${encodeURIComponent(teamId)}/cancel`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ reason }) });
  return response.ok;
}
export async function fetchDynamicAgents(): Promise<DynamicSnapshot> { return get<DynamicSnapshot>('/api/agents/dynamic'); }
export async function fetchAgentJob(jobId: string): Promise<Record<string, unknown>> { return get<Record<string, unknown>>(`/api/agents/jobs/${encodeURIComponent(jobId)}`); }
export async function submitAgentJob(agentId: string, objective: string): Promise<{ job_id: string; agent_id: string; state: string }> {
  const response = await fetch(`${apiBase}/api/agents/${encodeURIComponent(agentId)}/jobs`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify({ objective }) });
  if (!response.ok) throw new ApiError(`Job submission unavailable (${response.status})`, 'http');
  const data: unknown = await response.json();
  if (!object(data) || typeof data.job_id !== 'string') throw new ApiError('Job submission response was malformed', 'invalid');
  return data as { job_id: string; agent_id: string; state: string };
}
/* ── Agent Manager + CEO inbox (agents/agent_manager.py, agents/inbox.py) ──
   Every mutating call is a REQUEST to the backend; nothing here changes
   worker state locally (the stores re-read the backend's answer). */
import type { ManagerState, AgentMessage, InboxSummary } from '../types/argus';
async function postJson<T>(path: string, body: unknown): Promise<{ ok: boolean; status: number; data: T | null }> {
  const controller = new AbortController(); const timer = window.setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(`${apiBase}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { 'x-argus-token': token } : {}) }, body: JSON.stringify(body), signal: controller.signal });
    let data: unknown = null; try { data = await response.json(); } catch { data = null; }
    return { ok: response.ok, status: response.status, data: object(data) ? data as T : null };
  } catch { throw new ApiError('Backend is unavailable', 'network'); }
  finally { window.clearTimeout(timer); }
}
/** The wake sequence is over and the HUD is visible: ARGUS may greet now
 *  (main.py /hud-awake). Best effort -- if it fails, the voice process still
 *  greets on its own timeout, so this can only delay the greeting, never lose it. */
export async function notifyHudAwake(): Promise<void> {
  try { await postJson('/hud-awake', {}); } catch { /* best effort */ }
}
export async function fetchManagerState(): Promise<ManagerState> { return get<ManagerState>('/api/agents/manager'); }
export async function fetchInbox(thread = '', limit = 80): Promise<{ messages: AgentMessage[]; summary: InboxSummary }> {
  const q = new URLSearchParams({ limit: String(limit), ...(thread ? { thread } : {}) });
  return get<{ messages: AgentMessage[]; summary: InboxSummary }>(`/api/agents/inbox?${q}`);
}
export async function replyToMessage(messageId: string, reply: { text?: string; choice?: string }): Promise<{ ok: boolean; status: number; data: Record<string, unknown> | null }> {
  return postJson<Record<string, unknown>>(`/api/agents/inbox/${encodeURIComponent(messageId)}/reply`, { text: reply.text ?? '', choice: reply.choice ?? '' });
}
export async function markMessageRead(messageId: string): Promise<void> { await postJson(`/api/agents/inbox/${encodeURIComponent(messageId)}/read`, {}); }
export async function chatWithAgent(agentId: string, text: string): Promise<{ ok: boolean; status: number; data: Record<string, unknown> | null }> {
  return postJson<Record<string, unknown>>(`/api/agents/${encodeURIComponent(agentId)}/chat`, { text });
}
export async function submitManagerGoal(goal: string, material = ''): Promise<{ ok: boolean; status: number; data: Record<string, unknown> | null }> {
  return postJson<Record<string, unknown>>('/api/agents/manager/goals', { goal, material });
}
export async function releaseTemporaryAgent(agentId: string): Promise<boolean> {
  const response = await fetch(`${apiBase}/api/agents/dynamic/${encodeURIComponent(agentId)}`, { method: 'DELETE', headers: token ? { 'x-argus-token': token } : {} });
  return response.ok;
}
export async function cancelAgentJob(jobId: string): Promise<void> {
  const response = await fetch(`${apiBase}/api/agents/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE', headers: token ? { 'x-argus-token': token } : {} });
  if (!response.ok) throw new ApiError(`Job cancellation unavailable (${response.status})`, 'http');
}

export async function fetchHudSnapshot(): Promise<HudSnapshot> {
  const [status, telemetry, security, threat, auth, face] = await Promise.allSettled([
    get<BackendStatus>('/status'), get<BackendTelemetry>('/telemetry'), get<BackendSecurityReport>('/security-report'), get<BackendThreatReport>('/threat-report'), get<BackendAuthStatus>('/auth-status'), get<FaceStatus>('/face/status')
  ]);
  const value = <T>(result: PromiseSettledResult<T>): T | null => result.status === 'fulfilled' ? result.value : null;
  const snapshot = { status: value(status), telemetry: value(telemetry), security: value(security), threat: value(threat), auth: value(auth), face: value(face) };
  if (!snapshot.status && !snapshot.telemetry) {
    const failure = [status, telemetry].find((result): result is PromiseRejectedResult => result.status === 'rejected');
    throw failure?.reason instanceof ApiError ? failure.reason : new ApiError('Backend is unavailable', 'network');
  }
  return snapshot;
}
