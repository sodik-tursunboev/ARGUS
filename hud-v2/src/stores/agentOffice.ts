import { writable, derived, get } from 'svelte/store';
import { fetchAgentsStatus, fetchAgentJobs, submitAgentJob, cancelAgentJob, fetchAutonomyStatus, setAutonomyEnabled, ApiError } from '../services/api';
import type { AgentOfficeSnapshot, OfficeAgent, OfficeJob } from '../types/argus';



export type OfficeLink = 'loading' | 'online' | 'degraded' | 'offline';

export interface AgentActivityEntry {
  id: string;
  ts: number;
  agentId: string;
  label: string;      // e.g. "JOB QUEUED", "STARTED", "JOB COMPLETED"
  jobId?: string;
}

interface AgentOfficeState {
  link: OfficeLink;
  loaded: boolean;
  snapshot: AgentOfficeSnapshot | null;
  jobs: OfficeJob[];
  selectedAgentId: string | null;
  activity: AgentActivityEntry[];
  handoff: { from: string; to: string; jobId: string; ts: number } | null;
  lastError: string | null;
  autonomy: { enabled: boolean; interval_s: number; cycles: number; jobs_dispatched: number; skipped_busy: number } | null;
  autonomyNote: string;
}

export const MAX_ACTIVITY = 40;

export const agentOffice = writable<AgentOfficeState>({
  link: 'loading',
  loaded: false,
  snapshot: null,
  jobs: [],
  selectedAgentId: null,
  activity: [],
  handoff: null,
  lastError: null,
  autonomy: null,
  autonomyNote: '',
});

const TERMINAL_LABELS = new Set(['JOB COMPLETED', 'JOB FAILED', 'JOB CANCELLED']);
const LABEL_STATE: Record<string, string> = {
  'JOB QUEUED': 'queued',
  'STARTED': 'thinking',
  'STATE CHANGED': 'responding',
  'WAITING AUTH': 'waiting_auth',
  'JOB COMPLETED': 'completed',
  'JOB FAILED': 'error',
  'JOB CANCELLED': 'blocked',
};

/* ---- live WS patching ------------------------------------------------ */

export function applyAgentEvent(agentId: string, label: string, jobId: string | undefined, ts: number): void {
  agentOffice.update((current) => {
    if (!current.snapshot) return current; // REST snapshot is the authority
    const agents = current.snapshot.agents.map((a): OfficeAgent => {
      if (a.id !== agentId) return a;
      const state = LABEL_STATE[label] ?? a.state;
      return {
        ...a,
        state,
        current_job_id: TERMINAL_LABELS.has(label) ? '' : (jobId ?? a.current_job_id),
        last_activity_at: ts / 1000,
        queue_position: label === 'JOB QUEUED' ? Math.max(1, a.queue_position)
          : TERMINAL_LABELS.has(label) ? 0 : a.queue_position,
      };
    });
    const activity = [{ id: `${ts}:${agentId}:${label}:${jobId ?? ''}`, ts, agentId, label, jobId },
      ...current.activity].slice(0, MAX_ACTIVITY);
    const handoff = label === 'HANDOFF' && jobId
      ? { from: agentId, to: 'verifier', jobId, ts }
      : current.handoff;
    return { ...current, snapshot: { ...current.snapshot, agents }, activity, handoff };
  });
}

export function selectAgent(id: string | null): void {
  agentOffice.update((c) => ({ ...c, selectedAgentId: id }));
}

/* ---- REST ------------------------------------------------------------ */

export async function refreshAgentOffice(): Promise<void> {
  try {
    const [status, jobs] = await Promise.all([
      fetchAgentsStatus(),
      fetchAgentJobs().catch(() => ({ jobs: [], queue_depth: 0 })),
    ]);
    agentOffice.update((current) => ({
      ...current,
      link: 'online',
      loaded: true,
      lastError: null,
      snapshot: status,
      jobs: jobs.jobs,
      autonomy: (status as unknown as { autonomy?: AgentOfficeState['autonomy'] }).autonomy ?? current.autonomy,
    }));
  } catch (error) {
    agentOffice.update((current) => ({
      ...current,
      link: 'offline',
      loaded: true,
      lastError: error instanceof ApiError ? error.message : 'Agent control link unavailable',
    }));
  }
}

export function markOfficeDegraded(): void {
  agentOffice.update((c) => (c.link === 'online' ? { ...c, link: 'degraded' } : c));
}

export const officeSummary = derived(agentOffice, ($o) => ({
  total: $o.snapshot?.agents.length ?? 0,
  active: $o.snapshot?.active_count ?? 0,
  queued: $o.snapshot?.queue_depth ?? 0,
  idle: $o.snapshot?.agents.filter((a) => a.state === 'idle').length ?? 0,
}));

export const selectedAgent = derived(agentOffice, ($o) =>
  $o.snapshot?.agents.find((a) => a.id === $o.selectedAgentId) ?? null);

export async function submitTestJob(agentId: string, objective: string): Promise<{ ok: boolean; detail: string }> {
  try {
    await submitAgentJob(agentId, objective);
    await refreshAgentOffice();
    return { ok: true, detail: '' };
  } catch (error) {
    return { ok: false, detail: error instanceof ApiError ? error.message : 'Submission failed' };
  }
}

export async function cancelJob(jobId: string): Promise<void> {
  try { await cancelAgentJob(jobId); } catch { /* refresh reflects truth */ }
  await refreshAgentOffice();
}

/* Light cadence queue refresh: the queue table stays honest even if an
   individual WS event was missed while the page was in the background. */
export async function refreshJobs(): Promise<void> {
  try {
    const jobs = await fetchAgentJobs();
    agentOffice.update((current) => ({ ...current, jobs: jobs.jobs }));
  } catch { /* link state owns the error surface */ }
}

/* ---- bounded autonomy scheduler (owner kill-switch) ------------------ */

export async function setAutonomy(on: boolean): Promise<void> {
  try {
    const st = await setAutonomyEnabled(on);
    agentOffice.update((c) => ({
      ...c,
      autonomy: st,
      autonomyNote: st.enabled ? 'AUTONOMY ON — BACKGROUND ANALYSIS CYCLES' : 'AUTONOMY OFF — AGENTS WORK ONLY WHEN ASKED',
    }));
  } catch (error) {
    agentOffice.update((c) => ({
      ...c,
      autonomyNote: error instanceof ApiError ? error.message : 'AUTONOMY TOGGLE UNAVAILABLE',
    }));
  }
}

export async function refreshAutonomy(): Promise<void> {
  try {
    const st = await fetchAutonomyStatus();
    agentOffice.update((c) => ({ ...c, autonomy: st }));
  } catch { /* link state owns the error surface */ }
}

export function officeSnapshot(): AgentOfficeSnapshot | null {
  return get(agentOffice).snapshot;
}
