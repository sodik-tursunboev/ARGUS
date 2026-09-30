import type { HudEventEnvelope } from '../types/argus';

const agentEvents = new Set(['agent.registered', 'agent.job_queued', 'agent.started', 'agent.state_changed', 'agent.waiting_auth', 'agent.completed', 'agent.failed', 'agent.cancelled', 'agent.handoff']);
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);


export function parseAgentLifecycleEvent(event: HudEventEnvelope): { agentId: string; label: string; jobId?: string } | null {
  if (!agentEvents.has(event.type) || !isObject(event.payload)) return null;
  const agentId = typeof event.payload.agent_id === 'string' && /^[a-z_-]{1,32}$/.test(event.payload.agent_id)
    ? event.payload.agent_id : null;
  if (!agentId) return null;
  const jobId = typeof event.payload.job_id === 'string' && /^[0-9a-f]{1,32}$/.test(event.payload.job_id)
    ? event.payload.job_id : undefined;
  const labels: Record<string, string> = {
    'agent.registered': 'REGISTERED',
    'agent.job_queued': 'JOB QUEUED',
    'agent.started': 'STARTED',
    'agent.state_changed': 'STATE CHANGED',
    'agent.waiting_auth': 'WAITING AUTH',
    'agent.completed': 'JOB COMPLETED',
    'agent.failed': 'JOB FAILED',
    'agent.cancelled': 'JOB CANCELLED',
    'agent.handoff': 'HANDOFF',
  };
  return { agentId, label: labels[event.type] ?? event.type, jobId };
}
