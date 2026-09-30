import type { HudEventEnvelope } from '../types/argus';



const teamEventTypes = new Set([
  'team.created', 'team.plan_created', 'team.started', 'team.task_ready',
  'team.task_started', 'team.task_completed', 'team.task_failed',
  'team.agent_requested', 'team.agent_spawned', 'team.handoff',
  'team.verification_started', 'team.verification_completed',
  'team.replan_requested', 'team.replanned', 'team.partial', 'team.completed',
  'team.failed', 'team.cancelled', 'team.timed_out',
]);

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const idLike = (value: unknown, max = 40): string | undefined =>
  typeof value === 'string' && /^[a-z0-9_-]{1,40}$/i.test(value) ? value.slice(0, max) : undefined;
const str = (value: unknown, max = 64): string | undefined =>
  typeof value === 'string' ? value.slice(0, max) : undefined;
const num = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined;

export interface TeamLifecycleEvent {
  type: string; teamId: string; taskId?: string; agentId?: string; role?: string;
  kind?: string; state?: string; reason?: string; verdict?: string;
  decision?: string; fromAgent?: string; toAgent?: string; priority?: number;
  attempt?: number; durationS?: number; progress?: number;
  memberCount?: number; temporaryCount?: number; modelCalls?: number;
  replans?: number; handoffs?: number; taskCount?: number; added?: string[];
}

export function parseTeamEvent(event: HudEventEnvelope): TeamLifecycleEvent | null {
  if (!teamEventTypes.has(event.type) || !isObject(event.payload)) return null;
  const p = event.payload;
  const teamId = idLike(p.team_id, 20);
  if (!teamId) return null;
  return {
    type: event.type, teamId,
    taskId: idLike(p.task_id, 4), agentId: idLike(p.agent_id, 40),
    role: str(p.role, 24), kind: str(p.kind, 16), state: str(p.state, 24),
    reason: str(p.reason, 40), verdict: str(p.verdict, 24),
    decision: str(p.decision, 16), fromAgent: idLike(p.from_agent, 40),
    toAgent: idLike(p.to_agent, 40), priority: num(p.priority),
    attempt: num(p.attempt), durationS: num(p.duration_s), progress: num(p.progress),
    memberCount: num(p.member_count), temporaryCount: num(p.temporary_count),
    modelCalls: num(p.model_calls), replans: num(p.replans), handoffs: num(p.handoffs),
    taskCount: num(p.task_count),
    added: Array.isArray(p.added) ? p.added.filter((x): x is string => typeof x === 'string').slice(0, 12) : undefined,
  };
}



const dynamicEventTypes = new Set([
  'agent.proposed', 'agent.approved', 'agent.spawned', 'agent.expired',
  'agent.destroyed', 'agent.spawn_denied',
]);

export interface DynamicAgentLifecycleEvent {
  type: string; agentId?: string; parentId?: string; name?: string;
  agentType?: string; spawnDepth?: number; state?: string; reason?: string;
  ttlS?: number; dynamic?: boolean; finalStatus?: string;
}

export function parseDynamicAgentEvent(event: HudEventEnvelope): DynamicAgentLifecycleEvent | null {
  if (!dynamicEventTypes.has(event.type) || !isObject(event.payload)) return null;
  const p = event.payload;
  return {
    type: event.type, agentId: idLike(p.agent_id, 40), parentId: idLike(p.parent_id, 40),
    name: str(p.name, 64), agentType: str(p.agent_type, 24),
    spawnDepth: num(p.spawn_depth), state: str(p.state ?? p.status, 24),
    reason: str(p.reason, 64), ttlS: num(p.ttl_s),
    dynamic: typeof p.dynamic === 'boolean' ? p.dynamic : undefined,
    finalStatus: str(p.final_status, 24),
  };
}
