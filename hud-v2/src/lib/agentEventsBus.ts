import { applyAgentEvent, markOfficeDegraded } from '../stores/agentOffice';
import { parseAgentLifecycleEvent } from './agentEvents';
import { parseTeamEvent, parseDynamicAgentEvent } from './teamEvents';
import { applyTeamEvent, applyDynamicAgentEvent } from '../stores/teamOffice';
import { applyManagerEnvelope } from '../stores/agentManager';
import type { HudEventEnvelope } from '../types/argus';

type Handler = (event: HudEventEnvelope) => void;

const handlers = new Set<Handler>();



export function publishAgentEnvelope(event: HudEventEnvelope): void {
  const parsed = parseAgentLifecycleEvent(event);
  if (parsed) applyAgentEvent(parsed.agentId, parsed.label, parsed.jobId, Date.now());
  const team = parseTeamEvent(event);
  if (team) applyTeamEvent(team);
  const dynamic = parseDynamicAgentEvent(event);
  if (dynamic) applyDynamicAgentEvent(dynamic);
  // Agent Manager + CEO inbox: ids-only nudges -> a REST re-read.
  applyManagerEnvelope(event);
}

export function subscribeAgentEvents(handler: Handler): () => void {
  handlers.add(handler);
  return () => handlers.delete(handler);
}

export function noteOfficeLinkDegraded(): void {
  markOfficeDegraded();
}

export function currentEnvelopeSink(): (event: HudEventEnvelope) => void {
  return (event) => {
    for (const handler of handlers) handler(event);
    publishAgentEnvelope(event);
  };
}
