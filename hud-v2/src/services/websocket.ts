import type { HudEventEnvelope, HudEventType } from '../types/argus';

// agent.* lifecycle types ride the same envelope contract (agents/events.py);
// their payloads are strictly validated downstream in parseAgentLifecycleEvent
// (lib/agentEvents.ts), so the allowlist here is transport-level only.
const eventTypes = new Set<HudEventType>(['agent.state','agent.message','task.created','task.updated','task.completed','task.step.updated','task.failed','task.replanned','task.blocked','task.waiting_auth','security.state','security.decision','security.alert','auth.state','telemetry.system','telemetry.network','telemetry.model','audit.event','voice.state','voice.level','agent.registered','agent.job_queued','agent.started','agent.state_changed','agent.waiting_auth','agent.completed','agent.failed','agent.cancelled','agent.handoff',
  // Dynamic (temp local/cloud) agent lifecycle -- agents/events.py DYNAMIC_EVENTS.
  'agent.proposed','agent.approved','agent.spawned','agent.expired','agent.destroyed','agent.spawn_denied',
  // CEO inbox (agents/inbox.py): ids-only nudges; the text is read over REST.
  'agent.reply',
  'team.created','team.plan_created','team.started','team.task_ready','team.task_started','team.task_completed','team.task_failed','team.agent_requested','team.agent_spawned','team.handoff','team.verification_started','team.verification_completed','team.replan_requested','team.replanned','team.partial','team.completed','team.failed','team.cancelled','team.timed_out']);
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

export function parseHudEvent(raw: string): HudEventEnvelope | null {
  try {
    const value: unknown = JSON.parse(raw);
    if (!isObject(value) || typeof value.type !== 'string' || !eventTypes.has(value.type as HudEventType) || value.version !== 1 || typeof value.timestamp !== 'string' || !isObject(value.payload)) return null;
    const timestamp = Date.parse(value.timestamp);
    if (!Number.isFinite(timestamp)) return null;
    return { type: value.type as HudEventType, version: 1, timestamp: value.timestamp, eventId: typeof value.eventId === 'string' ? value.eventId : undefined, payload: value.payload };
  } catch { return null; }
}

export interface WebSocketOptions { url?: string; protocols?: string[]; onEvent: (event: HudEventEnvelope) => void; onState: (state: 'connecting' | 'connected' | 'reconnecting' | 'disconnected' | 'degraded' | 'failed', message?: string) => void; }

export class HudWebSocket {
  private socket: WebSocket | null = null;
  private retryTimer: number | null = null;
  private attempt = 0;
  private closed = false;
  private readonly seen = new Set<string>();
  private lastTimestamp = 0;
  private readonly maxAttempts = 8;

  constructor(private readonly options: WebSocketOptions) {}

  connect(): void {
    if (!this.options.url) { this.options.onState('degraded', 'Live channel is not configured; REST snapshot remains active'); return; }
    this.closed = false;
    this.open();
  }

  disconnect(): void {
    this.closed = true;
    if (this.retryTimer !== null) window.clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.socket?.close(); this.socket = null;
    this.options.onState('disconnected');
  }

  private open(): void {
    if (this.closed || !this.options.url) return;
    this.options.onState(this.attempt ? 'reconnecting' : 'connecting');
    try { this.socket = new WebSocket(this.options.url, this.options.protocols); }
    catch { this.retry('WebSocket could not be opened'); return; }
    this.socket.onopen = () => { this.attempt = 0; this.options.onState('connected'); };
    this.socket.onmessage = (message) => this.receive(message.data);
    this.socket.onerror = () => { /* close owns recovery so errors do not duplicate retries */ };
    this.socket.onclose = () => { this.socket = null; if (!this.closed) this.retry('Live connection closed'); };
  }

  private receive(raw: unknown): void {
    if (typeof raw !== 'string') return;
    const event = parseHudEvent(raw);
    if (!event) return;
    const eventTime = Date.parse(event.timestamp);
    const key = event.eventId || `${event.type}:${event.timestamp}`;
    if (this.seen.has(key) || eventTime < this.lastTimestamp) return;
    this.seen.add(key); this.lastTimestamp = eventTime;
    if (this.seen.size > 256) this.seen.delete(this.seen.values().next().value as string);
    this.options.onEvent(event);
  }

  private retry(message: string): void {
    if (this.closed) return;
    if (this.attempt >= this.maxAttempts) { this.options.onState('failed', 'Live channel retry limit reached; REST snapshot remains active'); return; }
    const delay = Math.min(30_000, 1_000 * 2 ** this.attempt);
    this.attempt += 1;
    this.options.onState('reconnecting', message);
    this.retryTimer = window.setTimeout(() => this.open(), delay);
  }
}
