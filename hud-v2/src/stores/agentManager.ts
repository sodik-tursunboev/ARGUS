import { writable, get } from 'svelte/store';
import {
  ApiError, fetchManagerState, fetchInbox, replyToMessage, markMessageRead,
  chatWithAgent, submitManagerGoal, releaseTemporaryAgent,
} from '../services/api';
import type { AgentMessage, InboxSummary, ManagerState, HudEventEnvelope } from '../types/argus';

/* The Agent Manager + CEO inbox, as the HUD sees them.

   The backend is the authority for all of it (agents/agent_manager.py,
   agents/inbox.py). This store only READS: a REST snapshot on demand, plus a
   debounced re-read whenever a WS event says something changed. The WS
   payload carries ids and codes only (the hub's hygiene rule), so message
   text always arrives through the authenticated, redacted REST view.

   Every action (reply, chat, goal, release a specialist) is a request; the
   store never edits worker or message state locally -- it re-reads the
   backend's answer. */

export type ManagerLink = 'loading' | 'online' | 'offline';

interface ManagerStoreState {
  link: ManagerLink;
  manager: ManagerState | null;
  messages: AgentMessage[];
  summary: InboxSummary | null;
  threads: Record<string, AgentMessage[]>;
  /** New messages worth surfacing, newest first; the city shows them as toasts. */
  toasts: AgentMessage[];
  lastError: string | null;
}

export const agentManager = writable<ManagerStoreState>({
  link: 'loading', manager: null, messages: [], summary: null, threads: {}, toasts: [], lastError: null,
});

const seen = new Set<string>();
let primed = false;

export async function refreshManager(): Promise<void> {
  try {
    const manager = await fetchManagerState();
    agentManager.update((s) => ({ ...s, manager, link: 'online', lastError: null }));
  } catch (error) {
    agentManager.update((s) => ({ ...s, link: 'offline', lastError: error instanceof ApiError ? error.message : 'Agent Manager unavailable' }));
  }
}

export async function refreshInbox(): Promise<void> {
  try {
    const { messages, summary } = await fetchInbox('', 80);
    // Toast only what is NEW since the last read and worth interrupting for:
    // NORMAL and above, never the INFO-level chatter (design §33). The very
    // first read primes the set without toasting the backlog.
    const fresh = primed ? messages.filter((m) => !seen.has(m.message_id) && m.priority !== 'INFO' && !m.read) : [];
    for (const m of messages) seen.add(m.message_id);
    primed = true;
    agentManager.update((s) => ({
      ...s, messages, summary, link: 'online',
      toasts: [...fresh, ...s.toasts].slice(0, 4),
    }));
  } catch (error) {
    agentManager.update((s) => ({ ...s, link: 'offline', lastError: error instanceof ApiError ? error.message : 'Inbox unavailable' }));
  }
}

export async function refreshThread(agentId: string): Promise<void> {
  if (!agentId) return;
  try {
    const { messages } = await fetchInbox(agentId, 40);
    agentManager.update((s) => ({ ...s, threads: { ...s.threads, [agentId]: messages } }));
  } catch { /* the link state is owned by refreshInbox */ }
}

export function dismissToast(messageId: string): void {
  agentManager.update((s) => ({ ...s, toasts: s.toasts.filter((m) => m.message_id !== messageId) }));
}

/** Network failure -> a readable reason instead of a throw, so a Send button
    can never stay stuck on "busy" when the backend is unreachable. */
async function attempt<T>(call: () => Promise<T>): Promise<T | string> {
  try { return await call(); }
  catch (error) { return error instanceof ApiError ? error.message : 'Backend is unavailable'; }
}

export async function replyTo(message: AgentMessage, reply: { text?: string; choice?: string }): Promise<string | null> {
  const out = await attempt(() => replyToMessage(message.message_id, reply));
  if (typeof out === 'string') return out;
  await Promise.all([refreshInbox(), refreshManager(), message.thread ? refreshThread(message.thread) : Promise.resolve()]);
  if (out.ok) return null;
  const reason = typeof out.data?.reason === 'string' ? out.data.reason : `HTTP ${out.status}`;
  return reason.replace(/_/g, ' ');
}

export async function markRead(messageId: string): Promise<void> {
  try { await markMessageRead(messageId); } catch { /* best effort */ }
  agentManager.update((s) => ({ ...s, messages: s.messages.map((m) => (m.message_id === messageId ? { ...m, read: true } : m)) }));
}

export async function sendChat(agentId: string, text: string): Promise<string | null> {
  const out = await attempt(() => chatWithAgent(agentId, text));
  if (typeof out === 'string') return out;
  await Promise.all([refreshThread(agentId), refreshInbox()]);
  if (out.ok && out.data?.ok !== false) return null;
  const reason = typeof out.data?.reason === 'string' ? out.data.reason : `HTTP ${out.status}`;
  return reason.replace(/_/g, ' ');
}

export async function submitGoal(goal: string, material = ''): Promise<Record<string, unknown> | null> {
  const out = await attempt(() => submitManagerGoal(goal, material));
  if (typeof out === 'string') return { outcome: 'failed', reason: out };
  await Promise.all([refreshInbox(), refreshManager()]);
  return out.data;
}

export async function releaseSpecialist(agentId: string): Promise<boolean> {
  const ok = await attempt(() => releaseTemporaryAgent(agentId));
  await refreshManager();
  return ok === true;
}

/* ── live nudges from the ONE WebSocket hub ──────────────────────────── */
let inboxTimer = 0;
let managerTimer = 0;

function soon(which: 'inbox' | 'manager'): void {
  if (which === 'inbox') {
    if (inboxTimer) return;
    inboxTimer = window.setTimeout(() => { inboxTimer = 0; void refreshInbox(); }, 250);
  } else {
    if (managerTimer) return;
    managerTimer = window.setTimeout(() => { managerTimer = 0; void refreshManager(); }, 400);
  }
}

/** Fed every hub envelope by lib/agentEventsBus.ts. */
export function applyManagerEnvelope(event: HudEventEnvelope): void {
  const t = event.type;
  if (t === 'agent.message' || t === 'agent.reply') {
    soon('inbox');
    const p = event.payload as Record<string, unknown> | undefined;
    const thread = typeof p?.thread === 'string' && /^[a-z0-9_-]{1,40}$/i.test(p.thread) ? p.thread : '';
    if (thread && get(agentManager).threads[thread]) void refreshThread(thread);
    return;
  }
  if (t.startsWith('team.') || t === 'agent.spawned' || t === 'agent.destroyed'
      || t === 'agent.spawn_denied' || t === 'agent.expired') soon('manager');
}
