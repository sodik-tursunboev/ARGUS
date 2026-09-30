import { get, writable } from 'svelte/store';
import { sendCommand } from '../services/api';
import { agent, setAgentSnapshot } from './agent';
import { addEvent } from './events';
import { notify } from './notifications';

/* AUTHENTICATION FLOW STATE.
   The backend owns every authentication decision. This module only records
   that the BACKEND asked for something, so the Authentication page can present
   it. A challenge is created from exactly three authoritative signals, never
   from text:
     - POST /command answered auth_required / confirmation_required
       (structured booleans from router.last_refused(), not the reply prose),
     - the WebSocket auth.state event with status required | expired,
     - GET /status pin_pending (a staged sensitive action is waiting on the PIN).
   Nothing here can unlock anything; a PIN never enters a store (the page keeps
   it in one local variable for the duration of a single request). */

export interface PendingAuth { mode: 'pin' | 'confirm'; command: string | null; action: string; level: string; requirement: string; at: number; }
export const pendingAuth = writable<PendingAuth | null>(null);

export const safeAction = (value: unknown): string => typeof value === 'string' && /^[a-z0-9._ -]{1,80}$/i.test(value) ? value : 'requested action';

/* Session-scoped auth trail for the Authentication page. Deliberately NOT the
   backend audit log (that is on the Logs page): this is what THIS window saw,
   built only from fixed words, an already-sanitised action name and a level --
   no secret, no free text from the backend, no reply prose. */
export type AuthEventKind = 'REQUIRED' | 'CONFIRMATION' | 'VERIFIED' | 'FAILED' | 'LOCKED OUT' | 'CANCELLED' | 'UNLOCKED' | 'LOCKED';
export interface AuthEvent { id: string; at: number; kind: AuthEventKind; detail: string; }
export const authEvents = writable<AuthEvent[]>([]);
let authSeq = 0;
export function logAuthEvent(kind: AuthEventKind, detail = ''): void {
  const at = Date.now();
  authEvents.update((rows) => [{ id: `${at}:${authSeq++}`, at, kind, detail: detail.slice(0, 80) }, ...rows].slice(0, 12));
}

/** Dispatch through the backend; only its response may request authentication. */
export async function dispatchCommand(text: string): Promise<void> {
  setAgentSnapshot({ ...get(agent), state: 'understanding' });
  try {
    const result = await sendCommand(text);
    if (result.auth_required) {
      const level = result.auth_level ? `L${result.auth_level}` : 'UNKNOWN';
      const action = safeAction(result.action);
      pendingAuth.set({ mode: 'pin', command: text, action, level, requirement: result.auth_requirement || 'authentication required by backend', at: Date.now() });
      logAuthEvent('REQUIRED', `${action} · ${level}`);
      setAgentSnapshot({ ...get(agent), state: 'waiting_auth' });
      return;
    }
    if (result.confirmation_required) {
      const level = result.auth_level ? `L${result.auth_level}` : 'UNKNOWN';
      const action = safeAction(result.action);
      pendingAuth.set({ mode: 'confirm', command: null, action, level, requirement: 'explicit confirmation required by backend', at: Date.now() });
      logAuthEvent('CONFIRMATION', `${action} · ${level}`);
      setAgentSnapshot({ ...get(agent), state: 'waiting_auth' });
      return;
    }
    addEvent('AGENT', typeof result.reply === 'string' ? result.reply : 'Command completed');
  } catch {
    addEvent('ERROR', 'Command dispatch failed', 'critical');
    notify('ERROR', 'Command dispatch failed', 'critical', 'logs');
    throw new Error('dispatch failed');
  } finally {
    if (!get(pendingAuth)) setAgentSnapshot({ ...get(agent), state: 'standby' });
  }
}

export function requestAuthFromBackend(action = 'pending confirmation'): void {
  if (get(pendingAuth)) return;
  const safe = safeAction(action);
  pendingAuth.set({ mode: 'pin', command: null, action: safe, level: 'UNKNOWN', requirement: 'authentication required by backend', at: Date.now() });
  logAuthEvent('REQUIRED', safe);
  setAgentSnapshot({ ...get(agent), state: 'waiting_auth' });
}

export function clearPendingAuth(): void { pendingAuth.set(null); }
