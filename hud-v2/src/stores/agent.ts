import { writable } from 'svelte/store';

export type AgentState =
  | 'booting'
  | 'standby'
  | 'listening'
  | 'understanding'
  | 'planning'
  | 'waiting_auth'
  | 'executing'
  | 'verifying'
  | 'completed'
  | 'warning'
  | 'blocked'
  | 'lockdown'
  | 'error';

export type VoiceMode = 'idle' | 'listening' | 'processing' | 'speaking' | 'disabled';

export interface AgentSnapshot {
  state: AgentState;
  activeCapability: string | null;
  voice: VoiceMode;
  voiceLevel?: number | null;
}

export const stateLabels: Record<AgentState, string> = {
  booting: 'BOOTING', standby: 'STANDBY', listening: 'LISTENING',
  understanding: 'UNDERSTANDING', planning: 'PLANNING', waiting_auth: 'WAITING FOR AUTH',
  executing: 'EXECUTING', verifying: 'VERIFYING', completed: 'COMPLETED',
  warning: 'WARNING', blocked: 'BLOCKED', lockdown: 'LOCKDOWN', error: 'ERROR'
};

export const agent = writable<AgentSnapshot>({
  state: 'booting',
  activeCapability: null,
  voice: 'idle',
  voiceLevel: null
});

export function setAgentSnapshot(next: AgentSnapshot): void {
  agent.set(next);
}
