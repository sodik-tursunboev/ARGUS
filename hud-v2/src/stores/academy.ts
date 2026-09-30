import { writable } from 'svelte/store';
import { fetchAcademy, trainAcademy, cancelAcademy, type AcademyDTO } from '../services/api';

interface AcademyState { link: 'loading' | 'online' | 'offline'; snapshot: AcademyDTO | null; error: string; }
export const academyState = writable<AcademyState>({ link: 'loading', snapshot: null, error: '' });

export async function refreshAcademy(): Promise<void> {
  try {
    const snapshot = await fetchAcademy();
    academyState.set({ link: 'online', snapshot, error: '' });
  } catch (error) {
    academyState.update((current) => ({ ...current, link: 'offline', error: error instanceof Error ? error.message : 'Academy unavailable' }));
  }
}

export async function sendToAcademy(agentIds: string[], topic = ''): Promise<void> {
  await trainAcademy(agentIds, topic);
  await refreshAcademy();
}

export async function stopAcademy(agentId: string): Promise<void> {
  await cancelAcademy(agentId);
  await refreshAcademy();
}
