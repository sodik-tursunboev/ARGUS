import { writable } from 'svelte/store';
import type { TimelineCategory, TimelineEvent } from '../types/argus';
const maxEvents = 60;
let eventSequence = 0;
export const secret = /(?:token|password|secret|api[_ -]?key|authorization|pin)/i;
export const timeline = writable<TimelineEvent[]>([]);
export function addEvent(category: TimelineCategory, message: unknown, severity: TimelineEvent['severity'] = 'info'): void {
  if (typeof message !== 'string' || secret.test(message)) return;
  const clean = message.replace(/[\r\n\t]+/g, ' ').trim().slice(0, 180); if (!clean) return;
  const timestamp = Date.now();
  const event = { id: `${timestamp}:${eventSequence++}:${category}`, category, message: clean, severity, timestamp };
  timeline.update((rows) => [event, ...rows.filter((row) => row.id !== event.id)].slice(0, maxEvents));
}
export const timelineLimit = maxEvents;
