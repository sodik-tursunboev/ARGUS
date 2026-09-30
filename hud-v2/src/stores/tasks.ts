import { derived, get, writable } from 'svelte/store';
import type { AgentState } from './agent';
import { agent, setAgentSnapshot } from './agent';
import type { ArgusTask, TaskLifecycleStatus } from '../types/argus';

export type { ArgusTask, ArgusTaskStep, TaskLifecycleStatus, TaskStepStatus } from '../types/argus';
export const emptyTask: ArgusTask = { goal: null, status: 'idle', currentStepId: null, steps: [], activeCapability: null, reason: null, replanAvailable: false, revision: 0 };
export const tasks = writable<ArgusTask>(emptyTask);
export const taskProgress = derived(tasks, ($tasks) => {
  const totalSteps = $tasks.steps.length;
  const completedSteps = $tasks.steps.filter((step) => step.status === 'complete' || step.status === 'skipped').length;
  const currentIndex = $tasks.currentStepId ? $tasks.steps.findIndex((step) => step.id === $tasks.currentStepId) : -1;
  return { totalSteps, completedSteps, currentIndex, percent: totalSteps ? (completedSteps / totalSteps) * 100 : 0 };
});
function stateForTask(status: TaskLifecycleStatus): AgentState | null {
  if (status === 'waiting_auth') return 'waiting_auth'; if (status === 'blocked') return 'blocked';
  if (status === 'failed') return 'error'; if (status === 'completed') return 'completed';
  if (status === 'created' || status === 'replanned') return 'planning';
  return status === 'executing' ? 'executing' : null;
}
function normalize(next: ArgusTask): ArgusTask {
  const steps = next.steps.map((step) => ({ ...step }));
  const currentStepId = steps.some((step) => step.id === next.currentStepId) ? next.currentStepId : steps.find((step) => step.status === 'active')?.id ?? null;
  return { ...emptyTask, ...next, steps, currentStepId };
}
/** One authoritative task update path. Task-derived core transitions live here. */
export function setTaskSnapshot(next: ArgusTask): void {
  const task = normalize(next); tasks.set(task);
  const state = stateForTask(task.status);
  if (state) setAgentSnapshot({ ...get(agent), state, activeCapability: task.activeCapability });
}
export function clearTask(): void { tasks.set(emptyTask); }
