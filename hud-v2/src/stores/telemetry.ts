import { derived, writable } from 'svelte/store';
import type { BackendTelemetry } from '../types/argus';

export const telemetry = writable<BackendTelemetry | null>(null);
export const metric = derived(telemetry, ($telemetry) => ({
  cpu: typeof $telemetry?.cpu === 'number' ? $telemetry.cpu : null,
  memory: typeof $telemetry?.mem_pct === 'number' ? $telemetry.mem_pct : null,
  disk: typeof $telemetry?.disk_pct === 'number' ? $telemetry.disk_pct : null,
  gpu: $telemetry?.gpu_available && typeof $telemetry.gpu_pct === 'number' ? $telemetry.gpu_pct : null
}));
