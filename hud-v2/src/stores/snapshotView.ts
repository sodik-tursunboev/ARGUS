import { writable } from 'svelte/store';
import type { BackendAuthStatus, BackendSecurityReport, BackendStatus, BackendThreatReport } from '../types/argus';
import type { FaceStatus } from '../lib/face';
export const snapshotStatus = writable<BackendStatus | null>(null);
export const securityReport = writable<BackendSecurityReport | null>(null);
export const threatReport = writable<BackendThreatReport | null>(null);
export const faceStatus = writable<FaceStatus | null>(null);
/** GET /auth-status verbatim (auth.status()): the session lock state. Refreshed by the fast lane in snapshot.ts. */
export const authStatus = writable<BackendAuthStatus | null>(null);
