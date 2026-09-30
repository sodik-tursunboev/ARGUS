import { writable } from 'svelte/store';
import type { SecurityAlert, SecurityAuthStatus, SecurityDecision, SecurityFields, SecurityFreshness, SecurityPosture } from '../types/argus';
export type { SecurityAlert, SecurityAuthStatus, SecurityDecision, SecurityFields, SecurityFreshness, SecurityPosture } from '../types/argus';

const unknownFields: SecurityFields = { deviceTrust: 'UNKNOWN', policyEngine: 'UNKNOWN', authLevel: 'UNKNOWN', userPresence: 'UNKNOWN', executor: 'UNKNOWN', networkPolicy: 'UNKNOWN', auditChain: 'UNKNOWN', threatState: 'UNKNOWN' };
export interface SecuritySnapshot {
  posture: SecurityPosture; link: 'offline' | 'unknown' | 'online'; auth: SecurityAuthStatus;
  freshness: SecurityFreshness; fields: SecurityFields; decision: SecurityDecision | null;
  alerts: SecurityAlert[]; recoveryPossible: boolean | null; updatedAt: number | null;
}
export const emptySecurity: SecuritySnapshot = { posture: 'unknown', link: 'offline', auth: 'unknown', freshness: 'loading', fields: unknownFields, decision: null, alerts: [], recoveryPossible: null, updatedAt: null };
export const security = writable<SecuritySnapshot>(emptySecurity);
function same(a: SecuritySnapshot, b: SecuritySnapshot): boolean { return JSON.stringify(a) === JSON.stringify(b); }
/** The sole store writer: bounded alert history and no-op update protection. */
export function setSecuritySnapshot(next: SecuritySnapshot): void {
  security.update((current) => same(current, next) ? current : { ...next, fields: { ...next.fields }, alerts: next.alerts.slice(0, 8) });
}
export function patchSecurity(next: Omit<Partial<SecuritySnapshot>, 'fields'> & { fields?: Partial<SecurityFields> }): void {
  security.update((current) => {
    const merged = { ...current, ...next, fields: next.fields ? { ...current.fields, ...next.fields } : current.fields, alerts: next.alerts ? next.alerts.slice(0, 8) : current.alerts };
    return same(current, merged) ? current : merged;
  });
}
