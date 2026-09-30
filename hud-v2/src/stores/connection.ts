import { derived, writable } from 'svelte/store';
import type { SnapshotSource } from '../types/argus';

export type SocketState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected' | 'degraded' | 'failed';
export interface ConnectionState { source: SnapshotSource; socket: SocketState; lastSuccessAt: number | null; lastSocketEventAt: number | null; lastAttemptAt: number | null; message: string | null; retryCount: number; socketRetryCount: number; }
export const connection = writable<ConnectionState>({ source: 'loading', socket: 'disconnected', lastSuccessAt: null, lastSocketEventAt: null, lastAttemptAt: null, message: null, retryCount: 0, socketRetryCount: 0 });
export const stale = derived(connection, ($connection) => $connection.lastSuccessAt !== null && Date.now() - $connection.lastSuccessAt > 15_000);
