import { derived, get, writable } from 'svelte/store';
import { getSettings } from '../services/api';
import type { BackendStatus } from '../types/argus';
import { connection } from './connection';
import { snapshotStatus } from './snapshotView';

/* VOICE / STT / TTS -- what the backend actually reports, and nothing else.

   ROOT CAUSE of "STT / TTS / voice look disconnected" (traced 2026-09-19):
     1. There is NO speech-engine endpoint. STT (stt_worker.py) and TTS
        (tts_worker.py) run in child processes of the voice process
        (argus -> voice -> {stt, tts}); the orchestrator that serves the HUD
        never sees them, so /status carries no engine, model or health for
        either. The panel therefore said NOT REPORTED, which was true.
     2. What the orchestrator DOES hold is the speech CONFIGURATION: GET /settings
        lists WHISPER_MODEL (the STT model id) and PIPER_MODEL_PATH (the TTS voice
        file). Those are read here -- as configured values, worded as such --
        instead of being hardcoded.
     3. The voice SESSION state (recording / thinking / speaking / standby) and
        the privacy mute ARE reported, in /status.voice_state and /status.muted,
        posted by the listener. But the backend WebSocket never publishes
        voice.state (only telemetry, auth.state, security.state, security.alert),
        and with the socket up the full snapshot only re-polled every 60 s, so
        the HUD showed a voice state up to a minute old. snapshot.ts now polls
        /status on a short lane (this store is fed by it), and 'speaking' -- which
        the listener posts but the HUD never mapped -- is mapped.
   Not available anywhere in the backend contract, and therefore NOT shown as a
   value: the STT/TTS engine names, worker health, wake-word detection state and
   a per-utterance verification result. The rows say NOT REPORTED for those. */

export type SpeechSource = 'unknown' | 'reported' | 'unavailable';
export interface SpeechConfig {
  source: SpeechSource;
  /** /settings WHISPER_MODEL (configured STT model id) */
  sttModel: string | null;
  /** file name of /settings PIPER_MODEL_PATH, without directory or extension (configured TTS voice) */
  ttsVoice: string | null;
  /** /settings ASSISTANT_NAME -- the wake matcher derives from it (settings.py) */
  wakeName: string | null;
  updatedAt: number | null;
}
export const speech = writable<SpeechConfig>({ source: 'unknown', sttModel: null, ttsVoice: null, wakeName: null, updatedAt: null });

const REFRESH_MS = 5 * 60_000;
let inflight = false;

const text = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value.trim() : null;

/** "C:\\...\\voices\\en_US-lessac-medium.onnx" -> "en_US-lessac-medium". Only the file stem is kept: never a directory. */
export function voiceName(path: unknown): string | null {
  const raw = text(path);
  if (!raw) return null;
  const file = raw.split(/[\\/]/).pop() ?? raw;
  return file.replace(/\.onnx(\.json)?$/i, '') || null;
}

/** Speech configuration changes only on restart, so it is read once, then at most every five minutes. */
export async function refreshSpeechConfig(force = false): Promise<void> {
  const current = get(speech);
  if (inflight || (!force && current.updatedAt !== null && Date.now() - current.updatedAt < REFRESH_MS)) return;
  inflight = true;
  try {
    const { fields } = await getSettings();
    const value = (name: string): unknown => fields.find((field) => field.name === name)?.value;
    speech.set({ source: 'reported', sttModel: text(value('WHISPER_MODEL')), ttsVoice: voiceName(value('PIPER_MODEL_PATH')), wakeName: text(value('ASSISTANT_NAME')), updatedAt: Date.now() });
  } catch {
    // keep any values already reported (stale but real); never invent one
    speech.update((c) => ({ ...c, source: c.source === 'reported' ? 'reported' : 'unavailable', updatedAt: Date.now() }));
  } finally {
    inflight = false;
  }
}

/* ── voice session ────────────────────────────────────────────────────── */
export type VoiceSessionKey = 'disconnected' | 'not-reported' | 'disabled' | 'listening' | 'processing' | 'speaking' | 'standby' | 'other';
export interface VoiceSession { key: VoiceSessionKey; label: string; detail: string }

/** /status.voice_state (+ muted) in the HUD's words. Pure. */
export function voiceSessionOf(status: BackendStatus | null, online: boolean): VoiceSession {
  if (!online) return { key: 'disconnected', label: 'DISCONNECTED', detail: 'Backend link is down' };
  if (!status) return { key: 'not-reported', label: 'NOT REPORTED', detail: 'No status from the backend yet' };
  if (status.muted === true) return { key: 'disabled', label: 'DISABLED', detail: 'Privacy mode: ARGUS is not listening' };
  switch (status.voice_state) {
    case 'recording': return { key: 'listening', label: 'LISTENING', detail: 'Capturing speech' };
    case 'thinking': return { key: 'processing', label: 'PROCESSING', detail: 'Working out a reply' };
    case 'speaking': return { key: 'speaking', label: 'SPEAKING', detail: 'Playing a spoken reply' };
    case 'standby': return { key: 'standby', label: 'STANDBY', detail: 'Waiting for the wake word' };
    default: return typeof status.voice_state === 'string' && status.voice_state
      ? { key: 'other', label: status.voice_state.toUpperCase(), detail: 'State reported by the backend' }
      : { key: 'not-reported', label: 'NOT REPORTED', detail: 'The backend sent no voice state' };
  }
}

/** Reachable = the last full snapshot got through (live/partial), or is only stale. */
export const voiceSession = derived([snapshotStatus, connection], ([$status, $connection]) =>
  voiceSessionOf($status, $connection.source === 'live' || $connection.source === 'partial' || $connection.source === 'stale'));
