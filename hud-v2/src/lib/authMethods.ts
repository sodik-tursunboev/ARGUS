/* ARGUS HUD V2 — authentication METHODS, as data.

   PURE: no stores, no fetching. Turns the backend's own reports into the words
   the Authentication page shows for PIN / VOICE / FACE. It decides nothing about
   access -- it only refuses to CLAIM more than the backend said:

     PIN    the backend's real unlock path (POST /unlock -> auth.verify()). Whether
            it is a required factor comes from /security-report authentication.factors.
     VOICE  the voice CHANNEL: /status voice_state + muted, and /security-report
            voice.{replay_detection, speaker_verification}. The liveness challenge
            (random phrase, auth.py) is spoken and heard by the voice process; the HUD
            never captures audio and has no result to show, so it never shows one.
            voiceauth.py says outright that speaker verification is NOT implemented
            (no embedding backend installed) -- reported here as NOT AVAILABLE.
     FACE   /face/status. faceauth is a PRESENCE factor: it can lock the session on
            walk-away and can be a second factor, but auth.PRESENCE_ONLY_FACTORS
            forbids it ever unlocking alone, and the camera is RGB-only.

   Absent fields read NOT REPORTED, a down link reads DISCONNECTED, a capability
   the backend says is missing reads NOT AVAILABLE. Nothing is guessed. */

import type { BackendAuthStatus, BackendSecurityReport } from '../types/argus';
import type { FaceStatus } from './face';
import type { VoiceSession } from '../stores/voice';

export type Tone = 'ok' | 'warn' | 'bad' | 'dim' | 'info';
export type MethodKey = 'pin' | 'voice' | 'face';
export interface Fact { k: string; v: string; tone?: Tone }
export interface MethodInfo {
  key: MethodKey;
  /** the one word/phrase the card leads with */
  status: string;
  tone: Tone;
  facts: Fact[];
  /** what this method can and can not do, in one sentence */
  note: string;
  /** can it answer a live challenge, in one word (the "available methods" chips) */
  usable: { label: string; tone: Tone };
}
export interface MethodInput {
  reachable: boolean;
  report: BackendSecurityReport | null;
  auth: BackendAuthStatus | null;
  face: FaceStatus | null;
  voice: VoiceSession;
}

const NOT_REPORTED = 'NOT REPORTED';
const onOff = (v: boolean | undefined, on = 'ON', off = 'OFF'): string => v === true ? on : v === false ? off : NOT_REPORTED;
const toneOnOff = (v: boolean | undefined, good: boolean): Tone => v === undefined ? 'dim' : v === good ? 'ok' : 'warn';

/** idle_lock_seconds in words: 300 -> "5 MIN", 45 -> "45 S". */
export function idleLockLabel(seconds: number | undefined): string {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) return NOT_REPORTED;
  return seconds % 60 === 0 ? `${seconds / 60} MIN` : `${Math.round(seconds)} S`;
}

/** The session's lock state, in the backend's words (auth.status()). */
export function sessionState(reachable: boolean, auth: BackendAuthStatus | null): { label: string; tone: Tone } {
  if (!reachable) return { label: 'DISCONNECTED', tone: 'dim' };
  if (!auth) return { label: NOT_REPORTED, tone: 'dim' };
  if (auth.enabled === false) return { label: 'DISABLED', tone: 'dim' };
  if (auth.locked_out) return { label: 'LOCKED OUT', tone: 'bad' };
  if (auth.unlocked === true) return { label: 'UNLOCKED', tone: 'ok' };
  if (auth.unlocked === false) return { label: 'LOCKED', tone: 'warn' };
  return { label: NOT_REPORTED, tone: 'dim' };
}

export function describeMethods({ reachable, report, auth, face, voice }: MethodInput): Record<MethodKey, MethodInfo> {
  const factors = Array.isArray(report?.authentication?.factors) ? report!.authentication!.factors! : null;
  const has = (name: string): boolean | undefined => factors === null ? undefined : factors.includes(name);
  const down = !reachable;

  /* ── PIN ── */
  const pinFacts: Fact[] = [];
  const hashed = report?.authentication?.pin_hashed;
  if (hashed !== undefined) pinFacts.push({ k: 'STORED AS', v: hashed ? 'SALTED HASH' : 'NOT HASHED', tone: hashed ? 'ok' : 'bad' });
  if (auth?.locked_out) pinFacts.push({ k: 'LOCKOUT', v: `${auth.lockout_seconds ?? 0} S`, tone: 'bad' });
  const pin: MethodInfo = {
    key: 'pin',
    status: down ? 'DISCONNECTED' : auth?.enabled === false ? 'DISABLED' : has('pin') === true ? 'REQUIRED' : has('pin') === false ? 'NOT REQUIRED' : 'AVAILABLE',
    tone: down || auth?.enabled === false || has('pin') === false ? 'dim' : 'ok',
    facts: pinFacts,
    note: 'Typed here, sent only to the local backend, cleared at once. It is never shown, logged or stored.',
    usable: down ? { label: 'DISCONNECTED', tone: 'dim' } : auth?.enabled === false ? { label: 'DISABLED', tone: 'dim' } : { label: 'AVAILABLE', tone: 'ok' },
  };

  /* ── VOICE ── */
  const voiceTone: Tone = voice.key === 'listening' || voice.key === 'speaking' || voice.key === 'processing' ? 'info' : voice.key === 'standby' ? 'ok' : voice.key === 'disabled' ? 'warn' : 'dim';
  const speaker = report?.voice?.speaker_verification;
  const voiceFacts: Fact[] = [
    { k: 'LIVENESS CHALLENGE', v: factors === null ? NOT_REPORTED : has('liveness') ? 'REQUIRED' : 'NOT REQUIRED', tone: 'dim' },
    { k: 'REPLAY GUARD', v: onOff(report?.voice?.replay_detection), tone: toneOnOff(report?.voice?.replay_detection, true) },
    { k: 'SPEAKER ID', v: speaker === undefined ? NOT_REPORTED : speaker ? 'AVAILABLE' : 'NOT AVAILABLE', tone: 'dim' },
  ];
  const voiceInfo: MethodInfo = {
    key: 'voice',
    status: voice.label,
    tone: voiceTone,
    facts: voiceFacts,
    note: 'Voice verification happens on the voice channel: say the challenge phrase aloud. This screen never records audio.',
    usable: down ? { label: 'DISCONNECTED', tone: 'dim' }
      : factors === null ? { label: NOT_REPORTED, tone: 'dim' }
      : has('liveness') ? { label: 'SPOKEN CHALLENGE', tone: 'ok' } : { label: 'NOT IN USE', tone: 'dim' },
  };

  /* ── FACE ── */
  const faceFacts: Fact[] = [];
  let faceStatus: string; let faceTone: Tone;
  if (down) { faceStatus = 'DISCONNECTED'; faceTone = 'dim'; }
  else if (!face) { faceStatus = NOT_REPORTED; faceTone = 'dim'; }
  else if (face.available === false) { faceStatus = 'NOT AVAILABLE'; faceTone = 'dim'; }
  else if (face.enrolled === false) { faceStatus = 'NOT ENROLLED'; faceTone = 'warn'; }
  else if (face.enrolled === true) { faceStatus = `ENROLLED · ${face.samples ?? 0} SAMPLES`; faceTone = 'ok'; }
  else { faceStatus = NOT_REPORTED; faceTone = 'dim'; }
  if (face && face.available !== false) {
    faceFacts.push({ k: 'PRESENCE WATCH', v: onOff(face.presence_watch), tone: face.presence_watch ? 'ok' : 'dim' });
    if (typeof face.checks === 'number') faceFacts.push({ k: 'MATCHED', v: `${face.matches ?? 0} / ${face.checks} CHECKS`, tone: 'dim' });
    if (typeof face.camera === 'string' && face.camera) faceFacts.push({ k: 'CAMERA', v: face.camera.toUpperCase(), tone: 'dim' });
  }
  const faceInfo: MethodInfo = {
    key: 'face',
    status: faceStatus,
    tone: faceTone,
    facts: faceFacts,
    note: 'A presence check only: a face never unlocks ARGUS on its own.',
    usable: down ? { label: 'DISCONNECTED', tone: 'dim' }
      : !face ? { label: NOT_REPORTED, tone: 'dim' }
      : face.available === false ? { label: 'NOT AVAILABLE', tone: 'dim' } : { label: 'PRESENCE ONLY', tone: 'info' },
  };

  return { pin, voice: voiceInfo, face: faceInfo };
}

/** The "available methods" line of a live challenge: each method and whether it can answer it. */
export function methodChips(methods: Record<MethodKey, MethodInfo>): Array<{ key: MethodKey; label: string; status: string; tone: Tone }> {
  return (['pin', 'voice', 'face'] as const).map((key) => ({ key, label: key.toUpperCase(), status: methods[key].usable.label, tone: methods[key].usable.tone }));
}
