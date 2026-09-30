<script lang="ts">
  import DashPanel from '../ui/Panel.svelte';
  import { snapshotStatus } from '../../stores/snapshotView';
  import { connection } from '../../stores/connection';
  import { speech } from '../../stores/voice';
  import { IconAI } from '../../lib/ui/icons';
  // Dashboard summary of the local model. Same backend contract and the same
  // wording rules as LocalAI.svelte (which the Tools page still uses): model is
  // the configured OLLAMA_MODEL, engine the routing tier of the LAST completed
  // exchange, history the live conversation window. STT and TTS are the
  // CONFIGURED speech model and voice, read from GET /settings (WHISPER_MODEL,
  // PIPER_MODEL_PATH -> the voice file's name): the backend exposes no engine or
  // worker-health endpoint (see stores/voice.ts for the trace), so engine names
  // are never shown and a missing field stays NOT REPORTED. The live voice
  // SESSION (listening / speaking ...) is the Voice chip in the core.
  // LATENCY is /status.last_latency_ms: the total time of the last completed
  // exchange, reported by the backend (null until one has happened).
  const NOT_REPORTED = 'NOT REPORTED';
  const reported = (value: unknown, fallback = NOT_REPORTED): string =>
    value === null || value === undefined || value === '' ? fallback : String(value);
  const fmtLatency = (ms: number): string => ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`;
  $: status = $snapshotStatus;
  $: model = typeof status?.model === 'string' && status.model ? status.model : NOT_REPORTED;
  $: engine = reported(status?.engine, 'LOCAL (NO EXCHANGE YET)').toUpperCase();
  $: conversation = typeof status?.history_msgs === 'number' && typeof status?.history_max === 'number'
    ? `${status.history_msgs} / ${status.history_max}` : NOT_REPORTED;
  $: latency = typeof status?.last_latency_ms === 'number' ? fmtLatency(status.last_latency_ms) : NOT_REPORTED;
  $: offline = !($connection.source === 'live' || $connection.source === 'partial');
  $: degraded = $connection.source === 'stale';
  const absent = (v: string): boolean => v === NOT_REPORTED || v === 'DISCONNECTED' || v === 'UNAVAILABLE' || v === '—';
  // never-fetched reads NOT REPORTED; a failed /settings read reads UNAVAILABLE; a reachable answer without the field stays NOT REPORTED
  const speechValue = (value: string | null): string => offline ? '—' : value ?? ($speech.source === 'unavailable' ? 'UNAVAILABLE' : NOT_REPORTED);
  // The model id is authoritative and case-sensitive: never upper-cased, never rewritten.
  $: rows = [
    { k: 'MODEL', v: offline ? 'DISCONNECTED' : model, hero: true, tip: 'Local model (configured)' },
    { k: 'ENGINE', v: engine, tip: 'Routing tier of the last exchange' },
    { k: 'HISTORY', v: offline ? '—' : conversation, tip: 'Conversation window' },
    { k: 'LATENCY', v: offline ? '—' : latency, tip: 'Total time of the last exchange' },
    { k: 'STT', v: speechValue($speech.sttModel), tip: 'Speech-to-text model (configured)' },
    { k: 'TTS', v: speechValue($speech.ttsVoice), tip: 'Text-to-speech voice (configured)' },
  ];
</script>

<DashPanel title="LOCAL AI" icon={IconAI} testid="local-ai" grow={1}>
  <span slot="end" class="dchip" class:ok={!offline} class:warn={offline}>{offline && !degraded ? $connection.source.toUpperCase() : degraded ? 'STALE' : 'CONFIGURED'}</span>
  <div class="drows rows">
    {#each rows as r (r.k)}
      <div class="drow row" title={r.tip}><span class="dk">{r.k}</span><span class="dv val" class:hero={r.hero} class:dim={absent(r.v)} title={r.v}>{r.v}</span></div>
    {/each}
  </div>
</DashPanel>

<style>
  .rows { flex: 1 1 auto; }
  .row { grid-template-columns: minmax(62px, 30%) minmax(0, 1fr); }
  /* every value is already worded in its final case (NOT REPORTED, LOCAL, 1.2 s, the model id) */
  .val { text-transform: none; }
  /* The model name is the one value people read at a glance: larger, cyan,
     original case, and only ever shortened by a controlled ellipsis (the full
     id is in the title tooltip). */
  .val.hero { font-size: var(--ds-label, 15px); color: var(--cyan-soft, #6ef3fb); letter-spacing: .01em; }
  .val.hero.dim { color: var(--muted, #537a84); }
</style>
