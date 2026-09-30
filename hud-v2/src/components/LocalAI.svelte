<script lang="ts">
  import { snapshotStatus } from '../stores/snapshotView';
  import { connection } from '../stores/connection';
  import { IconAI } from '../lib/ui/icons';
  $: status = $snapshotStatus;
  // Backend /status contract: model is the configured OLLAMA_MODEL (always
  // present on a live snapshot), engine is the routing tier of the LAST
  // completed exchange, history is the live conversation window. STT/TTS
  // have no REST contract yet — rendered as NOT REPORTED (a documented
  // absence), never as UNKNOWN (which would claim the backend answered).
  const reported = (value: unknown, fallback = 'NOT REPORTED'): string =>
    value === null || value === undefined || value === '' ? fallback : String(value);
  $: model = typeof status?.model === 'string' && status.model ? status.model : 'NOT REPORTED';
  $: engine = reported(status?.engine, 'LOCAL (NO EXCHANGE YET)').toUpperCase();
  $: conversation = typeof status?.history_msgs === 'number' && typeof status?.history_max === 'number'
    ? `${status.history_msgs} / ${status.history_max}` : 'NOT REPORTED';
  $: offline = !($connection.source === 'live' || $connection.source === 'partial');
  $: degraded = $connection.source === 'stale';
</script>
<section class="panel local-ai" data-testid="local-ai">
  <div class="panel-title"><h2><IconAI size={12} class="h2-icon" aria-hidden="true"/>LOCAL AI</h2><span class:unknown={offline && !degraded} class="status">{offline ? $connection.source.toUpperCase() : 'CONFIGURED'}</span></div>
  <dl>
    <div><dt>MODEL</dt><dd>{offline ? 'DISCONNECTED' : model}</dd></div>
    <div><dt>ENGINE</dt><dd>{engine}</dd></div>
    <div><dt>HISTORY</dt><dd>{offline ? '—' : conversation}</dd></div>
    <div><dt>STT</dt><dd class="dim">NOT REPORTED</dd></div>
    <div><dt>TTS</dt><dd class="dim">NOT REPORTED</dd></div>
  </dl>
</section>
