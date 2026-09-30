<script lang="ts">
  import { telemetry } from '../stores/telemetry';
  import { IconProcess } from '../lib/ui/icons';
  $: processes = $telemetry?.top_processes;
  $: anomalies = $telemetry?.anomalies;
  $: detections = $telemetry?.detections;
  const shown = (items: unknown[] | undefined) => Array.isArray(items) ? String(items.length) : '—';
  import { connection } from '../stores/connection';
  // The VISIBLE count is the backend's own cap description: the sampler
  // returns up to 6 representative processes (top by memory), so the panel
  // states that meaning instead of implying a machine-wide process count.
  $: offline = !($connection.source === 'live' || $connection.source === 'partial');
</script>
<section class="panel processes" data-testid="process-overview"><h2><IconProcess size={12} class="h2-icon" aria-hidden="true"/>PROCESS OVERVIEW</h2><div class="process-values"><div><b>{shown(processes)}</b><span>VISIBLE</span></div><div><b>{shown(anomalies)}</b><span>ANOMALIES</span></div><div><b>{shown(detections)}</b><span>DETECTIONS</span></div></div><p>{offline ? 'Process data DISCONNECTED — values are stale' : processes ? 'Sampler snapshot · top 6 by memory' : 'Sampler has not reported yet'}</p></section>
