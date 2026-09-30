<script lang="ts">
  // Network panel. The globe is a structural visual (wireframe hemisphere,
  // drifting meridians) -- it plots no locations, cities or geolocation and
  // carries no fabricated data. The counters beside it are the backend's real
  // byte counters; a value the backend does not report (connection count)
  // stays a dash. Node pulses fire only when a REAL backend event arrives on
  // the live timeline -- decoration keyed to reality, never on a timer.
  import { telemetry } from '../stores/telemetry'; import { connection } from '../stores/connection'; import { securityReport } from '../stores/snapshotView'; import { timeline } from '../stores/events'; import { IconNetwork } from '../lib/ui/icons';
  const gb = (value: number | undefined) => typeof value === 'number' ? `${value.toFixed(2)} GB` : '—';
  const lat = [-34, -17, 0, 17, 34];
  const meridians = [-42, -28, -14, 0, 14, 28, 42];
  // Structural node layout (abstract, no geography): the gateway sits on the
  // rim, the local host is emphasized near the centre, externals are spread.
  const externals: Array<[number, number, number]> = [
    [-30, -18, 1.5], [-12, -28, 1.2], [16, -16, 1.6], [28, 6, 1.3],
    [10, 26, 1.4], [-16, 20, 1.2], [-34, 8, 1.1],
  ];
  const arcs = [
    'M -2 2 Q -18 -14 -30 -18', 'M -2 2 Q 6 -20 16 -16', 'M -2 2 Q 18 0 28 6',
    'M -2 2 Q 4 16 10 26', 'M -2 2 Q -12 14 -16 20', 'M 16 -16 Q 24 -8 28 6',
  ];
  $: linkOk = $connection.source === 'live' || $connection.source === 'partial';
  // Real-activity pulse: re-keyed only when a fresh backend event lands.
  $: activityKey = $timeline.length ? $timeline[0].id : 'quiet';
</script>
<section class="panel network" data-testid="network"><div class="panel-title"><h2><IconNetwork size={12} class="h2-icon" aria-hidden="true"/>NETWORK</h2><span class:unknown={!$telemetry} class="status" title={$securityReport?.network?.egress_policy ?? 'Egress policy not reported'}>{$telemetry ? ($securityReport?.network?.egress_policy ? 'EGRESS ENFORCED' : 'SNAPSHOT') : 'UNKNOWN'}</span></div>
  <div class="net-visual">
    <svg class="globe" viewBox="-52 -52 104 104" aria-hidden="true" focusable="false" data-testid="network-globe">
      <defs><clipPath id="globe-clip"><circle r="48"/></clipPath></defs>
      <circle class="globe-halo" r="49"/>
      <circle class="globe-rim" r="48"/>
      <circle class="globe-outer" r="44.5"/>
      <g clip-path="url(#globe-clip)">
        {#each lat as y}<ellipse class="globe-line" cx="0" cy={y} rx={Math.sqrt(48*48 - y*y)} ry={Math.sqrt(48*48 - y*y) * 0.22}/>{/each}
        <g class="globe-meridians">{#each meridians as x}<ellipse class="globe-line" cx={x} cy="0" rx={Math.max(2, 48 - Math.abs(x) * 1.05)} ry="48"/>{/each}{#each meridians as x}<ellipse class="globe-line" cx={x + 98} cy="0" rx={Math.max(2, 48 - Math.abs(x) * 1.05)} ry="48"/>{/each}</g>
        <g class="globe-nodes">
          {#each externals as [x, y, r]}<circle class="globe-ext" cx={x} cy={y} r={r}/>{/each}
          {#each arcs as d}<path class="globe-arc" d={d}/>{/each}
          <g class="globe-gateway"><circle class="gateway-ring" cx="-2" cy="2" r="4.6"/><circle class="gateway-core" cx="-2" cy="2" r="1.9"/></g>
          {#key activityKey}<g class="globe-pulse"><circle cx="-2" cy="2" r="3"/><circle cx="16" cy="-16" r="2.4"/></g>{/key}
        </g>
      </g>
    </svg>
    <div class="topology-chain" class:degraded={!linkOk}><b><i class="dot"></i>ARGUS</b><span></span><b><i class="dot"></i>LOCAL HOST</b><span></span><b><i class="dot"></i>FASTAPI</b><span></span><b><i class="dot"></i>MODEL</b></div>
  </div>
  <div class="net-count"><div><b>{gb($telemetry?.net_recv_gb)}</b><span>RECEIVED</span></div><div><b>{gb($telemetry?.net_sent_gb)}</b><span>SENT</span></div><div><b>—</b><span>CONNECTIONS</span></div></div>
</section>
