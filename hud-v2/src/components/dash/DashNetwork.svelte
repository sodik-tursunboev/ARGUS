<script lang="ts">
  import DashPanel from '../ui/Panel.svelte';
  import { telemetry } from '../../stores/telemetry';
  import { connection } from '../../stores/connection';
  import { securityReport } from '../../stores/snapshotView';
  import { IconNetwork } from '../../lib/ui/icons';
  // Dashboard summary of the network. The globe and topology chain live only on
  // the Tools page's NetworkPanel; here the panel keeps the three facts worth
  // an immediate glance, all real: the egress-policy STATUS the backend
  // enforces, the LINK state of the backend channel, and the byte counters the
  // backend samples (session totals). The backend reports no network latency,
  // so none is shown; the one latency it does report (last model exchange) is
  // in LOCAL AI.
  const SOCKET_UP: Record<string, string> = {
    connected: 'ONLINE', connecting: 'CONNECTING', reconnecting: 'RECONNECTING',
    degraded: 'DEGRADED', disconnected: 'OFFLINE', failed: 'OFFLINE',
  };
  const gb = (value: number | undefined): string | null => typeof value === 'number' ? value.toFixed(2) : null;
  $: status = $telemetry ? ($securityReport?.network?.egress_policy ? 'EGRESS ENFORCED' : 'SNAPSHOT') : 'UNKNOWN';
  $: link = SOCKET_UP[$connection.socket] ?? $connection.source.toUpperCase();
  $: linkTone = link === 'ONLINE' ? 'ok' : link === 'OFFLINE' ? 'bad' : 'warn';
  $: recv = gb($telemetry?.net_recv_gb);
  $: sent = gb($telemetry?.net_sent_gb);
</script>

<DashPanel title="NETWORK" icon={IconNetwork} testid="network" grow={.7}>
  <span slot="end" class="dchip" class:info={!!$telemetry} class:warn={!$telemetry} title={$securityReport?.network?.egress_policy ?? 'Egress policy not reported'}>{status}</span>
  <div class="stats">
    <div class="stat"><span class="dk">LINK</span><b class="dv big {linkTone}" title={link}>{link}</b></div>
    <div class="stat"><span class="dk">RECEIVED</span><b class="dv big" class:dim={recv === null}>{#if recv !== null}{recv}<em>GB</em>{:else}—{/if}</b></div>
    <div class="stat"><span class="dk">SENT</span><b class="dv big" class:dim={sent === null}>{#if sent !== null}{sent}<em>GB</em>{:else}—{/if}</b></div>
  </div>
</DashPanel>

<style>
  .stats {
    flex: 1 1 auto; display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr) minmax(0, 1fr);
    align-content: center; gap: 0 clamp(8px, .8vw, 14px); min-width: 0;
  }
  .stat { display: grid; align-content: center; gap: clamp(3px, .5vh, 6px); min-width: 0; }
  .stat .dk { font-size: var(--ds-sec, 11px); letter-spacing: .09em; }
  .stat .big { font-size: var(--ds-label, 15px); letter-spacing: .02em; }
  .stat .big em { margin-left: 3px; font-style: normal; font-size: .72em; font-weight: 700; color: var(--secondary, #94bcc5); }
</style>
