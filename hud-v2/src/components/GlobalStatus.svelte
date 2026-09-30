<script lang="ts">
  import { agent } from '../stores/agent'; import { connection } from '../stores/connection'; import { security } from '../stores/security'; import { snapshotStatus } from '../stores/snapshotView'; import { tasks } from '../stores/tasks';
  import NotificationCenter from './NotificationCenter.svelte'; import { createEventDispatcher } from 'svelte';
  const known=(value:string|undefined|null)=>value?.toUpperCase()||'UNKNOWN';
  /* Spacers between chips: inline text nodes, not gap alone -- the chip row
     shares the 14px footer line with the NOTICES summary, and without an
     explicit separator 'NOTICES' rendered glued to the previous chip's
     value (measured in the structural audit). */
  /* Reactive, not const: a plain const evaluated once at mount froze every
     chip on its initial store value (BOOTING/LOADING/DISCONNECTED) for the
     whole session even while REST/WS were live. */
  $: chips = [
    ['ARGUS', known($agent.state)],
    ['BACKEND', $connection.source.toUpperCase()],
    ['WS', $connection.socket.toUpperCase()],
    ['AUTH', $security.auth.toUpperCase()],
    ['SECURITY', $security.posture.toUpperCase()],
    ['MODEL', known($snapshotStatus?.model)],
    ['TASK', $tasks.status.toUpperCase()],
  ] as const;
  const dispatch=createEventDispatcher<{navigate:string}>();
</script>
<section class="global-status" aria-label="ARGUS global status"><div class="status-chips">{#each chips as [label, value]}<span>{label} {value}</span>{/each}</div><NotificationCenter on:navigate={(event)=>dispatch('navigate',event.detail)}/></section>
