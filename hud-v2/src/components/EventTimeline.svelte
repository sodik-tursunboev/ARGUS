<script lang="ts">import { timeline } from '../stores/events'; import { connection } from '../stores/connection'; import DetailDrawer from './DetailDrawer.svelte'; import type { TimelineEvent } from '../types/argus'; import { IconTimeline } from '../lib/ui/icons'; const stamp=(time:number)=>new Date(time).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' }); let selected:TimelineEvent|null=null;
  // Real filter tabs over the real in-memory timeline. SECURITY groups the
  // enforcement categories; SYSTEM the operational ones. No synthetic rows.
  const FILTERS = ['ALL', 'AGENT', 'SECURITY', 'SYSTEM'] as const;
  type Filter = typeof FILTERS[number];
  let filter: Filter = 'ALL';
  const matches = (event: TimelineEvent, f: Filter): boolean => {
    if (f === 'ALL') return true;
    if (f === 'AGENT') return event.category === 'AGENT';
    if (f === 'SECURITY') return ['SECURITY', 'DETECT', 'POLICY', 'AUTH', 'ERROR'].includes(event.category);
    return ['SYSTEM', 'MODEL', 'EXECUTE', 'VERIFY'].includes(event.category);
  };
  $: live = $connection.socket === 'connected';
  $: rows = $timeline.filter((event) => matches(event, filter));
</script>
<section class="panel timeline" data-testid="event-timeline"><div class="timeline-head"><h2><IconTimeline size={12} class="h2-icon" aria-hidden="true"/>EVENT TIMELINE</h2><span class="tl-live" class:on={live}><i></i> {live ? 'LIVE' : $timeline.length ? 'HISTORY' : 'NO EVENTS'}</span></div>
  <div class="tl-tabs" role="tablist" aria-label="Timeline filters">{#each FILTERS as f}<button role="tab" aria-selected={filter===f} class:active={filter===f} on:click={()=>filter=f}>{f}</button>{/each}</div>
  <div class="event-list">{#if rows.length}{#each rows as event (event.id)}<button class:warning={event.severity === 'warning'} class:critical={event.severity === 'critical'} on:click={()=>selected=event}><time>{stamp(event.timestamp)}</time><b class={`chip chip-${event.category.toLowerCase()}`}>{event.category}</b><span>{event.message}</span></button>{/each}{:else}<div><time>—:—:—</time><b>SYSTEM</b><span>{filter === 'ALL' ? 'No safe backend events received' : `No ${filter.toLowerCase()} events in this session`}</span></div>{/if}</div></section><DetailDrawer open={selected!==null} title="EVENT DETAIL" fields={selected?[{label:'CATEGORY',value:selected.category},{label:'SEVERITY',value:selected.severity.toUpperCase()},{label:'TIME',value:new Date(selected.timestamp).toLocaleString()},{label:'MESSAGE',value:selected.message}]:[]} on:close={()=>selected=null}/>
