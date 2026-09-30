<script lang="ts">import { sendCommand } from '../services/api'; import { addEvent } from '../stores/events'; import { connection } from '../stores/connection'; import { createEventDispatcher } from 'svelte'; import type { ActionStatus } from '../types/argus'; import { IconLogs, IconSecurity, IconIntegrity, IconSystem, IconSecurityCenter, IconTools } from '../lib/ui/icons';
  const actions=[
    { label:'Security Summary', cmd:'security summary', icon:IconSecurity },
    { label:'Security State', cmd:'security state', icon:IconIntegrity },
    { label:'System Stats', cmd:'system stats', icon:IconSystem }
  ];
  let state:ActionStatus='idle'; const dispatch=createEventDispatcher<{navigate:string}>();
  // Two of the six tiles are real NAVIGATION shortcuts (Event Log -> logs
  // page, Security Center -> security page); the other three dispatch real
  // read-only commands. Nothing here fabricates an action.
  async function run(label:string,text:string){ if($connection.source==='unavailable'||state==='pending') return; state='pending'; addEvent('AGENT',`${label} requested`); try { const r=await sendCommand(text); const reply=typeof r.reply==='string'?r.reply:'Command completed'; state=/denied|not allowed|refus/i.test(reply)?'denied':'success'; addEvent(state==='denied'?'POLICY':'SYSTEM',reply,state==='denied'?'critical':'info'); } catch { state='failed'; addEvent('ERROR',`${label} could not reach the backend`,'critical'); } }</script>
<section class="panel quick" data-testid="quick-actions"><div class="panel-title"><h2>QUICK ACTIONS</h2><span class="status">{state.toUpperCase()}</span></div><div class="quick-grid">
  <button type="button" on:click={()=>dispatch('navigate','logs')}><i aria-hidden="true"><IconLogs size={15}/></i>Event Log</button>
  {#each actions as action}{@const A = action.icon}<button type="button" disabled={$connection.source==='unavailable'||state==='pending'} on:click={()=>run(action.label,action.cmd)}><i aria-hidden="true"><A size={15}/></i>{action.label}</button>{/each}
  <button type="button" on:click={()=>dispatch('navigate','security')}><i aria-hidden="true"><IconSecurityCenter size={15}/></i>Security Center</button>
  <button type="button" on:click={()=>dispatch('navigate','tools')}><i aria-hidden="true"><IconTools size={15}/></i>Diagnostics</button>
</div></section>
