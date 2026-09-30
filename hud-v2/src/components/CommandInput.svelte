<script lang="ts">import { onMount } from 'svelte'; import { connection } from '../stores/connection'; import { agent } from '../stores/agent'; import { dispatchCommand, pendingAuth } from '../stores/authFlow'; import { IconMic, IconSend } from '../lib/ui/icons';
  // dock=true renders the persistent application dock used on every page
  // except the dashboard: a compact one-line bar that reserves its own grid
  // row (it never floats over page content) and expands only while it is
  // actually in use -- focused, holding a draft, mid-dispatch, waiting on the
  // backend's auth request, or while the agent is working a command.
  export let dock=false;
  let draft=''; let pending=false; let notice='READY'; let input:HTMLInputElement; let history:string[]=[]; let historyIndex=-1; let focused=false;
  // 'loading' means no successful connection has ever been confirmed (see
  // snapshot.ts's bootstrapSnapshot) -- as untrustworthy as 'unavailable' for
  // whether a submitted command will actually reach a live backend.
  $: offline = $connection.source==='unavailable'||$connection.source==='loading';
  // Stale = we HAD a live backend but the latest polls/WS are failing. The
  // console stays usable (the backend may still answer) but states it.
  $: stale = $connection.source==='stale'||$connection.socket==='reconnecting';
  $: working = ['understanding','planning','executing','verifying','waiting_auth'].includes($agent.state);
  $: expanded = !dock || focused || pending || !!$pendingAuth || draft.trim().length>0 || working;
  $: stateNote = $pendingAuth ? 'AUTH REQUIRED' : pending ? 'PROCESSING' : working ? $agent.state.replace('_',' ').toUpperCase() : stale && notice==='READY' ? 'STALE LINK' : notice;
  async function submit(){if(pending||!draft.trim()||offline)return;const text=draft.trim();history=[text,...history.filter((item)=>item!==text)].slice(0,12);historyIndex=-1;pending=true;notice='PROCESSING';try{await dispatchCommand(text);draft='';notice='READY';}catch{notice='RETRY';}finally{pending=false;}} function key(event:KeyboardEvent){if(event.key==='Enter'){event.preventDefault();void submit();}if(event.key==='Escape'){draft='';input?.blur();}if(event.key==='ArrowUp'&&history.length){event.preventDefault();historyIndex=Math.min(historyIndex+1,history.length-1);draft=history[historyIndex];}if(event.key==='ArrowDown'&&historyIndex>=0){event.preventDefault();historyIndex-=1;draft=historyIndex>=0?history[historyIndex]:'';}} onMount(()=>{const focus=(event:KeyboardEvent)=>{if((event.ctrlKey||event.metaKey)&&event.code==='Space'){event.preventDefault();input?.focus();}};window.addEventListener('keydown',focus);return()=>window.removeEventListener('keydown',focus);});</script>
<section class="panel command" class:dock class:compact={dock && !expanded} class:working aria-label="Command console" data-testid="command"><div class="panel-title"><h2>VOICE / COMMAND</h2><span class:unknown={offline} class:amber={!!$pendingAuth||stale} class="status">{offline?'OFFLINE':stateNote}</span></div><div class="command-line"><button type="button" disabled title="No browser microphone capture route is exposed" aria-label="Microphone unavailable"><IconMic size={18} aria-hidden="true"/></button><input bind:this={input} bind:value={draft} disabled={offline||pending} on:keydown={key} on:focus={()=>focused=true} on:blur={()=>focused=false} placeholder={dock&&!expanded?'Command  ·  CTRL+SPACE':'Speak to ARGUS or type a command...'} /><button type="button" disabled={offline||pending||!draft.trim()} on:click={submit} aria-label="Send command"><IconSend size={18} aria-hidden="true"/></button></div><small class="command-help">{#if $pendingAuth}AUTHORIZATION PENDING · {$pendingAuth.action.toUpperCase()} · {$pendingAuth.level}{:else}CTRL+K PALETTE · CTRL+SPACE COMMAND · ↑/↓ RECENT · ESC CLEAR{/if}</small></section>
