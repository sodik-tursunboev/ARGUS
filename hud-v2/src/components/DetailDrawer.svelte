<script lang="ts">
  import { createEventDispatcher } from 'svelte'; import { IconClose } from '../lib/ui/icons'; export let open=false; export let title='DETAIL'; export let fields:{label:string;value:string}[]=[]; const dispatch=createEventDispatcher<{close:void}>();
  function close(){dispatch('close');} function backdrop(event:MouseEvent){if(event.target===event.currentTarget)close();}
  // Escape is handled at the window while the drawer is open. The previous
  // handler lived on the backdrop div, which only receives key events when it
  // has focus -- so Escape from anywhere else did nothing and the drawer
  // stayed up over the page (caught in the interaction run).
  function key(event:KeyboardEvent){if(open&&event.key==='Escape'){event.stopPropagation();close();}}
</script>
<svelte:window on:keydown={key}/>
{#if open}<div class="drawer-backdrop" role="presentation" on:click={backdrop}><div class="detail-drawer" role="dialog" aria-modal="true" aria-label={title}><header><h2>{title}</h2><button on:click={close} aria-label="Close detail"><IconClose size={16} aria-hidden="true"/></button></header>{#if fields.length}<dl>{#each fields as field}<div><dt>{field.label}</dt><dd>{field.value}</dd></div>{/each}</dl>{:else}<p>NO SAFE DETAIL AVAILABLE</p>{/if}</div></div>{/if}
