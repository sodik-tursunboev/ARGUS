<script lang="ts">
  // One authentication method (PIN / VOICE / FACE): a large icon (40px), the
  // method name (17px bold), its real status as the card's lead value, the
  // backend facts behind it, and a slot for the method's own control. The card
  // says what the backend reported and nothing more -- see lib/authMethods.ts.
  import type { Fact, Tone } from '../../lib/authMethods';
  export let title: string;
  export let icon: any;
  export let status: string;
  export let tone: Tone = 'dim';
  export let facts: Fact[] = [];
  export let note = '';
  export let testid: string | undefined = undefined;
</script>

<article class="mcard {tone}" data-testid={testid} aria-label={`${title} authentication`}>
  <header class="mhead">
    <span class="micon" aria-hidden="true"><svelte:component this={icon} weight="duotone" /></span>
    <div class="mtitle">
      <h3>{title}</h3>
      <b class="mstatus">{status}</b>
    </div>
  </header>
  {#if facts.length}
    <dl class="mfacts">
      {#each facts as fact (fact.k)}<div><dt>{fact.k}</dt><dd class={fact.tone ?? 'dim'}>{fact.v}</dd></div>{/each}
    </dl>
  {/if}
  <div class="mact"><slot /></div>
  {#if note}<p class="mnote">{note}</p>{/if}
</article>

<style>
  /* chamfered on opposite corners (TR + BL), one step in from the panels' 10px cut */
  .mcard {
    --accent: var(--muted, #537a84);
    position: relative; display: flex; flex-direction: column; gap: clamp(8px, 1.1vh, 12px); min-width: 0;
    padding: clamp(12px, 1.6vh, 16px) clamp(13px, 1.1vw, 18px);
    background: linear-gradient(160deg, rgba(11, 30, 36, .82), rgba(4, 13, 17, .66));
    border: 1px solid color-mix(in srgb, var(--accent) 38%, rgba(0, 234, 242, .1));
    box-shadow: inset 0 1px 0 rgba(210, 245, 250, .05), inset 0 0 26px rgba(0, 234, 242, .03);
    clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px));
  }
  .mcard::before { content: ''; position: absolute; left: 12px; top: 0; width: 26px; height: 2px; background: var(--accent); opacity: .95; }
  .mcard.ok { --accent: var(--green, #2df0a6); }
  .mcard.info { --accent: var(--cyan, #00eaf2); }
  .mcard.warn { --accent: var(--amber, #ffc24d); }
  .mcard.bad { --accent: var(--red, #ff4a63); }

  .mhead { display: flex; align-items: center; gap: clamp(11px, 1vw, 15px); min-width: 0; }
  .micon { display: grid; place-items: center; flex: 0 0 auto; width: clamp(34px, 3vw, 44px); height: clamp(34px, 3vw, 44px); color: var(--cyan-soft, #6ef3fb); filter: drop-shadow(0 0 8px rgba(0, 234, 242, .28)); }
  .micon :global(svg) { display: block; width: 100%; height: 100%; }
  .mtitle { display: grid; gap: 4px; min-width: 0; }
  h3 { margin: 0; font: 700 var(--ds-title, 17px)/1.1 var(--font-ui); letter-spacing: .09em; text-transform: uppercase; color: var(--text, #edf8fa); }
  /* the lead value: important, so it is large, coloured by tone, and WRAPS rather than truncates */
  .mstatus { min-width: 0; overflow-wrap: anywhere; font: 700 clamp(19px, 1.5vw, 24px)/1.1 var(--font-data); letter-spacing: .02em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  .ok .mstatus { color: var(--green, #2df0a6); }
  .info .mstatus { color: var(--cyan-soft, #6ef3fb); }
  .warn .mstatus { color: var(--amber, #ffc24d); }
  .bad .mstatus { color: var(--red, #ff4a63); }

  .mfacts { display: grid; margin: 0; min-width: 0; }
  .mfacts > div { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: baseline; column-gap: 12px; min-width: 0; padding: 6px 0; border-top: 1px solid rgba(223, 251, 255, .075); }
  dt { min-width: 0; font: 600 var(--ds-ui, 13px)/1.2 var(--font-ui); letter-spacing: .06em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  dd { margin: 0; min-width: 0; max-width: 100%; overflow-wrap: anywhere; text-align: right; font: 700 var(--ds-ui, 13px)/1.2 var(--font-data); letter-spacing: .03em; text-transform: uppercase; color: var(--text, #edf8fa); }
  dd.ok { color: var(--green, #2df0a6); }
  dd.warn { color: var(--amber, #ffc24d); }
  dd.bad { color: var(--red, #ff4a63); }
  dd.info { color: var(--cyan-soft, #6ef3fb); }
  dd.dim { color: var(--secondary, #94bcc5); }

  .mact { display: grid; gap: 9px; min-width: 0; }
  .mact:empty { display: none; }
  /* notes carry real caveats ("presence only", "never records audio"): secondary colour, not muted, so they stay readable */
  .mnote { margin: 0; margin-top: auto; padding-top: 2px; font: 500 var(--ds-data, 12px)/1.4 var(--font-ui); color: var(--secondary, #94bcc5); overflow-wrap: anywhere; }
</style>
