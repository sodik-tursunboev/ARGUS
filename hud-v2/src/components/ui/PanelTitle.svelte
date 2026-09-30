<script lang="ts">
  // The one panel heading: icon (20-24px) + title (16-18px, bold) + optional
  // status on the right. Every important panel on every page uses this instead
  // of a hand-rolled <div class="panel-title">, so the hierarchy is the same by
  // construction: the icon is always larger than the title's cap height and the
  // status can never cross the frame (it shrinks with an ellipsis before the
  // title does not). Sizes come from the density tokens in styles/dashboard.css.
  export let title: string;
  /** A Phosphor component, rendered duotone at the title-icon token size. */
  export let icon: any = null;
  export let tone: 'normal' | 'critical' | 'warn' = 'normal';
</script>

<header class="ptitle" class:critical={tone === 'critical'} class:warn={tone === 'warn'}>
  {#if icon}<span class="pt-icon" aria-hidden="true"><svelte:component this={icon} weight="duotone" /></span>{/if}
  <h2>{title}</h2>
  <span class="pt-end"><slot /></span>
</header>

<style>
  .ptitle {
    --pt-accent: var(--cyan, #00eaf2);
    position: relative; display: flex; align-items: center; gap: 9px; min-width: 0;
    padding-bottom: clamp(5px, .75vh, 8px); margin: 0 0 clamp(5px, .8vh, 9px);
    border-bottom: 1px solid rgba(223, 251, 255, .09);
  }
  .ptitle.critical { --pt-accent: var(--red, #ff4a63); }
  .ptitle.warn { --pt-accent: var(--amber, #ffc24d); }
  /* bright segment at the start of the title rule */
  .ptitle::after { content: ''; position: absolute; left: 0; bottom: -1px; width: 30px; height: 1px; background: var(--pt-accent); }
  .pt-icon { display: grid; place-items: center; flex: 0 0 auto; width: var(--ds-icon-title, 22px); height: var(--ds-icon-title, 22px); color: var(--cyan-soft, #6ef3fb); }
  .critical .pt-icon { color: var(--red, #ff4a63); }
  .warn .pt-icon { color: var(--amber, #ffc24d); }
  .pt-icon :global(svg) { display: block; width: 100%; height: 100%; }
  h2 {
    margin: 0; padding: 0; min-width: 0; flex: 0 1 auto; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font: 700 var(--ds-title, 17px)/1.1 var(--font-ui); letter-spacing: .07em; text-transform: uppercase; color: var(--text, #edf8fa);
  }
  .pt-end { display: flex; align-items: center; gap: 8px; min-width: 0; margin-left: auto; flex: 0 1 auto; }
</style>
