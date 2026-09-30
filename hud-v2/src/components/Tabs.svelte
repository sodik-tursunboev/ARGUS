<script lang="ts">
  // The ONE page heading + sub-tab strip, used by every page (Tasks, Agents,
  // Modules, Security, Logs, Tools, Authentication). Every tab carries a Phosphor
  // icon from the shared registry (lib/ui/icons.ts TAB_ICONS, keyed by `group`),
  // 18px against a 13px label -- the same "icon leads the text" rule the primary
  // navigation follows at 20px. No page carries its own tab CSS or icon logic.
  // A page with a heading and no views (Authentication) passes no items.
  import { createEventDispatcher } from 'svelte';
  import { iconSize, tabIcon } from '../lib/ui/icons';
  export let title: string;
  /** Which page's tabs these are: selects the icon set. */
  export let group = '';
  export let items: string[] = [];
  export let active = '';
  const dispatch = createEventDispatcher<{ select: string }>();
</script>

<section class="page-heading">
  <h1>{title}</h1>
  {#if items.length}
    <!-- .tabstrip / .stab, not the legacy .subtabs: those rules carry !important font-size/padding that would flatten the icons -->
    <div class="tabstrip" role="tablist" aria-label={`${title} views`}>
      {#each items as item (item)}{@const Icon = tabIcon(group, item)}
        <button type="button" role="tab" class="stab" class:active={active === item} aria-selected={active === item} data-tab={item} on:click={() => dispatch('select', item)}>
          <Icon size={iconSize.tab} weight={active === item ? 'duotone' : 'regular'} aria-hidden="true" /><span>{item}</span>
        </button>
      {/each}
    </div>
  {/if}
</section>

<style>
  .tabstrip { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; min-width: 0; }
  .stab {
    position: relative; display: inline-flex; align-items: center; gap: 8px; min-width: 0;
    height: 38px; padding: 0 14px; margin: 0; border: 0; border-radius: 0; background: transparent; cursor: pointer;
    color: var(--secondary); font: 700 13px/1 var(--font-ui); letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
    transition: color 160ms ease, background-color 160ms ease;
  }
  .stab :global(svg) { flex: 0 0 auto; display: block; width: 18px; height: 18px; }
  .stab:hover { color: var(--text); background: linear-gradient(180deg, transparent 30%, rgba(0, 234, 242, .07)); }
  .stab:hover :global(svg) { color: var(--cyan-soft); }
  .stab.active { color: var(--cyan-soft); background: linear-gradient(180deg, transparent 20%, rgba(0, 234, 242, .12)); }
  .stab:focus-visible { outline: 2px solid color-mix(in srgb, var(--cyan) 75%, transparent); outline-offset: -3px; }
  /* active marker: the button's own underline, scaled in -- costs no width, so selecting a tab never shifts the strip */
  .stab::after {
    content: ''; position: absolute; left: 10px; right: 10px; bottom: 0; height: 2px;
    background: var(--cyan); box-shadow: 0 0 10px rgba(0, 234, 242, .65);
    transform: scaleX(0); transform-origin: left center; transition: transform 200ms ease;
  }
  .stab.active::after { transform: scaleX(1); }
  @media (prefers-reduced-motion: reduce) { .stab, .stab::after { transition: none; } }
</style>
