<script lang="ts">
  import { onMount } from 'svelte';
  import { createEventDispatcher } from 'svelte';
  import { connection } from '../stores/connection';
  import { pendingAuth } from '../stores/authFlow';
  import BrandLockup from './BrandLockup.svelte';
  import { IconDashboard, IconTasks, IconAgents, IconOperations, IconModules, IconSecurity, IconAuthentication, IconLogs, IconTools, IconAbout, IconSettings, IconMore, IconCaret, iconSize } from '../lib/ui/icons';
  export let page: 'dashboard'|'tasks'|'agents'|'operations'|'modules'|'security'|'authentication'|'logs'|'tools'|'about'|'settings';
  const dispatch=createEventDispatcher<{navigate: typeof page}>(); const primary=['dashboard','tasks','agents','operations','security','authentication'] as const; const more=['modules','logs','tools','about','settings'] as const;
  const NAV_ICONS = { dashboard: IconDashboard, tasks: IconTasks, agents: IconAgents, operations: IconOperations, modules: IconModules, security: IconSecurity, authentication: IconAuthentication, logs: IconLogs, tools: IconTools, about: IconAbout, settings: IconSettings } as const;
  // A challenge the BACKEND raised (authFlow.pendingAuth) marks the Authentication tab until it is resolved.
  $: authAttention = !!$pendingAuth;

  /* ── MORE menu: explicit deterministic state ────────────────────────────
     The previous implementation used a native details element bound with
     bind:open, which kept its own DOM open-attribute in play and had NO
     outside-click, Escape, route-change or focus-loss dismissal — the menu
     could stay open indefinitely over the dashboard. State now has exactly
     one boolean and one writer (setMoreOpen); every dismissal path calls it.
     Listeners are registered on mount and REMOVED on destroy (no leaks). */
  let moreOpen = false;
  let moreNav: HTMLElement;
  let moreTrigger: HTMLButtonElement;
  const setMoreOpen = (open: boolean): void => { moreOpen = open; };
  const toggleMore = (): void => setMoreOpen(!moreOpen);
  // Route change closes the menu — no stale dropdown across pages.
  $: if (page !== undefined) setMoreOpen(false);

  onMount(() => {
    // Click-outside: pointerdown (capture) fires before the trigger's own
    // click, so clicking the trigger while open reaches the toggle (not an
    // instant close-reopen), and any pointer outside the menu closes it.
    const onPointerDown = (event: PointerEvent): void => {
      if (moreOpen && event.target instanceof Node && !moreNav.contains(event.target)) setMoreOpen(false);
    };
    // Escape closes and returns focus to the trigger (ARIA disclosure pattern).
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && moreOpen) { event.stopPropagation(); setMoreOpen(false); moreTrigger?.focus(); }
    };
    // Focus leaving the whole menu widget dismisses it (tab or click into
    // the page). focusout bubbles; relatedTarget null means focus left the
    // document entirely (window blur) and must NOT close it.
    const onFocusOut = (event: FocusEvent): void => {
      if (!moreOpen) return;
      const next = event.relatedTarget;
      if (!(next instanceof Node) || !moreNav.contains(next)) setMoreOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown, true);
    document.addEventListener('keydown', onKeyDown, true);
    moreNav.addEventListener('focusout', onFocusOut);
    const clock = window.setInterval(() => { nowElapsed = new Date(); }, 1_000);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown, true);
      moreNav.removeEventListener('focusout', onFocusOut);
      window.clearInterval(clock);
    };
  });
  // The emblem's eye is lit only while the backend snapshot channel is live --
  // the same real signal the header clock already words as BACKEND LINKED.
  $: linkLive = $connection.source === 'live';
  let nowElapsed = new Date();
  const time = () => nowElapsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const date = () => nowElapsed.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' }).toUpperCase();
  // Compact date for narrow windows (weekday and year dropped): the clock line is
  // "<date> · <connection state>", and at <=1500px the long form pushed the state
  // ("LIVE CHANNEL UNAVAILABLE") past the clock's width, cutting it mid-word.
  const dateShort = () => nowElapsed.toLocaleDateString([], { month: 'short', day: 'numeric' }).toUpperCase();

  // Secondary tactical micro-nav (reference strip beside the wordmark). Each
  // stop maps to a REAL surface -- navigation targets that exist, and ASSIST
  // which focuses the command console via the shared Ctrl+Space handler (a
  // real keydown listener in CommandInput). It never replaces the primary nav.
  type Micro = { label: string; kind: 'nav'; page: typeof page } | { label: string; kind: 'assist' };
  const MICRO: Micro[] = [
    { label: 'OBSERVE', kind: 'nav', page: 'logs' },
    { label: 'ANALYZE', kind: 'nav', page: 'agents' },
    { label: 'PROTECT', kind: 'nav', page: 'security' },
    { label: 'ASSIST', kind: 'assist' },
  ];
  $: activeMicro = page === 'logs' ? 'OBSERVE' : page === 'agents' ? 'ANALYZE' : page === 'security' ? 'PROTECT' : '';
  function microActivate(item: Micro): void {
    if (item.kind === 'nav') dispatch('navigate', item.page);
    else window.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', code: 'Space', ctrlKey: true, bubbles: true }));
  }
</script>

<header class="command-header panel-edge" data-testid="header">
  <div class="header-left">
  <BrandLockup live={linkLive}>
    <nav class="micro-nav" aria-label="Tactical shortcuts" data-testid="micro-navigation">{#each MICRO as item}<button type="button" class:active={activeMicro===item.label} on:click={()=>microActivate(item)}>{item.label}</button>{#if item.label!=='ASSIST'}<svg class="micro-chev" viewBox="0 0 8 8" aria-hidden="true" focusable="false"><path d="M2.2 1 5.4 4 2.2 7"/></svg>{/if}{/each}</nav>
  </BrandLockup>
  </div>
  <nav class="app-nav" aria-label="Application navigation" data-testid="navigation">
    {#each primary as item}{@const Icon = NAV_ICONS[item]}<button class="nav-item" class:active={page===item} class:attention={item==='authentication' && authAttention} aria-current={page===item?'page':undefined} title={item==='authentication' && authAttention ? 'Authentication required' : undefined} on:click={()=>dispatch('navigate',item)}><Icon size={iconSize.nav} weight={page===item?'duotone':'regular'} aria-hidden="true"/><span class="nav-label">{item}</span>{#if item==='authentication' && authAttention}<i class="nav-alert" aria-hidden="true"></i><span class="sr-only">required</span>{/if}</button>{/each}
    <div class="more-nav" bind:this={moreNav}>
      <button type="button" bind:this={moreTrigger} class="more-trigger nav-item" class:active={moreOpen || more.includes(page as typeof more[number])} aria-expanded={moreOpen} aria-haspopup="menu" aria-controls="more-menu" on:click={toggleMore} on:keydown={(e)=>{if(e.key==='ArrowDown'&&!moreOpen){e.preventDefault();setMoreOpen(true);}}}><IconMore size={iconSize.nav} weight={moreOpen || more.includes(page as typeof more[number]) ? 'duotone' : 'regular'} aria-hidden="true"/><span class="nav-label">MORE</span><IconCaret class="nav-caret" size={12} weight="bold" aria-hidden="true"/></button>
      {#if moreOpen}
        <div class="more-menu" id="more-menu" role="menu" aria-label="More pages">
          {#each more as item}{@const Icon = NAV_ICONS[item]}
            <button type="button" role="menuitem" class:active={page===item} aria-current={page===item?'page':undefined}
              on:click={()=>{dispatch('navigate',item); setMoreOpen(false); moreTrigger?.focus();}}
              on:keydown={(e)=>{if(e.key==='Escape'){e.stopPropagation();setMoreOpen(false);moreTrigger?.focus();}}}>
              <Icon size={iconSize.control} weight={page===item?'duotone':'regular'} aria-hidden="true"/><span class="nav-label">{item}</span>
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </nav>
  <div class="header-right">
  <div class="clock" data-testid="clock"><span><em class="dt-long">{date()}</em><em class="dt-short">{dateShort()}</em> · { $connection.socket === 'connected' ? 'CONNECTED' : $connection.socket === 'reconnecting' ? 'RECONNECTING' : $connection.source === 'stale' ? 'LIVE DATA STALE' : $connection.source === 'live' ? 'BACKEND LINKED' : $connection.socket === 'degraded' ? 'LIVE CHANNEL UNAVAILABLE' : $connection.source.toUpperCase() }</span><b>{time()}</b></div>
  </div>
</header>

<style>
  /* HUD V2 design pass 1 -- header identity + primary navigation.
     Scoped on purpose: the legacy header rules in shell/cockpit/stability.css
     fight each other with !important, so the nav and the micro strip are owned
     here (those legacy nav/micro/brand rules were removed, not overridden).
     Scale targets: nav icon 20px > label 13px, icon-to-label gap 8px. */
  .header-left { display: flex; align-items: center; flex: 1 1 auto; min-width: 0; }

  /* ---- clock: long date on wide windows, short date on narrow ones -------- */
  /* <em>, not <span>: the legacy `.clock span{display:block}` rule would stack nested spans */
  .dt-long, .dt-short { font-style: normal; }
  .dt-long { display: inline; }
  .dt-short { display: none; }
  @media (max-width: 1500px) { .dt-long { display: none; } .dt-short { display: inline; } }

  /* ---- primary navigation ------------------------------------------------ */
  /* Six primary tabs + MORE share the row with the brand and the clock, so the
     strip is driven by four tokens that step down with the window (icon stays 20px
     and the label stays 12-13px at every step -- only padding, gap and tracking
     give way). Widths measured at 1366 / 1440 / 1600 / 1920. */
  .command-header .app-nav {
    --nav-pad: 14px; --nav-gap: 8px; --nav-ls: .08em; --nav-fs: 13px; --nav-between: 6px;
    flex: 0 0 auto; display: flex; flex-wrap: nowrap; align-items: center; justify-content: center;
    gap: var(--nav-between); white-space: nowrap; opacity: 1; overflow: visible;
  }
  @media (max-width: 1699px) { .command-header .app-nav { --nav-pad: 11px; --nav-ls: .07em; --nav-between: 3px; } }
  @media (max-width: 1500px) { .command-header .app-nav { --nav-pad: 8px; --nav-gap: 7px; --nav-ls: .05em; --nav-between: 2px; } }
  @media (max-width: 1400px) { .command-header .app-nav { --nav-pad: 7px; --nav-ls: .04em; --nav-fs: 12.5px; --nav-between: 1px; } }
  .nav-item {
    position: relative; display: inline-flex; align-items: center; gap: var(--nav-gap);
    height: 46px; padding: 0 var(--nav-pad); margin: 0;
    border: 0; border-radius: 0; background: transparent; cursor: pointer;
    color: var(--secondary);
    font: 700 var(--nav-fs)/1 var(--font-ui); letter-spacing: var(--nav-ls); text-transform: uppercase;
    transition: color 160ms ease, background-color 160ms ease;
  }
  .nav-item :global(svg) { flex: 0 0 auto; display: block; width: 20px; height: 20px; }
  .nav-item:hover { color: var(--text); background: linear-gradient(180deg, transparent 30%, rgba(0, 234, 242, .07)); }
  .nav-item:hover :global(svg) { color: var(--cyan-soft); }
  .nav-item.active { color: var(--cyan-soft); background: linear-gradient(180deg, transparent 20%, rgba(0, 234, 242, .12)); }
  .nav-item:active { transform: translateY(1px); }
  .nav-item:focus-visible { outline: 2px solid color-mix(in srgb, var(--cyan) 75%, transparent); outline-offset: -3px; }
  /* Active marker: the button's own underline, scaled in -- costs zero width,
     so activating a tab never shifts the strip. */
  .nav-item::after {
    content: ''; position: absolute; left: calc(var(--nav-pad) - 2px); right: calc(var(--nav-pad) - 2px); bottom: 0; height: 2px;
    background: var(--cyan); box-shadow: 0 0 12px rgba(0, 234, 242, .7);
    transform: scaleX(0); transform-origin: left center; transition: transform 200ms ease;
  }
  .nav-item.active::after { transform: scaleX(1); }
  .nav-item :global(.nav-caret) { width: 12px; height: 12px; margin-left: -1px; opacity: .8; transition: transform 160ms ease; }
  .more-trigger[aria-expanded='true'] :global(.nav-caret) { transform: rotate(180deg); }

  /* A challenge the backend raised is waiting on the Authentication tab: amber
     glyph + label, a standing amber underline and a pulsing dot on the glyph. */
  .nav-item.attention, .nav-item.attention :global(svg) { color: var(--amber, #ffc24d); }
  .nav-item.attention::after { background: var(--amber, #ffc24d); box-shadow: 0 0 12px rgba(255, 194, 77, .7); transform: scaleX(1); }
  .nav-alert {
    position: absolute; top: 8px; left: calc(var(--nav-pad) + 13px); width: 8px; height: 8px; border-radius: 50%;
    background: var(--amber, #ffc24d); box-shadow: 0 0 0 2px rgba(6, 18, 22, .95), 0 0 10px rgba(255, 194, 77, .85);
    animation: nav-alert 1.4s ease-in-out infinite;
  }
  @keyframes nav-alert { 50% { opacity: .35; } }
  @media (prefers-reduced-motion: reduce) { .nav-alert { animation: none; } }
  .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

  /* ---- MORE dropdown: same icon + label language as the strip ------------ */
  .more-nav .more-menu { min-width: 190px; padding: 6px; gap: 2px; }
  .more-nav .more-menu button {
    display: flex; align-items: center; gap: 10px; width: 100%; padding: 10px 14px;
    color: var(--secondary); font: 600 12.5px/1 var(--font-ui); letter-spacing: .08em; text-transform: uppercase;
  }
  .more-nav .more-menu button :global(svg) { flex: 0 0 auto; display: block; width: 18px; height: 18px; }
  .more-nav .more-menu button:hover { background: rgba(0, 234, 242, .08); color: var(--text); }
  .more-nav .more-menu button.active { color: var(--cyan-soft); }

  /* ---- tactical micro strip: third line of the identity lockup ----------- */
  /* The strip fills its column exactly (the wordmark sets the column width; the
     stops spread evenly across it), so it is a justified third line of the
     lockup and can never run past the plate's edge. 10px is the decorative floor. */
  .micro-nav { display: flex; align-items: center; justify-content: space-between; align-self: stretch; width: 100%; gap: 5px; margin: 0; font: 600 10px/1 var(--font-ui); letter-spacing: .1em; }
  .micro-nav button {
    position: relative; padding: 0; border: 0; background: transparent; cursor: pointer;
    color: color-mix(in srgb, var(--secondary) 80%, transparent);
    font: inherit; letter-spacing: inherit; text-transform: uppercase; transition: color 160ms ease;
  }
  /* 11px text is a small target: extend the hit area without adding height. */
  .micro-nav button::after { content: ''; position: absolute; inset: -6px -4px; }
  .micro-nav button:hover, .micro-nav button.active { color: var(--cyan-soft); }
  .micro-nav button:focus-visible { outline: 1px solid var(--cyan-soft); outline-offset: 2px; }
  /* The strip is the lockup's third line, so it needs BOTH the tall (72px)
     header and a header wide enough that the primary nav and clock keep their
     room (measured: at 1440px wide the header has zero slack with it). Below
     that it steps aside -- every target is also one click away in the primary
     nav / MORE menu, and ASSIST stays on Ctrl+Space. */
  @media (max-height: 820px), (max-width: 1500px) { .micro-nav { display: none; } }
</style>
