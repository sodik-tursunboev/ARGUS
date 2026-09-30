<script lang="ts">
  /* The CEO's inbox: what the organisation needs you to know or decide.

     Reads stores/agentManager.ts (REST-backed, redacted server-side). Every
     button is a REQUEST to /api/agents/inbox/{id}/reply -- the backend routes
     it back to the hire / request / agent it answers. Choosing "hire" is a
     preference the Governor still rules on; it authenticates nothing.
     Message text is rendered as text, never markup. */
  import { onDestroy } from 'svelte';
  import { agentManager, replyTo, markRead, dismissToast } from '../../stores/agentManager';
  import { ROLE_ACCENT, hexToCss } from './cityPalette';
  import type { AgentMessage, InboxSection } from '../../types/argus';

  export let open = false;
  /** Ask the city to select (and frame) an agent. */
  export let onOpenAgent: (agentId: string) => void = () => {};

  const SECTIONS: InboxSection[] = ['IMPORTANT', 'QUESTIONS', 'PROGRESS', 'RESULTS'];
  const OPTION_LABEL: Record<string, string> = {
    hire: 'Approve hire', existing: 'Use existing agents', cancel: 'Cancel request',
    advise: 'Ask PLANNER instead', retry: 'Retry',
  };
  let section: InboxSection = 'QUESTIONS';
  let drafts: Record<string, string> = {};
  let busy: Record<string, boolean> = {};
  let errors: Record<string, string> = {};

  $: msgs = $agentManager.messages;
  $: counts = Object.fromEntries(SECTIONS.map((s) => [s, msgs.filter((m) => m.section === s && !m.read).length]));
  $: shown = msgs.filter((m) => m.section === section).slice(0, 40);
  $: unread = $agentManager.summary?.unread ?? 0;
  $: openQuestions = $agentManager.summary?.open_questions ?? 0;
  // Land on whatever needs the CEO most.
  $: if (open && counts.QUESTIONS === 0 && section === 'QUESTIONS' && counts.IMPORTANT > 0) section = 'IMPORTANT';

  const accent = (id: string) => hexToCss(id === 'manager' ? 0xffd166 : ROLE_ACCENT[id] ?? 0x9fb2c8);
  function ago(ts: number): string {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return 'now';
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
  }

  async function answer(m: AgentMessage, choice = ''): Promise<void> {
    const text = (drafts[m.message_id] ?? '').trim();
    if (!choice && !text) return;
    busy = { ...busy, [m.message_id]: true };
    const err = await replyTo(m, { choice, text });
    busy = { ...busy, [m.message_id]: false };
    errors = { ...errors, [m.message_id]: err ?? '' };
    if (!err) drafts = { ...drafts, [m.message_id]: '' };
  }

  function openMessage(m: AgentMessage): void {
    if (!m.read) void markRead(m.message_id);
  }

  // Toasts: NORMAL/IMPORTANT fade after a while; CRITICAL stays until seen.
  const timers = new Map<string, number>();
  $: for (const t of $agentManager.toasts) {
    if (t.priority !== 'CRITICAL' && !timers.has(t.message_id)) {
      timers.set(t.message_id, window.setTimeout(() => dismissToast(t.message_id), 7000));
    }
  }
  onDestroy(() => { for (const id of timers.values()) window.clearTimeout(id); });

  function openFromToast(m: AgentMessage): void {
    dismissToast(m.message_id);
    section = m.section === 'SENT' ? 'PROGRESS' : m.section;
    open = true;
  }
</script>

<button class="inbox-toggle" class:has={unread > 0} class:ask={openQuestions > 0}
  on:click={() => (open = !open)} aria-expanded={open} aria-label="CEO inbox">
  <span class="ic">✉</span> INBOX
  {#if unread}<b>{unread}</b>{/if}
</button>

<div class="toasts" aria-live="polite">
  {#each $agentManager.toasts.slice(0, 3) as t (t.message_id)}
    <button class="toast {t.priority.toLowerCase()}" style={`--a:${accent(t.sender_agent_id)}`}
      on:click={() => openFromToast(t)}>
      <span class="who">{t.sender_name}</span>
      <span class="what">{t.title}</span>
      {#if t.requires_reply}<span class="need">NEEDS YOU</span>{/if}
    </button>
  {/each}
</div>

{#if open}
  <aside class="inbox" aria-label="CEO inbox">
    <header>
      <div>
        <h3>CEO INBOX</h3>
        <p>Messages from your agents. Replies go back to the exact request they answer.</p>
      </div>
      <button class="x" on:click={() => (open = false)} aria-label="Close inbox">✕</button>
    </header>
    <nav>
      {#each SECTIONS as s}
        <button class:active={section === s} on:click={() => (section = s)}>
          {s}{#if counts[s]}<b>{counts[s]}</b>{/if}
        </button>
      {/each}
    </nav>
    <div class="list">
      {#if $agentManager.link === 'offline'}
        <p class="empty">The Agent Manager is unreachable -- no messages can be shown.</p>
      {:else if !shown.length}
        <p class="empty">{section === 'QUESTIONS' ? 'Nothing is waiting for you.' : 'No messages here yet.'}</p>
      {/if}
      {#each shown as m (m.message_id)}
        <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-noninteractive-element-interactions -->
        <article class="msg {m.priority.toLowerCase()}" class:unread={!m.read} style={`--a:${accent(m.sender_agent_id)}`}
          on:click={() => openMessage(m)}>
          <div class="meta">
            <button class="sender" on:click|stopPropagation={() => onOpenAgent(m.sender_agent_id)}
              title="Show this agent in the city">
              <i></i>{m.sender_name}
            </button>
            <span class="role">{m.sender_role}</span>
            <span class="type t-{m.type.toLowerCase()}">{m.type.replace('_', ' ')}</span>
            <time>{ago(m.created_at)}</time>
          </div>
          <h4>{m.title}</h4>
          {#if m.body}<p class="body">{m.body}</p>{/if}
          {#each m.replies as r}
            <p class="reply">You: {r.choice ? (OPTION_LABEL[r.choice] ?? r.choice) : ''}{r.choice && r.text ? ' -- ' : ''}{r.text}</p>
          {/each}
          {#if m.requires_reply && !m.resolved}
            <div class="actions">
              {#each m.reply_options as o}
                <button class:primary={o === 'hire' || o === 'retry'} disabled={busy[m.message_id]}
                  on:click|stopPropagation={() => answer(m, o)}>{OPTION_LABEL[o] ?? o}</button>
              {/each}
            </div>
            {#if m.type === 'QUESTION'}
              <div class="compose">
                <textarea rows="2" placeholder="Answer in your own words (e.g. paste the code or log)…"
                  bind:value={drafts[m.message_id]} on:click|stopPropagation></textarea>
                <button disabled={busy[m.message_id] || !(drafts[m.message_id] ?? '').trim()}
                  on:click|stopPropagation={() => answer(m)}>Send</button>
              </div>
            {/if}
            {#if m.type === 'APPROVAL_REQUEST'}
              <p class="fine">Approving is a preference, not a permission: the Governor still rules on the hire.</p>
            {/if}
          {/if}
          {#if errors[m.message_id]}<p class="err">{errors[m.message_id]}</p>{/if}
        </article>
      {/each}
    </div>
  </aside>
{/if}

<style>
  .inbox-toggle {
    position: absolute; top: 10px; right: 10px; z-index: 4;
    display: flex; align-items: center; gap: 6px; padding: 6px 12px;
    background: rgba(8, 15, 28, .88); border: 1px solid rgba(255, 209, 102, .45);
    border-radius: 6px; color: #ffe29a; font: 700 10.5px 'Space Grotesk', system-ui, sans-serif;
    letter-spacing: .12em; cursor: pointer;
  }
  .inbox-toggle .ic { font-size: 13px; }
  .inbox-toggle b {
    min-width: 18px; padding: 1px 5px; border-radius: 9px; background: #ffd166; color: #1a1406;
    font-size: 10px; letter-spacing: 0; text-align: center;
  }
  .inbox-toggle.ask { box-shadow: 0 0 0 1px #ffd166, 0 0 18px rgba(255, 209, 102, .35); }
  .inbox-toggle:focus-visible { outline: 2px solid #ffd166; outline-offset: 2px; }

  .toasts { position: absolute; top: 48px; left: 50%; transform: translateX(-50%); z-index: 5;
    display: grid; gap: 6px; width: min(420px, calc(100% - 32px)); pointer-events: none; }
  .toast {
    pointer-events: auto; all: unset; box-sizing: border-box; cursor: pointer;
    display: grid; grid-template-columns: auto 1fr auto; gap: 8px; align-items: center;
    padding: 8px 12px; border-radius: 7px; background: rgba(10, 18, 34, .95);
    border: 1px solid color-mix(in srgb, var(--a) 60%, transparent);
    box-shadow: 0 8px 28px rgba(0, 0, 0, .45); animation: drop .25s ease-out;
    font-family: 'Space Grotesk', system-ui, sans-serif;
  }
  .toast.critical { border-color: #ffd166; box-shadow: 0 0 0 1px #ffd166, 0 0 28px rgba(255, 209, 102, .4); }
  .toast .who { font-size: 10px; font-weight: 800; letter-spacing: .1em; color: var(--a); text-transform: uppercase; }
  .toast .what { font-size: 12px; color: #eef6ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .toast .need { font-size: 9px; font-weight: 800; letter-spacing: .12em; color: #1a1406; background: #ffd166; padding: 2px 6px; border-radius: 3px; }
  .toast:focus-visible { outline: 2px solid #ffd166; }
  @keyframes drop { from { transform: translateY(-8px); opacity: 0; } to { transform: none; opacity: 1; } }
  @media (prefers-reduced-motion: reduce) { .toast { animation: none; } }

  .inbox {
    position: absolute; top: 46px; right: 10px; bottom: 10px; z-index: 6;
    width: min(380px, calc(100% - 20px)); display: grid; grid-template-rows: auto auto 1fr;
    background: rgba(9, 16, 30, .96); border: 1px solid rgba(255, 209, 102, .35);
    border-radius: 9px; box-shadow: 0 18px 50px rgba(0, 0, 0, .5); backdrop-filter: blur(6px);
    font-family: 'Space Grotesk', system-ui, sans-serif;
  }
  header { display: flex; justify-content: space-between; gap: 8px; padding: 12px 14px 6px; }
  header h3 { margin: 0; font-size: 13px; letter-spacing: .14em; color: #ffe29a; }
  header p { margin: 3px 0 0; font-size: 10.5px; color: rgba(214, 228, 240, .6); line-height: 1.35; }
  .x { all: unset; cursor: pointer; color: rgba(214, 228, 240, .7); padding: 0 4px; height: 20px; }
  .x:focus-visible { outline: 2px solid #ffd166; }
  nav { display: flex; gap: 2px; padding: 4px 10px 8px; border-bottom: 1px solid rgba(255, 255, 255, .06); }
  nav button {
    all: unset; cursor: pointer; flex: 1; text-align: center; padding: 5px 2px; border-radius: 5px;
    font-size: 9.5px; font-weight: 700; letter-spacing: .1em; color: rgba(190, 208, 222, .7);
  }
  nav button.active { background: rgba(255, 209, 102, .12); color: #ffe29a; }
  nav button b { margin-left: 4px; color: #1a1406; background: #ffd166; border-radius: 7px; padding: 0 4px; font-size: 9px; }
  nav button:focus-visible { outline: 2px solid #ffd166; }
  .list { overflow-y: auto; padding: 8px 10px 12px; display: grid; gap: 8px; align-content: start; }
  .empty { margin: 18px 4px; font-size: 12px; color: rgba(190, 208, 222, .6); text-align: center; }
  .msg {
    padding: 9px 11px; border-radius: 7px; background: rgba(255, 255, 255, .03);
    border: 1px solid rgba(255, 255, 255, .06); border-left: 3px solid var(--a);
  }
  .msg.unread { background: rgba(255, 255, 255, .06); }
  .msg.important { border-color: rgba(255, 178, 68, .35); border-left-color: var(--a); }
  .msg.critical { border-color: rgba(255, 209, 102, .7); box-shadow: 0 0 16px rgba(255, 209, 102, .18); }
  .meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .sender { all: unset; cursor: pointer; display: flex; align-items: center; gap: 5px;
    font-size: 11px; font-weight: 800; letter-spacing: .04em; color: #eef6ff; }
  .sender i { width: 8px; height: 8px; border-radius: 50%; background: var(--a); box-shadow: 0 0 6px var(--a); }
  .sender:focus-visible { outline: 2px solid var(--a); }
  .role { font-size: 9px; letter-spacing: .1em; color: rgba(190, 208, 222, .55); text-transform: uppercase; }
  .type { font-size: 8.5px; font-weight: 800; letter-spacing: .1em; padding: 1px 5px; border-radius: 3px;
    background: rgba(255, 255, 255, .07); color: rgba(214, 228, 240, .8); }
  .t-approval_request, .t-question { background: rgba(255, 209, 102, .16); color: #ffe29a; }
  .t-warning, .t-failure { background: rgba(255, 138, 106, .16); color: #ffab94; }
  .t-result { background: rgba(74, 222, 158, .14); color: #7fe8b8; }
  time { margin-left: auto; font-size: 10px; color: rgba(190, 208, 222, .5); }
  h4 { margin: 5px 0 3px; font-size: 12.5px; color: #f1f7ff; line-height: 1.3; }
  .body { margin: 0; font-size: 11.5px; line-height: 1.45; color: rgba(214, 228, 240, .82); white-space: pre-wrap; }
  .reply { margin: 6px 0 0; font-size: 11px; color: #ffe29a; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .actions button, .compose button {
    all: unset; cursor: pointer; padding: 5px 10px; border-radius: 5px; font-size: 10.5px; font-weight: 700;
    letter-spacing: .04em; border: 1px solid rgba(214, 228, 240, .25); color: #e6f0f8;
  }
  .actions button.primary { background: #ffd166; color: #1a1406; border-color: #ffd166; }
  .actions button:disabled, .compose button:disabled { opacity: .45; cursor: default; }
  .actions button:focus-visible, .compose button:focus-visible { outline: 2px solid #ffd166; outline-offset: 1px; }
  .compose { display: grid; grid-template-columns: 1fr auto; gap: 6px; margin-top: 8px; }
  .compose textarea {
    resize: vertical; min-height: 36px; background: rgba(0, 0, 0, .3); color: #eef6ff;
    border: 1px solid rgba(214, 228, 240, .2); border-radius: 5px; padding: 6px 8px; font: 11.5px 'Space Grotesk', system-ui, sans-serif;
  }
  .compose button { align-self: end; }
  .fine { margin: 6px 0 0; font-size: 10px; color: rgba(190, 208, 222, .55); }
  .err { margin: 6px 0 0; font-size: 10.5px; color: #ff8f8f; }
</style>
