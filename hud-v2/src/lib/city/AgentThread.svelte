<script lang="ts">
  /* Direct line to one agent. "What are you doing?" is answered by the
     backend from runtime state; anything else becomes an ordinary analysis
     job for that agent. An agent can analyse and PROPOSE -- an action it
     suggests still goes through policy -> auth -> capability bus. Nothing
     typed here executes. */
  import { agentManager, refreshThread, sendChat } from '../../stores/agentManager';

  export let agentId: string;
  export let agentName = '';
  export let canWork = true;          // temps take work only from the Manager

  let text = '';
  let busy = false;
  let error = '';
  let lastId = '';

  $: if (agentId && agentId !== lastId) { lastId = agentId; error = ''; void refreshThread(agentId); }
  $: thread = [...($agentManager.threads[agentId] ?? [])].reverse().slice(-14);

  const SUGGEST = ['What are you doing?', 'Progress report'];

  async function send(msg = text): Promise<void> {
    const t = msg.trim();
    if (!t || busy) return;
    busy = true;
    error = (await sendChat(agentId, t)) ?? '';
    busy = false;
    if (!error) text = '';
  }
</script>

<div class="thread" aria-label={`Messages with ${agentName}`}>
  <div class="log">
    {#if !thread.length}
      <p class="empty">No messages with {agentName} yet.</p>
    {/if}
    {#each thread as m (m.message_id)}
      <p class="line" class:me={m.sender_agent_id === 'ceo'}>
        <b>{m.sender_agent_id === 'ceo' ? 'You' : m.sender_name}</b>
        {m.sender_agent_id === 'ceo' ? m.body : `${m.title !== 'Status' && m.title !== 'Done' ? m.title + ' -- ' : ''}${m.body}`}
      </p>
    {/each}
  </div>
  <div class="chips">
    {#each SUGGEST as s}<button on:click={() => send(s)} disabled={busy}>{s}</button>{/each}
  </div>
  <form on:submit|preventDefault={() => send()}>
    <input bind:value={text} maxlength="400"
      placeholder={canWork ? `Message ${agentName}…` : 'Ask what it is doing…'} aria-label={`Message ${agentName}`} />
    <button type="submit" disabled={busy || !text.trim()}>{busy ? '…' : 'Send'}</button>
  </form>
  {#if error}<p class="err">{error}</p>{/if}
  <p class="fine">Agents analyse and propose. Actions still need your approval through the normal command path.</p>
</div>

<style>
  .thread { display: grid; gap: 6px; margin-top: 8px; border-top: 1px solid rgba(255, 255, 255, .08); padding-top: 8px; }
  .log { max-height: 170px; overflow-y: auto; display: grid; gap: 5px; }
  .empty { margin: 0; font-size: 11px; color: rgba(190, 208, 222, .55); }
  .line { margin: 0; font-size: 11.5px; line-height: 1.4; color: rgba(214, 228, 240, .85);
    padding: 5px 8px; border-radius: 6px; background: rgba(255, 255, 255, .04); white-space: pre-wrap; }
  .line b { display: block; font-size: 9.5px; letter-spacing: .08em; color: var(--cat, #9deaff); text-transform: uppercase; }
  .line.me { background: rgba(255, 209, 102, .08); }
  .line.me b { color: #ffe29a; }
  .chips { display: flex; gap: 5px; flex-wrap: wrap; }
  .chips button { all: unset; cursor: pointer; font-size: 10px; padding: 3px 8px; border-radius: 10px;
    border: 1px solid rgba(214, 228, 240, .22); color: rgba(214, 228, 240, .85); }
  .chips button:focus-visible { outline: 2px solid var(--cat, #9deaff); }
  form { display: grid; grid-template-columns: 1fr auto; gap: 6px; }
  input { min-width: 0; background: rgba(0, 0, 0, .3); color: #eef6ff; border: 1px solid rgba(214, 228, 240, .2);
    border-radius: 5px; padding: 6px 8px; font: 11.5px 'Space Grotesk', system-ui, sans-serif; }
  input:focus-visible { outline: 2px solid var(--cat, #9deaff); outline-offset: 0; }
  form button { all: unset; cursor: pointer; padding: 5px 12px; border-radius: 5px; font-size: 10.5px; font-weight: 700;
    background: var(--cat, #38e0ff); color: #06121c; }
  form button:disabled { opacity: .45; cursor: default; }
  form button:focus-visible { outline: 2px solid #fff; }
  .err { margin: 0; font-size: 10.5px; color: #ff8f8f; }
  .fine { margin: 0; font-size: 9.5px; color: rgba(190, 208, 222, .5); line-height: 1.35; }
</style>
