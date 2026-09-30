<script lang="ts">
  /* AUDIT LOG viewer — the real /audit-log contract (HMAC-chained audit
     tail, already redacted by the backend before it was written). The
     frontend only reads the tail; nothing here can un-redact or modify. */
  import { onMount, onDestroy } from 'svelte';
  import { fetchAuditLog } from '../services/api';

  let lines: string[] = [];
  let loaded = false;
  let error = '';
  let now = Date.now();
  const timer = setInterval(() => (now = Date.now()), 5000);
  onDestroy(() => clearInterval(timer));

  const MAX_LINES = 120;

  async function load(): Promise<void> {
    try {
      const text = await fetchAuditLog();
      const all = text.split('\n').filter((l) => l.trim());
      lines = all.slice(-MAX_LINES);
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : 'Audit log unavailable';
    } finally {
      loaded = true;
    }
  }

  onMount(load);
  $: if (now) void 0; // re-render tick only
</script>

<section class="panel audit-panel" aria-label="Audit log tail">
  <div class="panel-title"><h2>AUDIT LOG</h2>
    <span class="status" class:unknown={!loaded || !!error}>
      {loaded ? (error ? 'UNAVAILABLE' : `${lines.length} ENTRIES · HMAC-CHAIN`) : 'LOADING'}
    </span>
    <button class="audit-refresh" on:click={load} disabled={!loaded}>REFRESH</button>
  </div>
  {#if error}
    <p class="rail-note">{error}</p>
  {:else if loaded && !lines.length}
    <p class="rail-note">No activity recorded yet.</p>
  {:else}
    <div class="audit-tail">
      {#each lines as line, i (i)}
        <div class="audit-line">{line}</div>
      {/each}
    </div>
  {/if}
</section>

<style>
  .audit-refresh { background: rgba(56, 224, 255, .08); color: #7de6ff; border: 1px solid rgba(56, 224, 255, .35); border-radius: 5px; padding: 3px 10px; font-size: 10px; font-weight: 700; letter-spacing: .12em; cursor: pointer; }
  .audit-refresh:hover:not(:disabled) { background: rgba(56, 224, 255, .18); }
  .audit-tail { display: grid; gap: 2px; max-height: 420px; overflow-y: auto; font-size: 11px; line-height: 1.55; }
  .audit-line { font-family: var(--font-mono, 'IBM Plex Mono', monospace); color: rgba(190, 214, 222, .8); white-space: pre-wrap; word-break: break-word; padding: 2px 8px; border-left: 2px solid rgba(56, 224, 255, .18); }
  .audit-line:nth-child(odd) { background: rgba(10, 22, 26, .4); }
</style>
