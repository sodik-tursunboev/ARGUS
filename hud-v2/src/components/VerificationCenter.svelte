<script lang="ts">
  /* VERIFICATION CENTER — one auto-opening surface for every verification
     ARGUS can demand (PIN, face, auth-state, confirmation). Rules:

       - It opens ITSELF when the backend demands verification: the existing
         pendingAuth flow (PIN/confirm) or a WebSocket auth.state
         required/expired event. The owner never has to hunt for a panel.
       - The PIN field stays type="password" — a credential is never shown,
         logged, or persisted. The backend remains the only authority; the
         modal merely presents the challenge and forwards input.
       - Face verification is a real POST /face/check (owner-initiated); its
         enrolment/presence state is read live from /face/status. Face alone
         NEVER unlocks anything (backend PRESENCE_ONLY_FACTORS) — it is a
         presence check the backend decides on.
       - Offline backend: the modal stays honest (no fake success states). */
  import { onDestroy } from 'svelte';
  import { pendingAuth, clearPendingAuth, dispatchCommand, requestAuthFromBackend } from '../stores/authFlow';
  import { unlock, sendCommand, fetchAuthStatus, fetchFaceStatus, postFaceCheck, type AuthStatusDTO, type FaceStatusDTO } from '../services/api';
  import { connection } from '../stores/connection';
  import { IconAuth, IconAuthLevel, IconVoice, IconLockdown, IconSecurity, IconThreat } from '../lib/ui/icons';
  import { get } from 'svelte/store';

  let open = false;
  let secret = '';
  let busy = false;
  let message = '';
  let faceNote = '';
  let authState: AuthStatusDTO | null = null;
  let faceState: FaceStatusDTO | null = null;
  let faceBusy = false;
  let pinField: HTMLInputElement | undefined;

  $: challenge = $pendingAuth;

  /* AUTO-OPEN on any verification demand, including a bare WS auth.state
     required/expired (the Challenge Watcher below mirrors it into a pending
     challenge). requestAuthFromBackend no-ops when a challenge already
     exists, so the two paths can never fight. */
  $: if (challenge) {
    open = true;
    message = '';
    void loadStates();
    void tickFocus();
  }

  async function tickFocus(): Promise<void> {
    await Promise.resolve();
    setTimeout(() => pinField?.focus(), 30);
  }

  async function loadStates(): Promise<void> {
    if ($connection.source === 'unavailable') return;
    try { authState = await fetchAuthStatus(); } catch { authState = null; }
    try { faceState = await fetchFaceStatus(); } catch { faceState = null; }
  }

  /* Live auth/face state refresh while the modal is open (every 5 s). */
  const stateTimer = window.setInterval(() => { if (open) void loadStates(); }, 5000);
  onDestroy(() => window.clearInterval(stateTimer));

  async function confirm(): Promise<void> {
    if (challenge?.mode === 'confirm') {
      busy = true;
      try { clearPendingAuth(); open = false; await dispatchCommand('confirm'); }
      catch { message = 'Confirmation service is unavailable.'; open = true; }
      finally { busy = false; }
      return;
    }
    if (busy || !secret || $connection.source === 'unavailable') return;
    busy = true; message = '';
    const supplied = secret; secret = '';
    try {
      const result = await unlock(supplied);
      if (!result.ok) { message = 'Authentication was not accepted.'; return; }
      const command = get(pendingAuth)?.command;
      clearPendingAuth();
      open = false;
      if (command) await dispatchCommand(command);
    } catch {
      message = 'Authentication service is unavailable.';
    } finally {
      busy = false;
    }
  }

  async function cancel(): Promise<void> {
    secret = '';
    try { await sendCommand('cancel'); } catch { /* local dismissal still hides the credential field */ }
    clearPendingAuth();
    open = false;
  }

  async function dismiss(): Promise<void> {
    secret = '';
    open = false;
  }

  async function runFaceCheck(): Promise<void> {
    faceBusy = true; faceNote = '';
    try {
      const result = await postFaceCheck();
      faceNote = result.message ? result.message.toUpperCase() : (result.ok ? 'FACE CHECK COMPLETE' : 'FACE CHECK UNAVAILABLE');
      if (result.needs_auth) requestAuthFromBackend('face check');
      void loadStates();
    } finally {
      faceBusy = false;
    }
  }
</script>

{#if open}
  <section class="auth-backdrop" role="presentation">
    <div class="auth-gate panel verify-center" role="dialog" aria-modal="true" aria-labelledby="verify-title">
      <div class="panel-title">
        <h2 id="verify-title">VERIFICATION CENTER</h2>
        <span class="status caution">{challenge ? challenge.level : 'SESSION CHECK'}</span>
      </div>

      {#if challenge}
        <p class="verify-lede">{challenge.mode === 'confirm'
          ? 'ARGUS requires backend confirmation before it can continue.'
          : 'ARGUS requires backend authentication before it can continue.'}</p>
        <dl class="verify-facts">
          <div><dt>ACTION</dt><dd>{challenge.action.toUpperCase()}</dd></div>
          <div><dt>REQUIREMENT</dt><dd>{challenge.requirement.toUpperCase()}</dd></div>
        </dl>

        {#if challenge.mode === 'pin'}
          <label class="verify-pin-label" for="argus-pin">
            <IconAuth size={18} aria-hidden="true" />
            <span>PIN — HIDDEN AS YOU TYPE</span>
            <input id="argus-pin" bind:this={pinField} bind:value={secret} type="password"
                   inputmode="numeric" autocomplete="off" autocapitalize="off" spellcheck="false"
                   disabled={busy} aria-describedby="verify-note" placeholder="••••••••" />
          </label>
          <small id="verify-note">The PIN is sent only to the local backend over the session link and is cleared immediately. It is never displayed or stored.</small>
        {/if}
      {:else}
        <p class="verify-lede">Session verification status, checked live against the backend.</p>
      {/if}

      <div class="verify-grid">
        <div class="verify-row">
          <span class="verify-icon ok"><IconSecurity size={18} aria-hidden="true" /></span>
          <div class="verify-kv"><span>BACKEND AUTH</span>
            <b>{authState ? (authState.unlocked ? 'UNLOCKED' : authState.locked_out ? `LOCKED OUT · ${authState.lockout_seconds}S` : 'LOCKED') : '—'}</b></div>
        </div>
        <div class="verify-row">
          <span class="verify-icon"><IconAuthLevel size={18} aria-hidden="true" /></span>
          <div class="verify-kv"><span>FACE</span>
            <b>{faceState ? (faceState.enrolled ? `ENROLLED · ${faceState.samples ?? 0} SAMPLES` : 'NOT ENROLLED') : '—'}</b></div>
        </div>
        <div class="verify-row">
          <span class="verify-icon"><IconVoice size={18} aria-hidden="true" /></span>
          <div class="verify-kv"><span>VOICE CHALLENGE</span>
            <b>VIA CONSOLE — SAY THE CHALLENGE PHRASE</b></div>
        </div>
        <div class="verify-row">
          <span class="verify-icon"><IconLockdown size={18} aria-hidden="true" /></span>
          <div class="verify-kv"><span>IDLE LOCK</span>
            <b>{authState ? `${authState.idle_lock_seconds}S` : '—'}</b></div>
        </div>
      </div>

      {#if message}<p class="auth-error" role="alert">{message}</p>{/if}
      {#if faceNote}<p class="verify-face-note" role="status">{faceNote}</p>{/if}

      <div class="verify-actions">
        {#if challenge}
          <button type="button" class="verify-ghost" on:click={cancel} disabled={busy}>CANCEL</button>
          <button type="button" class="verify-primary" disabled={busy || (challenge.mode === 'pin' && !secret)} on:click={confirm}>
            {busy ? 'VERIFYING…' : challenge.mode === 'confirm' ? 'CONFIRM' : 'UNLOCK'}</button>
        {:else}
          <button type="button" class="verify-ghost" on:click={dismiss}>CLOSE</button>
          <button type="button" class="verify-primary" disabled={faceBusy || $connection.source === 'unavailable'} on:click={runFaceCheck}>
            {faceBusy ? 'CHECKING…' : 'RUN FACE CHECK'}</button>
        {/if}
      </div>

      <p class="verify-foot">
        <IconThreat size={13} aria-hidden="true" />
        Face presence alone never unlocks ARGUS — the backend decides; this surface only presents the challenge.
      </p>
    </div>
  </section>
{/if}

<style>
  .verify-center { max-width: 520px; width: min(520px, 92vw); }
  .verify-lede { color: rgba(214, 238, 245, .8); font-size: 13.5px; line-height: 1.55; }
  .verify-facts { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 18px; margin: 10px 0; }
  .verify-facts dt { font-size: 10px; letter-spacing: .14em; color: rgba(160, 190, 200, .7); }
  .verify-facts dd { font-size: 14px; font-weight: 700; color: var(--text-strong, #e6f2f5); word-break: break-word; }
  .verify-pin-label { display: grid; grid-template-columns: auto 1fr; align-items: center; gap: 4px 10px; margin: 10px 0 6px; font-size: 11px; letter-spacing: .12em; color: rgba(160, 190, 200, .85); }
  .verify-pin-label input { grid-column: 1 / -1; background: rgba(6, 16, 20, .95); border: 1px solid rgba(56, 224, 255, .35); color: var(--text-strong, #e6f2f5); border-radius: 8px; padding: 12px 14px; font-size: 18px; letter-spacing: .35em; font-family: var(--font-data, monospace); }
  .verify-pin-label input:focus { outline: 1px solid var(--cyan, #38e0ff); }
  .verify-grid { display: grid; gap: 8px; margin: 12px 0 4px; }
  .verify-row { display: flex; align-items: center; gap: 12px; padding: 8px 10px; border: 1px solid rgba(56, 224, 255, .12); border-radius: 8px; background: rgba(8, 20, 24, .5); }
  .verify-icon { display: grid; place-items: center; width: 34px; height: 34px; border-radius: 8px; background: rgba(56, 224, 255, .08); color: rgba(56, 224, 255, .9); }
  .verify-icon.ok { color: #4ade9e; background: rgba(74, 222, 158, .08); }
  .verify-kv span { display: block; font-size: 9.5px; letter-spacing: .14em; color: rgba(160, 190, 200, .7); }
  .verify-kv b { font-size: 13.5px; font-weight: 700; color: var(--text-strong, #e6f2f5); }
  .verify-face-note { color: rgba(122, 230, 255, .9); font-size: 12.5px; }
  .verify-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 12px; }
  .verify-ghost { background: transparent; border: 1px solid rgba(56, 224, 255, .3); color: rgba(160, 220, 235, .9); border-radius: 7px; padding: 9px 16px; font-size: 12px; font-weight: 700; letter-spacing: .1em; cursor: pointer; }
  .verify-primary { background: rgba(56, 224, 255, .14); border: 1px solid rgba(56, 224, 255, .55); color: #a5ecff; border-radius: 7px; padding: 9px 18px; font-size: 12px; font-weight: 700; letter-spacing: .1em; cursor: pointer; }
  .verify-primary:disabled { opacity: .45; cursor: default; }
  .verify-ghost:hover:not(:disabled), .verify-primary:hover:not(:disabled) { background: rgba(56, 224, 255, .2); }
  .verify-foot { display: flex; align-items: center; gap: 7px; margin-top: 12px; font-size: 11px; color: rgba(160, 190, 200, .65); line-height: 1.5; }
</style>
