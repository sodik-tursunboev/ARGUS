<script lang="ts">
  /* AUTHENTICATION -- the ONE user-facing authentication surface.

     Rules this page keeps (they are the security architecture, not styling):
       - The BACKEND decides. This page presents a challenge the backend raised
         and forwards what the person types; it never decides that anything
         succeeded. "VERIFIED" is shown only after POST /unlock answers ok:true,
         and the lock state shown is /auth-status, re-read after every attempt.
       - A challenge exists only from authoritative backend signals (see
         stores/authFlow.ts). No reply prose is ever parsed.
       - The PIN lives in ONE local variable, from keystroke to request. It is a
         type="password" field (masked as typed, no reveal control), is cleared
         the moment it is submitted, when the challenge closes, when the window is
         hidden and when this page is destroyed. It is never put in a store,
         localStorage/sessionStorage, the URL, a log line, an event or the console.
       - Voice and face are shown as what the backend reports. Voice verification
         is spoken and heard by the voice process (this page records no audio) and
         face is a presence check that can never unlock alone -- so neither gets an
         invented result. */
  import { createEventDispatcher, onDestroy, onMount, tick } from 'svelte';
  import { get } from 'svelte/store';
  import Tabs from './Tabs.svelte';
  import Panel from './ui/Panel.svelte';
  import MethodCard from './ui/MethodCard.svelte';
  import { pendingAuth, clearPendingAuth, dispatchCommand, requestAuthFromBackend, authEvents, logAuthEvent, type AuthEventKind } from '../stores/authFlow';
  import { unlock, sendCommand, postFaceCheck } from '../services/api';
  import { refreshAuthNow, refreshFaceNow } from '../stores/snapshot';
  import { authStatus, securityReport, faceStatus } from '../stores/snapshotView';
  import { security } from '../stores/security';
  import { connection } from '../stores/connection';
  import { voiceSession } from '../stores/voice';
  import { describeMethods, methodChips, sessionState, idleLockLabel, type Tone } from '../lib/authMethods';
  import { IconAuthentication, IconMethodPin, IconMethodVoice, IconMethodFace, IconSession, IconUserPresence, IconLockdown, IconTimeline, IconAuth, IconWarning } from '../lib/ui/icons';

  const dispatch = createEventDispatcher<{ resolved: { outcome: 'verified' | 'cancelled' } }>();

  let secret = '';
  let busy = false;
  let verdict: { kind: 'verified' | 'failed' | 'lockedout'; message: string } | null = null;
  let faceBusy = false;
  let faceNote = '';
  let pinField: HTMLInputElement | undefined;
  let now = Date.now();
  let verdictTimer: number | undefined;

  $: reachable = $connection.source === 'live' || $connection.source === 'partial' || $connection.source === 'stale';
  $: challenge = $pendingAuth;
  $: auth = $authStatus;
  $: session = sessionState(reachable, auth);
  $: methods = describeMethods({ reachable, report: $securityReport, auth, face: $faceStatus, voice: $voiceSession });
  $: chips = methodChips(methods);
  $: authOff = auth?.enabled === false;
  $: lockedOut = !!auth?.locked_out;
  $: unlocked = auth?.unlocked === true && !authOff;
  // the countdown is derived from the backend's lockout_seconds at the moment it was read, then ticks locally
  $: lockUntil = lockedOut ? Date.now() + (auth?.lockout_seconds ?? 0) * 1000 : 0;
  $: lockLeft = lockedOut ? Math.max(0, Math.ceil((lockUntil - now) / 1000)) : 0;
  $: showPin = reachable && !authOff && (challenge ? challenge.mode === 'pin' : !unlocked);
  $: levelText = challenge && challenge.level && challenge.level !== 'UNKNOWN' ? challenge.level : 'NOT REPORTED';
  $: presence = $security.fields.userPresence;
  $: presenceTone = presence === 'WATCHING' ? 'ok' : presence === 'UNMONITORED' ? 'warn' : presence === 'IDLE LOCK' ? 'info' : 'dim';
  $: idleText = !reachable ? 'DISCONNECTED' : idleLockLabel(auth?.idle_lock_seconds);
  $: challengeText = !challenge ? 'NONE' : challenge.mode === 'confirm' ? 'CONFIRMATION REQUIRED' : 'AUTHENTICATION REQUIRED';
  $: if (!challenge) secret = '';
  $: if (challenge && showPin) void focusPin();

  async function focusPin(): Promise<void> { await tick(); pinField?.focus(); }

  function showVerdict(next: NonNullable<typeof verdict>, holdMs = 6000): void {
    verdict = next;
    window.clearTimeout(verdictTimer);
    verdictTimer = window.setTimeout(() => { verdict = null; }, holdMs);
  }

  async function submitPin(): Promise<void> {
    if (busy || !secret || !reachable || lockedOut) return;
    busy = true; verdict = null;
    let supplied = secret; secret = '';                 // out of the field (and its DOM value) before the request even starts
    try {
      const result = await unlock(supplied);
      supplied = '';
      if (result.ok !== true) {
        const out = result.status?.locked_out === true;
        showVerdict({ kind: out ? 'lockedout' : 'failed', message: typeof result.message === 'string' && result.message ? result.message : 'That did not work.' });
        logAuthEvent(out ? 'LOCKED OUT' : 'FAILED');
        await refreshAuthNow();
        return;
      }
      const command = get(pendingAuth)?.command ?? null;
      const action = get(pendingAuth)?.action ?? '';
      showVerdict({ kind: 'verified', message: 'Verified by the backend.' }, 4000);
      logAuthEvent('VERIFIED', action);
      clearPendingAuth();
      await refreshAuthNow();
      dispatch('resolved', { outcome: 'verified' });
      if (command) await dispatchCommand(command);      // the request that triggered the challenge is re-sent; the backend re-checks it
    } catch {
      supplied = '';
      showVerdict({ kind: 'failed', message: 'Authentication service is unavailable.' });
    } finally {
      busy = false;
    }
  }

  async function confirmAction(): Promise<void> {
    if (busy || challenge?.mode !== 'confirm') return;
    busy = true;
    try {
      logAuthEvent('CONFIRMATION', 'confirmed');
      clearPendingAuth();
      dispatch('resolved', { outcome: 'verified' });
      await dispatchCommand('confirm');
    } catch {
      showVerdict({ kind: 'failed', message: 'Confirmation service is unavailable.' });
    } finally {
      busy = false;
    }
  }

  async function cancel(): Promise<void> {
    secret = '';
    try { await sendCommand('cancel'); } catch { /* the local dismissal still clears the credential field */ }
    logAuthEvent('CANCELLED', challenge?.action ?? '');
    clearPendingAuth();
    dispatch('resolved', { outcome: 'cancelled' });
  }

  async function runFaceCheck(): Promise<void> {
    faceBusy = true; faceNote = '';
    try {
      const result = await postFaceCheck();
      faceNote = (result.message ? String(result.message) : result.ok ? 'Face check complete' : 'Face check unavailable').toUpperCase().slice(0, 140);
      if (result.needs_auth) requestAuthFromBackend('face check');   // the backend said a fresh unlock is needed first
      await refreshFaceNow();
    } finally {
      faceBusy = false;
    }
  }

  const stamp = (t: number): string => { const d = new Date(t); const p = (n: number): string => String(n).padStart(2, '0'); return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; };
  const kindTone = (kind: AuthEventKind): Tone => kind === 'VERIFIED' || kind === 'UNLOCKED' ? 'ok' : kind === 'FAILED' || kind === 'LOCKED OUT' ? 'bad' : kind === 'REQUIRED' || kind === 'CONFIRMATION' ? 'warn' : 'dim';
  const onKey = (event: KeyboardEvent): void => { if (event.key === 'Enter') { event.preventDefault(); void submitPin(); } };

  onMount(() => {
    void refreshAuthNow(); void refreshFaceNow();
    const tickTimer = window.setInterval(() => { now = Date.now(); }, 1000);
    // a hidden window never keeps a half-typed PIN
    const onHide = (): void => { if (document.visibilityState === 'hidden') secret = ''; };
    document.addEventListener('visibilitychange', onHide);
    return () => { window.clearInterval(tickTimer); document.removeEventListener('visibilitychange', onHide); };
  });
  onDestroy(() => { secret = ''; window.clearTimeout(verdictTimer); });
</script>

<Tabs title="AUTHENTICATION" group="authentication" />

<div class="auth-page" data-testid="authentication">
  <Panel title="AUTHENTICATION STATUS" icon={IconAuthentication} testid="auth-status">
    <div class="cells">
      <div class="cell">
        <span class="ck"><span class="ci" aria-hidden="true"><IconSession weight="duotone" /></span>SESSION LEVEL</span>
        <b class="cv {session.tone}" data-testid="auth-lock-state">{session.label}</b>
        <small>{lockedOut ? `TRY AGAIN IN ${lockLeft} S` : session.tone === 'ok' ? 'Unlocked by the backend' : session.label === 'LOCKED' ? 'Verify to unlock' : '\u00a0'}</small>
      </div>
      <div class="cell">
        <span class="ck"><span class="ci" aria-hidden="true"><IconLockdown weight="duotone" /></span>AUTO-LOCK</span>
        <b class="cv {idleText === 'DISCONNECTED' || idleText === 'NOT REPORTED' ? 'dim' : ''}">{idleText}</b>
        <small>{idleText.endsWith('MIN') || idleText.endsWith(' S') ? 'Idle time before it locks again' : '\u00a0'}</small>
      </div>
      <div class="cell">
        <span class="ck"><span class="ci" aria-hidden="true"><IconUserPresence weight="duotone" /></span>USER PRESENCE</span>
        <b class="cv {presenceTone}">{presence}</b>
        <small>From the face module and idle lock</small>
      </div>
      <div class="cell">
        <span class="ck"><span class="ci" aria-hidden="true"><IconAuth weight="duotone" /></span>ACTIVE CHALLENGE</span>
        <b class="cv {challenge ? 'warn' : 'dim'}" data-testid="auth-challenge-state">{challengeText}</b>
        <small>{challenge ? `${challenge.action.toUpperCase()} · ${levelText}` : 'The backend has not asked for anything'}</small>
      </div>
    </div>
  </Panel>

  {#if challenge}
    <Panel title={challenge.mode === 'confirm' ? 'CONFIRMATION REQUIRED' : 'AUTHENTICATION REQUIRED'} icon={IconWarning} tone="warn" testid="auth-challenge">
      <div class="ch-grid">
        <div class="ch-item">
          <span class="ck">REQUESTING ACTION</span>
          <b class="cv" data-testid="auth-challenge-action">{challenge.action.toUpperCase()}</b>
        </div>
        <div class="ch-item">
          <span class="ck">REQUIRED LEVEL</span>
          <b class="cv">{levelText}</b>
          <small>{challenge.requirement.toUpperCase()}</small>
        </div>
        <div class="ch-item ch-methods">
          <span class="ck">AVAILABLE METHODS</span>
          <div class="chips">
            {#each chips as chip (chip.key)}<span class="mchip {chip.tone}"><b>{chip.label}</b><em>{chip.status}</em></span>{/each}
          </div>
        </div>
      </div>
      {#if challenge.mode === 'confirm'}
        <div class="ch-actions">
          <button type="button" class="btn ghost" on:click={cancel} disabled={busy}>CANCEL</button>
          <button type="button" class="btn primary" on:click={confirmAction} disabled={busy}>{busy ? 'CONFIRMING…' : 'CONFIRM'}</button>
        </div>
      {/if}
    </Panel>
  {/if}

  <section class="methods" aria-label="Authentication methods">
    <MethodCard title="PIN" icon={IconMethodPin} status={methods.pin.status} tone={methods.pin.tone} facts={methods.pin.facts} note={methods.pin.note} testid="method-pin">
      {#if showPin}
        <label class="pin-label" for="argus-pin">PIN — HIDDEN AS YOU TYPE</label>
        <input id="argus-pin" bind:this={pinField} bind:value={secret} on:keydown={onKey}
               type="password" inputmode="numeric" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="64"
               data-lpignore="true" data-1p-ignore="true" data-form-type="other"
               disabled={busy || lockedOut} placeholder={lockedOut ? `Locked · ${lockLeft} s` : 'Enter PIN'} data-testid="pin-input" />
        <div class="pin-actions">
          {#if challenge}<button type="button" class="btn ghost" on:click={cancel} disabled={busy}>CANCEL</button>{/if}
          <button type="button" class="btn primary" on:click={submitPin} disabled={busy || !secret || lockedOut}>{busy ? 'VERIFYING…' : challenge ? 'VERIFY' : 'UNLOCK'}</button>
        </div>
      {:else if reachable && !authOff && unlocked}
        <p class="state-line ok">SESSION UNLOCKED</p>
      {:else if authOff}
        <p class="state-line dim">AUTHENTICATION IS SWITCHED OFF IN CONFIG</p>
      {/if}
      {#if verdict}
        <p class="verdict {verdict.kind}" role="status" data-testid="auth-verdict"><b>{verdict.kind === 'verified' ? 'VERIFIED' : verdict.kind === 'lockedout' ? 'LOCKED OUT' : 'AUTHENTICATION FAILED'}</b><span>{verdict.message}</span></p>
      {/if}
    </MethodCard>

    <MethodCard title="VOICE" icon={IconMethodVoice} status={methods.voice.status} tone={methods.voice.tone} facts={methods.voice.facts} note={methods.voice.note} testid="method-voice" />

    <MethodCard title="FACE" icon={IconMethodFace} status={methods.face.status} tone={methods.face.tone} facts={methods.face.facts} note={methods.face.note} testid="method-face">
      {#if reachable && $faceStatus && $faceStatus.available !== false && $faceStatus.enrolled}
        <button type="button" class="btn ghost wide" on:click={runFaceCheck} disabled={faceBusy}>{faceBusy ? 'CHECKING…' : 'RUN FACE CHECK'}</button>
      {/if}
      {#if faceNote}<p class="verdict info" role="status"><b>FACE CHECK</b><span>{faceNote}</span></p>{/if}
    </MethodCard>
  </section>

  <Panel title="RECENT AUTHENTICATION EVENTS" icon={IconTimeline} testid="auth-events">
    <span slot="end" class="scope">THIS SESSION</span>
    {#if $authEvents.length}
      <ul class="events">
        {#each $authEvents.slice(0, 6) as event (event.id)}
          <li><time>{stamp(event.at)}</time><b class="kind {kindTone(event.kind)}">{event.kind}</b><span>{event.detail}</span></li>
        {/each}
      </ul>
    {:else}
      <p class="empty">NO AUTHENTICATION EVENTS THIS SESSION</p>
    {/if}
  </Panel>
</div>

<style>
  .auth-page { display: grid; gap: var(--ds-gap, 10px); min-width: 0; padding-top: 2px; }

  /* ---- status strip + challenge share one label / value / caption type scale ---- */
  .cells { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0; min-width: 0; }
  .cell { display: grid; align-content: start; gap: 5px; min-width: 0; padding: 4px clamp(10px, 1.1vw, 18px); border-left: 1px solid rgba(223, 251, 255, .09); }
  .cell:first-child { padding-left: 0; border-left: 0; }
  .ck { display: inline-flex; align-items: center; gap: 8px; min-width: 0; font: 600 var(--ds-ui, 13px)/1.2 var(--font-ui); letter-spacing: .08em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  .ci { display: grid; place-items: center; flex: 0 0 auto; width: var(--ds-icon-row, 18px); height: var(--ds-icon-row, 18px); color: var(--cyan-soft, #6ef3fb); }
  .ci :global(svg) { display: block; width: 100%; height: 100%; }
  /* the important value: large, coloured by tone, wraps instead of truncating */
  .cv { min-width: 0; overflow-wrap: anywhere; font: 700 var(--ds-value, 24px)/1.1 var(--font-data); letter-spacing: .01em; text-transform: uppercase; color: var(--text, #edf8fa); }
  .cv.ok { color: var(--green, #2df0a6); }
  .cv.warn { color: var(--amber, #ffc24d); }
  .cv.bad { color: var(--red, #ff4a63); }
  .cv.info { color: var(--cyan-soft, #6ef3fb); }
  .cv.dim { color: var(--muted, #6b93a0); }
  small { min-width: 0; overflow-wrap: anywhere; font: 500 var(--ds-data, 12px)/1.35 var(--font-ui); color: var(--secondary, #94bcc5); }

  .ch-grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr) minmax(0, 1.5fr); gap: 0; min-width: 0; }
  .ch-item { display: grid; align-content: start; gap: 5px; min-width: 0; padding: 2px clamp(10px, 1.1vw, 18px); border-left: 1px solid rgba(255, 194, 77, .22); }
  .ch-item:first-child { padding-left: 0; border-left: 0; }
  .ch-item .cv { color: var(--amber, #ffc24d); }
  .ch-methods .chips { display: flex; flex-wrap: wrap; gap: 8px; min-width: 0; }
  .mchip { display: inline-flex; align-items: baseline; gap: 8px; min-width: 0; padding: 6px 10px; border: 1px solid currentColor; background: color-mix(in srgb, currentColor 9%, transparent); color: var(--secondary, #94bcc5); }
  .mchip b { font: 700 var(--ds-ui, 13px)/1 var(--font-ui); letter-spacing: .1em; color: var(--text, #edf8fa); }
  .mchip em { font: 700 var(--ds-data, 12px)/1 var(--font-data); font-style: normal; letter-spacing: .05em; }
  .mchip.ok { color: var(--green, #2df0a6); }
  .mchip.info { color: var(--cyan-soft, #6ef3fb); }
  .ch-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 12px; }

  /* ---- method cards: three columns on a desktop window, one column when narrow ---- */
  .methods { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--ds-gap, 10px); min-width: 0; align-items: stretch; }
  @media (max-width: 1099px) { .methods { grid-template-columns: minmax(0, 1fr); } .cells { grid-template-columns: repeat(2, minmax(0, 1fr)); row-gap: 12px; } .cell:nth-child(3) { padding-left: 0; border-left: 0; } .ch-grid { grid-template-columns: minmax(0, 1fr); row-gap: 10px; } .ch-item { padding-left: 0; border-left: 0; } }

  /* ---- PIN control ---- */
  .pin-label { font: 600 var(--ds-ui, 13px)/1.2 var(--font-ui); letter-spacing: .1em; color: var(--secondary, #94bcc5); }
  input {
    width: 100%; min-width: 0; box-sizing: border-box; height: 48px; padding: 0 14px;
    background: rgba(4, 12, 16, .96); border: 1px solid rgba(0, 234, 242, .42); border-radius: 0; color: var(--text, #edf8fa);
    font: 600 20px/1 var(--font-data); letter-spacing: .34em;
  }
  input::placeholder { letter-spacing: .06em; font-size: 14px; font-weight: 500; color: var(--muted, #6b93a0); }
  input:focus { outline: 2px solid var(--cyan, #00eaf2); outline-offset: 1px; }
  input:disabled { opacity: .55; }
  .pin-actions { display: flex; justify-content: flex-end; gap: 10px; min-width: 0; }
  .btn { min-width: 116px; height: 42px; padding: 0 18px; border-radius: 0; cursor: pointer; font: 700 13px/1 var(--font-ui); letter-spacing: .12em; white-space: nowrap; }
  .btn.wide { width: 100%; }
  .btn.primary { background: rgba(0, 234, 242, .16); border: 1px solid rgba(0, 234, 242, .7); color: #b9f6fb; }
  .btn.ghost { background: transparent; border: 1px solid rgba(0, 234, 242, .34); color: var(--cyan-soft, #6ef3fb); }
  .btn:hover:not(:disabled) { background: rgba(0, 234, 242, .24); }
  .btn:focus-visible { outline: 2px solid var(--cyan, #00eaf2); outline-offset: 2px; }
  .btn:disabled { opacity: .45; cursor: default; }

  .state-line { margin: 0; font: 700 var(--ds-label, 15px)/1.2 var(--font-data); letter-spacing: .06em; }
  .state-line.ok { color: var(--green, #2df0a6); }
  .state-line.dim { color: var(--secondary, #94bcc5); }
  .verdict { display: grid; gap: 3px; margin: 0; padding: 9px 12px; border: 1px solid currentColor; background: color-mix(in srgb, currentColor 9%, transparent); }
  .verdict b { font: 700 var(--ds-label, 15px)/1.1 var(--font-ui); letter-spacing: .08em; }
  .verdict span { font: 500 var(--ds-data, 12px)/1.35 var(--font-ui); color: var(--secondary, #94bcc5); overflow-wrap: anywhere; }
  .verdict.verified { color: var(--green, #2df0a6); }
  .verdict.failed, .verdict.lockedout { color: var(--red, #ff4a63); }
  .verdict.info { color: var(--cyan-soft, #6ef3fb); }

  /* ---- session events ---- */
  .scope { font: 700 var(--ds-sec, 11px)/1 var(--font-data); letter-spacing: .1em; color: var(--muted, #6b93a0); }
  .events { display: grid; margin: 0; padding: 0; list-style: none; }
  .events li { display: grid; grid-template-columns: 6.2em 8.6em minmax(0, 1fr); align-items: center; column-gap: 12px; min-width: 0; min-height: var(--ds-row, 28px); border-top: 1px solid rgba(223, 251, 255, .075); }
  .events li:first-child { border-top: 0; }
  time { font: 600 var(--ds-data, 12px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--muted, #6b93a0); }
  .kind { font: 700 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .07em; color: var(--secondary, #94bcc5); }
  .kind.ok { color: var(--green, #2df0a6); } .kind.warn { color: var(--amber, #ffc24d); } .kind.bad { color: var(--red, #ff4a63); }
  .events span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 500 var(--ds-ui, 13px)/1.2 var(--font-ui); text-transform: uppercase; color: var(--text, #edf8fa); }
  .empty { margin: 0; padding: 4px 0; font: 600 var(--ds-ui, 13px)/1.3 var(--font-data); letter-spacing: .06em; color: var(--secondary, #94bcc5); }
</style>
