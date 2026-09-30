/** Colour-role classifier for status words the backend already reports.
 *
 * Presentation only: it decides whether a REAL value is drawn in the good
 * (green), warning (amber), critical (red) or neutral role of the colour
 * hierarchy. It never changes, invents or infers the value itself; anything
 * it does not recognise stays neutral. */
export type Tone = 'ok' | 'warn' | 'bad' | 'dim' | '';

const GOOD = /^(ok|online|live|connected|normal|secure|sealed|signed|verified|valid|intact|hardened|enabled|enforced|configured|allowlisted|read-only|ready|standby|no violations?( reported)?|none|low|egress enforced|live snapshot|live sample|compl?ete[d]?)$/i;
const UNKNOWN = /^(unknown|unavailable|not exposed|loading|never|—|-|n\/a)$/i;
const WARN = /^(stale|partial|reconnecting|degraded|warning|medium|locked|open|writable|disabled|muted|waiting[_ ]auth|pending|caution|elevated)$/i;
const BAD = /^(critical|high|blocked|lockdown|broken|failed|error|violation|violations|tamper(ed)?|compromised|offline|disconnected|denied)$/i;

export function tone(value: string | null | undefined): Tone {
  if (value === null || value === undefined) return 'dim';
  const s = String(value).trim();
  if (!s) return 'dim';
  if (GOOD.test(s)) return 'ok';
  if (UNKNOWN.test(s)) return 'dim';
  if (WARN.test(s)) return 'warn';
  if (BAD.test(s)) return 'bad';
  // Compound backend strings ("audit_chain_broken", "SYSTEM CRITICAL",
  // "egress classes: 8 fixed, 1 open ..."): only a clearly critical word
  // promotes them; everything else is neutral.
  if (/\b(critical|lockdown|broken|tamper|violation)\b/i.test(s) && !/\bno violations?\b/i.test(s)) return 'bad';
  return '';
}
