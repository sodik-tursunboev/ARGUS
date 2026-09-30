/* ARGUS HUD V2 — threat detections, as data.

   PURE: no stores, no fetching, no clocks of its own (callers pass `now`).
   The Dashboard summary chart and the Security page monitor both consume this
   module, so a detection is normalised, tallied and time-binned in exactly one
   place and the two views can never disagree about the same event.

   SOURCE OF TRUTH. GET /threat-report -> threatmon.summary_state().recent is
   the raw detection buffer (last 10, newest first). A record carries
     severity   'critical' | 'high' | 'medium' | 'low'   (lower case)
     detector, name, technique
     ts         local time, %Y-%m-%dT%H:%M:%S            (no zone)
     at_epoch   unix seconds                              (unambiguous)
   `at` is NOT on those records (only baseline-style dumps use it), which is why
   this reads at_epoch first, then ts, then at. Nothing here samples, smooths,
   extrapolates or invents an event: a bar is a count of real detections whose
   real timestamp fell in that bin, and a detection with no timestamp is counted
   as `undated`, never plotted. The backend keeps only the last 10 records in
   this report, so a series is only as long as those 10 events -- the chart says
   so instead of pretending to a longer history. */

import { secret } from '../stores/events';
import type { BackendDetection } from '../types/argus';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
/** Worst first: legend order, and stack order from the top of a bar down. */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

export interface Detection {
  id: string;
  severity: Severity;
  label: string;
  detector: string;
  technique: string;
  /** epoch ms, or null when the record carried no usable timestamp */
  at: number | null;
  /** local %Y-%m-%dT%H:%M:%S rendering of `at` (what the backend's own `ts` looks like), or null */
  stamp: string | null;
}

const line = (value: unknown): string => typeof value === 'string' ? value.replace(/[\r\n\t]+/g, ' ').trim() : '';
const p2 = (n: number): string => String(n).padStart(2, '0');

export function toSeverity(value: unknown): Severity | null {
  const v = line(value).toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low') return v;
  // anything the backend calls informational sits at the bottom of the scale
  if (v === 'info' || v === 'informational') return 'low';
  return null;
}

/** at_epoch (seconds, or ms if already ms) first: it needs no zone guess. ts/at are local-time strings. */
export function detectionTime(item: BackendDetection): number | null {
  const epoch = item.at_epoch;
  if (typeof epoch === 'number' && Number.isFinite(epoch) && epoch > 0) return epoch < 1e11 ? epoch * 1000 : epoch;
  for (const raw of [item.ts, item.at]) {
    if (typeof raw === 'string' && raw) {
      const t = Date.parse(raw);   // date-time with no offset parses as LOCAL time, which is what the backend wrote
      if (Number.isFinite(t)) return t;
    }
  }
  return null;
}

export const localIso = (ms: number): string => {
  const d = new Date(ms);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
};

/** Detections in backend order (newest first). A record with an unrecognised severity is skipped; nothing else is dropped. */
export function normalizeDetections(recent: BackendDetection[] | null | undefined): Detection[] {
  if (!Array.isArray(recent)) return [];
  return recent.flatMap((item, index): Detection[] => {
    if (!item || typeof item !== 'object') return [];
    const severity = toSeverity(item.severity);
    if (!severity) return [];
    const detector = line(item.detector);
    const raw = line(item.name) || detector || 'detection';
    // A secret-shaped label is replaced, not dropped: the count must stay honest.
    const label = secret.test(raw) ? (detector && !secret.test(detector) ? detector : 'detection') : raw.slice(0, 100);
    const at = detectionTime(item);
    return [{ id: `${item.at_epoch ?? item.ts ?? item.at ?? 'r'}:${index}`, severity, label, detector, technique: line(item.technique), at, stamp: at === null ? null : localIso(at) }];
  });
}

export function tally(detections: Detection[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const d of detections) out[d.severity] += 1;
  return out;
}

/* ── time binning ─────────────────────────────────────────────────────── */
const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000;

export interface SeriesBin { start: number; end: number; counts: Record<Severity, number>; total: number }
export interface Series {
  bins: SeriesBin[];
  start: number;
  end: number;
  binMs: number;
  /** tallest bin (>= 1 whenever anything is plotted) */
  max: number;
  plotted: number;
  /** dated detections that fall before the window */
  older: number;
  /** detections with no usable timestamp: counted, never plotted */
  undated: number;
}

/** Bin widths a person can read a time axis in. */
const NICE_BIN_MS = [5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY];

export interface Timeframe { key: 'auto' | '1h' | '6h' | '24h' | '7d'; label: string; bins: number; binMs: number }
/** Fixed windows for the Security page control. `auto` is resolved by autoBinMs. */
export const TIMEFRAMES: readonly Timeframe[] = [
  { key: 'auto', label: 'AUTO', bins: 48, binMs: 0 },
  { key: '1h', label: '1 H', bins: 30, binMs: 2 * MIN },
  { key: '6h', label: '6 H', bins: 36, binMs: 10 * MIN },
  { key: '24h', label: '24 H', bins: 48, binMs: 30 * MIN },
  { key: '7d', label: '7 D', bins: 42, binMs: 4 * HOUR },
];

/** Smallest nice bin width whose window still reaches the oldest dated detection (never under a 30-minute window). */
export function autoBinMs(detections: Detection[], now: number, bins: number): number {
  const times = detections.flatMap((d) => d.at === null ? [] : [Math.min(d.at, now)]);
  const age = times.length ? now - Math.min(...times) : 0;
  const need = Math.max(age, 30 * MIN);
  for (const w of NICE_BIN_MS) if (w * bins >= need) return w;
  return NICE_BIN_MS[NICE_BIN_MS.length - 1];
}

export function buildSeries(detections: Detection[], now: number, bins: number, binMs: number): Series {
  const start = now - bins * binMs;
  const grid: SeriesBin[] = Array.from({ length: bins }, (_, i) => ({
    start: start + i * binMs, end: start + (i + 1) * binMs, counts: { critical: 0, high: 0, medium: 0, low: 0 }, total: 0,
  }));
  let older = 0, undated = 0, plotted = 0;
  for (const d of detections) {
    if (d.at === null) { undated += 1; continue; }
    const t = Math.min(d.at, now);            // a slightly-future clock never falls off the right edge
    if (t < start) { older += 1; continue; }
    const bin = grid[Math.min(bins - 1, Math.floor((t - start) / binMs))];
    bin.counts[d.severity] += 1; bin.total += 1; plotted += 1;
  }
  return { bins: grid, start, end: now, binMs, max: Math.max(1, ...grid.map((b) => b.total)), plotted, older, undated };
}

/* ── labels ───────────────────────────────────────────────────────────── */
export function spanLabel(ms: number): string {
  if (ms >= DAY) return `${Math.round(ms / DAY)} D`;
  if (ms >= HOUR) return `${Math.round(ms / HOUR)} H`;
  return `${Math.max(1, Math.round(ms / MIN))} MIN`;
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
export const clock = (ms: number): string => { const d = new Date(ms); return `${p2(d.getHours())}:${p2(d.getMinutes())}`; };
export const dayClock = (ms: number): string => { const d = new Date(ms); return `${MONTHS[d.getMonth()]} ${d.getDate()} ${clock(ms)}`; };
/** Axis label for a moment inside a window of `windowMs`: clock time when it is a day or less, date + time beyond. */
export const axisLabel = (ms: number, windowMs: number): string => windowMs <= DAY * 1.5 ? clock(ms) : dayClock(ms);

/** One-line description of a bin for tooltips / screen readers: "20:30 – 21:00 · 2 CRITICAL · 1 HIGH". */
export function describeBin(bin: SeriesBin, windowMs: number): string {
  const parts = SEVERITIES.filter((s) => bin.counts[s] > 0).map((s) => `${bin.counts[s]} ${s.toUpperCase()}`);
  return `${axisLabel(bin.start, windowMs)} – ${axisLabel(bin.end, windowMs)} · ${parts.length ? parts.join(' · ') : 'NO DETECTIONS'}`;
}
