// Fixed design canvas.
//
// The dashboard is composed ONCE, on a 1920x1080 coordinate system, and the
// whole composition is scaled uniformly to fit whatever content area the
// WebView2 window actually gives us. Nothing is hidden or reflowed per
// breakpoint: at 1366x768 the operator sees the same cockpit at 0.711x.
//
// Measurements come from the real renderable area (the viewport element's
// own box / window.innerWidth+innerHeight), never from screen.width/height --
// window chrome, a non-maximized window and the pywebview host all change
// what is actually available.
import { derived, writable } from 'svelte/store';

export const CANVAS_W = 1920;
export const CANVAS_H = 1080;

/** AUTO fits the full composition; the fixed modes are explicit operator zoom. */
export type ScaleMode = 'auto' | '0.9' | '1' | '1.1';
export const SCALE_MODES: { value: ScaleMode; label: string }[] = [
  { value: 'auto', label: 'AUTO FIT' },
  { value: '0.9', label: '90%' },
  { value: '1', label: '100%' },
  { value: '1.1', label: '110%' },
];

const SCALE_KEY = 'argus-hud-scale';
const WORDMARK_KEY = 'argus-hud-wordmark';
export type WordmarkStyle = 'signature';

function readMode(): ScaleMode {
  try {
    const raw = localStorage.getItem(SCALE_KEY);
    return SCALE_MODES.some((m) => m.value === raw) ? (raw as ScaleMode) : 'auto';
  } catch { return 'auto'; }
}

export const scaleMode = writable<ScaleMode>(readMode());
scaleMode.subscribe((mode) => { try { localStorage.setItem(SCALE_KEY, mode); } catch { /* private mode / quota: the in-memory preference still applies */ } });

/** Frontend-only brand preference; a single style exists today. */
export const wordmarkStyle = writable<WordmarkStyle>('signature');
wordmarkStyle.subscribe((style) => { try { localStorage.setItem(WORDMARK_KEY, style); } catch { /* same */ } });

/** Real renderable size of the host content area (updated by the shell). */
export const viewportSize = writable<{ w: number; h: number }>({
  w: typeof window !== 'undefined' ? window.innerWidth : CANVAS_W,
  h: typeof window !== 'undefined' ? window.innerHeight : CANVAS_H,
});

export interface CanvasMetrics {
  /** Scale actually applied to the canvas. */
  scale: number;
  /** min(vw/1920, vh/1080): what AUTO FIT would use. */
  fit: number;
  manual: boolean;
  /** Logical canvas size. Fixed 1920x1080 for the cockpit; the whole logical viewport for scrolling pages. */
  canvasW: number;
  canvasH: number;
  /** Rendered (post-scale) size of the canvas. */
  stageW: number;
  stageH: number;
  /** Letterbox offsets that centre the rendered canvas in the viewport (never negative). */
  x: number;
  y: number;
  /** True only in a manual zoom that no longer fits; the viewport then pans. */
  overflow: boolean;
}

export function computeMetrics(vw: number, vh: number, mode: ScaleMode, fixed: boolean): CanvasMetrics {
  const safeW = Math.max(1, vw), safeH = Math.max(1, vh);
  const fit = Math.min(safeW / CANVAS_W, safeH / CANVAS_H);
  const manual = mode !== 'auto';
  const scale = manual ? Number(mode) : fit;
  const canvasW = fixed ? CANVAS_W : Math.round(safeW / scale);
  const canvasH = fixed ? CANVAS_H : Math.round(safeH / scale);
  const stageW = canvasW * scale;
  const stageH = canvasH * scale;
  return {
    scale, fit, manual, canvasW, canvasH, stageW, stageH,
    x: Math.max(0, Math.floor((safeW - stageW) / 2)),
    y: Math.max(0, Math.floor((safeH - stageH) / 2)),
    overflow: stageW > safeW + 0.5 || stageH > safeH + 0.5,
  };
}

/** Convenience for components that only need the current scale (e.g. the settings readout). */
export const fitScale = derived(viewportSize, ($v) => Math.min($v.w / CANVAS_W, $v.h / CANVAS_H));
