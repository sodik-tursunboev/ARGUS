/* ARGUS AI City -- screen-space labels.
   ==========================================================================

   Why HTML and not canvas sprites: a sprite label is a texture in WORLD
   units, so on an orthographic city it is exactly as big as the zoom lets it
   be -- about twenty pixels wide at the overview, i.e. unreadable -- and its
   anti-aliased text goes soft on the dark background. A CSS2DObject is a real
   DOM element pinned to a world point: constant pixel size, crisp text, a
   solid backing plate, and it can never sink behind a building.

   The cost of constant pixel size is that labels collide when the camera
   pulls out. `declutter` handles that with measured screen boxes and a
   priority order instead of a hand-tuned zoom threshold per label (a tuned
   number only ever holds for the window size it was tuned at).
*/

import * as THREE from 'three';
import { CSS2DObject } from 'three/examples/jsm/renderers/CSS2DRenderer.js';
import { hexToCss } from './cityPalette';

export type LabelKind = 'district' | 'sub' | 'agent' | 'manager' | 'ceo';

export interface SceneLabel {
  obj: CSS2DObject;
  el: HTMLDivElement;
  kind: LabelKind;
  id: string;
  /** Estimated on-screen box in px. Estimated from text length rather than
   *  measured, because reading offsetWidth every frame forces a layout. */
  w: number;
  h: number;
  /** Box when `compact` (title line only). */
  wCompact: number;
  /** Title only -- set by the caller when the camera is too far out for the
   *  second line to earn its space. */
  compact: boolean;
  /** Labels sharing a group stand together (agents at one doorway) and are
   *  fanned out by `fanOut`; '' = not part of a cluster. */
  group: string;
  /** Set by the caller each frame: should this label show at all? */
  want: boolean;
  /** Higher wins a collision. */
  priority: number;
  key: string;
}

export function makeLabel(kind: LabelKind, id: string, accent: number): SceneLabel {
  const el = document.createElement('div');
  el.className = `cl cl-${kind}`;
  el.style.setProperty('--c', hexToCss(accent));
  const obj = new CSS2DObject(el);
  // Anchor the label's bottom-centre to its world point, so it sits ABOVE
  // what it names instead of across it.
  obj.center.set(0.5, 1);
  return { obj, el, kind, id, w: 0, h: 0, wCompact: 0, compact: false, group: '', want: true, priority: 0, key: '' };
}

export function setCompact(label: SceneLabel, compact: boolean): void {
  if (label.compact === compact) return;
  label.compact = compact;
  label.el.classList.toggle('compact', compact);
}

/** Rewrite a label's content -- a no-op when nothing changed, so a 10Hz
 *  store update does not churn the DOM. `chip` is a short state tag. */
export function setLabelText(label: SceneLabel, title: string, sub = '', chip = '', chipClass = ''): void {
  const key = `${title}|${sub}|${chip}|${chipClass}`;
  if (key === label.key) return;
  label.key = key;
  label.el.replaceChildren();
  const b = document.createElement('b');
  b.textContent = title;
  label.el.append(b);
  if (sub || chip) {
    const row = document.createElement('span');
    if (chip) {
      const c = document.createElement('i');
      c.textContent = chip;
      if (chipClass) c.className = chipClass;
      row.append(c);
    }
    if (sub) row.append(document.createTextNode(sub));
    label.el.append(row);
  }
  // ~6.4px per glyph at the label font sizes, plus padding.
  const glyph = label.kind === 'district' || label.kind === 'ceo' || label.kind === 'manager' ? 7.6 : 7.0;
  label.wCompact = title.length * glyph + 22 + (label.kind === 'agent' ? 12 : 0);
  label.w = Math.max(label.wCompact, (sub.length + chip.length + (chip ? 3 : 0)) * 5.6 + 22);
  label.h = sub || chip ? 36 : 22;
}

function effectivelyVisible(o: THREE.Object3D): boolean {
  for (let n: THREE.Object3D | null = o; n; n = n.parent) if (!n.visible) return false;
  return true;
}

const scratch = new THREE.Vector3();

function toScreen(l: SceneLabel, camera: THREE.Camera, width: number, height: number): [number, number] {
  l.obj.getWorldPosition(scratch).project(camera);
  return [(scratch.x + 1) / 2 * width, (1 - scratch.y) / 2 * height];
}

const LIFT_PX = 20;

/** Spread a cluster's tags so neighbours stop sitting on top of each other.
 *
 *  A row of agents projects to a diagonal on screen, and centred tags on a
 *  diagonal overlap pairwise no matter how the row is spaced. So, per group,
 *  sorted by screen x: tags alternate hanging LEFT and RIGHT of the head, which
 *  makes (left, right) neighbours disjoint by construction. The only pair
 *  that can still meet is (right, next-left); whichever of the two stands
 *  higher up the row is lifted clear. Measured from the real projection each
 *  frame, so it holds at any yaw, pitch or zoom. */
export function fanOut(labels: SceneLabel[], camera: THREE.Camera, width: number, height: number): void {
  const groups = new Map<string, { l: SceneLabel; x: number; y: number }[]>();
  for (const l of labels) {
    l.obj.center.set(0.5, 1);
    if (!l.group || !l.want) continue;
    const [x, y] = toScreen(l, camera, width, height);
    groups.set(l.group, [...(groups.get(l.group) ?? []), { l, x, y }]);
  }
  for (const list of groups.values()) {
    if (list.length < 2) continue;
    list.sort((a, b) => a.x - b.x);
    const lift = new Set<SceneLabel>();
    for (let k = 1; k < list.length - 1; k += 2) {
      const [a, b] = [list[k], list[k + 1]];
      lift.add(b.y > a.y ? a.l : b.l);
    }
    list.forEach(({ l }, k) => {
      const h = l.compact ? 22 : l.h;
      l.obj.center.set(k % 2 === 0 ? 1 : 0, lift.has(l) ? 1 + LIFT_PX / h : 1);
    });
  }
}

/** Greedy placement: highest priority first; a label whose box overlaps one
 *  already placed is hidden. Sets `obj.visible`, which CSS2DRenderer honours.
 *  The caller must have rendered (matrixWorld current) before calling. */
export function declutter(labels: SceneLabel[], camera: THREE.Camera, width: number, height: number): void {
  const placed: [number, number, number, number][] = [];
  const order = labels
    .filter((l) => {
      if (!l.want) { l.obj.visible = false; return false; }
      l.obj.visible = true;
      return effectivelyVisible(l.obj.parent ?? l.obj);
    })
    .sort((a, b) => b.priority - a.priority);
  for (const l of order) {
    const [x, y] = toScreen(l, camera, width, height);
    const w = l.compact ? l.wCompact : l.w;
    const h = l.compact ? 22 : l.h;
    // The box follows the label's anchor (fanOut moves it off-centre).
    const left = x - l.obj.center.x * w, top = y - l.obj.center.y * h;
    const box: [number, number, number, number] = [left - 3, top - 3, left + w + 3, top + h + 3];
    const clash = placed.some((p) => box[0] < p[2] && box[2] > p[0] && box[1] < p[3] && box[3] > p[1]);
    l.obj.visible = !clash;
    if (!clash) placed.push(box);
  }
}
