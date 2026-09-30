/* ARGUS AI City -- camera rig.
   ==========================================================================

   One OrthographicCamera, driven by an orbit rig: a look-at TARGET, a YAW, a
   PITCH and a ZOOM (the frustum half-height). Camera position is derived
   from those every frame, never set directly, which is what makes every
   transition -- preset, district focus, building focus, interior -- the same
   smooth interpolation instead of a special case.

   Why orthographic framing is exact here: with no perspective divide, a
   bounding box's on-screen extent is just its corners projected onto the
   camera's own right/up axes. So `frameBox` can fit a building precisely
   rather than guessing a distance from a radius -- which is what used to let
   a tall landmark clip out of frame.

   Mouse: left-drag ROTATES (or MOVES, when the owner switches the city to
   map-style dragging), right/middle/shift-drag does the other one, the wheel
   zooms toward the cursor and a double-click zooms in on the spot. Panning
   grabs the ground: the point under the cursor stays under it on both axes.
   Without a mouse: the on-screen camera pad and the keyboard (keyNudge) step
   the view with the same glide as a preset.
*/

import * as THREE from 'three';

export type CameraPreset =
  | 'CITY_OVERVIEW' | 'DISTRICT' | 'BUILDING_FOCUS' | 'STREET_LEVEL' | 'INTERIOR';

export interface RigLimits {
  minPitch: number;
  maxPitch: number;
  minZoom: number;
  maxZoom: number;
}

const DEG = Math.PI / 180;

export const DEFAULT_LIMITS: RigLimits = {
  // Below ~22 degrees an orthographic city turns into an edge-on smear where
  // the near blocks hide everything behind them; above ~72 it degenerates
  // toward a flat map and lookAt starts to flip.
  minPitch: 22 * DEG,
  maxPitch: 72 * DEG,
  // 9 = an 18-unit-tall view: a whole robot and its doorway. Anything closer
  // was the "awkward extreme close-up" -- a wall of one building's texture.
  minZoom: 9,
  maxZoom: 140,
};

export interface PresetSpec {
  yaw: number;
  pitch: number;
  zoom: number;
  label: string;
  hint: string;
}

/** Yaw stays in the 40-50 degree band that reads as isometric; only
 *  STREET_LEVEL drops the pitch, and it stays orthographic so it is a
 *  low-angle city view rather than a different projection. */
export const PRESETS: Record<CameraPreset, PresetSpec> = {
  CITY_OVERVIEW: { yaw: 45 * DEG, pitch: 44 * DEG, zoom: 96, label: 'CITY OVERVIEW', hint: 'The whole city' },
  DISTRICT: { yaw: 45 * DEG, pitch: 42 * DEG, zoom: 34, label: 'DISTRICT', hint: 'One block and its streets' },
  BUILDING_FOCUS: { yaw: 40 * DEG, pitch: 34 * DEG, zoom: 18, label: 'BUILDING', hint: 'A single structure' },
  STREET_LEVEL: { yaw: 48 * DEG, pitch: 24 * DEG, zoom: 14, label: 'STREET', hint: 'Down among the agents' },
  INTERIOR: { yaw: 45 * DEG, pitch: 46 * DEG, zoom: 16, label: 'INTERIOR', hint: 'Inside the building' },
};

/** Smoothing rates (1/s). Direct manipulation must feel attached to the
 *  mouse; a preset change should glide. One rate for both is why the old rig
 *  felt floaty under the hand and abrupt on presets at the same time. */
const RATE_INPUT = 16;
const RATE_TRANSITION = 5;

export class CityCameraRig {
  camera: THREE.OrthographicCamera;
  limits: RigLimits;

  /** Current (rendered) state. */
  private target = new THREE.Vector3(0, 2, 0);
  private yaw = PRESETS.CITY_OVERVIEW.yaw;
  private pitch = PRESETS.CITY_OVERVIEW.pitch;
  private zoom = PRESETS.CITY_OVERVIEW.zoom;

  /** Desired state; everything lerps toward this. */
  private wantTarget = new THREE.Vector3(0, 2, 0);
  private wantYaw = PRESETS.CITY_OVERVIEW.yaw;
  private wantPitch = PRESETS.CITY_OVERVIEW.pitch;
  private wantZoom = PRESETS.CITY_OVERVIEW.zoom;

  preset: CameraPreset = 'CITY_OVERVIEW';
  private aspect = 1.6;
  /** Last change came from the user's hand (fast follow) vs a programmatic
   *  transition (slow glide). */
  private direct = false;
  /** Where the look-at target may go. The city and each far-parked interior
   *  get their own box -- a single global radius is what sent the camera to
   *  an empty patch of ground whenever an interior was entered. */
  private bounds: THREE.Box3 | null = null;

  /** How far the camera stands off its look-at target. For an orthographic
   *  camera this never affects apparent size -- it only has to clear the near
   *  plane at any orbit angle, which at 400 units it always does, so no
   *  building can ever be clipped by the camera. It IS, however, the depth
   *  everything in the scene renders at, so the scene's fog band has to be
   *  derived from it. Exposed for exactly that reason. */
  static readonly standoff = 400;
  private readonly distance = CityCameraRig.standoff;

  private scratch = new THREE.Vector3();
  private right = new THREE.Vector3();
  private upAxis = new THREE.Vector3();
  private forward = new THREE.Vector3();

  constructor(aspect: number, limits: RigLimits = DEFAULT_LIMITS) {
    this.limits = limits;
    this.aspect = aspect;
    this.camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0.5, this.distance * 2.5);
    this.applyFrustum();
    this.sync(1);
  }

  /** Orthonormal view basis for a yaw/pitch pair. */
  private basisFor(yaw: number, pitch: number, fwd: THREE.Vector3, right: THREE.Vector3, up: THREE.Vector3): void {
    const cp = Math.cos(pitch), sp = Math.sin(pitch);
    fwd.set(-cp * Math.sin(yaw), -sp, -cp * Math.cos(yaw)).normalize();
    right.set(Math.cos(yaw), 0, -Math.sin(yaw)).normalize();
    // right x forward IS screen-up (camera x cross -z = +y). The old basis
    // negated it; harmless while `up` was only used inside abs() by
    // frameBox, wrong the moment zoom-to-cursor needed its sign.
    up.crossVectors(right, fwd).normalize();
  }

  private applyFrustum(): void {
    const h = this.zoom;
    const w = h * this.aspect;
    this.camera.left = -w;
    this.camera.right = w;
    this.camera.top = h;
    this.camera.bottom = -h;
    this.camera.updateProjectionMatrix();
  }

  setAspect(aspect: number): void {
    this.aspect = aspect;
    this.applyFrustum();
  }

  /** Advance toward the desired state. `t` of 1 snaps (used on construction
   *  and on an explicit teleport). */
  sync(t: number): void {
    this.target.lerp(this.wantTarget, t);
    this.yaw += (this.wantYaw - this.yaw) * t;
    this.pitch += (this.wantPitch - this.pitch) * t;
    this.zoom += (this.wantZoom - this.zoom) * t;

    this.basisFor(this.yaw, this.pitch, this.forward, this.right, this.upAxis);
    this.camera.position.copy(this.target).addScaledVector(this.forward, -this.distance);
    this.camera.up.set(0, 1, 0);
    this.camera.lookAt(this.target);
    this.applyFrustum();
  }

  /** Frame-rate independent smoothing: the same feel at 30 or 60fps. */
  update(dt: number): void {
    const rate = this.direct ? RATE_INPUT : RATE_TRANSITION;
    this.sync(1 - Math.exp(-Math.min(dt, 0.1) * rate));
  }

  /** True once the rig has effectively arrived -- the scene renders every
   *  frame until then and drops back to its 30fps budget after. */
  settled(): boolean {
    return this.target.distanceTo(this.wantTarget) < 0.05
      && Math.abs(this.zoom - this.wantZoom) < 0.05
      && Math.abs(this.yaw - this.wantYaw) < 0.002
      && Math.abs(this.pitch - this.wantPitch) < 0.002;
  }

  get currentZoom(): number { return this.zoom; }
  get currentTarget(): THREE.Vector3 { return this.target; }
  /** Where the camera is heading -- the right anchor for a new preset, even
   *  mid-transition. */
  get desiredTarget(): THREE.Vector3 { return this.wantTarget; }

  setBounds(box: THREE.Box3 | null): void {
    this.bounds = box ? box.clone() : null;
  }

  // ---- intent ------------------------------------------------------------

  applyPreset(preset: CameraPreset, target?: THREE.Vector3): void {
    const spec = PRESETS[preset];
    this.direct = false;
    this.preset = preset;
    this.wantYaw = spec.yaw;
    this.wantPitch = spec.pitch;
    this.wantZoom = this.clampZoom(spec.zoom);
    if (target) this.wantTarget.copy(this.clampTarget(target.clone()));
  }

  /** `yaw` (radians, optional) also swings the camera round to that bearing
   *  -- a ROOM view uses it to face a wall screen square on. */
  lookAtPoint(point: THREE.Vector3, zoom?: number, direct = false, yaw?: number): void {
    this.direct = direct;
    this.wantTarget.copy(this.clampTarget(point.clone()));
    if (zoom !== undefined) this.wantZoom = this.clampZoom(zoom);
    if (yaw !== undefined) this.wantYaw = yaw;
  }

  /** Frame a world-space box exactly, with padding. Projects the box's eight
   *  corners onto the camera's right/up axes at the DESIRED orbit angles (not
   *  the current ones) so the fit is correct once the transition lands. */
  frameBox(box: THREE.Box3, pad = 1.18, minZoom = 7): void {
    this.direct = false;
    const fwd = new THREE.Vector3(), right = new THREE.Vector3(), up = new THREE.Vector3();
    this.basisFor(this.wantYaw, this.wantPitch, fwd, right, up);

    const centre = new THREE.Vector3();
    box.getCenter(centre);
    let halfW = 0, halfH = 0;
    const c = new THREE.Vector3();
    for (let i = 0; i < 8; i++) {
      c.set(
        i & 1 ? box.max.x : box.min.x,
        i & 2 ? box.max.y : box.min.y,
        i & 4 ? box.max.z : box.min.z,
      ).sub(centre);
      halfW = Math.max(halfW, Math.abs(c.dot(right)));
      halfH = Math.max(halfH, Math.abs(c.dot(up)));
    }
    const needed = Math.max(halfH, halfW / this.aspect) * pad;
    this.wantTarget.copy(this.clampTarget(centre));
    this.wantZoom = this.clampZoom(Math.max(minZoom, needed));
  }

  // ---- user input --------------------------------------------------------

  orbit(dxPixels: number, dyPixels: number): void {
    this.direct = true;
    // Drag right swings the camera left round the target; drag down tilts
    // toward top-down -- the OrbitControls/MapControls convention.
    this.wantYaw -= dxPixels * 0.005;
    this.wantPitch = THREE.MathUtils.clamp(
      this.wantPitch + dyPixels * 0.004, this.limits.minPitch, this.limits.maxPitch);
  }

  /** Grab-the-ground pan: the point under the cursor stays under the cursor
   *  on BOTH axes. Horizontal is a plain screen-right move; vertical walks
   *  the ground plane, divided by sin(pitch) because the ground is
   *  foreshortened by exactly that on screen -- without it the city lagged
   *  behind the mouse by a third at the default tilt. */
  pan(dxPixels: number, dyPixels: number, viewportHeight: number): void {
    this.direct = true;
    const worldPerPixel = (this.zoom * 2) / Math.max(1, viewportHeight);
    const fwd = this.forward, right = this.right;
    this.basisFor(this.wantYaw, this.wantPitch, fwd, right, this.upAxis);
    this.wantTarget.addScaledVector(right, -dxPixels * worldPerPixel);
    this.scratch.set(fwd.x, 0, fwd.z).normalize()
      .multiplyScalar(dyPixels * worldPerPixel / Math.max(0.2, Math.sin(this.wantPitch)));
    this.wantTarget.add(this.scratch);
    this.wantTarget.copy(this.clampTarget(this.wantTarget));
    // Restore the RENDERED basis -- sync() owns these vectors.
    this.basisFor(this.yaw, this.pitch, this.forward, this.right, this.upAxis);
  }

  /** Zoom toward the point under the cursor (normalised device coords).
   *  Exact for an orthographic view: scaling the target's offset from the
   *  ground point P by the zoom ratio leaves P at the same screen position. */
  zoomAt(deltaY: number, ndcX = 0, ndcY = 0): void {
    this.direct = true;
    const next = this.clampZoom(this.wantZoom * Math.exp(deltaY * 0.0011));
    const k = next / this.wantZoom;
    if (Math.abs(k - 1) < 1e-6) return;
    const fwd = new THREE.Vector3(), right = new THREE.Vector3(), up = new THREE.Vector3();
    this.basisFor(this.wantYaw, this.wantPitch, fwd, right, up);
    const o = this.wantTarget.clone()
      .addScaledVector(right, ndcX * this.wantZoom * this.aspect)
      .addScaledVector(up, ndcY * this.wantZoom);
    // Ray o + s*fwd meets the horizontal plane through the target.
    const s = (this.wantTarget.y - o.y) / (fwd.y || -1e-6);
    const p = o.addScaledVector(fwd, s);
    this.wantTarget.sub(p).multiplyScalar(k).add(p);
    this.wantTarget.copy(this.clampTarget(this.wantTarget));
    this.wantZoom = next;
  }

  /** A button or key press: a step of the DESIRED view that glides, so a
   *  held key or a run of clicks reads as one continuous move. Pan steps are
   *  screen-relative (right = screen right, forward = screen up, walked
   *  along the ground) in fractions of the view's half-height, so one press
   *  moves the same share of the screen at any zoom. */
  nudge(o: { yaw?: number; pitch?: number; zoom?: number; right?: number; forward?: number }): void {
    this.direct = false;
    if (o.yaw) this.wantYaw += o.yaw;
    if (o.pitch) this.wantPitch = THREE.MathUtils.clamp(this.wantPitch + o.pitch, this.limits.minPitch, this.limits.maxPitch);
    if (o.zoom) this.wantZoom = this.clampZoom(this.wantZoom * o.zoom);
    if (o.right || o.forward) {
      const fwd = new THREE.Vector3(), right = new THREE.Vector3(), up = new THREE.Vector3();
      this.basisFor(this.wantYaw, this.wantPitch, fwd, right, up);
      fwd.y = 0;
      fwd.normalize();
      this.wantTarget.addScaledVector(right, (o.right ?? 0) * this.wantZoom)
        .addScaledVector(fwd, (o.forward ?? 0) * this.wantZoom);
      this.wantTarget.copy(this.clampTarget(this.wantTarget));
    }
  }

  private clampZoom(z: number): number {
    return THREE.MathUtils.clamp(z, this.limits.minZoom, this.limits.maxZoom);
  }

  private clampTarget(v: THREE.Vector3): THREE.Vector3 {
    if (!this.bounds) return v;
    return v.set(
      THREE.MathUtils.clamp(v.x, this.bounds.min.x, this.bounds.max.x),
      THREE.MathUtils.clamp(v.y, this.bounds.min.y, this.bounds.max.y),
      THREE.MathUtils.clamp(v.z, this.bounds.min.z, this.bounds.max.z),
    );
  }

  /** Move the rig somewhere far away without a visible sweep across the
   *  city -- used when entering an interior parked at its own origin. */
  teleportTo(target: THREE.Vector3, preset: CameraPreset, zoom?: number): void {
    this.applyPreset(preset, target);
    if (zoom !== undefined) this.wantZoom = this.clampZoom(zoom);
    this.target.copy(this.wantTarget);
    this.yaw = this.wantYaw;
    this.pitch = this.wantPitch;
    this.zoom = this.wantZoom;
    this.sync(1);
  }
}

export type DragMode = 'orbit' | 'pan';

/** Which drag a pointer-down starts. Left does `left` -- orbit by default
 *  (the standard 3D-viewer habit), or pan when the owner switches the city
 *  to map-style MOVE -- and middle/right or a modified left drag do the
 *  other one (a trackpad has no middle or right button to drag with). */
export function dragModeFor(button: number, mods: { shiftKey?: boolean; ctrlKey?: boolean; altKey?: boolean } = {},
  left: DragMode = 'orbit'): DragMode {
  const other: DragMode = left === 'orbit' ? 'pan' : 'orbit';
  if (button === 1 || button === 2) return other;
  return mods.shiftKey || mods.ctrlKey || mods.altKey ? other : left;
}

/** Keyboard camera: WASD / arrows move, Q/E turn, R/F tilt, +/- zoom. The
 *  step for one key event (the OS auto-repeat makes a held key continuous).
 *  Null = not a camera key. */
export function keyNudge(key: string): Parameters<CityCameraRig['nudge']>[0] | null {
  switch (key.toLowerCase()) {
    case 'w': case 'arrowup': return { forward: 0.08 };
    case 's': case 'arrowdown': return { forward: -0.08 };
    case 'a': case 'arrowleft': return { right: -0.08 };
    case 'd': case 'arrowright': return { right: 0.08 };
    case 'q': return { yaw: -5 * DEG };
    case 'e': return { yaw: 5 * DEG };
    case 'r': return { pitch: 3 * DEG };
    case 'f': return { pitch: -3 * DEG };
    case '+': case '=': return { zoom: 0.9 };
    case '-': case '_': return { zoom: 1.1 };
    default: return null;
  }
}

/** Attach pan/rotate/zoom to a DOM element. Returns a detach function.
 *  `onInteract` fires on any manual control so the caller can drop out of a
 *  preset's "follow" behaviour the moment the user takes over. */
export function attachCameraControls(
  el: HTMLElement,
  rig: CityCameraRig,
  opts: { onInteract?: () => void; isDragBlocked?: () => boolean; leftDrag?: () => DragMode } = {},
): () => void {
  let dragging: DragMode | null = null;
  let lastX = 0, lastY = 0;
  let moved = 0;

  const down = (e: PointerEvent) => {
    if (opts.isDragBlocked?.()) return;
    dragging = dragModeFor(e.button, e, opts.leftDrag?.());
    el.dataset.drag = dragging;
    lastX = e.clientX;
    lastY = e.clientY;
    moved = 0;
    el.setPointerCapture?.(e.pointerId);
  };

  const move = (e: PointerEvent) => {
    if (!dragging) return;
    const dx = e.clientX - lastX;
    const dy = e.clientY - lastY;
    lastX = e.clientX;
    lastY = e.clientY;
    moved += Math.abs(dx) + Math.abs(dy);
    // A click with a hair of jitter must stay a click, not nudge the city.
    if (moved <= 3) return;
    if (dragging === 'orbit') rig.orbit(dx, dy);
    else rig.pan(dx, dy, el.clientHeight);
    opts.onInteract?.();
  };

  const up = (e: PointerEvent) => {
    dragging = null;
    delete el.dataset.drag;
    el.releasePointerCapture?.(e.pointerId);
  };

  const wheel = (e: WheelEvent) => {
    e.preventDefault();
    const rect = el.getBoundingClientRect();
    const ndcX = ((e.clientX - rect.left) / Math.max(1, rect.width)) * 2 - 1;
    const ndcY = -((e.clientY - rect.top) / Math.max(1, rect.height)) * 2 + 1;
    // Line-mode wheels (Firefox) report ~3 per notch instead of ~100.
    const dy = e.deltaMode === 1 ? e.deltaY * 33 : e.deltaY;
    rig.zoomAt(THREE.MathUtils.clamp(dy, -240, 240), ndcX, ndcY);
    opts.onInteract?.();
  };

  const context = (e: Event) => e.preventDefault();

  // Double-click: zoom in on the spot, no drag needed.
  const dbl = (e: MouseEvent) => {
    const rect = el.getBoundingClientRect();
    rig.zoomAt(-420, ((e.clientX - rect.left) / Math.max(1, rect.width)) * 2 - 1,
      -((e.clientY - rect.top) / Math.max(1, rect.height)) * 2 + 1);
    opts.onInteract?.();
  };

  el.addEventListener('pointerdown', down);
  el.addEventListener('pointermove', move);
  el.addEventListener('pointerup', up);
  el.addEventListener('pointercancel', up);
  el.addEventListener('wheel', wheel, { passive: false });
  el.addEventListener('contextmenu', context);
  el.addEventListener('dblclick', dbl);

  return () => {
    el.removeEventListener('pointerdown', down);
    el.removeEventListener('pointermove', move);
    el.removeEventListener('pointerup', up);
    el.removeEventListener('pointercancel', up);
    el.removeEventListener('wheel', wheel);
    el.removeEventListener('contextmenu', context);
    el.removeEventListener('dblclick', dbl);
  };
}

/** Did the last pointer sequence move far enough to count as a drag rather
 *  than a click? The scene uses this so panning never also selects. */
export function makeClickGuard(threshold = 4) {
  let sx = 0, sy = 0, dist = 0;
  return {
    start(e: PointerEvent) { sx = e.clientX; sy = e.clientY; dist = 0; },
    move(e: PointerEvent) { dist = Math.max(dist, Math.hypot(e.clientX - sx, e.clientY - sy)); },
    isClick() { return dist <= threshold; },
  };
}
