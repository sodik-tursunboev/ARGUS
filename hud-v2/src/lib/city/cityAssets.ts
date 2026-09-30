/* ARGUS AI City -- GLB asset registry.
   ==========================================================================

   The city's hero architecture and its robot citizens are authored in
   Blender (tools/blender/) and shipped as optimized GLB. This module is the
   only thing that knows how they get from public/assets/city/ into the
   scene.

   Two cloning strategies, deliberately:

   - Static buildings/props use THREE.Object3D.clone(), which SHARES geometry
     and materials with the source. Twenty scenery blocks therefore cost
     twenty draw calls against one set of buffers, not twenty uploads. The
     price is that a material change hits every clone -- which is exactly why
     anything whose colour changes at runtime gets its material cloned
     explicitly via `instantiate(..., { isolateMaterials: true })`.

   - The robot is a SKINNED mesh, so it needs SkeletonUtils.clone(): a plain
     clone would leave every copy bound to the original's skeleton and they
     would all animate identically.

   Loading is non-blocking. The scene builds its layout immediately and each
   GLB drops in when it arrives, so a slow disk never leaves a blank canvas.
*/

import * as THREE from 'three';
import { GLTFLoader, type GLTF } from 'three/examples/jsm/loaders/GLTFLoader.js';
import { clone as cloneSkinned } from 'three/examples/jsm/utils/SkeletonUtils.js';

const ASSET_BASE = 'assets/city';

export interface ManifestEntry {
  file: string;
  name: string;
  triangles: number;
  bytes: number;
  objects: number;
  kind?: string;
  family?: string;
  animations?: string[];
  height?: number;
  bones?: number;
}

export interface Manifest {
  generator: string;
  scale: string;
  assets: ManifestEntry[];
  totals: { files: number; triangles: number; bytes: number };
}

export interface LoadedModel {
  scene: THREE.Group;
  animations: THREE.AnimationClip[];
  entry: ManifestEntry | null;
  /** Local-space bounds, measured once -- camera framing reads this instead
   *  of re-running setFromObject on every focus click. */
  box: THREE.Box3;
  size: THREE.Vector3;
}

const loader = new GLTFLoader();
const models = new Map<string, LoadedModel>();
const inflight = new Map<string, Promise<LoadedModel | null>>();
let manifest: Manifest | null = null;
let manifestPromise: Promise<Manifest | null> | null = null;

/** Resolve a URL under the app's base path. Vite serves `public/` at the
 *  configured base, which is not necessarily "/" -- joining by hand breaks
 *  the moment the HUD is served from a sub-path. */
function assetUrl(rel: string): string {
  const base = import.meta.env.BASE_URL ?? '/';
  return `${base.replace(/\/$/, '')}/${ASSET_BASE}/${rel}`;
}

export function loadManifest(): Promise<Manifest | null> {
  if (manifest) return Promise.resolve(manifest);
  if (manifestPromise) return manifestPromise;
  manifestPromise = fetch(assetUrl('manifest.json'))
    .then((r) => (r.ok ? r.json() : null))
    .then((json: Manifest | null) => {
      manifest = json;
      return json;
    })
    .catch(() => null);
  return manifestPromise;
}

export function manifestEntry(name: string): ManifestEntry | null {
  return manifest?.assets.find((a) => a.name === name) ?? null;
}

export function assetStats(): { files: number; triangles: number; bytes: number } | null {
  return manifest?.totals ?? null;
}

/** Load one GLB by its subdir + basename. Resolves to null (never throws) if
 *  the asset is missing, so a partial asset build degrades to the procedural
 *  fallback instead of blanking the scene. */
export function loadModel(subdir: string, name: string): Promise<LoadedModel | null> {
  const key = `${subdir}/${name}`;
  const cached = models.get(key);
  if (cached) return Promise.resolve(cached);
  const pending = inflight.get(key);
  if (pending) return pending;

  const p = new Promise<LoadedModel | null>((resolve) => {
    loader.load(
      assetUrl(`${subdir}/${name}.glb`),
      (gltf: GLTF) => {
        const box = new THREE.Box3().setFromObject(gltf.scene);
        const size = new THREE.Vector3();
        box.getSize(size);
        // Shadows are opted into per-instance by the scene's shadow budget;
        // default everything off so a 30-building city does not silently
        // become 30 shadow casters.
        gltf.scene.traverse((child: THREE.Object3D) => {
          child.castShadow = false;
          child.receiveShadow = false;
        });
        const model: LoadedModel = {
          scene: gltf.scene,
          animations: gltf.animations,
          entry: manifestEntry(name),
          box,
          size,
        };
        models.set(key, model);
        inflight.delete(key);
        resolve(model);
      },
      undefined,
      () => {
        inflight.delete(key);
        resolve(null);
      },
    );
  });
  inflight.set(key, p);
  return p;
}

export interface InstantiateOpts {
  /** Clone materials so this instance can be recoloured without affecting
   *  every other copy. Only for things that actually change colour. */
  isolateMaterials?: boolean;
  /** Use skinned cloning. Required for the robot; wasteful for anything else. */
  skinned?: boolean;
  castShadow?: boolean;
  receiveShadow?: boolean;
}

export function instantiate(model: LoadedModel, opts: InstantiateOpts = {}): THREE.Group {
  const root = (opts.skinned
    ? (cloneSkinned(model.scene) as THREE.Group)
    : model.scene.clone(true)) as THREE.Group;

  if (opts.isolateMaterials || opts.castShadow || opts.receiveShadow) {
    root.traverse((child: THREE.Object3D) => {
      const mesh = child as THREE.Mesh;
      if (!(child instanceof THREE.Mesh)) return;
      if (opts.castShadow) mesh.castShadow = true;
      if (opts.receiveShadow) mesh.receiveShadow = true;
      if (opts.isolateMaterials) {
        const m = mesh.material;
        mesh.material = Array.isArray(m)
          ? m.map((x) => x.clone())
          : (m as THREE.Material).clone();
      }
    });
  }
  return root;
}

/** Collect the emissive materials inside an instance, keyed by material name.
 *  The scene uses this to drive live-state colour onto exactly the parts the
 *  asset intends to be lit, instead of tinting a whole building. */
export function emissiveMaterials(root: THREE.Object3D): Map<string, THREE.MeshStandardMaterial[]> {
  const out = new Map<string, THREE.MeshStandardMaterial[]>();
  root.traverse((child: THREE.Object3D) => {
    if (!(child instanceof THREE.Mesh)) return;
    const mats = Array.isArray(child.material) ? child.material : [child.material];
    for (const m of mats) {
      const std = m as THREE.MeshStandardMaterial;
      if (!std || std.emissiveIntensity === undefined || std.emissiveIntensity <= 0.01) continue;
      const list = out.get(std.name) ?? [];
      list.push(std);
      out.set(std.name, list);
    }
  });
  return out;
}

/** Free everything this module holds. The caches outlive a component
 *  instance, so the scene's unmount must call this explicitly. */
export function disposeAssets(): void {
  for (const model of models.values()) {
    model.scene.traverse((child: THREE.Object3D) => {
      if (!(child instanceof THREE.Mesh)) return;
      child.geometry?.dispose();
      const m = child.material;
      (Array.isArray(m) ? m : [m]).forEach((mat) => (mat as THREE.Material)?.dispose());
    });
  }
  models.clear();
  inflight.clear();
  manifest = null;
  manifestPromise = null;
}
