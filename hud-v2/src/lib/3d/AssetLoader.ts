/* ARGUS 3D Asset Loader — Centralized loader for real 3D assets
   Loads GLB/GLTF models with caching and fallback support */
import * as THREE from 'three';
import { GLTFLoader, type GLTF } from 'three/examples/jsm/loaders/GLTFLoader.js';
import { FBXLoader } from 'three/examples/jsm/loaders/FBXLoader.js';

export interface LoadedAsset {
  scene: THREE.Group;
  animations: THREE.AnimationClip[];
  assetName: string;
}

export interface AssetConfig {
  scale: number;
  rotation: [number, number, number];
  position: [number, number, number];
}

class AssetLoaderCache {
  private gltfLoader: GLTFLoader;
  private fbxLoader: FBXLoader;
  private cache: Map<string, LoadedAsset> = new Map();
  private loading: Map<string, Promise<LoadedAsset>> = new Map();

  constructor() {
    this.gltfLoader = new GLTFLoader();
    this.fbxLoader = new FBXLoader();
  }

  async loadGLB(path: string, assetName: string): Promise<LoadedAsset> {
    // Check cache first
    if (this.cache.has(path)) {
      return this.cache.get(path)!;
    }

    // Check if already loading
    if (this.loading.has(path)) {
      return this.loading.get(path)!;
    }

    // Start loading
    const loadPromise = new Promise<LoadedAsset>((resolve, reject) => {
      this.gltfLoader.load(
        path,
        (gltf: GLTF) => {
          const asset: LoadedAsset = {
            scene: gltf.scene,
            animations: gltf.animations,
            assetName,
          };
          this.cache.set(path, asset);
          this.loading.delete(path);
          resolve(asset);
        },
        undefined,
        (error: unknown) => {
          this.loading.delete(path);
          reject(new Error(`Failed to load ${path}: ${error}`));
        }
      );
    });

    this.loading.set(path, loadPromise);
    return loadPromise;
  }

  async loadFBX(path: string, assetName: string): Promise<LoadedAsset> {
    // Check cache first
    if (this.cache.has(path)) {
      return this.cache.get(path)!;
    }

    // Check if already loading
    if (this.loading.has(path)) {
      return this.loading.get(path)!;
    }

    // Start loading
    const loadPromise = new Promise<LoadedAsset>((resolve, reject) => {
      this.fbxLoader.load(
        path,
        (fbx: THREE.Group) => {
          const asset: LoadedAsset = {
            scene: fbx,
            animations: (fbx as THREE.Group & { animations?: THREE.AnimationClip[] }).animations || [],
            assetName,
          };
          this.cache.set(path, asset);
          this.loading.delete(path);
          resolve(asset);
        },
        undefined,
        (error: unknown) => {
          this.loading.delete(path);
          reject(new Error(`Failed to load ${path}: ${error}`));
        }
      );
    });

    this.loading.set(path, loadPromise);
    return loadPromise;
  }

  // Clone a loaded asset (safe for multiple instances)
  cloneAsset(asset: LoadedAsset): THREE.Group {
    const clone = asset.scene.clone();
    // Deep clone materials if needed
    clone.traverse((child: THREE.Object3D) => {
      if (child instanceof THREE.Mesh) {
        if (Array.isArray(child.material)) {
          child.material = child.material.map((m: THREE.Material) => m.clone());
        } else if (child.material) {
          child.material = child.material.clone();
        }
      }
    });
    return clone;
  }

  // Get cached asset if available
  getCached(path: string): LoadedAsset | undefined {
    return this.cache.get(path);
  }

  // Clear cache
  clearCache(): void {
    this.cache.forEach((asset) => {
      asset.scene.traverse((child: THREE.Object3D) => {
        if (child instanceof THREE.Mesh) {
          child.geometry?.dispose();
          if (Array.isArray(child.material)) {
            child.material.forEach((m: THREE.Material) => m.dispose());
          } else if (child.material) {
            child.material.dispose();
          }
        }
      });
    });
    this.cache.clear();
  }
}

// Singleton instance
export const assetLoader = new AssetLoaderCache();

// Asset configuration for ARGUS office
export const ASSET_CONFIGS: Record<string, AssetConfig> = {
  // Room structure (GLB)
  'template-floor': { scale: 1.0, rotation: [0, 0, 0], position: [0, 0, 0] },
  'template-wall': { scale: 1.0, rotation: [0, 0, 0], position: [0, 0, 0] },
  'corridor': { scale: 1.0, rotation: [0, 0, 0], position: [0, 0, 0] },

  // Furniture (FBX from ScifiOfficeLite)
  'table': { scale: 0.01, rotation: [0, Math.PI, 0], position: [0, 0, 0] },
  'chair': { scale: 0.01, rotation: [0, 0, 0], position: [0, 0, 0] },
  'pc': { scale: 0.01, rotation: [0, 0, 0], position: [0, 0, 0] },
  'server-rack': { scale: 0.01, rotation: [0, 0, 0], position: [0, 0, 0] },
};

// Asset paths
export const ASSET_PATHS = {
  // GLB format (preferred)
  floor: '/assets/3d/environment/Models/GLB format/template-floor.glb',
  wall: '/assets/3d/environment/Models/GLB format/template-wall.glb',
  corridor: '/assets/3d/environment/Models/GLB format/corridor.glb',
  roomSmall: '/assets/3d/environment/Models/GLB format/room-small.glb',
  cables: '/assets/3d/environment/Models/GLB format/cables.glb',
  computer: '/assets/3d/environment/Models/GLB format/computer.glb',
  computerScreen: '/assets/3d/environment/Models/GLB format/computer-screen.glb',

  // FBX format (fallback)
  table: '/assets/3d/scifi-office/Table 1.FBX',
  chair: '/assets/3d/scifi-office/office chair.FBX',
  pc: '/assets/3d/scifi-office/PC 2.FBX',
  serverRack: '/assets/3d/scifi-office/Server Rack.FBX',
};
