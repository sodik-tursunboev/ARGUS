/* Backend /face/status contract — faceauth.status() documented verbatim.
   The endpoint fails open with available:false + error when faceauth cannot
   start; the fields below are the complete documented shape. */
export interface FaceStatus {
  available?: boolean;
  presence_watch?: boolean;
  presence_locks?: number;
  presence_interval?: number;
  enrolled?: boolean;
  samples?: number;
  threshold?: number | null;
  checks?: number;
  matches?: number;
  last_distance?: number | null;
  last_brightness?: number | null;
  liveness?: string;
  liveness_last?: string;
  presence_idle_lock_s?: number;
  camera?: string;
  spoofable?: string;
  last_error?: string;
  error?: string;
}
