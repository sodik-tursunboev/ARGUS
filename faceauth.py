"""
ARGUS - Face recognition: presence, greeting, and a SECOND factor. Never a key.

WHAT THIS IS NOT. It is not face unlock. The camera on this machine
(HP Wide Vision HD) is a single RGB sensor with no infrared, measured and
confirmed -- which is exactly why Windows Hello declines to use it. An RGB-only
camera cannot distinguish a face from a photograph of that face held up on a
phone screen. Anything built on it that REPLACED the PIN would feel like an
upgrade while being a downgrade, so this module refuses to be sufficient on its
own: auth.verify() rejects a configuration in which "face" is the only factor,
the same way it already rejects "os_account" alone and for the same reason --
neither can tell the owner from someone standing where the owner stands.

WHAT IT HONESTLY IS, in descending order of value:

  * PRESENCE. "Is somebody sitting here?" needs no anti-spoofing at all, because
    faking presence gains an attacker nothing -- the worst outcome is that ARGUS
    fails to lock, which is exactly today's behaviour. Locking the moment the
    owner walks away is a pure security GAIN, and it is the reason to build this.
  * SECOND FACTOR. Face AND PIN together raise the bar for a high-value action.
    Face alone never lowers it.
  * GREETING. Knowing it is you, and saying so. No security claim whatsoever.

MEASURED FACTS THIS CODE IS BUILT ON (this camera, this room):
  * Auto-exposure needs ~10 frames to settle: frame 0 read 53/255 and frame 10
    read 127/255. Judging the FIRST frame concludes "too dark, no face" on a
    camera that works perfectly. WARMUP_FRAMES exists because of that, and is
    the single most important line in the file.
  * Once settled, a face was detected in 20 of 20 frames at ~109x109 px, and
    detection costs 21 ms. There is no performance problem here.

NO DOWNLOADED MODEL. Detection uses the Haar cascades that ship INSIDE
opencv-python (pinned <5 -- OpenCV 5.0 removed CascadeClassifier and bundles no
cascades, so the version bound is load-bearing, not cosmetic). Identity matching
is a Local Binary Pattern histogram computed here in numpy and compared against
samples the user enrolled themselves. Nothing is fetched, so there are no
third-party weights to vet -- which matters more than a couple of points of
accuracy on a machine whose owner's rule is to treat outside code as hostile.

ACCURACY, STATED PLAINLY. LBP histogram matching is decent at "is this the same
person in similar light" and mediocre under a big lighting or pose change. It
is appropriate for a greeting and for a second factor. It would not be
appropriate as a lock, which is the other reason it is not one. status()
reports the enrolled sample count and the measured margin rather than implying
a confidence it has not earned.

PRIVACY. No image is ever stored. Enrolment keeps histograms only -- a vector
of counts from which the face cannot be reconstructed. The camera is opened,
used and RELEASED for every single check: holding it open would block Zoom and
every other app, and would light the privacy indicator permanently.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

try:
    import numpy as np
except Exception:
    np = None
try:
    import cv2
except Exception:
    cv2 = None

# Auto-exposure. See the module docstring -- without this the camera looks dark
# and broken. Measured: frame 0 = 53/255, frame 10 = 127/255 on this hardware.
WARMUP_FRAMES = 12
CAMERA_INDEX = 0
FACE_SIZE = 100                 # normalised crop, px
GRID = 8                        # LBP cells per side -> GRID*GRID*256 features
ENROLL_SAMPLES = 12
# Chi-square distance below which two histograms are "the same person".
# Calibrated at enrolment against the spread of the user's own samples rather
# than hardcoded, because the right value depends on the camera and the room.
DEFAULT_THRESHOLD = 0.32
MIN_BRIGHTNESS = 35             # below this the frame is genuinely unusable

# ── liveness assessment (1.4.1) ─────────────────────────────────────────────
# The audit's honest gap: verify() compared histograms and never asked whether
# the frames behaved like a LIVE sensor. Two passive checks close the cheapest
# part of that gap, both pure and testable without a camera:
#
#   * TEMPORAL MICRO-MOTION. A living face moves between frames -- breathing,
#     sway, blinks -- and the crop's mean absolute inter-frame difference sits
#     well above what sensor noise alone produces. A printed photo or a frozen
#     frame produces noise-floor differences only. gesturewatch measured this
#     sensor's still-scene noise (max ~11 counts on scattered pixels, mean
#     ~0.3); MOTION_FLOOR sits above that and below real facial motion.
#   * SCREEN REPLAY. A phone/monitor recapture carries the display's refresh
#     structure -- periodic banding the eye dismisses but an FFT sees as sharp
#     high-frequency peaks. A directly-viewed face does not produce them.
#
# WHAT THIS DOES NOT CLAIM, stated because a liveness check that overclaims is
# worse than none: it RAISES the cost of a spoof, it does not prevent one. A
# photo wobbled on a stick defeats the temporal check (the crop moves); a
# high-quality print under diffuse light defeats the FFT check. The auth.py
# rule that face is never sufficient alone is what actually holds the line,
# and it is untouched. Off by default like every factor that adds failure
# modes to authentication (HELLO_ENABLED, TOKEN_ROTATE_SECONDS): enable with
# ARGUS_FACE_LIVENESS=1 once you have lived with the false-refusal rate.
LIVENESS_ON = os.environ.get("ARGUS_FACE_LIVENESS", "") == "1"
MOTION_FLOOR = 1.8              # mean-abs crop diff a live face exceeds
REPLAY_BAND_RATIO = 6.0         # FFT peak-to-median ratio that says "screen"

STORE_OVERRIDE = None           # tests point this at a temp file

_lock = threading.RLock()
_state = {
    "available": bool(cv2 is not None and np is not None),
    "last_error": "",
    "checks": 0,
    "matches": 0,
    "last_distance": None,
    "last_brightness": None,
}


# ── camera ───────────────────────────────────────────────────────────────────
def _cascade():
    path = os.path.join(cv2.data.haarcascades,
                        "haarcascade_frontalface_default.xml")
    c = cv2.CascadeClassifier(path)
    return None if c.empty() else c


def grab_frames(n: int = 1, warmup: int = WARMUP_FRAMES):
    """Open the camera, let exposure settle, return N frames, RELEASE it.

    The camera is never held between calls. That is deliberate: an assistant
    that keeps the webcam open blocks every video app on the machine and leaves
    the privacy light on, which is its own kind of hostile.
    """
    if not _state["available"]:
        return []
    cap = None
    try:
        cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW)
        if not cap.isOpened():
            _state["last_error"] = "camera did not open (in use by another app?)"
            return []
        for _ in range(max(0, warmup)):
            cap.read()
        out = []
        for _ in range(max(1, n)):
            ok, frame = cap.read()
            if ok and frame is not None:
                out.append(frame)
        if out:
            _state["last_brightness"] = float(out[-1].mean())
        return out
    except Exception as e:
        _state["last_error"] = f"capture: {type(e).__name__}"
        return []
    finally:
        try:
            if cap is not None:
                cap.release()
        except Exception:
            pass


def detect_face(frame):
    """The largest face in FRAME as a normalised, equalised grayscale crop."""
    casc = _cascade()
    if casc is None:
        _state["last_error"] = "no bundled cascade (opencv-python 5 removed them)"
        return None
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.equalizeHist(gray)
    faces = casc.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5,
                                  minSize=(70, 70))
    if len(faces) == 0:
        return None
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    crop = gray[y:y + h, x:x + w]
    crop = cv2.resize(crop, (FACE_SIZE, FACE_SIZE),
                      interpolation=cv2.INTER_AREA)
    return cv2.equalizeHist(crop)


# ── the descriptor: local binary patterns, computed here ────────────────────
def _smooth(img):
    """3x3 binomial blur, separable, in pure numpy.

    LOAD-BEARING, not a nicety. LBP encodes each pixel by comparing it with its
    eight neighbours, so a one-level sensor fluctuation flips bits: without this
    the descriptor measures NOISE rather than the face. Measured on synthetic
    faces: two views of the SAME person sat 0.43 apart, which was exactly as far
    as a different person -- the check could not tell anyone from anyone. A dim
    webcam like this one is the noisiest case there is, so this matters more
    here than it would on good hardware.
    """
    a = img.astype(np.float64)
    pad = np.pad(a, 1, mode="edge")
    cols = (pad[:, :-2] + 2.0 * pad[:, 1:-1] + pad[:, 2:]) / 4.0
    return (cols[:-2, :] + 2.0 * cols[1:-1, :] + cols[2:, :]) / 4.0


def lbp_histogram(face) -> "np.ndarray":
    """A GRID x GRID grid of 256-bin LBP histograms, L1-normalised.

    Pure numpy and pure function -- no camera, no state -- so the matching
    logic is testable on synthetic images without any hardware at all.
    """
    img = _smooth(face)
    c = img[1:-1, 1:-1]
    # The eight neighbours, each contributing one bit. Order is fixed; any
    # consistent order gives an equivalent descriptor.
    neigh = [img[:-2, :-2], img[:-2, 1:-1], img[:-2, 2:], img[1:-1, 2:],
             img[2:, 2:], img[2:, 1:-1], img[2:, :-2], img[1:-1, :-2]]
    code = np.zeros(c.shape, dtype=np.uint8)
    for bit, nb in enumerate(neigh):
        code |= ((nb >= c).astype(np.uint8) << bit)

    h, w = code.shape
    ch, cw = h // GRID, w // GRID
    hists = []
    for gy in range(GRID):
        for gx in range(GRID):
            cell = code[gy * ch:(gy + 1) * ch, gx * cw:(gx + 1) * cw]
            hist = np.bincount(cell.ravel(), minlength=256).astype(np.float64)
            s = hist.sum()
            hists.append(hist / s if s else hist)
    v = np.concatenate(hists)
    total = v.sum()
    return v / total if total else v


def distance(a, b) -> float:
    """Chi-square distance between two histograms. 0 = identical."""
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    denom = a + b
    mask = denom > 0
    return float(0.5 * np.sum(((a[mask] - b[mask]) ** 2) / denom[mask]))


# ── enrolment store (histograms only -- never an image) ─────────────────────
def _store_path():
    return STORE_OVERRIDE or paths.writable("face_enrollment.json")


def load_enrollment() -> dict:
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or not isinstance(d.get("samples"), list):
            return {}
        return d
    except (OSError, ValueError):
        return {}


def is_enrolled() -> bool:
    return bool(load_enrollment().get("samples"))


def forget() -> str:
    try:
        os.remove(_store_path())
        return "Face data deleted. I no longer recognise you by sight."
    except FileNotFoundError:
        return "There was no face data to delete."
    except OSError as e:
        return f"Couldn't delete the face data ({type(e).__name__})."


def enroll(samples: int = ENROLL_SAMPLES) -> str:
    """Capture SAMPLES views and store their histograms (never the images)."""
    if not _state["available"]:
        return ("Face recognition needs opencv-python and numpy, which aren't "
                "installed.")
    frames = grab_frames(n=samples, warmup=WARMUP_FRAMES)
    if not frames:
        return (f"I couldn't get a picture from the camera. "
                f"{_state['last_error'] or 'It may be in use by another app.'}")
    if (_state["last_brightness"] or 0) < MIN_BRIGHTNESS:
        return ("It's too dark for the camera to see you. Turn a light on and "
                "ask me to learn your face again.")

    hists = []
    for f in frames:
        face = detect_face(f)
        if face is not None:
            hists.append(lbp_histogram(face).tolist())
    if len(hists) < 3:
        return (f"I only got a clear look at you {len(hists)} time(s). Sit "
                f"square to the camera in decent light and ask me again.")

    # Calibrate the threshold from the spread of the user's OWN samples: the
    # distance a genuine match has to beat depends on this camera and this
    # room, and a hardcoded number would be wrong on both.
    #
    # The 75th PERCENTILE, not the maximum. Using max() lets a single bad
    # enrolment frame -- a blink, a turn, a shadow -- set the bar for every
    # future check, and a threshold widened that way admits other people.
    # Measured: with six genuinely different faces treated as one person's
    # enrolment, max() produced a threshold that accepted a stranger at 0.436.
    # A percentile ignores the outlier sample instead of being defined by it.
    arr = [np.asarray(h) for h in hists]
    spread = [distance(arr[i], arr[j])
              for i in range(len(arr)) for j in range(i + 1, len(arr))]
    typical = float(np.percentile(spread, 75)) if spread else DEFAULT_THRESHOLD
    # The multiplier is deliberately mean (1.05, not 1.3) and the ceiling hard.
    # The margin here is genuinely thin -- measured on this descriptor, two
    # views of one face sit ~0.29 apart and a different face ~0.32, so a
    # generous threshold swallows the gap entirely and admits strangers. The
    # two errors are not equal: a false REJECT costs a retry (and the PIN still
    # works), while a false ACCEPT is the failure this whole module is not
    # allowed to have. So it errs toward rejecting.
    threshold = min(max(typical * 1.05, 0.08), 0.30)

    try:
        with open(_store_path(), "w", encoding="utf-8") as fh:
            json.dump({"samples": hists, "threshold": threshold,
                       "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "note": "LBP histograms only -- no image is stored"},
                      fh)
    except OSError as e:
        return f"I couldn't save your face data ({type(e).__name__})."
    # If the calibration hit the ceiling, the enrolment views disagreed so much
    # that the threshold can no longer separate people. Say so: a check the user
    # believes in but which cannot discriminate is worse than one they know is
    # weak, and the fix (better light, sit still, re-enrol) is theirs to make.
    if threshold >= 0.30 - 1e-9:
        return (f"Learned your face from {len(hists)} views, but they varied a "
                f"lot — recognition will be unreliable and may not know you. "
                f"Re-run it in steadier light, facing the camera, for a better "
                f"result. Your PIN is unaffected either way.")
    return (f"Learned your face from {len(hists)} views. I'll use it to greet "
            f"you and as a second check — never instead of your PIN.")


# ── liveness ────────────────────────────────────────────────────────────────
def temporal_motion(crops: list) -> float:
    """Max mean-abs difference between CONSECUTIVE face crops, or 0.0.

    Pure. Crops are same-size grayscale/colour arrays; fewer than two crops or
    mismatched shapes (a face that appeared mid-sequence) score 0, which the
    caller treats as "cannot assess" rather than "live" -- fail-closed.
    """
    if np is None or not crops or len(crops) < 2:
        return 0.0
    worst = 0.0
    for a, b in zip(crops, crops[1:]):
        if a.shape != b.shape:
            continue
        try:
            d = float(np.abs(a.astype(np.float64) - b.astype(np.float64)).mean())
        except Exception:
            continue
        worst = max(worst, d)
    return worst


def replay_score(crop) -> float:
    """Peak-to-median ratio of the crop's high-passed FFT spectrum, or 0.0.

    Pure. A screen recapture shows refresh banding: a few FFT bins far above
    the surrounding spectrum. A face under diffuse light has a smooth falloff.
    The crop is high-passed first (a column difference kills the smooth
    lighting gradient) so the comparison is between the banding peak and the
    noise floor, not between banding and the face's own low-frequency mass.
    Deliberately crude -- a tripwire for a specific attack shape, not a
    general texture classifier.
    """
    if np is None or crop is None:
        return 0.0
    try:
        g = crop if crop.ndim == 2 else np.asarray(crop).mean(axis=2)
        g = np.asarray(g, dtype=np.float64)
        if g.shape[1] < 8 or g.shape[0] < 8:
            return 0.0
        d = np.diff(g, axis=1)                 # high-pass: kill the gradient
        spec = np.abs(np.fft.fft2(d - d.mean()))
        if spec.size == 0:
            return 0.0
        peak = float(spec.max())
        med = float(np.median(spec))
        # A PERFECTLY periodic recapture parks its whole spectrum in a few
        # bins and the median floor is exactly zero -- the strongest form of
        # this attack, which a naive peak/median guard scores as 0.0. Floor
        # the divisor instead: no floor -> an unmeasurable ratio; a real noisy
        # recapture is unaffected.
        return peak / max(med, 1e-9) if peak > 1e-9 else 0.0
    except Exception:
        return 0.0


def assess_liveness(crops: list) -> tuple:
    """(live, reason) for a sequence of face crops.

    Fail-closed on every uncertainty: too few frames, mismatched shapes, a
    numeric error -- all report (False, why) so a caller that opts into the
    assessment never mistakes a broken check for a passed one.
    """
    if not crops or len(crops) < 2:
        return False, "not enough frames to assess"
    motion = temporal_motion(crops)
    if motion < MOTION_FLOOR:
        return False, (f"face is static across frames (motion {motion:.2f} < "
                       f"{MOTION_FLOOR}) -- a photo or frozen image")
    replay = max(replay_score(c) for c in crops[-2:])
    if replay > REPLAY_BAND_RATIO:
        return False, (f"screen-replay banding detected (ratio {replay:.1f} > "
                       f"{REPLAY_BAND_RATIO})")
    return True, f"live (motion {motion:.2f}, replay ratio {replay:.1f})"


def _input_idle_seconds():
    """Seconds since the last keyboard/mouse input, or None if unknowable.

    The camera-independent presence signal the audit asked for: GetLastInputInfo
    needs no device, holds no handle, and cannot be contended by Zoom -- so it
    works exactly when the camera cannot.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        tick = ctypes.windll.kernel32.GetTickCount()
        idle_ms = (tick - info.dwTime) & 0xFFFFFFFF   # wrap-safe
        return idle_ms / 1000.0
    except Exception:
        return None


# ── the checks ───────────────────────────────────────────────────────────────
def present() -> bool:
    """Is ANY face in front of the camera? No identity, no spoof resistance
    needed -- faking presence gains an attacker nothing."""
    for f in grab_frames(n=3):
        if detect_face(f) is not None:
            return True
    return False


def verify(_supplied: str = "") -> bool:
    """auth.FACTORS entry point. True only if the enrolled face is seen NOW.

    Fails CLOSED on every uncertainty: no camera, no enrolment, too dark, no
    face, or a distance above the calibrated threshold. The signature takes the
    supplied secret and ignores it so this slots into auth.FACTORS unchanged --
    a face is not something you type.
    """
    with _lock:
        _state["checks"] += 1
    data = load_enrollment()
    samples = data.get("samples") or []
    if not samples or not _state["available"]:
        return False
    threshold = float(data.get("threshold") or DEFAULT_THRESHOLD)

    frames = grab_frames(n=4)
    if not frames:
        return False
    if (_state["last_brightness"] or 0) < MIN_BRIGHTNESS:
        _state["last_error"] = "too dark to see"
        return False

    enrolled = [np.asarray(s, dtype=np.float64) for s in samples]
    best = None
    crops = []
    for f in frames:
        face = detect_face(f)
        if face is None:
            continue
        crops.append(face)
        h = lbp_histogram(face)
        d = min(distance(h, e) for e in enrolled)
        best = d if best is None else min(best, d)
    with _lock:
        _state["last_distance"] = best
    if best is None:
        return False
    ok = best <= threshold
    if ok and LIVENESS_ON:
        # Identity matched, but a photograph of the owner matches too -- that
        # is the RGB-only ceiling this module was written under. When the
        # assessment is opted in, a face that does not BEHAVE like a face
        # refuses the factor. An assessment error refuses as well: fail-closed
        # is the only direction a check inside an authentication factor may
        # fail in.
        try:
            live, why = assess_liveness(crops)
        except Exception as e:
            live, why = False, f"liveness assessment error: {type(e).__name__}"
        with _lock:
            _state["last_liveness"] = why
        if not live:
            _state["last_error"] = f"liveness: {why}"
            return False
    if ok:
        with _lock:
            _state["matches"] += 1
    return ok


def recognise() -> tuple:
    """(recognised, message) for the greeting path. Never raises."""
    try:
        if not is_enrolled():
            return False, ("I don't know your face yet. Say 'learn my face' "
                           "and look at the camera.")
        if verify():
            return True, "Welcome back."
        b = _state.get("last_brightness")
        if b is not None and b < MIN_BRIGHTNESS:
            return False, "It's too dark for me to see who's there."
        if _state.get("last_distance") is None:
            return False, "I can't see a face at the camera."
        return False, "That doesn't look like you to me."
    except Exception as e:
        return False, f"The camera check failed ({type(e).__name__})."


# ── presence auto-lock ───────────────────────────────────────────────────────
# The one use of this camera that is a straight security GAIN. Spoofing
# "somebody is present" buys an attacker nothing -- the worst case is that ARGUS
# fails to lock, which is exactly today's behaviour -- so it needs none of the
# anti-spoofing the camera cannot provide.
PRESENCE_INTERVAL_S = 45
# Two consecutive misses, not one. A single miss is you reaching for a coffee or
# turning to speak to someone; locking on that would be the kind of "helpful"
# behaviour people switch off within a day.
PRESENCE_MISSES_TO_LOCK = 2
# No keyboard or mouse input for this long -> lock even when the camera cannot
# vouch (another app holds it). Matches the idle-lock cadence already documented
# in the security posture, so the two signals agree about what "walked away"
# means. Input within the window -> someone is there; the camera error alone
# still locks nothing, exactly as before.
PRESENCE_IDLE_LOCK_S = 300
_presence = {"on": False, "misses": 0, "thread": False, "last_seen": 0.0,
             "locks": 0}


def presence_enabled() -> bool:
    return bool(_presence["on"])


def set_presence(on: bool) -> str:
    _presence["on"] = bool(on)
    _presence["misses"] = 0
    if on and not is_enrolled():
        _presence["on"] = False
        return ("I need to learn your face first. Say 'learn my face' and look "
                "at the camera.")
    if on:
        _start_presence_thread()
        return (f"Watching. I'll lock ARGUS about "
                f"{PRESENCE_INTERVAL_S * PRESENCE_MISSES_TO_LOCK}s after you "
                f"leave the camera.")
    return "Stopped watching for you. The normal idle timer still applies."


def _presence_tick():
    """One check. Returns True if it locked. Never raises."""
    import auth
    if not _presence["on"] or not auth.is_unlocked():
        _presence["misses"] = 0
        return False
    try:
        seen = present()
    except Exception as e:
        # A camera failure still must not lock ON ITS OWN: the webcam being
        # busy is not evidence of anything. But since 1.4.1 it ORs with a
        # camera-independent signal: if the keyboard and mouse have been idle
        # for PRESENCE_IDLE_LOCK_S, nobody is using the machine regardless of
        # what the camera can or cannot see -- which is exactly the
        # walked-away-mid-video-call case where this feature used to go dark.
        # Input active -> the user is there -> never lock on a camera error.
        _state["last_error"] = f"presence: {type(e).__name__}"
        idle = _input_idle_seconds()
        if idle is not None and idle >= PRESENCE_IDLE_LOCK_S:
            _presence["misses"] = 0
            _presence["locks"] += 1
            auth.lock(f"camera unavailable and no input for {int(idle)}s")
            return True
        return False
    if seen:
        _presence["misses"] = 0
        _presence["last_seen"] = time.time()
        return False
    _presence["misses"] += 1
    if _presence["misses"] >= PRESENCE_MISSES_TO_LOCK:
        _presence["misses"] = 0
        _presence["locks"] += 1
        auth.lock("nobody at the camera")
        return True
    return False


def _presence_loop():
    while True:
        try:
            _presence_tick()
        except Exception as e:
            _state["last_error"] = f"presence loop: {type(e).__name__}"
        time.sleep(PRESENCE_INTERVAL_S)


def _start_presence_thread():
    with _lock:
        if _presence["thread"]:
            return
        _presence["thread"] = True
    threading.Thread(target=_presence_loop, daemon=True,
                     name="argus-face-presence").start()


def status() -> dict:
    data = load_enrollment()
    return {
        "available": _state["available"],
        "presence_watch": bool(_presence["on"]),
        "presence_locks": _presence["locks"],
        "presence_interval": PRESENCE_INTERVAL_S,
        "enrolled": bool(data.get("samples")),
        "samples": len(data.get("samples") or []),
        "threshold": data.get("threshold"),
        "checks": _state["checks"],
        "matches": _state["matches"],
        "last_distance": _state["last_distance"],
        "last_brightness": _state["last_brightness"],
        "liveness": ("on -- static/screen-replay assessment refuses the factor"
                     if LIVENESS_ON else
                     "off (ARGUS_FACE_LIVENESS=1 to enable)"),
        "liveness_last": _state.get("last_liveness", ""),
        "presence_idle_lock_s": PRESENCE_IDLE_LOCK_S,
        "camera": "RGB only, no infrared",
        "spoofable": ("harder than before -- a motionless photo or a screen "
                      "replay is refused when liveness is on; a photo moved in "
                      "hand is not, which is why this is never sufficient "
                      "alone"),
        "last_error": _state["last_error"],
    }
