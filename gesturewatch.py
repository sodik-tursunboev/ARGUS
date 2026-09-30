"""
ARGUS - Gesture control: wave at it.

WHAT THE HARDWARE ACTUALLY SUPPORTS, measured on this machine rather than
assumed from a demo video:

    camera            640x480 @ 30fps
    scene brightness  27/255 in this room at night (139 in daylight)
    motion noise      mean 0.34, max 11 on a still scene

That measurement is the whole design. Finger-pose tracking -- "hold up three
fingers" -- needs to SEE the hand: skin-tone segmentation, contour convexity,
or a trained model. At 27/255 there is not enough light to segment anything,
and the honest ceiling of that approach in this room is "sometimes". It would
also mean adding mediapipe (~100MB) to a locked dependency set.

Frame differencing measures CHANGE, not appearance, so darkness costs it
almost nothing -- and against a noise floor of 0.34 a real hand crossing the
frame is enormous. So the vocabulary is coarse MOTION: swipes and a held
palm. Fewer gestures, but ones that work in the room this actually runs in.

THE CAMERA IS NEVER HELD AMBIENTLY. faceauth states the rule and it applies
here with more force: an assistant that keeps the webcam open blocks every
video app on the machine and leaves the privacy light burning. Worse,
threatmon/privacy.py watches which processes use the camera -- an always-on
gesture watcher would make ARGUS the loudest entry in its own privacy report.
So this is ARMED, TIME-BOXED, and released on the way out, every time.

A GESTURE IS NOT AUTHENTICATION, and no amount of engineering can make it one.
Anyone standing in front of the camera can wave, exactly as anyone can be
seen -- which is why auth.py already classes face as presence-only and never
a key. Gestures are weaker still: no identity at all. So the action table
below contains only things that are harmless when a stranger does them, and
the asymmetry in it is deliberate:

    swipe left   -> mute the microphone      (privacy INCREASES)
    swipe right  -> nothing                  (unmuting must be a spoken,
                                              authenticated act)

A control that can only fail safe is a control a stranger cannot misuse.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

# ── tuning, all in NORMALISED units so resolution never matters ──────────────
PROC_W, PROC_H = 160, 120     # differencing runs here; 640x480 is wasted work
DIFF_THRESHOLD = 18           # per-pixel change counted as motion (noise max was 11)
MIN_MOTION_FRAC = 0.012       # a hand fills at least this much of the frame
MAX_MOTION_FRAC = 0.55        # more than this is the whole scene changing (a light
                              # switch, someone walking past) -- not a gesture
TRACK_WINDOW_S = 0.9          # how long a gesture may take
MIN_TRAVEL = 0.22             # fraction of frame width/height a swipe must cross
AXIS_RATIO = 1.8              # how much one axis must dominate to be a swipe
HOLD_MIN_S = 0.7              # a palm must be still this long to count as a hold
HOLD_MAX_TRAVEL = 0.10        # ...and must not wander further than this
DEBOUNCE_S = 1.2              # after a gesture, ignore everything briefly

ARM_SECONDS = 45.0            # how long a single arming lasts
IDLE_RELEASE_S = 20.0         # nothing seen for this long -> give the camera back
FRAME_SLEEP_S = 0.03

# ── what a gesture may do ────────────────────────────────────────────────────
# Every entry must be safe for an UNKNOWN PERSON to trigger, because that is
# exactly who might. Nothing here reveals information, changes security state
# in a loosening direction, spends money, or touches a file.
GESTURE_ACTIONS = {
    "palm_hold": "silence",     # stop ARGUS talking -- the universal "stop"
    "swipe_down": "dismiss",    # clear the intel overlay
    "swipe_left": "mute",       # microphone off: strictly more private
    "swipe_right": None,        # deliberately nothing. See the module docstring.
    "swipe_up": None,
}

_lock = threading.RLock()
_state = {
    "armed": False,
    "until": 0.0,
    "thread": None,
    "last_gesture": "",
    "last_at": 0.0,
    "count": 0,
    "last_error": "",
    "recent": [],               # (name, epoch) for the HUD
}


def available() -> bool:
    """True when the camera stack can be used at all."""
    try:
        import cv2  # noqa: F401
    except Exception:
        return False
    try:
        import faceauth
        return bool(faceauth._state.get("available", True))
    except Exception:
        return True


# ── detection ────────────────────────────────────────────────────────────────
def _prep(frame):
    """Grayscale, downscaled, blurred. Blur matters: without it, sensor noise
    in a dark frame survives thresholding as a scatter of specks and the
    centroid jumps around the frame instead of tracking a hand."""
    import cv2

    small = cv2.resize(frame, (PROC_W, PROC_H), interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    return cv2.GaussianBlur(gray, (5, 5), 0)


def _motion(prev, cur):
    """(fraction_moving, (cx, cy)) in normalised coords, or (0, None)."""
    import cv2
    import numpy as np

    diff = cv2.absdiff(prev, cur)
    _, mask = cv2.threshold(diff, DIFF_THRESHOLD, 255, cv2.THRESH_BINARY)
    moving = int(np.count_nonzero(mask))
    frac = moving / float(PROC_W * PROC_H)
    if frac < MIN_MOTION_FRAC or frac > MAX_MOTION_FRAC:
        return frac, None
    ys, xs = np.nonzero(mask)
    return frac, (float(xs.mean()) / PROC_W, float(ys.mean()) / PROC_H)


def classify(track: list) -> str:
    """A path of (t, x, y) points -> a gesture name, or "".

    Pure and side-effect free so it can be tested without a camera, which is
    the only way to test the thresholds honestly.
    """
    if len(track) < 4:
        return ""
    t0, t1 = track[0][0], track[-1][0]
    if t1 - t0 > TRACK_WINDOW_S:
        return ""
    xs = [p[1] for p in track]
    ys = [p[2] for p in track]
    dx, dy = xs[-1] - xs[0], ys[-1] - ys[0]
    spread = max(max(xs) - min(xs), max(ys) - min(ys))

    # A hold first: it is the absence of travel, so checking it after the
    # swipe tests would let a jittery hold register as a tiny swipe.
    if (t1 - t0) >= HOLD_MIN_S and spread <= HOLD_MAX_TRAVEL:
        return "palm_hold"

    if abs(dx) >= MIN_TRAVEL and abs(dx) >= AXIS_RATIO * abs(dy):
        return "swipe_right" if dx > 0 else "swipe_left"
    if abs(dy) >= MIN_TRAVEL and abs(dy) >= AXIS_RATIO * abs(dx):
        return "swipe_down" if dy > 0 else "swipe_up"
    return ""


# ── acting on one ────────────────────────────────────────────────────────────
def _do_silence() -> str:
    import tts
    tts.stop()
    return "stopped speaking"


def _do_dismiss() -> str:
    from skills import intel_skill
    intel_skill.clear()
    return "dismissed the panel"


def _do_mute() -> str:
    """Privacy mode ON. There is deliberately no gesture that turns it OFF.

    enable(), never disable(): muting is the fail-safe direction, so a
    stranger triggering it costs nothing. Unmuting reopens the microphone,
    which is a loosening of privacy and therefore has to be a spoken,
    authenticated act -- see GESTURE_ACTIONS, where swipe_right is bound to
    nothing on purpose.
    """
    from skills import privacy_skill
    privacy_skill.enable()
    return "microphone muted"


_ACTIONS = {"silence": _do_silence, "dismiss": _do_dismiss, "mute": _do_mute}


def perform(gesture: str) -> str:
    """Run the action bound to GESTURE. Returns what happened, or "".

    The binding is looked up in GESTURE_ACTIONS and nowhere else. A gesture
    with no binding does nothing at all -- it is not passed on to a model, a
    router, or anything else that might find a use for it.
    """
    action = GESTURE_ACTIONS.get(gesture)
    if not action:
        return ""
    fn = _ACTIONS.get(action)
    if fn is None:
        return ""
    try:
        did = fn()
    except Exception as e:
        with _lock:
            _state["last_error"] = f"{type(e).__name__}: {str(e)[:60]}"
        return ""
    try:
        import security
        security.audit("gesture", f"{gesture} -> {action}", "ok")
    except Exception:
        pass
    return did


def _record(gesture: str):
    now = time.time()
    with _lock:
        _state["last_gesture"] = gesture
        _state["last_at"] = now
        _state["count"] += 1
        _state["recent"] = (_state["recent"] + [(gesture, now)])[-10:]


# ── the armed window ─────────────────────────────────────────────────────────
def _watch(until: float):
    """Hold the camera for one armed window, then give it back. Never raises."""
    import cv2

    import faceauth

    cap = None
    try:
        cap = cv2.VideoCapture(faceauth.CAMERA_INDEX, cv2.CAP_DSHOW)
        if not cap.isOpened():
            with _lock:
                _state["last_error"] = "camera did not open (in use?)"
            return
        for _ in range(faceauth.WARMUP_FRAMES):
            cap.read()          # this sensor ramps exposure; measured

        prev = None
        track = []
        last_seen = time.time()
        blocked_until = 0.0

        while True:
            with _lock:
                if not _state["armed"] or time.time() > _state["until"]:
                    return
            if time.time() - last_seen > IDLE_RELEASE_S:
                # Nobody is gesturing. Giving the camera back matters more
                # than staying ready -- see the module docstring.
                return

            ok, frame = cap.read()
            if not ok or frame is None:
                time.sleep(FRAME_SLEEP_S)
                continue
            cur = _prep(frame)
            if prev is None:
                prev = cur
                continue

            now = time.time()
            frac, centre = _motion(prev, cur)
            prev = cur

            if now < blocked_until:
                track = []
                continue

            if centre is None:
                if track:
                    g = classify(track)
                    if g:
                        _record(g)
                        perform(g)
                        blocked_until = now + DEBOUNCE_S
                    track = []
                time.sleep(FRAME_SLEEP_S)
                continue

            last_seen = now
            track.append((now, centre[0], centre[1]))
            # Trim to the window so a slow drift across a minute is never
            # mistaken for one fast swipe.
            track = [p for p in track if now - p[0] <= TRACK_WINDOW_S]

            g = classify(track)
            if g:
                _record(g)
                perform(g)
                blocked_until = now + DEBOUNCE_S
                track = []
    except Exception as e:
        with _lock:
            _state["last_error"] = f"{type(e).__name__}: {str(e)[:70]}"
    finally:
        try:
            if cap is not None:
                cap.release()
        except Exception:
            pass
        with _lock:
            _state["armed"] = False
            _state["thread"] = None


def arm(seconds: float = ARM_SECONDS) -> str:
    """Watch for gestures for a bounded window, then release the camera."""
    if not available():
        return "I can't use the camera right now."
    with _lock:
        if _state["armed"]:
            _state["until"] = time.time() + seconds     # extend, don't stack
            return f"Still watching — {int(seconds)} more seconds."
        _state["armed"] = True
        _state["until"] = time.time() + seconds
        t = threading.Thread(target=_watch, args=(_state["until"],),
                             name="gesture-watch", daemon=True)
        _state["thread"] = t
    t.start()
    return (f"Watching for gestures for {int(seconds)} seconds. "
            f"Open palm to stop me talking, swipe down to clear the panel, "
            f"swipe left to mute the microphone.")


def disarm() -> str:
    with _lock:
        was = _state["armed"]
        _state["armed"] = False
    return "Camera released." if was else "I wasn't watching."


def status() -> dict:
    now = time.time()
    with _lock:
        armed = _state["armed"]
        return {
            "skill": "gesture",
            "available": available(),
            "armed": armed,
            "seconds_left": max(0, int(_state["until"] - now)) if armed else 0,
            "gestures_seen": _state["count"],
            "last_gesture": _state["last_gesture"],
            "last_error": _state["last_error"],
            # Stated in status because it is a security property, not a
            # detail: a gesture can never authenticate anything.
            "can_authenticate": False,
            "holds_camera_when_idle": False,
        }
