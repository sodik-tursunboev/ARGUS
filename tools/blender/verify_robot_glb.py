"""Import the EXPORTED robot GLB back into Blender and render real animation
frames from it.

This is the honest test. Posing a rig by hand in the authoring scene proves
nothing about the artifact three.js will actually load: the export path bakes
actions, converts Y-up, and rebuilds the skin. Rendering the re-imported GLB
exercises exactly what ships.

    blender --background --python tools/blender/verify_robot_glb.py
"""

import bpy
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus_kit import ASSET_ROOT  # noqa: E402
from render_preview import setup_night_scene, add_iso_camera, ground_plane, render_to, PREVIEW_DIR  # noqa: E402

GLB = os.path.join(ASSET_ROOT, "robots", "argus_robot.glb")

# clip -> frame to sample. Mid-stride for WALK, settled for the static poses.
SHOTS = [("IDLE", 20), ("WALK", 7), ("WALK", 19), ("WORK_AT_DESK", 30),
         ("THINK", 40), ("STUDY", 60), ("VERIFY", 30), ("READ", 60)]


def import_robot():
    before = set(bpy.data.objects)
    bpy.ops.import_scene.gltf(filepath=GLB)
    return [o for o in bpy.data.objects if o not in before]


def find_armature(objs):
    for o in objs:
        if o.type == "ARMATURE":
            return o
    return None


def main():
    bpy.ops.wm.read_factory_settings(use_empty=True)
    setup_night_scene(2400, 820)
    ground_plane(60)

    for i, (clip, frame) in enumerate(SHOTS):
        objs = import_robot()
        arm = find_armature(objs)
        if arm is None:
            print("NO ARMATURE in import")
            continue
        action = bpy.data.actions.get(clip)
        if action is None:
            # Re-imported actions get suffixed (.001, .002...) per import.
            cands = sorted(a.name for a in bpy.data.actions if a.name.startswith(clip))
            action = bpy.data.actions.get(cands[-1]) if cands else None
        if action is None:
            print("MISSING ACTION %s" % clip)
        else:
            if not arm.animation_data:
                arm.animation_data_create()
            _assign_action(arm, action)

        t = (i - (len(SHOTS) - 1) / 2) * 2.3 / math.sqrt(2)
        for o in objs:
            if o.parent is None:
                o.location = (t, t, 0)

    add_iso_camera((0, 0, 0.95), ortho_scale=11.0)
    # Every clip has data at both of these frames, so two renders show the
    # whole line-up in two different moments of its own animation.
    for frame in (7, 20):
        bpy.context.scene.frame_set(frame)
        render_to(os.path.join(PREVIEW_DIR, "robot_glb_f%02d.png" % frame))


def _assign_action(arm, action):
    """Assigning an Action in Blender 4.4+ also needs a slot bound, or the
    action evaluates to nothing."""
    arm.animation_data.action = action
    slots = getattr(action, "slots", None)
    if slots:
        try:
            arm.animation_data.action_slot = slots[0]
        except (AttributeError, TypeError):
            pass


if __name__ == "__main__":
    main()
