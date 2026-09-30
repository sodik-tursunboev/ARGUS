"""Render an isometric contact sheet of the generated city assets.

This exists so the asset build can be REVIEWED, not just trusted. Running the
exporter and reading "tris=7288" tells you nothing about whether a building
looks like a building. Renders go to tools/blender/preview/.

    blender --background --python tools/blender/render_preview.py -- buildings
    blender --background --python tools/blender/render_preview.py -- robot
"""

import bpy
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus_kit import reset_scene, new_collection, get_material  # noqa: E402

PREVIEW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "preview")


def _pick_engine():
    """Blender renamed EEVEE across releases; use whatever this build has."""
    for name in ("BLENDER_EEVEE_NEXT", "BLENDER_EEVEE", "BLENDER_WORKBENCH"):
        try:
            bpy.context.scene.render.engine = name
            return name
        except TypeError:
            continue
    return bpy.context.scene.render.engine


def setup_night_scene(width=1920, height=1080):
    scene = bpy.context.scene
    engine = _pick_engine()
    scene.render.resolution_x = width
    scene.render.resolution_y = height
    scene.render.resolution_percentage = 100
    scene.render.film_transparent = False
    if hasattr(scene, "eevee"):
        for attr, val in (("taa_render_samples", 24), ("use_bloom", True), ("bloom_intensity", 0.03)):
            if hasattr(scene.eevee, attr):
                setattr(scene.eevee, attr, val)

    # Deep navy world, matching the runtime's night art direction.
    world = bpy.data.worlds.new("preview_world")
    scene.world = world
    world.use_nodes = True
    bg = world.node_tree.nodes.get("Background")
    if bg:
        bg.inputs[0].default_value = (0.012, 0.018, 0.035, 1.0)
        bg.inputs[1].default_value = 0.6

    # Moonlight key + cool fill, the same two-light read the runtime uses.
    key_data = bpy.data.lights.new("key", type="SUN")
    key_data.energy = 3.4
    key_data.color = (0.78, 0.84, 1.0)
    key = bpy.data.objects.new("key", key_data)
    key.rotation_euler = (math.radians(52), 0, math.radians(38))
    scene.collection.objects.link(key)

    fill_data = bpy.data.lights.new("fill", type="SUN")
    fill_data.energy = 1.3
    fill_data.color = (0.25, 0.68, 1.0)
    fill = bpy.data.objects.new("fill", fill_data)
    fill.rotation_euler = (math.radians(62), 0, math.radians(-135))
    scene.collection.objects.link(fill)
    return engine


def add_iso_camera(target, ortho_scale):
    """The same 45deg-yaw / ~38deg-pitch orthographic rig the runtime uses, so
    a preview render predicts what the city will actually look like."""
    cam_data = bpy.data.cameras.new("iso")
    cam_data.type = "ORTHO"
    cam_data.ortho_scale = ortho_scale
    cam = bpy.data.objects.new("iso", cam_data)
    bpy.context.scene.collection.objects.link(cam)
    bpy.context.scene.camera = cam

    dist = ortho_scale * 3.0
    yaw = math.radians(45)
    pitch = math.radians(38)
    cam.location = (
        target[0] + math.cos(pitch) * math.sin(yaw) * dist,
        target[1] - math.cos(pitch) * math.cos(yaw) * dist,
        target[2] + math.sin(pitch) * dist,
    )
    cam.rotation_euler = (math.pi / 2 - pitch, 0, yaw)
    return cam


def ground_plane(size=400):
    mesh = bpy.data.meshes.new("ground")
    import bmesh
    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=size / 2)
    bm.to_mesh(mesh)
    bm.free()
    mesh.materials.append(get_material("ARGUS_Asphalt"))
    obj = bpy.data.objects.new("ground", mesh)
    bpy.context.scene.collection.objects.link(obj)
    return obj


def render_to(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    bpy.context.scene.render.filepath = path
    bpy.context.scene.render.image_settings.file_format = "PNG"
    bpy.ops.render.render(write_still=True)
    print("RENDERED %s" % path)


def preview_buildings():
    import build_buildings as bb

    reset_scene()
    setup_night_scene(2200, 1300)
    ground_plane(600)
    col = new_collection("sheet")

    # Lay every building out on a grid, tallest rows at the back.
    entries = bb.BUILDINGS
    cols = 6
    spacing = 46.0
    for i, (name, fn, kind, family) in enumerate(entries):
        gx = (i % cols - (cols - 1) / 2) * spacing
        gy = ((i // cols) - (len(entries) / cols - 1) / 2) * spacing
        builder = fn()
        objs = builder.emit(col)
        for o in objs:
            o.location = (gx, gy, 0)

    add_iso_camera((0, 0, 8), ortho_scale=spacing * cols * 0.92)
    render_to(os.path.join(PREVIEW_DIR, "buildings_sheet.png"))


def _screen_row(i, count, spacing):
    """At a 45-degree camera yaw, screen-horizontal is the world (1,1)
    diagonal -- laying assets out along world X alone walks them straight off
    the side of the frame."""
    t = (i - (count - 1) / 2) * spacing / math.sqrt(2)
    return (t, t)


def preview_hero():
    """Close-up of the hero buildings, where façade detail has to hold up."""
    import build_buildings as bb

    heroes = ["core_tower", "agent_hq", "academy", "verification_institute",
              "security_command", "model_compute"]
    lookup = {n: fn for n, fn, _k, _f in bb.BUILDINGS}
    reset_scene()
    setup_night_scene(2400, 1000)
    ground_plane(500)
    col = new_collection("hero")
    for i, name in enumerate(heroes):
        gx, gy = _screen_row(i, len(heroes), 44.0)
        objs = lookup[name]().emit(col)
        for o in objs:
            o.location = (gx, gy, 0)
    add_iso_camera((0, 0, 16), ortho_scale=44.0 * len(heroes) * 0.56)
    render_to(os.path.join(PREVIEW_DIR, "hero_sheet.png"))


def preview_robot():
    """One robot per pose, plus a door for scale -- a robot that looks fine in
    rest pose can still read wrong mid-stride, so the poses get reviewed too."""
    import build_robot as br
    import bmesh
    from argus_kit import Builder, DOOR_H

    poses = ["IDLE", "WALK", "WORK_AT_DESK", "THINK", "STUDY", "VERIFY"]
    frames = {"WALK": 7, "TYPE": 5}

    reset_scene()
    setup_night_scene(2200, 900)
    ground_plane(40)
    col = new_collection("robot")

    for i, clip in enumerate(poses):
        gx, gy = _screen_row(i, len(poses), 2.4)
        arm, meshes = br.build_robot_scene(col)
        bpy.context.view_layer.objects.active = arm
        bpy.ops.object.mode_set(mode="POSE")
        rot_keys, loc_keys = dict((n, fn) for n, _l, _lo, fn in br.CLIPS)[clip]()
        br.reset_pose(arm)
        # Apply the clip's pose at a representative frame directly.
        target = frames.get(clip, 1)
        for bone_name, kf in rot_keys.items():
            pb = arm.pose.bones.get(bone_name)
            if pb is None:
                continue
            pb.rotation_mode = "XYZ"
            pb.rotation_euler = _sample(kf, target)
        for bone_name, kf in loc_keys.items():
            pb = arm.pose.bones.get(bone_name)
            if pb:
                pb.location = _sample(kf, target)
        bpy.ops.object.mode_set(mode="OBJECT")
        for o in [arm] + meshes:
            o.location = (gx, gy, 0)

    # A door frame at real scale, so the robot's height can be judged.
    b = Builder("scale_ref")
    dx, dy = _screen_row(len(poses), len(poses) + 1, 2.4)
    b.m("ARGUS_Concrete").box(0, 0, 1.45, 2.4, 0.4, 2.9, bevel=0.03)
    b.m("ARGUS_WarmGlass").box(0, -0.12, DOOR_H / 2, 1.5, 0.2, DOOR_H)
    for o in b.emit(col):
        o.location = (dx + 1.2, dy + 1.2, 0)

    add_iso_camera((0, 0, 0.95), ortho_scale=10.5)
    render_to(os.path.join(PREVIEW_DIR, "robot_sheet.png"))


def _sample(keyframes, frame):
    """Linear sample of a keyframe list at `frame` -- good enough to preview a
    pose without running Blender's evaluator."""
    keyframes = sorted(keyframes)
    if frame <= keyframes[0][0]:
        return keyframes[0][1]
    if frame >= keyframes[-1][0]:
        return keyframes[-1][1]
    for (f0, v0), (f1, v1) in zip(keyframes, keyframes[1:]):
        if f0 <= frame <= f1:
            t = (frame - f0) / max(1e-6, (f1 - f0))
            return tuple(a + (b - a) * t for a, b in zip(v0, v1))
    return keyframes[0][1]


def preview_interiors():
    import build_interiors as bi

    reset_scene()
    setup_night_scene(2000, 1100)
    col = new_collection("interiors")
    for i, (name, fn) in enumerate(bi.INTERIORS):
        gx = (i - (len(bi.INTERIORS) - 1) / 2) * 62.0
        objs = fn().emit(col)
        for o in objs:
            o.location = (gx, 0, 0)
    add_iso_camera((0, 0, 2), ortho_scale=64.0 * len(bi.INTERIORS) * 0.58)
    render_to(os.path.join(PREVIEW_DIR, "interiors_sheet.png"))


def preview_props():
    import build_props as bp

    reset_scene()
    setup_night_scene(1800, 700)
    ground_plane(120)
    col = new_collection("props")
    names = [n for n, _fn in bp.PROPS]
    lookup = dict(bp.PROPS)
    for i, name in enumerate(names):
        gx = (i % 10 - 4.5) * 5.0
        gy = (i // 10 - 0.5) * 5.0
        objs = lookup[name]().emit(col)
        for o in objs:
            o.location = (gx, gy, 0)
    add_iso_camera((0, 0, 1.4), ortho_scale=54.0)
    render_to(os.path.join(PREVIEW_DIR, "props_sheet.png"))


TARGETS = {
    "buildings": preview_buildings,
    "hero": preview_hero,
    "robot": preview_robot,
    "interiors": preview_interiors,
    "props": preview_props,
}

if __name__ == "__main__":
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else ["buildings"]
    for target in argv:
        fn = TARGETS.get(target)
        if fn is None:
            print("unknown preview target: %s" % target)
            continue
        fn()
