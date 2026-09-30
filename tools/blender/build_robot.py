"""ARGUS AI City -- the mini ARGUS robot.

A small professional service/intelligence unit: angular helmet with a thin
cyan visor line, armoured chassis with a core light, a compute pack on its
back, two-segment arms ending in a gripper, two-segment legs on compact feet.
Roughly 1.75 units tall, so it stands correctly against a 2.3-unit door.

Rigged with a real armature (18 bones) and RIGIDLY skinned -- every vertex is
weighted 1.0 to exactly one bone. That is the right rig for hard-surface
robot parts: no deformation artefacts, no weight painting, and it exports to
glTF as a normal skinned mesh that three.js AnimationMixer can drive.

Orientation: the robot faces Blender -Y, which the glTF Y-up conversion turns
into +Z -- the direction the runtime's `atan2(dx, dz)` heading assumes, and
the same way every building's entrance faces.
"""

import bmesh
import bpy
import math
import os
import sys
from mathutils import Vector, Matrix

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus_kit import (  # noqa: E402
    ROBOT_H, export_glb, get_material, new_collection, reset_scene,
)

# --------------------------------------------------------------------------
# Skeleton
# --------------------------------------------------------------------------

# name: (head, tail, parent). Z-up, robot facing -Y.
BONES = [
    ("root",        (0.00, 0.00, 0.00), (0.00, -0.14, 0.00), None),
    ("pelvis",      (0.00, 0.00, 0.78), (0.00, 0.00, 0.94), "root"),
    ("chest",       (0.00, 0.00, 0.94), (0.00, 0.00, 1.30), "pelvis"),
    ("head",        (0.00, 0.00, 1.34), (0.00, 0.00, 1.74), "chest"),

    ("shoulder.L",  (0.10, 0.00, 1.24), (0.27, 0.00, 1.24), "chest"),
    ("upperarm.L",  (0.27, 0.00, 1.22), (0.27, 0.00, 0.94), "shoulder.L"),
    ("forearm.L",   (0.27, 0.00, 0.94), (0.27, 0.00, 0.69), "upperarm.L"),
    ("hand.L",      (0.27, 0.00, 0.69), (0.27, 0.00, 0.56), "forearm.L"),

    ("shoulder.R",  (-0.10, 0.00, 1.24), (-0.27, 0.00, 1.24), "chest"),
    ("upperarm.R",  (-0.27, 0.00, 1.22), (-0.27, 0.00, 0.94), "shoulder.R"),
    ("forearm.R",   (-0.27, 0.00, 0.94), (-0.27, 0.00, 0.69), "upperarm.R"),
    ("hand.R",      (-0.27, 0.00, 0.69), (-0.27, 0.00, 0.56), "forearm.R"),

    ("thigh.L",     (0.12, 0.00, 0.76), (0.12, 0.00, 0.40), "pelvis"),
    ("shin.L",      (0.12, 0.00, 0.40), (0.12, 0.00, 0.08), "thigh.L"),
    ("foot.L",      (0.12, 0.00, 0.08), (0.12, -0.18, 0.05), "shin.L"),

    ("thigh.R",     (-0.12, 0.00, 0.76), (-0.12, 0.00, 0.40), "pelvis"),
    ("shin.R",      (-0.12, 0.00, 0.40), (-0.12, 0.00, 0.08), "thigh.R"),
    ("foot.R",      (-0.12, 0.00, 0.08), (-0.12, -0.18, 0.05), "shin.R"),
]


def build_armature(collection):
    arm_data = bpy.data.armatures.new("ARGUSRobotRig")
    arm_obj = bpy.data.objects.new("ARGUSRobotRig", arm_data)
    collection.objects.link(arm_obj)
    bpy.context.view_layer.objects.active = arm_obj
    bpy.ops.object.mode_set(mode="EDIT")
    created = {}
    for name, head, tail, parent in BONES:
        eb = arm_data.edit_bones.new(name)
        eb.head = Vector(head)
        eb.tail = Vector(tail)
        eb.use_connect = False
        created[name] = eb
        if parent:
            eb.parent = created[parent]
    bpy.ops.object.mode_set(mode="OBJECT")
    return arm_obj


# --------------------------------------------------------------------------
# Rigidly-skinned mesh builder
# --------------------------------------------------------------------------

class RiggedBuilder:
    """Accumulates boxes tagged with the bone that owns them, then emits one
    mesh per material with a vertex group per bone (weight 1.0). Merging by
    material is what keeps a robot at ~4 draw calls instead of ~20."""

    def __init__(self):
        self._by_material = {}      # material -> list[(bone, bmesh)]
        self._order = []

    def box(self, bone, material, cx, cy, cz, sx, sy, sz, bevel=0.012, rot=None):
        bm = bmesh.new()
        bmesh.ops.create_cube(bm, size=1.0)
        bmesh.ops.scale(bm, vec=Vector((sx, sy, sz)), verts=bm.verts)
        if bevel > 0:
            bmesh.ops.bevel(bm, geom=list(bm.verts) + list(bm.edges), offset=bevel,
                            segments=1, affect="EDGES", clamp_overlap=True)
        if rot is not None:
            bmesh.ops.rotate(bm, verts=bm.verts, cent=Vector((0, 0, 0)),
                             matrix=Matrix.Rotation(rot[1], 3, "X") if rot[0] == "X"
                             else Matrix.Rotation(rot[1], 3, rot[0]))
        bmesh.ops.translate(bm, vec=Vector((cx, cy, cz)), verts=bm.verts)
        if material not in self._by_material:
            self._by_material[material] = []
            self._order.append(material)
        self._by_material[material].append((bone, bm))
        return self

    def cyl(self, bone, material, cx, cy, cz, r, h, segs=8, axis="Z"):
        bm = bmesh.new()
        bmesh.ops.create_cone(bm, cap_ends=True, cap_tris=False, segments=segs,
                              radius1=r, radius2=r, depth=h)
        if axis != "Z":
            bmesh.ops.rotate(bm, verts=bm.verts, cent=Vector((0, 0, 0)),
                             matrix=Matrix.Rotation(math.pi / 2, 3, "X" if axis == "Y" else "Y"))
        bmesh.ops.translate(bm, vec=Vector((cx, cy, cz)), verts=bm.verts)
        if material not in self._by_material:
            self._by_material[material] = []
            self._order.append(material)
        self._by_material[material].append((bone, bm))
        return self

    def emit(self, name, collection, armature):
        objs = []
        for material in self._order:
            chunks = self._by_material[material]
            merged = bmesh.new()
            spans = []          # (bone, first_index, count)
            for bone, bm in chunks:
                start = len(merged.verts)
                scratch = bpy.data.meshes.new("__rb")
                bm.to_mesh(scratch)
                merged.from_mesh(scratch)
                bpy.data.meshes.remove(scratch)
                bm.free()
                merged.verts.ensure_lookup_table()
                spans.append((bone, start, len(merged.verts) - start))

            mesh = bpy.data.meshes.new("%s_%s" % (name, material.replace("ARGUS_", "")))
            merged.normal_update()
            merged.to_mesh(mesh)
            merged.free()
            mesh.materials.append(get_material(material))
            for poly in mesh.polygons:
                poly.use_smooth = False

            obj = bpy.data.objects.new(mesh.name, mesh)
            collection.objects.link(obj)

            # Rigid skin: each span of vertices belongs entirely to one bone.
            for bone, start, count in spans:
                vg = obj.vertex_groups.get(bone) or obj.vertex_groups.new(name=bone)
                vg.add(list(range(start, start + count)), 1.0, "REPLACE")

            obj.parent = armature
            mod = obj.modifiers.new("Armature", "ARMATURE")
            mod.object = armature
            objs.append(obj)
        return objs


# --------------------------------------------------------------------------
# The robot mesh
# --------------------------------------------------------------------------

BODY = "ARGUS_RobotBody"
JOINT = "ARGUS_RobotJoint"
PLATE = "ARGUS_RobotPlate"
VISOR = "ARGUS_Visor"


def build_robot_mesh(rb):
    # ---- pelvis -----------------------------------------------------------
    rb.box("pelvis", JOINT, 0, 0, 0.83, 0.34, 0.24, 0.16)
    rb.box("pelvis", PLATE, 0, -0.015, 0.90, 0.40, 0.27, 0.07)

    # ---- chest: an armoured chassis, wider at the shoulders ---------------
    rb.box("chest", BODY, 0, 0, 1.10, 0.44, 0.28, 0.34)
    rb.box("chest", PLATE, 0, -0.155, 1.14, 0.34, 0.06, 0.24)      # breastplate
    rb.box("chest", PLATE, 0, 0, 1.28, 0.50, 0.30, 0.09)           # collar
    rb.box("chest", JOINT, 0, 0, 0.96, 0.36, 0.24, 0.07)           # waist ring
    # The ARGUS core light: a small recessed chevron, the only lit part of the
    # torso. Role colour is applied to this material at runtime.
    rb.box("chest", JOINT, 0, -0.175, 1.14, 0.15, 0.03, 0.15)
    rb.box("chest", VISOR, 0, -0.192, 1.14, 0.10, 0.02, 0.10)
    # Back compute/battery pack.
    rb.box("chest", PLATE, 0, 0.175, 1.12, 0.30, 0.10, 0.26)
    rb.box("chest", JOINT, 0, 0.235, 1.12, 0.22, 0.03, 0.18)
    for sx in (-1, 1):
        rb.box("chest", VISOR, sx * 0.085, 0.245, 1.19, 0.035, 0.015, 0.035)

    # ---- head: angular helmet + a single thin visor line ------------------
    rb.box("head", PLATE, 0, 0, 1.52, 0.29, 0.26, 0.22)            # skull
    rb.box("head", PLATE, 0, -0.02, 1.66, 0.25, 0.22, 0.07)        # crown
    rb.box("head", JOINT, 0, -0.125, 1.52, 0.26, 0.05, 0.15)       # visor recess
    rb.box("head", VISOR, 0, -0.152, 1.53, 0.215, 0.02, 0.045)     # visor line
    for sx in (-1, 1):                                             # ear units
        rb.box("head", JOINT, sx * 0.152, 0.01, 1.50, 0.035, 0.11, 0.10)
    rb.box("head", JOINT, 0, 0, 1.36, 0.14, 0.14, 0.07)            # neck

    # ---- arms -------------------------------------------------------------
    for side, sx in (("L", 1), ("R", -1)):
        rb.box("shoulder.%s" % side, PLATE, sx * 0.255, 0, 1.245, 0.14, 0.24, 0.20)
        rb.box("upperarm.%s" % side, BODY, sx * 0.27, 0, 1.08, 0.105, 0.115, 0.28)
        rb.box("upperarm.%s" % side, JOINT, sx * 0.27, 0, 0.945, 0.095, 0.105, 0.06)
        rb.box("forearm.%s" % side, BODY, sx * 0.27, 0, 0.815, 0.095, 0.105, 0.25)
        rb.box("forearm.%s" % side, PLATE, sx * 0.295, 0, 0.83, 0.05, 0.09, 0.18)
        # Gripper: two short fingers, enough to read as a hand at this scale.
        rb.box("hand.%s" % side, JOINT, sx * 0.27, 0, 0.665, 0.09, 0.10, 0.07)
        for fy in (-0.035, 0.035):
            rb.box("hand.%s" % side, PLATE, sx * 0.27, fy, 0.60, 0.07, 0.03, 0.08)

    # ---- legs -------------------------------------------------------------
    for side, sx in (("L", 1), ("R", -1)):
        rb.box("thigh.%s" % side, BODY, sx * 0.12, 0, 0.58, 0.155, 0.165, 0.36)
        rb.box("thigh.%s" % side, PLATE, sx * 0.145, 0, 0.62, 0.05, 0.13, 0.22)
        rb.box("thigh.%s" % side, JOINT, sx * 0.12, 0, 0.405, 0.125, 0.135, 0.06)
        rb.box("shin.%s" % side, BODY, sx * 0.12, 0, 0.24, 0.135, 0.145, 0.32)
        rb.box("shin.%s" % side, PLATE, sx * 0.12, -0.075, 0.26, 0.11, 0.04, 0.20)
        rb.box("foot.%s" % side, JOINT, sx * 0.12, -0.055, 0.055, 0.155, 0.27, 0.09)
        rb.box("foot.%s" % side, PLATE, sx * 0.12, -0.155, 0.035, 0.145, 0.10, 0.05)


# --------------------------------------------------------------------------
# Animation
# --------------------------------------------------------------------------

# Each clip: (name, length_in_frames, loop, {bone: [(frame, (rx, ry, rz)), ...]})
# Rotations are XYZ Euler radians in the bone's local space.
D = math.radians


def _walk():
    """A readable four-key walk cycle: contact, pass, contact, pass. The knee
    only bends on the swing half so the foot never scythes through the
    pavement, and the arms counter-swing."""
    keys = {
        "thigh.L": [(1, (D(32), 0, 0)), (13, (D(-28), 0, 0)), (25, (D(32), 0, 0))],
        "shin.L": [(1, (D(-6), 0, 0)), (7, (D(-46), 0, 0)), (13, (D(-3), 0, 0)), (25, (D(-6), 0, 0))],
        "foot.L": [(1, (D(-14), 0, 0)), (7, (D(12), 0, 0)), (13, (D(10), 0, 0)), (25, (D(-14), 0, 0))],
        "thigh.R": [(1, (D(-28), 0, 0)), (13, (D(32), 0, 0)), (25, (D(-28), 0, 0))],
        "shin.R": [(1, (D(-3), 0, 0)), (13, (D(-6), 0, 0)), (19, (D(-46), 0, 0)), (25, (D(-3), 0, 0))],
        "foot.R": [(1, (D(10), 0, 0)), (13, (D(-14), 0, 0)), (19, (D(12), 0, 0)), (25, (D(10), 0, 0))],
        "upperarm.L": [(1, (D(-22), 0, 0)), (13, (D(24), 0, 0)), (25, (D(-22), 0, 0))],
        "upperarm.R": [(1, (D(24), 0, 0)), (13, (D(-22), 0, 0)), (25, (D(24), 0, 0))],
        "forearm.L": [(1, (D(-18), 0, 0)), (13, (D(-30), 0, 0)), (25, (D(-18), 0, 0))],
        "forearm.R": [(1, (D(-30), 0, 0)), (13, (D(-18), 0, 0)), (25, (D(-30), 0, 0))],
        "pelvis": [(1, (0, 0, D(3))), (7, (0, 0, 0)), (13, (0, 0, D(-3))), (19, (0, 0, 0)), (25, (0, 0, D(3)))],
        "chest": [(1, (0, 0, D(-4))), (13, (0, 0, D(4))), (25, (0, 0, D(-4)))],
        "head": [(1, (0, 0, D(2))), (13, (0, 0, D(-2))), (25, (0, 0, D(2)))],
    }
    # Body bob: two rises per stride, driven on the root bone's Z location.
    loc = {"root": [(1, (0, 0, 0.0)), (7, (0, 0, 0.035)), (13, (0, 0, 0.0)),
                    (19, (0, 0, 0.035)), (25, (0, 0, 0.0))]}
    return keys, loc


def _idle():
    return {
        "chest": [(1, (D(0.6), 0, 0)), (48, (D(-0.8), 0, 0)), (96, (D(0.6), 0, 0))],
        "head": [(1, (0, D(11), 0)), (40, (0, D(-9), 0)), (96, (0, D(11), 0))],
        "upperarm.L": [(1, (D(-3), 0, D(-3))), (48, (D(-5), 0, D(-3))), (96, (D(-3), 0, D(-3)))],
        "upperarm.R": [(1, (D(-5), 0, D(3))), (48, (D(-3), 0, D(3))), (96, (D(-5), 0, D(3)))],
        "forearm.L": [(1, (D(-9), 0, 0)), (96, (D(-9), 0, 0))],
        "forearm.R": [(1, (D(-9), 0, 0)), (96, (D(-9), 0, 0))],
    }, {}


def _wait():
    return {
        "chest": [(1, (0, 0, 0)), (60, (D(-1.2), 0, 0)), (120, (0, 0, 0))],
        "head": [(1, (0, 0, 0)), (120, (0, 0, 0))],
        "upperarm.L": [(1, (D(-4), 0, D(-4))), (120, (D(-4), 0, D(-4)))],
        "upperarm.R": [(1, (D(-4), 0, D(4))), (120, (D(-4), 0, D(4)))],
        "forearm.L": [(1, (D(-12), 0, 0)), (120, (D(-12), 0, 0))],
        "forearm.R": [(1, (D(-12), 0, 0)), (120, (D(-12), 0, 0))],
    }, {}


def _work_at_desk():
    """Standing at a terminal: leaning very slightly in, arms forward-down."""
    return {
        "chest": [(1, (D(7), 0, 0)), (60, (D(8), 0, 0)), (120, (D(7), 0, 0))],
        "head": [(1, (D(13), 0, 0)), (120, (D(13), 0, 0))],
        "upperarm.L": [(1, (D(-56), 0, D(-5))), (120, (D(-56), 0, D(-5)))],
        "upperarm.R": [(1, (D(-56), 0, D(5))), (120, (D(-56), 0, D(5)))],
        "forearm.L": [(1, (D(-42), 0, 0)), (120, (D(-42), 0, 0))],
        "forearm.R": [(1, (D(-42), 0, 0)), (120, (D(-42), 0, 0))],
        "hand.L": [(1, (D(-8), 0, 0)), (120, (D(-8), 0, 0))],
        "hand.R": [(1, (D(-8), 0, 0)), (120, (D(-8), 0, 0))],
    }, {}


def _type_():
    """Same posture as WORK, with the hands actually moving."""
    keys, loc = _work_at_desk()
    keys["hand.L"] = [(1, (D(-4), 0, 0)), (5, (D(-16), 0, 0)), (9, (D(-4), 0, 0)),
                      (15, (D(-14), 0, 0)), (20, (D(-4), 0, 0)), (24, (D(-4), 0, 0))]
    keys["hand.R"] = [(1, (D(-14), 0, 0)), (6, (D(-4), 0, 0)), (11, (D(-16), 0, 0)),
                      (17, (D(-4), 0, 0)), (24, (D(-14), 0, 0))]
    keys["forearm.L"] = [(1, (D(-42), 0, 0)), (12, (D(-45), 0, 0)), (24, (D(-42), 0, 0))]
    keys["forearm.R"] = [(1, (D(-45), 0, 0)), (12, (D(-42), 0, 0)), (24, (D(-45), 0, 0))]
    return keys, loc


def _think():
    return {
        "head": [(1, (D(-4), D(18), 0)), (45, (D(6), D(-14), 0)), (90, (D(-4), D(18), 0))],
        "chest": [(1, (0, D(4), 0)), (45, (0, D(-3), 0)), (90, (0, D(4), 0))],
        "upperarm.L": [(1, (D(-8), 0, D(-4))), (90, (D(-8), 0, D(-4)))],
        "upperarm.R": [(1, (D(-38), 0, D(7))), (45, (D(-42), 0, D(7))), (90, (D(-38), 0, D(7)))],
        "forearm.R": [(1, (D(-72), 0, 0)), (90, (D(-72), 0, 0))],
        "hand.R": [(1, (D(-18), 0, 0)), (90, (D(-18), 0, 0))],
    }, {}


def _study():
    """Seated-height reading posture at a classroom desk: head down over the
    work surface, one hand steadying it."""
    return {
        "chest": [(1, (D(14), 0, 0)), (70, (D(16), 0, 0)), (140, (D(14), 0, 0))],
        "head": [(1, (D(22), D(-5), 0)), (45, (D(24), D(6), 0)), (90, (D(22), D(-6), 0)), (140, (D(22), D(-5), 0))],
        "upperarm.L": [(1, (D(-48), 0, D(-8))), (140, (D(-48), 0, D(-8)))],
        "upperarm.R": [(1, (D(-52), 0, D(8))), (140, (D(-52), 0, D(8)))],
        "forearm.L": [(1, (D(-56), 0, 0)), (140, (D(-56), 0, 0))],
        "forearm.R": [(1, (D(-48), 0, 0)), (70, (D(-54), 0, 0)), (140, (D(-48), 0, 0))],
    }, {}


def _read():
    return {
        "chest": [(1, (D(5), 0, 0)), (140, (D(5), 0, 0))],
        "head": [(1, (D(19), D(-7), 0)), (70, (D(19), D(7), 0)), (140, (D(19), D(-7), 0))],
        "upperarm.L": [(1, (D(-62), 0, D(-10))), (140, (D(-62), 0, D(-10)))],
        "upperarm.R": [(1, (D(-62), 0, D(10))), (140, (D(-62), 0, D(10)))],
        "forearm.L": [(1, (D(-62), 0, 0)), (140, (D(-62), 0, 0))],
        "forearm.R": [(1, (D(-62), 0, 0)), (140, (D(-62), 0, 0))],
    }, {}


def _verify():
    """Working a verification station: one arm raised to the chamber, head
    tracking it."""
    return {
        "chest": [(1, (D(3), D(-8), 0)), (60, (D(3), D(-6), 0)), (120, (D(3), D(-8), 0))],
        "head": [(1, (D(-6), D(-16), 0)), (60, (D(-2), D(-12), 0)), (120, (D(-6), D(-16), 0))],
        "upperarm.L": [(1, (D(-10), 0, D(-4))), (120, (D(-10), 0, D(-4)))],
        "upperarm.R": [(1, (D(-88), 0, D(14))), (30, (D(-96), 0, D(14))), (75, (D(-84), 0, D(14))), (120, (D(-88), 0, D(14)))],
        "forearm.R": [(1, (D(-26), 0, 0)), (30, (D(-16), 0, 0)), (120, (D(-26), 0, 0))],
        "hand.R": [(1, (D(-8), 0, 0)), (30, (D(6), 0, 0)), (60, (D(-8), 0, 0)), (120, (D(-8), 0, 0))],
    }, {}


def _enter_door():
    """A short non-looping transition: the unit steps forward and sinks out of
    view through the doorway. The runtime hides it on the last frame."""
    keys, loc = _walk()
    trimmed = {}
    for bone, frames in keys.items():
        trimmed[bone] = [(f, v) for f, v in frames if f <= 25]
    trimmed["chest"] = [(1, (0, 0, 0)), (25, (D(4), 0, 0))]
    loc = {"root": [(1, (0, 0.0, 0.0)), (18, (0, -0.55, 0.0)), (25, (0, -0.95, -0.35))]}
    return trimmed, loc


def _exit_door():
    keys, loc = _enter_door()
    out = {}
    for bone, frames in keys.items():
        last = frames[-1][0]
        out[bone] = [(last + 1 - f, v) for f, v in reversed(frames)]
    loc = {"root": [(1, (0, -0.95, -0.35)), (8, (0, -0.55, 0.0)), (25, (0, 0.0, 0.0))]}
    return out, loc


CLIPS = [
    ("IDLE", 96, True, _idle),
    ("WALK", 25, True, _walk),
    ("WORK_AT_DESK", 120, True, _work_at_desk),
    ("TYPE", 24, True, _type_),
    ("STUDY", 140, True, _study),
    ("READ", 140, True, _read),
    ("WAIT", 120, True, _wait),
    ("THINK", 90, True, _think),
    ("VERIFY", 120, True, _verify),
    ("ENTER_DOOR", 25, False, _enter_door),
    ("EXIT_DOOR", 25, False, _exit_door),
]


def action_fcurves(action):
    """Blender 4.4+ moved an Action's F-curves out of `action.fcurves` and into
    slotted layers (`action.layers[].strips[].channelbags[].fcurves`). Support
    both so these scripts are not pinned to one Blender release."""
    legacy = getattr(action, "fcurves", None)
    if legacy is not None:
        return list(legacy)
    curves = []
    for layer in getattr(action, "layers", []):
        for strip in getattr(layer, "strips", []):
            for bag in getattr(strip, "channelbags", []):
                curves.extend(bag.fcurves)
    return curves


def make_action(arm_obj, name, length, rot_keys, loc_keys):
    """Author one Action on the armature. Blender's glTF exporter emits one
    named animation per Action, which is exactly the clip list three.js wants."""
    action = bpy.data.actions.new(name)
    action.use_fake_user = True
    if not arm_obj.animation_data:
        arm_obj.animation_data_create()
    arm_obj.animation_data.action = action

    for pb in arm_obj.pose.bones:
        pb.rotation_mode = "XYZ"

    # Every clip keys every animated channel at frame 1 and at `length`, so no
    # clip inherits a stale pose from whichever clip played before it.
    for bone_name, frames in sorted(rot_keys.items()):
        pb = arm_obj.pose.bones.get(bone_name)
        if pb is None:
            continue
        for frame, rot in frames:
            pb.rotation_euler = rot
            pb.keyframe_insert(data_path="rotation_euler", frame=frame)
    for bone_name, frames in sorted(loc_keys.items()):
        pb = arm_obj.pose.bones.get(bone_name)
        if pb is None:
            continue
        for frame, loc in frames:
            pb.location = loc
            pb.keyframe_insert(data_path="location", frame=frame)

    for fc in action_fcurves(action):
        for kp in fc.keyframe_points:
            kp.interpolation = "BEZIER"
            kp.handle_left_type = "AUTO_CLAMPED"
            kp.handle_right_type = "AUTO_CLAMPED"
    return action


def reset_pose(arm_obj):
    for pb in arm_obj.pose.bones:
        pb.rotation_euler = (0, 0, 0)
        pb.location = (0, 0, 0)
        pb.scale = (1, 1, 1)


def build_robot_scene(collection, preview_poses=False):
    """Build rig + mesh into `collection`. Returns (armature, mesh objects)."""
    arm = build_armature(collection)
    rb = RiggedBuilder()
    build_robot_mesh(rb)
    meshes = rb.emit("argus_robot", collection, arm)
    return arm, meshes


def build_and_export():
    reset_scene()
    col = new_collection("argus_robot")
    arm, meshes = build_robot_scene(col)

    bpy.context.view_layer.objects.active = arm
    bpy.ops.object.mode_set(mode="POSE")
    names = []
    for name, length, loop, fn in CLIPS:
        reset_pose(arm)
        rot_keys, loc_keys = fn()
        make_action(arm, name, length, rot_keys, loc_keys)
        names.append(name)
    reset_pose(arm)
    bpy.ops.object.mode_set(mode="OBJECT")

    # Keep every action alive through the export; the exporter walks
    # bpy.data.actions for ACTIONS mode.
    bpy.context.scene.frame_start = 1
    bpy.context.scene.frame_end = 140

    export_glb([arm] + meshes, "robots", "argus_robot",
               extras={"kind": "character", "height": ROBOT_H, "animations": names,
                       "bones": len(BONES)})


if __name__ == "__main__":
    from argus_kit import write_manifest
    build_and_export()
    write_manifest()
