"""ARGUS AI City -- building assets.

Seven architectural families with genuinely different silhouette logic. Not one tower generator with different heights: a hardened security
block batters its base and buries small deep-set windows in thick wall; an
academic building runs horizontal bands behind a colonnade; an industrial
shed is long, low and barrel-roofed with stacks and pipe racks. You should be
able to tell them apart from the city overview by outline alone.

Blender is Z-up; the glTF exporter converts to the Y-up the runtime uses.
Every building's base sits at z=0 and is centred on x=y=0, so the runtime can
drop it straight onto a block.
"""

import math
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus_kit import (  # noqa: E402
    Builder, FLOOR_H, DOOR_H, get_material, new_collection, reset_scene,
    export_glb, rnd, rnd_range, window_grid, floor_band, corner_columns,
    parapet, entrance, roof_plant, antenna, light_strip, sign_plate,
)


# ==========================================================================
# FAMILY A -- ARGUS CORPORATE / COMMAND
# Stepped setbacks, a lit structural spine, deep vertical fins, a crown.
# ==========================================================================

def family_corporate(b, floors, w, d, seed, accent="ARGUS_Cyan",
                     setbacks=((0.55, 0.78), (0.82, 0.58)), spine=True, crown=True):
    """Tall, tapering in discrete SETBACKS rather than a smooth taper -- the
    stepped profile is the family's signature."""
    z = 0.0
    cur_w, cur_d = w, d
    step_i = 0
    for i in range(floors):
        t = i / max(1, floors - 1)
        for frac, scale in setbacks:
            if abs(t - frac) < (0.5 / floors) and step_i < len(setbacks):
                cur_w, cur_d = w * scale, d * scale
                step_i += 1
                # A terrace slab is what makes a setback read as architecture
                # instead of a modelling accident.
                b.m("ARGUS_Concrete").box(0, 0, z + 0.14, cur_w + 2.2, cur_d + 2.2, 0.28, bevel=0.03)
                b.m("ARGUS_Steel").box(0, 0, z + 0.62, cur_w + 2.0, cur_d + 2.0, 0.10)
                light_strip(b, 0, 0, cur_w + 2.2, cur_d + 2.2, z + 0.32, accent, 0.06)
                break

        floor_band(b, 0, 0, cur_w, cur_d, z + 0.13)
        body_h = FLOOR_H - 0.26
        bz = z + 0.26 + body_h / 2
        b.m("ARGUS_Graphite").box(0, 0, bz, cur_w * 0.985, cur_d * 0.985, body_h)

        if i == 0:
            # Double-height glazed lobby at grade.
            window_grid(b, -cur_w / 2 + 0.6, cur_w / 2 - 0.6, z + 0.5, z + body_h - 0.2,
                        -cur_d / 2, -0.30, seed + 500, rows=1, lit_ratio=0.9, cool_ratio=0.0)
        else:
            for sy, yy in ((-1, -cur_d / 2), (1, cur_d / 2)):
                window_grid(b, -cur_w / 2 + 0.5, cur_w / 2 - 0.5, bz - body_h * 0.34, bz + body_h * 0.34,
                            yy, sy * -0.28, seed + i * 97 + (0 if sy < 0 else 311), rows=1)
            for sx, xx in ((-1, -cur_w / 2), (1, cur_w / 2)):
                _side_windows(b, xx, sx, -cur_d / 2 + 0.5, cur_d / 2 - 0.5,
                              bz - body_h * 0.34, bz + body_h * 0.34, seed + i * 61 + (0 if sx < 0 else 733))
        z += FLOOR_H

    corner_columns(b, 0, 0, w, d, 0, z * 0.62, size=0.46)
    corner_columns(b, 0, 0, cur_w, cur_d, z * 0.55, z, size=0.38)

    if spine:
        # The illuminated central spine: a recessed slot of glass with a thin
        # light line in it, running the full height on both long faces.
        for sy, yy in ((-1, -1), (1, 1)):
            b.m("ARGUS_DarkAlloy").box(0, yy * (d / 2 + 0.06), z * 0.5, 1.9, 0.5, z)
            b.m("ARGUS_BlackGlass").box(0, yy * (d / 2 + 0.22), z * 0.5, 1.35, 0.22, z * 0.99)
            b.m(accent).box(0, yy * (d / 2 + 0.34), z * 0.5, 0.16, 0.08, z * 0.97)

    parapet(b, 0, 0, cur_w, cur_d, z, height=0.85)
    roof_plant(b, 0, 0, cur_w, cur_d, z, seed, accent)

    if crown:
        # A real crown: a stepped lantern with lit mullions, not a cone.
        cz = z + 0.9
        for k, (cw, ch) in enumerate(((cur_w * 0.62, 1.7), (cur_w * 0.42, 1.4), (cur_w * 0.24, 1.1))):
            b.m("ARGUS_DarkAlloy").box(0, 0, cz + ch / 2, cw, cw * (cur_d / cur_w), ch, bevel=0.05)
            light_strip(b, 0, 0, cw * 1.01, cw * (cur_d / cur_w) * 1.01, cz + ch - 0.12, accent, 0.07)
            cz += ch
        antenna(b, 0, 0, cz, 4.2, accent)
    return z


def _side_windows(b, xx, sx, y0, y1, z0, z1, seed):
    """Window band on an X-facing facade. Kept separate from window_grid so
    the wide/narrow elevations can carry different rhythms."""
    depth = sx * 0.28
    span = y1 - y0
    cols = max(1, int(span / 2.1))
    cw = (span / cols) * 0.60
    ch = (z1 - z0) * 0.62
    cz = (z0 + z1) / 2
    for c in range(cols):
        cy = y0 + (c + 0.5) * (span / cols)
        roll = rnd(seed + c * 17)
        mat = "ARGUS_WarmGlass" if roll > 0.80 else ("ARGUS_CoolGlass" if roll < 0.10 else "ARGUS_BlackGlass")
        b.m("ARGUS_DarkAlloy").box(xx + depth * 0.5, cy, cz, abs(depth), cw + 0.14, ch + 0.14)
        b.m(mat).box(xx + depth * 0.12, cy, cz, abs(depth) * 0.35, cw, ch)


def build_core_tower():
    b = Builder("core_tower", "corporate")
    # Plaza podium the tower stands on.
    b.m("ARGUS_Concrete").box(0, 0, 0.25, 26, 26, 0.5, bevel=0.06)
    b.m("ARGUS_Sidewalk").box(0, 0, 0.54, 24.6, 24.6, 0.08)
    light_strip(b, 0, 0, 24.8, 24.8, 0.56, "ARGUS_Cyan", 0.06)
    for sx in (-1, 1):
        for sy in (-1, 1):
            b.m("ARGUS_Steel").box(sx * 9.2, sy * 9.2, 2.1, 0.30, 0.30, 4.2)
            b.m("ARGUS_Cyan").cyl(sx * 9.2, sy * 9.2, 4.3, 0.22, 0.22, 0.16, segs=8)

    top = family_corporate(b, 13, 11.5, 10.5, seed=11, accent="ARGUS_Cyan")
    entrance(b, 0, -5.6, 3.4, 0.58, face=-1)
    sign_plate(b, 0, -5.45, top * 0.30, 6.4, 1.5, face=-1, accent="ARGUS_Cyan")
    # Four low pavilions anchoring the plaza corners.
    for sx, sy in ((-1, 1), (1, 1), (-1, -1), (1, -1)):
        px, py = sx * 9.4, sy * 9.4
        b.m("ARGUS_Graphite").box(px, py, 1.7, 4.4, 4.4, 3.4, bevel=0.06)
        b.m("ARGUS_Steel").box(px, py, 3.52, 4.9, 4.9, 0.24, bevel=0.03)
        window_grid(b, px - 1.7, px + 1.7, 0.9, 2.7, py - 2.2, -0.26, seed=int(px * 7 + py))
    return b


def build_agent_hq():
    b = Builder("agent_hq", "corporate")
    # Broad 7-floor operations block with two command wings and sky bridges.
    top = family_corporate(b, 7, 17, 12, seed=23, accent="ARGUS_Cyan",
                           setbacks=((0.72, 0.86),), spine=True, crown=False)
    for side in (-1, 1):
        wx = side * 13.6
        wz = 0.0
        for i in range(4):
            floor_band(b, wx, 1.5, 7.6, 8.4, wz + 0.13)
            body_h = FLOOR_H - 0.26
            b.m("ARGUS_Graphite").box(wx, 1.5, wz + 0.26 + body_h / 2, 7.4, 8.2, body_h)
            window_grid(b, wx - 3.1, wx + 3.1, wz + 0.7, wz + body_h - 0.15, -2.7, -0.26, seed=int(41 * side + i * 13))
            _side_windows(b, wx + side * 3.8, side, -2.2, 5.4, wz + 0.7, wz + body_h - 0.15, seed=int(77 * side + i * 9))
            wz += FLOOR_H
        parapet(b, wx, 1.5, 7.6, 8.4, wz, height=0.7)
        roof_plant(b, wx, 1.5, 7.6, 8.4, wz, seed=int(55 * side))
        corner_columns(b, wx, 1.5, 7.6, 8.4, 0, wz, size=0.40)
        entrance(b, wx, -2.8, 2.4, 0.0, face=-1)
        # Sky bridge to the main block.
        b.m("ARGUS_DarkAlloy").box(side * 9.6, 1.5, FLOOR_H * 3 + 1.1, 6.0, 2.4, 2.4, bevel=0.05)
        b.m("ARGUS_BlackGlass").box(side * 9.6, 1.5, FLOOR_H * 3 + 1.2, 5.6, 2.55, 1.5)
        b.m("ARGUS_Cyan").box(side * 9.6, 1.5, FLOOR_H * 3 + 0.05, 5.8, 2.5, 0.06)
        # Exterior structural terrace.
        b.m("ARGUS_Steel").box(wx, -3.4, FLOOR_H * 2 + 0.2, 7.2, 2.0, 0.18, bevel=0.03)
        for k in range(6):
            b.m("ARGUS_Steel").box(wx - 3.2 + k * 1.28, -4.3, FLOOR_H * 2 + 0.66, 0.07, 0.07, 0.92)
        b.m("ARGUS_Steel").box(wx, -4.3, FLOOR_H * 2 + 1.14, 7.2, 0.08, 0.08)

    entrance(b, 0, -6.1, 4.6, 0.0, face=-1)
    # Glass atrium over the main entrance.
    b.m("ARGUS_Steel").box(0, -6.6, FLOOR_H * 2 + 0.1, 11.0, 3.2, 0.2, bevel=0.03)
    b.m("ARGUS_BlackGlass").box(0, -6.9, FLOOR_H * 1.0, 10.2, 0.18, FLOOR_H * 2 - 0.4)
    for k in range(5):
        b.m("ARGUS_Steel").box(-4.4 + k * 2.2, -6.9, FLOOR_H * 1.0, 0.16, 0.30, FLOOR_H * 2 - 0.4)
    sign_plate(b, 0, -6.15, FLOOR_H * 2 + 1.35, 7.6, 1.5, face=-1, accent="ARGUS_Cyan")
    # Rooftop communications array.
    for k, ox in enumerate((-3.2, 0.0, 3.4)):
        antenna(b, ox, -2.0, top + 0.9, 3.0 + k * 0.8, "ARGUS_Cyan", dish=(k != 1))
    b.m("ARGUS_Steel").box(0, 3.0, top + 1.5, 6.0, 0.16, 0.16)
    b.m("ARGUS_Steel").box(0, 3.0, top + 0.9, 0.16, 0.16, 1.2)
    return b


# ==========================================================================
# FAMILY B -- ACADEMIC / RESEARCH
# Horizontal banding, a colonnade, a rotunda, courtyard wings.
# ==========================================================================

def family_academic(b, floors, w, d, seed, accent="ARGUS_Violet", second="ARGUS_Cyan"):
    z = 0.0
    for i in range(floors):
        # Deep continuous cornice bands -- the family reads HORIZONTAL where
        # the corporate family reads vertical.
        b.m("ARGUS_Concrete").box(0, 0, z + 0.20, w + 0.9, d + 0.9, 0.40, bevel=0.04)
        body_h = FLOOR_H - 0.40
        bz = z + 0.40 + body_h / 2
        b.m("ARGUS_Graphite").box(0, 0, bz, w, d, body_h)
        # Tall narrow academic windows, paired.
        for sy, yy in ((-1, -d / 2), (1, d / 2)):
            window_grid(b, -w / 2 + 0.7, w / 2 - 0.7, bz - body_h * 0.36, bz + body_h * 0.36,
                        yy, sy * -0.26, seed + i * 71 + (0 if sy < 0 else 401),
                        cols=max(2, int(w / 1.5)), rows=1, lit_ratio=0.30)
        for sx, xx in ((-1, -w / 2), (1, w / 2)):
            _side_windows(b, xx, sx, -d / 2 + 0.7, d / 2 - 0.7,
                          bz - body_h * 0.36, bz + body_h * 0.36, seed + i * 53 + (0 if sx < 0 else 907))
        z += FLOOR_H
    b.m("ARGUS_Concrete").box(0, 0, z + 0.26, w + 1.4, d + 1.4, 0.52, bevel=0.05)
    light_strip(b, 0, 0, w + 1.4, d + 1.4, z + 0.04, second, 0.06)
    parapet(b, 0, 0, w + 1.0, d + 1.0, z + 0.52, height=0.62)
    return z + 0.52


def colonnade(b, cx, cy, width, count, height, depth=0.55, mat="ARGUS_Concrete"):
    for i in range(count):
        px = cx - width / 2 + (i + 0.5) * (width / count)
        b.m(mat).cyl(px, cy, height / 2, 0.30, 0.34, height, segs=10)
        b.m("ARGUS_Steel").box(px, cy, height - 0.12, 0.80, 0.80, 0.24, bevel=0.03)
    b.m(mat).box(cx, cy, height + 0.36, width + 0.9, depth * 2.2, 0.72, bevel=0.04)


def build_academy():
    b = Builder("academy", "academic")
    top = family_academic(b, 6, 19, 11, seed=31, accent="ARGUS_Violet", second="ARGUS_Cyan")
    # Rotunda: the Academy's landmark element.
    b.m("ARGUS_Concrete").cyl(0, 6.4, 2.6, 4.6, 5.0, 5.2, segs=16, bevel=0.05)
    for k in range(12):
        a = (k / 12) * math.pi * 2
        b.m("ARGUS_Steel").box(math.cos(a) * 4.75, 6.4 + math.sin(a) * 4.75, 3.0, 0.22, 0.22, 4.4)
    b.m("ARGUS_BlackGlass").cyl(0, 6.4, 3.0, 4.35, 4.35, 4.2, segs=16)
    b.m("ARGUS_Concrete").cyl(0, 6.4, 5.5, 4.2, 5.1, 0.6, segs=16, bevel=0.04)
    b.m("ARGUS_Violet").cyl(0, 6.4, 5.92, 3.9, 3.9, 0.08, segs=16)
    b.m("ARGUS_Concrete").cyl(0, 6.4, 6.9, 1.2, 3.6, 2.2, segs=16)
    b.m("ARGUS_Cyan").cyl(0, 6.4, 8.3, 0.28, 0.28, 0.8, segs=8)

    # Library wing (west) and simulation wing (east) forming a courtyard.
    for side, label_accent in ((-1, "ARGUS_Violet"), (1, "ARGUS_Cyan")):
        wx = side * 14.2
        z = 0.0
        for i in range(3):
            b.m("ARGUS_Concrete").box(wx, 5.0, z + 0.18, 8.4, 11.4, 0.36, bevel=0.03)
            bh = FLOOR_H - 0.36
            b.m("ARGUS_Graphite").box(wx, 5.0, z + 0.36 + bh / 2, 8.0, 11.0, bh)
            window_grid(b, wx - 3.4, wx + 3.4, z + 0.8, z + bh - 0.1, -0.55, -0.26,
                        seed=int(120 * side + i * 31), cols=5, rows=1)
            _side_windows(b, wx + side * 4.05, side, 0.2, 9.8, z + 0.8, z + bh - 0.1,
                          seed=int(210 * side + i * 17))
            z += FLOOR_H
        b.m("ARGUS_Concrete").box(wx, 5.0, z + 0.24, 9.0, 12.0, 0.48, bevel=0.04)
        light_strip(b, wx, 5.0, 9.0, 12.0, z + 0.02, label_accent, 0.06)
        parapet(b, wx, 5.0, 8.6, 11.6, z + 0.48, height=0.56)
        roof_plant(b, wx, 5.0, 8.4, 11.4, z + 0.48, seed=int(90 * side), accent=label_accent)
        entrance(b, wx, -0.9, 2.2, 0.0, face=-1, accent=label_accent)

    # Courtyard paving, steps and the colonnaded entry screen.
    b.m("ARGUS_Sidewalk").box(0, 2.0, 0.14, 17.0, 12.0, 0.28, bevel=0.03)
    b.m("ARGUS_Violet").box(0, 2.0, 0.29, 6.0, 6.0, 0.03)
    b.m("ARGUS_Concrete").box(0, 2.0, 0.31, 5.4, 5.4, 0.04)
    colonnade(b, 0, -5.6, 16.0, 7, 4.6)
    for i in range(3):
        b.m("ARGUS_Concrete").box(0, -7.4 - i * 0.5, 0.10 - i * 0.13, 12.0 - i * 0.8, 1.0, 0.26)
    entrance(b, 0, -5.3, 3.6, 0.0, face=-1, accent="ARGUS_Cyan", canopy=False)
    sign_plate(b, 0, -5.75, 6.0, 8.2, 1.6, face=-1, accent="ARGUS_Cyan")
    return b


def build_research_annex():
    b = Builder("research_annex", "academic")
    top = family_academic(b, 3, 10, 8, seed=57, second="ARGUS_Cyan")
    entrance(b, 0, -4.1, 2.2, 0.0, face=-1)
    roof_plant(b, 0, 0, 10, 8, top, seed=57)
    sign_plate(b, 0, -4.15, top * 0.55, 4.4, 1.0, face=-1)
    return b


# ==========================================================================
# FAMILY C -- SECURITY / HARDENED
# Battered (sloped) base, thick wall, small deep-set windows, buttresses.
# ==========================================================================

def family_hardened(b, floors, w, d, seed, accent="ARGUS_Teal", batter=1.5):
    # Battered plinth: wider at the ground, sloping in. Instantly reads as
    # defensive rather than commercial.
    b.m("ARGUS_Concrete").box(0, 0, 0.9, w + batter * 2, d + batter * 2, 1.8, bevel=0.10)
    b.m("ARGUS_DarkAlloy").box(0, 0, 1.95, w + batter, d + batter, 0.30, bevel=0.04)
    z = 2.1
    for i in range(floors):
        b.m("ARGUS_Concrete").box(0, 0, z + 0.16, w + 0.5, d + 0.5, 0.32, bevel=0.03)
        bh = FLOOR_H - 0.32
        b.m("ARGUS_Graphite").box(0, 0, z + 0.32 + bh / 2, w, d, bh)
        # Slit windows: narrow, deep, few. Set into a heavy reveal.
        for sy, yy in ((-1, -d / 2), (1, d / 2)):
            window_grid(b, -w / 2 + 1.2, w / 2 - 1.2, z + 0.32 + bh * 0.34, z + 0.32 + bh * 0.62,
                        yy, sy * -0.40, seed + i * 43 + (0 if sy < 0 else 611),
                        cols=max(2, int(w / 2.6)), rows=1, lit_ratio=0.35, cool_ratio=0.25, recess=0.06)
        z += FLOOR_H
    # Buttresses at the corners and mid-span.
    for sx in (-1, 1):
        for oy in (-d * 0.3, d * 0.3):
            b.m("ARGUS_Concrete").box(sx * (w / 2 + 0.35), oy, (z - 2.1) / 2 + 2.1,
                                      0.9, 1.5, z - 2.1, bevel=0.04)
    b.m("ARGUS_DarkAlloy").box(0, 0, z + 0.25, w + 1.1, d + 1.1, 0.50, bevel=0.05)
    parapet(b, 0, 0, w + 0.9, d + 0.9, z + 0.50, height=1.05, thickness=0.42)
    light_strip(b, 0, 0, w + 1.1, d + 1.1, z + 0.04, accent, 0.06)
    return z + 0.50


def build_security_command():
    b = Builder("security_command", "hardened")
    top = family_hardened(b, 5, 12, 11, seed=71)
    entrance(b, 0, -6.9, 3.0, 2.1, face=-1)
    # Vehicle barrier + guard post at the approach.
    for sx in (-1, 1):
        b.m("ARGUS_Steel").box(sx * 4.6, -9.4, 0.55, 0.36, 0.36, 1.10)
        b.m("ARGUS_Cyan").box(sx * 2.6, -9.4, 1.02, 3.6, 0.16, 0.16)
    b.m("ARGUS_Graphite").box(-7.4, -9.0, 1.25, 2.4, 2.4, 2.5, bevel=0.05)
    b.m("ARGUS_BlackGlass").box(-7.4, -10.15, 1.85, 1.9, 0.12, 1.0)
    b.m("ARGUS_Steel").box(-7.4, -9.0, 2.62, 2.9, 2.9, 0.24, bevel=0.03)
    roof_plant(b, 0, 0, 12, 11, top, seed=71)
    for k, ox in enumerate((-4.2, -2.6, 4.4)):
        antenna(b, ox, 3.8, top + 1.0, 2.4 + k * 0.7, "ARGUS_Cyan", dish=(k == 2))
    # Surveillance masts on the parapet.
    for sx in (-1, 1):
        b.m("ARGUS_Steel").cyl(sx * 5.4, -5.2, top + 1.5, 0.08, 0.08, 1.6, segs=6)
        b.m("ARGUS_DarkAlloy").box(sx * 5.4, -5.45, top + 2.35, 0.34, 0.5, 0.26, bevel=0.03)
        b.m("ARGUS_Red").cyl(sx * 5.4, -5.72, top + 2.35, 0.06, 0.06, 0.05, segs=6)
    sign_plate(b, 0, -6.95, top * 0.62, 5.6, 1.2, face=-1)
    return b


def build_hardened_annex(name, w=8.0, d=7.0, floors=2, seed=101, accent="ARGUS_Teal"):
    b = Builder(name, "hardened")
    top = family_hardened(b, floors, w, d, seed, accent=accent, batter=1.0)
    entrance(b, 0, -(d / 2 + 1.0), 2.2, 2.1, face=-1, accent=accent)
    roof_plant(b, 0, 0, w, d, top, seed=seed, accent=accent)
    sign_plate(b, 0, -(d / 2 + 1.05), top * 0.66, 3.8, 0.9, face=-1, accent=accent)
    return b


# ==========================================================================
# FAMILY D -- INDUSTRIAL / COMPUTE
# Long low sheds, barrel roofs, stacks, pipe racks, transformer yards.
# ==========================================================================

def barrel_shed(b, cx, cy, w, d, h, seed, segs=7, accent="ARGUS_Amber"):
    """A long hall with a curved roof -- an industrial silhouette no amount of
    box-stacking produces."""
    b.m("ARGUS_Concrete").box(cx, cy, 0.35, w + 0.8, d + 0.8, 0.70, bevel=0.05)
    b.m("ARGUS_Graphite").box(cx, cy, 0.70 + h / 2, w, d, h)
    r = w / 2
    for i in range(segs):
        a0 = math.pi * (i / segs)
        a1 = math.pi * ((i + 1) / segs)
        am = (a0 + a1) / 2
        seg_w = r * (a1 - a0) * 1.06
        b.m("ARGUS_Steel").box(cx + math.cos(am) * r * 0.86, cy,
                               0.70 + h + math.sin(am) * r * 0.52,
                               seg_w, d + 0.5, 0.26)
    # Ribs across the roof.
    for k in range(4):
        b.m("ARGUS_DarkAlloy").box(cx, cy - d / 2 + (k + 0.5) * (d / 4), 0.70 + h + 0.30,
                                   w * 0.94, 0.20, 0.12)
    # Clerestory light strip along the ridge.
    b.m(accent).box(cx, cy, 0.70 + h + r * 0.53, 0.20, d * 0.86, 0.10)
    # Louvre bands on the long walls.
    for sy in (-1, 1):
        for k in range(5):
            b.m("ARGUS_DarkAlloy").box(cx - w * 0.36 + k * (w * 0.18), cy + sy * (d / 2 + 0.05),
                                       0.70 + h * 0.66, w * 0.13, 0.16, h * 0.30)
            b.m("ARGUS_CoolGlass").box(cx - w * 0.36 + k * (w * 0.18), cy + sy * (d / 2 + 0.14),
                                       0.70 + h * 0.66, w * 0.10, 0.06, h * 0.22)


def build_model_compute():
    b = Builder("model_compute", "industrial")
    # Control block.
    z = 0.0
    for i in range(3):
        floor_band(b, 0, 7.4, 11, 7, z + 0.13)
        bh = FLOOR_H - 0.26
        b.m("ARGUS_Graphite").box(0, 7.4, z + 0.26 + bh / 2, 10.6, 6.8, bh)
        window_grid(b, -4.6, 4.6, z + 0.7, z + bh - 0.1, 4.0, -0.26, seed=13 + i * 29, cols=5, rows=1)
        z += FLOOR_H
    parapet(b, 0, 7.4, 11, 7, z, height=0.6)
    roof_plant(b, 0, 7.4, 11, 7, z, seed=13, accent="ARGUS_Amber")
    entrance(b, 0, 3.9, 3.0, 0.0, face=-1, accent="ARGUS_Amber")
    sign_plate(b, 0, 3.85, z * 0.62, 6.0, 1.2, face=-1, accent="ARGUS_Amber")

    # Two compute halls.
    for sx in (-1, 1):
        barrel_shed(b, sx * 7.4, -5.0, 9.0, 15.0, 4.2, seed=int(200 + sx * 7))
    # Central model core: a contained beam in a lattice shaft.
    b.m("ARGUS_Concrete").cyl(0, -5.0, 0.4, 2.6, 2.9, 0.8, segs=12, bevel=0.05)
    for k in range(8):
        a = (k / 8) * math.pi * 2
        b.m("ARGUS_Steel").box(math.cos(a) * 2.3, -5.0 + math.sin(a) * 2.3, 4.5, 0.18, 0.18, 8.0)
    b.m("ARGUS_Amber").cyl(0, -5.0, 4.6, 0.55, 0.55, 7.6, segs=10)
    for zz in (2.2, 5.0, 7.8):
        b.m("ARGUS_Steel").cyl(0, -5.0, zz, 2.45, 2.45, 0.16, segs=12)
    b.m("ARGUS_DarkAlloy").cyl(0, -5.0, 8.9, 1.6, 2.5, 1.2, segs=12, bevel=0.04)

    # Cooling stacks.
    for sx in (-1, 1):
        cx = sx * 15.4
        b.m("ARGUS_Concrete").cyl(cx, -4.0, 2.0, 1.75, 2.45, 4.0, segs=14, bevel=0.06)
        b.m("ARGUS_Steel").cyl(cx, -4.0, 5.3, 2.20, 1.75, 2.6, segs=14)
        b.m("ARGUS_DarkAlloy").cyl(cx, -4.0, 6.70, 2.05, 2.05, 0.28, segs=14)
        b.m("ARGUS_Amber").cyl(cx, -4.0, 6.90, 1.80, 1.80, 0.06, segs=14)
    # Transformer yard + pipe rack along the service edge.
    for k in range(5):
        tx = -8.0 + k * 4.0
        b.m("ARGUS_DarkAlloy").box(tx, 13.4, 0.85, 1.7, 1.4, 1.7, bevel=0.04)
        b.m("ARGUS_Steel").box(tx, 13.4, 1.86, 1.9, 1.6, 0.14)
        for j in range(3):
            b.m("ARGUS_Steel").cyl(tx - 0.5 + j * 0.5, 13.4, 2.25, 0.07, 0.07, 0.65, segs=6)
    for k in range(7):
        b.m("ARGUS_Steel").box(-10.0 + k * 3.4, 11.4, 1.6, 0.18, 0.18, 3.2)
    for zz, rr in ((3.2, 0.22), (2.75, 0.17)):
        b.m("ARGUS_Steel").cyl(0, 11.4, zz, rr, rr, 24.0, segs=8)
    # Rotate the two long pipes along X (built along Z, so lay them down).
    return b


def build_capability_center():
    b = Builder("capability_center", "industrial")
    top = family_hardened(b, 4, 15, 10, seed=167, accent="ARGUS_Amber", batter=1.2)
    # Loading bays with roller shutters.
    for i in range(3):
        by = -4.4 + i * 4.4
        b.m("ARGUS_Concrete").box(10.6, by, 1.75, 4.6, 3.6, 3.5, bevel=0.05)
        b.m("ARGUS_DarkAlloy").box(12.95, by, 1.45, 0.16, 3.0, 2.9)
        for k in range(6):
            b.m("ARGUS_Steel").box(13.03, by, 0.32 + k * 0.48, 0.05, 2.9, 0.22)
        b.m("ARGUS_Amber").box(10.6, by, 3.62, 4.8, 3.8, 0.08)
        b.m("ARGUS_Concrete").box(15.2, by, 0.08, 4.0, 3.4, 0.16)
    entrance(b, 0, 5.9, 3.4, 2.1, face=1, accent="ARGUS_Amber")
    roof_plant(b, 0, 0, 15, 10, top, seed=167, accent="ARGUS_Amber")
    sign_plate(b, 0, 5.95, top * 0.66, 5.8, 1.2, face=1, accent="ARGUS_Amber")
    # Hard perimeter bollards.
    for k in range(9):
        b.m("ARGUS_Steel").cyl(-10.0 + k * 2.5, -8.4, 0.45, 0.13, 0.15, 0.9, segs=8)
    return b


def build_data_vault():
    b = Builder("data_vault", "industrial")
    # Recessed apron -- the vault sits a step BELOW its own block.
    b.m("ARGUS_Asphalt").box(0, 0, -0.10, 22, 17, 0.20)
    b.m("ARGUS_Concrete").box(0, 0, 2.3, 15, 11.5, 4.6, bevel=0.14)
    # Heavy corner masses.
    for sx in (-1, 1):
        for sy in (-1, 1):
            b.m("ARGUS_DarkAlloy").box(sx * 7.1, sy * 5.4, 2.6, 2.0, 2.0, 5.2, bevel=0.10)
    b.m("ARGUS_DarkAlloy").box(0, 0, 4.95, 15.6, 12.1, 0.70, bevel=0.06)
    b.m("ARGUS_Steel").box(0, 0, 5.42, 13.0, 9.6, 0.24, bevel=0.03)
    for zz in (1.5, 3.3):
        for sy in (-1, 1):
            b.m("ARGUS_Cyan").box(0, sy * 5.76, zz, 13.2, 0.06, 0.09)
        for sx in (-1, 1):
            b.m("ARGUS_Cyan").box(sx * 7.52, 0, zz, 0.06, 9.8, 0.09)
    # Blast door.
    b.m("ARGUS_DarkAlloy").box(0, -5.9, 1.55, 4.4, 0.7, 3.1, bevel=0.05)
    b.m("ARGUS_Steel").cyl(0, -6.3, 1.5, 1.15, 1.15, 0.22, segs=16)
    b.m("ARGUS_Cyan").cyl(0, -6.44, 1.5, 0.75, 0.75, 0.06, segs=16)
    for k in range(4):
        a = (k / 4) * math.pi * 2 + math.pi / 4
        b.m("ARGUS_Steel").box(math.cos(a) * 1.5, -6.34, 1.5 + math.sin(a) * 1.5, 0.24, 0.16, 0.24)
    # Only a few tiny security windows.
    for sx in (-1, 1):
        for k in range(2):
            b.m("ARGUS_DarkAlloy").box(sx * 7.62, -1.8 + k * 3.6, 3.7, 0.16, 0.9, 0.5)
            b.m("ARGUS_CoolGlass").box(sx * 7.68, -1.8 + k * 3.6, 3.7, 0.06, 0.62, 0.32)
    b.m("ARGUS_Steel").cyl(5.2, 3.6, 5.9, 0.10, 0.10, 0.9, segs=6)
    b.m("ARGUS_Cyan").cyl(5.2, 3.6, 6.4, 0.08, 0.08, 0.10, segs=6)
    sign_plate(b, 0, -5.95, 4.1, 4.6, 0.9, face=-1, accent="ARGUS_Violet")
    return b


# ==========================================================================
# FAMILY E -- CIVIC / PUBLIC
# Strict symmetry, a podium, a portico, a glazed central hall.
# ==========================================================================

def build_verification_institute():
    b = Builder("verification_institute", "civic")
    # Podium with steps across the full frontage.
    b.m("ARGUS_Concrete").box(0, 0, 0.55, 24, 17, 1.10, bevel=0.06)
    for i in range(4):
        b.m("ARGUS_Concrete").box(0, -8.8 - i * 0.62, 0.98 - i * 0.26, 14.0 - i * 0.7, 0.66, 0.26)
    # Twin wings -- identical, which is the family's whole point.
    for side in (-1, 1):
        wx = side * 7.6
        z = 1.10
        for i in range(5):
            b.m("ARGUS_Steel").box(wx, 0, z + 0.14, 8.0, 13.4, 0.28, bevel=0.03)
            bh = FLOOR_H - 0.28
            b.m("ARGUS_Graphite").box(wx, 0, z + 0.28 + bh / 2, 7.7, 13.0, bh)
            for sy, yy in ((-1, -6.5), (1, 6.5)):
                window_grid(b, wx - 3.2, wx + 3.2, z + 0.7, z + bh - 0.12, yy, sy * -0.26,
                            seed=int(61 * side + i * 23 + (0 if sy < 0 else 400)), cols=4, rows=1,
                            lit_ratio=0.18, cool_ratio=0.22)
            _side_windows(b, wx + side * 3.9, side, -5.8, 5.8, z + 0.7, z + bh - 0.12,
                          seed=int(133 * side + i * 19))
            z += FLOOR_H
        b.m("ARGUS_Concrete").box(wx, 0, z + 0.22, 8.6, 14.0, 0.44, bevel=0.04)
        parapet(b, wx, 0, 8.2, 13.6, z + 0.44, height=0.60)
        roof_plant(b, wx, 0, 8.0, 13.4, z + 0.44, seed=int(88 * side), accent="ARGUS_White")
        corner_columns(b, wx, 0, 8.0, 13.4, 1.10, z, size=0.36, mat="ARGUS_Steel")
    top = 1.10 + 5 * FLOOR_H + 0.44

    # Central glazed validation hall, one storey taller.
    hz = 1.10
    b.m("ARGUS_Steel").box(0, 0, hz + (6 * FLOOR_H) / 2, 7.4, 12.0, 6 * FLOOR_H)
    b.m("ARGUS_BlackGlass").box(0, 0, hz + (6 * FLOOR_H) / 2, 7.0, 12.4, 6 * FLOOR_H - 0.5)
    for k in range(7):
        b.m("ARGUS_Steel").box(0, -5.6 + k * 1.87, hz + (6 * FLOOR_H) / 2, 7.6, 0.18, 6 * FLOOR_H - 0.3)
    for k in range(6):
        b.m("ARGUS_Steel").box(0, 0, hz + 0.4 + k * FLOOR_H, 7.6, 12.2, 0.16)
    b.m("ARGUS_White").box(0, 0, hz + 6 * FLOOR_H - 0.4, 0.14, 12.2, 0.14)
    ctop = hz + 6 * FLOOR_H
    b.m("ARGUS_Concrete").box(0, 0, ctop + 0.25, 8.2, 12.8, 0.50, bevel=0.04)

    # Rooftop verification frame: a clean open square.
    fz = ctop + 2.6
    for oy in (-5.0, 5.0):
        b.m("ARGUS_White").box(0, oy, fz, 6.6, 0.18, 0.18)
    for ox in (-3.2, 3.2):
        b.m("ARGUS_White").box(ox, 0, fz, 0.18, 10.2, 0.18)
    for ox in (-3.2, 3.2):
        for oy in (-5.0, 5.0):
            b.m("ARGUS_Steel").box(ox, oy, ctop + 1.55, 0.20, 0.20, 2.1)

    # Portico across the entrance.
    colonnade(b, 0, -8.0, 13.0, 6, 5.4, mat="ARGUS_Steel")
    entrance(b, 0, -6.2, 3.4, 1.10, face=-1, accent="ARGUS_White", canopy=False)
    sign_plate(b, 0, -8.7, 6.6, 9.2, 1.4, face=-1, accent="ARGUS_White")
    return b


def build_policy_gate():
    b = Builder("policy_gate", "civic")
    # Twin checkpoint towers flanking a carriageway that passes BETWEEN them.
    for side in (-1, 1):
        tx = side * 7.2
        b.m("ARGUS_Concrete").box(tx, 0, 0.8, 6.0, 7.4, 1.6, bevel=0.08)
        z = 1.6
        for i in range(3):
            b.m("ARGUS_Steel").box(tx, 0, z + 0.14, 5.4, 6.8, 0.28, bevel=0.03)
            bh = FLOOR_H - 0.28
            b.m("ARGUS_Graphite").box(tx, 0, z + 0.28 + bh / 2, 5.1, 6.5, bh)
            window_grid(b, tx - 2.0, tx + 2.0, z + 0.7, z + bh - 0.1, -3.25, -0.26,
                        seed=int(173 * side + i * 11), cols=3, rows=1, lit_ratio=0.4, cool_ratio=0.3)
            z += FLOOR_H
        b.m("ARGUS_DarkAlloy").box(tx, 0, z + 0.26, 6.2, 7.6, 0.52, bevel=0.05)
        parapet(b, tx, 0, 5.8, 7.2, z + 0.52, height=0.7)
        antenna(b, tx, -2.2, z + 0.52, 2.6, "ARGUS_White", dish=False)
        # Inspection window looking onto the lane.
        b.m("ARGUS_DarkAlloy").box(tx - side * 2.6, 0, 2.5, 0.20, 3.4, 1.5)
        b.m("ARGUS_CoolGlass").box(tx - side * 2.72, 0, 2.5, 0.08, 3.0, 1.2)
    gz = 1.6 + 3 * FLOOR_H + 0.52

    # Span beam and scanner across the lane.
    b.m("ARGUS_DarkAlloy").box(0, 0, gz - 1.1, 16.0, 3.0, 1.5, bevel=0.06)
    b.m("ARGUS_White").box(0, 0, gz - 1.95, 15.4, 3.1, 0.16)
    b.m("ARGUS_Steel").box(0, 0, gz + 0.1, 16.4, 3.4, 0.30, bevel=0.04)
    for k in range(9):
        b.m("ARGUS_Steel").box(-7.2 + k * 1.8, 0, gz - 2.4, 0.16, 2.6, 0.9)
    # Barrier arms and lane markers.
    for sy in (-1, 1):
        by = sy * 5.0
        for sx in (-1, 1):
            b.m("ARGUS_Steel").box(sx * 3.4, by, 0.55, 0.34, 0.34, 1.10)
            b.m("ARGUS_White").box(sx * 1.7, by, 1.02, 3.2, 0.16, 0.16)
        b.m("ARGUS_Concrete").box(0, by, 0.22, 3.0, 1.2, 0.44, bevel=0.04)
    sign_plate(b, -7.2, -3.85, 8.4, 3.6, 0.9, face=-1, accent="ARGUS_White")
    sign_plate(b, 7.2, -3.85, 8.4, 3.6, 0.9, face=-1, accent="ARGUS_White")
    return b


def build_specialist_yard():
    b = Builder("specialist_yard", "civic")
    # Dispatch office.
    z = 0.0
    for i in range(2):
        floor_band(b, 0, 7.0, 10, 6, z + 0.13)
        bh = FLOOR_H - 0.26
        b.m("ARGUS_Graphite").box(0, 7.0, z + 0.26 + bh / 2, 9.7, 5.8, bh)
        window_grid(b, -4.2, 4.2, z + 0.7, z + bh - 0.1, 4.0, -0.26, seed=29 + i * 37, cols=5, rows=1)
        z += FLOOR_H
    parapet(b, 0, 7.0, 10, 6, z, height=0.55)
    roof_plant(b, 0, 7.0, 10, 6, z, seed=29)
    entrance(b, 0, 3.9, 2.6, 0.0, face=-1)
    sign_plate(b, 0, 3.85, z * 0.60, 5.2, 1.0, face=-1)
    # Spin-up pads: dark and empty until the backend really spawns a worker.
    for i in range(8):
        col, row = i % 4, i // 4
        px, py = -6.6 + col * 4.4, -8.6 + row * 4.6
        b.m("ARGUS_Asphalt").box(px, py, 0.10, 3.4, 3.4, 0.20)
        b.m("ARGUS_Steel").box(px, py, 0.26, 2.9, 2.9, 0.12, bevel=0.03)
        b.m("ARGUS_DarkAlloy").cyl(px, py, 0.62, 1.30, 1.45, 0.60, segs=8, bevel=0.04)
        for k in range(4):
            a = (k / 4) * math.pi * 2 + math.pi / 4
            b.m("ARGUS_Steel").box(px + math.cos(a) * 1.55, py + math.sin(a) * 1.55, 0.75, 0.14, 0.14, 1.1)
        b.m("ARGUS_Cyan").box(px, py, 0.94, 1.5, 0.05, 0.05)
    return b


def build_transit_pavilion():
    """Scenery: a public transit shelter. No ARGUS capability."""
    b = Builder("transit_pavilion", "civic")
    b.m("ARGUS_Sidewalk").box(0, 0, 0.11, 14, 5.0, 0.22, bevel=0.03)
    for k in range(6):
        b.m("ARGUS_Steel").cyl(-5.6 + k * 2.24, -1.9, 1.55, 0.10, 0.12, 2.9, segs=8)
        b.m("ARGUS_Steel").cyl(-5.6 + k * 2.24, 1.9, 1.55, 0.10, 0.12, 2.9, segs=8)
    b.m("ARGUS_DarkAlloy").box(0, 0, 3.12, 13.4, 5.2, 0.24, bevel=0.04)
    b.m("ARGUS_Cyan").box(0, -2.5, 2.96, 13.0, 0.07, 0.07)
    b.m("ARGUS_BlackGlass").box(0, 2.1, 1.7, 12.6, 0.10, 2.0)
    b.m("ARGUS_WarmGlass").box(-4.4, 2.05, 1.7, 1.6, 0.06, 1.7)
    for k in range(3):
        b.m("ARGUS_Steel").box(-3.0 + k * 3.0, 0.4, 0.62, 2.2, 0.55, 0.12, bevel=0.02)
        b.m("ARGUS_Steel").box(-3.0 + k * 3.0, 0.62, 0.90, 2.2, 0.10, 0.45)
    return b


# ==========================================================================
# FAMILY F -- CLOUD / EXTERNAL
# Cantilevered glass slabs on thin columns. Deliberately unlike the city.
# ==========================================================================

def build_cloud_embassy():
    b = Builder("cloud_embassy", "cloud")
    b.m("ARGUS_Concrete").cyl(0, 0, 0.9, 11.0, 12.2, 1.8, segs=22, bevel=0.08)
    b.m("ARGUS_Sidewalk").cyl(0, 0, 1.84, 10.4, 10.4, 0.10, segs=22)
    b.m("ARGUS_Amber").cyl(0, 0, 1.92, 10.0, 10.0, 0.05, segs=22)
    z = 1.9
    # Slabs that step and cantilever alternately -- no two floors align.
    for i in range(4):
        off = (0.9 if i % 2 == 0 else -0.9)
        w = 15.0 - i * 0.8
        d = 11.0 - i * 0.5
        b.m("ARGUS_Steel").box(off, 0, z + 0.16, w, d, 0.32, bevel=0.04)
        bh = FLOOR_H - 0.32
        b.m("ARGUS_BlackGlass").box(off, 0, z + 0.32 + bh / 2, w - 0.7, d - 0.7, bh)
        for k in range(int(w / 2.0)):
            b.m("ARGUS_Steel").box(off - w / 2 + 0.6 + k * 2.0, 0, z + 0.32 + bh / 2, 0.14, d - 0.6, bh)
        b.m("ARGUS_Amber").box(off, 0, z + 0.36, w + 0.1, d + 0.1, 0.06)
        # Thin exposed columns, not a solid core.
        for sx in (-1, 1):
            b.m("ARGUS_Steel").cyl(off + sx * (w / 2 - 0.9), 0, z + FLOOR_H / 2, 0.14, 0.14, FLOOR_H, segs=8)
        z += FLOOR_H
    b.m("ARGUS_Steel").box(0, 0, z + 0.18, 13.0, 9.8, 0.36, bevel=0.04)
    b.m("ARGUS_Violet").box(0, 0, z + 0.42, 12.6, 9.4, 0.05)
    # Signal mast + the one approved data link heading toward Core.
    antenna(b, 4.6, -3.0, z + 0.36, 4.6, "ARGUS_Amber")
    b.m("ARGUS_Steel").cyl(0, 0, z + 1.2, 0.22, 0.22, 1.8, segs=8)
    b.m("ARGUS_Amber").cyl(0, 0, z + 2.2, 0.55, 0.05, 0.6, segs=12)
    entrance(b, 0, -5.6, 3.0, 1.9, face=-1, accent="ARGUS_Amber")
    sign_plate(b, 0, -7.7, 4.4, 5.6, 1.1, face=-1, accent="ARGUS_Amber")
    return b


# ==========================================================================
# FAMILY G -- UTILITY / SERVICE (scenery: )
# Street-level shopfronts and small service sheds. These are ENVIRONMENT.
# ==========================================================================

def shopfront(b, cx, cy, w, d, accent, seed, awning=True, storey2=False):
    h = FLOOR_H
    b.m("ARGUS_Concrete").box(cx, cy, 0.14, w + 0.7, d + 0.7, 0.28, bevel=0.03)
    b.m("ARGUS_Graphite").box(cx, cy, 0.28 + h / 2, w, d, h)
    # Glazed storefront with a warm interior behind it.
    b.m("ARGUS_DarkAlloy").box(cx, cy - d / 2, 0.28 + h * 0.52, w - 0.5, 0.30, h * 0.66)
    b.m("ARGUS_WarmGlass").box(cx, cy - d / 2 - 0.10, 0.28 + h * 0.52, w - 0.9, 0.10, h * 0.58)
    for k in range(max(1, int(w / 1.7))):
        b.m("ARGUS_Steel").box(cx - w / 2 + 0.7 + k * 1.7, cy - d / 2 - 0.12, 0.28 + h * 0.52, 0.10, 0.14, h * 0.58)
    b.m("ARGUS_DarkAlloy").box(cx + w * 0.34, cy - d / 2 - 0.08, 0.28 + DOOR_H / 2, 1.1, 0.14, DOOR_H)
    if awning:
        b.m(accent).box(cx, cy - d / 2 - 0.75, 0.28 + h * 0.90, w + 0.4, 1.5, 0.12, bevel=0.03)
        for sx in (-1, 1):
            b.m("ARGUS_Steel").box(cx + sx * (w / 2 - 0.2), cy - d / 2 - 0.10, 0.28 + h * 0.95, 0.07, 1.3, 0.07)
    b.m("ARGUS_DarkAlloy").box(cx, cy - d / 2 - 0.02, 0.28 + h * 0.97, w * 0.62, 0.22, 0.60)
    b.m(accent).box(cx, cy - d / 2 - 0.14, 0.28 + h * 0.97, w * 0.55, 0.05, 0.46)
    if storey2:
        b.m("ARGUS_Steel").box(cx, cy, 0.28 + h + 0.14, w + 0.5, d + 0.5, 0.28, bevel=0.03)
        b.m("ARGUS_Graphite").box(cx, cy, 0.28 + h + 0.28 + (h - 0.3) / 2, w * 0.96, d * 0.96, h - 0.3)
        window_grid(b, cx - w * 0.4, cx + w * 0.4, 0.28 + h + 0.7, 0.28 + h * 2 - 0.4,
                    cy - d * 0.48, -0.24, seed, cols=max(2, int(w / 2.0)), rows=1, lit_ratio=0.4)
        top = 0.28 + h * 2
    else:
        top = 0.28 + h
    b.m("ARGUS_Concrete").box(cx, cy, top + 0.16, w + 0.8, d + 0.8, 0.32, bevel=0.03)
    b.m("ARGUS_Steel").box(cx + w * 0.22, cy + d * 0.18, top + 0.72, 1.3, 1.1, 0.8, bevel=0.03)
    return top + 0.32


def build_shop(name, accent, seed, w=9.0, d=7.0, storey2=False, extra=None):
    b = Builder(name, "utility")
    top = shopfront(b, 0, 0, w, d, accent, seed, storey2=storey2)
    if extra:
        extra(b, top)
    return b


def _charging_extra(b, top):
    # Robot charging bays: pylons + a canopy, clearly service equipment.
    for k in range(3):
        px = -3.2 + k * 3.2
        b.m("ARGUS_Steel").box(px, -6.2, 0.75, 0.5, 0.5, 1.5, bevel=0.04)
        b.m("ARGUS_Cyan").box(px, -6.46, 1.15, 0.30, 0.05, 0.55)
        b.m("ARGUS_DarkAlloy").box(px, -6.2, 1.58, 0.7, 0.7, 0.16, bevel=0.03)
        b.m("ARGUS_Sidewalk").box(px, -7.4, 0.06, 1.8, 2.0, 0.12)
    b.m("ARGUS_Steel").box(0, -6.9, 3.1, 11.0, 3.4, 0.18, bevel=0.03)
    for sx in (-1, 1):
        b.m("ARGUS_Steel").cyl(sx * 5.0, -6.9, 1.55, 0.11, 0.13, 3.1, segs=8)
    b.m("ARGUS_Cyan").box(0, -8.5, 2.96, 10.6, 0.06, 0.06)


def _depot_extra(b, top):
    # Parts depot yard: crates and a small gantry.
    for k in range(5):
        px = -4.0 + (k % 3) * 4.0
        py = -6.6 - (k // 3) * 2.6
        b.m("ARGUS_Steel").box(px, py, 0.55, 1.8, 1.6, 1.1, bevel=0.04)
        b.m("ARGUS_Amber").box(px, py - 0.82, 0.8, 0.9, 0.04, 0.22)
    for sx in (-1, 1):
        b.m("ARGUS_Steel").cyl(sx * 5.4, -7.6, 1.85, 0.12, 0.14, 3.7, segs=8)
    b.m("ARGUS_Steel").box(0, -7.6, 3.75, 11.4, 0.30, 0.30, bevel=0.03)
    b.m("ARGUS_DarkAlloy").box(1.6, -7.6, 3.35, 0.9, 0.9, 0.5, bevel=0.03)


def build_office_block(name, floors, w, d, seed, accent="ARGUS_Cyan", family="utility"):
    """Generic mixed-use scenery block -- fills a city block so the campus is
    surrounded by a city, not by empty ground. ENVIRONMENT only."""
    b = Builder(name, family)
    z = 0.0
    style = int(rnd(seed) * 3)
    for i in range(floors):
        if style == 0:
            b.m("ARGUS_Concrete").box(0, 0, z + 0.15, w + 0.6, d + 0.6, 0.30, bevel=0.03)
        else:
            b.m("ARGUS_Steel").box(0, 0, z + 0.13, w + 0.25, d + 0.25, 0.26, bevel=0.02)
        bh = FLOOR_H - 0.30
        b.m("ARGUS_Graphite").box(0, 0, z + 0.30 + bh / 2, w, d, bh)
        cols = max(2, int(w / (1.7 if style == 1 else 2.3)))
        for sy, yy in ((-1, -d / 2), (1, d / 2)):
            window_grid(b, -w / 2 + 0.5, w / 2 - 0.5, z + 0.72, z + 0.30 + bh - 0.14, yy, sy * -0.24,
                        seed + i * 59 + (0 if sy < 0 else 271), cols=cols, rows=1,
                        lit_ratio=0.24 + rnd(seed + i) * 0.14)
        for sx, xx in ((-1, -w / 2), (1, w / 2)):
            _side_windows(b, xx, sx, -d / 2 + 0.5, d / 2 - 0.5, z + 0.72, z + 0.30 + bh - 0.14,
                          seed + i * 41 + (0 if sx < 0 else 617))
        z += FLOOR_H
    if style == 2:
        corner_columns(b, 0, 0, w, d, 0, z, size=0.34)
    parapet(b, 0, 0, w, d, z, height=0.55 + rnd(seed + 3) * 0.4)
    roof_plant(b, 0, 0, w, d, z, seed, accent)
    if rnd(seed + 9) > 0.55:
        antenna(b, w * 0.24, -d * 0.2, z, 2.2 + rnd(seed + 5) * 1.8, accent, dish=rnd(seed + 6) > 0.5)
    entrance(b, 0, -d / 2 - 0.2, 2.2, 0.0, face=-1, accent=accent)
    return b


def build_utility_shed(name, seed, w=7.0, d=6.0):
    b = Builder(name, "utility")
    b.m("ARGUS_Concrete").box(0, 0, 0.14, w + 0.8, d + 0.8, 0.28, bevel=0.03)
    b.m("ARGUS_Graphite").box(0, 0, 1.75, w, d, 3.2)
    b.m("ARGUS_DarkAlloy").box(0, 0, 3.48, w + 0.7, d + 0.7, 0.26, bevel=0.03)
    for k in range(4):
        b.m("ARGUS_Steel").box(0, -d / 2 + (k + 0.5) * (d / 4), 3.74, w * 0.85, 0.22, 0.26)
    b.m("ARGUS_DarkAlloy").box(0, -d / 2 - 0.06, 1.25, 2.6, 0.16, 2.3)
    for k in range(5):
        b.m("ARGUS_Steel").box(0, -d / 2 - 0.14, 0.35 + k * 0.45, 2.5, 0.05, 0.20)
    b.m("ARGUS_Steel").box(w * 0.3, d * 0.2, 4.05, 1.5, 1.3, 0.9, bevel=0.03)
    b.m("ARGUS_Cyan").box(-w * 0.3, -d / 2 - 0.1, 2.75, 1.2, 0.05, 0.18)
    b.m("ARGUS_Steel").cyl(-w * 0.32, d * 0.3, 4.3, 0.26, 0.30, 1.4, segs=8)
    return b


# ==========================================================================
# FAMILY H -- RESIDENTIAL / LIVING
# Shallow floor plates, deep balconies, warm interiors, a planted roof.
# Reads completely differently from an office: the light is warm, the
# openings are wide, and the facade is broken up by projecting slabs.
# ==========================================================================

def family_residential(b, floors, w, d, seed, accent="ARGUS_SoftBlue"):
    z = 0.0
    for i in range(floors):
        b.m("ARGUS_Concrete").box(0, 0, z + 0.15, w + 0.5, d + 0.5, 0.30, bevel=0.03)
        bh = FLOOR_H - 0.30
        b.m("ARGUS_Graphite").box(0, 0, z + 0.30 + bh / 2, w, d, bh)
        # Wide warm windows -- homes, not offices: far more lit than dark.
        for sy, yy in ((-1, -d / 2), (1, d / 2)):
            window_grid(b, -w / 2 + 0.6, w / 2 - 0.6, z + 0.72, z + 0.30 + bh - 0.22, yy, sy * -0.24,
                        seed + i * 83 + (0 if sy < 0 else 359),
                        cols=max(2, int(w / 2.6)), rows=1, lit_ratio=0.62, cool_ratio=0.04)
        # Projecting balcony slabs on the long face, alternating each floor.
        if i > 0:
            by = (-d / 2 - 0.85) if i % 2 == 0 else (d / 2 + 0.85)
            b.m("ARGUS_Concrete").box(0, by, z + 0.32, w * 0.82, 1.7, 0.18, bevel=0.03)
            b.m("ARGUS_Steel").box(0, by - (0.8 if by < 0 else -0.8), z + 0.85, w * 0.82, 0.07, 0.07)
            for k in range(int(w * 0.82 / 0.6)):
                b.m("ARGUS_Steel").box(-w * 0.41 + 0.3 + k * 0.6, by - (0.8 if by < 0 else -0.8),
                                       z + 0.60, 0.045, 0.045, 0.50)
        z += FLOOR_H
    # Planted roof terrace.
    b.m("ARGUS_Concrete").box(0, 0, z + 0.16, w + 0.7, d + 0.7, 0.32, bevel=0.04)
    b.m("ARGUS_Sidewalk").box(0, 0, z + 0.36, w * 0.9, d * 0.9, 0.08)
    parapet(b, 0, 0, w + 0.5, d + 0.5, z + 0.32, height=0.95, thickness=0.22)
    for k in range(4):
        px = -w * 0.3 + k * (w * 0.2)
        b.m("ARGUS_Concrete").box(px, d * 0.25, z + 0.62, 1.1, 1.1, 0.44, bevel=0.03)
        b.m("ARGUS_Foliage").cyl(px, d * 0.25, z + 1.24, 0.18, 0.78, 1.25, segs=6)
    b.m(accent).box(0, -d / 2 - 0.28, z + 0.30, w * 0.9, 0.06, 0.06)
    return z + 0.32


def build_residential_block(name, floors, w, d, seed, accent="ARGUS_SoftBlue"):
    b = Builder(name, "residential")
    top = family_residential(b, floors, w, d, seed, accent)
    entrance(b, 0, -d / 2 - 0.2, 2.6, 0.0, face=-1, accent=accent)
    # Ground-floor lobby glazing either side of the door.
    for sx in (-1, 1):
        b.m("ARGUS_WarmGlass").box(sx * (w * 0.30), -d / 2 - 0.06, 1.35, w * 0.22, 0.08, 1.9)
    sign_plate(b, 0, -d / 2 - 0.16, top * 0.52, 3.2, 0.7, face=-1, accent=accent)
    return b


def build_lab_block(name, seed, w=11.0, d=9.0, floors=3):
    """Research lab: an academic frame wrapped around a glazed clean-room
    volume, with roof extract stacks."""
    b = Builder(name, "academic")
    top = family_academic(b, floors, w, d, seed, accent="ARGUS_Violet", second="ARGUS_Cyan")
    b.m("ARGUS_Steel").box(0, d * 0.10, top + 1.2, w * 0.52, d * 0.5, 2.4, bevel=0.05)
    b.m("ARGUS_CoolGlass").box(0, d * 0.10 - d * 0.26, top + 1.2, w * 0.44, 0.10, 1.7)
    for k in range(3):
        b.m("ARGUS_Steel").cyl(-w * 0.28 + k * (w * 0.28), -d * 0.28, top + 1.0, 0.28, 0.34, 2.0, segs=8)
        b.m("ARGUS_Violet").cyl(-w * 0.28 + k * (w * 0.28), -d * 0.28, top + 2.06, 0.26, 0.26, 0.10, segs=8)
    entrance(b, 0, -d / 2 - 0.2, 2.6, 0.0, face=-1, accent="ARGUS_Violet")
    sign_plate(b, 0, -d / 2 - 0.16, top * 0.58, 4.2, 0.9, face=-1, accent="ARGUS_Violet")
    return b


# ==========================================================================
# Build driver
# ==========================================================================

# (name, builder, kind) -- kind is carried into the manifest so the runtime
# and the scenery gate can tell an operational ARGUS facility from scenery.
BUILDINGS = [
    ("core_tower", build_core_tower, "operational", "corporate"),
    ("agent_hq", build_agent_hq, "operational", "corporate"),
    ("academy", build_academy, "operational", "academic"),
    ("research_annex", build_research_annex, "operational", "academic"),
    ("security_command", build_security_command, "operational", "hardened"),
    ("threat_lab", lambda: build_hardened_annex("threat_lab", 8.4, 7.0, 2, 101, "ARGUS_Amber"), "operational", "hardened"),
    ("forensics_center", lambda: build_hardened_annex("forensics_center", 8.0, 7.4, 3, 113, "ARGUS_Cyan"), "operational", "hardened"),
    ("response_center", lambda: build_hardened_annex("response_center", 8.4, 7.0, 2, 127, "ARGUS_Red"), "operational", "hardened"),
    ("operations_center", lambda: build_hardened_annex("operations_center", 13.0, 9.0, 4, 139, "ARGUS_Cyan"), "operational", "hardened"),
    ("model_compute", build_model_compute, "operational", "industrial"),
    ("capability_center", build_capability_center, "operational", "industrial"),
    ("data_vault", build_data_vault, "operational", "industrial"),
    ("verification_institute", build_verification_institute, "operational", "civic"),
    ("policy_gate", build_policy_gate, "operational", "civic"),
    ("specialist_yard", build_specialist_yard, "operational", "civic"),
    ("cloud_embassy", build_cloud_embassy, "operational", "cloud"),
    # --- scenery ----------------------------------------------------------
    ("transit_pavilion", build_transit_pavilion, "scenery", "civic"),
    ("shop_charging", lambda: build_shop("shop_charging", "ARGUS_Cyan", 301, 9.0, 7.0, False, _charging_extra), "scenery", "utility"),
    ("shop_parts", lambda: build_shop("shop_parts", "ARGUS_Amber", 307, 9.5, 7.5, True, _depot_extra), "scenery", "utility"),
    ("shop_cafe", lambda: build_shop("shop_cafe", "ARGUS_WarmGlass", 311, 8.0, 6.5, True), "scenery", "utility"),
    ("shop_maintenance", lambda: build_shop("shop_maintenance", "ARGUS_Cyan", 313, 10.0, 7.0, False), "scenery", "utility"),
    ("shop_supply", lambda: build_shop("shop_supply", "ARGUS_Violet", 317, 8.6, 7.0, True), "scenery", "utility"),
    ("utility_shed_a", lambda: build_utility_shed("utility_shed_a", 401), "scenery", "utility"),
    ("utility_shed_b", lambda: build_utility_shed("utility_shed_b", 409, 8.5, 6.5), "scenery", "utility"),
    ("office_block_a", lambda: build_office_block("office_block_a", 6, 12.0, 10.0, 501), "scenery", "utility"),
    ("office_block_b", lambda: build_office_block("office_block_b", 9, 9.5, 9.5, 509, "ARGUS_Violet"), "scenery", "utility"),
    ("office_block_c", lambda: build_office_block("office_block_c", 4, 14.0, 9.0, 521), "scenery", "utility"),
    ("office_block_d", lambda: build_office_block("office_block_d", 11, 8.5, 8.0, 523, "ARGUS_Amber"), "scenery", "utility"),
    ("office_block_e", lambda: build_office_block("office_block_e", 7, 11.0, 8.5, 541), "scenery", "utility"),
    # --- residential / living quarter (scenery: no backend agent lives here) ---
    ("residential_a", lambda: build_residential_block("residential_a", 5, 12.0, 9.0, 601), "scenery", "residential"),
    ("residential_b", lambda: build_residential_block("residential_b", 7, 10.0, 8.5, 607), "scenery", "residential"),
    ("residential_c", lambda: build_residential_block("residential_c", 4, 13.5, 9.5, 613, "ARGUS_WarmGlass"), "scenery", "residential"),
    ("residential_tower", lambda: build_residential_block("residential_tower", 10, 9.5, 9.0, 619), "scenery", "residential"),
    ("lab_block_a", lambda: build_lab_block("lab_block_a", 631), "operational", "academic"),
    ("lab_block_b", lambda: build_lab_block("lab_block_b", 641, 9.5, 8.0, 4), "operational", "academic"),
]


def build_all_buildings():
    for name, fn, kind, family in BUILDINGS:
        reset_scene()
        col = new_collection(name)
        builder = fn()
        objs = builder.emit(col)
        export_glb(objs, "buildings", name, extras={"kind": kind, "family": family})


if __name__ == "__main__":
    from argus_kit import write_manifest
    build_all_buildings()
    write_manifest()
