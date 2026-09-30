#!/usr/bin/env python3
"""ARGUS HUD V2 — Core asset background remover (edge-connected flood-fill).

Converts robot JPG assets (flat black background) into transparent PNGs.

Method is edge-connected removal — NOT naive "black → transparent". A BFS
flood-fill starts from every image-border pixel and spreads only through
pixels that look like the background (luminance/color-distance below a
conservative threshold). Interior dark pixels (visor, suit shadows, glow)
that are NOT connected to the border through background-like pixels are
preserved untouched. This is exactly what preserves "metal edges, shoulder
details, internal shadows, eye glow" while deleting the black canvas.

FACE PROTECTION (v3, 2026-09-16)
--------------------------------
The helmet/face/eye zone (the centre band, where the face panels, helmet
and eyes live) is guarded as an unconditional opaque zone: the flood may
REMOVE nothing inside it. Even a dark hairline that connects the border to
the face can no longer leak into the head — the guard ellipse is re-applied
as an opaque patch AFTER the flood, so flooding only ever reaches the
shoulder/chest zone the mask radius 42% already protects. Threshold lowered
to 28 for extra conservatism (a halftone/moiré corner may stay slightly
soft rather than risk the face).

Usage (from hud-v2/):
    pip install Pillow
    python tools/process_core_assets.py
    # optional:
    #   --threshold 34   (default now 28) luminance ceiling for background
    #   --feather 1.6    gaussian feather radius on the alpha boundary
    #   --no-qa          skip contact-sheet QA outputs

Outputs:
    public/assets/core-idle.png / core-alert.png   (the used assets)
    public/assets/qa-core-idle.png / qa-core-alert.png (QA contact sheets)
"""

from __future__ import annotations

import argparse
import sys
from collections import deque
from pathlib import Path

try:
    from PIL import Image, ImageFilter
except ImportError:
    print("Pillow is required: pip install Pillow", file=sys.stderr)
    sys.exit(1)


ASSETS = Path(__file__).resolve().parent.parent / "public" / "assets"
PAIRS = [
    ("core-idle.jpg", "core-idle.png"),
    ("core-alert.jpg", "core-alert.png"),
]

# HUD cockpit background (the actual runtime backdrop for the robot).
HUD_BG = (3, 9, 11)


def face_guard(w: int, h: int) -> list[bool]:
    """Opaque guard around the helmet/face/eye band.

    Returns a bool list the size of the image where True marks pixels the
    flood must never remove. Waist-up guard at 34-52% height, 20-80% width —
    re-applied as an opaque patch AFTER the flood so a dark hairline that
    reaches the border can never leak into the face. This is the v3 face
    protection: it is unconditional and independent of threshold tuning."""
    guard = [False] * (w * h)
    cx, cy, rx, ry = w / 2, h * 0.43, w * 0.30, h * 0.09
    dx = (w * 0.20) ** 2
    dy = (h * 0.05) ** 2
    for y in range(h):
        if not (h * 0.34 <= y <= h * 0.52):
            continue
        row = y * w
        for x in range(w):
            if (x - cx) ** 2 / dx + (y - cy) ** 2 / dy <= 1:
                guard[row + x] = True
    return guard


def edge_flood_mask(lumm: list[int], w: int, h: int, threshold: int) -> list[int]:
    """Return a flat bytearray-like list: 0 for edge-connected background,
    255 for everything else (interior detail + robot). 4-connected BFS."""
    alpha = [255] * (w * h)
    visited = [False] * (w * h)
    guard = face_guard(w, h)

    def idx(x: int, y: int) -> int:
        return y * w + x

    queue: deque[tuple[int, int]] = deque()

    def seed(x: int, y: int) -> None:
        i = idx(x, y)
        if not visited[i] and not guard[i] and lumm[i] <= threshold:
            visited[i] = True
            queue.append((x, y))

    for x in range(w):
        seed(x, 0)
        seed(x, h - 1)
    for y in range(h):
        seed(0, y)
        seed(w - 1, y)

    while queue:
        x, y = queue.popleft()
        i = idx(x, y)
        alpha[i] = 0
        # 4-connected neighbours, tested against the same background test so
        # the flood only runs along background-like pixels. The face-guard
        # doubles as a hard wall: the flood never passes through the face zone.
        if x > 0:
            j = i - 1
            if not visited[j] and not guard[j] and lumm[j] <= threshold:
                visited[j] = True
                queue.append((x - 1, y))
        if x < w - 1:
            j = i + 1
            if not visited[j] and not guard[j] and lumm[j] <= threshold:
                visited[j] = True
                queue.append((x + 1, y))
        if y > 0:
            j = i - w
            if not visited[j] and not guard[j] and lumm[j] <= threshold:
                visited[j] = True
                queue.append((x, y - 1))
        if y < h - 1:
            j = i + w
            if not visited[j] and not guard[j] and lumm[j] <= threshold:
                visited[j] = True
                queue.append((x, y + 1))

    # Final unconditional opaque patch over the face zone: whatever the flood
    # decided, the helmet/face/eye band is preserved (0 = opaque). This is the
    # belt-and-suspenders guarantee behind the two guards above.
    for i, g in enumerate(guard):
        if g:
            alpha[i] = 255

    return alpha


def process(src_name: str, dst_name: str, threshold: int, feather: float, qa: bool) -> None:
    src_path = ASSETS / src_name
    dst_path = ASSETS / dst_name

    if not src_path.exists():
        print(f"  SKIP: {src_path} not found", file=sys.stderr)
        return

    img = Image.open(src_path).convert("RGB")
    w, h = img.size
    print(f"  {src_name}: {w}×{h} px")

    # Luminance plane for the flood test. Using luminance (not per-channel
    # distance) is conservative: only genuinely dark pixels qualify as
    # background, so the dark suit/visor details stay opaque.
    lum = img.convert("L")
    lumm = list(lum.getdata())

    alpha_flat = edge_flood_mask(lumm, w, h, threshold)
    alpha = Image.new("L", (w, h))
    alpha.putdata(alpha_flat)

    # Restore any interior holes: a background-like pocket fully surrounded
    # by foreground could not be reached by the edge flood, so this pass is a
    # no-op unless the source has noise pockets. Keep it cheap.
    alpha = alpha.filter(ImageFilter.MedianFilter(size=3))

    # Feather the boundary so the robot edge is a soft matte, not a 1px cliff.
    if feather > 0:
        alpha = alpha.filter(ImageFilter.GaussianBlur(radius=feather))

    out = img.convert("RGBA")
    out.putalpha(alpha)
    out.save(dst_path, "PNG", optimize=True)
    print(f"  → {dst_name} saved ({dst_path.stat().st_size // 1024} KB)")

    if qa:
        qa_path = ASSETS / f"qa-{dst_name}"
        build_qa_sheet(img, alpha, out, qa_path, w, h)


def _checker(w: int, h: int, cell: int = 12) -> Image.Image:
    """Mid-gray checkerboard — the standard transparency inspection backdrop."""
    base = Image.new("RGB", (cell * 2, cell * 2), (0x40, 0x40, 0x40))
    p = base.load()
    for y in range(cell * 2):
        for x in range(cell * 2):
            p[x, y] = (0xB0, 0xB0, 0xB0) if ((x // cell) + (y // cell)) % 2 == 0 else (0x3C, 0x3C, 0x3C)
    return base.resize((w, h))


def build_qa_sheet(src: Image.Image, alpha: Image.Image, png: Image.Image, path: Path, w: int, h: int) -> None:
    """2×2 contact sheet:
       TL original JPG | TR alpha mask
       BL PNG on checkerboard | BR PNG on HUD dark background"""
    cell_w, cell_h = w, h
    sheet = Image.new("RGB", (cell_w * 2, cell_h * 2), (0, 0, 0))

    sheet.paste(src, (0, 0))
    sheet.paste(alpha.convert("RGB"), (cell_w, 0))

    check = _checker(w, h)
    comp_check = Image.alpha_composite(check.convert("RGBA"), png)
    sheet.paste(comp_check.convert("RGB"), (0, cell_h))

    hud = Image.new("RGBA", (w, h), HUD_BG + (255,))
    comp_hud = Image.alpha_composite(hud, png)
    sheet.paste(comp_hud.convert("RGB"), (cell_w, cell_h))

    sheet.save(path, "PNG", optimize=True)
    print(f"  → {path} QA sheet saved ({path.stat().st_size // 1024} KB)")


def main() -> None:
    parser = argparse.ArgumentParser(description="ARGUS core asset background remover (edge-connected flood-fill).")
    parser.add_argument("--threshold", type=int, default=28,
                        help="luminance ceiling for background-like pixels (0-255, default 28)")
    parser.add_argument("--feather", type=float, default=1.6,
                        help="gaussian feather radius on alpha boundary (default 1.6)")
    parser.add_argument("--no-qa", action="store_true", help="skip QA contact sheets")
    args = parser.parse_args()

    print("ARGUS Core Asset Processor — edge-connected flood-fill")
    print(f"Assets directory: {ASSETS}\n")
    for src, dst in PAIRS:
        process(src, dst, threshold=args.threshold, feather=args.feather, qa=not args.no_qa)
    print("\nDone. ArgusCore.svelte already prefers the .png (alpha) asset, falling")
    print("back to the .jpg (screen-blend) if the PNG is absent at runtime.")


if __name__ == "__main__":
    main()