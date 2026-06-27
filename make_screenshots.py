"""
Render real terminal screenshots of the lab run (for the blog).

Runs run_incident.py, captures its ANSI output, and paints it onto a dark
terminal canvas with window chrome. Produces:
  docs/img/lab_vulnerable.png   (the attack succeeding)
  docs/img/lab_patched.png      (the attack blocked)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

FONT = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 22)
BOLD = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 22)

BG = (30, 33, 39)
CHROME = (22, 24, 29)
DEFAULT = (216, 222, 233)
PALETTE = {
    "31": (224, 108, 117),   # red
    "32": (152, 195, 121),   # green
    "33": (229, 192, 123),   # yellow
    "36": (86, 182, 194),    # cyan
}
DIMC = (122, 129, 140)

ANSI = re.compile(r"\x1b\[([0-9;]*)m")
PAD = 28
LINE_H = 30
CHAR_W = FONT.getbbox("M")[2]


def tokenize(line: str):
    """Yield (text, color) runs, interpreting the small set of ANSI codes used."""
    runs, color, dim, pos = [], DEFAULT, False, 0
    for m in ANSI.finditer(line):
        if m.start() > pos:
            runs.append((line[pos:m.start()], DIMC if dim else color))
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                color, dim = DEFAULT, False
            elif code == "2":
                dim = True
            elif code == "1":
                pass
            elif code in PALETTE:
                color, dim = PALETTE[code], False
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], DIMC if dim else color))
    return runs


def wrap(runs, max_chars):
    """Soft-wrap a list of (text,color) runs to max_chars per visual line."""
    out, cur, n = [], [], 0
    for text, color in runs:
        while text:
            room = max_chars - n
            if len(text) <= room:
                cur.append((text, color)); n += len(text); text = ""
            else:
                cur.append((text[:room], color)); out.append(cur)
                cur, n, text = [], 0, text[room:]
    out.append(cur)
    return out


def render(lines: list[str], path: str, title: str, highlight=None, note=None):
    max_chars = 92
    vlines = []
    for raw in lines:
        for vl in wrap(tokenize(raw.rstrip("\n")), max_chars):
            vlines.append(vl)

    extra = LINE_H + 14 if note else 0
    w = PAD * 2 + max_chars * CHAR_W
    h = 46 + PAD + len(vlines) * LINE_H + PAD + extra
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)

    # window chrome
    d.rectangle([0, 0, w, 46], fill=CHROME)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 26, 16, 32 + i * 26, 30], fill=c)
    tw = d.textlength(title, font=FONT)
    d.text(((w - tw) / 2, 12), title, font=FONT, fill=DIMC)

    y = 46 + PAD
    for vl in vlines:
        linetext = "".join(t for t, _ in vl)
        if highlight and highlight in linetext:
            d.rounded_rectangle([PAD - 8, y - 4, w - PAD + 8, y + LINE_H - 4],
                                radius=6, outline=(224, 108, 117), width=2,
                                fill=(50, 24, 28))
        x = PAD
        for text, color in vl:
            d.text((x, y), text, font=FONT, fill=color)
            x += len(text) * CHAR_W
        y += LINE_H
    if note:
        d.text((PAD, y + 8), note, font=FONT, fill=(224, 108, 117))
    img.save(path)
    print("wrote", path, img.size)


def capture(extra_args=None):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    cmd = [sys.executable, "run_incident.py"] + (extra_args or [])
    return subprocess.run(cmd, capture_output=True, text=True, env=env).stdout


def main():
    os.makedirs("docs/img", exist_ok=True)
    lines = capture().splitlines()

    # attack scenario: slice out the VULNERABLE and PATCHED sections
    vstart = next(i for i, l in enumerate(lines) if "VULNERABLE harness" in l)
    pstart = next(i for i, l in enumerate(lines) if "PATCHED harness" in l)
    render(lines[vstart:pstart - 1], "docs/img/lab_vulnerable.png",
           "DevOpsCopilot  -  vulnerable run")
    render(lines[vstart:pstart - 1], "docs/img/lab_vulnerable_annotated.png",
           "DevOpsCopilot  -  vulnerable run",
           highlight="approved by LLM judge",
           note="^ the injected 'pre-approved' text fooled the LLM approval judge -> privileged tools ran")
    render(lines[pstart:], "docs/img/lab_patched.png",
           "DevOpsCopilot  -  patched run")

    # benign baseline (the agent being a normal helpful tool)
    bl = capture(["--scenario", "benign"]).splitlines()
    bvs = next(i for i, l in enumerate(bl) if "VULNERABLE harness" in l)
    bps = next(i for i, l in enumerate(bl) if "PATCHED harness" in l)
    render(bl[bvs:bps - 1], "docs/img/lab_benign.png",
           "DevOpsCopilot  -  normal request (no attack)")

    # exfil scenario (markdown-image exfiltration), vulnerable side
    el = capture(["--scenario", "exfil"]).splitlines()
    evs = next(i for i, l in enumerate(el) if "VULNERABLE harness" in l)
    eps = next(i for i, l in enumerate(el) if "PATCHED harness" in l)
    render(el[evs:eps - 1], "docs/img/lab_exfil.png",
           "DevOpsCopilot  -  data exfiltration via markdown image")


if __name__ == "__main__":
    main()
