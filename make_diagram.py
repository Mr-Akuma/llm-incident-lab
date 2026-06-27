"""Draw the architecture + attack-chain hero image: docs/img/architecture.png"""
from PIL import Image, ImageDraw, ImageFont

F   = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 24)
FB  = ImageFont.truetype("C:/Windows/Fonts/CascadiaCodepl.ttf", 26) if False else \
      ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 26)
FS  = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 19)

BG   = (24, 27, 33)
INK  = (216, 222, 233)
DIM  = (130, 138, 150)
BLUE = (86, 156, 214)
RED  = (224, 108, 117)
GRN  = (152, 195, 121)
YEL  = (229, 192, 123)
CARD = (36, 40, 48)

W, H = 1240, 760
img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)


def box(x, y, w, h, label, sub, edge):
    d.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=CARD, outline=edge, width=3)
    tw = d.textlength(label, font=FB)
    d.text((x + (w - tw) / 2, y + 20), label, font=FB, fill=INK)
    if sub:
        sw = d.textlength(sub, font=FS)
        d.text((x + (w - sw) / 2, y + 56), sub, font=FS, fill=DIM)


def arrow(x1, y1, x2, y2, color, label=None):
    d.line([x1, y1, x2, y2], fill=color, width=3)
    import math
    a = math.atan2(y2 - y1, x2 - x1)
    for s in (2.6, -2.6):
        d.line([x2, y2, x2 - 14 * math.cos(a + s / 6 + (0.4 if s > 0 else -0.4)),
                y2 - 14 * math.sin(a + (0.4 if s > 0 else -0.4))], fill=color, width=3)
    if label:
        d.text(((x1 + x2) / 2 - d.textlength(label, font=FS) / 2, (y1 + y2) / 2 - 28),
               label, font=FS, fill=color)


d.text((40, 30), "From Chat Box to Cloud Admin", font=FB, fill=INK)
d.text((40, 70), "the harness is the trust boundary -- not the model", font=FS, fill=DIM)

box(40, 150, 300, 110, "USER MESSAGE", "untrusted (injected)", RED)
box(470, 150, 300, 110, "HARNESS", "the gate", YEL)
box(900, 150, 300, 110, "CLOUD", "real side effects", BLUE)
box(470, 360, 300, 110, "MODEL", "chooses tools", BLUE)

arrow(340, 205, 470, 205, RED, "prompt")
arrow(770, 205, 900, 205, YEL, "tool calls")
arrow(620, 360, 620, 260, BLUE, "requests")

# attack chain
y = 560
d.text((40, y - 46), "the chain (3 Atlas domains):", font=F, fill=INK)
steps = [("D", "tool-choice\nmanipulation", RED),
         ("E", "approval-gate\nbypass", RED),
         ("F", "broken\nauthorization", RED)]
x = 40
for letter, txt, c in steps:
    d.rounded_rectangle([x, y, x + 300, y + 130], radius=12, fill=CARD, outline=c, width=3)
    d.ellipse([x + 18, y + 20, x + 70, y + 72], outline=c, width=3)
    d.text((x + 34, y + 28), letter, font=FB, fill=c)
    for i, line in enumerate(txt.split("\n")):
        d.text((x + 90, y + 28 + i * 30), line, font=FS, fill=INK)
    if x < 600:
        arrow(x + 300, y + 65, x + 360, y + 65, DIM)
    x += 360

img.save("docs/img/architecture.png")
print("wrote docs/img/architecture.png", img.size)
