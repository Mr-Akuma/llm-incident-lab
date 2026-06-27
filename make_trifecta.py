"""The Lethal Trifecta venn -> docs/img/trifecta.png"""
from PIL import Image, ImageDraw, ImageFont

FB = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 26)
F  = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 21)
FS = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 18)

W, H = 1100, 880
base = Image.new("RGB", (W, H), (24, 27, 33))
d = ImageDraw.Draw(base)
d.text((40, 30), "The Lethal Trifecta", font=FB, fill=(230, 233, 239))
d.text((40, 72), "an agent is dangerous only where all three overlap",
       font=FS, fill=(140, 148, 160))

# three translucent circles
layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
ld = ImageDraw.Draw(layer)
R = 250
cx, cy = W // 2, 470
import math
centers = [(cx, cy - 150), (cx - 170, cy + 130), (cx + 170, cy + 130)]
cols = [(224, 108, 117, 90), (86, 182, 194, 90), (152, 195, 121, 90)]
for (x, y), c in zip(centers, cols):
    ld.ellipse([x - R, y - R, x + R, y + R], fill=c, outline=c[:3] + (255,), width=3)
base.paste(Image.alpha_composite(base.convert("RGBA"), layer).convert("RGB"), (0, 0))
d = ImageDraw.Draw(base)


def label(x, y, lines, color):
    for i, ln in enumerate(lines):
        d.text((x - d.textlength(ln, font=F) / 2, y + i * 26), ln, font=F, fill=color)


label(cx, cy - 320, ["1. ACCESS TO", "PRIVATE DATA"], (240, 200, 205))
label(cx - 320, cy + 200, ["2. EXPOSED TO", "UNTRUSTED CONTENT"], (190, 232, 240))
label(cx + 320, cy + 200, ["3. CAN ACT /", "EXFILTRATE"], (205, 235, 180))

# center
d.text((cx - d.textlength("PWNABLE", font=FB) / 2, cy + 30), "PWNABLE",
       font=FB, fill=(255, 255, 255))

# footnotes mapping to the lab
y = 800
d.text((40, y), "our lab: prod secrets/other tenants  x  pasted ticket  x  delete/rotate/shell",
       font=FS, fill=(140, 148, 160))
base.save("docs/img/trifecta.png")
print("wrote docs/img/trifecta.png", base.size)
