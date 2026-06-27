"""L x I severity matrix with this incident plotted -> docs/img/severity.png"""
from PIL import Image, ImageDraw, ImageFont

FB = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 30)
F  = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 20)
FS = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 17)

W, H = 760, 700
img = Image.new("RGB", (W, H), (11, 13, 18))
d = ImageDraw.Draw(img)

d.text((40, 28), "Risk = Likelihood x Impact", font=FB, fill=(255, 255, 255))
d.text((42, 70), "where this incident lands", font=FS, fill=(154, 163, 178))

CELL = 96
ox, oy = 150, 120          # grid origin (top-left of the 5x5)

def colour(score):
    if score <= 4:  return (60, 120, 70)
    if score <= 9:  return (130, 150, 60)
    if score <= 14: return (190, 160, 60)
    if score <= 19: return (200, 110, 60)
    return (200, 70, 80)

# rows: likelihood 5 (top) .. 1 (bottom); cols: impact 1 (left) .. 5 (right)
for r in range(5):
    likelihood = 5 - r
    for c in range(5):
        impact = c + 1
        x, y = ox + c * CELL, oy + r * CELL
        score = likelihood * impact
        d.rounded_rectangle([x + 4, y + 4, x + CELL - 4, y + CELL - 4],
                            radius=10, fill=colour(score))
        d.text((x + CELL / 2, y + CELL / 2), str(score), font=F,
               fill=(20, 22, 26), anchor="mm")

# axes
d.text((ox + 5 * CELL / 2, oy + 5 * CELL + 34), "Impact  ->", font=F,
       fill=(216, 222, 233), anchor="mm")
for c in range(5):
    d.text((ox + c * CELL + CELL / 2, oy + 5 * CELL + 8), str(c + 1), font=FS,
           fill=(154, 163, 178), anchor="mm")
# y axis label (vertical-ish, stacked)
d.text((54, oy + 5 * CELL / 2), "Likelihood", font=F, fill=(216, 222, 233), anchor="mm")
for r in range(5):
    d.text((ox - 18, oy + r * CELL + CELL / 2), str(5 - r), font=FS,
           fill=(154, 163, 178), anchor="mm")

# marker: impact 5, likelihood 4 -> col 4 (0-idx), row 1 (0-idx for L=4)
mc, mr = 4, 1
mx = ox + mc * CELL + CELL / 2
my = oy + mr * CELL + CELL / 2
d.ellipse([mx - 22, my - 22, mx + 22, my + 22], outline=(255, 255, 255), width=4)
d.text((ox + 5 * CELL + 0, oy - 6), "", font=FS, fill=(255, 255, 255))

# legend / callout
ly = oy + 5 * CELL + 70
d.text((40, ly), "This incident:  Likelihood 4  x  Impact 5  =  20  ->  CRITICAL",
       font=F, fill=(255, 255, 255))
d.text((40, ly + 32),
       "Irreversible: confidentiality + integrity + availability, in one chat message.",
       font=FS, fill=(154, 163, 178))

img.save("docs/img/severity.png")
print("wrote docs/img/severity.png", img.size)
