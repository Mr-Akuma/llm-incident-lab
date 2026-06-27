"""Gate decision flow: vulnerable vs patched. -> docs/img/gate_flow.png"""
from PIL import Image, ImageDraw, ImageFont

FB = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 23)
F  = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 19)
FS = ImageFont.truetype("C:/Windows/Fonts/CascadiaCode.ttf", 17)

BG=(24,27,33); CARD=(36,40,48); INK=(230,233,239); DIM=(140,148,160)
RED=(224,108,117); GRN=(152,195,121); YEL=(229,192,123); CYN=(86,182,194)

W,H=1240,720
img=Image.new("RGB",(W,H),BG); d=ImageDraw.Draw(img)

def node(cx,y,w,h,text,edge,fill=CARD,font=F):
    x=cx-w//2
    d.rounded_rectangle([x,y,x+w,y+h],radius=12,fill=fill,outline=edge,width=3)
    lines=text.split("\n")
    ty=y+(h-len(lines)*24)//2
    for ln in lines:
        d.text((cx-d.textlength(ln,font=font)//2,ty),ln,font=font,fill=INK); ty+=24

def arr(x1,y1,x2,y2,c=DIM,label=None):
    import math
    d.line([x1,y1,x2,y2],fill=c,width=3)
    a=math.atan2(y2-y1,x2-x1)
    for s in (0.4,-0.4):
        d.line([x2,y2,x2-15*math.cos(a+s),y2-15*math.sin(a+s)],fill=c,width=3)
    if label:
        d.text((x1+ (x2-x1)/2 - d.textlength(label,font=FS)/2, (y1+y2)/2-22),label,font=FS,fill=c)

d.text((40,28),"The gate: one decision, two outcomes",font=FB,fill=INK)

# shared top
node(620,90,360,56,"model requests a tool call",CYN)
arr(620,146,620,196)
node(620,196,360,56,"is it a SAFE (read-only) tool?",YEL)
arr(620,252,300,300,GRN,"yes")
node(300,300,300,52,"run it",GRN)
arr(620,252,940,300,RED,"no (privileged)")

# split: vulnerable (left-down) vs patched (right-down)
d.text((150,380),"VULNERABLE harness",font=FB,fill=RED)
node(300,420,360,56,"approval_note in the input?",RED)
arr(300,476,300,536,RED,"yes (forged)")
node(300,536,360,56,"RUN  (attacker wins)",RED,fill=(60,36,40))

d.text((820,380),"PATCHED harness",font=FB,fill=GRN)
node(960,420,360,52,"strip model's approval_note",GRN)
arr(960,472,960,520)
node(960,520,360,52,"caller role + tenant OK?",GRN)
arr(960,572,960,620)
node(960,620,360,52,"out-of-band human approves?",GRN)
arr(960,672,760,700,GRN,"yes");
# deny path note
d.text((1150,560),"any no\n-> BLOCK",font=FS,fill=RED)

img.save("docs/img/gate_flow.png"); print("wrote docs/img/gate_flow.png",img.size)
