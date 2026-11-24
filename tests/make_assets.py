"""Creates the sample files the browser tests use (in /tmp). Run once: python3 tests/make_assets.py"""
from PIL import Image, ImageDraw
import json, gzip, os, subprocess
os.makedirs('/tmp/stk', exist_ok=True)
Image.new('RGB', (1600, 1200), (30, 140, 220)).save('/tmp/photo.jpg', exif=b'Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00GPSDATA-SECRET')
open('/tmp/doc.pdf', 'wb').write(b'%PDF-1.4 fake ' + b'x' * 90000)
fr = []
for i in range(8):
    im = Image.new('RGBA', (256, 256), (0, 0, 0, 0)); d = ImageDraw.Draw(im); r = 40 + i * 8
    d.ellipse([128 - r, 128 - r, 128 + r, 128 + r], fill=(255, 80, 140, 255)); fr.append(im)
fr[0].save('/tmp/stk/heart.gif', save_all=True, append_images=fr[1:], duration=90, loop=0, disposal=2)
fr[0].save('/tmp/stk/anim.webp', save_all=True, append_images=fr[1:], duration=90, loop=0)
Image.new('RGB', (900, 700), (40, 160, 90)).save('/tmp/stk/static.jpg')
lot = {"v": "5.7.4", "fr": 30, "ip": 0, "op": 60, "w": 512, "h": 512, "nm": "bounce", "ddd": 0, "assets": [], "layers": [{"ddd": 0, "ind": 1, "ty": 4, "nm": "ball", "sr": 1, "ks": {"o": {"a": 0, "k": 100}, "r": {"a": 0, "k": 0}, "p": {"a": 1, "k": [{"t": 0, "s": [256, 120, 0], "i": {"x": [0.5], "y": [1]}, "o": {"x": [0.5], "y": [0]}}, {"t": 30, "s": [256, 392, 0], "i": {"x": [0.5], "y": [1]}, "o": {"x": [0.5], "y": [0]}}, {"t": 60, "s": [256, 120, 0]}]}, "a": {"a": 0, "k": [0, 0, 0]}, "s": {"a": 0, "k": [100, 100, 100]}}, "ao": 0, "shapes": [{"ty": "el", "p": {"a": 0, "k": [0, 0]}, "s": {"a": 0, "k": [160, 160]}, "nm": "e"}, {"ty": "fl", "c": {"a": 0, "k": [0.36, 0.55, 1, 1]}, "o": {"a": 0, "k": 100}, "r": 1, "nm": "f"}], "ip": 0, "op": 60, "st": 0, "bm": 0}]}
open('/tmp/stk/bounce.tgs', 'wb').write(gzip.compress(json.dumps(lot).encode()))
subprocess.run(['ffmpeg', '-loglevel', 'error', '-y', '-f', 'lavfi', '-i', 'color=c=orange:s=256x256:d=2,format=yuva420p', '-c:v', 'libvpx-vp9', '-an', '/tmp/stk/clip.webm'])
print('assets ready in /tmp')
