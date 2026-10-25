"""Rebuilds photo-gps.jpg and photo-gps.heic, the EXIF test fixtures.

Synthetic 480x360 image with deliberately fictional metadata: a GPS point in
the open South Atlantic (0°30'0"S 25°0'0"W, no land within hundreds of km)
and a made-up camera, so the fixtures reveal nothing about anyone.

    pip install pillow piexif pillow-heif
    python tests/fixtures/make-photos.py
"""
from pathlib import Path

import piexif
import pillow_heif
from PIL import Image, ImageDraw

HERE = Path(__file__).parent
MAKE, MODEL, SOFTWARE = 'FixtureCam', 'Model T-1', 'make-photos.py'


def image():
    im = Image.new('RGB', (480, 360))
    d = ImageDraw.Draw(im)
    for y in range(360):  # vertical gradient, then a few shapes so the codecs have edges to keep
        d.line([(0, y), (479, y)], fill=(40 + y // 3, 90, 200 - y // 3))
    d.rectangle([40, 40, 200, 160], fill=(240, 200, 60))
    d.ellipse([260, 150, 440, 330], fill=(30, 160, 110))
    d.text((48, 300), 'EXIF fixture', fill=(255, 255, 255))
    return im


def exif_bytes():
    zeroth = {piexif.ImageIFD.Make: MAKE, piexif.ImageIFD.Model: MODEL, piexif.ImageIFD.Software: SOFTWARE}
    gps = {
        piexif.GPSIFD.GPSLatitudeRef: 'S', piexif.GPSIFD.GPSLatitude: ((0, 1), (30, 1), (0, 1)),
        piexif.GPSIFD.GPSLongitudeRef: 'W', piexif.GPSIFD.GPSLongitude: ((25, 1), (0, 1), (0, 1)),
    }
    return piexif.dump({'0th': zeroth, 'Exif': {}, 'GPS': gps, '1st': {}, 'thumbnail': None})


if __name__ == '__main__':
    im, exif = image(), exif_bytes()
    im.save(HERE / 'photo-gps.jpg', 'JPEG', quality=85, exif=exif)
    pillow_heif.register_heif_opener()
    im.save(HERE / 'photo-gps.heic', 'HEIF', quality=80, exif=exif)
    print('wrote photo-gps.jpg and photo-gps.heic')
