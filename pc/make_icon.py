"""Genera icon.ico y icon.png a partir de icon_source.png (recorte cuadrado con esquinas redondeadas)."""
from PIL import Image, ImageDraw


def draw(size, src="icon_source.png"):
    im = Image.open(src).convert("RGBA")
    w, h = im.size
    m = min(w, h)
    l, t = (w - m) // 2, (h - m) // 2
    im = im.crop((l + 2, t + 2, l + m - 2, t + m - 2)).resize((size * 4, size * 4), Image.LANCZOS)
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.size[0] - 1, im.size[1] - 1), radius=int(im.size[0] * 0.2), fill=255)
    im.putalpha(mask)
    return im.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    sizes = [16, 24, 32, 48, 64, 128, 256]
    draw(256).save("icon.ico", sizes=[(n, n) for n in sizes])
    draw(128).save("icon.png")
    print("icon.ico creado")
