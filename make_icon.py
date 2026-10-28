"""Genera icon.ico (candado sobre fondo degradado) con Pillow."""
from PIL import Image, ImageDraw


def draw(size):
    s = size * 4  # se dibuja grande y se reduce para suavizar bordes
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # fondo degradado diagonal con esquinas redondeadas
    grad = Image.new("RGBA", (s, s))
    px = grad.load()
    a, b = (108, 123, 255), (143, 91, 255)
    for y in range(s):
        for x in range(s):
            t = (x + y) / (2 * s)
            px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, s - 1, s - 1), radius=int(s * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    w = (255, 255, 255, 255)
    # arco del candado
    d.arc((s * 0.30, s * 0.17, s * 0.70, s * 0.57), 180, 360, fill=w, width=int(s * 0.07))
    d.line((s * 0.30, s * 0.37, s * 0.30, s * 0.47), fill=w, width=int(s * 0.07))
    d.line((s * 0.70, s * 0.37, s * 0.70, s * 0.47), fill=w, width=int(s * 0.07))
    # cuerpo y ojo de la cerradura
    d.rounded_rectangle((s * 0.22, s * 0.45, s * 0.78, s * 0.80), radius=int(s * 0.06), fill=w)
    d.ellipse((s * 0.45, s * 0.53, s * 0.55, s * 0.63), fill=(108, 123, 255, 255))
    d.rectangle((s * 0.48, s * 0.60, s * 0.52, s * 0.71), fill=(108, 123, 255, 255))
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    sizes = [16, 24, 32, 48, 64, 128, 256]
    big = draw(256)
    big.save("icon.ico", sizes=[(n, n) for n in sizes])
    print("icon.ico creado")
