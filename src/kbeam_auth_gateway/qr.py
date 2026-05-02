from __future__ import annotations

import io

import qrcode
import qrcode.image.svg


def qr_svg_for_url(url: str) -> str:
    image = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue().decode("utf-8")

