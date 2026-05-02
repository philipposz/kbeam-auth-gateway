from __future__ import annotations

import io

import qrcode
import qrcode.image.svg


def qr_svg_for_url(url: str) -> str:
    image = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    svg = output.getvalue().decode("utf-8")
    svg_start = svg.find("<svg ")
    svg_start_close = svg.find(">", svg_start)
    if svg_start >= 0 and svg_start_close >= 0:
        svg = (
            svg[: svg_start_close + 1]
            + '<rect width="100%" height="100%" fill="#ffffff"/>'
            + svg[svg_start_close + 1 :]
        )
    return svg
