"""Web screenshot capturing for routers, gateways, and web management panels."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import shutil
from typing import Optional

logger = logging.getLogger(__name__)


def generate_web_card_image(
    out_file: Path,
    ip: str,
    port: int,
    web_url: str,
    brand: str = "",
    model: str = "",
    title: str = "",
    category: str = "router",
) -> bool:
    """Generate a clean visual card placeholder image when browser capture is unavailable."""
    try:
        from PIL import Image, ImageDraw

        width, height = 800, 500
        # Dark modern palette
        bg_color = (24, 28, 37)
        card_bg = (33, 38, 50)
        border_color = (55, 65, 81)
        text_white = (243, 244, 246)
        text_gray = (156, 163, 175)
        accent_color = (59, 130, 246) if category == "router" else (16, 185, 129)

        img = Image.new("RGB", (width, height), color=bg_color)
        draw = ImageDraw.Draw(img)

        # Card container
        draw.rectangle([(30, 30), (width - 30, height - 30)], fill=card_bg, outline=border_color, width=2)

        # Header bar
        draw.rectangle([(30, 30), (width - 30, 90)], fill=(40, 46, 62))
        badge_text = f"[{category.upper()}] {brand or 'Web Device'}".strip()
        draw.text((50, 50), badge_text, fill=accent_color)

        # URL / Target line
        draw.text((50, 120), f"URL: {web_url or f'http://{ip}:{port}/'}", fill=text_white)
        draw.text((50, 160), f"Host: {ip}:{port}", fill=text_gray)

        if model:
            draw.text((50, 200), f"Model: {model}", fill=text_white)

        if title:
            draw.text((50, 240), f"Title: {title[:80]}", fill=text_gray)

        draw.text((50, 300), "Web Management Interface Detected", fill=text_white)
        draw.text((50, 340), "Direct browser access available via IP:PORT", fill=text_gray)

        # Footer
        draw.line([(30, height - 70), (width - 30, height - 70)], fill=border_color, width=1)
        draw.text((50, height - 55), "Camera & Device Scanner v2", fill=text_gray)

        out_file.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(out_file), "JPEG", quality=85)
        return True
    except Exception as exc:
        logger.debug("[WebCapture] Card generation failed: %s", exc)
        return False


async def capture_web_screenshot(
    ip: str,
    port: int,
    web_url: str = "",
    capture_dir: Optional[Path] = None,
    brand: str = "",
    model: str = "",
    title: str = "",
    category: str = "router",
    timeout: float = 5.0,
) -> Optional[str]:
    """Capture a screenshot of a web panel via wkhtmltoimage or generate a visual card."""
    if not capture_dir:
        return None

    capture_dir = Path(capture_dir)
    capture_dir.mkdir(parents=True, exist_ok=True)

    filename = f"web_{ip}_{port}.jpg"
    out_file = capture_dir / filename
    rel_url = f"/v2_captures/{filename}"

    target_url = web_url or f"http://{ip}:{port}/"
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    wkhtml = shutil.which("wkhtmltoimage")
    if wkhtml:
        cmd = [
            wkhtml,
            "--quality", "80",
            "--width", "1024",
            "--height", "640",
            "--load-error-handling", "ignore",
            "--load-media-error-handling", "ignore",
            "--disable-plugins",
            "--no-stop-slow-scripts",
            "--javascript-delay", "400",
            target_url,
            str(out_file),
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
                if out_file.is_file() and out_file.stat().st_size > 500:
                    return rel_url
            except asyncio.TimeoutError:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        except Exception as exc:
            logger.debug("[WebCapture] wkhtmltoimage error on %s: %s", target_url, exc)

    # Fallback: Generate structured info card image
    if generate_web_card_image(out_file, ip, port, target_url, brand, model, title, category):
        return rel_url

    return None
