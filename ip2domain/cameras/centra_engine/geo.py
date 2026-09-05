import json
import logging
import os
import re
from typing import List, Optional

logger = logging.getLogger(__name__)

DEFAULT_CENTRA_CAMERAS = [{
    "id": "I-374-1",
    "camera_type": "I",
    "title": "Домофон Сибиряков-Гвардейцев 14",
    "address": "Новокузнецк, ул. Сибиряков-Гвардейцев, 14",
    "embed_url": "https://flus4.mycentra.ru/I-374-1/embed.html",
    "media_info_url": "https://flus4.mycentra.ru/I-374-1/media_info.json",
}]


def _centra_cameras() -> List[dict]:
    raw = os.environ.get("IP2DOMAIN_CENTRA_CAMERAS")
    if not raw:
        return DEFAULT_CENTRA_CAMERAS
    try:
        cameras = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Ignoring invalid IP2DOMAIN_CENTRA_CAMERAS: %s", exc)
        return DEFAULT_CENTRA_CAMERAS
    if not isinstance(cameras, list):
        logger.warning("Ignoring IP2DOMAIN_CENTRA_CAMERAS: expected a JSON array")
        return DEFAULT_CENTRA_CAMERAS
    return cameras


def _centra_address(title: str) -> str:
    address = re.sub(r"^домофон\s+", "", str(title), flags=re.IGNORECASE).strip()
    configured_city = os.environ.get("IP2DOMAIN_CENTRA_CITY", "Новокузнецк").strip()
    configured_region = os.environ.get("IP2DOMAIN_CENTRA_REGION", "Кемеровская область").strip()
    city_match = re.search(r"\(([^()]*)\)\s*$", address)
    city = city_match.group(1).strip() if city_match else configured_city
    if city_match:
        address = address[:city_match.start()].strip()
    nested_locality = re.fullmatch(
        r"(?i)(Таштагол|Шерегеш),\s*(?:ул\.?\s+)?(.+?),\s*(\d+[а-я]?(?:/\d+)?)",
        address,
    )
    if nested_locality:
        city = nested_locality.group(1).title()
        street = nested_locality.group(2).strip().title()
        address = f"ул. {street}, {nested_locality.group(3)}"
    else:
        street_match = re.fullmatch(r"(.+?)\s+(\d+[А-Яа-яA-Za-z]?(?:/\d+)?)", address)
        if street_match:
            street, house = street_match.groups()
            address = f"ул. {street.strip()}, {house}"
    location = ", ".join(part for part in ("Россия", configured_region, city) if part)
    result = f"{location}, {address}" if location and address else address
    return _centra_address_override(result)


def _centra_address_override(address: str) -> str:
    nested_locality = re.fullmatch(
        r"(?i)(Россия,\s*Кемеровская область(?:\s*-\s*Кузбасс)?,\s*)"
        r"Новокузнецк,\s*(?:ул\.?\s+)?(Таштагол|Шерегеш),\s*"
        r"(?:ул\.?\s+)?(.+?),\s*(\d+[а-я]?(?:/\d+)?)",
        address.strip(),
    )
    if nested_locality:
        return (f"{nested_locality.group(1)}{nested_locality.group(2).title()}, "
                f"ул. {nested_locality.group(3)}, {nested_locality.group(4)}")
    overrides = {
        ("нестерова", "26а"): "Осинники",
        ("50 лет октября", "31"): "Осинники",
    }
    normalized = address.casefold().replace("ё", "е")
    for (street, house), locality in overrides.items():
        if re.search(rf"(?i),\s*(?:ул\.?\s+)?{re.escape(street)}\s*,\s*{re.escape(house)}\s*$", normalized):
            parts = [part.strip() for part in address.split(",")]
            if len(parts) >= 3:
                parts[2] = locality
                return ", ".join(parts)
    return address


def _dadata_address(address: str) -> str:
    return re.sub(
        r"(?i)(?<=,\s)(?:ул(?:ица)?|пр-?т|просп(?:ект)?|пр-?д|проезд|пер(?:еулок)?)\.?\s+",
        "",
        address.strip(),
    )


def _centra_locality(address: str) -> str:
    parts = [part.strip() for part in address.split(",") if part.strip()]
    return parts[2] if len(parts) >= 3 else os.environ.get("IP2DOMAIN_CENTRA_CITY", "Новокузнецк")


def _dadata_queries(address: str) -> List[str]:
    primary = _dadata_address(address)
    aliases = [primary]
    replacements = {
        r"(?i)(?<=,\s)Рихарда\s+Зорге(?=,|$)": "Зорге",
        r"(?i)(?<=,\s)(\d+)[-‐‑–—]?(?:й|ый|ой)\s+микрорайон(?=,|$)": r"Микрорайон \1",
    }
    for pattern, replacement in replacements.items():
        candidate = re.sub(pattern, replacement, primary)
        if candidate != primary and candidate not in aliases:
            aliases.append(candidate)
    return aliases
