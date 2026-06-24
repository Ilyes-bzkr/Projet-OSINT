"""
exif_extractor — OSINT Eagle
Extraction de métadonnées EXIF (GPS, date, appareil) depuis photos et vidéos.
"""

import asyncio
import json
import re
from io import BytesIO

import httpx
from PIL import ExifTags, Image

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel

__all__ = ["extract_from_url", "extract_video_metadata"]

_TIMEOUT = 15.0
_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Eagle/1.0)"}
_FFPROBE_TIMEOUT = 30.0
_ISO6709_RE = re.compile(r"^([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)")


def _gps_to_decimal(gps_coord: tuple, gps_ref: str) -> float:
    degrees, minutes, seconds = gps_coord
    decimal = float(degrees) + float(minutes) / 60.0 + float(seconds) / 3600.0
    if gps_ref in ("S", "W"):
        decimal = -decimal
    return decimal


def _parse_gps_info(gps_info: dict) -> tuple[float, float] | None:
    try:
        lat = _gps_to_decimal(gps_info[2], gps_info[1])
        lon = _gps_to_decimal(gps_info[4], gps_info[3])
        return lat, lon
    except (KeyError, IndexError, TypeError, ZeroDivisionError):
        return None


async def _download_image(image_url: str) -> bytes | None:
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("GET", image_url) as resp:
                content_type = resp.headers.get("content-type", "")
                if not content_type.startswith("image/"):
                    return None

                chunks = bytearray()
                async for chunk in resp.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > _MAX_IMAGE_BYTES:
                        logger.warning(f"exif_extractor : image trop volumineuse, abandon : {image_url}")
                        return None
                return bytes(chunks)
    except Exception as e:
        logger.warning(f"exif_extractor : erreur téléchargement '{image_url}' : {e}")
        return None


async def extract_from_url(image_url: str, search_id: str) -> list[OsintResult]:
    """Extrait les métadonnées EXIF (GPS, date, appareil) d'une image distante."""
    results: list[OsintResult] = []

    content = await _download_image(image_url)
    if not content:
        return results

    try:
        image = Image.open(BytesIO(content))
        exif_raw = image._getexif()
    except Exception as e:
        logger.warning(f"exif_extractor : impossible de lire l'EXIF de '{image_url}' : {e}")
        return results

    if not exif_raw:
        return results

    tags = {ExifTags.TAGS.get(tag_id, tag_id): value for tag_id, value in exif_raw.items()}

    lat_lon = None
    gps_ifd = tags.get("GPSInfo")
    if isinstance(gps_ifd, dict):
        lat_lon = _parse_gps_info(gps_ifd)

    date_taken = tags.get("DateTimeOriginal") or tags.get("DateTime")
    make = tags.get("Make")
    model = tags.get("Model")
    device = " ".join(p for p in [make, model] if p) or None

    if lat_lon:
        lat, lon = lat_lon
        results.append(OsintResult(
            search_id=search_id,
            module=ModuleType.WEB_SEARCH,
            category=ResultCategory.IDENTITY,
            title=f"Localisation EXIF : {lat:.4f}, {lon:.4f}",
            url=f"https://maps.google.com/?q={lat},{lon}",
            snippet=f"Photo prise à ces coordonnées le {date_taken}" if date_taken else "Coordonnées extraites de l'EXIF",
            raw_data={"lat": lat, "lon": lon, "date": date_taken, "device": device, "source_image": image_url},
            risk_level=RiskLevel.HIGH,
            is_sensitive=True,
        ))
    elif date_taken or device:
        results.append(OsintResult(
            search_id=search_id,
            module=ModuleType.WEB_SEARCH,
            category=ResultCategory.IDENTITY,
            title="Métadonnées EXIF trouvées",
            url=None,
            snippet=f"Date : {date_taken or 'inconnue'} — Appareil : {device or 'inconnu'}",
            raw_data={"lat": None, "lon": None, "date": date_taken, "device": device, "source_image": image_url},
            risk_level=RiskLevel.LOW,
            is_sensitive=False,
        ))

    return results


def _parse_iso6709(value: str) -> tuple[float, float] | None:
    match = _ISO6709_RE.match(value.strip())
    if not match:
        return None
    try:
        return float(match.group(1)), float(match.group(2))
    except ValueError:
        return None


async def extract_video_metadata(video_url: str, search_id: str) -> list[OsintResult]:
    """Extrait les métadonnées (date, GPS) d'une vidéo distante via ffprobe."""
    results: list[OsintResult] = []

    try:
        process = await asyncio.create_subprocess_exec(
            "ffprobe", "-v", "quiet", "-print_format", "json",
            "-show_format", "-show_streams", video_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=_FFPROBE_TIMEOUT)
    except FileNotFoundError:
        logger.warning("exif_extractor : ffprobe non installé, extraction métadonnées vidéo désactivée. Installer ffmpeg.")
        return results
    except asyncio.TimeoutError:
        logger.warning(f"exif_extractor : timeout ffprobe pour '{video_url}'")
        return results
    except Exception as e:
        logger.warning(f"exif_extractor : erreur ffprobe pour '{video_url}' : {e}")
        return results

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning(f"exif_extractor : sortie ffprobe invalide pour '{video_url}'")
        return results

    tags = data.get("format", {}).get("tags", {}) or {}
    creation_time = tags.get("creation_time")
    location_raw = tags.get("location") or tags.get("com.apple.quicktime.location.ISO6709")

    lat_lon = _parse_iso6709(location_raw) if location_raw else None

    if lat_lon:
        lat, lon = lat_lon
        results.append(OsintResult(
            search_id=search_id,
            module=ModuleType.WEB_SEARCH,
            category=ResultCategory.IDENTITY,
            title=f"Localisation vidéo : {lat:.4f}, {lon:.4f}",
            url=f"https://maps.google.com/?q={lat},{lon}",
            snippet=f"Vidéo filmée à ces coordonnées le {creation_time}" if creation_time else "Coordonnées extraites des métadonnées vidéo",
            raw_data={"lat": lat, "lon": lon, "date": creation_time, "source_video": video_url},
            risk_level=RiskLevel.HIGH,
            is_sensitive=True,
        ))
    elif creation_time:
        results.append(OsintResult(
            search_id=search_id,
            module=ModuleType.WEB_SEARCH,
            category=ResultCategory.IDENTITY,
            title="Métadonnées vidéo trouvées",
            url=None,
            snippet=f"Date de création : {creation_time}",
            raw_data={"lat": None, "lon": None, "date": creation_time, "source_video": video_url},
            risk_level=RiskLevel.LOW,
            is_sensitive=False,
        ))

    return results
