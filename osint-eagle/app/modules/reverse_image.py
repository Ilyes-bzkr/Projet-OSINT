"""
reverse_image — OSINT Eagle
Recherche d'image inversée via Yandex Images et Google Lens (Playwright).

Ces deux moteurs sont parmi les seuls à proposer une recherche par
similarité faciale/visuelle exploitable sans clé API. Le navigateur
(Browser) est injecté par l'appelant pour permettre la réutilisation
d'une même instance Playwright à travers plusieurs recherches d'images.
"""

import asyncio
import random
import urllib.parse

from playwright.async_api import Browser, Error as PlaywrightError

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory

__all__ = ["search_yandex", "search_google_lens", "search_all_engines"]

_MAX_RESULTS_PER_ENGINE = 10
_GOTO_TIMEOUT = 20000  # ms
_RESULT_WAIT_TIMEOUT = 8000  # ms

_YANDEX_URL = "https://yandex.com/images/search?rpt=imageview&url={url}"
_LENS_URL = "https://lens.google.com/uploadbyurl?url={url}"

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


async def search_yandex(image_url: str, search_id: str, browser: Browser) -> list[OsintResult]:
    """Recherche les sites où la même image apparaît via Yandex Images."""
    results: list[OsintResult] = []
    url = _YANDEX_URL.format(url=urllib.parse.quote(image_url, safe=""))
    page = await browser.new_page(user_agent=_random_ua())

    try:
        await page.goto(url, timeout=_GOTO_TIMEOUT, wait_until="load")
        await page.wait_for_selector(
            ".CbirSites-Items, .similar-sites", timeout=_RESULT_WAIT_TIMEOUT
        )
        raw_items = await page.eval_on_selector_all(
            ".CbirSites-Item, .similar-sites .item",
            """els => els.map(el => {
                const a = el.querySelector("a.CbirSites-ItemTitle, a");
                const snippetEl = el.querySelector(".CbirSites-ItemDescription, .item__text");
                return {
                    title: a ? a.innerText : null,
                    href: a ? a.href : null,
                    snippet: snippetEl ? snippetEl.innerText : null,
                };
            })""",
        )
        for item in raw_items[:_MAX_RESULTS_PER_ENGINE]:
            if not item.get("href"):
                continue
            results.append(OsintResult(
                search_id=search_id,
                module=ModuleType.WEB_SEARCH,
                category=ResultCategory.IDENTITY,
                title=item.get("title") or item["href"],
                url=item["href"],
                snippet=item.get("snippet"),
                raw_data={"source_image": image_url, "engine": "yandex", "media_type": "reverse_image"},
                is_sensitive=True,
            ))
    except (PlaywrightError, asyncio.TimeoutError):
        logger.warning(f"reverse_image : aucun résultat Yandex pour '{image_url}'")
    except Exception as e:
        logger.warning(f"reverse_image : erreur Yandex pour '{image_url}' : {e}")
    finally:
        await page.close()

    return results


async def search_google_lens(image_url: str, search_id: str, browser: Browser) -> list[OsintResult]:
    """Recherche les pages contenant une image visuellement similaire via Google Lens."""
    results: list[OsintResult] = []
    url = _LENS_URL.format(url=urllib.parse.quote(image_url, safe=""))
    page = await browser.new_page(user_agent=_random_ua())

    try:
        await page.goto(url, timeout=_GOTO_TIMEOUT, wait_until="load")
        await page.wait_for_selector(".Vd9M6, a[jsname]", timeout=_RESULT_WAIT_TIMEOUT)
        raw_items = await page.eval_on_selector_all(
            ".Vd9M6, a[jsname]",
            """els => els.map(el => {
                const a = el.tagName === "A" ? el : el.querySelector("a");
                const titleEl = el.querySelector("[role='heading']") || el;
                return {
                    title: titleEl ? titleEl.innerText : null,
                    href: a ? a.href : null,
                    snippet: null,
                };
            })""",
        )
        for item in raw_items[:_MAX_RESULTS_PER_ENGINE]:
            if not item.get("href"):
                continue
            results.append(OsintResult(
                search_id=search_id,
                module=ModuleType.WEB_SEARCH,
                category=ResultCategory.IDENTITY,
                title=item.get("title") or item["href"],
                url=item["href"],
                snippet=item.get("snippet"),
                raw_data={"source_image": image_url, "engine": "google_lens", "media_type": "reverse_image"},
                is_sensitive=True,
            ))
    except (PlaywrightError, asyncio.TimeoutError):
        logger.warning(f"reverse_image : aucun résultat Google Lens pour '{image_url}'")
    except Exception as e:
        logger.warning(f"reverse_image : erreur Google Lens pour '{image_url}' : {e}")
    finally:
        await page.close()

    return results


async def search_all_engines(image_url: str, search_id: str, browser: Browser) -> list[OsintResult]:
    """Lance Yandex et Google Lens en parallèle, déduplique par URL."""
    yandex_results, lens_results = await asyncio.gather(
        search_yandex(image_url, search_id, browser),
        search_google_lens(image_url, search_id, browser),
    )

    seen_urls: set[str] = set()
    combined: list[OsintResult] = []
    for result in yandex_results + lens_results:
        if result.url in seen_urls:
            continue
        seen_urls.add(result.url)
        combined.append(result)

    logger.info(f"reverse_image : {len(combined)} résultats uniques pour '{image_url}'")
    return combined
