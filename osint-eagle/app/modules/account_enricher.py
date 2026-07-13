"""
account_enricher — OSINT Eagle
Enrichissement des comptes "coquilles vides" (Maigret CLAIMED sans attributs).

Beaucoup de comptes confirmés par Maigret n'exposent que platform+username+url :
sans nom/ville/bio/lien, la corroboration et la convergence inter-comptes n'ont
aucune matière. Ce module va chercher ces attributs ailleurs via une
re-recherche SearXNG ciblée (gratuite) + une extraction IA (Haiku), puis remplit
raw_data["content"].

Garde-fous anti-invention (NE PAS affaiblir) :
- extraction STRICTEMENT littérale (prompt + champs nullables, jamais de texte libre) ;
- PROVENANCE vérifiée EN CODE : un attribut n'est retenu que si sa source_url fait
  partie des URLs réellement fournies ET que sa valeur apparaît littéralement dans
  le snippet cité. Sinon il est rejeté (null). Garantie indépendante du modèle.

Tout est async et isolé en try/except : un échec SearXNG/IA ne casse jamais le
pipeline (on log et on n'enrichit rien).
"""

import json
from typing import Optional

from anthropic import AsyncAnthropic

from app.core.config import settings
from app.core.logger import logger
from app.models.result import ConfidenceLevel, OsintResult
from app.models.search import NameProfile
from app.modules.evidence_engine import account_content_view, classify_pseudo, loose_contains
from app.modules.web_search import _search_searxng

__all__ = ["enrich_accounts"]

# Extraction = tâche simple (spans littéraux) → Haiku 4.5 (3x moins cher que Sonnet).
_ENRICH_MODEL = "claude-haiku-4-5"
_MAX_TOKENS = 1500
_TIMEOUT = 60.0

# Cap dur : au plus K usernames distincts ré-enrichis par recherche (coût/latence).
_MAX_USERNAMES = 8
_SNIPPETS_PER_USERNAME = 5
_SNIPPET_MAX_LEN = 300

# Attributs scalaires extraits (links est traité à part car c'est une liste).
_SCALAR_FIELDS = ("fullname", "location", "occupation", "bio", "email")

# Plateformes à profil public exploitable : priorité d'enrichissement si > K usernames.
_PUBLIC_PROFILE_PLATFORMS = (
    "linkedin", "twitter", "x", "github", "about.me", "instagram",
    "facebook", "medium", "behance", "dribbble", "gitlab",
)

_TRUSTED = {ConfidenceLevel.CONFIRMED.value, ConfidenceLevel.CORROBORATED.value}

_SYSTEM_PROMPT = (
    "Tu es un extracteur de données OSINT strict. Tu ne fais qu'EXTRAIRE des "
    "informations littéralement présentes dans les extraits fournis. "
    "Tu n'infères jamais, ne devines jamais, n'utilises AUCUNE connaissance "
    "externe. Réponds UNIQUEMENT en JSON valide, sans aucun texte autour."
)


def _username_of(result: OsintResult) -> Optional[str]:
    raw = result.raw_data or {}
    return raw.get("username") or raw.get("login")


def _select_targets(results: list[OsintResult]) -> list[OsintResult]:
    """Comptes à enrichir : non déjà fiables (confirmed/corroborated), à content
    vide (rien à recouper sinon) et porteurs d'un username."""
    targets: list[OsintResult] = []
    for result in results:
        raw = result.raw_data or {}
        if raw.get("confidence") in _TRUSTED:
            continue
        if account_content_view(raw):  # déjà des attributs : inutile d'enrichir
            continue
        if not _username_of(result):
            continue
        targets.append(result)
    return targets


def _prioritize(usernames: list[str], by_username: dict[str, list[OsintResult]]) -> list[str]:
    """Trie les usernames : ceux présents sur une plateforme à profil public d'abord
    (plus de chances d'exposer des attributs dans les snippets), puis par nombre de
    comptes concernés."""
    def _score(username: str) -> tuple[int, int]:
        platforms = []
        for result in by_username[username]:
            raw = result.raw_data or {}
            platforms.append((raw.get("platform") or ("github" if raw.get("login") else "")).lower())
        has_public = any(any(p in plat for p in _PUBLIC_PROFILE_PLATFORMS) for plat in platforms)
        return (1 if has_public else 0, len(by_username[username]))

    return sorted(usernames, key=_score, reverse=True)


def _build_extraction_prompt(usable: dict[str, list[dict]]) -> str:
    blocks = []
    for username, snippets in usable.items():
        lines = [f'Username: "{username}"', "Extraits :"]
        for snippet in snippets:
            lines.append(f'  - [source_url: {snippet["url"]}] {snippet["text"]}')
        blocks.append("\n".join(lines))
    payload = "\n\n".join(blocks)

    return (
        "Pour chaque username ci-dessous, extrais les attributs SEULEMENT s'ils "
        "apparaissent LITTÉRALEMENT dans ses extraits.\n"
        "- Si un attribut n'est pas explicitement écrit dans un extrait : value = null.\n"
        "- Pour chaque attribut extrait, indique l'URL EXACTE de l'extrait d'où il "
        "provient dans source_url (recopie une des source_url fournies).\n"
        "- Ne fabrique JAMAIS un lien (links) : ne retiens un lien que s'il apparaît "
        "littéralement dans un extrait.\n"
        "- N'utilise aucune connaissance externe, ne devine pas.\n\n"
        f"{payload}\n\n"
        "Réponds avec ce format JSON exact (une entrée par username) :\n"
        "{\n"
        '  "<username>": {\n'
        '    "fullname":   {"value": <str|null>, "source_url": <str|null>},\n'
        '    "location":   {"value": <str|null>, "source_url": <str|null>},\n'
        '    "occupation": {"value": <str|null>, "source_url": <str|null>},\n'
        '    "bio":        {"value": <str|null>, "source_url": <str|null>},\n'
        '    "email":      {"value": <str|null>, "source_url": <str|null>},\n'
        '    "links":      [{"value": <str>, "source_url": <str>}]\n'
        "  }\n"
        "}"
    )


def _parse_extraction(raw_text: str) -> dict:
    text = (raw_text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text.strip())
    except json.JSONDecodeError:
        logger.warning("[enrich] réponse IA non-JSON, extraction ignorée")
        return {}
    return data if isinstance(data, dict) else {}


def _snippet_names_target(text: str, profile: Optional[NameProfile]) -> bool:
    """True si le snippet co-mentionne le prénom ET le nom de la cible."""
    if not profile:
        return True
    return (loose_contains(text, profile.first_name, min_len=2)
            and loose_contains(text, profile.last_name, min_len=2))


def _needs_name_gate(username: str, profile: Optional[NameProfile]) -> bool:
    """Le garde-fou anti-homonyme (Phase 4) s'applique aux usernames SIMPLES
    (dérivés du nom → nombreux homonymes). Un username DISTINCTIF est un identifiant
    fiable en soi : ré-chercher ce handle ramène très probablement la même personne,
    on n'exige donc pas la co-mention du nom."""
    if not profile or not profile.last_name:
        return False
    return classify_pseudo(username, profile.first_name, profile.last_name) != "distinctive"


def _validate_attrs(
    raw_attrs: dict,
    snippets: list[dict],
    profile: Optional[NameProfile] = None,
    username: str = "",
) -> tuple[dict, dict]:
    """Filtre les attributs extraits par PROVENANCE (garde-fou anti-invention) :
    un attribut n'est retenu que si sa source_url est l'une des URLs fournies ET que
    sa valeur apparaît littéralement dans le snippet cité. Sinon rejeté.

    Garde-fou anti-homonyme (Phase 4) : si `profile` est fourni et que `username`
    est SIMPLE (dérivé du nom), un attribut n'est retenu que si son snippet
    co-mentionne le nom de la cible — sinon c'est probablement un homonyme et on
    rejette (on n'attache jamais un attribut d'homonyme au compte cible).

    Retourne (content, provenance) — content au format raw_data["content"].
    """
    url_to_text = {s["url"]: s["text"] for s in snippets}
    content: dict = {}
    provenance: dict = {}

    if not isinstance(raw_attrs, dict):
        return content, provenance

    name_gate = _needs_name_gate(username, profile)

    for field in _SCALAR_FIELDS:
        entry = raw_attrs.get(field)
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        source = entry.get("source_url")
        if not value or not isinstance(value, str):
            continue
        text = url_to_text.get(source)
        if not text:
            continue  # provenance absente / inventée
        if not loose_contains(text, value, min_len=2):
            continue  # la valeur n'apparaît pas littéralement → rejet
        if name_gate and not _snippet_names_target(text, profile):
            continue  # snippet ne parle pas de la cible → homonyme probable, rejet
        content[field] = value.strip()
        provenance[field] = source

    links: list[str] = []
    for entry in raw_attrs.get("links") or []:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        source = entry.get("source_url")
        if not value or not isinstance(value, str):
            continue
        text = url_to_text.get(source)
        if not text or value.lower() not in text.lower():
            continue  # lien non présent littéralement → rejet (jamais d'inférence)
        if name_gate and not _snippet_names_target(text, profile):
            continue  # lien issu d'un snippet d'homonyme probable → rejet
        clean = value.strip()
        links.append(clean)
        provenance[f"link:{clean}"] = source
    if links:
        content["links"] = links

    return content, provenance


def _count_attrs(content: dict) -> int:
    return len([k for k in content if k != "links"]) + len(content.get("links") or [])


async def _research(username: str) -> list[dict]:
    """Re-recherche SearXNG d'un username → snippets {url, text}."""
    try:
        raw = await _search_searxng(f'"{username}"', _SNIPPETS_PER_USERNAME)
    except Exception as e:  # SearXNG ne lève jamais en principe ; ceinture+bretelles.
        logger.warning(f"[enrich] re-recherche échouée pour @{username} : {e}")
        return []
    snippets = []
    for item in raw:
        url = item.get("href")
        if not url:
            continue
        text = " ".join(p for p in (item.get("title"), item.get("body")) if p)[:_SNIPPET_MAX_LEN]
        snippets.append({"url": url, "text": text})
    return snippets


async def _extract(client: AsyncAnthropic, usable: dict[str, list[dict]]) -> dict:
    response = await client.messages.create(
        model=_ENRICH_MODEL,
        max_tokens=_MAX_TOKENS,
        temperature=0,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_extraction_prompt(usable)}],
    )
    raw_text = response.content[0].text if response.content else ""
    return _parse_extraction(raw_text)


async def enrich_accounts(results: list[OsintResult], profile: NameProfile) -> None:
    """Enrichit en place les comptes à content vide (raw_data["content"]).

    Ne lève jamais : tout est isolé en try/except. Modifie raw_data des comptes
    enrichis (content + enriched=True + content_provenance).
    """
    try:
        if not settings.anthropic_api_key:
            logger.warning("[enrich] ANTHROPIC_API_KEY absente, enrichissement ignoré")
            return

        targets = _select_targets(results)
        if not targets:
            logger.info("[enrich] aucun compte à enrichir (content déjà présent ou comptes fiables)")
            return

        by_username: dict[str, list[OsintResult]] = {}
        for result in targets:
            by_username.setdefault(_username_of(result), []).append(result)

        selected = _prioritize(list(by_username.keys()), by_username)[:_MAX_USERNAMES]
        logger.info(
            f"[enrich] {len(by_username)} username(s) distinct(s) à content vide, "
            f"{len(selected)} retenu(s) (cap {_MAX_USERNAMES})"
        )

        usable: dict[str, list[dict]] = {}
        for username in selected:
            snippets = await _research(username)
            if snippets:
                usable[username] = snippets
        if not usable:
            logger.info("[enrich] aucune re-recherche exploitable (SearXNG vide ?), enrichissement ignoré")
            return

        client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=_TIMEOUT)
        try:
            extracted = await _extract(client, usable)
        except Exception as e:
            logger.warning(f"[enrich] échec extraction IA (ignoré) : {e}")
            return

        enriched_users = 0
        total_attrs = 0
        for username, accounts in by_username.items():
            if username not in usable:
                continue
            content, provenance = _validate_attrs(
                extracted.get(username) or {}, usable[username], profile, username
            )
            if not content:
                continue
            enriched_users += 1
            total_attrs += _count_attrs(content)
            for account in accounts:
                account.raw_data["content"] = content
                account.raw_data["enriched"] = True
                account.raw_data["content_provenance"] = provenance
            logger.info(f"[enrich] @{username} → {sorted(content.keys())}")

        logger.info(
            f"[enrich] {enriched_users} username(s) enrichi(s), {total_attrs} attribut(s) au total"
        )
    except Exception as e:
        logger.warning(f"[enrich] échec enrichissement (ignoré) : {e}")
