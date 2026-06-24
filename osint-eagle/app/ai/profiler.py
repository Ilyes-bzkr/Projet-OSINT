"""
profiler — OSINT Eagle
Agrégation cross-sources en profil structuré via Claude.
"""

import json
import urllib.parse

from anthropic import AsyncAnthropic

from app.core.config import settings
from app.core.logger import logger
from app.models.result import OsintResult
from app.models.search import NameProfile

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 4000
_TIMEOUT = 60.0
_MAX_RESULTS = 50
_SNIPPET_MAX_LEN = 150

_SYSTEM_PROMPT = (
    "Tu es un analyste de renseignement expert en OSINT. "
    "Tu construis des fiches de renseignement complètes "
    "à partir de données publiques. "
    "Sois exhaustif, précis, et factuellement rigoureux. "
    "Ne jamais inventer d'informations non présentes dans "
    "les données. Si une information est incertaine, le mentionner. "
    "Réponds UNIQUEMENT avec du JSON pur, sans markdown, "
    "sans backticks, sans texte avant ou après. "
    "Le JSON doit commencer par { et finir par }"
)

_PROFILE_SCHEMA = """{
  "identity": {
    "full_name": str,
    "first_name": str,
    "last_name": str,
    "age_estimated": str ou null,
    "nationality": str ou null,
    "languages": [str],
    "photo_url": str ou null (meilleure photo trouvée)
  },
  "location": {
    "current_city": str ou null,
    "current_country": str ou null,
    "past_cities": [str],
    "timezone_estimated": str ou null,
    "location_confidence": "high"|"medium"|"low"
  },
  "contact": {
    "emails": [{"value": str, "source": str, "leaked": bool}],
    "phones": [{"value": str, "source": str}],
    "usernames": [{"value": str, "platform": str, "url": str}]
  },
  "professional": {
    "current_employer": str ou null,
    "past_employers": [str],
    "current_school": str ou null,
    "field": str ou null,
    "skills": [str],
    "job_title": str ou null
  },
  "activities": [
    {
      "category": str,
      "description": str,
      "frequency": str ou null,
      "evidence": str,
      "sources_count": int
    }
  ],
  "behavior": {
    "most_active_platforms": [str],
    "posting_hours_estimated": str ou null,
    "tone": str,
    "recurring_topics": [str],
    "posting_frequency": str ou null,
    "writing_style": str ou null
  },
  "network": {
    "mentioned_people": [{"name": str, "relation": str ou null}],
    "communities": [str],
    "organizations": [str]
  },
  "breaches": [
    {
      "source": str,
      "date": str,
      "data_exposed": [str],
      "severity": "critical"|"high"|"medium"
    }
  ],
  "digital_footprint": {
    "total_platforms_found": int,
    "platforms_confirmed": [str],
    "oldest_online_presence": str ou null,
    "public_exposure_level": "very_high"|"high"|"medium"|"low",
    "what_stranger_finds": str
  },
  "privacy_score": {
    "score": int,
    "level": "critical"|"high"|"medium"|"low",
    "main_risks": [str],
    "score_breakdown": {
      "personal_info_exposed": int,
      "contact_info_exposed": int,
      "professional_info_exposed": int,
      "breach_exposure": int,
      "social_footprint": int
    }
  },
  "summary": str,
  "confidence_overall": "high"|"medium"|"low",
  "data_freshness": str
}"""


def _domain_of(url: str | None) -> str:
    if not url:
        return ""
    return urllib.parse.urlparse(url).netloc


def _result_to_payload(result: OsintResult) -> dict:
    snippet = result.snippet or ""
    if len(snippet) > _SNIPPET_MAX_LEN:
        snippet = snippet[:_SNIPPET_MAX_LEN]
    return {
        "title": result.title,
        "domain": _domain_of(result.url),
        "snippet": snippet,
        "module": result.module.value,
    }


def _group_by_module(results: list[OsintResult]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for result in results:
        grouped.setdefault(result.module.value, []).append(_result_to_payload(result))
    return grouped


def _build_user_prompt(profile: NameProfile, results: list[OsintResult]) -> str:
    grouped = _group_by_module(results)
    data_str = json.dumps(grouped, ensure_ascii=False)
    return (
        f"Construis une fiche de renseignement complète pour :\n{profile.full_name}\n\n"
        f"Données collectées ({len(results)} sources) :\n{data_str}\n\n"
        f"Génère un JSON avec cette structure exacte :\n\n{_PROFILE_SCHEMA}"
    )


def _clean_json_text(raw_text: str) -> str:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


def _minimal_fallback_profile(profile: NameProfile, results: list[OsintResult]) -> dict:
    """Profil minimal construit directement depuis les résultats, sans IA."""
    emails = []
    usernames = []
    platforms = set()
    breaches = []
    for result in results:
        raw = result.raw_data or {}
        if raw.get("email"):
            emails.append({"value": raw["email"], "source": result.module.value, "leaked": result.module.value == "breach"})
        if raw.get("username") and raw.get("platform"):
            usernames.append({"value": raw["username"], "platform": raw["platform"], "url": result.url or ""})
            platforms.add(raw["platform"])
        if result.module.value == "breach":
            breaches.append({
                "source": raw.get("source", result.title),
                "date": raw.get("date", ""),
                "data_exposed": raw.get("types", []) if isinstance(raw.get("types"), list) else [],
                "severity": "critical",
            })

    return {
        "identity": {
            "full_name": profile.full_name, "first_name": profile.first_name,
            "last_name": profile.last_name, "age_estimated": None, "nationality": None,
            "languages": [], "photo_url": None,
        },
        "location": {
            "current_city": None, "current_country": None, "past_cities": [],
            "timezone_estimated": None, "location_confidence": "low",
        },
        "contact": {"emails": emails, "phones": [], "usernames": usernames},
        "professional": {
            "current_employer": None, "past_employers": [], "current_school": None,
            "field": None, "skills": [], "job_title": None,
        },
        "activities": [],
        "behavior": {
            "most_active_platforms": list(platforms), "posting_hours_estimated": None,
            "tone": "inconnu", "recurring_topics": [], "posting_frequency": None,
            "writing_style": None,
        },
        "network": {"mentioned_people": [], "communities": [], "organizations": []},
        "breaches": breaches,
        "digital_footprint": {
            "total_platforms_found": len(platforms), "platforms_confirmed": list(platforms),
            "oldest_online_presence": None,
            "public_exposure_level": "high" if breaches else "medium",
            "what_stranger_finds": "Profil partiel généré sans analyse IA (erreur de parsing).",
        },
        "privacy_score": {
            "score": 50, "level": "medium", "main_risks": [],
            "score_breakdown": {
                "personal_info_exposed": 10, "contact_info_exposed": 10,
                "professional_info_exposed": 10, "breach_exposure": 10, "social_footprint": 10,
            },
        },
        "summary": "Profil minimal généré automatiquement (analyse IA indisponible).",
        "confidence_overall": "low",
        "data_freshness": "inconnu",
    }


async def build_profile(
    results: list[OsintResult],
    profile: NameProfile,
    search_id: str,
) -> dict:
    """Construit un profil structuré via un appel unique à Claude."""
    if not settings.anthropic_api_key:
        logger.warning("[AI] ANTHROPIC_API_KEY absente, profil IA ignoré")
        return _minimal_fallback_profile(profile, results)

    selected = sorted(results, key=lambda r: r.relevance_score, reverse=True)[:_MAX_RESULTS]

    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=_TIMEOUT)

    for attempt in range(2):
        try:
            response = await client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                temperature=0,
                system=_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": _build_user_prompt(profile, selected) if attempt == 0 else
                    f"Réponds UNIQUEMENT avec un JSON valide pour : {profile.full_name}.\n"
                    f"Structure exacte requise (respecte chaque clé) :\n{_PROFILE_SCHEMA}\n\n"
                    f"Données disponibles : {json.dumps(_group_by_module(selected), ensure_ascii=False)[:6000]}",
                }],
            )
            raw_text = response.content[0].text if response.content else ""
            cleaned = _clean_json_text(raw_text)
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning(
                f"[AI] JSON malformé du profil (tentative {attempt + 1}/2), "
                f"raw_response[:100]={raw_text[:100]!r}"
            )
            continue
        except Exception as e:
            logger.error(f"[AI] Erreur appel Claude profiler : {e}")
            break

    logger.error("[AI] Échec construction profil IA, retour profil minimal")
    return _minimal_fallback_profile(profile, results)
