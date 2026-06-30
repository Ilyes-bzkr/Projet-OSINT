"""
profiler — OSINT Eagle
Agrégation cross-sources en profil structuré via Claude.
"""

import json
import re
import urllib.parse

from anthropic import AsyncAnthropic

from app.core.config import settings
from app.core.logger import logger
from app.models.result import ConfidenceLevel, OsintResult
from app.models.search import NameProfile

_MODEL = "claude-sonnet-4-6"
# Le schéma de profil (11 sections) génère un JSON volumineux : 4000 tokens le
# tronquaient systématiquement -> json.loads échouait -> fallback minimal à chaque
# recherche. 8000 laisse une marge confortable (claude-sonnet-4-6 le supporte).
_MAX_TOKENS = 8000
# Timeout relevé en conséquence : 8000 tokens de sortie demandent plus de temps
# de génération que 4000, on évite ainsi de couper la réponse en plein vol.
_TIMEOUT = 120.0
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
  "unverified_namesakes": [
    {"platform": str, "username": str, "url": str ou null, "note": str}
  ],
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


_TRUSTED_CONF = {ConfidenceLevel.CONFIRMED.value, ConfidenceLevel.CORROBORATED.value}


def _is_account(result: OsintResult) -> bool:
    raw = result.raw_data or {}
    return bool(raw.get("username") or raw.get("login"))


def _is_offtarget(result: OsintResult) -> bool:
    """True si le résultat n'appartient PAS à l'identité cible → exclu du profil
    principal (phase B, désambiguïsation par grappe).

    Priorités :
    - confirmed / corroborated : appartenance ÉTABLIE → toujours profil principal
      (on ne bannit jamais un compte prouvé, même hors grappe-cible).
    - in_target_cluster == True  → profil principal (grappe-cible, mode A).
    - in_target_cluster == False → hors-cible (autre grappe d'homonyme, ou document
      au nom seul non rattaché à une ancre — P5).
    - tag absent (résultats dérivés couche 2, paste, breach, mode B) → règle
      historique : guessed = hors-cible, sinon profil principal.
    """
    raw = result.raw_data or {}
    if raw.get("confidence") in _TRUSTED_CONF:
        return False
    in_target = raw.get("in_target_cluster")
    if in_target is True:
        return False
    if in_target is False:
        return True
    return raw.get("confidence") == ConfidenceLevel.GUESSED.value


def _clusters_overview(results: list[OsintResult]) -> list[dict]:
    """Aperçu déterministe (sans IA) des grappes d'identité, pour présenter les
    personnes distinctes trouvées sous ce nom (mode B) ou situer la grappe-cible."""
    clusters: dict[str, dict] = {}
    for result in results:
        raw = result.raw_data or {}
        cid = raw.get("cluster_id")
        if not cid or not _is_account(result):
            continue
        entry = clusters.setdefault(cid, {"cluster_id": cid, "is_target": False, "accounts": []})
        if raw.get("in_target_cluster") is True:
            entry["is_target"] = True
        entry["accounts"].append({
            "platform": raw.get("platform") or _domain_of(result.url),
            "username": raw.get("username") or raw.get("login") or "",
            "url": result.url,
        })
    return list(clusters.values())


def _finalize_profile(parsed: dict, results: list[OsintResult]) -> dict:
    """Renseigne de façon DÉTERMINISTE les sections de désambiguïsation, quoi que
    l'IA ait produit : comptes hors-cible (homonymes) et aperçu des grappes."""
    parsed["unverified_namesakes"] = [
        _namesake_payload(r) for r in results if _is_offtarget(r) and _is_account(r)
    ]
    overview = _clusters_overview(results)
    if len(overview) > 1:
        parsed["identity_clusters"] = overview
    return parsed


def _namesake_payload(result: OsintResult) -> dict:
    raw = result.raw_data or {}
    return {
        "platform": raw.get("platform") or _domain_of(result.url),
        "username": raw.get("username") or raw.get("login") or "",
        "url": result.url,
        "note": "non vérifié",
    }


def _build_user_prompt(profile: NameProfile, results: list[OsintResult]) -> str:
    # Le profil principal ne se construit QUE sur la grappe-cible (mode A) / les
    # données confirmées-corroborées ; les comptes hors-cible (autres grappes
    # d'homonymes) et les documents au nom seul non rattachés sont isolés.
    main = [r for r in results if not _is_offtarget(r)]
    offtarget_accounts = [r for r in results if _is_offtarget(r) and _is_account(r)]

    data_str = json.dumps(_group_by_module(main), ensure_ascii=False)
    namesakes_str = json.dumps([_namesake_payload(r) for r in offtarget_accounts], ensure_ascii=False)

    return (
        f"Construis une fiche de renseignement complète pour :\n{profile.full_name}\n\n"
        f"Données CONFIRMÉES / CORROBORÉES ({len(main)} sources) :\n{data_str}\n\n"
        f"Comptes au même nom NON VÉRIFIÉS (homonymes possibles, {len(offtarget_accounts)}) :\n{namesakes_str}\n\n"
        "RÈGLES IMPÉRATIVES :\n"
        "- Construis TOUT le profil principal (identité, localisation, contact, "
        "professionnel, activités, réseau, etc.) UNIQUEMENT à partir des données "
        "confirmées/corroborées.\n"
        "- N'utilise JAMAIS les comptes non vérifiés comme des faits sur la cible : "
        "recopie-les tels quels dans le champ 'unverified_namesakes' et nulle part ailleurs.\n\n"
        f"Génère un JSON avec cette structure exacte :\n\n{_PROFILE_SCHEMA}"
    )


def _clean_json_text(raw_text: str) -> str:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


def _repair_truncated_json(text: str) -> str | None:
    """Tente de réparer un JSON coupé en plein vol (réponse tronquée).

    Heuristique : ferme une éventuelle chaîne non terminée, supprime une virgule
    ou une paire "clé": pendante, puis referme toutes les accolades/crochets
    restés ouverts. Couvre les troncatures les plus fréquentes (coupure au milieu
    d'une valeur ou après une virgule). Retourne None si rien d'exploitable.
    """
    text = text.strip()
    if not text:
        return None

    stack: list[str] = []
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]" and stack:
            stack.pop()

    repaired = text
    if in_string:  # chaîne non terminée (cas le plus fréquent) -> on la ferme
        repaired += '"'

    repaired = repaired.rstrip()
    repaired = re.sub(r",\s*$", "", repaired)                 # virgule pendante
    repaired = re.sub(r',?\s*"[^"]*"\s*:\s*$', "", repaired)  # paire "clé": sans valeur
    repaired = repaired.rstrip().rstrip(",")

    for closer in reversed(stack):
        repaired += closer

    return repaired if repaired != text else None


def _parse_profile_json(text: str) -> dict | None:
    """Parse le JSON du profil, avec réparation d'une troncature résiduelle."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    repaired = _repair_truncated_json(text)
    if repaired:
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            return None
    return None


def _minimal_fallback_profile(profile: NameProfile, results: list[OsintResult]) -> dict:
    """Profil minimal construit directement depuis les résultats, sans IA."""
    emails = []
    usernames = []
    platforms = set()
    breaches = []
    namesakes = []
    for result in results:
        raw = result.raw_data or {}
        # Hors-cible (autre grappe / document non rattaché) : isolé, jamais mêlé
        # à l'identité principale.
        if _is_offtarget(result):
            if _is_account(result):
                namesakes.append(_namesake_payload(result))
            continue
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

    return _finalize_profile({
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
        "unverified_namesakes": namesakes,
        "summary": "Profil minimal généré automatiquement (analyse IA indisponible).",
        "confidence_overall": "low",
        "data_freshness": "inconnu",
    }, results)


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
            parsed = _parse_profile_json(cleaned)
            if parsed is not None:
                if attempt == 0 and not raw_text.rstrip().endswith("}"):
                    logger.info("[AI] Profil récupéré après réparation d'une réponse tronquée")
                return _finalize_profile(parsed, results)
            # Échec malgré la réparation : on logge début ET fin pour confirmer
            # visuellement une troncature (le JSON commence bien mais finit coupé).
            stop_reason = getattr(response, "stop_reason", None)
            logger.warning(
                f"[AI] JSON malformé du profil (tentative {attempt + 1}/2, "
                f"stop_reason={stop_reason}) | début={raw_text[:100]!r} | "
                f"fin={raw_text[-100:]!r}"
            )
            continue
        except Exception as e:
            logger.error(f"[AI] Erreur appel Claude profiler : {e}")
            break

    logger.error("[AI] Échec construction profil IA, retour profil minimal")
    return _minimal_fallback_profile(profile, results)
