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
from app.modules.evidence_engine import account_content_view, loose_contains

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
  "field_sources": {
    "<section.champ>": "<url EXACTE recopiée d'une source fournie qui atteste ce champ>"
  },
  "summary": str,
  "confidence_overall": "high"|"medium"|"low",
  "data_freshness": str
}"""

# Champs d'identité « déductibles » : le modèle ne doit les renseigner que si la
# valeur est LITTÉRALEMENT présente dans une source fournie. Une passe de validation
# en code (_enforce_sourced_fields) remet à null tout ce qui n'est pas attesté —
# garantie anti-invention indépendante du modèle (mêmes principes que
# account_enricher._validate_attrs). Format : {section: (champs scalaires,), (champs listes,)}.
_SOURCED_SCALARS = {
    "identity": ("age_estimated", "nationality"),
    "location": ("current_city", "current_country", "timezone_estimated"),
    "professional": ("current_employer", "current_school", "field", "job_title"),
    "behavior": ("posting_hours_estimated", "writing_style"),
}
_SOURCED_LISTS = {
    "identity": ("languages",),
    "location": ("past_cities",),
    "professional": ("past_employers",),
}


def _domain_of(url: str | None) -> str:
    if not url:
        return ""
    return urllib.parse.urlparse(url).netloc


def _result_to_payload(result: OsintResult) -> dict:
    snippet = result.snippet or ""
    if len(snippet) > _SNIPPET_MAX_LEN:
        snippet = snippet[:_SNIPPET_MAX_LEN]
    payload = {
        "title": result.title,
        "domain": _domain_of(result.url),
        # URL complète : sert de citation de source vérifiable par le modèle et
        # par la passe de validation en code (field_sources).
        "url": result.url,
        "snippet": snippet,
        "module": result.module.value,
    }
    # Niveau de confiance d'appartenance (comptes confirmés / corroborés / devinés) :
    # transmis pour que le modèle traite un compte prouvé comme un fait et un compte
    # deviné avec prudence. Sans ce champ, tout le travail du moteur de preuves était
    # perdu à l'étape de synthèse finale.
    confidence = (result.raw_data or {}).get("confidence")
    if confidence:
        payload["confidence"] = confidence
    return payload


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

    Priorités (la séparation de grappe l'emporte sur « corroborated ») :
    - confirmed (match EXACT d'ancre : pseudo/email) → toujours profil principal.
    - weak_mention → hors-cible (jamais un fait).
    - in_target_cluster == False → hors-cible **même si corroborated** : une grappe
      non-cible est un homonyme, et la corroboration par cohérence interne
      (convergence) prouve « même personne entre eux », pas « c'est la cible ».
    - in_target_cluster == True → profil principal (grappe-cible, mode A).
    - tag absent (résultats dérivés couche 2, paste, breach, mode B) → corroboré =
      profil principal ; guessed = hors-cible.
    """
    raw = result.raw_data or {}
    confidence = raw.get("confidence")
    # Match exact d'ancre : appartenance certaine, toujours profil principal.
    if confidence == ConfidenceLevel.CONFIRMED.value:
        return False
    # Mention faible (nom trouvé dans un fichier/classement, hit hors-sujet).
    if raw.get("weak_mention"):
        return True
    # Grappe d'identité (mode A) : la non-appartenance à la grappe-cible prime sur
    # « corroborated » — on isole les homonymes corroborés par cohérence interne.
    in_target = raw.get("in_target_cluster")
    if in_target is False:
        return True
    if in_target is True:
        return False
    # Pas de tag de grappe : corroboré = principal, guessed = hors-cible.
    if confidence == ConfidenceLevel.CORROBORATED.value:
        return False
    return confidence == ConfidenceLevel.GUESSED.value


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


def _build_sources_text(results: list[OsintResult]) -> str:
    """Corpus texte des sources RÉELLEMENT fournies au modèle (profil principal).

    Sert de vérité pour la passe anti-invention : un attribut d'identité n'est
    conservé que si sa valeur apparaît littéralement ici. On agrège titre, snippet,
    et le contenu structuré des comptes (nom affiché, ville, métier, bio, liens…)
    pour reconnaître aussi les attributs issus de comptes confirmés/corroborés.
    """
    parts: list[str] = []
    for result in results:
        parts.append(result.title or "")
        parts.append(result.snippet or "")
        raw = result.raw_data or {}
        for value in account_content_view(raw).values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(v) for v in value)
    return " \n ".join(p for p in parts if p)


def _enforce_sourced_fields(parsed: dict, sources_text: str) -> dict:
    """Passe de validation DÉTERMINISTE anti-invention (Phase 1).

    Remet à null tout champ d'identité déductible dont la valeur n'apparaît pas
    littéralement dans les sources fournies, et filtre les listes de la même façon.
    Garantie indépendante du modèle : même si l'IA invente « tunisien » ou « EPITA »,
    ces valeurs disparaissent si aucune source ne les atteste. N'affecte PAS les
    champs issus de modules déterministes (contact, fuites, empreinte, comptes).
    """
    if not isinstance(parsed, dict) or not sources_text:
        return parsed

    removed: list[str] = []

    for section, keys in _SOURCED_SCALARS.items():
        sec = parsed.get(section)
        if not isinstance(sec, dict):
            continue
        for key in keys:
            value = sec.get(key)
            if isinstance(value, str) and value.strip() and not loose_contains(sources_text, value, min_len=2):
                sec[key] = None
                removed.append(f"{section}.{key}={value!r}")

    for section, keys in _SOURCED_LISTS.items():
        sec = parsed.get(section)
        if not isinstance(sec, dict):
            continue
        for key in keys:
            values = sec.get(key)
            if not isinstance(values, list):
                continue
            kept = [v for v in values if isinstance(v, str) and loose_contains(sources_text, v, min_len=2)]
            if len(kept) != len(values):
                removed.append(f"{section}.{key} (-{len(values) - len(kept)})")
            sec[key] = kept

    if removed:
        logger.info(
            f"[AI] provenance : {len(removed)} attribut(s) d'identité non sourcé(s) "
            f"neutralisé(s) : {removed}"
        )
    return parsed


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
        "recopie-les tels quels dans le champ 'unverified_namesakes' et nulle part ailleurs.\n"
        "- INTERDICTION D'INFÉRER : pour tout champ d'identité déductible "
        "(nationalité, âge, ville/pays actuel, villes passées, langues, employeur, "
        "école, métier, domaine, timezone, style d'écriture), ne mets une valeur que "
        "si elle est ÉCRITE LITTÉRALEMENT dans une source fournie. Ne déduis JAMAIS "
        "une nationalité/origine d'un nom, d'une langue ou d'un classement par pays. "
        "Si ce n'est pas explicitement écrit, mets null (ou liste vide).\n"
        "- Pour chacun de ces champs renseignés, ajoute une entrée dans 'field_sources' "
        "avec la clé '<section>.<champ>' (ex: 'location.current_city') et l'URL EXACTE "
        "de la source qui l'atteste (recopiée depuis le champ 'url' des données).\n"
        "- Le champ 'summary' ne doit énoncer que des faits sourcés, sans spéculation.\n\n"
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

    # Corpus des sources du profil principal (hors homonymes) : vérité de la passe
    # anti-invention appliquée après génération.
    sources_text = _build_sources_text([r for r in selected if not _is_offtarget(r)])

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
                # Garde-fou anti-invention : neutralise les attributs d'identité non
                # attestés par une source avant toute mise en forme / affichage.
                parsed = _enforce_sourced_fields(parsed, sources_text)
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
