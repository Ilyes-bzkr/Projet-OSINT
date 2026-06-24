"""
analyzer — OSINT Eagle
Filtrage et scoring de pertinence par IA (Claude).
"""

import json
from typing import Callable, Optional

from anthropic import APITimeoutError, AsyncAnthropic

from app.core.config import settings
from app.core.logger import logger
from app.models.result import OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile, SearchAnchors

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 4000
_TIMEOUT = 120.0
_BATCH_SIZE = 30
_SNIPPET_MAX_LEN = 300

_SYSTEM_PROMPT = (
    "Tu es un analyste OSINT expert. Tu dois déterminer si "
    "chaque résultat concerne réellement la personne cible. "
    "Réponds UNIQUEMENT en JSON valide, aucun texte autour."
)


def _is_always_kept(result: OsintResult) -> bool:
    """Les fuites de données et résultats critiques ne sont jamais filtrés."""
    return result.category == ResultCategory.BREACH or result.risk_level == RiskLevel.CRITICAL


def _result_to_payload(result: OsintResult) -> dict:
    snippet = result.snippet or ""
    if len(snippet) > _SNIPPET_MAX_LEN:
        snippet = snippet[:_SNIPPET_MAX_LEN]
    return {
        "id": result.id,
        "title": result.title,
        "url": result.url,
        "snippet": snippet,
        "module": result.module.value,
        "category": result.category.value,
    }


def _build_user_prompt(
    profile: NameProfile,
    contexte_connu: str,
    batch: list[OsintResult],
    anchors_summary: str = "",
) -> str:
    items = json.dumps([_result_to_payload(r) for r in batch], ensure_ascii=False)

    # Bloc d'ancrage : injecté seulement si l'utilisateur a fourni des ancres.
    anchors_block = ""
    if anchors_summary:
        anchors_block = (
            f"Ancres de vérité fournies par l'utilisateur : {anchors_summary}\n"
            "Règles d'ancrage (prioritaires) :\n"
            "- Un résultat qui CORROBORE une ou plusieurs ancres (même ville, même "
            "école/employeur, même pseudo, tranche d'âge cohérente) → score élevé (0.85-1.0).\n"
            "- Un résultat qui CONTREDIT explicitement une ancre (autre ville claire, autre "
            "employeur/métier incompatible, tranche d'âge manifestement différente) → score très "
            "bas (0.0-0.2) : c'est très probablement un homonyme.\n"
            "- Un résultat qui ne mentionne aucune ancre (ni corroboration ni contradiction) → "
            "juge uniquement sur le nom, score moyen. L'ABSENCE d'information n'est PAS une "
            "contradiction : ne pénalise jamais un résultat au seul motif qu'il ne cite pas les ancres.\n\n"
        )

    return (
        f"Personne recherchée : {profile.full_name}\n"
        f"Variantes connues : {', '.join(profile.full_variants)}\n"
        f"Informations contextuelles disponibles : {contexte_connu or 'Aucune'}\n\n"
        f"{anchors_block}"
        "Pour chaque résultat ci-dessous, donne un score de 0.0 à 1.0 "
        "indiquant la probabilité que ce résultat concerne la cible.\n\n"
        "Critères :\n"
        "- 0.9-1.0 : Nom exact + éléments distinctifs (ville, employeur, photo)\n"
        "- 0.7-0.8 : Nom exact, contexte plausible\n"
        "- 0.5-0.6 : Nom présent mais ambigu (homonyme possible)\n"
        "- 0.0-0.4 : Probablement pas la bonne personne\n\n"
        f"Résultats à analyser :\n{items}\n\n"
        "Réponds avec ce format exact :\n"
        "{\n"
        '  "scores": [\n'
        '    {"id": "xxx", "score": 0.85, "reason": "raison courte"},\n'
        "    ...\n"
        "  ]\n"
        "}"
    )


def _parse_scores_response(raw_text: str) -> dict[str, float]:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("[AI] Réponse de scoring non-JSON, batch ignoré")
        return {}
    scores = {}
    for item in data.get("scores", []):
        rid = item.get("id")
        score = item.get("score")
        if rid is not None and isinstance(score, (int, float)):
            scores[rid] = float(score)
    return scores


def _extract_context_summary(batch: list[OsintResult], previous: str) -> str:
    """Construit un résumé court du contexte cumulatif à partir des snippets/titres du batch."""
    fragments = [previous] if previous else []
    for result in batch[:10]:
        if result.snippet:
            fragments.append(result.snippet[:100])
    return " | ".join(f for f in fragments if f)[:500]


async def filter_results(
    results: list[OsintResult],
    profile: NameProfile,
    search_id: str,
    callback: Optional[Callable] = None,
    anchors: Optional[SearchAnchors] = None,
) -> list[OsintResult]:
    """Filtre les résultats peu pertinents via l'API Claude, par batches de 50.

    Si des ancres sont fournies, le prompt de scoring les utilise pour favoriser
    les résultats qui les corroborent et rejeter ceux qui les contredisent.
    Sans ancres, le comportement est identique à l'historique.
    """
    if not results:
        return []

    if not settings.anthropic_api_key:
        logger.warning("[AI] ANTHROPIC_API_KEY absente, filtrage IA ignoré")
        return results

    # Résumé des ancres (jamais bloquant : au pire on filtre sans ancres).
    anchors_summary = ""
    if anchors is not None:
        try:
            anchors_summary = anchors.to_prompt_summary()
        except Exception as e:
            logger.warning(f"[AI] Ancres ignorées pour le filtrage : {e}")
            anchors_summary = ""
    if anchors_summary:
        logger.info(f"[AI] Filtrage ancré actif : {anchors_summary}")

    always_kept = [r for r in results if _is_always_kept(r)]
    to_score = [r for r in results if not _is_always_kept(r)]

    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=_TIMEOUT)
    batches = [to_score[i:i + _BATCH_SIZE] for i in range(0, len(to_score), _BATCH_SIZE)]
    kept: list[OsintResult] = []
    context_summary = ""
    total_batches = len(batches)

    for batch_idx, batch in enumerate(batches, start=1):
        try:
            response = await client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                temperature=0,
                system=_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": _build_user_prompt(profile, context_summary, batch, anchors_summary),
                }],
            )
            raw_text = response.content[0].text if response.content else ""
            scores = _parse_scores_response(raw_text)
        except APITimeoutError:
            logger.warning(f"[AI] Timeout Claude (batch {batch_idx}/{total_batches}), batch suivant...")
            scores = {}
        except Exception as e:
            logger.error(f"[AI] Erreur appel Claude (batch {batch_idx}/{total_batches}) : {e}")
            scores = {}

        batch_kept = 0
        for result in batch:
            score = scores.get(result.id, 0.0)
            result.relevance_score = score
            if score >= 0.5:
                kept.append(result)
                batch_kept += 1

        context_summary = _extract_context_summary(batch, context_summary)

        if callback:
            try:
                outcome = callback(f"Analyse batch {batch_idx}/{total_batches} — {batch_kept} résultats validés...")
                if outcome is not None and hasattr(outcome, "__await__"):
                    await outcome
            except Exception as e:
                logger.warning(f"[AI] Erreur callback progression : {e}")

    for result in always_kept:
        result.relevance_score = 1.0

    final_results = always_kept + kept
    total = len(results)
    validated = len(final_results)
    filtered_pct = round((1 - validated / total) * 100) if total else 0
    logger.info(f"[AI] {validated}/{total} résultats validés après filtrage ({filtered_pct}% filtrés)")

    return final_results
