"""
reporter — OSINT Eagle
Génération du rapport HTML final à partir du profil structuré.
"""

import html

from app.core.logger import logger
from app.models.search import NameProfile

_CATEGORY_ICONS = {
    "sport": "⚽", "gaming": "🎮", "musique": "🎵", "music": "🎵",
    "fitness": "🏃", "tech": "💻", "voyage": "✈️", "travel": "✈️",
    "cuisine": "🍳", "food": "🍳", "art": "🎨", "lecture": "📚",
    "reading": "📚", "photo": "📷", "cinema": "🎬", "film": "🎬",
}

_CONFIDENCE_LABELS = {"high": "Confiance élevée", "medium": "Confiance moyenne", "low": "Confiance faible"}

_SEVERITY_LABELS = {"critical": "CRITIQUE", "high": "ÉLEVÉ", "medium": "MOYEN"}

_COUNTRY_FLAGS = {
    "france": "🇫🇷", "etats-unis": "🇺🇸", "états-unis": "🇺🇸", "usa": "🇺🇸",
    "royaume-uni": "🇬🇧", "uk": "🇬🇧", "allemagne": "🇩🇪", "espagne": "🇪🇸",
    "italie": "🇮🇹", "belgique": "🇧🇪", "suisse": "🇨🇭", "canada": "🇨🇦",
}


def _esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _flag_for_country(country: str) -> str:
    if not country:
        return "🌍"
    return _COUNTRY_FLAGS.get(country.strip().lower(), "🌍")


def _icon_for_activity(category: str) -> str:
    if not category:
        return "🔹"
    return _CATEGORY_ICONS.get(category.strip().lower(), "🔹")


def _confidence_badge(level: str) -> str:
    level = level or "low"
    return f'<span class="confidence-badge confidence-{_esc(level)}">{_esc(_CONFIDENCE_LABELS.get(level, level))}</span>'


def _render_identity(identity: dict) -> str:
    photo = identity.get("photo_url")
    photo_html = f'<img class="ai-identity-photo" src="{_esc(photo)}" alt="photo">' if photo else ""
    languages = identity.get("languages") or []
    languages_html = ", ".join(_esc(l) for l in languages) if languages else "Inconnues"
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">👤</span> IDENTITÉ</h3>
      <div class="ai-identity-row">
        {photo_html}
        <div class="ai-identity-info">
          <div class="ai-identity-name">{_esc(identity.get('full_name'))}</div>
          <div class="ai-identity-meta">
            {_esc(identity.get('age_estimated') or 'Âge inconnu')} &middot;
            {_esc(identity.get('nationality') or 'Nationalité inconnue')}
          </div>
          <div class="ai-identity-meta">Langues : {languages_html}</div>
        </div>
      </div>
    </div>"""


def _render_location(location: dict) -> str:
    past_cities = location.get("past_cities") or []
    past_html = "".join(f"<li>{_esc(c)}</li>" for c in past_cities) if past_cities else "<li class='empty-state'>Aucune</li>"
    flag = _flag_for_country(location.get("current_country"))
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">📍</span> LOCALISATION</h3>
      <p>{flag} <strong>{_esc(location.get('current_city') or 'Inconnue')}</strong>, {_esc(location.get('current_country') or '')}</p>
      <p class="ai-label">Villes passées :</p>
      <ul class="ai-list">{past_html}</ul>
      <p class="ai-label">Timezone estimée : {_esc(location.get('timezone_estimated') or 'Inconnue')}</p>
      {_confidence_badge(location.get('location_confidence'))}
    </div>"""


def _render_contact(contact: dict) -> str:
    emails = contact.get("emails") or []
    phones = contact.get("phones") or []
    usernames = contact.get("usernames") or []

    _leaked_badge = '<span class="badge-leaked">LEAKÉ</span>'
    emails_html = "".join(
        f"<li>{_esc(e.get('value'))} "
        f"{_leaked_badge if e.get('leaked') else ''} "
        f"<span class='ai-source'>({_esc(e.get('source'))})</span></li>"
        for e in emails
    ) or "<li class='empty-state'>Aucun email trouvé</li>"

    phones_html = "".join(
        f"<li>{_esc(p.get('value'))} <span class='ai-source'>({_esc(p.get('source'))})</span></li>"
        for p in phones
    ) or "<li class='empty-state'>Aucun téléphone trouvé</li>"

    usernames_html = "".join(
        f"<li><a href=\"{_esc(u.get('url'))}\" target=\"_blank\" rel=\"noopener\">{_esc(u.get('platform'))} — @{_esc(u.get('value'))}</a></li>"
        for u in usernames
    ) or "<li class='empty-state'>Aucun pseudo trouvé</li>"

    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">📧</span> CONTACT</h3>
      <p class="ai-label">Emails :</p>
      <ul class="ai-list">{emails_html}</ul>
      <p class="ai-label">Téléphones :</p>
      <ul class="ai-list">{phones_html}</ul>
      <p class="ai-label">Pseudos :</p>
      <ul class="ai-list">{usernames_html}</ul>
    </div>"""


def _render_professional(professional: dict) -> str:
    past_employers = professional.get("past_employers") or []
    skills = professional.get("skills") or []
    past_html = "".join(f"<li>{_esc(e)}</li>" for e in past_employers) if past_employers else "<li class='empty-state'>Aucun</li>"
    skills_html = "".join(f"<span class='skill-tag'>{_esc(s)}</span>" for s in skills) if skills else "<span class='empty-state'>Aucune compétence identifiée</span>"
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">💼</span> PROFESSIONNEL</h3>
      <p class="ai-highlight">{_esc(professional.get('current_employer') or 'Employeur actuel inconnu')}</p>
      <p>{_esc(professional.get('job_title') or '')}</p>
      <p class="ai-label">Anciens employeurs :</p>
      <ul class="ai-list">{past_html}</ul>
      <p class="ai-label">Formation : {_esc(professional.get('current_school') or 'Inconnue')}</p>
      <p class="ai-label">Compétences :</p>
      <div class="skill-tags">{skills_html}</div>
    </div>"""


def _render_activities(activities: list) -> str:
    if not activities:
        return """
        <div class="ai-section">
          <h3 class="ai-section-title"><span class="ai-icon">🎯</span> ACTIVITÉS &amp; CENTRES D'INTÉRÊT</h3>
          <p class="empty-state">Aucune activité identifiée</p>
        </div>"""
    items = "".join(
        f"""<div class="activity-item">
          <span class="activity-icon">{_icon_for_activity(a.get('category'))}</span>
          <div class="activity-content">
            <div class="activity-desc">{_esc(a.get('description'))}</div>
            <div class="activity-meta">
              {_esc(a.get('frequency') or '')}
              <span class="activity-sources">({_esc(a.get('sources_count', 0))} source(s))</span>
            </div>
          </div>
        </div>"""
        for a in activities
    )
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">🎯</span> ACTIVITÉS &amp; CENTRES D'INTÉRÊT</h3>
      {items}
    </div>"""


def _render_behavior(behavior: dict) -> str:
    platforms = behavior.get("most_active_platforms") or []
    topics = behavior.get("recurring_topics") or []
    platforms_html = "".join(f"<span class='platform-tag'>{_esc(p)}</span>" for p in platforms) or "<span class='empty-state'>Aucune</span>"
    topics_html = "".join(f"<span class='skill-tag'>{_esc(t)}</span>" for t in topics) or "<span class='empty-state'>Aucun</span>"
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">📊</span> COMPORTEMENT EN LIGNE</h3>
      <p class="ai-label">Plateformes les plus actives :</p>
      <div class="platform-tags">{platforms_html}</div>
      <p>Heures de publication : {_esc(behavior.get('posting_hours_estimated') or 'Inconnues')}</p>
      <p>Ton général : {_esc(behavior.get('tone') or 'Inconnu')}</p>
      <p class="ai-label">Sujets récurrents :</p>
      <div class="skill-tags">{topics_html}</div>
      <p>Fréquence de publication : {_esc(behavior.get('posting_frequency') or 'Inconnue')}</p>
    </div>"""


def _render_network(network: dict) -> str:
    people = network.get("mentioned_people") or []
    communities = network.get("communities") or []
    organizations = network.get("organizations") or []
    people_html = "".join(
        f"<li>{_esc(p.get('name'))}{' — ' + _esc(p.get('relation')) if p.get('relation') else ''}</li>"
        for p in people
    ) or "<li class='empty-state'>Aucune personne identifiée</li>"
    communities_html = ", ".join(_esc(c) for c in communities) or "Aucune"
    organizations_html = ", ".join(_esc(o) for o in organizations) or "Aucune"
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">🕸️</span> RÉSEAU</h3>
      <p class="ai-label">Personnes mentionnées :</p>
      <ul class="ai-list">{people_html}</ul>
      <p>Communautés : {communities_html}</p>
      <p>Organisations : {organizations_html}</p>
    </div>"""


def _render_breaches(breaches: list) -> str:
    if not breaches:
        return """
        <div class="ai-section ai-section-danger">
          <h3 class="ai-section-title"><span class="ai-icon">🔓</span> FUITES DÉTECTÉES</h3>
          <span class="badge-no-leak">AUCUNE FUITE DÉTECTÉE</span>
        </div>"""
    items = "".join(
        f"""<div class="breach-item">
          <div class="breach-source">{_esc(b.get('source'))}</div>
          <div class="breach-date">{_esc(b.get('date'))}</div>
          <div class="breach-types">
            {''.join(f"<span class='badge-leaked'>{_esc(t)}</span>" for t in (b.get('data_exposed') or []))}
          </div>
          <span class="badge-severity-{_esc(b.get('severity', 'medium'))}">{_esc(_SEVERITY_LABELS.get(b.get('severity'), 'MOYEN'))}</span>
        </div>"""
        for b in breaches
    )
    return f"""
    <div class="ai-section ai-section-danger">
      <h3 class="ai-section-title"><span class="ai-icon">🔓</span> FUITES DÉTECTÉES</h3>
      {items}
    </div>"""


def _render_digital_footprint(footprint: dict) -> str:
    platforms = footprint.get("platforms_confirmed") or []
    platforms_html = "".join(f"<span class='platform-tag'>{_esc(p)}</span>" for p in platforms) or "<span class='empty-state'>Aucune</span>"
    return f"""
    <div class="ai-section">
      <h3 class="ai-section-title"><span class="ai-icon">🌐</span> EMPREINTE DIGITALE</h3>
      <p><strong>{_esc(footprint.get('total_platforms_found', 0))}</strong> plateformes trouvées</p>
      <div class="platform-tags">{platforms_html}</div>
      <p>Présence en ligne depuis : {_esc(footprint.get('oldest_online_presence') or 'Inconnue')}</p>
      <p>Niveau d'exposition publique : <strong>{_esc(footprint.get('public_exposure_level') or 'inconnu')}</strong></p>
      <p class="ai-narrative">{_esc(footprint.get('what_stranger_finds') or '')}</p>
    </div>"""


def _render_privacy_score(privacy: dict) -> str:
    score = privacy.get("score", 0)
    level = privacy.get("level", "medium")
    breakdown = privacy.get("score_breakdown") or {}
    risks = privacy.get("main_risks") or []
    risks_html = "".join(f"<li>{_esc(r)}</li>" for r in risks) or "<li class='empty-state'>Aucun risque majeur identifié</li>"

    breakdown_labels = {
        "personal_info_exposed": "Infos personnelles exposées",
        "contact_info_exposed": "Infos de contact exposées",
        "professional_info_exposed": "Infos professionnelles",
        "breach_exposure": "Exposition aux fuites",
        "social_footprint": "Empreinte sociale",
    }
    breakdown_html = "".join(
        f"""<div class="risk-bar-row">
          <span class="risk-bar-label">{label}</span>
          <div class="risk-bar"><div class="risk-bar-fill" style="width:{min(100, int(breakdown.get(key, 0) / 20 * 100))}%"></div></div>
          <span class="risk-bar-value">{_esc(breakdown.get(key, 0))}/20</span>
        </div>"""
        for key, label in breakdown_labels.items()
    )

    return f"""
    <div class="ai-section ai-section-score">
      <h3 class="ai-section-title"><span class="ai-icon">⚠️</span> SCORE DE RISQUE PRIVACY</h3>
      <div class="risk-score-circle risk-score-{_esc(level)}">
        <span class="risk-score-value">{_esc(score)}</span>
        <span class="risk-score-max">/100</span>
      </div>
      <div class="risk-breakdown">{breakdown_html}</div>
      <p class="ai-label">Risques principaux :</p>
      <ul class="ai-list">{risks_html}</ul>
    </div>"""


async def generate_report_html(ai_profile: dict, profile: NameProfile) -> str:
    """Génère le HTML complet du rapport IA à injecter dans le panneau droit."""
    try:
        identity = ai_profile.get("identity", {}) or {}
        location = ai_profile.get("location", {}) or {}
        contact = ai_profile.get("contact", {}) or {}
        professional = ai_profile.get("professional", {}) or {}
        activities = ai_profile.get("activities", []) or []
        behavior = ai_profile.get("behavior", {}) or {}
        network = ai_profile.get("network", {}) or {}
        breaches = ai_profile.get("breaches", []) or []
        footprint = ai_profile.get("digital_footprint", {}) or {}
        privacy = ai_profile.get("privacy_score", {}) or {}
        summary = ai_profile.get("summary", "")
        confidence = ai_profile.get("confidence_overall", "low")

        sections = [
            f'<div class="ai-summary">{_esc(summary)} {_confidence_badge(confidence)}</div>',
            _render_identity(identity),
            _render_location(location),
            _render_contact(contact),
            _render_professional(professional),
            _render_activities(activities),
            _render_behavior(behavior),
            _render_network(network),
            _render_breaches(breaches),
            _render_digital_footprint(footprint),
            _render_privacy_score(privacy),
        ]
        return "\n".join(sections)
    except Exception as e:
        logger.error(f"[AI] Erreur génération HTML du rapport : {e}")
        return '<div class="ai-section ai-section-danger">Erreur lors de la génération du rapport IA.</div>'
