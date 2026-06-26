"""
evidence_engine — OSINT Eagle
Moteur de preuves DÉTERMINISTE (aucun appel réseau / IA).

Maigret confirme qu'un compte EXISTE, jamais qu'il APPARTIENT à la cible. Ce
module décide si un compte DEVINÉ (homonyme potentiel) peut être promu au rang
de compte appartenant à la cible, en recoupant son CONTENU (snippet / ids_data
exposés par social_checker) avec les identifiants déjà CONFIRMÉS de la cible.

Grille de force des recoupements :
- PREUVE FORTE   (1 suffit)  : email identique, téléphone identique, pseudo
                               DISTINCTIF identique, lien croisé vers une identité
                               confirmée (URL/handle distinctif).
- PREUVE MOYENNE (il en faut 2) : pseudo SIMPLE identique, employeur/école
                               concordant, nom complet exact + élément contextuel
                               concordant (localisation).
- PREUVE FAIBLE  (jamais)    : même ville / pays / tranche d'âge / juste le nom.

Décision : >= 1 forte OU >= 2 moyennes  →  "corroborated", sinon "guessed".
Un compte dont le pseudo est exactement un identifiant confirmé est "confirmed".
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from app.models.result import ConfidenceLevel

__all__ = [
    "ConfirmedReference",
    "classify_pseudo",
    "evaluate_account",
    "norm",
    "norm_email",
    "loose_contains",
]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?\d[\s.\-]?){8,15}")
# Année de naissance plausible (~1950–2019) : un pseudo "nom + année" reste SIMPLE.
_YEAR_RE = re.compile(r"^(?:19[5-9]\d|20[0-1]\d)$")

# Champs d'ids_data portant l'avatar : exclus du texte/liens analysés (une URL
# d'image ne prouve pas une appartenance).
_AVATAR_FIELDS = {"image", "avatar", "image_url", "avatar_url"}

# Longueur minimale d'un handle confirmé pour servir de preuve de lien croisé
# (évite qu'un token court et banal ne matche par hasard).
_MIN_HANDLE_LEN = 4


def _strip_accents(text: Optional[str]) -> str:
    norm = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in norm if not unicodedata.combining(c))


def _norm(text: Optional[str]) -> str:
    """Minuscule, sans accents, alphanumérique uniquement (séparateurs supprimés)."""
    return re.sub(r"[^a-z0-9]", "", _strip_accents(text).lower())


def _loose(text: Optional[str]) -> str:
    """Minuscule sans accents en conservant les espaces (pour le matching d'expressions)."""
    return _strip_accents(text).lower()


def _norm_email(email: Optional[str]) -> str:
    return (email or "").strip().lower()


def _norm_phone(phone: Optional[str]) -> str:
    """Conserve les 9 derniers chiffres (tolère préfixes pays / formats variés)."""
    digits = re.sub(r"\D", "", phone or "")
    return digits[-9:] if len(digits) >= 9 else ""


# --- Helpers publics réutilisables (mêmes règles de normalisation que le moteur) ---

def norm(text: Optional[str]) -> str:
    """Minuscule, sans accents, alphanumérique uniquement (séparateurs supprimés)."""
    return _norm(text)


def norm_email(email: Optional[str]) -> str:
    return _norm_email(email)


def loose_contains(haystack: Optional[str], needle: Optional[str], min_len: int = 3) -> bool:
    """True si `needle` (>= min_len) apparaît dans `haystack`, casse/accents ignorés."""
    hay = _loose(haystack)
    nee = _loose(needle).strip()
    return bool(nee) and len(nee) >= min_len and nee in hay


@dataclass
class ConfirmedReference:
    """Identifiants CONFIRMÉS de la cible servant de référence aux preuves."""
    first_name: str = ""
    last_name: str = ""
    full_name: str = ""
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    usernames: set = field(default_factory=set)
    links: set = field(default_factory=set)
    employer: Optional[str] = None
    city: Optional[str] = None


def _residue(username: str, first: str, last: str) -> str:
    """Résidu du pseudo après retrait des éléments prénom/nom (insensible
    casse/accents/séparateurs)."""
    u = _norm(username)
    for tok in (_norm(first), _norm(last)):
        if tok and len(tok) >= 2:
            u = u.replace(tok, "")
    return u


def classify_pseudo(username: str, first: str, last: str) -> str:
    """Retourne 'simple' ou 'distinctive' selon l'entropie du résidu.

    - résidu vide / un seul caractère / séparateurs          → simple
    - résidu = année de naissance plausible (~1950–2019)     → simple
    - résidu avec lettres/chiffres imprévisibles             → distinctive
      (un nombre qui n'est PAS une année plausible, ex. "93", rend distinctif)
    """
    res = _residue(username, first, last)
    if len(res) <= 1:
        return "simple"
    if _YEAR_RE.match(res):
        return "simple"
    return "distinctive"


def _account_text_and_links(account_raw: dict, snippet: Optional[str]) -> tuple[str, str]:
    """Agrège le texte exploitable et les liens d'un compte (hors avatar)."""
    content = account_raw.get("content") or {}
    ids_data = account_raw.get("ids_data") or {}

    text_parts = [
        snippet or "",
        content.get("fullname") or "",
        content.get("location") or "",
        content.get("occupation") or "",
        content.get("bio") or "",
        content.get("email") or "",
    ]
    links = list(content.get("links") or [])
    for key, value in ids_data.items():
        if key in _AVATAR_FIELDS or not isinstance(value, str):
            continue
        text_parts.append(value)
        if value.startswith("http"):
            links.append(value)

    return " ".join(p for p in text_parts if p), " ".join(links)


def _confirmed_emails(ref: ConfirmedReference) -> set:
    return {_norm_email(e) for e in ref.emails if e}


def _link_token(link: str) -> str:
    """Réduit une URL confirmée à son host+chemin significatif (sans schéma/www)."""
    token = re.sub(r"^https?://", "", _loose(link)).lstrip("/")
    token = re.sub(r"^www\.", "", token)
    return token.strip("/")


def evaluate_account(
    account_raw: dict,
    snippet: Optional[str],
    account_username: str,
    ref: ConfirmedReference,
) -> tuple[str, list[str]]:
    """Évalue un compte deviné et retourne (niveau, raisons).

    Le niveau est l'une des valeurs de ConfidenceLevel. Les raisons listent les
    preuves trouvées (pour le logging et l'affichage).
    """
    reasons: list[str] = []

    # 0) Pseudo exactement égal à un identifiant confirmé → confirmed.
    norm_user = _norm(account_username)
    ref_users_norm = {_norm(u) for u in ref.usernames if u}
    if norm_user and norm_user in ref_users_norm:
        return ConfidenceLevel.CONFIRMED.value, ["pseudo identique à un identifiant confirmé (GitHub/ancre)"]

    text_blob, links_blob = _account_text_and_links(account_raw, snippet)
    text_norm = _norm(text_blob)
    text_loose = _loose(text_blob)
    links_norm = _norm(links_blob)

    strong = 0
    medium = 0

    # === PREUVES FORTES ===

    # Email identique à un email confirmé.
    acct_emails = {_norm_email(e) for e in _EMAIL_RE.findall(text_blob)}
    ref_emails = _confirmed_emails(ref)
    email_hit = acct_emails & ref_emails
    if email_hit:
        strong += 1
        reasons.append(f"email identique confirmé ({sorted(email_hit)[0]})")

    # Téléphone identique à un numéro confirmé.
    acct_phones = {_norm_phone(p) for p in _PHONE_RE.findall(text_blob)} - {""}
    ref_phones = {_norm_phone(p) for p in ref.phones if p} - {""}
    if acct_phones & ref_phones:
        strong += 1
        reasons.append("téléphone identique confirmé")

    # Lien croisé vers un pseudo DISTINCTIF confirmé (présent dans le texte/liens).
    for u in ref.usernames:
        nu = _norm(u)
        if len(nu) >= _MIN_HANDLE_LEN and classify_pseudo(u, ref.first_name, ref.last_name) == "distinctive":
            if nu in text_norm or nu in links_norm:
                strong += 1
                reasons.append(f"référence croisée vers un pseudo distinctif confirmé ({u})")
                break

    # Lien croisé vers une URL confirmée (ex. le GitHub confirmé dans la bio).
    for link in ref.links:
        token = _link_token(link)
        if token and len(token) >= _MIN_HANDLE_LEN and token in links_blob.lower():
            strong += 1
            reasons.append(f"lien vers une URL confirmée ({token})")
            break

    # === PREUVES MOYENNES ===

    # Employeur / école concordant (expression complète, tolérante casse/accents).
    if ref.employer:
        emp = _loose(ref.employer).strip()
        if emp and len(emp) >= 3 and emp in text_loose:
            medium += 1
            reasons.append(f"employeur/école concordant ({ref.employer})")

    # Nom complet exact affiché + élément contextuel concordant (localisation).
    content = account_raw.get("content") or {}
    displayed = content.get("fullname")
    first_n, last_n = _norm(ref.first_name), _norm(ref.last_name)
    if displayed and first_n and last_n:
        disp_n = _norm(displayed)
        if first_n in disp_n and last_n in disp_n:
            contextual = False
            if ref.city:
                city = _loose(ref.city).strip()
                loc = _loose(content.get("location"))
                if city and city in loc:
                    contextual = True
            if contextual:
                medium += 1
                reasons.append("nom complet exact + localisation concordante")

    # === DÉCISION ===
    if strong >= 1 or medium >= 2:
        return ConfidenceLevel.CORROBORATED.value, reasons
    return ConfidenceLevel.GUESSED.value, reasons
