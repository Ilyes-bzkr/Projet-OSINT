"""
name_engine — OSINT Eagle
Générateur de variantes de nom, de username et de dorks de recherche.
"""

import re
import unicodedata

from app.models.search import NameProfile

__all__ = ["generate_search_profile", "generate_anchored_dorks"]

_FRENCH_MEDIA = ["lemonde.fr", "lefigaro.fr", "liberation.fr", "ouest-france.fr", "20minutes.fr"]


def _strip_accents(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(c for c in normalized if not unicodedata.combining(c))


def _clean_token(token: str) -> str:
    token = _strip_accents(token).lower()
    return re.sub(r"[^a-z0-9]", "", token)


def _split_name(full_name: str) -> tuple[str, str]:
    words = full_name.strip().split()
    if len(words) == 1:
        return words[0], ""
    if len(words) == 2:
        return words[0], words[1]
    return words[0], words[-1]


def _build_full_variants(first: str, last: str) -> list[str]:
    if not last:
        return [first, first.lower(), first.upper()]

    first_initial = first[0]
    last_initial = last[0]

    variants = [
        f"{first} {last}",
        f"{last} {first}",
        f"{first.lower()} {last.lower()}",
        f"{last.upper()} {first.upper()}",
        f"{first_initial}. {last}",
        f"{first} {last_initial}.",
        f"{last}, {first}",
        f"{first}-{last}",
        f"{last}-{first}",
        f"{first.upper()} {last.upper()}",
    ]
    # Dédupliquer en conservant l'ordre
    seen = set()
    unique = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _build_username_variants(first: str, last: str) -> list[str]:
    f = _clean_token(first)
    l = _clean_token(last) if last else ""

    if not l:
        variants = [f, f"{f}1", f"{f}123", f"{f}99", f"x{f}", f"{f}officiel"]
    else:
        fi = f[0] if f else ""
        li = l[0] if l else ""
        l_novowel = re.sub(r"[aeiou]", "", l)
        l4 = l[:4]
        f3 = f[:3]
        l_consonants3 = l_novowel[:3]

        variants = [
            f"{f}{l}",
            f"{f}.{l}",
            f"{f}_{l}",
            f"{f}-{l}",
            f"{l}{f}",
            f"{fi}.{l}",
            f"{f}{li}",
            f"{fi}{l}",
            f"{f}{l}1",
            f"{f}{l}123",
            f"{f}_{l}99",
            f"{l}.{f}",
            f"{l}_{f}",
            f"{fi}{li}",
            f"{f}{l}2024",
        ]

        # Suppression des voyelles du nom de famille (pseudos tronqués type "bzkr")
        if l_novowel:
            variants += [f"{f}_{l_novowel}", f"{f}{l_novowel}", f"{f}.{l_novowel}"]

        # Troncature à 4 lettres du nom de famille
        if l4:
            variants += [f"{f}_{l4}", f"{f}{l4}"]

        # Prénom tronqué (3 lettres) + nom tronqué (3 consonnes)
        if f3 and l_consonants3:
            variants += [f"{f3}_{l_consonants3}", f"{f3}{l_consonants3}"]

        # Initiale + nom tronqué
        if fi and l_novowel:
            variants.append(f"{fi}{l_novowel}")
        if fi and l4:
            variants.append(f"{fi}{l4}")

        # Prénom complet + chiffres courants (pseudo principal souvent déjà pris)
        variants += [f"{f}01", f"{f}_01", f"{f}1", f"{f}123", f"{f}_1"]

        # Nom de famille consonantique + prénom
        if l_novowel:
            variants += [f"{l_novowel}{f}", f"{l_novowel}_{f}"]

    seen = set()
    unique = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            unique.append(v)
    return unique[:50]


def _build_search_queries(full_name: str) -> dict[str, list[str]]:
    quoted = f'"{full_name}"'
    return {
        "identity": [quoted],
        "contact": [
            f"{quoted} email",
            f"{quoted} phone",
            f"{quoted} adresse",
            f"{quoted} mobile",
        ],
        "professional": [
            f"{quoted} site:linkedin.com",
            f"{quoted} CV",
            f"{quoted} employeur",
            f"{quoted} ingénieur",
            f"{quoted} stage",
        ],
        "social": [
            f"{quoted} site:twitter.com",
            f"{quoted} site:instagram.com",
            f"{quoted} site:facebook.com",
            f"{quoted} site:reddit.com",
            f"{quoted} site:tiktok.com",
        ],
        "technical": [
            f"{quoted} site:github.com",
            f"{quoted} site:stackoverflow.com",
            f"{quoted} site:gitlab.com",
        ],
        "documents": [
            f"{quoted} filetype:pdf",
            f"{quoted} filetype:doc",
        ],
        "news": [f"{quoted} site:{media}" for media in _FRENCH_MEDIA],
        "academic": [
            f"{quoted} université",
            f"{quoted} école",
            f"{quoted} étudiant",
        ],
    }


def generate_search_profile(full_name: str) -> NameProfile:
    """Génère le profil de recherche complet pour un nom donné."""
    first, last = _split_name(full_name)

    return NameProfile(
        first_name=first,
        last_name=last,
        full_name=full_name,
        full_variants=_build_full_variants(first, last),
        username_variants=_build_username_variants(first, last),
        search_queries=_build_search_queries(full_name),
    )


def generate_anchored_dorks(
    first: str,
    last: str,
    city: str | None = None,
    employer: str | None = None,
) -> list[str]:
    """Génère des dorks à haute précision combinant le nom et les ancres.

    Beaucoup plus discriminants que le nom seul : en croisant le nom avec la
    ville et/ou l'employeur/école, on réduit fortement les homonymes.

    Retourne une liste vide si ni ville ni employeur ne sont fournis.
    """
    full_name = f"{first} {last}".strip() if last else (first or "").strip()
    if not full_name:
        return []

    city = (city or "").strip()
    employer = (employer or "").strip()
    quoted = f'"{full_name}"'

    queries: list[str] = []

    if city:
        queries.append(f'{quoted} "{city}"')
        queries.append(f'{quoted} "{city}" site:linkedin.com')

    if employer:
        queries.append(f'{quoted} "{employer}"')
        queries.append(f'{quoted} "{employer}" site:linkedin.com')

    # Variante la plus discriminante : nom + ville + employeur.
    if city and employer:
        queries.append(f'{quoted} "{city}" "{employer}"')

    # Dédupliquer en conservant l'ordre.
    seen = set()
    unique = []
    for q in queries:
        if q not in seen:
            seen.add(q)
            unique.append(q)
    return unique
