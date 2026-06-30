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
    "account_content_view",
    "converge_accounts",
    "norm",
    "norm_email",
    "loose_contains",
]

# GitHub expose ses attributs à plat dans raw_data ; les autres comptes (Maigret)
# sous raw_data["content"]. Cette table sert à présenter une vue unifiée.
_GITHUB_TOPLEVEL = {
    "fullname": "name",
    "location": "location",
    "occupation": "company",
    "bio": "bio",
    "email": "email",
}

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


def account_content_view(raw_data: Optional[dict]) -> dict:
    """Vue UNIFIÉE des attributs d'un compte, quelle que soit sa source.

    - Maigret / social : attributs déjà sous raw_data["content"].
    - GitHub : attributs à plat (name/location/company/bio/email/blog) → mappés
      vers le même vocabulaire (fullname/location/occupation/bio/email/links).

    Ne renvoie que les champs non vides ; {} si rien d'exploitable. Sert de
    matière commune à l'enrichissement et à la convergence inter-comptes.
    """
    raw = raw_data or {}
    content = {k: v for k, v in (raw.get("content") or {}).items() if v}
    if content:
        return dict(content)
    # Pas de bloc content : tenter la forme GitHub (attributs à plat).
    if raw.get("login"):
        gh: dict = {}
        for attr, key in _GITHUB_TOPLEVEL.items():
            if raw.get(key):
                gh[attr] = raw[key]
        if raw.get("blog"):
            gh["links"] = [raw["blog"]]
        return gh
    return {}


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


# ─────────────────────────────────────────────────────────────────────────────
# CONVERGENCE INTER-COMPTES (Piste A)
# evaluate_account compare UN compte à la référence (ancres / GitHub confirmé).
# Quand la référence est vide (ni ancre ni GitHub confirmé), aucun guessed ne peut
# être promu. La convergence exploite la COHÉRENCE MUTUELLE : des comptes guessed
# qui affichent les mêmes attributs distinctifs se prouvent l'un l'autre.
# Plafond = corroborated (jamais confirmed). En cas de doute → guessed (sûr).
# ─────────────────────────────────────────────────────────────────────────────
_MIN_XLINK_HANDLE = 4


def _is_nontrivial_name(name: Optional[str]) -> bool:
    """Nom complet « non-trivial » : >= 2 tokens et assez long (évite qu'un simple
    prénom partagé serve de signal)."""
    tokens = [t for t in _loose(name).split() if t]
    return len(_norm(name)) >= 6 and len(tokens) >= 2


def _bio_similar(a: Optional[str], b: Optional[str]) -> bool:
    """Bios quasi identiques : égalité normalisée OU fort recouvrement de tokens."""
    ta = {t for t in _loose(a).split() if t}
    tb = {t for t in _loose(b).split() if t}
    if not ta or not tb:
        return False
    if _norm(a) == _norm(b):
        return True
    return len(ta & tb) / len(ta | tb) >= 0.8


def _same_or_substring(a: str, b: str) -> bool:
    la, lb = _loose(a), _loose(b)
    return _norm(a) == _norm(b) or la in lb or lb in la


def _references(a: dict, b: dict) -> bool:
    """Vrai si le compte `a` pointe LITTÉRALEMENT vers `b` via ses liens sortants
    (pseudo distinctif de `b` présent dans un lien de `a`)."""
    handle = _norm(b.get("username"))
    if len(handle) < _MIN_XLINK_HANDLE:
        return False
    links_blob = _norm(" ".join(a.get("content", {}).get("links") or []))
    return handle in links_blob


def _pair_signals(a: dict, b: dict) -> tuple[bool, set, list]:
    """Analyse une paire de comptes. Retourne (incompatible, attributs_moyens, signaux_forts).

    incompatible=True (divergence sur un attribut distinctif) ⇒ aucune arête : les
    comptes restent dans des clusters séparés (garde-fou anti-homonyme).
    """
    ca, cb = a.get("content", {}), b.get("content", {})

    # --- Divergence (homonymes distincts) : ville / occupation présentes et inconciliables ---
    la, lb = ca.get("location"), cb.get("location")
    if la and lb and not _same_or_substring(la, lb):
        return True, set(), []
    oa, ob = ca.get("occupation"), cb.get("occupation")
    if oa and ob and not (_same_or_substring(oa, ob) or loose_contains(oa, ob, 3) or loose_contains(ob, oa, 3)):
        return True, set(), []

    mediums: set = set()
    strong: list = []

    fa, fb = ca.get("fullname"), cb.get("fullname")
    if fa and fb and _norm(fa) == _norm(fb) and _is_nontrivial_name(fa):
        mediums.add("fullname")
    if la and lb and _same_or_substring(la, lb):
        mediums.add("location")
    if oa and ob and (_same_or_substring(oa, ob) or loose_contains(oa, ob, 3) or loose_contains(ob, oa, 3)):
        mediums.add("occupation")
    if _bio_similar(ca.get("bio"), cb.get("bio")):
        mediums.add("bio")

    ea, eb = ca.get("email"), cb.get("email")
    if ea and eb and _norm_email(ea) == _norm_email(eb):
        strong.append("email partagé")
    if _references(a, b) or _references(b, a):
        strong.append("lien croisé")

    # Pseudo DISTINCTIF identique (non dérivable du nom) : preuve forte de même
    # personne. Un pseudo SIMPLE (= le nom décliné) ne compte pas (cf. P2).
    ua, ub = a.get("username"), b.get("username")
    if (ua and ub and _norm(ua) == _norm(ub)
            and classify_pseudo(ua, a.get("first_name", ""), a.get("last_name", "")) == "distinctive"):
        strong.append("pseudo distinctif identique")

    return False, mediums, strong


def converge_accounts(accounts: list[dict], strict_edges: bool = False) -> list[dict]:
    """Regroupe des comptes en clusters mutuellement cohérents et décide de leur
    promotion en corroborated.

    Chaque `account` : {key, username, content:{fullname,location,occupation,bio,
    email,links}, first_name, last_name}. Retourne une liste de clusters :
        {"members": [key, ...], "promoted": bool, "signals": [str, ...]}

    Promotion d'un cluster ⇔ il est INTERNEMENT cohérent (aucune paire divergente)
    ET réunit AU MOINS un signal FORT, OU >= 2 attributs MOYENS distincts. Le palier
    faible (variantes de pseudo) ne promeut jamais seul. Plafond = corroborated.

    `strict_edges` : règle de FORMATION des arêtes (regroupement), distincte de la
    règle de promotion.
    - False (défaut, convergence) : une arête dès qu'il existe un signal (>=1 moyen
      ou fort). La promotion reste conditionnée au seuil ci-dessus.
    - True (grappes d'identité, Piste A phase A) : une arête exige une VRAIE liaison
      (>=1 fort OU >=2 moyens distincts). Un nom partagé seul (1 moyen) ne fusionne
      donc PAS deux nœuds → homonymes séparés.
    """
    n = len(accounts)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        parent[find(x)] = find(y)

    edge_med: dict = {}
    edge_strong: dict = {}
    incompatible_pairs: set = set()

    for i in range(n):
        for j in range(i + 1, n):
            incompatible, mediums, strong = _pair_signals(accounts[i], accounts[j])
            if incompatible:
                incompatible_pairs.add((i, j))
                continue
            has_edge = (bool(strong) or len(mediums) >= 2) if strict_edges else bool(mediums or strong)
            if has_edge:
                union(i, j)
                edge_med[(i, j)] = mediums
                edge_strong[(i, j)] = strong

    components: dict = {}
    for i in range(n):
        components.setdefault(find(i), []).append(i)

    clusters: list = []
    for members in components.values():
        keys = [accounts[m]["key"] for m in members]
        if len(members) < 2:
            clusters.append({"members": keys, "promoted": False, "signals": []})
            continue

        mset = set(members)
        consistent = not any(i in mset and j in mset for (i, j) in incompatible_pairs)

        medium_attrs: set = set()
        strong_sigs: list = []
        for (i, j), meds in edge_med.items():
            if i in mset and j in mset:
                medium_attrs |= meds
        for (i, j), strs in edge_strong.items():
            if i in mset and j in mset:
                strong_sigs.extend(strs)

        promoted = consistent and (bool(strong_sigs) or len(medium_attrs) >= 2)

        signals = [f"FORT: {s}" for s in sorted(set(strong_sigs))]
        signals += [f"MOYEN: {m}" for m in sorted(medium_attrs)]
        signals.append("FAIBLE: variantes de pseudo")
        if not consistent:
            signals.append("conflit homonyme (divergence) → non promu")

        clusters.append({"members": keys, "promoted": promoted, "signals": signals})

    return clusters
