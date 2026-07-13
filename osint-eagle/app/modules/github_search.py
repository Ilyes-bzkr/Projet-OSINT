"""
github_search — OSINT Eagle
Recherche de profils et activité GitHub.
"""

from typing import Callable

import httpx

from app.core.config import settings
from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

__all__ = ["search_github"]

_BASE_URL = "https://api.github.com"
_HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (compatible; OSINT-Eagle/1.0)",
    "Accept": "application/vnd.github+json",
}
_TIMEOUT = 8.0


def _build_headers() -> dict:
    headers = dict(_HEADERS_BASE)
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


async def search_github(profile: NameProfile, search_id: str, callback: Callable) -> list[OsintResult]:
    """Cherche des profils, repos et emails associés au nom via l'API GitHub."""
    results: list[OsintResult] = []
    headers = _build_headers()

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        usernames = await _search_user_profiles(client, profile, search_id, callback, results)
        await _search_commit_emails(client, usernames, search_id, callback, results)
        await _search_code(client, profile, search_id, callback, results)

    logger.info(f"github_search : {len(results)} résultats trouvés")
    return results


async def _search_user_profiles(
    client: httpx.AsyncClient,
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    results: list,
) -> list[str]:
    usernames: list[str] = []
    try:
        resp = await client.get(
            f"{_BASE_URL}/search/users",
            params={"q": profile.full_name, "per_page": 5},
        )
        if resp.status_code != 200:
            logger.warning(f"github_search : search/users a retourné {resp.status_code}")
            return usernames

        for item in resp.json().get("items", []):
            login = item.get("login")
            if not login:
                continue
            try:
                detail_resp = await client.get(f"{_BASE_URL}/users/{login}")
                if detail_resp.status_code != 200:
                    continue
                user = detail_resp.json()
            except Exception as e:
                logger.warning(f"github_search : erreur détail utilisateur {login} : {e}")
                continue

            usernames.append(login)

            result = OsintResult(
                search_id=search_id,
                module=ModuleType.GITHUB,
                category=ResultCategory.TECHNICAL,
                title=f"GitHub : {user.get('login')}",
                url=user.get("html_url"),
                snippet=user.get("bio"),
                raw_data={
                    "login": user.get("login"),
                    "name": user.get("name"),
                    "bio": user.get("bio"),
                    "location": user.get("location"),
                    "email": user.get("email"),
                    "company": user.get("company"),
                    "blog": user.get("blog"),
                    "public_repos": user.get("public_repos"),
                    "followers": user.get("followers"),
                    "avatar_url": user.get("avatar_url"),
                },
                risk_level=RiskLevel.MEDIUM,
            )
            results.append(result)
            _safe_callback(callback, result)

            if user.get("email"):
                email_result = OsintResult(
                    search_id=search_id,
                    module=ModuleType.GITHUB,
                    category=ResultCategory.CONTACT,
                    title=f"Email public GitHub : {user.get('login')}",
                    url=user.get("html_url"),
                    snippet=user.get("email"),
                    raw_data={"login": login, "email": user.get("email"), "source": "profile"},
                    risk_level=RiskLevel.HIGH,
                    is_sensitive=True,
                )
                results.append(email_result)
                _safe_callback(callback, email_result)

    except Exception as e:
        logger.warning(f"github_search : erreur search/users : {e}")

    return usernames


async def _search_commit_emails(
    client: httpx.AsyncClient,
    usernames: list[str],
    search_id: str,
    callback: Callable,
    results: list,
):
    for login in usernames:
        try:
            repos_resp = await client.get(
                f"{_BASE_URL}/users/{login}/repos",
                params={"per_page": 10, "sort": "updated"},
            )
            if repos_resp.status_code != 200:
                continue
            repos = repos_resp.json()
        except Exception as e:
            logger.warning(f"github_search : erreur repos de {login} : {e}")
            continue

        for repo in repos:
            repo_name = repo.get("name")
            if not repo_name:
                continue
            try:
                commits_resp = await client.get(
                    f"{_BASE_URL}/repos/{login}/{repo_name}/commits",
                    params={"per_page": 5},
                )
                if commits_resp.status_code != 200:
                    continue
                commits = commits_resp.json()
            except Exception as e:
                logger.warning(f"github_search : erreur commits {login}/{repo_name} : {e}")
                continue

            for commit in commits:
                author = commit.get("commit", {}).get("author", {})
                email = author.get("email")
                if not email or "noreply.github.com" in email:
                    continue

                result = OsintResult(
                    search_id=search_id,
                    module=ModuleType.GITHUB,
                    category=ResultCategory.CONTACT,
                    title=f"Email trouvé dans un commit : {login}/{repo_name}",
                    url=commit.get("html_url"),
                    snippet=email,
                    raw_data={
                        "login": login,
                        "repo": repo_name,
                        "email": email,
                        "source": "commit",
                    },
                    risk_level=RiskLevel.HIGH,
                    is_sensitive=True,
                )
                results.append(result)
                _safe_callback(callback, result)


async def _search_code(
    client: httpx.AsyncClient,
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    results: list,
):
    try:
        resp = await client.get(
            f"{_BASE_URL}/search/code",
            params={"q": profile.full_name, "per_page": 5},
        )
        if resp.status_code != 200:
            logger.warning(f"github_search : search/code a retourné {resp.status_code}")
            return

        for item in resp.json().get("items", []):
            result = OsintResult(
                search_id=search_id,
                module=ModuleType.GITHUB,
                category=ResultCategory.TECHNICAL,
                title=f"Nom trouvé dans le code : {item.get('repository', {}).get('full_name')}",
                url=item.get("html_url"),
                snippet=item.get("path"),
                # weak_mention : simple présence du nom dans un fichier (ex. un
                # classement "top-github-users-tunisia"). Ne prouve RIEN sur la
                # cible → jamais traité comme un fait par le profileur (isolé en
                # "à vérifier"). Évite la déduction "origine tunisienne".
                raw_data={
                    "repository": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "weak_mention": True,
                },
                risk_level=RiskLevel.MEDIUM,
            )
            results.append(result)
            _safe_callback(callback, result)

    except Exception as e:
        logger.warning(f"github_search : erreur search/code : {e}")


def _safe_callback(callback: Callable, result: OsintResult):
    try:
        callback(result)
    except Exception as e:
        logger.warning(f"github_search : erreur callback : {e}")
