# SearXNG local — canal `web_search` d'OSINT Eagle

`web_search.py` n'interroge plus Bing en scraping (challenge anti-bot
Cloudflare → 0 résultat). Il consomme désormais l'**API JSON d'une instance
SearXNG auto-hébergée en local** (métamoteur libre, agrège google/bing/
duckduckgo/brave/mojeek/…, aucune clé API, aucune carte bancaire).

> On ne code **aucun** contournement de captcha : SearXNG gère ses propres
> moteurs, on ne fait que consommer une API JSON locale légitime.

## Commandes (Docker Desktop déjà lancé)

```bash
# 1. Démarrer le conteneur (depuis ce dossier searxng/)
cd searxng && docker compose up -d

# 2. Vérifier qu'il tourne
docker ps        # doit lister un conteneur "searxng" (ports 8888->8080)

# 3. Arrêter (si besoin)
docker compose down
```

## Test du format JSON (l'étape qui fait foi)

Ouvre dans le navigateur :

    http://localhost:8888/search?q=test&format=json

- ✅ Tu vois du **JSON** (`{"query": "test", "results": [ ... ]}`) → tout est bon.
- ❌ Tu vois du **HTML** (ou une erreur « Forbidden / format not allowed ») →
  le format JSON n'est pas activé : vérifie `search.formats` dans
  [config/settings.yml](config/settings.yml) (doit contenir `html` ET `json`),
  puis `docker compose restart`.

## Configurer l'URL côté app (optionnel)

Par défaut l'app cible `http://localhost:8888`. Pour pointer ailleurs, exporte
la variable d'environnement avant de lancer l'app :

```bash
export SEARXNG_URL="http://localhost:8888"
```
