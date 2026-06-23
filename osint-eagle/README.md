# 🦅 OSINT Eagle

Application personnelle de recherche OSINT (Open Source Intelligence).
Permet de trouver toutes les données publiques disponibles sur une personne
et de générer des demandes de suppression RGPD.

> ⚠️ Usage personnel et éducatif uniquement. Ne recherchez que vos propres données.

## Installation

```bash
git clone https://github.com/[your-username]/osint-eagle.git
cd osint-eagle
pip install -r requirements.txt
cp .env.example .env
# Remplir .env avec vos clés API
bash scripts/install_playwright.sh
```

## Démarrage

```bash
python main.py
# Ouvrir http://127.0.0.1:8000
```

## Configuration

Copier `.env.example` en `.env` et renseigner :
- `ANTHROPIC_API_KEY` : clé API Anthropic (claude.ai/settings)
- `HIBP_API_KEY` : clé HaveIBeenPwned (haveibeenpwned.com/api)
- `GITHUB_TOKEN` : optionnel, augmente les rate limits GitHub

## Stack

- **Backend** : Python 3.11 + FastAPI + WebSockets
- **IA** : Claude API (Anthropic)
- **Scraping** : httpx + BeautifulSoup + Playwright
- **Base de données** : SQLite async

## Statut de développement

- [x] Phase 0 — Setup & scaffolding
- [ ] Phase 1 — Infrastructure backend
- [ ] Phase 2 — Modules OSINT core
- [ ] Phase 3 — Frontend
- [ ] Phase 4 — Couche IA
- [ ] Phase 5 — Data brokers
- [ ] Phase 6 — Module suppression
- [ ] Phase 7 — Tests & polish
