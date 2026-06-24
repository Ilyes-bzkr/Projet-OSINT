// OSINT Eagle — logique frontend (Phase 3).

const WS_URL = `ws://${location.hostname}:${location.port || 8000}/ws/search`;

const MODULE_CARDS = [
  { key: "web_search", icon: "🌐", label: "Web Search" },
  { key: "github", icon: "🐙", label: "GitHub" },
  { key: "social", icon: "👤", label: "Réseaux Sociaux" },
  { key: "breach", icon: "🔓", label: "Fuites de données" },
  { key: "paste", icon: "📋", label: "Paste Sites" },
  { key: "data_brokers", icon: "🏢", label: "Data Brokers" },
  { key: "ai_analysis", icon: "🤖", label: "IA Analysis" },
];

const ROTATING_TEXTS = [
  "Analyse du nom et génération des variantes...",
  "Recherche dans les moteurs de recherche...",
  "Vérification des profils GitHub...",
  "Scan des réseaux sociaux...",
  "Vérification des bases de fuites...",
  "Recherche sur les sites de paste...",
  "Analyse des data brokers...",
  "Compilation des résultats...",
  "Filtrage des résultats par intelligence artificielle...",
  "Construction du profil de renseignement...",
  "Analyse des comportements et activités...",
  "Génération du rapport final...",
];

const PLATFORM_EMOJI = {
  GitHub: "🐙", GitLab: "🦊", Bitbucket: "🪣",
  Twitter: "🐦", X: "🐦", Instagram: "📸", Facebook: "📘",
  Reddit: "👽", TikTok: "🎵", Telegram: "✈️", Tumblr: "📓",
  PyPI: "🐍", YouTube: "▶️",
};

const CATEGORY_GROUP_LABELS = {
  developer: "Développeur",
  social: "Social",
  content: "Contenu",
  creative: "Contenu",
  professional: "Pro",
  identity: "Pro",
};

const MODULE_LABELS = {
  web_search: "🌐 Web Search",
  github: "🐙 GitHub",
  social: "👤 Réseaux Sociaux",
  breach: "🔓 Fuites de données",
  paste: "📋 Paste Sites",
};

const RISK_WEIGHTS = { low: 1, medium: 3, high: 8, critical: 15 };

const state = {
  screen: "home",
  searchName: "",
  anchors: {},
  ws: null,
  manualClose: false,
  reconnectAttempts: 0,
  rotatingTimer: null,
  rotatingIndex: 0,
  moduleStatus: {},
  moduleCounts: {},
  completedCount: 0,
  totalResults: 0,
  aiRiskScore: null,
  aiProfile: null,
  results: {
    web_search: [], github: [], social: [], breach: [], paste: [],
    photos: [], documents: [], videos: [], accounts: [],
  },
};

function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function showScreen(name) {
  state.screen = name;
  ["screen-home", "screen-searching", "screen-results"].forEach((id) => {
    $(id).classList.toggle("active", id === `screen-${name}`);
  });
}

function showToast(message) {
  const container = $("toast-container");
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// === ÉCRAN 2 : modules grid ===

function buildModuleCards() {
  const grid = $("modules-grid");
  grid.innerHTML = "";
  MODULE_CARDS.forEach((m) => {
    state.moduleStatus[m.key] = "pending";
    state.moduleCounts[m.key] = 0;
    const card = document.createElement("div");
    card.className = "module-card status-pending";
    card.id = `module-card-${m.key}`;
    card.innerHTML = `
      <div class="module-info">
        <span class="module-icon">${m.icon}</span>
        <span class="module-name">${m.label}</span>
      </div>
      <div class="module-meta">
        <span class="module-count" id="module-count-${m.key}">0</span>
        <span class="module-status" id="module-status-${m.key}">PENDING</span>
      </div>`;
    grid.appendChild(card);
  });
}

function updateModuleCard(key, status) {
  const card = $(`module-card-${key}`);
  const statusEl = $(`module-status-${key}`);
  if (!card || !statusEl) return;
  state.moduleStatus[key] = status;
  card.classList.remove("status-pending", "status-running", "status-completed", "status-failed");
  card.classList.add(`status-${status}`);
  const labels = { pending: "PENDING", running: "RUNNING", completed: "COMPLETED ✓", failed: "FAILED ✗" };
  statusEl.textContent = labels[status] || status.toUpperCase();
}

function incrementModuleCount(key) {
  if (!(key in state.moduleCounts)) return;
  state.moduleCounts[key] += 1;
  const el = $(`module-count-${key}`);
  if (el) el.textContent = String(state.moduleCounts[key]);
}

const REAL_MODULES = ["web_search", "github", "social", "breach", "paste"];

function updateGlobalProgress() {
  const completed = REAL_MODULES.filter((k) => state.moduleStatus[k] === "completed" || state.moduleStatus[k] === "failed").length;
  const pct = Math.round((completed / REAL_MODULES.length) * 100);
  $("progress-fill").style.width = `${pct}%`;
  $("progress-percent").textContent = `${pct}%`;
}

function startRotatingText() {
  const el = $("rotating-text");
  state.rotatingIndex = 0;
  el.textContent = ROTATING_TEXTS[0];
  el.classList.add("fade-in");
  state.rotatingTimer = setInterval(() => {
    el.classList.remove("fade-in");
    el.classList.add("fade-out");
    setTimeout(() => {
      state.rotatingIndex = (state.rotatingIndex + 1) % ROTATING_TEXTS.length;
      el.textContent = ROTATING_TEXTS[state.rotatingIndex];
      el.classList.remove("fade-out");
      el.classList.add("fade-in");
    }, 400);
  }, 2500);
}

function stopRotatingText() {
  if (state.rotatingTimer) clearInterval(state.rotatingTimer);
  state.rotatingTimer = null;
}

// === WebSocket ===

function connectWebSocket() {
  state.manualClose = false;
  const ws = new WebSocket(WS_URL);
  state.ws = ws;

  ws.onopen = () => {
    state.reconnectAttempts = 0;
    ws.send(JSON.stringify({ name: state.searchName, anchors: state.anchors || {} }));
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
    } catch (e) {
      console.error("Message WebSocket invalide", e);
    }
  };

  ws.onclose = () => {
    if (state.manualClose) return;
    if (state.screen === "searching" && state.reconnectAttempts < 3) {
      state.reconnectAttempts += 1;
      showToast("Connexion perdue, nouvelle tentative...");
      setTimeout(() => connectWebSocket(), 1500);
    }
  };

  ws.onerror = () => {
    showToast("Erreur de connexion WebSocket");
  };
}

function handleMessage(msg) {
  switch (msg.type) {
    case "started":
      handleStarted(msg);
      break;
    case "progress":
      handleProgress(msg);
      break;
    case "result":
      handleResult(msg);
      break;
    case "complete":
      handleComplete(msg);
      break;
    case "error":
      handleError(msg);
      break;
    case "ai_profile":
      handleAiProfile(msg);
      break;
  }
}

function handleStarted(msg) {
  showScreen("searching");
  $("searched-name").textContent = (msg.data && msg.data.name) || state.searchName;
  buildModuleCards();
  $("progress-fill").style.width = "0%";
  $("progress-percent").textContent = "0%";
  $("total-counter").textContent = "0 résultats trouvés";
  state.aiRiskScore = null;
  state.aiProfile = null;
  $("ai-placeholder").hidden = false;
  $("ai-report").hidden = true;
  $("ai-report").innerHTML = "";
  $("ai-report").classList.remove("fade-in");
  startRotatingText();
}

function handleProgress(msg) {
  const moduleKey = msg.module;
  if (!moduleKey || !(moduleKey in state.moduleStatus)) return;
  const status = (msg.data && msg.data.status) || "running";
  updateModuleCard(moduleKey, status === "running" ? "running" : status === "completed" ? "completed" : status);
  updateGlobalProgress();
}

function handleResult(msg) {
  const moduleKey = msg.module;
  const result = msg.data;
  if (!result) return;

  state.totalResults += 1;
  $("total-counter").textContent = `${state.totalResults} résultats trouvés`;
  incrementModuleCount(moduleKey);

  if (moduleKey in state.results) {
    state.results[moduleKey].push(result);
  }

  if (moduleKey === "github" && result.raw_data && result.raw_data.avatar_url) {
    state.results.photos.push({
      url: result.raw_data.avatar_url,
      platform: "GitHub",
    });
  }

  if (moduleKey === "web_search" && result.category === "document") {
    state.results.documents.push(result);
  }

  if (result.url && /youtube\.com|youtu\.be/.test(result.url)) {
    state.results.videos.push(result);
  }

  if (moduleKey === "social") {
    state.results.accounts.push(result);
  }
}

function handleError(msg) {
  if (msg.module && msg.module in state.moduleStatus) {
    updateModuleCard(msg.module, "failed");
    updateGlobalProgress();
  }
  showToast(msg.message || "Une erreur est survenue");
}

function handleComplete(msg) {
  stopRotatingText();
  REAL_MODULES.forEach((k) => {
    if (state.moduleStatus[k] === "running" || state.moduleStatus[k] === "pending") {
      updateModuleCard(k, "completed");
    }
  });
  updateGlobalProgress();
  if (state.aiRiskScore === null && msg && msg.data && typeof msg.data.risk_score === "number") {
    state.aiRiskScore = msg.data.risk_score;
  }
  renderResultsScreen();
  showScreen("results");
}

function handleAiProfile(msg) {
  const data = msg.data || {};
  state.aiRiskScore = typeof data.risk_score === "number" ? data.risk_score : state.aiRiskScore;
  state.aiProfile = data.profile || null;

  const placeholder = $("ai-placeholder");
  const report = $("ai-report");
  placeholder.hidden = true;
  report.innerHTML = data.html || "";
  report.hidden = false;
  report.classList.remove("fade-in");
  requestAnimationFrame(() => report.classList.add("fade-in"));

  if (state.aiRiskScore !== null) {
    updateRiskBadge(state.aiRiskScore);
  }

  const rightPanel = document.querySelector(".results-right");
  if (rightPanel) rightPanel.scrollTop = 0;

  showToast("✓ Analyse IA terminée");
}

// === ÉCRAN 3 : résultats ===

function computeRiskScore() {
  let score = 0;
  Object.values(state.results).forEach((arr) => {
    if (!Array.isArray(arr)) return;
    arr.forEach((r) => {
      if (r && r.risk_level && RISK_WEIGHTS[r.risk_level]) {
        score += RISK_WEIGHTS[r.risk_level];
      }
    });
  });
  return Math.min(100, score);
}

function updateRiskBadge(score) {
  const badge = $("risk-badge");
  badge.textContent = `RISQUE : ${score}/100`;
  badge.classList.remove("risk-low", "risk-medium", "risk-high");
  badge.classList.add(score < 30 ? "risk-low" : score <= 70 ? "risk-medium" : "risk-high");
}

function renderResultsScreen() {
  $("results-name").textContent = state.searchName.toUpperCase();

  const score = state.aiRiskScore !== null && state.aiRiskScore !== undefined ? state.aiRiskScore : computeRiskScore();
  updateRiskBadge(score);

  renderPhotos();
  renderDocuments();
  renderVideos();
  renderAccounts();
}

function renderPhotos() {
  const grid = $("photos-grid");
  if (state.results.photos.length === 0) {
    grid.innerHTML = `<div class="empty-state">👤 Aucune photo trouvée</div>`;
    return;
  }
  grid.innerHTML = state.results.photos
    .map(
      (p) => `
      <div class="photo-item">
        <img src="${escapeHtml(p.url)}" alt="avatar" loading="lazy">
        <span class="photo-badge">${escapeHtml(p.platform)}</span>
      </div>`
    )
    .join("");
}

function renderDocuments() {
  const list = $("documents-list");
  if (state.results.documents.length === 0) {
    list.innerHTML = `<li class="empty-state">📄 Aucun document trouvé</li>`;
    return;
  }
  list.innerHTML = state.results.documents
    .map((d) => {
      const date = d.found_at ? new Date(d.found_at).toLocaleDateString("fr-FR") : "";
      return `
      <li>
        <span class="doc-icon">📄</span>
        <div class="doc-meta">
          <span class="doc-title">${escapeHtml(d.title)}</span>
          <a href="${escapeHtml(d.url)}" target="_blank" rel="noopener">${escapeHtml(d.url)}</a>
          ${date ? `<span class="doc-date">${date}</span>` : ""}
        </div>
      </li>`;
    })
    .join("");
}

function renderVideos() {
  const list = $("videos-list");
  if (state.results.videos.length === 0) {
    list.innerHTML = `<li class="empty-state">▶️ Aucune vidéo trouvée</li>`;
    return;
  }
  list.innerHTML = state.results.videos
    .map(
      (v) => `
      <li>
        <span class="video-icon">▶️</span>
        <div class="video-meta">
          <span class="video-title">${escapeHtml(v.title)}</span>
          <a href="${escapeHtml(v.url)}" target="_blank" rel="noopener">${escapeHtml(v.url)}</a>
        </div>
      </li>`
    )
    .join("");
}

function renderAccounts() {
  const container = $("accounts-list");
  if (state.results.accounts.length === 0) {
    container.innerHTML = `<div class="empty-state">🔍 Aucun compte trouvé</div>`;
    return;
  }

  const groups = {};
  state.results.accounts.forEach((a) => {
    const raw = a.raw_data || {};
    const groupKey = CATEGORY_GROUP_LABELS[raw.category_platform] || "Autres";
    if (!groups[groupKey]) groups[groupKey] = [];
    groups[groupKey].push(a);
  });

  container.innerHTML = Object.entries(groups)
    .map(([groupName, items]) => {
      const rows = items
        .map((a) => {
          const raw = a.raw_data || {};
          const emoji = PLATFORM_EMOJI[raw.platform] || "🔗";
          return `
          <div class="account-item">
            <span class="account-emoji">${emoji}</span>
            <span>${escapeHtml(raw.platform)} — @${escapeHtml(raw.username)}</span>
            <a href="${escapeHtml(a.url)}" target="_blank" rel="noopener">↗</a>
          </div>`;
        })
        .join("");
      return `<div class="account-group"><h5>${escapeHtml(groupName)}</h5>${rows}</div>`;
    })
    .join("");
}

// === PANNEAU DÉTAILS ===

function openDetailsPanel() {
  renderDetailsPanel();
  $("details-overlay").classList.add("open");
  $("details-panel").classList.add("open");
}

function closeDetailsPanel() {
  $("details-overlay").classList.remove("open");
  $("details-panel").classList.remove("open");
}

function renderDetailsPanel() {
  $("details-count").textContent = `${state.totalResults} résultats`;
  const body = $("details-panel-body");

  body.innerHTML = REAL_MODULES
    .map((key) => {
      const items = state.results[key] || [];
      const itemsHtml = items.length
        ? items
            .map(
              (r) => `
            <div class="raw-result-item">
              <div class="rr-title">${escapeHtml(r.title)}</div>
              ${r.url ? `<a class="rr-url" href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.url)}</a>` : ""}
              ${r.snippet ? `<div class="rr-snippet">${escapeHtml(r.snippet)}</div>` : ""}
              <span class="risk-tag ${escapeHtml(r.risk_level)}">${escapeHtml((r.risk_level || "low").toUpperCase())}</span>
            </div>`
            )
            .join("")
        : `<div class="empty-state">Aucun résultat</div>`;

      return `
      <div class="accordion-section">
        <button class="accordion-header" data-target="acc-${key}">
          <span>${MODULE_LABELS[key]} (${items.length} résultats)</span>
          <span class="arrow">▼</span>
        </button>
        <div class="accordion-content" id="acc-${key}">${itemsHtml}</div>
      </div>`;
    })
    .join("");

  body.querySelectorAll(".accordion-header").forEach((btn) => {
    btn.addEventListener("click", () => {
      const content = $(btn.dataset.target);
      const collapsed = content.classList.toggle("collapsed");
      btn.classList.toggle("collapsed", collapsed);
    });
  });
}

// === Cadrage avant-recherche (ancres) ===

function setupScopingToggle() {
  const toggle = $("scoping-toggle");
  const fields = $("scoping-fields");
  if (!toggle || !fields) return;
  const icon = toggle.querySelector(".scoping-icon");

  toggle.addEventListener("click", () => {
    const willOpen = fields.hasAttribute("hidden");
    if (willOpen) {
      fields.removeAttribute("hidden");
      // Forcer un reflow avant d'ajouter la classe pour déclencher la transition.
      requestAnimationFrame(() => fields.classList.add("open"));
    } else {
      fields.classList.remove("open");
      // Masquer une fois l'animation de repli terminée.
      setTimeout(() => {
        if (!fields.classList.contains("open")) fields.setAttribute("hidden", "");
      }, 400);
    }
    toggle.setAttribute("aria-expanded", String(willOpen));
    if (icon) icon.textContent = willOpen ? "−" : "+";
  });
}

function collectAnchors() {
  const read = (id) => {
    const el = $(id);
    if (!el) return null;
    const value = (el.value || "").trim();
    return value.length ? value : null;
  };
  return {
    city: read("anchor-city"),
    employer: read("anchor-employer"),
    username: read("anchor-username"),
    email: read("anchor-email"),
    age_range: read("anchor-age"),
  };
}

// === Recherche / reset ===

function startSearch(name) {
  const trimmed = name.trim();
  if (trimmed.length < 2) {
    showToast("Entrez un nom complet valide");
    return;
  }
  state.searchName = trimmed;
  state.anchors = collectAnchors();
  state.totalResults = 0;
  state.moduleStatus = {};
  state.moduleCounts = {};
  state.aiRiskScore = null;
  state.aiProfile = null;
  state.results = {
    web_search: [], github: [], social: [], breach: [], paste: [],
    photos: [], documents: [], videos: [], accounts: [],
  };
  connectWebSocket();
}

function newSearch() {
  state.manualClose = true;
  if (state.ws) {
    try { state.ws.close(); } catch (e) { /* noop */ }
  }
  stopRotatingText();
  closeDetailsPanel();
  $("search-input").value = "";
  showScreen("home");
}

// === Init ===

document.addEventListener("DOMContentLoaded", () => {
  setupScopingToggle();
  $("search-btn").addEventListener("click", () => startSearch($("search-input").value));
  $("search-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") startSearch($("search-input").value);
  });
  $("details-btn").addEventListener("click", openDetailsPanel);
  $("details-close").addEventListener("click", closeDetailsPanel);
  $("details-overlay").addEventListener("click", closeDetailsPanel);
  $("new-search-btn").addEventListener("click", newSearch);
});
