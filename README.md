# SENTINEL-X 2.0

> **"See the Threat. Understand the Risk. Act with Confidence."**

Intelligent Cyber Threat Intelligence, Correlation & Investigation Platform.

---

## Overview

SENTINEL-X 2.0 is a full-stack cybersecurity threat intelligence platform that allows security analysts to investigate indicators of compromise (IPs, domains, URLs, and file hashes), correlate findings across intelligence sources, score risk automatically, and manage investigation cases — all from a unified web interface.

### Key Features

| Feature | Description |
|---|---|
| **Indicator Investigation** | Submit IPs, IPv6, domains, URLs, MD5/SHA1/SHA256 hashes for instant analysis |
| **Multi-Source Correlation** | Cross-reference VirusTotal and AlienVault OTX; detect agreements and conflicts |
| **Risk Scoring** | Automated 0–100 risk score with contributing factor breakdown |
| **Recommendation Engine** | Context-aware analyst action recommendations by risk class and indicator type |
| **Case Management** | Create, triage, and track investigation cases with analyst notes and activity timelines |
| **Relationship Graph** | Interactive indicator relationship explorer (ReactFlow) |
| **Threat Intelligence Feed** | Filterable, searchable feed of all investigated indicators |
| **JSON Report Export** | Download structured investigation reports for external tooling |
| **Demo Mode** | Pre-loaded investigation scenarios covering all risk classes — no API keys required |
| **SSRF Protection** | Private/reserved IP addresses are blocked from external provider queries |
| **Rate Limiting** | Per-IP rate limiting on all endpoints via Flask-Limiter |

---

## Quick Start

### Requirements

- Python 3.11+
- Node.js 18+ (for frontend development)

### Backend

```bash
# 1. Clone / extract the project
cd sentinel-x

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run (demo mode enabled by default)
python app.py
```

The API server starts on `http://localhost:5000`.

Default credentials: `admin` / `ChangeMe!2024`

### Frontend (Development)

```bash
cd frontend
npm install
npm run dev
```

The dev server starts on `http://localhost:5173` and proxies `/api` requests to port 5000.

### Frontend (Production Build)

```bash
cd frontend
npm run build
# Output in frontend/dist/ — served automatically by Flask
```

---

## Configuration

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random | Flask session secret — **change in production** |
| `FLASK_ENV` | `development` | `development` or `production` |
| `PORT` | `5000` | Backend listen port |
| `VT_API_KEY` | _(empty)_ | VirusTotal API v3 key |
| `OTX_API_KEY` | _(empty)_ | AlienVault OTX API key |
| `DEMO_MODE` | `true` | Load demo investigation scenarios on startup |
| `ADMIN_USERNAME` | `admin` | Initial admin username (first run only) |
| `ADMIN_PASSWORD` | `ChangeMe!2024` | Initial admin password (first run only) |
| `DATABASE_URL` | SQLite | SQLAlchemy connection string |
| `PROVIDER_TIMEOUT` | `10` | HTTP timeout (seconds) for provider queries |

---

## Intelligence Providers

Both providers are **optional**. Without API keys, SENTINEL-X runs entirely in demo mode with pre-loaded scenarios.

### VirusTotal

- Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us)
- Set `VT_API_KEY=<your-key>` in `.env`
- Supports: IP, IPv6, domain, URL, MD5, SHA1, SHA256

### AlienVault OTX

- Get a free API key at [otx.alienvault.com](https://otx.alienvault.com)
- Set `OTX_API_KEY=<your-key>` in `.env`
- Supports: IP, IPv6, domain, URL, MD5, SHA1, SHA256

---

## Running Tests

```bash
pytest app.py -v
```

Test suites included:

| Suite | Coverage |
|---|---|
| `TestIndicatorDetection` | Type detection for all indicator types |
| `TestNormalization` | Canonical form normalization |
| `TestSSRFProtection` | Private/reserved IP blocking |
| `TestRiskScoring` | Score computation, caps, classification |
| `TestCorrelationEngine` | Agreement, conflict, tag overlap detection |
| `TestRecommendations` | Action generation, deduplication |
| `TestAPIAuth` | Login validation, protected endpoint auth |
| `TestInputValidation` | Empty/oversized/private/unknown indicators |
| `TestDemoDataSeparation` | Demo flag integrity |
| `TestDatabasePersistence` | Write/read, unique constraint enforcement |

---

## Architecture

```
sentinel-x/
├── app.py                    # Single-file Python backend (Flask)
├── requirements.txt
├── .env.example
├── docker-compose.yml
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    ├── src/
    │   ├── App.tsx           # Auth context + routing
    │   ├── api/client.ts     # Axios instance
    │   ├── types/index.ts    # All TypeScript types
    │   ├── hooks/
    │   │   └── useDebounce.ts
    │   ├── pages/
    │   │   ├── LoginPage.tsx
    │   │   ├── DashboardPage.tsx
    │   │   ├── InvestigatePage.tsx
    │   │   ├── CasesPage.tsx
    │   │   ├── CaseDetailPage.tsx
    │   │   ├── HistoryPage.tsx
    │   │   ├── GraphPage.tsx
    │   │   ├── FeedPage.tsx
    │   │   └── SettingsPage.tsx
    │   └── components/
    │       ├── Layout.tsx
    │       ├── RiskBadge.tsx
    │       ├── SourceStatusPanel.tsx
    │       ├── InvestigationResult.tsx
    │       ├── CorrelationPanel.tsx
    │       ├── ScoringPanel.tsx
    │       └── RecommendationsPanel.tsx
    └── dist/                 # Built frontend (served by Flask)
```

### Backend modules (all in `app.py`)

| Module | Role |
|---|---|
| Database models | SQLAlchemy ORM — 12 models |
| Input validation | Regex + `ipaddress` module type detection and normalization |
| Provider adapters | VirusTotal v3 + AlienVault OTX REST adapters with status normalization |
| Correlation engine | Multi-source agreement/conflict analysis with overlapping tag detection |
| Risk scoring | Weighted factor model capped at 0–100 |
| Recommendation engine | Rule-based action generation by risk class and indicator type |
| Investigation orchestrator | Full pipeline: validate → query → correlate → score → recommend → persist |
| Demo data | 5 idempotent scenarios covering all risk classes |
| Flask routes | Auth, investigations, cases, graph, reports, dashboard, feed, settings, SPA catch-all |

---

## Docker

```bash
# Build and start both services
docker-compose up --build

# Backend: http://localhost:5000
# Frontend: http://localhost:5173
```

You will need to create `Dockerfile` and `frontend/Dockerfile` for production container builds (not included by default — use the development workflow above for getting started).

---

## API Reference

All endpoints require session authentication (POST `/api/auth/login` first).

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Log in, create session |
| `POST` | `/api/auth/logout` | Clear session |
| `GET`  | `/api/auth/me` | Current user |
| `POST` | `/api/investigate` | Submit indicator for investigation |
| `GET`  | `/api/investigations` | List investigations (paginated, filterable) |
| `GET`  | `/api/investigations/:id` | Investigation detail with source results |
| `GET`  | `/api/investigations/:id/compare` | Snapshot comparison |
| `GET`  | `/api/cases` | List cases |
| `POST` | `/api/cases` | Create case |
| `GET`  | `/api/cases/:id` | Case detail with indicators, notes, activity |
| `PATCH`| `/api/cases/:id` | Update case status/severity |
| `POST` | `/api/cases/:id/notes` | Add analyst note |
| `POST` | `/api/cases/:id/indicators` | Link indicator to case |
| `GET`  | `/api/graph` | Indicator relationship graph nodes/edges |
| `GET`  | `/api/reports/:id/json` | Download JSON investigation report |
| `GET`  | `/api/dashboard` | SOC dashboard stats and recent activity |
| `GET`  | `/api/feed` | Threat intelligence feed (paginated, filterable) |
| `GET`  | `/api/settings` | Provider configuration status |

---

## Security Notes

- **Change `ADMIN_PASSWORD` immediately** on first run.
- **Generate a strong `SECRET_KEY`** for production: `python -c "import secrets; print(secrets.token_hex(32))"`
- SSRF protection blocks investigation of private/reserved IP ranges (RFC 1918, loopback, link-local).
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` in production mode.
- Request size is capped at 1 MB.
- All investigation reports carry a legal notice that they are analytical only and do not constitute legal evidence.

---

## License

This project is provided for educational and operational security purposes. Use responsibly and in accordance with applicable laws and the terms of service of any intelligence providers you configure.
