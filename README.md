# SecKB — Security Knowledge Base Dashboard

A local, AI-powered security knowledge base for penetration testers and red teamers. Automatically fetches security writeups, scores them, generates comprehensive pentest notes, and surfaces them in a fast dashboard — all running on your machine.

---

## Project Architecture

```
security-pipeline/
├── webapp/
│   ├── server.js              # Express API server (port 3000)
│   ├── public/index.html      # Full SPA dashboard (no framework, vanilla JS)
│   └── db/security_kb.db     # SQLite database (auto-created, gitignored)
│
├── fetch-articles.js          # RSS pipeline: fetch → score → notes → save
├── backfill-notes.js          # Re-generate AI notes for articles missing content
├── telegram-bot.js            # Telegram bot: send URL → auto-import
│
├── .env                       # Your API keys (gitignored — see .env.example)
├── .env.example               # Template showing all required keys
│
├── logs/                      # Runtime logs (gitignored)
├── systemd/                   # Systemd service files
└── scripts/                   # Setup helper scripts
```

---

## Features

### Dashboard (localhost:3000)
- **Article list** — filter by VAPT level, severity, category, vulnerability type, search
- **Article detail** — 18 AI-generated sections per article:
  - What Is It (ELI5 + analogy), Mental Model, Memory Hook
  - Where to Look, Behavioral Indicators, How to Find It
  - Root Cause, Exploitation Walkthrough, Payloads & Commands
  - Payload Mutations (WAF bypasses), Impact, Chaining Opportunities
  - Detection & Hunting, Remediation, Key Takeaways
  - Difficulty Tips, Real-World Scenario, Custom Header Guide
- **Flashcards** — spaced-repetition style review (Know It / Review Later)
- **Interactive Labs** — Gemini-generated step-by-step hands-on labs per article
- **Progress tracker** — completion % per VAPT level
- **Daily Challenge** — auto-selected unread high-quality article
- **Import URL** — paste any Medium/HackerNoon/blog URL, AI imports it in ~30s
- **AI Chat** — floating chat widget powered by Groq or Gemini
- **3 Themes** — Dark (default), Warm, Light

### Automation
- **Cron pipeline** — every 30 min: RSS feed scan → score → notes → save
- **Telegram Bot** — @Pentest_resource_bot: send URL → bot replies with import result
- **Auto-start** — crontab `@reboot` entries for server + bot

### AI Stack
| Component | Model | Purpose |
|-----------|-------|---------|
| Groq | llama-3.1-8b-instant | Article scoring, note generation, chat |
| Gemini | gemini-2.0-flash-lite | Lab generation, optional chat |

---

## VAPT Level System

Articles are scored and classified by practitioner level:

| Level | Description | Examples |
|-------|-------------|---------|
| Foundation | Core web concepts | HTTP basics, HTTPS, cookies |
| Recon | Information gathering | OSINT, subdomain enum, Shodan |
| Low | Entry-level vulns | Clickjacking, CORS misconfig |
| Medium | Common VAPT vulns | XSS, CSRF, IDOR, path traversal |
| High | Advanced exploitation | SQLi, SSRF, JWT attacks, OAuth |
| Critical | High-impact vulns | RCE, deserialization, SSTI |
| Advanced | Complex attack chains | Prototype pollution, race conditions |
| Expert | Research-level | 0-days, novel technique discovery |

---

## Database Schema

SQLite table `articles` with 35 columns:

```sql
CREATE TABLE articles (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  date_added               TEXT,
  title                    TEXT NOT NULL,
  vapt_level               TEXT DEFAULT 'Medium',
  category                 TEXT,
  vulnerability_type       TEXT,
  severity                 TEXT,        -- Low | Medium | High | Critical
  quality_score            INTEGER,     -- 0-10 AI score
  tools_used               TEXT,
  source_url               TEXT UNIQUE,
  one_line_summary         TEXT,
  beginner_context         TEXT,
  -- AI-generated pentest notes (18 fields)
  what_is_it               TEXT,
  mental_model             TEXT,
  memory_hook              TEXT,
  where_to_look            TEXT,
  behavioral_indicators    TEXT,
  how_to_find_it           TEXT,
  root_cause               TEXT,
  exploitation_walkthrough TEXT,
  payloads_and_commands    TEXT,
  payload_mutations        TEXT,
  impact                   TEXT,
  chaining_opportunities   TEXT,
  detection_and_hunting    TEXT,
  remediation              TEXT,
  key_takeaways            TEXT,
  difficulty_tips          TEXT,
  real_world_scenario      TEXT,
  custom_header_guide      TEXT,
  -- User data
  personal_notes           TEXT,
  flashcard_status         TEXT DEFAULT 'unseen',  -- unseen | known | review
  lab_content              TEXT,        -- JSON blob from Gemini
  status                   TEXT DEFAULT 'new',     -- new | reviewed | practiced | mastered
  created_at               DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/articles` | List with filters: severity, category, vuln, level, search, score_min |
| GET | `/api/articles/:id` | Single article (all 35 fields) |
| POST | `/api/articles` | Save article (used by fetch pipeline) |
| PATCH | `/api/articles/:id/status` | Update status |
| GET/PATCH | `/api/articles/:id/notes` | Personal notes |
| PATCH | `/api/articles/:id/flashcard` | Update flashcard status |
| GET | `/api/articles/:id/lab` | Get cached lab |
| POST | `/api/articles/:id/lab/generate` | Generate lab via Gemini |
| GET | `/api/import-url` | SSE stream: fetch URL → score → notes → save |
| POST | `/api/chat` | AI chat (Groq or Gemini) |
| GET | `/api/flashcards` | Random flashcard deck |
| GET | `/api/daily-challenge` | Today's challenge article |
| GET | `/api/progress` | Completion % per VAPT level |
| GET | `/api/stats` | Full stats (counts, top-scoring, recent) |
| GET | `/api/filters` | Available filter values |
| GET | `/api/check-url` | Dedup check before import |
| GET | `/api/system-status` | Server health (uptime, article count) |

---

## RSS Feed Sources (24 feeds)

The auto-fetch pipeline monitors these sources every 30 minutes:

| Source | Level | Topic |
|--------|-------|-------|
| PortSwigger Blog | Foundation | Web Security Research |
| OWASP Blog | Foundation | Standards & Guidance |
| Medium: Bug Bounty | High | Real-world findings |
| Medium: XSS | Medium | Cross-site scripting |
| Medium: SQL Injection | High | Database attacks |
| Medium: SSRF | Critical | Server-side request forgery |
| Medium: IDOR | Medium | Broken access control |
| Medium: CSRF | Medium | Request forgery |
| Medium: Authentication | High | Auth bypass |
| Medium: JWT | High | Token attacks |
| Medium: Web App Security | Medium | General security |
| Medium: Pentesting | Advanced | Professional techniques |
| Medium: CTF | Medium | Capture-the-flag writeups |
| Medium: Reconnaissance | Recon | Information gathering |
| Medium: OSINT | Recon | Open-source intelligence |
| Medium: Subdomain Takeover | Low | Misconfiguration |
| Medium: Command Injection | Critical | OS command injection |
| Medium: Path Traversal | Medium | Directory traversal |
| Medium: Broken Access Control | Medium | Authorization flaws |
| Medium: Prototype Pollution | Advanced | JS prototype attacks |
| Medium: Deserialization | Expert | Object injection |
| Medium: Race Condition | Advanced | Timing attacks |
| Medium: API Security | High | API vulnerabilities |
| Medium: CORS | Low | Cross-origin misconfig |

---

## Article Scoring (AI Quality Filter)

Each article is scored 0–10 by Groq. Only articles scoring ≥ 6 are saved. Scoring criteria:
- Technical depth and accuracy
- Includes working payloads/commands
- Practical pentesting applicability
- VAPT level appropriateness

Score interpretation:
- `6-7` — Good introductory content
- `8` — Solid technical writeup
- `9` — Advanced, highly practical
- `10` — Rare: exceptional research/0-day

---

## Quick Start

### Prerequisites
- Node.js 18+ (uses built-in `fetch`)
- A free [Groq API key](https://console.groq.com/keys) (required)
- A free [Gemini API key](https://aistudio.google.com/apikey) (optional, for Labs)
- A Telegram bot token from @BotFather (optional, for bot)

### Setup

```bash
git clone https://github.com/Pavankumar77theblaster/SecKB-VAPT.git
cd SecKB-VAPT

# Configure API keys
cp .env.example .env
# Edit .env and fill in your keys

# Install webapp dependencies
cd webapp && npm install && cd ..

# Start the dashboard
node webapp/server.js
# → Opens at http://localhost:3000
```

### Populate with articles (first run)

```bash
# Fetch from 24 RSS feeds, last 7 days, up to 20 articles
node fetch-articles.js --limit 20 --days 7
```

### Backfill missing notes

```bash
# Re-generate AI notes for any articles missing content
node backfill-notes.js
```

### Start Telegram bot

```bash
node telegram-bot.js
# Now send any URL to @Pentest_resource_bot → auto-imports to dashboard
```

### Auto-start on reboot (add to crontab)

```bash
crontab -e
```

Add these lines:
```
# Auto-fetch new articles every 30 min
*/30 * * * * cd /path/to/SecKB-VAPT && node fetch-articles.js --limit 15 --days 1 >> logs/fetch.log 2>&1

# Auto-start server on reboot
@reboot cd /path/to/SecKB-VAPT/webapp && nohup node server.js >> /path/to/SecKB-VAPT/logs/server.log 2>&1 &

# Auto-start Telegram bot on reboot
@reboot cd /path/to/SecKB-VAPT && nohup node telegram-bot.js >> logs/telegram-bot.log 2>&1 &
```

---

## Import URL Feature

From the dashboard header, click **+ Import URL** and paste any public security article. The pipeline:

1. Fetches the page HTML (with browser-like headers)
2. Extracts title + readable text content
3. Sends to Groq for scoring (`llama-3.1-8b-instant`)
4. If score ≥ 6 and security-relevant: generates 18-field pentest notes
5. Saves to SQLite with full metadata
6. Live SSE progress shown in modal

Takes ~20–40 seconds per article.

---

## Telegram Bot

Send any URL to **@Pentest_resource_bot**:

```
You: https://medium.com/some-security-article
Bot: ⏳ Importing article...
Bot: ✅ Added to SecKB!
     📌 SQL Injection Exploitation Deep Dive
     ⭐ Score: 9/10 | High | Critical | SQLi
     🔗 Open Dashboard: http://localhost:3000
```

The bot calls the same `/api/import-url` SSE endpoint and parses the stream.

---

## AI Chat Widget

Click the 💬 button (bottom-right of dashboard) to open the chat panel.

- Toggle between **Groq** (fast, free) and **Gemini** (optional)
- Ask anything: exploit techniques, tool usage, CTF hints, code review
- Chat history kept per session
- Uses `POST /api/chat` endpoint

---

## Vulnerability Categories

| Category | Vulnerability Types |
|----------|-------------------|
| Client-Side Attacks | XSS, CSRF, Clickjacking, Prototype Pollution |
| Injection Attacks | SQLi, Command Injection, SSTI, XXE, LDAP Injection |
| Broken Access Control | IDOR, Path Traversal, Privilege Escalation |
| Authentication & Sessions | Auth Bypass, JWT Attack, OAuth Attack, Session Fixation |
| Server-Side Attacks | SSRF, Deserialization, File Upload, RCE |
| API & Web Services | GraphQL, REST API flaws, CORS, Mass Assignment |
| Cloud & Infrastructure | Misconfiguration, IDOR in cloud storage, IMDS attacks |
| Recon & Enumeration | Subdomain Takeover, Info Disclosure, OSINT |
| Exploit Chaining | Multi-vuln attack paths |
| Web Fundamentals | HTTP mechanics, cookies, same-origin policy |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Node.js (built-in `https`, no framework for scripts) |
| Web Server | Express.js |
| Database | SQLite via better-sqlite3 |
| Frontend | Vanilla JS SPA (no React/Vue/Angular) |
| AI Scoring | Groq API — llama-3.1-8b-instant |
| AI Notes | Groq API — llama-3.1-8b-instant |
| AI Labs | Gemini API — gemini-2.0-flash-lite |
| AI Chat | Groq (default) + Gemini (optional) |
| Real-time | SSE (Server-Sent Events) for import progress |
| Telegram | Long-polling via HTTPS (no extra npm packages) |
| Styling | Pure CSS with CSS custom properties (3 themes) |
| RSS | Custom XML parser (no xml2js dependency) |
| Autostart | cron `@reboot` entries |

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus search |
| `Escape` | Close detail panel / modal / chat |
| `Space` | Flip flashcard |
| `→` / `←` | Next / previous flashcard |
| `k` | Mark flashcard as "Know It" |
| `r` | Mark flashcard as "Review Later" |

---

## Project Data Flow

```
RSS Feeds (24)
     │
     ▼ node fetch-articles.js (cron: every 30 min)
     │
     ├─ Parse XML → extract title + content
     ├─ Deduplicate (check source_url in DB)
     ├─ Score with Groq (0-10, skip if <6 or not security)
     ├─ Generate 18-field pentest notes with Groq
     └─ POST /api/articles → SQLite

Manual Import
     │
     ├─ Dashboard "Import URL" modal
     │   └─ GET /api/import-url (SSE stream) → same pipeline
     │
     └─ Telegram Bot @Pentest_resource_bot
         └─ URL message → GET /api/import-url → reply with result

Dashboard (SPA)
     │
     ├─ GET /api/articles → article list with filters
     ├─ GET /api/articles/:id → full article detail
     ├─ POST /api/articles/:id/lab/generate → Gemini lab
     ├─ POST /api/chat → Groq/Gemini chat
     └─ PATCH endpoints → status, notes, flashcard updates
```

---

## License

MIT — fork it, extend it, use it for your VAPT prep.
