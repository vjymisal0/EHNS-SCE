# File Security Analyzer Tool

A production-ready static file security analysis platform built with **FastAPI** (Python) and **Next.js** (TypeScript).

## Architecture

```
backend/          → FastAPI REST API + MongoDB
frontend/         → Next.js 16 App Router + TailwindCSS + Recharts
```

## Features

- **File metadata inspection** – size, name, MIME type
- **MIME validation** – magic-number-based detection vs declared Content-Type
- **Hash generation** – MD5, SHA-1, SHA-256 for threat intelligence lookup
- **Double extension detection** – catches `report.pdf.exe` style attacks
- **Suspicious string scanning** – static pattern matching for known threats
- **Shannon entropy** – identifies encrypted/packed/obfuscated payloads
- **Heuristic risk scoring** – weighted scoring with LOW/MEDIUM/HIGH classification
- **Cybersecurity dashboard** – dark-themed monitoring UI with charts

## Prerequisites

- Python 3.10+ with [uv](https://docs.astral.sh/uv/)
- Node.js 18+
- MongoDB running on `localhost:27017`

## Quick Start

### Backend

```bash
cd backend
uv venv
uv sync
uv run uvicorn app.main:app --reload --port 8000
```

API docs at http://localhost:8000/docs

#### Run Backend Now (PowerShell)

```powershell
Set-Location "D:\EHNS SCE\backend"
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Verify backend health:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing
```

Open docs:

- http://127.0.0.1:8000/docs

Stop server:

- Press `Ctrl+C` in the backend terminal.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MONGO_URL` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB_NAME` | `file_security_analyzer` | Database name |
| `MAX_FILE_SIZE_BYTES` | `10485760` (10 MB) | Upload size limit |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `RATE_LIMIT` | `10/minute` | API rate limit |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend URL for frontend |

## Risk Scoring

| Signal | Points |
|---|---|
| MIME type mismatch | +40 |
| High entropy (>7.5) | +30 |
| Suspicious strings | +25 |
| Double extension | +20 |

| Score Range | Level |
|---|---|
| 0–30 | LOW |
| 31–60 | MEDIUM |
| 61+ | HIGH |

## Security Decisions

- **No file execution** – files are read into memory, analyzed, and discarded
- **Filename sanitization** – UUID prefix, character stripping, length limits
- **Path traversal prevention** – resolved path validated against upload directory
- **Upload size limits** – hard 10 MB cap to prevent DoS
- **CORS restricted** – only configured origins allowed
- **Rate limiting** – SlowAPI middleware prevents abuse
- **Security headers** – X-Content-Type-Options, X-Frame-Options on all responses
- **No disk persistence of uploads** – file bytes stay in memory only
