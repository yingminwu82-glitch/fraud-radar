# Fraud Radar

Fraud Radar is a university prototype for explainable, multi-source transaction risk assessment. It combines normalized risk signals with configurable risk profiles. Scores indicate suspicious indicators; they are not a definitive finding of fraud.

## Architecture

The React/TypeScript client calls a FastAPI service. The service persists transactions, profiles, analyses, and provider results in SQLite through SQLAlchemy. Fraud provider adapters emit common signals; the scoring engine aggregates duplicate signals and applies profile-specific weights. An LLM interface is present as a future extension point and is not called in this stage.

```text
React + Vite  ->  FastAPI routes  ->  services
                                  ├─ fraud provider interface + mock adapter
                                  ├─ normalized signal aggregation + risk engine
                                  ├─ SQLite repositories/models
                                  └─ LLM interface (not implemented)
```

## Stack and folders

- Frontend: React, TypeScript, Vite, Tailwind CSS
- Backend: Python, FastAPI, Pydantic, SQLAlchemy, SQLite
- Tests: pytest

```text
backend/app/{api,core,models,schemas,services}
backend/tests
frontend/src/{components,pages,services,types}
data/mock_transactions.json
```

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

API docs are available at `http://localhost:8000/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` requests to FastAPI at `http://localhost:8000`.

## Configuration

`backend/.env.example` documents the settings. `USE_MOCK_APIS=true` uses deterministic local mock provider responses and makes no external requests. Keep real provider credentials in backend environment variables only. No real provider integration is included in this stage.

## Mock analysis and scoring

Start at the Transaction Analysis page and choose a risk profile. Provider responses are normalized to shared signals, then duplicate detections are combined using the strongest severity rather than counted repeatedly. For each risk category, the engine calculates a signal score, normalized preference weight, and score contribution. Preference weights sum to one; a zero-valued profile falls back to equal weights. Classification thresholds are configurable in `backend/app/core/config.py`.

The seed examples are synthetic and intended only for demonstrations. The same transaction's latest normalized provider results can be rescored with another profile without calling providers again.

## Tests

```powershell
cd backend
pytest
```

Tests cover health, profile validation and persistence, normalized weights, mock scoring, and score bounds.

## Future work

Provider adapters are intentionally placeholders; the provider interface and normalized signal schema are ready for later FFraud, IP-DB, VirusTotal, VPNDetection, or IPLogs integrations. Never return fabricated results when real-provider mode is selected. The LLM interface reserves provider configuration for a later stage. LLMs must explain a deterministic score and must not calculate it. Reports, chatbot, authentication, biometric ingestion, and production banking integrations are outside this prototype stage.
