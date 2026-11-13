# Fraud Radar

Fraud Radar is a university prototype for explainable, multi-source transaction risk assessment. It combines normalized risk signals with configurable risk profiles. Scores indicate suspicious indicators; they are not a definitive finding of fraud.

## Architecture

The React/TypeScript client calls a FastAPI service. The service persists transactions, profiles, analyses, provider results, AI reports, and short chat sessions in SQLite through SQLAlchemy. Fraud provider adapters emit common signals; the Risk Engine fuses evidence and applies profile-specific weights. The LLM layer interprets stored structured results and never calculates or changes the official score.

```text
React + Vite  ->  FastAPI routes  ->  services
                                  ├─ FFraud, IP-DB, VirusTotal adapters + deterministic mock adapters
                                  ├─ category normalization, evidence fusion + profile risk engine
                                  ├─ SQLite repositories/models
                                  └─ LLM interpretation interface (mock / DeepSeek)
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

`backend/.env.example` documents the settings. `USE_MOCK_APIS=true` uses deterministic local responses and makes no external requests. For real integrations, set `USE_MOCK_APIS=false`; FFraud's public IP endpoint can be called without a key, while IP-DB and VirusTotal need `IPDB_API_KEY` and `VIRUSTOTAL_API_KEY`. `FFRAUD_API_KEY` is optional. Keep credentials in the backend environment only. Each provider has an independent timeout, error state, and status result; a failed provider does not stop the others. The `/api/providers/status` endpoint backs the API Monitoring page.

The AI layer is configured separately. `USE_MOCK_LLM=true` (default) uses deterministic report and chat responses and makes no DeepSeek calls. For live interpretation, set `USE_MOCK_LLM=false`, then configure `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`, and `DEEPSEEK_BASE_URL`. Credentials remain backend-only. The model receives only the selected analysis's bounded transaction context, Risk Engine categories, normalized provider evidence, and preferences.

## Mock analysis and scoring

Start at the Transaction Analysis page and choose a risk profile. Each source's raw fields are mapped to six shared categories. Repeated provider detections use the strongest score; provider agreement raises evidence strength but never adds duplicate risk points. Category risk is the maximum distinct factor severity. The preference weight is multiplied by evidence strength, then normalized among categories with usable evidence; unknown categories are omitted from the score instead of being treated as zero. Missing provider results are shown as unavailable. Provider results are cached for `PROVIDER_CACHE_TTL_SECONDS` (default 24 hours) and shared across profile rescoring; select “Refresh provider data” to bypass the cache. Classification thresholds are configurable in `backend/app/core/config.py`.

Provider mapping rules: FFraud's `fraud_score` is used as IP reputation; VPN/proxy/Tor, hosting, abuse, and threat tags map to their corresponding categories. IP-DB's returned `abuseConfidenceScore`, `blacklistSources`, and `networkType` map to IP reputation, malicious infrastructure, and network anonymity; absent fields remain unknown. The adapter validates IPv4/IPv6 input, sends the credential only in the `Key` request header, and classifies authentication failures, rate limits, timeouts, transport errors, and malformed responses without failing the other providers. VirusTotal reputation maps to IP reputation; its malicious/suspicious engine counts use `(malicious + 0.5 × suspicious) / total × 400`, capped at 100. Provider confidence affects evidence strength. Country location is not scored unless transaction context can support a comparison.

Risk dimension IDs keep the existing six Risk Engine categories: `ip_reputation`, `network_anonymity`, `malicious_infrastructure`, `geographic_risk`, `transaction_behavior`, and `account_characteristics` (displayed as Account Profile Risk). API category responses also include a dimension name, evidence status, and coverage. Coverage denominator counts distinct scoreable signal types (not provider count or raw metadata count); it measures data presence, not severity. Scores and weights retain the existing Risk Engine formula. IP-derived country/ASN/ISP are contextual until comparable transaction geography is present. Transaction amount and velocity are separate signals; velocity is the recent transaction count supplied by the caller, with no historical baseline or time window implied. Account Age is caller-supplied; account history, device, and biometric evidence are unavailable from the current providers.

To test IP-DB locally, set `IPDB_API_KEY` in the private `backend/.env`, set `USE_MOCK_APIS=false`, and run an analysis with an IP address. The provider's result and status appear in the analysis response and API Monitoring page. Automated tests mock HTTP responses and do not consume API quota: `cd backend; python -m pytest tests/test_ipdb.py`.

VirusTotal notes that queried indicators may be added to its community dataset. Do not submit sensitive or personally identifying IP indicators unless your institution is permitted to share them.

The seed examples are synthetic and intended only for demonstrations. The same transaction's latest normalized provider results can be rescored with another profile without calling providers again.

## AI Reports and Provider Evidence

After running an assessment, select **Generate report** to request an AI Fraud Risk Report. `POST /api/ai/report/{analysis_id}` stores one report per analysis and reuses it by default; pass `{"regenerate": true}` to regenerate. `GET /api/ai/report/{analysis_id}` retrieves the saved report. The report covers the six existing categories, provider agreement, contributions, profile preferences, positive signals, limitations, and recommended actions. The final score and risk level are copied from the persisted Risk Engine record after the model response is validated.

Both contextual Q&A panels reuse `POST /api/ai/chat/{analysis_id}`. Send `{ "question": "...", "session_id": 1, "context_type": "report" }` for AI Report Q&A, or set `context_type` to `"provider_evidence"` for Provider Evidence Q&A. The default is `report` for older clients. Sessions are scoped to one analysis and one context type; a session cannot be reused across the two panels. Read messages with `GET /api/ai/chat/{analysis_id}/{session_id}` and clear them with `DELETE` on that same path. Chat history is short and transaction-specific. Mock mode supports both features without API credits. If DeepSeek is unavailable, the risk assessment remains available and the AI feature reports a temporary service error.

Provider Evidence Q&A receives allowlisted provider-reported fields, provider statuses, backend-normalized signals, and their mappings to the existing Risk Engine dimensions. It does not receive the professional report. AI Report Q&A receives the current report context. The interface labels provider facts separately from normalized signals and AI explanations; contextual provider fields are not described as score inputs unless the normalized evidence mapping shows that relationship.

The backend calls DeepSeek's OpenAI-compatible `https://api.deepseek.com/chat/completions` endpoint. Set `DEEPSEEK_BASE_URL` to the base URL only (without `/chat/completions`). The example defaults to `deepseek-v4-flash`; override it with an account-supported model via `DEEPSEEK_MODEL`.

## Tests

```powershell
cd backend
pytest
```

Tests cover health, profile validation and persistence, normalized weights, multi-source mock scoring, cache reuse across profiles, provider mapping, AI service output validation, report caching, missing keys, Fraud Detective session history, provider evidence context contents, context/session separation, and current-analysis scoping.

### Q&A validation checklist

- [ ] Generate an analysis in Transaction Analysis, then open the Provider Evidence navigation page and expand FFraud, IP-DB and VirusTotal details.
- [ ] Ask Provider Evidence Q&A about an actual returned field such as FFraud `fraud_score` or VirusTotal `last_analysis_stats`.
- [ ] Confirm the answer distinguishes provider-reported facts, backend-normalized signals, and AI explanation, and only associates mapped scoreable signals with a Risk Engine dimension.
- [ ] Open AI Reports and generate or load the complete AI Fraud Risk Report; confirm the report appears above AI Report Q&A.
- [ ] Ask AI Report Q&A about the report summary, dimension contributions, preferences, or recommendations.
- [ ] Confirm each panel maintains and clears its own conversation and the backend rejects reusing one context's session in the other context.
- [ ] Run a second analysis and verify both panels use the new `analysis_id` and do not show the previous analysis's local messages.
- [ ] Confirm Transaction Analysis contains transaction input and Risk Engine results without the full AI report or either Q&A panel.
- [ ] In mock mode, verify both context paths work without calling DeepSeek; in real mode, confirm each answer uses only its corresponding current-analysis context.

## Future work

LLMs only interpret deterministic Risk Engine output and must not calculate it. Authentication, biometric ingestion, and production banking integrations remain outside this prototype stage. In real-provider mode, missing provider credentials are reported as disabled; the service never falls back to mock detection data.
