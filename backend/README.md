# Hidden Dependency X-Ray (HDX) — Backend Service

Privacy-first dependency intelligence and resilience platform backend.

## Environment Configuration

Configure `GEMINI_API_KEY` for optional cloud-based generative architectural explanations:

1. Copy `.env.example` to `.env` in the project root or in `backend/.env`:
   ```bash
   cp .env.example .env
   ```
2. Set your Google Gemini API key:
   ```env
   GEMINI_API_KEY=your_actual_gemini_api_key_here
   GEMINI_MODEL=gemini-2.5-flash
   ```
3. When `GEMINI_API_KEY` is omitted, BlindSpot operates in **Local-First Mode** with deterministic rule-based explanations. Core features (project scanning, dependency graph, vulnerability reconciliation, risk scoring, failure simulation) run 100% locally and never require an internet connection or API key.

## Starting the Backend

```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

## Running Tests

```bash
# Run complete test suite
pytest ../tests/ -v

# Run Gemini integration and unit tests
pytest ../tests/integrations/test_gemini.py -v
```
