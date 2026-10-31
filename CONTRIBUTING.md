# Contributing to Hidden Dependency X-Ray (HDX)

Welcome to the team! This repository is organized for high-velocity, contract-first collaboration during hackathons and agile sprints.

---

## 1. Team Roles & Ownership

Each teammate owns specific subdirectories and capabilities:

| Role | Name / Handle | Primary Responsibility | Owned Directories |
|---|---|---|---|
| **System Lead** | Architect | Schemas, tooling, coordination, docs | `contracts/`, `scripts/`, `docs/`, `CONTRIBUTING.md`, `README.md` |
| **Role A** | Scanner & Backend | Manifest parsing, runtime evidence, sample app | `backend/app/ingestion/`, `backend/app/security/`, `demo/`, `fixtures/`, `tests/ingestion/` |
| **Role B** | Graph & Simulation | Database, graph model, failure simulation | `backend/app/graph/`, `backend/app/analysis/`, `backend/app/models/`, `backend/app/db/`, `backend/app/api/` |
| **Role C** | Frontend | React dashboard, Cytoscape visualization | `frontend/` |
| **Role D** | Knowledge & Trust | Knowledge Plane, Gemini AI, Solana, Ed25519 | `knowledge-plane/`, `backend/app/integrations/`, `tests/integrations/` |

---

## 2. Contract-First Development Philosophy

**Golden Rule**: Never modify data schemas or API signatures in isolation.

1. **All contracts live in `contracts/`**:
   - `graph-schema.json`
   - `evidence-schema.json`
   - `scan-schema.json`
   - `finding-schema.json`
   - `scenario-schema.json`
   - `openapi.yaml`
2. **Contract Agreement (Hours 0–2)**:
   - Changes to request/response shapes must be discussed and committed to `contracts/` before updating backend models (`backend/app/models/`) or frontend TypeScript types (`frontend/src/types/`).
3. **Mock First**:
   - Role C (Frontend) should build against fixture responses in `fixtures/` while Role A & B implement the backend.

---

## 3. Branching & Pull Requests

- **`main`**: Always deployable, passing tests.
- **Feature Branches**:
  - `feat/scanner-<feature>` (Role A)
  - `feat/graph-<feature>` (Role B)
  - `feat/ui-<feature>` (Role C)
  - `feat/knowledge-<feature>` (Role D)
  - `docs/<topic>` (Lead)
- **Commit Messages**: Follow Conventional Commits:
  - `feat(ingestion): add npm package-lock parser`
  - `feat(graph): implement blast-radius traversal`
  - `feat(ui): add Cytoscape node inspector drawer`
  - `feat(trust): add Solana devnet bundle verifier`
  - `fix(contracts): update finding severity enum`

---

## 4. Local Development Workflow

### Setup (First Time)
Run the automated bootstrap script:
```powershell
.\scripts\setup.ps1
```

### Running Locally
```powershell
.\scripts\start.ps1
```

### Running Tests
Before opening a PR or merging to main, verify all tests pass:
```powershell
.\scripts\test.ps1
```

---

## 5. Coding Standards

- **Python**: PEP 8 compliance, formatted with `ruff` or `black`, typed with Pydantic v2.
- **TypeScript**: Strict type checking (`noImplicitAny: true`), functional React components with hooks.
- **Security & Privacy**:
  - Never check in API keys or private keys (`.env` is in `.gitignore`).
  - No raw customer code or telemetry is ever uploaded to external cloud endpoints.

