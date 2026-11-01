# Blindspot

> **Dependency intelligence, live vulnerability radar, AI-powered security insights, and cryptographically verified supply chain resilience.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Cytoscape.js-61DAFB.svg?logo=react)](https://react.dev)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB-47A248.svg?logo=mongodb)](https://www.mongodb.com/)
[![Gemini](https://img.shields.io/badge/AI-Google%20Gemini-4285F4.svg?logo=googlegemini)](https://ai.google.dev/)
[![Solana](https://img.shields.io/badge/Blockchain-Solana%20Devnet-9945FF.svg?logo=solana)](https://solana.com)

---

## What is Blindspot?

Modern applications rely on external services, APIs, databases, and multi-tier package trees. When an open-source package is compromised or an external API experiences an outage, teams often have no clear visibility into how deeply their systems are impacted.

**Blindspot** is a dependency intelligence and supply-chain resilience platform. It scans your codebase, maps your architecture into a multi-tier dependency graph (from direct packages down to transitive dependencies), monitors endpoint reachability and OSV security vulnerabilities, analyzes third-party vendor dependencies, and anchors cryptographic hashes of public knowledge and value-transfer data to Solana.

Blindspot also integrates **Google Gemini** to generate structured, audience-aware explanations of security findings and remediation recommendations. Its privacy-conscious AI integration sends sanitized vulnerability metadata rather than source code or secrets, and can fall back to deterministic local explanations when Gemini is unavailable.

---

## Core Capabilities & How They Work

### 1. Multi-Tier Dependency Graph

- **Direct Dependencies (Tier 3):** Extracted from manifests (`package.json`, `requirements.txt`).
- **Transitive Sub-Dependencies (Tier 4):** Extracted from lockfiles (`package-lock.json`, `poetry.lock`).
- **Deep Transitive Dependencies (Tier 5):** Mapped across deeper dependency layers.
- **Infrastructure & Databases (Tier 3):** Discovered from `docker-compose.yml` and environment configuration, including PostgreSQL, Redis, MongoDB, MySQL, and RabbitMQ.
- **External Cloud Vendors (Tier 4):** Identified from network calls and API clients, including Stripe, Razorpay, Auth0, Solana, Supabase, and OpenAI.
- **Business Journeys (Tier 0):** Inferred operational journeys connecting technical services to user-facing workflows.

### 2. Live Radar & Probing

- **Real-Time Endpoint Prober:** Probes external endpoints for reachability and latency. Down or degraded endpoints can be marked in the graph and raised as findings.
- **Google OSV Advisory Database:** Queries OSV advisories for exact package versions across direct and transitive dependencies.
- **Blast Radius Simulation:** Simulates outages on graph nodes (for example, Stripe, a database, or a library) and calculates affected components, business journeys, and impact.
- **Dependency Reconciliation:** Compares declared dependencies, observed runtime connections, and other available evidence to highlight discrepancies and unexpected relationships.

### 3. Google Gemini AI Intelligence

Blindspot integrates **Google Gemini** as an AI-powered security explanation and vendor-enrichment service.

#### AI-Powered Vulnerability Explanations

Gemini analyzes structured vulnerability and dependency metadata to generate explanations that are easier to act on.

For each supported finding, it can produce:

- **Security Summary:** A readable explanation of the vulnerability or advisory.
- **Why It Matters:** An explanation of potential runtime, operational, and business impact.
- **Technical Impact:** How the affected dependency may influence the application and its dependency graph.
- **Safe Remediation Steps:** Practical recommendations for developers or enterprise security teams.
- **Confidence Score:** A model-generated confidence estimate accompanying the explanation.

#### Builder and Enterprise Context

Explanations can be tailored to the intended audience:

- **Builder / Developer:** Practical remediation guidance, package upgrade suggestions, and development-focused next steps.
- **Enterprise:** Dependency propagation, business continuity, blast-radius implications, and resilience-focused recommendations.

#### Privacy-Conscious AI Processing

Blindspot applies a sanitization layer before sending finding context to Gemini.

- Only selected structured vulnerability metadata is included in the AI prompt.
- Source code, credentials, passwords, tokens, and private traces are excluded from the sanitized payload.
- Sensitive patterns such as IP addresses and absolute filesystem paths are redacted.
- The `/api/v1/ai/preview-payload` endpoint allows the application to inspect the exact sanitized payload before transmission.
- The explanation endpoint supports a `user_approved_transmission` field and rejects requests when it is false.

Gemini is used for explanation and enrichment; it does not need access to the user's source-code archive.

#### Offline and Failure Fallback

Blindspot does not depend entirely on Gemini being available.

- If `GEMINI_API_KEY` is not configured, the backend generates deterministic local explanations.
- If the Gemini API is unreachable, times out, or encounters quota or authentication errors, the backend returns a structured fallback response.
- API status codes distinguish configuration, connectivity, authentication, quota, and model availability problems.

#### Public Vendor Profile Enrichment

Gemini can also help enrich third-party vendor profiles by domain.

- Blindspot uses a local curated vendor database for supported vendors.
- For other domains, it can request a structured public subprocessor profile from Gemini.
- Returned profiles can include disclosed subprocessors and source references.

AI-generated vendor enrichment is informational and should be independently checked. It is **not equivalent to a vendor-signed passport, certificate, or cryptographic identity verification**.

### 4. Solana Integration & Hashed OBV Transfers

- **SHA-256 Hashing:** OBV data payloads transferred via Solana are serialized canonically and hashed using SHA-256 for cryptographic integrity.
- **Solana Devnet Memo Program:** Anchors the resulting SHA-256 hash on-chain using the standard Memo program (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
- **On-Chain Transaction Verification:** Checks transaction signatures and block confirmations via Solana JSON-RPC endpoints.
- **Offline Resilience:** Supports offline demonstration behavior using simulated signatures and deterministic hashes. Simulated signatures are not real on-chain transactions or proof of blockchain confirmation.

### 5. Third-Party Vendor Certificates & Passports

Blindspot provides mechanisms for inspecting third-party vendor trust information.

- **X.509 PEM Validation:** Allows teams to store and validate vendor authenticity certificates.
- **MongoDB Persistence:** Certificates and validation statuses are stored persistently in MongoDB, with an in-memory fallback where supported.
- **Vendor Passport JSON:** Uses a structured format for vendor identity, disclosed upstream dependencies, services, and validity periods.
- **Schema Validation:** Validates passport structure, required fields, timestamps, expiry, and duplicate passport identifiers.
- **Trust Separation:** A structurally valid passport is not automatically considered authenticated. Cryptographic verification against independently trusted keys is a separate requirement.

Malformed, expired, or unverified vendor trust information should be surfaced clearly rather than silently treated as trusted.

---

## Architecture Overview

```text
 ┌───────────────────────────┐       ┌───────────────────────────┐
 │   Frontend (React + Vite) │ <---> │      FastAPI Backend      │
 │  Cytoscape Interactive UI │       │   Unified Graph Engine    │
 └───────────────────────────┘       └─────────────┬─────────────┘
                                                   │
                ┌──────────────────────────────────┼──────────────────────────────────┐
                │                                  │                                  │
     ┌──────────▼──────────┐            ┌──────────▼─────────┐            ┌───────────▼──────────┐
     │  Multi-Tier Parser  │            │   MongoDB Store    │            │    Google Gemini     │
     │ Direct & Transitive │            │ Scans, Graphs,     │            │ Sanitized AI         │
     │ Lockfile Ingestion  │            │ Findings, Evidence │            │ Explanations         │
     └─────────────────────┘            │ Vendor Trust Data  │            │ Vendor Enrichment    │
                                        └────────────────────┘            └──────────────────────┘

                                                   │
                                        ┌──────────▼──────────┐
                                        │    Solana Devnet    │
                                        │ SHA-256 Hash        │
                                        │ On-Chain Anchoring  │
                                        └─────────────────────┘
```

### Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Dependency Graph Visualization | Cytoscape.js |
| Backend API | Python, FastAPI, Pydantic |
| Graph Engine | NetworkX |
| Database | MongoDB |
| Dependency & Security Intelligence | Package parsers, Google OSV |
| AI Intelligence | Google Gemini API, official `google-genai` SDK |
| Browser / Runtime Observation | Playwright, OpenTelemetry |
| Cryptographic Trust | Ed25519, X.509, SHA-256 |
| Blockchain | Solana Devnet |

---

## Graph Node Legend: Shapes & Colors

| Shape | Color | Tier | Meaning |
|---|---|---|---|
| **Star** | Gold / Yellow | Tier 0 | **Business Journey** (e.g., Core Operations, Checkout Flow) |
| **Pill / Oval** | Blue / Slate | Tier 1 | **Root Application** (entrypoint codebase) |
| **Hexagon** | Blue | Tier 2 | **Internal Microservice** (backend, frontend, worker) |
| **Rectangle** | Cyan / Blue | Tier 3 | **Declared Direct Package** (from manifest) |
| **Rectangle** | Light Blue | Tier 4 | **Transitive Package** (dependency from lockfile) |
| **Rectangle** | Dark Slate | Tier 5 | **Deep Transitive Package** |
| **Cylinder** | Slate / Gray | Tier 3 | **Infrastructure Resource** (Database, Cache, Queue) |
| **Hexagon** | Purple / Orange | Tier 4 | **External Vendor API** (Stripe, Solana, Auth0, etc.) |
| **Border: Red** | Red | Any | **Compromised / Outage** (Known vulnerability or failing health probe) |

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- (Optional) MongoDB running locally on `mongodb://localhost:27017`
- (Optional) Google Gemini API key for live AI explanations and vendor enrichment
- (Optional) Solana Devnet access for blockchain anchoring

### 1. Backend Setup

```bash
cd backend
pip install -e .
python main.py
```

Backend runs at `http://127.0.0.1:8000`.

API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`.

### 3. Configure Google Gemini (Optional)

Gemini is optional. Blindspot can still provide deterministic local explanations when no API key is configured or Gemini is unavailable.

1. Obtain a Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Configure the following variables in `backend/.env` or your backend process environment:

```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=your_supported_gemini_model
```

3. Restart the backend.

The following endpoint can be used to check whether Gemini is configured:

```http
GET http://127.0.0.1:8000/api/v1/ai/status
```

**Important:** Never commit real API keys or secrets to Git. Keep local environment files out of version control.

---

## Running the Automated Test Suite

Run the backend test suite from the project root:

```bash
cd backend
python -m pytest ../tests -v
```

The automated tests cover areas including:

- Ingestion parsers (npm, PyPI, lockfiles, and dependency discovery)
- Graph engine and failure simulation calculations
- MongoDB connection and persistence
- Solana Devnet cluster status, hash anchoring, and transaction verification
- Gemini API integration, sanitized payload handling, structured explanations, and fallback behavior
- Knowledge bundle signing and verification
- Vendor Passport schema and validation
- Third-party vendor intelligence and certificate handling
- API routes and integration behavior

Some tests may be skipped when external services or credentials are unavailable.

---

## API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Run a scan on a local repository path |
| `POST` | `/api/v1/scans/direct` | Run a scan on direct JSON payload files |
| `GET` | `/api/v1/scans/{scan_id}/graph` | Retrieve the generated dependency graph |
| `POST` | `/api/v1/scans/solana-transfer` | Execute an OBV transfer with SHA-256 hash anchoring on Solana |
| `POST` | `/api/v1/scans/vendor-certificates` | Store and validate a vendor X.509 certificate |
| `GET` | `/api/v1/scans/vendor-certificates/{vendor}` | Retrieve stored certificate status for a vendor |
| `POST` | `/api/v1/scans/{scan_id}/simulate` | Run failure simulation and calculate impact |
| `GET` | `/api/v1/ai/status` | Check Gemini configuration and service readiness |
| `POST` | `/api/v1/ai/preview-payload` | Preview the sanitized vulnerability metadata intended for Gemini |
| `POST` | `/api/v1/ai/explain` | Generate an AI-powered vulnerability explanation and remediation guidance |
| `POST` | `/api/v1/ai/enrich-vendor` | Enrich a vendor profile with publicly disclosed subprocessor information |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
