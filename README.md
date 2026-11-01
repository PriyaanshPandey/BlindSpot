# Blindspot

> **Dependency intelligence, live vulnerability radar, and cryptographically verified supply chain resilience.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Cytoscape.js-61DAFB.svg?logo=react)](https://react.dev)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB-47A248.svg?logo=mongodb)](https://www.mongodb.com/)
[![Solana](https://img.shields.io/badge/Blockchain-Solana%20Devnet-9945FF.svg?logo=solana)](https://solana.com)

---

## What is Blindspot?

Modern applications rely on external services, APIs, databases, and multi-tier package trees. When an open-source package is compromised or an external API experiences an outage, teams often have no clear visibility into how deeply their systems are impacted.

**Blindspot** scans your codebase, maps your entire architecture into a multi-tier dependency graph (from direct packages down to 2nd and 3rd layer transitive dependencies), monitors live reachability and OSV security vulnerabilities, verifies third-party vendor certificates, and anchors On-Chain Value (OBV) transactions to Solana.

---

## Core Capabilities & How They Work

### 1. Multi-Tier Dependency Graph
- **Direct Dependencies (Tier 3)**: Extracted from manifests (`package.json`, `requirements.txt`).
- **Transitive Sub-Dependencies (Tier 4)**: Extracted from lockfiles (`package-lock.json`, `poetry.lock`).
- **Deep Transitive Dependencies (Tier 5)**: Extracted across 3rd-party to 4th-party and 5th-party layers.
- **Infrastructure & Databases (Tier 3)**: Discovered automatically from `docker-compose.yml` and environment variables (PostgreSQL, Redis, MongoDB, MySQL, RabbitMQ).
- **External Cloud Vendors (Tier 4)**: Identified from live network calls and API clients (Stripe, Razorpay, Auth0, Solana, Supabase, OpenAI).
- **Business Journeys (Tier 0)**: Inferred operational journeys connecting services to user-facing workflows.

### 2. Live Radar & Probing
- **Real-Time Endpoint Prober**: Probes external endpoints for reachability and latency. Down or degraded endpoints are immediately marked in the graph and raised as critical findings.
- **Google OSV Advisory Database**: Queries live OSV advisories for exact package versions across direct and transitive dependencies.
- **Blast Radius Simulation**: Simulates outages on any node (e.g., Stripe, database, or library) and computes code impact percentage and affected journeys.

### 3. Solana Integration & Hashed OBV Transfers
- **SHA-256 Hashing**: Any On-Chain Value (OBV) data payload transferred via Solana is serialized canonically and hashed using SHA-256 for cryptographic integrity.
- **Solana Devnet Memo Program**: Anchors the resulting SHA-256 hash on-chain using the standard Memo program (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
- **On-Chain Transaction Verification**: Checks transaction signatures and block confirmations via Solana JSON-RPC endpoints.
- **Offline Resilience**: Automatically operates offline when disconnected, generating simulated signatures and deterministic hashes for reliable demonstrations.

### 4. Third-Party Vendor Certificates
- **X.509 PEM Validation**: Allows teams to store and verify vendor authenticity certificates.
- **MongoDB Persistence**: Certificates and validation statuses are stored persistently in MongoDB (with automatic in-memory fallback).
- **Verification Guarantee**: Malformed or unverified vendor certificates are flagged during scanning to block unauthenticated third-party services.

---

## Architecture Overview

```
 ┌───────────────────────────┐       ┌───────────────────────────┐
 │   Frontend (React + Vite) │ <---> │      FastAPI Backend      │
 │  Cytoscape Interactive UI │       │   Unified Graph Engine    │
 └───────────────────────────┘       └─────────────┬─────────────┘
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                │                                                                     │
     ┌──────────▼──────────┐              ┌────────▼──────────┐            ┌──────────▼──────────┐
     │  Multi-Tier Parser  │              │   MongoDB Store   │            │   Solana Devnet     │
     │ Direct & Transitive │              │ Scans, Graphs,    │            │ SHA-256 Hashed OBV  │
     │ Lockfile Ingestion  │              │ Vendor Certs      │            │ On-Chain Anchors    │
     └─────────────────────┘              └───────────────────┘            └─────────────────────┘
```

---

## Graph Node Legend: Shapes & Colors

| Shape | Color | Tier | Meaning |
|---|---|---|---|
| **Star** | Gold / Yellow | Tier 0 | **Business Journey** (e.g., Core Operations, Checkout Flow) |
| **Pill / Oval** | Blue / Slate | Tier 1 | **Root Application** (entrypoint codebase) |
| **Hexagon** | Blue | Tier 2 | **Internal Microservice** (backend, frontend, worker) |
| **Rectangle** | Cyan / Blue | Tier 3 | **Declared Direct Package** (from manifest) |
| **Rectangle** | Light Blue | Tier 4 | **Transitive Package** (2nd-layer dependency from lockfile) |
| **Rectangle** | Dark Slate | Tier 5 | **Deep Transitive Package** (3rd-layer dependency) |
| **Cylinder** | Slate / Gray | Tier 3 | **Infrastructure Resource** (Database, Cache, Queue) |
| **Hexagon** | Purple / Orange | Tier 4 | **External Vendor API** (Stripe, Solana, Auth0, etc.) |
| **Border: Red** | Red | Any | **Compromised / Outage** (Known CVE or failing health probe) |

---

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) MongoDB running locally on `mongodb://localhost:27017`

### 1. Backend Setup
```bash
cd backend
pip install -r pyproject.toml # or pip install -e .
python main.py
```
Backend runs at `http://127.0.0.1:8000`. API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at `http://localhost:5173`.

---

## Running the Automated Test Suite

Run all unit, integration, and security tests from the project root:

```bash
cd backend
python -m pytest ../tests -v
```

All 42 test suites verify:
- Ingestion parsers (npm, PyPI, lockfiles, multi-tier dependencies)
- Graph engine and failure simulation calculations
- MongoDB connection and persistence
- Solana Devnet cluster status, hash anchoring, and transaction verification
- Third-party vendor certificate validation

---

## API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Run a scan on a local repository path |
| `POST` | `/api/v1/scans/direct` | Run a scan on direct JSON payload files |
| `GET` | `/api/v1/scans/{scan_id}/graph` | Retrieve the generated dependency graph |
| `POST` | `/api/v1/scans/solana-transfer` | Execute an OBV transfer with SHA-256 hash on Solana |
| `POST` | `/api/v1/scans/vendor-certificates` | Store and validate a vendor X.509 certificate |
| `GET` | `/api/v1/scans/vendor-certificates/{vendor}` | Retrieve stored certificate status for a vendor |
| `POST` | `/api/v1/scans/{scan_id}/simulate` | Run failure simulation and calculate impact percentage |

---

## License

This project is licensed under the MIT License.
