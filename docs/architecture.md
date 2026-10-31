# HDX System Architecture

## Overview
Hidden Dependency X-Ray (HDX) operates on a **Local-First, Cloud-Assisted** model.

```mermaid
flowchart TB
    subgraph DataPlane["Data Plane (Local Customer Environment)"]
        Parser["Manifest & Ingestion Engine"]
        Tracer["Runtime Tracing Ingestion"]
        Reconcile["Reconciliation & Discrepancy Detector"]
        Graph["Unified Graph Engine (NetworkX/MongoDB)"]
        Simulator["Failure & Financial Exposure Simulator"]
        UI["React + Cytoscape UI"]
        
        Parser --> Reconcile
        Tracer --> Reconcile
        Reconcile --> Graph
        Graph --> Simulator
        Graph --> UI
        Simulator --> UI
    end

    subgraph KnowledgePlane["Knowledge Plane (DigitalOcean Cloud)"]
        VulnFeed["Advisory Ingest (OSV/KEV)"]
        Passports["Vendor Passport Registry"]
        Gemini["Gemini AI Enrichment"]
        Signer["Ed25519 Signer & Bundle Packager"]
        Solana["Solana Devnet Anchor"]
        
        VulnFeed --> Signer
        Passports --> Signer
        Gemini --> Passports
        Signer --> Solana
    end

    Signer -->|"Signed Knowledge Bundles"| Reconcile
```

## Security & Privacy Guarantee
1. **Source Code Confidentiality**: Code repositories, manifests, and local traces are evaluated purely on the customer's machine.
2. **Zero Telemetry Exfiltration**: No outbound telemetry containing internal hostnames, credentials, or customer identifiers is emitted.
3. **Cryptographic Integrity**: Incoming bundles from the Knowledge Plane are verified with Ed25519 signatures and cross-checked against Solana Devnet transaction roots.

