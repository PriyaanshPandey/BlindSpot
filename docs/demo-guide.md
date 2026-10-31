# HDX 5-Minute Hackathon Presentation Guide

## Demo Checklist Before Stepping on Stage
- [ ] Backend running (`uvicorn main:app --reload`) on port 8000
- [ ] Frontend running (`npm run dev`) on port 5173
- [ ] Browser window open with clean zoom level

---

## 5-Minute Talking Track

| Minute | Section | Actions on Screen | Key Talking Points |
|---|---|---|---|
| **0:00 - 1:00** | **The Problem** | Show Nexus Commerce architecture diagram | "Modern systems rely on hundreds of external dependencies. What we document and what our apps actually call in production are often in dangerous conflict." |
| **1:00 - 2:00** | **Discovery & Ingestion** | Click "Run HDX Discovery" on Nexus Commerce | "In seconds, HDX parses static package manifests, Terraform declarations, and live OpenTelemetry traces locally without uploading our code." |
| **2:00 - 3:00** | **The Reveal (Discrepancy)** | Toggle "Runtime Observations" layer | "Look here: `telemetry.untrusted-cdn.net` was captured in browser traffic but appears in zero architecture documentation. This is an invisible attack vector." |
| **3:00 - 4:00** | **Failure Simulation & Blast Radius** | Click "Stripe" node -> "Simulate 4-Hour Outage" | "When Stripe goes down, what breaks? HDX traces dependencies to business journeys. Checkout halts, affecting 1,200 orders/hr with **$216,000 in gross exposure**." |
| **4:00 - 5:00** | **Trust & Passports** | Click Stripe's Vendor Passport; show Solana badge | "Notice how we discover Stripe's reliance on AWS US-East-1 via signed Vendor Passports anchored to Solana Devnet. Cryptographic proof with zero privacy invasion." |

