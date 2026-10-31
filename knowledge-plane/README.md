# HDX Knowledge Plane [Role D]

The public knowledge infrastructure for **Hidden Dependency X-Ray (HDX)**.

## Core Principle
**Customer code and dependency maps are NEVER sent to the Knowledge Plane.**
The Knowledge Plane is strictly one-way distribution: it packages, signs, and distributes verified public vulnerability and vendor relationship intelligence.

## Components
1. **Schemas** (`schemas/bundle-schema.json`): Canonical format for signed bundles.
2. **Vendor Passports** (`sample-data/vendor-passports.json`): Voluntary cryptographic vendor disclosures (e.g. Stripe -> AWS, Twilio -> Cloudflare).
3. **Publisher** (`publisher/publish.py`): Packages advisories, signs with Ed25519, and pushes bundle metadata.
4. **Solana Devnet Anchor** (`solana/anchor.js`): Publishes SHA-256 bundle hashes to the Solana Devnet blockchain.
5. **Distribution Service** (`service/server.py`): Lightweight CDN/HTTP server for client bundle retrieval in Hybrid Mode.

